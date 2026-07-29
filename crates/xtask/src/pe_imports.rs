use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use object::endian::LittleEndian as LE;
use object::read::pe::{Import as PeImport, PeFile64};
use object::{Architecture, FileKind, Object};

pub(crate) const PE_IMPORT_POLICY_ID: &str = "pe-no-vc-runtime-imports-v1";

const RVA_BASED_DELAY_IMPORT_ATTRIBUTES: u32 = 1;
const FORBIDDEN_PREFIXES: &[&str] = &[
    "vcruntime",
    "msvcr",
    "msvcp",
    "msvcm",
    "concrt",
    "vccorlib",
    "vcamp",
    "vcomp",
];
const FORBIDDEN_VERSIONED_MFC_PREFIXES: &[&str] =
    &["mfc", "mfcm", "mfcmifc", "mfco", "mfcd", "mfcn"];

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct PeImportAudit {
    pub(crate) load_time_imports: Vec<String>,
    pub(crate) delay_load_imports: Vec<String>,
}

#[allow(
    dead_code,
    reason = "retained as the regular-file path entry point alongside the byte-bound preflight API"
)]
pub(crate) fn audit_x86_64_pe_imports(path: &Path) -> Result<PeImportAudit, String> {
    let before = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect PE artifact {}: {error}", path.display()))?;
    if before.file_type().is_symlink() {
        return Err(format!(
            "PE artifact must be a regular non-symlink file: {}",
            path.display()
        ));
    }
    if !before.is_file() {
        return Err(format!(
            "PE artifact must be a regular file: {}",
            path.display()
        ));
    }

    let data =
        fs::read(path).map_err(|error| format!("read PE artifact {}: {error}", path.display()))?;
    let after = fs::symlink_metadata(path)
        .map_err(|error| format!("reinspect PE artifact {}: {error}", path.display()))?;
    if after.file_type().is_symlink() || !after.is_file() {
        return Err(format!(
            "PE artifact changed file type while it was read: {}",
            path.display()
        ));
    }
    let byte_len = u64::try_from(data.len())
        .map_err(|_| format!("PE artifact is too large to audit: {}", path.display()))?;
    if before.len() != byte_len || after.len() != byte_len {
        return Err(format!(
            "PE artifact size changed while it was read: {}",
            path.display()
        ));
    }

    audit_x86_64_pe_import_bytes(&data)
        .map_err(|error| format!("PE import audit failed for {}: {error}", path.display()))
}

pub(crate) fn audit_x86_64_pe_import_bytes(data: &[u8]) -> Result<PeImportAudit, String> {
    match FileKind::parse(data) {
        Ok(FileKind::Pe64) => {}
        Ok(kind) => {
            return Err(format!(
                "expected a PE32+ AMD64 executable, found object kind {kind:?}"
            ));
        }
        Err(error) => {
            return Err(format!(
                "expected a well-formed PE32+ AMD64 executable: {error}"
            ));
        }
    }

    let file = PeFile64::parse(data)
        .map_err(|error| format!("parse PE32+ headers and sections: {error}"))?;
    if file.architecture() != Architecture::X86_64 {
        return Err(format!(
            "expected PE32+ AMD64 architecture, found {:?}",
            file.architecture()
        ));
    }

    let load_time_imports = collect_load_time_imports(&file)?;
    let delay_load_imports = collect_delay_load_imports(&file)?;
    reject_forbidden_imports(&load_time_imports, &delay_load_imports)?;

    Ok(PeImportAudit {
        load_time_imports,
        delay_load_imports,
    })
}

fn collect_load_time_imports(file: &PeFile64<'_>) -> Result<Vec<String>, String> {
    let Some(table) = file
        .import_table()
        .map_err(|error| format!("parse load-time import table: {error}"))?
    else {
        return Ok(Vec::new());
    };
    let descriptors = table
        .descriptors()
        .map_err(|error| format!("parse load-time import descriptors: {error}"))?;
    let mut libraries = BTreeSet::new();

    for (index, descriptor) in descriptors.enumerate() {
        let descriptor = descriptor
            .map_err(|error| format!("parse load-time import descriptor {}: {error}", index + 1))?;
        let raw_name = table
            .name(descriptor.name.get(LE))
            .map_err(|error| format!("read load-time import name {}: {error}", index + 1))?;
        libraries.insert(normalize_library_name(raw_name, "load-time", index + 1)?);

        let mut thunk_address = descriptor.original_first_thunk.get(LE);
        if thunk_address == 0 {
            thunk_address = descriptor.first_thunk.get(LE);
        }
        if thunk_address == 0 {
            return Err(format!(
                "load-time import descriptor {} has no thunk table",
                index + 1
            ));
        }
        let mut thunks = table.thunks(thunk_address).map_err(|error| {
            format!(
                "parse load-time import thunk table for descriptor {}: {error}",
                index + 1
            )
        })?;
        let mut thunk_index = 0usize;
        while let Some(thunk) = thunks
            .next::<object::pe::ImageNtHeaders64>()
            .map_err(|error| {
                format!(
                    "parse load-time import thunk {} for descriptor {}: {error}",
                    thunk_index + 1,
                    index + 1
                )
            })?
        {
            thunk_index += 1;
            let import = table
                .import::<object::pe::ImageNtHeaders64>(thunk)
                .map_err(|error| {
                    format!(
                        "parse load-time import thunk {} for descriptor {}: {error}",
                        thunk_index,
                        index + 1
                    )
                })?;
            validate_import_symbol_name(import, "load-time", index + 1, thunk_index)?;
        }
    }

    Ok(libraries.into_iter().collect())
}

fn collect_delay_load_imports(file: &PeFile64<'_>) -> Result<Vec<String>, String> {
    let Some(table) = file
        .data_directories()
        .delay_load_import_table(file.data(), &file.section_table())
        .map_err(|error| format!("parse delay-load import table: {error}"))?
    else {
        return Ok(Vec::new());
    };
    let descriptors = table
        .descriptors()
        .map_err(|error| format!("parse delay-load import descriptors: {error}"))?;
    let mut libraries = BTreeSet::new();

    for (index, descriptor) in descriptors.enumerate() {
        let descriptor = descriptor.map_err(|error| {
            format!("parse delay-load import descriptor {}: {error}", index + 1)
        })?;
        let attributes = descriptor.attributes.get(LE);
        if attributes != RVA_BASED_DELAY_IMPORT_ATTRIBUTES {
            return Err(format!(
                "delay-load import descriptor {} has unsupported attributes 0x{attributes:08x}; PE32+ audit requires RVA-based attributes 0x00000001",
                index + 1
            ));
        }
        let raw_name = table
            .name(descriptor.dll_name_rva.get(LE))
            .map_err(|error| format!("read delay-load import name {}: {error}", index + 1))?;
        libraries.insert(normalize_library_name(raw_name, "delay-load", index + 1)?);

        let thunk_address = descriptor.import_name_table_rva.get(LE);
        if thunk_address == 0 {
            return Err(format!(
                "delay-load import descriptor {} has no import name table",
                index + 1
            ));
        }
        let mut thunks = table.thunks(thunk_address).map_err(|error| {
            format!(
                "parse delay-load import thunk table for descriptor {}: {error}",
                index + 1
            )
        })?;
        let mut thunk_index = 0usize;
        while let Some(thunk) = thunks
            .next::<object::pe::ImageNtHeaders64>()
            .map_err(|error| {
                format!(
                    "parse delay-load import thunk {} for descriptor {}: {error}",
                    thunk_index + 1,
                    index + 1
                )
            })?
        {
            thunk_index += 1;
            let import = table
                .import::<object::pe::ImageNtHeaders64>(thunk)
                .map_err(|error| {
                    format!(
                        "parse delay-load import thunk {} for descriptor {}: {error}",
                        thunk_index,
                        index + 1
                    )
                })?;
            validate_import_symbol_name(import, "delay-load", index + 1, thunk_index)?;
        }
    }

    Ok(libraries.into_iter().collect())
}

fn normalize_library_name(
    name: &[u8],
    import_class: &str,
    descriptor_index: usize,
) -> Result<String, String> {
    if name.is_empty() {
        return Err(format!(
            "{import_class} import descriptor {descriptor_index} has an empty library name"
        ));
    }
    if !name.iter().all(|byte| byte.is_ascii_graphic()) {
        return Err(format!(
            "{import_class} import descriptor {descriptor_index} library name must contain only printable non-whitespace ASCII"
        ));
    }
    if name.iter().any(|byte| matches!(byte, b'/' | b'\\' | b':')) {
        return Err(format!(
            "{import_class} import descriptor {descriptor_index} library name must be a basename without path separators or a drive/stream colon"
        ));
    }

    let normalized = name
        .iter()
        .map(|byte| char::from(byte.to_ascii_lowercase()))
        .collect::<String>();
    let Some(stem) = normalized.strip_suffix(".dll") else {
        return Err(format!(
            "{import_class} import descriptor {descriptor_index} library name must end with .dll"
        ));
    };
    if stem.is_empty() || matches!(stem, "." | "..") {
        return Err(format!(
            "{import_class} import descriptor {descriptor_index} library name must have a non-dot basename before .dll"
        ));
    }
    Ok(normalized)
}

fn validate_import_symbol_name(
    import: PeImport<'_>,
    import_class: &str,
    descriptor_index: usize,
    thunk_index: usize,
) -> Result<(), String> {
    let PeImport::Name(_, name) = import else {
        return Ok(());
    };
    if name.is_empty() || !name.iter().all(|byte| byte.is_ascii_graphic()) {
        return Err(format!(
            "{import_class} import symbol {thunk_index} for descriptor {descriptor_index} must be nonempty printable non-whitespace ASCII"
        ));
    }
    Ok(())
}

fn reject_forbidden_imports(
    load_time_imports: &[String],
    delay_load_imports: &[String],
) -> Result<(), String> {
    let forbidden_load_time = load_time_imports
        .iter()
        .filter(|name| is_forbidden_runtime_import(name))
        .cloned()
        .collect::<Vec<_>>();
    let forbidden_delay_load = delay_load_imports
        .iter()
        .filter(|name| is_forbidden_runtime_import(name))
        .cloned()
        .collect::<Vec<_>>();
    if forbidden_load_time.is_empty() && forbidden_delay_load.is_empty() {
        return Ok(());
    }

    Err(format!(
        "PE import policy {PE_IMPORT_POLICY_ID} rejected forbidden VC/UCRT DLLs (load-time: [{}]; delay-load: [{}])",
        forbidden_load_time.join(", "),
        forbidden_delay_load.join(", ")
    ))
}

fn is_forbidden_runtime_import(name: &str) -> bool {
    let Some(stem) = name.strip_suffix(".dll") else {
        return false;
    };
    stem.starts_with("api-ms-win-crt-")
        || matches!(stem, "ucrtbase" | "ucrtbased" | "ucrtbase_enclave")
        || FORBIDDEN_PREFIXES
            .iter()
            .any(|prefix| stem.starts_with(prefix))
        || FORBIDDEN_VERSIONED_MFC_PREFIXES
            .iter()
            .any(|prefix| has_ascii_digit_version(stem, prefix))
        || stem == "atl"
        || has_ascii_digit_version(stem, "atl")
}

fn has_ascii_digit_version(stem: &str, prefix: &str) -> bool {
    stem.strip_prefix(prefix)
        .and_then(|tail| tail.as_bytes().first())
        .is_some_and(|byte| byte.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;

    const PE_OFFSET: usize = 0x80;
    const COFF_HEADER_OFFSET: usize = PE_OFFSET + 4;
    const OPTIONAL_HEADER_OFFSET: usize = COFF_HEADER_OFFSET + 20;
    const DATA_DIRECTORY_OFFSET: usize = OPTIONAL_HEADER_OFFSET + 112;
    const SECTION_HEADER_OFFSET: usize = OPTIONAL_HEADER_OFFSET + 0xf0;
    const SECTION_RAW_OFFSET: usize = 0x200;
    const SECTION_RVA: u32 = 0x1000;
    const SECTION_SIZE: usize = 0x1000;
    const IMPORT_DESCRIPTORS_RVA: u32 = 0x1000;
    const IMPORT_THUNKS_RVA: u32 = 0x1100;
    const IMPORT_NAMES_RVA: u32 = 0x1200;
    const DELAY_DESCRIPTORS_RVA: u32 = 0x1400;
    const DELAY_THUNKS_RVA: u32 = 0x1600;
    const DELAY_NAMES_RVA: u32 = 0x1800;
    const NAMED_IMPORT_RVA: u32 = 0x1a00;

    fn put_u16(data: &mut [u8], offset: usize, value: u16) {
        data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(data: &mut [u8], offset: usize, value: u64) {
        data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn rva_offset(rva: u32) -> usize {
        SECTION_RAW_OFFSET + usize::try_from(rva - SECTION_RVA).expect("fixture RVA fits usize")
    }

    fn fixture(load_time: &[&[u8]], delay_load: &[&[u8]]) -> Vec<u8> {
        let mut data = vec![0u8; SECTION_RAW_OFFSET + SECTION_SIZE];
        data[0..2].copy_from_slice(b"MZ");
        put_u32(&mut data, 0x3c, PE_OFFSET as u32);
        data[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PE\0\0");

        put_u16(
            &mut data,
            COFF_HEADER_OFFSET,
            object::pe::IMAGE_FILE_MACHINE_AMD64,
        );
        put_u16(&mut data, COFF_HEADER_OFFSET + 2, 1);
        put_u16(&mut data, COFF_HEADER_OFFSET + 16, 0xf0);
        put_u16(
            &mut data,
            COFF_HEADER_OFFSET + 18,
            object::pe::IMAGE_FILE_EXECUTABLE_IMAGE | object::pe::IMAGE_FILE_LARGE_ADDRESS_AWARE,
        );

        put_u16(&mut data, OPTIONAL_HEADER_OFFSET, 0x20b);
        data[OPTIONAL_HEADER_OFFSET + 2] = 14;
        put_u32(&mut data, OPTIONAL_HEADER_OFFSET + 4, 0x200);
        put_u32(&mut data, OPTIONAL_HEADER_OFFSET + 8, SECTION_SIZE as u32);
        put_u32(&mut data, OPTIONAL_HEADER_OFFSET + 16, SECTION_RVA);
        put_u32(&mut data, OPTIONAL_HEADER_OFFSET + 20, SECTION_RVA);
        put_u64(
            &mut data,
            OPTIONAL_HEADER_OFFSET + 24,
            0x0000_0001_4000_0000,
        );
        put_u32(&mut data, OPTIONAL_HEADER_OFFSET + 32, 0x1000);
        put_u32(&mut data, OPTIONAL_HEADER_OFFSET + 36, 0x200);
        put_u16(&mut data, OPTIONAL_HEADER_OFFSET + 40, 6);
        put_u16(&mut data, OPTIONAL_HEADER_OFFSET + 48, 6);
        put_u32(&mut data, OPTIONAL_HEADER_OFFSET + 56, 0x2000);
        put_u32(
            &mut data,
            OPTIONAL_HEADER_OFFSET + 60,
            SECTION_RAW_OFFSET as u32,
        );
        put_u16(&mut data, OPTIONAL_HEADER_OFFSET + 68, 3);
        put_u16(&mut data, OPTIONAL_HEADER_OFFSET + 70, 0x8160);
        put_u64(&mut data, OPTIONAL_HEADER_OFFSET + 72, 0x10_0000);
        put_u64(&mut data, OPTIONAL_HEADER_OFFSET + 80, 0x1000);
        put_u64(&mut data, OPTIONAL_HEADER_OFFSET + 88, 0x10_0000);
        put_u64(&mut data, OPTIONAL_HEADER_OFFSET + 96, 0x1000);
        put_u32(&mut data, OPTIONAL_HEADER_OFFSET + 108, 16);

        data[SECTION_HEADER_OFFSET..SECTION_HEADER_OFFSET + 8].copy_from_slice(b".rdata\0\0");
        put_u32(&mut data, SECTION_HEADER_OFFSET + 8, SECTION_SIZE as u32);
        put_u32(&mut data, SECTION_HEADER_OFFSET + 12, SECTION_RVA);
        put_u32(&mut data, SECTION_HEADER_OFFSET + 16, SECTION_SIZE as u32);
        put_u32(
            &mut data,
            SECTION_HEADER_OFFSET + 20,
            SECTION_RAW_OFFSET as u32,
        );
        put_u32(
            &mut data,
            SECTION_HEADER_OFFSET + 36,
            object::pe::IMAGE_SCN_CNT_INITIALIZED_DATA | object::pe::IMAGE_SCN_MEM_READ,
        );

        if !load_time.is_empty() {
            let directory = DATA_DIRECTORY_OFFSET + object::pe::IMAGE_DIRECTORY_ENTRY_IMPORT * 8;
            put_u32(&mut data, directory, IMPORT_DESCRIPTORS_RVA);
            put_u32(
                &mut data,
                directory + 4,
                u32::try_from((load_time.len() + 1) * 20).expect("fixture directory size fits"),
            );
            let mut name_rva = IMPORT_NAMES_RVA;
            for (index, name) in load_time.iter().enumerate() {
                let descriptor = rva_offset(IMPORT_DESCRIPTORS_RVA) + index * 20;
                let thunk_rva = IMPORT_THUNKS_RVA
                    + u32::try_from(index * 16).expect("fixture thunk offset fits");
                put_u32(&mut data, descriptor, thunk_rva);
                put_u32(&mut data, descriptor + 12, name_rva);
                put_u32(&mut data, descriptor + 16, thunk_rva);
                put_u64(
                    &mut data,
                    rva_offset(thunk_rva),
                    object::pe::IMAGE_ORDINAL_FLAG64 | 1,
                );

                let name_offset = rva_offset(name_rva);
                data[name_offset..name_offset + name.len()].copy_from_slice(name);
                name_rva += u32::try_from(name.len() + 1).expect("fixture name length fits");
            }
        }

        if !delay_load.is_empty() {
            let directory =
                DATA_DIRECTORY_OFFSET + object::pe::IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT * 8;
            put_u32(&mut data, directory, DELAY_DESCRIPTORS_RVA);
            put_u32(
                &mut data,
                directory + 4,
                u32::try_from((delay_load.len() + 1) * 32).expect("fixture directory size fits"),
            );
            let mut name_rva = DELAY_NAMES_RVA;
            for (index, name) in delay_load.iter().enumerate() {
                let descriptor = rva_offset(DELAY_DESCRIPTORS_RVA) + index * 32;
                let thunk_rva = DELAY_THUNKS_RVA
                    + u32::try_from(index * 16).expect("fixture thunk offset fits");
                put_u32(&mut data, descriptor, RVA_BASED_DELAY_IMPORT_ATTRIBUTES);
                put_u32(&mut data, descriptor + 4, name_rva);
                put_u32(&mut data, descriptor + 12, thunk_rva);
                put_u32(&mut data, descriptor + 16, thunk_rva);
                put_u64(
                    &mut data,
                    rva_offset(thunk_rva),
                    object::pe::IMAGE_ORDINAL_FLAG64 | 1,
                );

                let name_offset = rva_offset(name_rva);
                data[name_offset..name_offset + name.len()].copy_from_slice(name);
                name_rva += u32::try_from(name.len() + 1).expect("fixture name length fits");
            }
        }

        data
    }

    fn audit_fixture(data: &[u8]) -> Result<PeImportAudit, String> {
        let directory = tempdir().expect("create fixture directory");
        let path = directory.path().join("candidate.exe");
        fs::write(&path, data).expect("write PE fixture");
        audit_x86_64_pe_imports(&path)
    }

    #[test]
    fn inventories_both_import_tables_in_stable_canonical_order() {
        let audit = audit_fixture(&fixture(
            &[b"USER32.DLL", b"kernel32.dll", b"User32.dll"],
            &[b"SHELL32.DLL", b"advapi32.dll", b"shell32.dll"],
        ))
        .expect("valid PE fixture should pass");

        assert_eq!(
            audit,
            PeImportAudit {
                load_time_imports: vec!["kernel32.dll".to_owned(), "user32.dll".to_owned()],
                delay_load_imports: vec!["advapi32.dll".to_owned(), "shell32.dll".to_owned()],
            }
        );
    }

    #[test]
    fn empty_import_directories_produce_empty_inventories() {
        let bytes = fixture(&[], &[]);
        let audit =
            audit_x86_64_pe_import_bytes(&bytes).expect("valid in-memory PE fixture should pass");
        assert_eq!(
            audit,
            PeImportAudit {
                load_time_imports: Vec::new(),
                delay_load_imports: Vec::new(),
            }
        );
    }

    #[test]
    fn forbidden_runtime_policy_is_anchored_and_requires_dll_extension() {
        let forbidden = [
            "api-ms-win-crt-runtime-l1-1-0.dll",
            "ucrtbase.dll",
            "ucrtbased.dll",
            "ucrtbase_enclave.dll",
            "vcruntime140.dll",
            "msvcr120.dll",
            "msvcp140_atomic_wait.dll",
            "msvcm90.dll",
            "concrt140.dll",
            "vccorlib140.dll",
            "vcamp140.dll",
            "vcomp140.dll",
            "mfc140u.dll",
            "mfcm140.dll",
            "mfcmifc80.dll",
            "mfco42d.dll",
            "mfcd42d.dll",
            "mfcn42d.dll",
            "atl.dll",
            "atl140.dll",
        ];
        for name in forbidden {
            assert!(
                is_forbidden_runtime_import(name),
                "{name} must be forbidden"
            );
        }

        let allowed_near_misses = [
            "xapi-ms-win-crt-runtime-l1-1-0.dll",
            "ucrtbase_proxy.dll",
            "ucrtbased_proxy.dll",
            "xvcruntime140.dll",
            "xmsvcr120.dll",
            "xmsvcp140.dll",
            "xconcrt140.dll",
            "xvccorlib140.dll",
            "xvcamp140.dll",
            "xvcomp140.dll",
            "xmfc140u.dll",
            "xatl140.dll",
            "mfcore.dll",
            "mfcaptureengine.dll",
            "atlthunk.dll",
            "vcruntime140.dll.backup",
        ];
        for name in allowed_near_misses {
            assert!(
                !is_forbidden_runtime_import(name),
                "{name} must not match the versioned policy"
            );
        }
    }

    #[test]
    fn rejects_forbidden_load_time_and_delay_load_imports_after_case_folding() {
        let load_error = audit_fixture(&fixture(&[b"VCRUNTIME140.DLL"], &[]))
            .expect_err("load-time VC runtime must fail");
        assert!(load_error.contains(PE_IMPORT_POLICY_ID));
        assert!(load_error.contains("vcruntime140.dll"));
        assert!(load_error.contains("load-time"));

        let delay_error = audit_fixture(&fixture(&[], &[b"API-MS-WIN-CRT-HEAP-L1-1-0.DLL"]))
            .expect_err("delay-load UCRT must fail");
        assert!(delay_error.contains(PE_IMPORT_POLICY_ID));
        assert!(delay_error.contains("api-ms-win-crt-heap-l1-1-0.dll"));
        assert!(delay_error.contains("delay-load"));
    }

    #[test]
    fn rejects_non_pe_pe32_and_non_amd64_artifacts() {
        let non_pe = audit_fixture(b"not a PE file").expect_err("non-PE must fail");
        assert!(non_pe.contains("well-formed PE32+ AMD64"));

        let mut pe32 = fixture(&[], &[]);
        put_u16(&mut pe32, OPTIONAL_HEADER_OFFSET, 0x10b);
        let pe32_error = audit_fixture(&pe32).expect_err("PE32 must fail");
        assert!(pe32_error.contains("expected a PE32+ AMD64"));
        assert!(pe32_error.contains("Pe32"));

        let mut arm64 = fixture(&[], &[]);
        put_u16(
            &mut arm64,
            COFF_HEADER_OFFSET,
            object::pe::IMAGE_FILE_MACHINE_ARM64,
        );
        let architecture_error = audit_fixture(&arm64).expect_err("ARM64 must fail");
        assert!(architecture_error.contains("expected PE32+ AMD64 architecture"));
        assert!(architecture_error.contains("Aarch64"));
    }

    #[test]
    fn rejects_truncated_or_malformed_import_tables() {
        let mut truncated = fixture(&[b"kernel32.dll"], &[]);
        truncated.truncate(OPTIONAL_HEADER_OFFSET + 40);
        let truncated_error = audit_fixture(&truncated).expect_err("truncated PE must fail");
        assert!(
            truncated_error.contains("PE32+"),
            "unexpected truncated-PE error: {truncated_error}"
        );

        let mut bad_name_rva = fixture(&[b"kernel32.dll"], &[]);
        put_u32(
            &mut bad_name_rva,
            rva_offset(IMPORT_DESCRIPTORS_RVA) + 12,
            0xffff_fff0,
        );
        let name_error = audit_fixture(&bad_name_rva).expect_err("invalid name RVA must fail");
        assert!(name_error.contains("read load-time import name"));

        let mut missing_thunks = fixture(&[b"kernel32.dll"], &[]);
        put_u32(&mut missing_thunks, rva_offset(IMPORT_DESCRIPTORS_RVA), 0);
        put_u32(
            &mut missing_thunks,
            rva_offset(IMPORT_DESCRIPTORS_RVA) + 16,
            0,
        );
        let thunk_error =
            audit_fixture(&missing_thunks).expect_err("missing thunk table must fail");
        assert!(thunk_error.contains("has no thunk table"));
    }

    #[test]
    fn validates_named_symbols_and_rejects_malformed_symbol_names() {
        let mut named = fixture(&[b"kernel32.dll"], &[b"shell32.dll"]);
        put_u64(
            &mut named,
            rva_offset(IMPORT_THUNKS_RVA),
            u64::from(NAMED_IMPORT_RVA),
        );
        put_u16(&mut named, rva_offset(NAMED_IMPORT_RVA), 7);
        let load_symbol = b"CreateFileW";
        let load_symbol_offset = rva_offset(NAMED_IMPORT_RVA) + 2;
        named[load_symbol_offset..load_symbol_offset + load_symbol.len()]
            .copy_from_slice(load_symbol);

        let delay_symbol_rva = NAMED_IMPORT_RVA + 0x40;
        put_u64(
            &mut named,
            rva_offset(DELAY_THUNKS_RVA),
            u64::from(delay_symbol_rva),
        );
        put_u16(&mut named, rva_offset(delay_symbol_rva), 11);
        let delay_symbol = b"CommandLineToArgvW";
        let delay_symbol_offset = rva_offset(delay_symbol_rva) + 2;
        named[delay_symbol_offset..delay_symbol_offset + delay_symbol.len()]
            .copy_from_slice(delay_symbol);
        audit_fixture(&named).expect("well-formed named imports should pass");

        named[load_symbol_offset] = 0xff;
        let load_error = audit_fixture(&named).expect_err("non-ASCII load-time symbol must fail");
        assert!(load_error.contains("load-time import symbol"));

        named[load_symbol_offset] = b'C';
        named[delay_symbol_offset] = 0xff;
        let delay_error = audit_fixture(&named).expect_err("non-ASCII delay-load symbol must fail");
        assert!(delay_error.contains("delay-load import symbol"));
    }

    #[test]
    fn rejects_import_tables_without_null_terminators() {
        let mut load = fixture(&[b"kernel32.dll"], &[]);
        let final_descriptor_rva = SECTION_RVA + SECTION_SIZE as u32 - 20;
        let first_descriptor = load
            [rva_offset(IMPORT_DESCRIPTORS_RVA)..rva_offset(IMPORT_DESCRIPTORS_RVA) + 20]
            .to_vec();
        load[rva_offset(final_descriptor_rva)..rva_offset(final_descriptor_rva) + 20]
            .copy_from_slice(&first_descriptor);
        let import_directory = DATA_DIRECTORY_OFFSET + object::pe::IMAGE_DIRECTORY_ENTRY_IMPORT * 8;
        put_u32(&mut load, import_directory, final_descriptor_rva);
        let load_error =
            audit_fixture(&load).expect_err("unterminated import descriptors must fail");
        assert!(load_error.contains("parse load-time import descriptor 2"));

        let mut delay = fixture(&[], &[b"shell32.dll"]);
        let final_descriptor_rva = SECTION_RVA + SECTION_SIZE as u32 - 32;
        let first_descriptor = delay
            [rva_offset(DELAY_DESCRIPTORS_RVA)..rva_offset(DELAY_DESCRIPTORS_RVA) + 32]
            .to_vec();
        delay[rva_offset(final_descriptor_rva)..rva_offset(final_descriptor_rva) + 32]
            .copy_from_slice(&first_descriptor);
        let delay_directory =
            DATA_DIRECTORY_OFFSET + object::pe::IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT * 8;
        put_u32(&mut delay, delay_directory, final_descriptor_rva);
        let delay_error =
            audit_fixture(&delay).expect_err("unterminated delay descriptors must fail");
        assert!(delay_error.contains("parse delay-load import descriptor 2"));

        let final_thunk_rva = SECTION_RVA + SECTION_SIZE as u32 - 8;
        let mut load_thunks = fixture(&[b"kernel32.dll"], &[]);
        put_u32(
            &mut load_thunks,
            rva_offset(IMPORT_DESCRIPTORS_RVA),
            final_thunk_rva,
        );
        put_u32(
            &mut load_thunks,
            rva_offset(IMPORT_DESCRIPTORS_RVA) + 16,
            final_thunk_rva,
        );
        put_u64(
            &mut load_thunks,
            rva_offset(final_thunk_rva),
            object::pe::IMAGE_ORDINAL_FLAG64 | 1,
        );
        let load_thunk_error =
            audit_fixture(&load_thunks).expect_err("unterminated import thunks must fail");
        assert!(load_thunk_error.contains("parse load-time import thunk 2"));

        let mut delay_thunks = fixture(&[], &[b"shell32.dll"]);
        put_u32(
            &mut delay_thunks,
            rva_offset(DELAY_DESCRIPTORS_RVA) + 16,
            final_thunk_rva,
        );
        put_u64(
            &mut delay_thunks,
            rva_offset(final_thunk_rva),
            object::pe::IMAGE_ORDINAL_FLAG64 | 1,
        );
        let delay_thunk_error =
            audit_fixture(&delay_thunks).expect_err("unterminated delay thunks must fail");
        assert!(delay_thunk_error.contains("parse delay-load import thunk 2"));
    }

    #[test]
    fn rejects_malformed_library_names_in_both_tables() {
        let invalid_names: &[&[u8]] = &[
            b"",
            b".",
            b"..",
            b".dll",
            b"..dll",
            b"extensionless",
            b"name.exe",
            b"with space.dll",
            b"tab\tname.dll",
            b"dir/name.dll",
            b"dir\\name.dll",
            b"C:name.dll",
            b"\xffname.dll",
        ];
        for name in invalid_names {
            let load_error =
                audit_fixture(&fixture(&[*name], &[])).expect_err("invalid load name must fail");
            assert!(
                load_error.contains("load-time import descriptor"),
                "unexpected error for {name:?}: {load_error}"
            );

            let delay_error =
                audit_fixture(&fixture(&[], &[*name])).expect_err("invalid delay name must fail");
            assert!(
                delay_error.contains("delay-load import descriptor"),
                "unexpected error for {name:?}: {delay_error}"
            );
        }
    }

    #[test]
    fn rejects_non_rva_delay_descriptors_and_missing_delay_thunks() {
        let mut bad_attributes = fixture(&[], &[b"shell32.dll"]);
        put_u32(&mut bad_attributes, rva_offset(DELAY_DESCRIPTORS_RVA), 0);
        let attributes_error =
            audit_fixture(&bad_attributes).expect_err("legacy delay descriptor must fail closed");
        assert!(attributes_error.contains("requires RVA-based attributes"));

        let mut missing_thunks = fixture(&[], &[b"shell32.dll"]);
        put_u32(
            &mut missing_thunks,
            rva_offset(DELAY_DESCRIPTORS_RVA) + 16,
            0,
        );
        let thunk_error =
            audit_fixture(&missing_thunks).expect_err("missing delay thunk table must fail");
        assert!(thunk_error.contains("has no import name table"));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_artifacts() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().expect("create fixture directory");
        let target = directory.path().join("target.exe");
        let link = directory.path().join("candidate.exe");
        fs::write(&target, fixture(&[], &[])).expect("write PE fixture");
        symlink(&target, &link).expect("create fixture symlink");

        let error = audit_x86_64_pe_imports(&link).expect_err("symlink must fail");
        assert!(error.contains("regular non-symlink file"));
    }
}
