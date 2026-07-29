use acadrust::{CadDocument, DwgReader, DxfError, DxfReader};
use std::io::{Error, ErrorKind, Read};
use std::path::Path;

pub fn open_drawing(path: &Path) -> Result<CadDocument, DxfError> {
    match path.extension().and_then(|e| e.to_str()) {
        Some(extension) if extension.eq_ignore_ascii_case("dxf") => {
            DxfReader::from_file(path)?.read()
        }
        Some(extension) if extension.eq_ignore_ascii_case("dwg") => {
            let mut reader = DwgReader::from_file(path)?;
            reader.read()
        }
        Some(ext) => Err(DxfError::InvalidFormat(format!(
            "unsupported extension {ext:?}; expected .dxf or .dwg"
        ))),
        None => Err(DxfError::InvalidFormat(
            "file has no extension; expected .dxf or .dwg".to_string(),
        )),
    }
}

/// Read the persisted six-byte DWG family marker without launching AutoCAD.
///
/// Engine-backed mutations use this before activation so the selected
/// catalogue row must explicitly admit the drawing format.
pub fn inspect_dwg_version(path: &Path) -> std::io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut version = [0_u8; 6];
    file.read_exact(&mut version)?;
    if &version[..2] != b"AC" || !version[2..].iter().all(u8::is_ascii_digit) {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "DWG header must begin with one exact ACnnnn version marker: {}",
                path.display()
            ),
        ));
    }
    Ok(std::str::from_utf8(&version)
        .expect("validated ASCII DWG version")
        .to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use acadrust::{CadDocument, DxfWriter};

    #[test]
    fn open_dxf_round_trip() {
        let doc = CadDocument::new();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("drawing.dxf");
        DxfWriter::new(&doc).write_to_file(&path).unwrap();
        let result = open_drawing(&path);
        assert!(result.is_ok());
    }

    #[test]
    fn open_dwg_round_trip() {
        let doc = CadDocument::new();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("drawing.dwg");
        acadrust::DwgWriter::write_to_file(&path, &doc).unwrap();
        let result = open_drawing(&path);
        assert!(result.is_ok());
    }

    #[test]
    fn open_drawing_accepts_mixed_case_extensions() {
        let doc = CadDocument::new();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("drawing.DwG");
        acadrust::DwgWriter::write_to_file(&path, &doc).unwrap();
        let result = open_drawing(&path);
        assert!(result.is_ok());
    }

    #[test]
    fn open_unsupported_extension_errors() {
        let result = open_drawing(Path::new("drawing.xyz"));
        assert!(result.is_err());
    }

    #[test]
    fn open_no_extension_errors() {
        let result = open_drawing(Path::new("drawing"));
        assert!(result.is_err());
    }

    #[test]
    fn inspect_dwg_version_reads_and_validates_the_persisted_marker() {
        let directory = tempfile::tempdir().unwrap();
        let valid = directory.path().join("valid.dwg");
        std::fs::write(&valid, b"AC1032payload").unwrap();
        assert_eq!(inspect_dwg_version(&valid).unwrap(), "AC1032");

        let invalid = directory.path().join("invalid.dwg");
        std::fs::write(&invalid, b"AC10x2payload").unwrap();
        assert_eq!(
            inspect_dwg_version(&invalid).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
    }
}
