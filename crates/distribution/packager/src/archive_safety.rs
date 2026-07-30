use anyhow::{bail, Result};
use std::collections::BTreeMap;

const MAX_WINDOWS_RELATIVE_PATH_BYTES: usize = 240;
const MAX_WINDOWS_COMPONENT_BYTES: usize = 200;

/// Validate one regular-file archive path against the package verifier's
/// portable Windows extraction policy.
pub(crate) fn validate_archive_path(path: &str) -> Result<()> {
    if path.is_empty()
        || !path.is_ascii()
        || path.len() > MAX_WINDOWS_RELATIVE_PATH_BYTES
        || path.starts_with('/')
        || path.starts_with('\\')
        || path.ends_with('/')
        || path.contains('\\')
    {
        bail!("unsafe archive path {path:?}");
    }
    for component in path.split('/') {
        if component.is_empty()
            || matches!(component, "." | "..")
            || component.len() > MAX_WINDOWS_COMPONENT_BYTES
            || component.ends_with(' ')
            || component.ends_with('.')
            || component.bytes().any(|byte| {
                byte < b' '
                    || byte == 0x7f
                    || matches!(byte, b'<' | b'>' | b':' | b'"' | b'\\' | b'|' | b'?' | b'*')
            })
        {
            bail!("unsafe archive path component {component:?} in {path:?}");
        }
        let stem = component
            .split('.')
            .next()
            .unwrap_or(component)
            .to_ascii_lowercase();
        let reserved = matches!(stem.as_str(), "con" | "prn" | "aux" | "nul")
            || stem.strip_prefix("com").is_some_and(|suffix| {
                matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
            })
            || stem.strip_prefix("lpt").is_some_and(|suffix| {
                matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
            });
        if reserved {
            bail!("reserved Windows device component {component:?} in archive path {path:?}");
        }
    }
    Ok(())
}

/// Admit one regular-file archive path into a case-insensitive namespace,
/// rejecting duplicates and file/descendant conflicts.
pub(crate) fn insert_archive_path(
    casefolded: &mut BTreeMap<String, String>,
    path: &str,
) -> Result<()> {
    let folded = path.to_ascii_lowercase();
    if let Some(existing) = casefolded.get(&folded) {
        bail!("duplicate or case-colliding archive paths {existing:?} and {path:?}");
    }
    for (index, byte) in folded.bytes().enumerate() {
        if byte == b'/' {
            let ancestor = &folded[..index];
            if let Some(existing) = casefolded.get(ancestor) {
                bail!("archive file {existing:?} conflicts with descendant {path:?}");
            }
        }
    }
    let descendant_prefix = format!("{folded}/");
    if let Some((candidate, existing)) = casefolded.range(descendant_prefix.clone()..).next() {
        if candidate.starts_with(&descendant_prefix) {
            bail!("archive file {path:?} conflicts with descendant {existing:?}");
        }
    }
    casefolded.insert(folded, path.to_owned());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn portable_archive_namespace_rejects_aliases_and_ancestor_conflicts() {
        for path in [
            "",
            "../escape",
            "/absolute",
            "workspace/a\\b",
            "workspace/CON.txt",
            "workspace/trailing.",
            "workspace/trailing ",
        ] {
            assert!(validate_archive_path(path).is_err(), "{path:?}");
        }
        validate_archive_path("workspace/crates/example/src/lib.rs").unwrap();

        let mut paths = BTreeMap::new();
        insert_archive_path(&mut paths, "workspace/file").unwrap();
        assert!(insert_archive_path(&mut paths, "WORKSPACE/FILE").is_err());
        assert!(insert_archive_path(&mut paths, "workspace/file/child").is_err());

        let mut descendants = BTreeMap::new();
        insert_archive_path(&mut descendants, "workspace/file/child").unwrap();
        assert!(insert_archive_path(&mut descendants, "workspace/file").is_err());
    }
}
