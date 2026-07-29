use std::collections::{BTreeSet, HashMap};

use anyhow::{anyhow, Result};

use crate::ops::profiles::TitleBlockFingerprint;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DxfPatchResult {
    pub content: String,
    pub target_inserts: usize,
    pub attributes_written: usize,
}

#[derive(Debug)]
struct InsertAttrib {
    tag: String,
    value_line_index: Option<usize>,
}

#[derive(Debug)]
struct InsertEntity {
    block_name: String,
    tags: Vec<String>,
    attribs: Vec<InsertAttrib>,
}

/// Patch ATTRIB values in an ASCII DXF file.
///
/// For every INSERT whose block name and sorted ATTRIB tag set match
/// `fingerprint`, any ATTRIB whose tag is a key in `replacements`
/// (case-insensitive) has its value replaced. All other content is passed
/// through byte-for-byte.
///
/// Line endings (LF or CRLF) are detected from the input and preserved.
/// Returns `Err` if the content appears to be binary DXF.
pub fn patch_dxf_attributes(
    content: &str,
    fingerprint: &TitleBlockFingerprint,
    replacements: &HashMap<String, String>,
) -> Result<DxfPatchResult> {
    if content.starts_with("AutoCAD Binary DXF") {
        return Err(anyhow!(
            "binary DXF is not supported; save as ASCII DXF in AutoCAD \
             or use the accoreconsole path for DWG files"
        ));
    }

    if replacements.is_empty() {
        return Ok(DxfPatchResult {
            content: content.to_string(),
            target_inserts: 0,
            attributes_written: 0,
        });
    }

    // Detect line ending style
    let crlf = content.contains("\r\n");
    let sep = if crlf { "\r\n" } else { "\n" };

    // Split preserving the style (CRLF split leaves no trailing \r)
    let lines: Vec<&str> = if crlf {
        content.split("\r\n").collect()
    } else {
        content.split('\n').collect()
    };

    // If content ends with the separator, split produces a trailing empty element.
    // We track this so we can restore it on output.
    let trailing = content.ends_with(sep);
    let n = if trailing && !lines.is_empty() {
        lines.len() - 1
    } else {
        lines.len()
    };

    let upper_reps: HashMap<String, &str> = replacements
        .iter()
        .map(|(k, v)| (normalize(k), v.as_str()))
        .collect();

    // Exclude split's synthetic trailing empty element; append exactly one
    // separator below when the original content ended with one.
    let mut out: Vec<String> = lines[..n].iter().map(|line| line.to_string()).collect();
    let inserts = collect_inserts(&lines, n);
    let matching: Vec<_> = inserts
        .iter()
        .filter(|insert| {
            insert.block_name == fingerprint.block_name && insert.tags == fingerprint.attribute_tags
        })
        .collect();

    if matching.is_empty() {
        return Err(anyhow!(
            "no matching title-block INSERT for fingerprint block '{}' tags {:?}",
            fingerprint.block_name,
            fingerprint.attribute_tags
        ));
    }

    for insert in &matching {
        for tag in upper_reps.keys() {
            let occurrences: Vec<_> = insert
                .attribs
                .iter()
                .filter(|attrib| attrib.tag == *tag && attrib.value_line_index.is_some())
                .collect();
            if occurrences.is_empty() {
                return Err(anyhow!(
                    "requested tag '{tag}' is missing from matching title-block INSERT '{}'",
                    insert.block_name
                ));
            }
            if occurrences.len() > 1 {
                return Err(anyhow!(
                    "requested tag '{tag}' appears {} times in matching title-block INSERT '{}'",
                    occurrences.len(),
                    insert.block_name
                ));
            }
        }
    }

    let mut attributes_written = 0;
    for insert in &matching {
        for attrib in &insert.attribs {
            if let Some(&new_val) = upper_reps.get(attrib.tag.as_str()) {
                let Some(value_line_index) = attrib.value_line_index else {
                    continue;
                };
                out[value_line_index] = new_val.to_string();
                attributes_written += 1;
            }
        }
    }

    let expected_writes = matching.len() * upper_reps.len();
    if attributes_written != expected_writes {
        return Err(anyhow!(
            "partial write: expected {expected_writes} attribute writes across {} target INSERTs, wrote {attributes_written}",
            matching.len()
        ));
    }

    let mut result = out.join(sep);
    if trailing {
        result.push_str(sep);
    }
    Ok(DxfPatchResult {
        content: result,
        target_inserts: matching.len(),
        attributes_written,
    })
}

fn collect_inserts(lines: &[&str], n: usize) -> Vec<InsertEntity> {
    let mut inserts = Vec::new();
    let mut i = 0_usize;

    while i + 1 < n {
        let gc = lines[i].trim();
        let val = lines[i + 1].trim();
        if gc == "0" && val == "INSERT" {
            let (insert, next_i) = parse_insert(lines, n, i + 2);
            inserts.push(insert);
            i = next_i;
        } else {
            i += 2;
        }
    }

    inserts
}

fn parse_insert(lines: &[&str], n: usize, mut i: usize) -> (InsertEntity, usize) {
    let mut block_name = String::new();
    let mut attribs = Vec::new();

    while i + 1 < n {
        let gc = lines[i].trim();
        let val = lines[i + 1].trim();
        if gc == "0" {
            match val {
                "ATTRIB" => {
                    let (attrib, next_i) = parse_attrib(lines, n, i + 2);
                    if let Some(attrib) = attrib {
                        attribs.push(attrib);
                    }
                    i = next_i;
                }
                "SEQEND" => return (build_insert(block_name, attribs), i + 2),
                "INSERT" => return (build_insert(block_name, attribs), i),
                _ => return (build_insert(block_name, attribs), i),
            }
        } else {
            if gc == "2" && block_name.is_empty() {
                block_name = normalize(val);
            }
            i += 2;
        }
    }

    (build_insert(block_name, attribs), i)
}

fn parse_attrib(lines: &[&str], n: usize, mut i: usize) -> (Option<InsertAttrib>, usize) {
    let mut tag = None;
    let mut value_line_index = None;

    while i + 1 < n {
        let gc = lines[i].trim();
        let val = lines[i + 1].trim();
        if gc == "0" {
            break;
        }
        if gc == "2" && tag.is_none() {
            tag = Some(normalize(val));
        } else if gc == "1" {
            value_line_index = Some(i + 1);
        }
        i += 2;
    }

    (
        tag.map(|tag| InsertAttrib {
            tag,
            value_line_index,
        }),
        i,
    )
}

fn build_insert(block_name: String, attribs: Vec<InsertAttrib>) -> InsertEntity {
    let tags = attribs
        .iter()
        .map(|attrib| attrib.tag.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    InsertEntity {
        block_name,
        tags,
        attribs,
    }
}

fn normalize(value: &str) -> String {
    value.trim().to_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::profiles::TitleBlockFingerprint;
    use std::collections::HashMap;

    /// Minimal valid ASCII DXF with one INSERT+ATTRIB sequence.
    fn minimal_dxf(block: &str, tag: &str, value: &str) -> String {
        format!(
            "  0\nSECTION\n  2\nENTITIES\n  \
             0\nINSERT\n  2\n{block}\n 66\n     1\n  \
             0\nATTRIB\n  2\n{tag}\n  1\n{value}\n  \
             0\nSEQEND\n  0\nENDSEC\n  0\nEOF\n"
        )
    }

    fn reps(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn fingerprint(block: &str, tags: &[&str]) -> TitleBlockFingerprint {
        TitleBlockFingerprint::new(block, tags.iter().copied())
    }

    fn insert_dxf(block: &str, attrs: &[(&str, &str)]) -> String {
        let mut dxf = format!("  0\nINSERT\n  2\n{block}\n 66\n     1\n");
        for (tag, value) in attrs {
            dxf.push_str(&format!("  0\nATTRIB\n  2\n{tag}\n  1\n{value}\n"));
        }
        dxf.push_str("  0\nSEQEND\n");
        dxf
    }

    fn dxf_with_inserts(inserts: &[String]) -> String {
        let mut dxf = "  0\nSECTION\n  2\nENTITIES\n".to_string();
        for insert in inserts {
            dxf.push_str(insert);
        }
        dxf.push_str("  0\nENDSEC\n  0\nEOF\n");
        dxf
    }

    #[test]
    fn patch_known_attribute() {
        let dxf = minimal_dxf("AUTOCAD_MCP_GENERIC", "REVISION", "P01");
        let patched = patch_dxf_attributes(
            &dxf,
            &fingerprint("AUTOCAD_MCP_GENERIC", &["REVISION"]),
            &reps(&[("REVISION", "P02")]),
        )
        .unwrap();
        assert_eq!(patched.target_inserts, 1);
        assert_eq!(patched.attributes_written, 1);
        assert_eq!(patched.content, dxf.replace("P01", "P02"));
        assert!(
            patched.content.contains("P02"),
            "new value missing:\n{}",
            patched.content
        );
        assert!(
            !patched.content.contains("P01"),
            "old value still present:\n{}",
            patched.content
        );
    }

    #[test]
    fn non_matching_block_returns_error() {
        let dxf = minimal_dxf("OTHER_BLOCK", "REVISION", "P01");
        let err = patch_dxf_attributes(
            &dxf,
            &fingerprint("AUTOCAD_MCP_GENERIC", &["REVISION"]),
            &reps(&[("REVISION", "P02")]),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("no matching title-block INSERT"),
            "got: {err}"
        );
    }

    #[test]
    fn replacement_tag_missing_from_target_returns_error() {
        let dxf = minimal_dxf("AUTOCAD_MCP_GENERIC", "SHEET", "3");
        let err = patch_dxf_attributes(
            &dxf,
            &fingerprint("AUTOCAD_MCP_GENERIC", &["SHEET"]),
            &reps(&[("REVISION", "P02")]),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("requested tag 'REVISION'"),
            "got: {err}"
        );
    }

    #[test]
    fn binary_dxf_returns_err() {
        let result = patch_dxf_attributes(
            "AutoCAD Binary DXF\r\n",
            &fingerprint("X", &[]),
            &HashMap::new(),
        );
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string().to_lowercase();
        assert!(msg.contains("binary"), "got: {msg}");
    }

    #[test]
    fn empty_replacements_returns_content_unchanged() {
        let dxf = minimal_dxf("AUTOCAD_MCP_GENERIC", "REVISION", "P01");
        let patched = patch_dxf_attributes(
            &dxf,
            &fingerprint("AUTOCAD_MCP_GENERIC", &["REVISION"]),
            &HashMap::new(),
        )
        .unwrap();
        assert_eq!(patched.content, dxf);
        assert_eq!(patched.target_inserts, 0);
        assert_eq!(patched.attributes_written, 0);
    }

    #[test]
    fn structural_content_outside_target_entity_unchanged() {
        let dxf = minimal_dxf("AUTOCAD_MCP_GENERIC", "REVISION", "P01");
        let patched = patch_dxf_attributes(
            &dxf,
            &fingerprint("AUTOCAD_MCP_GENERIC", &["REVISION"]),
            &reps(&[("REVISION", "P02")]),
        )
        .unwrap();
        assert!(
            patched.content.contains("SECTION"),
            "section header preserved"
        );
        assert!(
            patched.content.contains("ENTITIES"),
            "entities section preserved"
        );
        assert!(patched.content.contains("EOF"), "EOF preserved");
        assert!(patched.content.contains("SEQEND"), "SEQEND preserved");
    }

    #[test]
    fn patch_preserves_crlf_line_endings() {
        let dxf = minimal_dxf("AUTOCAD_MCP_GENERIC", "REVISION", "P01").replace('\n', "\r\n");
        let patched = patch_dxf_attributes(
            &dxf,
            &fingerprint("AUTOCAD_MCP_GENERIC", &["REVISION"]),
            &reps(&[("REVISION", "P02")]),
        )
        .unwrap();
        assert_eq!(patched.content, dxf.replace("P01", "P02"));
        assert!(patched.content.contains("\r\n"), "CRLF must be preserved");
        assert!(patched.content.contains("P02"), "patch applied");
        assert!(!patched.content.contains("P01"), "old value gone");
    }

    #[test]
    fn patch_case_insensitive_block_name() {
        let dxf = minimal_dxf("autocad_mcp_generic", "REVISION", "P01");
        let patched = patch_dxf_attributes(
            &dxf,
            &fingerprint("AUTOCAD_MCP_GENERIC", &["REVISION"]),
            &reps(&[("REVISION", "P02")]),
        )
        .unwrap();
        assert!(
            patched.content.contains("P02"),
            "block name match should be case-insensitive:\n{}",
            patched.content
        );
    }

    #[test]
    fn patch_case_insensitive_tag_name() {
        let dxf = minimal_dxf("AUTOCAD_MCP_GENERIC", "revision", "P01");
        let patched = patch_dxf_attributes(
            &dxf,
            &fingerprint("AUTOCAD_MCP_GENERIC", &["REVISION"]),
            &reps(&[("REVISION", "P02")]),
        )
        .unwrap();
        assert!(
            patched.content.contains("P02"),
            "tag name match should be case-insensitive:\n{}",
            patched.content
        );
    }

    #[test]
    fn multiple_fields_all_patched() {
        // Two ATTRIBs in sequence on the same INSERT
        let dxf = concat!(
            "  0\nSECTION\n  2\nENTITIES\n",
            "  0\nINSERT\n  2\nAUTOCAD_MCP_GENERIC\n 66\n     1\n",
            "  0\nATTRIB\n  2\nREVISION\n  1\nP01\n",
            "  0\nATTRIB\n  2\nDRAWING_NUMBER\n  1\nOLD-001\n",
            "  0\nSEQEND\n  0\nENDSEC\n  0\nEOF\n"
        );
        let patched = patch_dxf_attributes(
            dxf,
            &fingerprint("AUTOCAD_MCP_GENERIC", &["REVISION", "DRAWING_NUMBER"]),
            &reps(&[("REVISION", "P02"), ("DRAWING_NUMBER", "NEW-001")]),
        )
        .unwrap();
        assert_eq!(patched.target_inserts, 1);
        assert_eq!(patched.attributes_written, 2);
        assert!(patched.content.contains("P02"));
        assert!(patched.content.contains("NEW-001"));
        assert!(!patched.content.contains("P01"));
        assert!(!patched.content.contains("OLD-001"));
    }

    #[test]
    fn patch_only_exact_fingerprint_match() {
        let dxf = dxf_with_inserts(&[
            insert_dxf("AUTOCAD_MCP_GENERIC", &[("REVISION", "P01")]),
            insert_dxf(
                "AUTOCAD_MCP_GENERIC",
                &[("REVISION", "P01"), ("DRAWING_NUMBER", "A-001")],
            ),
        ]);
        let patched = patch_dxf_attributes(
            &dxf,
            &fingerprint("AUTOCAD_MCP_GENERIC", &["REVISION", "DRAWING_NUMBER"]),
            &reps(&[("REVISION", "P02")]),
        )
        .unwrap();

        assert_eq!(patched.target_inserts, 1);
        assert_eq!(patched.attributes_written, 1);
        assert!(patched.content.contains("A-001"));
        assert_eq!(patched.content.matches("P02").count(), 1);
        assert_eq!(patched.content.matches("P01").count(), 1);
    }

    #[test]
    fn patch_errors_when_requested_tag_missing_from_matching_target() {
        let dxf = dxf_with_inserts(&[insert_dxf(
            "AUTOCAD_MCP_GENERIC",
            &[("REVISION", "P01"), ("DRAWING_NUMBER", "A-001")],
        )]);
        let err = patch_dxf_attributes(
            &dxf,
            &fingerprint("AUTOCAD_MCP_GENERIC", &["REVISION", "DRAWING_NUMBER"]),
            &reps(&[("SHEET", "1")]),
        )
        .unwrap_err();

        assert!(
            err.to_string().contains("requested tag 'SHEET'"),
            "got: {err}"
        );
    }

    #[test]
    fn patch_errors_when_no_exact_fingerprint_target_exists() {
        let dxf = dxf_with_inserts(&[insert_dxf("AUTOCAD_MCP_GENERIC", &[("REVISION", "P01")])]);
        let err = patch_dxf_attributes(
            &dxf,
            &fingerprint("AUTOCAD_MCP_GENERIC", &["REVISION", "DRAWING_NUMBER"]),
            &reps(&[("REVISION", "P02")]),
        )
        .unwrap_err();

        assert!(
            err.to_string().contains("no matching title-block INSERT"),
            "got: {err}"
        );
    }
}
