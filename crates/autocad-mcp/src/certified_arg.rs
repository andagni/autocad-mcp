use std::collections::BTreeSet;

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const CERTIFIED_ARG_POLICY_SCHEMA_VERSION: u32 = 1;
pub const PUBLIC_DEVELOPMENT_ARG_POLICY_ID: &str = "autocad-mcp-public-development-v1";
pub const XREF_ISOLATED_PROFILE_TOKEN_ENV: &str = "AUTOCAD_MCP_XREF_PROFILE_TOKEN";
pub const XREF_PROFILE_LIFECYCLE_COORDINATION_ENV: &str =
    "AUTOCAD_MCP_XREF_PROFILE_LIFECYCLE_COORDINATION";

const HKCU_AUTOCAD_PREFIX: [&str; 4] = ["HKEY_CURRENT_USER", "Software", "Autodesk", "AutoCAD"];
const DEDICATED_PROFILE_PREFIX: &str = "AutoCAD-MCP ";
const XREF_ISOLATED_PROFILE_PREFIX: &str = "AutoCAD-MCP XREF ";
const XREF_ISOLATED_PROFILE_TOKEN_LEN: usize = 32;

/// Closed purpose classes for exact-value ARG policies.
///
/// A development fixture proves parsing and build plumbing. A Preview
/// candidate activation policy admits one package-owned evaluation profile.
/// Neither purpose is a certification result, Release qualification, or
/// distribution approval.
#[derive(Debug, Clone, Copy, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CertifiedArgPolicyPurpose {
    DevelopmentFixture,
    PreviewCandidateActivation,
}

/// Registry value forms intentionally supported by closed public policies.
///
/// Additional `.reg`/ARG forms require an explicit schema and parser review;
/// they must not be accepted through a generic raw-value escape hatch.
#[derive(Debug, Clone, Copy, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CertifiedArgValueType {
    String,
    Dword,
}

#[derive(Debug, Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertifiedArgValue {
    /// Empty means the profile root itself. Otherwise this is a normalized
    /// backslash-separated key path relative to that root.
    pub relative_key: String,
    pub value_name: String,
    #[serde(rename = "type")]
    pub value_type: CertifiedArgValueType,
    /// Decoded string data or exactly eight lowercase hexadecimal DWORD
    /// digits.
    pub value: String,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertifiedArgPolicy {
    pub schema_version: u32,
    pub policy_id: String,
    pub purpose: CertifiedArgPolicyPurpose,
    pub profile_root: String,
    pub profile_name: String,
    pub values: Vec<CertifiedArgValue>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertifiedArgInspection {
    pub schema_version: u32,
    pub policy_id: String,
    pub purpose: CertifiedArgPolicyPurpose,
    pub profile_root: String,
    pub profile_name: String,
    pub raw_arg_sha256: String,
    pub policy_sha256: String,
    pub values: Vec<CertifiedArgValue>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CertifiedArgProfileBinding {
    pub profile_root: String,
    pub hkcu_subkey: String,
    pub hkcu_parent_subkey: String,
    pub profile_name: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DerivedXrefCertifiedArg {
    pub bytes: Vec<u8>,
    pub binding: CertifiedArgProfileBinding,
}

/// Binds every registry header in a digest-validated ARG to one dedicated
/// AutoCAD profile root. Callers still own the exact-byte policy and digest
/// checks; this function supplies the narrower registry-lifecycle identity.
pub fn certified_arg_profile_binding(arg_bytes: &[u8]) -> Result<CertifiedArgProfileBinding> {
    let text = decode_arg(arg_bytes)?;
    let mut common_root: Option<Vec<String>> = None;
    let mut header_count = 0_usize;

    for (line_index, line) in text.lines().enumerate() {
        let line = line.trim();
        if !line.starts_with('[') {
            continue;
        }
        if !line.ends_with(']') || line.len() < 3 {
            bail!(
                "certified ARG registry header on line {} is malformed",
                line_index + 1
            );
        }
        let header = &line[1..line.len() - 1];
        if header.starts_with('-')
            || header.trim() != header
            || header.contains(['[', ']'])
            || header.chars().any(char::is_control)
        {
            bail!(
                "certified ARG registry header on line {} is not an import header",
                line_index + 1
            );
        }
        let components = header.split('\\').collect::<Vec<_>>();
        if components.iter().any(|component| component.is_empty())
            || components.len() < HKCU_AUTOCAD_PREFIX.len() + 4
            || !components[..HKCU_AUTOCAD_PREFIX.len()]
                .iter()
                .zip(HKCU_AUTOCAD_PREFIX)
                .all(|(actual, expected)| actual.eq_ignore_ascii_case(expected))
        {
            bail!(
                "certified ARG registry header on line {} is not beneath HKEY_CURRENT_USER\\Software\\Autodesk\\AutoCAD",
                line_index + 1
            );
        }
        let profiles_index = components
            .iter()
            .enumerate()
            .skip(HKCU_AUTOCAD_PREFIX.len())
            .find_map(|(index, component)| {
                component.eq_ignore_ascii_case("Profiles").then_some(index)
            })
            .ok_or_else(|| {
                anyhow!(
                    "certified ARG registry header on line {} has no Profiles component",
                    line_index + 1
                )
            })?;
        let profile_index = profiles_index + 1;
        let profile_name = components.get(profile_index).ok_or_else(|| {
            anyhow!(
                "certified ARG registry header on line {} does not name a profile",
                line_index + 1
            )
        })?;
        if profile_name.is_empty()
            || !profile_name.starts_with(DEDICATED_PROFILE_PREFIX)
            || profile_name.contains(['\\', '/', '[', ']'])
            || profile_name.chars().any(char::is_control)
        {
            bail!(
                "certified ARG registry header on line {} does not name one dedicated AutoCAD-MCP profile",
                line_index + 1
            );
        }
        let root = components[..=profile_index]
            .iter()
            .map(|component| (*component).to_string())
            .collect::<Vec<_>>();
        if let Some(expected) = &common_root {
            if &root != expected {
                bail!(
                    "certified ARG registry header on line {} does not use the exact common profile-root spelling",
                    line_index + 1
                );
            }
        } else {
            common_root = Some(root.clone());
        }
        if components.len() < root.len()
            || !components
                .iter()
                .zip(&root)
                .all(|(left, right)| *left == right)
        {
            bail!(
                "certified ARG registry header on line {} escapes its profile root",
                line_index + 1
            );
        }
        header_count += 1;
    }

    let root = common_root
        .filter(|_| header_count != 0)
        .ok_or_else(|| anyhow!("certified ARG contains no registry profile headers"))?;
    let profile_name = root
        .last()
        .cloned()
        .ok_or_else(|| anyhow!("certified ARG profile root is empty"))?;
    Ok(CertifiedArgProfileBinding {
        profile_root: root.join("\\"),
        hkcu_subkey: root[1..].join("\\"),
        hkcu_parent_subkey: root[1..root.len() - 1].join("\\"),
        profile_name,
    })
}

pub fn validate_xref_isolated_profile_token(token: &str) -> Result<()> {
    if token.len() != XREF_ISOLATED_PROFILE_TOKEN_LEN
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!(
            "XREF isolated-profile token must contain exactly {XREF_ISOLATED_PROFILE_TOKEN_LEN} lowercase hexadecimal digits"
        );
    }
    Ok(())
}

pub fn xref_isolated_profile_name(token: &str) -> Result<String> {
    validate_xref_isolated_profile_token(token)?;
    Ok(format!("{XREF_ISOLATED_PROFILE_PREFIX}{token}"))
}

/// Rewrites only registry-header roots in an already digest-validated ARG.
/// Value names, value bytes, ordering, line endings, and source encoding remain
/// unchanged, while every launch receives a separately owned profile subtree.
pub fn derive_xref_certified_arg(arg_bytes: &[u8], token: &str) -> Result<DerivedXrefCertifiedArg> {
    let source = certified_arg_profile_binding(arg_bytes)?;
    let profile_name = xref_isolated_profile_name(token)?;
    let profile_root = format!(
        "HKEY_CURRENT_USER\\{}\\{}",
        source.hkcu_parent_subkey, profile_name
    );
    let (text, encoding) = decode_arg_with_encoding(arg_bytes)?;

    let mut replacements = 0_usize;
    for (index, _) in text.match_indices(&source.profile_root) {
        let prefix = &text[..index];
        let suffix = &text[index + source.profile_root.len()..];
        if !prefix.ends_with('[') || !(suffix.starts_with(']') || suffix.starts_with('\\')) {
            bail!(
                "certified ARG profile root occurs outside an exact registry header; unique derivation is unsafe"
            );
        }
        replacements += 1;
    }
    if replacements == 0 {
        bail!("certified ARG unique-profile derivation found no registry headers");
    }

    let derived_text = text.replace(&source.profile_root, &profile_root);
    let bytes = encode_arg(&derived_text, encoding);
    let binding = certified_arg_profile_binding(&bytes)?;
    if binding.profile_root != profile_root || binding.profile_name != profile_name {
        bail!("derived XREF ARG did not bind to the requested unique profile root");
    }
    Ok(DerivedXrefCertifiedArg { bytes, binding })
}

/// Parses every nonblank ARG line and requires its complete registry inventory
/// to equal the supplied closed policy.
///
/// Hashes cover the exact caller-supplied bytes. Text decoding is used only for
/// validation and never changes the bytes whose digest is reported.
pub fn validate_distribution_safe_arg(
    arg_bytes: &[u8],
    policy_json_bytes: &[u8],
) -> Result<CertifiedArgInspection> {
    if arg_bytes.is_empty() {
        bail!("certified ARG must not be empty");
    }
    let policy: CertifiedArgPolicy = serde_json::from_slice(policy_json_bytes)
        .map_err(|error| anyhow!("invalid certified ARG policy JSON: {error}"))?;
    validate_policy(&policy)?;

    let parsed = parse_arg(arg_bytes, &policy)?;
    if parsed.values != policy.values {
        let expected = policy.values.iter().cloned().collect::<BTreeSet<_>>();
        let actual = parsed.values.iter().cloned().collect::<BTreeSet<_>>();
        let missing = expected.difference(&actual).collect::<Vec<_>>();
        let extra = actual.difference(&expected).collect::<Vec<_>>();
        bail!(
            "certified ARG value inventory does not equal the exact policy; missing={missing:?}, extra={extra:?}"
        );
    }

    Ok(CertifiedArgInspection {
        schema_version: CERTIFIED_ARG_POLICY_SCHEMA_VERSION,
        policy_id: policy.policy_id,
        purpose: policy.purpose,
        profile_root: policy.profile_root,
        profile_name: policy.profile_name,
        raw_arg_sha256: lowercase_sha256(arg_bytes),
        policy_sha256: lowercase_sha256(policy_json_bytes),
        values: parsed.values,
    })
}

fn lowercase_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn validate_policy(policy: &CertifiedArgPolicy) -> Result<()> {
    if policy.schema_version != CERTIFIED_ARG_POLICY_SCHEMA_VERSION {
        bail!(
            "certified ARG policy schema_version {} is unsupported; expected {}",
            policy.schema_version,
            CERTIFIED_ARG_POLICY_SCHEMA_VERSION
        );
    }
    validate_policy_id(&policy.policy_id)?;
    validate_profile_root(&policy.profile_root, &policy.profile_name)?;
    if policy.values.is_empty() {
        bail!("certified ARG policy values must not be empty");
    }

    let mut previous_sort_key: Option<(String, String)> = None;
    let mut identities = BTreeSet::new();
    for (index, value) in policy.values.iter().enumerate() {
        validate_relative_key(&value.relative_key).map_err(|error| {
            anyhow!("certified ARG policy values[{index}] relative_key: {error}")
        })?;
        validate_value_name(&value.value_name)
            .map_err(|error| anyhow!("certified ARG policy values[{index}] value_name: {error}"))?;
        validate_policy_value(value)
            .map_err(|error| anyhow!("certified ARG policy values[{index}] value: {error}"))?;

        let sort_key = (
            value.relative_key.to_ascii_lowercase(),
            value.value_name.to_ascii_lowercase(),
        );
        if previous_sort_key
            .as_ref()
            .is_some_and(|previous| previous >= &sort_key)
        {
            bail!(
                "certified ARG policy values must be sorted and unique by case-insensitive relative_key/value_name"
            );
        }
        previous_sort_key = Some(sort_key.clone());
        if !identities.insert(sort_key) {
            bail!("certified ARG policy has a duplicate case-insensitive relative_key/value_name");
        }
    }
    Ok(())
}

pub fn validate_policy_id(policy_id: &str) -> Result<()> {
    if policy_id.is_empty()
        || policy_id != policy_id.trim()
        || !policy_id.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
    {
        bail!(
            "certified ARG policy_id must be nonempty canonical lowercase ASCII with only '-' or '_' separators"
        );
    }
    Ok(())
}

fn validate_profile_root(profile_root: &str, profile_name: &str) -> Result<()> {
    if profile_root.is_empty()
        || profile_root != profile_root.trim()
        || profile_root.contains('/')
        || profile_root.contains(['[', ']'])
        || profile_root.chars().any(char::is_control)
    {
        bail!("certified ARG policy profile_root is not a canonical registry path");
    }
    if profile_name.is_empty()
        || profile_name != profile_name.trim()
        || !profile_name.starts_with(DEDICATED_PROFILE_PREFIX)
        || profile_name.contains(['\\', '/', '[', ']'])
        || profile_name.chars().any(char::is_control)
    {
        bail!("certified ARG policy profile_name must be one dedicated canonical AutoCAD-MCP name");
    }

    let components = profile_root.split('\\').collect::<Vec<_>>();
    if components.iter().any(|component| component.is_empty())
        || components
            .iter()
            .any(|component| matches!(*component, "." | ".."))
        || components.len() < HKCU_AUTOCAD_PREFIX.len() + 4
        || components[..HKCU_AUTOCAD_PREFIX.len()] != HKCU_AUTOCAD_PREFIX
        || components[components.len() - 2] != "Profiles"
        || components[components.len() - 1] != profile_name
        || components[HKCU_AUTOCAD_PREFIX.len()..components.len() - 2].contains(&"Profiles")
    {
        bail!(
            "certified ARG policy profile_root must name the exact dedicated profile below HKEY_CURRENT_USER\\Software\\Autodesk\\AutoCAD\\...\\Profiles"
        );
    }
    Ok(())
}

fn validate_relative_key(relative_key: &str) -> Result<()> {
    if relative_key.is_empty() {
        return Ok(());
    }
    if relative_key.contains('/')
        || relative_key.starts_with('\\')
        || relative_key.ends_with('\\')
        || relative_key.contains(['[', ']'])
        || relative_key.chars().any(char::is_control)
        || relative_key
            .split('\\')
            .any(|component| matches!(component, "." | "..") || component.is_empty())
    {
        bail!("relative registry key is not normalized");
    }
    Ok(())
}

fn validate_value_name(value_name: &str) -> Result<()> {
    if value_name.is_empty()
        || value_name != value_name.trim()
        || value_name.chars().any(char::is_control)
    {
        bail!("registry value_name must be nonempty, trimmed, and free of control characters");
    }
    Ok(())
}

fn validate_policy_value(value: &CertifiedArgValue) -> Result<()> {
    match value.value_type {
        CertifiedArgValueType::String => {
            if value.value.contains('\0') || value.value.chars().any(char::is_control) {
                bail!("string value contains a control character");
            }
            if value.value.as_bytes().windows(3).any(|window| {
                window[0].is_ascii_alphabetic()
                    && window[1] == b':'
                    && matches!(window[2], b'\\' | b'/')
            }) || value.value.contains(['\\', '/', '%', '$'])
            {
                bail!(
                    "public development string values must not contain paths or environment expansion syntax"
                );
            }
        }
        CertifiedArgValueType::Dword => {
            if value.value.len() != 8
                || !value
                    .value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            {
                bail!("DWORD value must be exactly eight lowercase hexadecimal digits");
            }
        }
    }
    Ok(())
}

#[derive(Debug)]
struct ParsedArg {
    values: Vec<CertifiedArgValue>,
}

fn parse_arg(bytes: &[u8], policy: &CertifiedArgPolicy) -> Result<ParsedArg> {
    let text = decode_arg(bytes)?;
    let expected_headers = policy
        .values
        .iter()
        .map(|value| header_for_relative_key(&policy.profile_root, &value.relative_key))
        .collect::<BTreeSet<_>>();
    let mut observed_headers = BTreeSet::new();
    let mut observed_header_identities = BTreeSet::new();
    let mut observed_value_identities = BTreeSet::new();
    let mut values = Vec::new();
    let mut current_relative_key: Option<String> = None;
    let mut saw_signature = false;

    for (line_index, raw_line) in text.lines().enumerate() {
        let line_number = line_index + 1;
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if line.trim().is_empty() {
            continue;
        }
        if line != line.trim() {
            bail!("certified ARG line {line_number} has leading or trailing whitespace");
        }
        if line.starts_with(';') || line.starts_with('#') {
            bail!("certified ARG line {line_number} is a comment; comments are not admitted");
        }
        if line.ends_with('\\') {
            bail!("certified ARG line {line_number} uses an unsupported continuation");
        }

        if !saw_signature {
            if line != "Windows Registry Editor Version 5.00" {
                bail!(
                    "certified ARG first nonblank line must be 'Windows Registry Editor Version 5.00'"
                );
            }
            saw_signature = true;
            continue;
        }

        if line.starts_with('[') {
            let relative_key = parse_header(line, line_number, &policy.profile_root)?;
            let full_header = header_for_relative_key(&policy.profile_root, &relative_key);
            let identity = full_header.to_ascii_lowercase();
            if !observed_header_identities.insert(identity) {
                bail!("certified ARG line {line_number} duplicates a registry header");
            }
            if !expected_headers.contains(&full_header) {
                bail!("certified ARG line {line_number} declares an unallowlisted registry header");
            }
            observed_headers.insert(full_header);
            current_relative_key = Some(relative_key);
            continue;
        }

        let relative_key = current_relative_key.as_ref().ok_or_else(|| {
            anyhow!("certified ARG line {line_number} declares a value before any registry header")
        })?;
        let parsed_value = parse_value_line(line, line_number, relative_key)?;
        let identity = (
            parsed_value.relative_key.to_ascii_lowercase(),
            parsed_value.value_name.to_ascii_lowercase(),
        );
        if !observed_value_identities.insert(identity) {
            bail!("certified ARG line {line_number} duplicates a registry value");
        }
        values.push(parsed_value);
    }

    if !saw_signature {
        bail!("certified ARG contains no registry editor signature");
    }
    if observed_headers != expected_headers {
        let missing = expected_headers
            .difference(&observed_headers)
            .collect::<Vec<_>>();
        bail!("certified ARG omits policy-required registry headers: {missing:?}");
    }
    values.sort();
    Ok(ParsedArg { values })
}

fn header_for_relative_key(profile_root: &str, relative_key: &str) -> String {
    if relative_key.is_empty() {
        profile_root.to_string()
    } else {
        format!("{profile_root}\\{relative_key}")
    }
}

fn parse_header(line: &str, line_number: usize, profile_root: &str) -> Result<String> {
    if !line.ends_with(']')
        || line.len() < 3
        || line.starts_with("[-")
        || line[1..line.len() - 1].contains(['[', ']'])
    {
        bail!("certified ARG registry header on line {line_number} is malformed");
    }
    let header = &line[1..line.len() - 1];
    if header == profile_root {
        return Ok(String::new());
    }
    let relative_key = header
        .strip_prefix(profile_root)
        .and_then(|suffix| suffix.strip_prefix('\\'))
        .ok_or_else(|| {
            anyhow!(
                "certified ARG registry header on line {line_number} is outside the exact policy profile root"
            )
        })?;
    validate_relative_key(relative_key)
        .with_context(|| format!("certified ARG registry header on line {line_number}"))?;
    Ok(relative_key.to_string())
}

fn parse_value_line(
    line: &str,
    line_number: usize,
    relative_key: &str,
) -> Result<CertifiedArgValue> {
    if line.starts_with('@') || line.starts_with('-') {
        bail!("certified ARG line {line_number} uses an unsupported default or deletion value");
    }
    let (value_name, remainder) = parse_quoted(line, line_number, "value name")?;
    validate_value_name(&value_name)
        .with_context(|| format!("certified ARG line {line_number} value name"))?;
    let encoded = remainder
        .strip_prefix('=')
        .ok_or_else(|| anyhow!("certified ARG line {line_number} lacks an exact '=' separator"))?;
    if encoded.starts_with('"') {
        let (value, trailing) = parse_quoted(encoded, line_number, "string value")?;
        if !trailing.is_empty() {
            bail!("certified ARG line {line_number} has trailing data after a string value");
        }
        Ok(CertifiedArgValue {
            relative_key: relative_key.to_string(),
            value_name,
            value_type: CertifiedArgValueType::String,
            value,
        })
    } else if let Some(value) = encoded.strip_prefix("dword:") {
        if value.len() != 8
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            bail!(
                "certified ARG line {line_number} DWORD must have exactly eight lowercase hexadecimal digits"
            );
        }
        Ok(CertifiedArgValue {
            relative_key: relative_key.to_string(),
            value_name,
            value_type: CertifiedArgValueType::Dword,
            value: value.to_string(),
        })
    } else {
        bail!("certified ARG line {line_number} uses an unsupported registry value type");
    }
}

fn parse_quoted<'a>(input: &'a str, line_number: usize, label: &str) -> Result<(String, &'a str)> {
    let payload = input
        .strip_prefix('"')
        .ok_or_else(|| anyhow!("certified ARG line {line_number} {label} must be quoted"))?;
    let mut decoded = String::new();
    let mut escaped = false;
    for (index, character) in payload.char_indices() {
        if escaped {
            match character {
                '\\' | '"' => decoded.push(character),
                _ => {
                    bail!(
                        "certified ARG line {line_number} {label} has malformed escape '\\{character}'"
                    )
                }
            }
            escaped = false;
            continue;
        }
        match character {
            '\\' => escaped = true,
            '"' => {
                if decoded.contains('\0') || decoded.chars().any(char::is_control) {
                    bail!("certified ARG line {line_number} {label} contains a control character");
                }
                return Ok((decoded, &payload[index + character.len_utf8()..]));
            }
            character if character.is_control() => {
                bail!("certified ARG line {line_number} {label} contains a control character")
            }
            _ => decoded.push(character),
        }
    }
    if escaped {
        bail!("certified ARG line {line_number} {label} ends with an incomplete escape");
    }
    bail!("certified ARG line {line_number} {label} has no closing quote")
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ArgTextEncoding {
    Utf8,
    Utf8Bom,
    Utf16LittleEndian,
    Utf16BigEndian,
}

fn decode_arg_with_encoding(bytes: &[u8]) -> Result<(String, ArgTextEncoding)> {
    fn decode_utf16(bytes: &[u8], little_endian: bool) -> Result<String> {
        if !bytes.len().is_multiple_of(2) {
            bail!("certified ARG has an odd-length UTF-16 payload");
        }
        let code_units = bytes
            .chunks_exact(2)
            .map(|pair| {
                if little_endian {
                    u16::from_le_bytes([pair[0], pair[1]])
                } else {
                    u16::from_be_bytes([pair[0], pair[1]])
                }
            })
            .collect::<Vec<_>>();
        String::from_utf16(&code_units).context("certified ARG is not valid UTF-16")
    }

    let (decoded, encoding) = if let Some(payload) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        (
            std::str::from_utf8(payload)
                .context("certified ARG is not valid BOM-marked UTF-8")?
                .to_string(),
            ArgTextEncoding::Utf8Bom,
        )
    } else if let Some(payload) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        (
            decode_utf16(payload, true)?,
            ArgTextEncoding::Utf16LittleEndian,
        )
    } else if let Some(payload) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        (
            decode_utf16(payload, false)?,
            ArgTextEncoding::Utf16BigEndian,
        )
    } else {
        (
            std::str::from_utf8(bytes)
                .context("certified ARG is neither UTF-8 nor BOM-marked UTF-16")?
                .to_string(),
            ArgTextEncoding::Utf8,
        )
    };
    if decoded.contains('\0') {
        bail!("certified ARG contains a NUL character");
    }
    Ok((decoded, encoding))
}

fn decode_arg(bytes: &[u8]) -> Result<String> {
    decode_arg_with_encoding(bytes).map(|(text, _)| text)
}

fn encode_arg(text: &str, encoding: ArgTextEncoding) -> Vec<u8> {
    match encoding {
        ArgTextEncoding::Utf8 => text.as_bytes().to_vec(),
        ArgTextEncoding::Utf8Bom => [0xEF, 0xBB, 0xBF]
            .into_iter()
            .chain(text.as_bytes().iter().copied())
            .collect(),
        ArgTextEncoding::Utf16LittleEndian | ArgTextEncoding::Utf16BigEndian => {
            let little_endian = encoding == ArgTextEncoding::Utf16LittleEndian;
            let mut bytes = if little_endian {
                vec![0xFF, 0xFE]
            } else {
                vec![0xFE, 0xFF]
            };
            for code_unit in text.encode_utf16() {
                bytes.extend(if little_endian {
                    code_unit.to_le_bytes()
                } else {
                    code_unit.to_be_bytes()
                });
            }
            bytes
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &[u8] = include_bytes!(
        "../../../tests/fixtures/windows_certification/public-development-profile.arg"
    );
    const POLICY: &[u8] = include_bytes!(
        "../../../tests/fixtures/windows_certification/public-development-arg-policy.json"
    );

    fn policy_value() -> serde_json::Value {
        serde_json::from_slice(POLICY).unwrap()
    }

    fn policy_bytes(value: &serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(value).unwrap()
    }

    fn fixture_text() -> String {
        std::str::from_utf8(FIXTURE).unwrap().to_string()
    }

    fn validate_text(text: &str) -> Result<CertifiedArgInspection> {
        validate_distribution_safe_arg(text.as_bytes(), POLICY)
    }

    fn utf16(text: &str, little_endian: bool) -> Vec<u8> {
        let mut bytes = if little_endian {
            vec![0xFF, 0xFE]
        } else {
            vec![0xFE, 0xFF]
        };
        for code_unit in text.encode_utf16() {
            bytes.extend(if little_endian {
                code_unit.to_le_bytes()
            } else {
                code_unit.to_be_bytes()
            });
        }
        bytes
    }

    #[test]
    fn committed_public_development_arg_matches_the_exact_closed_policy() {
        let inspection = validate_distribution_safe_arg(FIXTURE, POLICY).unwrap();
        assert_eq!(inspection.schema_version, 1);
        assert_eq!(inspection.policy_id, PUBLIC_DEVELOPMENT_ARG_POLICY_ID);
        assert_eq!(
            inspection.purpose,
            CertifiedArgPolicyPurpose::DevelopmentFixture
        );
        assert_eq!(inspection.values.len(), 3);
        assert_eq!(inspection.raw_arg_sha256, lowercase_sha256(FIXTURE));
        assert_eq!(inspection.policy_sha256, lowercase_sha256(POLICY));
        assert!(inspection
            .raw_arg_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')));
    }

    #[test]
    fn policy_schema_is_closed_and_inventory_is_sorted_unique() {
        let mut unknown_root = policy_value();
        unknown_root["unexpected"] = serde_json::json!(true);
        let error =
            validate_distribution_safe_arg(FIXTURE, &policy_bytes(&unknown_root)).unwrap_err();
        assert!(error.to_string().contains("unknown field `unexpected`"));

        let mut unknown_row = policy_value();
        unknown_row["values"][0]["unexpected"] = serde_json::json!(true);
        let error =
            validate_distribution_safe_arg(FIXTURE, &policy_bytes(&unknown_row)).unwrap_err();
        assert!(error.to_string().contains("unknown field `unexpected`"));

        let mut unsorted = policy_value();
        unsorted["values"].as_array_mut().unwrap().swap(0, 1);
        let error = validate_distribution_safe_arg(FIXTURE, &policy_bytes(&unsorted)).unwrap_err();
        assert!(error.to_string().contains("sorted and unique"));

        let mut duplicate = policy_value();
        let duplicate_row = duplicate["values"][0].clone();
        duplicate["values"]
            .as_array_mut()
            .unwrap()
            .insert(1, duplicate_row);
        let error = validate_distribution_safe_arg(FIXTURE, &policy_bytes(&duplicate)).unwrap_err();
        assert!(error.to_string().contains("sorted and unique"));
    }

    #[test]
    fn policy_rejects_duplicate_json_keys() {
        let text = std::str::from_utf8(POLICY).unwrap();
        let duplicate = text.replacen(
            "\"purpose\": \"development_fixture\",",
            "\"purpose\": \"development_fixture\", \"purpose\": \"development_fixture\",",
            1,
        );
        let error = validate_distribution_safe_arg(FIXTURE, duplicate.as_bytes()).unwrap_err();
        assert!(
            error.to_string().contains("duplicate field `purpose`"),
            "{error}"
        );
    }

    #[test]
    fn exact_profile_root_and_dedicated_name_are_required() {
        let mut wrong_name = policy_value();
        wrong_name["profile_name"] = serde_json::json!("<<Unnamed Profile>>");
        let error =
            validate_distribution_safe_arg(FIXTURE, &policy_bytes(&wrong_name)).unwrap_err();
        assert!(error.to_string().contains("dedicated canonical"));

        let mut wrong_hive = policy_value();
        wrong_hive["profile_root"] = serde_json::json!(
            "HKEY_LOCAL_MACHINE\\Software\\Autodesk\\AutoCAD\\R25.1\\ACAD-9101:409\\Profiles\\AutoCAD-MCP Public Development"
        );
        let error =
            validate_distribution_safe_arg(FIXTURE, &policy_bytes(&wrong_hive)).unwrap_err();
        assert!(error.to_string().contains("exact dedicated profile"));

        let wrong_arg_root = fixture_text().replace(
            "Profiles\\AutoCAD-MCP Public Development",
            "Profiles\\AutoCAD-MCP Other",
        );
        let error = validate_text(&wrong_arg_root).unwrap_err();
        assert!(error.to_string().contains("outside the exact policy"));
    }

    #[test]
    fn every_header_and_value_must_equal_the_policy_inventory() {
        let duplicate_header = fixture_text().replace(
            "\"Description\"=",
            "[HKEY_CURRENT_USER\\Software\\Autodesk\\AutoCAD\\R25.1\\ACAD-9101:409\\Profiles\\AutoCAD-MCP Public Development]\n\"Description\"=",
        );
        assert!(validate_text(&duplicate_header)
            .unwrap_err()
            .to_string()
            .contains("duplicates a registry header"));

        let duplicate_value = fixture_text().replace(
            "\"Description\"=\"Synthetic",
            "\"Description\"=\"Duplicate\"\n\"Description\"=\"Synthetic",
        );
        assert!(validate_text(&duplicate_value)
            .unwrap_err()
            .to_string()
            .contains("duplicates a registry value"));

        let extra_value = fixture_text().replace(
            "\"FixturePurpose\"=\"development-only\"",
            "\"FixturePurpose\"=\"development-only\"\n\"Extra\"=\"public\"",
        );
        assert!(validate_text(&extra_value)
            .unwrap_err()
            .to_string()
            .contains("extra="));

        let omitted_value = fixture_text()
            .lines()
            .filter(|line| !line.starts_with("\"FixturePurpose\"="))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(validate_text(&omitted_value)
            .unwrap_err()
            .to_string()
            .contains("missing="));

        let extra_header = format!(
            "{}\n[{}\\Unapproved]\n",
            fixture_text(),
            policy_value()["profile_root"].as_str().unwrap()
        );
        assert!(validate_text(&extra_header)
            .unwrap_err()
            .to_string()
            .contains("unallowlisted registry header"));
    }

    #[test]
    fn comments_deletions_continuations_and_unknown_lines_are_rejected() {
        let text = fixture_text();
        for (mutation, expected) in [
            (
                text.replace(
                    "Windows Registry Editor Version 5.00",
                    "Windows Registry Editor Version 5.00\n; hidden comment",
                ),
                "comments are not admitted",
            ),
            (
                text.replace("[HKEY_CURRENT_USER", "[-HKEY_CURRENT_USER"),
                "malformed",
            ),
            (
                text.replace(
                    "\"FixturePurpose\"=\"development-only\"",
                    "\"FixturePurpose\"=\"development-only\"\\",
                ),
                "unsupported continuation",
            ),
            (
                text.replace(
                    "\"FixturePurpose\"=\"development-only\"",
                    "unparsed material",
                ),
                "must be quoted",
            ),
        ] {
            let error = validate_text(&mutation).unwrap_err().to_string();
            assert!(error.contains(expected), "{error}");
        }
    }

    #[test]
    fn only_exact_string_and_lowercase_dword_values_are_supported() {
        let hex = fixture_text().replace("dword:00000000", "hex:00");
        assert!(validate_text(&hex)
            .unwrap_err()
            .to_string()
            .contains("unsupported registry value type"));

        let uppercase = fixture_text().replace("dword:00000000", "dword:0000000A");
        assert!(validate_text(&uppercase)
            .unwrap_err()
            .to_string()
            .contains("lowercase hexadecimal"));

        let default_value = fixture_text().replace(
            "\"Description\"=\"Synthetic public development fixture; not certified or approved for release or distribution\"",
            "@=\"default\"",
        );
        assert!(validate_text(&default_value)
            .unwrap_err()
            .to_string()
            .contains("default or deletion"));
    }

    #[test]
    fn malformed_escapes_nul_and_malformed_encodings_are_rejected() {
        let malformed_escape = fixture_text().replace("development-only", "development\\q-only");
        assert!(validate_text(&malformed_escape)
            .unwrap_err()
            .to_string()
            .contains("malformed escape"));

        let mut nul = FIXTURE.to_vec();
        nul.push(0);
        assert!(validate_distribution_safe_arg(&nul, POLICY)
            .unwrap_err()
            .to_string()
            .contains("NUL"));

        let odd_utf16 = [0xFF, 0xFE, b'W'];
        assert!(validate_distribution_safe_arg(&odd_utf16, POLICY)
            .unwrap_err()
            .to_string()
            .contains("odd-length"));
        assert!(validate_distribution_safe_arg(&[0x80], POLICY).is_err());
    }

    #[test]
    fn supported_bom_encodings_preserve_semantics_and_hash_raw_bytes() {
        let text = fixture_text();
        let mut utf8_bom = vec![0xEF, 0xBB, 0xBF];
        utf8_bom.extend(text.as_bytes());
        let utf16_le = utf16(&text, true);
        let utf16_be = utf16(&text, false);

        for bytes in [&utf8_bom, &utf16_le, &utf16_be] {
            let inspection = validate_distribution_safe_arg(bytes, POLICY).unwrap();
            assert_eq!(inspection.values.len(), 3);
            assert_eq!(inspection.raw_arg_sha256, lowercase_sha256(bytes));
        }
    }

    #[test]
    fn xref_profile_derivation_changes_only_header_roots_and_preserves_encoding() {
        const TOKEN: &str = "0123456789abcdef0123456789abcdef";
        let text = fixture_text();
        let mut utf8_bom = vec![0xEF, 0xBB, 0xBF];
        utf8_bom.extend(text.as_bytes());
        let utf16_le = utf16(&text, true);
        let utf16_be = utf16(&text, false);

        for bytes in [FIXTURE, &utf8_bom, &utf16_le, &utf16_be] {
            let source = certified_arg_profile_binding(bytes).unwrap();
            let derived = derive_xref_certified_arg(bytes, TOKEN).unwrap();
            assert_eq!(
                derived.binding.profile_name,
                "AutoCAD-MCP XREF 0123456789abcdef0123456789abcdef"
            );
            assert_eq!(
                derived.binding.hkcu_parent_subkey,
                source.hkcu_parent_subkey
            );
            assert!(!decode_arg(&derived.bytes)
                .unwrap()
                .contains(&source.profile_root));

            let (_, source_encoding) = decode_arg_with_encoding(bytes).unwrap();
            let (_, derived_encoding) = decode_arg_with_encoding(&derived.bytes).unwrap();
            assert_eq!(derived_encoding, source_encoding);
            let round_trip = derive_xref_certified_arg(bytes, TOKEN).unwrap();
            assert_eq!(round_trip, derived);
        }
    }

    #[test]
    fn xref_profile_derivation_rejects_ambiguous_or_noncanonical_inputs() {
        for token in [
            "",
            "0123456789abcdef",
            "0123456789ABCDEF0123456789ABCDEF",
            "g123456789abcdef0123456789abcdef",
        ] {
            assert!(derive_xref_certified_arg(FIXTURE, token).is_err());
        }

        let source = certified_arg_profile_binding(FIXTURE).unwrap();
        let unsafe_value = fixture_text().replace(
            "development-only",
            &format!("development-only {}", source.profile_root),
        );
        assert!(derive_xref_certified_arg(
            unsafe_value.as_bytes(),
            "0123456789abcdef0123456789abcdef"
        )
        .unwrap_err()
        .to_string()
        .contains("outside an exact registry header"));
    }

    #[test]
    fn public_policy_rejects_path_and_environment_value_admission() {
        for private_value in [
            "C:\\Users\\username\\plotters",
            "\\\\server\\share",
            "%USERPROFILE%",
            "${HOME}",
            "relative/path",
        ] {
            let mut policy = policy_value();
            policy["values"][0]["value"] = serde_json::json!(private_value);
            let error =
                validate_distribution_safe_arg(FIXTURE, &policy_bytes(&policy)).unwrap_err();
            assert!(
                error.to_string().contains("paths or environment expansion"),
                "{error}"
            );
        }
    }
}
