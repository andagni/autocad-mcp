//! Pure lexical classification of persisted XREF paths.
//!
//! Filesystem probing, search-path policy, and mutation validation remain
//! application responsibilities. This module owns only the interpretation
//! needed while projecting a drawing snapshot.

use crate::contract::xrefs::XrefPathMode;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AbsolutePathKind {
    WindowsDrive,
    WindowsUnc,
    Posix,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsupportedPathReason {
    Empty,
    ControlCharacter,
    DriveRelative,
    WindowsRootRelative,
    MalformedUnc,
    WindowsDevicePath,
    HomeExpansion,
    EnvironmentExpansion,
    UnsupportedScheme,
    MalformedUrl,
    UnknownForm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XrefPathSyntax {
    WindowsDriveAbsolute,
    WindowsUncAbsolute,
    PosixAbsolute,
    Relative,
    FilenameOnly,
    Url,
    Unsupported(UnsupportedPathReason),
}

impl XrefPathSyntax {
    pub fn mode(self) -> XrefPathMode {
        match self {
            Self::WindowsDriveAbsolute | Self::WindowsUncAbsolute | Self::PosixAbsolute => {
                XrefPathMode::Absolute
            }
            Self::Relative => XrefPathMode::Relative,
            Self::FilenameOnly => XrefPathMode::FilenameOnly,
            Self::Url => XrefPathMode::Url,
            Self::Unsupported(_) => XrefPathMode::Unsupported,
        }
    }

    pub fn absolute_kind(self) -> Option<AbsolutePathKind> {
        match self {
            Self::WindowsDriveAbsolute => Some(AbsolutePathKind::WindowsDrive),
            Self::WindowsUncAbsolute => Some(AbsolutePathKind::WindowsUnc),
            Self::PosixAbsolute => Some(AbsolutePathKind::Posix),
            Self::Relative | Self::FilenameOnly | Self::Url | Self::Unsupported(_) => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedXrefPath {
    saved_path: String,
    syntax: XrefPathSyntax,
    basename: Option<String>,
    has_trailing_separator: bool,
}

impl ParsedXrefPath {
    pub fn saved_path(&self) -> &str {
        &self.saved_path
    }

    pub fn syntax(&self) -> XrefPathSyntax {
        self.syntax
    }

    pub fn mode(&self) -> XrefPathMode {
        self.syntax.mode()
    }

    pub fn basename(&self) -> Option<&str> {
        self.basename.as_deref()
    }

    pub fn has_trailing_separator(&self) -> bool {
        self.has_trailing_separator
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AbsoluteRoot {
    WindowsDrive,
    WindowsUnc,
    Posix,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AbsoluteParts {
    root: AbsoluteRoot,
    components: Vec<String>,
}

enum AbsoluteParse {
    Absolute(AbsoluteParts),
    Unsupported(UnsupportedPathReason),
    NotAbsolute,
}

fn is_separator(byte: u8) -> bool {
    matches!(byte, b'/' | b'\\')
}

fn has_two_leading_separators(bytes: &[u8]) -> bool {
    bytes.len() >= 2 && is_separator(bytes[0]) && is_separator(bytes[1])
}

fn split_components(value: &str) -> Vec<String> {
    value
        .split(['/', '\\'])
        .filter(|component| !component.is_empty())
        .map(str::to_owned)
        .collect()
}

fn parse_unc_remainder(value: &str) -> Result<AbsoluteParts, UnsupportedPathReason> {
    let mut components = split_components(value).into_iter();
    let Some(server) = components.next() else {
        return Err(UnsupportedPathReason::MalformedUnc);
    };
    let Some(share) = components.next() else {
        return Err(UnsupportedPathReason::MalformedUnc);
    };
    if matches!(server.as_str(), "." | "..") || matches!(share.as_str(), "." | "..") {
        return Err(UnsupportedPathReason::MalformedUnc);
    }

    Ok(AbsoluteParts {
        root: AbsoluteRoot::WindowsUnc,
        components: components.collect(),
    })
}

fn parse_drive_path(value: &str) -> Result<AbsoluteParts, UnsupportedPathReason> {
    let bytes = value.as_bytes();
    if bytes.len() < 3 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' {
        return Err(UnsupportedPathReason::WindowsDevicePath);
    }
    if !is_separator(bytes[2]) {
        return Err(UnsupportedPathReason::DriveRelative);
    }

    Ok(AbsoluteParts {
        root: AbsoluteRoot::WindowsDrive,
        components: split_components(&value[3..]),
    })
}

fn parse_absolute_path(value: &str) -> AbsoluteParse {
    let bytes = value.as_bytes();

    if bytes.len() >= 4
        && has_two_leading_separators(bytes)
        && matches!(bytes[2], b'?' | b'.')
        && is_separator(bytes[3])
    {
        if bytes[2] == b'.' {
            return AbsoluteParse::Unsupported(UnsupportedPathReason::WindowsDevicePath);
        }

        let remainder = &value[4..];
        let remainder_bytes = remainder.as_bytes();
        if remainder_bytes.len() >= 4
            && remainder_bytes[..3].eq_ignore_ascii_case(b"UNC")
            && is_separator(remainder_bytes[3])
        {
            return match parse_unc_remainder(&remainder[4..]) {
                Ok(parts) => AbsoluteParse::Absolute(parts),
                Err(reason) => AbsoluteParse::Unsupported(reason),
            };
        }

        return match parse_drive_path(remainder) {
            Ok(parts) => AbsoluteParse::Absolute(parts),
            Err(_) => AbsoluteParse::Unsupported(UnsupportedPathReason::WindowsDevicePath),
        };
    }

    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return match parse_drive_path(value) {
            Ok(parts) => AbsoluteParse::Absolute(parts),
            Err(reason) => AbsoluteParse::Unsupported(reason),
        };
    }

    if has_two_leading_separators(bytes) {
        return match parse_unc_remainder(&value[2..]) {
            Ok(parts) => AbsoluteParse::Absolute(parts),
            Err(reason) => AbsoluteParse::Unsupported(reason),
        };
    }

    if bytes.first() == Some(&b'/') {
        return AbsoluteParse::Absolute(AbsoluteParts {
            root: AbsoluteRoot::Posix,
            components: split_components(&value[1..]),
        });
    }

    if bytes.first() == Some(&b'\\') {
        return AbsoluteParse::Unsupported(UnsupportedPathReason::WindowsRootRelative);
    }

    AbsoluteParse::NotAbsolute
}

fn contains_control_character(value: &str) -> bool {
    value
        .chars()
        .any(|character| character.is_control() || character == '\u{7f}')
}

fn has_percent_expansion(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if let Some(end) = bytes[index + 1..].iter().position(|byte| *byte == b'%') {
                if end > 0 {
                    return true;
                }
                index += end + 2;
                continue;
            }
        }
        index += 1;
    }
    false
}

fn has_bang_expansion(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'!' {
            if let Some(end) = bytes[index + 1..].iter().position(|byte| *byte == b'!') {
                if end > 0 {
                    return true;
                }
                index += end + 2;
                continue;
            }
        }
        index += 1;
    }
    false
}

fn has_dollar_expansion(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.windows(2).any(|pair| {
        pair[0] == b'$'
            && (pair[1].is_ascii_alphanumeric() || matches!(pair[1], b'_' | b'{' | b'('))
    })
}

fn ambient_expansion_reason(value: &str) -> Option<UnsupportedPathReason> {
    if value.starts_with('~') {
        return Some(UnsupportedPathReason::HomeExpansion);
    }
    if has_percent_expansion(value) || has_bang_expansion(value) || has_dollar_expansion(value) {
        return Some(UnsupportedPathReason::EnvironmentExpansion);
    }
    None
}

fn uri_scheme(value: &str) -> Option<(&str, &str)> {
    let colon = value.find(':')?;
    let scheme = &value[..colon];
    let mut bytes = scheme.bytes();
    if !bytes.next().is_some_and(|byte| byte.is_ascii_alphabetic())
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
    {
        return None;
    }
    Some((scheme, &value[colon + 1..]))
}

fn has_valid_url_authority(remainder: &str) -> bool {
    let Some(authority_and_path) = remainder.strip_prefix("//") else {
        return false;
    };
    let authority_end = authority_and_path
        .find(['/', '\\', '?', '#'])
        .unwrap_or(authority_and_path.len());
    let authority = &authority_and_path[..authority_end];
    !authority.is_empty() && !authority.chars().any(char::is_whitespace)
}

fn ordinary_basename(components: &[String]) -> Option<String> {
    components
        .last()
        .filter(|component| !matches!(component.as_str(), "." | ".."))
        .cloned()
}

pub fn parse_saved_path(saved_path: &str) -> ParsedXrefPath {
    let has_trailing_separator = saved_path
        .as_bytes()
        .last()
        .is_some_and(|byte| is_separator(*byte));

    let (syntax, basename) = if saved_path.is_empty() {
        (
            XrefPathSyntax::Unsupported(UnsupportedPathReason::Empty),
            None,
        )
    } else if contains_control_character(saved_path) {
        (
            XrefPathSyntax::Unsupported(UnsupportedPathReason::ControlCharacter),
            None,
        )
    } else {
        match parse_absolute_path(saved_path) {
            AbsoluteParse::Absolute(parts) => {
                if let Some(reason) = ambient_expansion_reason(saved_path) {
                    (XrefPathSyntax::Unsupported(reason), None)
                } else {
                    let syntax = match parts.root {
                        AbsoluteRoot::WindowsDrive => XrefPathSyntax::WindowsDriveAbsolute,
                        AbsoluteRoot::WindowsUnc => XrefPathSyntax::WindowsUncAbsolute,
                        AbsoluteRoot::Posix => XrefPathSyntax::PosixAbsolute,
                    };
                    (syntax, ordinary_basename(&parts.components))
                }
            }
            AbsoluteParse::Unsupported(reason) => (XrefPathSyntax::Unsupported(reason), None),
            AbsoluteParse::NotAbsolute => {
                if let Some((scheme, remainder)) = uri_scheme(saved_path) {
                    let allowed = matches!(
                        scheme.to_ascii_lowercase().as_str(),
                        "http" | "https" | "ftp"
                    );
                    if allowed && has_valid_url_authority(remainder) {
                        (XrefPathSyntax::Url, None)
                    } else if allowed {
                        (
                            XrefPathSyntax::Unsupported(UnsupportedPathReason::MalformedUrl),
                            None,
                        )
                    } else {
                        (
                            XrefPathSyntax::Unsupported(UnsupportedPathReason::UnsupportedScheme),
                            None,
                        )
                    }
                } else if saved_path.contains("://") {
                    (
                        XrefPathSyntax::Unsupported(UnsupportedPathReason::UnknownForm),
                        None,
                    )
                } else if let Some(reason) = ambient_expansion_reason(saved_path) {
                    (XrefPathSyntax::Unsupported(reason), None)
                } else {
                    let components = split_components(saved_path);
                    let syntax = if saved_path.as_bytes().iter().any(|byte| is_separator(*byte))
                        || matches!(saved_path, "." | "..")
                    {
                        XrefPathSyntax::Relative
                    } else {
                        XrefPathSyntax::FilenameOnly
                    };
                    (syntax, ordinary_basename(&components))
                }
            }
        }
    };

    ParsedXrefPath {
        saved_path: saved_path.to_owned(),
        syntax,
        basename,
        has_trailing_separator,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saved_path_modes_cover_supported_and_rejected_syntaxes() {
        for (path, expected) in [
            (r"C:\refs\site.dwg", XrefPathMode::Absolute),
            (r"\\server\share\site.dwg", XrefPathMode::Absolute),
            ("/refs/site.dwg", XrefPathMode::Absolute),
            ("../refs/site.dwg", XrefPathMode::Relative),
            ("site.dwg", XrefPathMode::FilenameOnly),
            ("https://example.test/site.dwg", XrefPathMode::Url),
            ("C:site.dwg", XrefPathMode::Unsupported),
        ] {
            assert_eq!(parse_saved_path(path).mode(), expected, "{path}");
        }
    }

    #[test]
    fn classification_preserves_basename_and_trailing_separator_facts() {
        let parsed = parse_saved_path("../refs/site.dwg");
        assert_eq!(parsed.basename(), Some("site.dwg"));
        assert!(!parsed.has_trailing_separator());

        let directory = parse_saved_path("../refs/");
        assert_eq!(directory.basename(), Some("refs"));
        assert!(directory.has_trailing_separator());
    }
}
