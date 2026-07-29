//! Reader-owned projection for internal drawing format certification facts.

use acadrust::CadDocument;

use super::contract::DrawingFormatFacts;
use super::{ReadError, ReadErrorKind};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FormatFactsReadError {
    code: &'static str,
    message: &'static str,
}

impl FormatFactsReadError {
    pub(super) fn unsupported_diagnostic() -> Self {
        Self {
            code: "unsupported_format_facts_data",
            message:
                "reader reported an unsupported diagnostic that may affect drawing format facts",
        }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &'static str {
        self.message
    }
}

impl std::fmt::Display for FormatFactsReadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "code={} {}", self.code, self.message)
    }
}

impl std::error::Error for FormatFactsReadError {}

pub fn map_snapshot_open_error(error: ReadError) -> FormatFactsReadError {
    let (code, message) = match error.kind() {
        ReadErrorKind::UnsupportedFormat => (
            "unsupported_format",
            "reader rejected the declared drawing snapshot format",
        ),
        ReadErrorKind::NotFound | ReadErrorKind::Unreadable => (
            "drawing_unreadable",
            "reader could not read the captured drawing snapshot",
        ),
        ReadErrorKind::InvalidDrawing => (
            "invalid_drawing",
            "reader could not decode the captured drawing snapshot",
        ),
        ReadErrorKind::IncompleteDrawing => (
            "incomplete_drawing",
            "reader reported incomplete data while decoding the captured drawing snapshot",
        ),
    };
    FormatFactsReadError { code, message }
}

pub(super) fn read_format_facts(document: &CadDocument) -> DrawingFormatFacts {
    DrawingFormatFacts {
        drawing_version: document.version.as_str().to_string(),
        code_page: document.header.code_page.clone(),
    }
}

#[cfg(test)]
mod tests {
    use acadrust::types::DxfVersion;

    use super::*;

    #[test]
    fn backend_projection_exposes_only_decoded_version_and_code_page() {
        let mut document = CadDocument::with_version(DxfVersion::AC1027);
        document.header.code_page = "ANSI_1252".to_string();

        assert_eq!(
            read_format_facts(&document),
            DrawingFormatFacts {
                drawing_version: "AC1027".to_string(),
                code_page: "ANSI_1252".to_string(),
            }
        );
    }

    #[test]
    fn snapshot_open_errors_are_stable_and_hide_backend_text() {
        let backend_error = ReadError::invalid_drawing("backend-specific detail");

        let error = map_snapshot_open_error(backend_error);

        assert_eq!(error.code(), "invalid_drawing");
        assert_eq!(
            error.message(),
            "reader could not decode the captured drawing snapshot"
        );
        assert!(!error.to_string().contains("backend-specific detail"));
    }
}
