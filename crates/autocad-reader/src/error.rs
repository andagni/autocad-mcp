#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadErrorKind {
    UnsupportedFormat,
    NotFound,
    Unreadable,
    InvalidDrawing,
    IncompleteDrawing,
}

pub struct ReadError {
    kind: ReadErrorKind,
    message: String,
    internal_detail: Option<String>,
    fatal_diagnostics: Vec<String>,
}

impl std::fmt::Debug for ReadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReadError")
            .field("kind", &self.kind)
            .field("message", &self.message)
            .field("has_internal_detail", &self.internal_detail.is_some())
            .field("fatal_diagnostic_count", &self.fatal_diagnostics.len())
            .finish()
    }
}

impl ReadError {
    fn new(
        kind: ReadErrorKind,
        message: impl Into<String>,
        internal_detail: Option<String>,
        fatal_diagnostics: Vec<String>,
    ) -> Self {
        Self {
            kind,
            message: message.into(),
            internal_detail,
            fatal_diagnostics,
        }
    }

    pub(super) fn capture(error: std::io::Error) -> Self {
        let kind = if error.kind() == std::io::ErrorKind::NotFound {
            ReadErrorKind::NotFound
        } else {
            ReadErrorKind::Unreadable
        };
        let message = match kind {
            ReadErrorKind::NotFound => "drawing was not found",
            ReadErrorKind::Unreadable => "drawing could not be captured",
            _ => unreachable!("capture errors map only to path-capture kinds"),
        };
        Self::new(kind, message, Some(error.to_string()), Vec::new())
    }

    pub(super) fn invalid_drawing(internal_detail: impl Into<String>) -> Self {
        Self::new(
            ReadErrorKind::InvalidDrawing,
            "drawing could not be decoded",
            Some(internal_detail.into()),
            Vec::new(),
        )
    }

    pub(super) fn unsupported_format(message: impl Into<String>) -> Self {
        Self::new(ReadErrorKind::UnsupportedFormat, message, None, Vec::new())
    }

    pub(super) fn incomplete(format: &str, fatal_diagnostics: Vec<String>) -> Self {
        Self::new(
            ReadErrorKind::IncompleteDrawing,
            format!(
                "reader reported an error diagnostic while reading {format}; drawing projection is incomplete"
            ),
            None,
            fatal_diagnostics,
        )
    }

    pub fn kind(&self) -> ReadErrorKind {
        self.kind
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    #[cfg(test)]
    pub(super) fn internal_detail(&self) -> Option<&str> {
        self.internal_detail.as_deref()
    }

    #[cfg(test)]
    pub(super) fn fatal_diagnostics(&self) -> &[String] {
        &self.fatal_diagnostics
    }
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ReadError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_errors_expose_only_reader_owned_messages() {
        let missing = ReadError::capture(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "backend-specific missing marker",
        ));
        assert_eq!(missing.kind(), ReadErrorKind::NotFound);
        assert_eq!(missing.message(), "drawing was not found");
        assert_eq!(missing.to_string(), "drawing was not found");
        assert_eq!(
            missing.internal_detail(),
            Some("backend-specific missing marker")
        );
        assert!(!format!("{missing:?}").contains("backend-specific missing marker"));
        assert!(missing.fatal_diagnostics().is_empty());

        let unreadable = ReadError::capture(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "backend-specific unreadable marker",
        ));
        assert_eq!(unreadable.kind(), ReadErrorKind::Unreadable);
        assert_eq!(unreadable.message(), "drawing could not be captured");
        assert_eq!(unreadable.to_string(), "drawing could not be captured");
        assert_eq!(
            unreadable.internal_detail(),
            Some("backend-specific unreadable marker")
        );
        assert!(!format!("{unreadable:?}").contains("backend-specific unreadable marker"));
        assert!(unreadable.fatal_diagnostics().is_empty());
    }

    #[test]
    fn invalid_drawing_hides_backend_text() {
        let error = ReadError::invalid_drawing("backend-specific decode marker");

        assert_eq!(error.kind(), ReadErrorKind::InvalidDrawing);
        assert_eq!(error.message(), "drawing could not be decoded");
        assert_eq!(error.to_string(), "drawing could not be decoded");
        assert_eq!(
            error.internal_detail(),
            Some("backend-specific decode marker")
        );
        assert!(!format!("{error:?}").contains("backend-specific decode marker"));
        assert!(error.fatal_diagnostics().is_empty());
    }

    #[test]
    fn unsupported_and_incomplete_messages_are_reader_owned() {
        let unsupported =
            ReadError::unsupported_format("unsupported extension \"xyz\"; expected .dxf or .dwg");
        assert_eq!(unsupported.kind(), ReadErrorKind::UnsupportedFormat);
        assert_eq!(
            unsupported.message(),
            "unsupported extension \"xyz\"; expected .dxf or .dwg"
        );
        assert_eq!(unsupported.internal_detail(), None);
        assert!(unsupported.fatal_diagnostics().is_empty());

        let incomplete =
            ReadError::incomplete("DWG", vec!["backend-specific diagnostic".to_string()]);
        assert_eq!(incomplete.kind(), ReadErrorKind::IncompleteDrawing);
        assert_eq!(
            incomplete.message(),
            "reader reported an error diagnostic while reading DWG; drawing projection is incomplete"
        );
        assert_eq!(
            incomplete.fatal_diagnostics(),
            ["backend-specific diagnostic"]
        );
        assert_eq!(incomplete.internal_detail(), None);
        assert!(!format!("{incomplete:?}").contains("backend-specific diagnostic"));
    }
}
