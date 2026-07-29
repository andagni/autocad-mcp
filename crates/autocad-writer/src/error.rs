#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteErrorKind {
    UnsupportedFormat,
    NotFound,
    Unreadable,
    InvalidDrawing,
    UnsupportedSourceData,
    InvalidRequest,
    TargetNotFound,
    AmbiguousTarget,
    BackendCapability,
    EncodeFailed,
    VerificationFailed,
}

pub struct WriteError {
    kind: WriteErrorKind,
    code: &'static str,
    message: String,
    internal_detail: Option<String>,
}

impl std::fmt::Debug for WriteError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WriteError")
            .field("kind", &self.kind)
            .field("code", &self.code)
            .field("message", &self.message)
            .field("has_internal_detail", &self.internal_detail.is_some())
            .finish()
    }
}

impl WriteError {
    pub(crate) fn new(
        kind: WriteErrorKind,
        code: &'static str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            code,
            message: message.into(),
            internal_detail: None,
        }
    }

    pub(crate) fn with_internal_detail(mut self, detail: impl Into<String>) -> Self {
        self.internal_detail = Some(detail.into());
        self
    }

    pub(crate) fn capture(error: std::io::Error) -> Self {
        let (kind, code, message) = if error.kind() == std::io::ErrorKind::NotFound {
            (
                WriteErrorKind::NotFound,
                "drawing_not_found",
                "drawing was not found",
            )
        } else {
            (
                WriteErrorKind::Unreadable,
                "drawing_unreadable",
                "drawing could not be captured",
            )
        };
        Self::new(kind, code, message).with_internal_detail(error.to_string())
    }

    pub(crate) fn unsupported_format(message: impl Into<String>) -> Self {
        Self::new(
            WriteErrorKind::UnsupportedFormat,
            "unsupported_format",
            message,
        )
    }

    pub(crate) fn invalid_drawing(detail: impl Into<String>) -> Self {
        Self::new(
            WriteErrorKind::InvalidDrawing,
            "invalid_drawing",
            "drawing could not be decoded",
        )
        .with_internal_detail(detail)
    }

    pub(crate) fn unsupported_source(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(WriteErrorKind::UnsupportedSourceData, code, message)
    }

    pub(crate) fn invalid_request(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(WriteErrorKind::InvalidRequest, code, message)
    }

    pub(crate) fn target_not_found(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(WriteErrorKind::TargetNotFound, code, message)
    }

    pub(crate) fn ambiguous_target(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(WriteErrorKind::AmbiguousTarget, code, message)
    }

    pub(crate) fn backend_capability(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(WriteErrorKind::BackendCapability, code, message)
    }

    pub(crate) fn encode(detail: impl Into<String>) -> Self {
        Self::new(
            WriteErrorKind::EncodeFailed,
            "candidate_encode_failed",
            "drawing candidate could not be encoded",
        )
        .with_internal_detail(detail)
    }

    pub(crate) fn verification(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(WriteErrorKind::VerificationFailed, code, message)
    }

    pub(crate) fn from_reader(error: autocad_reader::ReadError) -> Self {
        use autocad_reader::ReadErrorKind;

        match error.kind() {
            ReadErrorKind::UnsupportedFormat => Self::unsupported_format(error.message()),
            ReadErrorKind::NotFound => Self::new(
                WriteErrorKind::NotFound,
                "drawing_not_found",
                "drawing was not found",
            ),
            ReadErrorKind::Unreadable => Self::new(
                WriteErrorKind::Unreadable,
                "drawing_unreadable",
                "drawing could not be captured",
            ),
            ReadErrorKind::InvalidDrawing => Self::invalid_drawing(error.message()),
            ReadErrorKind::IncompleteDrawing => Self::unsupported_source(
                "unsupported_source_diagnostics",
                "reader reported incomplete drawing data; candidate generation is unsafe",
            ),
        }
    }

    pub fn kind(&self) -> WriteErrorKind {
        self.kind
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    #[cfg(test)]
    pub(crate) fn internal_detail(&self) -> Option<&str> {
        self.internal_detail.as_deref()
    }
}

impl std::fmt::Display for WriteError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "code={} {}", self.code, self.message)
    }
}

impl std::error::Error for WriteError {}
