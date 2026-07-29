/// Minimal decoded header facts required by internal certification.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DrawingFormatFacts {
    pub drawing_version: String,
    pub code_page: String,
}
