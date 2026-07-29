use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrawingFormat {
    Dwg,
    Dxf,
}

impl DrawingFormat {
    pub fn from_path(path: &std::path::Path) -> Result<Self, super::ReadError> {
        match path.extension().and_then(|extension| extension.to_str()) {
            Some(extension) if extension.eq_ignore_ascii_case("dwg") => Ok(Self::Dwg),
            Some(extension) if extension.eq_ignore_ascii_case("dxf") => Ok(Self::Dxf),
            Some(extension) => Err(super::ReadError::unsupported_format(format!(
                "unsupported extension {extension:?}; expected .dxf or .dwg"
            ))),
            None => Err(super::ReadError::unsupported_format(
                "file has no extension; expected .dxf or .dwg",
            )),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Dwg => "DWG",
            Self::Dxf => "DXF",
        }
    }
}

/// One immutable drawing capture supplied to the reader backend.
#[derive(Debug, Clone)]
pub struct DrawingSnapshot {
    format: DrawingFormat,
    bytes: Arc<[u8]>,
}

impl DrawingSnapshot {
    pub fn new(format: DrawingFormat, bytes: impl Into<Arc<[u8]>>) -> Self {
        Self {
            format,
            bytes: bytes.into(),
        }
    }

    pub(super) fn format(&self) -> DrawingFormat {
        self.format
    }

    pub(super) fn bytes(&self) -> Arc<[u8]> {
        Arc::clone(&self.bytes)
    }
}
