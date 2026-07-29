use std::sync::Arc;

use super::WriteError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrawingFormat {
    Dwg,
    Dxf,
}

impl DrawingFormat {
    pub fn from_path(path: &std::path::Path) -> Result<Self, WriteError> {
        match path.extension().and_then(|extension| extension.to_str()) {
            Some(extension) if extension.eq_ignore_ascii_case("dwg") => Ok(Self::Dwg),
            Some(extension) if extension.eq_ignore_ascii_case("dxf") => Ok(Self::Dxf),
            Some(extension) => Err(WriteError::unsupported_format(format!(
                "unsupported extension {extension:?}; expected .dxf or .dwg"
            ))),
            None => Err(WriteError::unsupported_format(
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

    pub(crate) fn reader_format(self) -> autocad_reader::DrawingFormat {
        match self {
            Self::Dwg => autocad_reader::DrawingFormat::Dwg,
            Self::Dxf => autocad_reader::DrawingFormat::Dxf,
        }
    }
}

/// One immutable capture supplied to the writer backend.
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

    pub fn format(&self) -> DrawingFormat {
        self.format
    }

    pub(crate) fn bytes(&self) -> Arc<[u8]> {
        Arc::clone(&self.bytes)
    }

    pub(crate) fn reader_snapshot(&self) -> autocad_reader::DrawingSnapshot {
        autocad_reader::DrawingSnapshot::new(self.format.reader_format(), self.bytes())
    }
}
