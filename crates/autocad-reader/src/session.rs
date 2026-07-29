use std::path::Path;

use acadrust::CadDocument;

use super::backend::{self, ReadDiagnostic, ReadDiagnosticKind};
use super::contract::{
    BlockDefinitionRecord, BlockDefinitionSelector, BlockInfo, BlockInsertRecord,
    BlockInsertSelector, DimensionStyleRecord, DrawingFormatFacts, DrawingSummary,
    EntityListOptions, EntityListResult, EntityRecord, EntitySelector, LayerRecord, LayerSelector,
    LayoutInfo, LayoutRecord, LayoutSelector, LayoutViewportRecord, LayoutViewportSelector,
    LinetypeRecord, NamedUcsRecord, NamedViewRecord, PlotSettingRecord, PlotSettingSelector,
    SymbolSelector, TextItem, TextListOptions, TextRecord, TextSelector, TextStyleRecord,
    TitleBlockInfo,
};
use super::{
    blocks, drawing, entities, format_facts, layers, layouts, symbols, text, title_blocks, xrefs,
    DrawingFormat, DrawingSnapshot, FormatFactsReadError, ReadError,
};

pub struct Reader;

impl Reader {
    pub fn open_path(path: &Path) -> Result<DrawingReadSession, ReadError> {
        Self::open_path_with_capture(path, |captured_path| std::fs::read(captured_path))
    }

    fn open_path_with_capture(
        path: &Path,
        capture: impl FnOnce(&Path) -> std::io::Result<Vec<u8>>,
    ) -> Result<DrawingReadSession, ReadError> {
        let format = DrawingFormat::from_path(path)?;
        let bytes = capture(path).map_err(ReadError::capture)?;
        Self::open_snapshot(DrawingSnapshot::new(format, bytes))
    }

    pub fn open_snapshot(snapshot: DrawingSnapshot) -> Result<DrawingReadSession, ReadError> {
        let parsed = backend::parse(&snapshot)?;
        Ok(DrawingReadSession {
            snapshot,
            document: parsed.document,
            diagnostics: parsed.diagnostics,
        })
    }
}

/// One successfully decoded immutable drawing snapshot.
///
/// The backend document is deliberately private. Read families cross this
/// boundary through contract records and selectors, never through acadrust
/// types.
pub struct DrawingReadSession {
    snapshot: DrawingSnapshot,
    document: CadDocument,
    diagnostics: Vec<ReadDiagnostic>,
}

impl DrawingReadSession {
    fn document(&self) -> &CadDocument {
        // Retain the immutable capture for future low-level evidence adapters.
        let _snapshot = &self.snapshot;
        &self.document
    }

    pub fn xref_session(
        &self,
    ) -> Result<xrefs::XrefReadSession, super::contract::xrefs::XrefError> {
        xrefs::XrefReadSession::from_drawing(self.snapshot.clone(), self.document())
    }

    fn ensure_block_diagnostic_fidelity(&self) -> Result<(), blocks::BlockReadError> {
        if self.diagnostics.iter().any(|diagnostic| {
            !matches!(diagnostic.kind, ReadDiagnosticKind::Warning)
                || !is_proven_safe_read_warning(&diagnostic.message)
        }) {
            return Err(blocks::BlockReadError::new(
                "unsupported_block_data",
                "reader reported an unsupported diagnostic that may affect block interpretation",
            ));
        }
        Ok(())
    }

    pub(super) fn ensure_drawing_diagnostic_fidelity(
        &self,
    ) -> Result<(), drawing::DrawingReadError> {
        if self.diagnostics.iter().any(|diagnostic| {
            !matches!(diagnostic.kind, ReadDiagnosticKind::Warning)
                || !is_proven_safe_read_warning(&diagnostic.message)
        }) {
            return Err(drawing::DrawingReadError::new(
                "unsupported_drawing_data",
                "reader reported an unsupported diagnostic that may affect drawing interpretation",
            ));
        }
        Ok(())
    }

    pub(super) fn ensure_format_facts_diagnostic_fidelity(
        &self,
    ) -> Result<(), FormatFactsReadError> {
        if self.diagnostics.iter().any(|diagnostic| {
            !matches!(diagnostic.kind, ReadDiagnosticKind::Warning)
                || !is_proven_safe_read_warning(&diagnostic.message)
        }) {
            return Err(format_facts::FormatFactsReadError::unsupported_diagnostic());
        }
        Ok(())
    }

    pub(super) fn ensure_entity_diagnostic_fidelity(
        &self,
    ) -> Result<(), entities::EntityReadError> {
        if self.diagnostics.iter().any(|diagnostic| {
            !matches!(diagnostic.kind, ReadDiagnosticKind::Warning)
                || !is_proven_safe_read_warning(&diagnostic.message)
        }) {
            return Err(entities::EntityReadError::new(
                "unsupported_entity_data",
                "reader reported an unsupported diagnostic that may affect entity interpretation",
            ));
        }
        Ok(())
    }

    pub(super) fn ensure_title_block_diagnostic_fidelity(
        &self,
    ) -> Result<(), title_blocks::TitleBlockReadError> {
        if self.diagnostics.iter().any(|diagnostic| {
            !matches!(diagnostic.kind, ReadDiagnosticKind::Warning)
                || !is_proven_safe_read_warning(&diagnostic.message)
        }) {
            return Err(title_blocks::TitleBlockReadError::new(
                "unsupported_title_block_data",
                "reader reported an unsupported diagnostic that may affect title-block interpretation",
            ));
        }
        Ok(())
    }

    pub(super) fn ensure_text_diagnostic_fidelity(&self) -> Result<(), text::TextReadError> {
        if self.diagnostics.iter().any(|diagnostic| {
            !matches!(diagnostic.kind, ReadDiagnosticKind::Warning)
                || !is_proven_safe_read_warning(&diagnostic.message)
        }) {
            return Err(text::TextReadError::new(
                "unsupported_text_data",
                "reader reported an unsupported diagnostic that may affect text interpretation",
            ));
        }
        Ok(())
    }

    pub(super) fn ensure_layer_diagnostic_fidelity(&self) -> Result<(), layers::LayerReadError> {
        if self.diagnostics.iter().any(|diagnostic| {
            !matches!(diagnostic.kind, ReadDiagnosticKind::Warning)
                || !is_proven_safe_read_warning(&diagnostic.message)
        }) {
            return Err(layers::LayerReadError::new(
                "unsupported_layer_data",
                "reader reported an unsupported diagnostic that may affect layer interpretation",
            ));
        }
        Ok(())
    }

    pub(super) fn ensure_layout_diagnostic_fidelity(&self) -> Result<(), layouts::LayoutReadError> {
        if self.diagnostics.iter().any(|diagnostic| {
            !matches!(diagnostic.kind, ReadDiagnosticKind::Warning)
                || !is_proven_safe_read_warning(&diagnostic.message)
        }) {
            return Err(layouts::LayoutReadError::new(
                "unsupported_layout_data",
                "reader reported an unsupported diagnostic that may affect layout interpretation",
            ));
        }
        Ok(())
    }

    pub(super) fn ensure_symbol_diagnostic_fidelity(&self) -> Result<(), symbols::SymbolReadError> {
        if self.diagnostics.iter().any(|diagnostic| {
            !matches!(diagnostic.kind, ReadDiagnosticKind::Warning)
                || !is_proven_safe_read_warning(&diagnostic.message)
        }) {
            return Err(symbols::SymbolReadError::new(
                "unsupported_symbol_data",
                "reader reported an unsupported diagnostic that may affect symbol interpretation",
            ));
        }
        Ok(())
    }

    pub fn list_blocks(&self) -> Result<Vec<BlockInfo>, blocks::BlockReadError> {
        self.ensure_block_diagnostic_fidelity()?;
        Ok(blocks::list_blocks(self.document()))
    }

    pub fn get_drawing(&self) -> Result<DrawingSummary, drawing::DrawingReadError> {
        self.ensure_drawing_diagnostic_fidelity()?;
        drawing::get_drawing(self.document())
    }

    pub fn format_facts(&self) -> Result<DrawingFormatFacts, FormatFactsReadError> {
        self.ensure_format_facts_diagnostic_fidelity()?;
        Ok(format_facts::read_format_facts(self.document()))
    }

    pub fn list_block_definitions(
        &self,
    ) -> Result<Vec<BlockDefinitionRecord>, blocks::BlockReadError> {
        self.ensure_block_diagnostic_fidelity()?;
        blocks::list_block_definitions(self.document())
    }

    pub fn get_block_definition(
        &self,
        selector: &BlockDefinitionSelector,
    ) -> Result<BlockDefinitionRecord, blocks::BlockReadError> {
        self.ensure_block_diagnostic_fidelity()?;
        blocks::get_block_definition(self.document(), selector)
    }

    pub fn list_block_inserts(&self) -> Result<Vec<BlockInsertRecord>, blocks::BlockReadError> {
        self.ensure_block_diagnostic_fidelity()?;
        blocks::list_block_inserts(self.document())
    }

    pub fn get_block_insert(
        &self,
        selector: &BlockInsertSelector,
    ) -> Result<BlockInsertRecord, blocks::BlockReadError> {
        self.ensure_block_diagnostic_fidelity()?;
        blocks::get_block_insert(self.document(), selector)
    }

    pub fn list_entities(
        &self,
        options: &EntityListOptions,
    ) -> Result<EntityListResult, entities::EntityReadError> {
        self.ensure_entity_diagnostic_fidelity()?;
        entities::list_entities(self.document(), options)
    }

    pub fn get_entity(
        &self,
        selector: &EntitySelector,
    ) -> Result<EntityRecord, entities::EntityReadError> {
        self.ensure_entity_diagnostic_fidelity()?;
        entities::get_entity(self.document(), &selector.handle)
    }

    pub fn dump_text(&self) -> Result<Vec<TextItem>, text::TextReadError> {
        self.ensure_text_diagnostic_fidelity()?;
        Ok(text::dump_text(self.document()))
    }

    pub fn list_text(
        &self,
        options: &TextListOptions,
    ) -> Result<Vec<TextRecord>, text::TextReadError> {
        self.ensure_text_diagnostic_fidelity()?;
        text::list_text(self.document(), options)
    }

    pub fn get_text(&self, selector: &TextSelector) -> Result<TextRecord, text::TextReadError> {
        self.ensure_text_diagnostic_fidelity()?;
        text::get_text(self.document(), selector)
    }

    pub fn list_layers(&self) -> Result<Vec<LayerRecord>, layers::LayerReadError> {
        self.ensure_layer_diagnostic_fidelity()?;
        layers::list_layers(self.document(), &self.snapshot)
    }

    pub fn get_layer(
        &self,
        selector: &LayerSelector,
    ) -> Result<LayerRecord, layers::LayerReadError> {
        self.ensure_layer_diagnostic_fidelity()?;
        layers::get_layer(self.document(), &self.snapshot, selector)
    }

    pub fn read_title_blocks(
        &self,
    ) -> Result<Vec<TitleBlockInfo>, title_blocks::TitleBlockReadError> {
        self.ensure_title_block_diagnostic_fidelity()?;
        Ok(title_blocks::read_title_blocks(self.document()))
    }

    pub fn list_layouts(&self) -> Result<Vec<LayoutInfo>, layouts::LayoutReadError> {
        self.ensure_layout_diagnostic_fidelity()?;
        Ok(layouts::list_layouts(self.document()))
    }

    pub fn get_layout(
        &self,
        selector: &LayoutSelector,
    ) -> Result<LayoutRecord, layouts::LayoutReadError> {
        self.ensure_layout_diagnostic_fidelity()?;
        layouts::get_layout(self.document(), selector)
    }

    pub fn list_layout_viewports(
        &self,
        selector: Option<&LayoutSelector>,
    ) -> Result<Vec<LayoutViewportRecord>, layouts::LayoutReadError> {
        self.ensure_layout_diagnostic_fidelity()?;
        layouts::list_layout_viewports(self.document(), selector)
    }

    pub fn get_layout_viewport(
        &self,
        selector: &LayoutViewportSelector,
    ) -> Result<LayoutViewportRecord, layouts::LayoutReadError> {
        self.ensure_layout_diagnostic_fidelity()?;
        layouts::get_layout_viewport(self.document(), &selector.handle)
    }

    pub fn list_plot_settings(&self) -> Result<Vec<PlotSettingRecord>, layouts::LayoutReadError> {
        self.ensure_layout_diagnostic_fidelity()?;
        layouts::list_plot_settings(self.document())
    }

    pub fn get_plot_setting(
        &self,
        selector: &PlotSettingSelector,
    ) -> Result<PlotSettingRecord, layouts::LayoutReadError> {
        self.ensure_layout_diagnostic_fidelity()?;
        layouts::get_plot_setting(self.document(), selector)
    }

    pub fn list_linetypes(&self) -> Result<Vec<LinetypeRecord>, symbols::SymbolReadError> {
        self.ensure_symbol_diagnostic_fidelity()?;
        symbols::list_linetypes(self.document())
    }

    pub fn get_linetype(
        &self,
        selector: &SymbolSelector,
    ) -> Result<LinetypeRecord, symbols::SymbolReadError> {
        self.ensure_symbol_diagnostic_fidelity()?;
        symbols::get_linetype(self.document(), selector)
    }

    pub fn list_text_styles(&self) -> Result<Vec<TextStyleRecord>, symbols::SymbolReadError> {
        self.ensure_symbol_diagnostic_fidelity()?;
        symbols::list_text_styles(self.document())
    }

    pub fn get_text_style(
        &self,
        selector: &SymbolSelector,
    ) -> Result<TextStyleRecord, symbols::SymbolReadError> {
        self.ensure_symbol_diagnostic_fidelity()?;
        symbols::get_text_style(self.document(), selector)
    }

    pub fn list_dimension_styles(
        &self,
    ) -> Result<Vec<DimensionStyleRecord>, symbols::SymbolReadError> {
        self.ensure_symbol_diagnostic_fidelity()?;
        symbols::list_dimension_styles(self.document())
    }

    pub fn get_dimension_style(
        &self,
        selector: &SymbolSelector,
    ) -> Result<DimensionStyleRecord, symbols::SymbolReadError> {
        self.ensure_symbol_diagnostic_fidelity()?;
        symbols::get_dimension_style(self.document(), selector)
    }

    pub fn list_named_views(&self) -> Result<Vec<NamedViewRecord>, symbols::SymbolReadError> {
        self.ensure_symbol_diagnostic_fidelity()?;
        symbols::list_named_views(self.document())
    }

    pub fn get_named_view(
        &self,
        selector: &SymbolSelector,
    ) -> Result<NamedViewRecord, symbols::SymbolReadError> {
        self.ensure_symbol_diagnostic_fidelity()?;
        symbols::get_named_view(self.document(), selector)
    }

    pub fn list_named_ucs(&self) -> Result<Vec<NamedUcsRecord>, symbols::SymbolReadError> {
        self.ensure_symbol_diagnostic_fidelity()?;
        symbols::list_named_ucs(self.document())
    }

    pub fn get_named_ucs(
        &self,
        selector: &SymbolSelector,
    ) -> Result<NamedUcsRecord, symbols::SymbolReadError> {
        self.ensure_symbol_diagnostic_fidelity()?;
        symbols::get_named_ucs(self.document(), selector)
    }

    #[cfg(test)]
    pub(super) fn into_backend_document(self) -> CadDocument {
        self.document
    }

    #[cfg(test)]
    pub(super) fn snapshot(&self) -> &DrawingSnapshot {
        &self.snapshot
    }

    #[cfg(test)]
    pub(super) fn diagnostics(&self) -> &[ReadDiagnostic] {
        &self.diagnostics
    }
}

fn is_proven_safe_read_warning(message: &str) -> bool {
    let fixed_telemetry = [
        "Reading DWG file version:",
        "AC15 file header: 6 locator records,",
        "AC18 inner header:",
        "AC1021 header:",
        "AC1021 Header CRC-64 extracted:",
        "AC1021 CRC Seeds:",
        "AC1021 Pages Map CRC:",
        "AC1021 Sections Map CRC:",
        "  Section '",
        "AcDs: attached ",
    ]
    .iter()
    .any(|prefix| message.starts_with(prefix));
    fixed_telemetry
        || [
            ("AC18: Read ", " page records from page map"),
            ("AC18: Read ", " section descriptors from section map"),
            ("AC1021: Read ", " page records from page map"),
            ("AC1021: Read ", " section descriptors from section map"),
        ]
        .iter()
        .any(|(prefix, suffix)| warning_reports_positive_count(message, prefix, suffix))
}

fn warning_reports_positive_count(message: &str, prefix: &str, suffix: &str) -> bool {
    message
        .strip_prefix(prefix)
        .and_then(|value| value.strip_suffix(suffix))
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|count| count > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use acadrust::{
        entities::{EntityType, Text},
        types::{Handle, Vector3},
    };

    fn dxf_fixture_path() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/xrefs/portable-evidence-ascii.dxf")
    }

    fn dwg_fixture_path() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/corpus/open/acadsharp/dynamic-blocks/BLOCKVISIBILITYPARAMETER.dwg")
    }

    fn title_block_fixture_path() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/corpus/open/project/generic-title-block-ascii.dxf")
    }

    #[test]
    fn reader_session_constructor_inventory_remains_closed() {
        let source = include_str!("session.rs");
        let marker = ["pub fn ", "open_"].concat();
        let path_entrypoint = ["pub fn ", "open_path("].concat();
        let snapshot_entrypoint = ["pub fn ", "open_snapshot("].concat();

        assert_eq!(source.matches(&marker).count(), 2);
        assert_eq!(source.matches(&path_entrypoint).count(), 1);
        assert_eq!(source.matches(&snapshot_entrypoint).count(), 1);
    }

    #[test]
    fn reader_has_exactly_the_two_accepted_open_entrypoints() {
        let source = include_str!("session.rs");
        let marker = ["pub fn ", "open_"].concat();
        let mut entrypoints = source
            .match_indices(&marker)
            .filter_map(|(offset, _)| {
                let remainder = &source[offset + marker.len()..];
                remainder
                    .split_once('(')
                    .map(|(suffix, _)| format!("open_{suffix}"))
            })
            .collect::<Vec<_>>();
        entrypoints.sort();
        assert_eq!(
            entrypoints,
            vec!["open_path".to_string(), "open_snapshot".to_string()]
        );
    }

    #[test]
    fn path_and_snapshot_entrypoints_decode_the_same_capture() {
        let path = dwg_fixture_path();
        let bytes = std::fs::read(&path).unwrap();
        let captures = std::cell::Cell::new(0);
        let from_path = Reader::open_path_with_capture(&path, |captured_path| {
            assert_eq!(captured_path, path);
            captures.set(captures.get() + 1);
            Ok(bytes.clone())
        })
        .unwrap();
        let snapshot = DrawingSnapshot::new(DrawingFormat::Dwg, bytes.clone());
        let from_snapshot = Reader::open_snapshot(snapshot).unwrap();

        assert_eq!(captures.get(), 1);
        assert_eq!(
            serde_json::to_value(from_path.list_block_definitions().unwrap()).unwrap(),
            serde_json::to_value(from_snapshot.list_block_definitions().unwrap()).unwrap()
        );
        assert_eq!(
            serde_json::to_value(from_path.get_drawing().unwrap()).unwrap(),
            serde_json::to_value(from_snapshot.get_drawing().unwrap()).unwrap()
        );
        assert_eq!(
            from_path.format_facts().unwrap(),
            from_snapshot.format_facts().unwrap()
        );
        assert_eq!(
            serde_json::to_value(from_path.list_block_inserts().unwrap()).unwrap(),
            serde_json::to_value(from_snapshot.list_block_inserts().unwrap()).unwrap()
        );
        let entity_options = EntityListOptions::default();
        let path_entities = from_path.list_entities(&entity_options).unwrap();
        let snapshot_entities = from_snapshot.list_entities(&entity_options).unwrap();
        assert_eq!(
            serde_json::to_value(&path_entities).unwrap(),
            serde_json::to_value(&snapshot_entities).unwrap()
        );
        let selector = EntitySelector {
            handle: path_entities
                .items
                .first()
                .expect("qualification fixture must contain an entity")
                .handle
                .clone(),
        };
        assert_eq!(
            serde_json::to_value(from_path.get_entity(&selector).unwrap()).unwrap(),
            serde_json::to_value(from_snapshot.get_entity(&selector).unwrap()).unwrap()
        );
        assert_eq!(
            serde_json::to_value(from_path.dump_text().unwrap()).unwrap(),
            serde_json::to_value(from_snapshot.dump_text().unwrap()).unwrap()
        );
        let text_options = TextListOptions::default();
        assert_eq!(
            serde_json::to_value(from_path.list_text(&text_options).unwrap()).unwrap(),
            serde_json::to_value(from_snapshot.list_text(&text_options).unwrap()).unwrap()
        );
        let path_layouts = from_path.list_layouts().unwrap();
        let snapshot_layouts = from_snapshot.list_layouts().unwrap();
        assert_eq!(
            serde_json::to_value(&path_layouts).unwrap(),
            serde_json::to_value(&snapshot_layouts).unwrap()
        );
        let layout_selector = LayoutSelector {
            handle: None,
            name: Some(
                path_layouts
                    .first()
                    .expect("qualification fixture must contain a layout")
                    .name
                    .clone(),
            ),
        };
        assert_eq!(
            serde_json::to_value(from_path.get_layout(&layout_selector).unwrap()).unwrap(),
            serde_json::to_value(from_snapshot.get_layout(&layout_selector).unwrap()).unwrap()
        );
        let path_viewports = from_path.list_layout_viewports(None).unwrap();
        let snapshot_viewports = from_snapshot.list_layout_viewports(None).unwrap();
        assert_eq!(
            serde_json::to_value(&path_viewports).unwrap(),
            serde_json::to_value(&snapshot_viewports).unwrap()
        );
        if let Some(viewport) = path_viewports.first() {
            let selector = LayoutViewportSelector {
                handle: viewport.handle.clone(),
            };
            assert_eq!(
                serde_json::to_value(from_path.get_layout_viewport(&selector).unwrap()).unwrap(),
                serde_json::to_value(from_snapshot.get_layout_viewport(&selector).unwrap())
                    .unwrap()
            );
        }
        let path_plot_settings = from_path.list_plot_settings().unwrap();
        let snapshot_plot_settings = from_snapshot.list_plot_settings().unwrap();
        assert_eq!(
            serde_json::to_value(&path_plot_settings).unwrap(),
            serde_json::to_value(&snapshot_plot_settings).unwrap()
        );
        if let Some(setting) = path_plot_settings.first() {
            let selector = PlotSettingSelector {
                handle: Some(setting.handle.clone()),
                name: Some(setting.name.clone()),
            };
            assert_eq!(
                serde_json::to_value(from_path.get_plot_setting(&selector).unwrap()).unwrap(),
                serde_json::to_value(from_snapshot.get_plot_setting(&selector).unwrap()).unwrap()
            );
        }
        assert_eq!(
            from_path.list_linetypes().unwrap(),
            from_snapshot.list_linetypes().unwrap()
        );
        assert_eq!(
            from_path.list_text_styles().unwrap(),
            from_snapshot.list_text_styles().unwrap()
        );
        assert_eq!(
            from_path.list_dimension_styles().unwrap(),
            from_snapshot.list_dimension_styles().unwrap()
        );
        assert_eq!(
            from_path.list_named_views().unwrap(),
            from_snapshot.list_named_views().unwrap()
        );
        assert_eq!(
            from_path.list_named_ucs().unwrap(),
            from_snapshot.list_named_ucs().unwrap()
        );
        assert_eq!(
            serde_json::to_value(from_path.list_layers().unwrap()).unwrap(),
            serde_json::to_value(from_snapshot.list_layers().unwrap()).unwrap()
        );
        assert_eq!(from_path.diagnostics(), from_snapshot.diagnostics());
        assert_eq!(from_path.snapshot().bytes().as_ref(), bytes.as_slice());
    }

    #[test]
    fn layer_path_and_snapshot_entrypoints_use_the_same_dxf_direct_fields() {
        let path = title_block_fixture_path();
        let bytes = std::fs::read(&path).unwrap();
        let from_path = Reader::open_path(&path).unwrap();
        let from_snapshot =
            Reader::open_snapshot(DrawingSnapshot::new(DrawingFormat::Dxf, bytes)).unwrap();

        assert_eq!(
            serde_json::to_value(from_path.list_layers().unwrap()).unwrap(),
            serde_json::to_value(from_snapshot.list_layers().unwrap()).unwrap()
        );
        let selector = LayerSelector {
            name: Some("0".to_string()),
            ..Default::default()
        };
        assert_eq!(
            serde_json::to_value(from_path.get_layer(&selector).unwrap()).unwrap(),
            serde_json::to_value(from_snapshot.get_layer(&selector).unwrap()).unwrap()
        );
    }

    #[test]
    fn path_entrypoint_is_independent_of_later_file_changes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("drawing.dxf");
        std::fs::copy(dxf_fixture_path(), &path).unwrap();

        let session = Reader::open_path(&path).unwrap();
        let blocks_before = serde_json::to_value(session.list_blocks().unwrap()).unwrap();
        let layers_before = serde_json::to_value(session.list_layers().unwrap()).unwrap();
        std::fs::write(&path, b"not a drawing").unwrap();

        assert_eq!(
            serde_json::to_value(session.list_blocks().unwrap()).unwrap(),
            blocks_before
        );
        assert_eq!(
            serde_json::to_value(session.list_layers().unwrap()).unwrap(),
            layers_before
        );
    }

    #[test]
    fn title_block_path_and_snapshot_entrypoints_decode_the_same_split_records() {
        let path = title_block_fixture_path();
        let bytes = std::fs::read(&path).unwrap();
        let from_path = Reader::open_path(&path).unwrap();
        let from_snapshot =
            Reader::open_snapshot(DrawingSnapshot::new(DrawingFormat::Dxf, bytes)).unwrap();

        let path_records = from_path.read_title_blocks().unwrap();
        let snapshot_records = from_snapshot.read_title_blocks().unwrap();
        assert_eq!(path_records, snapshot_records);
        assert_eq!(
            path_records
                .iter()
                .map(|record| record.block_name.as_str())
                .collect::<Vec<_>>(),
            ["OTHER_TITLE_BLOCK", "AUTOCAD_MCP_GENERIC"]
        );
        assert!(path_records
            .iter()
            .all(|record| record.attribute_arrays.is_empty()));
    }

    #[test]
    fn declared_format_must_match_parseable_content() {
        let mut truncated_binary_dxf = b"AutoCAD Binary DXF\r\n\x1a\0".to_vec();
        truncated_binary_dxf.extend_from_slice(&[0, 0]);
        let mut header_only_dwg = vec![0; 0x61];
        header_only_dwg[..6].copy_from_slice(b"AC1015");

        for snapshot in [
            DrawingSnapshot::new(DrawingFormat::Dwg, b"not a DWG".to_vec()),
            DrawingSnapshot::new(DrawingFormat::Dxf, b"not a DXF".to_vec()),
            DrawingSnapshot::new(DrawingFormat::Dxf, b"999\nSECTION EOF\n".to_vec()),
            DrawingSnapshot::new(DrawingFormat::Dxf, b"0\nSECTION\n0\nEOF\n".to_vec()),
            DrawingSnapshot::new(
                DrawingFormat::Dxf,
                b"0\nsection\n2\nHEADER\n0\nENDSEC\n0\nEOF\n".to_vec(),
            ),
            DrawingSnapshot::new(
                DrawingFormat::Dxf,
                b"0\nSECTION \n2\nHEADER\n0\nENDSEC\n0\nEOF\n".to_vec(),
            ),
            DrawingSnapshot::new(DrawingFormat::Dxf, truncated_binary_dxf),
            DrawingSnapshot::new(DrawingFormat::Dwg, header_only_dwg),
            DrawingSnapshot::new(
                DrawingFormat::Dwg,
                std::fs::read(dxf_fixture_path()).unwrap(),
            ),
            DrawingSnapshot::new(
                DrawingFormat::Dxf,
                std::fs::read(dwg_fixture_path()).unwrap(),
            ),
        ] {
            let error = match Reader::open_snapshot(snapshot) {
                Ok(_) => panic!("mismatched or invalid drawing content must fail"),
                Err(error) => error,
            };

            assert_eq!(error.kind(), super::super::ReadErrorKind::InvalidDrawing);
        }
    }

    #[test]
    fn path_error_categories_preserve_extension_precedence() {
        let unsupported = match Reader::open_path(Path::new("missing.xyz")) {
            Ok(_) => panic!("unsupported extension must fail before filesystem access"),
            Err(error) => error,
        };
        assert_eq!(
            unsupported.kind(),
            super::super::ReadErrorKind::UnsupportedFormat
        );
        assert_eq!(
            unsupported.message(),
            "unsupported extension \"xyz\"; expected .dxf or .dwg"
        );
        let no_extension = match Reader::open_path(Path::new("missing")) {
            Ok(_) => panic!("missing extension must fail before filesystem access"),
            Err(error) => error,
        };
        assert_eq!(
            no_extension.kind(),
            super::super::ReadErrorKind::UnsupportedFormat
        );

        let directory = tempfile::tempdir().unwrap();
        let missing = match Reader::open_path(&directory.path().join("missing.dwg")) {
            Ok(_) => panic!("missing supported drawing must fail"),
            Err(error) => error,
        };
        assert_eq!(missing.kind(), super::super::ReadErrorKind::NotFound);

        let unreadable_path = directory.path().join("directory.dwg");
        std::fs::create_dir(&unreadable_path).unwrap();
        let unreadable = match Reader::open_path(&unreadable_path) {
            Ok(_) => panic!("a directory cannot be captured as a drawing"),
            Err(error) => error,
        };
        assert_eq!(unreadable.kind(), super::super::ReadErrorKind::Unreadable);
    }

    #[test]
    fn block_family_accepts_only_proven_safe_backend_telemetry() {
        let mut session = Reader::open_path(&dwg_fixture_path()).unwrap();
        let definition = session
            .list_block_definitions()
            .unwrap()
            .into_iter()
            .next()
            .expect("qualification fixture must contain a block definition");
        let insert = session
            .list_block_inserts()
            .unwrap()
            .into_iter()
            .next()
            .expect("qualification fixture must contain a block insert");
        session.diagnostics.push(ReadDiagnostic {
            kind: ReadDiagnosticKind::Warning,
            message: "Reading DWG file version: AC1027 (AC24)".to_string(),
        });
        session.diagnostics.push(ReadDiagnostic {
            kind: ReadDiagnosticKind::Warning,
            message: "AC18: Read 3 page records from page map".to_string(),
        });
        assert!(session.list_blocks().is_ok());
        assert!(session.list_block_definitions().is_ok());
        assert!(session
            .get_block_definition(&BlockDefinitionSelector {
                handle: Some(definition.handle),
                name: Some(definition.name),
            })
            .is_ok());
        assert!(session.list_block_inserts().is_ok());
        assert!(session
            .get_block_insert(&BlockInsertSelector {
                handle: insert.handle,
            })
            .is_ok());

        for diagnostic in [
            ReadDiagnostic {
                kind: ReadDiagnosticKind::Warning,
                message: "Failed to read handles: backend-specific detail".to_string(),
            },
            ReadDiagnostic {
                kind: ReadDiagnosticKind::Warning,
                message: "AC18: Read 0 page records from page map".to_string(),
            },
            ReadDiagnostic {
                kind: ReadDiagnosticKind::NotSupported,
                message: "backend-specific detail must remain internal".to_string(),
            },
            ReadDiagnostic {
                kind: ReadDiagnosticKind::NotImplemented,
                message: "backend-specific detail must remain internal".to_string(),
            },
        ] {
            let mut session = Reader::open_path(&dxf_fixture_path()).unwrap();
            session.diagnostics.push(diagnostic);
            for error in [
                session.list_blocks().unwrap_err(),
                session.list_block_definitions().unwrap_err(),
                session
                    .get_block_definition(&BlockDefinitionSelector::default())
                    .unwrap_err(),
                session.list_block_inserts().unwrap_err(),
                session
                    .get_block_insert(&BlockInsertSelector {
                        handle: "0".to_string(),
                    })
                    .unwrap_err(),
            ] {
                assert_eq!(error.code(), "unsupported_block_data");
                assert!(!error.message().contains("backend-specific detail"));
            }
        }
    }

    #[test]
    fn drawing_family_accepts_only_proven_safe_backend_telemetry() {
        let mut session = Reader::open_path(&dwg_fixture_path()).unwrap();
        session.diagnostics.push(ReadDiagnostic {
            kind: ReadDiagnosticKind::Warning,
            message: "Reading DWG file version: AC1027 (AC24)".to_string(),
        });
        session.diagnostics.push(ReadDiagnostic {
            kind: ReadDiagnosticKind::Warning,
            message: "AC18: Read 3 page records from page map".to_string(),
        });
        assert!(session.ensure_drawing_diagnostic_fidelity().is_ok());
        assert!(session.get_drawing().is_ok());

        for diagnostic in [
            ReadDiagnostic {
                kind: ReadDiagnosticKind::Warning,
                message: "Failed to read handles: backend-specific detail".to_string(),
            },
            ReadDiagnostic {
                kind: ReadDiagnosticKind::Warning,
                message: "AC18: Read 0 page records from page map".to_string(),
            },
            ReadDiagnostic {
                kind: ReadDiagnosticKind::NotSupported,
                message: "backend-specific detail must remain internal".to_string(),
            },
            ReadDiagnostic {
                kind: ReadDiagnosticKind::NotImplemented,
                message: "backend-specific detail must remain internal".to_string(),
            },
        ] {
            let mut session = Reader::open_path(&dwg_fixture_path()).unwrap();
            session.diagnostics.push(diagnostic);
            for error in [
                session.ensure_drawing_diagnostic_fidelity().unwrap_err(),
                session.get_drawing().unwrap_err(),
            ] {
                assert_eq!(error.code(), "unsupported_drawing_data");
                assert_eq!(
                    error.message(),
                    "reader reported an unsupported diagnostic that may affect drawing interpretation"
                );
                assert!(!error.message().contains("backend-specific detail"));
            }
        }
    }

    #[test]
    fn format_facts_query_accepts_only_proven_safe_backend_telemetry() {
        let bytes = std::fs::read(dxf_fixture_path()).unwrap();
        let mut session =
            Reader::open_snapshot(DrawingSnapshot::new(DrawingFormat::Dxf, bytes)).unwrap();
        assert_eq!(
            session.format_facts().unwrap(),
            DrawingFormatFacts {
                drawing_version: "AC1027".to_string(),
                code_page: "ANSI_1252".to_string(),
            }
        );

        session.diagnostics.push(ReadDiagnostic {
            kind: ReadDiagnosticKind::Warning,
            message: "Reading DWG file version: AC1027 (AC24)".to_string(),
        });
        session.diagnostics.push(ReadDiagnostic {
            kind: ReadDiagnosticKind::Warning,
            message: "AC18: Read 3 page records from page map".to_string(),
        });
        assert!(session.ensure_format_facts_diagnostic_fidelity().is_ok());
        assert!(session.format_facts().is_ok());

        for diagnostic in [
            ReadDiagnostic {
                kind: ReadDiagnosticKind::Warning,
                message: "Failed to read handles: backend-specific detail".to_string(),
            },
            ReadDiagnostic {
                kind: ReadDiagnosticKind::Warning,
                message: "AC18: Read 0 page records from page map".to_string(),
            },
            ReadDiagnostic {
                kind: ReadDiagnosticKind::NotSupported,
                message: "backend-specific detail must remain internal".to_string(),
            },
            ReadDiagnostic {
                kind: ReadDiagnosticKind::NotImplemented,
                message: "backend-specific detail must remain internal".to_string(),
            },
        ] {
            let bytes = std::fs::read(dxf_fixture_path()).unwrap();
            let mut session =
                Reader::open_snapshot(DrawingSnapshot::new(DrawingFormat::Dxf, bytes)).unwrap();
            session.diagnostics.push(diagnostic);
            for error in [
                session
                    .ensure_format_facts_diagnostic_fidelity()
                    .unwrap_err(),
                session.format_facts().unwrap_err(),
            ] {
                assert_eq!(error.code(), "unsupported_format_facts_data");
                assert_eq!(
                    error.message(),
                    "reader reported an unsupported diagnostic that may affect drawing format facts"
                );
                assert!(!error.message().contains("backend-specific detail"));
            }
        }
    }

    #[test]
    fn entity_family_accepts_only_proven_safe_backend_telemetry() {
        let options = EntityListOptions::default();
        let mut session = Reader::open_path(&dwg_fixture_path()).unwrap();
        let handle = session
            .list_entities(&options)
            .unwrap()
            .items
            .first()
            .expect("qualification fixture must contain an entity")
            .handle
            .clone();
        let selector = EntitySelector { handle };
        session.diagnostics.push(ReadDiagnostic {
            kind: ReadDiagnosticKind::Warning,
            message: "Reading DWG file version: AC1027 (AC24)".to_string(),
        });
        session.diagnostics.push(ReadDiagnostic {
            kind: ReadDiagnosticKind::Warning,
            message: "AC18: Read 3 page records from page map".to_string(),
        });
        assert!(session.list_entities(&options).is_ok());
        assert!(session.get_entity(&selector).is_ok());

        for diagnostic in [
            ReadDiagnostic {
                kind: ReadDiagnosticKind::Warning,
                message: "Failed to read handles: backend-specific detail".to_string(),
            },
            ReadDiagnostic {
                kind: ReadDiagnosticKind::Warning,
                message: "AC18: Read 0 page records from page map".to_string(),
            },
            ReadDiagnostic {
                kind: ReadDiagnosticKind::NotSupported,
                message: "backend-specific detail must remain internal".to_string(),
            },
            ReadDiagnostic {
                kind: ReadDiagnosticKind::NotImplemented,
                message: "backend-specific detail must remain internal".to_string(),
            },
        ] {
            let mut session = Reader::open_path(&dwg_fixture_path()).unwrap();
            let handle = session
                .list_entities(&options)
                .unwrap()
                .items
                .first()
                .expect("qualification fixture must contain an entity")
                .handle
                .clone();
            session.diagnostics.push(diagnostic);
            for error in [
                session.list_entities(&options).unwrap_err(),
                session.get_entity(&EntitySelector { handle }).unwrap_err(),
            ] {
                assert_eq!(error.code(), "unsupported_entity_data");
                assert_eq!(
                    error.message(),
                    "reader reported an unsupported diagnostic that may affect entity interpretation"
                );
                assert!(!error.message().contains("backend-specific detail"));
            }
        }
    }

    #[test]
    fn symbol_family_accepts_only_proven_safe_backend_telemetry() {
        let mut session = Reader::open_path(&dwg_fixture_path()).unwrap();
        session.diagnostics.push(ReadDiagnostic {
            kind: ReadDiagnosticKind::Warning,
            message: "Reading DWG file version: AC1027 (AC24)".to_string(),
        });
        session.diagnostics.push(ReadDiagnostic {
            kind: ReadDiagnosticKind::Warning,
            message: "AC18: Read 3 page records from page map".to_string(),
        });
        assert!(session.ensure_symbol_diagnostic_fidelity().is_ok());
        assert!(session.list_linetypes().is_ok());
        assert!(session.list_text_styles().is_ok());
        assert!(session.list_dimension_styles().is_ok());
        assert!(session.list_named_views().is_ok());
        assert!(session.list_named_ucs().is_ok());

        for diagnostic in [
            ReadDiagnostic {
                kind: ReadDiagnosticKind::Warning,
                message: "Failed to read handles: backend-specific detail".to_string(),
            },
            ReadDiagnostic {
                kind: ReadDiagnosticKind::Warning,
                message: "AC18: Read 0 page records from page map".to_string(),
            },
            ReadDiagnostic {
                kind: ReadDiagnosticKind::NotSupported,
                message: "backend-specific detail must remain internal".to_string(),
            },
            ReadDiagnostic {
                kind: ReadDiagnosticKind::NotImplemented,
                message: "backend-specific detail must remain internal".to_string(),
            },
        ] {
            let mut session = Reader::open_path(&dwg_fixture_path()).unwrap();
            session.diagnostics.push(diagnostic);
            let selector = SymbolSelector::default();
            for error in [
                session.list_linetypes().unwrap_err(),
                session.get_linetype(&selector).unwrap_err(),
                session.list_text_styles().unwrap_err(),
                session.get_text_style(&selector).unwrap_err(),
                session.list_dimension_styles().unwrap_err(),
                session.get_dimension_style(&selector).unwrap_err(),
                session.list_named_views().unwrap_err(),
                session.get_named_view(&selector).unwrap_err(),
                session.list_named_ucs().unwrap_err(),
                session.get_named_ucs(&selector).unwrap_err(),
            ] {
                assert_eq!(error.code(), "unsupported_symbol_data");
                assert_eq!(
                    error.message(),
                    "reader reported an unsupported diagnostic that may affect symbol interpretation"
                );
                assert!(!error.message().contains("backend-specific detail"));
            }
        }
    }

    #[test]
    fn title_block_family_accepts_only_proven_safe_backend_telemetry() {
        let mut session = Reader::open_path(&title_block_fixture_path()).unwrap();
        session.diagnostics.push(ReadDiagnostic {
            kind: ReadDiagnosticKind::Warning,
            message: "Reading DWG file version: AC1027 (AC24)".to_string(),
        });
        session.diagnostics.push(ReadDiagnostic {
            kind: ReadDiagnosticKind::Warning,
            message: "AC18: Read 3 page records from page map".to_string(),
        });
        assert!(session.ensure_title_block_diagnostic_fidelity().is_ok());
        assert_eq!(session.read_title_blocks().unwrap().len(), 2);

        for diagnostic in [
            ReadDiagnostic {
                kind: ReadDiagnosticKind::Warning,
                message: "Failed to read handles: backend-specific detail".to_string(),
            },
            ReadDiagnostic {
                kind: ReadDiagnosticKind::Warning,
                message: "AC18: Read 0 page records from page map".to_string(),
            },
            ReadDiagnostic {
                kind: ReadDiagnosticKind::NotSupported,
                message: "backend-specific detail must remain internal".to_string(),
            },
            ReadDiagnostic {
                kind: ReadDiagnosticKind::NotImplemented,
                message: "backend-specific detail must remain internal".to_string(),
            },
        ] {
            let mut session = Reader::open_path(&title_block_fixture_path()).unwrap();
            session.diagnostics.push(diagnostic);
            for error in [
                session
                    .ensure_title_block_diagnostic_fidelity()
                    .unwrap_err(),
                session.read_title_blocks().unwrap_err(),
            ] {
                assert_eq!(error.code(), "unsupported_title_block_data");
                assert_eq!(
                    error.message(),
                    "reader reported an unsupported diagnostic that may affect title-block interpretation"
                );
                assert!(!error.message().contains("backend-specific detail"));
            }
        }
    }

    fn text_session() -> DrawingReadSession {
        let mut document = CadDocument::new();
        let mut text = Text::with_value("Reader boundary", Vector3::new(1.0, 2.0, 3.0));
        text.common.handle = Handle::new(0x70);
        document.add_entity(EntityType::Text(text)).unwrap();
        DrawingReadSession {
            snapshot: DrawingSnapshot::new(DrawingFormat::Dxf, Vec::new()),
            document,
            diagnostics: Vec::new(),
        }
    }

    #[test]
    fn text_family_accepts_only_proven_safe_backend_telemetry() {
        let options = TextListOptions::default();
        let selector = TextSelector {
            handle: "70".to_string(),
        };
        let mut session = text_session();
        session.diagnostics.push(ReadDiagnostic {
            kind: ReadDiagnosticKind::Warning,
            message: "Reading DWG file version: AC1027 (AC24)".to_string(),
        });
        session.diagnostics.push(ReadDiagnostic {
            kind: ReadDiagnosticKind::Warning,
            message: "AC18: Read 3 page records from page map".to_string(),
        });
        assert_eq!(session.dump_text().unwrap().len(), 1);
        assert_eq!(session.list_text(&options).unwrap().len(), 1);
        assert_eq!(session.get_text(&selector).unwrap().handle, "70");

        for diagnostic in [
            ReadDiagnostic {
                kind: ReadDiagnosticKind::Warning,
                message: "Failed to read handles: backend-specific detail".to_string(),
            },
            ReadDiagnostic {
                kind: ReadDiagnosticKind::Warning,
                message: "AC18: Read 0 page records from page map".to_string(),
            },
            ReadDiagnostic {
                kind: ReadDiagnosticKind::NotSupported,
                message: "backend-specific detail must remain internal".to_string(),
            },
            ReadDiagnostic {
                kind: ReadDiagnosticKind::NotImplemented,
                message: "backend-specific detail must remain internal".to_string(),
            },
        ] {
            let mut session = text_session();
            session.diagnostics.push(diagnostic);
            for error in [
                session.dump_text().unwrap_err(),
                session.list_text(&options).unwrap_err(),
                session.get_text(&selector).unwrap_err(),
            ] {
                assert_eq!(error.code(), "unsupported_text_data");
                assert_eq!(
                    error.message(),
                    "reader reported an unsupported diagnostic that may affect text interpretation"
                );
                assert!(!error.message().contains("backend-specific detail"));
            }
        }
    }

    #[test]
    fn layout_family_accepts_only_proven_safe_backend_telemetry() {
        let mut session = Reader::open_path(&dwg_fixture_path()).unwrap();
        session.diagnostics.push(ReadDiagnostic {
            kind: ReadDiagnosticKind::Warning,
            message: "Reading DWG file version: AC1027 (AC24)".to_string(),
        });
        session.diagnostics.push(ReadDiagnostic {
            kind: ReadDiagnosticKind::Warning,
            message: "AC18: Read 3 page records from page map".to_string(),
        });
        assert!(session.ensure_layout_diagnostic_fidelity().is_ok());
        assert!(session.list_layouts().is_ok());
        assert!(session.list_layout_viewports(None).is_ok());
        assert!(session.list_plot_settings().is_ok());

        for diagnostic in [
            ReadDiagnostic {
                kind: ReadDiagnosticKind::Warning,
                message: "Failed to read handles: backend-specific detail".to_string(),
            },
            ReadDiagnostic {
                kind: ReadDiagnosticKind::Warning,
                message: "AC18: Read 0 page records from page map".to_string(),
            },
            ReadDiagnostic {
                kind: ReadDiagnosticKind::NotSupported,
                message: "backend-specific detail must remain internal".to_string(),
            },
            ReadDiagnostic {
                kind: ReadDiagnosticKind::NotImplemented,
                message: "backend-specific detail must remain internal".to_string(),
            },
        ] {
            let mut session = Reader::open_path(&dwg_fixture_path()).unwrap();
            session.diagnostics.push(diagnostic);
            for error in [
                session.ensure_layout_diagnostic_fidelity().unwrap_err(),
                session.list_layouts().unwrap_err(),
                session.get_layout(&LayoutSelector::default()).unwrap_err(),
                session.list_layout_viewports(None).unwrap_err(),
                session
                    .get_layout_viewport(&LayoutViewportSelector {
                        handle: "0".to_string(),
                    })
                    .unwrap_err(),
                session.list_plot_settings().unwrap_err(),
                session
                    .get_plot_setting(&PlotSettingSelector::default())
                    .unwrap_err(),
            ] {
                assert_eq!(error.code(), "unsupported_layout_data");
                assert_eq!(
                    error.message(),
                    "reader reported an unsupported diagnostic that may affect layout interpretation"
                );
                assert!(!error.message().contains("backend-specific detail"));
            }
        }
    }

    #[test]
    fn layer_family_accepts_only_proven_safe_backend_telemetry() {
        let selector = LayerSelector {
            name: Some("0".to_string()),
            ..Default::default()
        };
        let mut session = Reader::open_path(&title_block_fixture_path()).unwrap();
        session.diagnostics.push(ReadDiagnostic {
            kind: ReadDiagnosticKind::Warning,
            message: "Reading DWG file version: AC1027 (AC24)".to_string(),
        });
        session.diagnostics.push(ReadDiagnostic {
            kind: ReadDiagnosticKind::Warning,
            message: "AC18: Read 3 page records from page map".to_string(),
        });
        assert!(session.ensure_layer_diagnostic_fidelity().is_ok());
        assert!(!session.list_layers().unwrap().is_empty());
        assert_eq!(session.get_layer(&selector).unwrap().name, "0");

        for diagnostic in [
            ReadDiagnostic {
                kind: ReadDiagnosticKind::Warning,
                message: "Failed to read handles: backend-specific detail".to_string(),
            },
            ReadDiagnostic {
                kind: ReadDiagnosticKind::Warning,
                message: "AC18: Read 0 page records from page map".to_string(),
            },
            ReadDiagnostic {
                kind: ReadDiagnosticKind::NotSupported,
                message: "backend-specific detail must remain internal".to_string(),
            },
            ReadDiagnostic {
                kind: ReadDiagnosticKind::NotImplemented,
                message: "backend-specific detail must remain internal".to_string(),
            },
        ] {
            let mut session = Reader::open_path(&title_block_fixture_path()).unwrap();
            session.diagnostics.push(diagnostic);
            for error in [
                session.ensure_layer_diagnostic_fidelity().unwrap_err(),
                session.list_layers().unwrap_err(),
                session.get_layer(&selector).unwrap_err(),
            ] {
                assert_eq!(error.code(), "unsupported_layer_data");
                assert_eq!(
                    error.message(),
                    "reader reported an unsupported diagnostic that may affect layer interpretation"
                );
                assert!(!error.message().contains("backend-specific detail"));
            }
        }
    }
}
