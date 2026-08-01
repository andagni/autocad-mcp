use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;

use acadrust::entities::EntityType;
use acadrust::notification::NotificationType;
use acadrust::objects::ObjectType;
use acadrust::{CadDocument, DwgReader, DxfReader};
use autocad_reader::contract::xrefs::{XrefInstanceListOptions, XrefInstanceRecord};
use autocad_reader::contract::{
    BlockDefinitionRecord, BlockInsertRecord, DimensionStyleRecord, LayerRecord, LayoutRecord,
    LayoutSelector, LayoutViewportRecord, LinetypeRecord, PlotSettingRecord, TextStyleRecord,
};

use crate::{DrawingFormat, DrawingSnapshot};

use super::{PortablePlotError, ResourceDigest, SourceHandle};

mod compiler;

pub use compiler::{
    compile_portable_scene, compile_portable_scene_with_resources, PortablePlotLimits,
    PortablePlotReceipt, PortableResourceReceipt, PortableSceneCompilation,
};

/// Stable description of an Acadrust field or resource limitation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BackendLimitation {
    /// Acadrust 0.4.1 does not retain ByLayer/ByBlock transparency modes.
    TransparencyInheritanceUnavailable,
    /// A nonzero block base point has no independent reader/oracle projection.
    NonzeroBlockBasePointUnqualified,
    /// The drawing identifies resources that only a caller bundle may resolve.
    ExternalDependenciesRequireBundle,
    /// The persisted BLOCK_HEADER reverse INSERT index contains stale
    /// non-INSERT references, while every decoded INSERT is independently
    /// accounted for.
    StaleBlockInsertIndexIgnored,
}

/// Aggregate inventory sizes, excluding source names and drawing content.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SourceInventoryCounts {
    pub entities: usize,
    pub layers: usize,
    pub block_definitions: usize,
    pub block_inserts: usize,
    pub layouts: usize,
    pub viewports: usize,
    pub linetypes: usize,
    pub text_styles: usize,
    pub dimension_styles: usize,
    pub plot_settings: usize,
    pub external_dependencies: usize,
}

/// Independently checked selected-layout identity and paper facts.
#[derive(Debug, Clone, PartialEq)]
pub struct SelectedLayoutInventory {
    handle: SourceHandle,
    name: String,
    is_model: bool,
    paper_width_mm: f64,
    paper_height_mm: f64,
    viewport_handles: Vec<SourceHandle>,
    requests_plot_styles: bool,
}

impl SelectedLayoutInventory {
    pub fn handle(&self) -> &SourceHandle {
        &self.handle
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn is_model(&self) -> bool {
        self.is_model
    }

    pub fn paper_width_mm(&self) -> f64 {
        self.paper_width_mm
    }

    pub fn paper_height_mm(&self) -> f64 {
        self.paper_height_mm
    }

    pub fn viewport_handles(&self) -> &[SourceHandle] {
        &self.viewport_handles
    }

    pub fn requests_plot_styles(&self) -> bool {
        self.requests_plot_styles
    }
}

/// Transport-neutral inventory derived from one immutable drawing snapshot.
#[derive(Debug, Clone, PartialEq)]
pub struct PortableSourceInventory {
    source_digest: ResourceDigest,
    source_bytes: usize,
    format: DrawingFormat,
    source_version: String,
    selected_layout: SelectedLayoutInventory,
    counts: SourceInventoryCounts,
    entity_counts: BTreeMap<String, usize>,
    limitations: Vec<BackendLimitation>,
}

impl PortableSourceInventory {
    pub fn source_digest(&self) -> ResourceDigest {
        self.source_digest
    }

    pub fn source_bytes(&self) -> usize {
        self.source_bytes
    }

    pub fn format(&self) -> DrawingFormat {
        self.format
    }

    pub fn source_version(&self) -> &str {
        &self.source_version
    }

    pub fn selected_layout(&self) -> &SelectedLayoutInventory {
        &self.selected_layout
    }

    pub fn counts(&self) -> SourceInventoryCounts {
        self.counts
    }

    pub fn entity_counts(&self) -> &BTreeMap<String, usize> {
        &self.entity_counts
    }

    pub fn limitations(&self) -> &[BackendLimitation] {
        &self.limitations
    }

    /// Check only the immutable source/layout admission portion of
    /// `portable_2d_v1`. Semantic completeness is decided during compilation.
    pub fn admit_portable_2d_v1(&self) -> Result<(), PortablePlotError> {
        if self.format != DrawingFormat::Dwg || self.source_version != "AC1032" {
            return Err(PortablePlotError::new(
                "source_profile_not_admitted",
                "portable_2d_v1 admits only AC1032 DWG snapshots",
            ));
        }
        if self.selected_layout.is_model {
            return Err(PortablePlotError::new(
                "layout_profile_not_admitted",
                "portable_2d_v1 requires a paper-space layout",
            ));
        }
        if !finite_positive(self.selected_layout.paper_width_mm)
            || !finite_positive(self.selected_layout.paper_height_mm)
        {
            return Err(PortablePlotError::new(
                "layout_paper_geometry_invalid",
                "portable_2d_v1 requires finite positive stored paper geometry",
            ));
        }
        Ok(())
    }
}

struct IndependentInventories {
    source_version: String,
    layouts: Vec<autocad_reader::contract::LayoutInfo>,
    selected_layout: LayoutRecord,
    selected_layout_plot_flags: autocad_reader::contract::PlotFlagsRecord,
    selected_viewports: Vec<LayoutViewportRecord>,
    layers: Vec<LayerRecord>,
    blocks: Vec<BlockDefinitionRecord>,
    inserts: Vec<BlockInsertRecord>,
    xref_instances: Vec<XrefInstanceRecord>,
    block_references: BTreeMap<String, BTreeSet<String>>,
    linetypes: Vec<LinetypeRecord>,
    text_styles: Vec<TextStyleRecord>,
    dimension_styles: Vec<DimensionStyleRecord>,
    plot_settings: Vec<PlotSettingRecord>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct SourceCrossCheck {
    stale_block_insert_index: bool,
}

/// Inspect one immutable source without exposing Acadrust types or opening any
/// drawing-supplied external path.
pub fn inspect_portable_source(
    snapshot: &DrawingSnapshot,
    layout_name: &str,
) -> Result<PortableSourceInventory, PortablePlotError> {
    if layout_name.trim().is_empty() {
        return Err(PortablePlotError::new(
            "layout_selector_invalid",
            "a non-empty layout name is required",
        ));
    }
    let independent = independent_inventories(snapshot, layout_name)?;
    let document = parse_backend_snapshot(snapshot)?;
    let cross_check = cross_check_source(&document, &independent)?;

    let entity_counts = entity_counts(&document)?;
    let dependencies = external_dependency_count(&document)?;
    let nonzero_base = document.block_records.iter().any(|block| {
        block.base_point.x != 0.0 || block.base_point.y != 0.0 || block.base_point.z != 0.0
    });
    let mut limitations = vec![BackendLimitation::TransparencyInheritanceUnavailable];
    if nonzero_base {
        limitations.push(BackendLimitation::NonzeroBlockBasePointUnqualified);
    }
    if dependencies > 0 {
        limitations.push(BackendLimitation::ExternalDependenciesRequireBundle);
    }
    if cross_check.stale_block_insert_index {
        limitations.push(BackendLimitation::StaleBlockInsertIndexIgnored);
    }
    limitations.sort();
    limitations.dedup();

    let requests_plot_styles = independent.selected_layout_plot_flags.plot_plot_styles;
    let block_inserts = independent
        .inserts
        .len()
        .checked_add(independent.xref_instances.len())
        .ok_or_else(|| {
            PortablePlotError::new(
                "source_inventory_overflow",
                "source block-insert inventory overflowed",
            )
        })?;

    let selected_layout = SelectedLayoutInventory {
        handle: SourceHandle::new(&independent.selected_layout.handle)?,
        name: independent.selected_layout.name.clone(),
        is_model: independent.selected_layout.is_model,
        paper_width_mm: independent.selected_layout.plot_settings.paper_width_mm,
        paper_height_mm: independent.selected_layout.plot_settings.paper_height_mm,
        viewport_handles: independent
            .selected_viewports
            .iter()
            .map(|viewport| SourceHandle::new(&viewport.handle))
            .collect::<Result<Vec<_>, _>>()?,
        requests_plot_styles,
    };

    Ok(PortableSourceInventory {
        source_digest: ResourceDigest::of(snapshot.bytes().as_ref()),
        source_bytes: snapshot.bytes().len(),
        format: snapshot.format(),
        source_version: independent.source_version,
        selected_layout,
        counts: SourceInventoryCounts {
            entities: document.entities().count(),
            layers: independent.layers.len(),
            block_definitions: independent.blocks.len(),
            block_inserts,
            layouts: independent.layouts.len(),
            viewports: independent.selected_viewports.len(),
            linetypes: independent.linetypes.len(),
            text_styles: independent.text_styles.len(),
            dimension_styles: independent.dimension_styles.len(),
            plot_settings: independent.plot_settings.len(),
            external_dependencies: dependencies,
        },
        entity_counts,
        limitations,
    })
}

fn independent_inventories(
    snapshot: &DrawingSnapshot,
    layout_name: &str,
) -> Result<IndependentInventories, PortablePlotError> {
    let session = autocad_reader::Reader::open_snapshot(snapshot.reader_snapshot())
        .map_err(|error| reader_error("source_reader_admission_failed", error))?;
    let source_version = session
        .format_facts()
        .map_err(|error| reader_error("source_version_unavailable", error))?
        .drawing_version;
    let layouts = session
        .list_layouts()
        .map_err(|error| reader_error("layout_inventory_unavailable", error))?;
    let selector = LayoutSelector {
        handle: None,
        name: Some(layout_name.to_owned()),
    };
    let selected_layout = session
        .get_layout(&selector)
        .map_err(|error| reader_error("layout_selection_failed", error))?;
    let selected_selector = LayoutSelector {
        handle: Some(selected_layout.handle.clone()),
        name: Some(selected_layout.name.clone()),
    };
    let selected_layout_plot_flags = session
        .get_embedded_layout_plot_flags(&selected_selector)
        .map_err(|error| reader_error("embedded_plot_flags_unavailable", error))?;
    let selected_viewports = session
        .list_layout_viewports(Some(&selected_selector))
        .map_err(|error| reader_error("viewport_inventory_unavailable", error))?;
    let layers = session
        .list_layers()
        .map_err(|error| reader_error("layer_inventory_unavailable", error))?;
    let blocks = session
        .list_block_definitions()
        .map_err(|error| reader_error("block_inventory_unavailable", error))?;
    let inserts = session
        .list_block_inserts()
        .map_err(|error| reader_error("insert_inventory_unavailable", error))?;
    let xref_session = session
        .xref_session()
        .map_err(|error| reader_error("insert_graph_unavailable", error))?;
    if !xref_session.evidence().block_references_complete {
        return Err(PortablePlotError::new(
            "insert_graph_unavailable",
            "the independent low-level reader could not account for every persisted INSERT edge",
        ));
    }
    let block_references = xref_session
        .evidence()
        .block_references
        .iter()
        .map(|(owner, references)| {
            (
                owner.clone(),
                references.iter().cloned().collect::<BTreeSet<_>>(),
            )
        })
        .collect();
    let xref_instances = xref_session
        .list_instances(&XrefInstanceListOptions::default())
        .map_err(|error| reader_error("xref_inventory_unavailable", error))?;
    let linetypes = session
        .list_linetypes()
        .map_err(|error| reader_error("linetype_inventory_unavailable", error))?;
    let text_styles = session
        .list_text_styles()
        .map_err(|error| reader_error("text_style_inventory_unavailable", error))?;
    let dimension_styles = session
        .list_dimension_styles()
        .map_err(|error| reader_error("dimension_style_inventory_unavailable", error))?;
    let plot_settings = session
        .list_plot_settings()
        .map_err(|error| reader_error("plot_settings_inventory_unavailable", error))?;

    ensure_unique(
        layouts
            .iter()
            .map(|layout| layout.name.to_ascii_uppercase()),
        "layout names",
    )?;
    ensure_unique(
        layers.iter().map(|layer| layer.name.to_ascii_uppercase()),
        "layer names",
    )?;
    ensure_unique(
        blocks.iter().map(|block| block.handle.clone()),
        "block handles",
    )?;
    ensure_unique(
        inserts
            .iter()
            .map(|insert| insert.handle.clone())
            .chain(xref_instances.iter().map(|insert| insert.handle.clone())),
        "insert handles",
    )?;
    ensure_unique(
        selected_viewports
            .iter()
            .map(|viewport| viewport.handle.clone()),
        "viewport handles",
    )?;

    Ok(IndependentInventories {
        source_version,
        layouts,
        selected_layout,
        selected_layout_plot_flags,
        selected_viewports,
        layers,
        blocks,
        inserts,
        xref_instances,
        block_references,
        linetypes,
        text_styles,
        dimension_styles,
        plot_settings,
    })
}

fn reader_error(code: &'static str, error: impl std::fmt::Display) -> PortablePlotError {
    PortablePlotError::new(
        code,
        format!("independent reader rejected the inventory: {error}"),
    )
}

fn ensure_unique(
    values: impl IntoIterator<Item = String>,
    label: &'static str,
) -> Result<(), PortablePlotError> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(PortablePlotError::new(
                "source_identity_contradictory",
                format!("independent reader reported duplicate {label}"),
            ));
        }
    }
    Ok(())
}

fn parse_backend_snapshot(snapshot: &DrawingSnapshot) -> Result<CadDocument, PortablePlotError> {
    let bytes = snapshot.bytes();
    let document = match snapshot.format() {
        DrawingFormat::Dwg => {
            let mut reader = DwgReader::from_stream(Cursor::new(bytes));
            reader.read().map_err(|_| {
                PortablePlotError::new(
                    "source_backend_parse_failed",
                    "Acadrust could not decode the immutable DWG snapshot",
                )
            })?
        }
        DrawingFormat::Dxf => DxfReader::from_reader(Cursor::new(bytes))
            .and_then(DxfReader::read)
            .map_err(|_| {
                PortablePlotError::new(
                    "source_backend_parse_failed",
                    "Acadrust could not decode the immutable DXF snapshot",
                )
            })?,
    };
    for notification in &document.notifications {
        match notification.notification_type {
            NotificationType::Warning if safe_backend_telemetry(&notification.message) => {}
            NotificationType::Warning => {
                return Err(PortablePlotError::new(
                    "source_backend_warning_unclassified",
                    "Acadrust emitted an unclassified source warning",
                ));
            }
            NotificationType::NotImplemented => {
                return Err(PortablePlotError::new(
                    "source_backend_not_implemented",
                    "Acadrust reported source data that it did not decode",
                ));
            }
            NotificationType::NotSupported => {
                return Err(PortablePlotError::new(
                    "source_backend_not_supported",
                    "Acadrust reported unsupported source data",
                ));
            }
            NotificationType::Error => {
                return Err(PortablePlotError::new(
                    "source_backend_parse_incomplete",
                    "Acadrust recovered from a source parse error",
                ));
            }
        }
    }
    Ok(document)
}

fn safe_backend_telemetry(message: &str) -> bool {
    [
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
    .any(|prefix| message.starts_with(prefix))
        || [
            ("AC18: Read ", " page records from page map"),
            ("AC18: Read ", " section descriptors from section map"),
            ("AC1021: Read ", " page records from page map"),
            ("AC1021: Read ", " section descriptors from section map"),
        ]
        .iter()
        .any(|(prefix, suffix)| {
            message
                .strip_prefix(prefix)
                .and_then(|value| value.strip_suffix(suffix))
                .and_then(|value| value.parse::<usize>().ok())
                .is_some_and(|count| count > 0)
        })
}

fn cross_check_source(
    document: &CadDocument,
    independent: &IndependentInventories,
) -> Result<SourceCrossCheck, PortablePlotError> {
    if format!("{:?}", document.version) != independent.source_version {
        return Err(PortablePlotError::new(
            "source_version_contradictory",
            "Acadrust and the independent reader disagree on source version",
        ));
    }

    let raw_layouts = document
        .objects
        .values()
        .filter_map(|object| match object {
            ObjectType::Layout(layout) => Some(layout),
            _ => None,
        })
        .collect::<Vec<_>>();
    let matches = raw_layouts
        .iter()
        .copied()
        .filter(|layout| layout.name == independent.selected_layout.name)
        .collect::<Vec<_>>();
    let [layout] = matches.as_slice() else {
        return Err(PortablePlotError::new(
            "layout_identity_contradictory",
            "Acadrust did not expose exactly one independently selected layout",
        ));
    };
    if canonical_handle(layout.handle) != independent.selected_layout.handle
        || canonical_handle(layout.block_record)
            != independent
                .selected_layout
                .block_record_handle
                .clone()
                .unwrap_or_default()
    {
        return Err(PortablePlotError::new(
            "layout_identity_contradictory",
            "Acadrust and the independent reader disagree on layout handles",
        ));
    }
    if layout.paper_width != independent.selected_layout.plot_settings.paper_width_mm
        || layout.paper_height != independent.selected_layout.plot_settings.paper_height_mm
        || layout.plot_rotation != independent.selected_layout.plot_settings.rotation_code
    {
        return Err(PortablePlotError::new(
            "layout_plot_settings_contradictory",
            "Acadrust and the independent reader disagree on embedded paper geometry",
        ));
    }

    let backend_viewports = document
        .entities()
        .filter_map(|entity| match entity {
            EntityType::Viewport(viewport)
                if viewport.common.owner_handle == layout.block_record =>
            {
                Some(canonical_handle(viewport.common.handle))
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let independent_viewports = independent
        .selected_viewports
        .iter()
        .map(|viewport| viewport.handle.clone())
        .collect::<BTreeSet<_>>();
    if backend_viewports != independent_viewports {
        return Err(PortablePlotError::new(
            "viewport_identity_contradictory",
            "Acadrust and the independent reader disagree on selected-layout viewport handles",
        ));
    }
    require_matching_set(
        "layer_identity_contradictory",
        "Acadrust and the independent reader disagree on layer identities",
        document
            .layers
            .iter()
            .map(|layer| (canonical_handle(layer.handle), layer.name.clone()))
            .collect(),
        independent
            .layers
            .iter()
            .map(|layer| (layer.handle.clone(), layer.name.clone()))
            .collect(),
    )?;
    require_matching_set(
        "linetype_identity_contradictory",
        "Acadrust and the independent reader disagree on linetype identities",
        document
            .line_types
            .iter()
            .map(|linetype| (canonical_handle(linetype.handle), linetype.name.clone()))
            .collect(),
        independent
            .linetypes
            .iter()
            .map(|linetype| (linetype.handle.clone(), linetype.name.clone()))
            .collect(),
    )?;
    require_matching_set(
        "text_style_identity_contradictory",
        "Acadrust and the independent reader disagree on text-style identities",
        document
            .text_styles
            .iter()
            .map(|style| (canonical_handle(style.handle), style.name.clone()))
            .collect(),
        independent
            .text_styles
            .iter()
            .map(|style| (style.handle.clone(), style.name.clone()))
            .collect(),
    )?;
    require_matching_set(
        "dimension_style_identity_contradictory",
        "Acadrust and the independent reader disagree on dimension-style identities",
        document
            .dim_styles
            .iter()
            .map(|style| (canonical_handle(style.handle), style.name.clone()))
            .collect(),
        independent
            .dimension_styles
            .iter()
            .map(|style| (style.handle.clone(), style.name.clone()))
            .collect(),
    )?;
    require_matching_set(
        "block_identity_contradictory",
        "Acadrust and the independent reader disagree on block identities",
        document
            .block_records
            .iter()
            .map(|block| (canonical_handle(block.handle), block.name.clone()))
            .collect(),
        independent
            .blocks
            .iter()
            .map(|block| (block.handle.clone(), block.name.clone()))
            .collect(),
    )?;
    require_matching_set(
        "xref_identity_contradictory",
        "Acadrust and the independent reader disagree on XREF block identities",
        document
            .block_records
            .iter()
            .filter(|block| {
                block.flags.is_xref
                    || block.flags.is_xref_overlay
                    || block.flags.is_external
                    || !block.xref_path.is_empty()
            })
            .map(|block| {
                (
                    canonical_handle(block.handle),
                    block.name.clone(),
                    block.flags.is_xref,
                    block.flags.is_xref_overlay,
                    normalized_dependency_identity(&block.xref_path),
                )
            })
            .collect(),
        independent
            .blocks
            .iter()
            .filter(|block| block.is_xref || block.is_xref_overlay || block.xref_dependent)
            .map(|block| {
                (
                    block.handle.clone(),
                    block.name.clone(),
                    block.is_xref,
                    block.is_xref_overlay,
                    block
                        .xref_path
                        .as_deref()
                        .map(normalized_dependency_identity)
                        .unwrap_or_default(),
                )
            })
            .collect(),
    )?;
    require_matching_set(
        "block_ownership_contradictory",
        "Acadrust and the independent reader disagree on block-owned entity handles",
        document
            .block_records
            .iter()
            .map(|block| {
                (
                    canonical_handle(block.handle),
                    block
                        .entity_handles
                        .iter()
                        .copied()
                        .map(canonical_handle)
                        .collect::<BTreeSet<_>>(),
                )
            })
            .collect(),
        independent
            .blocks
            .iter()
            .map(|block| {
                (
                    block.handle.clone(),
                    block
                        .entity_handles
                        .iter()
                        .cloned()
                        .collect::<BTreeSet<_>>(),
                )
            })
            .collect(),
    )?;
    let stale_block_insert_index = reconcile_block_insert_index(
        document
            .block_records
            .iter()
            .map(|block| {
                (
                    canonical_handle(block.handle),
                    block
                        .insert_handles
                        .iter()
                        .copied()
                        .map(canonical_handle)
                        .collect::<Vec<_>>(),
                )
            })
            .collect(),
        independent
            .blocks
            .iter()
            .map(|block| {
                (
                    block.handle.clone(),
                    block
                        .insert_handles
                        .iter()
                        .cloned()
                        .collect::<BTreeSet<_>>(),
                )
            })
            .collect(),
        document
            .entities()
            .filter_map(|entity| match entity {
                EntityType::Insert(insert) => Some(canonical_handle(insert.common.handle)),
                _ => None,
            })
            .collect(),
    )?;
    require_matching_set(
        "insert_identity_contradictory",
        "Acadrust and the independent reader disagree on INSERT identity or ownership",
        document
            .entities()
            .filter_map(|entity| match entity {
                EntityType::Insert(insert) => Some((
                    canonical_handle(insert.common.handle),
                    insert.block_name.clone(),
                    canonical_handle(insert.common.owner_handle),
                )),
                _ => None,
            })
            .collect(),
        independent
            .inserts
            .iter()
            .map(|insert| {
                (
                    insert.handle.clone(),
                    insert.block_name.clone(),
                    insert.owner_handle.clone().unwrap_or_default(),
                )
            })
            .chain(independent.xref_instances.iter().map(|insert| {
                (
                    insert.handle.clone(),
                    insert.attachment_name.clone(),
                    insert.owner_handle.clone(),
                )
            }))
            .collect(),
    )?;
    let definitions_by_name = independent.blocks.iter().fold(
        BTreeMap::<String, Vec<String>>::new(),
        |mut definitions, block| {
            definitions
                .entry(block.name.to_uppercase())
                .or_default()
                .push(block.handle.clone());
            definitions
        },
    );
    let mut backend_block_references = BTreeMap::<String, BTreeSet<String>>::new();
    for entity in document.entities() {
        let EntityType::Insert(insert) = entity else {
            continue;
        };
        let Some([definition]) = definitions_by_name
            .get(&insert.block_name.to_uppercase())
            .map(Vec::as_slice)
        else {
            return Err(PortablePlotError::new(
                "insert_graph_contradictory",
                "an INSERT does not resolve to exactly one independently identified block definition",
            ));
        };
        backend_block_references
            .entry(canonical_handle(insert.common.owner_handle))
            .or_default()
            .insert(definition.clone());
    }
    require_matching_insert_graph(backend_block_references, &independent.block_references)?;
    validate_backend_handle_ownership(document)?;
    Ok(SourceCrossCheck {
        stale_block_insert_index,
    })
}

fn require_matching_insert_graph(
    backend: BTreeMap<String, BTreeSet<String>>,
    independent: &BTreeMap<String, BTreeSet<String>>,
) -> Result<(), PortablePlotError> {
    if &backend == independent {
        Ok(())
    } else {
        Err(PortablePlotError::new(
            "insert_graph_contradictory",
            "Acadrust and the independent low-level reader disagree on INSERT owner-to-definition edges",
        ))
    }
}

fn require_matching_set<T: Ord>(
    code: &'static str,
    message: &'static str,
    backend: BTreeSet<T>,
    independent: BTreeSet<T>,
) -> Result<(), PortablePlotError> {
    if backend == independent {
        Ok(())
    } else {
        Err(PortablePlotError::new(code, message))
    }
}

fn reconcile_block_insert_index(
    backend: BTreeMap<String, Vec<String>>,
    semantic: BTreeMap<String, BTreeSet<String>>,
    backend_insert_handles: BTreeSet<String>,
) -> Result<bool, PortablePlotError> {
    if backend.keys().collect::<Vec<_>>() != semantic.keys().collect::<Vec<_>>() {
        return Err(PortablePlotError::new(
            "block_ownership_contradictory",
            "Acadrust and the independent reader disagree on block reverse-index ownership",
        ));
    }

    let mut stale = false;
    for (block_handle, raw_handles) in backend {
        if raw_handles.iter().any(String::is_empty) {
            return Err(PortablePlotError::new(
                "block_ownership_contradictory",
                "Acadrust exposed a null BLOCK_HEADER reverse INSERT reference",
            ));
        }
        let raw = raw_handles.iter().cloned().collect::<BTreeSet<_>>();
        if raw.len() != raw_handles.len() {
            return Err(PortablePlotError::new(
                "block_ownership_contradictory",
                "Acadrust exposed a duplicate BLOCK_HEADER reverse INSERT reference",
            ));
        }
        let expected = &semantic[&block_handle];
        if !expected.is_subset(&raw) {
            return Err(PortablePlotError::new(
                "block_ownership_contradictory",
                "the BLOCK_HEADER reverse index omits a decoded INSERT reference",
            ));
        }
        for extra in raw.difference(expected) {
            if backend_insert_handles.contains(extra) {
                return Err(PortablePlotError::new(
                    "block_ownership_contradictory",
                    "the BLOCK_HEADER reverse index assigns a decoded INSERT to the wrong definition",
                ));
            }
            stale = true;
        }
    }
    Ok(stale)
}

fn normalized_dependency_identity(value: &str) -> String {
    value
        .trim()
        .replace('\\', "/")
        .trim_start_matches("./")
        .to_ascii_lowercase()
}

fn validate_backend_handle_ownership(document: &CadDocument) -> Result<(), PortablePlotError> {
    let mut handles = BTreeSet::new();
    let mut insert = |handle: acadrust::types::Handle| {
        if handle.is_null() || handles.insert(canonical_handle(handle)) {
            Ok(())
        } else {
            Err(PortablePlotError::new(
                "source_handle_ownership_contradictory",
                "Acadrust exposes one non-null handle for more than one source object",
            ))
        }
    };
    for handle in document
        .layers
        .iter()
        .map(|entry| entry.handle)
        .chain(document.line_types.iter().map(|entry| entry.handle))
        .chain(document.text_styles.iter().map(|entry| entry.handle))
        .chain(document.dim_styles.iter().map(|entry| entry.handle))
        .chain(document.block_records.iter().map(|entry| entry.handle))
        .chain(
            document
                .entities()
                .map(|entity| entity.as_entity().handle()),
        )
        .chain(document.objects.keys().copied())
    {
        insert(handle)?;
    }
    Ok(())
}

fn entity_counts(document: &CadDocument) -> Result<BTreeMap<String, usize>, PortablePlotError> {
    let mut counts = BTreeMap::<String, usize>::new();
    for entity in document.entities() {
        let name = entity.as_entity().entity_type().to_ascii_uppercase();
        let count = counts.entry(name).or_default();
        *count = count.checked_add(1).ok_or_else(|| {
            PortablePlotError::new(
                "source_inventory_overflow",
                "source entity inventory overflowed",
            )
        })?;
    }
    Ok(counts)
}

fn external_dependency_count(document: &CadDocument) -> Result<usize, PortablePlotError> {
    let block_dependencies = document
        .block_records
        .iter()
        .filter(|block| {
            block.flags.is_xref
                || block.flags.is_xref_overlay
                || block.flags.is_external
                || !block.xref_path.is_empty()
        })
        .count();
    let entity_dependencies = document
        .entities()
        .filter(|entity| matches!(entity, EntityType::RasterImage(_) | EntityType::Underlay(_)))
        .count();
    block_dependencies
        .checked_add(entity_dependencies)
        .ok_or_else(|| {
            PortablePlotError::new(
                "source_inventory_overflow",
                "external dependency inventory overflowed",
            )
        })
}

fn canonical_handle(handle: acadrust::types::Handle) -> String {
    if handle.is_null() {
        String::new()
    } else {
        format!("{handle:X}")
    }
}

fn finite_positive(value: f64) -> bool {
    value.is_finite() && value > 0.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DrawingSnapshot;

    fn fixture_snapshot() -> DrawingSnapshot {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/corpus/open/acadsharp/dynamic-blocks/BLOCKVISIBILITYPARAMETER.dwg");
        DrawingSnapshot::new(DrawingFormat::Dwg, std::fs::read(path).unwrap())
    }

    fn synthetic_plot_snapshot() -> DrawingSnapshot {
        let mut document = CadDocument::new();
        for object in document.objects.values_mut() {
            if let ObjectType::Layout(layout) = object {
                if layout.name == "Layout1" {
                    layout.paper_width = 297.0;
                    layout.paper_height = 210.0;
                }
            }
        }
        document
            .add_entity_to_layout(
                EntityType::Line(acadrust::entities::Line::from_coords(
                    10.0, 10.0, 0.0, 100.0, 80.0, 0.0,
                )),
                "Layout1",
            )
            .unwrap();
        DrawingSnapshot::new(
            DrawingFormat::Dwg,
            acadrust::DwgWriter::write_to_vec(&document).unwrap(),
        )
    }

    fn synthetic_stale_insert_index_snapshot() -> DrawingSnapshot {
        let mut document = CadDocument::new();
        let paper_block = document
            .objects
            .values_mut()
            .find_map(|object| match object {
                ObjectType::Layout(layout) if layout.name == "Layout1" => {
                    layout.paper_width = 297.0;
                    layout.paper_height = 210.0;
                    Some(layout.block_record)
                }
                _ => None,
            })
            .unwrap();
        let line_handle = document
            .add_entity_to_layout(
                EntityType::Line(acadrust::entities::Line::from_coords(
                    10.0, 10.0, 0.0, 100.0, 80.0, 0.0,
                )),
                "Layout1",
            )
            .unwrap();
        let block = document
            .block_records
            .iter_mut()
            .find(|block| block.handle == paper_block)
            .unwrap();
        block.insert_count_bytes = vec![1];
        block.insert_handles = vec![line_handle];
        DrawingSnapshot::new(
            DrawingFormat::Dwg,
            acadrust::DwgWriter::write_to_vec(&document).unwrap(),
        )
    }

    fn raw_insert_index(entries: &[(&str, &[&str])]) -> BTreeMap<String, Vec<String>> {
        entries
            .iter()
            .map(|(owner, handles)| {
                (
                    (*owner).to_string(),
                    handles.iter().map(|handle| (*handle).to_string()).collect(),
                )
            })
            .collect()
    }

    fn semantic_insert_index(entries: &[(&str, &[&str])]) -> BTreeMap<String, BTreeSet<String>> {
        entries
            .iter()
            .map(|(owner, handles)| {
                (
                    (*owner).to_string(),
                    handles.iter().map(|handle| (*handle).to_string()).collect(),
                )
            })
            .collect()
    }

    fn insert_handles(handles: &[&str]) -> BTreeSet<String> {
        handles.iter().map(|handle| (*handle).to_string()).collect()
    }

    #[test]
    fn contradictory_insert_graphs_remain_fail_closed() {
        let backend = semantic_insert_index(&[("A", &["B"])]);
        let independent = semantic_insert_index(&[("A", &["C"])]);
        assert_eq!(
            require_matching_insert_graph(backend, &independent)
                .unwrap_err()
                .code(),
            "insert_graph_contradictory"
        );
        let graph = semantic_insert_index(&[("A", &["B"])]);
        require_matching_insert_graph(graph.clone(), &graph).unwrap();
    }

    #[test]
    fn stale_non_insert_reverse_references_are_visible_but_do_not_hide_real_inserts() {
        assert!(!reconcile_block_insert_index(
            raw_insert_index(&[("A", &["10"])]),
            semantic_insert_index(&[("A", &["10"])]),
            insert_handles(&["10"]),
        )
        .unwrap());
        assert!(reconcile_block_insert_index(
            raw_insert_index(&[("A", &["10", "20"])]),
            semantic_insert_index(&[("A", &["10"])]),
            insert_handles(&["10"]),
        )
        .unwrap());
    }

    #[test]
    fn reverse_index_reconciliation_rejects_missing_wrong_duplicate_and_null_references() {
        for (backend, semantic, inserts) in [
            (
                raw_insert_index(&[("A", &[])]),
                semantic_insert_index(&[("A", &["10"])]),
                insert_handles(&["10"]),
            ),
            (
                raw_insert_index(&[("A", &["10"])]),
                semantic_insert_index(&[("A", &[])]),
                insert_handles(&["10"]),
            ),
            (
                raw_insert_index(&[("A", &["10", "10"])]),
                semantic_insert_index(&[("A", &["10"])]),
                insert_handles(&["10"]),
            ),
            (
                raw_insert_index(&[("A", &[""])]),
                semantic_insert_index(&[("A", &[])]),
                insert_handles(&[]),
            ),
        ] {
            assert_eq!(
                reconcile_block_insert_index(backend, semantic, inserts)
                    .unwrap_err()
                    .code(),
                "block_ownership_contradictory"
            );
        }
    }

    #[test]
    fn proven_stale_reverse_index_is_source_visible_but_not_a_fidelity_loss() {
        let snapshot = synthetic_stale_insert_index_snapshot();
        let inventory = inspect_portable_source(&snapshot, "Layout1").unwrap();
        assert!(inventory
            .limitations()
            .contains(&BackendLimitation::StaleBlockInsertIndexIgnored));
        assert_eq!(inventory.counts().block_inserts, 0);

        let compilation =
            compile_portable_scene(&snapshot, "Layout1", PortablePlotLimits::default()).unwrap();
        assert_eq!(
            compilation.receipt().fidelity().completeness(),
            crate::portable_plot::PlotCompleteness::Partial
        );
        assert!(!compilation
            .receipt()
            .fidelity()
            .diagnostic_counts()
            .contains_key("stale_block_insert_index_ignored"));
    }

    #[test]
    fn immutable_snapshot_is_cross_checked_into_a_stable_inventory() {
        let snapshot = fixture_snapshot();
        let session = autocad_reader::Reader::open_snapshot(snapshot.reader_snapshot()).unwrap();
        let paper_layout = session
            .list_layouts()
            .unwrap()
            .into_iter()
            .find(|layout| !layout.is_model)
            .unwrap();
        let inventory = inspect_portable_source(&snapshot, &paper_layout.name).unwrap();
        assert_eq!(inventory.format(), DrawingFormat::Dwg);
        assert_eq!(
            inventory.source_digest(),
            ResourceDigest::of(snapshot.bytes().as_ref())
        );
        assert_eq!(inventory.selected_layout().name(), paper_layout.name);
        assert_eq!(
            inventory.counts().entities,
            inventory.entity_counts().values().sum::<usize>()
        );
        assert_eq!(
            inventory.counts().block_inserts,
            inventory
                .entity_counts()
                .get("INSERT")
                .copied()
                .unwrap_or_default()
        );
        assert!(inventory
            .limitations()
            .contains(&BackendLimitation::TransparencyInheritanceUnavailable));
    }

    #[test]
    fn generated_ac1032_snapshot_reaches_semantic_scene_compilation() {
        let snapshot = synthetic_plot_snapshot();
        let compilation =
            compile_portable_scene(&snapshot, "Layout1", PortablePlotLimits::default()).unwrap();
        assert!(
            compilation.display_list().is_some(),
            "generated AC1032 snapshot must produce a complete or explicitly partial development scene: {:?}",
            compilation.receipt().fidelity()
        );
        assert_ne!(
            compilation.receipt().fidelity().completeness(),
            crate::portable_plot::PlotCompleteness::Rejected
        );
        assert!(compilation.receipt().usage().is_some());
    }

    #[test]
    fn xref_inserts_are_admitted_through_the_independent_xref_union() {
        let mut document = CadDocument::new();
        for object in document.objects.values_mut() {
            if let ObjectType::Layout(layout) = object {
                if layout.name == "Layout1" {
                    layout.paper_width = 297.0;
                    layout.paper_height = 210.0;
                }
            }
        }
        let mut attachment = acadrust::tables::BlockRecord::new("QUALIFICATION_XREF");
        attachment.handle = document.allocate_handle();
        attachment.block_entity_handle = document.allocate_handle();
        attachment.block_end_handle = document.allocate_handle();
        attachment.flags.is_xref = true;
        attachment.xref_path = "qualification-xref.dwg".to_owned();
        document.block_records.add(attachment).unwrap();
        let insert = acadrust::entities::Insert::new(
            "QUALIFICATION_XREF",
            acadrust::types::Vector3::new(10.0, 20.0, 0.0),
        );
        let insert_handle = document
            .add_entity_to_layout(EntityType::Insert(insert), "Layout1")
            .unwrap();
        let attachment = document
            .block_records
            .get_mut("QUALIFICATION_XREF")
            .unwrap();
        attachment.insert_count_bytes = vec![1];
        attachment.insert_handles = vec![insert_handle];
        let snapshot = DrawingSnapshot::new(
            DrawingFormat::Dwg,
            acadrust::DwgWriter::write_to_vec(&document).unwrap(),
        );

        let session = autocad_reader::Reader::open_snapshot(snapshot.reader_snapshot()).unwrap();
        assert!(session.list_block_inserts().unwrap().is_empty());
        let xrefs = session
            .xref_session()
            .unwrap()
            .list_instances(&XrefInstanceListOptions::default())
            .unwrap();
        assert_eq!(xrefs.len(), 1);
        assert_eq!(xrefs[0].handle, canonical_handle(insert_handle));

        let inventory = inspect_portable_source(&snapshot, "Layout1").unwrap();
        assert_eq!(inventory.counts().block_inserts, 1);
        assert!(inventory
            .limitations()
            .contains(&BackendLimitation::ExternalDependenciesRequireBundle));
    }

    #[test]
    fn external_block_flag_is_counted_once_without_other_xref_markers() {
        let mut document = CadDocument::new();
        let baseline = external_dependency_count(&document).unwrap();
        let mut external = acadrust::tables::BlockRecord::new("EXTERNAL_ONLY");
        external.handle = document.allocate_handle();
        external.block_entity_handle = document.allocate_handle();
        external.block_end_handle = document.allocate_handle();
        external.flags.is_external = true;
        document.block_records.add(external).unwrap();
        assert_eq!(external_dependency_count(&document).unwrap(), baseline + 1);

        let external = document.block_records.get_mut("EXTERNAL_ONLY").unwrap();
        external.flags.is_xref = true;
        external.flags.is_xref_overlay = true;
        external.xref_path = "same-member.dwg".to_owned();
        assert_eq!(external_dependency_count(&document).unwrap(), baseline + 1);
    }

    #[test]
    fn a_missing_layout_fails_at_the_independent_reader_boundary() {
        let error =
            inspect_portable_source(&fixture_snapshot(), "definitely-not-a-layout").unwrap_err();
        assert_eq!(error.code(), "layout_selection_failed");
    }

    #[test]
    fn portable_v1_admission_is_exact_about_version_format_and_space() {
        let snapshot = fixture_snapshot();
        let session = autocad_reader::Reader::open_snapshot(snapshot.reader_snapshot()).unwrap();
        let model_layout = session
            .list_layouts()
            .unwrap()
            .into_iter()
            .find(|layout| layout.is_model)
            .unwrap();
        let inventory = inspect_portable_source(&snapshot, &model_layout.name).unwrap();
        let error = inventory.admit_portable_2d_v1().unwrap_err();
        assert!(matches!(
            error.code(),
            "source_profile_not_admitted" | "layout_profile_not_admitted"
        ));
    }

    #[test]
    fn declared_format_mismatch_is_rejected_before_backend_projection() {
        let snapshot = fixture_snapshot();
        let mismatched = DrawingSnapshot::new(DrawingFormat::Dxf, snapshot.bytes());
        assert_eq!(
            inspect_portable_source(&mismatched, "Layout1")
                .unwrap_err()
                .code(),
            "source_reader_admission_failed"
        );
    }
}
