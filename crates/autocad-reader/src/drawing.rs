//! Reader-owned DWG drawing summary projection.
//!
//! The public router limits this expanded projection to DWG input because the
//! pinned DXF decoder does not preserve every required classification field.
//!
//! Empty/sentinel extents and non-finite coordinates are represented as
//! unavailable rather than returned as plausible geometry.

use std::collections::{HashMap, HashSet};

use acadrust::{
    objects::ObjectType,
    tables::BlockRecord,
    types::{Handle, Vector2, Vector3},
    CadDocument,
};

use super::{
    contract::{
        DrawingBounds2, DrawingBounds2Availability, DrawingBounds3, DrawingBounds3Availability,
        DrawingBoundsUnavailableReason, DrawingCounts, DrawingCurrentSettings, DrawingCurrentUcs,
        DrawingExtentsUnavailableReason, DrawingGeometry, DrawingInsertionUnit,
        DrawingMeasurementSystem, DrawingMetadata, DrawingPoint2, DrawingPoint3,
        DrawingPoint3Availability, DrawingPointUnavailableReason, DrawingSavedValueSource,
        DrawingSpaceCurrentUcs, DrawingSpaceGeometry, DrawingSpaceRecord, DrawingSpaces,
        DrawingSummary, DrawingUcsAvailability, DrawingUcsBasis, DrawingUcsUnavailableReason,
        DrawingUnits,
    },
    entity_identity::is_semantic_entity,
    owners::{
        is_model_space_block, is_xref_definition, resolve_direct_owner, DirectOwnerContext,
        DirectOwnerType, DirectOwnerUnavailableReason,
    },
};

impl DrawingInsertionUnit {
    fn from_code(code: i16) -> Option<Self> {
        Some(match code {
            0 => Self::Unitless,
            1 => Self::Inches,
            2 => Self::Feet,
            3 => Self::Miles,
            4 => Self::Millimeters,
            5 => Self::Centimeters,
            6 => Self::Meters,
            7 => Self::Kilometers,
            8 => Self::Microinches,
            9 => Self::Mils,
            10 => Self::Yards,
            11 => Self::Angstroms,
            12 => Self::Nanometers,
            13 => Self::Microns,
            14 => Self::Decimeters,
            15 => Self::Decameters,
            16 => Self::Hectometers,
            17 => Self::Gigameters,
            18 => Self::AstronomicalUnits,
            19 => Self::LightYears,
            20 => Self::Parsecs,
            21 => Self::UsSurveyFeet,
            22 => Self::UsSurveyInches,
            23 => Self::UsSurveyYards,
            24 => Self::UsSurveyMiles,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrawingReadError {
    code: &'static str,
    message: String,
}

impl DrawingReadError {
    pub(crate) fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for DrawingReadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "code={} {}", self.code, self.message)
    }
}

impl std::error::Error for DrawingReadError {}

fn validate_block_record_identities(doc: &CadDocument) -> Result<(), DrawingReadError> {
    let mut records = doc.block_records.iter().collect::<Vec<_>>();
    records.sort_by_key(|record| record.handle.value());

    if records.iter().any(|record| record.handle.is_null()) {
        return Err(DrawingReadError::new(
            "invalid_block_record_handle",
            "drawing contains a block record with handle 0",
        ));
    }
    if let Some(pair) = records
        .windows(2)
        .find(|pair| pair[0].handle == pair[1].handle)
    {
        return Err(DrawingReadError::new(
            "duplicate_block_record_handle",
            format!(
                "multiple block records use handle {:X}",
                pair[0].handle.value()
            ),
        ));
    }

    let model_records = records
        .iter()
        .filter(|record| is_model_space_block(record))
        .collect::<Vec<_>>();
    if model_records.len() > 1 {
        return Err(DrawingReadError::new(
            "ambiguous_model_space",
            "multiple block records identify themselves as model space",
        ));
    }
    if doc.header.model_space_block_handle.is_valid() {
        if let Some(header_record) = records
            .iter()
            .find(|record| record.handle == doc.header.model_space_block_handle)
        {
            if !is_model_space_block(header_record) {
                return Err(DrawingReadError::new(
                    "contradictory_model_space",
                    format!(
                        "header model-space handle {:X} identifies block `{}`",
                        header_record.handle.value(),
                        header_record.name
                    ),
                ));
            }
        }
    }

    Ok(())
}

/// Return a bounded drawing-level summary without interpreting fields that the
/// pinned document model does not preserve.
pub(super) fn get_drawing(doc: &CadDocument) -> Result<DrawingSummary, DrawingReadError> {
    validate_block_record_identities(doc)?;
    let header = &doc.header;
    let owner_classes = block_owner_classes(doc)?;
    let spaces = drawing_spaces(doc, &owner_classes);
    let model_has_content = spaces
        .model_space
        .as_ref()
        .is_some_and(|space| space.entity_count > 0);
    let paper_has_content = spaces
        .paper_spaces
        .iter()
        .any(|space| space.entity_count > 0);
    Ok(DrawingSummary {
        version: doc.version.as_str().to_string(),
        maintenance_version: doc.maintenance_version,
        units: DrawingUnits {
            insertion_unit_code: header.insertion_units,
            insertion_unit: DrawingInsertionUnit::from_code(header.insertion_units),
            measurement_system_code: header.measurement,
            measurement_system: match header.measurement {
                0 => DrawingMeasurementSystem::English,
                1 => DrawingMeasurementSystem::Metric,
                _ => DrawingMeasurementSystem::Unknown,
            },
            linear_format_code: header.linear_unit_format,
            linear_precision: header.linear_unit_precision,
            angular_format_code: header.angular_unit_format,
            angular_precision: header.angular_unit_precision,
        },
        metadata: DrawingMetadata {
            code_page: header.code_page.clone(),
            last_saved_by: nonempty(&header.last_saved_by),
            project_name: nonempty(&header.project_name),
            fingerprint_guid: nonempty(&header.fingerprint_guid),
            version_guid: nonempty(&header.version_guid),
            hyperlink_base: nonempty(&header.hyperlink_base),
        },
        geometry: DrawingGeometry {
            model_space: DrawingSpaceGeometry {
                source: DrawingSavedValueSource::SavedHeader,
                insertion_base: point3_availability(header.model_space_insertion_base),
                extents: extents3_availability(
                    header.model_space_extents_min,
                    header.model_space_extents_max,
                    model_has_content,
                ),
                limits: bounds2_availability(
                    header.model_space_limits_min,
                    header.model_space_limits_max,
                ),
            },
            paper_space: DrawingSpaceGeometry {
                source: DrawingSavedValueSource::SavedHeader,
                insertion_base: point3_availability(header.paper_space_insertion_base),
                extents: extents3_availability(
                    header.paper_space_extents_min,
                    header.paper_space_extents_max,
                    paper_has_content,
                ),
                limits: bounds2_availability(
                    header.paper_space_limits_min,
                    header.paper_space_limits_max,
                ),
            },
        },
        current_ucs: DrawingCurrentUcs {
            model_space: DrawingSpaceCurrentUcs {
                source: DrawingSavedValueSource::SavedHeader,
                name: nonempty(&header.model_space_ucs_name),
                basis: ucs_availability(
                    header.model_space_ucs_origin,
                    header.model_space_ucs_x_axis,
                    header.model_space_ucs_y_axis,
                ),
            },
            paper_space: DrawingSpaceCurrentUcs {
                source: DrawingSavedValueSource::SavedHeader,
                name: nonempty(&header.paper_space_ucs_name),
                basis: ucs_availability(
                    header.paper_space_ucs_origin,
                    header.paper_space_ucs_x_axis,
                    header.paper_space_ucs_y_axis,
                ),
            },
        },
        spaces,
        counts: drawing_counts(doc, &owner_classes),
        current_settings: DrawingCurrentSettings {
            layer: header.current_layer_name.clone(),
            linetype: header.current_linetype_name.clone(),
            text_style: header.current_text_style_name.clone(),
            dimension_style: header.current_dimstyle_name.clone(),
            table_style: header.current_table_style_name.clone(),
            multileader_style: header.current_mleader_style_name.clone(),
            show_model_space: header.show_model_space,
        },
    })
}

fn drawing_counts(
    doc: &CadDocument,
    owner_classes: &HashMap<Handle, BlockOwnerClass>,
) -> DrawingCounts {
    DrawingCounts {
        entities: doc
            .entities()
            .filter(|entity| is_semantic_entity(entity))
            .count(),
        visible_entities: doc
            .entities()
            .filter(|entity| is_semantic_entity(entity))
            .filter(|entity| !entity.common().invisible)
            .count(),
        unknown_entities: doc
            .entities()
            .filter(|entity| is_semantic_entity(entity))
            .filter(|entity| matches!(entity, acadrust::entities::EntityType::Unknown(_)))
            .count(),
        layers: doc.layers.len(),
        linetypes: doc.line_types.len(),
        text_styles: doc.text_styles.len(),
        dimension_styles: doc.dim_styles.len(),
        named_views: doc.views.len(),
        named_ucs: doc.ucss.len(),
        block_definitions: doc
            .block_records
            .iter()
            .filter(|block| {
                matches!(
                    owner_classes.get(&block.handle),
                    Some(BlockOwnerClass::BlockDefinition)
                ) && !is_xref_definition(block)
                    && !super::is_xref_dependent_definition(block)
            })
            .count(),
        xref_attachments: doc
            .block_records
            .iter()
            .filter(|block| is_xref_definition(block))
            .count(),
        layouts: doc
            .objects
            .values()
            .filter(|object| matches!(object, ObjectType::Layout(_)))
            .count(),
        objects: doc.objects.len(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockOwnerClass {
    ModelSpace,
    PaperSpace,
    BlockDefinition,
}

fn block_owner_classes(
    doc: &CadDocument,
) -> Result<HashMap<Handle, BlockOwnerClass>, DrawingReadError> {
    let mut classes = HashMap::new();
    for block in doc.block_records.iter() {
        let context = resolve_direct_owner(doc, block.handle).map_err(|error| {
            DrawingReadError::new("unsupported_drawing_data", error.to_string())
        })?;
        let class = match context {
            Some(DirectOwnerContext::Available {
                owner_type: DirectOwnerType::ModelSpace,
                ..
            }) => BlockOwnerClass::ModelSpace,
            Some(DirectOwnerContext::Available {
                owner_type: DirectOwnerType::PaperSpace,
                ..
            })
            | Some(DirectOwnerContext::Unavailable {
                reason: DirectOwnerUnavailableReason::MissingPaperSpaceLayout,
            }) => BlockOwnerClass::PaperSpace,
            Some(DirectOwnerContext::Available {
                owner_type: DirectOwnerType::BlockDefinition,
                ..
            }) => BlockOwnerClass::BlockDefinition,
            Some(DirectOwnerContext::Available {
                owner_type: DirectOwnerType::Entity,
                ..
            })
            | Some(DirectOwnerContext::Unavailable {
                reason: DirectOwnerUnavailableReason::UnresolvedOwner,
            })
            | None => {
                return Err(DrawingReadError::new(
                    "unsupported_drawing_data",
                    format!(
                        "block record {:X} has no coherent semantic owner classification",
                        block.handle.value()
                    ),
                ))
            }
        };
        if classes.insert(block.handle, class).is_some() {
            return Err(DrawingReadError::new(
                "duplicate_block_record_handle",
                format!(
                    "multiple block records use handle {:X}",
                    block.handle.value()
                ),
            ));
        }
    }
    Ok(classes)
}

fn drawing_spaces(
    doc: &CadDocument,
    owner_classes: &HashMap<Handle, BlockOwnerClass>,
) -> DrawingSpaces {
    let entity_counts = entity_counts_by_owner(doc);

    let model_block = doc.block_records.iter().find(|block| {
        matches!(
            owner_classes.get(&block.handle),
            Some(BlockOwnerClass::ModelSpace)
        )
    });
    let model_space = model_block.map(|block| space_record(block, &entity_counts));

    let mut paper_blocks = doc
        .block_records
        .iter()
        .filter(|block| {
            matches!(
                owner_classes.get(&block.handle),
                Some(BlockOwnerClass::PaperSpace)
            )
        })
        .collect::<Vec<_>>();
    paper_blocks.sort_by(|left, right| {
        left.name
            .to_uppercase()
            .cmp(&right.name.to_uppercase())
            .then_with(|| left.handle.cmp(&right.handle))
    });
    paper_blocks.dedup_by_key(|block| block.handle);
    let paper_spaces = paper_blocks
        .into_iter()
        .map(|block| space_record(block, &entity_counts))
        .collect::<Vec<_>>();

    let entity_handles = doc
        .entities()
        .filter(|entity| is_semantic_entity(entity))
        .map(|entity| entity.common().handle)
        .filter(|handle| handle.is_valid())
        .collect::<HashSet<_>>();

    let mut block_definition_entity_count = 0;
    let mut nested_entity_count = 0;
    let mut unresolved_owner_entity_count = 0;
    for entity in doc.entities().filter(|entity| is_semantic_entity(entity)) {
        let owner = entity.common().owner_handle;
        match owner_classes.get(&owner) {
            Some(BlockOwnerClass::ModelSpace | BlockOwnerClass::PaperSpace) => {}
            Some(BlockOwnerClass::BlockDefinition) => {
                block_definition_entity_count += 1;
            }
            None if owner.is_valid() && entity_handles.contains(&owner) => {
                nested_entity_count += 1;
            }
            None => {
                unresolved_owner_entity_count += 1;
            }
        }
    }

    DrawingSpaces {
        model_space,
        paper_spaces,
        block_definition_entity_count,
        nested_entity_count,
        unresolved_owner_entity_count,
    }
}

fn entity_counts_by_owner(doc: &CadDocument) -> HashMap<Handle, usize> {
    let mut counts = HashMap::new();
    for entity in doc.entities().filter(|entity| is_semantic_entity(entity)) {
        *counts.entry(entity.common().owner_handle).or_insert(0) += 1;
    }
    counts
}

fn space_record(block: &BlockRecord, entity_counts: &HashMap<Handle, usize>) -> DrawingSpaceRecord {
    DrawingSpaceRecord {
        handle: optional_handle(block.handle),
        name: block.name.clone(),
        entity_count: entity_counts.get(&block.handle).copied().unwrap_or(0),
    }
}

fn optional_handle(handle: Handle) -> Option<String> {
    handle.is_valid().then(|| format!("{:X}", handle.value()))
}

fn nonempty(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_string())
}

fn point2(value: Vector2) -> DrawingPoint2 {
    DrawingPoint2 {
        x: value.x,
        y: value.y,
    }
}

fn point3(value: Vector3) -> DrawingPoint3 {
    DrawingPoint3 {
        x: value.x,
        y: value.y,
        z: value.z,
    }
}

fn point2_is_finite(value: Vector2) -> bool {
    value.x.is_finite() && value.y.is_finite()
}

fn point3_is_finite(value: Vector3) -> bool {
    value.x.is_finite() && value.y.is_finite() && value.z.is_finite()
}

fn point3_availability(value: Vector3) -> DrawingPoint3Availability {
    if point3_is_finite(value) {
        DrawingPoint3Availability::Available {
            point: point3(value),
        }
    } else {
        DrawingPoint3Availability::Unavailable {
            reason: DrawingPointUnavailableReason::NonFinite,
        }
    }
}

fn bounds2_availability(min: Vector2, max: Vector2) -> DrawingBounds2Availability {
    if !point2_is_finite(min) || !point2_is_finite(max) {
        return DrawingBounds2Availability::Unavailable {
            reason: DrawingBoundsUnavailableReason::NonFinite,
        };
    }
    if min.x > max.x || min.y > max.y {
        return DrawingBounds2Availability::Unavailable {
            reason: DrawingBoundsUnavailableReason::InvertedBounds,
        };
    }
    DrawingBounds2Availability::Available {
        bounds: DrawingBounds2 {
            min: point2(min),
            max: point2(max),
        },
    }
}

fn is_empty_space_extents_sentinel(min: Vector3, max: Vector3) -> bool {
    const EMPTY_EXTENTS_MAX: f64 = 1.0e20;
    let standard_sentinel = min.x == EMPTY_EXTENTS_MAX
        && min.y == EMPTY_EXTENTS_MAX
        && min.z == EMPTY_EXTENTS_MAX
        && max.x == -EMPTY_EXTENTS_MAX
        && max.y == -EMPTY_EXTENTS_MAX
        && max.z == -EMPTY_EXTENTS_MAX;
    let zero_origin_sentinel = min.x == 0.0
        && min.y == 0.0
        && min.z == 0.0
        && max.x == 0.0
        && max.y == 0.0
        && max.z == 0.0;
    standard_sentinel || zero_origin_sentinel
}

fn extents3_availability(
    min: Vector3,
    max: Vector3,
    has_content: bool,
) -> DrawingBounds3Availability {
    if !point3_is_finite(min) || !point3_is_finite(max) {
        return DrawingBounds3Availability::Unavailable {
            reason: DrawingExtentsUnavailableReason::NonFinite,
        };
    }
    if !has_content && is_empty_space_extents_sentinel(min, max) {
        return DrawingBounds3Availability::Unavailable {
            reason: DrawingExtentsUnavailableReason::EmptySpaceSentinel,
        };
    }
    if min.x > max.x || min.y > max.y || min.z > max.z {
        return DrawingBounds3Availability::Unavailable {
            reason: DrawingExtentsUnavailableReason::InvertedBounds,
        };
    }
    DrawingBounds3Availability::Available {
        bounds: DrawingBounds3 {
            min: point3(min),
            max: point3(max),
        },
    }
}

fn ucs_availability(origin: Vector3, x_axis: Vector3, y_axis: Vector3) -> DrawingUcsAvailability {
    if !point3_is_finite(origin) || !point3_is_finite(x_axis) || !point3_is_finite(y_axis) {
        return DrawingUcsAvailability::Unavailable {
            reason: DrawingUcsUnavailableReason::NonFinite,
        };
    }
    DrawingUcsAvailability::Available {
        basis: DrawingUcsBasis {
            origin: point3(origin),
            x_axis: point3(x_axis),
            y_axis: point3(y_axis),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        contract::{EntityListOptions, MAX_ENTITY_LIST_LIMIT},
        Reader,
    };
    use acadrust::{
        entities::{AttributeEntity, Circle, EntityType, Insert, Line, UnknownEntity},
        objects::Layout,
        tables::BlockRecord,
        types::{DxfVersion, Handle, Vector2, Vector3},
        CadDocument,
    };
    use std::path::{Path, PathBuf};

    fn fixture_path(relative: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(relative)
    }

    fn get_drawing(doc: &CadDocument) -> DrawingSummary {
        super::get_drawing(doc).unwrap()
    }

    #[test]
    fn new_document_summary_reports_defaults_without_fake_extents() {
        let summary = get_drawing(&CadDocument::new());

        assert_eq!(summary.version, "AC1032");
        assert_eq!(summary.maintenance_version, 0);
        assert_eq!(
            summary.units.insertion_unit,
            Some(DrawingInsertionUnit::Unitless)
        );
        assert_eq!(
            summary.units.measurement_system,
            DrawingMeasurementSystem::English
        );
        assert_eq!(summary.metadata.code_page, "ANSI_1252");
        assert_eq!(
            summary.geometry.model_space.source,
            DrawingSavedValueSource::SavedHeader
        );
        assert_eq!(
            summary.geometry.model_space.extents,
            DrawingBounds3Availability::Unavailable {
                reason: DrawingExtentsUnavailableReason::EmptySpaceSentinel,
            }
        );
        assert_eq!(
            summary.geometry.paper_space.extents,
            DrawingBounds3Availability::Unavailable {
                reason: DrawingExtentsUnavailableReason::EmptySpaceSentinel,
            }
        );
        assert_eq!(
            summary.current_ucs.model_space.source,
            DrawingSavedValueSource::SavedHeader
        );
        assert_eq!(summary.current_ucs.model_space.name, None);
        assert_eq!(
            summary.current_ucs.model_space.basis,
            DrawingUcsAvailability::Available {
                basis: DrawingUcsBasis {
                    origin: DrawingPoint3 {
                        x: 0.0,
                        y: 0.0,
                        z: 0.0,
                    },
                    x_axis: DrawingPoint3 {
                        x: 1.0,
                        y: 0.0,
                        z: 0.0,
                    },
                    y_axis: DrawingPoint3 {
                        x: 0.0,
                        y: 1.0,
                        z: 0.0,
                    },
                },
            }
        );
        assert_eq!(summary.counts.entities, 0);
        assert_eq!(summary.counts.layers, 1);
        assert_eq!(summary.counts.linetypes, 3);
        assert_eq!(summary.counts.text_styles, 1);
        assert_eq!(summary.counts.dimension_styles, 1);
        assert_eq!(summary.counts.block_definitions, 0);
        assert_eq!(summary.counts.xref_attachments, 0);
        assert_eq!(summary.counts.layouts, 2);
        assert_eq!(
            summary.spaces.model_space.as_ref().unwrap().name,
            "*Model_Space"
        );
        assert_eq!(summary.spaces.paper_spaces.len(), 1);
    }

    #[test]
    fn version_units_and_unknown_codes_are_preserved() {
        let mut doc = CadDocument::with_version(DxfVersion::AC1027);
        doc.maintenance_version = 7;
        doc.header.insertion_units = 4;
        doc.header.measurement = 1;

        let summary = get_drawing(&doc);
        assert_eq!(summary.version, "AC1027");
        assert_eq!(summary.maintenance_version, 7);
        assert_eq!(
            summary.units.insertion_unit,
            Some(DrawingInsertionUnit::Millimeters)
        );
        assert_eq!(
            summary.units.measurement_system,
            DrawingMeasurementSystem::Metric
        );

        doc.header.insertion_units = 99;
        doc.header.measurement = 42;
        let summary = get_drawing(&doc);
        assert_eq!(summary.units.insertion_unit_code, 99);
        assert_eq!(summary.units.insertion_unit, None);
        assert_eq!(summary.units.measurement_system_code, 42);
        assert_eq!(
            summary.units.measurement_system,
            DrawingMeasurementSystem::Unknown
        );
    }

    #[test]
    fn all_known_insertion_unit_codes_have_closed_names() {
        for code in 0..=24 {
            assert!(
                DrawingInsertionUnit::from_code(code).is_some(),
                "missing INSUNITS code {code}"
            );
        }
        assert_eq!(DrawingInsertionUnit::from_code(-1), None);
        assert_eq!(DrawingInsertionUnit::from_code(25), None);
    }

    #[test]
    fn valid_geometry_is_exposed_and_inverted_or_nonfinite_values_are_not() {
        let mut doc = CadDocument::new();
        doc.header.model_space_insertion_base = Vector3::new(1.0, 2.0, 3.0);
        doc.header.model_space_extents_min = Vector3::new(-1.0, -2.0, -3.0);
        doc.header.model_space_extents_max = Vector3::new(4.0, 5.0, 6.0);
        doc.header.model_space_limits_min = Vector2::new(-10.0, -20.0);
        doc.header.model_space_limits_max = Vector2::new(10.0, 20.0);

        let geometry = get_drawing(&doc).geometry.model_space;
        assert_eq!(
            geometry.insertion_base,
            DrawingPoint3Availability::Available {
                point: DrawingPoint3 {
                    x: 1.0,
                    y: 2.0,
                    z: 3.0,
                },
            }
        );
        assert_eq!(
            geometry.extents,
            DrawingBounds3Availability::Available {
                bounds: DrawingBounds3 {
                    min: DrawingPoint3 {
                        x: -1.0,
                        y: -2.0,
                        z: -3.0,
                    },
                    max: DrawingPoint3 {
                        x: 4.0,
                        y: 5.0,
                        z: 6.0,
                    },
                },
            }
        );
        assert_eq!(
            geometry.limits,
            DrawingBounds2Availability::Available {
                bounds: DrawingBounds2 {
                    min: DrawingPoint2 { x: -10.0, y: -20.0 },
                    max: DrawingPoint2 { x: 10.0, y: 20.0 },
                },
            }
        );

        doc.header.model_space_extents_min = Vector3::new(10.0, 0.0, 0.0);
        doc.header.model_space_extents_max = Vector3::new(0.0, 10.0, 10.0);
        doc.header.model_space_limits_min = Vector2::new(f64::NAN, 0.0);
        doc.header.model_space_insertion_base = Vector3::new(f64::INFINITY, 0.0, 0.0);
        let geometry = get_drawing(&doc).geometry.model_space;
        assert_eq!(
            geometry.extents,
            DrawingBounds3Availability::Unavailable {
                reason: DrawingExtentsUnavailableReason::InvertedBounds,
            }
        );
        assert_eq!(
            geometry.limits,
            DrawingBounds2Availability::Unavailable {
                reason: DrawingBoundsUnavailableReason::NonFinite,
            }
        );
        assert_eq!(
            geometry.insertion_base,
            DrawingPoint3Availability::Unavailable {
                reason: DrawingPointUnavailableReason::NonFinite,
            }
        );

        doc.header.model_space_extents_min = Vector3::new(f64::NAN, 0.0, 0.0);
        let geometry = get_drawing(&doc).geometry.model_space;
        assert_eq!(
            geometry.extents,
            DrawingBounds3Availability::Unavailable {
                reason: DrawingExtentsUnavailableReason::NonFinite,
            }
        );

        doc.header.model_space_extents_min = Vector3::ZERO;
        doc.header.model_space_extents_max = Vector3::ZERO;
        let geometry = get_drawing(&doc).geometry.model_space;
        assert_eq!(
            geometry.extents,
            DrawingBounds3Availability::Unavailable {
                reason: DrawingExtentsUnavailableReason::EmptySpaceSentinel,
            }
        );
        serde_json::to_string(&get_drawing(&doc)).unwrap();
    }

    #[test]
    fn current_model_and_paper_ucs_are_saved_header_values_with_availability() {
        let mut doc = CadDocument::new();
        doc.header.model_space_ucs_name = "SITE".to_string();
        doc.header.model_space_ucs_origin = Vector3::new(10.0, 20.0, 30.0);
        doc.header.model_space_ucs_x_axis = Vector3::new(0.0, 1.0, 0.0);
        doc.header.model_space_ucs_y_axis = Vector3::new(-1.0, 0.0, 0.0);
        doc.header.paper_space_ucs_name = "SHEET".to_string();
        doc.header.paper_space_ucs_origin = Vector3::new(1.0, 2.0, 0.0);

        let current = get_drawing(&doc).current_ucs;
        assert_eq!(
            current.model_space.source,
            DrawingSavedValueSource::SavedHeader
        );
        assert_eq!(current.model_space.name.as_deref(), Some("SITE"));
        assert_eq!(
            current.model_space.basis,
            DrawingUcsAvailability::Available {
                basis: DrawingUcsBasis {
                    origin: DrawingPoint3 {
                        x: 10.0,
                        y: 20.0,
                        z: 30.0,
                    },
                    x_axis: DrawingPoint3 {
                        x: 0.0,
                        y: 1.0,
                        z: 0.0,
                    },
                    y_axis: DrawingPoint3 {
                        x: -1.0,
                        y: 0.0,
                        z: 0.0,
                    },
                },
            }
        );
        assert_eq!(
            current.paper_space.source,
            DrawingSavedValueSource::SavedHeader
        );
        assert_eq!(current.paper_space.name.as_deref(), Some("SHEET"));

        doc.header.paper_space_ucs_y_axis = Vector3::new(0.0, f64::NAN, 0.0);
        let paper = get_drawing(&doc).current_ucs.paper_space;
        assert_eq!(paper.name.as_deref(), Some("SHEET"));
        assert_eq!(
            paper.basis,
            DrawingUcsAvailability::Unavailable {
                reason: DrawingUcsUnavailableReason::NonFinite,
            }
        );
        serde_json::to_string(&paper).unwrap();
    }

    #[test]
    fn metadata_distinguishes_absent_from_preserved_values() {
        let mut doc = CadDocument::new();
        let empty = get_drawing(&doc).metadata;
        assert_eq!(empty.last_saved_by, None);
        assert_eq!(empty.project_name, None);

        doc.header.last_saved_by = "A. Drafter".to_string();
        doc.header.project_name = "Station".to_string();
        doc.header.fingerprint_guid = "{FINGERPRINT}".to_string();
        doc.header.version_guid = "{VERSION}".to_string();
        doc.header.hyperlink_base = "drawings/".to_string();
        let metadata = get_drawing(&doc).metadata;
        assert_eq!(metadata.last_saved_by.as_deref(), Some("A. Drafter"));
        assert_eq!(metadata.project_name.as_deref(), Some("Station"));
        assert_eq!(metadata.fingerprint_guid.as_deref(), Some("{FINGERPRINT}"));
        assert_eq!(metadata.version_guid.as_deref(), Some("{VERSION}"));
        assert_eq!(metadata.hyperlink_base.as_deref(), Some("drawings/"));
    }

    #[test]
    fn counts_cover_entities_resources_layouts_and_dependencies() {
        let mut doc = CadDocument::new();
        doc.add_entity(EntityType::Line(Line::new())).unwrap();

        let mut hidden = Circle::new();
        hidden.common.invisible = true;
        doc.add_paper_space_entity(EntityType::Circle(hidden))
            .unwrap();

        let mut block = BlockRecord::new("DETAIL");
        block.handle = doc.allocate_handle();
        let block_handle = block.handle;
        doc.block_records.add(block).unwrap();
        let mut block_line = Line::new();
        block_line.common.owner_handle = block_handle;
        doc.add_entity(EntityType::Line(block_line)).unwrap();

        let mut xref = BlockRecord::new("SITE");
        xref.handle = doc.allocate_handle();
        xref.xref_path = "refs/site.dwg".to_string();
        doc.block_records.add(xref).unwrap();

        let mut external = BlockRecord::new("SITE|DETAIL");
        external.handle = doc.allocate_handle();
        doc.block_records.add(external).unwrap();

        let unknown = UnknownEntity::new("ACAD_PROXY_ENTITY");
        doc.add_entity(EntityType::Unknown(unknown)).unwrap();

        let summary = get_drawing(&doc);
        assert_eq!(summary.counts.entities, 4);
        assert_eq!(summary.counts.visible_entities, 3);
        assert_eq!(summary.counts.unknown_entities, 1);
        assert_eq!(summary.counts.block_definitions, 1);
        assert_eq!(summary.counts.xref_attachments, 1);
        assert_eq!(summary.spaces.model_space.unwrap().entity_count, 2);
        assert_eq!(summary.spaces.paper_spaces[0].entity_count, 1);
        assert_eq!(summary.spaces.block_definition_entity_count, 1);
    }

    #[test]
    fn tier1_dwg_summary_count_agrees_with_semantic_list_and_backend_iteration() {
        let path =
            fixture_path("tests/corpus/open/acadsharp/dynamic-blocks/BLOCKVISIBILITYPARAMETER.dwg");
        let session = Reader::open_path(&path).unwrap();
        let listed = session
            .list_entities(&EntityListOptions {
                include_invisible: true,
                limit: MAX_ENTITY_LIST_LIMIT,
                ..Default::default()
            })
            .unwrap();
        let summary = session.get_drawing().unwrap();
        let backend_entity_count = session.into_backend_document().entity_count();

        assert_eq!(summary.counts.entities, listed.total);
        assert_eq!(summary.counts.entities, backend_entity_count);
        assert_eq!(
            summary.spaces.model_space.unwrap().entity_count
                + summary
                    .spaces
                    .paper_spaces
                    .iter()
                    .map(|space| space.entity_count)
                    .sum::<usize>()
                + summary.spaces.block_definition_entity_count
                + summary.spaces.nested_entity_count
                + summary.spaces.unresolved_owner_entity_count,
            summary.counts.entities
        );
    }

    #[test]
    fn nested_entity_ownership_is_not_misclassified_as_a_space() {
        let mut doc = CadDocument::new();
        let insert_handle = doc
            .add_entity(EntityType::Insert(Insert::new("TITLE", Vector3::ZERO)))
            .unwrap();
        let mut attribute = AttributeEntity::simple("SHEET", "A1");
        attribute.common.owner_handle = insert_handle;
        doc.add_entity(EntityType::AttributeEntity(attribute))
            .unwrap();

        let spaces = get_drawing(&doc).spaces;
        assert_eq!(spaces.model_space.unwrap().entity_count, 1);
        assert_eq!(spaces.nested_entity_count, 1);
        assert_eq!(spaces.unresolved_owner_entity_count, 0);
    }

    #[test]
    fn paper_spaces_are_deterministic_after_layout_additions() {
        let mut doc = CadDocument::new();
        doc.add_layout("Sheet Z").unwrap();
        doc.add_layout("Sheet A").unwrap();

        let first = get_drawing(&doc).spaces.paper_spaces;
        let second = get_drawing(&doc).spaces.paper_spaces;
        assert_eq!(first, second);
        let names = first
            .iter()
            .map(|space| space.name.to_uppercase())
            .collect::<Vec<_>>();
        assert!(names.windows(2).all(|pair| pair[0] <= pair[1]));
    }

    #[test]
    fn layout_object_join_drives_nonstandard_paper_space_classification() {
        let mut doc = CadDocument::new();
        let layout_handle = doc.add_layout("Sheet Custom").unwrap();
        let block_handle = match doc.objects.get(&layout_handle).unwrap() {
            ObjectType::Layout(layout) => layout.block_record,
            _ => panic!("new layout handle did not resolve to a LAYOUT object"),
        };
        doc.block_records
            .iter_mut()
            .find(|block| block.handle == block_handle)
            .unwrap()
            .name = "SHEET_CUSTOM_BACKING".to_string();

        let mut line = Line::new();
        line.common.owner_handle = block_handle;
        doc.add_entity(EntityType::Line(line)).unwrap();

        let expected_entity_count = doc
            .entities()
            .filter(|entity| {
                is_semantic_entity(entity) && entity.common().owner_handle == block_handle
            })
            .count();
        let summary = get_drawing(&doc);
        let expected_handle = format!("{:X}", block_handle.value());
        let paper = summary
            .spaces
            .paper_spaces
            .iter()
            .find(|space| space.handle.as_deref() == Some(expected_handle.as_str()))
            .unwrap();
        assert_eq!(paper.name, "SHEET_CUSTOM_BACKING");
        assert_eq!(paper.entity_count, expected_entity_count);
        assert_eq!(summary.spaces.block_definition_entity_count, 0);
        assert_eq!(summary.counts.block_definitions, 0);
    }

    #[test]
    fn duplicate_layout_to_block_join_fails_drawing_summary() {
        let mut doc = CadDocument::new();
        let paper = doc.header.paper_space_block_handle;
        let mut duplicate = Layout::new("Duplicate");
        duplicate.handle = Handle::new(0xD01);
        duplicate.block_record = paper;
        doc.objects
            .insert(duplicate.handle, ObjectType::Layout(duplicate));

        let error = super::get_drawing(&doc).unwrap_err();
        assert_eq!(error.code(), "unsupported_drawing_data");
        assert!(error.message().contains("duplicate_owner_layout"));
    }

    #[test]
    fn current_settings_are_preserved() {
        let mut doc = CadDocument::new();
        doc.header.current_layer_name = "A-WALL".to_string();
        doc.header.current_linetype_name = "DASHED".to_string();
        doc.header.current_text_style_name = "NOTES".to_string();
        doc.header.current_dimstyle_name = "ISO-25".to_string();
        doc.header.show_model_space = false;

        let settings = get_drawing(&doc).current_settings;
        assert_eq!(settings.layer, "A-WALL");
        assert_eq!(settings.linetype, "DASHED");
        assert_eq!(settings.text_style, "NOTES");
        assert_eq!(settings.dimension_style, "ISO-25");
        assert!(!settings.show_model_space);
    }

    #[test]
    fn duplicate_or_contradictory_model_space_records_fail_closed() {
        let mut duplicate = CadDocument::new();
        let mut first = BlockRecord::new("DETAIL_A");
        first.handle = Handle::new(0xD00);
        duplicate.block_records.add(first).unwrap();
        let mut second = BlockRecord::new("DETAIL_B");
        second.handle = Handle::new(0xD00);
        duplicate.block_records.add(second).unwrap();
        let error = super::get_drawing(&duplicate).unwrap_err();
        assert_eq!(error.code(), "duplicate_block_record_handle");

        let mut contradictory = CadDocument::new();
        let model_handle = contradictory.header.model_space_block_handle;
        contradictory
            .block_records
            .iter_mut()
            .find(|record| record.handle == model_handle)
            .unwrap()
            .name = "NOT_MODEL_SPACE".to_string();
        let error = super::get_drawing(&contradictory).unwrap_err();
        assert_eq!(error.code(), "contradictory_model_space");
    }

    #[test]
    fn summary_round_trips_rejects_unknown_fields_and_has_a_schema() {
        let summary = get_drawing(&CadDocument::new());
        let json = serde_json::to_string(&summary).unwrap();
        let parsed: DrawingSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, summary);

        let mut value = serde_json::to_value(&summary).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_string(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<DrawingSummary>(value).is_err());

        let mut nested = serde_json::to_value(&summary).unwrap();
        nested["geometry"]["model_space"]["extents"]
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_string(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<DrawingSummary>(nested).is_err());

        let unavailable = DrawingBounds3Availability::Unavailable {
            reason: DrawingExtentsUnavailableReason::EmptySpaceSentinel,
        };
        let value = serde_json::to_value(unavailable).unwrap();
        assert_eq!(value["state"], "unavailable");
        assert_eq!(value["reason"], "empty_space_sentinel");
        assert_eq!(
            serde_json::from_value::<DrawingBounds3Availability>(value).unwrap(),
            unavailable
        );
        assert!(
            serde_json::from_value::<DrawingBounds3Availability>(serde_json::json!({
                "state": "unavailable",
                "reason": "guessed"
            }))
            .is_err()
        );

        let _summary_schema = schemars::schema_for!(DrawingSummary);
        let _geometry_schema = schemars::schema_for!(DrawingSpaceGeometry);
        let _ucs_schema = schemars::schema_for!(DrawingSpaceCurrentUcs);
    }
}
