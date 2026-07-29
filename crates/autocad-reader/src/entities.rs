//! Reader-owned bounded DWG entity inspection.
//!
//! The public router limits this expanded projection to DWG input because the
//! pinned DXF decoder does not preserve every required classification field.
//! The common record is available for every semantic entity represented by
//! `acadrust`; structural BLOCK, ENDBLK, and SEQEND markers are excluded.
//! [`EntityDetail`] intentionally exposes fixed-size detail for a useful subset
//! of entity types. Complex collections such as polyline vertices, hatch
//! boundaries, and mesh faces are summarized by counts rather than copied into
//! list responses. TABLE, MULTILEADER, 3DSOLID, and ACAD_SURFACE projections
//! remain unsupported until representative committed decoder proof exists.

use std::{collections::BTreeSet, fmt};

use acadrust::{
    entities::{BoundaryEdge, EntityType},
    types::{Color, Handle, LineWeight, Vector3},
    CadDocument,
};

use super::{
    contract::{
        EntityBooleanAvailability, EntityBooleanUnavailableReason, EntityBounds3,
        EntityBoundsAvailability, EntityBoundsUnavailableReason, EntityColor, EntityDetail,
        EntityDetailUnsupportedReason, EntityHelixConstraint, EntityHelixHandedness,
        EntityLineWeight, EntityLinetype, EntityListOptions, EntityListResult,
        EntityNumberAvailability, EntityNumberUnavailableReason, EntityPoint3, EntityRecord,
        EntityScale3, EntityStringAvailability, EntityStringUnavailableReason, EntityTransparency,
        PolylineRepresentation, MAX_ENTITY_LIST_LIMIT,
    },
    dynamic_blocks::resolve_dynamic_block_link,
    entity_identity::{
        entity_type_name, is_semantic_entity,
        validate_semantic_entity_handles as validate_reader_entity_handles,
        ACADRUST_INSERT_SCALE_SENTINEL,
    },
    owners::resolve_direct_owner,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityReadError {
    code: &'static str,
    message: String,
}

impl EntityReadError {
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

impl fmt::Display for EntityReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "code={} {}", self.code, self.message)
    }
}

impl std::error::Error for EntityReadError {}

struct EntityFilters {
    entity_types: Option<BTreeSet<String>>,
    layer: Option<String>,
    owner_handle: Option<Handle>,
}

fn validate_semantic_entity_handles(doc: &CadDocument) -> Result<(), EntityReadError> {
    validate_reader_entity_handles(doc)
        .map_err(|error| EntityReadError::new(error.code(), error.message()))
}

/// List entities in canonical handle order using bounded pagination.
pub(super) fn list_entities(
    doc: &CadDocument,
    options: &EntityListOptions,
) -> Result<EntityListResult, EntityReadError> {
    let filters = validate_options(options)?;
    validate_semantic_entity_handles(doc)?;
    let mut matches = doc
        .entities()
        .filter(|entity| is_semantic_entity(entity))
        .filter(|entity| options.include_invisible || !entity.common().invisible)
        .filter(|entity| {
            filters
                .entity_types
                .as_ref()
                .map(|types| types.contains(&entity_type_name(entity)))
                .unwrap_or(true)
        })
        .filter(|entity| {
            filters
                .layer
                .as_ref()
                .map(|layer| cad_name_key(&entity.common().layer) == *layer)
                .unwrap_or(true)
        })
        .filter(|entity| {
            filters
                .owner_handle
                .map(|owner| entity.common().owner_handle == owner)
                .unwrap_or(true)
        })
        .collect::<Vec<_>>();

    matches.sort_by(|left, right| {
        left.common()
            .handle
            .cmp(&right.common().handle)
            .then_with(|| entity_type_name(left).cmp(&entity_type_name(right)))
            .then_with(|| left.common().layer.cmp(&right.common().layer))
    });

    let total = matches.len();
    let items = matches
        .into_iter()
        .skip(options.offset)
        .take(options.limit)
        .map(|entity| entity_record(doc, entity))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(EntityListResult {
        items,
        total,
        offset: options.offset,
        limit: options.limit,
    })
}

/// Get exactly one entity by hexadecimal handle.
pub(super) fn get_entity(doc: &CadDocument, handle: &str) -> Result<EntityRecord, EntityReadError> {
    let parsed = parse_handle(handle)?;
    let matches = doc
        .entities()
        .filter(|entity| is_semantic_entity(entity) && entity.common().handle == parsed)
        .collect::<Vec<_>>();
    let entity = match matches.as_slice() {
        [] => {
            return Err(EntityReadError::new(
                "entity_not_found",
                format!("entity `{}` was not found", canonical_handle(parsed)),
            ))
        }
        [entity] => *entity,
        _ => {
            return Err(EntityReadError::new(
                "duplicate_entity_handle",
                format!(
                    "multiple semantic entities use handle `{}`",
                    canonical_handle(parsed)
                ),
            ))
        }
    };
    entity_record(doc, entity)
}

fn validate_options(options: &EntityListOptions) -> Result<EntityFilters, EntityReadError> {
    if options.limit > MAX_ENTITY_LIST_LIMIT {
        return Err(EntityReadError::new(
            "entity_limit_exceeded",
            format!(
                "entity list limit {} exceeds the maximum {}",
                options.limit, MAX_ENTITY_LIST_LIMIT
            ),
        ));
    }
    if options.limit == 0 {
        return Err(EntityReadError::new(
            "invalid_entity_limit",
            "entity list limit must be at least 1",
        ));
    }

    let entity_types = match &options.entity_types {
        None => None,
        Some(types) if types.is_empty() => {
            return Err(EntityReadError::new(
                "invalid_entity_type_filter",
                "entity_types must contain at least one entity type when provided",
            ));
        }
        Some(types) => {
            let mut normalized = BTreeSet::new();
            for entity_type in types {
                if entity_type.trim().is_empty() {
                    return Err(EntityReadError::new(
                        "invalid_entity_type_filter",
                        "entity_types cannot contain an empty entity type",
                    ));
                }
                if entity_type.trim() != entity_type {
                    return Err(EntityReadError::new(
                        "invalid_entity_type_filter",
                        "entity_types cannot contain surrounding whitespace",
                    ));
                }
                normalized.insert(entity_type.to_uppercase());
            }
            Some(normalized)
        }
    };

    let layer = options
        .layer
        .as_ref()
        .map(|layer| {
            if layer.trim().is_empty() {
                Err(EntityReadError::new(
                    "invalid_entity_layer_filter",
                    "layer cannot be empty when provided",
                ))
            } else if layer.trim() != layer {
                Err(EntityReadError::new(
                    "invalid_entity_layer_filter",
                    "layer cannot contain surrounding whitespace",
                ))
            } else {
                Ok(cad_name_key(layer))
            }
        })
        .transpose()?;

    let owner_handle = options
        .owner_handle
        .as_deref()
        .map(parse_handle)
        .transpose()?;

    Ok(EntityFilters {
        entity_types,
        layer,
        owner_handle,
    })
}

fn entity_record(doc: &CadDocument, entity: &EntityType) -> Result<EntityRecord, EntityReadError> {
    let common = entity.common();
    if common.handle.is_null() {
        return Err(EntityReadError::new(
            "invalid_entity_handle",
            "drawing contains an entity with handle 0",
        ));
    }

    let record = EntityRecord {
        handle: canonical_handle(common.handle),
        entity_type: entity_type_name(entity),
        owner_handle: optional_handle(common.owner_handle),
        owner_context: resolve_direct_owner(doc, common.owner_handle)
            .map_err(|error| EntityReadError::new("unsupported_entity_data", error.to_string()))?,
        layer: common.layer.clone(),
        visible: !common.invisible,
        color: entity_color(common.color),
        linetype: entity_linetype(&common.linetype),
        linetype_scale: common.linetype_scale,
        line_weight: entity_line_weight(common.line_weight),
        transparency: EntityTransparency {
            alpha: common.transparency.alpha(),
            fraction: common.transparency.as_percent(),
        },
        bounds: entity_bounds(entity),
        detail: entity_detail(doc, entity)?,
    };
    validate_finite_record(&record)?;
    Ok(record)
}

fn require_finite(value: f64, field: &str) -> Result<(), EntityReadError> {
    if !value.is_finite() {
        return Err(EntityReadError::new(
            "unsupported_entity_data",
            format!("{field} is not a finite number"),
        ));
    }
    Ok(())
}

fn require_finite_point(point: EntityPoint3, field: &str) -> Result<(), EntityReadError> {
    require_finite(point.x, &format!("{field}.x"))?;
    require_finite(point.y, &format!("{field}.y"))?;
    require_finite(point.z, &format!("{field}.z"))
}

fn validate_finite_record(record: &EntityRecord) -> Result<(), EntityReadError> {
    require_finite(record.linetype_scale, "entity linetype_scale")?;
    require_finite(record.transparency.fraction, "entity transparency fraction")?;
    match &record.detail {
        EntityDetail::Point { location } => require_finite_point(*location, "point location")?,
        EntityDetail::Line { start, end } => {
            require_finite_point(*start, "line start")?;
            require_finite_point(*end, "line end")?;
        }
        EntityDetail::Circle { center, radius } => {
            require_finite_point(*center, "circle center")?;
            require_finite(*radius, "circle radius")?;
        }
        EntityDetail::Arc {
            center,
            radius,
            start_angle_radians,
            end_angle_radians,
        } => {
            require_finite_point(*center, "arc center")?;
            require_finite(*radius, "arc radius")?;
            require_finite(*start_angle_radians, "arc start angle")?;
            require_finite(*end_angle_radians, "arc end angle")?;
        }
        EntityDetail::Ellipse {
            center,
            major_axis,
            minor_axis_ratio,
            start_parameter,
            end_parameter,
        } => {
            require_finite_point(*center, "ellipse center")?;
            require_finite_point(*major_axis, "ellipse major axis")?;
            require_finite(*minor_axis_ratio, "ellipse minor axis ratio")?;
            require_finite(*start_parameter, "ellipse start parameter")?;
            require_finite(*end_parameter, "ellipse end parameter")?;
        }
        EntityDetail::Helix {
            axis_base_point,
            start_point,
            axis_vector,
            radius,
            turns,
            turn_height,
            ..
        } => {
            require_finite_point(*axis_base_point, "HELIX axis base point")?;
            require_finite_point(*start_point, "HELIX start point")?;
            require_finite_point(*axis_vector, "HELIX axis vector")?;
            require_finite(*radius, "HELIX radius")?;
            require_finite(*turns, "HELIX turns")?;
            require_finite(*turn_height, "HELIX turn height")?;
        }
        EntityDetail::Polyline { elevation, .. } => {
            if let Some(elevation) = elevation {
                require_finite(*elevation, "polyline elevation")?;
            }
        }
        EntityDetail::Text {
            insertion_point,
            height,
            rotation_radians,
            ..
        } => {
            require_finite_point(*insertion_point, "TEXT insertion point")?;
            require_finite(*height, "TEXT height")?;
            require_finite(*rotation_radians, "TEXT rotation")?;
        }
        EntityDetail::Mtext {
            insertion_point,
            height,
            rectangle_width,
            rotation_radians,
            ..
        } => {
            require_finite_point(*insertion_point, "MTEXT insertion point")?;
            require_finite(*height, "MTEXT height")?;
            require_finite(*rectangle_width, "MTEXT rectangle width")?;
            require_finite(*rotation_radians, "MTEXT rotation")?;
        }
        EntityDetail::Insert {
            insertion_point,
            scale,
            rotation_radians,
            ..
        } => {
            require_finite_point(*insertion_point, "INSERT insertion point")?;
            require_finite(scale.x, "INSERT scale.x")?;
            require_finite(scale.y, "INSERT scale.y")?;
            require_finite(scale.z, "INSERT scale.z")?;
            if [scale.x, scale.y, scale.z]
                .into_iter()
                .any(|value| value == ACADRUST_INSERT_SCALE_SENTINEL)
            {
                return Err(EntityReadError::new(
                    "unsupported_entity_data",
                    "reader cannot recover the saved INSERT scale",
                ));
            }
            require_finite(*rotation_radians, "INSERT rotation")?;
        }
        EntityDetail::Attribute {
            insertion_point,
            height,
            rotation_radians,
            ..
        }
        | EntityDetail::AttributeDefinition {
            insertion_point,
            height,
            rotation_radians,
            ..
        } => {
            require_finite_point(*insertion_point, "attribute insertion point")?;
            require_finite(*height, "attribute height")?;
            require_finite(*rotation_radians, "attribute rotation")?;
        }
        EntityDetail::Dimension {
            measurement,
            definition_point,
            ..
        } => {
            require_finite(*measurement, "dimension measurement")?;
            require_finite_point(*definition_point, "dimension definition point")?;
        }
        EntityDetail::Viewport {
            center,
            width,
            height,
            ..
        } => {
            require_finite_point(*center, "viewport center")?;
            require_finite(*width, "viewport width")?;
            require_finite(*height, "viewport height")?;
        }
        EntityDetail::Hatch { .. }
        | EntityDetail::Leader { .. }
        | EntityDetail::Unknown { .. }
        | EntityDetail::Unsupported { .. } => {}
    }
    Ok(())
}

fn entity_detail(
    document: &CadDocument,
    entity: &EntityType,
) -> Result<EntityDetail, EntityReadError> {
    Ok(match entity {
        EntityType::Point(point) => EntityDetail::Point {
            location: point3(point.location),
        },
        EntityType::Line(line) => EntityDetail::Line {
            start: point3(line.start),
            end: point3(line.end),
        },
        EntityType::Circle(circle) => EntityDetail::Circle {
            center: point3(circle.center),
            radius: circle.radius,
        },
        EntityType::Arc(arc) => EntityDetail::Arc {
            center: point3(arc.center),
            radius: arc.radius,
            start_angle_radians: arc.start_angle,
            end_angle_radians: arc.end_angle,
        },
        EntityType::Ellipse(ellipse) => EntityDetail::Ellipse {
            center: point3(ellipse.center),
            major_axis: point3(ellipse.major_axis),
            minor_axis_ratio: ellipse.minor_axis_ratio,
            start_parameter: ellipse.start_parameter,
            end_parameter: ellipse.end_parameter,
        },
        EntityType::Helix(helix) => EntityDetail::Helix {
            axis_base_point: point3(helix.axis_base_point),
            start_point: point3(helix.start_point),
            axis_vector: point3(helix.axis_vector),
            radius: helix.radius,
            turns: helix.turns,
            turn_height: helix.turn_height,
            handedness: if helix.handedness {
                EntityHelixHandedness::Right
            } else {
                EntityHelixHandedness::Left
            },
            constraint: match helix.constraint {
                acadrust::entities::HelixConstraint::TurnHeight => {
                    EntityHelixConstraint::TurnHeight
                }
                acadrust::entities::HelixConstraint::Turns => EntityHelixConstraint::Turns,
                acadrust::entities::HelixConstraint::Height => EntityHelixConstraint::Height,
            },
        },
        EntityType::LwPolyline(polyline) => EntityDetail::Polyline {
            representation: PolylineRepresentation::Lightweight2d,
            vertex_count: polyline.vertices.len(),
            face_count: None,
            is_closed: polyline.is_closed,
            elevation: Some(polyline.elevation),
        },
        EntityType::Polyline2D(polyline) => EntityDetail::Polyline {
            representation: PolylineRepresentation::Heavyweight2d,
            vertex_count: polyline.vertices.len(),
            face_count: None,
            is_closed: polyline.is_closed(),
            elevation: Some(polyline.elevation),
        },
        EntityType::Polyline(polyline) => EntityDetail::Polyline {
            representation: PolylineRepresentation::Legacy3d,
            vertex_count: polyline.vertices.len(),
            face_count: None,
            is_closed: polyline.is_closed(),
            elevation: None,
        },
        EntityType::Polyline3D(polyline) => EntityDetail::Polyline {
            representation: PolylineRepresentation::Polyline3d,
            vertex_count: polyline.vertices.len(),
            face_count: None,
            is_closed: polyline.is_closed(),
            elevation: None,
        },
        EntityType::PolyfaceMesh(mesh) => EntityDetail::Polyline {
            representation: PolylineRepresentation::PolyfaceMesh,
            vertex_count: mesh.vertices.len(),
            face_count: Some(mesh.faces.len()),
            is_closed: mesh
                .flags
                .contains(acadrust::entities::PolyfaceMeshFlags::CLOSED),
            elevation: Some(mesh.elevation),
        },
        EntityType::PolygonMesh(mesh) => EntityDetail::Polyline {
            representation: PolylineRepresentation::PolygonMesh,
            vertex_count: mesh.vertices.len(),
            face_count: None,
            is_closed: mesh.is_closed_m() || mesh.is_closed_n(),
            elevation: Some(mesh.elevation),
        },
        EntityType::Text(text) => EntityDetail::Text {
            value: text.value.clone(),
            insertion_point: point3(text.insertion_point),
            height: text.height,
            rotation_radians: text.rotation,
            style: text.style.clone(),
        },
        EntityType::MText(text) => EntityDetail::Mtext {
            value: text.value.clone(),
            insertion_point: point3(text.insertion_point),
            height: text.height,
            rectangle_width: text.rectangle_width,
            rotation_radians: text.rotation,
            style: text.style.clone(),
        },
        EntityType::Insert(insert) => EntityDetail::Insert {
            block_name: insert.block_name.clone(),
            insertion_point: point3(insert.insert_point),
            scale: EntityScale3 {
                x: insert.x_scale(),
                y: insert.y_scale(),
                z: insert.z_scale(),
            },
            rotation_radians: insert.rotation,
            column_count: insert.column_count,
            row_count: insert.row_count,
            attribute_count: insert.attributes.len(),
            dynamic_block: resolve_dynamic_block_link(document, insert)
                .map_err(|error| EntityReadError::new(error.code(), error.message()))?,
        },
        EntityType::AttributeEntity(attribute) => EntityDetail::Attribute {
            tag: attribute.tag.clone(),
            value: attribute.value.clone(),
            insertion_point: point3(attribute.insertion_point),
            height: attribute.height,
            rotation_radians: attribute.rotation,
            style: parser_defaulted_string(),
        },
        EntityType::AttributeDefinition(attribute) => EntityDetail::AttributeDefinition {
            tag: attribute.tag.clone(),
            prompt: parser_defaulted_string(),
            default_value: attribute.default_value.clone(),
            insertion_point: point3(attribute.insertion_point),
            height: attribute.height,
            rotation_radians: attribute.rotation,
            style: parser_defaulted_string(),
        },
        EntityType::Hatch(hatch) => EntityDetail::Hatch {
            pattern_name: hatch.pattern.name.clone(),
            is_solid: hatch.is_solid,
            is_associative: hatch.is_associative,
            boundary_path_count: hatch.paths.len(),
            seed_point_count: hatch.seed_points.len(),
        },
        EntityType::Dimension(dimension) => EntityDetail::Dimension {
            subtype: entity.as_entity().entity_type().to_string(),
            measurement: dimension.base().actual_measurement,
            text: dimension.base().text.clone(),
            style: dimension.base().style_name.clone(),
            definition_point: point3(dimension.base().definition_point),
        },
        EntityType::Leader(leader) => EntityDetail::Leader {
            vertex_count: leader.vertices.len(),
            arrow_enabled: leader.arrow_enabled,
            dimension_style: leader.dimension_style.clone(),
            annotation_handle: optional_handle(leader.annotation_handle),
        },
        EntityType::Viewport(viewport) => EntityDetail::Viewport {
            id: viewport.id,
            center: point3(viewport.center),
            width: viewport.width,
            height: viewport.height,
            // acadrust 0.4.1 retains the viewport on/off bit, but exposing it
            // would change the established public DTO and JSON. Preserve the
            // legacy unavailable value until that public change is qualified
            // separately; ParserDiscarded remains the compatibility value
            // serialized by the existing contract.
            is_on: EntityBooleanAvailability::Unavailable {
                reason: EntityBooleanUnavailableReason::ParserDiscarded,
            },
            is_locked: viewport.status.locked,
            // Neither pinned reader populates this field, so the observed
            // value is Viewport::new()'s synthesized default.
            custom_scale: EntityNumberAvailability::Unavailable {
                reason: EntityNumberUnavailableReason::ParserDefaulted,
            },
        },
        EntityType::Unknown(unknown) => EntityDetail::Unknown {
            dwg_type_code: (unknown.dwg_type_code != 0).then_some(unknown.dwg_type_code),
        },
        _ => EntityDetail::Unsupported {
            reason: EntityDetailUnsupportedReason::NotModeledByGenericSurface,
        },
    })
}

fn parser_defaulted_string() -> EntityStringAvailability {
    EntityStringAvailability::Unavailable {
        reason: EntityStringUnavailableReason::ParserDefaulted,
    }
}

fn point3(value: Vector3) -> EntityPoint3 {
    EntityPoint3 {
        x: value.x,
        y: value.y,
        z: value.z,
    }
}

fn entity_color(color: Color) -> EntityColor {
    match color {
        Color::ByLayer => EntityColor::ByLayer,
        Color::ByBlock => EntityColor::ByBlock,
        Color::Index(index) => EntityColor::Indexed { index },
        Color::Rgb { r, g, b } => EntityColor::TrueColor {
            red: r,
            green: g,
            blue: b,
        },
    }
}

fn entity_linetype(linetype: &str) -> EntityLinetype {
    if linetype.is_empty() || linetype.eq_ignore_ascii_case("ByLayer") {
        EntityLinetype::ByLayer
    } else if linetype.eq_ignore_ascii_case("ByBlock") {
        EntityLinetype::ByBlock
    } else {
        EntityLinetype::Named {
            name: linetype.to_string(),
        }
    }
}

fn entity_line_weight(line_weight: LineWeight) -> EntityLineWeight {
    match line_weight {
        LineWeight::ByLayer => EntityLineWeight::ByLayer,
        LineWeight::ByBlock => EntityLineWeight::ByBlock,
        LineWeight::Default => EntityLineWeight::Default,
        LineWeight::Value(value) if (0..=211).contains(&value) => EntityLineWeight::Value {
            hundredths_mm: value,
        },
        LineWeight::Value(raw_value) => EntityLineWeight::Raw { raw_value },
    }
}

fn entity_bounds(entity: &EntityType) -> EntityBoundsAvailability {
    if let Some(reason) = bounds_unavailable_reason(entity) {
        return EntityBoundsAvailability::Unavailable { reason };
    }

    let bounds = entity.as_entity().bounding_box();
    project_bounds(bounds.min, bounds.max)
}

fn project_bounds(min: Vector3, max: Vector3) -> EntityBoundsAvailability {
    let (Some(min), Some(max)) = (finite_point3(min), finite_point3(max)) else {
        return EntityBoundsAvailability::Unavailable {
            reason: EntityBoundsUnavailableReason::NonFiniteProjection,
        };
    };
    if min.x > max.x || min.y > max.y || min.z > max.z {
        return EntityBoundsAvailability::Unavailable {
            reason: EntityBoundsUnavailableReason::InvertedProjection,
        };
    }
    EntityBoundsAvailability::Available {
        bounds: EntityBounds3 { min, max },
    }
}

/// Identify acadrust variants whose bounding-box implementation is absent,
/// deliberately incomplete, unbounded, or lacks enough modeled geometry.
fn bounds_unavailable_reason(entity: &EntityType) -> Option<EntityBoundsUnavailableReason> {
    match entity {
        EntityType::Block(_)
        | EntityType::BlockEnd(_)
        | EntityType::Seqend(_)
        | EntityType::Unknown(_)
        | EntityType::MultiLeader(_)
        | EntityType::Solid3D(_)
        | EntityType::Surface(_)
        | EntityType::Table(_) => Some(EntityBoundsUnavailableReason::UnsupportedEntityType),
        EntityType::Insert(_)
        | EntityType::Text(_)
        | EntityType::MText(_)
        | EntityType::AttributeEntity(_)
        | EntityType::AttributeDefinition(_)
        | EntityType::Dimension(_)
        | EntityType::Shape(_)
        | EntityType::Tolerance(_)
        | EntityType::Helix(_) => Some(EntityBoundsUnavailableReason::UnreliableModelProjection),
        EntityType::Ray(_) | EntityType::XLine(_) => {
            Some(EntityBoundsUnavailableReason::UnboundedGeometry)
        }
        EntityType::Polyline(polyline) => insufficient(polyline.vertices.is_empty()),
        EntityType::Polyline2D(polyline) => {
            insufficient(polyline.vertices.is_empty()).or_else(|| {
                polyline2d_bounds_are_unreliable(polyline)
                    .then_some(EntityBoundsUnavailableReason::UnreliableModelProjection)
            })
        }
        EntityType::Polyline3D(polyline) => insufficient(polyline.vertices.is_empty()),
        EntityType::LwPolyline(polyline) => {
            insufficient(polyline.vertices.is_empty()).or_else(|| {
                lwpolyline_bounds_are_unreliable(polyline)
                    .then_some(EntityBoundsUnavailableReason::UnreliableModelProjection)
            })
        }
        EntityType::Spline(spline) => {
            insufficient(spline.control_points.is_empty() && spline.fit_points.is_empty())
        }
        EntityType::Hatch(hatch) => insufficient(!hatch.paths.iter().any(|path| {
            path.edges.iter().any(|edge| match edge {
                BoundaryEdge::Line(_)
                | BoundaryEdge::CircularArc(_)
                | BoundaryEdge::EllipticArc(_) => true,
                BoundaryEdge::Spline(spline) => !spline.control_points.is_empty(),
                BoundaryEdge::Polyline(polyline) => !polyline.vertices.is_empty(),
            })
        })),
        EntityType::Underlay(underlay) => insufficient(underlay.clip_boundary_vertices.is_empty()),
        EntityType::Leader(leader) => insufficient(leader.vertices.is_empty()).or(Some(
            EntityBoundsUnavailableReason::UnreliableModelProjection,
        )),
        EntityType::MLine(mline) => insufficient(mline.vertices.is_empty()),
        EntityType::Mesh(mesh) => insufficient(mesh.vertices.is_empty()),
        EntityType::PolyfaceMesh(mesh) => insufficient(mesh.vertices.is_empty()),
        EntityType::PolygonMesh(mesh) => insufficient(mesh.vertices.is_empty()),
        EntityType::Region(region) => {
            insufficient(!region.wires.iter().any(|wire| !wire.points.is_empty()))
        }
        EntityType::Body(body) => {
            insufficient(!body.wires.iter().any(|wire| !wire.points.is_empty()))
        }
        EntityType::Point(_)
        | EntityType::Line(_)
        | EntityType::Circle(_)
        | EntityType::Arc(_)
        | EntityType::Ellipse(_)
        | EntityType::Solid(_)
        | EntityType::Face3D(_)
        | EntityType::Viewport(_)
        | EntityType::RasterImage(_)
        | EntityType::Wipeout(_)
        | EntityType::Ole2Frame(_) => None,
    }
}

fn lwpolyline_bounds_are_unreliable(polyline: &acadrust::entities::LwPolyline) -> bool {
    polyline.constant_width != 0.0
        || polyline.thickness != 0.0
        || polyline.normal != Vector3::UNIT_Z
        || polyline.vertices.iter().any(|vertex| {
            vertex.bulge != 0.0 || vertex.start_width != 0.0 || vertex.end_width != 0.0
        })
}

fn polyline2d_bounds_are_unreliable(polyline: &acadrust::entities::Polyline2D) -> bool {
    use acadrust::entities::{PolylineFlags, SmoothSurfaceType, VertexFlags};

    let fitted = polyline.flags.bits()
        & (PolylineFlags::CURVE_FIT.bits() | PolylineFlags::SPLINE_FIT.bits())
        != 0;
    polyline.start_width != 0.0
        || polyline.end_width != 0.0
        || polyline.thickness != 0.0
        || polyline.normal != Vector3::UNIT_Z
        || polyline.smooth_surface != SmoothSurfaceType::None
        || fitted
        || polyline.vertices.iter().any(|vertex| {
            let fitted_vertex = vertex.flags.bits()
                & (VertexFlags::EXTRA_VERTEX.bits()
                    | VertexFlags::CURVE_FIT_TANGENT.bits()
                    | VertexFlags::SPLINE_VERTEX.bits()
                    | VertexFlags::SPLINE_CONTROL.bits())
                != 0;
            vertex.bulge != 0.0
                || vertex.start_width != 0.0
                || vertex.end_width != 0.0
                || fitted_vertex
        })
}

fn insufficient(condition: bool) -> Option<EntityBoundsUnavailableReason> {
    condition.then_some(EntityBoundsUnavailableReason::InsufficientModeledGeometry)
}

fn finite_point3(value: Vector3) -> Option<EntityPoint3> {
    (value.x.is_finite() && value.y.is_finite() && value.z.is_finite()).then_some(EntityPoint3 {
        x: value.x,
        y: value.y,
        z: value.z,
    })
}

fn cad_name_key(value: &str) -> String {
    value.to_uppercase()
}

fn optional_handle(handle: Handle) -> Option<String> {
    handle.is_valid().then(|| canonical_handle(handle))
}

fn canonical_handle(handle: Handle) -> String {
    format!("{:X}", handle.value())
}

fn parse_handle(input: &str) -> Result<Handle, EntityReadError> {
    let trimmed = input.trim();
    if trimmed != input {
        return Err(EntityReadError::new(
            "invalid_entity_handle",
            format!("entity handle must not contain surrounding whitespace: `{input}`"),
        ));
    }
    let digits = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if digits.is_empty() {
        return Err(EntityReadError::new(
            "invalid_entity_handle",
            "entity handle cannot be empty",
        ));
    }

    let value = u64::from_str_radix(digits, 16).map_err(|_| {
        EntityReadError::new(
            "invalid_entity_handle",
            format!("invalid hexadecimal entity handle `{input}`"),
        )
    })?;
    let handle = Handle::new(value);
    if handle.is_null() {
        return Err(EntityReadError::new(
            "invalid_entity_handle",
            "entity handle 0 is invalid",
        ));
    }
    Ok(handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        contract::{
            DirectOwnerContext, DirectOwnerType, DirectOwnerUnavailableReason, DynamicBlockLink,
            DEFAULT_ENTITY_LIST_LIMIT,
        },
        Reader,
    };
    use acadrust::{
        entities::{
            solid3d::Wire, AttributeDefinition, AttributeEntity, BoundaryPath, Circle, Dimension,
            DimensionLinear, EntityType, Hatch, Helix, HelixConstraint, Insert, Leader, Line,
            LwPolyline, MText, MultiLeader, Polyline2D, Ray, Shape, Solid, Solid3D, Surface,
            SurfaceKind, Table, Text, Tolerance, Underlay, UnknownEntity, Vertex2D, Viewport,
            XLine,
        },
        tables::BlockRecord,
        types::{Color, Handle, LineWeight, Transparency, Vector2, Vector3},
        CadDocument,
    };
    use std::path::{Path, PathBuf};

    fn fixture_path(relative: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(relative)
    }

    fn add_with_handle(doc: &mut CadDocument, mut entity: EntityType, handle: u64) -> Handle {
        entity.common_mut().handle = Handle::new(handle);
        doc.add_entity(entity).unwrap()
    }

    #[test]
    fn default_options_are_bounded() {
        let options = EntityListOptions::default();
        assert_eq!(options.offset, 0);
        assert_eq!(options.limit, DEFAULT_ENTITY_LIST_LIMIT);
        assert!(!options.include_invisible);
    }

    #[test]
    fn options_deserialize_with_defaults_and_reject_unknown_fields() {
        let options: EntityListOptions = serde_json::from_str("{}").unwrap();
        assert_eq!(options, EntityListOptions::default());
        assert!(serde_json::from_str::<EntityListOptions>(r#"{"unexpected":true}"#).is_err());
    }

    #[test]
    fn empty_document_returns_an_empty_envelope() {
        let result = list_entities(&CadDocument::new(), &EntityListOptions::default()).unwrap();
        assert!(result.items.is_empty());
        assert_eq!(result.total, 0);
        assert_eq!(result.offset, 0);
        assert_eq!(result.limit, DEFAULT_ENTITY_LIST_LIMIT);
    }

    #[test]
    fn list_is_sorted_by_numeric_handle_not_insertion_order() {
        let mut doc = CadDocument::new();
        add_with_handle(
            &mut doc,
            EntityType::Circle(Circle::from_coords(0.0, 0.0, 0.0, 1.0)),
            0x100,
        );
        add_with_handle(
            &mut doc,
            EntityType::Line(Line::from_coords(0.0, 0.0, 0.0, 1.0, 1.0, 0.0)),
            0x20,
        );

        let result = list_entities(&doc, &EntityListOptions::default()).unwrap();
        assert_eq!(
            result
                .items
                .iter()
                .map(|item| item.handle.as_str())
                .collect::<Vec<_>>(),
            ["20", "100"]
        );
    }

    #[test]
    fn combined_filters_are_exact_and_total_is_post_filter() {
        let mut doc = CadDocument::new();
        let mut visible = Line::new();
        visible.common.layer = "Walls".to_string();
        add_with_handle(&mut doc, EntityType::Line(visible), 0x20);

        let mut invisible = Line::new();
        invisible.common.layer = "WALLS".to_string();
        invisible.common.invisible = true;
        add_with_handle(&mut doc, EntityType::Line(invisible), 0x21);

        let mut other = Circle::new();
        other.common.layer = "Walls-Notes".to_string();
        add_with_handle(&mut doc, EntityType::Circle(other), 0x22);

        let options = EntityListOptions {
            entity_types: Some(vec!["line".to_string()]),
            layer: Some("walls".to_string()),
            include_invisible: true,
            offset: 1,
            limit: 1,
            ..Default::default()
        };
        let result = list_entities(&doc, &options).unwrap();
        assert_eq!(result.total, 2);
        assert_eq!(result.items.len(), 1);
        assert_eq!(result.items[0].handle, "21");
    }

    #[test]
    fn exact_name_filters_reject_surrounding_whitespace() {
        let doc = CadDocument::new();
        for options in [
            EntityListOptions {
                entity_types: Some(vec![" LINE".to_string()]),
                ..Default::default()
            },
            EntityListOptions {
                layer: Some("Walls ".to_string()),
                ..Default::default()
            },
        ] {
            let error = list_entities(&doc, &options).unwrap_err();
            assert!(
                matches!(
                    error.code(),
                    "invalid_entity_type_filter" | "invalid_entity_layer_filter"
                ),
                "unexpected code {}",
                error.code()
            );
            assert!(error.message().contains("surrounding whitespace"));
        }
    }

    #[test]
    fn dimension_filter_uses_the_canonical_common_entity_type() {
        let mut doc = CadDocument::new();
        doc.add_entity(EntityType::Dimension(Dimension::Linear(
            DimensionLinear::new(Vector3::ZERO, Vector3::new(3.0, 4.0, 0.0)),
        )))
        .unwrap();
        doc.add_entity(EntityType::Line(Line::new())).unwrap();

        let result = list_entities(
            &doc,
            &EntityListOptions {
                entity_types: Some(vec!["dimension".to_string()]),
                ..Default::default()
            },
        )
        .unwrap();

        assert_eq!(result.total, 1);
        assert_eq!(result.items[0].entity_type, "DIMENSION");
        assert!(matches!(
            result.items[0].detail,
            EntityDetail::Dimension { ref subtype, .. } if subtype == "DIMENSION_LINEAR"
        ));
    }

    #[test]
    fn invisible_entities_are_excluded_by_default() {
        let mut doc = CadDocument::new();
        let mut line = Line::new();
        line.common.invisible = true;
        doc.add_entity(EntityType::Line(line)).unwrap();

        assert_eq!(
            list_entities(&doc, &EntityListOptions::default())
                .unwrap()
                .total,
            0
        );
        let options = EntityListOptions {
            include_invisible: true,
            ..Default::default()
        };
        assert_eq!(list_entities(&doc, &options).unwrap().total, 1);
    }

    #[test]
    fn filters_cannot_hide_duplicate_semantic_entity_handles() {
        let mut doc = CadDocument::new();
        let mut visible = Line::new();
        visible.common.handle = Handle::new(0xABC);
        doc.add_entity(EntityType::Line(visible)).unwrap();

        let mut hidden = Circle::new();
        hidden.common.handle = Handle::new(0xABC);
        hidden.common.invisible = true;
        doc.add_entity(EntityType::Circle(hidden)).unwrap();

        let error = list_entities(&doc, &EntityListOptions::default()).unwrap_err();
        assert_eq!(error.code(), "duplicate_entity_handle");
        assert_eq!(get_entity(&doc, "ABC").unwrap_err().code(), error.code());
    }

    #[test]
    fn parser_clamped_insert_scales_fail_closed_across_entity_reads() {
        let mut doc = CadDocument::new();
        let mut definition = BlockRecord::new("MARKER");
        definition.handle = Handle::new(0x40);
        doc.block_records.add_or_replace(definition);
        let mut insert = Insert::new("MARKER", Vector3::ZERO).with_scale(0.0, 1.0, 1.0);
        insert.common.handle = Handle::new(0x70);
        doc.add_entity(EntityType::Insert(insert)).unwrap();

        for error in [
            list_entities(&doc, &EntityListOptions::default()).unwrap_err(),
            get_entity(&doc, "70").unwrap_err(),
        ] {
            assert_eq!(error.code(), "unsupported_entity_data");
            assert_eq!(
                error.message(),
                "reader cannot recover the saved INSERT scale"
            );
            assert!(!error.message().contains("acadrust"));
        }
    }

    #[test]
    fn owner_filter_accepts_prefixed_hex() {
        let mut doc = CadDocument::new();
        let handle = doc
            .add_entity(EntityType::Line(Line::new()))
            .expect("add line");
        let owner = doc.get_entity(handle).unwrap().common().owner_handle;
        let options = EntityListOptions {
            owner_handle: Some(format!("0x{:x}", owner.value())),
            ..Default::default()
        };

        let result = list_entities(&doc, &options).unwrap();
        assert_eq!(result.total, 1);
        assert_eq!(result.items[0].owner_handle, Some(canonical_handle(owner)));
    }

    #[test]
    fn zero_limit_is_rejected() {
        let mut doc = CadDocument::new();
        doc.add_entity(EntityType::Line(Line::new())).unwrap();
        let options = EntityListOptions {
            limit: 0,
            ..Default::default()
        };

        let error = list_entities(&doc, &options).unwrap_err();
        assert_eq!(error.code(), "invalid_entity_limit");
    }

    #[test]
    fn list_rejects_limits_above_hard_maximum() {
        let options = EntityListOptions {
            limit: MAX_ENTITY_LIST_LIMIT + 1,
            ..Default::default()
        };
        let error = list_entities(&CadDocument::new(), &options).unwrap_err();
        assert_eq!(error.code(), "entity_limit_exceeded");
    }

    #[test]
    fn list_rejects_ambiguous_empty_filters() {
        let empty_types = EntityListOptions {
            entity_types: Some(Vec::new()),
            ..Default::default()
        };
        assert_eq!(
            list_entities(&CadDocument::new(), &empty_types)
                .unwrap_err()
                .code(),
            "invalid_entity_type_filter"
        );

        let empty_layer = EntityListOptions {
            layer: Some("  ".to_string()),
            ..Default::default()
        };
        assert_eq!(
            list_entities(&CadDocument::new(), &empty_layer)
                .unwrap_err()
                .code(),
            "invalid_entity_layer_filter"
        );
    }

    #[test]
    fn get_entity_is_exact_and_canonicalizes_the_handle() {
        let mut doc = CadDocument::new();
        add_with_handle(&mut doc, EntityType::Circle(Circle::new()), 0xAB);

        let record = get_entity(&doc, "0x00ab").unwrap();
        assert_eq!(record.handle, "AB");
        assert_eq!(record.entity_type, "CIRCLE");

        let error = get_entity(&doc, "AC").unwrap_err();
        assert_eq!(error.code(), "entity_not_found");
        assert_eq!(
            get_entity(&doc, "not-hex").unwrap_err().code(),
            "invalid_entity_handle"
        );
        assert_eq!(
            get_entity(&doc, "0").unwrap_err().code(),
            "invalid_entity_handle"
        );
    }

    #[test]
    fn get_entity_ignores_unrelated_invalid_and_duplicate_handles() {
        let mut doc = CadDocument::new();
        add_with_handle(&mut doc, EntityType::Circle(Circle::new()), 0xAB);

        let invalid_handle = add_with_handle(&mut doc, EntityType::Line(Line::new()), 0xBC);
        doc.get_entity_mut(invalid_handle)
            .unwrap()
            .common_mut()
            .handle = Handle::NULL;

        add_with_handle(&mut doc, EntityType::Line(Line::new()), 0xCD);
        add_with_handle(&mut doc, EntityType::Circle(Circle::new()), 0xCD);

        let record = get_entity(&doc, "AB").unwrap();
        assert_eq!(record.handle, "AB");
        assert_eq!(record.entity_type, "CIRCLE");

        let error = list_entities(
            &doc,
            &EntityListOptions {
                include_invisible: true,
                ..Default::default()
            },
        )
        .unwrap_err();
        assert_eq!(error.code(), "invalid_entity_handle");
    }

    #[test]
    fn common_record_reports_model_space_owner_layer_and_visibility() {
        let mut doc = CadDocument::new();
        let mut line = Line::new();
        line.common.layer = "STRUCTURE".to_string();
        let handle = doc.add_entity(EntityType::Line(line)).unwrap();

        let record = get_entity(&doc, &canonical_handle(handle)).unwrap();
        assert_eq!(record.layer, "STRUCTURE");
        assert!(record.visible);
        assert_eq!(
            record.owner_context,
            Some(DirectOwnerContext::Available {
                owner_type: DirectOwnerType::ModelSpace,
                owner_name: "Model".to_string(),
            })
        );
    }

    #[test]
    fn common_record_exposes_closed_display_properties_and_modeled_bounds() {
        let mut doc = CadDocument::new();
        let mut line = Line::from_coords(1.0, 2.0, 3.0, 4.0, 5.0, 6.0);
        line.common.color = Color::from_rgb(10, 20, 30);
        line.common.linetype = "DASHED".to_string();
        line.common.linetype_scale = 2.5;
        line.common.line_weight = LineWeight::Value(25);
        line.common.transparency = Transparency::new(128);
        let handle = doc.add_entity(EntityType::Line(line)).unwrap();

        let record = get_entity(&doc, &canonical_handle(handle)).unwrap();
        assert_eq!(
            record.color,
            EntityColor::TrueColor {
                red: 10,
                green: 20,
                blue: 30,
            }
        );
        assert_eq!(
            record.linetype,
            EntityLinetype::Named {
                name: "DASHED".to_string(),
            }
        );
        assert_eq!(record.linetype_scale, 2.5);
        assert_eq!(
            record.line_weight,
            EntityLineWeight::Value { hundredths_mm: 25 }
        );
        assert_eq!(record.transparency.alpha, 128);
        assert!((record.transparency.fraction - 128.0 / 255.0).abs() < 1e-12);
        assert_eq!(
            record.bounds,
            EntityBoundsAvailability::Available {
                bounds: EntityBounds3 {
                    min: EntityPoint3 {
                        x: 1.0,
                        y: 2.0,
                        z: 3.0,
                    },
                    max: EntityPoint3 {
                        x: 4.0,
                        y: 5.0,
                        z: 6.0,
                    },
                },
            }
        );
    }

    #[test]
    fn display_fallbacks_preserve_raw_values_without_debug_strings() {
        let mut doc = CadDocument::new();
        let mut line = Line::new();
        line.common.color = Color::Index(42);
        line.common.linetype = "ByBlock".to_string();
        line.common.line_weight = LineWeight::Value(-42);
        let handle = doc.add_entity(EntityType::Line(line)).unwrap();

        let record = get_entity(&doc, &canonical_handle(handle)).unwrap();
        assert_eq!(record.color, EntityColor::Indexed { index: 42 });
        assert_eq!(record.linetype, EntityLinetype::ByBlock);
        assert_eq!(record.line_weight, EntityLineWeight::Raw { raw_value: -42 });
    }

    #[test]
    fn unavailable_bounds_report_closed_reasons_and_non_finite_detail_fails() {
        let mut doc = CadDocument::new();
        let unknown_handle = doc
            .add_entity(EntityType::Unknown(UnknownEntity::new("ACAD_PROXY_ENTITY")))
            .unwrap();
        let empty_hatch_handle = doc.add_entity(EntityType::Hatch(Hatch::new())).unwrap();
        let mut empty_path_hatch = Hatch::new();
        empty_path_hatch.paths.push(BoundaryPath::new());
        let empty_path_hatch_handle = doc.add_entity(EntityType::Hatch(empty_path_hatch)).unwrap();
        let unclipped_underlay_handle = doc
            .add_entity(EntityType::Underlay(Underlay::pdf()))
            .unwrap();
        let mut invalid_line = Line::new();
        invalid_line.start.x = f64::NAN;
        invalid_line.end.x = f64::NAN;
        let invalid_line_handle = doc.add_entity(EntityType::Line(invalid_line)).unwrap();

        assert_eq!(
            get_entity(&doc, &canonical_handle(unknown_handle))
                .unwrap()
                .bounds,
            EntityBoundsAvailability::Unavailable {
                reason: EntityBoundsUnavailableReason::UnsupportedEntityType,
            }
        );
        assert_eq!(
            get_entity(&doc, &canonical_handle(empty_hatch_handle))
                .unwrap()
                .bounds,
            EntityBoundsAvailability::Unavailable {
                reason: EntityBoundsUnavailableReason::InsufficientModeledGeometry,
            }
        );
        assert_eq!(
            get_entity(&doc, &canonical_handle(empty_path_hatch_handle))
                .unwrap()
                .bounds,
            EntityBoundsAvailability::Unavailable {
                reason: EntityBoundsUnavailableReason::InsufficientModeledGeometry,
            }
        );
        assert_eq!(
            get_entity(&doc, &canonical_handle(unclipped_underlay_handle))
                .unwrap()
                .bounds,
            EntityBoundsAvailability::Unavailable {
                reason: EntityBoundsUnavailableReason::InsufficientModeledGeometry,
            }
        );
        let error = get_entity(&doc, &canonical_handle(invalid_line_handle)).unwrap_err();
        assert_eq!(error.code(), "unsupported_entity_data");
        assert!(error.message().contains("not a finite number"));
    }

    #[test]
    fn bounds_reason_mapping_distinguishes_unreliable_and_unbounded_geometry() {
        let heuristic_entities = [
            EntityType::Insert(Insert::new("DETAIL", Vector3::ZERO)),
            EntityType::Text(Text::new()),
            EntityType::MText(MText::new()),
            EntityType::AttributeEntity(AttributeEntity::new(
                "TAG".to_string(),
                "VALUE".to_string(),
            )),
            EntityType::AttributeDefinition(AttributeDefinition::new(
                "TAG".to_string(),
                "Prompt".to_string(),
                "Default".to_string(),
            )),
            EntityType::Dimension(Dimension::Linear(DimensionLinear::new(
                Vector3::ZERO,
                Vector3::new(1.0, 1.0, 0.0),
            ))),
            EntityType::Leader(Leader::two_point(
                Vector3::ZERO,
                Vector3::new(1.0, 1.0, 0.0),
            )),
            EntityType::Shape(Shape::new()),
            EntityType::Tolerance(Tolerance::new()),
        ];
        for entity in &heuristic_entities {
            assert_eq!(
                bounds_unavailable_reason(entity),
                Some(EntityBoundsUnavailableReason::UnreliableModelProjection)
            );
        }

        let unbounded_entities = [
            EntityType::Ray(Ray::new(Vector3::ZERO, Vector3::new(1.0, 0.0, 0.0))),
            EntityType::XLine(XLine::new(Vector3::ZERO, Vector3::new(1.0, 0.0, 0.0))),
        ];
        for entity in &unbounded_entities {
            assert_eq!(
                bounds_unavailable_reason(entity),
                Some(EntityBoundsUnavailableReason::UnboundedGeometry)
            );
        }
    }

    #[test]
    fn curved_wide_extruded_or_ocs_2d_polylines_do_not_publish_vertex_only_bounds() {
        let straight =
            LwPolyline::from_points(vec![Vector2::new(0.0, 0.0), Vector2::new(1.0, 1.0)]);
        assert_eq!(
            bounds_unavailable_reason(&EntityType::LwPolyline(straight)),
            None
        );

        let mut curved =
            LwPolyline::from_points(vec![Vector2::new(0.0, 0.0), Vector2::new(1.0, 1.0)]);
        curved.vertices[0].bulge = 1.0;
        assert_eq!(
            bounds_unavailable_reason(&EntityType::LwPolyline(curved)),
            Some(EntityBoundsUnavailableReason::UnreliableModelProjection)
        );

        let mut wide =
            LwPolyline::from_points(vec![Vector2::new(0.0, 0.0), Vector2::new(1.0, 1.0)]);
        wide.constant_width = 0.5;
        assert_eq!(
            bounds_unavailable_reason(&EntityType::LwPolyline(wide)),
            Some(EntityBoundsUnavailableReason::UnreliableModelProjection)
        );

        let mut extruded =
            LwPolyline::from_points(vec![Vector2::new(0.0, 0.0), Vector2::new(1.0, 1.0)]);
        extruded.thickness = 1.0;
        assert_eq!(
            bounds_unavailable_reason(&EntityType::LwPolyline(extruded)),
            Some(EntityBoundsUnavailableReason::UnreliableModelProjection)
        );

        let mut ocs = LwPolyline::from_points(vec![Vector2::new(0.0, 0.0), Vector2::new(1.0, 1.0)]);
        ocs.normal = Vector3::UNIT_Y;
        assert_eq!(
            bounds_unavailable_reason(&EntityType::LwPolyline(ocs)),
            Some(EntityBoundsUnavailableReason::UnreliableModelProjection)
        );

        let mut heavy = Polyline2D::new();
        heavy.add_vertex(Vertex2D::from_point(Vector2::new(0.0, 0.0)));
        heavy.add_vertex(Vertex2D::from_point(Vector2::new(1.0, 1.0)));
        assert_eq!(
            bounds_unavailable_reason(&EntityType::Polyline2D(heavy.clone())),
            None
        );
        heavy.vertices[0].bulge = -0.5;
        assert_eq!(
            bounds_unavailable_reason(&EntityType::Polyline2D(heavy)),
            Some(EntityBoundsUnavailableReason::UnreliableModelProjection)
        );
    }

    #[test]
    fn bounds_projection_reports_non_finite_and_inverted_inputs() {
        assert_eq!(
            project_bounds(
                Vector3::new(f64::NAN, 0.0, 0.0),
                Vector3::new(1.0, 1.0, 1.0),
            ),
            EntityBoundsAvailability::Unavailable {
                reason: EntityBoundsUnavailableReason::NonFiniteProjection,
            }
        );
        assert_eq!(
            project_bounds(Vector3::new(2.0, 0.0, 0.0), Vector3::new(1.0, 1.0, 1.0),),
            EntityBoundsAvailability::Unavailable {
                reason: EntityBoundsUnavailableReason::InvertedProjection,
            }
        );
    }

    #[test]
    fn availability_values_are_closed_tagged_objects() {
        let bounds = EntityBoundsAvailability::Available {
            bounds: EntityBounds3 {
                min: EntityPoint3 {
                    x: 1.0,
                    y: 2.0,
                    z: 3.0,
                },
                max: EntityPoint3 {
                    x: 4.0,
                    y: 5.0,
                    z: 6.0,
                },
            },
        };
        assert_eq!(
            serde_json::to_value(bounds).unwrap(),
            serde_json::json!({
                "state": "available",
                "bounds": {
                    "min": {"x": 1.0, "y": 2.0, "z": 3.0},
                    "max": {"x": 4.0, "y": 5.0, "z": 6.0}
                }
            })
        );
        assert!(
            serde_json::from_value::<EntityBoundsAvailability>(serde_json::json!({
                "state": "available",
                "bounds": {
                    "min": {"x": 1.0, "y": 2.0, "z": 3.0},
                    "max": {"x": 4.0, "y": 5.0, "z": 6.0}
                },
                "reason": "non_finite_projection"
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<EntityBoundsAvailability>(serde_json::json!({
                "state": "unavailable"
            }))
            .is_err()
        );

        assert_eq!(
            serde_json::to_value(parser_defaulted_string()).unwrap(),
            serde_json::json!({
                "state": "unavailable",
                "reason": "parser_defaulted"
            })
        );
        assert!(
            serde_json::from_value::<EntityStringAvailability>(serde_json::json!({
                "state": "unavailable",
                "reason": "parser_defaulted",
                "value": "fabricated"
            }))
            .is_err()
        );

        let discarded_boolean = EntityBooleanAvailability::Unavailable {
            reason: EntityBooleanUnavailableReason::ParserDiscarded,
        };
        assert_eq!(
            serde_json::to_value(discarded_boolean).unwrap(),
            serde_json::json!({
                "state": "unavailable",
                "reason": "parser_discarded"
            })
        );
        assert!(
            serde_json::from_value::<EntityBooleanAvailability>(serde_json::json!({
                "state": "unavailable",
                "reason": "parser_discarded",
                "value": true
            }))
            .is_err()
        );

        let defaulted_number = EntityNumberAvailability::Unavailable {
            reason: EntityNumberUnavailableReason::ParserDefaulted,
        };
        assert_eq!(
            serde_json::to_value(defaulted_number).unwrap(),
            serde_json::json!({
                "state": "unavailable",
                "reason": "parser_defaulted"
            })
        );
        assert!(
            serde_json::from_value::<EntityNumberAvailability>(serde_json::json!({
                "state": "unavailable",
                "reason": "parser_defaulted",
                "value": 1.0
            }))
            .is_err()
        );

        let schema = serde_json::to_string(&schemars::schema_for!(EntityRecord)).unwrap();
        for required_value in [
            "available",
            "helix",
            "left",
            "right",
            "turn_height",
            "turns",
            "height",
            "unsupported_entity_type",
            "unreliable_model_projection",
            "unbounded_geometry",
            "insufficient_modeled_geometry",
            "non_finite_projection",
            "inverted_projection",
            "not_modeled_by_generic_surface",
            "parser_discarded",
            "parser_defaulted",
        ] {
            assert!(
                schema.contains(required_value),
                "EntityRecord schema must contain `{required_value}`"
            );
        }
    }

    #[test]
    fn viewport_detail_preserves_is_on_availability_contract() {
        let document = CadDocument::new();
        let mut viewport = Viewport::new();
        viewport.status = acadrust::entities::viewport::ViewportStatusFlags::from_bits(0xC000);
        viewport.custom_scale = 42.0;

        assert_eq!(
            entity_detail(&document, &EntityType::Viewport(viewport)).unwrap(),
            EntityDetail::Viewport {
                id: 0,
                center: EntityPoint3 {
                    x: 0.0,
                    y: 0.0,
                    z: 0.0,
                },
                width: 297.0,
                height: 210.0,
                is_on: EntityBooleanAvailability::Unavailable {
                    reason: EntityBooleanUnavailableReason::ParserDiscarded,
                },
                is_locked: true,
                custom_scale: EntityNumberAvailability::Unavailable {
                    reason: EntityNumberUnavailableReason::ParserDefaulted,
                },
            }
        );

        let mut viewport = Viewport::new();
        viewport.status = acadrust::entities::viewport::ViewportStatusFlags::from_bits(0x2000);
        assert!(matches!(
            entity_detail(&document, &EntityType::Viewport(viewport)).unwrap(),
            EntityDetail::Viewport {
                is_locked: false,
                ..
            }
        ));
    }

    #[test]
    fn common_record_resolves_block_and_entity_owners() {
        let mut doc = CadDocument::new();
        let block_handle = doc.allocate_handle();
        let mut block = BlockRecord::new("DETAIL");
        block.handle = block_handle;
        doc.block_records.add(block).unwrap();

        let mut line = Line::new();
        line.common.owner_handle = block_handle;
        let line_handle = doc.add_entity(EntityType::Line(line)).unwrap();
        assert_eq!(
            get_entity(&doc, &canonical_handle(line_handle))
                .unwrap()
                .owner_context
                .unwrap(),
            DirectOwnerContext::Available {
                owner_type: DirectOwnerType::BlockDefinition,
                owner_name: "DETAIL".to_string(),
            }
        );

        let insert_handle = doc
            .add_entity(EntityType::Insert(Insert::new("DETAIL", Vector3::ZERO)))
            .unwrap();
        let mut attribute = AttributeEntity::simple("SHEET", "A1");
        attribute.common.owner_handle = insert_handle;
        let attribute_handle = doc
            .add_entity(EntityType::AttributeEntity(attribute))
            .unwrap();
        let context = get_entity(&doc, &canonical_handle(attribute_handle))
            .unwrap()
            .owner_context
            .unwrap();
        assert_eq!(
            context,
            DirectOwnerContext::Available {
                owner_type: DirectOwnerType::Entity,
                owner_name: "INSERT".to_string(),
            }
        );
    }

    #[test]
    fn common_record_tags_non_null_unresolved_owner_as_unavailable() {
        let mut doc = CadDocument::new();
        let line_handle = doc.add_entity(EntityType::Line(Line::new())).unwrap();
        doc.get_entity_mut(line_handle)
            .unwrap()
            .common_mut()
            .owner_handle = Handle::new(0xFFFF);

        assert_eq!(
            get_entity(&doc, &canonical_handle(line_handle))
                .unwrap()
                .owner_context,
            Some(DirectOwnerContext::Unavailable {
                reason: DirectOwnerUnavailableReason::UnresolvedOwner,
            })
        );
    }

    #[test]
    fn primitive_and_text_details_are_preserved() {
        let mut doc = CadDocument::new();
        let line_handle = doc
            .add_entity(EntityType::Line(Line::from_coords(
                1.0, 2.0, 3.0, 4.0, 5.0, 6.0,
            )))
            .unwrap();
        let text_handle = doc
            .add_entity(EntityType::Text(Text::with_value(
                "North",
                Vector3::new(7.0, 8.0, 9.0),
            )))
            .unwrap();

        assert!(matches!(
            get_entity(&doc, &canonical_handle(line_handle))
                .unwrap()
                .detail,
            EntityDetail::Line {
                start: EntityPoint3 {
                    x: 1.0,
                    y: 2.0,
                    z: 3.0
                },
                end: EntityPoint3 {
                    x: 4.0,
                    y: 5.0,
                    z: 6.0
                }
            }
        ));
        assert!(matches!(
            get_entity(&doc, &canonical_handle(text_handle))
                .unwrap()
                .detail,
            EntityDetail::Text { value, .. } if value == "North"
        ));
    }

    #[test]
    fn complex_geometry_is_summarized_without_copying_children() {
        let mut doc = CadDocument::new();
        let mut polyline = LwPolyline::from_points(vec![
            Vector2::new(0.0, 0.0),
            Vector2::new(1.0, 0.0),
            Vector2::new(1.0, 1.0),
        ]);
        polyline.close();
        let polyline_handle = doc.add_entity(EntityType::LwPolyline(polyline)).unwrap();
        let hatch_handle = doc.add_entity(EntityType::Hatch(Hatch::solid())).unwrap();

        assert!(matches!(
            get_entity(&doc, &canonical_handle(polyline_handle))
                .unwrap()
                .detail,
            EntityDetail::Polyline {
                representation: PolylineRepresentation::Lightweight2d,
                vertex_count: 3,
                is_closed: true,
                ..
            }
        ));
        assert!(matches!(
            get_entity(&doc, &canonical_handle(hatch_handle))
                .unwrap()
                .detail,
            EntityDetail::Hatch {
                boundary_path_count: 0,
                ..
            }
        ));
    }

    #[test]
    fn helix_detail_projects_saved_parameters_but_not_control_hull_bounds() {
        let mut doc = CadDocument::new();
        let mut helix = Helix::new();
        helix.axis_base_point = Vector3::new(2.0, 3.0, 4.0);
        helix.start_point = Vector3::new(5.0, 6.0, 7.0);
        helix.axis_vector = Vector3::new(0.0, 1.0, 0.0);
        helix.radius = 8.0;
        helix.turns = 2.5;
        helix.turn_height = 1.25;
        helix.handedness = false;
        helix.constraint = HelixConstraint::Height;
        helix.spline.control_points = vec![
            Vector3::new(-10.0, -20.0, -30.0),
            Vector3::new(10.0, 20.0, 30.0),
        ];
        let handle = doc.add_entity(EntityType::Helix(helix)).unwrap();

        let record = get_entity(&doc, &canonical_handle(handle)).unwrap();
        assert_eq!(record.entity_type, "HELIX");
        assert_eq!(
            record.bounds,
            EntityBoundsAvailability::Unavailable {
                reason: EntityBoundsUnavailableReason::UnreliableModelProjection,
            }
        );
        assert_eq!(
            record.detail,
            EntityDetail::Helix {
                axis_base_point: EntityPoint3 {
                    x: 2.0,
                    y: 3.0,
                    z: 4.0,
                },
                start_point: EntityPoint3 {
                    x: 5.0,
                    y: 6.0,
                    z: 7.0,
                },
                axis_vector: EntityPoint3 {
                    x: 0.0,
                    y: 1.0,
                    z: 0.0,
                },
                radius: 8.0,
                turns: 2.5,
                turn_height: 1.25,
                handedness: EntityHelixHandedness::Left,
                constraint: EntityHelixConstraint::Height,
            }
        );
        assert_eq!(
            serde_json::to_value(&record.detail).unwrap(),
            serde_json::json!({
                "kind": "helix",
                "axis_base_point": {"x": 2.0, "y": 3.0, "z": 4.0},
                "start_point": {"x": 5.0, "y": 6.0, "z": 7.0},
                "axis_vector": {"x": 0.0, "y": 1.0, "z": 0.0},
                "radius": 8.0,
                "turns": 2.5,
                "turn_height": 1.25,
                "handedness": "left",
                "constraint": "height"
            })
        );
    }

    #[test]
    fn helix_enums_map_every_saved_value_and_non_finite_detail_fails_closed() {
        let document = CadDocument::new();
        for (backend, projected) in [
            (
                HelixConstraint::TurnHeight,
                EntityHelixConstraint::TurnHeight,
            ),
            (HelixConstraint::Turns, EntityHelixConstraint::Turns),
            (HelixConstraint::Height, EntityHelixConstraint::Height),
        ] {
            let mut helix = Helix::new();
            helix.constraint = backend;
            assert!(matches!(
                entity_detail(&document, &EntityType::Helix(helix)).unwrap(),
                EntityDetail::Helix {
                    handedness: EntityHelixHandedness::Right,
                    constraint,
                    ..
                } if constraint == projected
            ));
        }

        let mut invalid = CadDocument::new();
        let mut helix = Helix::new();
        helix.turns = f64::NAN;
        let handle = invalid.add_entity(EntityType::Helix(helix)).unwrap();
        let error = get_entity(&invalid, &canonical_handle(handle)).unwrap_err();
        assert_eq!(error.code(), "unsupported_entity_data");
        assert!(error.message().contains("HELIX turns"));
    }

    #[test]
    fn surface_inventory_preserves_subtype_but_never_publishes_wire_bounds() {
        let mut doc = CadDocument::new();
        let mut surface = Surface::new(SurfaceKind::Lofted);
        surface.wires.push(Wire::from_points(vec![
            Vector3::new(-1.0e308, -2.0, -3.0),
            Vector3::new(1.0e308, 2.0, 3.0),
        ]));
        let handle = doc.add_entity(EntityType::Surface(surface)).unwrap();

        let record = get_entity(&doc, &canonical_handle(handle)).unwrap();
        assert_eq!(record.entity_type, "LOFTEDSURFACE");
        assert_eq!(
            record.bounds,
            EntityBoundsAvailability::Unavailable {
                reason: EntityBoundsUnavailableReason::UnsupportedEntityType,
            }
        );
        assert_eq!(
            record.detail,
            EntityDetail::Unsupported {
                reason: EntityDetailUnsupportedReason::NotModeledByGenericSurface,
            }
        );
    }

    #[test]
    fn unproven_table_multileader_solid3d_and_surface_projections_fail_closed() {
        let document = CadDocument::new();
        let entities = [
            EntityType::Table(Table::new(Vector3::ZERO, 1, 1)),
            EntityType::MultiLeader(MultiLeader::new()),
            EntityType::Solid3D(Solid3D::new()),
            EntityType::Surface(Surface::new(SurfaceKind::Plane)),
        ];

        for entity in &entities {
            assert_eq!(
                bounds_unavailable_reason(entity),
                Some(EntityBoundsUnavailableReason::UnsupportedEntityType),
                "{} bounds must remain unavailable",
                entity_type_name(entity)
            );
            assert_eq!(
                entity_detail(&document, entity).unwrap(),
                EntityDetail::Unsupported {
                    reason: EntityDetailUnsupportedReason::NotModeledByGenericSurface,
                },
                "{} detail must remain unsupported",
                entity_type_name(entity)
            );
        }
    }

    #[test]
    fn unmodeled_detail_and_parser_defaulted_attribute_strings_are_explicit() {
        let document = CadDocument::new();
        let unsupported = entity_detail(
            &document,
            &EntityType::Solid(Solid::triangle(
                Vector3::ZERO,
                Vector3::new(1.0, 0.0, 0.0),
                Vector3::new(0.0, 1.0, 0.0),
            )),
        )
        .unwrap();
        assert_eq!(
            unsupported,
            EntityDetail::Unsupported {
                reason: EntityDetailUnsupportedReason::NotModeledByGenericSurface,
            }
        );
        assert_eq!(
            serde_json::to_value(unsupported).unwrap(),
            serde_json::json!({
                "kind": "unsupported",
                "reason": "not_modeled_by_generic_surface"
            })
        );

        let mut attribute = AttributeEntity::new("SHEET".to_string(), "A1".to_string());
        attribute.text_style = "CUSTOM_ATTRIB_STYLE".to_string();
        assert!(matches!(
            entity_detail(&document, &EntityType::AttributeEntity(attribute)).unwrap(),
            EntityDetail::Attribute {
                tag,
                value,
                style: EntityStringAvailability::Unavailable {
                    reason: EntityStringUnavailableReason::ParserDefaulted,
                },
                ..
            } if tag == "SHEET" && value == "A1"
        ));

        let mut definition = AttributeDefinition::new(
            "SHEET".to_string(),
            "Enter sheet".to_string(),
            "A0".to_string(),
        );
        definition.text_style = "CUSTOM_ATTDEF_STYLE".to_string();
        assert!(matches!(
            entity_detail(&document, &EntityType::AttributeDefinition(definition)).unwrap(),
            EntityDetail::AttributeDefinition {
                tag,
                prompt: EntityStringAvailability::Unavailable {
                    reason: EntityStringUnavailableReason::ParserDefaulted,
                },
                default_value,
                style: EntityStringAvailability::Unavailable {
                    reason: EntityStringUnavailableReason::ParserDefaulted,
                },
                ..
            } if tag == "SHEET" && default_value == "A0"
        ));
    }

    #[test]
    fn unknown_entity_retains_source_type_name_without_raw_payload() {
        let mut doc = CadDocument::new();
        let mut unknown = UnknownEntity::new("acad_proxy_entity");
        unknown.dwg_type_code = 498;
        let handle = doc.add_entity(EntityType::Unknown(unknown)).unwrap();

        let record = get_entity(&doc, &canonical_handle(handle)).unwrap();
        assert_eq!(record.entity_type, "ACAD_PROXY_ENTITY");
        assert_eq!(
            record.detail,
            EntityDetail::Unknown {
                dwg_type_code: Some(498)
            }
        );
    }

    #[test]
    fn invalid_zero_handle_in_document_fails_closed() {
        let mut doc = CadDocument::new();
        let handle = doc.add_entity(EntityType::Line(Line::new())).unwrap();
        doc.get_entity_mut(handle).unwrap().common_mut().handle = Handle::NULL;

        let error = list_entities(
            &doc,
            &EntityListOptions {
                include_invisible: true,
                ..Default::default()
            },
        )
        .unwrap_err();
        assert_eq!(error.code(), "invalid_entity_handle");
    }

    #[test]
    fn tier1_dwg_public_list_matches_backend_filtered_iteration() {
        let doc = Reader::open_path(&fixture_path(
            "tests/corpus/open/acadsharp/dynamic-blocks/BLOCKVISIBILITYPARAMETER.dwg",
        ))
        .unwrap()
        .into_backend_document();
        let backend_entity_count = doc.entity_count();

        assert!(doc.entities().all(|entity| {
            !matches!(
                entity,
                EntityType::Block(_) | EntityType::BlockEnd(_) | EntityType::Seqend(_)
            )
        }));

        let listed = list_entities(
            &doc,
            &EntityListOptions {
                include_invisible: true,
                limit: MAX_ENTITY_LIST_LIMIT,
                ..Default::default()
            },
        )
        .unwrap();

        assert_eq!(listed.total, backend_entity_count);
        assert!(listed.items.iter().all(|record| {
            !matches!(record.entity_type.as_str(), "BLOCK" | "ENDBLK" | "SEQEND")
        }));
        let dynamic_insert = listed
            .items
            .iter()
            .find(|record| record.handle == "252")
            .expect("fixture INSERT 252");
        assert!(matches!(
            &dynamic_insert.detail,
            EntityDetail::Insert {
                dynamic_block: DynamicBlockLink::Available {
                    definition_handle,
                    definition_name,
                    ..
                },
                ..
            } if definition_handle == "24F"
                && definition_name == "block_visibility_parameter"
        ));
        for expected in &listed.items {
            assert_eq!(get_entity(&doc, &expected.handle).unwrap(), *expected);
        }
    }

    #[test]
    fn record_round_trips_and_schema_is_constructible() {
        let mut doc = CadDocument::new();
        let handle = doc.add_entity(EntityType::Line(Line::new())).unwrap();
        let record = get_entity(&doc, &canonical_handle(handle)).unwrap();
        let json = serde_json::to_string(&record).unwrap();
        let parsed: EntityRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, record);
        let _schema = schemars::schema_for!(EntityListOptions);
        let _schema = schemars::schema_for!(EntityRecord);
    }
}
