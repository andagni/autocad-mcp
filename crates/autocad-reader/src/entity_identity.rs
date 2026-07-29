use acadrust::{entities::EntityType, types::Handle, CadDocument};

pub(crate) const ACADRUST_INSERT_SCALE_SENTINEL: f64 = 1e-12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SemanticEntityHandleError {
    code: &'static str,
    message: &'static str,
}

impl SemanticEntityHandleError {
    pub(crate) fn code(&self) -> &'static str {
        self.code
    }

    pub(crate) fn message(&self) -> &'static str {
        self.message
    }
}

pub(crate) fn validate_semantic_entity_handles(
    document: &CadDocument,
) -> Result<(), SemanticEntityHandleError> {
    let mut handles = document
        .entities()
        .filter(|entity| is_semantic_entity(entity))
        .map(|entity| entity.common().handle)
        .collect::<Vec<_>>();
    if handles.iter().any(|handle| handle.is_null()) {
        return Err(SemanticEntityHandleError {
            code: "invalid_entity_handle",
            message: "drawing contains an entity with handle 0",
        });
    }
    for entity in document.entities() {
        if let EntityType::Insert(insert) = entity {
            handles.extend(
                insert
                    .attributes
                    .iter()
                    .map(|attribute| attribute.common.handle)
                    .filter(Handle::is_valid),
            );
        }
    }
    handles.sort_by_key(Handle::value);
    if handles.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(SemanticEntityHandleError {
            code: "duplicate_entity_handle",
            message:
                "drawing contains multiple public entities or attached attributes with the same handle",
        });
    }
    Ok(())
}

pub(crate) fn is_semantic_entity(entity: &EntityType) -> bool {
    !matches!(
        entity,
        EntityType::Block(_) | EntityType::BlockEnd(_) | EntityType::Seqend(_)
    )
}

pub(crate) fn entity_type_name(entity: &EntityType) -> String {
    match entity {
        EntityType::Dimension(_) => "DIMENSION".to_string(),
        EntityType::Surface(surface) => surface.kind.dxf_name().to_string(),
        EntityType::Unknown(unknown) if !unknown.dxf_name.trim().is_empty() => {
            unknown.dxf_name.trim().to_uppercase()
        }
        _ => entity.as_entity().entity_type().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use acadrust::entities::{Surface, SurfaceKind};

    #[test]
    fn surface_entity_names_preserve_the_decoded_subtype() {
        for (kind, expected) in [
            (SurfaceKind::Generic, "SURFACE"),
            (SurfaceKind::Plane, "PLANESURFACE"),
            (SurfaceKind::Extruded, "EXTRUDEDSURFACE"),
            (SurfaceKind::Lofted, "LOFTEDSURFACE"),
            (SurfaceKind::Revolved, "REVOLVEDSURFACE"),
            (SurfaceKind::Swept, "SWEPTSURFACE"),
            (SurfaceKind::Nurb, "NURBSURFACE"),
        ] {
            assert_eq!(
                entity_type_name(&EntityType::Surface(Surface::new(kind))),
                expected
            );
        }
    }
}
