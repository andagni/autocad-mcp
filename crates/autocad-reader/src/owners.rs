//! Shared fail-closed direct-owner resolution for expanded read records.
//! This implementation is owned by the transitional reader boundary.

use acadrust::{
    entities::EntityType,
    objects::{Layout, ObjectType},
    tables::BlockRecord,
    types::Handle,
    CadDocument,
};

pub use super::contract::{DirectOwnerContext, DirectOwnerType, DirectOwnerUnavailableReason};
use super::entity_identity::entity_type_name;

// Was missing a `message()` accessor for its first several years, which
// meant every caller that folds a `DirectOwnerError` into its own coded
// error (see `blocks.rs`, `drawing.rs`, `entities.rs`, `layouts.rs`,
// `text.rs`) had to go through `Display`/`to_string()` instead — doubling
// the `code=<code>` prefix in the resulting message, the same bug class
// `e4ee102` fixed for `XrefError`. `domain_error!` gives every domain error
// `message()` unconditionally so this can't recur; the call sites were
// fixed alongside this migration.
autocad_diagnostics::domain_error!(pub struct DirectOwnerError, new = pub(crate));

pub fn owner_name_eq(left: &str, right: &str) -> bool {
    left.to_uppercase() == right.to_uppercase()
}

fn unique_match<'a, T>(
    matches: Vec<&'a T>,
    code: &'static str,
    message: impl FnOnce() -> String,
) -> Result<Option<&'a T>, DirectOwnerError> {
    match matches.as_slice() {
        [] => Ok(None),
        [value] => Ok(Some(*value)),
        _ => Err(DirectOwnerError::new(code, message())),
    }
}

fn matching_block(
    doc: &CadDocument,
    owner: Handle,
) -> Result<Option<&BlockRecord>, DirectOwnerError> {
    unique_match(
        doc.block_records
            .iter()
            .filter(|block| block.handle == owner)
            .collect(),
        "duplicate_owner_block_record",
        || {
            format!(
                "owner handle {:X} resolves to multiple block records",
                owner.value()
            )
        },
    )
}

fn matching_entity(
    doc: &CadDocument,
    owner: Handle,
) -> Result<Option<&EntityType>, DirectOwnerError> {
    unique_match(
        doc.entities()
            .filter(|entity| entity.common().handle == owner)
            .collect(),
        "duplicate_owner_entity",
        || {
            format!(
                "owner handle {:X} resolves to multiple entities",
                owner.value()
            )
        },
    )
}

fn matching_layout(doc: &CadDocument, owner: Handle) -> Result<Option<&Layout>, DirectOwnerError> {
    unique_match(
        doc.objects
            .values()
            .filter_map(|object| match object {
                ObjectType::Layout(layout) if layout.block_record == owner => Some(layout),
                _ => None,
            })
            .collect(),
        "duplicate_owner_layout",
        || {
            format!(
                "owner handle {:X} resolves to multiple layouts",
                owner.value()
            )
        },
    )
}

fn contradiction(owner: Handle, detail: impl Into<String>) -> DirectOwnerError {
    DirectOwnerError::new(
        "contradictory_owner_identity",
        format!(
            "owner handle {:X} has contradictory ownership facts: {}",
            owner.value(),
            detail.into()
        ),
    )
}

pub(crate) fn is_model_space_block(block: &BlockRecord) -> bool {
    owner_name_eq(&block.name, "*Model_Space")
}

pub(crate) fn is_paper_space_block(block: &BlockRecord) -> bool {
    block.name.to_uppercase().starts_with("*PAPER_SPACE")
}

/// Return whether a BLOCK_RECORD contains direct XREF-definition evidence.
///
/// Keep dependent-symbol naming (`flags.is_external` or `name` containing
/// `|`) separate: those records are XREF-dependent host-table content, not
/// attachment definitions.
pub(crate) fn is_xref_definition(block: &BlockRecord) -> bool {
    block.flags.is_xref || block.flags.is_xref_overlay || !block.xref_path.is_empty()
}

/// Resolve the semantic direct owner of one persisted owner handle.
///
/// `Ok(None)` is reserved for a null owner handle. A non-null handle always
/// returns an availability-tagged context unless duplicate or contradictory
/// document facts make the result unsafe.
pub fn resolve_direct_owner(
    doc: &CadDocument,
    owner: Handle,
) -> Result<Option<DirectOwnerContext>, DirectOwnerError> {
    if owner.is_null() {
        return Ok(None);
    }

    let block = matching_block(doc, owner)?;
    let entity = matching_entity(doc, owner)?;
    let layout = matching_layout(doc, owner)?;

    if block.is_some() && entity.is_some() {
        return Err(contradiction(
            owner,
            "the same handle identifies both a block record and an entity",
        ));
    }

    match (block, entity, layout) {
        (Some(_), None, Some(layout)) if layout.name.trim().is_empty() => Err(contradiction(
            owner,
            "layout-backed block has an empty layout name",
        )),
        (Some(block), None, Some(layout)) if owner_name_eq(&layout.name, "Model") => {
            if !is_model_space_block(block) {
                return Err(contradiction(
                    owner,
                    format!(
                        "block `{}` is linked to the Model layout but is not a model-space alias",
                        block.name
                    ),
                ));
            }
            Ok(Some(DirectOwnerContext::Available {
                owner_type: DirectOwnerType::ModelSpace,
                owner_name: "Model".to_string(),
            }))
        }
        (Some(block), None, Some(layout)) => {
            if is_model_space_block(block) {
                return Err(contradiction(
                    owner,
                    format!(
                        "model-space block is linked to layout `{}` instead of `Model`",
                        layout.name
                    ),
                ));
            }
            Ok(Some(DirectOwnerContext::Available {
                owner_type: DirectOwnerType::PaperSpace,
                owner_name: layout.name.clone(),
            }))
        }
        (Some(block), None, None) if is_model_space_block(block) => {
            Ok(Some(DirectOwnerContext::Available {
                owner_type: DirectOwnerType::ModelSpace,
                owner_name: "Model".to_string(),
            }))
        }
        (Some(block), None, None) if is_paper_space_block(block) => {
            Ok(Some(DirectOwnerContext::Unavailable {
                reason: DirectOwnerUnavailableReason::MissingPaperSpaceLayout,
            }))
        }
        (Some(block), None, None) => Ok(Some(DirectOwnerContext::Available {
            owner_type: DirectOwnerType::BlockDefinition,
            owner_name: block.name.clone(),
        })),
        (None, Some(entity), Some(layout)) => Err(contradiction(
            owner,
            format!(
                "entity `{}` is also referenced as layout `{}` block record",
                entity_type_name(entity),
                layout.name
            ),
        )),
        (None, Some(entity), None) => Ok(Some(DirectOwnerContext::Available {
            owner_type: DirectOwnerType::Entity,
            owner_name: entity_type_name(entity),
        })),
        (None, None, Some(layout)) => Err(contradiction(
            owner,
            format!("layout `{}` references a missing block record", layout.name),
        )),
        (None, None, None) => Ok(Some(DirectOwnerContext::Unavailable {
            reason: DirectOwnerUnavailableReason::UnresolvedOwner,
        })),
        (Some(_), Some(_), _) => unreachable!("block/entity contradiction handled above"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use acadrust::{
        entities::{EntityType, Line},
        objects::Layout,
        tables::BlockRecord,
    };

    #[test]
    fn resolves_model_paper_block_and_entity_owner_names() {
        let mut doc = CadDocument::new();

        assert_eq!(
            resolve_direct_owner(&doc, doc.header.model_space_block_handle).unwrap(),
            Some(DirectOwnerContext::Available {
                owner_type: DirectOwnerType::ModelSpace,
                owner_name: "Model".to_string(),
            })
        );
        assert_eq!(
            resolve_direct_owner(&doc, doc.header.paper_space_block_handle).unwrap(),
            Some(DirectOwnerContext::Available {
                owner_type: DirectOwnerType::PaperSpace,
                owner_name: "Layout1".to_string(),
            })
        );

        let mut block = BlockRecord::new("DETAIL");
        block.handle = Handle::new(0xA00);
        doc.block_records.add(block).unwrap();
        assert_eq!(
            resolve_direct_owner(&doc, Handle::new(0xA00)).unwrap(),
            Some(DirectOwnerContext::Available {
                owner_type: DirectOwnerType::BlockDefinition,
                owner_name: "DETAIL".to_string(),
            })
        );

        let mut line = Line::new();
        line.common.handle = Handle::new(0xA01);
        doc.add_entity(EntityType::Line(line)).unwrap();
        assert_eq!(
            resolve_direct_owner(&doc, Handle::new(0xA01)).unwrap(),
            Some(DirectOwnerContext::Available {
                owner_type: DirectOwnerType::Entity,
                owner_name: "LINE".to_string(),
            })
        );
    }

    #[test]
    fn legacy_model_alias_and_layout_join_classify_space_owners() {
        let mut doc = CadDocument::new();

        let legacy_model_handle = doc.header.model_space_block_handle;
        let mut legacy_model = BlockRecord::new("*MODEL_SPACE");
        legacy_model.handle = legacy_model_handle;
        doc.block_records.add_or_replace(legacy_model);
        assert_eq!(
            resolve_direct_owner(&doc, legacy_model_handle).unwrap(),
            Some(DirectOwnerContext::Available {
                owner_type: DirectOwnerType::ModelSpace,
                owner_name: "Model".to_string(),
            })
        );

        let joined_paper_handle = Handle::new(0xA12);
        let mut joined_paper = BlockRecord::new("LEGACY_LAYOUT_BLOCK");
        joined_paper.handle = joined_paper_handle;
        doc.block_records.add(joined_paper).unwrap();
        let mut paper_layout = Layout::new("Sheet A");
        paper_layout.handle = Handle::new(0xA13);
        paper_layout.block_record = joined_paper_handle;
        doc.objects
            .insert(paper_layout.handle, ObjectType::Layout(paper_layout));
        assert_eq!(
            resolve_direct_owner(&doc, joined_paper_handle).unwrap(),
            Some(DirectOwnerContext::Available {
                owner_type: DirectOwnerType::PaperSpace,
                owner_name: "Sheet A".to_string(),
            })
        );
    }

    #[test]
    fn unresolved_and_missing_paper_layout_are_closed_unavailable_states() {
        let mut doc = CadDocument::new();
        assert_eq!(
            resolve_direct_owner(&doc, Handle::new(0xFFFF)).unwrap(),
            Some(DirectOwnerContext::Unavailable {
                reason: DirectOwnerUnavailableReason::UnresolvedOwner,
            })
        );

        let paper = doc.header.paper_space_block_handle;
        doc.objects.retain(|_, object| {
            !matches!(object, ObjectType::Layout(layout) if layout.block_record == paper)
        });
        assert_eq!(
            resolve_direct_owner(&doc, paper).unwrap(),
            Some(DirectOwnerContext::Unavailable {
                reason: DirectOwnerUnavailableReason::MissingPaperSpaceLayout,
            })
        );
    }

    #[test]
    fn duplicate_and_contradictory_owner_facts_fail_closed() {
        let mut duplicate_blocks = CadDocument::new();
        for name in ["A", "B"] {
            let mut block = BlockRecord::new(name);
            block.handle = Handle::new(0xB00);
            duplicate_blocks.block_records.add(block).unwrap();
        }
        assert_eq!(
            resolve_direct_owner(&duplicate_blocks, Handle::new(0xB00))
                .unwrap_err()
                .code(),
            "duplicate_owner_block_record"
        );

        let mut duplicate_entities = CadDocument::new();
        for _ in 0..2 {
            let mut line = Line::new();
            line.common.handle = Handle::new(0xB01);
            duplicate_entities
                .add_entity(EntityType::Line(line))
                .unwrap();
        }
        assert_eq!(
            resolve_direct_owner(&duplicate_entities, Handle::new(0xB01))
                .unwrap_err()
                .code(),
            "duplicate_owner_entity"
        );

        let mut contradictory = CadDocument::new();
        let mut block = BlockRecord::new("DETAIL");
        block.handle = Handle::new(0xB02);
        contradictory.block_records.add(block).unwrap();
        let mut line = Line::new();
        line.common.handle = Handle::new(0xB02);
        contradictory.add_entity(EntityType::Line(line)).unwrap();
        assert_eq!(
            resolve_direct_owner(&contradictory, Handle::new(0xB02))
                .unwrap_err()
                .code(),
            "contradictory_owner_identity"
        );

        let paper = contradictory.header.paper_space_block_handle;
        let mut extra = Layout::new("Layout2");
        extra.handle = Handle::new(0xB03);
        extra.block_record = paper;
        contradictory
            .objects
            .insert(extra.handle, ObjectType::Layout(extra));
        assert_eq!(
            resolve_direct_owner(&contradictory, paper)
                .unwrap_err()
                .code(),
            "duplicate_owner_layout"
        );
    }

    #[test]
    fn context_json_is_closed_and_availability_tagged() {
        let context = DirectOwnerContext::Available {
            owner_type: DirectOwnerType::ModelSpace,
            owner_name: "Model".to_string(),
        };
        assert_eq!(
            serde_json::to_value(&context).unwrap(),
            serde_json::json!({
                "state": "available",
                "owner_type": "model_space",
                "owner_name": "Model"
            })
        );
        assert!(
            serde_json::from_value::<DirectOwnerContext>(serde_json::json!({
                "state": "unavailable",
                "reason": "unresolved_owner",
                "extra": true
            }))
            .is_err()
        );
        let _schema = schemars::schema_for!(DirectOwnerContext);
    }

    #[test]
    fn xref_definition_evidence_includes_a_saved_path_without_flags() {
        let mut path_only = BlockRecord::new("SITE");
        path_only.xref_path = "refs/site.dwg".to_string();
        assert!(is_xref_definition(&path_only));

        let mut dependent_symbol = BlockRecord::new("SITE|DETAIL");
        dependent_symbol.flags.is_external = true;
        assert!(!is_xref_definition(&dependent_symbol));
    }
}
