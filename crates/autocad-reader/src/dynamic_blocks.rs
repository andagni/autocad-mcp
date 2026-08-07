//! Deterministic, read-only dynamic-block linkage for INSERT entities.
//! This implementation is owned by the transitional reader boundary.
//!
//! `acadrust` retains the relevant DWG objects in two side maps, but its
//! convenience resolver selects from `HashMap` iteration with `find`. Public
//! output must not depend on that order. This module resolves every candidate,
//! rejects contradictory or ambiguous graphs, and exposes only bounded
//! metadata. In particular, it does not infer the active visibility state from
//! entity invisibility: distinct persisted states may have identical member
//! sets, and the pinned reader does not retain the selected state value.

use std::collections::BTreeSet;

use acadrust::{
    entities::Insert,
    objects::{BlockVisibilityParameter, ObjectType},
    tables::BlockRecord,
    types::Handle,
    CadDocument,
};

pub use super::contract::{
    DynamicBlockLink, DynamicBlockUnavailableReason, DynamicCurrentState,
    DynamicCurrentStateUnavailableReason, DynamicVisibilityParameter,
    DynamicVisibilityParameterUnavailableReason,
};

const MAX_OWNER_CHAIN_NODES: usize = 16;
const UNSUPPORTED_DYNAMIC_BLOCK_DATA: &str = "unsupported_dynamic_block_data";

autocad_diagnostics::domain_error!(pub struct DynamicBlockReadError, new = pub(self));

impl DynamicBlockReadError {
    fn unsupported(message: impl Into<String>) -> Self {
        Self::new(UNSUPPORTED_DYNAMIC_BLOCK_DATA, message)
    }
}

/// Resolve bounded dynamic-block metadata for an already selected INSERT.
///
/// This accepts the INSERT by reference so both generic entity reads and the
/// dedicated ordinary-block-insert surface can reuse the same resolver without
/// independently selecting an entity by handle.
pub fn resolve_dynamic_block_link(
    document: &CadDocument,
    insert: &Insert,
) -> Result<DynamicBlockLink, DynamicBlockReadError> {
    let effective_definition = unique_definition_by_name(document, &insert.block_name)?;
    let representations = reachable_representations(document, insert)?;

    let (dynamic_definition, representation_proven) = match representations.as_slice() {
        [] => (effective_definition, false),
        [(_, definition_handle)] => (
            unique_definition_by_handle(document, *definition_handle)?,
            true,
        ),
        candidates => {
            let facts = candidates
                .iter()
                .map(|(representation, definition)| {
                    format!("{:X}->{:X}", representation.value(), definition.value())
                })
                .collect::<Vec<_>>()
                .join(", ");
            return Err(DynamicBlockReadError::unsupported(format!(
                "INSERT {:X} has multiple reachable dynamic-block representations: {facts}",
                insert.common.handle.value()
            )));
        }
    };

    let parameters = visibility_parameters_for_definition(document, dynamic_definition.handle)?;

    if !representation_proven && parameters.is_empty() {
        return Ok(DynamicBlockLink::Unavailable {
            reason: DynamicBlockUnavailableReason::LinkNotProven,
        });
    }

    let visibility_parameter = match parameters.as_slice() {
        [] => DynamicVisibilityParameter::Unavailable {
            reason: DynamicVisibilityParameterUnavailableReason::ParameterNotProven,
        },
        [(map_handle, parameter)] => {
            validate_parameter_identity(*map_handle, parameter)?;
            DynamicVisibilityParameter::Available {
                handle: canonical_handle(*map_handle, "visibility parameter")?,
                name: parameter.name.clone(),
                selectable_state_count: parameter.states.len(),
                current_state: DynamicCurrentState::Unavailable {
                    reason: DynamicCurrentStateUnavailableReason::ParserNotRetained,
                },
            }
        }
        candidates => {
            let handles = candidates
                .iter()
                .map(|(handle, _)| format!("{:X}", handle.value()))
                .collect::<Vec<_>>()
                .join(", ");
            return Err(DynamicBlockReadError::unsupported(format!(
                "dynamic block definition {:X} has multiple reachable visibility parameters: {handles}",
                dynamic_definition.handle.value()
            )));
        }
    };

    Ok(DynamicBlockLink::Available {
        definition_handle: canonical_handle(dynamic_definition.handle, "dynamic block definition")?,
        definition_name: dynamic_definition.name.clone(),
        visibility_parameter,
    })
}

fn unique_definition_by_name<'a>(
    document: &'a CadDocument,
    name: &str,
) -> Result<&'a BlockRecord, DynamicBlockReadError> {
    let name_key = cad_name_key(name);
    let mut matches = document
        .block_records
        .iter()
        .filter(|definition| cad_name_key(&definition.name) == name_key)
        .collect::<Vec<_>>();
    matches.sort_by_key(|definition| definition.handle.value());

    match matches.as_slice() {
        [definition] => {
            canonical_handle(definition.handle, "effective block definition")?;
            Ok(*definition)
        }
        [] => Err(DynamicBlockReadError::unsupported(format!(
            "INSERT references missing block definition `{name}`"
        ))),
        definitions => Err(DynamicBlockReadError::unsupported(format!(
            "INSERT block definition `{name}` is ambiguous across handles {}",
            definitions
                .iter()
                .map(|definition| format!("{:X}", definition.handle.value()))
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

fn unique_definition_by_handle(
    document: &CadDocument,
    handle: Handle,
) -> Result<&BlockRecord, DynamicBlockReadError> {
    canonical_handle(handle, "dynamic block definition")?;
    let matches = document
        .block_records
        .iter()
        .filter(|definition| definition.handle == handle)
        .collect::<Vec<_>>();

    match matches.as_slice() {
        [definition] => Ok(*definition),
        [] => Err(DynamicBlockReadError::unsupported(format!(
            "dynamic block representation references missing definition {:X}",
            handle.value()
        ))),
        _ => Err(DynamicBlockReadError::unsupported(format!(
            "multiple block definitions share dynamic definition handle {:X}",
            handle.value()
        ))),
    }
}

fn reachable_representations(
    document: &CadDocument,
    insert: &Insert,
) -> Result<Vec<(Handle, Handle)>, DynamicBlockReadError> {
    let Some(extension_dictionary) = insert.common.xdictionary_handle else {
        return Ok(Vec::new());
    };
    canonical_handle(extension_dictionary, "INSERT extension dictionary")?;

    let mut retained = document
        .block_representations
        .iter()
        .map(|(representation, definition)| (*representation, *definition))
        .collect::<Vec<_>>();
    retained
        .sort_by_key(|(representation, definition)| (representation.value(), definition.value()));

    let mut candidates = Vec::new();
    for (representation, definition) in retained {
        canonical_handle(representation, "dynamic block representation")?;
        canonical_handle(definition, "dynamic block representation target")?;
        if owner_chain_reaches(
            document,
            representation,
            extension_dictionary,
            "dynamic block representation",
        )? {
            candidates.push((representation, definition));
        }
    }

    if candidates.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(DynamicBlockReadError::unsupported(
            "duplicate dynamic-block representation identities were retained",
        ));
    }
    Ok(candidates)
}

fn visibility_parameters_for_definition(
    document: &CadDocument,
    definition: Handle,
) -> Result<Vec<(Handle, &BlockVisibilityParameter)>, DynamicBlockReadError> {
    let mut retained = document.block_visibility_params.iter().collect::<Vec<_>>();
    retained.sort_by_key(|(handle, _)| handle.value());

    let mut candidates = Vec::new();
    for (map_handle, parameter) in retained {
        if owner_chain_reaches(
            document,
            parameter.owner,
            definition,
            "dynamic visibility parameter",
        )? {
            candidates.push((*map_handle, parameter));
        }
    }
    if candidates.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(DynamicBlockReadError::unsupported(
            "duplicate dynamic visibility parameter identities were retained",
        ));
    }
    Ok(candidates)
}

fn validate_parameter_identity(
    map_handle: Handle,
    parameter: &BlockVisibilityParameter,
) -> Result<(), DynamicBlockReadError> {
    canonical_handle(map_handle, "visibility parameter")?;
    if parameter.handle != map_handle {
        return Err(DynamicBlockReadError::unsupported(format!(
            "visibility parameter map key {:X} contradicts retained handle {:X}",
            map_handle.value(),
            parameter.handle.value()
        )));
    }
    Ok(())
}

fn owner_chain_reaches(
    document: &CadDocument,
    start: Handle,
    target: Handle,
    resource: &str,
) -> Result<bool, DynamicBlockReadError> {
    if start.is_null() {
        return Ok(false);
    }
    canonical_handle(target, "owner-chain target")?;

    let mut current = start;
    let mut visited = BTreeSet::new();
    for _ in 0..MAX_OWNER_CHAIN_NODES {
        if current == target {
            return Ok(true);
        }
        if !visited.insert(current) {
            return Err(DynamicBlockReadError::unsupported(format!(
                "{resource} owner chain contains a cycle at {:X}",
                current.value()
            )));
        }

        let Some(next) = object_owner(document, current) else {
            return Ok(false);
        };
        if next.is_null() {
            return Ok(false);
        }
        current = next;
    }

    if current == target {
        Ok(true)
    } else {
        Err(DynamicBlockReadError::unsupported(format!(
            "{resource} owner chain exceeds the {MAX_OWNER_CHAIN_NODES}-node safety bound"
        )))
    }
}

fn object_owner(document: &CadDocument, handle: Handle) -> Option<Handle> {
    match document.objects.get(&handle)? {
        ObjectType::Dictionary(dictionary) => Some(dictionary.owner),
        ObjectType::DictionaryWithDefault(dictionary) => Some(dictionary.owner),
        ObjectType::Unknown { owner, .. } => Some(*owner),
        _ => None,
    }
}

fn canonical_handle(handle: Handle, resource: &str) -> Result<String, DynamicBlockReadError> {
    if handle.is_null() {
        return Err(DynamicBlockReadError::unsupported(format!(
            "{resource} has null handle 0"
        )));
    }
    Ok(format!("{:X}", handle.value()))
}

fn cad_name_key(name: &str) -> String {
    name.to_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use acadrust::{
        entities::EntityType,
        objects::{BlockVisibilityState, ObjectType},
        tables::BlockRecord,
        types::Vector3,
        DwgReader,
    };
    use serde_json::json;
    use std::path::{Path, PathBuf};

    fn fixture_path(relative: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(relative)
    }

    fn visibility_fixture() -> CadDocument {
        let path =
            fixture_path("tests/corpus/open/acadsharp/dynamic-blocks/BLOCKVISIBILITYPARAMETER.dwg");
        let mut reader = DwgReader::from_file(path).expect("open visibility fixture");
        reader.read().expect("read visibility fixture")
    }

    fn insert_by_handle(document: &CadDocument, handle: u64) -> &Insert {
        document
            .entities()
            .find_map(|entity| match entity {
                EntityType::Insert(insert) if insert.common.handle == Handle::new(handle) => {
                    Some(insert)
                }
                _ => None,
            })
            .unwrap_or_else(|| panic!("fixture INSERT {handle:X}"))
    }

    fn add_definition(document: &mut CadDocument, name: &str, handle: u64) {
        let mut definition = BlockRecord::new(name);
        definition.handle = Handle::new(handle);
        document.block_records.add_or_replace(definition);
    }

    fn insert(name: &str, handle: u64) -> Insert {
        let mut insert = Insert::new(name, Vector3::ZERO);
        insert.common.handle = Handle::new(handle);
        insert
    }

    fn unknown_object(handle: u64, owner: u64) -> ObjectType {
        ObjectType::Unknown {
            type_name: "TEST_DYNAMIC_OBJECT".to_string(),
            handle: Handle::new(handle),
            owner: Handle::new(owner),
            raw_dxf_codes: None,
            raw_dwg_data: None,
            raw_dwg_handle_bits: 0,
            raw_dwg_version: None,
        }
    }

    fn expected_fixture_link() -> DynamicBlockLink {
        DynamicBlockLink::Available {
            definition_handle: "24F".to_string(),
            definition_name: "block_visibility_parameter".to_string(),
            visibility_parameter: DynamicVisibilityParameter::Available {
                handle: "33B".to_string(),
                name: "Test visibility".to_string(),
                selectable_state_count: 4,
                current_state: DynamicCurrentState::Unavailable {
                    reason: DynamicCurrentStateUnavailableReason::ParserNotRetained,
                },
            },
        }
    }

    #[test]
    fn tier1_visibility_inserts_resolve_without_inferring_current_state() {
        let document = visibility_fixture();
        for handle in [0x252, 0x268, 0x284, 0x28C] {
            assert_eq!(
                resolve_dynamic_block_link(&document, insert_by_handle(&document, handle)).unwrap(),
                expected_fixture_link()
            );
        }

        let parameter = document
            .block_visibility_params
            .get(&Handle::new(0x33B))
            .expect("visibility parameter 33B");
        let state_one = parameter
            .states
            .iter()
            .find(|state| state.name == "VisibilityState1")
            .expect("VisibilityState1");
        let show_all = parameter
            .states
            .iter()
            .find(|state| state.name == "ShowAll")
            .expect("ShowAll");
        assert_eq!(
            state_one.visible_blocks, show_all.visible_blocks,
            "identical member sets prove that current state cannot be inferred"
        );
    }

    #[test]
    fn static_insert_reports_only_that_link_is_not_proven() {
        let mut document = CadDocument::new();
        add_definition(&mut document, "STATIC", 0xA0);
        let insert = insert("STATIC", 0xA1);

        assert_eq!(
            resolve_dynamic_block_link(&document, &insert).unwrap(),
            DynamicBlockLink::Unavailable {
                reason: DynamicBlockUnavailableReason::LinkNotProven
            }
        );
    }

    #[test]
    fn direct_definition_visibility_parameter_proves_link_without_representation() {
        let mut document = CadDocument::new();
        add_definition(&mut document, "DIRECT_DYNAMIC", 0xB0);
        let insert = insert("DIRECT_DYNAMIC", 0xB1);

        let mut parameter = BlockVisibilityParameter {
            handle: Handle::new(0xB2),
            owner: Handle::new(0xB0),
            name: "Visibility".to_string(),
            ..Default::default()
        };
        parameter.states.push(BlockVisibilityState {
            name: "Default".to_string(),
            ..Default::default()
        });
        document
            .block_visibility_params
            .insert(parameter.handle, parameter);

        assert_eq!(
            resolve_dynamic_block_link(&document, &insert).unwrap(),
            DynamicBlockLink::Available {
                definition_handle: "B0".to_string(),
                definition_name: "DIRECT_DYNAMIC".to_string(),
                visibility_parameter: DynamicVisibilityParameter::Available {
                    handle: "B2".to_string(),
                    name: "Visibility".to_string(),
                    selectable_state_count: 1,
                    current_state: DynamicCurrentState::Unavailable {
                        reason: DynamicCurrentStateUnavailableReason::ParserNotRetained
                    }
                }
            }
        );
    }

    #[test]
    fn representation_without_parameter_reports_the_proven_definition_only() {
        let mut document = CadDocument::new();
        add_definition(&mut document, "*U1", 0xB4);
        add_definition(&mut document, "DYNAMIC", 0xB5);
        let mut insert = insert("*U1", 0xB6);
        insert.common.xdictionary_handle = Some(Handle::new(0xB7));
        document
            .objects
            .insert(Handle::new(0xB8), unknown_object(0xB8, 0xB7));
        document
            .block_representations
            .insert(Handle::new(0xB8), Handle::new(0xB5));

        assert_eq!(
            resolve_dynamic_block_link(&document, &insert).unwrap(),
            DynamicBlockLink::Available {
                definition_handle: "B5".to_string(),
                definition_name: "DYNAMIC".to_string(),
                visibility_parameter: DynamicVisibilityParameter::Unavailable {
                    reason: DynamicVisibilityParameterUnavailableReason::ParameterNotProven,
                },
            }
        );
    }

    #[test]
    fn multiple_reachable_representations_fail_closed_even_for_the_same_target() {
        let mut document = CadDocument::new();
        add_definition(&mut document, "*U1", 0xC0);
        add_definition(&mut document, "DYNAMIC", 0xC1);
        let mut insert = insert("*U1", 0xC2);
        insert.common.xdictionary_handle = Some(Handle::new(0xC3));

        for representation in [0xC4, 0xC5] {
            document.objects.insert(
                Handle::new(representation),
                unknown_object(representation, 0xC3),
            );
            document
                .block_representations
                .insert(Handle::new(representation), Handle::new(0xC1));
        }

        let error = resolve_dynamic_block_link(&document, &insert).unwrap_err();
        assert_eq!(error.code(), "unsupported_dynamic_block_data");
        assert!(error.message().contains("multiple reachable"));
    }

    #[test]
    fn missing_and_ambiguous_definitions_fail_closed() {
        let mut missing_document = CadDocument::new();
        add_definition(&mut missing_document, "*U1", 0xC8);
        let mut missing_insert = insert("*U1", 0xC9);
        missing_insert.common.xdictionary_handle = Some(Handle::new(0xCA));
        missing_document
            .objects
            .insert(Handle::new(0xCB), unknown_object(0xCB, 0xCA));
        missing_document
            .block_representations
            .insert(Handle::new(0xCB), Handle::new(0xCC));
        let error = resolve_dynamic_block_link(&missing_document, &missing_insert).unwrap_err();
        assert!(error.message().contains("missing definition CC"));

        let mut ambiguous_document = CadDocument::new();
        let mut first = BlockRecord::new("DUPLICATE");
        first.handle = Handle::new(0xCD);
        ambiguous_document.block_records.add_allow_duplicate(first);
        let mut second = BlockRecord::new("duplicate");
        second.handle = Handle::new(0xCE);
        ambiguous_document.block_records.add_allow_duplicate(second);
        let ambiguous_insert = insert("Duplicate", 0xCF);
        let error = resolve_dynamic_block_link(&ambiguous_document, &ambiguous_insert).unwrap_err();
        assert!(error.message().contains("ambiguous across handles CD, CE"));
    }

    #[test]
    fn malformed_side_map_entries_are_checked_in_numeric_handle_order() {
        let mut document = CadDocument::new();
        add_definition(&mut document, "*U1", 0xD4);
        let mut insert = insert("*U1", 0xD5);
        insert.common.xdictionary_handle = Some(Handle::new(0xD6));
        document
            .block_representations
            .insert(Handle::new(0xD8), Handle::NULL);
        document
            .block_representations
            .insert(Handle::NULL, Handle::new(0xD7));

        let error = resolve_dynamic_block_link(&document, &insert).unwrap_err();
        assert_eq!(
            error.message(),
            "dynamic block representation has null handle 0"
        );
    }

    #[test]
    fn multiple_visibility_parameters_for_one_definition_fail_closed() {
        let mut document = CadDocument::new();
        add_definition(&mut document, "DYNAMIC", 0xD0);
        let insert = insert("DYNAMIC", 0xD1);

        for handle in [0xD2, 0xD3] {
            let parameter = BlockVisibilityParameter {
                handle: Handle::new(handle),
                owner: Handle::new(0xD0),
                name: format!("Visibility {handle:X}"),
                ..Default::default()
            };
            document
                .block_visibility_params
                .insert(parameter.handle, parameter);
        }

        let error = resolve_dynamic_block_link(&document, &insert).unwrap_err();
        assert_eq!(error.code(), "unsupported_dynamic_block_data");
        assert!(error.message().contains("multiple reachable"));
    }

    #[test]
    fn cyclic_representation_owner_chain_fails_closed() {
        let mut document = CadDocument::new();
        add_definition(&mut document, "*U1", 0xE0);
        add_definition(&mut document, "DYNAMIC", 0xE1);
        let mut insert = insert("*U1", 0xE2);
        insert.common.xdictionary_handle = Some(Handle::new(0xE3));

        document
            .objects
            .insert(Handle::new(0xE4), unknown_object(0xE4, 0xE5));
        document
            .objects
            .insert(Handle::new(0xE5), unknown_object(0xE5, 0xE4));
        document
            .block_representations
            .insert(Handle::new(0xE4), Handle::new(0xE1));

        let error = resolve_dynamic_block_link(&document, &insert).unwrap_err();
        assert_eq!(error.code(), "unsupported_dynamic_block_data");
        assert!(error.message().contains("cycle"));
    }

    #[test]
    fn parameter_map_identity_is_exact() {
        let mut document = CadDocument::new();
        add_definition(&mut document, "DYNAMIC", 0xF0);
        let insert = insert("DYNAMIC", 0xF1);

        let parameter = BlockVisibilityParameter {
            handle: Handle::new(0xF3),
            owner: Handle::new(0xF0),
            name: "Visibility".to_string(),
            ..Default::default()
        };
        document
            .block_visibility_params
            .insert(Handle::new(0xF2), parameter);
        let error = resolve_dynamic_block_link(&document, &insert).unwrap_err();
        assert!(error.message().contains("contradicts retained handle"));
    }

    #[test]
    fn response_types_round_trip_and_reject_unknown_fields() {
        let expected = expected_fixture_link();
        let value = serde_json::to_value(&expected).unwrap();
        assert_eq!(
            value,
            json!({
                "state": "available",
                "definition_handle": "24F",
                "definition_name": "block_visibility_parameter",
                "visibility_parameter": {
                    "state": "available",
                    "handle": "33B",
                    "name": "Test visibility",
                    "selectable_state_count": 4,
                    "current_state": {
                        "state": "unavailable",
                        "reason": "parser_not_retained"
                    }
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<DynamicBlockLink>(value).unwrap(),
            expected
        );

        assert!(serde_json::from_value::<DynamicBlockLink>(json!({
            "state": "unavailable",
            "reason": "link_not_proven",
            "extra": true
        }))
        .is_err());
        assert!(serde_json::from_value::<DynamicBlockLink>(json!({
            "state": "available",
            "definition_handle": "24F",
            "definition_name": "block_visibility_parameter",
            "visibility_parameter": {
                "state": "unavailable",
                "reason": "parameter_not_proven",
                "extra": true
            }
        }))
        .is_err());
        assert!(serde_json::from_value::<DynamicBlockLink>(json!({
            "state": "available",
            "definition_handle": "24F",
            "definition_name": "block_visibility_parameter",
            "visibility_parameter": {
                "state": "available",
                "handle": "33B",
                "name": "Test visibility",
                "selectable_state_count": 4,
                "current_state": {
                    "state": "unavailable",
                    "reason": "parser_not_retained",
                    "extra": true
                }
            }
        }))
        .is_err());

        let schema = serde_json::to_string(&schemars::schema_for!(DynamicBlockLink)).unwrap();
        assert!(schema.contains("\"additionalProperties\":false"));
    }
}
