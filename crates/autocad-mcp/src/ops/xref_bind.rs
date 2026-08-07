use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::certification::{
    XrefBindStrategy, XrefBindVerifierProfile, XrefClipPolicy, XrefClipVerifierProfile,
    XrefMutationOperation, XrefVerifierSymbolType,
};

use super::{
    xref_graph::require_complete_dependency_graph_for_mutation,
    xref_mutation::{
        XrefLockedMutationContext, XrefMutationEngineBoundary, XrefMutationOperationCallback,
        XrefOperationContext, XrefSourceIdentityProvenance, XrefSourceInput, XrefTransactionError,
        XrefTransactionErrorCode, XrefVerificationContext,
    },
    xrefs::{
        canonical_input_handle, canonicalize_handle_chain, canonicalize_unique_handle_set,
        compare_handle_chains, compare_numeric_handles, compare_xref_names,
        sort_instance_handle_mappings, sort_symbol_mappings, sort_xref_dependency_records,
        xref_failure_code, xref_name_eq, BindXrefRequest, BindXrefResponse, BindXrefStatus,
        ReferenceType, XrefAttachmentRecord, XrefBoundBlock, XrefBoundDependency,
        XrefDependencyRecord, XrefDependencyStrategy, XrefDependencyTraversalEnvelope, XrefError,
        XrefInspectionState, XrefInstanceHandleMapping, XrefPropagationState, XrefSymbolMapping,
        XrefSymbolResolution, XrefSymbolStrategy, XrefSymbolType,
    },
};

const SENTINEL_PREFIX: &str = "AUTOCAD_MCP_XREF_BIND_V1|";
const SCRIPT_FILE_NAME: &str = "xref-bind-operation.lsp";
const EVIDENCE_FILE_NAME: &str = "xref-bind-evidence.jsonl";

autocad_diagnostics::domain_error!(pub(crate) struct BindError, new = pub(self));

impl BindError {
    fn unsupported(detail: impl Into<String>) -> Self {
        Self::new(xref_failure_code::UNSUPPORTED_XREF_CONTENT, detail)
    }

    pub(crate) fn verification(detail: impl Into<String>) -> Self {
        Self::new(xref_failure_code::VERIFICATION_FAILED, detail)
    }
}

impl From<XrefError> for BindError {
    fn from(error: XrefError) -> Self {
        Self::new(
            match error.code() {
                xref_failure_code::INVALID_PARAMETERS => xref_failure_code::INVALID_PARAMETERS,
                xref_failure_code::INVALID_HANDLE => xref_failure_code::INVALID_HANDLE,
                xref_failure_code::MISSING_IDENTITY => xref_failure_code::MISSING_IDENTITY,
                xref_failure_code::AMBIGUOUS_IDENTITY => xref_failure_code::AMBIGUOUS_IDENTITY,
                xref_failure_code::CONTRADICTORY_IDENTITY => {
                    xref_failure_code::CONTRADICTORY_IDENTITY
                }
                xref_failure_code::EXPECTED_HANDLE_MISMATCH => {
                    xref_failure_code::EXPECTED_HANDLE_MISMATCH
                }
                xref_failure_code::EXPECTED_NAME_MISMATCH => {
                    xref_failure_code::EXPECTED_NAME_MISMATCH
                }
                xref_failure_code::EXPECTED_INSTANCE_COUNT_MISMATCH => {
                    xref_failure_code::EXPECTED_INSTANCE_COUNT_MISMATCH
                }
                xref_failure_code::EXPECTED_INSTANCE_HANDLES_MISMATCH => {
                    xref_failure_code::EXPECTED_INSTANCE_HANDLES_MISMATCH
                }
                xref_failure_code::XREF_SOURCE_NOT_FOUND => {
                    xref_failure_code::XREF_SOURCE_NOT_FOUND
                }
                xref_failure_code::XREF_SOURCE_UNREADABLE => {
                    xref_failure_code::XREF_SOURCE_UNREADABLE
                }
                xref_failure_code::UNSUPPORTED_XREF_SOURCE => {
                    xref_failure_code::UNSUPPORTED_XREF_SOURCE
                }
                xref_failure_code::CIRCULAR_XREF => xref_failure_code::CIRCULAR_XREF,
                xref_failure_code::DEPENDENCY_TRAVERSAL_INCOMPLETE => {
                    xref_failure_code::DEPENDENCY_TRAVERSAL_INCOMPLETE
                }
                _ => xref_failure_code::UNSUPPORTED_XREF_CONTENT,
            },
            error.to_string(),
        )
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct BindVerifierContract {
    pub profile_id: String,
    pub absolute_tolerance: f64,
    pub relative_tolerance: f64,
    object_classes: BTreeMap<String, BTreeSet<String>>,
    symbol_types: BTreeMap<u8, BTreeSet<String>>,
    mapped_identity_fields: BTreeSet<String>,
    operation_differences: BTreeSet<String>,
    prefix_differences: BTreeSet<String>,
    merge_differences: BTreeSet<String>,
}

impl BindVerifierContract {
    pub(crate) fn from_profile(profile: &XrefBindVerifierProfile) -> Result<Self, BindError> {
        validate_tolerances(profile.absolute_tolerance, profile.relative_tolerance)?;

        let mut object_classes = BTreeMap::new();
        for class in &profile.object_classes {
            let fields = unique_field_set(&class.fields, "object class", &class.class_name)?;
            if class.class_name.is_empty()
                || object_classes
                    .insert(class.class_name.clone(), fields)
                    .is_some()
            {
                return Err(BindError::unsupported(format!(
                    "bind profile '{}' has duplicate or empty object class '{}'",
                    profile.profile_id, class.class_name
                )));
            }
        }

        let mut symbol_types = BTreeMap::new();
        for symbol in &profile.symbol_types {
            let symbol_type = symbol_type_from_profile(symbol.symbol_type);
            let fields =
                unique_field_set(&symbol.fields, "symbol type", symbol_type_name(symbol_type))?;
            if symbol_types
                .insert(symbol_type.sort_rank(), fields)
                .is_some()
            {
                return Err(BindError::unsupported(format!(
                    "bind profile '{}' has duplicate symbol type '{}'",
                    profile.profile_id,
                    symbol_type_name(symbol_type)
                )));
            }
        }

        let mapped_identity_fields = unique_field_set(
            &profile.mapped_identity_fields,
            "mapped identity",
            &profile.profile_id,
        )?;
        let operation_differences = profile
            .authorized_differences
            .iter()
            .find(|entry| entry.operation == XrefMutationOperation::BindXref)
            .ok_or_else(|| {
                BindError::unsupported(format!(
                    "bind profile '{}' has no bind_xref operation exceptions",
                    profile.profile_id
                ))
            })
            .and_then(|entry| {
                unique_field_set(&entry.fields, "operation exception", "bind_xref")
            })?;

        let strategy_fields = |strategy: XrefBindStrategy| {
            profile
                .strategy_authorized_differences
                .iter()
                .find(|entry| entry.strategy == strategy)
                .ok_or_else(|| {
                    BindError::unsupported(format!(
                        "bind profile '{}' has no {} strategy exceptions",
                        profile.profile_id,
                        strategy.as_str()
                    ))
                })
                .and_then(|entry| {
                    unique_field_set(&entry.fields, "strategy exception", strategy.as_str())
                })
        };

        let contract = Self {
            profile_id: profile.profile_id.clone(),
            absolute_tolerance: profile.absolute_tolerance,
            relative_tolerance: profile.relative_tolerance,
            object_classes,
            symbol_types,
            mapped_identity_fields,
            operation_differences,
            prefix_differences: strategy_fields(XrefBindStrategy::Prefix)?,
            merge_differences: strategy_fields(XrefBindStrategy::Merge)?,
        };
        contract.validate_required_exceptions()?;
        Ok(contract)
    }

    fn validate_required_exceptions(&self) -> Result<(), BindError> {
        require_fields(
            &self.operation_differences,
            &[
                "ordinary_blocks",
                "symbols",
                "xref_attachments",
                "xref_instances",
            ],
            "bind_xref operation",
        )?;
        require_fields(
            &self.prefix_differences,
            &["symbol_handles", "symbol_names"],
            "prefix strategy",
        )?;
        require_fields(
            &self.merge_differences,
            &["symbol_content", "symbol_handles", "symbol_names"],
            "merge strategy",
        )?;
        require_fields(
            &self.mapped_identity_fields,
            &["handle", "owner_handle"],
            "mapped identity",
        )
    }

    fn object_fields(&self, class_name: &str) -> Option<&BTreeSet<String>> {
        self.object_classes.get(class_name)
    }

    fn symbol_fields(&self, symbol_type: XrefSymbolType) -> Option<&BTreeSet<String>> {
        self.symbol_types.get(&symbol_type.sort_rank())
    }

    fn strategy_differences(&self, strategy: XrefSymbolStrategy) -> &BTreeSet<String> {
        match strategy {
            XrefSymbolStrategy::Prefix => &self.prefix_differences,
            XrefSymbolStrategy::Merge => &self.merge_differences,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct BindClipVerifierContract {
    pub profile_id: String,
    pub absolute_tolerance: f64,
    pub relative_tolerance: f64,
    fields: BTreeSet<String>,
}

impl BindClipVerifierContract {
    pub(crate) fn from_profile(profile: &XrefClipVerifierProfile) -> Result<Self, BindError> {
        validate_tolerances(profile.absolute_tolerance, profile.relative_tolerance)?;
        Ok(Self {
            profile_id: profile.profile_id.clone(),
            absolute_tolerance: profile.absolute_tolerance,
            relative_tolerance: profile.relative_tolerance,
            fields: unique_field_set(&profile.clip_fields, "clip field", &profile.profile_id)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum BindClipAdmission {
    Reject,
    Verify(BindClipVerifierContract),
}

fn validate_tolerances(absolute: f64, relative: f64) -> Result<(), BindError> {
    if !absolute.is_finite() || !relative.is_finite() || absolute < 0.0 || relative < 0.0 {
        return Err(BindError::unsupported(
            "bind verifier tolerances must be finite and non-negative",
        ));
    }
    Ok(())
}

fn unique_field_set(
    fields: &[String],
    kind: &str,
    owner: &str,
) -> Result<BTreeSet<String>, BindError> {
    let set: BTreeSet<_> = fields.iter().cloned().collect();
    if set.len() != fields.len() || set.iter().any(String::is_empty) {
        return Err(BindError::unsupported(format!(
            "{kind} list for '{owner}' contains an empty or duplicate field"
        )));
    }
    Ok(set)
}

fn require_fields(
    actual: &BTreeSet<String>,
    required: &[&str],
    label: &str,
) -> Result<(), BindError> {
    if let Some(missing) = required.iter().find(|field| !actual.contains(**field)) {
        return Err(BindError::unsupported(format!(
            "active bind verifier does not authorize required {label} field '{missing}'"
        )));
    }
    Ok(())
}

fn symbol_type_from_profile(value: XrefVerifierSymbolType) -> XrefSymbolType {
    match value {
        XrefVerifierSymbolType::Block => XrefSymbolType::Block,
        XrefVerifierSymbolType::Layer => XrefSymbolType::Layer,
        XrefVerifierSymbolType::Linetype => XrefSymbolType::Linetype,
        XrefVerifierSymbolType::TextStyle => XrefSymbolType::TextStyle,
        XrefVerifierSymbolType::DimensionStyle => XrefSymbolType::DimensionStyle,
        XrefVerifierSymbolType::TableStyle => XrefSymbolType::TableStyle,
        XrefVerifierSymbolType::MultileaderStyle => XrefSymbolType::MultileaderStyle,
        XrefVerifierSymbolType::Material => XrefSymbolType::Material,
        XrefVerifierSymbolType::PlotStyle => XrefSymbolType::PlotStyle,
        XrefVerifierSymbolType::VisualStyle => XrefSymbolType::VisualStyle,
    }
}

fn symbol_type_name(value: XrefSymbolType) -> &'static str {
    match value {
        XrefSymbolType::Block => "block",
        XrefSymbolType::Layer => "layer",
        XrefSymbolType::Linetype => "linetype",
        XrefSymbolType::TextStyle => "text_style",
        XrefSymbolType::DimensionStyle => "dimension_style",
        XrefSymbolType::TableStyle => "table_style",
        XrefSymbolType::MultileaderStyle => "multileader_style",
        XrefSymbolType::Material => "material",
        XrefSymbolType::PlotStyle => "plot_style",
        XrefSymbolType::VisualStyle => "visual_style",
    }
}

fn symbol_table_name(value: XrefSymbolType) -> &'static str {
    match value {
        XrefSymbolType::Block => "BLOCK",
        XrefSymbolType::Layer => "LAYER",
        XrefSymbolType::Linetype => "LTYPE",
        XrefSymbolType::TextStyle => "STYLE",
        XrefSymbolType::DimensionStyle => "DIMSTYLE",
        XrefSymbolType::TableStyle => "TABLESTYLE",
        XrefSymbolType::MultileaderStyle => "MLEADERSTYLE",
        XrefSymbolType::Material => "MATERIAL",
        XrefSymbolType::PlotStyle => "PLOTSTYLE",
        XrefSymbolType::VisualStyle => "VISUALSTYLE",
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BindStructuralProjection {
    pub complete: bool,
    pub objects: Vec<BindProjectedObject>,
    pub symbols: Vec<BindProjectedSymbol>,
    pub clips: Vec<BindProjectedClip>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BindProjectedObject {
    /// Empty for a host-owned object; otherwise the source attachment scope.
    pub attachment_chain: Vec<String>,
    /// Stable pre-bind identity. Post-bind evidence keeps this value unchanged.
    pub logical_handle: String,
    /// Actual handle in the drawing represented by this projection.
    pub handle: String,
    pub class_name: String,
    pub fields: BTreeMap<String, Value>,
    pub is_proxy: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BindProjectedSymbol {
    /// Empty for a pre-existing host definition.
    pub attachment_chain: Vec<String>,
    pub logical_handle: String,
    pub handle: String,
    pub symbol_type: XrefSymbolType,
    pub source_name: String,
    pub name: String,
    pub fields: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BindProjectedClip {
    pub attachment_chain: Vec<String>,
    pub instance_logical_handle: String,
    pub fields: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BindHostSymbol {
    pub symbol_type: XrefSymbolType,
    pub handle: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BindSymbolCandidate {
    pub attachment_chain: Vec<String>,
    /// Attachment names from the direct root through this occurrence.
    pub attachment_namespace: Vec<String>,
    pub symbol_type: XrefSymbolType,
    pub source_handle: String,
    pub source_name: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BindInstanceAdmission {
    pub attachment_chain: Vec<String>,
    pub old_handle: String,
    pub owner_handle: String,
    pub owner_writable_preserving: bool,
    pub layer_locked: bool,
    pub locked_properties_preserved: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clip_fields: Option<BTreeMap<String, Value>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BindSymbolAllocation {
    pub candidate: BindSymbolCandidate,
    pub final_name: String,
    pub resolution: XrefSymbolResolution,
    /// Known before mutation only for a host merge substitution.
    pub existing_final_handle: Option<String>,
    /// Set for `earlier_import_used` and identifies the winning candidate.
    pub winning_source: Option<(Vec<String>, String)>,
    /// A deterministic collision-free staging name used by prefix execution.
    pub temporary_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct BindPreflightInput {
    pub request: BindXrefRequest,
    pub dependency_graph: XrefDependencyTraversalEnvelope,
    pub host_digest_sha256: Option<String>,
    pub source_inputs: Vec<XrefSourceInput>,
    pub host_symbols: Vec<BindHostSymbol>,
    pub dependent_symbols: Vec<BindSymbolCandidate>,
    pub instances: Vec<BindInstanceAdmission>,
    pub pre_projection: BindStructuralProjection,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct BindPlan {
    pub request: BindXrefRequest,
    pub root_chain: Vec<String>,
    pub attachment: XrefAttachmentRecord,
    pub selected_dependencies: Vec<XrefDependencyRecord>,
    pub excluded_overlay_dependencies: Vec<XrefDependencyRecord>,
    pub instances: Vec<BindInstanceAdmission>,
    pub symbol_allocations: Vec<BindSymbolAllocation>,
    pub pre_projection: BindStructuralProjection,
    pub verifier: BindVerifierContract,
    pub clip_admission: BindClipAdmission,
}

impl BindPlan {
    fn selected_records(&self) -> impl Iterator<Item = (&[String], &XrefAttachmentRecord)> {
        std::iter::once((self.root_chain.as_slice(), &self.attachment)).chain(
            self.selected_dependencies
                .iter()
                .map(|record| (record.attachment_chain.as_slice(), &record.attachment)),
        )
    }
}

pub(crate) fn allocate_bind_symbols(
    strategy: XrefSymbolStrategy,
    host_symbols: &[BindHostSymbol],
    candidates: &[BindSymbolCandidate],
) -> Result<Vec<BindSymbolAllocation>, BindError> {
    let mut host_by_type_and_name = BTreeMap::new();
    let mut used_names: BTreeMap<u8, BTreeMap<String, String>> = BTreeMap::new();
    for host in host_symbols {
        let handle = canonical_non_null_handle(&host.handle, "host symbol handle")?;
        validate_symbol_name(&host.name)?;
        let key = folded_name(&host.name);
        let typed_key = (host.symbol_type.sort_rank(), key.clone());
        if host_by_type_and_name
            .insert(typed_key, (handle, host.name.clone()))
            .is_some()
        {
            return Err(BindError::unsupported(format!(
                "pre-bind host has case-insensitive duplicate {} name '{}'",
                symbol_type_name(host.symbol_type),
                host.name
            )));
        }
        used_names
            .entry(host.symbol_type.sort_rank())
            .or_default()
            .insert(key, host.name.clone());
    }

    let mut ordered = candidates.to_vec();
    for candidate in &mut ordered {
        canonicalize_candidate(candidate)?;
    }
    ordered.sort_by(compare_candidates);

    let mut candidate_keys = BTreeSet::new();
    for candidate in &ordered {
        let key = (
            chain_key(&candidate.attachment_chain),
            candidate.symbol_type.sort_rank(),
            folded_name(&candidate.source_name),
        );
        if !candidate_keys.insert(key) {
            return Err(BindError::unsupported(format!(
                "duplicate dependent {} symbol '{}' in attachment chain {}",
                symbol_type_name(candidate.symbol_type),
                candidate.source_name,
                display_chain(&candidate.attachment_chain)
            )));
        }
    }

    let mut imported_by_type_and_name: BTreeMap<(u8, String), (Vec<String>, String, String)> =
        BTreeMap::new();
    let mut allocations = Vec::with_capacity(ordered.len());

    for candidate in ordered {
        let tokens = namespace_tokens(&candidate)?;
        let rank = candidate.symbol_type.sort_rank();
        let (final_name, resolution, existing_final_handle, winning_source) = match strategy {
            XrefSymbolStrategy::Prefix => {
                let names = used_names.entry(rank).or_default();
                let mut integer = 0_u64;
                let final_name = loop {
                    let separator = format!("${integer}$");
                    let proposed = tokens.join(&separator);
                    validate_symbol_name(&proposed)?;
                    if !names.contains_key(&folded_name(&proposed)) {
                        break proposed;
                    }
                    integer = integer.checked_add(1).ok_or_else(|| {
                        BindError::unsupported(format!(
                            "prefix allocation exhausted for '{}'",
                            candidate.source_name
                        ))
                    })?;
                };
                names.insert(folded_name(&final_name), final_name.clone());
                (final_name, XrefSymbolResolution::Prefixed, None, None)
            }
            XrefSymbolStrategy::Merge => {
                let final_name = tokens
                    .last()
                    .expect("validated namespace has a local token")
                    .clone();
                validate_symbol_name(&final_name)?;
                let key = (rank, folded_name(&final_name));
                if let Some((handle, host_name)) = host_by_type_and_name.get(&key) {
                    (
                        host_name.clone(),
                        XrefSymbolResolution::HostDefinitionUsed,
                        Some(handle.clone()),
                        None,
                    )
                } else if let Some((chain, handle, imported_name)) =
                    imported_by_type_and_name.get(&key)
                {
                    (
                        imported_name.clone(),
                        XrefSymbolResolution::EarlierImportUsed,
                        None,
                        Some((chain.clone(), handle.clone())),
                    )
                } else {
                    imported_by_type_and_name.insert(
                        key,
                        (
                            candidate.attachment_chain.clone(),
                            candidate.source_handle.clone(),
                            final_name.clone(),
                        ),
                    );
                    used_names
                        .entry(rank)
                        .or_default()
                        .insert(folded_name(&final_name), final_name.clone());
                    (final_name, XrefSymbolResolution::Imported, None, None)
                }
            }
        };

        allocations.push(BindSymbolAllocation {
            candidate,
            final_name,
            resolution,
            existing_final_handle,
            winning_source,
            temporary_name: None,
        });
    }

    if strategy == XrefSymbolStrategy::Prefix {
        allocate_temporary_names(&mut allocations, &mut used_names)?;
    }
    Ok(allocations)
}

fn allocate_temporary_names(
    allocations: &mut [BindSymbolAllocation],
    used_names: &mut BTreeMap<u8, BTreeMap<String, String>>,
) -> Result<(), BindError> {
    for (index, allocation) in allocations.iter_mut().enumerate() {
        let rank = allocation.candidate.symbol_type.sort_rank();
        let names = used_names.entry(rank).or_default();
        let base = format!(
            "$ACM$BIND$TMP${}${}",
            index, allocation.candidate.source_handle
        );
        let mut suffix = 0_u64;
        let temporary_name = loop {
            let proposed = if suffix == 0 {
                base.clone()
            } else {
                format!("{base}${suffix}")
            };
            validate_symbol_name(&proposed)?;
            if !names.contains_key(&folded_name(&proposed)) {
                break proposed;
            }
            suffix = suffix.checked_add(1).ok_or_else(|| {
                BindError::unsupported("temporary prefix-name allocation exhausted")
            })?;
        };
        names.insert(folded_name(&temporary_name), temporary_name.clone());
        allocation.temporary_name = Some(temporary_name);
    }
    Ok(())
}

fn canonicalize_candidate(candidate: &mut BindSymbolCandidate) -> Result<(), BindError> {
    candidate.attachment_chain = canonicalize_handle_chain(&candidate.attachment_chain)?;
    if candidate
        .attachment_chain
        .iter()
        .any(|handle| handle == "0")
    {
        return Err(BindError::unsupported(
            "dependent symbol attachment chain contains a null handle",
        ));
    }
    candidate.source_handle =
        canonical_non_null_handle(&candidate.source_handle, "dependent symbol handle")?;
    let _ = namespace_tokens(candidate)?;
    Ok(())
}

fn namespace_tokens(candidate: &BindSymbolCandidate) -> Result<Vec<String>, BindError> {
    let tokens: Vec<_> = candidate
        .source_name
        .split('|')
        .map(str::to_owned)
        .collect();
    if tokens.len() < 2 || tokens.iter().any(String::is_empty) {
        return Err(BindError::unsupported(format!(
            "dependent symbol '{}' has an empty or missing XREF namespace",
            candidate.source_name
        )));
    }
    if tokens.len() != candidate.attachment_namespace.len() + 1
        || !tokens[..tokens.len() - 1]
            .iter()
            .zip(&candidate.attachment_namespace)
            .all(|(token, namespace)| !namespace.is_empty() && xref_name_eq(token, namespace))
    {
        return Err(BindError::unsupported(format!(
            "dependent symbol '{}' does not match attachment namespace {}",
            candidate.source_name,
            candidate.attachment_namespace.join("|")
        )));
    }
    Ok(tokens)
}

pub(crate) fn validate_symbol_name(name: &str) -> Result<(), BindError> {
    const FORBIDDEN: &[char] = &[
        '<', '>', '/', '\\', '"', ':', ';', '?', '*', '|', ',', '=', '`',
    ];
    if name.is_empty()
        || name.trim() != name
        || name.chars().count() > 255
        || name
            .chars()
            .any(|character| character.is_ascii_control() || FORBIDDEN.contains(&character))
    {
        return Err(BindError::unsupported(format!(
            "generated AutoCAD symbol name '{}' is invalid",
            name
        )));
    }
    Ok(())
}

fn compare_candidates(left: &BindSymbolCandidate, right: &BindSymbolCandidate) -> Ordering {
    compare_handle_chains(&left.attachment_chain, &right.attachment_chain)
        .expect("canonical candidate chains must compare")
        .then_with(|| {
            left.symbol_type
                .sort_rank()
                .cmp(&right.symbol_type.sort_rank())
        })
        .then_with(|| compare_xref_names(&left.source_name, &right.source_name))
}

fn folded_name(name: &str) -> String {
    name.to_uppercase()
}

fn chain_key(chain: &[String]) -> String {
    chain.join("/")
}

fn display_chain(chain: &[String]) -> String {
    if chain.is_empty() {
        "<host>".to_string()
    } else {
        chain_key(chain)
    }
}

fn canonical_non_null_handle(handle: &str, field: &str) -> Result<String, BindError> {
    let canonical = canonical_input_handle(handle)?;
    if canonical == "0" {
        return Err(BindError::unsupported(format!(
            "{field} must be a non-null handle"
        )));
    }
    Ok(canonical)
}

pub(crate) fn preflight_bind(
    input: &BindPreflightInput,
    verifier: BindVerifierContract,
    clip_admission: BindClipAdmission,
) -> Result<BindPlan, BindError> {
    verifier.validate_required_exceptions()?;
    require_complete_dependency_graph_for_mutation(&input.dependency_graph)?;

    if input.request.drawing_path != input.dependency_graph.drawing {
        return Err(BindError::new(
            xref_failure_code::CONTRADICTORY_IDENTITY,
            "bind request drawing does not match the dependency graph drawing",
        ));
    }

    let mut dependencies = input.dependency_graph.dependencies.clone();
    sort_xref_dependency_records(&mut dependencies)?;
    reject_duplicate_chains(&dependencies)?;
    let root_indices: Vec<_> = dependencies
        .iter()
        .enumerate()
        .filter(|(_, record)| record.depth == 0)
        .map(|(index, _)| index)
        .collect();
    if root_indices.len() != 1 {
        return Err(BindError::new(
            xref_failure_code::DEPENDENCY_TRAVERSAL_INCOMPLETE,
            format!(
                "bind requires exactly one root dependency record, found {}",
                root_indices.len()
            ),
        ));
    }

    validate_overlay_partition(&dependencies)?;
    let root = dependencies[root_indices[0]].clone();
    validate_request_identity_and_guards(&input.request, &root.attachment, &input.instances)?;

    let propagated: Vec<_> = dependencies
        .iter()
        .filter(|record| record.propagation_state == XrefPropagationState::Propagated)
        .cloned()
        .collect();
    if input.request.dependency_strategy == XrefDependencyStrategy::RejectNested
        && !propagated.is_empty()
    {
        return Err(BindError::new(
            xref_failure_code::NESTED_XREFS_PRESENT,
            format!(
                "propagated nested attachment {} violates reject_nested",
                display_chain(&propagated[0].attachment_chain)
            ),
        ));
    }

    let mut selected_dependencies =
        if input.request.dependency_strategy == XrefDependencyStrategy::BindNested {
            propagated
        } else {
            Vec::new()
        };
    sort_xref_dependency_records(&mut selected_dependencies)?;
    let mut excluded_overlay_dependencies: Vec<_> = dependencies
        .into_iter()
        .filter(|record| record.propagation_state == XrefPropagationState::ExcludedOverlay)
        .collect();
    sort_xref_dependency_records(&mut excluded_overlay_dependencies)?;

    let selected_chains: BTreeSet<_> = std::iter::once(chain_key(&root.attachment_chain))
        .chain(
            selected_dependencies
                .iter()
                .map(|record| chain_key(&record.attachment_chain)),
        )
        .collect();
    let mut instances = canonicalize_instances(
        &input.instances,
        &root,
        &selected_dependencies,
        &selected_chains,
        &clip_admission,
    )?;
    instances.sort_by(compare_instances);

    let symbol_allocations = allocate_bind_symbols(
        input.request.symbol_strategy,
        &input.host_symbols,
        &input.dependent_symbols,
    )?;
    validate_symbol_scopes(&symbol_allocations, &selected_chains)?;
    validate_projection(
        &input.pre_projection,
        &verifier,
        &clip_admission,
        &selected_chains,
        &symbol_allocations,
        &instances,
    )?;

    Ok(BindPlan {
        request: input.request.clone(),
        root_chain: root.attachment_chain,
        attachment: root.attachment,
        selected_dependencies,
        excluded_overlay_dependencies,
        instances,
        symbol_allocations,
        pre_projection: canonical_projection(&input.pre_projection, &verifier, &clip_admission)?,
        verifier,
        clip_admission,
    })
}

fn reject_duplicate_chains(records: &[XrefDependencyRecord]) -> Result<(), BindError> {
    let mut chains = BTreeSet::new();
    for record in records {
        if !chains.insert(chain_key(&record.attachment_chain)) {
            return Err(BindError::new(
                xref_failure_code::DEPENDENCY_TRAVERSAL_INCOMPLETE,
                format!(
                    "dependency traversal repeated attachment chain {}",
                    display_chain(&record.attachment_chain)
                ),
            ));
        }
    }
    Ok(())
}

fn validate_overlay_partition(records: &[XrefDependencyRecord]) -> Result<(), BindError> {
    let excluded: Vec<_> = records
        .iter()
        .filter(|record| record.propagation_state == XrefPropagationState::ExcludedOverlay)
        .map(|record| record.attachment_chain.as_slice())
        .collect();

    for record in records {
        if record.depth == 0 {
            if record.propagation_state != XrefPropagationState::Root {
                return Err(BindError::new(
                    xref_failure_code::DEPENDENCY_TRAVERSAL_INCOMPLETE,
                    "depth-zero bind dependency is not marked as root",
                ));
            }
            // A direct overlay root is selected and inspected normally.
            continue;
        }

        let overlay = record.attachment.reference_type == ReferenceType::Overlay;
        let excluded_overlay = record.propagation_state == XrefPropagationState::ExcludedOverlay;
        if overlay != excluded_overlay
            || (excluded_overlay && record.inspection_state != XrefInspectionState::TerminalOverlay)
        {
            return Err(BindError::new(
                xref_failure_code::DEPENDENCY_TRAVERSAL_INCOMPLETE,
                format!(
                    "non-root overlay partition is inconsistent at {}",
                    display_chain(&record.attachment_chain)
                ),
            ));
        }
        if !overlay && record.propagation_state != XrefPropagationState::Propagated {
            return Err(BindError::new(
                xref_failure_code::DEPENDENCY_TRAVERSAL_INCOMPLETE,
                format!(
                    "attached nested dependency is not propagated at {}",
                    display_chain(&record.attachment_chain)
                ),
            ));
        }

        if excluded.iter().any(|ancestor| {
            ancestor.len() < record.attachment_chain.len()
                && record.attachment_chain.starts_with(ancestor)
        }) {
            return Err(BindError::new(
                xref_failure_code::DEPENDENCY_TRAVERSAL_INCOMPLETE,
                format!(
                    "dependency traversal inspected below excluded overlay {}",
                    display_chain(&record.attachment_chain)
                ),
            ));
        }
    }
    Ok(())
}

fn validate_request_identity_and_guards(
    request: &BindXrefRequest,
    attachment: &XrefAttachmentRecord,
    instances: &[BindInstanceAdmission],
) -> Result<(), BindError> {
    if request.handle.is_none() && request.name.is_none() {
        return Err(BindError::new(
            xref_failure_code::MISSING_IDENTITY,
            "bind_xref requires an attachment handle or name",
        ));
    }

    if let Some(handle) = &request.handle {
        if canonical_input_handle(handle)? != attachment.handle {
            return Err(BindError::new(
                if request.name.is_some() {
                    xref_failure_code::CONTRADICTORY_IDENTITY
                } else {
                    xref_failure_code::XREF_NOT_FOUND
                },
                "bind attachment selector does not identify the graph root",
            ));
        }
    }
    if let Some(name) = &request.name {
        if !xref_name_eq(name, &attachment.name) {
            return Err(BindError::new(
                if request.handle.is_some() {
                    xref_failure_code::CONTRADICTORY_IDENTITY
                } else {
                    xref_failure_code::XREF_NOT_FOUND
                },
                "bind attachment selector does not identify the graph root",
            ));
        }
    }
    if request
        .expected_handle
        .as_ref()
        .map(|handle| canonical_input_handle(handle))
        .transpose()?
        .is_some_and(|handle| handle != attachment.handle)
    {
        return Err(BindError::new(
            xref_failure_code::EXPECTED_HANDLE_MISMATCH,
            format!("actual attachment handle is {}", attachment.handle),
        ));
    }
    if request
        .expected_name
        .as_ref()
        .is_some_and(|name| !xref_name_eq(name, &attachment.name))
    {
        return Err(BindError::new(
            xref_failure_code::EXPECTED_NAME_MISMATCH,
            format!("actual attachment name is {}", attachment.name),
        ));
    }

    let root_chain = vec![attachment.handle.clone()];
    let mut root_handles = Vec::new();
    for instance in instances {
        if canonicalize_handle_chain(&instance.attachment_chain)? == root_chain {
            root_handles.push(canonical_non_null_handle(
                &instance.old_handle,
                "instance handle",
            )?);
        }
    }
    root_handles.sort_by(|left, right| {
        compare_numeric_handles(left, right).expect("canonical handles must compare")
    });
    if request
        .expected_instance_count
        .is_some_and(|expected| expected != root_handles.len() as u64)
    {
        return Err(BindError::new(
            xref_failure_code::EXPECTED_INSTANCE_COUNT_MISMATCH,
            format!("actual instance count is {}", root_handles.len()),
        ));
    }
    if let Some(expected) = &request.expected_instance_handles {
        if canonicalize_unique_handle_set(expected)? != root_handles {
            return Err(BindError::new(
                xref_failure_code::EXPECTED_INSTANCE_HANDLES_MISMATCH,
                format!("actual instance handles are [{}]", root_handles.join(",")),
            ));
        }
    }
    Ok(())
}

fn canonicalize_instances(
    instances: &[BindInstanceAdmission],
    root: &XrefDependencyRecord,
    selected_dependencies: &[XrefDependencyRecord],
    selected_chains: &BTreeSet<String>,
    clip_admission: &BindClipAdmission,
) -> Result<Vec<BindInstanceAdmission>, BindError> {
    let expected_counts: BTreeMap<_, _> = std::iter::once(root)
        .chain(selected_dependencies)
        .map(|record| {
            (
                chain_key(&record.attachment_chain),
                record.attachment.instance_count,
            )
        })
        .collect();
    let mut actual_counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut identities = BTreeSet::new();
    let mut canonical = Vec::with_capacity(instances.len());

    for instance in instances {
        let mut instance = instance.clone();
        instance.attachment_chain = canonicalize_handle_chain(&instance.attachment_chain)?;
        instance.old_handle =
            canonical_non_null_handle(&instance.old_handle, "converted instance handle")?;
        instance.owner_handle =
            canonical_non_null_handle(&instance.owner_handle, "instance owner handle")?;
        let chain = chain_key(&instance.attachment_chain);
        if !selected_chains.contains(&chain) {
            return Err(BindError::unsupported(format!(
                "instance {} belongs to unselected attachment chain {}",
                instance.old_handle,
                display_chain(&instance.attachment_chain)
            )));
        }
        if !identities.insert((chain.clone(), instance.old_handle.clone())) {
            return Err(BindError::unsupported(format!(
                "duplicate scoped instance handle {chain}/{}",
                instance.old_handle
            )));
        }
        *actual_counts.entry(chain).or_default() += 1;

        if !instance.owner_writable_preserving {
            return Err(BindError::new(
                xref_failure_code::UNSUPPORTED_XREF_OWNER,
                format!(
                    "instance {} owner {} is not provably writable with ownership preserved",
                    instance.old_handle, instance.owner_handle
                ),
            ));
        }
        if instance.layer_locked && !instance.locked_properties_preserved {
            return Err(BindError::new(
                xref_failure_code::XREF_INSTANCE_LOCKED,
                format!(
                    "instance {} is on a locked layer without handle/property preservation proof",
                    instance.old_handle
                ),
            ));
        }
        validate_instance_clip(&instance, clip_admission)?;
        canonical.push(instance);
    }

    for (chain, expected) in expected_counts {
        let actual = actual_counts.get(&chain).copied().unwrap_or_default();
        if actual != expected {
            return Err(BindError::new(
                xref_failure_code::DEPENDENCY_TRAVERSAL_INCOMPLETE,
                format!(
                    "attachment chain {chain} declares {expected} instances but projection contains {actual}"
                ),
            ));
        }
    }
    Ok(canonical)
}

fn validate_instance_clip(
    instance: &BindInstanceAdmission,
    admission: &BindClipAdmission,
) -> Result<(), BindError> {
    let Some(fields) = &instance.clip_fields else {
        return Ok(());
    };
    match admission {
        BindClipAdmission::Reject => Err(BindError::new(
            xref_failure_code::UNSUPPORTED_XREF_CLIP_DATA,
            format!(
                "instance {} has a clip and the active capability row rejects clips",
                instance.old_handle
            ),
        )),
        BindClipAdmission::Verify(profile) => {
            require_exact_field_keys(fields, &profile.fields, "clip", &instance.old_handle)
        }
    }
}

fn compare_instances(left: &BindInstanceAdmission, right: &BindInstanceAdmission) -> Ordering {
    compare_handle_chains(&left.attachment_chain, &right.attachment_chain)
        .expect("canonical instance chains must compare")
        .then_with(|| {
            compare_numeric_handles(&left.old_handle, &right.old_handle)
                .expect("canonical instance handles must compare")
        })
}

fn validate_symbol_scopes(
    allocations: &[BindSymbolAllocation],
    selected_chains: &BTreeSet<String>,
) -> Result<(), BindError> {
    for allocation in allocations {
        let chain = chain_key(&allocation.candidate.attachment_chain);
        if !selected_chains.contains(&chain) {
            return Err(BindError::unsupported(format!(
                "dependent symbol '{}' belongs to unselected attachment chain {chain}",
                allocation.candidate.source_name
            )));
        }
    }
    Ok(())
}

fn validate_projection(
    projection: &BindStructuralProjection,
    verifier: &BindVerifierContract,
    clip_admission: &BindClipAdmission,
    selected_chains: &BTreeSet<String>,
    allocations: &[BindSymbolAllocation],
    instances: &[BindInstanceAdmission],
) -> Result<(), BindError> {
    let canonical = canonical_projection(projection, verifier, clip_admission)?;
    for object in &canonical.objects {
        if !object.attachment_chain.is_empty()
            && !selected_chains.contains(&chain_key(&object.attachment_chain))
        {
            return Err(BindError::unsupported(format!(
                "projected object {} belongs to an excluded or unknown attachment chain {}",
                object.logical_handle,
                display_chain(&object.attachment_chain)
            )));
        }
    }

    let projected_symbols: BTreeSet<_> = canonical
        .symbols
        .iter()
        .filter(|symbol| !symbol.attachment_chain.is_empty())
        .map(projected_symbol_key)
        .collect();
    let allocated_symbols: BTreeSet<_> = allocations
        .iter()
        .map(|allocation| candidate_key(&allocation.candidate))
        .collect();
    if projected_symbols != allocated_symbols {
        return Err(BindError::unsupported(
            "selected dependent symbol inventory does not exactly match the structural projection",
        ));
    }
    for allocation in allocations
        .iter()
        .filter(|allocation| allocation.resolution == XrefSymbolResolution::HostDefinitionUsed)
    {
        let host_handle = allocation
            .existing_final_handle
            .as_ref()
            .expect("host merge allocation has a host handle");
        let matches = canonical.symbols.iter().filter(|symbol| {
            symbol.attachment_chain.is_empty()
                && symbol.symbol_type == allocation.candidate.symbol_type
                && symbol.handle == *host_handle
                && symbol.logical_handle == *host_handle
                && symbol.name == allocation.final_name
        });
        if matches.count() != 1 {
            return Err(BindError::unsupported(format!(
                "host merge winner '{}' is not represented exactly once in the pre-bind projection",
                allocation.final_name
            )));
        }
    }

    let projected_clips: BTreeSet<_> = canonical
        .clips
        .iter()
        .map(|clip| {
            (
                chain_key(&clip.attachment_chain),
                clip.instance_logical_handle.clone(),
            )
        })
        .collect();
    let admitted_clips: BTreeSet<_> = instances
        .iter()
        .filter(|instance| instance.clip_fields.is_some())
        .map(|instance| {
            (
                chain_key(&instance.attachment_chain),
                instance.old_handle.clone(),
            )
        })
        .collect();
    if projected_clips != admitted_clips {
        return Err(BindError::unsupported(
            "clip admission inventory does not exactly match the structural projection",
        ));
    }
    Ok(())
}

fn canonical_projection(
    projection: &BindStructuralProjection,
    verifier: &BindVerifierContract,
    clip_admission: &BindClipAdmission,
) -> Result<BindStructuralProjection, BindError> {
    if !projection.complete {
        return Err(BindError::unsupported(
            "bind structural traversal cannot prove complete content coverage",
        ));
    }
    let mut projection = projection.clone();
    let mut object_keys = BTreeSet::new();
    for object in &mut projection.objects {
        canonicalize_optional_scope(&mut object.attachment_chain)?;
        object.logical_handle =
            canonical_non_null_handle(&object.logical_handle, "object logical handle")?;
        object.handle = canonical_non_null_handle(&object.handle, "object handle")?;
        if object.is_proxy {
            return Err(BindError::unsupported(format!(
                "proxy object {} occurs in selected bind content",
                object.logical_handle
            )));
        }
        let admitted = verifier.object_fields(&object.class_name).ok_or_else(|| {
            BindError::unsupported(format!(
                "object class '{}' is absent from bind verifier '{}'",
                object.class_name, verifier.profile_id
            ))
        })?;
        require_exact_field_keys(&object.fields, admitted, "object", &object.logical_handle)?;
        if !object_keys.insert(projected_object_key(object)) {
            return Err(BindError::unsupported(format!(
                "duplicate projected object identity {}/{}",
                display_chain(&object.attachment_chain),
                object.logical_handle
            )));
        }
    }

    let mut symbol_keys = BTreeSet::new();
    for symbol in &mut projection.symbols {
        canonicalize_optional_scope(&mut symbol.attachment_chain)?;
        symbol.logical_handle =
            canonical_non_null_handle(&symbol.logical_handle, "symbol logical handle")?;
        symbol.handle = canonical_non_null_handle(&symbol.handle, "symbol handle")?;
        if symbol.attachment_chain.is_empty() {
            validate_symbol_name(&symbol.name)?;
        } else {
            if !symbol.source_name.contains('|') {
                return Err(BindError::unsupported(format!(
                    "dependent projected symbol '{}' has no namespace",
                    symbol.source_name
                )));
            }
            if symbol.name != symbol.source_name {
                validate_symbol_name(&symbol.name)?;
            }
        }
        let admitted = verifier.symbol_fields(symbol.symbol_type).ok_or_else(|| {
            BindError::unsupported(format!(
                "symbol type '{}' is absent from bind verifier '{}'",
                symbol_type_name(symbol.symbol_type),
                verifier.profile_id
            ))
        })?;
        require_exact_field_keys(&symbol.fields, admitted, "symbol", &symbol.logical_handle)?;
        if !symbol_keys.insert(projected_symbol_key(symbol)) {
            return Err(BindError::unsupported(format!(
                "duplicate projected symbol identity {}/{}",
                display_chain(&symbol.attachment_chain),
                symbol.logical_handle
            )));
        }
    }

    let mut clip_keys = BTreeSet::new();
    for clip in &mut projection.clips {
        canonicalize_optional_scope(&mut clip.attachment_chain)?;
        if clip.attachment_chain.is_empty() {
            return Err(BindError::unsupported(
                "bind clip projection requires an attachment chain",
            ));
        }
        clip.instance_logical_handle = canonical_non_null_handle(
            &clip.instance_logical_handle,
            "clipped instance logical handle",
        )?;
        let profile = match clip_admission {
            BindClipAdmission::Reject => {
                return Err(BindError::new(
                    xref_failure_code::UNSUPPORTED_XREF_CLIP_DATA,
                    "clip projection is present under a rejecting capability row",
                ));
            }
            BindClipAdmission::Verify(profile) => profile,
        };
        require_exact_field_keys(
            &clip.fields,
            &profile.fields,
            "clip",
            &clip.instance_logical_handle,
        )?;
        if !clip_keys.insert((
            chain_key(&clip.attachment_chain),
            clip.instance_logical_handle.clone(),
        )) {
            return Err(BindError::unsupported(format!(
                "duplicate clip projection for {}/{}",
                display_chain(&clip.attachment_chain),
                clip.instance_logical_handle
            )));
        }
    }

    projection.objects.sort_by(compare_projected_objects);
    projection.symbols.sort_by(compare_projected_symbols);
    projection.clips.sort_by(compare_projected_clips);
    Ok(projection)
}

fn canonicalize_optional_scope(chain: &mut Vec<String>) -> Result<(), BindError> {
    if !chain.is_empty() {
        *chain = canonicalize_handle_chain(chain)?;
        if chain.iter().any(|handle| handle == "0") {
            return Err(BindError::unsupported(
                "projection attachment chain contains a null handle",
            ));
        }
    }
    Ok(())
}

fn require_exact_field_keys(
    fields: &BTreeMap<String, Value>,
    admitted: &BTreeSet<String>,
    kind: &str,
    identity: &str,
) -> Result<(), BindError> {
    let actual: BTreeSet<_> = fields.keys().cloned().collect();
    if &actual != admitted {
        let missing = admitted.difference(&actual).cloned().collect::<Vec<_>>();
        let extra = actual.difference(admitted).cloned().collect::<Vec<_>>();
        return Err(BindError::unsupported(format!(
            "{kind} {identity} fields do not match the active profile; missing={missing:?}, extra={extra:?}"
        )));
    }
    Ok(())
}

fn projected_object_key(object: &BindProjectedObject) -> (String, String) {
    (
        chain_key(&object.attachment_chain),
        object.logical_handle.clone(),
    )
}

fn projected_symbol_key(symbol: &BindProjectedSymbol) -> (String, u8, String) {
    (
        chain_key(&symbol.attachment_chain),
        symbol.symbol_type.sort_rank(),
        symbol.logical_handle.clone(),
    )
}

fn candidate_key(candidate: &BindSymbolCandidate) -> (String, u8, String) {
    (
        chain_key(&candidate.attachment_chain),
        candidate.symbol_type.sort_rank(),
        candidate.source_handle.clone(),
    )
}

fn compare_optional_chains(left: &[String], right: &[String]) -> Ordering {
    match (left.is_empty(), right.is_empty()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        (false, false) => compare_handle_chains(left, right)
            .expect("canonical projection attachment chains must compare"),
    }
}

fn compare_projected_objects(left: &BindProjectedObject, right: &BindProjectedObject) -> Ordering {
    compare_optional_chains(&left.attachment_chain, &right.attachment_chain)
        .then_with(|| {
            compare_numeric_handles(&left.logical_handle, &right.logical_handle)
                .expect("canonical projected object handles must compare")
        })
        .then_with(|| left.class_name.cmp(&right.class_name))
}

fn compare_projected_symbols(left: &BindProjectedSymbol, right: &BindProjectedSymbol) -> Ordering {
    compare_optional_chains(&left.attachment_chain, &right.attachment_chain)
        .then_with(|| {
            left.symbol_type
                .sort_rank()
                .cmp(&right.symbol_type.sort_rank())
        })
        .then_with(|| compare_xref_names(&left.source_name, &right.source_name))
        .then_with(|| {
            compare_numeric_handles(&left.logical_handle, &right.logical_handle)
                .expect("canonical projected symbol handles must compare")
        })
}

fn compare_projected_clips(left: &BindProjectedClip, right: &BindProjectedClip) -> Ordering {
    compare_handle_chains(&left.attachment_chain, &right.attachment_chain)
        .expect("canonical projected clip chains must compare")
        .then_with(|| {
            compare_numeric_handles(
                &left.instance_logical_handle,
                &right.instance_logical_handle,
            )
            .expect("canonical projected clip handles must compare")
        })
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum BindSentinelRecord {
    RootBlock {
        block: XrefBoundBlock,
    },
    InstanceMapping {
        mapping: XrefInstanceHandleMapping,
    },
    SymbolMapping {
        mapping: XrefSymbolMapping,
    },
    BoundDependency {
        dependency: XrefBoundDependency,
    },
    ExcludedOverlay {
        dependency: XrefDependencyRecord,
    },
    PostProjection {
        projection: BindStructuralProjection,
    },
    ProjectedObject {
        object: BindProjectedObject,
    },
    ProjectedSymbol {
        symbol: BindProjectedSymbol,
    },
    ProjectedClip {
        clip: BindProjectedClip,
    },
    Failure {
        code: String,
        detail: String,
    },
    Complete,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct BindExecutionEvidence {
    pub response: BindXrefResponse,
    pub post_projection: BindStructuralProjection,
}

pub(crate) trait BindPersistedEvidenceReader {
    fn read_persisted_bind_evidence(
        &mut self,
        temporary_host: &Path,
        plan: &BindPlan,
        execution: &BindExecutionEvidence,
    ) -> Result<BindExecutionEvidence, BindError>;
}

pub(crate) fn parse_bind_sentinels(
    output: &str,
    plan: &BindPlan,
) -> Result<BindExecutionEvidence, BindError> {
    let mut root_block = None;
    let mut instance_mappings = Vec::new();
    let mut symbol_mappings = Vec::new();
    let mut bound_dependencies = Vec::new();
    let mut excluded_overlays = Vec::new();
    let mut post_projection = None;
    let mut projected_objects = Vec::new();
    let mut projected_symbols = Vec::new();
    let mut projected_clips = Vec::new();
    let mut saw_record = false;
    let mut complete = false;

    for (line_number, line) in output.lines().enumerate() {
        let Some(payload) = line.strip_prefix(SENTINEL_PREFIX) else {
            continue;
        };
        saw_record = true;
        if complete {
            return Err(BindError::verification(format!(
                "bind sentinel occurs after complete at line {}",
                line_number + 1
            )));
        }
        let record: BindSentinelRecord = serde_json::from_str(payload).map_err(|error| {
            BindError::verification(format!(
                "invalid bind sentinel at line {}: {error}",
                line_number + 1
            ))
        })?;
        match record {
            BindSentinelRecord::RootBlock { block } => {
                replace_once(&mut root_block, block, "root_block")?;
            }
            BindSentinelRecord::InstanceMapping { mapping } => instance_mappings.push(mapping),
            BindSentinelRecord::SymbolMapping { mapping } => symbol_mappings.push(mapping),
            BindSentinelRecord::BoundDependency { dependency } => {
                bound_dependencies.push(dependency)
            }
            BindSentinelRecord::ExcludedOverlay { dependency } => {
                excluded_overlays.push(dependency)
            }
            BindSentinelRecord::PostProjection { projection } => {
                replace_once(&mut post_projection, projection, "post_projection")?;
            }
            BindSentinelRecord::ProjectedObject { object } => projected_objects.push(object),
            BindSentinelRecord::ProjectedSymbol { symbol } => projected_symbols.push(symbol),
            BindSentinelRecord::ProjectedClip { clip } => projected_clips.push(clip),
            BindSentinelRecord::Failure { code, detail } => {
                return Err(BindError::verification(format!(
                    "native bind failed with code={code}: {detail}"
                )));
            }
            BindSentinelRecord::Complete => complete = true,
        }
    }

    if !saw_record || !complete {
        return Err(BindError::verification(
            "bind evidence is absent or truncated before the complete sentinel",
        ));
    }
    let block = root_block
        .ok_or_else(|| BindError::verification("bind evidence has no root block sentinel"))?;
    let has_fragments = !projected_objects.is_empty()
        || !projected_symbols.is_empty()
        || !projected_clips.is_empty();
    if post_projection.is_some() && has_fragments {
        return Err(BindError::verification(
            "bind evidence mixes aggregate and fragmented post projections",
        ));
    }
    let post_projection = post_projection
        .or_else(|| {
            has_fragments.then_some(BindStructuralProjection {
                complete: true,
                objects: projected_objects,
                symbols: projected_symbols,
                clips: projected_clips,
            })
        })
        .ok_or_else(|| BindError::verification("bind evidence has no post projection sentinel"))?;

    canonicalize_bound_block(&block, "root block")?;
    if !xref_name_eq(&block.name, &plan.attachment.name) {
        return Err(BindError::verification(format!(
            "root block name '{}' does not preserve attachment name '{}'",
            block.name, plan.attachment.name
        )));
    }
    sort_instance_handle_mappings(&mut instance_mappings)
        .map_err(|error| BindError::verification(error.to_string()))?;
    sort_symbol_mappings(&mut symbol_mappings)
        .map_err(|error| BindError::verification(error.to_string()))?;
    sort_bound_dependencies(&mut bound_dependencies)?;
    sort_xref_dependency_records(&mut excluded_overlays)
        .map_err(|error| BindError::verification(error.to_string()))?;

    validate_instance_mapping_evidence(plan, &instance_mappings)?;
    validate_symbol_mapping_evidence(plan, &symbol_mappings)?;
    validate_dependency_evidence(plan, &bound_dependencies, &excluded_overlays)?;

    Ok(BindExecutionEvidence {
        response: BindXrefResponse {
            status: BindXrefStatus::Bound,
            drawing: plan.request.drawing_path.clone(),
            symbol_strategy: plan.request.symbol_strategy,
            dependency_strategy: plan.request.dependency_strategy,
            attachment: plan.attachment.clone(),
            block,
            instance_handle_mappings: instance_mappings,
            symbol_mappings,
            bound_dependencies,
            excluded_overlay_dependencies: excluded_overlays,
        },
        post_projection,
    })
}

fn replace_once<T>(slot: &mut Option<T>, value: T, label: &str) -> Result<(), BindError> {
    if slot.replace(value).is_some() {
        return Err(BindError::verification(format!(
            "duplicate {label} bind sentinel"
        )));
    }
    Ok(())
}

fn canonicalize_bound_block(block: &XrefBoundBlock, label: &str) -> Result<(), BindError> {
    let canonical = canonical_non_null_handle(&block.handle, label)
        .map_err(|error| BindError::verification(error.message()))?;
    if canonical != block.handle {
        return Err(BindError::verification(format!(
            "{label} handle '{}' is not canonical",
            block.handle
        )));
    }
    validate_symbol_name(&block.name).map_err(|error| BindError::verification(error.message()))
}

fn sort_bound_dependencies(dependencies: &mut [XrefBoundDependency]) -> Result<(), BindError> {
    for dependency in dependencies.iter() {
        let canonical = canonicalize_handle_chain(&dependency.attachment_chain)
            .map_err(|error| BindError::verification(error.to_string()))?;
        if canonical != dependency.attachment_chain || canonical.iter().any(|value| value == "0") {
            return Err(BindError::verification(
                "bound dependency has a non-canonical attachment chain",
            ));
        }
        dependency
            .attachment
            .validate()
            .map_err(|error| BindError::verification(error.to_string()))?;
        canonicalize_bound_block(&dependency.block, "bound dependency block")?;
    }
    dependencies.sort_by(|left, right| {
        compare_handle_chains(&left.attachment_chain, &right.attachment_chain)
            .expect("validated bound dependency chains must compare")
    });
    Ok(())
}

fn validate_instance_mapping_evidence(
    plan: &BindPlan,
    mappings: &[XrefInstanceHandleMapping],
) -> Result<(), BindError> {
    let expected: Vec<_> = plan
        .instances
        .iter()
        .map(|instance| {
            (
                chain_key(&instance.attachment_chain),
                instance.old_handle.clone(),
            )
        })
        .collect();
    let actual: Vec<_> = mappings
        .iter()
        .map(|mapping| {
            (
                chain_key(&mapping.attachment_chain),
                mapping.old_handle.clone(),
            )
        })
        .collect();
    if actual != expected {
        return Err(BindError::verification(format!(
            "instance mapping identities differ from preflight; expected={expected:?}, actual={actual:?}"
        )));
    }
    let mut new_identities = BTreeSet::new();
    for mapping in mappings {
        if !new_identities.insert((
            chain_key(&mapping.attachment_chain),
            mapping.new_handle.clone(),
        )) {
            return Err(BindError::verification(format!(
                "multiple instances map to new handle {} in chain {}",
                mapping.new_handle,
                display_chain(&mapping.attachment_chain)
            )));
        }
    }
    Ok(())
}

fn validate_symbol_mapping_evidence(
    plan: &BindPlan,
    mappings: &[XrefSymbolMapping],
) -> Result<(), BindError> {
    if mappings.len() != plan.symbol_allocations.len() {
        return Err(BindError::verification(format!(
            "expected {} symbol mappings, found {}",
            plan.symbol_allocations.len(),
            mappings.len()
        )));
    }
    let mut by_source = BTreeMap::new();
    for mapping in mappings {
        let key = (
            chain_key(&mapping.attachment_chain),
            mapping.symbol_type.sort_rank(),
            mapping.source_handle.clone(),
        );
        if by_source.insert(key, mapping).is_some() {
            return Err(BindError::verification(
                "bind evidence contains duplicate scoped symbol mappings",
            ));
        }
    }

    for allocation in &plan.symbol_allocations {
        let key = candidate_key(&allocation.candidate);
        let mapping = by_source.get(&key).ok_or_else(|| {
            BindError::verification(format!(
                "missing symbol mapping for {}/{}",
                display_chain(&allocation.candidate.attachment_chain),
                allocation.candidate.source_handle
            ))
        })?;
        if mapping.source_name != allocation.candidate.source_name
            || mapping.final_name != allocation.final_name
            || mapping.resolution != allocation.resolution
        {
            return Err(BindError::verification(format!(
                "symbol mapping for '{}' differs from deterministic allocation",
                allocation.candidate.source_name
            )));
        }
        if allocation
            .existing_final_handle
            .as_ref()
            .is_some_and(|handle| handle != &mapping.final_handle)
        {
            return Err(BindError::verification(format!(
                "host merge for '{}' did not retain the pre-bind host handle",
                allocation.candidate.source_name
            )));
        }
        if let Some((winning_chain, winning_handle)) = &allocation.winning_source {
            let winning = by_source
                .get(&(
                    chain_key(winning_chain),
                    allocation.candidate.symbol_type.sort_rank(),
                    winning_handle.clone(),
                ))
                .ok_or_else(|| {
                    BindError::verification(format!(
                        "earlier import winner is absent for '{}'",
                        allocation.candidate.source_name
                    ))
                })?;
            if mapping.final_handle != winning.final_handle
                || mapping.final_name != winning.final_name
            {
                return Err(BindError::verification(format!(
                    "earlier import for '{}' did not reuse the first imported definition",
                    allocation.candidate.source_name
                )));
            }
        }
    }
    Ok(())
}

fn validate_dependency_evidence(
    plan: &BindPlan,
    bound: &[XrefBoundDependency],
    excluded: &[XrefDependencyRecord],
) -> Result<(), BindError> {
    if bound.len() != plan.selected_dependencies.len() {
        return Err(BindError::verification(format!(
            "expected {} bound dependencies, found {}",
            plan.selected_dependencies.len(),
            bound.len()
        )));
    }
    for (actual, expected) in bound.iter().zip(&plan.selected_dependencies) {
        if actual.attachment_chain != expected.attachment_chain
            || actual.attachment != expected.attachment
            || !xref_name_eq(&actual.block.name, &expected.attachment.name)
        {
            return Err(BindError::verification(format!(
                "bound dependency evidence differs at chain {}",
                display_chain(&expected.attachment_chain)
            )));
        }
    }
    if excluded != plan.excluded_overlay_dependencies {
        return Err(BindError::verification(
            "excluded overlay evidence differs from the preflight graph partition",
        ));
    }
    Ok(())
}

pub(crate) fn verify_bind_equivalence(
    plan: &BindPlan,
    evidence: &BindExecutionEvidence,
) -> Result<(), BindError> {
    validate_response_against_plan(plan, &evidence.response)?;
    let post = canonical_projection(
        &evidence.post_projection,
        &plan.verifier,
        &plan.clip_admission,
    )
    .map_err(|error| BindError::verification(error.to_string()))?;
    let pre = &plan.pre_projection;

    let identity_map = build_identity_map(plan, &evidence.response, pre, &post)?;
    verify_objects(plan, pre, &post, &identity_map, &evidence.response)?;
    verify_symbols(plan, pre, &post, &identity_map, &evidence.response)?;
    verify_clips(plan, pre, &post)?;
    Ok(())
}

fn validate_response_against_plan(
    plan: &BindPlan,
    response: &BindXrefResponse,
) -> Result<(), BindError> {
    if response.status != BindXrefStatus::Bound
        || response.drawing != plan.request.drawing_path
        || response.symbol_strategy != plan.request.symbol_strategy
        || response.dependency_strategy != plan.request.dependency_strategy
        || response.attachment != plan.attachment
    {
        return Err(BindError::verification(
            "bind response header differs from the preflight plan",
        ));
    }
    canonicalize_bound_block(&response.block, "root block")?;

    let mut instances = response.instance_handle_mappings.clone();
    sort_instance_handle_mappings(&mut instances)
        .map_err(|error| BindError::verification(error.to_string()))?;
    if instances != response.instance_handle_mappings {
        return Err(BindError::verification(
            "instance handle mappings are not in canonical response order",
        ));
    }
    let mut symbols = response.symbol_mappings.clone();
    sort_symbol_mappings(&mut symbols)
        .map_err(|error| BindError::verification(error.to_string()))?;
    if symbols != response.symbol_mappings {
        return Err(BindError::verification(
            "symbol mappings are not in canonical response order",
        ));
    }
    let mut bound = response.bound_dependencies.clone();
    sort_bound_dependencies(&mut bound)?;
    if bound != response.bound_dependencies {
        return Err(BindError::verification(
            "bound dependencies are not in canonical response order",
        ));
    }
    let mut excluded = response.excluded_overlay_dependencies.clone();
    sort_xref_dependency_records(&mut excluded)
        .map_err(|error| BindError::verification(error.to_string()))?;
    if excluded != response.excluded_overlay_dependencies {
        return Err(BindError::verification(
            "excluded overlays are not in canonical response order",
        ));
    }
    validate_instance_mapping_evidence(plan, &instances)?;
    validate_symbol_mapping_evidence(plan, &symbols)?;
    validate_dependency_evidence(plan, &bound, &excluded)
}

type ScopedIdentityMap = BTreeMap<(String, String), String>;

fn build_identity_map(
    plan: &BindPlan,
    response: &BindXrefResponse,
    pre: &BindStructuralProjection,
    post: &BindStructuralProjection,
) -> Result<ScopedIdentityMap, BindError> {
    let mut mappings = ScopedIdentityMap::new();
    let mut reverse = BTreeSet::new();

    for (before, after) in pre.objects.iter().zip(&post.objects) {
        if projected_object_key(before) == projected_object_key(after) {
            insert_identity_mapping(
                &mut mappings,
                &mut reverse,
                &before.attachment_chain,
                &before.handle,
                &after.handle,
            )?;
        }
    }
    for mapping in &response.instance_handle_mappings {
        insert_identity_mapping(
            &mut mappings,
            &mut reverse,
            &mapping.attachment_chain,
            &mapping.old_handle,
            &mapping.new_handle,
        )?;
    }
    for mapping in &response.symbol_mappings {
        insert_identity_mapping(
            &mut mappings,
            &mut reverse,
            &mapping.attachment_chain,
            &mapping.source_handle,
            &mapping.final_handle,
        )?;
    }
    insert_identity_mapping(
        &mut mappings,
        &mut reverse,
        &plan.root_chain,
        &plan.attachment.handle,
        &response.block.handle,
    )?;
    for dependency in &response.bound_dependencies {
        insert_identity_mapping(
            &mut mappings,
            &mut reverse,
            &dependency.attachment_chain,
            &dependency.attachment.handle,
            &dependency.block.handle,
        )?;
    }
    Ok(mappings)
}

fn insert_identity_mapping(
    mappings: &mut ScopedIdentityMap,
    reverse: &mut BTreeSet<(String, String)>,
    chain: &[String],
    old: &str,
    new: &str,
) -> Result<(), BindError> {
    let key = (chain_key(chain), old.to_string());
    if let Some(existing) = mappings.insert(key.clone(), new.to_string()) {
        if existing != new {
            return Err(BindError::verification(format!(
                "identity {}/{} maps to both {} and {}",
                display_chain(chain),
                old,
                existing,
                new
            )));
        }
    }
    if !reverse.insert((key.0.clone(), new.to_string())) && old != new {
        // Many-to-one symbol merge is verified separately and is the only exception.
        mappings.insert(key, new.to_string());
    }
    Ok(())
}

fn verify_objects(
    plan: &BindPlan,
    pre: &BindStructuralProjection,
    post: &BindStructuralProjection,
    identities: &ScopedIdentityMap,
    response: &BindXrefResponse,
) -> Result<(), BindError> {
    let before: BTreeMap<_, _> = pre
        .objects
        .iter()
        .map(|object| (projected_object_key(object), object))
        .collect();
    let after: BTreeMap<_, _> = post
        .objects
        .iter()
        .map(|object| (projected_object_key(object), object))
        .collect();
    if before.keys().ne(after.keys()) {
        return Err(BindError::verification(
            "post-bind object identity set differs from the pre-bind projection",
        ));
    }

    for (key, before) in before {
        let after = after[&key];
        if before.class_name != after.class_name || before.is_proxy || after.is_proxy {
            return Err(BindError::verification(format!(
                "object class/proxy state changed for {}/{}",
                display_chain(&before.attachment_chain),
                before.logical_handle
            )));
        }
        let expected_handle = map_identity(identities, &before.attachment_chain, &before.handle);
        if expected_handle != after.handle
            || (before.handle != after.handle
                && !plan.verifier.mapped_identity_fields.contains("handle"))
        {
            return Err(BindError::verification(format!(
                "object handle mapping is invalid for {}/{}",
                display_chain(&before.attachment_chain),
                before.logical_handle
            )));
        }
        for (field, before_value) in &before.fields {
            let after_value = &after.fields[field];
            let expected = expected_object_field(
                field,
                before_value,
                &before.attachment_chain,
                identities,
                response,
                &plan.verifier,
            )?;
            if !values_equivalent(
                &expected,
                after_value,
                plan.verifier.absolute_tolerance,
                plan.verifier.relative_tolerance,
            ) {
                return Err(BindError::verification(format!(
                    "object field '{}' changed outside the bind profile for {}/{}",
                    field,
                    display_chain(&before.attachment_chain),
                    before.logical_handle
                )));
            }
        }
    }
    Ok(())
}

fn expected_object_field(
    field: &str,
    before: &Value,
    chain: &[String],
    identities: &ScopedIdentityMap,
    response: &BindXrefResponse,
    verifier: &BindVerifierContract,
) -> Result<Value, BindError> {
    match field {
        "owner_handle" => map_handle_value(before, chain, identities, verifier),
        "attachment_handle" => {
            if !verifier.operation_differences.contains("xref_instances") {
                return Ok(before.clone());
            }
            map_attachment_handle_value(before, chain, response)
        }
        "layer" => map_symbol_name_value(before, chain, XrefSymbolType::Layer, response),
        _ => Ok(before.clone()),
    }
}

fn map_handle_value(
    value: &Value,
    chain: &[String],
    identities: &ScopedIdentityMap,
    verifier: &BindVerifierContract,
) -> Result<Value, BindError> {
    let Some(handle) = value.as_str() else {
        return Err(BindError::verification(
            "mapped identity field is not represented as a string handle",
        ));
    };
    let mapped = map_identity(identities, chain, handle);
    if mapped != handle && !verifier.mapped_identity_fields.contains("owner_handle") {
        return Err(BindError::verification(
            "owner handle changed without profile authorization",
        ));
    }
    Ok(Value::String(mapped))
}

fn map_attachment_handle_value(
    value: &Value,
    object_chain: &[String],
    response: &BindXrefResponse,
) -> Result<Value, BindError> {
    let Some(handle) = value.as_str() else {
        return Err(BindError::verification(
            "attachment_handle field is not represented as a string handle",
        ));
    };
    if handle == response.attachment.handle && object_chain == response.block_chain_hint() {
        return Ok(Value::String(response.block.handle.clone()));
    }
    for dependency in &response.bound_dependencies {
        if handle == dependency.attachment.handle
            && (object_chain == dependency.attachment_chain
                || dependency
                    .attachment_chain
                    .strip_suffix(&[handle.to_string()])
                    .is_some_and(|parent| parent == object_chain))
        {
            return Ok(Value::String(dependency.block.handle.clone()));
        }
    }
    Ok(value.clone())
}

trait BindResponseChainHint {
    fn block_chain_hint(&self) -> &[String];
}

impl BindResponseChainHint for BindXrefResponse {
    fn block_chain_hint(&self) -> &[String] {
        // The root chain is always exactly the selected attachment handle.
        std::slice::from_ref(&self.attachment.handle)
    }
}

fn map_symbol_name_value(
    value: &Value,
    chain: &[String],
    symbol_type: XrefSymbolType,
    response: &BindXrefResponse,
) -> Result<Value, BindError> {
    let Some(name) = value.as_str() else {
        return Ok(value.clone());
    };
    let mapping = response.symbol_mappings.iter().find(|mapping| {
        mapping.attachment_chain == chain
            && mapping.symbol_type == symbol_type
            && mapping.source_name == name
    });
    Ok(mapping
        .map(|mapping| Value::String(mapping.final_name.clone()))
        .unwrap_or_else(|| value.clone()))
}

fn map_identity(identities: &ScopedIdentityMap, chain: &[String], handle: &str) -> String {
    identities
        .get(&(chain_key(chain), handle.to_string()))
        .cloned()
        .unwrap_or_else(|| handle.to_string())
}

fn verify_symbols(
    plan: &BindPlan,
    pre: &BindStructuralProjection,
    post: &BindStructuralProjection,
    identities: &ScopedIdentityMap,
    response: &BindXrefResponse,
) -> Result<(), BindError> {
    let before: BTreeMap<_, _> = pre
        .symbols
        .iter()
        .map(|symbol| (projected_symbol_key(symbol), symbol))
        .collect();
    let after: BTreeMap<_, _> = post
        .symbols
        .iter()
        .map(|symbol| (projected_symbol_key(symbol), symbol))
        .collect();
    if before.keys().ne(after.keys()) {
        return Err(BindError::verification(
            "post-bind symbol identity set differs from the pre-bind projection",
        ));
    }

    let response_by_source: BTreeMap<_, _> = response
        .symbol_mappings
        .iter()
        .map(|mapping| {
            (
                (
                    chain_key(&mapping.attachment_chain),
                    mapping.symbol_type.sort_rank(),
                    mapping.source_handle.clone(),
                ),
                mapping,
            )
        })
        .collect();
    let strategy_exceptions = plan
        .verifier
        .strategy_differences(plan.request.symbol_strategy);

    for (key, before) in before {
        let after = after[&key];
        if before.symbol_type != after.symbol_type || before.source_name != after.source_name {
            return Err(BindError::verification(format!(
                "symbol type/source identity changed for {}/{}",
                display_chain(&before.attachment_chain),
                before.logical_handle
            )));
        }

        if before.attachment_chain.is_empty() {
            if before.handle != after.handle
                || before.name != after.name
                || !field_maps_equivalent(
                    &before.fields,
                    &after.fields,
                    plan.verifier.absolute_tolerance,
                    plan.verifier.relative_tolerance,
                )
            {
                return Err(BindError::verification(format!(
                    "pre-bind host {} definition '{}' changed",
                    symbol_type_name(before.symbol_type),
                    before.name
                )));
            }
            continue;
        }

        let mapping = response_by_source.get(&key).ok_or_else(|| {
            BindError::verification(format!(
                "dependent symbol {}/{} has no response mapping",
                display_chain(&before.attachment_chain),
                before.logical_handle
            ))
        })?;
        if after.handle != mapping.final_handle || after.name != mapping.final_name {
            return Err(BindError::verification(format!(
                "post projection disagrees with response mapping for '{}'",
                before.source_name
            )));
        }
        if before.handle != after.handle && !strategy_exceptions.contains("symbol_handles") {
            return Err(BindError::verification(format!(
                "symbol handle changed without {} authorization",
                match plan.request.symbol_strategy {
                    XrefSymbolStrategy::Prefix => "prefix",
                    XrefSymbolStrategy::Merge => "merge",
                }
            )));
        }
        if before.name != after.name && !strategy_exceptions.contains("symbol_names") {
            return Err(BindError::verification(
                "symbol name changed without strategy authorization",
            ));
        }

        let substitution = matches!(
            mapping.resolution,
            XrefSymbolResolution::HostDefinitionUsed | XrefSymbolResolution::EarlierImportUsed
        );
        if substitution {
            if plan.request.symbol_strategy != XrefSymbolStrategy::Merge
                || !strategy_exceptions.contains("symbol_content")
            {
                return Err(BindError::verification(
                    "merge symbol substitution lacks profile authorization",
                ));
            }
            continue;
        }

        for (field, before_value) in &before.fields {
            let after_value = &after.fields[field];
            if before.symbol_type == XrefSymbolType::Block
                && matches!(field.as_str(), "flags" | "saved_path")
                && plan
                    .verifier
                    .operation_differences
                    .contains("ordinary_blocks")
                && plan
                    .verifier
                    .operation_differences
                    .contains("xref_attachments")
            {
                continue;
            }
            let expected = match field.as_str() {
                "name" => Value::String(mapping.final_name.clone()),
                "owner_handle" => map_handle_value(
                    before_value,
                    &before.attachment_chain,
                    identities,
                    &plan.verifier,
                )?,
                "line_type" => map_symbol_name_value(
                    before_value,
                    &before.attachment_chain,
                    XrefSymbolType::Linetype,
                    response,
                )?,
                _ => before_value.clone(),
            };
            if !values_equivalent(
                &expected,
                after_value,
                plan.verifier.absolute_tolerance,
                plan.verifier.relative_tolerance,
            ) {
                return Err(BindError::verification(format!(
                    "symbol field '{}' changed outside the active profile for '{}'",
                    field, before.source_name
                )));
            }
        }
    }
    Ok(())
}

fn verify_clips(
    plan: &BindPlan,
    pre: &BindStructuralProjection,
    post: &BindStructuralProjection,
) -> Result<(), BindError> {
    match &plan.clip_admission {
        BindClipAdmission::Reject => {
            if pre.clips.is_empty() && post.clips.is_empty() {
                Ok(())
            } else {
                Err(BindError::verification(
                    "clip evidence appeared under a rejecting capability row",
                ))
            }
        }
        BindClipAdmission::Verify(profile) => {
            let before: BTreeMap<_, _> = pre
                .clips
                .iter()
                .map(|clip| {
                    (
                        (
                            chain_key(&clip.attachment_chain),
                            clip.instance_logical_handle.clone(),
                        ),
                        clip,
                    )
                })
                .collect();
            let after: BTreeMap<_, _> = post
                .clips
                .iter()
                .map(|clip| {
                    (
                        (
                            chain_key(&clip.attachment_chain),
                            clip.instance_logical_handle.clone(),
                        ),
                        clip,
                    )
                })
                .collect();
            if before.keys().ne(after.keys()) {
                return Err(BindError::verification(
                    "post-bind clip identity set differs from pre-bind evidence",
                ));
            }
            for (key, before) in before {
                if !field_maps_equivalent(
                    &before.fields,
                    &after[&key].fields,
                    profile.absolute_tolerance,
                    profile.relative_tolerance,
                ) {
                    return Err(BindError::verification(format!(
                        "clip fields changed for {}/{}",
                        key.0, key.1
                    )));
                }
            }
            Ok(())
        }
    }
}

fn field_maps_equivalent(
    left: &BTreeMap<String, Value>,
    right: &BTreeMap<String, Value>,
    absolute_tolerance: f64,
    relative_tolerance: f64,
) -> bool {
    left.len() == right.len()
        && left.iter().all(|(field, value)| {
            right.get(field).is_some_and(|other| {
                values_equivalent(value, other, absolute_tolerance, relative_tolerance)
            })
        })
}

pub(crate) fn values_equivalent(
    left: &Value,
    right: &Value,
    absolute_tolerance: f64,
    relative_tolerance: f64,
) -> bool {
    match (left, right) {
        (Value::Number(left), Value::Number(right)) => {
            let (Some(left), Some(right)) = (left.as_f64(), right.as_f64()) else {
                return left == right;
            };
            let difference = (left - right).abs();
            difference <= absolute_tolerance + relative_tolerance * left.abs().max(right.abs())
        }
        (Value::Array(left), Value::Array(right)) => {
            left.len() == right.len()
                && left.iter().zip(right).all(|(left, right)| {
                    values_equivalent(left, right, absolute_tolerance, relative_tolerance)
                })
        }
        (Value::Object(left), Value::Object(right)) => {
            left.len() == right.len()
                && left.iter().all(|(key, left)| {
                    right.get(key).is_some_and(|right| {
                        values_equivalent(left, right, absolute_tolerance, relative_tolerance)
                    })
                })
        }
        _ => left == right,
    }
}

pub(crate) fn generate_bind_autolisp(
    plan: &BindPlan,
    evidence_path: &Path,
) -> Result<String, BindError> {
    if !evidence_path.is_absolute() {
        return Err(BindError::new(
            xref_failure_code::WRITE_FAILED,
            "bind evidence path must be absolute",
        ));
    }

    let mut script = String::new();
    script.push_str(
        r#"(vl-load-com)
(defun acm-replace-all (text old new / at)
  (while (setq at (vl-string-search old text))
    (setq text (strcat (substr text 1 at) new (substr text (+ at (strlen old) 1)))))
  text)
(defun acm-json-string (value / text)
  (setq text (if value (vl-princ-to-string value) ""))
  (setq text (acm-replace-all text "\\" "\\\\"))
  (setq text (acm-replace-all text "\"" "\\\""))
  (setq text (acm-replace-all text (chr 13) "\\r"))
  (setq text (acm-replace-all text (chr 10) "\\n"))
  (setq text (acm-replace-all text (chr 9) "\\t"))
  (strcat "\"" text "\""))
(defun acm-normalize (value)
  (cond
    ((= (type value) 'VARIANT) (acm-normalize (vlax-variant-value value)))
    ((= (type value) 'SAFEARRAY) (mapcar 'acm-normalize (vlax-safearray->list value)))
    (T value)))
(defun acm-json-array (values / output first)
  (setq output "[" first T)
  (foreach value values
    (if first (setq first nil) (setq output (strcat output ",")))
    (setq output (strcat output (acm-json-value value))))
  (strcat output "]"))
(defun acm-json-value (raw / value)
  (setq value (acm-normalize raw))
  (cond
    ((eq value :vlax-true) "true")
    ((eq value :vlax-false) "false")
    ((null value) "null")
    ((= (type value) 'STR) (acm-json-string value))
    ((numberp value) (vl-princ-to-string value))
    ((listp value) (acm-json-array value))
    (T (acm-json-string (vl-princ-to-string value)))))
(defun acm-emit (json) (write-line (strcat "AUTOCAD_MCP_XREF_BIND_V1|" json) acm-out))
(defun acm-required (value detail)
  (if value value (error (strcat "AUTOCAD_MCP_BIND: " detail))))
(defun acm-object-by-handle (handle)
  (acm-required (vlax-ename->vla-object (handent handle)) (strcat "missing handle " handle)))
(defun acm-symbol-by-name (table name)
  (acm-required (vlax-ename->vla-object (tblobjname table name))
    (strcat "missing " table " symbol " name)))
(defun acm-handle (object) (strcase (vla-get-Handle object)))
(defun acm-owner-handle (object / owner)
  (setq owner (vla-ObjectIDToObject (vla-get-ActiveDocument (vlax-get-acad-object))
                (vla-get-OwnerID object)))
  (acm-handle owner))
(defun acm-dxf (object code / pair)
  (setq pair (assoc code (entget (vlax-vla-object->ename object))))
  (if pair (cdr pair) nil))
(defun acm-dxf-list (object code / output)
  (setq output nil)
  (foreach pair (entget (vlax-vla-object->ename object))
    (if (= (car pair) code) (setq output (append output (list (cdr pair))))))
  output)
(defun acm-field-value (object class field / name record)
  (cond
    ((= field "owner_handle") (acm-owner-handle object))
    ((= field "attachment_handle")
      (setq name (vla-get-Name object))
      (acm-handle (acm-symbol-by-name "BLOCK" name)))
    ((= field "layer") (vla-get-Layer object))
    ((= field "position") (vla-get-InsertionPoint object))
    ((= field "start_point") (vla-get-StartPoint object))
    ((= field "end_point") (vla-get-EndPoint object))
    ((= field "rotation") (vla-get-Rotation object))
    ((= field "scale")
      (list (vla-get-XScaleFactor object) (vla-get-YScaleFactor object)
            (vla-get-ZScaleFactor object)))
    ((= field "visibility") (vla-get-Visible object))
    ((= field "column_count") (vla-get-Columns object))
    ((= field "column_spacing") (vla-get-ColumnSpacing object))
    ((= field "row_count") (vla-get-Rows object))
    ((= field "row_spacing") (vla-get-RowSpacing object))
    ((= field "base_point") (vla-get-Origin object))
    ((= field "flags") (if (setq record (acm-dxf object 70)) record 0))
    ((= field "name") (vla-get-Name object))
    ((= field "saved_path") (if (setq record (acm-dxf object 1)) record ""))
    ((= field "color_index") (vla-get-Color object))
    ((= field "line_type") (vla-get-Linetype object))
    ((= field "line_weight") (vla-get-Lineweight object))
    ((= field "description") (vla-get-Description object))
    ((= field "pattern") (acm-dxf-list object 49))
    (T (error (strcat "AUTOCAD_MCP_BIND: unsupported projected field " class "." field)))))
(defun acm-fields-json (object class fields / output first)
  (setq output "{" first T)
  (foreach field fields
    (if first (setq first nil) (setq output (strcat output ",")))
    (setq output (strcat output (acm-json-string field) ":"
                  (acm-json-value (acm-field-value object class field)))))
  (strcat output "}"))
(defun acm-object-json (chain logical class object fields)
  (strcat "{\"attachment_chain\":" chain
    ",\"logical_handle\":" (acm-json-string logical)
    ",\"handle\":" (acm-json-string (acm-handle object))
    ",\"class_name\":" (acm-json-string class)
    ",\"fields\":" (acm-fields-json object class fields)
    ",\"is_proxy\":false}"))
(defun acm-symbol-json (chain logical symbol-type source-name final-name class object fields)
  (strcat "{\"attachment_chain\":" chain
    ",\"logical_handle\":" (acm-json-string logical)
    ",\"handle\":" (acm-json-string (acm-handle object))
    ",\"symbol_type\":" (acm-json-string symbol-type)
    ",\"source_name\":" (acm-json-string source-name)
    ",\"name\":" (acm-json-string final-name)
    ",\"fields\":" (acm-fields-json object class fields) "}"))
(defun acm-bind-block (object prefix)
  (if (= (vla-get-IsXRef object) :vlax-true) (vla-Bind object prefix)))
(defun acm-rename-symbol (object name)
  (acm-required object (strcat "missing symbol for deterministic rename " name))
  (vla-put-Name object name))
"#,
    );

    script.push_str("(defun acm-run-bind (/ )\n");

    for (index, (_, attachment)) in plan.selected_records().enumerate() {
        script.push_str(&format!(
            "  (setq acm-block-{index} (acm-object-by-handle {}))\n",
            lisp_string(&attachment.handle)
        ));
    }
    for (index, instance) in plan.instances.iter().enumerate() {
        script.push_str(&format!(
            "  (setq acm-instance-{index} (acm-object-by-handle {}))\n",
            lisp_string(&instance.old_handle)
        ));
    }
    for (index, allocation) in plan.symbol_allocations.iter().enumerate() {
        script.push_str(&format!(
            "  (setq acm-source-symbol-{index} (acm-symbol-by-name {} {}))\n",
            lisp_string(symbol_table_name(allocation.candidate.symbol_type)),
            lisp_string(&allocation.candidate.source_name)
        ));
    }
    for (index, object) in plan.pre_projection.objects.iter().enumerate() {
        script.push_str(&format!(
            "  (setq acm-project-object-{index} (acm-object-by-handle {}))\n",
            lisp_string(&object.handle)
        ));
    }

    let bind_flag = if plan.request.symbol_strategy == XrefSymbolStrategy::Merge {
        ":vlax-true"
    } else {
        ":vlax-false"
    };
    for (index, _) in plan.selected_records().enumerate() {
        script.push_str(&format!(
            "  (acm-bind-block acm-block-{index} {bind_flag})\n"
        ));
    }

    if plan.request.symbol_strategy == XrefSymbolStrategy::Prefix {
        for (index, allocation) in plan.symbol_allocations.iter().enumerate() {
            script.push_str(&format!(
                "  (acm-rename-symbol acm-source-symbol-{index} {})\n",
                lisp_string(
                    allocation
                        .temporary_name
                        .as_deref()
                        .expect("prefix allocation has a temporary name")
                )
            ));
        }
        for (index, allocation) in plan.symbol_allocations.iter().enumerate() {
            script.push_str(&format!(
                "  (acm-rename-symbol acm-source-symbol-{index} {})\n",
                lisp_string(&allocation.final_name)
            ));
        }
    }

    let root_prefix = "{\"kind\":\"root_block\",\"block\":{\"handle\":";
    let root_suffix = format!(
        ",\"name\":{}}}}}",
        serde_json::to_string(&plan.attachment.name).expect("serialize attachment name")
    );
    script.push_str(&format!(
        "  (acm-emit (strcat {} (acm-json-string (acm-handle acm-block-0)) {}))\n",
        lisp_string(root_prefix),
        lisp_string(&root_suffix)
    ));

    for (index, instance) in plan.instances.iter().enumerate() {
        let prefix_json = format!(
            "{{\"kind\":\"instance_mapping\",\"mapping\":{{\"attachment_chain\":{},\"old_handle\":{},\"new_handle\":",
            json(&instance.attachment_chain),
            json(&instance.old_handle)
        );
        script.push_str(&format!(
            "  (acm-emit (strcat {} (acm-json-string (acm-handle acm-instance-{index})) \"}}}}\"))\n",
            lisp_string(&prefix_json)
        ));
    }

    for allocation in &plan.symbol_allocations {
        let prefix_json = format!(
            "{{\"kind\":\"symbol_mapping\",\"mapping\":{{\"attachment_chain\":{},\"symbol_type\":{},\"source_handle\":{},\"source_name\":{},\"final_handle\":",
            json(&allocation.candidate.attachment_chain),
            json(symbol_type_name(allocation.candidate.symbol_type)),
            json(&allocation.candidate.source_handle),
            json(&allocation.candidate.source_name)
        );
        let suffix_json = format!(
            ",\"final_name\":{},\"resolution\":{}}}}}",
            json(&allocation.final_name),
            json(symbol_resolution_name(allocation.resolution))
        );
        script.push_str(&format!(
            "  (setq acm-final-symbol (acm-symbol-by-name {} {}))\n",
            lisp_string(symbol_table_name(allocation.candidate.symbol_type)),
            lisp_string(&allocation.final_name)
        ));
        script.push_str(&format!(
            "  (acm-emit (strcat {} (acm-json-string (acm-handle acm-final-symbol)) {}))\n",
            lisp_string(&prefix_json),
            lisp_string(&suffix_json)
        ));
    }

    for (index, dependency) in plan.selected_dependencies.iter().enumerate() {
        let prefix_json = format!(
            "{{\"kind\":\"bound_dependency\",\"dependency\":{{\"attachment_chain\":{},\"attachment\":{},\"block\":{{\"handle\":",
            json(&dependency.attachment_chain),
            json(&dependency.attachment)
        );
        let suffix_json = format!(",\"name\":{}}}}}}}}}", json(&dependency.attachment.name));
        script.push_str(&format!(
            "  (acm-emit (strcat {} (acm-json-string (acm-handle acm-block-{})) {}))\n",
            lisp_string(&prefix_json),
            index + 1,
            lisp_string(&suffix_json)
        ));
    }
    for dependency in &plan.excluded_overlay_dependencies {
        emit_static(
            &mut script,
            &BindSentinelRecord::ExcludedOverlay {
                dependency: dependency.clone(),
            },
        )?;
    }

    for (index, object) in plan.pre_projection.objects.iter().enumerate() {
        let fields = lisp_string_list(object.fields.keys().map(String::as_str));
        script.push_str(&format!(
            "  (acm-emit (strcat \"{{\\\"kind\\\":\\\"projected_object\\\",\\\"object\\\":\" (acm-object-json {} {} {} acm-project-object-{index} {}) \"}}\"))\n",
            lisp_string(&json(&object.attachment_chain)),
            lisp_string(&object.logical_handle),
            lisp_string(&object.class_name),
            fields
        ));
    }

    for symbol in &plan.pre_projection.symbols {
        let final_name = if symbol.attachment_chain.is_empty() {
            symbol.name.clone()
        } else {
            plan.symbol_allocations
                .iter()
                .find(|allocation| {
                    candidate_key(&allocation.candidate) == projected_symbol_key(symbol)
                })
                .map(|allocation| allocation.final_name.clone())
                .ok_or_else(|| {
                    BindError::unsupported(format!(
                        "projection symbol '{}' has no deterministic allocation",
                        symbol.source_name
                    ))
                })?
        };
        let fields = lisp_string_list(symbol.fields.keys().map(String::as_str));
        script.push_str(&format!(
            "  (setq acm-project-symbol (acm-symbol-by-name {} {}))\n",
            lisp_string(symbol_table_name(symbol.symbol_type)),
            lisp_string(&final_name)
        ));
        script.push_str(&format!(
            "  (acm-emit (strcat \"{{\\\"kind\\\":\\\"projected_symbol\\\",\\\"symbol\\\":\" (acm-symbol-json {} {} {} {} {} {} acm-project-symbol {}) \"}}\"))\n",
            lisp_string(&json(&symbol.attachment_chain)),
            lisp_string(&symbol.logical_handle),
            lisp_string(symbol_type_name(symbol.symbol_type)),
            lisp_string(&symbol.source_name),
            lisp_string(&final_name),
            lisp_string(symbol_projection_class(symbol.symbol_type)),
            fields
        ));
    }

    if plan.pre_projection.objects.is_empty()
        && plan.pre_projection.symbols.is_empty()
        && plan.pre_projection.clips.is_empty()
    {
        emit_static(
            &mut script,
            &BindSentinelRecord::PostProjection {
                projection: BindStructuralProjection {
                    complete: true,
                    objects: Vec::new(),
                    symbols: Vec::new(),
                    clips: Vec::new(),
                },
            },
        )?;
    }
    if !plan.pre_projection.clips.is_empty() {
        script.push_str(
            "  (error \"AUTOCAD_MCP_BIND: native clip projection requires a certified clip extractor\")\n",
        );
    }
    emit_static(&mut script, &BindSentinelRecord::Complete)?;
    script.push_str("  T)\n");

    script.push_str(&format!(
        "(defun autocad-mcp-xref-operation (/ acm-error)\n  (setq acm-out (open {} \"w\"))\n",
        lisp_string(&path_for_lisp(evidence_path))
    ));
    script.push_str(
        r#"  (if (not acm-out) (error "AUTOCAD_MCP_BIND: cannot open evidence file"))
  (setq acm-error (vl-catch-all-apply 'acm-run-bind '()))
  (if (vl-catch-all-error-p acm-error)
    (acm-emit (strcat "{\"kind\":\"failure\",\"code\":\"write_failed\",\"detail\":"
      (acm-json-string (vl-catch-all-error-message acm-error)) "}")))
  (close acm-out)
  (if (vl-catch-all-error-p acm-error) (error (vl-catch-all-error-message acm-error)))
  (princ))
(princ)
"#,
    );
    Ok(script)
}

fn emit_static(script: &mut String, record: &BindSentinelRecord) -> Result<(), BindError> {
    let payload = serde_json::to_string(record).map_err(|error| {
        BindError::new(
            xref_failure_code::WRITE_FAILED,
            format!("serialize bind sentinel: {error}"),
        )
    })?;
    script.push_str(&format!("  (acm-emit {})\n", lisp_string(&payload)));
    Ok(())
}

fn json(value: &(impl Serialize + ?Sized)) -> String {
    serde_json::to_string(value).expect("bind plan values must serialize")
}

fn lisp_string(value: &str) -> String {
    let escaped = value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\r', "\\r")
        .replace('\n', "\\n");
    format!("\"{escaped}\"")
}

fn lisp_string_list<'a>(values: impl Iterator<Item = &'a str>) -> String {
    format!(
        "(list {})",
        values.map(lisp_string).collect::<Vec<_>>().join(" ")
    )
}

fn path_for_lisp(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn symbol_resolution_name(value: XrefSymbolResolution) -> &'static str {
    match value {
        XrefSymbolResolution::Prefixed => "prefixed",
        XrefSymbolResolution::Imported => "imported",
        XrefSymbolResolution::HostDefinitionUsed => "host_definition_used",
        XrefSymbolResolution::EarlierImportUsed => "earlier_import_used",
    }
}

fn symbol_projection_class(value: XrefSymbolType) -> &'static str {
    match value {
        XrefSymbolType::Block => "AcDbBlockTableRecord",
        XrefSymbolType::Layer => "AcDbLayerTableRecord",
        XrefSymbolType::Linetype => "AcDbLinetypeTableRecord",
        XrefSymbolType::TextStyle => "AcDbTextStyleTableRecord",
        XrefSymbolType::DimensionStyle => "AcDbDimStyleTableRecord",
        XrefSymbolType::TableStyle => "AcDbTableStyle",
        XrefSymbolType::MultileaderStyle => "AcDbMLeaderStyle",
        XrefSymbolType::Material => "AcDbMaterial",
        XrefSymbolType::PlotStyle => "AcDbPlaceHolder",
        XrefSymbolType::VisualStyle => "AcDbVisualStyle",
    }
}

#[derive(Debug, Clone)]
pub(crate) struct BindXrefOperation<Reader> {
    input: BindPreflightInput,
    persisted_evidence_reader: Reader,
    plan: Option<BindPlan>,
    evidence_path: Option<PathBuf>,
    locked_sources: Vec<XrefSourceInput>,
}

impl<Reader> BindXrefOperation<Reader> {
    pub(crate) fn new(input: BindPreflightInput, persisted_evidence_reader: Reader) -> Self {
        Self {
            input,
            persisted_evidence_reader,
            plan: None,
            evidence_path: None,
            locked_sources: Vec::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn plan(&self) -> Option<&BindPlan> {
        self.plan.as_ref()
    }
}

impl<Reader> XrefMutationOperationCallback for BindXrefOperation<Reader>
where
    Reader: BindPersistedEvidenceReader,
{
    type Response = BindXrefResponse;

    fn validate_locked(
        &mut self,
        context: &XrefLockedMutationContext<'_>,
    ) -> Result<(), XrefTransactionError> {
        if Path::new(&self.input.request.drawing_path) != context.host_path {
            return Err(XrefTransactionError::new(
                XrefTransactionErrorCode::Domain(
                    xref_failure_code::CONTRADICTORY_IDENTITY.to_string(),
                ),
                "bind request drawing_path differs from the locked host path",
            ));
        }
        let expected_host_digest = self.input.host_digest_sha256.as_deref().ok_or_else(|| {
            XrefTransactionError::new(
                XrefTransactionErrorCode::Domain(
                    xref_failure_code::UNSUPPORTED_XREF_SOURCE.to_string(),
                ),
                "bind preflight did not retain the exact host-byte digest",
            )
        })?;
        if context.host.digest.hex() != expected_host_digest {
            return Err(XrefTransactionError::new(
                XrefTransactionErrorCode::ConcurrentDrawingModification,
                "bind dependency preflight describes a different host byte version",
            ));
        }
        if self.input.source_inputs.iter().any(|source| {
            source.inspected_digest_sha256.is_none()
                || source.identity_provenance != XrefSourceIdentityProvenance::PathObservation
        }) {
            return Err(XrefTransactionError::new(
                XrefTransactionErrorCode::Domain(
                    xref_failure_code::UNSUPPORTED_XREF_SOURCE.to_string(),
                ),
                "bind dependency preflight lacks exact source-byte evidence",
            ));
        }
        self.locked_sources = self.input.source_inputs.clone();
        for source in &mut self.locked_sources {
            source.identity_provenance = XrefSourceIdentityProvenance::DigestBoundGraphTraversal;
        }
        if !context
            .admission
            .capability
            .operations
            .contains(&XrefMutationOperation::BindXref)
        {
            return Err(XrefTransactionError::new(
                XrefTransactionErrorCode::UnsupportedPlatform,
                "active XREF capability row does not certify bind_xref",
            ));
        }
        let bind_profile = context.admission.bind_profile.ok_or_else(|| {
            XrefTransactionError::new(
                XrefTransactionErrorCode::UnsupportedPlatform,
                "active XREF capability row has no bind verifier profile",
            )
        })?;
        let verifier = BindVerifierContract::from_profile(bind_profile)
            .map_err(bind_validation_transaction_error)?;
        let clip_admission = match context.admission.capability.clip_policy {
            XrefClipPolicy::Reject => BindClipAdmission::Reject,
            XrefClipPolicy::Verify => {
                let profile = context.admission.clip_profile.ok_or_else(|| {
                    XrefTransactionError::new(
                        XrefTransactionErrorCode::UnsupportedPlatform,
                        "clip-verifying XREF capability row has no clip verifier profile",
                    )
                })?;
                BindClipAdmission::Verify(
                    BindClipVerifierContract::from_profile(profile)
                        .map_err(bind_validation_transaction_error)?,
                )
            }
        };
        self.plan = Some(
            preflight_bind(&self.input, verifier, clip_admission)
                .map_err(bind_validation_transaction_error)?,
        );
        self.evidence_path = None;
        Ok(())
    }

    fn locked_source_inputs(&self) -> Option<&[XrefSourceInput]> {
        Some(&self.locked_sources)
    }

    fn execute(
        &mut self,
        engine: &mut dyn XrefMutationEngineBoundary,
        context: &XrefOperationContext<'_>,
    ) -> Result<Vec<PathBuf>, XrefTransactionError> {
        let plan = self.plan.as_ref().ok_or_else(|| {
            XrefTransactionError::new(
                XrefTransactionErrorCode::WriteFailed,
                "bind operation executed before locked preflight",
            )
        })?;
        let script_path = context.staging_directory.join(SCRIPT_FILE_NAME);
        let evidence_path = context.staging_directory.join(EVIDENCE_FILE_NAME);
        let script = generate_bind_autolisp(plan, &evidence_path)
            .map_err(bind_execution_transaction_error)?;
        fs::write(&script_path, script).map_err(|error| {
            XrefTransactionError::new(
                XrefTransactionErrorCode::WriteFailed,
                format!("write native bind script: {error}"),
            )
        })?;
        engine.execute_operation(&script_path).map_err(|error| {
            XrefTransactionError::new(
                XrefTransactionErrorCode::WriteFailed,
                format!("register native bind script: {error}"),
            )
        })?;
        self.evidence_path = Some(evidence_path.clone());
        Ok(vec![script_path, evidence_path])
    }

    fn verify(
        &mut self,
        context: &XrefVerificationContext<'_>,
    ) -> Result<Self::Response, XrefTransactionError> {
        let plan = self.plan.as_ref().ok_or_else(|| {
            XrefTransactionError::new(
                XrefTransactionErrorCode::VerificationFailed,
                "bind verification ran without a preflight plan",
            )
        })?;
        let evidence_path = self.evidence_path.as_ref().ok_or_else(|| {
            XrefTransactionError::new(
                XrefTransactionErrorCode::VerificationFailed,
                "bind verification ran without an evidence path",
            )
        })?;
        let output = fs::read_to_string(evidence_path).map_err(|error| {
            XrefTransactionError::new(
                XrefTransactionErrorCode::VerificationFailed,
                format!("read native bind evidence: {error}"),
            )
        })?;
        let execution =
            parse_bind_sentinels(&output, plan).map_err(bind_verification_transaction_error)?;
        let persisted = self
            .persisted_evidence_reader
            .read_persisted_bind_evidence(context.temporary_host, plan, &execution)
            .map_err(bind_verification_transaction_error)?;
        if persisted.response != execution.response {
            return Err(bind_verification_transaction_error(BindError::verification(
                "persisted post-save bind response evidence differs from the native execution sentinel",
            )));
        }
        verify_bind_equivalence(plan, &persisted).map_err(bind_verification_transaction_error)?;
        Ok(persisted.response)
    }
}

fn bind_validation_transaction_error(error: BindError) -> XrefTransactionError {
    XrefTransactionError::new(
        XrefTransactionErrorCode::Domain(error.code().to_string()),
        error.message(),
    )
}

fn bind_execution_transaction_error(error: BindError) -> XrefTransactionError {
    XrefTransactionError::new(XrefTransactionErrorCode::WriteFailed, error.message())
}

fn bind_verification_transaction_error(error: BindError) -> XrefTransactionError {
    XrefTransactionError::new(
        XrefTransactionErrorCode::VerificationFailed,
        error.to_string(),
    )
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, path::PathBuf, rc::Rc};

    use serde_json::json;

    use crate::certification::embedded_xref_artifacts;

    use super::*;
    use crate::ops::{
        xref_mutation::{
            embedded_xref_mutation_admission, ProductionXrefFileSystem, XrefCapabilityQuery,
            XrefHostFormatFacts, XrefMutationFileSystem, XrefSourceSnapshot,
        },
        xref_path::FilesystemIdentity,
        xrefs::{
            LoadState, XrefPathMode, XrefPointAvailability, XrefResolutionBasis,
            XrefResolutionState, XrefTraversalLimitReason, XrefTraversalTruncation,
        },
    };

    #[derive(Debug, Clone, Copy, Default)]
    struct TestPersistedEvidenceReader;

    impl BindPersistedEvidenceReader for TestPersistedEvidenceReader {
        fn read_persisted_bind_evidence(
            &mut self,
            _temporary_host: &Path,
            _plan: &BindPlan,
            execution: &BindExecutionEvidence,
        ) -> Result<BindExecutionEvidence, BindError> {
            Ok(execution.clone())
        }
    }

    #[derive(Debug, Clone)]
    struct FixedPersistedEvidenceReader {
        evidence: BindExecutionEvidence,
        paths: Rc<RefCell<Vec<PathBuf>>>,
    }

    impl BindPersistedEvidenceReader for FixedPersistedEvidenceReader {
        fn read_persisted_bind_evidence(
            &mut self,
            temporary_host: &Path,
            _plan: &BindPlan,
            _execution: &BindExecutionEvidence,
        ) -> Result<BindExecutionEvidence, BindError> {
            self.paths.borrow_mut().push(temporary_host.to_path_buf());
            Ok(self.evidence.clone())
        }
    }

    fn fields(entries: &[(&str, Value)]) -> BTreeMap<String, Value> {
        entries
            .iter()
            .map(|(name, value)| ((*name).to_string(), value.clone()))
            .collect()
    }

    fn attachment(
        handle: &str,
        name: &str,
        reference_type: ReferenceType,
        instance_count: u64,
    ) -> XrefAttachmentRecord {
        XrefAttachmentRecord {
            handle: handle.to_string(),
            name: name.to_string(),
            saved_path: format!("{name}.dwg"),
            path_mode: XrefPathMode::Relative,
            reference_type,
            load_state: LoadState::Loaded,
            instance_count,
            definition_base_point: XrefPointAvailability::Unavailable,
        }
    }

    fn dependency(
        chain: &[&str],
        name: &str,
        reference_type: ReferenceType,
        propagation_state: XrefPropagationState,
        instance_count: u64,
    ) -> XrefDependencyRecord {
        let handle = chain.last().expect("dependency chain has a handle");
        let depth = u32::try_from(chain.len() - 1).unwrap();
        let terminal_overlay = propagation_state == XrefPropagationState::ExcludedOverlay;
        XrefDependencyRecord {
            attachment_chain: chain.iter().map(|value| (*value).to_string()).collect(),
            depth,
            immediate_host_path: if depth == 0 {
                "/project/host.dwg".to_string()
            } else {
                format!("/project/{}.dwg", chain[chain.len() - 2])
            },
            attachment: attachment(handle, name, reference_type, instance_count),
            propagation_state,
            resolution_state: XrefResolutionState::Resolved,
            resolved_path: Some(format!("/project/{name}.dwg")),
            resolution_basis: Some(XrefResolutionBasis::HostRelative),
            inspection_state: if terminal_overlay {
                XrefInspectionState::TerminalOverlay
            } else {
                XrefInspectionState::Inspected
            },
            cycle_target_chain: None,
        }
    }

    fn graph(records: Vec<XrefDependencyRecord>) -> XrefDependencyTraversalEnvelope {
        XrefDependencyTraversalEnvelope {
            drawing: "/project/host.dwg".to_string(),
            within_limits: true,
            truncation: None,
            dependencies: records,
        }
    }

    fn request(
        symbol_strategy: XrefSymbolStrategy,
        dependency_strategy: XrefDependencyStrategy,
    ) -> BindXrefRequest {
        BindXrefRequest {
            drawing_path: "/project/host.dwg".to_string(),
            handle: Some("2a".to_string()),
            name: Some("root".to_string()),
            expected_handle: Some("0x2A".to_string()),
            expected_name: Some("ROOT".to_string()),
            expected_instance_count: Some(1),
            expected_instance_handles: Some(vec!["040".to_string()]),
            symbol_strategy,
            dependency_strategy,
            search_paths: None,
        }
    }

    fn block_reference(chain: &[&str]) -> BindProjectedObject {
        BindProjectedObject {
            attachment_chain: chain.iter().map(|value| (*value).to_string()).collect(),
            logical_handle: "40".to_string(),
            handle: "40".to_string(),
            class_name: "AcDbBlockReference".to_string(),
            fields: fields(&[
                ("attachment_handle", json!("2A")),
                ("layer", json!("0")),
                ("owner_handle", json!("10")),
                ("position", json!([0.0, 0.0, 0.0])),
                ("rotation", json!(0.0)),
                ("scale", json!([1.0, 1.0, 1.0])),
                ("visibility", json!(true)),
            ]),
            is_proxy: false,
        }
    }

    fn line_object(chain: &[&str]) -> BindProjectedObject {
        BindProjectedObject {
            attachment_chain: chain.iter().map(|value| (*value).to_string()).collect(),
            logical_handle: "70".to_string(),
            handle: "70".to_string(),
            class_name: "AcDbLine".to_string(),
            fields: fields(&[
                ("end_point", json!([10.0, 0.0, 0.0])),
                ("layer", json!("ROOT|WALL")),
                ("owner_handle", json!("2A")),
                ("start_point", json!([0.0, 0.0, 0.0])),
            ]),
            is_proxy: false,
        }
    }

    fn layer_symbol(chain: &[&str], handle: &str, source_name: &str) -> BindProjectedSymbol {
        BindProjectedSymbol {
            attachment_chain: chain.iter().map(|value| (*value).to_string()).collect(),
            logical_handle: handle.to_string(),
            handle: handle.to_string(),
            symbol_type: XrefSymbolType::Layer,
            source_name: source_name.to_string(),
            name: source_name.to_string(),
            fields: fields(&[
                ("color_index", json!(7)),
                ("flags", json!(16)),
                ("line_type", json!("Continuous")),
                ("line_weight", json!(-3)),
                ("name", json!(source_name)),
            ]),
        }
    }

    fn root_candidate() -> BindSymbolCandidate {
        BindSymbolCandidate {
            attachment_chain: vec!["2A".to_string()],
            attachment_namespace: vec!["ROOT".to_string()],
            symbol_type: XrefSymbolType::Layer,
            source_handle: "61".to_string(),
            source_name: "ROOT|WALL".to_string(),
        }
    }

    fn root_instance() -> BindInstanceAdmission {
        BindInstanceAdmission {
            attachment_chain: vec!["2A".to_string()],
            old_handle: "40".to_string(),
            owner_handle: "10".to_string(),
            owner_writable_preserving: true,
            layer_locked: false,
            locked_properties_preserved: false,
            clip_fields: None,
        }
    }

    fn fixture(
        symbol_strategy: XrefSymbolStrategy,
        dependency_strategy: XrefDependencyStrategy,
    ) -> BindPreflightInput {
        BindPreflightInput {
            request: request(symbol_strategy, dependency_strategy),
            dependency_graph: graph(vec![dependency(
                &["2A"],
                "ROOT",
                ReferenceType::Attachment,
                XrefPropagationState::Root,
                1,
            )]),
            host_digest_sha256: None,
            source_inputs: Vec::new(),
            host_symbols: Vec::new(),
            dependent_symbols: vec![root_candidate()],
            instances: vec![root_instance()],
            pre_projection: BindStructuralProjection {
                complete: true,
                objects: vec![line_object(&["2A"]), block_reference(&["2A"])],
                symbols: vec![layer_symbol(&["2A"], "61", "ROOT|WALL")],
                clips: Vec::new(),
            },
        }
    }

    fn verifier() -> BindVerifierContract {
        let registry = embedded_xref_artifacts().expect("embedded XREF artifacts are valid");
        BindVerifierContract::from_profile(
            registry
                .bind_profile("xref-bind-v1")
                .expect("embedded bind profile exists"),
        )
        .unwrap()
    }

    fn clip_verifier() -> BindClipVerifierContract {
        let registry = embedded_xref_artifacts().expect("embedded XREF artifacts are valid");
        BindClipVerifierContract::from_profile(
            registry
                .clip_profile("xref-clip-v1")
                .expect("embedded clip profile exists"),
        )
        .unwrap()
    }

    fn plan(symbol_strategy: XrefSymbolStrategy) -> BindPlan {
        preflight_bind(
            &fixture(symbol_strategy, XrefDependencyStrategy::RejectNested),
            verifier(),
            BindClipAdmission::Reject,
        )
        .unwrap()
    }

    #[test]
    fn prefix_allocation_is_depth_independent_case_insensitive_and_numeric() {
        let candidates = vec![
            BindSymbolCandidate {
                attachment_chain: vec!["10".to_string()],
                attachment_namespace: vec!["ROOT".to_string(), "NEST".to_string()],
                symbol_type: XrefSymbolType::Layer,
                source_handle: "62".to_string(),
                source_name: "ROOT|NEST|Wall".to_string(),
            },
            BindSymbolCandidate {
                attachment_chain: vec!["2".to_string()],
                attachment_namespace: vec!["SITE".to_string()],
                symbol_type: XrefSymbolType::Linetype,
                source_handle: "63".to_string(),
                source_name: "SITE|Wall".to_string(),
            },
        ];
        let host = vec![
            BindHostSymbol {
                symbol_type: XrefSymbolType::Layer,
                handle: "11".to_string(),
                name: "root$0$nest$0$WALL".to_string(),
            },
            BindHostSymbol {
                symbol_type: XrefSymbolType::Layer,
                handle: "12".to_string(),
                name: "ROOT$1$NEST$1$WALL".to_string(),
            },
        ];

        let allocations =
            allocate_bind_symbols(XrefSymbolStrategy::Prefix, &host, &candidates).unwrap();

        assert_eq!(allocations[0].candidate.attachment_chain, ["2"]);
        assert_eq!(allocations[0].final_name, "SITE$0$Wall");
        assert_eq!(allocations[1].final_name, "ROOT$2$NEST$2$Wall");
        assert!(allocations
            .iter()
            .all(|allocation| allocation.temporary_name.is_some()));
    }

    #[test]
    fn prefix_allocation_is_independent_per_symbol_table() {
        let mut layer = root_candidate();
        layer.source_name = "ROOT|DASHED".to_string();
        let mut linetype = layer.clone();
        linetype.symbol_type = XrefSymbolType::Linetype;
        linetype.source_handle = "62".to_string();
        let host = vec![BindHostSymbol {
            symbol_type: XrefSymbolType::Layer,
            handle: "10".to_string(),
            name: "ROOT$0$DASHED".to_string(),
        }];

        let allocations =
            allocate_bind_symbols(XrefSymbolStrategy::Prefix, &host, &[layer, linetype]).unwrap();
        assert_eq!(allocations[0].final_name, "ROOT$1$DASHED");
        assert_eq!(allocations[1].final_name, "ROOT$0$DASHED");
    }

    #[test]
    fn merge_uses_host_then_first_candidate_in_canonical_order() {
        let root = root_candidate();
        let nested = BindSymbolCandidate {
            attachment_chain: vec!["2A".to_string(), "B".to_string()],
            attachment_namespace: vec!["ROOT".to_string(), "NEST".to_string()],
            symbol_type: XrefSymbolType::Layer,
            source_handle: "62".to_string(),
            source_name: "ROOT|NEST|WALL".to_string(),
        };
        let host = vec![BindHostSymbol {
            symbol_type: XrefSymbolType::Linetype,
            handle: "12".to_string(),
            name: "Wall".to_string(),
        }];
        let mut linetype = nested.clone();
        linetype.symbol_type = XrefSymbolType::Linetype;
        linetype.source_handle = "63".to_string();

        let allocations =
            allocate_bind_symbols(XrefSymbolStrategy::Merge, &host, &[nested, linetype, root])
                .unwrap();

        assert_eq!(allocations[0].resolution, XrefSymbolResolution::Imported);
        assert_eq!(
            allocations[1].resolution,
            XrefSymbolResolution::EarlierImportUsed
        );
        assert_eq!(
            allocations[1].winning_source,
            Some((vec!["2A".to_string()], "61".to_string()))
        );
        assert_eq!(
            allocations[2].resolution,
            XrefSymbolResolution::HostDefinitionUsed
        );
        assert_eq!(allocations[2].final_name, "Wall");
    }

    #[test]
    fn namespaces_and_generated_names_are_closed() {
        let mut candidate = root_candidate();
        candidate.source_name = "ROOT||WALL".to_string();
        assert_eq!(
            allocate_bind_symbols(XrefSymbolStrategy::Prefix, &[], &[candidate])
                .unwrap_err()
                .code(),
            xref_failure_code::UNSUPPORTED_XREF_CONTENT
        );

        let mut candidate = root_candidate();
        candidate.attachment_namespace = vec!["OTHER".to_string()];
        assert!(allocate_bind_symbols(XrefSymbolStrategy::Merge, &[], &[candidate]).is_err());

        let mut candidate = root_candidate();
        candidate.source_name = format!("ROOT|{}", "X".repeat(251));
        assert!(allocate_bind_symbols(XrefSymbolStrategy::Prefix, &[], &[candidate]).is_err());
    }

    #[test]
    fn reject_nested_ignores_excluded_overlays_but_rejects_propagated_children() {
        let mut input = fixture(
            XrefSymbolStrategy::Prefix,
            XrefDependencyStrategy::RejectNested,
        );
        input.dependency_graph.dependencies.push(dependency(
            &["2A", "C"],
            "OVER",
            ReferenceType::Overlay,
            XrefPropagationState::ExcludedOverlay,
            0,
        ));
        let admitted = preflight_bind(&input, verifier(), BindClipAdmission::Reject).unwrap();
        assert_eq!(admitted.excluded_overlay_dependencies.len(), 1);

        input.dependency_graph.dependencies.push(dependency(
            &["2A", "B"],
            "NEST",
            ReferenceType::Attachment,
            XrefPropagationState::Propagated,
            0,
        ));
        let error = preflight_bind(&input, verifier(), BindClipAdmission::Reject).unwrap_err();
        assert_eq!(error.code(), xref_failure_code::NESTED_XREFS_PRESENT);
    }

    #[test]
    fn bind_nested_admits_direct_overlay_root_and_repeated_sources() {
        let mut input = fixture(
            XrefSymbolStrategy::Prefix,
            XrefDependencyStrategy::BindNested,
        );
        input.dependency_graph.dependencies[0]
            .attachment
            .reference_type = ReferenceType::Overlay;
        let mut first = dependency(
            &["2A", "B"],
            "NEST_A",
            ReferenceType::Attachment,
            XrefPropagationState::Propagated,
            0,
        );
        let mut second = dependency(
            &["2A", "C"],
            "NEST_B",
            ReferenceType::Attachment,
            XrefPropagationState::Propagated,
            0,
        );
        first.resolved_path = Some("/project/shared.dwg".to_string());
        second.resolved_path = first.resolved_path.clone();
        input.dependency_graph.dependencies.extend([second, first]);

        let admitted = preflight_bind(&input, verifier(), BindClipAdmission::Reject).unwrap();
        assert_eq!(admitted.selected_dependencies.len(), 2);
        assert_eq!(
            admitted.selected_dependencies[0].attachment_chain,
            ["2A", "B"]
        );
        assert_eq!(
            admitted.selected_dependencies[1].attachment_chain,
            ["2A", "C"]
        );
    }

    #[test]
    fn graph_cycles_limits_and_repeated_chains_fail_before_mutation() {
        let mut cycle_input = fixture(
            XrefSymbolStrategy::Prefix,
            XrefDependencyStrategy::BindNested,
        );
        let mut cycle = dependency(
            &["2A", "B"],
            "NEST",
            ReferenceType::Attachment,
            XrefPropagationState::Propagated,
            0,
        );
        cycle.inspection_state = XrefInspectionState::Cycle;
        cycle.cycle_target_chain = Some(vec!["2A".to_string()]);
        cycle_input.dependency_graph.dependencies.push(cycle);
        assert_eq!(
            preflight_bind(&cycle_input, verifier(), BindClipAdmission::Reject)
                .unwrap_err()
                .code(),
            xref_failure_code::CIRCULAR_XREF
        );

        let mut limited = fixture(
            XrefSymbolStrategy::Prefix,
            XrefDependencyStrategy::BindNested,
        );
        limited.dependency_graph.within_limits = false;
        limited.dependency_graph.truncation = Some(XrefTraversalTruncation {
            reason: XrefTraversalLimitReason::MaxDepth,
            limit: 256,
            attachment_chain: vec!["2A".to_string(), "B".to_string()],
        });
        assert_eq!(
            preflight_bind(&limited, verifier(), BindClipAdmission::Reject)
                .unwrap_err()
                .code(),
            xref_failure_code::DEPENDENCY_TRAVERSAL_INCOMPLETE
        );

        let mut repeated = fixture(
            XrefSymbolStrategy::Prefix,
            XrefDependencyStrategy::RejectNested,
        );
        repeated
            .dependency_graph
            .dependencies
            .push(repeated.dependency_graph.dependencies[0].clone());
        assert_eq!(
            preflight_bind(&repeated, verifier(), BindClipAdmission::Reject)
                .unwrap_err()
                .code(),
            xref_failure_code::DEPENDENCY_TRAVERSAL_INCOMPLETE
        );
    }

    #[test]
    fn non_root_overlay_partition_is_closed() {
        let mut input = fixture(
            XrefSymbolStrategy::Prefix,
            XrefDependencyStrategy::BindNested,
        );
        let mut invalid = dependency(
            &["2A", "B"],
            "OVER",
            ReferenceType::Overlay,
            XrefPropagationState::Propagated,
            0,
        );
        invalid.inspection_state = XrefInspectionState::Inspected;
        input.dependency_graph.dependencies.push(invalid);
        assert_eq!(
            preflight_bind(&input, verifier(), BindClipAdmission::Reject)
                .unwrap_err()
                .code(),
            xref_failure_code::DEPENDENCY_TRAVERSAL_INCOMPLETE
        );
    }

    #[test]
    fn profile_admission_rejects_unknown_classes_symbols_fields_and_proxies() {
        type BindInputMutation = Box<dyn Fn(&mut BindPreflightInput)>;
        let cases: Vec<BindInputMutation> = vec![
            Box::new(|input| input.pre_projection.objects[0].class_name = "AcDbCircle".into()),
            Box::new(|input| {
                input.pre_projection.objects[0].fields.remove("end_point");
            }),
            Box::new(|input| input.pre_projection.objects[0].is_proxy = true),
            Box::new(|input| {
                input.pre_projection.symbols[0].symbol_type = XrefSymbolType::TextStyle;
                input.dependent_symbols[0].symbol_type = XrefSymbolType::TextStyle;
            }),
            Box::new(|input| input.pre_projection.complete = false),
        ];

        for mutate in cases {
            let mut input = fixture(
                XrefSymbolStrategy::Prefix,
                XrefDependencyStrategy::RejectNested,
            );
            mutate(&mut input);
            assert_eq!(
                preflight_bind(&input, verifier(), BindClipAdmission::Reject)
                    .unwrap_err()
                    .code(),
                xref_failure_code::UNSUPPORTED_XREF_CONTENT
            );
        }
    }

    #[test]
    fn owner_and_locked_instance_proofs_are_required() {
        let mut owner = fixture(
            XrefSymbolStrategy::Prefix,
            XrefDependencyStrategy::RejectNested,
        );
        owner.instances[0].owner_writable_preserving = false;
        assert_eq!(
            preflight_bind(&owner, verifier(), BindClipAdmission::Reject)
                .unwrap_err()
                .code(),
            xref_failure_code::UNSUPPORTED_XREF_OWNER
        );

        let mut locked = fixture(
            XrefSymbolStrategy::Prefix,
            XrefDependencyStrategy::RejectNested,
        );
        locked.instances[0].layer_locked = true;
        assert_eq!(
            preflight_bind(&locked, verifier(), BindClipAdmission::Reject)
                .unwrap_err()
                .code(),
            xref_failure_code::XREF_INSTANCE_LOCKED
        );
        locked.instances[0].locked_properties_preserved = true;
        assert!(preflight_bind(&locked, verifier(), BindClipAdmission::Reject).is_ok());
    }

    #[test]
    fn clip_policy_rejects_or_requires_the_exact_profile_projection() {
        let clip_profile = clip_verifier();
        let clip_fields: BTreeMap<_, _> = clip_profile
            .fields
            .iter()
            .map(|field| (field.clone(), Value::Null))
            .collect();
        let mut input = fixture(
            XrefSymbolStrategy::Prefix,
            XrefDependencyStrategy::RejectNested,
        );
        input.instances[0].clip_fields = Some(clip_fields.clone());
        input.pre_projection.clips.push(BindProjectedClip {
            attachment_chain: vec!["2A".to_string()],
            instance_logical_handle: "40".to_string(),
            fields: clip_fields,
        });
        assert_eq!(
            preflight_bind(&input, verifier(), BindClipAdmission::Reject)
                .unwrap_err()
                .code(),
            xref_failure_code::UNSUPPORTED_XREF_CLIP_DATA
        );
        assert!(preflight_bind(
            &input,
            verifier(),
            BindClipAdmission::Verify(clip_profile.clone())
        )
        .is_ok());

        input.instances[0]
            .clip_fields
            .as_mut()
            .unwrap()
            .remove("normal");
        assert_eq!(
            preflight_bind(&input, verifier(), BindClipAdmission::Verify(clip_profile))
                .unwrap_err()
                .code(),
            xref_failure_code::UNSUPPORTED_XREF_CONTENT
        );
    }

    #[test]
    fn selector_and_destructive_guards_use_canonical_identity() {
        let admitted = preflight_bind(
            &fixture(
                XrefSymbolStrategy::Prefix,
                XrefDependencyStrategy::RejectNested,
            ),
            verifier(),
            BindClipAdmission::Reject,
        )
        .unwrap();
        assert_eq!(admitted.attachment.handle, "2A");

        let mut lowercase_scope = fixture(
            XrefSymbolStrategy::Prefix,
            XrefDependencyStrategy::RejectNested,
        );
        lowercase_scope.instances[0].attachment_chain = vec!["02a".to_string()];
        assert!(preflight_bind(&lowercase_scope, verifier(), BindClipAdmission::Reject).is_ok());

        let mut input = fixture(
            XrefSymbolStrategy::Prefix,
            XrefDependencyStrategy::RejectNested,
        );
        input.request.expected_instance_handles = Some(vec!["41".to_string()]);
        assert_eq!(
            preflight_bind(&input, verifier(), BindClipAdmission::Reject)
                .unwrap_err()
                .code(),
            xref_failure_code::EXPECTED_INSTANCE_HANDLES_MISMATCH
        );

        input.request.expected_instance_handles = Some(vec!["40".to_string()]);
        input.request.name = Some("OTHER".to_string());
        assert_eq!(
            preflight_bind(&input, verifier(), BindClipAdmission::Reject)
                .unwrap_err()
                .code(),
            xref_failure_code::CONTRADICTORY_IDENTITY
        );
    }

    #[test]
    fn merge_host_winner_requires_pre_bind_structural_evidence() {
        let mut input = fixture(
            XrefSymbolStrategy::Merge,
            XrefDependencyStrategy::RejectNested,
        );
        input.host_symbols.push(BindHostSymbol {
            symbol_type: XrefSymbolType::Layer,
            handle: "12".to_string(),
            name: "Wall".to_string(),
        });
        assert_eq!(
            preflight_bind(&input, verifier(), BindClipAdmission::Reject)
                .unwrap_err()
                .code(),
            xref_failure_code::UNSUPPORTED_XREF_CONTENT
        );
    }

    fn sentinel_line(record: &BindSentinelRecord) -> String {
        format!(
            "{SENTINEL_PREFIX}{}\n",
            serde_json::to_string(record).unwrap()
        )
    }

    fn successful_output(plan: &BindPlan) -> (String, BindStructuralProjection) {
        let root_block = XrefBoundBlock {
            handle: "90".to_string(),
            name: plan.attachment.name.clone(),
        };
        let instance_mappings: Vec<_> = plan
            .instances
            .iter()
            .map(|instance| XrefInstanceHandleMapping {
                attachment_chain: instance.attachment_chain.clone(),
                old_handle: instance.old_handle.clone(),
                new_handle: instance.old_handle.clone(),
            })
            .collect();

        let mut source_to_final: BTreeMap<(String, u8, String), String> = BTreeMap::new();
        let mut symbol_mappings = Vec::new();
        for (index, allocation) in plan.symbol_allocations.iter().enumerate() {
            let final_handle = if let Some(handle) = &allocation.existing_final_handle {
                handle.clone()
            } else if let Some((chain, handle)) = &allocation.winning_source {
                source_to_final
                    .get(&(
                        chain_key(chain),
                        allocation.candidate.symbol_type.sort_rank(),
                        handle.clone(),
                    ))
                    .expect("earlier winner was allocated first")
                    .clone()
            } else {
                format!("{:X}", 0xA0 + index)
            };
            source_to_final.insert(candidate_key(&allocation.candidate), final_handle.clone());
            symbol_mappings.push(XrefSymbolMapping {
                attachment_chain: allocation.candidate.attachment_chain.clone(),
                symbol_type: allocation.candidate.symbol_type,
                source_handle: allocation.candidate.source_handle.clone(),
                source_name: allocation.candidate.source_name.clone(),
                final_handle,
                final_name: allocation.final_name.clone(),
                resolution: allocation.resolution,
            });
        }

        let bound_dependencies: Vec<_> = plan
            .selected_dependencies
            .iter()
            .enumerate()
            .map(|(index, dependency)| XrefBoundDependency {
                attachment_chain: dependency.attachment_chain.clone(),
                attachment: dependency.attachment.clone(),
                block: XrefBoundBlock {
                    handle: format!("{:X}", 0xB0 + index),
                    name: dependency.attachment.name.clone(),
                },
            })
            .collect();

        let mut post = plan.pre_projection.clone();
        for (index, object) in post.objects.iter_mut().enumerate() {
            if object.class_name == "AcDbBlockReference" {
                object
                    .fields
                    .insert("attachment_handle".to_string(), json!(root_block.handle));
            } else {
                object.handle = format!("{:X}", 0xC0 + index);
                if object.fields.get("owner_handle") == Some(&json!(plan.attachment.handle)) {
                    object
                        .fields
                        .insert("owner_handle".to_string(), json!(root_block.handle));
                }
                if let Some(Value::String(layer)) = object.fields.get("layer") {
                    if let Some(mapping) = symbol_mappings.iter().find(|mapping| {
                        mapping.attachment_chain == object.attachment_chain
                            && mapping.symbol_type == XrefSymbolType::Layer
                            && &mapping.source_name == layer
                    }) {
                        object
                            .fields
                            .insert("layer".to_string(), json!(mapping.final_name));
                    }
                }
            }
        }
        for symbol in &mut post.symbols {
            if symbol.attachment_chain.is_empty() {
                continue;
            }
            let mapping = symbol_mappings
                .iter()
                .find(|mapping| {
                    mapping.attachment_chain == symbol.attachment_chain
                        && mapping.symbol_type == symbol.symbol_type
                        && mapping.source_handle == symbol.logical_handle
                })
                .unwrap();
            symbol.handle = mapping.final_handle.clone();
            symbol.name = mapping.final_name.clone();
            symbol
                .fields
                .insert("name".to_string(), json!(mapping.final_name));
        }

        let mut output = String::new();
        for mapping in symbol_mappings.iter().rev() {
            output.push_str(&sentinel_line(&BindSentinelRecord::SymbolMapping {
                mapping: mapping.clone(),
            }));
        }
        for mapping in instance_mappings.iter().rev() {
            output.push_str(&sentinel_line(&BindSentinelRecord::InstanceMapping {
                mapping: mapping.clone(),
            }));
        }
        for dependency in bound_dependencies.iter().rev() {
            output.push_str(&sentinel_line(&BindSentinelRecord::BoundDependency {
                dependency: dependency.clone(),
            }));
        }
        for dependency in plan.excluded_overlay_dependencies.iter().rev() {
            output.push_str(&sentinel_line(&BindSentinelRecord::ExcludedOverlay {
                dependency: dependency.clone(),
            }));
        }
        output.push_str(&sentinel_line(&BindSentinelRecord::RootBlock {
            block: root_block,
        }));
        output.push_str(&sentinel_line(&BindSentinelRecord::PostProjection {
            projection: post.clone(),
        }));
        output.push_str(&sentinel_line(&BindSentinelRecord::Complete));
        (output, post)
    }

    #[test]
    fn sentinel_parser_maps_and_sorts_the_exact_closed_response() {
        let plan = plan(XrefSymbolStrategy::Prefix);
        let (output, _) = successful_output(&plan);
        let evidence = parse_bind_sentinels(&format!("noise\n{output}"), &plan).unwrap();

        assert_eq!(evidence.response.status, BindXrefStatus::Bound);
        assert_eq!(evidence.response.block.handle, "90");
        assert_eq!(evidence.response.instance_handle_mappings.len(), 1);
        assert_eq!(evidence.response.symbol_mappings.len(), 1);
        assert_eq!(
            evidence.response.symbol_mappings[0].final_name,
            "ROOT$0$WALL"
        );
    }

    #[test]
    fn sentinel_parser_rejects_truncation_duplicates_and_plan_drift() {
        let plan = plan(XrefSymbolStrategy::Prefix);
        let (mut output, _) = successful_output(&plan);
        let complete = sentinel_line(&BindSentinelRecord::Complete);
        output = output.strip_suffix(&complete).unwrap().to_string();
        assert_eq!(
            parse_bind_sentinels(&output, &plan).unwrap_err().code(),
            xref_failure_code::VERIFICATION_FAILED
        );

        let (mut output, _) = successful_output(&plan);
        output.push_str(&sentinel_line(&BindSentinelRecord::Complete));
        assert!(parse_bind_sentinels(&output, &plan).is_err());

        let bad = XrefSymbolMapping {
            attachment_chain: vec!["2A".to_string()],
            symbol_type: XrefSymbolType::Layer,
            source_handle: "61".to_string(),
            source_name: "ROOT|WALL".to_string(),
            final_handle: "A0".to_string(),
            final_name: "WRONG".to_string(),
            resolution: XrefSymbolResolution::Prefixed,
        };
        let output = [
            sentinel_line(&BindSentinelRecord::RootBlock {
                block: XrefBoundBlock {
                    handle: "90".to_string(),
                    name: "ROOT".to_string(),
                },
            }),
            sentinel_line(&BindSentinelRecord::InstanceMapping {
                mapping: XrefInstanceHandleMapping {
                    attachment_chain: vec!["2A".to_string()],
                    old_handle: "40".to_string(),
                    new_handle: "40".to_string(),
                },
            }),
            sentinel_line(&BindSentinelRecord::SymbolMapping { mapping: bad }),
            sentinel_line(&BindSentinelRecord::PostProjection {
                projection: plan.pre_projection.clone(),
            }),
            sentinel_line(&BindSentinelRecord::Complete),
        ]
        .concat();
        assert!(parse_bind_sentinels(&output, &plan).is_err());
    }

    #[test]
    fn structural_verifier_applies_identity_and_prefix_name_mappings() {
        let plan = plan(XrefSymbolStrategy::Prefix);
        let (output, _) = successful_output(&plan);
        let evidence = parse_bind_sentinels(&output, &plan).unwrap();
        verify_bind_equivalence(&plan, &evidence).unwrap();
    }

    #[test]
    fn structural_verifier_rejects_unprofiled_geometry_change() {
        let plan = plan(XrefSymbolStrategy::Prefix);
        let (output, _) = successful_output(&plan);
        let mut evidence = parse_bind_sentinels(&output, &plan).unwrap();
        let line = evidence
            .post_projection
            .objects
            .iter_mut()
            .find(|object| object.class_name == "AcDbLine")
            .unwrap();
        line.fields
            .insert("end_point".to_string(), json!([11.0, 0.0, 0.0]));

        assert_eq!(
            verify_bind_equivalence(&plan, &evidence)
                .unwrap_err()
                .code(),
            xref_failure_code::VERIFICATION_FAILED
        );
    }

    #[test]
    fn merge_host_substitution_is_the_only_content_exception() {
        let mut input = fixture(
            XrefSymbolStrategy::Merge,
            XrefDependencyStrategy::RejectNested,
        );
        input.host_symbols.push(BindHostSymbol {
            symbol_type: XrefSymbolType::Layer,
            handle: "12".to_string(),
            name: "Wall".to_string(),
        });
        let mut host = layer_symbol(&[], "12", "Wall");
        host.fields.insert("color_index".to_string(), json!(3));
        host.fields.insert("flags".to_string(), json!(0));
        input.pre_projection.symbols.push(host);
        let plan = preflight_bind(&input, verifier(), BindClipAdmission::Reject).unwrap();
        let (output, _) = successful_output(&plan);
        let mut evidence = parse_bind_sentinels(&output, &plan).unwrap();
        let dependent = evidence
            .post_projection
            .symbols
            .iter_mut()
            .find(|symbol| !symbol.attachment_chain.is_empty())
            .unwrap();
        dependent.fields.insert("color_index".to_string(), json!(3));
        dependent.fields.insert("flags".to_string(), json!(0));

        verify_bind_equivalence(&plan, &evidence).unwrap();
        assert_eq!(
            evidence.response.symbol_mappings[0].resolution,
            XrefSymbolResolution::HostDefinitionUsed
        );
        assert_eq!(evidence.response.symbol_mappings[0].final_handle, "12");
        assert_eq!(evidence.response.symbol_mappings[0].final_name, "Wall");
    }

    #[test]
    fn merge_earlier_import_substitution_is_verified_many_to_one() {
        let mut input = fixture(
            XrefSymbolStrategy::Merge,
            XrefDependencyStrategy::BindNested,
        );
        input.dependency_graph.dependencies.push(dependency(
            &["2A", "B"],
            "NEST",
            ReferenceType::Attachment,
            XrefPropagationState::Propagated,
            0,
        ));
        input.dependent_symbols.push(BindSymbolCandidate {
            attachment_chain: vec!["2A".to_string(), "B".to_string()],
            attachment_namespace: vec!["ROOT".to_string(), "NEST".to_string()],
            symbol_type: XrefSymbolType::Layer,
            source_handle: "62".to_string(),
            source_name: "ROOT|NEST|WALL".to_string(),
        });
        input
            .pre_projection
            .symbols
            .push(layer_symbol(&["2A", "B"], "62", "ROOT|NEST|WALL"));
        let plan = preflight_bind(&input, verifier(), BindClipAdmission::Reject).unwrap();
        let (output, _) = successful_output(&plan);
        let mut evidence = parse_bind_sentinels(&output, &plan).unwrap();
        let later = evidence
            .post_projection
            .symbols
            .iter_mut()
            .find(|symbol| symbol.logical_handle == "62")
            .unwrap();
        later.fields.insert("color_index".to_string(), json!(1));

        verify_bind_equivalence(&plan, &evidence).unwrap();
        assert_eq!(
            evidence.response.symbol_mappings[1].resolution,
            XrefSymbolResolution::EarlierImportUsed
        );
        assert_eq!(
            evidence.response.symbol_mappings[0].final_handle,
            evidence.response.symbol_mappings[1].final_handle
        );
    }

    #[test]
    fn native_script_uses_literal_order_two_phase_renaming_and_sentinels() {
        let plan = plan(XrefSymbolStrategy::Prefix);
        let directory = tempfile::tempdir().unwrap();
        let evidence_path = directory.path().join(EVIDENCE_FILE_NAME);
        let script = generate_bind_autolisp(&plan, &evidence_path).unwrap();

        assert!(script.contains("(defun autocad-mcp-xref-operation"));
        assert!(script.contains("(acm-bind-block acm-block-0 :vlax-false)"));
        assert!(script.contains("$ACM$BIND$TMP$"));
        assert!(script.contains("ROOT$0$WALL"));
        assert!(script.contains(SENTINEL_PREFIX));
        assert!(script.contains("projected_object"));
        assert!(script.contains("projected_symbol"));
        assert!(!script.contains("tblnext"));
        assert!(!script.contains("vlax-for"));
        assert!(generate_bind_autolisp(&plan, Path::new("relative.jsonl")).is_err());
    }

    #[test]
    fn native_bind_flag_matches_activex_symbol_strategy_semantics() {
        let directory = tempfile::tempdir().unwrap();
        let prefix_script = generate_bind_autolisp(
            &plan(XrefSymbolStrategy::Prefix),
            &directory.path().join("xref-bind-prefix.jsonl"),
        )
        .unwrap();
        assert!(prefix_script.contains("(acm-bind-block acm-block-0 :vlax-false)"));
        assert!(!prefix_script.contains("(acm-bind-block acm-block-0 :vlax-true)"));

        let merge_script = generate_bind_autolisp(
            &plan(XrefSymbolStrategy::Merge),
            &directory.path().join("xref-bind-merge.jsonl"),
        )
        .unwrap();
        assert!(merge_script.contains("(acm-bind-block acm-block-0 :vlax-true)"));
        assert!(!merge_script.contains("(acm-bind-block acm-block-0 :vlax-false)"));
    }

    #[test]
    fn fragmented_projection_sentinels_are_accepted_but_cannot_mix_with_aggregate() {
        let plan = plan(XrefSymbolStrategy::Prefix);
        let (aggregate, post) = successful_output(&plan);
        let evidence = parse_bind_sentinels(&aggregate, &plan).unwrap();
        let mut output = String::new();
        output.push_str(&sentinel_line(&BindSentinelRecord::RootBlock {
            block: evidence.response.block.clone(),
        }));
        for mapping in &evidence.response.instance_handle_mappings {
            output.push_str(&sentinel_line(&BindSentinelRecord::InstanceMapping {
                mapping: mapping.clone(),
            }));
        }
        for mapping in &evidence.response.symbol_mappings {
            output.push_str(&sentinel_line(&BindSentinelRecord::SymbolMapping {
                mapping: mapping.clone(),
            }));
        }
        for object in &post.objects {
            output.push_str(&sentinel_line(&BindSentinelRecord::ProjectedObject {
                object: object.clone(),
            }));
        }
        for symbol in &post.symbols {
            output.push_str(&sentinel_line(&BindSentinelRecord::ProjectedSymbol {
                symbol: symbol.clone(),
            }));
        }
        output.push_str(&sentinel_line(&BindSentinelRecord::Complete));
        assert!(parse_bind_sentinels(&output, &plan).is_ok());

        let mixed = format!(
            "{}{}{}",
            output
                .strip_suffix(&sentinel_line(&BindSentinelRecord::Complete))
                .unwrap(),
            sentinel_line(&BindSentinelRecord::PostProjection { projection: post }),
            sentinel_line(&BindSentinelRecord::Complete)
        );
        assert!(parse_bind_sentinels(&mixed, &plan).is_err());
    }

    #[test]
    fn numeric_equivalence_is_recursive_and_tolerance_bounded() {
        assert!(values_equivalent(
            &json!({"point": [1.0, 2.0]}),
            &json!({"point": [1.0 + 5e-13, 2.0]}),
            1e-12,
            1e-12
        ));
        assert!(!values_equivalent(
            &json!([1.0, 2.0]),
            &json!([1.0, 2.01]),
            1e-12,
            1e-12
        ));
        assert!(!values_equivalent(
            &json!({"a": 1}),
            &json!({"b": 1}),
            1e-12,
            1e-12
        ));
    }

    #[test]
    fn callback_verifies_the_persisted_post_save_host_not_the_sentinel_projection() {
        let plan = plan(XrefSymbolStrategy::Prefix);
        let (output, post_projection) = successful_output(&plan);
        let persisted = parse_bind_sentinels(&output, &plan).unwrap();

        let mut stale_projection = post_projection.clone();
        stale_projection
            .objects
            .iter_mut()
            .find(|object| object.class_name == "AcDbLine")
            .unwrap()
            .fields
            .insert("end_point".to_string(), json!([999.0, 0.0, 0.0]));
        let stale_output = output.replace(
            &sentinel_line(&BindSentinelRecord::PostProjection {
                projection: post_projection,
            }),
            &sentinel_line(&BindSentinelRecord::PostProjection {
                projection: stale_projection,
            }),
        );
        assert_ne!(stale_output, output);

        let temporary = tempfile::tempdir().unwrap();
        let temporary_host = temporary.path().join("post-save-host.dwg");
        let evidence_path = temporary.path().join(EVIDENCE_FILE_NAME);
        fs::write(&temporary_host, b"persisted-host").unwrap();
        fs::write(&evidence_path, stale_output).unwrap();
        let paths = Rc::new(RefCell::new(Vec::new()));
        let reader = FixedPersistedEvidenceReader {
            evidence: persisted,
            paths: paths.clone(),
        };
        let mut operation = BindXrefOperation::new(
            fixture(
                XrefSymbolStrategy::Prefix,
                XrefDependencyStrategy::RejectNested,
            ),
            reader,
        );
        operation.plan = Some(plan);
        operation.evidence_path = Some(evidence_path);

        let mut file_system = ProductionXrefFileSystem::default();
        let output_observation = file_system.observe_path(&temporary_host).unwrap();
        let sources: Vec<XrefSourceSnapshot> = Vec::new();
        let response = operation
            .verify(&XrefVerificationContext {
                temporary_host: &temporary_host,
                output: &output_observation,
                source_snapshots: &sources,
            })
            .unwrap();

        assert_eq!(response.status, BindXrefStatus::Bound);
        assert_eq!(*paths.borrow(), vec![temporary_host]);
    }

    #[test]
    fn callback_adapter_starts_without_a_plan() {
        let operation = BindXrefOperation::new(
            fixture(
                XrefSymbolStrategy::Prefix,
                XrefDependencyStrategy::RejectNested,
            ),
            TestPersistedEvidenceReader,
        );
        assert!(operation.plan().is_none());
    }

    #[test]
    fn bind_callback_upgrades_exact_digest_bound_sources_under_the_locked_host() {
        let directory = tempfile::tempdir().unwrap();
        let host_path = directory.path().join("host.dwg");
        fs::write(&host_path, b"locked-host-version").unwrap();
        let mut file_system = ProductionXrefFileSystem::default();
        let host = file_system.observe_path(&host_path).unwrap();

        let mut input = fixture(
            XrefSymbolStrategy::Prefix,
            XrefDependencyStrategy::RejectNested,
        );
        let drawing = host_path.to_string_lossy().into_owned();
        input.request.drawing_path = drawing.clone();
        input.dependency_graph.drawing = drawing.clone();
        input.host_digest_sha256 = Some(host.digest.hex());
        input.source_inputs = vec![XrefSourceInput {
            source_id: "2A".to_string(),
            path: PathBuf::from("/refs/root.dwg"),
            saved_path: "root.dwg".to_string(),
            immediate_host_source_id: None,
            filesystem_identity: FilesystemIdentity::opaque(b"root-source".to_vec()).unwrap(),
            identity_provenance: XrefSourceIdentityProvenance::PathObservation,
            inspected_digest_sha256: Some("11".repeat(32)),
        }];

        let admission = embedded_xref_mutation_admission(XrefCapabilityQuery {
            host_format: crate::certification::XrefHostFormat::Dwg,
            drawing_version: "AC1032",
            dxf_form: crate::certification::XrefDxfForm::NotApplicable,
            code_page: None,
            operation: XrefMutationOperation::BindXref,
        })
        .unwrap();
        let format = XrefHostFormatFacts {
            host_format: crate::certification::XrefHostFormat::Dwg,
            drawing_version: "AC1032".to_string(),
            dxf_form: crate::certification::XrefDxfForm::NotApplicable,
            code_page: None,
        };
        let mut operation = BindXrefOperation::new(input, TestPersistedEvidenceReader);
        operation
            .validate_locked(&XrefLockedMutationContext {
                host_path: &host_path,
                host: &host,
                format: &format,
                admission: &admission,
            })
            .unwrap();
        let locked = operation.locked_source_inputs().unwrap();
        assert_eq!(locked.len(), 1);
        assert_eq!(
            locked[0].identity_provenance,
            XrefSourceIdentityProvenance::DigestBoundGraphTraversal
        );
        assert_eq!(locked[0].inspected_digest_sha256, Some("11".repeat(32)));
    }
}
