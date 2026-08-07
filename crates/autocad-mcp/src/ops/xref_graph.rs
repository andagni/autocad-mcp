use super::{
    xref_path::{
        build_resolution_plan, resolve_candidate_plan, validate_search_paths, AbsolutePathKind,
        CanonicalDisplayPath, FilesystemIdentity, PathPlatform, ResolutionCandidateProbe,
        SearchPathInspector, SearchPathValidationError, ValidatedSearchPaths, XrefPathResolution,
    },
    xrefs::{
        canonical_input_handle, sort_xref_attachment_records, xref_failure_code, xref_name_eq,
        ListXrefDependenciesRequest, ReferenceType, XrefAttachmentRecord, XrefDependencyRecord,
        XrefDependencyTraversalEnvelope, XrefError, XrefInspectionState, XrefPathMode,
        XrefPropagationState, XrefResolutionState, XrefSelector, XrefTraversalLimitReason,
        XrefTraversalTruncation,
    },
};

pub const DEFAULT_DEPENDENCY_MAX_DEPTH: u32 = 32;
pub const DEFAULT_DEPENDENCY_MAX_NODES: u32 = 10_000;
pub const MAX_DEPENDENCY_DEPTH: u32 = 256;
pub const MAX_DEPENDENCY_NODES: u32 = 100_000;
pub const MUTATION_DEPENDENCY_MAX_DEPTH: u32 = MAX_DEPENDENCY_DEPTH;
pub const MUTATION_DEPENDENCY_MAX_NODES: u32 = MAX_DEPENDENCY_NODES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XrefTraversalLimits {
    max_depth: u32,
    max_nodes: u32,
}

impl XrefTraversalLimits {
    pub fn try_new(max_depth: u32, max_nodes: u32) -> Result<Self, XrefError> {
        if max_depth > MAX_DEPENDENCY_DEPTH {
            return Err(XrefError::new(
                xref_failure_code::INVALID_PARAMETERS,
                format!("max_depth must be in 0..={MAX_DEPENDENCY_DEPTH}, got {max_depth}"),
            ));
        }
        if !(1..=MAX_DEPENDENCY_NODES).contains(&max_nodes) {
            return Err(XrefError::new(
                xref_failure_code::INVALID_PARAMETERS,
                format!("max_nodes must be in 1..={MAX_DEPENDENCY_NODES}, got {max_nodes}"),
            ));
        }
        Ok(Self {
            max_depth,
            max_nodes,
        })
    }

    pub fn for_list(max_depth: Option<u32>, max_nodes: Option<u32>) -> Result<Self, XrefError> {
        Self::try_new(
            max_depth.unwrap_or(DEFAULT_DEPENDENCY_MAX_DEPTH),
            max_nodes.unwrap_or(DEFAULT_DEPENDENCY_MAX_NODES),
        )
    }

    pub const fn for_mutation() -> Self {
        Self {
            max_depth: MUTATION_DEPENDENCY_MAX_DEPTH,
            max_nodes: MUTATION_DEPENDENCY_MAX_NODES,
        }
    }

    pub const fn max_depth(self) -> u32 {
        self.max_depth
    }

    pub const fn max_nodes(self) -> u32 {
        self.max_nodes
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct XrefGraphSource {
    drawing_path: CanonicalDisplayPath,
    filesystem_identity: FilesystemIdentity,
    attachments: Vec<XrefAttachmentRecord>,
}

impl XrefGraphSource {
    pub fn try_new(
        drawing_path: CanonicalDisplayPath,
        filesystem_identity: FilesystemIdentity,
        mut attachments: Vec<XrefAttachmentRecord>,
    ) -> Result<Self, XrefError> {
        normalize_attachment_set(&mut attachments)?;
        Ok(Self {
            drawing_path,
            filesystem_identity,
            attachments,
        })
    }

    pub fn from_filesystem_canonical_path(
        drawing_path: &str,
        filesystem_identity: FilesystemIdentity,
        attachments: Vec<XrefAttachmentRecord>,
    ) -> Result<Self, XrefError> {
        let drawing_path = CanonicalDisplayPath::from_filesystem_canonical_path(drawing_path)
            .map_err(|error| {
                XrefError::new(
                    xref_failure_code::UNSUPPORTED_XREF_DATA,
                    format!("root drawing path is not canonicalizable: {error}"),
                )
            })?;
        Self::try_new(drawing_path, filesystem_identity, attachments)
    }

    pub fn drawing_path(&self) -> &CanonicalDisplayPath {
        &self.drawing_path
    }

    pub fn filesystem_identity(&self) -> &FilesystemIdentity {
        &self.filesystem_identity
    }

    pub fn attachments(&self) -> &[XrefAttachmentRecord] {
        &self.attachments
    }

    pub fn platform(&self) -> PathPlatform {
        match self.drawing_path.kind() {
            AbsolutePathKind::Posix => PathPlatform::Posix,
            AbsolutePathKind::WindowsDrive | AbsolutePathKind::WindowsUnc => PathPlatform::Windows,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum XrefSourceInspection {
    Inspected {
        attachments: Vec<XrefAttachmentRecord>,
        content_sha256: Option<String>,
    },
    Unsupported,
}

/// Supplies filesystem probes and complete direct XREF sets for resolved sources.
///
/// `Unsupported` means the source resolved but its complete child set cannot be
/// proven. Malformed attachment evidence must be returned as an `XrefError`
/// instead of a partial `Inspected` set.
pub trait XrefDependencyProvider: ResolutionCandidateProbe + SearchPathInspector {
    fn inspect_resolved_source(
        &mut self,
        resolved_path: &CanonicalDisplayPath,
        filesystem_identity: &FilesystemIdentity,
    ) -> Result<XrefSourceInspection, XrefError>;
}

fn normalize_attachment_set(records: &mut [XrefAttachmentRecord]) -> Result<(), XrefError> {
    sort_xref_attachment_records(records)?;
    if records
        .windows(2)
        .any(|pair| pair[0].handle == pair[1].handle)
    {
        return Err(XrefError::new(
            xref_failure_code::UNSUPPORTED_XREF_DATA,
            "an immediate host contains duplicate canonical XREF handles",
        ));
    }
    Ok(())
}

fn resolve_root_by_handle(
    attachments: &[XrefAttachmentRecord],
    wanted: &str,
) -> Result<usize, XrefError> {
    let wanted = canonical_input_handle(wanted)?;
    attachments
        .iter()
        .position(|attachment| attachment.handle == wanted)
        .ok_or_else(|| {
            XrefError::new(
                xref_failure_code::XREF_NOT_FOUND,
                format!("XREF handle `{wanted}` was not found"),
            )
        })
}

fn resolve_root_by_name(
    attachments: &[XrefAttachmentRecord],
    wanted: &str,
) -> Result<usize, XrefError> {
    if wanted.trim().is_empty() {
        return Err(XrefError::new(
            xref_failure_code::XREF_NOT_FOUND,
            "empty XREF name was not found",
        ));
    }
    let matches = attachments
        .iter()
        .enumerate()
        .filter_map(|(index, attachment)| xref_name_eq(&attachment.name, wanted).then_some(index))
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [] => Err(XrefError::new(
            xref_failure_code::XREF_NOT_FOUND,
            format!("XREF name `{wanted}` was not found"),
        )),
        [index] => Ok(*index),
        _ => Err(XrefError::new(
            xref_failure_code::AMBIGUOUS_IDENTITY,
            format!("XREF name `{wanted}` matches more than one attachment"),
        )),
    }
}

fn select_roots(
    source: &XrefGraphSource,
    selector: Option<&XrefSelector>,
) -> Result<Vec<XrefAttachmentRecord>, XrefError> {
    let Some(selector) = selector else {
        return Ok(source.attachments.clone());
    };
    let has_usable_name = selector
        .name
        .as_deref()
        .is_some_and(|name| !name.trim().is_empty());
    if selector.handle.is_none() && !has_usable_name {
        return Err(XrefError::new(
            xref_failure_code::MISSING_IDENTITY,
            "dependency root selection requires a handle or non-empty name",
        ));
    }

    let by_handle = selector
        .handle
        .as_deref()
        .map(|handle| resolve_root_by_handle(&source.attachments, handle))
        .transpose()?;
    let by_name = selector
        .name
        .as_deref()
        .map(|name| resolve_root_by_name(&source.attachments, name))
        .transpose()?;

    let index = match (by_handle, by_name) {
        (Some(handle_index), Some(name_index)) if handle_index == name_index => handle_index,
        (Some(_), Some(_)) => {
            return Err(XrefError::new(
                xref_failure_code::CONTRADICTORY_IDENTITY,
                "XREF handle and name select different dependency roots",
            ));
        }
        (Some(index), None) | (None, Some(index)) => index,
        (None, None) => {
            return Err(XrefError::new(
                xref_failure_code::MISSING_IDENTITY,
                "dependency root selection requires a handle or non-empty name",
            ));
        }
    };
    Ok(vec![source.attachments[index].clone()])
}

fn map_search_path_error(error: SearchPathValidationError) -> XrefError {
    XrefError::new(xref_failure_code::INVALID_SEARCH_PATH, error.detail())
}

/// Adapts the public list request to the pure traversal engine.
///
/// `source` must be the canonical root host loaded for `request.drawing_path`.
pub fn list_xref_dependencies<P>(
    source: &XrefGraphSource,
    request: &ListXrefDependenciesRequest,
    provider: &mut P,
) -> Result<XrefDependencyTraversalEnvelope, XrefError>
where
    P: XrefDependencyProvider + ?Sized,
{
    let limits = XrefTraversalLimits::for_list(request.max_depth, request.max_nodes)?;
    let search_paths = validate_search_paths(
        request.search_paths.as_deref().unwrap_or_default(),
        source.platform(),
        provider,
    )
    .map_err(map_search_path_error)?;
    let selector = (request.handle.is_some() || request.name.is_some()).then(|| XrefSelector {
        handle: request.handle.clone(),
        name: request.name.clone(),
    });
    traverse_xref_dependencies(source, selector.as_ref(), &search_paths, limits, provider)
}

pub fn traverse_xref_dependencies<P>(
    source: &XrefGraphSource,
    root_selector: Option<&XrefSelector>,
    search_paths: &ValidatedSearchPaths,
    limits: XrefTraversalLimits,
    provider: &mut P,
) -> Result<XrefDependencyTraversalEnvelope, XrefError>
where
    P: XrefDependencyProvider + ?Sized,
{
    if source.platform() != search_paths.platform() {
        return Err(XrefError::new(
            xref_failure_code::UNSUPPORTED_XREF_DATA,
            "root drawing and validated search paths use different path platforms",
        ));
    }

    let roots = select_roots(source, root_selector)?;
    let mut traversal = Traversal {
        provider,
        search_paths,
        limits,
        dependencies: Vec::new(),
        truncation: None,
        ancestors: vec![Ancestor {
            identity: source.filesystem_identity.clone(),
            attachment_chain: Vec::new(),
        }],
    };

    for root in roots {
        let chain = vec![root.handle.clone()];
        traversal.visit(root, source.drawing_path.clone(), chain, 0)?;
        if traversal.truncation.is_some() {
            break;
        }
    }

    let envelope = XrefDependencyTraversalEnvelope {
        drawing: source.drawing_path.as_str().to_owned(),
        within_limits: traversal.truncation.is_none(),
        truncation: traversal.truncation,
        dependencies: traversal.dependencies,
    };
    envelope.validate()?;
    Ok(envelope)
}

pub fn traverse_xref_dependencies_for_mutation<P>(
    source: &XrefGraphSource,
    root_selector: Option<&XrefSelector>,
    search_paths: &ValidatedSearchPaths,
    provider: &mut P,
) -> Result<XrefDependencyTraversalEnvelope, XrefError>
where
    P: XrefDependencyProvider + ?Sized,
{
    let envelope = traverse_xref_dependencies(
        source,
        root_selector,
        search_paths,
        XrefTraversalLimits::for_mutation(),
        provider,
    )?;
    require_complete_dependency_graph_for_mutation(&envelope)?;
    Ok(envelope)
}

pub fn require_complete_dependency_graph_for_mutation(
    envelope: &XrefDependencyTraversalEnvelope,
) -> Result<(), XrefError> {
    envelope.validate()?;
    if let Some(truncation) = &envelope.truncation {
        return Err(XrefError::new(
            xref_failure_code::DEPENDENCY_TRAVERSAL_INCOMPLETE,
            format!(
                "dependency traversal reached {:?}={} before `{}`",
                truncation.reason,
                truncation.limit,
                truncation.attachment_chain.join("/")
            ),
        ));
    }

    for dependency in &envelope.dependencies {
        let chain = dependency.attachment_chain.join("/");
        let error = match dependency.inspection_state {
            XrefInspectionState::Inspected | XrefInspectionState::TerminalOverlay => None,
            XrefInspectionState::Cycle => Some(XrefError::new(
                xref_failure_code::CIRCULAR_XREF,
                format!("dependency `{chain}` creates an XREF cycle"),
            )),
            XrefInspectionState::Unsupported => Some(XrefError::new(
                xref_failure_code::DEPENDENCY_TRAVERSAL_INCOMPLETE,
                format!("dependency `{chain}` has an unprovable child set"),
            )),
            XrefInspectionState::NotResolved => {
                let (code, description) = match dependency.resolution_state {
                    XrefResolutionState::NotFound => {
                        (xref_failure_code::XREF_SOURCE_NOT_FOUND, "was not found")
                    }
                    XrefResolutionState::Unresolved => (
                        xref_failure_code::XREF_SOURCE_UNREADABLE,
                        "could not be read or parsed",
                    ),
                    XrefResolutionState::Unsupported => (
                        xref_failure_code::UNSUPPORTED_XREF_SOURCE,
                        "uses an unsupported source",
                    ),
                    XrefResolutionState::Resolved => {
                        return Err(XrefError::new(
                            xref_failure_code::UNSUPPORTED_XREF_DATA,
                            format!(
                                "dependency `{chain}` has inconsistent resolution and inspection states"
                            ),
                        ));
                    }
                };
                // Mirror `resolve_xref_path`'s shape: name the attempted path and
                // whether it was recorded as saved-absolute or saved-relative,
                // rather than surfacing only the attachment chain. The actual
                // search-path candidates tried aren't retained per dependency
                // node, so this can't yet show every location probed the way
                // `resolve_xref_path` does for a single, directly-queried XREF —
                // but the saved path itself was always available and is the
                // detail most useful for diagnosing why a dependency couldn't
                // be resolved during traversal.
                let saved_path = &dependency.attachment.saved_path;
                let path_mode = match dependency.attachment.path_mode {
                    XrefPathMode::Absolute => "saved as an absolute path",
                    XrefPathMode::Relative => "saved as a host-relative path",
                    XrefPathMode::FilenameOnly => "saved as a filename-only reference",
                    XrefPathMode::Url => "saved as a URL",
                    XrefPathMode::Unsupported => "saved with an unsupported path syntax",
                };
                Some(XrefError::new(
                    code,
                    format!(
                        "dependency `{chain}` source {description}; attempted path \
                         `{saved_path}` ({path_mode})"
                    ),
                ))
            }
        };
        if let Some(error) = error {
            return Err(error);
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct Ancestor {
    identity: FilesystemIdentity,
    attachment_chain: Vec<String>,
}

struct Traversal<'a, P: ?Sized> {
    provider: &'a mut P,
    search_paths: &'a ValidatedSearchPaths,
    limits: XrefTraversalLimits,
    dependencies: Vec<XrefDependencyRecord>,
    truncation: Option<XrefTraversalTruncation>,
    ancestors: Vec<Ancestor>,
}

impl<P> Traversal<'_, P>
where
    P: XrefDependencyProvider + ?Sized,
{
    fn truncate(
        &mut self,
        reason: XrefTraversalLimitReason,
        limit: u32,
        attachment_chain: Vec<String>,
    ) {
        if self.truncation.is_none() {
            self.truncation = Some(XrefTraversalTruncation {
                reason,
                limit,
                attachment_chain,
            });
        }
    }

    fn visit(
        &mut self,
        attachment: XrefAttachmentRecord,
        immediate_host_path: CanonicalDisplayPath,
        attachment_chain: Vec<String>,
        depth: u32,
    ) -> Result<(), XrefError> {
        if depth > self.limits.max_depth {
            self.truncate(
                XrefTraversalLimitReason::MaxDepth,
                self.limits.max_depth,
                attachment_chain,
            );
            return Ok(());
        }
        if self.dependencies.len() >= self.limits.max_nodes as usize {
            self.truncate(
                XrefTraversalLimitReason::MaxNodes,
                self.limits.max_nodes,
                attachment_chain,
            );
            return Ok(());
        }

        let plan = build_resolution_plan(
            &attachment.saved_path,
            &immediate_host_path,
            self.search_paths.platform(),
            self.search_paths,
        )
        .map_err(|error| {
            XrefError::new(
                xref_failure_code::UNSUPPORTED_XREF_DATA,
                format!("cannot resolve dependency `{}`: {error}", attachment.handle),
            )
        })?;
        let resolution = resolve_candidate_plan(&plan, self.provider).map_err(|error| {
            XrefError::new(
                xref_failure_code::UNSUPPORTED_XREF_DATA,
                format!(
                    "dependency `{}` returned invalid resolution evidence: {error}",
                    attachment.handle
                ),
            )
        })?;
        let propagation_state = if depth == 0 {
            XrefPropagationState::Root
        } else if attachment.reference_type == ReferenceType::Overlay {
            XrefPropagationState::ExcludedOverlay
        } else {
            XrefPropagationState::Propagated
        };

        if propagation_state == XrefPropagationState::ExcludedOverlay {
            let record = dependency_record(
                attachment_chain,
                depth,
                immediate_host_path,
                attachment,
                propagation_state,
                &resolution,
                XrefInspectionState::TerminalOverlay,
                None,
            )?;
            self.dependencies.push(record);
            return Ok(());
        }

        if resolution.resolution_state() != XrefResolutionState::Resolved {
            let record = dependency_record(
                attachment_chain,
                depth,
                immediate_host_path,
                attachment,
                propagation_state,
                &resolution,
                XrefInspectionState::NotResolved,
                None,
            )?;
            self.dependencies.push(record);
            return Ok(());
        }

        let resolved_path = resolution
            .resolved_path()
            .expect("validated resolved path resolution has a path")
            .clone();
        let filesystem_identity = resolution
            .filesystem_identity()
            .expect("validated resolved path resolution has an identity")
            .clone();
        if let Some(target) = self
            .ancestors
            .iter()
            .find(|ancestor| ancestor.identity == filesystem_identity)
            .map(|ancestor| ancestor.attachment_chain.clone())
        {
            let record = dependency_record(
                attachment_chain,
                depth,
                immediate_host_path,
                attachment,
                propagation_state,
                &resolution,
                XrefInspectionState::Cycle,
                Some(target),
            )?;
            self.dependencies.push(record);
            return Ok(());
        }

        match self
            .provider
            .inspect_resolved_source(&resolved_path, &filesystem_identity)?
        {
            XrefSourceInspection::Unsupported => {
                let record = dependency_record(
                    attachment_chain,
                    depth,
                    immediate_host_path,
                    attachment,
                    propagation_state,
                    &resolution,
                    XrefInspectionState::Unsupported,
                    None,
                )?;
                self.dependencies.push(record);
            }
            XrefSourceInspection::Inspected {
                attachments: mut children,
                ..
            } => {
                normalize_attachment_set(&mut children)?;
                let record = dependency_record(
                    attachment_chain.clone(),
                    depth,
                    immediate_host_path,
                    attachment,
                    propagation_state,
                    &resolution,
                    XrefInspectionState::Inspected,
                    None,
                )?;
                self.dependencies.push(record);
                self.ancestors.push(Ancestor {
                    identity: filesystem_identity,
                    attachment_chain: attachment_chain.clone(),
                });

                for child in children {
                    let mut child_chain = attachment_chain.clone();
                    child_chain.push(child.handle.clone());
                    let result = self.visit(child, resolved_path.clone(), child_chain, depth + 1);
                    if let Err(error) = result {
                        self.ancestors.pop();
                        return Err(error);
                    }
                    if self.truncation.is_some() {
                        break;
                    }
                }
                self.ancestors.pop();
            }
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn dependency_record(
    attachment_chain: Vec<String>,
    depth: u32,
    immediate_host_path: CanonicalDisplayPath,
    attachment: XrefAttachmentRecord,
    propagation_state: XrefPropagationState,
    resolution: &XrefPathResolution,
    inspection_state: XrefInspectionState,
    cycle_target_chain: Option<Vec<String>>,
) -> Result<XrefDependencyRecord, XrefError> {
    let record = XrefDependencyRecord {
        attachment_chain,
        depth,
        immediate_host_path: immediate_host_path.as_str().to_owned(),
        attachment,
        propagation_state,
        resolution_state: resolution.resolution_state(),
        resolved_path: resolution
            .resolved_path()
            .map(|path| path.as_str().to_owned()),
        resolution_basis: resolution.resolution_basis(),
        inspection_state,
        cycle_target_chain,
    };
    record.validate()?;
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::super::{
        xref_path::{
            parse_saved_path, CandidateProbeResult, CanonicalExistingPath, ResolutionCandidate,
            SearchPathInspection,
        },
        xrefs::{LoadState, XrefPointAvailability, XrefResolutionBasis},
    };
    use super::*;
    use serde_json::json;
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct FakeProvider {
        probes: BTreeMap<String, CandidateProbeResult>,
        inspections: BTreeMap<String, Result<XrefSourceInspection, XrefError>>,
        search_paths: BTreeMap<String, SearchPathInspection>,
        probe_calls: Vec<String>,
        inspection_calls: Vec<String>,
    }

    impl FakeProvider {
        fn resolve(&mut self, candidate_path: &str, canonical_path: &str, identity_key: &str) {
            self.probes.insert(
                candidate_path.to_owned(),
                CandidateProbeResult::Resolved(existing(canonical_path, identity_key)),
            );
        }

        fn probe_as(&mut self, candidate_path: &str, result: CandidateProbeResult) {
            self.probes.insert(candidate_path.to_owned(), result);
        }

        fn inspect(&mut self, canonical_path: &str, children: Vec<XrefAttachmentRecord>) {
            self.inspections.insert(
                canonical_path.to_owned(),
                Ok(XrefSourceInspection::Inspected {
                    attachments: children,
                    content_sha256: Some("11".repeat(32)),
                }),
            );
        }

        fn unsupported_inspection(&mut self, canonical_path: &str) {
            self.inspections.insert(
                canonical_path.to_owned(),
                Ok(XrefSourceInspection::Unsupported),
            );
        }
    }

    impl ResolutionCandidateProbe for FakeProvider {
        fn probe_candidate(&mut self, candidate: &ResolutionCandidate) -> CandidateProbeResult {
            self.probe_calls.push(candidate.path().to_owned());
            self.probes
                .get(candidate.path())
                .cloned()
                .unwrap_or(CandidateProbeResult::Missing)
        }
    }

    impl SearchPathInspector for FakeProvider {
        fn inspect_search_path(&mut self, absolute_path: &str) -> SearchPathInspection {
            self.search_paths
                .get(absolute_path)
                .cloned()
                .unwrap_or(SearchPathInspection::Missing)
        }
    }

    impl XrefDependencyProvider for FakeProvider {
        fn inspect_resolved_source(
            &mut self,
            resolved_path: &CanonicalDisplayPath,
            _filesystem_identity: &FilesystemIdentity,
        ) -> Result<XrefSourceInspection, XrefError> {
            self.inspection_calls
                .push(resolved_path.as_str().to_owned());
            self.inspections
                .get(resolved_path.as_str())
                .cloned()
                .unwrap_or_else(|| {
                    Err(XrefError::new(
                        xref_failure_code::UNSUPPORTED_XREF_DATA,
                        format!(
                            "test provider has no inspection for `{}`",
                            resolved_path.as_str()
                        ),
                    ))
                })
        }
    }

    fn identity(key: &str) -> FilesystemIdentity {
        FilesystemIdentity::opaque(key.as_bytes().to_vec()).unwrap()
    }

    fn existing(path: &str, identity_key: &str) -> CanonicalExistingPath {
        CanonicalExistingPath::from_filesystem_canonical_path(path, identity(identity_key)).unwrap()
    }

    fn attachment(
        handle: &str,
        name: &str,
        saved_path: &str,
        reference_type: ReferenceType,
    ) -> XrefAttachmentRecord {
        XrefAttachmentRecord {
            handle: handle.to_owned(),
            name: name.to_owned(),
            saved_path: saved_path.to_owned(),
            path_mode: parse_saved_path(saved_path).mode(),
            reference_type,
            load_state: LoadState::Unavailable,
            instance_count: 0,
            definition_base_point: XrefPointAvailability::Unavailable,
        }
    }

    fn source(attachments: Vec<XrefAttachmentRecord>) -> XrefGraphSource {
        XrefGraphSource::from_filesystem_canonical_path(
            "/graph/root.dwg",
            identity("root"),
            attachments,
        )
        .unwrap()
    }

    fn empty_search_paths() -> ValidatedSearchPaths {
        ValidatedSearchPaths::empty(PathPlatform::Posix)
    }

    fn list_request() -> ListXrefDependenciesRequest {
        ListXrefDependenciesRequest {
            drawing_path: "/graph/root.dwg".to_owned(),
            handle: None,
            name: None,
            search_paths: None,
            max_depth: None,
            max_nodes: None,
        }
    }

    fn selector(handle: Option<&str>, name: Option<&str>) -> XrefSelector {
        XrefSelector {
            handle: handle.map(str::to_owned),
            name: name.map(str::to_owned),
        }
    }

    fn chains(envelope: &XrefDependencyTraversalEnvelope) -> Vec<Vec<String>> {
        envelope
            .dependencies
            .iter()
            .map(|dependency| dependency.attachment_chain.clone())
            .collect()
    }

    fn traverse(
        source: &XrefGraphSource,
        provider: &mut FakeProvider,
    ) -> XrefDependencyTraversalEnvelope {
        traverse_xref_dependencies(
            source,
            None,
            &empty_search_paths(),
            XrefTraversalLimits::for_list(None, None).unwrap(),
            provider,
        )
        .unwrap()
    }

    #[test]
    fn exact_envelope_and_dependency_record_are_serialized() {
        let root = source(vec![attachment(
            "A",
            "MISSING",
            "missing.dwg",
            ReferenceType::Attachment,
        )]);
        let envelope =
            list_xref_dependencies(&root, &list_request(), &mut FakeProvider::default()).unwrap();

        assert_eq!(
            serde_json::to_value(&envelope).unwrap(),
            json!({
                "drawing": "/graph/root.dwg",
                "within_limits": true,
                "truncation": null,
                "dependencies": [{
                    "attachment_chain": ["A"],
                    "depth": 0,
                    "immediate_host_path": "/graph/root.dwg",
                    "attachment": {
                        "handle": "A",
                        "name": "MISSING",
                        "saved_path": "missing.dwg",
                        "path_mode": "filename_only",
                        "reference_type": "attachment",
                        "load_state": "unavailable",
                        "instance_count": 0,
                        "definition_base_point": {"state": "unavailable"}
                    },
                    "propagation_state": "root",
                    "resolution_state": "not_found",
                    "resolved_path": null,
                    "resolution_basis": null,
                    "inspection_state": "not_resolved",
                    "cycle_target_chain": null
                }]
            })
        );
        envelope.validate().unwrap();
    }

    #[test]
    fn traversal_is_numeric_depth_first_preorder_and_only_nested_overlays_terminate() {
        let root = source(vec![
            attachment("10", "TEN", "ten.dwg", ReferenceType::Attachment),
            attachment(
                "F",
                "OVERLAY_ROOT",
                "overlay-root.dwg",
                ReferenceType::Overlay,
            ),
        ]);
        let mut provider = FakeProvider::default();
        provider.resolve(
            "/graph/overlay-root.dwg",
            "/graph/overlay-root.dwg",
            "overlay-root",
        );
        provider.inspect(
            "/graph/overlay-root.dwg",
            vec![attachment(
                "2",
                "OVERLAY_CHILD",
                "leaf.dwg",
                ReferenceType::Attachment,
            )],
        );
        provider.resolve("/graph/leaf.dwg", "/graph/leaf.dwg", "overlay-leaf");
        provider.inspect("/graph/leaf.dwg", vec![]);
        provider.resolve("/graph/ten.dwg", "/graph/ten.dwg", "ten");
        provider.inspect(
            "/graph/ten.dwg",
            vec![
                attachment(
                    "10",
                    "TEN_CHILD",
                    "ten-child.dwg",
                    ReferenceType::Attachment,
                ),
                attachment(
                    "F",
                    "NESTED_OVERLAY",
                    "nested-overlay.dwg",
                    ReferenceType::Overlay,
                ),
            ],
        );
        provider.resolve(
            "/graph/nested-overlay.dwg",
            "/graph/nested-overlay.dwg",
            "nested-overlay",
        );
        provider.inspect(
            "/graph/nested-overlay.dwg",
            vec![attachment(
                "1",
                "EXCLUDED",
                "excluded.dwg",
                ReferenceType::Attachment,
            )],
        );
        provider.resolve("/graph/ten-child.dwg", "/graph/ten-child.dwg", "ten-child");
        provider.inspect("/graph/ten-child.dwg", vec![]);

        let envelope = traverse(&root, &mut provider);
        assert_eq!(
            chains(&envelope),
            vec![
                vec!["F".to_owned()],
                vec!["F".to_owned(), "2".to_owned()],
                vec!["10".to_owned()],
                vec!["10".to_owned(), "F".to_owned()],
                vec!["10".to_owned(), "10".to_owned()],
            ]
        );
        assert_eq!(
            envelope
                .dependencies
                .iter()
                .map(|dependency| dependency.propagation_state)
                .collect::<Vec<_>>(),
            vec![
                XrefPropagationState::Root,
                XrefPropagationState::Propagated,
                XrefPropagationState::Root,
                XrefPropagationState::ExcludedOverlay,
                XrefPropagationState::Propagated,
            ]
        );
        assert_eq!(
            envelope.dependencies[0].inspection_state,
            XrefInspectionState::Inspected
        );
        assert_eq!(
            envelope.dependencies[3].inspection_state,
            XrefInspectionState::TerminalOverlay
        );
        assert_eq!(
            provider.inspection_calls,
            vec![
                "/graph/overlay-root.dwg",
                "/graph/leaf.dwg",
                "/graph/ten.dwg",
                "/graph/ten-child.dwg",
            ]
        );
    }

    #[test]
    fn root_selector_accepts_handle_or_name_and_preserves_identity_errors() {
        let root = source(vec![
            attachment("10", "SITE", "site.dwg", ReferenceType::Attachment),
            attachment("F", "GRID", "grid.dwg", ReferenceType::Attachment),
        ]);
        let paths = empty_search_paths();
        let limits = XrefTraversalLimits::for_list(None, None).unwrap();

        let by_handle = traverse_xref_dependencies(
            &root,
            Some(&selector(Some("0x0010"), None)),
            &paths,
            limits,
            &mut FakeProvider::default(),
        )
        .unwrap();
        assert_eq!(chains(&by_handle), vec![vec!["10".to_owned()]]);

        let by_name = traverse_xref_dependencies(
            &root,
            Some(&selector(None, Some("grid"))),
            &paths,
            limits,
            &mut FakeProvider::default(),
        )
        .unwrap();
        assert_eq!(chains(&by_name), vec![vec!["F".to_owned()]]);

        let error = traverse_xref_dependencies(
            &root,
            Some(&selector(Some("10"), Some("GRID"))),
            &paths,
            limits,
            &mut FakeProvider::default(),
        )
        .unwrap_err();
        assert_eq!(error.code(), xref_failure_code::CONTRADICTORY_IDENTITY);

        let error = traverse_xref_dependencies(
            &root,
            Some(&XrefSelector::default()),
            &paths,
            limits,
            &mut FakeProvider::default(),
        )
        .unwrap_err();
        assert_eq!(error.code(), xref_failure_code::MISSING_IDENTITY);

        let ambiguous = source(vec![
            attachment("1", "DUP", "one.dwg", ReferenceType::Attachment),
            attachment("2", "dup", "two.dwg", ReferenceType::Attachment),
        ]);
        let error = traverse_xref_dependencies(
            &ambiguous,
            Some(&selector(None, Some("DuP"))),
            &paths,
            limits,
            &mut FakeProvider::default(),
        )
        .unwrap_err();
        assert_eq!(error.code(), xref_failure_code::AMBIGUOUS_IDENTITY);
    }

    #[test]
    fn filesystem_identity_cycles_target_root_or_current_ancestor_chain() {
        let root = source(vec![
            attachment("1", "SELF", "root-alias.dwg", ReferenceType::Attachment),
            attachment("2", "PARENT", "parent.dwg", ReferenceType::Attachment),
        ]);
        let mut provider = FakeProvider::default();
        provider.resolve("/graph/root-alias.dwg", "/aliases/root.dwg", "root");
        provider.resolve("/graph/parent.dwg", "/graph/parent.dwg", "parent");
        provider.inspect(
            "/graph/parent.dwg",
            vec![attachment(
                "3",
                "PARENT_ALIAS",
                "/aliases/parent.dwg",
                ReferenceType::Attachment,
            )],
        );
        provider.resolve("/aliases/parent.dwg", "/different/parent.dwg", "parent");

        let envelope = traverse(&root, &mut provider);
        assert_eq!(
            chains(&envelope),
            vec![
                vec!["1".to_owned()],
                vec!["2".to_owned()],
                vec!["2".to_owned(), "3".to_owned()],
            ]
        );
        assert_eq!(
            envelope.dependencies[0].cycle_target_chain,
            Some(Vec::new())
        );
        assert_eq!(
            envelope.dependencies[2].cycle_target_chain,
            Some(vec!["2".to_owned()])
        );
        assert_eq!(
            provider.inspection_calls,
            vec!["/graph/parent.dwg".to_owned()]
        );
    }

    #[test]
    fn diamond_sources_are_expanded_once_per_occurrence_not_globally() {
        let root = source(vec![
            attachment("1", "SHARED_A", "shared-a.dwg", ReferenceType::Attachment),
            attachment("2", "SHARED_B", "shared-b.dwg", ReferenceType::Attachment),
        ]);
        let mut provider = FakeProvider::default();
        provider.resolve("/graph/shared-a.dwg", "/real/shared.dwg", "shared");
        provider.resolve("/graph/shared-b.dwg", "/real/shared.dwg", "shared");
        provider.inspect(
            "/real/shared.dwg",
            vec![attachment(
                "3",
                "LEAF",
                "leaf.dwg",
                ReferenceType::Attachment,
            )],
        );
        provider.resolve("/real/leaf.dwg", "/real/leaf.dwg", "leaf");
        provider.inspect("/real/leaf.dwg", vec![]);

        let envelope = traverse(&root, &mut provider);
        assert_eq!(
            chains(&envelope),
            vec![
                vec!["1".to_owned()],
                vec!["1".to_owned(), "3".to_owned()],
                vec!["2".to_owned()],
                vec!["2".to_owned(), "3".to_owned()],
            ]
        );
        assert_eq!(
            provider
                .inspection_calls
                .iter()
                .filter(|path| path.as_str() == "/real/shared.dwg")
                .count(),
            2
        );
        assert_eq!(
            provider
                .inspection_calls
                .iter()
                .filter(|path| path.as_str() == "/real/leaf.dwg")
                .count(),
            2
        );
    }

    #[test]
    fn every_resolution_and_inspection_terminal_state_is_exact() {
        let root = source(vec![
            attachment("1", "MISSING", "missing.dwg", ReferenceType::Attachment),
            attachment(
                "2",
                "UNREADABLE",
                "unreadable.dwg",
                ReferenceType::Attachment,
            ),
            attachment(
                "3",
                "UNSUPPORTED_PATH",
                "unsupported.dwg",
                ReferenceType::Attachment,
            ),
            attachment("4", "PROXY", "proxy.dwg", ReferenceType::Attachment),
            attachment("5", "PARENT", "parent.dwg", ReferenceType::Attachment),
            attachment(
                "6",
                "DIRECT_OVERLAY_UNSUPPORTED",
                "unsupported-overlay.dwg",
                ReferenceType::Overlay,
            ),
        ]);
        let mut provider = FakeProvider::default();
        provider.probe_as("/graph/unreadable.dwg", CandidateProbeResult::Unresolved);
        provider.probe_as("/graph/unsupported.dwg", CandidateProbeResult::Unsupported);
        provider.resolve("/graph/proxy.dwg", "/graph/proxy.dwg", "proxy");
        provider.unsupported_inspection("/graph/proxy.dwg");
        provider.resolve("/graph/parent.dwg", "/graph/parent.dwg", "parent");
        provider.inspect(
            "/graph/parent.dwg",
            vec![attachment(
                "A",
                "NESTED_OVERLAY",
                "nested-missing.dwg",
                ReferenceType::Overlay,
            )],
        );
        provider.probe_as(
            "/graph/unsupported-overlay.dwg",
            CandidateProbeResult::Unsupported,
        );

        let envelope = traverse(&root, &mut provider);
        let states = envelope
            .dependencies
            .iter()
            .map(|dependency| {
                (
                    dependency.attachment_chain.clone(),
                    dependency.resolution_state,
                    dependency.inspection_state,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            states,
            vec![
                (
                    vec!["1".to_owned()],
                    XrefResolutionState::NotFound,
                    XrefInspectionState::NotResolved,
                ),
                (
                    vec!["2".to_owned()],
                    XrefResolutionState::Unresolved,
                    XrefInspectionState::NotResolved,
                ),
                (
                    vec!["3".to_owned()],
                    XrefResolutionState::Unsupported,
                    XrefInspectionState::NotResolved,
                ),
                (
                    vec!["4".to_owned()],
                    XrefResolutionState::Resolved,
                    XrefInspectionState::Unsupported,
                ),
                (
                    vec!["5".to_owned()],
                    XrefResolutionState::Resolved,
                    XrefInspectionState::Inspected,
                ),
                (
                    vec!["5".to_owned(), "A".to_owned()],
                    XrefResolutionState::NotFound,
                    XrefInspectionState::TerminalOverlay,
                ),
                (
                    vec!["6".to_owned()],
                    XrefResolutionState::Unsupported,
                    XrefInspectionState::NotResolved,
                ),
            ]
        );
        assert!(envelope.within_limits);
        assert_eq!(envelope.truncation, None);
    }

    #[test]
    fn depth_and_node_limits_return_the_first_deterministic_prefix() {
        let root = source(vec![
            attachment("1", "PARENT", "parent.dwg", ReferenceType::Attachment),
            attachment("2", "ROOT_LEAF", "root-leaf.dwg", ReferenceType::Attachment),
        ]);
        let configured_provider = || {
            let mut provider = FakeProvider::default();
            provider.resolve("/graph/parent.dwg", "/graph/parent.dwg", "parent");
            provider.inspect(
                "/graph/parent.dwg",
                vec![
                    attachment("10", "CHILD_10", "child-10.dwg", ReferenceType::Attachment),
                    attachment("F", "CHILD_F", "child-f.dwg", ReferenceType::Attachment),
                ],
            );
            provider.resolve("/graph/child-f.dwg", "/graph/child-f.dwg", "child-f");
            provider.inspect("/graph/child-f.dwg", vec![]);
            provider.resolve("/graph/child-10.dwg", "/graph/child-10.dwg", "child-10");
            provider.inspect("/graph/child-10.dwg", vec![]);
            provider.resolve("/graph/root-leaf.dwg", "/graph/root-leaf.dwg", "root-leaf");
            provider.inspect("/graph/root-leaf.dwg", vec![]);
            provider
        };
        let paths = empty_search_paths();

        let mut provider = configured_provider();
        let depth_limited = traverse_xref_dependencies(
            &root,
            None,
            &paths,
            XrefTraversalLimits::try_new(0, 1).unwrap(),
            &mut provider,
        )
        .unwrap();
        assert_eq!(chains(&depth_limited), vec![vec!["1".to_owned()]]);
        assert_eq!(
            depth_limited.truncation,
            Some(XrefTraversalTruncation {
                reason: XrefTraversalLimitReason::MaxDepth,
                limit: 0,
                attachment_chain: vec!["1".to_owned(), "F".to_owned()],
            })
        );
        assert!(!depth_limited.within_limits);

        let mut provider = configured_provider();
        let node_limited = traverse_xref_dependencies(
            &root,
            None,
            &paths,
            XrefTraversalLimits::try_new(10, 2).unwrap(),
            &mut provider,
        )
        .unwrap();
        assert_eq!(
            chains(&node_limited),
            vec![vec!["1".to_owned()], vec!["1".to_owned(), "F".to_owned()],]
        );
        assert_eq!(
            node_limited.truncation,
            Some(XrefTraversalTruncation {
                reason: XrefTraversalLimitReason::MaxNodes,
                limit: 2,
                attachment_chain: vec!["1".to_owned(), "10".to_owned()],
            })
        );

        let mut provider = configured_provider();
        let selected_leaf = traverse_xref_dependencies(
            &root,
            Some(&selector(Some("2"), None)),
            &paths,
            XrefTraversalLimits::try_new(0, 1).unwrap(),
            &mut provider,
        )
        .unwrap();
        assert!(selected_leaf.within_limits);
        assert_eq!(selected_leaf.truncation, None);
        assert_eq!(chains(&selected_leaf), vec![vec!["2".to_owned()]]);
    }

    #[test]
    fn list_request_validates_limits_and_uses_ordered_search_path_resolution() {
        let root = source(vec![attachment(
            "1",
            "SEARCHED",
            "nested/site.dwg",
            ReferenceType::Attachment,
        )]);
        let mut request = list_request();
        request.search_paths = Some(vec!["/search".to_owned()]);
        let mut provider = FakeProvider::default();
        provider.search_paths.insert(
            "/search".to_owned(),
            SearchPathInspection::ReadableDirectory(
                CanonicalDisplayPath::from_filesystem_canonical_path("/real/search").unwrap(),
            ),
        );
        provider.resolve(
            "/real/search/site.dwg",
            "/sources/site.dwg",
            "searched-site",
        );
        provider.inspect("/sources/site.dwg", vec![]);

        let envelope = list_xref_dependencies(&root, &request, &mut provider).unwrap();
        assert_eq!(
            envelope.dependencies[0].resolution_basis,
            Some(XrefResolutionBasis::ExplicitSearchPath)
        );
        assert_eq!(
            provider.probe_calls,
            vec![
                "/graph/nested/site.dwg".to_owned(),
                "/real/search/site.dwg".to_owned(),
            ]
        );

        request.max_depth = Some(MAX_DEPENDENCY_DEPTH + 1);
        let error =
            list_xref_dependencies(&root, &request, &mut FakeProvider::default()).unwrap_err();
        assert_eq!(error.code(), xref_failure_code::INVALID_PARAMETERS);
        request.max_depth = None;
        request.max_nodes = Some(0);
        let error =
            list_xref_dependencies(&root, &request, &mut FakeProvider::default()).unwrap_err();
        assert_eq!(error.code(), xref_failure_code::INVALID_PARAMETERS);

        request.max_nodes = None;
        let error =
            list_xref_dependencies(&root, &request, &mut FakeProvider::default()).unwrap_err();
        assert_eq!(error.code(), xref_failure_code::INVALID_SEARCH_PATH);
    }

    #[test]
    fn mutation_mode_uses_fixed_limits_and_maps_required_terminal_nodes() {
        assert_eq!(
            XrefTraversalLimits::for_mutation(),
            XrefTraversalLimits::try_new(256, 100_000).unwrap()
        );

        let state_cases = [
            (
                "missing.dwg",
                None,
                xref_failure_code::XREF_SOURCE_NOT_FOUND,
            ),
            (
                "unreadable.dwg",
                Some(CandidateProbeResult::Unresolved),
                xref_failure_code::XREF_SOURCE_UNREADABLE,
            ),
            (
                "unsupported.dwg",
                Some(CandidateProbeResult::Unsupported),
                xref_failure_code::UNSUPPORTED_XREF_SOURCE,
            ),
        ];
        for (saved_path, probe, expected_code) in state_cases {
            let root = source(vec![attachment(
                "1",
                "ROOT",
                saved_path,
                ReferenceType::Attachment,
            )]);
            let mut provider = FakeProvider::default();
            if let Some(probe) = probe {
                provider.probe_as(&format!("/graph/{saved_path}"), probe);
            }
            let error = traverse_xref_dependencies_for_mutation(
                &root,
                None,
                &empty_search_paths(),
                &mut provider,
            )
            .unwrap_err();
            assert_eq!(error.code(), expected_code, "{saved_path}");
            // The diagnostic must name the attempted path and how it was
            // saved, not just the attachment chain — mirrors the shape
            // `resolve_xref_path` already used for its own not-found case.
            assert!(
                error
                    .message()
                    .contains(&format!("attempted path `{saved_path}`")),
                "{saved_path}: {}",
                error.message()
            );
            assert!(
                error
                    .message()
                    .contains("saved as a filename-only reference"),
                "{saved_path}: {}",
                error.message()
            );
        }

        let proxy_root = source(vec![attachment(
            "1",
            "PROXY",
            "proxy.dwg",
            ReferenceType::Attachment,
        )]);
        let mut provider = FakeProvider::default();
        provider.resolve("/graph/proxy.dwg", "/graph/proxy.dwg", "proxy");
        provider.unsupported_inspection("/graph/proxy.dwg");
        let error = traverse_xref_dependencies_for_mutation(
            &proxy_root,
            None,
            &empty_search_paths(),
            &mut provider,
        )
        .unwrap_err();
        assert_eq!(
            error.code(),
            xref_failure_code::DEPENDENCY_TRAVERSAL_INCOMPLETE
        );

        let cycle_root = source(vec![attachment(
            "1",
            "SELF",
            "self.dwg",
            ReferenceType::Attachment,
        )]);
        let mut provider = FakeProvider::default();
        provider.resolve("/graph/self.dwg", "/alias/root.dwg", "root");
        let error = traverse_xref_dependencies_for_mutation(
            &cycle_root,
            None,
            &empty_search_paths(),
            &mut provider,
        )
        .unwrap_err();
        assert_eq!(error.code(), xref_failure_code::CIRCULAR_XREF);

        let overlay_root = source(vec![attachment(
            "1",
            "PARENT",
            "parent.dwg",
            ReferenceType::Attachment,
        )]);
        let mut provider = FakeProvider::default();
        provider.resolve("/graph/parent.dwg", "/graph/parent.dwg", "parent");
        provider.inspect(
            "/graph/parent.dwg",
            vec![attachment(
                "2",
                "EXCLUDED",
                "missing.dwg",
                ReferenceType::Overlay,
            )],
        );
        traverse_xref_dependencies_for_mutation(
            &overlay_root,
            None,
            &empty_search_paths(),
            &mut provider,
        )
        .unwrap();

        let mut provider = FakeProvider::default();
        provider.resolve("/graph/parent.dwg", "/graph/parent.dwg", "parent");
        provider.inspect(
            "/graph/parent.dwg",
            vec![attachment(
                "2",
                "CHILD",
                "child.dwg",
                ReferenceType::Attachment,
            )],
        );
        let truncated = traverse_xref_dependencies(
            &overlay_root,
            None,
            &empty_search_paths(),
            XrefTraversalLimits::try_new(0, 1).unwrap(),
            &mut provider,
        )
        .unwrap();
        let error = require_complete_dependency_graph_for_mutation(&truncated).unwrap_err();
        assert_eq!(
            error.code(),
            xref_failure_code::DEPENDENCY_TRAVERSAL_INCOMPLETE
        );
    }

    #[test]
    fn graph_boundaries_reject_invalid_attachment_and_record_invariants() {
        let invalid_root = attachment("0a", "BAD", "bad.dwg", ReferenceType::Attachment);
        let error = XrefGraphSource::from_filesystem_canonical_path(
            "/graph/root.dwg",
            identity("root"),
            vec![invalid_root],
        )
        .unwrap_err();
        assert_eq!(error.code(), xref_failure_code::UNSUPPORTED_XREF_DATA);

        let duplicate = attachment("A", "ONE", "one.dwg", ReferenceType::Attachment);
        let error = XrefGraphSource::from_filesystem_canonical_path(
            "/graph/root.dwg",
            identity("root"),
            vec![
                duplicate.clone(),
                attachment("A", "TWO", "two.dwg", ReferenceType::Attachment),
            ],
        )
        .unwrap_err();
        assert_eq!(error.code(), xref_failure_code::UNSUPPORTED_XREF_DATA);

        let resolution = XrefPathResolution::try_from_parts(
            XrefResolutionState::NotFound,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        for (chain, depth) in [
            (vec!["B".to_owned()], 0),
            (vec!["A".to_owned(), "B".to_owned()], 0),
            (vec!["0A".to_owned()], 0),
        ] {
            let error = dependency_record(
                chain,
                depth,
                CanonicalDisplayPath::from_filesystem_canonical_path("/graph/root.dwg").unwrap(),
                duplicate.clone(),
                XrefPropagationState::Root,
                &resolution,
                XrefInspectionState::NotResolved,
                None,
            )
            .unwrap_err();
            assert_eq!(error.code(), xref_failure_code::UNSUPPORTED_XREF_DATA);
        }

        let parent = source(vec![attachment(
            "1",
            "PARENT",
            "parent.dwg",
            ReferenceType::Attachment,
        )]);
        let mut provider = FakeProvider::default();
        provider.resolve("/graph/parent.dwg", "/graph/parent.dwg", "parent");
        provider.inspect(
            "/graph/parent.dwg",
            vec![attachment(
                "0b",
                "MALFORMED_CHILD",
                "child.dwg",
                ReferenceType::Attachment,
            )],
        );
        let error = traverse_xref_dependencies(
            &parent,
            None,
            &empty_search_paths(),
            XrefTraversalLimits::for_list(None, None).unwrap(),
            &mut provider,
        )
        .unwrap_err();
        assert_eq!(error.code(), xref_failure_code::UNSUPPORTED_XREF_DATA);
    }

    #[test]
    fn graph_fixture_descriptors_are_valid_and_document_every_required_family() {
        let descriptors = [
            include_str!("../../../../tests/fixtures/xrefs/graph/traversal.json"),
            include_str!("../../../../tests/fixtures/xrefs/graph/cycles-and-diamonds.json"),
            include_str!("../../../../tests/fixtures/xrefs/graph/states-and-limits.json"),
        ];
        let mut scenario_ids = Vec::new();
        for descriptor in descriptors {
            let value: serde_json::Value = serde_json::from_str(descriptor).unwrap();
            assert_eq!(value["descriptor_version"], 1);
            for scenario in value["scenarios"].as_array().unwrap() {
                scenario_ids.push(scenario["id"].as_str().unwrap().to_owned());
            }
        }
        for expected in [
            "numeric-depth-first-preorder",
            "direct-overlay-root",
            "terminal-nested-overlay",
            "root-self-cycle",
            "ancestor-cycle",
            "diamond-repeat",
            "terminal-source-states",
            "max-depth-first-truncation",
            "max-nodes-first-truncation",
        ] {
            assert!(scenario_ids.iter().any(|id| id == expected), "{expected}");
        }
    }
}
