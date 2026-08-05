use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use acadrust::CadDocument;

use super::backend;
#[cfg(feature = "preview")]
use super::contract::dwg_preview_qualified_route;
use super::contract::{
    mutation_capabilities, AttachXref, AttachXrefResult, BindXref, BindXrefResult, CreateLayer,
    DeleteLayer, DeleteXrefInstance, DeleteXrefInstanceResult, DetachXref, DetachXrefResult,
    InsertXrefInstance, InsertXrefInstanceResult, LayerMutation, LoadState, MutationCapability,
    MutationRoute, ReloadXref, ReloadXrefResult, RenameLayer, TitleBlockWrite,
    TitleBlockWriteResult, UnloadXref, UnloadXrefResult, UpdateLayer, UpdateXref,
    UpdateXrefInstance, UpdateXrefInstanceResult, UpdateXrefResult,
};
use super::title_blocks::TitleBlockPostcondition;
use super::xref_handle_bridge::XrefHandleBridge;
use super::xref_reader_postconditions::ReaderVerification;
use super::{
    layers, title_blocks, xref_reader_postconditions, xrefs, DrawingFormat, DrawingSnapshot,
    WriteError,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoundtripClaimBoundary {
    DevelopmentEvidenceOnly,
    PreviewQualified,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoundtripReceipt {
    pub claim_boundary: RoundtripClaimBoundary,
    pub format: String,
    pub source_sha256: String,
    pub candidate_sha256: String,
    pub source_bytes: usize,
    pub candidate_bytes: usize,
    pub operations: Vec<MutationRoute>,
    pub reader_reopen_verified: bool,
    pub operation_postconditions_verified: bool,
    pub whole_document_preservation_verified: bool,
    pub native_host_verified: bool,
    /// Disclosed, non-blocking risks the backend could not rule out for this
    /// specific candidate (for example, an XREF request property acadrust
    /// 0.4.1 has no primitive to materialize). Empty for routes that carry no
    /// such disclosure.
    pub diagnostics: Vec<String>,
}

#[derive(Debug)]
pub struct RoundtripCandidate {
    bytes: Vec<u8>,
    receipt: RoundtripReceipt,
}

impl RoundtripCandidate {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn receipt(&self) -> &RoundtripReceipt {
        &self.receipt
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn into_parts(self) -> (Vec<u8>, RoundtripReceipt) {
        (self.bytes, self.receipt)
    }
}

enum Postcondition {
    Layer(LayerMutation),
    TitleBlock(TitleBlockPostcondition),
    Xref(xrefs::XrefPostcondition),
}

/// XREF routes acadrust 0.4.1 has no primitive to materialize at all. These
/// stay hard-blocked exactly as before this integration: unlike the six real
/// XREF mutation routes below (which have a dedicated handle-bridge and
/// postcondition-verification story), reload/unload/bind would otherwise
/// silently accept a request and report best-effort, unverifiable results.
/// Relaxing that is a distinct, disclosed-risk product decision left for a
/// separate change.
fn blocked_xref_route(route: MutationRoute) -> WriteError {
    let code = match route {
        MutationRoute::ReloadXref | MutationRoute::UnloadXref => "xref_load_state_not_preserved",
        MutationRoute::BindXref => "xref_graph_import_unavailable",
        _ => unreachable!("blocked_xref_route is only called for load-state/bind routes"),
    };
    WriteError::backend_capability(
        code,
        "the selected writer backend cannot preserve the invariants required by this XREF mutation",
    )
    .with_internal_detail(match route {
        MutationRoute::ReloadXref | MutationRoute::UnloadXref => {
            "acadrust 0.4.1 drops XREF load state and writes every R2000+ XREF as unloaded"
        }
        MutationRoute::BindXref => {
            "acadrust 0.4.1 has no complete graph-import and handle-remapping primitive"
        }
        _ => unreachable!("blocked_xref_route is only called for load-state/bind routes"),
    })
}

pub struct Writer;

impl Writer {
    pub fn open_path(path: &Path) -> Result<DrawingWriteSession, WriteError> {
        Self::open_path_with_capture(path, |captured_path| std::fs::read(captured_path))
    }

    fn open_path_with_capture(
        path: &Path,
        capture: impl FnOnce(&Path) -> std::io::Result<Vec<u8>>,
    ) -> Result<DrawingWriteSession, WriteError> {
        let format = DrawingFormat::from_path(path)?;
        let bytes = capture(path).map_err(WriteError::capture)?;
        Self::open_snapshot(DrawingSnapshot::new(format, bytes))
    }

    pub fn open_snapshot(snapshot: DrawingSnapshot) -> Result<DrawingWriteSession, WriteError> {
        let mut parsed = backend::parse(&snapshot)?;
        let xref_handle_bridge = XrefHandleBridge::from_source(&snapshot, &mut parsed.document)?;
        Ok(DrawingWriteSession {
            snapshot,
            document: parsed.document,
            #[cfg(feature = "preview")]
            source_dwg_preservation: parsed.dwg_preservation_seal,
            xref_handle_bridge,
            xref_load_states: BTreeMap::new(),
            operation: None,
            postcondition: None,
            mutation_diagnostics: Vec::new(),
        })
    }

    pub fn mutation_capabilities() -> Vec<MutationCapability> {
        mutation_capabilities()
    }
}

/// One privately decoded drawing capture and at most one planned mutation.
///
/// One-operation sessions align the candidate and receipt with one public MCP
/// tool invocation and keep its allowed-delta proof unambiguous.
pub struct DrawingWriteSession {
    snapshot: DrawingSnapshot,
    document: CadDocument,
    #[cfg(feature = "preview")]
    source_dwg_preservation: Option<backend::DwgPreservationSeal>,
    xref_handle_bridge: XrefHandleBridge,
    xref_load_states: BTreeMap<String, LoadState>,
    operation: Option<MutationRoute>,
    postcondition: Option<Postcondition>,
    mutation_diagnostics: Vec<String>,
}

impl DrawingWriteSession {
    #[cfg(test)]
    pub(crate) fn from_document_for_test(format: DrawingFormat, document: CadDocument) -> Self {
        let xref_handle_bridge = XrefHandleBridge::identity(&document);
        Self {
            snapshot: DrawingSnapshot::new(format, Vec::<u8>::new()),
            document,
            #[cfg(feature = "preview")]
            source_dwg_preservation: None,
            xref_handle_bridge,
            xref_load_states: BTreeMap::new(),
            operation: None,
            postcondition: None,
            mutation_diagnostics: Vec::new(),
        }
    }

    pub fn format(&self) -> DrawingFormat {
        self.snapshot.format()
    }

    fn ensure_empty(&self) -> Result<(), WriteError> {
        if self.operation.is_some() {
            return Err(WriteError::invalid_request(
                "multiple_mutations_unsupported",
                "a writer session accepts exactly one drawing mutation",
            ));
        }
        Ok(())
    }

    /// The six real XREF mutation routes' handle-bridge and postcondition
    /// verification is proven only for native AC1032 DWG and, for ASCII DXF,
    /// exactly AC1032/`ANSI_1252` (matching the DWG-equivalent tuple the
    /// bridge was built and tested against). DWG sources already get this
    /// for free from `backend::admit_dwg_encode`; ASCII DXF has no such
    /// version/code-page check in the generic admission path, so it is
    /// enforced here, scoped to only these six routes.
    fn ensure_xref_ascii_dxf_source_qualified(&self) -> Result<(), WriteError> {
        if self.format() != DrawingFormat::Dxf {
            return Ok(());
        }
        if self.document.version != acadrust::types::DxfVersion::AC1032
            || self.document.header.code_page != "ANSI_1252"
        {
            return Err(WriteError::unsupported_source(
                "unsupported_format",
                "XREF mutation routes admit only AC1032 ASCII DXF with the ANSI_1252 code page",
            ));
        }
        Ok(())
    }

    pub fn create_layer(&mut self, request: CreateLayer) -> Result<LayerMutation, WriteError> {
        self.ensure_empty()?;
        let format = self.format();
        let mut document = self.document.clone();
        let mutation = layers::create(&mut document, format, &request)?;
        self.document = document;
        self.operation = Some(MutationRoute::CreateLayer);
        self.postcondition = Some(Postcondition::Layer(mutation.clone()));
        Ok(mutation)
    }

    pub fn update_layer(&mut self, request: UpdateLayer) -> Result<LayerMutation, WriteError> {
        self.ensure_empty()?;
        let format = self.format();
        let mut document = self.document.clone();
        let mutation = layers::update(&mut document, format, &request)?;
        self.document = document;
        self.operation = Some(MutationRoute::UpdateLayer);
        self.postcondition = Some(Postcondition::Layer(mutation.clone()));
        Ok(mutation)
    }

    pub fn rename_layer(&mut self, request: RenameLayer) -> Result<LayerMutation, WriteError> {
        self.ensure_empty()?;
        let format = self.format();
        let mut document = self.document.clone();
        let mutation = layers::rename(&mut document, format, &request)?;
        self.document = document;
        self.operation = Some(MutationRoute::RenameLayer);
        self.postcondition = Some(Postcondition::Layer(mutation.clone()));
        Ok(mutation)
    }

    pub fn delete_layer(&mut self, request: DeleteLayer) -> Result<LayerMutation, WriteError> {
        self.ensure_empty()?;
        let mut document = self.document.clone();
        let mutation = layers::delete(&mut document, &request)?;
        self.document = document;
        self.operation = Some(MutationRoute::DeleteLayer);
        self.postcondition = Some(Postcondition::Layer(mutation.clone()));
        Ok(mutation)
    }

    pub fn write_title_block(
        &mut self,
        request: TitleBlockWrite,
    ) -> Result<TitleBlockWriteResult, WriteError> {
        self.ensure_empty()?;
        let mut document = self.document.clone();
        let (result, postcondition) = title_blocks::write(&mut document, &request)?;
        self.document = document;
        self.operation = Some(MutationRoute::WriteTitleBlock);
        self.postcondition = Some(Postcondition::TitleBlock(postcondition));
        Ok(result)
    }

    pub fn attach_xref(&mut self, request: AttachXref) -> Result<AttachXrefResult, WriteError> {
        self.ensure_empty()?;
        self.ensure_xref_ascii_dxf_source_qualified()?;
        let mut document = self.document.clone();
        let mut load_states = self.xref_load_states.clone();
        let mutation = xrefs::attach(
            &mut document,
            self.format(),
            &mut load_states,
            &self.xref_handle_bridge,
            &request,
        )?;
        self.document = document;
        self.xref_load_states = load_states;
        self.operation = Some(MutationRoute::AttachXref);
        self.postcondition = Some(Postcondition::Xref(mutation.postcondition));
        self.mutation_diagnostics = mutation.diagnostics;
        Ok(mutation.result)
    }

    pub fn update_xref(&mut self, request: UpdateXref) -> Result<UpdateXrefResult, WriteError> {
        self.ensure_empty()?;
        self.ensure_xref_ascii_dxf_source_qualified()?;
        let mut document = self.document.clone();
        let mut load_states = self.xref_load_states.clone();
        let mutation = xrefs::update(
            &mut document,
            self.format(),
            &mut load_states,
            &self.xref_handle_bridge,
            &request,
        )?;
        self.document = document;
        self.xref_load_states = load_states;
        self.operation = Some(MutationRoute::UpdateXref);
        self.postcondition = Some(Postcondition::Xref(mutation.postcondition));
        self.mutation_diagnostics = mutation.diagnostics;
        Ok(mutation.result)
    }

    pub fn detach_xref(&mut self, request: DetachXref) -> Result<DetachXrefResult, WriteError> {
        self.ensure_empty()?;
        self.ensure_xref_ascii_dxf_source_qualified()?;
        let mut document = self.document.clone();
        let mut load_states = self.xref_load_states.clone();
        let mutation = xrefs::detach(
            &mut document,
            self.format(),
            &mut load_states,
            &self.xref_handle_bridge,
            &request,
        )?;
        self.document = document;
        self.xref_load_states = load_states;
        self.operation = Some(MutationRoute::DetachXref);
        self.postcondition = Some(Postcondition::Xref(mutation.postcondition));
        self.mutation_diagnostics = mutation.diagnostics;
        Ok(mutation.result)
    }

    pub fn insert_xref_instance(
        &mut self,
        request: InsertXrefInstance,
    ) -> Result<InsertXrefInstanceResult, WriteError> {
        self.ensure_empty()?;
        self.ensure_xref_ascii_dxf_source_qualified()?;
        let mut document = self.document.clone();
        let mutation = xrefs::insert_instance(
            &mut document,
            self.format(),
            &self.xref_handle_bridge,
            &request,
        )?;
        self.document = document;
        self.operation = Some(MutationRoute::InsertXrefInstance);
        self.postcondition = Some(Postcondition::Xref(mutation.postcondition));
        self.mutation_diagnostics = mutation.diagnostics;
        Ok(mutation.result)
    }

    pub fn update_xref_instance(
        &mut self,
        request: UpdateXrefInstance,
    ) -> Result<UpdateXrefInstanceResult, WriteError> {
        self.ensure_empty()?;
        self.ensure_xref_ascii_dxf_source_qualified()?;
        let mut document = self.document.clone();
        let mutation = xrefs::update_instance(
            &mut document,
            self.format(),
            &self.xref_handle_bridge,
            &request,
        )?;
        self.document = document;
        self.operation = Some(MutationRoute::UpdateXrefInstance);
        self.postcondition = Some(Postcondition::Xref(mutation.postcondition));
        self.mutation_diagnostics = mutation.diagnostics;
        Ok(mutation.result)
    }

    pub fn delete_xref_instance(
        &mut self,
        request: DeleteXrefInstance,
    ) -> Result<DeleteXrefInstanceResult, WriteError> {
        self.ensure_empty()?;
        self.ensure_xref_ascii_dxf_source_qualified()?;
        let mut document = self.document.clone();
        let mutation = xrefs::delete_instance(
            &mut document,
            self.format(),
            &self.xref_handle_bridge,
            &request,
        )?;
        self.document = document;
        self.operation = Some(MutationRoute::DeleteXrefInstance);
        self.postcondition = Some(Postcondition::Xref(mutation.postcondition));
        self.mutation_diagnostics = mutation.diagnostics;
        Ok(mutation.result)
    }

    pub fn reload_xref(&mut self, _request: ReloadXref) -> Result<ReloadXrefResult, WriteError> {
        Err(blocked_xref_route(MutationRoute::ReloadXref))
    }

    pub fn unload_xref(&mut self, _request: UnloadXref) -> Result<UnloadXrefResult, WriteError> {
        Err(blocked_xref_route(MutationRoute::UnloadXref))
    }

    pub fn bind_xref(&mut self, _request: BindXref) -> Result<BindXrefResult, WriteError> {
        Err(blocked_xref_route(MutationRoute::BindXref))
    }

    pub fn encode_candidate(&self) -> Result<RoundtripCandidate, WriteError> {
        let operation = self.operation.ok_or_else(|| {
            WriteError::invalid_request(
                "empty_mutation",
                "candidate generation requires one successful drawing mutation",
            )
        })?;
        #[cfg(feature = "preview")]
        if self.format() == DrawingFormat::Dwg && !dwg_preview_qualified_route(operation) {
            return Err(WriteError::backend_capability(
                "preview_dwg_route_not_qualified",
                "Preview DWG candidate generation is qualified only for title-block writes and \
                 the six proven XREF mutation routes",
            ));
        }
        let bytes = backend::encode(self.format(), &self.document)?;
        let candidate_snapshot = DrawingSnapshot::new(self.format(), bytes.clone());
        let candidate_reader = autocad_reader::Reader::open_snapshot(
            candidate_snapshot.reader_snapshot(),
        )
        .map_err(|_| {
            WriteError::verification(
                "candidate_reader_reopen_failed",
                "independent reader boundary rejected the encoded candidate",
            )
        })?;
        let postcondition = self
            .postcondition
            .as_ref()
            .expect("successful operation stores a postcondition");
        match (operation, postcondition) {
            (
                MutationRoute::CreateLayer
                | MutationRoute::UpdateLayer
                | MutationRoute::RenameLayer
                | MutationRoute::DeleteLayer,
                Postcondition::Layer(expected),
            ) => layers::verify_reader(&candidate_reader, expected)?,
            (MutationRoute::WriteTitleBlock, Postcondition::TitleBlock(expected)) => {
                title_blocks::verify_reader(&candidate_reader, expected)?
            }
            (
                MutationRoute::AttachXref
                | MutationRoute::UpdateXref
                | MutationRoute::DetachXref
                | MutationRoute::InsertXrefInstance
                | MutationRoute::UpdateXrefInstance
                | MutationRoute::DeleteXrefInstance,
                Postcondition::Xref(expected),
            ) => match xref_reader_postconditions::verify(&candidate_reader, expected)? {
                ReaderVerification::Verified => {}
                ReaderVerification::Unavailable { reason_code } => {
                    return Err(WriteError::verification(
                        "xref_postcondition_unavailable",
                        "independent reader projection could not observe this XREF mutation's \
                         postcondition",
                    )
                    .with_internal_detail(reason_code));
                }
            },
            _ => {
                return Err(WriteError::verification(
                    "unsupported_candidate_operation",
                    "operation and candidate postcondition do not match",
                ));
            }
        }

        let mut reparsed = backend::parse(&candidate_snapshot)?;
        // acadrust's ASCII-DXF (and, for some routes, DWG) serialization does
        // not reliably round-trip a freshly changed XREF block record's
        // reverse INSERT-handle index -- a real backend limitation, not a
        // bug here. `XrefHandleBridge::verify_candidate` reports that one
        // specific condition as `candidate_xref_reverse_index_unobservable_
        // by_acadrust`; everything else it reports is a real contradiction.
        // The independent-reader postcondition check above already ran and
        // succeeded regardless, so this downgrades to "not confirmed by a
        // second, backend-reparse proof" rather than failing the candidate
        // outright -- `xrefs::verify` (which depends on that reparsed
        // document being trustworthy) is skipped in that case, exactly as
        // it is on the pre-integration implementation this was ported from.
        let mut backend_postcondition_verified = true;
        if matches!(postcondition, Postcondition::Xref(_)) {
            match XrefHandleBridge::verify_candidate(&candidate_snapshot, &mut reparsed.document) {
                Ok(_) => {}
                Err(error)
                    if error.code() == "candidate_xref_reverse_index_unobservable_by_acadrust" =>
                {
                    backend_postcondition_verified = false;
                }
                Err(error) => return Err(error),
            }
        }
        if backend_postcondition_verified {
            match postcondition {
                Postcondition::Layer(expected) => {
                    layers::verify(&reparsed.document, self.format(), expected)?;
                }
                Postcondition::TitleBlock(expected) => {
                    title_blocks::verify(&reparsed.document, expected)?;
                }
                Postcondition::Xref(expected) => {
                    xrefs::verify(&reparsed.document, expected).map_err(|code| {
                        WriteError::verification(
                            "xref_postcondition_contradicted",
                            "encoded candidate does not satisfy the requested XREF mutation's \
                             postcondition",
                        )
                        .with_internal_detail(code)
                    })?;
                }
            }
        }

        #[cfg(feature = "preview")]
        let whole_document_preservation_verified =
            if self.format() == DrawingFormat::Dwg && operation == MutationRoute::WriteTitleBlock {
                let source = self.source_dwg_preservation.as_ref().ok_or_else(|| {
                    WriteError::verification(
                        "preview_dwg_source_seal_missing",
                        "locked source has no DWG preservation seal",
                    )
                })?;
                backend::verify_dwg_title_block_preservation(
                    source,
                    &self.document,
                    &candidate_snapshot,
                    &reparsed.document,
                )?;
                true
            } else {
                false
            };
        #[cfg(not(feature = "preview"))]
        let whole_document_preservation_verified = false;

        let source = self.snapshot.bytes();
        // Only mutated by the `#[cfg(feature = "preview")]` block below.
        #[cfg_attr(not(feature = "preview"), allow(unused_mut))]
        let mut diagnostics = if matches!(postcondition, Postcondition::Xref(_)) {
            self.mutation_diagnostics.clone()
        } else {
            Vec::new()
        };
        // Preview builds relax `admit_dwg_encode`'s GeoData/VisualStyle/
        // Material/TableStyle refusals so encode can proceed -- see the
        // matching `backend::has_unwritable_dwg_*` predicates -- but that
        // relaxation must never be silent: record each as a risk diagnostic
        // on every affected candidate, regardless of which route produced it.
        #[cfg(feature = "preview")]
        if self.format() == DrawingFormat::Dwg {
            if backend::has_unwritable_dwg_geodata(&self.document) {
                diagnostics
                    .push("dwg_geodata_object_will_be_dropped_by_acadrust_writer".to_string());
            }
            if backend::has_unwritable_dwg_visual_style(&self.document) {
                diagnostics
                    .push("dwg_visual_style_object_will_be_dropped_by_acadrust_writer".to_string());
            }
            if backend::has_unwritable_dwg_material(&self.document) {
                diagnostics
                    .push("dwg_material_object_will_be_dropped_by_acadrust_writer".to_string());
            }
            if backend::has_unwritable_dwg_table_style(&self.document) {
                diagnostics
                    .push("dwg_table_style_object_will_be_dropped_by_acadrust_writer".to_string());
            }
        }
        let receipt = RoundtripReceipt {
            claim_boundary: if whole_document_preservation_verified {
                RoundtripClaimBoundary::PreviewQualified
            } else {
                RoundtripClaimBoundary::DevelopmentEvidenceOnly
            },
            format: self.format().name().to_string(),
            source_sha256: sha256(&source),
            candidate_sha256: sha256(&bytes),
            source_bytes: source.len(),
            candidate_bytes: bytes.len(),
            operations: vec![operation],
            reader_reopen_verified: true,
            operation_postconditions_verified: backend_postcondition_verified,
            whole_document_preservation_verified,
            native_host_verified: false,
            diagnostics,
        };
        Ok(RoundtripCandidate { bytes, receipt })
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
