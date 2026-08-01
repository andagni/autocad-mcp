use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use acadrust::CadDocument;

use super::backend;
use super::contract::{
    mutation_capabilities, AttachXref, AttachXrefResult, BindXref, BindXrefResult, CreateLayer,
    DeleteLayer, DeleteXrefInstance, DeleteXrefInstanceResult, DetachXref, DetachXrefResult,
    InsertXrefInstance, InsertXrefInstanceResult, LayerMutation, MutationCapability, MutationRoute,
    ReloadXref, ReloadXrefResult, RenameLayer, TitleBlockWrite, TitleBlockWriteResult, UnloadXref,
    UnloadXrefResult, UpdateLayer, UpdateXref, UpdateXrefInstance, UpdateXrefInstanceResult,
    UpdateXrefResult,
};
use super::title_blocks::TitleBlockPostcondition;
use super::{layers, title_blocks, xrefs, DrawingFormat, DrawingSnapshot, WriteError};

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
        let parsed = backend::parse(&snapshot)?;
        Ok(DrawingWriteSession {
            snapshot,
            document: parsed.document,
            #[cfg(feature = "preview")]
            source_dwg_preservation: parsed.dwg_preservation_seal,
            operation: None,
            postcondition: None,
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
    operation: Option<MutationRoute>,
    postcondition: Option<Postcondition>,
}

impl DrawingWriteSession {
    #[cfg(test)]
    pub(crate) fn from_document_for_test(format: DrawingFormat, document: CadDocument) -> Self {
        Self {
            snapshot: DrawingSnapshot::new(format, Vec::<u8>::new()),
            document,
            #[cfg(feature = "preview")]
            source_dwg_preservation: None,
            operation: None,
            postcondition: None,
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
        xrefs::attach(&request)
    }

    pub fn update_xref(&mut self, request: UpdateXref) -> Result<UpdateXrefResult, WriteError> {
        xrefs::update(&request)
    }

    pub fn detach_xref(&mut self, request: DetachXref) -> Result<DetachXrefResult, WriteError> {
        xrefs::detach(&request)
    }

    pub fn insert_xref_instance(
        &mut self,
        request: InsertXrefInstance,
    ) -> Result<InsertXrefInstanceResult, WriteError> {
        xrefs::insert_instance(&request)
    }

    pub fn update_xref_instance(
        &mut self,
        request: UpdateXrefInstance,
    ) -> Result<UpdateXrefInstanceResult, WriteError> {
        xrefs::update_instance(&request)
    }

    pub fn delete_xref_instance(
        &mut self,
        request: DeleteXrefInstance,
    ) -> Result<DeleteXrefInstanceResult, WriteError> {
        xrefs::delete_instance(&request)
    }

    pub fn reload_xref(&mut self, request: ReloadXref) -> Result<ReloadXrefResult, WriteError> {
        xrefs::reload(&request)
    }

    pub fn unload_xref(&mut self, request: UnloadXref) -> Result<UnloadXrefResult, WriteError> {
        xrefs::unload(&request)
    }

    pub fn bind_xref(&mut self, request: BindXref) -> Result<BindXrefResult, WriteError> {
        xrefs::bind(&request)
    }

    pub fn encode_candidate(&self) -> Result<RoundtripCandidate, WriteError> {
        let operation = self.operation.ok_or_else(|| {
            WriteError::invalid_request(
                "empty_mutation",
                "candidate generation requires one successful drawing mutation",
            )
        })?;
        #[cfg(feature = "preview")]
        if self.format() == DrawingFormat::Dwg && operation != MutationRoute::WriteTitleBlock {
            return Err(WriteError::backend_capability(
                "preview_dwg_route_not_qualified",
                "Preview DWG candidate generation is qualified only for title-block writes",
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
            _ => {
                return Err(WriteError::verification(
                    "unsupported_candidate_operation",
                    "operation and candidate postcondition do not match",
                ));
            }
        }

        let reparsed = backend::parse(&candidate_snapshot)?;
        match postcondition {
            Postcondition::Layer(expected) => {
                layers::verify(&reparsed.document, self.format(), expected)?;
            }
            Postcondition::TitleBlock(expected) => {
                title_blocks::verify(&reparsed.document, expected)?;
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
            operation_postconditions_verified: true,
            whole_document_preservation_verified,
            native_host_verified: false,
        };
        Ok(RoundtripCandidate { bytes, receipt })
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
