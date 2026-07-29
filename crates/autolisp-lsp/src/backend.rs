use std::sync::Arc;
use tokio::sync::RwLock;
use tower_lsp::jsonrpc::Result as LspResult;
use tower_lsp::lsp_types::*;
use tower_lsp::{Client, LanguageServer};

use crate::document::{
    completions, diagnostics_for_text, hover_for_symbol, symbol_at_position, DocumentStore,
};
use crate::index::SymbolIndex;

pub struct Backend {
    client: Client,
    index: Arc<SymbolIndex>,
    docs: Arc<RwLock<DocumentStore>>,
}

impl Backend {
    pub fn new(client: Client, index: SymbolIndex) -> Self {
        Self {
            client,
            index: Arc::new(index),
            docs: Arc::new(RwLock::new(DocumentStore::default())),
        }
    }
}

#[tower_lsp::async_trait]
impl LanguageServer for Backend {
    async fn initialize(&self, _: InitializeParams) -> LspResult<InitializeResult> {
        Ok(InitializeResult {
            capabilities: ServerCapabilities {
                text_document_sync: Some(TextDocumentSyncCapability::Kind(
                    TextDocumentSyncKind::FULL,
                )),
                hover_provider: Some(HoverProviderCapability::Simple(true)),
                completion_provider: Some(CompletionOptions::default()),
                ..ServerCapabilities::default()
            },
            server_info: Some(ServerInfo {
                name: "autolisp-lsp".to_string(),
                version: Some(env!("CARGO_PKG_VERSION").to_string()),
            }),
        })
    }

    async fn initialized(&self, _: InitializedParams) {}

    async fn shutdown(&self) -> LspResult<()> {
        Ok(())
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        let uri = params.text_document.uri;
        let text = params.text_document.text;
        self.docs.write().await.open(uri.clone(), text.clone());
        self.client
            .publish_diagnostics(uri.clone(), diagnostics_for_text(&uri, &text), None)
            .await;
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        let uri = params.text_document.uri;
        let Some(text) = params
            .content_changes
            .into_iter()
            .last()
            .map(|change| change.text)
        else {
            return;
        };
        self.docs.write().await.change(uri.clone(), text.clone());
        self.client
            .publish_diagnostics(uri.clone(), diagnostics_for_text(&uri, &text), None)
            .await;
    }

    async fn hover(&self, params: HoverParams) -> LspResult<Option<Hover>> {
        let uri = params.text_document_position_params.text_document.uri;
        let position = params.text_document_position_params.position;
        let docs = self.docs.read().await;
        let Some(text) = docs.get(&uri) else {
            return Ok(None);
        };
        let Some(symbol) = symbol_at_position(text, position) else {
            return Ok(None);
        };
        Ok(hover_for_symbol(&self.index, &symbol))
    }

    async fn completion(&self, params: CompletionParams) -> LspResult<Option<CompletionResponse>> {
        let uri = params.text_document_position.text_document.uri;
        let position = params.text_document_position.position;
        let docs = self.docs.read().await;
        let prefix = docs
            .get(&uri)
            .and_then(|text| symbol_at_position(text, position))
            .unwrap_or_default();
        Ok(Some(CompletionResponse::Array(completions(
            &self.index,
            &prefix,
        ))))
    }
}
