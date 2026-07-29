use autolisp_lsp::backend::Backend;
use autolisp_lsp::index::SymbolIndex;
use tower_lsp::{LspService, Server};

#[tokio::main]
async fn main() {
    let index = match SymbolIndex::load_embedded() {
        Ok(index) => index,
        Err(e) => {
            eprintln!("ERROR: failed to load embedded AutoLISP LSP index: {e}");
            std::process::exit(1);
        }
    };

    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    let (service, socket) = LspService::new(|client| Backend::new(client, index.clone()));
    Server::new(stdin, stdout, socket).serve(service).await;
}
