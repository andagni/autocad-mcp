use autolisp_validate::{check_source, Severity};
use std::collections::BTreeMap;
use tower_lsp::lsp_types::{
    CompletionItem, CompletionItemKind, Diagnostic, DiagnosticSeverity, Hover, HoverContents,
    MarkedString, Position, Range, Url,
};

use crate::index::{SymbolEntry, SymbolIndex, SymbolKind};

#[derive(Default)]
pub struct DocumentStore {
    docs: BTreeMap<Url, String>,
}

impl DocumentStore {
    pub fn open(&mut self, uri: Url, text: String) {
        self.docs.insert(uri, text);
    }

    pub fn change(&mut self, uri: Url, text: String) {
        self.docs.insert(uri, text);
    }

    pub fn get(&self, uri: &Url) -> Option<&str> {
        self.docs.get(uri).map(String::as_str)
    }
}

pub fn symbol_at_position(text: &str, position: Position) -> Option<String> {
    let line = text.lines().nth(position.line as usize)?;
    let byte_at_position = byte_index_for_utf16_position(line, position.character);
    let mut start = byte_at_position.min(line.len());
    while start > 0 {
        let prev = line[..start].char_indices().next_back().unwrap();
        if is_symbol_char(prev.1) {
            start = prev.0;
        } else {
            break;
        }
    }
    let mut end = byte_at_position.min(line.len());
    while end < line.len() {
        let ch = line[end..].chars().next().unwrap();
        if is_symbol_char(ch) {
            end += ch.len_utf8();
        } else {
            break;
        }
    }
    (start < end).then(|| line[start..end].to_string())
}

fn is_symbol_char(ch: char) -> bool {
    !ch.is_whitespace() && !matches!(ch, '(' | ')' | '"' | ';' | '\'')
}

fn byte_index_for_utf16_position(line: &str, character: u32) -> usize {
    let target = character as usize;
    let mut utf16_units = 0usize;
    for (byte_idx, ch) in line.char_indices() {
        if utf16_units >= target {
            return byte_idx;
        }
        utf16_units += ch.len_utf16();
        if utf16_units > target {
            return byte_idx;
        }
    }
    line.len()
}

pub fn hover_for_symbol(index: &SymbolIndex, symbol: &str) -> Option<Hover> {
    let entry = index.get(symbol)?;
    let mut value = format!(
        "```lisp\n{}\n```\n\n{}\n\nSource: `{}`",
        entry.signature, entry.summary, entry.source
    );
    if let Some(detail) = &entry.detail {
        if !detail.is_empty() {
            value.push_str("\n\n");
            value.push_str(detail);
        }
    }
    Some(Hover {
        contents: HoverContents::Scalar(MarkedString::String(value)),
        range: None,
    })
}

pub fn completions(index: &SymbolIndex, prefix: &str) -> Vec<CompletionItem> {
    index
        .completions_for_prefix(prefix)
        .into_iter()
        .map(completion_item)
        .collect()
}

fn completion_item(entry: &SymbolEntry) -> CompletionItem {
    CompletionItem {
        label: entry.name.clone(),
        kind: Some(match entry.kind {
            SymbolKind::Builtin => CompletionItemKind::FUNCTION,
            SymbolKind::Command => CompletionItemKind::METHOD,
        }),
        detail: Some(entry.signature.clone()),
        documentation: Some(tower_lsp::lsp_types::Documentation::String(
            entry.summary.clone(),
        )),
        insert_text: Some(entry.name.clone()),
        ..CompletionItem::default()
    }
}

pub fn diagnostics_for_text(uri: &Url, text: &str) -> Vec<Diagnostic> {
    let report = check_source(text, uri.path());
    report
        .diagnostics
        .into_iter()
        .map(|diag| {
            let line = diag.line.saturating_sub(1) as u32;
            Diagnostic {
                range: Range {
                    start: Position { line, character: 0 },
                    end: Position { line, character: 1 },
                },
                severity: Some(match diag.severity {
                    Severity::Error => DiagnosticSeverity::ERROR,
                    Severity::Warning => DiagnosticSeverity::WARNING,
                }),
                source: Some("autolisp-validate".to_string()),
                message: diag.message,
                ..Diagnostic::default()
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_namespaced_symbol_at_position() {
        let text = "(sample:active-doc)\n";
        assert_eq!(
            symbol_at_position(
                text,
                Position {
                    line: 0,
                    character: 3
                }
            )
            .as_deref(),
            Some("sample:active-doc")
        );
    }

    #[test]
    fn extracts_symbol_after_non_bmp_unicode_using_lsp_utf16_position() {
        let text = "; 😀😀😀😀 prefix (setq value 1)\n";
        let prefix = "; 😀😀😀😀 prefix (se";
        let character = prefix.encode_utf16().count() as u32;
        assert_eq!(
            symbol_at_position(text, Position { line: 0, character }).as_deref(),
            Some("setq")
        );
    }

    #[test]
    fn extracts_symbols_with_common_autolisp_name_punctuation() {
        let text = "(foo.bar $state acad!helper)\n";
        assert_eq!(
            symbol_at_position(
                text,
                Position {
                    line: 0,
                    character: 5
                }
            )
            .as_deref(),
            Some("foo.bar")
        );
        assert_eq!(
            symbol_at_position(
                text,
                Position {
                    line: 0,
                    character: 10
                }
            )
            .as_deref(),
            Some("$state")
        );
        assert_eq!(
            symbol_at_position(
                text,
                Position {
                    line: 0,
                    character: 18
                }
            )
            .as_deref(),
            Some("acad!helper")
        );
    }

    #[test]
    fn document_store_opens_changes_and_gets_text() {
        let mut store = DocumentStore::default();
        let uri = Url::parse("file:///tmp/test.lsp").unwrap();
        let missing_uri = Url::parse("file:///tmp/missing.lsp").unwrap();

        assert_eq!(store.get(&missing_uri), None);

        store.open(uri.clone(), "(setq value 1)\n".to_string());
        assert_eq!(store.get(&uri), Some("(setq value 1)\n"));

        store.change(uri.clone(), "(setq value 2)\n".to_string());
        assert_eq!(store.get(&uri), Some("(setq value 2)\n"));
    }

    #[test]
    fn hover_for_known_symbol_contains_signature_and_source() {
        let index = SymbolIndex::load_embedded().unwrap();
        let hover = hover_for_symbol(&index, "setq").unwrap();
        let HoverContents::Scalar(MarkedString::String(value)) = hover.contents else {
            panic!("expected string hover");
        };
        assert!(value.contains("(setq symbol value"));
        assert!(value.contains("Source:"));
    }

    #[test]
    fn unknown_symbol_has_no_hover() {
        let index = SymbolIndex::load_embedded().unwrap();
        assert!(hover_for_symbol(&index, "not-a-real-symbol").is_none());
    }

    #[test]
    fn completions_are_prefix_matched() {
        let index = SymbolIndex::load_embedded().unwrap();
        let items = completions(&index, "ss");
        let labels: Vec<&str> = items.iter().map(|item| item.label.as_str()).collect();
        assert!(labels.contains(&"ssget"));
        assert!(labels.contains(&"ssname"));
        assert!(labels.contains(&"sslength"));
    }

    #[test]
    fn diagnostics_convert_validator_warning() {
        let uri = Url::parse("file:///tmp/test.lsp").unwrap();
        let diagnostics = diagnostics_for_text(&uri, "(let ((x 1)) x)\n");
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].severity, Some(DiagnosticSeverity::WARNING));
        assert_eq!(diagnostics[0].source.as_deref(), Some("autolisp-validate"));
    }
}
