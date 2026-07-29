use serde::Deserialize;
use std::error::Error;
use std::fmt;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct SymbolEntry {
    pub name: String,
    pub kind: SymbolKind,
    pub signature: String,
    pub summary: String,
    pub detail: Option<String>,
    pub source: String,
    pub completion: bool,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SymbolKind {
    Builtin,
    Command,
}

#[derive(Debug)]
pub enum IndexLoadError {
    Json(serde_json::Error),
    UnsupportedSchema(u32),
}

impl fmt::Display for IndexLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(err) => write!(f, "failed to parse LSP index JSON: {err}"),
            Self::UnsupportedSchema(version) => {
                write!(f, "unsupported LSP index schema version: {version}")
            }
        }
    }
}

impl Error for IndexLoadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Json(err) => Some(err),
            Self::UnsupportedSchema(_) => None,
        }
    }
}

impl From<serde_json::Error> for IndexLoadError {
    fn from(err: serde_json::Error) -> Self {
        Self::Json(err)
    }
}

#[derive(Debug, Clone, Deserialize)]
struct RawIndex {
    schema_version: u32,
    symbols: Vec<SymbolEntry>,
}

#[derive(Debug, Clone)]
pub struct SymbolIndex {
    symbols: Vec<SymbolEntry>,
}

impl SymbolIndex {
    pub fn load_embedded() -> Result<Self, IndexLoadError> {
        Self::from_json(include_str!(
            "../../../plugin/skills/autolisp/references/autolisp-lsp-index.json"
        ))
    }

    pub fn from_json(text: &str) -> Result<Self, IndexLoadError> {
        let raw: RawIndex = serde_json::from_str(text)?;
        if raw.schema_version != 1 {
            return Err(IndexLoadError::UnsupportedSchema(raw.schema_version));
        }
        Ok(Self {
            symbols: raw.symbols,
        })
    }

    pub fn get(&self, symbol: &str) -> Option<&SymbolEntry> {
        self.symbols
            .iter()
            .find(|entry| entry.name.eq_ignore_ascii_case(symbol))
    }

    pub fn completions_for_prefix(&self, prefix: &str) -> Vec<&SymbolEntry> {
        let prefix = prefix.to_ascii_lowercase();
        self.symbols
            .iter()
            .filter(|entry| {
                entry.completion && entry.name.to_ascii_lowercase().starts_with(&prefix)
            })
            .collect()
    }

    pub fn symbols(&self) -> &[SymbolEntry] {
        &self.symbols
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_index_loads() {
        let index = SymbolIndex::load_embedded().unwrap();
        assert!(index.symbols().len() >= 25);
    }

    #[test]
    fn embedded_index_contains_required_builtins() {
        let index = SymbolIndex::load_embedded().unwrap();
        assert_eq!(index.get("setq").unwrap().kind, SymbolKind::Builtin);
        assert_eq!(index.get("ssget").unwrap().kind, SymbolKind::Builtin);
    }

    #[test]
    fn unsupported_schema_returns_error() {
        let err = SymbolIndex::from_json(r#"{"schema_version":2,"symbols":[]}"#).unwrap_err();
        assert!(matches!(err, IndexLoadError::UnsupportedSchema(2)));
    }

    #[test]
    fn lookup_is_case_insensitive() {
        let index = SymbolIndex::load_embedded().unwrap();
        assert_eq!(index.get("SETQ").unwrap().name, "setq");
    }

    #[test]
    fn completion_matching_is_case_insensitive() {
        let index = SymbolIndex::load_embedded().unwrap();
        let names: Vec<&str> = index
            .completions_for_prefix("SS")
            .into_iter()
            .map(|entry| entry.name.as_str())
            .collect();
        assert!(names.contains(&"ssget"));
        assert!(names.contains(&"ssname"));
        assert!(names.contains(&"sslength"));
    }

    #[test]
    fn completion_matching_filters_non_completion_entries() {
        let index = SymbolIndex::from_json(
            r#"{
                "schema_version": 1,
                "symbols": [
                    {
                        "name": "sample-visible",
                        "kind": "builtin",
                        "signature": "(sample-visible)",
                        "summary": "Included.",
                        "detail": null,
                        "source": "test",
                        "completion": true
                    },
                    {
                        "name": "sample-hidden",
                        "kind": "builtin",
                        "signature": "(sample-hidden)",
                        "summary": "Filtered.",
                        "detail": null,
                        "source": "test",
                        "completion": false
                    }
                ]
            }"#,
        )
        .unwrap();
        let names: Vec<&str> = index
            .completions_for_prefix("sample-")
            .into_iter()
            .map(|entry| entry.name.as_str())
            .collect();
        assert_eq!(names, vec!["sample-visible"]);
    }
}
