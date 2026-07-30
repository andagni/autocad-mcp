use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use proc_macro2::{TokenStream, TokenTree};
use sha2::{Digest, Sha256};
use syn::ext::IdentExt;
use syn::parse::Parser;
use syn::punctuated::Punctuated;
use syn::visit::{self, Visit};
use syn::{Attribute, Expr, Item, Meta, Token, UseTree};
use walkdir::WalkDir;

const PROJECT_LICENSE: &str = "GPL-3.0-or-later";
const CANONICAL_GPLV3_SHA256: &str =
    "3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986";
const WINDOWS_XREF_WORKFLOW_SHA256: &str =
    "54c1d868f130d93270fc07c53df6c28ee4465878070b9603c0cbba69c4161db1";
const WINDOWS_NATIVE_HARNESS_WORKFLOW_SHA256: &str =
    "5c4578575f0aed1266322a67d8fc362bd2ff578948f5c483dd1d9dfeb48412b3";
const WINDOWS_PREVIEW_REVIEW_WORKFLOW_SHA256: &str =
    "b247c7c233c58ba997d0a63664adab8d057e0f80721e042705da777ef7da8709";
const MCPB_VALIDATOR_PACKAGE_SHA256: &str =
    "ff8efca13765d492da22711f73935d09f95871dfa30d2275844f6ec182956240";
const MCPB_VALIDATOR_LOCK_SHA256: &str =
    "a5a19b3a1c767ac109cf7deebf2a41fbf77810444d21bb09e6c6004cc36deefb";
const PUBLIC_DEVELOPMENT_ARG_SHA256: &str =
    "77c7bcf316b2a5bac231eef67c3acd52954a13bcd74b3eb10466ffd979443e95";
const PUBLIC_DEVELOPMENT_ARG_POLICY_SHA256: &str =
    "f937351b66e4fd2f421f8bdb8e58370e69d7a6e4f896352cf8da1f13209cb2a4";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate must be inside the workspace")
        .to_path_buf()
}

const READER_ESCAPE_IDENTIFIERS: [&str; 3] = [
    "open_legacy_read_document",
    "open_legacy_read_snapshot",
    "open_drawing",
];

#[derive(Clone, Copy)]
struct TruthPossibility {
    can_be_true: bool,
    can_be_false: bool,
}

impl TruthPossibility {
    const UNKNOWN: Self = Self {
        can_be_true: true,
        can_be_false: true,
    };
}

fn normalized_identifier(identifier: &proc_macro2::Ident) -> String {
    identifier.unraw().to_string()
}

fn path_is_identifier(path: &syn::Path, expected: &str) -> bool {
    path.get_ident()
        .is_some_and(|identifier| normalized_identifier(identifier) == expected)
}

fn nested_cfg_predicates(list: &syn::MetaList) -> Option<Vec<Meta>> {
    Punctuated::<Meta, Token![,]>::parse_terminated
        .parse2(list.tokens.clone())
        .ok()
        .map(|predicates| predicates.into_iter().collect())
}

fn cfg_truth_when_test_is_false(predicate: &Meta) -> TruthPossibility {
    match predicate {
        Meta::Path(path) if path_is_identifier(path, "test") => TruthPossibility {
            can_be_true: false,
            can_be_false: true,
        },
        Meta::Path(_) | Meta::NameValue(_) => TruthPossibility::UNKNOWN,
        Meta::List(list) if path_is_identifier(&list.path, "all") => {
            let Some(predicates) = nested_cfg_predicates(list) else {
                return TruthPossibility::UNKNOWN;
            };
            TruthPossibility {
                can_be_true: predicates
                    .iter()
                    .all(|predicate| cfg_truth_when_test_is_false(predicate).can_be_true),
                can_be_false: predicates
                    .iter()
                    .any(|predicate| cfg_truth_when_test_is_false(predicate).can_be_false),
            }
        }
        Meta::List(list) if path_is_identifier(&list.path, "any") => {
            let Some(predicates) = nested_cfg_predicates(list) else {
                return TruthPossibility::UNKNOWN;
            };
            TruthPossibility {
                can_be_true: predicates
                    .iter()
                    .any(|predicate| cfg_truth_when_test_is_false(predicate).can_be_true),
                can_be_false: predicates
                    .iter()
                    .all(|predicate| cfg_truth_when_test_is_false(predicate).can_be_false),
            }
        }
        Meta::List(list) if path_is_identifier(&list.path, "not") => {
            let Some(predicates) = nested_cfg_predicates(list) else {
                return TruthPossibility::UNKNOWN;
            };
            if let [predicate] = predicates.as_slice() {
                let operand = cfg_truth_when_test_is_false(predicate);
                TruthPossibility {
                    can_be_true: operand.can_be_false,
                    can_be_false: operand.can_be_true,
                }
            } else {
                TruthPossibility::UNKNOWN
            }
        }
        Meta::List(_) => TruthPossibility::UNKNOWN,
    }
}

fn attributes_require_test(attributes: &[Attribute]) -> bool {
    attributes
        .iter()
        .filter(|attribute| path_is_identifier(attribute.path(), "cfg"))
        .filter_map(|attribute| attribute.parse_args::<Meta>().ok())
        .any(|predicate| !cfg_truth_when_test_is_false(&predicate).can_be_true)
}

fn item_attributes(item: &Item) -> &[Attribute] {
    match item {
        Item::Const(item) => &item.attrs,
        Item::Enum(item) => &item.attrs,
        Item::ExternCrate(item) => &item.attrs,
        Item::Fn(item) => &item.attrs,
        Item::ForeignMod(item) => &item.attrs,
        Item::Impl(item) => &item.attrs,
        Item::Macro(item) => &item.attrs,
        Item::Mod(item) => &item.attrs,
        Item::Static(item) => &item.attrs,
        Item::Struct(item) => &item.attrs,
        Item::Trait(item) => &item.attrs,
        Item::TraitAlias(item) => &item.attrs,
        Item::Type(item) => &item.attrs,
        Item::Union(item) => &item.attrs,
        Item::Use(item) => &item.attrs,
        Item::Verbatim(_) => &[],
        _ => &[],
    }
}

fn escape_identifier(identifier: &str) -> Option<&'static str> {
    READER_ESCAPE_IDENTIFIERS
        .iter()
        .copied()
        .find(|candidate| *candidate == identifier)
}

#[derive(Debug, Default)]
struct RustSourceFacts {
    identifier_counts: BTreeMap<String, usize>,
    type_definitions: Vec<String>,
    function_definitions: Vec<String>,
    path_references: BTreeSet<String>,
    escape_direct_calls: BTreeMap<&'static str, usize>,
    escape_non_call_references: BTreeMap<&'static str, usize>,
}

impl RustSourceFacts {
    fn record_identifier(&mut self, identifier: &str) {
        *self
            .identifier_counts
            .entry(identifier.to_string())
            .or_default() += 1;
    }

    fn identifier_count(&self, identifier: &str) -> usize {
        self.identifier_counts
            .get(identifier)
            .copied()
            .unwrap_or_default()
    }

    fn has_identifier(&self, identifier: &str) -> bool {
        self.identifier_count(identifier) > 0
    }
}

struct ProductionFactsVisitor {
    facts: RustSourceFacts,
    skip_test_items: bool,
    direct_call_callee: Option<(*const syn::Path, &'static str)>,
}

impl ProductionFactsVisitor {
    fn new(skip_test_items: bool) -> Self {
        Self {
            facts: RustSourceFacts::default(),
            skip_test_items,
            direct_call_callee: None,
        }
    }

    fn record_escape_reference(&mut self, identifier: &str) {
        if let Some(identifier) = escape_identifier(identifier) {
            *self
                .facts
                .escape_non_call_references
                .entry(identifier)
                .or_default() += 1;
        }
    }

    fn record_token_stream(&mut self, stream: TokenStream) {
        for token in stream {
            match token {
                TokenTree::Group(group) => self.record_token_stream(group.stream()),
                TokenTree::Ident(identifier) => {
                    let identifier = normalized_identifier(&identifier);
                    self.facts.record_identifier(&identifier);
                    self.record_escape_reference(&identifier);
                }
                TokenTree::Punct(_) | TokenTree::Literal(_) => {}
            }
        }
    }

    fn record_use_tree_escape_references(&mut self, tree: &UseTree) {
        match tree {
            UseTree::Path(path) => {
                self.record_escape_reference(&normalized_identifier(&path.ident));
                self.record_use_tree_escape_references(&path.tree);
            }
            UseTree::Name(name) => {
                self.record_escape_reference(&normalized_identifier(&name.ident));
            }
            UseTree::Rename(rename) => {
                self.record_escape_reference(&normalized_identifier(&rename.ident));
            }
            UseTree::Group(group) => {
                for tree in &group.items {
                    self.record_use_tree_escape_references(tree);
                }
            }
            UseTree::Glob(_) => {}
        }
    }

    fn record_use_tree_paths(&mut self, tree: &UseTree, prefix: &[String]) {
        match tree {
            UseTree::Path(path) => {
                let mut path_prefix = prefix.to_vec();
                path_prefix.push(normalized_identifier(&path.ident));
                self.record_use_tree_paths(&path.tree, &path_prefix);
            }
            UseTree::Name(name) => {
                let mut path = prefix.to_vec();
                path.push(normalized_identifier(&name.ident));
                self.facts.path_references.insert(path.join("::"));
            }
            UseTree::Rename(rename) => {
                let mut path = prefix.to_vec();
                path.push(normalized_identifier(&rename.ident));
                self.facts.path_references.insert(path.join("::"));
            }
            UseTree::Glob(_) => {
                self.facts.path_references.insert(prefix.join("::"));
            }
            UseTree::Group(group) => {
                for tree in &group.items {
                    self.record_use_tree_paths(tree, prefix);
                }
            }
        }
    }
}

impl<'ast> Visit<'ast> for ProductionFactsVisitor {
    fn visit_item(&mut self, item: &'ast Item) {
        if self.skip_test_items && attributes_require_test(item_attributes(item)) {
            return;
        }
        if let Item::Verbatim(tokens) = item {
            self.record_token_stream(tokens.clone());
            return;
        }
        visit::visit_item(self, item);
    }

    fn visit_ident(&mut self, identifier: &'ast proc_macro2::Ident) {
        self.facts
            .record_identifier(&normalized_identifier(identifier));
    }

    fn visit_item_struct(&mut self, item: &'ast syn::ItemStruct) {
        self.facts
            .type_definitions
            .push(normalized_identifier(&item.ident));
        visit::visit_item_struct(self, item);
    }

    fn visit_item_enum(&mut self, item: &'ast syn::ItemEnum) {
        self.facts
            .type_definitions
            .push(normalized_identifier(&item.ident));
        visit::visit_item_enum(self, item);
    }

    fn visit_item_union(&mut self, item: &'ast syn::ItemUnion) {
        self.facts
            .type_definitions
            .push(normalized_identifier(&item.ident));
        visit::visit_item_union(self, item);
    }

    fn visit_item_type(&mut self, item: &'ast syn::ItemType) {
        self.facts
            .type_definitions
            .push(normalized_identifier(&item.ident));
        visit::visit_item_type(self, item);
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        self.facts
            .function_definitions
            .push(normalized_identifier(&item.sig.ident));
        visit::visit_item_fn(self, item);
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        self.record_use_tree_escape_references(&item.tree);
        self.record_use_tree_paths(&item.tree, &[]);
        visit::visit_item_use(self, item);
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        self.facts.path_references.insert(
            path.segments
                .iter()
                .map(|segment| normalized_identifier(&segment.ident))
                .collect::<Vec<_>>()
                .join("::"),
        );
        let path_pointer = path as *const syn::Path;
        let final_segment = path
            .segments
            .last()
            .map(|segment| normalized_identifier(&segment.ident));
        for segment in &path.segments {
            let identifier = normalized_identifier(&segment.ident);
            if let Some(identifier) = escape_identifier(&identifier) {
                let is_direct_callee =
                    self.direct_call_callee
                        .is_some_and(|(allowed_path, allowed_identifier)| {
                            std::ptr::eq(allowed_path, path_pointer)
                                && allowed_identifier == identifier
                                && final_segment.as_deref() == Some(identifier)
                        });
                if !is_direct_callee {
                    *self
                        .facts
                        .escape_non_call_references
                        .entry(identifier)
                        .or_default() += 1;
                }
            }
        }
        visit::visit_path(self, path);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        let direct_escape = match call.func.as_ref() {
            Expr::Path(expression) => expression
                .path
                .segments
                .last()
                .and_then(|segment| escape_identifier(&normalized_identifier(&segment.ident)))
                .map(|identifier| (&expression.path as *const syn::Path, identifier)),
            _ => None,
        };
        if let Some((path, identifier)) = direct_escape {
            *self
                .facts
                .escape_direct_calls
                .entry(identifier)
                .or_default() += 1;
            let previous = self.direct_call_callee.replace((path, identifier));
            self.visit_expr(call.func.as_ref());
            self.direct_call_callee = previous;
        } else {
            self.visit_expr(call.func.as_ref());
        }
        for argument in &call.args {
            self.visit_expr(argument);
        }
        for attribute in &call.attrs {
            self.visit_attribute(attribute);
        }
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        self.record_token_stream(mac.tokens.clone());
        visit::visit_macro(self, mac);
    }

    fn visit_meta_list(&mut self, meta: &'ast syn::MetaList) {
        self.record_token_stream(meta.tokens.clone());
        visit::visit_meta_list(self, meta);
    }
}

fn rust_source_facts(source: &str, skip_test_items: bool) -> RustSourceFacts {
    let file = syn::parse_file(source)
        .unwrap_or_else(|error| panic!("parse repository Rust source: {error}"));
    if skip_test_items && attributes_require_test(&file.attrs) {
        return RustSourceFacts::default();
    }
    let mut visitor = ProductionFactsVisitor::new(skip_test_items);
    visitor.visit_file(&file);
    visitor.facts
}

fn impl_method_body_facts(source: &str, method_name: &str) -> RustSourceFacts {
    let file = syn::parse_file(source)
        .unwrap_or_else(|error| panic!("parse repository Rust source: {error}"));
    let methods = file
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Impl(item) => Some(item),
            _ => None,
        })
        .flat_map(|item| item.items.iter())
        .filter_map(|item| match item {
            syn::ImplItem::Fn(method)
                if normalized_identifier(&method.sig.ident) == method_name =>
            {
                Some(method)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        methods.len(),
        1,
        "expected exactly one implementation method named {method_name}"
    );
    let mut visitor = ProductionFactsVisitor::new(false);
    visitor.visit_block(&methods[0].block);
    visitor.facts
}

fn function_body_facts(source: &str, function_name: &str) -> RustSourceFacts {
    let file = syn::parse_file(source)
        .unwrap_or_else(|error| panic!("parse repository Rust source: {error}"));
    let functions = file
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Fn(function) if normalized_identifier(&function.sig.ident) == function_name => {
                Some(function)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        functions.len(),
        1,
        "expected exactly one free function named {function_name}"
    );
    let mut visitor = ProductionFactsVisitor::new(false);
    visitor.visit_block(&functions[0].block);
    visitor.facts
}

fn repository_relative_path(repository: &Path, path: &Path) -> String {
    path.strip_prefix(repository)
        .expect("source path should be below the repository")
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn reader_boundary_production_sources(repository: &Path) -> BTreeMap<String, RustSourceFacts> {
    ["crates/autocad-mcp/src", "crates/autocad-reader/src"]
        .into_iter()
        .flat_map(|source_root| {
            WalkDir::new(repository.join(source_root))
                .follow_links(false)
                .into_iter()
                .map(move |entry| {
                    entry.unwrap_or_else(|error| {
                        panic!("{source_root} source tree should be readable: {error}")
                    })
                })
                .filter(|entry| entry.file_type().is_file())
                .filter(|entry| {
                    entry.path().extension().and_then(|value| value.to_str()) == Some("rs")
                })
        })
        .map(|entry| {
            let path = entry.path();
            let relative = repository_relative_path(repository, path);
            let source = std::fs::read_to_string(path)
                .unwrap_or_else(|error| panic!("read repository source {relative}: {error}"));
            (relative, rust_source_facts(&source, true))
        })
        .collect()
}

fn writer_boundary_production_sources(repository: &Path) -> BTreeMap<String, RustSourceFacts> {
    let source_root = "crates/autocad-writer/src";
    WalkDir::new(repository.join(source_root))
        .follow_links(false)
        .into_iter()
        .map(|entry| {
            entry.unwrap_or_else(|error| {
                panic!("{source_root} source tree should be readable: {error}")
            })
        })
        .filter(|entry| entry.file_type().is_file())
        .filter(|entry| entry.path().extension().and_then(|value| value.to_str()) == Some("rs"))
        .map(|entry| {
            let path = entry.path();
            let relative = repository_relative_path(repository, path);
            let source = std::fs::read_to_string(path)
                .unwrap_or_else(|error| panic!("read repository source {relative}: {error}"));
            (relative, rust_source_facts(&source, true))
        })
        .collect()
}

#[test]
fn writer_boundary_is_internal_backend_owned_and_application_independent() {
    let repository = repository_root();
    let sources = writer_boundary_production_sources(&repository);
    assert!(
        !sources.is_empty(),
        "writer-boundary policy must scan the extracted crate"
    );
    assert!(
        sources
            .values()
            .any(|facts| facts.has_identifier("acadrust")),
        "writer boundary must own the selected mutable backend"
    );
    for (path, facts) in &sources {
        assert!(
            !facts.has_identifier("autocad_mcp"),
            "writer production source must not depend on the application crate: {path}"
        );
        for reference in &facts.path_references {
            assert!(
                reference != "autocad_mcp"
                    && !reference.starts_with("autocad_mcp::")
                    && reference != "crate::ops"
                    && !reference.starts_with("crate::ops::")
                    && reference != "crate::server"
                    && !reference.starts_with("crate::server::"),
                "writer production source must not depend on application ops or server paths: \
                 {path}: {reference}"
            );
        }
    }

    let boundary_test_path = repository.join("crates/autocad-mcp/tests/writer_contract.rs");
    let boundary_test_facts = rust_source_facts(
        &std::fs::read_to_string(&boundary_test_path)
            .expect("writer contract test target should be readable"),
        false,
    );
    assert!(
        ["acadrust", "CadDocument", "DwgWriter", "DxfWriter"]
            .iter()
            .all(|identifier| !boundary_test_facts.has_identifier(identifier)),
        "writer contract target must remain independent of backend models and fixture writers"
    );

    let session = std::fs::read_to_string(repository.join("crates/autocad-writer/src/session.rs"))
        .expect("writer session source should be readable");
    assert!(
        !session.contains("write_to_file"),
        "writer session must return owned candidates rather than writing source paths"
    );
    for required_receipt_boundary in [
        "RoundtripClaimBoundary::DevelopmentEvidenceOnly",
        "whole_document_preservation_verified: false",
        "native_host_verified: false",
    ] {
        assert!(
            session.contains(required_receipt_boundary),
            "writer receipt must retain its non-certifying boundary: {required_receipt_boundary}"
        );
    }
    let backend =
        std::fs::read_to_string(repository.join("crates/autocad-writer/src/backend/mod.rs"))
            .expect("writer backend source should be readable");
    assert!(
        backend.contains("dwg_candidate_preservation_unqualified")
            && backend.contains("xref_metadata_not_preserved")
            && backend.contains("extended_data_not_preserved")
            && backend.contains("color_book_not_preserved"),
        "writer admission must fail closed for known unqualified candidate source shapes"
    );
    let capability = std::fs::read_to_string(
        repository.join("crates/autocad-writer/src/contract/capability.rs"),
    )
    .expect("writer capability source should be readable");
    assert!(
        capability.contains("AsciiDxf") && !capability.contains("CandidateFormat::Dwg"),
        "candidate-generation capability must remain restricted to admitted ASCII DXF"
    );
    let xref_contract =
        std::fs::read_to_string(repository.join("crates/autocad-writer/src/contract/xrefs.rs"))
            .expect("writer XREF contract source should be readable");
    for required_contract in [
        "DrawingPolicy",
        "PreserveHost",
        "SourceAuthoritative",
        "Synchronize",
        "XrefDestructiveAttachmentGuard",
        "XrefInstanceAttachmentGuard",
        "XrefInstancePlacement",
        "AttachXrefResult",
        "BindXrefResult",
    ] {
        assert!(
            xref_contract.contains(required_contract),
            "writer XREF contract parity is missing {required_contract}"
        );
    }
    for route in [
        "CreateLayer",
        "UpdateLayer",
        "RenameLayer",
        "DeleteLayer",
        "WriteTitleBlock",
        "AttachXref",
        "UpdateXref",
        "DetachXref",
        "InsertXrefInstance",
        "UpdateXrefInstance",
        "DeleteXrefInstance",
        "ReloadXref",
        "UnloadXref",
        "BindXref",
        "PlotToPdf",
    ] {
        assert!(
            session.contains(route)
                || std::fs::read_to_string(
                    repository.join("crates/autocad-writer/src/contract/capability.rs")
                )
                .expect("writer capability source should be readable")
                .contains(route),
            "writer route inventory is missing {route}"
        );
    }
}

#[test]
fn reader_boundary_source_scanner_excludes_non_production_tokens() {
    let source = r###"
        use acadrust::CadDocument;
        const COMMENT_SHAPED_LITERAL: &str = "acadrust CadDocument";
        const RAW_LITERAL: &str = r#"acadrust CadDocument"#;
        const QUOTE_LITERAL: char = '"';
        const BACKEND_INITIAL: char = 'a';
        // acadrust::CadDocument
        /* CadDocument, with /* nested acadrust */ comments */

        fn lifetime_is_not_a_character<'a>(value: &'a str) -> &'a str {
            value
        }

        #[cfg(test)]
        use acadrust::DxfWriter;

        #[cfg(test)]
        const LESS_THAN_IN_TEST_CODE: bool = 1 < 2;

        use production_probe::AfterTestCfg;

        #[cfg(all(test, unix))]
        fn backend_fixture(document: CadDocument) {
            let _ = document;
        }

        #[cfg(not(not(test)))]
        use acadrust::DwgWriter;

        #[cfg(any(test,))]
        use acadrust::DxfDocument;

        #[cfg(test)]
        mod tests {
            use acadrust::CadDocument;
        }

        #[cfg(any(feature = "preview", test))]
        fn production_feature_path(document: CadDocument) {
            let _ = document;
        }
    "###;
    let facts = rust_source_facts(source, true);

    assert_eq!(
        facts.identifier_count("acadrust"),
        1,
        "only the production backend import should remain"
    );
    assert_eq!(
        facts.identifier_count("CadDocument"),
        2,
        "the production import and non-test feature path should remain"
    );
    assert!(
        !facts.has_identifier("DxfWriter")
            && !facts.has_identifier("DwgWriter")
            && !facts.has_identifier("DxfDocument"),
        "test-only imports must not create a production policy consumer"
    );
    assert_eq!(
        facts.identifier_count("AfterTestCfg"),
        1,
        "a test-only comparison must not hide later production syntax"
    );

    let inner_test_only =
        rust_source_facts("#![cfg(not(not(test)))] use acadrust::CadDocument;", true);
    assert!(
        inner_test_only.identifier_counts.is_empty(),
        "a test-only inner cfg must exclude the whole source"
    );

    let raw_backend = rust_source_facts("use r#acadrust::r#CadDocument;", true);
    assert_eq!(raw_backend.identifier_count("acadrust"), 1);
    assert_eq!(raw_backend.identifier_count("CadDocument"), 1);
    let raw_test_only = rust_source_facts("#[cfg(r#test)] use r#acadrust::r#CadDocument;", true);
    assert!(
        raw_test_only.identifier_counts.is_empty(),
        "raw identifiers must not bypass backend or cfg(test) classification"
    );

    let application_paths = rust_source_facts(
        r#"
            use crate::ops::{reader::read, nested::Thing as Alias};

            fn serve() {
                crate::server::serve_stdio();
            }

            #[cfg(test)]
            use autocad_mcp::ops::fixture;
        "#,
        true,
    );
    for expected in [
        "crate::ops::reader::read",
        "crate::ops::nested::Thing",
        "crate::server::serve_stdio",
    ] {
        assert!(
            application_paths.path_references.contains(expected),
            "production qualified path should be recorded: {expected}"
        );
    }
    assert!(
        application_paths
            .path_references
            .iter()
            .all(|path| !path.starts_with("autocad_mcp::")),
        "test-only application paths must not enter production policy facts"
    );
}

#[test]
fn reader_boundary_source_scanner_rejects_escape_aliases_and_function_values() {
    let facts = rust_source_facts(
        r#"
            fn direct(path: &std::path::Path) {
                crate::reader::open_drawing(path);
            }

            fn indirect(path: &std::path::Path) {
                use crate::reader::open_drawing as open;
                open(path);
                let opener = crate::reader::open_drawing;
                opener(path);
                (crate::reader::open_drawing)(path);
            }
        "#,
        true,
    );
    assert_eq!(
        facts.escape_direct_calls.get("open_drawing"),
        Some(&1),
        "only a structurally direct call may enter the exact call-site baseline"
    );
    assert_eq!(
        facts.escape_non_call_references.get("open_drawing"),
        Some(&3),
        "aliases, function values, and parenthesized callees must be rejected"
    );

    let raw_facts = rust_source_facts(
        r#"
            fn direct(path: &std::path::Path) {
                crate::reader::r#open_drawing(path);
            }

            fn indirect(path: &std::path::Path) {
                use crate::reader::r#open_drawing as open;
                open(path);
            }
        "#,
        true,
    );
    assert_eq!(raw_facts.escape_direct_calls.get("open_drawing"), Some(&1));
    assert_eq!(
        raw_facts.escape_non_call_references.get("open_drawing"),
        Some(&1),
        "raw identifiers must not bypass direct-call classification"
    );
}

#[test]
fn reader_boundary_backend_consumers_contracts_and_bridges_are_closed() {
    let repository = repository_root();
    let sources = reader_boundary_production_sources(&repository);
    let reader_root = "crates/autocad-reader/src/";
    let embedded_reader_root = repository.join("crates/autocad-mcp/src/autocad_reader");
    assert!(
        !embedded_reader_root.exists(),
        "the extracted reader must not regain an embedded autocad-mcp source tree"
    );

    let reader_sources = sources
        .iter()
        .filter(|(path, _)| path.starts_with(reader_root))
        .collect::<BTreeMap<_, _>>();
    assert!(
        !reader_sources.is_empty(),
        "reader-boundary policy must scan the extracted crate"
    );
    for (path, facts) in &reader_sources {
        assert!(
            !facts.has_identifier("autocad_mcp"),
            "reader production source must not depend on the application crate: {path}"
        );
        for reference in &facts.path_references {
            assert!(
                reference != "autocad_mcp"
                    && !reference.starts_with("autocad_mcp::")
                    && reference != "crate::ops"
                    && !reference.starts_with("crate::ops::")
                    && reference != "crate::server"
                    && !reference.starts_with("crate::server::")
                    && reference != "super::ops"
                    && !reference.starts_with("super::ops::")
                    && reference != "super::server"
                    && !reference.starts_with("super::server::"),
                "reader production source must not depend on application ops or server paths: \
                 {path}: {reference}"
            );
        }
    }
    let boundary_test_path = repository.join("crates/autocad-mcp/tests/reader_contract.rs");
    let boundary_test_facts = rust_source_facts(
        &std::fs::read_to_string(&boundary_test_path)
            .expect("reader contract test target should be readable"),
        false,
    );
    assert!(
        ["acadrust", "CadDocument", "DwgWriter", "DxfWriter"]
            .iter()
            .all(|identifier| !boundary_test_facts.has_identifier(identifier)),
        "reader contract target must remain independent of backend models and fixture writers"
    );

    let server_path = repository.join("crates/autocad-mcp/src/server.rs");
    let server_source =
        std::fs::read_to_string(&server_path).expect("server source should be readable");
    for method_name in [
        "list_entities",
        "get_entity",
        "get_drawing",
        "list_text",
        "get_text",
        "get_layout",
        "list_layout_viewports",
        "get_layout_viewport",
        "list_plot_settings",
        "get_plot_setting",
        "list_linetypes",
        "get_linetype",
        "list_text_styles",
        "get_text_style",
        "list_dimension_styles",
        "get_dimension_style",
        "list_named_views",
        "get_named_view",
        "list_named_ucs",
        "get_named_ucs",
    ] {
        let facts = impl_method_body_facts(&server_source, method_name);
        assert_eq!(
            facts.identifier_count("fallible_dwg_session_read_op"),
            1,
            "{method_name} must route exactly once through the DWG session helper"
        );
        for forbidden in [
            "read_op",
            "fallible_dwg_read_op",
            "fallible_read_op",
            "checked_read_document",
            "open_legacy_read_document",
            "open_drawing",
            "CadDocument",
            "acadrust",
        ] {
            assert_eq!(
                facts.identifier_count(forbidden),
                0,
                "{method_name} must not use legacy or backend-typed read routing: {forbidden}"
            );
        }
        assert!(
            facts.identifier_count(method_name) > 0,
            "{method_name} must invoke its same-named session query"
        );
    }
    for method_name in ["list_layers", "get_layer"] {
        let facts = impl_method_body_facts(&server_source, method_name);
        assert_eq!(
            facts.identifier_count("layer_session_read_op"),
            1,
            "{method_name} must use exactly one application-owned layer session route"
        );
        assert!(
            facts.identifier_count(method_name) > 0,
            "{method_name} must invoke its same-named session query"
        );
        for forbidden in [
            "layer_io",
            "open_path",
            "open_drawing",
            "open_legacy_read_document",
            "open_legacy_read_snapshot",
            "CadDocument",
            "acadrust",
        ] {
            assert_eq!(
                facts.identifier_count(forbidden),
                0,
                "{method_name} must not route through mutation, legacy, or backend code: \
                 {forbidden}"
            );
        }
    }
    let layer_session_route = function_body_facts(&server_source, "layer_session_read_op");
    assert_eq!(
        layer_session_route.identifier_count("checked_layer_read_session"),
        1,
        "the layer session route must construct exactly one checked reader session"
    );
    for forbidden in [
        "layer_io",
        "open_path",
        "open_snapshot",
        "DrawingSnapshot",
        "CadDocument",
        "acadrust",
    ] {
        assert_eq!(
            layer_session_route.identifier_count(forbidden),
            0,
            "the layer session route must not capture, decode, or use mutation/backend routing: \
             {forbidden}"
        );
    }
    let layer_session_adapter = function_body_facts(&server_source, "checked_layer_read_session");
    assert_eq!(
        layer_session_adapter.identifier_count("validated_layer_read_path"),
        1,
        "layer path policy must be applied exactly once by the application"
    );
    assert_eq!(
        layer_session_adapter.identifier_count("open_snapshot"),
        1,
        "layer reads must enter through exactly one ordinary reader snapshot entrypoint"
    );
    assert_eq!(
        layer_session_adapter.identifier_count("DrawingSnapshot"),
        1,
        "layer reads must construct exactly one immutable reader snapshot"
    );
    assert_eq!(
        layer_session_adapter.identifier_count("read"),
        1,
        "application layer routing must capture drawing bytes exactly once"
    );
    for forbidden in [
        "layer_io",
        "capture_layer_snapshot",
        "map_layer_snapshot_open_error",
        "open_path",
        "read_to_string",
        "open_drawing",
        "open_legacy_read_document",
        "open_legacy_read_snapshot",
        "CadDocument",
        "acadrust",
    ] {
        assert_eq!(
            layer_session_adapter.identifier_count(forbidden),
            0,
            "layer session adapter must not use mutation, legacy, or backend routing: {forbidden}"
        );
    }
    let layer_path_policy = function_body_facts(&server_source, "validated_layer_read_path");
    assert_eq!(
        layer_path_policy.identifier_count("canonicalize"),
        1,
        "application layer path policy must canonicalize exactly once"
    );
    for forbidden in [
        "read",
        "read_to_string",
        "File",
        "OpenOptions",
        "Reader",
        "DrawingSnapshot",
        "open_path",
        "open_snapshot",
        "DxfReader",
        "CadDocument",
        "parse_raw_dxf_pairs",
        "parsed_raw_table",
        "acadrust",
    ] {
        assert_eq!(
            layer_path_policy.identifier_count(forbidden),
            0,
            "layer path policy must not capture, decode, or parse drawing content: {forbidden}"
        );
    }
    for removed in ["capture_layer_snapshot", "map_layer_snapshot_open_error"] {
        assert_eq!(
            reader_sources
                .values()
                .map(|facts| facts.identifier_count(removed))
                .sum::<usize>(),
            0,
            "the extracted reader must not regain the removed layer acquisition API: {removed}"
        );
    }
    let reader_layer_facts = reader_sources
        .iter()
        .find_map(|(path, facts)| {
            (path.as_str() == "crates/autocad-reader/src/layers.rs").then_some(*facts)
        })
        .expect("reader layer source must be scanned");
    for forbidden in [
        "Path",
        "PathBuf",
        "fs",
        "File",
        "OpenOptions",
        "canonicalize",
        "read_to_string",
        "open_path",
        "open_snapshot",
        "from_file",
    ] {
        assert_eq!(
            reader_layer_facts.identifier_count(forbidden),
            0,
            "reader layer projection must not reacquire drawing content or create another \
             construction entrypoint: {forbidden}"
        );
    }
    let reader_error_source =
        std::fs::read_to_string(repository.join("crates/autocad-reader/src/error.rs"))
            .expect("reader error source should be readable");
    let reader_error_facts = rust_source_facts(&reader_error_source, true);
    assert_eq!(
        reader_error_facts.identifier_count("DxfError"),
        0,
        "reader-owned public error mapping must not store a backend error type"
    );
    for source_path in [
        "crates/autocad-reader/src/blocks.rs",
        "crates/autocad-reader/src/entities.rs",
        "crates/autocad-reader/src/layers.rs",
    ] {
        let source = std::fs::read_to_string(repository.join(source_path))
            .unwrap_or_else(|error| panic!("read {source_path}: {error}"));
        assert!(
            !source.contains("acadrust's synthesized scale sentinel")
                && !source.contains("cannot be mutated safely with the selected parser backend"),
            "reader-owned public errors must not expose backend or mutation implementation \
             wording: {source_path}"
        );
    }
    for method_name in ["dump_text", "list_layouts"] {
        let facts = impl_method_body_facts(&server_source, method_name);
        assert_eq!(
            facts.identifier_count("fallible_session_read_op"),
            1,
            "{method_name} must route exactly once through the all-format session helper"
        );
        for forbidden in [
            "read_op",
            "fallible_dwg_session_read_op",
            "fallible_dwg_read_op",
            "fallible_read_op",
            "checked_read_document",
            "open_legacy_read_document",
            "open_legacy_read_snapshot",
            "open_drawing",
            "CadDocument",
            "acadrust",
        ] {
            assert_eq!(
                facts.identifier_count(forbidden),
                0,
                "{method_name} must preserve all-format session routing and avoid legacy or \
                 backend-typed routing: {forbidden}"
            );
        }
        assert!(
            facts.identifier_count(method_name) > 0,
            "{method_name} must invoke its same-named session query"
        );
    }
    let title_block_handler = impl_method_body_facts(&server_source, "read_title_blocks");
    assert_eq!(
        title_block_handler.identifier_count("open_path"),
        1,
        "read_title_blocks must open exactly one immutable reader session"
    );
    assert_eq!(
        title_block_handler.identifier_count("read_title_blocks"),
        1,
        "read_title_blocks must invoke exactly one same-named session query"
    );
    for forbidden in [
        "checked_read_document",
        "open_legacy_read_document",
        "open_legacy_read_snapshot",
        "open_drawing",
        "CadDocument",
        "acadrust",
        "project_title_blocks_for_mutation",
    ] {
        assert_eq!(
            title_block_handler.identifier_count(forbidden),
            0,
            "read_title_blocks must not use legacy, backend-typed, or mutation routing: \
             {forbidden}"
        );
    }

    let xref_io_path = "crates/autocad-mcp/src/ops/xref_io.rs";
    let xref_io_source = std::fs::read_to_string(repository.join(xref_io_path))
        .expect("XREF I/O source should be readable");
    let xref_decode = function_body_facts(&xref_io_source, "decode_snapshot");
    assert_eq!(
        xref_decode.identifier_count("open_snapshot"),
        1,
        "XREF interpretation must enter through exactly one ordinary snapshot session"
    );
    assert_eq!(
        xref_decode.identifier_count("xref_session"),
        1,
        "XREF high-level and low-level evidence must derive from that drawing session"
    );
    for forbidden in [
        "open_xref_snapshot",
        "open_drawing",
        "open_legacy_read_document",
        "open_legacy_read_snapshot",
        "CadDocument",
        "acadrust",
    ] {
        assert_eq!(
            xref_decode.identifier_count(forbidden),
            0,
            "XREF snapshot decoding must not establish a parallel or backend-typed entrypoint: \
             {forbidden}"
        );
    }

    let certification_path = "crates/autocad-mcp/src/certification.rs";
    let certification_source = std::fs::read_to_string(repository.join(certification_path))
        .expect("certification source should be readable");
    let certification_format =
        function_body_facts(&certification_source, "inspect_xref_certification_format");
    assert_eq!(
        certification_format.identifier_count("open_snapshot"),
        1,
        "certification DXF facts must use the ordinary immutable-snapshot entrypoint"
    );
    assert_eq!(
        certification_format.identifier_count("format_facts"),
        1,
        "certification DXF facts must invoke exactly one reader-owned format-facts query"
    );
    for forbidden in [
        "open_drawing",
        "open_legacy_read_document",
        "open_legacy_read_snapshot",
        "CadDocument",
        "acadrust",
    ] {
        assert_eq!(
            certification_format.identifier_count(forbidden),
            0,
            "certification format inspection must not use legacy or backend-typed routing: \
             {forbidden}"
        );
    }

    // This exact transition baseline must contract in the same commit that a
    // registered family retires, so a stale exception cannot be reused.
    let allowed_backend_consumers = [
        "crates/autocad-mcp/src/ops/layer_io.rs",
        "crates/autocad-mcp/src/ops/layers.rs",
        "crates/autocad-mcp/src/ops/title_blocks.rs",
        "crates/autocad-mcp/src/reader.rs",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let actual_backend_consumers = sources
        .iter()
        .filter(|(path, _)| !path.starts_with(reader_root))
        .filter(|(_, facts)| {
            facts.has_identifier("acadrust") || facts.has_identifier("CadDocument")
        })
        .map(|(path, _)| path.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual_backend_consumers, allowed_backend_consumers,
        "production backend consumers changed; update the transition register and exact \
         repository baseline in the same reviewed commit"
    );

    let entity_compatibility = sources
        .get("crates/autocad-mcp/src/ops/entities.rs")
        .expect("entity compatibility module should exist");
    for forbidden in ["acadrust", "CadDocument", "list_entities", "get_entity"] {
        assert_eq!(
            entity_compatibility.identifier_count(forbidden),
            0,
            "retired ops::entities must not expose backend projection identifier {forbidden}"
        );
    }
    for (path, forbidden) in [
        (
            "crates/autocad-mcp/src/ops/drawing.rs",
            &["acadrust", "CadDocument", "get_drawing"][..],
        ),
        (
            "crates/autocad-mcp/src/ops/text.rs",
            &[
                "acadrust",
                "CadDocument",
                "dump_text",
                "list_text",
                "get_text",
            ][..],
        ),
        (
            "crates/autocad-mcp/src/ops/layouts.rs",
            &[
                "acadrust",
                "CadDocument",
                "list_layouts",
                "get_layout",
                "list_layout_viewports",
                "get_layout_viewport",
                "list_plot_settings",
                "get_plot_setting",
            ][..],
        ),
        (
            "crates/autocad-mcp/src/ops/symbols.rs",
            &[
                "acadrust",
                "CadDocument",
                "list_linetypes",
                "get_linetype",
                "list_text_styles",
                "get_text_style",
                "list_dimension_styles",
                "get_dimension_style",
                "list_named_views",
                "get_named_view",
                "list_named_ucs",
                "get_named_ucs",
            ][..],
        ),
    ] {
        let compatibility = sources
            .get(path)
            .unwrap_or_else(|| panic!("reader-migrated compatibility module should exist: {path}"));
        for identifier in forbidden {
            assert_eq!(
                compatibility.identifier_count(identifier),
                0,
                "retired {path} must not expose backend projection identifier {identifier}"
            );
        }
    }

    for retired_path in [
        "crates/autocad-mcp/src/ops/owners.rs",
        "crates/autocad-mcp/src/ops/xref_evidence.rs",
    ] {
        assert!(
            !sources.contains_key(retired_path),
            "retired reader adapter must remain absent: {retired_path}"
        );
    }
    let layer_mutation = sources
        .get("crates/autocad-mcp/src/ops/layers.rs")
        .expect("layer mutation module should exist");
    for retired in [
        "LayerReadContext",
        "LayerReadMetadata",
        "list_layers",
        "get_layer",
    ] {
        assert_eq!(
            layer_mutation.identifier_count(retired),
            0,
            "layer mutation module must not regain public-read projection {retired}"
        );
    }
    let layer_io_mutation = sources
        .get("crates/autocad-mcp/src/ops/layer_io.rs")
        .expect("layer I/O mutation module should exist");
    for retired in [
        "list_layers_file",
        "get_layer_file",
        "open_legacy_read_document",
        "open_legacy_read_snapshot",
    ] {
        assert_eq!(
            layer_io_mutation.identifier_count(retired),
            0,
            "layer mutation I/O must not regain public-read bridge {retired}"
        );
    }
    let xref_compatibility = sources
        .get("crates/autocad-mcp/src/ops/xrefs.rs")
        .expect("XREF compatibility and mutation module should exist");
    for forbidden in [
        "acadrust",
        "CadDocument",
        "read_dxf_snapshot",
        "read_dwg_snapshot",
    ] {
        assert_eq!(
            xref_compatibility.identifier_count(forbidden),
            0,
            "XREF application code must not regain backend evidence projection {forbidden}"
        );
    }
    for path in [
        "crates/autocad-mcp/src/ops/xref_io.rs",
        "crates/autocad-mcp/src/ops/xref_runtime.rs",
        "crates/autocad-mcp/src/ops/xref_instance_mutation.rs",
    ] {
        let facts = sources
            .get(path)
            .unwrap_or_else(|| panic!("XREF application module should exist: {path}"));
        for forbidden in ["acadrust", "CadDocument", "open_drawing"] {
            assert_eq!(
                facts.identifier_count(forbidden),
                0,
                "XREF application module must remain backend-independent: {path}: {forbidden}"
            );
        }
    }
    let dynamic_compatibility = sources
        .get("crates/autocad-mcp/src/ops/dynamic_blocks.rs")
        .expect("dynamic-block compatibility module should exist");
    assert_eq!(
        dynamic_compatibility.identifier_count("resolve_dynamic_block_link"),
        0,
        "the entity-only backend-typed dynamic-block resolver adapter must remain retired"
    );
    let title_block_mutation_projection = sources
        .get("crates/autocad-mcp/src/ops/title_blocks.rs")
        .expect("title-block mutation-preparation module should exist");
    assert_eq!(
        title_block_mutation_projection.identifier_count("read_title_blocks"),
        0,
        "ops::title_blocks must not retain a public-read projection"
    );
    assert_eq!(
        title_block_mutation_projection.identifier_count("project_title_blocks_for_mutation"),
        1,
        "the remaining backend-typed title-block projection must be explicitly mutation-only"
    );
    for path in [
        "crates/autocad-mcp/src/ops/survey.rs",
        "crates/autocad-mcp/src/ops/profile_admin.rs",
    ] {
        let facts = sources
            .get(path)
            .unwrap_or_else(|| panic!("reader-migrated administrator module should exist: {path}"));
        for forbidden in [
            "acadrust",
            "CadDocument",
            "open_drawing",
            "project_title_blocks_for_mutation",
        ] {
            assert_eq!(
                facts.identifier_count(forbidden),
                0,
                "{path} must not use backend-typed or mutation-only title-block routing: \
                 {forbidden}"
            );
        }
    }

    let canonical_contracts = [
        ("BlockInfo", "crates/autocad-reader/src/contract/blocks.rs"),
        (
            "BlockPoint3",
            "crates/autocad-reader/src/contract/blocks.rs",
        ),
        (
            "BlockDefinitionRecord",
            "crates/autocad-reader/src/contract/blocks.rs",
        ),
        (
            "BlockDefinitionSelector",
            "crates/autocad-reader/src/contract/blocks.rs",
        ),
        (
            "BlockAttributeRecord",
            "crates/autocad-reader/src/contract/blocks.rs",
        ),
        (
            "BlockInsertRecord",
            "crates/autocad-reader/src/contract/blocks.rs",
        ),
        (
            "BlockInsertSelector",
            "crates/autocad-reader/src/contract/blocks.rs",
        ),
        (
            "DirectOwnerType",
            "crates/autocad-reader/src/contract/owners.rs",
        ),
        (
            "DirectOwnerUnavailableReason",
            "crates/autocad-reader/src/contract/owners.rs",
        ),
        (
            "DirectOwnerContext",
            "crates/autocad-reader/src/contract/owners.rs",
        ),
        (
            "DynamicBlockUnavailableReason",
            "crates/autocad-reader/src/contract/dynamic_blocks.rs",
        ),
        (
            "DynamicVisibilityParameterUnavailableReason",
            "crates/autocad-reader/src/contract/dynamic_blocks.rs",
        ),
        (
            "DynamicCurrentStateUnavailableReason",
            "crates/autocad-reader/src/contract/dynamic_blocks.rs",
        ),
        (
            "DynamicCurrentState",
            "crates/autocad-reader/src/contract/dynamic_blocks.rs",
        ),
        (
            "DynamicVisibilityParameter",
            "crates/autocad-reader/src/contract/dynamic_blocks.rs",
        ),
        (
            "DynamicBlockLink",
            "crates/autocad-reader/src/contract/dynamic_blocks.rs",
        ),
        (
            "EntityPoint3",
            "crates/autocad-reader/src/contract/entities.rs",
        ),
        (
            "EntityScale3",
            "crates/autocad-reader/src/contract/entities.rs",
        ),
        (
            "EntityBounds3",
            "crates/autocad-reader/src/contract/entities.rs",
        ),
        (
            "EntityBoundsUnavailableReason",
            "crates/autocad-reader/src/contract/entities.rs",
        ),
        (
            "EntityBoundsAvailability",
            "crates/autocad-reader/src/contract/entities.rs",
        ),
        (
            "EntityStringUnavailableReason",
            "crates/autocad-reader/src/contract/entities.rs",
        ),
        (
            "EntityStringAvailability",
            "crates/autocad-reader/src/contract/entities.rs",
        ),
        (
            "EntityBooleanUnavailableReason",
            "crates/autocad-reader/src/contract/entities.rs",
        ),
        (
            "EntityBooleanAvailability",
            "crates/autocad-reader/src/contract/entities.rs",
        ),
        (
            "EntityNumberUnavailableReason",
            "crates/autocad-reader/src/contract/entities.rs",
        ),
        (
            "EntityNumberAvailability",
            "crates/autocad-reader/src/contract/entities.rs",
        ),
        (
            "EntityColor",
            "crates/autocad-reader/src/contract/entities.rs",
        ),
        (
            "EntityLinetype",
            "crates/autocad-reader/src/contract/entities.rs",
        ),
        (
            "EntityLineWeight",
            "crates/autocad-reader/src/contract/entities.rs",
        ),
        (
            "EntityTransparency",
            "crates/autocad-reader/src/contract/entities.rs",
        ),
        (
            "PolylineRepresentation",
            "crates/autocad-reader/src/contract/entities.rs",
        ),
        (
            "EntityHelixHandedness",
            "crates/autocad-reader/src/contract/entities.rs",
        ),
        (
            "EntityHelixConstraint",
            "crates/autocad-reader/src/contract/entities.rs",
        ),
        (
            "EntityDetailUnsupportedReason",
            "crates/autocad-reader/src/contract/entities.rs",
        ),
        (
            "EntityDetail",
            "crates/autocad-reader/src/contract/entities.rs",
        ),
        (
            "EntityRecord",
            "crates/autocad-reader/src/contract/entities.rs",
        ),
        (
            "EntityListOptions",
            "crates/autocad-reader/src/contract/entities.rs",
        ),
        (
            "EntitySelector",
            "crates/autocad-reader/src/contract/entities.rs",
        ),
        (
            "EntityListResult",
            "crates/autocad-reader/src/contract/entities.rs",
        ),
        (
            "DrawingPoint2",
            "crates/autocad-reader/src/contract/drawing.rs",
        ),
        (
            "DrawingPoint3",
            "crates/autocad-reader/src/contract/drawing.rs",
        ),
        (
            "DrawingBounds2",
            "crates/autocad-reader/src/contract/drawing.rs",
        ),
        (
            "DrawingBounds3",
            "crates/autocad-reader/src/contract/drawing.rs",
        ),
        (
            "DrawingSavedValueSource",
            "crates/autocad-reader/src/contract/drawing.rs",
        ),
        (
            "DrawingPointUnavailableReason",
            "crates/autocad-reader/src/contract/drawing.rs",
        ),
        (
            "DrawingBoundsUnavailableReason",
            "crates/autocad-reader/src/contract/drawing.rs",
        ),
        (
            "DrawingExtentsUnavailableReason",
            "crates/autocad-reader/src/contract/drawing.rs",
        ),
        (
            "DrawingPoint3Availability",
            "crates/autocad-reader/src/contract/drawing.rs",
        ),
        (
            "DrawingBounds2Availability",
            "crates/autocad-reader/src/contract/drawing.rs",
        ),
        (
            "DrawingBounds3Availability",
            "crates/autocad-reader/src/contract/drawing.rs",
        ),
        (
            "DrawingInsertionUnit",
            "crates/autocad-reader/src/contract/drawing.rs",
        ),
        (
            "DrawingMeasurementSystem",
            "crates/autocad-reader/src/contract/drawing.rs",
        ),
        (
            "DrawingUnits",
            "crates/autocad-reader/src/contract/drawing.rs",
        ),
        (
            "DrawingMetadata",
            "crates/autocad-reader/src/contract/drawing.rs",
        ),
        (
            "DrawingSpaceGeometry",
            "crates/autocad-reader/src/contract/drawing.rs",
        ),
        (
            "DrawingGeometry",
            "crates/autocad-reader/src/contract/drawing.rs",
        ),
        (
            "DrawingUcsBasis",
            "crates/autocad-reader/src/contract/drawing.rs",
        ),
        (
            "DrawingUcsUnavailableReason",
            "crates/autocad-reader/src/contract/drawing.rs",
        ),
        (
            "DrawingUcsAvailability",
            "crates/autocad-reader/src/contract/drawing.rs",
        ),
        (
            "DrawingSpaceCurrentUcs",
            "crates/autocad-reader/src/contract/drawing.rs",
        ),
        (
            "DrawingCurrentUcs",
            "crates/autocad-reader/src/contract/drawing.rs",
        ),
        (
            "DrawingSpaceRecord",
            "crates/autocad-reader/src/contract/drawing.rs",
        ),
        (
            "DrawingSpaces",
            "crates/autocad-reader/src/contract/drawing.rs",
        ),
        (
            "DrawingCounts",
            "crates/autocad-reader/src/contract/drawing.rs",
        ),
        (
            "DrawingCurrentSettings",
            "crates/autocad-reader/src/contract/drawing.rs",
        ),
        (
            "DrawingSummary",
            "crates/autocad-reader/src/contract/drawing.rs",
        ),
        ("TextItem", "crates/autocad-reader/src/contract/text.rs"),
        ("TextPoint3", "crates/autocad-reader/src/contract/text.rs"),
        (
            "TextEntityKind",
            "crates/autocad-reader/src/contract/text.rs",
        ),
        (
            "TextHorizontalAlignment",
            "crates/autocad-reader/src/contract/text.rs",
        ),
        (
            "TextVerticalAlignment",
            "crates/autocad-reader/src/contract/text.rs",
        ),
        (
            "MTextAttachmentPoint",
            "crates/autocad-reader/src/contract/text.rs",
        ),
        (
            "MTextDrawingDirection",
            "crates/autocad-reader/src/contract/text.rs",
        ),
        ("TextRecord", "crates/autocad-reader/src/contract/text.rs"),
        (
            "TextListOptions",
            "crates/autocad-reader/src/contract/text.rs",
        ),
        ("TextSelector", "crates/autocad-reader/src/contract/text.rs"),
        (
            "LayoutInfo",
            "crates/autocad-reader/src/contract/layouts.rs",
        ),
        (
            "LayoutSelector",
            "crates/autocad-reader/src/contract/layouts.rs",
        ),
        (
            "LayoutViewportSelector",
            "crates/autocad-reader/src/contract/layouts.rs",
        ),
        ("Point2", "crates/autocad-reader/src/contract/layouts.rs"),
        ("Point3", "crates/autocad-reader/src/contract/layouts.rs"),
        ("Bounds2", "crates/autocad-reader/src/contract/layouts.rs"),
        ("Bounds3", "crates/autocad-reader/src/contract/layouts.rs"),
        (
            "LayoutUcsRecord",
            "crates/autocad-reader/src/contract/layouts.rs",
        ),
        (
            "EmbeddedPlotSettingsRecord",
            "crates/autocad-reader/src/contract/layouts.rs",
        ),
        (
            "LayoutRecord",
            "crates/autocad-reader/src/contract/layouts.rs",
        ),
        (
            "LayoutViewportResourceType",
            "crates/autocad-reader/src/contract/layouts.rs",
        ),
        (
            "LayoutViewportRenderMode",
            "crates/autocad-reader/src/contract/layouts.rs",
        ),
        (
            "LayoutViewportRecord",
            "crates/autocad-reader/src/contract/layouts.rs",
        ),
        (
            "PlotSettingSelector",
            "crates/autocad-reader/src/contract/layouts.rs",
        ),
        (
            "PlotPaperUnits",
            "crates/autocad-reader/src/contract/layouts.rs",
        ),
        (
            "PlotRotation",
            "crates/autocad-reader/src/contract/layouts.rs",
        ),
        ("PlotArea", "crates/autocad-reader/src/contract/layouts.rs"),
        (
            "PlotScaleType",
            "crates/autocad-reader/src/contract/layouts.rs",
        ),
        (
            "PlotShadeMode",
            "crates/autocad-reader/src/contract/layouts.rs",
        ),
        (
            "PlotShadeResolution",
            "crates/autocad-reader/src/contract/layouts.rs",
        ),
        (
            "PaperMargins",
            "crates/autocad-reader/src/contract/layouts.rs",
        ),
        (
            "PlotWindowRecord",
            "crates/autocad-reader/src/contract/layouts.rs",
        ),
        (
            "PlotFlagsRecord",
            "crates/autocad-reader/src/contract/layouts.rs",
        ),
        (
            "PlotSettingRecord",
            "crates/autocad-reader/src/contract/layouts.rs",
        ),
        (
            "SymbolSelector",
            "crates/autocad-reader/src/contract/symbols.rs",
        ),
        (
            "LinetypeElementKind",
            "crates/autocad-reader/src/contract/symbols.rs",
        ),
        (
            "LinetypeElementRecord",
            "crates/autocad-reader/src/contract/symbols.rs",
        ),
        (
            "LinetypeRecord",
            "crates/autocad-reader/src/contract/symbols.rs",
        ),
        (
            "TextStyleRecord",
            "crates/autocad-reader/src/contract/symbols.rs",
        ),
        (
            "DimensionStyleRecord",
            "crates/autocad-reader/src/contract/symbols.rs",
        ),
        (
            "SymbolPoint3",
            "crates/autocad-reader/src/contract/symbols.rs",
        ),
        (
            "NamedViewRecord",
            "crates/autocad-reader/src/contract/symbols.rs",
        ),
        (
            "NamedUcsRecord",
            "crates/autocad-reader/src/contract/symbols.rs",
        ),
        (
            "LayerLineWeight",
            "crates/autocad-reader/src/contract/layers.rs",
        ),
        (
            "LayerRecord",
            "crates/autocad-reader/src/contract/layers.rs",
        ),
        (
            "LayerSelector",
            "crates/autocad-reader/src/contract/layers.rs",
        ),
        (
            "DrawingFormatFacts",
            "crates/autocad-reader/src/contract/format_facts.rs",
        ),
        (
            "ReferenceType",
            "crates/autocad-reader/src/contract/xrefs.rs",
        ),
        ("LoadState", "crates/autocad-reader/src/contract/xrefs.rs"),
        (
            "XrefPathMode",
            "crates/autocad-reader/src/contract/xrefs.rs",
        ),
        (
            "XrefOwnerType",
            "crates/autocad-reader/src/contract/xrefs.rs",
        ),
        (
            "XrefVisibility",
            "crates/autocad-reader/src/contract/xrefs.rs",
        ),
        (
            "XrefPlacementKind",
            "crates/autocad-reader/src/contract/xrefs.rs",
        ),
        (
            "InsertionUnit",
            "crates/autocad-reader/src/contract/xrefs.rs",
        ),
        (
            "XrefUnitBasis",
            "crates/autocad-reader/src/contract/xrefs.rs",
        ),
        ("XrefPoint3", "crates/autocad-reader/src/contract/xrefs.rs"),
        ("XrefScale3", "crates/autocad-reader/src/contract/xrefs.rs"),
        ("XrefVector3", "crates/autocad-reader/src/contract/xrefs.rs"),
        ("XrefPoint", "crates/autocad-reader/src/contract/xrefs.rs"),
        ("XrefScale", "crates/autocad-reader/src/contract/xrefs.rs"),
        ("XrefNormal", "crates/autocad-reader/src/contract/xrefs.rs"),
        (
            "XrefPointAvailability",
            "crates/autocad-reader/src/contract/xrefs.rs",
        ),
        (
            "XrefUnitValue",
            "crates/autocad-reader/src/contract/xrefs.rs",
        ),
        (
            "XrefUnitScaling",
            "crates/autocad-reader/src/contract/xrefs.rs",
        ),
        (
            "PersistedInsertionUnits",
            "crates/autocad-reader/src/contract/xrefs.rs",
        ),
        (
            "XrefRectangularArray",
            "crates/autocad-reader/src/contract/xrefs.rs",
        ),
        (
            "XrefAttachmentRecord",
            "crates/autocad-reader/src/contract/xrefs.rs",
        ),
        (
            "XrefInstanceRecord",
            "crates/autocad-reader/src/contract/xrefs.rs",
        ),
        (
            "XrefSelector",
            "crates/autocad-reader/src/contract/xrefs.rs",
        ),
        (
            "XrefAttachmentSelector",
            "crates/autocad-reader/src/contract/xrefs.rs",
        ),
        (
            "XrefInstanceSelector",
            "crates/autocad-reader/src/contract/xrefs.rs",
        ),
        (
            "XrefInstanceListOptions",
            "crates/autocad-reader/src/contract/xrefs.rs",
        ),
        (
            "XrefEvidenceValue",
            "crates/autocad-reader/src/contract/xrefs.rs",
        ),
        (
            "XrefMembershipEvidence",
            "crates/autocad-reader/src/contract/xrefs.rs",
        ),
        (
            "XrefPersistedPlacementEvidence",
            "crates/autocad-reader/src/contract/xrefs.rs",
        ),
        (
            "XrefPersistedInstanceEvidence",
            "crates/autocad-reader/src/contract/xrefs.rs",
        ),
        (
            "XrefDomainEvidence",
            "crates/autocad-reader/src/contract/xrefs.rs",
        ),
        ("Fact", "crates/autocad-reader/src/contract/xrefs.rs"),
        (
            "XrefSnapshotEvidence",
            "crates/autocad-reader/src/contract/xrefs.rs",
        ),
        (
            "OwnerEvidence",
            "crates/autocad-reader/src/contract/xrefs.rs",
        ),
        (
            "LayerEvidence",
            "crates/autocad-reader/src/contract/xrefs.rs",
        ),
        (
            "XrefPortableLayerProperties",
            "crates/autocad-reader/src/contract/xrefs.rs",
        ),
        (
            "XrefPortableClipEvidence",
            "crates/autocad-reader/src/contract/xrefs.rs",
        ),
        ("XrefError", "crates/autocad-reader/src/contract/xrefs.rs"),
        ("AbsolutePathKind", "crates/autocad-reader/src/xref_path.rs"),
        (
            "UnsupportedPathReason",
            "crates/autocad-reader/src/xref_path.rs",
        ),
        ("XrefPathSyntax", "crates/autocad-reader/src/xref_path.rs"),
        ("ParsedXrefPath", "crates/autocad-reader/src/xref_path.rs"),
        (
            "TitleBlockInfo",
            "crates/autocad-reader/src/contract/title_blocks.rs",
        ),
    ];
    for (contract, canonical_path) in canonical_contracts {
        let definitions = sources
            .iter()
            .flat_map(|(path, facts)| {
                facts
                    .type_definitions
                    .iter()
                    .filter(move |definition| definition.as_str() == contract)
                    .map(move |_| path.as_str())
            })
            .collect::<Vec<_>>();
        assert_eq!(
            definitions,
            [canonical_path],
            "reader contract {contract} must have exactly one canonical definition"
        );
    }

    let parse_saved_path_definitions = sources
        .iter()
        .flat_map(|(path, facts)| {
            facts
                .function_definitions
                .iter()
                .filter(|definition| definition.as_str() == "parse_saved_path")
                .map(move |_| path.as_str())
        })
        .collect::<Vec<_>>();
    assert_eq!(
        parse_saved_path_definitions,
        ["crates/autocad-reader/src/xref_path.rs"],
        "saved XREF path parsing must have exactly one reader-owned implementation"
    );
    let parent_xref_path = sources
        .get("crates/autocad-mcp/src/ops/xref_path.rs")
        .expect("parent XREF path policy module should exist");
    for reference in [
        "crate::autocad_reader::xref_path::parse_saved_path",
        "crate::autocad_reader::xref_path::AbsolutePathKind",
        "crate::autocad_reader::xref_path::ParsedXrefPath",
        "crate::autocad_reader::xref_path::UnsupportedPathReason",
        "crate::autocad_reader::xref_path::XrefPathSyntax",
    ] {
        assert!(
            parent_xref_path.path_references.contains(reference),
            "parent XREF path policy must re-export reader-owned path syntax: {reference}"
        );
    }

    let expected_legacy_document_calls = BTreeMap::new();
    let expected_legacy_snapshot_calls = BTreeMap::new();
    let expected_unchecked_open_calls =
        BTreeMap::from([("crates/autocad-mcp/src/server.rs", 1usize)]);
    for (function, expected) in [
        ("open_legacy_read_document", expected_legacy_document_calls),
        ("open_legacy_read_snapshot", expected_legacy_snapshot_calls),
        ("open_drawing", expected_unchecked_open_calls),
    ] {
        let non_call_references = sources
            .iter()
            .filter_map(|(path, facts)| {
                facts
                    .escape_non_call_references
                    .get(function)
                    .copied()
                    .filter(|count| *count > 0)
                    .map(|count| (path.as_str(), count))
            })
            .collect::<BTreeMap<_, _>>();
        assert!(
            non_call_references.is_empty(),
            "reader backend escape {function} must only appear as a structurally direct call; \
             non-call references: {non_call_references:?}"
        );
        let actual = sources
            .iter()
            .filter_map(|(path, facts)| {
                facts
                    .escape_direct_calls
                    .get(function)
                    .copied()
                    .filter(|count| *count > 0)
                    .map(|count| (path.as_str(), count))
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            actual, expected,
            "reader backend escape call sites changed for {function}"
        );
    }
}

#[test]
fn reader_backend_manifest_requirement_is_exact() {
    let repository = repository_root();
    let metadata = cargo_metadata(&repository);
    let packages = metadata["packages"]
        .as_array()
        .expect("cargo metadata packages should be an array");
    let parent = packages
        .iter()
        .find(|package| package["name"] == "autocad-mcp")
        .expect("workspace metadata must contain autocad-mcp");
    let reader = packages
        .iter()
        .find(|package| package["name"] == "autocad-reader")
        .expect("workspace metadata must contain the extracted autocad-reader package");
    let writer = packages
        .iter()
        .find(|package| package["name"] == "autocad-writer")
        .expect("workspace metadata must contain the extracted autocad-writer package");
    let expected_reader_manifest = repository.join("crates/autocad-reader/Cargo.toml");
    let expected_reader_package = repository.join("crates/autocad-reader");
    let expected_writer_manifest = repository.join("crates/autocad-writer/Cargo.toml");
    let expected_writer_package = repository.join("crates/autocad-writer");

    assert_eq!(
        reader["publish"].as_array().map(Vec::len),
        Some(0),
        "the internal autocad-reader package must remain nonpublished"
    );
    assert_eq!(
        reader["manifest_path"].as_str().map(Path::new),
        Some(expected_reader_manifest.as_path()),
        "workspace metadata must select the extracted reader manifest"
    );

    let reader_dependencies = reader["dependencies"]
        .as_array()
        .expect("autocad-reader dependencies should be an array");
    assert!(
        reader_dependencies
            .iter()
            .all(|dependency| dependency["name"] != "autocad-mcp"),
        "autocad-reader must not depend back on the application package"
    );
    let reader_backends = reader_dependencies
        .iter()
        .filter(|dependency| dependency["name"] == "acadrust")
        .collect::<Vec<_>>();
    assert_eq!(
        reader_backends.len(),
        1,
        "autocad-reader must have exactly one selected acadrust dependency"
    );
    let reader_backend = reader_backends[0];
    assert!(
        reader_backend["rename"].is_null(),
        "the reader backend must not be renamed around source-boundary policy"
    );
    assert_eq!(
        reader_backend["req"].as_str(),
        Some("=0.4.1"),
        "autocad-reader must retain the reviewed exact acadrust requirement"
    );

    assert_eq!(
        writer["publish"].as_array().map(Vec::len),
        Some(0),
        "the internal autocad-writer package must remain nonpublished"
    );
    assert_eq!(
        writer["manifest_path"].as_str().map(Path::new),
        Some(expected_writer_manifest.as_path()),
        "workspace metadata must select the extracted writer manifest"
    );
    let writer_dependencies = writer["dependencies"]
        .as_array()
        .expect("autocad-writer dependencies should be an array");
    assert!(
        writer_dependencies
            .iter()
            .all(|dependency| dependency["name"] != "autocad-mcp"),
        "autocad-writer must not depend back on the application package"
    );
    let writer_backends = writer_dependencies
        .iter()
        .filter(|dependency| dependency["name"] == "acadrust")
        .collect::<Vec<_>>();
    assert_eq!(
        writer_backends.len(),
        1,
        "autocad-writer must have exactly one selected acadrust dependency"
    );
    assert!(
        writer_backends[0]["rename"].is_null(),
        "the writer backend must not be renamed around source-boundary policy"
    );
    assert_eq!(
        writer_backends[0]["req"].as_str(),
        Some("=0.4.1"),
        "autocad-writer must retain the reviewed exact acadrust requirement"
    );
    let writer_readers = writer_dependencies
        .iter()
        .filter(|dependency| dependency["name"] == "autocad-reader")
        .collect::<Vec<_>>();
    assert_eq!(
        writer_readers.len(),
        1,
        "autocad-writer must use exactly one independent reader boundary"
    );
    assert_eq!(
        writer_readers[0]["path"].as_str().map(Path::new),
        Some(expected_reader_package.as_path()),
        "autocad-writer must use the exact sibling reader package"
    );

    let parent_dependencies = parent["dependencies"]
        .as_array()
        .expect("autocad-mcp dependencies should be an array");
    let parent_reader_dependencies = parent_dependencies
        .iter()
        .filter(|dependency| dependency["name"] == "autocad-reader")
        .collect::<Vec<_>>();
    assert_eq!(
        parent_reader_dependencies.len(),
        1,
        "autocad-mcp must have exactly one dependency on the extracted reader"
    );
    let parent_reader = parent_reader_dependencies[0];
    assert!(
        parent_reader["rename"].is_null(),
        "autocad-mcp must not rename the reader package around boundary policy"
    );
    assert_eq!(
        parent_reader["path"].as_str().map(Path::new),
        Some(expected_reader_package.as_path()),
        "autocad-mcp must depend on the workspace reader at ../autocad-reader"
    );
    let parent_writer_dependencies = parent_dependencies
        .iter()
        .filter(|dependency| dependency["name"] == "autocad-writer")
        .collect::<Vec<_>>();
    assert_eq!(
        parent_writer_dependencies.len(),
        1,
        "autocad-mcp must have exactly one dependency on the extracted writer"
    );
    let parent_writer = parent_writer_dependencies[0];
    assert!(
        parent_writer["rename"].is_null(),
        "autocad-mcp must not rename the writer package around boundary policy"
    );
    assert_eq!(
        parent_writer["path"].as_str().map(Path::new),
        Some(expected_writer_package.as_path()),
        "autocad-mcp must depend on the workspace writer at ../autocad-writer"
    );

    let parent_backends = parent_dependencies
        .iter()
        .filter(|dependency| dependency["name"] == "acadrust")
        .collect::<Vec<_>>();
    assert_eq!(
        parent_backends.len(),
        1,
        "autocad-mcp must retain exactly one acadrust dependency for mutation code"
    );
    let parent_backend = parent_backends[0];
    assert!(
        parent_backend["rename"].is_null(),
        "the mutation backend must not be renamed around source-boundary policy"
    );
    assert_eq!(
        parent_backend["req"].as_str(),
        Some("=0.4.1"),
        "autocad-mcp mutation code must retain the reviewed exact acadrust requirement"
    );

    let parent_manifest = std::fs::read_to_string(repository.join("crates/autocad-mcp/Cargo.toml"))
        .expect("autocad-mcp manifest should be readable");
    assert!(
        parent_manifest
            .lines()
            .any(|line| line.trim() == r#"autocad-reader = { path = "../autocad-reader" }"#),
        "autocad-mcp must spell the reader dependency as the exact sibling path"
    );
    assert!(
        parent_manifest
            .lines()
            .any(|line| line.trim() == r#"autocad-writer = { path = "../autocad-writer" }"#),
        "autocad-mcp must spell the writer dependency as the exact sibling path"
    );
    let reader_manifest =
        std::fs::read_to_string(repository.join("crates/autocad-reader/Cargo.toml"))
            .expect("autocad-reader manifest should be readable");
    assert!(
        reader_manifest
            .lines()
            .any(|line| line.trim() == "publish = false"),
        "autocad-reader must remain explicitly nonpublished"
    );
    let writer_manifest =
        std::fs::read_to_string(repository.join("crates/autocad-writer/Cargo.toml"))
            .expect("autocad-writer manifest should be readable");
    assert!(
        writer_manifest
            .lines()
            .any(|line| line.trim() == "publish = false"),
        "autocad-writer must remain explicitly nonpublished"
    );
}

fn git_command(repository: &Path) -> Command {
    #[cfg(windows)]
    const NULL_DEVICE: &str = "NUL";
    #[cfg(not(windows))]
    const NULL_DEVICE: &str = "/dev/null";

    let inherited_environment = [
        ("PATH", std::env::var_os("PATH")),
        ("SystemRoot", std::env::var_os("SystemRoot")),
        ("WINDIR", std::env::var_os("WINDIR")),
        ("TMPDIR", std::env::var_os("TMPDIR")),
        ("TMP", std::env::var_os("TMP")),
        ("TEMP", std::env::var_os("TEMP")),
    ];
    let mut command = Command::new("git");
    command.env_clear().current_dir(repository);
    for (name, value) in inherited_environment {
        if let Some(value) = value {
            command.env(name, value);
        }
    }
    command
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_SYSTEM", NULL_DEVICE)
        .env("GIT_CONFIG_GLOBAL", NULL_DEVICE)
        .env("GIT_CONFIG_COUNT", "0")
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0");
    command
}

fn is_ignored(repository: &Path, path: &str) -> bool {
    let status = git_command(repository)
        .args(["check-ignore", "--quiet", "--no-index", "--", path])
        .status()
        .expect("git should be available for repository-policy tests");

    match status.code() {
        Some(0) => true,
        Some(1) => false,
        code => panic!("git check-ignore failed for {path} with status {code:?}"),
    }
}

fn tracked_paths(repository: &Path) -> Vec<String> {
    let output = git_command(repository)
        .args(["ls-files", "--cached", "-z", "--"])
        .output()
        .expect("git should enumerate tracked paths");
    assert!(
        output.status.success(),
        "git ls-files failed with status {:?}",
        output.status.code()
    );

    output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .map(|path| {
            std::str::from_utf8(path)
                .expect("tracked paths must be UTF-8")
                .to_owned()
        })
        .collect()
}

fn tracked_whitelist_violations(repository: &Path) -> Vec<String> {
    tracked_paths(repository)
        .into_iter()
        .filter(|path| is_ignored(repository, path))
        .collect()
}

fn cargo_metadata(repository: &Path) -> serde_json::Value {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(cargo)
        .current_dir(repository)
        .args(["metadata", "--locked", "--no-deps", "--format-version", "1"])
        .output()
        .expect("cargo metadata should run");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("cargo metadata should emit JSON")
}

fn run_git(repository: &Path, arguments: &[&str]) {
    let status = git_command(repository)
        .args(arguments)
        .status()
        .expect("git command should run");
    assert!(
        status.success(),
        "git {arguments:?} failed with status {:?}",
        status.code()
    );
}

#[test]
fn whitelist_admits_reviewed_shapes_and_denies_unreviewed_paths() {
    let repository = repository_root();
    for path in [
        ".gitattributes",
        ".githooks/pre-push",
        ".github/workflows/windows-native-harness.yml",
        ".github/workflows/windows-preview-review-candidate.yml",
        ".github/workflows/windows-xref-guarded-rename.yml",
        "README.md",
        "rust-toolchain.toml",
        "crates/autocad-reader/.gitignore",
        "crates/autocad-reader/Cargo.toml",
        "crates/autocad-reader/src/mod.rs",
        "crates/autocad-reader/src/contract/xrefs.rs",
        "crates/autocad-reader/src/xref_path.rs",
        "crates/autocad-writer/.gitignore",
        "crates/autocad-writer/Cargo.toml",
        "crates/autocad-writer/src/mod.rs",
        "crates/autocad-writer/src/contract/capability.rs",
        "crates/autocad-writer/src/session.rs",
        "crates/autocad-mcp/tests/writer_contract.rs",
        "crates/autocad-mcp/src/ops/new_operation.rs",
        "crates/distribution/.gitignore",
        "crates/distribution/approval/src/lib.rs",
        "crates/distribution/evidence/src/lib.rs",
        "crates/distribution/packager/src/lib.rs",
        "crates/distribution/plugin-validation/src/lib.rs",
        "crates/distribution/qualification/src/lib.rs",
        "crates/xtask/src/main.rs",
        "plugin/.lsp.json",
        "plugin/.third-party/.gitignore",
        "plugin/.third-party/third-party-license-policy.json",
        "plugin/.third-party/third-party-license-provenance.json",
        "plugin/.third-party/source-lock.spdx.json",
        "plugin/.third-party/license-supplements/.gitignore",
        "plugin/.third-party/license-supplements/rmcp-1.7.0-LICENSE.txt",
        "plugin/.third-party/source-closure-windows.spdx.json",
        "plugin/skills/autolisp/references/new-public-reference.md",
        "plugin/skills/autolisp/references/dcl/new-public-reference.md",
        "plugin/skills/autolisp/references/documentation-provenance.json",
        "tests/new_integration.rs",
        "tests/fixtures/plugin-example/.claude-plugin/plugin.schema.json",
        "tests/fixtures/plugin-example/.lsp.schema.json",
        "tests/fixtures/plugin-example/.mcp.schema.json",
        "tests/fixtures/plugin-example/skills/skill/SKILL.schema.yaml",
        "tests/fixtures/windows_certification/public-development-profile.arg",
        "tests/fixtures/windows_certification/public-development-arg-policy.json",
        "tests/fixtures/xrefs/portable-evidence-ascii.dxf",
        "tests/reader-qualification/acadrust-0.4.0-diagnostic-baseline.json",
        "tests/reader-qualification/acadrust-0.4.1-diagnostic-baseline.json",
        "tests/reader-qualification/acadrust-0.4.1-on-0.4.0-fixtures.json",
        "crates/distribution/approval/schemas/owner-distribution-approval.schema.json",
        "crates/distribution/approval/schemas/preview-clean-host-receipt.schema.json",
        "crates/distribution/approval/schemas/preview-publication-handoff.schema.json",
        "crates/distribution/approval/schemas/windows-preview-build-attestation.schema.json",
        "crates/distribution/packager/tools/.gitignore",
        "crates/distribution/packager/tools/mcpb-validator/.gitignore",
        "crates/distribution/packager/tools/mcpb-validator/package.json",
        "crates/distribution/packager/tools/mcpb-validator/package-lock.json",
    ] {
        assert!(!is_ignored(&repository, path), "{path} should be admitted");
    }

    for path in [
        "unreviewed-root-file",
        ".githooks/pre-commit",
        ".githooks/pre-push.sh",
        ".github/workflows/local-script.sh",
        "crates/unreviewed/Cargo.toml",
        "crates/autocad-reader/README.md",
        "crates/autocad-reader/tests/unreviewed.rs",
        "crates/autocad-reader/src/generated/table.json",
        "crates/autocad-reader/docs/2026-07-29-unreviewed-design.md",
        "crates/autocad-writer/README.md",
        "crates/autocad-writer/tests/unreviewed.rs",
        "crates/autocad-writer/src/generated/table.json",
        "crates/autocad-writer/docs/2026-07-29-unreviewed-design.md",
        "crates/autocad-mcp/docs/2026-07-29-unreviewed-design.md",
        "crates/autolisp-lsp/docs/2026-07-29-unreviewed-design.md",
        "crates/autolisp-validate/docs/2026-07-07-unreviewed-design.md",
        "crates/distribution/approval/docs/2026-07-29-unreviewed-design.md",
        "crates/distribution/evidence/docs/2026-07-29-unreviewed-design.md",
        "crates/distribution/packager/docs/2026-07-29-unreviewed-design.md",
        "crates/distribution/plugin-validation/docs/2026-07-29-unreviewed-design.md",
        "crates/distribution/qualification/docs/2026-07-28-unreviewed-design.md",
        "crates/distribution-approval/docs/2026-07-29-unreviewed-design.md",
        "crates/distribution-approval/src/unreviewed.json",
        "crates/distribution-evidence/docs/2026-07-29-unreviewed-design.md",
        "crates/distribution-evidence/src/unreviewed.json",
        "crates/plugin-validate/docs/2026-07-29-unreviewed-design.md",
        "crates/release-packager/docs/2026-07-29-unreviewed-design.md",
        "crates/release-qualification/docs/2026-07-28-unreviewed-design.md",
        "crates/release-qualification/src/unreviewed.json",
        "crates/autocad-mcp/src/generated/table.json",
        "crates/xtask/docs/2026-07-29-unreviewed-design.md",
        "crates/xtask/scripts/local-gate.sh",
        "docs/.gitignore",
        "docs/specs/unreviewed.md",
        "docs/plans/unreviewed.md",
        "plugin/README.md",
        "plugin/private/secret.md",
        "plugin/.third-party/private.json",
        "plugin/.third-party/license-supplements/unreviewed.txt",
        "plugin/dependency-license-policy.json",
        "plugin/dependency-license-provenance.json",
        "plugin/dependency-source-lock.spdx.json",
        "plugin/dependency-windows-source-closure.spdx.json",
        "plugin/dependency-license-supplements/rmcp-1.7.0-LICENSE.txt",
        "plugin/skills/autolisp/references/private.json",
        "tests/corpus/open/unreviewed.dwg",
        "tests/corpus/open/unreviewed.dxf",
        "tests/fixtures/plugin-example/nested/example.json",
        "tests/fixtures/plugin-example/nested/example.yaml",
        "tests/fixtures/plugin-example/nested/example.md",
        "tests/fixtures/plugin-example/source.bin",
        "tests/fixtures/plugin-example/scripts/unreviewed.js",
        "tests/fixtures/windows_certification/unreviewed.arg",
        "tests/fixtures/windows_certification/unreviewed-policy.json",
        "tests/reader-qualification/unreviewed.json",
        "crates/distribution/approval/schemas/unreviewed.schema.json",
        "schemas/release/unreviewed.schema.json",
        "schemas/unreviewed.schema.json",
        "tools/unreviewed.txt",
        "tools/mcpb-validator/unreviewed.json",
        "tools/unreviewed-validator/package.json",
        "crates/distribution/packager/tools/mcpb-validator/unreviewed.json",
        "crates/distribution/packager/tools/unreviewed-validator/package.json",
    ] {
        assert!(
            is_ignored(&repository, path),
            "{path} should remain ignored"
        );
    }
}

#[test]
fn tracked_tree_and_public_orientation_exclude_private_specifications() {
    let repository = repository_root();
    let tracked = tracked_paths(&repository);
    let tracked_specifications = tracked
        .iter()
        .filter(|path| {
            path.starts_with("docs/") || (path.starts_with("crates/") && path.contains("/docs/"))
        })
        .collect::<Vec<_>>();
    assert!(
        tracked_specifications.is_empty(),
        "root and crate specification directories must remain absent from the tracked tree: {tracked_specifications:?}"
    );

    let readme =
        std::fs::read_to_string(repository.join("README.md")).expect("README should be readable");
    let fixture_ledger = std::fs::read_to_string(repository.join("tests/fixture-provenance.json"))
        .expect("fixture provenance ledger should be readable");
    for (label, content) in [("README", readme), ("fixture provenance", fixture_ledger)] {
        for line in content.lines() {
            assert!(
                !(line.contains("crates/") && line.contains("/docs/"))
                    && !line.contains("docs/specs/")
                    && !line.contains("docs/plans/"),
                "{label} must not reference a removed private specification path: {line}"
            );
        }
    }
}

#[cfg(unix)]
#[test]
fn local_pre_push_hook_is_executable() {
    use std::os::unix::fs::PermissionsExt;

    let hook = repository_root().join(".githooks/pre-push");
    let metadata = std::fs::metadata(&hook).expect("tracked pre-push hook should exist");
    assert!(metadata.is_file(), "pre-push hook must be a regular file");
    assert_ne!(
        metadata.permissions().mode() & 0o111,
        0,
        "pre-push hook must have an executable bit"
    );
}

#[cfg(unix)]
#[test]
fn local_pre_push_hook_has_valid_shell_syntax() {
    let hook = repository_root().join(".githooks/pre-push");
    let output = Command::new("/bin/sh")
        .args(["-n"])
        .arg(&hook)
        .output()
        .expect("POSIX sh should be available to validate the pre-push hook");
    assert!(
        output.status.success(),
        "pre-push hook must have valid POSIX shell syntax: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn local_pre_push_hook_scopes_incremental_compilation_to_serial_gate_work() {
    let hook = std::fs::read_to_string(repository_root().join(".githooks/pre-push"))
        .expect("tracked pre-push hook should be readable UTF-8");
    let incremental = hook
        .find("export CARGO_INCREMENTAL=1")
        .expect("pre-push hook must opt its serial Cargo work into incremental compilation");
    let thin_command =
        "exec cargo run --locked -p xtask --no-default-features --bin pre-push-dispatch -- \"$@\"";
    let coordinator = hook
        .find(thin_command)
        .expect("pre-push hook must launch the tracked thin dispatcher");
    assert!(
        incremental < coordinator,
        "incremental compilation must be enabled before the coordinator and its child gates launch"
    );
    assert_eq!(
        hook.matches("CARGO_INCREMENTAL").count(),
        1,
        "the hook must have one closed incremental-compilation override"
    );
    assert_eq!(
        hook.matches("cargo run").count(),
        1,
        "the hook must launch exactly one Cargo coordinator"
    );
    assert!(
        hook.contains("--no-default-features --bin pre-push-dispatch"),
        "the hook must exclude the full xtask and product dependency graph"
    );
    assert!(
        !hook.contains("-p xtask -- pre-push"),
        "the hook must not bootstrap pre-push through the full xtask binary"
    );
    assert!(
        !hook.contains("CARGO_TARGET_DIR"),
        "the hook must continue to use the repository-configured shared target"
    );
}

#[test]
fn xref_failpoint_clippy_is_scoped_to_the_instrumented_product_targets() {
    let repository = repository_root();
    let manifest = std::fs::read_to_string(repository.join("crates/autocad-mcp/Cargo.toml"))
        .expect("autocad-mcp manifest should be readable");
    let profile = concat!(
        "[[package.metadata.local-gate.profiles]]\n",
        "name = \"xref-certification-failpoints\"\n",
        "features = [\"xref-certification-failpoints\"]\n",
        "clippy = true\n",
        "test = false\n",
        "targets = [\"lib\", \"bin:autocad-mcp\"]\n",
    );
    assert_eq!(
        manifest.matches(profile).count(),
        1,
        "XREF failpoint Clippy must cover only the instrumented library and product binary"
    );

    let coordinator = std::fs::read_to_string(repository.join("crates/xtask/src/main.rs"))
        .expect("xtask coordinator should be readable");
    for boundary in [
        "LocalGateProfileTarget::Lib => arguments.push(\"--lib\".to_owned())",
        "arguments.extend([\"--bin\".to_owned(), binary.clone()])",
        "arguments.push(\"--no-deps\".to_owned())",
    ] {
        assert!(
            coordinator.contains(boundary),
            "scoped feature-profile Clippy is missing boundary: {boundary}"
        );
    }
}

#[test]
fn thin_pre_push_dispatch_has_no_active_normal_or_build_dependencies() {
    let repository = repository_root();
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(cargo)
        .current_dir(&repository)
        .args([
            "metadata",
            "--locked",
            "--format-version",
            "1",
            "--no-default-features",
        ])
        .output()
        .expect("no-default-features cargo metadata should run");
    assert!(
        output.status.success(),
        "no-default-features cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("cargo metadata should emit JSON");
    let xtask = metadata["packages"]
        .as_array()
        .expect("metadata packages should be an array")
        .iter()
        .find(|package| package["name"] == "xtask")
        .expect("metadata should contain xtask");
    let xtask_id = xtask["id"]
        .as_str()
        .expect("xtask package ID should be text");
    let xtask_node = metadata["resolve"]["nodes"]
        .as_array()
        .expect("metadata resolve nodes should be an array")
        .iter()
        .find(|node| node["id"] == xtask_id)
        .expect("metadata resolve should contain xtask");
    let active_non_dev_dependencies = xtask_node["deps"]
        .as_array()
        .expect("xtask dependency nodes should be an array")
        .iter()
        .filter(|dependency| {
            dependency["dep_kinds"]
                .as_array()
                .expect("dependency kinds should be an array")
                .iter()
                .any(|kind| kind["kind"].is_null() || kind["kind"] == "build")
        })
        .map(|dependency| dependency["name"].as_str().unwrap_or("<non-text>"))
        .collect::<Vec<_>>();
    assert!(
        active_non_dev_dependencies.is_empty(),
        "the no-default-features pre-push dispatcher must not activate normal or build dependencies: {active_non_dev_dependencies:?}"
    );

    let targets = xtask["targets"]
        .as_array()
        .expect("xtask targets should be an array");
    let dispatcher = targets
        .iter()
        .find(|target| target["name"] == "pre-push-dispatch")
        .expect("xtask must expose the thin pre-push dispatcher");
    assert!(
        dispatcher["required-features"].is_null(),
        "the thin dispatcher must remain available without the full feature"
    );
    let full_xtask = targets
        .iter()
        .find(|target| target["name"] == "xtask")
        .expect("xtask must retain its full coordinator");
    assert_eq!(
        full_xtask["required-features"],
        serde_json::json!(["full"]),
        "the full coordinator must remain feature-gated away from rapid pre-push"
    );
}

#[test]
fn content_validation_receipts_are_advisory_and_package_owned() {
    let repository = repository_root();
    let receipt_engine =
        std::fs::read_to_string(repository.join("crates/xtask/src/content_receipt.rs"))
            .expect("content receipt engine should be readable");
    for boundary in [
        r#"const RECEIPT_SCOPE: &str = "advisory_validation_cache_only";"#,
        "release_authority: false,",
        r#"const DISABLE_RECEIPTS_ENVIRONMENT: &str = "AUTOCAD_MCP_DISABLE_CONTENT_RECEIPTS";"#,
        r#"const CACHE_COMPONENTS: [&str; 2] = ["local-ci-receipts", "v1"];"#,
        "#[serde(deny_unknown_fields)]",
    ] {
        assert!(
            receipt_engine.contains(boundary),
            "content receipts must retain their non-authoritative boundary: {boundary}"
        );
    }
    for forbidden in [
        "owner_distribution_approval",
        "signing_authority",
        "publication_authority",
        "native_autocad_certification",
    ] {
        assert!(
            !receipt_engine.contains(forbidden),
            "advisory content receipts must not acquire {forbidden}"
        );
    }

    let declarations = WalkDir::new(repository.join("crates"))
        .follow_links(false)
        .into_iter()
        .map(|entry| entry.expect("crate tree should be walkable"))
        .filter(|entry| entry.file_type().is_file() && entry.file_name() == "Cargo.toml")
        .filter_map(|entry| {
            let contents = std::fs::read_to_string(entry.path())
                .expect("Cargo manifest should be readable UTF-8");
            contents.contains("content-receipt").then(|| {
                entry
                    .path()
                    .strip_prefix(&repository)
                    .expect("manifest should be repository-relative")
                    .to_string_lossy()
                    .replace('\\', "/")
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(
        declarations,
        ["crates/distribution/evidence/Cargo.toml"],
        "content-receipt declarations must remain closed to reviewed package-owned checks"
    );

    let evidence_manifest =
        std::fs::read_to_string(repository.join("crates/distribution/evidence/Cargo.toml"))
            .expect("distribution-evidence manifest should be readable");
    assert_eq!(
        evidence_manifest
            .matches(r#"content-receipt = "distribution-evidence""#)
            .count(),
        1,
        "distribution evidence must own exactly one content receipt target"
    );
}

#[test]
fn project_license_is_canonical_and_consistent() {
    let repository = repository_root();
    let root_license = std::fs::read(repository.join("LICENSE"))
        .expect("root LICENSE should be a readable regular file");
    let plugin_license = std::fs::read(repository.join("plugin/LICENSE"))
        .expect("plugin LICENSE should be a readable regular file");

    assert!(!root_license.is_empty(), "root LICENSE must be nonempty");
    assert_eq!(
        root_license, plugin_license,
        "license texts must be identical"
    );
    assert_eq!(
        format!("{:x}", Sha256::digest(&root_license)),
        CANONICAL_GPLV3_SHA256,
        "LICENSE must remain the unmodified canonical GNU GPLv3 text"
    );

    let plugin_json: serde_json::Value = serde_json::from_slice(
        &std::fs::read(repository.join("plugin/.claude-plugin/plugin.json"))
            .expect("plugin metadata should be readable"),
    )
    .expect("plugin metadata should be valid JSON");
    assert_eq!(plugin_json["license"], PROJECT_LICENSE);

    let metadata = cargo_metadata(&repository);
    let packages = metadata["packages"]
        .as_array()
        .expect("cargo metadata packages should be an array");
    assert!(
        !packages.is_empty(),
        "workspace must contain at least one Cargo package"
    );
    for package in packages {
        assert_eq!(
            package["license"], PROJECT_LICENSE,
            "Cargo package {} has inconsistent licensing",
            package["name"]
        );
    }
}

#[test]
fn supplemental_mcpb_validator_is_private_exact_and_lockfile_bound() {
    let repository = repository_root();
    let package_path =
        repository.join("crates/distribution/packager/tools/mcpb-validator/package.json");
    let lock_path =
        repository.join("crates/distribution/packager/tools/mcpb-validator/package-lock.json");
    let tracked = tracked_paths(&repository);
    for required in [
        "crates/distribution/packager/tools/mcpb-validator/package.json",
        "crates/distribution/packager/tools/mcpb-validator/package-lock.json",
    ] {
        assert!(
            tracked.iter().any(|path| path == required),
            "the sealed source must track the supplemental validator input: {required}"
        );
    }
    let package_bytes = std::fs::read(&package_path).expect("validator package should be readable");
    let lock_bytes = std::fs::read(&lock_path).expect("validator lockfile should be readable");
    assert_eq!(
        format!("{:x}", Sha256::digest(&package_bytes)),
        MCPB_VALIDATOR_PACKAGE_SHA256,
        "the reviewed supplemental MCPB validator package changed"
    );
    assert_eq!(
        format!("{:x}", Sha256::digest(&lock_bytes)),
        MCPB_VALIDATOR_LOCK_SHA256,
        "the reviewed supplemental MCPB validator lockfile changed"
    );

    let package: serde_json::Value =
        serde_json::from_slice(&package_bytes).expect("validator package should be JSON");
    assert_eq!(
        package,
        serde_json::json!({
            "name": "autocad-mcp-mcpb-validator",
            "version": "0.0.0",
            "private": true,
            "description": "Pinned supplemental MCPB manifest validator for release review",
            "engines": {"node": "24.18.0"},
            "devDependencies": {"@anthropic-ai/mcpb": "2.1.2"},
            "overrides": {"tmp": "0.2.7"}
        }),
        "the supplemental validator package contract changed"
    );

    let lock: serde_json::Value =
        serde_json::from_slice(&lock_bytes).expect("validator lockfile should be JSON");
    assert_eq!(lock["lockfileVersion"], 3);
    assert_eq!(lock["requires"], true);
    let packages = lock["packages"]
        .as_object()
        .expect("validator lockfile packages should be an object");
    assert_eq!(
        packages.len(),
        55,
        "validator dependency closure changed without review"
    );
    assert_eq!(
        packages[""]["devDependencies"],
        serde_json::json!({"@anthropic-ai/mcpb": "2.1.2"})
    );
    assert_eq!(
        packages[""]["engines"],
        serde_json::json!({"node": "24.18.0"})
    );
    let mcpb = &packages["node_modules/@anthropic-ai/mcpb"];
    assert_eq!(mcpb["version"], "2.1.2");
    assert_eq!(
        mcpb["integrity"],
        "sha512-goRbBC8ySo7SWb7tRzr+tL6FxDc4JPTRCdgfD2omba7freofvjq5rom1lBnYHZHo6Mizs1jAHJeN53aZbDoy8A=="
    );
    assert_eq!(mcpb["license"], "MIT");
    assert_eq!(mcpb["bin"], serde_json::json!({"mcpb": "dist/cli/cli.js"}));
    let patched_tmp = &packages["node_modules/tmp"];
    assert_eq!(
        patched_tmp["version"], "0.2.7",
        "the reviewed tmp path-traversal fixes must not be regressed"
    );
    assert_eq!(
        patched_tmp["integrity"],
        "sha512-e0votIpp4Uo2AJYSzVHV6xCcawuiez3DzqDAbrTc3YxBkplN6e+dM13ZeIcZnDg/QpSuU2zfZ3rzwY8ukEnaXw=="
    );
    assert!(
        !packages.contains_key("node_modules/os-tmpdir"),
        "the obsolete vulnerable tmp closure must not return"
    );
    for (path, dependency) in packages {
        if path.is_empty() {
            continue;
        }
        assert_eq!(
            dependency["dev"], true,
            "validator dependency {path} must remain development-only"
        );
        assert!(
            dependency["resolved"]
                .as_str()
                .is_some_and(|value| value.starts_with("https://registry.npmjs.org/")),
            "validator dependency {path} must use the reviewed npm registry"
        );
        assert!(
            dependency["integrity"]
                .as_str()
                .is_some_and(|value| value.starts_with("sha512-")),
            "validator dependency {path} must be integrity-bound"
        );
        assert!(
            dependency["license"]
                .as_str()
                .is_some_and(|value| !value.is_empty()),
            "validator dependency {path} must declare its package licence"
        );
    }
    assert!(
        !tracked.iter().any(|path| path.contains("/node_modules/")),
        "restored validator dependencies must never be tracked"
    );

    let attributes = std::fs::read_to_string(repository.join(".gitattributes"))
        .expect(".gitattributes should be readable");
    assert!(
        attributes.lines().any(|line| {
            line == "crates/distribution/packager/tools/mcpb-validator/*.json text eol=lf"
        }),
        "validator JSON line endings must remain stable"
    );
}

#[test]
fn autolisp_documentation_provenance_is_closed_and_line_endings_are_stable() {
    let repository = repository_root();
    for required in [
        "plugin/skills/autolisp/SKILL.md",
        "plugin/skills/autolisp/references/documentation-provenance.json",
    ] {
        assert!(
            repository.join(required).is_file(),
            "required documentation provenance boundary is missing: {required}"
        );
    }
    let errors = plugin_validate::validate_documentation_provenance(&repository.join("plugin"));
    assert!(
        errors.is_empty(),
        "AutoLISP documentation provenance failed: {errors:?}"
    );

    let attributes = std::fs::read_to_string(repository.join(".gitattributes"))
        .expect(".gitattributes should be readable");
    for expected in [
        "plugin/skills/autolisp/SKILL.md text eol=lf",
        "plugin/skills/autolisp/references/*.md text eol=lf",
        "plugin/skills/autolisp/references/**/*.md text eol=lf",
        "plugin/skills/autolisp/references/autolisp-lsp-index.json text eol=lf",
        "plugin/skills/autolisp/references/documentation-provenance.json text eol=lf",
    ] {
        assert!(
            attributes.lines().any(|line| line == expected),
            "documentation provenance line-ending rule is missing: {expected}"
        );
    }
}

#[test]
fn public_development_arg_is_exact_byte_bound_and_policy_closed() {
    let repository = repository_root();
    let arg_path =
        repository.join("tests/fixtures/windows_certification/public-development-profile.arg");
    let policy_path =
        repository.join("tests/fixtures/windows_certification/public-development-arg-policy.json");
    let arg_bytes = std::fs::read(&arg_path).expect("public development ARG should be readable");
    let policy_bytes =
        std::fs::read(&policy_path).expect("public development ARG policy should be readable");

    assert_eq!(
        format!("{:x}", Sha256::digest(&arg_bytes)),
        PUBLIC_DEVELOPMENT_ARG_SHA256,
        "the reviewed synthetic public ARG bytes changed"
    );
    assert_eq!(
        format!("{:x}", Sha256::digest(&policy_bytes)),
        PUBLIC_DEVELOPMENT_ARG_POLICY_SHA256,
        "the reviewed synthetic public ARG policy bytes changed"
    );
    let inspection =
        autocad_mcp::certified_arg::validate_distribution_safe_arg(&arg_bytes, &policy_bytes)
            .expect("the reviewed synthetic public ARG should satisfy its closed policy");
    assert_eq!(inspection.raw_arg_sha256, PUBLIC_DEVELOPMENT_ARG_SHA256);
    assert_eq!(
        inspection.policy_sha256,
        PUBLIC_DEVELOPMENT_ARG_POLICY_SHA256
    );

    let attributes = std::fs::read_to_string(repository.join(".gitattributes"))
        .expect(".gitattributes should be readable");
    let first_rule = attributes
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'));
    assert_eq!(
        first_rule,
        Some("* text=auto eol=lf"),
        "all detected text must be materialized as LF before isolated Git checks; \
         exact-byte inputs remain protected by the later binary rules"
    );
    for expected in [
        "Cargo.lock text eol=lf",
        "rust-toolchain.toml text eol=lf",
        "crates/**/*.rs text eol=lf",
        "tests/**/*.rs text eol=lf",
        "crates/autocad-mcp/Cargo.toml text eol=lf",
        "crates/autocad-mcp/build.rs text eol=lf",
        "crates/autocad-mcp/src/**/*.rs text eol=lf",
        "crates/autocad-mcp/resources/*.json text eol=lf",
        "crates/autocad-mcp/profile-registry/*.json text eol=lf",
        "crates/distribution/approval/Cargo.toml text eol=lf",
        "crates/distribution/approval/src/**/*.rs text eol=lf",
        "crates/distribution/evidence/src/lib.rs text eol=lf",
        "crates/distribution/qualification/Cargo.toml text eol=lf",
        "crates/distribution/qualification/src/**/*.rs text eol=lf",
        "crates/xtask/src/source_bundle.rs text eol=lf",
        "plugin/.third-party/third-party-license-policy.json text eol=lf",
        "plugin/.third-party/third-party-license-provenance.json text eol=lf",
        "plugin/.third-party/source-lock.spdx.json text eol=lf",
        "plugin/.third-party/source-closure-windows.spdx.json text eol=lf",
        "plugin/.third-party/license-supplements/* binary",
        "crates/distribution/approval/schemas/owner-distribution-approval.schema.json text eol=lf",
        "crates/distribution/approval/schemas/preview-clean-host-receipt.schema.json text eol=lf",
        "crates/distribution/approval/schemas/preview-publication-handoff.schema.json text eol=lf",
        "crates/distribution/approval/schemas/windows-preview-build-attestation.schema.json text eol=lf",
        "tests/fixtures/windows_certification/public-development-arg-policy.json text eol=lf",
        "tests/fixtures/windows_certification/public-development-profile.arg binary",
        "tests/fixtures/xrefs/*.dxf binary",
        "tests/reader-qualification/*.json text eol=lf",
    ] {
        assert!(
            attributes.lines().any(|line| line == expected),
            "preflight exact-byte input attribute is missing: {expected}"
        );
    }
}

#[test]
fn preview_activation_profile_directory_matches_the_embedded_bundle_exactly() {
    const SOURCE_RESOURCE_PREFIX: &str = "crates/autocad-mcp/resources/";
    const PROFILE_PREFIX: &str = "activation-profiles/";

    let repository = repository_root();
    let profile_directory = repository.join("crates/autocad-mcp/resources/activation-profiles");
    let directory_metadata = std::fs::symlink_metadata(&profile_directory)
        .expect("Preview activation profile directory should be readable");
    assert!(
        directory_metadata.is_dir() && !directory_metadata.file_type().is_symlink(),
        "Preview activation profile directory must be one real directory"
    );

    let expected = autocad_mcp::activation::embedded_activation_bundle()
        .expect("embedded Preview activation bundle should be valid")
        .files
        .into_iter()
        .filter_map(|file| file.path.strip_prefix(PROFILE_PREFIX))
        .map(|path| format!("{SOURCE_RESOURCE_PREFIX}{PROFILE_PREFIX}{path}"))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        expected.len(),
        20,
        "embedded Preview activation bundle must bind ten ARG/policy pairs"
    );

    let actual = std::fs::read_dir(&profile_directory)
        .expect("Preview activation profile directory should be enumerable")
        .map(|entry| {
            let entry = entry.expect("Preview activation profile entry should be readable");
            let file_type = entry
                .file_type()
                .expect("Preview activation profile entry type should be readable");
            assert!(
                file_type.is_file() && !file_type.is_symlink(),
                "Preview activation profile inventory admits regular files only"
            );
            repository_relative_path(&repository, &entry.path())
        })
        .collect::<BTreeSet<_>>();

    assert_eq!(
        actual, expected,
        "Preview activation profile directory must equal the exact embedded ARG/policy inventory"
    );
}

#[test]
fn every_tracked_file_is_admitted_by_the_whitelist() {
    let violations = tracked_whitelist_violations(&repository_root());
    assert!(
        violations.is_empty(),
        "tracked paths bypass the whitelist policy: {violations:?}"
    );
}

#[test]
fn tracked_file_audit_detects_a_forced_add() {
    let repository = tempfile::tempdir().expect("temporary repository should be creatable");
    run_git(repository.path(), &["init", "--quiet"]);
    std::fs::write(
        repository.path().join(".gitignore"),
        "/*\n!/.gitignore\n!/tests/\n",
    )
    .unwrap();
    std::fs::create_dir(repository.path().join("tests")).unwrap();
    std::fs::write(
        repository.path().join("tests/.gitignore"),
        "/**\n!/.gitignore\n!/**/*.rs\n",
    )
    .unwrap();
    std::fs::write(
        repository.path().join("tests/accepted.rs"),
        "fn accepted() {}\n",
    )
    .unwrap();
    std::fs::write(
        repository.path().join("tests/unreviewed.dwg"),
        b"unreviewed",
    )
    .unwrap();

    run_git(
        repository.path(),
        &[
            "add",
            "--",
            ".gitignore",
            "tests/.gitignore",
            "tests/accepted.rs",
        ],
    );
    run_git(
        repository.path(),
        &["add", "--force", "--", "tests/unreviewed.dwg"],
    );

    assert_eq!(
        tracked_whitelist_violations(repository.path()),
        ["tests/unreviewed.dwg"]
    );
}

fn assert_windows_workflow_envelope(name: &str, workflow: &str) {
    assert!(
        workflow.contains("runs-on: windows-2025"),
        "{name} must use the reviewed GitHub-hosted Windows image"
    );
    assert!(
        workflow.contains("permissions:\n  contents: read"),
        "{name} must have a read-only token"
    );
    assert!(
        workflow.contains("persist-credentials: false"),
        "{name} must not persist checkout credentials"
    );
    assert!(
        workflow.contains("CARGO_INCREMENTAL: \"0\""),
        "{name} must disable incremental compilation"
    );

    for line in workflow.lines().map(str::trim) {
        let Some(action) = line
            .strip_prefix("uses: ")
            .or_else(|| line.strip_prefix("- uses: "))
        else {
            continue;
        };
        let (_, revision) = action
            .split_once('@')
            .expect("workflow actions must include an immutable revision");
        let revision = revision
            .split_whitespace()
            .next()
            .expect("workflow action revision must be present");
        assert_eq!(
            revision.len(),
            40,
            "{name} actions must use full commit SHAs"
        );
        assert!(
            revision.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "{name} action revision is not hexadecimal"
        );
    }

    for forbidden in [
        "pull_request_target",
        "contents: write",
        "permissions: write-all",
        "secrets.",
        "secrets[",
        "environment:",
        "self-hosted",
        "write-all",
        "AUTOCAD_MCP_TIER2_MANIFEST",
        "AUTOCAD_MCP_XREF_CERT_MANIFEST",
        "AUTOCAD_MCP_CERT_OUTPUT_DIR",
        "AUTOCAD_MCP_XREF_CERTIFIED_ARG_PATH",
        "AUTOCAD_MCP_XREF_CERTIFIED_ARG_SHA256",
        "AUTOCAD_MCP_ACCORECONSOLE_PATH",
        "AUTOCAD_MCP_XREF_FAILPOINT",
    ] {
        assert!(
            !workflow.contains(forbidden),
            "{name} contains forbidden scope: {forbidden}"
        );
    }
}

fn workflow_run_commands(workflow: &str) -> Vec<&str> {
    workflow
        .lines()
        .filter_map(|line| line.trim().strip_prefix("run: "))
        .collect()
}

fn assert_windows_development_cache_contract(
    name: &str,
    workflow: &str,
    dependency_cache_writer: bool,
    content_receipt_cache: bool,
) {
    let restore = concat!(
        "uses: actions/cache/restore@",
        "caa296126883cff596d87d8935842f9db880ef25 # v5.1.0"
    );
    let save = concat!(
        "uses: actions/cache/save@",
        "caa296126883cff596d87d8935842f9db880ef25 # v5.1.0"
    );
    let sccache = concat!(
        "uses: mozilla-actions/sccache-action@",
        "9e7fa8a12102821edf02ca5dbea1acd0f89a2696 # v0.0.10"
    );
    let cache_key = concat!(
        "cargo-registry-v1-windows-2025-${{ runner.arch }}-",
        "${{ hashFiles('rust-toolchain.toml') }}-${{ hashFiles('Cargo.lock') }}"
    );

    assert_eq!(
        workflow.matches(restore).count(),
        1 + usize::from(content_receipt_cache),
        "{name} cache-restore action inventory changed"
    );
    assert_eq!(
        workflow.matches(sccache).count(),
        1,
        "{name} must install the one reviewed compiler cache"
    );
    let sccache_install = workflow
        .find("- name: Install the pinned shared compiler cache")
        .expect("development workflow must install sccache");
    let first_cargo = workflow
        .find("run: cargo fetch --locked")
        .expect("development workflow must fetch locked dependencies");
    assert!(
        sccache_install < first_cargo,
        "{name} must install sccache before any Cargo command can inherit RUSTC_WRAPPER=sccache"
    );
    assert_eq!(
        workflow.matches("version: \"v0.15.0\"").count(),
        1,
        "{name} must pin the reviewed sccache binary version"
    );
    assert_eq!(
        workflow.matches("RUSTC_WRAPPER: sccache").count(),
        1,
        "{name} must configure sccache exactly once"
    );
    assert_eq!(
        workflow.matches("SCCACHE_GHA_ENABLED: \"true\"").count(),
        1,
        "{name} must use the shared GitHub Actions compiler cache"
    );
    assert_eq!(
        workflow
            .matches("SCCACHE_BASEDIRS: ${{ github.workspace }}")
            .count(),
        1,
        "{name} must normalize the checkout root for cross-workflow hits"
    );
    let steps = workflow
        .find("    steps:\n")
        .expect("development workflow must have a steps block");
    for variable in [
        "RUSTC_WRAPPER: sccache",
        "SCCACHE_BASEDIRS: ${{ github.workspace }}",
        "SCCACHE_GHA_ENABLED: \"true\"",
    ] {
        assert!(
            workflow
                .find(variable)
                .is_some_and(|position| position < steps),
            "{name} must configure {variable} at job scope so every Cargo step inherits it"
        );
    }
    assert!(
        workflow.contains(cache_key),
        "{name} dependency cache must bind the runner, toolchain, and Cargo.lock"
    );
    assert!(
        workflow.contains(
            "restore-keys: |\n            cargo-registry-v1-windows-2025-${{ runner.arch }}-"
        ),
        "{name} must use only the reviewed dependency-cache restore prefix"
    );
    for path in ["~/.cargo/registry/index", "~/.cargo/registry/cache"] {
        assert!(
            workflow.contains(path),
            "{name} dependency cache is missing {path}"
        );
    }
    for forbidden in [
        "~/.cargo/registry/src",
        "~/.cargo/git",
        "enableCrossOsArchive",
        "CARGO_INCREMENTAL: \"1\"",
    ] {
        assert!(
            !workflow.contains(forbidden),
            "{name} cache contains forbidden state: {forbidden}"
        );
    }

    if dependency_cache_writer {
        assert_eq!(
            workflow.matches(save).count(),
            1 + usize::from(content_receipt_cache),
            "{name} cache-save action inventory changed"
        );
        assert!(workflow.contains(
            "if: ${{ github.event_name == 'push' && github.ref == 'refs/heads/main' && steps.cargo-dependencies.outputs.cache-hit != 'true' }}"
        ));
    } else {
        assert!(
            !workflow.contains(save),
            "{name} must remain restore-only for dependency caching"
        );
    }
}

fn assert_windows_semantic_receipt_cache_contract(workflow: &str) {
    let path = "path: target/local-ci-receipts/v1/windows-native-semantic";
    let key = "key: windows-semantic-receipt-v1-windows-2025-${{ runner.arch }}-${{ steps.windows-receipt-context.outputs.sha256 }}-${{ hashFiles('Cargo.lock', 'Cargo.toml', 'rust-toolchain.toml', 'crates/**', 'tests/fixtures/**', '.github/workflows/windows-native-harness.yml') }}";
    assert_eq!(
        workflow.matches(path).count(),
        2,
        "Windows semantic receipt restore and save must use one exact path"
    );
    assert_eq!(
        workflow.matches(key).count(),
        2,
        "Windows semantic receipt restore and save must use one exact content key"
    );
    assert_eq!(
        workflow.matches("id: windows-semantic-receipt").count(),
        1,
        "Windows semantic receipt must have one cache-hit source"
    );
    assert_eq!(
        workflow.matches("id: windows-receipt-context").count(),
        1,
        "Windows semantic receipts must bind one hosted-image observation"
    );
    assert!(workflow.contains("$env:ImageOS`n$env:ImageVersion`n$env:RUNNER_OS`n$env:RUNNER_ARCH"));
    assert!(workflow.contains(
        "if: ${{ github.event_name == 'push' && github.ref == 'refs/heads/main' && steps.windows-semantic-receipt.outputs.cache-hit != 'true' }}"
    ));
    let semantic = workflow
        .find("- name: Run the repository-owned Windows semantic tests")
        .expect("Windows semantic step should exist");
    let save = workflow
        .find("- name: Save the trusted main Windows semantic receipt")
        .expect("Windows semantic receipt save should exist");
    let candidate = workflow
        .find("- name: Seal the deterministic Windows target source candidate")
        .expect("Windows candidate step should exist");
    assert!(
        semantic < save && save < candidate,
        "a successful semantic result must be cached before independent candidate/build failures"
    );
    let receipt_restore = workflow
        .split("- name: Restore an exact main-authored Windows semantic receipt")
        .nth(1)
        .and_then(|tail| {
            tail.split("- name: Run the repository-owned Windows semantic tests")
                .next()
        })
        .expect("Windows semantic receipt restore block should be closed");
    assert!(
        !receipt_restore.contains("restore-keys:"),
        "validation receipts must restore only an exact content key"
    );
    assert!(
        !workflow.contains("path: target\n"),
        "the Windows workflow must never cache the full Cargo target"
    );
}

fn assert_workflow_path_routing(workflow: &str, expected_paths: &[&str]) {
    for path in expected_paths {
        assert_eq!(
            workflow.matches(&format!("      - {path}\n")).count(),
            2,
            "workflow path routing must include {path} for both pull requests and main pushes"
        );
    }
    assert_eq!(
        workflow.matches("    paths:\n").count(),
        2,
        "workflow must have one pull-request and one push path filter"
    );
}

fn assert_windows_only_test(source: &str, source_path: &str, test_name: &str) {
    let marker = format!("fn {test_name}(");
    let position = source.find(&marker).unwrap_or_else(|| {
        panic!("Windows workflow test is missing from {source_path}: {test_name}")
    });
    let attributes = source[..position].lines().rev().take(4).collect::<Vec<_>>();
    assert!(
        attributes.iter().any(|line| line.trim() == "#[test]"),
        "Windows workflow filter does not name a test in {source_path}: {test_name}"
    );
    assert!(
        attributes.iter().any(|line| {
            matches!(
                line.trim(),
                "#[cfg(windows)]" | "#[cfg(target_os = \"windows\")]"
            )
        }),
        "Windows workflow test is not explicitly Windows-only in {source_path}: {test_name}"
    );
}

#[test]
fn windows_workflows_are_narrow_read_only_and_immutable() {
    let repository = repository_root();
    let workflow_directory = repository.join(".github/workflows");
    let mut workflow_inventory = std::fs::read_dir(&workflow_directory)
        .expect("workflow directory should be readable")
        .filter_map(|entry| {
            let entry = entry.expect("workflow entry should be readable");
            matches!(
                entry
                    .path()
                    .extension()
                    .and_then(|extension| extension.to_str()),
                Some("yml" | "yaml")
            )
            .then(|| entry.file_name().to_string_lossy().into_owned())
        })
        .collect::<Vec<_>>();
    workflow_inventory.sort();
    assert_eq!(
        workflow_inventory,
        [
            "windows-native-harness.yml",
            "windows-preview-review-candidate.yml",
            "windows-xref-guarded-rename.yml"
        ],
        "the remote-Windows workflow inventory is closed"
    );
    let attributes = std::fs::read_to_string(repository.join(".gitattributes"))
        .expect(".gitattributes should be readable");
    for workflow in &workflow_inventory {
        let expected = format!(".github/workflows/{workflow} text eol=lf");
        assert!(
            attributes.lines().any(|line| line == expected),
            "digest-bound workflow is missing its exact LF attribute: {workflow}"
        );
    }

    let xref_path = workflow_directory.join("windows-xref-guarded-rename.yml");
    let xref_bytes = std::fs::read(&xref_path).expect("XREF workflow should be readable");
    assert_eq!(
        format!("{:x}", Sha256::digest(&xref_bytes)),
        WINDOWS_XREF_WORKFLOW_SHA256,
        "the reviewed one-job Windows workflow changed"
    );
    let xref_workflow =
        std::str::from_utf8(&xref_bytes).expect("XREF workflow should remain UTF-8");

    assert_windows_workflow_envelope("XREF feasibility workflow", xref_workflow);
    assert!(xref_workflow.contains(
        "run: $env:GIT_CONFIG_NOSYSTEM = \"1\"; $env:GIT_CONFIG_SYSTEM = \"NUL\"; \
         $env:GIT_CONFIG_GLOBAL = \"NUL\"; $env:GIT_ATTR_NOSYSTEM = \"1\"; \
         $status = @(git status --porcelain=v1 --untracked-files=all); \
         if ($LASTEXITCODE -ne 0) { throw \"isolated Git status failed\" }; \
         if ($status.Count -ne 0) { $status | Write-Error; \
         throw \"checkout bytes depend on ambient Git configuration\" }"
    ));
    assert!(xref_workflow.contains("name: Native filesystem feasibility characterization"));
    assert!(xref_workflow
        .contains("cargo run --locked -p xtask -- windows-native-tests --suite guarded-rename"));
    assert!(xref_workflow
        .contains("path: target/xref-windows-guarded-rename-feasibility-evidence.json"));
    assert_windows_development_cache_contract(
        "XREF feasibility workflow",
        xref_workflow,
        false,
        false,
    );
    assert_workflow_path_routing(
        xref_workflow,
        &[
            ".gitattributes",
            ".github/workflows/windows-xref-guarded-rename.yml",
            "Cargo.lock",
            "Cargo.toml",
            "crates/**",
            "rust-toolchain.toml",
        ],
    );
    assert_eq!(
        xref_workflow.matches("uses: ").count(),
        4,
        "XREF feasibility workflow may import only checkout, cache restore, sccache, and artifact upload"
    );
    let xref_source = std::fs::read_to_string(
        repository.join("crates/autocad-mcp/tests/windows_guarded_rename.rs"),
    )
    .expect("XREF guarded-rename source should be readable");
    assert!(
        xref_source.contains("#[cfg(target_os = \"windows\")]\nmod windows {"),
        "the remotely selected XREF test module must remain explicitly Windows-only"
    );
    assert!(
        xref_source.contains("fn windows_guarded_rename_feasibility_probe()"),
        "the remotely selected XREF test must remain in its reviewed source"
    );

    for forbidden in [
        "cargo clippy",
        "local-gate",
        "plugin-validate",
        "release-packager",
    ] {
        assert!(
            !xref_workflow.contains(forbidden),
            "XREF feasibility workflow contains forbidden scope: {forbidden}"
        );
    }

    let native_path = workflow_directory.join("windows-native-harness.yml");
    let native_bytes =
        std::fs::read(&native_path).expect("native Windows workflow should be readable");
    assert_eq!(
        format!("{:x}", Sha256::digest(&native_bytes)),
        WINDOWS_NATIVE_HARNESS_WORKFLOW_SHA256,
        "the reviewed native Windows workflow changed"
    );
    let native_workflow =
        std::str::from_utf8(&native_bytes).expect("native Windows workflow should remain UTF-8");

    assert_windows_workflow_envelope("native Windows workflow", native_workflow);
    assert!(native_workflow.contains("name: Windows-only non-AutoCAD evidence"));
    assert_windows_development_cache_contract(
        "native Windows workflow",
        native_workflow,
        true,
        true,
    );
    assert_windows_semantic_receipt_cache_contract(native_workflow);
    assert_workflow_path_routing(
        native_workflow,
        &[
            ".gitattributes",
            ".github/workflows/windows-native-harness.yml",
            "Cargo.lock",
            "Cargo.toml",
            "crates/**",
            "plugin/**",
            "rust-toolchain.toml",
            "tests/fixtures/**",
        ],
    );
    assert_eq!(
        native_workflow.matches("uses: ").count(),
        6,
        "native Windows workflow may import only checkout, two cache restores, two cache saves, and sccache"
    );
    let expected_native_commands = [
        "$env:GIT_CONFIG_NOSYSTEM = \"1\"; $env:GIT_CONFIG_SYSTEM = \"NUL\"; $env:GIT_CONFIG_GLOBAL = \"NUL\"; $env:GIT_ATTR_NOSYSTEM = \"1\"; $status = @(git status --porcelain=v1 --untracked-files=all); if ($LASTEXITCODE -ne 0) { throw \"isolated Git status failed\" }; if ($status.Count -ne 0) { $status | Write-Error; throw \"checkout bytes depend on ambient Git configuration\" }",
        "rustup toolchain install --no-self-update",
        "$bytes = [Text.Encoding]::UTF8.GetBytes(\"$env:ImageOS`n$env:ImageVersion`n$env:RUNNER_OS`n$env:RUNNER_ARCH\"); $hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant(); \"sha256=$hash\" | Out-File -FilePath $env:GITHUB_OUTPUT -Encoding utf8 -Append",
        "cargo fetch --locked",
        "cargo run --locked -p xtask -- windows-native-tests --suite semantic --content-receipt",
        "cargo run --locked -p xtask -- source-candidate-seal --output-dir target/windows-source-candidate --mode preview",
        "cargo run --locked -p xtask -- windows-certification-build-preflight --arg tests/fixtures/windows_certification/public-development-profile.arg --arg-policy tests/fixtures/windows_certification/public-development-arg-policy.json --output-dir target/windows-certification-preflight",
        "cargo run --locked -p release-packager -- desktop-smoke --binary target/windows-certification-preflight/artifacts/release/autocad-mcp.exe --fixture tests/fixtures/xrefs/portable-evidence-ascii.dxf",
        "cargo run --locked -p release-packager -- lsp-smoke --binary target/windows-certification-preflight/artifacts/release/autolisp-lsp.exe",
        "cargo run --locked -p release-packager -- package --target windows-x64 --binary target/windows-certification-preflight/artifacts/preview/autocad-mcp.exe --lsp-binary target/windows-certification-preflight/artifacts/release/autolisp-lsp.exe --out-dir target/windows-preview-package --preview",
        "cargo run --locked -p release-packager -- smoke --package target/windows-preview-package/autocad-mcp-windows-x64-preview.mcpb --fixture tests/fixtures/xrefs/portable-evidence-ascii.dxf --require-executable --require-lsp-executable",
    ];
    assert_eq!(
        workflow_run_commands(native_workflow),
        expected_native_commands,
        "native Windows workflow command inventory changed"
    );
    assert!(
        !native_workflow.contains("cargo run --locked -p distribution-evidence -- check"),
        "the Windows workflow must not duplicate the full evidence check performed by candidate sealing"
    );
    let candidate_seal_source =
        std::fs::read_to_string(repository.join("crates/xtask/src/candidate_seal.rs"))
            .expect("candidate seal source should be readable");
    assert!(
        candidate_seal_source.contains("distribution_evidence::check(repository)"),
        "source candidate sealing must retain its full distribution-evidence validation"
    );

    for (source_path, test_names) in [
        (
            "crates/autocad-mcp/src/engine.rs",
            &[
                "accoreconsole_command_normalizes_only_autocad_path_arguments",
                "certified_profile_guard_allows_compatible_reader_and_denies_mutation_or_replacement",
                "certified_profile_guard_detects_transition_window_tampering",
                "unique_xref_profile_registry_lifecycle_refuses_adoption_and_cleans_owned_root",
                "bounded_windows_probe_runner_drains_all_bytes_while_retaining_a_strict_cap",
                "bounded_windows_probe_runner_observes_pre_spawn_cancellation",
                "bounded_windows_probe_runner_linearizes_cancellation_before_resume",
                "bounded_windows_probe_runner_terminates_inherited_pipe_tree_on_timeout",
                "bounded_windows_probe_runner_cancels_and_joins_running_tree",
                "activation_windows_observation_requires_a_fixed_file_version_resource",
                "activation_windows_executable_launch_lease_guards_file_and_parent_through_spawn",
            ][..],
        ),
        (
            "crates/autocad-mcp/src/activation_platform.rs",
            &[
                "activation_windows_exact_override_rejects_unc_before_canonicalization",
                "activation_windows_fixed_local_volume_admission_rejects_unc",
                "activation_windows_registry_root_seam_reads_exact_language_and_location_and_cleans_up",
            ][..],
        ),
        (
            "crates/autocad-mcp/src/ops/xref_mutation.rs",
            &[
                "production_windows_transactional_install_is_atomic_and_guarded",
                "production_windows_source_snapshot_excludes_every_original_path_read",
            ][..],
        ),
        (
            "crates/autocad-mcp/tests/windows_certification.rs",
            &[
                "certified_profile_registry_guard_owns_only_a_new_exact_subtree",
                "exact_runtime_file_binding_denies_windows_write_delete_and_ancestor_rename",
                "bounded_certification_runner_terminates_the_windows_process_tree",
                "bounded_certification_runner_rejects_a_successful_parent_with_a_live_descendant",
            ][..],
        ),
        (
            "crates/distribution/packager/src/smoke.rs",
            &[
                "windows_run_with_timeout_rejects_oversized_stdout",
                "windows_run_with_timeout_terminates_process_tree_after_direct_child_exit",
            ][..],
        ),
    ] {
        let source = std::fs::read_to_string(repository.join(source_path))
            .unwrap_or_else(|error| panic!("read {source_path}: {error}"));
        for test_name in test_names {
            assert_windows_only_test(&source, source_path, test_name);
        }
    }

    for forbidden in [
        "AUTOCAD_MCP_",
        "actions/upload-artifact",
        "--ignored",
        "--workspace",
        "--all-targets",
        "cargo clippy",
        "certification-manifest-preflight",
        "--bin autocad-mcp",
        "--lib --",
        "--test windows_certification --",
        "cargo test --locked -p release-packager -- --",
        "cargo test --locked -p xtask",
        "local-gate",
        "plugin-validate",
        "tests/corpus",
    ] {
        assert!(
            !native_workflow.contains(forbidden),
            "native Windows workflow contains forbidden scope: {forbidden}"
        );
    }
}

#[test]
fn preview_review_workflow_is_signed_protected_and_non_publishing() {
    let repository = repository_root();
    let path = repository.join(".github/workflows/windows-preview-review-candidate.yml");
    let bytes = std::fs::read(&path).expect("Preview review workflow should be readable");
    assert_eq!(
        format!("{:x}", Sha256::digest(&bytes)),
        WINDOWS_PREVIEW_REVIEW_WORKFLOW_SHA256,
        "the reviewed Preview candidate workflow changed"
    );
    let workflow =
        std::str::from_utf8(&bytes).expect("Preview review workflow should remain UTF-8");

    assert!(workflow.starts_with("name: Windows Preview signed review candidate\n\n"));
    assert!(workflow.contains("on:\n  workflow_dispatch:\n"));
    assert!(!workflow.contains("\n  pull_request:"));
    assert!(!workflow.contains("\n  push:"));
    assert!(!workflow.contains("\n  schedule:"));
    assert!(workflow.contains("permissions:\n  contents: read"));
    assert_eq!(
        workflow.matches("permissions:").count(),
        4,
        "Preview candidate workflow must have the global envelope, two empty isolated envelopes, and the exact attestation envelope"
    );
    assert_eq!(
        workflow.matches("    permissions: {}").count(),
        2,
        "signing and supplemental MCPB validation must have empty permission envelopes"
    );
    assert_eq!(workflow.matches("      id-token: write").count(), 1);
    assert_eq!(workflow.matches("      attestations: write").count(), 1);
    assert_eq!(workflow.matches("      contents: read").count(), 1);
    assert!(!workflow.contains("artifact-metadata: write"));
    assert_eq!(
        workflow.matches("environment: preview-signing").count(),
        1,
        "only the isolated signing job may use the protected Environment"
    );
    assert_eq!(
        workflow.matches("runs-on: windows-2025").count(),
        5,
        "the Preview review path must remain a five-job Windows pipeline"
    );
    for job in [
        "  build-preview-inputs:",
        "  sign-preview-binaries:",
        "  package-preview-review:",
        "  validate-preview-mcpb:",
        "  attest-preview-review:",
    ] {
        assert!(
            workflow.contains(job),
            "Preview review workflow is missing job: {job}"
        );
    }
    assert!(workflow.contains("    needs: build-preview-inputs"));
    assert!(workflow
        .contains("    needs:\n      - build-preview-inputs\n      - sign-preview-binaries"));
    assert!(workflow.contains("CARGO_INCREMENTAL: \"0\""));
    assert!(workflow.contains("persist-credentials: false"));
    assert!(workflow.contains("GITHUB_REF -cne \"refs/heads/main\""));
    assert!(workflow.contains("source_commit must exactly equal the checked-out main commit"));
    assert!(workflow.contains("signing_certificate_thumbprint:"));
    assert!(workflow.contains("protected_environment_configuration_reviewed:"));
    assert_eq!(
        workflow
            .matches("- name: Require the authorized GitHub execution context")
            .count(),
        5,
        "every Preview workflow job must begin with the origin and principal guard"
    );
    assert_eq!(
        workflow
            .matches("Preview candidate workflow context is not authorized")
            .count(),
        5,
        "every Preview workflow job must fail closed on an unauthorized rerun context"
    );

    let build_job_start = workflow
        .find("  build-preview-inputs:")
        .expect("build job should be present");
    let signing_job_start = workflow
        .find("  sign-preview-binaries:")
        .expect("signing job should be present");
    let package_job_start = workflow
        .find("  package-preview-review:")
        .expect("package job should be present");
    let validation_job_start = workflow
        .find("  validate-preview-mcpb:")
        .expect("supplemental MCPB validation job should be present");
    let attestation_job_start = workflow
        .find("  attest-preview-review:")
        .expect("supplemental attestation job should be present");
    assert!(
        build_job_start < signing_job_start
            && signing_job_start < package_job_start
            && package_job_start < validation_job_start
            && validation_job_start < attestation_job_start
    );
    let build_job = &workflow[build_job_start..signing_job_start];
    let signing_job = &workflow[signing_job_start..package_job_start];
    let package_job = &workflow[package_job_start..validation_job_start];
    let validation_job = &workflow[validation_job_start..attestation_job_start];
    let attestation_job = &workflow[attestation_job_start..];
    assert!(!build_job.contains("${{ secrets."));
    assert!(!build_job.contains("${{ vars."));
    assert!(!build_job.contains("environment:"));
    assert!(!package_job.contains("${{ secrets."));
    assert!(!package_job.contains("${{ vars."));
    assert!(!package_job.contains("environment:"));
    assert!(signing_job.contains("environment: preview-signing"));
    assert!(signing_job.contains("permissions: {}"));
    assert!(!signing_job.contains("actions/checkout"));
    assert!(!signing_job.contains("cargo "));
    assert!(!signing_job.contains("git "));
    assert!(validation_job.contains("permissions: {}"));
    assert!(!validation_job.contains("actions/checkout"));
    assert!(!validation_job.contains("${{ secrets."));
    assert!(!validation_job.contains("${{ vars."));
    assert!(!validation_job.contains("environment:"));
    assert!(!validation_job.contains("cargo "));
    assert!(!validation_job.contains("git "));
    assert!(!validation_job.contains("actions/attest"));
    assert!(!attestation_job.contains("actions/checkout"));
    assert!(!attestation_job.contains("${{ secrets."));
    assert!(!attestation_job.contains("${{ vars."));
    assert!(!attestation_job.contains("environment:"));
    assert!(!attestation_job.contains("cargo "));
    assert!(!attestation_job.contains("git "));
    assert!(!attestation_job.contains("npm "));

    assert_eq!(
        workflow.matches("uses: ").count(),
        12,
        "Preview candidate workflow may import only the reviewed checkout, artifact, Node, and attestation actions"
    );
    for line in workflow.lines().map(str::trim) {
        let Some(action) = line
            .strip_prefix("uses: ")
            .or_else(|| line.strip_prefix("- uses: "))
        else {
            continue;
        };
        let (_, revision) = action
            .split_once('@')
            .expect("Preview candidate actions must include an immutable revision");
        let revision = revision
            .split_whitespace()
            .next()
            .expect("Preview candidate action revision must be present");
        assert_eq!(
            revision.len(),
            40,
            "Preview candidate actions must use full commit SHAs"
        );
        assert!(
            revision.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "Preview candidate action revision is not hexadecimal"
        );
    }
    let checkout_action =
        "uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1";
    let download_action =
        "uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1";
    let upload_action =
        "uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1";
    let setup_node_action =
        "uses: actions/setup-node@820762786026740c76f36085b0efc47a31fe5020 # v7.0.0";
    let attest_action = "uses: actions/attest@f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6 # v4.2.0";
    assert_eq!(workflow.matches(checkout_action).count(), 2);
    assert_eq!(workflow.matches(download_action).count(), 5);
    assert_eq!(workflow.matches(upload_action).count(), 3);
    assert_eq!(workflow.matches(setup_node_action).count(), 1);
    assert_eq!(workflow.matches(attest_action).count(), 1);
    assert_eq!(
        workflow.matches("Compare-Object").count(),
        8,
        "every closed-inventory comparison must remain reviewable"
    );
    for line in workflow
        .lines()
        .filter(|line| line.contains("Compare-Object"))
    {
        assert!(
            line.contains("-CaseSensitive"),
            "closed-inventory comparison is not case-sensitive: {line}"
        );
    }
    assert_eq!(
        workflow.matches("[System.StringComparer]::Ordinal").count(),
        5,
        "every checksum inventory must use exact ordinal path keys"
    );
    for forbidden in [
        "$checksumMap = @{}",
        "$buildChecksumMap = @{}",
        "$signedChecksumMap = @{}",
    ] {
        assert!(
            !workflow.contains(forbidden),
            "checksum inventory regressed to case-insensitive keys: {forbidden}"
        );
    }

    assert_eq!(
        workflow.matches("${{ secrets.").count(),
        2,
        "only the exact PFX and password secrets are admitted"
    );
    for secret in [
        "secrets.WINDOWS_SIGNING_CERTIFICATE_PFX_BASE64",
        "secrets.WINDOWS_SIGNING_CERTIFICATE_PASSWORD",
    ] {
        assert!(
            workflow.contains(secret),
            "missing signing secret: {secret}"
        );
    }
    for variable in [
        "vars.WINDOWS_SIGNING_CERTIFICATE_PFX_SHA256",
        "vars.WINDOWS_SIGNING_CERTIFICATE_THUMBPRINT",
        "vars.WINDOWS_SIGNING_TIMESTAMP_URL",
    ] {
        assert!(
            workflow.contains(variable),
            "missing protected signing variable: {variable}"
        );
    }
    assert_eq!(
        workflow.matches("${{ vars.").count(),
        3,
        "only the exact digest, signer, and timestamp variables are admitted"
    );

    let expected_commands = [
        "|",
        "|",
        "rustup toolchain install --no-self-update",
        "cargo fetch --locked",
        "cargo run --locked -p distribution-evidence -- check",
        "cargo run --locked -p xtask -- source-candidate-seal --output-dir target/windows-preview-source-candidate --mode preview",
        "|",
        "|",
        "|",
        "|",
        "|",
        "|",
        "|",
        "rustup toolchain install --no-self-update",
        "cargo fetch --locked",
        "|",
        "cargo run --locked -p xtask -- source-candidate-verify --candidate-dir target/windows-preview-build-input/source-candidate --mode preview",
        "cargo run --locked -p release-packager -- package --target windows-x64 --binary target/windows-preview-signed/autocad-mcp.exe --lsp-binary target/windows-preview-signed/autolisp-lsp.exe --out-dir target/windows-preview-package --preview",
        "|",
        "cargo run --locked -p release-packager -- smoke --package target/windows-preview-review/autocad-mcp-windows-x64-preview.mcpb --fixture tests/fixtures/xrefs/portable-evidence-ascii.dxf --require-executable --require-lsp-executable",
        "|",
        "|",
        "|",
        "|",
        "|",
        "|",
        "|",
        "|",
    ];
    assert_eq!(
        workflow_run_commands(workflow),
        expected_commands,
        "Preview candidate single-line command inventory changed"
    );
    assert!(workflow.contains(
        "cargo run --locked -p xtask -- windows-certification-build-preflight --arg tests/fixtures/windows_certification/public-development-profile.arg --arg-policy tests/fixtures/windows_certification/public-development-arg-policy.json --output-dir target/windows-preview-build-preflight"
    ));
    for contract in [
        "SIGNING_CERTIFICATE_PFX_SHA256 -cnotmatch '^[0-9a-f]{64}$'",
        "SIGNING_CERTIFICATE_THUMBPRINT -cnotmatch '^[0-9a-f]{40}$'",
        "PROTECTED_ENVIRONMENT_CONFIGURATION_REVIEWED -cne \"true\"",
        "DISPATCH_SIGNING_CERTIFICATE_THUMBPRINT -cne $env:SIGNING_CERTIFICATE_THUMBPRINT",
        "$timestamp.Scheme -cne \"https\"",
        "ConvertTo-SecureString",
        "Import-PfxCertificate",
        "Remove-Item Env:SIGNING_CERTIFICATE_PASSWORD",
        "Remove-Item Env:SIGNING_CERTIFICATE_PFX_BASE64",
        "sign /sha1 $expectedThumbprint /s My",
        "Remove-Item -LiteralPath $certificatePath -DeleteKey -Force",
        "signtool.exe",
        "Get-AuthenticodeSignature",
        "TimeStamperCertificate",
        "packaged executable bytes differ from the signed handoff",
        "source-candidate-verify --candidate-dir target/windows-preview-build-input/source-candidate --mode preview",
        "create-preview-build-attestation",
        "--github-repository \"$env:ATTESTATION_GITHUB_REPOSITORY\"",
        "--github-server-url \"$env:ATTESTATION_GITHUB_SERVER_URL\"",
        "--github-ref \"$env:ATTESTATION_GITHUB_REF\"",
        "--github-event-name \"$env:ATTESTATION_GITHUB_EVENT_NAME\"",
        "--github-actor \"$env:ATTESTATION_GITHUB_ACTOR\"",
        "--github-triggering-actor \"$env:ATTESTATION_GITHUB_TRIGGERING_ACTOR\"",
        "GITHUB_REPOSITORY -cne \"andagni/autocad-mcp\"",
        "GITHUB_SERVER_URL -cne \"https://github.com\"",
        "GITHUB_EVENT_NAME -cne \"workflow_dispatch\"",
        "GITHUB_ACTOR -cne \"andagni\"",
        "GITHUB_TRIGGERING_ACTOR -cne \"andagni\"",
        "Preview candidate workflow context is not authorized",
        "tar -xf $reviewMcpb -C $extractDirectory",
        "path: target/windows-preview-review/",
        "retention-days: 7",
        "if-no-files-found: error",
        "compression-level: 0",
        "overwrite: false",
        "include-hidden-files: false",
        "node-version: 24.18.0",
        "package-manager-cache: false",
        "npm ci --prefix $validatorRoot --include=dev --ignore-scripts --no-audit --no-fund",
        "node $cli validate $mcpbDirectory",
        "the official MCPB CLI version does not match the reviewed lock",
        "actions/attest@f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6",
        "create-storage-record: false",
        "target/windows-preview-review/autocad-mcp-windows-x64-preview.mcpb",
        "target/windows-preview-review/autocad-mcp-windows-x64-preview-build-source.zip",
    ] {
        assert!(
            workflow.contains(contract),
            "Preview candidate workflow is missing contract: {contract}"
        );
    }
    assert!(
        !workflow.contains("/p $env:SIGNING_CERTIFICATE_PASSWORD"),
        "the PFX password must not be passed on a child-process command line"
    );
    assert_eq!(workflow.matches("retention-days: 1").count(), 2);
    for retained in [
        "autocad-mcp-windows-x64-preview.mcpb",
        "autocad-mcp-windows-x64-preview-build-source.zip",
        "distribution-evidence/windows-x64-preview-build.json",
        "distribution-evidence/windows-x64-preview-source-closure.spdx.json",
        "review-only/unsigned-development-preflight.json",
        "SHA256SUMS.txt",
    ] {
        assert!(
            workflow.contains(retained),
            "Preview review inventory is missing {retained}"
        );
    }
    let assemble_position = workflow
        .find("- name: Assemble the exact non-publishing review bytes")
        .expect("final review assembly step should be present");
    let smoke_position = workflow
        .find("- name: Smoke both signed executables from the exact review MCPB")
        .expect("exact final-path smoke should be present");
    let verify_position = workflow
        .find("- name: Verify the exact signed review inputs")
        .expect("exact signed-input verification should be present");
    let build_attestation_position = workflow
        .find("- name: Create the final post-signing Preview build attestation")
        .expect("final Preview build attestation step should be present");
    let checksum_position = workflow
        .find("- name: Checksum and close the exact upload inventory")
        .expect("exact upload checksum closure should be present");
    let upload_position = workflow
        .find("- name: Upload the signed non-publishing review candidate")
        .expect("final upload should be present");
    let supplemental_validation_position = workflow
        .find("  validate-preview-mcpb:")
        .expect("supplemental MCPB validation job should be present");
    let supplemental_attestation_position = workflow
        .find("  attest-preview-review:")
        .expect("supplemental attestation job should be present");
    assert!(
        assemble_position < smoke_position
            && smoke_position < verify_position
            && verify_position < build_attestation_position
            && build_attestation_position < checksum_position
            && checksum_position < upload_position
            && upload_position < supplemental_validation_position
            && supplemental_validation_position < supplemental_attestation_position,
        "final MCPB bytes must be assembled, smoked, verified, uploaded, independently validated, and only then attested"
    );

    for forbidden in [
        "pull_request_target",
        "contents: write",
        "permissions: write-all",
        "write-all",
        "gh release",
        "current-distribution-verify",
        "owner_distribution_approval",
        "OWNER_DISTRIBUTION_APPROVAL",
        "AUTOCAD_MCP_TIER2_MANIFEST",
        "AUTOCAD_MCP_XREF_CERT_MANIFEST",
        "AUTOCAD_MCP_CERT_OUTPUT_DIR",
        "AUTOCAD_MCP_XREF_CERTIFIED_ARG_PATH",
        "AUTOCAD_MCP_ACCORECONSOLE_PATH",
        "AUTOCAD_MCP_XREF_FAILPOINT",
        "--ignored",
        "tests/corpus",
        "self-hosted",
        "mcpb pack",
        "mcpb sign",
        "mcpb verify",
    ] {
        assert!(
            !workflow.contains(forbidden),
            "Preview candidate workflow contains forbidden scope: {forbidden}"
        );
    }
}

#[test]
fn preview_publication_bridge_is_fixed_noninteractive_and_private_by_construction() {
    let repository = repository_root();
    let publisher = std::fs::read_to_string(
        repository.join("crates/distribution/packager/src/preview_publication.rs"),
    )
    .expect("Preview publisher source should be readable");
    let production = publisher
        .split_once("#[cfg(test)]")
        .map_or(publisher.as_str(), |(production, _)| production);

    for required in [
        "pub const PREVIEW_GITHUB_REPOSITORY: &str = \"andagni/autocad-mcp\";",
        "const GITHUB_API_VERSION: &str = \"2026-03-10\";",
        "repos/andagni/autocad-mcp/immutable-releases",
        "(\"GH_PROMPT_DISABLED\".to_owned(), \"1\".to_owned())",
        "\"--no-replace-objects\"",
        "\"ls-files\", \"-v\", \"-z\"",
        "make_latest: \"false\"",
        "each of the seven Preview assets must be smaller than 2 GiB",
        "remote_asset.state != \"uploaded\"",
        "source_authority_sha256",
        "source repository must be the primary common checkout",
        "owner-selected GitHub CLI executable changed during publication",
        "staged Preview public assets must be anonymous regular files",
        "execute_with_github_token_and_file_stdin",
        "GH_NO_EXTENSION_UPDATE_NOTIFIER",
        "branches?per_page={PAGE_SIZE}&page={page}",
        "exclusive_write_window_confirmed",
        "owner-enforced exclusive write window",
        "sealing is unsupported on Windows until owner-only private-key ACL admission is implemented",
        "verify immutable GitHub release",
    ] {
        assert!(
            production.contains(required),
            "Preview publisher is missing closed publication policy: {required}"
        );
    }
    for forbidden in [
        "--clobber",
        "\"delete\"",
        "release delete",
        "contents: write",
    ] {
        assert!(
            !production.contains(forbidden),
            "Preview publisher admits a forbidden mutation path: {forbidden}"
        );
    }

    let handoff_contract = std::fs::read_to_string(
        repository.join("crates/distribution/approval/src/preview_publication_handoff.rs"),
    )
    .expect("Preview handoff contract should be readable");
    for required in [
        "PREVIEW_PUBLICATION_HANDOFF_SCHEMA_VERSION: u32 = 2",
        "autocad-mcp.release/preview-publication-handoff/v2",
        "source_authority_sha256",
    ] {
        assert!(
            handoff_contract.contains(required),
            "Preview handoff is missing authenticated source-authority policy: {required}"
        );
    }
    let public_inventory_start = handoff_contract
        .find("pub const PREVIEW_PUBLICATION_PUBLIC_ASSET_PATHS")
        .expect("Preview handoff should declare the public asset inventory");
    let public_inventory_tail = &handoff_contract[public_inventory_start..];
    let public_inventory_end = public_inventory_tail
        .find("];")
        .expect("Preview public asset inventory should be closed");
    let public_inventory = &public_inventory_tail[..public_inventory_end];
    for public in [
        "PREVIEW_PUBLICATION_MCPB_PATH",
        "PREVIEW_PUBLICATION_SOURCE_ARCHIVE_PATH",
        "PREVIEW_PUBLICATION_SOURCE_CLOSURE_SBOM_PATH",
        "PREVIEW_PUBLICATION_BUILD_ATTESTATION_PATH",
        "PREVIEW_PUBLICATION_CLEAN_HOST_RECEIPT_PATH",
        "PREVIEW_PUBLICATION_OWNER_APPROVAL_PATH",
    ] {
        assert!(
            public_inventory.contains(public),
            "Preview public inventory is missing {public}"
        );
    }
    for private in [
        "PREVIEW_PUBLICATION_PROJECTION_RECEIPT_PATH",
        "PREVIEW_PUBLICATION_CURRENT_DISTRIBUTION_RECEIPT_PATH",
        "PREVIEW_PUBLICATION_HANDOFF",
    ] {
        assert!(
            !public_inventory.contains(private),
            "private selection material entered the Preview public inventory: {private}"
        );
    }
}
