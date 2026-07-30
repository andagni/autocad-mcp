use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use proc_macro2::{TokenStream, TokenTree};
use syn::ext::IdentExt;
use syn::parse::Parser;
use syn::punctuated::Punctuated;
use syn::visit::{self, Visit};
use syn::{Attribute, Expr, Item, Meta, Token, UseTree};
use walkdir::WalkDir;

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate must be inside the workspace")
        .to_path_buf()
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
