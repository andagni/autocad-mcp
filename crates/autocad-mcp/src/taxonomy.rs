use crate::ops::xrefs::{xref_failure_codes, XrefTool};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolOperation {
    Create,
    Read,
    Update,
    Delete,
    List,
    Reload,
    Unload,
    Bind,
    Resolve,
    Export,
    Survey,
    Validate,
    Audit,
}

impl ToolOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Read => "read",
            Self::Update => "update",
            Self::Delete => "delete",
            Self::List => "list",
            Self::Reload => "reload",
            Self::Unload => "unload",
            Self::Bind => "bind",
            Self::Resolve => "resolve",
            Self::Export => "export",
            Self::Survey => "survey",
            Self::Validate => "validate",
            Self::Audit => "audit",
        }
    }

    pub fn is_crudl(self) -> bool {
        matches!(
            self,
            Self::Create | Self::Read | Self::Update | Self::Delete | Self::List
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolTaxonomy {
    pub domain: &'static str,
    pub operation: ToolOperation,
    pub identity: &'static str,
    pub mutation_scope: &'static str,
    pub platform: &'static str,
    pub failure_codes: Vec<&'static str>,
    pub failure_semantics: String,
}

impl ToolTaxonomy {
    fn descriptive(
        domain: &'static str,
        operation: ToolOperation,
        identity: &'static str,
        mutation_scope: &'static str,
        platform: &'static str,
        failure_semantics: &'static str,
    ) -> Self {
        Self {
            domain,
            operation,
            identity,
            mutation_scope,
            platform,
            failure_codes: Vec::new(),
            failure_semantics: failure_semantics.to_owned(),
        }
    }

    fn xref(definition: XrefTaxonomyDefinition) -> Self {
        let failure_codes = xref_failure_codes(definition.tool);
        let failure_semantics = render_xref_failure_semantics(&failure_codes);

        Self {
            domain: definition.domain,
            operation: definition.operation,
            identity: definition.identity,
            mutation_scope: definition.mutation_scope,
            platform: definition.platform,
            failure_codes,
            failure_semantics,
        }
    }
}

fn render_xref_failure_semantics(failure_codes: &[&str]) -> String {
    let codes = failure_codes
        .iter()
        .map(|code| format!("`{code}`"))
        .collect::<Vec<_>>()
        .join(", ");
    format!("Fail with one of the XREF contract codes: {codes}.")
}

#[derive(Debug, Clone, Copy)]
struct XrefTaxonomyDefinition {
    name: &'static str,
    tool: XrefTool,
    domain: &'static str,
    operation: ToolOperation,
    identity: &'static str,
    mutation_scope: &'static str,
    platform: &'static str,
}

const XREF_TAXONOMY: [XrefTaxonomyDefinition; 15] = [
    XrefTaxonomyDefinition {
        name: "list_xrefs",
        tool: XrefTool::ListXrefs,
        domain: "xref_attachment",
        operation: ToolOperation::List,
        identity: "drawing_path",
        mutation_scope: "no_mutation",
        platform: "DWG and DXF read on all build targets",
    },
    XrefTaxonomyDefinition {
        name: "get_xref",
        tool: XrefTool::GetXref,
        domain: "xref_attachment",
        operation: ToolOperation::Read,
        identity: "drawing_path + attachment handle or name",
        mutation_scope: "no_mutation",
        platform: "DWG and DXF read on all build targets",
    },
    XrefTaxonomyDefinition {
        name: "attach_xref",
        tool: XrefTool::AttachXref,
        domain: "xref_attachment",
        operation: ToolOperation::Create,
        identity: "drawing_path + new attachment name",
        mutation_scope:
            "Creates one direct attachment and one initial instance in the host; source unchanged",
        platform: "Windows with AutoCAD; DWG and DXF hosts",
    },
    XrefTaxonomyDefinition {
        name: "update_xref",
        tool: XrefTool::UpdateXref,
        domain: "xref_attachment",
        operation: ToolOperation::Update,
        identity: "drawing_path + attachment handle or name",
        mutation_scope:
            "Mutates accepted properties of one direct attachment; source unchanged",
        platform: "Windows with AutoCAD; DWG and DXF hosts",
    },
    XrefTaxonomyDefinition {
        name: "detach_xref",
        tool: XrefTool::DetachXref,
        domain: "xref_attachment",
        operation: ToolOperation::Delete,
        identity: "drawing_path + attachment handle or name",
        mutation_scope: "Removes one direct attachment, its instances, and its dependent host definitions; source unchanged",
        platform: "Windows with AutoCAD; DWG and DXF hosts",
    },
    XrefTaxonomyDefinition {
        name: "list_xref_instances",
        tool: XrefTool::ListXrefInstances,
        domain: "xref_instance",
        operation: ToolOperation::List,
        identity: "drawing_path + optional exact filters",
        mutation_scope: "no_mutation",
        platform: "DWG and DXF read on all build targets",
    },
    XrefTaxonomyDefinition {
        name: "get_xref_instance",
        tool: XrefTool::GetXrefInstance,
        domain: "xref_instance",
        operation: ToolOperation::Read,
        identity: "drawing_path + instance handle",
        mutation_scope: "no_mutation",
        platform: "DWG and DXF read on all build targets",
    },
    XrefTaxonomyDefinition {
        name: "insert_xref_instance",
        tool: XrefTool::InsertXrefInstance,
        domain: "xref_instance",
        operation: ToolOperation::Create,
        identity: "drawing_path + direct attachment identity",
        mutation_scope:
            "Creates one persisted reference entity in the host; source unchanged",
        platform: "Windows with AutoCAD; DWG and DXF hosts",
    },
    XrefTaxonomyDefinition {
        name: "update_xref_instance",
        tool: XrefTool::UpdateXrefInstance,
        domain: "xref_instance",
        operation: ToolOperation::Update,
        identity: "drawing_path + instance handle",
        mutation_scope:
            "Mutates accepted placement properties of one persisted reference entity",
        platform: "Windows with AutoCAD; DWG and DXF hosts",
    },
    XrefTaxonomyDefinition {
        name: "delete_xref_instance",
        tool: XrefTool::DeleteXrefInstance,
        domain: "xref_instance",
        operation: ToolOperation::Delete,
        identity: "drawing_path + instance handle",
        mutation_scope:
            "Removes one persisted reference entity; attachment retained",
        platform: "Windows with AutoCAD; DWG and DXF hosts",
    },
    XrefTaxonomyDefinition {
        name: "reload_xref",
        tool: XrefTool::ReloadXref,
        domain: "xref_attachment",
        operation: ToolOperation::Reload,
        identity: "drawing_path + attachment handle or name",
        mutation_scope:
            "Refreshes and persists one direct attachment from the latest source graph",
        platform: "Windows with AutoCAD; DWG and DXF hosts",
    },
    XrefTaxonomyDefinition {
        name: "unload_xref",
        tool: XrefTool::UnloadXref,
        domain: "xref_attachment",
        operation: ToolOperation::Unload,
        identity: "drawing_path + attachment handle or name",
        mutation_scope: "Persists the unloaded state of one direct attachment",
        platform: "Windows with AutoCAD; DWG and DXF hosts",
    },
    XrefTaxonomyDefinition {
        name: "bind_xref",
        tool: XrefTool::BindXref,
        domain: "xref_attachment",
        operation: ToolOperation::Bind,
        identity: "drawing_path + attachment handle or name",
        mutation_scope: "Converts one direct attachment and selected propagated dependencies into host-owned blocks and symbols",
        platform: "Windows with AutoCAD; DWG and DXF hosts",
    },
    XrefTaxonomyDefinition {
        name: "resolve_xref_path",
        tool: XrefTool::ResolveXrefPath,
        domain: "xref_attachment",
        operation: ToolOperation::Resolve,
        identity: "drawing_path + attachment handle or name",
        mutation_scope: "no_mutation",
        platform: "DWG and DXF read on all build targets",
    },
    XrefTaxonomyDefinition {
        name: "list_xref_dependencies",
        tool: XrefTool::ListXrefDependencies,
        domain: "xref_dependency",
        operation: ToolOperation::List,
        identity: "drawing_path + optional direct root attachment",
        mutation_scope: "no_mutation",
        platform: "DWG and DXF read on all build targets",
    },
];

pub fn tool_taxonomy() -> BTreeMap<&'static str, ToolTaxonomy> {
    let mut taxonomy = BTreeMap::from([
        (
            "list_layers",
            ToolTaxonomy::descriptive(
                "layer",
                ToolOperation::List,
                "drawing_path",
                "no_mutation",
                "DWG and DXF read on all build targets",
                "Fail on missing, unreadable, or unsupported drawing paths",
            ),
        ),
        (
            "get_layer",
            ToolTaxonomy::descriptive(
                "layer",
                ToolOperation::Read,
                "drawing_path + layer handle or name",
                "no_mutation",
                "DWG and DXF read on all build targets",
                "Fail on missing drawing, missing layer, ambiguous identity, or contradictory identity",
            ),
        ),
        (
            "create_layer",
            ToolTaxonomy::descriptive(
                "layer",
                ToolOperation::Create,
                "drawing_path",
                "Adds one host-owned layer table record named by `name` with branch-final writable properties",
                "Native-DXF write on all build targets; DWG write on Windows with AutoCAD",
                "Fail on invalid name, name collision, invalid or unsupported property value, missing linetype, invalid lineweight, unsupported existing layer data, unsupported platform, unsupported format, write failure, or uncertain mutation state",
            ),
        ),
        (
            "update_layer",
            ToolTaxonomy::descriptive(
                "layer",
                ToolOperation::Update,
                "drawing_path + layer handle or name",
                "Mutates branch-final writable properties on one existing layer table record; `expected_*` parameters are stale-state guards, not identity",
                "Native-DXF write on all build targets; DWG write on Windows with AutoCAD",
                "Fail on missing layer, stale guard, empty properties, invalid or unsupported property value, current-layer freeze, unsupported xref-dependent DXF line_type override, unsupported platform, unsupported format, unsupported existing layer data, write failure, or uncertain mutation state",
            ),
        ),
        (
            "rename_layer",
            ToolTaxonomy::descriptive(
                "layer",
                ToolOperation::Update,
                "drawing_path + layer handle or name",
                "Renames one layer table record to `new_name` and updates represented layer-name references needed to preserve membership; `expected_*` parameters are stale-state guards, not identity",
                "Native-DXF write on all build targets; DWG write on Windows with AutoCAD",
                "Fail on protected layer, invalid new name, name collision, xref-dependent target, stale guard, unsupported platform, unsupported format, write failure, or uncertain mutation state",
            ),
        ),
        (
            "delete_layer",
            ToolTaxonomy::descriptive(
                "layer",
                ToolOperation::Delete,
                "drawing_path + layer handle or name",
                "Removes one unused host-owned layer table record; `expected_*` parameters are stale-state guards, not identity",
                "Native-DXF write on all build targets; DWG write on Windows with AutoCAD",
                "Fail on protected layer, current layer, xref-dependent target, content/reference use, stale guard, unsupported platform, unsupported format, write failure, or uncertain mutation state",
            ),
        ),
        (
            "list_blocks",
            ToolTaxonomy::descriptive(
                "block_definition",
                ToolOperation::List,
                "drawing_path",
                "no_mutation",
                "DWG and DXF read on all build targets; MVP packages on Windows and macOS",
                "Fail on missing, unreadable, or unsupported drawing paths",
            ),
        ),
        (
            "get_drawing",
            ToolTaxonomy::descriptive(
                "drawing",
                ToolOperation::Read,
                "drawing_path",
                "no_mutation",
                "DWG read on all build targets; MVP packages on Windows and macOS",
                "Fail on missing, unreadable, or unsupported drawing paths, invalid or duplicate block-record handles, duplicate or contradictory layout-owner facts, or contradictory model-space identity; saved-header geometry and current model/paper UCS are availability-tagged",
            ),
        ),
        (
            "list_entities",
            ToolTaxonomy::descriptive(
                "entity",
                ToolOperation::List,
                "drawing_path + optional exact filters + page",
                "no_mutation",
                "DWG read on all build targets; MVP packages on Windows and macOS",
                "Fail on missing, unreadable, or non-DWG drawing paths, invalid filters or pagination, duplicate handles, duplicate or contradictory direct-owner facts, unsupported modeled data, or ambiguous/contradictory dynamic-block linkage",
            ),
        ),
        (
            "get_entity",
            ToolTaxonomy::descriptive(
                "entity",
                ToolOperation::Read,
                "drawing_path + entity handle",
                "no_mutation",
                "DWG read on all build targets; MVP packages on Windows and macOS",
                "Fail on missing, unreadable, or non-DWG drawing paths, invalid or missing entities, duplicate selected identity, duplicate or contradictory direct-owner facts for the target, unsupported target data, or ambiguous/contradictory target dynamic-block linkage; unrelated malformed handles do not fail the target",
            ),
        ),
        (
            "list_block_definitions",
            ToolTaxonomy::descriptive(
                "block_definition",
                ToolOperation::List,
                "drawing_path",
                "no_mutation",
                "DWG read on all build targets; MVP packages on Windows and macOS",
                "Fail on missing, unreadable, or non-DWG drawing paths, invalid or duplicate handles, ambiguous layout ownership, or unsupported modeled data",
            ),
        ),
        (
            "get_block_definition",
            ToolTaxonomy::descriptive(
                "block_definition",
                ToolOperation::Read,
                "drawing_path + block-definition handle or name",
                "no_mutation",
                "DWG read on all build targets; MVP packages on Windows and macOS",
                "Fail on missing, unreadable, or non-DWG drawing paths, invalid handles, missing definitions, ambiguous identity, contradictory identity, ambiguous layout ownership, or unsupported modeled data",
            ),
        ),
        (
            "list_block_inserts",
            ToolTaxonomy::descriptive(
                "block_insert",
                ToolOperation::List,
                "drawing_path",
                "no_mutation",
                "DWG read on all build targets; MVP packages on Windows and macOS",
                "Fail on missing, unreadable, or non-DWG drawing paths, unresolved definitions, duplicate handles, duplicate or contradictory direct-owner facts, unsupported modeled data, or ambiguous/contradictory dynamic-block linkage",
            ),
        ),
        (
            "get_block_insert",
            ToolTaxonomy::descriptive(
                "block_insert",
                ToolOperation::Read,
                "drawing_path + block-insert handle",
                "no_mutation",
                "DWG read on all build targets; MVP packages on Windows and macOS",
                "Fail on missing, unreadable, or non-DWG drawing paths, invalid handles, missing ordinary inserts, duplicate or contradictory direct-owner facts, unsupported modeled data, or ambiguous/contradictory dynamic-block linkage",
            ),
        ),
        (
            "list_text",
            ToolTaxonomy::descriptive(
                "text",
                ToolOperation::List,
                "drawing_path + optional exact text type, layer, or direct-owner selector",
                "no_mutation",
                "DWG read on all build targets; MVP packages on Windows and macOS",
                "Fail on missing, unreadable, or non-DWG drawing paths, invalid filters, contradictory owner selectors, duplicate selected handles, duplicate or contradictory direct-owner facts in the selected scope, or unsupported selected data",
            ),
        ),
        (
            "get_text",
            ToolTaxonomy::descriptive(
                "text",
                ToolOperation::Read,
                "drawing_path + text-entity handle",
                "no_mutation",
                "DWG read on all build targets; MVP packages on Windows and macOS",
                "Fail on missing, unreadable, or non-DWG drawing paths, invalid handles, missing or non-text entities, duplicate selected identity, duplicate or contradictory direct-owner facts for the target, or unsupported target data; unrelated malformed handles do not fail the target",
            ),
        ),
        (
            "read_title_blocks",
            ToolTaxonomy::descriptive(
                "title_block",
                ToolOperation::Read,
                "drawing_path + optional attribute-value mode",
                "no_mutation",
                "DWG and DXF read on all build targets; MVP packages on Windows and macOS",
                "Fail on missing, unreadable, or unsupported drawing paths; duplicate normalized tags are successful partial data with ordered arrays and structured warnings",
            ),
        ),
        (
            "dump_text",
            ToolTaxonomy::descriptive(
                "text",
                ToolOperation::List,
                "drawing_path",
                "no_mutation",
                "DWG and DXF read on all build targets; MVP packages on Windows and macOS",
                "Fail on missing, unreadable, or unsupported drawing paths",
            ),
        ),
        (
            "get_layout",
            ToolTaxonomy::descriptive(
                "layout",
                ToolOperation::Read,
                "drawing_path + layout handle or name",
                "no_mutation",
                "DWG read on all build targets; MVP packages on Windows and macOS",
                "Fail on missing, unreadable, or non-DWG drawing paths, invalid handles or names, missing layouts, ambiguous or contradictory identity, unsupported modeled data, or contradictory semantic owner and header facts",
            ),
        ),
        (
            "list_layout_viewports",
            ToolTaxonomy::descriptive(
                "layout_viewport",
                ToolOperation::List,
                "drawing_path + optional layout handle or name",
                "no_mutation",
                "DWG read on all build targets; MVP packages on Windows and macOS",
                "Fail on missing, unreadable, or non-DWG drawing paths, invalid layout identity, missing layouts, duplicate semantic entity handles, ambiguous ownership, unsupported modeled data, or negative/non-finite saved scale operands; zero scale operands are successful unavailable data",
            ),
        ),
        (
            "get_layout_viewport",
            ToolTaxonomy::descriptive(
                "layout_viewport",
                ToolOperation::Read,
                "drawing_path + viewport entity handle",
                "no_mutation",
                "DWG read on all build targets; MVP packages on Windows and macOS",
                "Fail on missing, unreadable, or non-DWG drawing paths, invalid handles, missing viewports, duplicate selected identity, negative/non-finite saved scale operands, or viewports not owned by a paper-space layout; unrelated malformed handles do not fail the target",
            ),
        ),
        (
            "list_plot_settings",
            ToolTaxonomy::descriptive(
                "plot_setting",
                ToolOperation::List,
                "drawing_path",
                "no_mutation",
                "DWG read on all build targets; MVP packages on Windows and macOS",
                "Fail on missing, unreadable, or non-DWG drawing paths, invalid or duplicate handles, unsupported modeled data, or unusable saved scale operands",
            ),
        ),
        (
            "get_plot_setting",
            ToolTaxonomy::descriptive(
                "plot_setting",
                ToolOperation::Read,
                "drawing_path + plot-setting handle or page name",
                "no_mutation",
                "DWG read on all build targets; MVP packages on Windows and macOS",
                "Fail on missing, unreadable, or non-DWG drawing paths, invalid handles or names, missing settings, ambiguous identity, contradictory identity, unsupported modeled data, or unusable saved scale operands",
            ),
        ),
        (
            "list_linetypes",
            ToolTaxonomy::descriptive(
                "linetype",
                ToolOperation::List,
                "drawing_path",
                "no_mutation",
                "DWG read on all build targets; MVP packages on Windows and macOS",
                "Fail on missing, unreadable, or non-DWG drawing paths, invalid or duplicate handles, or unsupported modeled data",
            ),
        ),
        (
            "get_linetype",
            ToolTaxonomy::descriptive(
                "linetype",
                ToolOperation::Read,
                "drawing_path + linetype handle or name",
                "no_mutation",
                "DWG read on all build targets; MVP packages on Windows and macOS",
                "Fail on missing, unreadable, or unsupported drawing paths, invalid handles, missing linetypes, ambiguous identity, or contradictory identity",
            ),
        ),
        (
            "list_text_styles",
            ToolTaxonomy::descriptive(
                "text_style",
                ToolOperation::List,
                "drawing_path",
                "no_mutation",
                "DWG read on all build targets; MVP packages on Windows and macOS",
                "Fail on missing, unreadable, or non-DWG drawing paths, invalid or duplicate handles, or unsupported modeled data",
            ),
        ),
        (
            "get_text_style",
            ToolTaxonomy::descriptive(
                "text_style",
                ToolOperation::Read,
                "drawing_path + text-style handle or name",
                "no_mutation",
                "DWG read on all build targets; MVP packages on Windows and macOS",
                "Fail on missing, unreadable, or unsupported drawing paths, invalid handles, missing text styles, ambiguous identity, or contradictory identity",
            ),
        ),
        (
            "list_dimension_styles",
            ToolTaxonomy::descriptive(
                "dimension_style",
                ToolOperation::List,
                "drawing_path",
                "no_mutation",
                "DWG read on all build targets; MVP packages on Windows and macOS",
                "Fail on missing, unreadable, or non-DWG drawing paths, invalid or duplicate handles, or unsupported modeled data",
            ),
        ),
        (
            "get_dimension_style",
            ToolTaxonomy::descriptive(
                "dimension_style",
                ToolOperation::Read,
                "drawing_path + dimension-style handle or name",
                "no_mutation",
                "DWG read on all build targets; MVP packages on Windows and macOS",
                "Fail on missing, unreadable, or unsupported drawing paths, invalid handles, missing dimension styles, ambiguous identity, or contradictory identity",
            ),
        ),
        (
            "list_named_views",
            ToolTaxonomy::descriptive(
                "named_view",
                ToolOperation::List,
                "drawing_path",
                "no_mutation",
                "DWG read on all build targets; MVP packages on Windows and macOS",
                "Fail on missing, unreadable, or non-DWG drawing paths, invalid or duplicate handles, or unsupported modeled data",
            ),
        ),
        (
            "get_named_view",
            ToolTaxonomy::descriptive(
                "named_view",
                ToolOperation::Read,
                "drawing_path + named-view handle or name",
                "no_mutation",
                "DWG read on all build targets; MVP packages on Windows and macOS",
                "Fail on missing, unreadable, or unsupported drawing paths, invalid handles, missing named views, ambiguous identity, or contradictory identity",
            ),
        ),
        (
            "list_named_ucs",
            ToolTaxonomy::descriptive(
                "named_ucs",
                ToolOperation::List,
                "drawing_path",
                "no_mutation",
                "DWG read on all build targets; MVP packages on Windows and macOS",
                "Fail on missing, unreadable, or non-DWG drawing paths, invalid or duplicate handles, or unsupported modeled data",
            ),
        ),
        (
            "get_named_ucs",
            ToolTaxonomy::descriptive(
                "named_ucs",
                ToolOperation::Read,
                "drawing_path + named-UCS handle or name",
                "no_mutation",
                "DWG read on all build targets; MVP packages on Windows and macOS",
                "Fail on missing, unreadable, or unsupported drawing paths, invalid handles, missing named UCS records, ambiguous identity, or contradictory identity",
            ),
        ),
        (
            "write_title_block",
            ToolTaxonomy::descriptive(
                "title_block_field",
                ToolOperation::Update,
                "drawing_path + resolved title-block fingerprint + requested canonical field keys",
                "Matching title-block attribute values on all target inserts matching the resolved fingerprint",
                "Native-DXF write on all build targets; Release DWG write on Windows with AutoCAD; Preview AC1032 DWG write on Windows through the bounded acadrust preservation oracle",
                "Fail on empty fields, unrecognised or ambiguous title-block profile, unknown canonical field, unsupported platform/version/form/section/entity, preservation-oracle mismatch, source lock or identity race, no matching target insert, missing or duplicate requested tag, guarded install uncertainty, partial write, or write failure",
            ),
        ),
        (
            "list_layouts",
            ToolTaxonomy::descriptive(
                "layout",
                ToolOperation::List,
                "drawing_path",
                "no_mutation",
                "DWG and DXF read on all build targets; MVP packages on Windows and macOS",
                "Fail on missing, unreadable, or unsupported drawing paths",
            ),
        ),
        (
            "plot_to_pdf",
            ToolTaxonomy::descriptive(
                "drawing",
                ToolOperation::Export,
                "drawing_path + layout",
                "Output PDF at `output`; source drawing unchanged",
                "Windows with AutoCAD; DWG only; requires existing file-plotter page setup",
                "Fail on unsupported platform, non-DWG input, missing layout, invalid output path, prompt mismatch or missing result sentinel, and output PDF not being created",
            ),
        ),
    ]);

    for definition in XREF_TAXONOMY {
        taxonomy.insert(definition.name, ToolTaxonomy::xref(definition));
    }
    taxonomy
}

#[cfg(test)]
mod tests {
    use super::{render_xref_failure_semantics, tool_taxonomy, ToolOperation};
    use crate::{
        ops::xrefs::{xref_failure_codes, XrefTool},
        server::AutocadServer,
    };
    use autocad_writer::contract::{MutationRoute, ALL_MUTATION_ROUTES};
    use std::collections::BTreeSet;

    fn string_set(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    fn taxonomy_tools() -> BTreeSet<String> {
        tool_taxonomy()
            .keys()
            .map(|tool| (*tool).to_owned())
            .collect()
    }

    fn expected_tools() -> BTreeSet<String> {
        string_set(&[
            "attach_xref",
            "bind_xref",
            "create_layer",
            "delete_layer",
            "delete_xref_instance",
            "detach_xref",
            "dump_text",
            "get_block_definition",
            "get_block_insert",
            "get_dimension_style",
            "get_drawing",
            "get_entity",
            "get_layer",
            "get_layout",
            "get_layout_viewport",
            "get_linetype",
            "get_named_ucs",
            "get_named_view",
            "get_plot_setting",
            "get_text",
            "get_text_style",
            "get_xref",
            "get_xref_instance",
            "insert_xref_instance",
            "list_block_definitions",
            "list_block_inserts",
            "list_blocks",
            "list_dimension_styles",
            "list_entities",
            "list_layers",
            "list_layouts",
            "list_layout_viewports",
            "list_linetypes",
            "list_named_ucs",
            "list_named_views",
            "list_plot_settings",
            "list_text",
            "list_text_styles",
            "list_xref_dependencies",
            "list_xref_instances",
            "list_xrefs",
            "plot_to_pdf",
            "read_title_blocks",
            "reload_xref",
            "rename_layer",
            "resolve_xref_path",
            "unload_xref",
            "update_layer",
            "update_xref",
            "update_xref_instance",
            "write_title_block",
        ])
    }

    fn writer_route_name(route: MutationRoute) -> &'static str {
        match route {
            MutationRoute::CreateLayer => "create_layer",
            MutationRoute::UpdateLayer => "update_layer",
            MutationRoute::RenameLayer => "rename_layer",
            MutationRoute::DeleteLayer => "delete_layer",
            MutationRoute::WriteTitleBlock => "write_title_block",
            MutationRoute::AttachXref => "attach_xref",
            MutationRoute::UpdateXref => "update_xref",
            MutationRoute::DetachXref => "detach_xref",
            MutationRoute::InsertXrefInstance => "insert_xref_instance",
            MutationRoute::UpdateXrefInstance => "update_xref_instance",
            MutationRoute::DeleteXrefInstance => "delete_xref_instance",
            MutationRoute::ReloadXref => "reload_xref",
            MutationRoute::UnloadXref => "unload_xref",
            MutationRoute::BindXref => "bind_xref",
            MutationRoute::PlotToPdf => "plot_to_pdf",
        }
    }

    fn expected_xref_classification() -> [(&'static str, XrefTool, &'static str, ToolOperation); 15]
    {
        [
            (
                "list_xrefs",
                XrefTool::ListXrefs,
                "xref_attachment",
                ToolOperation::List,
            ),
            (
                "get_xref",
                XrefTool::GetXref,
                "xref_attachment",
                ToolOperation::Read,
            ),
            (
                "attach_xref",
                XrefTool::AttachXref,
                "xref_attachment",
                ToolOperation::Create,
            ),
            (
                "update_xref",
                XrefTool::UpdateXref,
                "xref_attachment",
                ToolOperation::Update,
            ),
            (
                "detach_xref",
                XrefTool::DetachXref,
                "xref_attachment",
                ToolOperation::Delete,
            ),
            (
                "list_xref_instances",
                XrefTool::ListXrefInstances,
                "xref_instance",
                ToolOperation::List,
            ),
            (
                "get_xref_instance",
                XrefTool::GetXrefInstance,
                "xref_instance",
                ToolOperation::Read,
            ),
            (
                "insert_xref_instance",
                XrefTool::InsertXrefInstance,
                "xref_instance",
                ToolOperation::Create,
            ),
            (
                "update_xref_instance",
                XrefTool::UpdateXrefInstance,
                "xref_instance",
                ToolOperation::Update,
            ),
            (
                "delete_xref_instance",
                XrefTool::DeleteXrefInstance,
                "xref_instance",
                ToolOperation::Delete,
            ),
            (
                "reload_xref",
                XrefTool::ReloadXref,
                "xref_attachment",
                ToolOperation::Reload,
            ),
            (
                "unload_xref",
                XrefTool::UnloadXref,
                "xref_attachment",
                ToolOperation::Unload,
            ),
            (
                "bind_xref",
                XrefTool::BindXref,
                "xref_attachment",
                ToolOperation::Bind,
            ),
            (
                "resolve_xref_path",
                XrefTool::ResolveXrefPath,
                "xref_attachment",
                ToolOperation::Resolve,
            ),
            (
                "list_xref_dependencies",
                XrefTool::ListXrefDependencies,
                "xref_dependency",
                ToolOperation::List,
            ),
        ]
    }

    #[test]
    fn taxonomy_has_the_exact_fifty_one_tools() {
        assert_eq!(taxonomy_tools(), expected_tools());
    }

    #[test]
    fn taxonomy_matches_the_eventual_router_surface() {
        let router_tools = AutocadServer::tool_router()
            .list_all()
            .into_iter()
            .map(|tool| tool.name.to_string())
            .collect::<BTreeSet<_>>();

        assert_eq!(
            router_tools,
            expected_tools(),
            "the router must expose the exact 51-tool surface"
        );
        assert_eq!(taxonomy_tools(), router_tools);
    }

    #[test]
    fn writer_route_inventory_matches_the_live_mutation_taxonomy() {
        let taxonomy_mutations = tool_taxonomy()
            .into_iter()
            .filter(|(_, row)| row.mutation_scope != "no_mutation")
            .map(|(name, _)| name.to_string())
            .collect::<BTreeSet<_>>();
        let writer_mutations = ALL_MUTATION_ROUTES
            .into_iter()
            .map(writer_route_name)
            .map(str::to_string)
            .collect::<BTreeSet<_>>();

        assert_eq!(writer_mutations, taxonomy_mutations);
        assert_eq!(writer_mutations.len(), 15);
    }

    #[test]
    fn router_read_only_annotations_match_the_taxonomy_mutation_boundary() {
        let taxonomy = tool_taxonomy();
        let tools = AutocadServer::tool_router().list_all();

        for tool in tools {
            let name: &str = tool.name.as_ref();
            let row = taxonomy
                .get(name)
                .unwrap_or_else(|| panic!("missing taxonomy row `{name}`"));
            let annotations = tool
                .annotations
                .as_ref()
                .unwrap_or_else(|| panic!("missing annotations for `{name}`"));
            assert_eq!(
                annotations.read_only_hint,
                Some(row.mutation_scope == "no_mutation"),
                "`{name}` readOnlyHint disagrees with its mutation scope"
            );
        }
    }

    #[test]
    fn xref_rows_store_sorted_source_failure_codes_and_derived_prose() {
        let taxonomy = tool_taxonomy();

        for (name, tool, _, _) in expected_xref_classification() {
            let row = taxonomy
                .get(name)
                .unwrap_or_else(|| panic!("missing XREF taxonomy row `{name}`"));
            let expected = xref_failure_codes(tool);
            let mut sorted = expected.clone();
            sorted.sort_unstable();
            sorted.dedup();

            assert_eq!(row.failure_codes, expected, "{name} codes drifted");
            assert_eq!(row.failure_codes, sorted, "{name} codes must be sorted");
            assert_eq!(
                row.failure_semantics,
                render_xref_failure_semantics(&row.failure_codes),
                "{name} prose must be derived from its structured codes"
            );
        }
    }

    #[test]
    fn xref_rows_match_the_normative_domains_operations_and_platforms() {
        let taxonomy = tool_taxonomy();

        for (name, _, domain, operation) in expected_xref_classification() {
            let row = taxonomy
                .get(name)
                .unwrap_or_else(|| panic!("missing XREF taxonomy row `{name}`"));
            let expected_platform = if matches!(
                operation,
                ToolOperation::Read | ToolOperation::List | ToolOperation::Resolve
            ) {
                "DWG and DXF read on all build targets"
            } else {
                "Windows with AutoCAD; DWG and DXF hosts"
            };

            assert_eq!(row.domain, domain, "{name} domain drifted");
            assert_eq!(row.operation, operation, "{name} operation drifted");
            assert_eq!(row.platform, expected_platform, "{name} platform drifted");
        }
    }

    #[test]
    fn taxonomy_metadata_string_fields_are_non_empty() {
        for (tool, taxonomy) in tool_taxonomy() {
            assert!(
                !taxonomy.domain.is_empty(),
                "{tool} domain must be non-empty"
            );
            assert!(
                !taxonomy.identity.is_empty(),
                "{tool} identity must be non-empty"
            );
            assert!(
                !taxonomy.mutation_scope.is_empty(),
                "{tool} mutation_scope must be non-empty"
            );
            assert!(
                !taxonomy.platform.is_empty(),
                "{tool} platform must be non-empty"
            );
            assert!(
                !taxonomy.failure_semantics.is_empty(),
                "{tool} failure_semantics must be non-empty"
            );
        }
    }

    #[test]
    fn expanded_p0_taxonomy_tracks_drawing_owner_and_text_filter_contracts() {
        let taxonomy = tool_taxonomy();
        assert!(taxonomy["get_drawing"]
            .failure_semantics
            .contains("saved-header geometry and current model/paper UCS are availability-tagged"));
        assert_eq!(
            taxonomy["list_text"].identity,
            "drawing_path + optional exact text type, layer, or direct-owner selector"
        );
        assert!(taxonomy["list_text"]
            .failure_semantics
            .contains("contradictory owner selectors"));

        for tool in [
            "list_entities",
            "get_entity",
            "list_block_inserts",
            "get_block_insert",
            "list_text",
            "get_text",
        ] {
            assert!(
                taxonomy[tool]
                    .failure_semantics
                    .contains("duplicate or contradictory direct-owner facts"),
                "{tool} must fail closed on ambiguous direct-owner evidence"
            );
        }
        for tool in ["list_entities", "list_block_inserts", "get_block_insert"] {
            assert!(
                taxonomy[tool]
                    .failure_semantics
                    .contains("ambiguous/contradictory dynamic-block linkage"),
                "{tool} must fail closed on ambiguous dynamic-block evidence"
            );
        }
        assert!(
            taxonomy["get_entity"]
                .failure_semantics
                .contains("ambiguous/contradictory target dynamic-block linkage"),
            "get_entity must validate ambiguous dynamic-block evidence only for the target"
        );
    }

    #[test]
    fn tool_operation_labels_are_stable() {
        let labels = [
            (ToolOperation::Create, "create"),
            (ToolOperation::Read, "read"),
            (ToolOperation::Update, "update"),
            (ToolOperation::Delete, "delete"),
            (ToolOperation::List, "list"),
            (ToolOperation::Reload, "reload"),
            (ToolOperation::Unload, "unload"),
            (ToolOperation::Bind, "bind"),
            (ToolOperation::Resolve, "resolve"),
            (ToolOperation::Export, "export"),
            (ToolOperation::Survey, "survey"),
            (ToolOperation::Validate, "validate"),
            (ToolOperation::Audit, "audit"),
        ];

        for (operation, expected) in labels {
            assert_eq!(operation.as_str(), expected);
        }
    }

    #[test]
    fn crudl_grouping_is_derived_from_operation_variants() {
        for operation in [
            ToolOperation::Create,
            ToolOperation::Read,
            ToolOperation::Update,
            ToolOperation::Delete,
            ToolOperation::List,
        ] {
            assert!(operation.is_crudl(), "{operation:?} should be CRUDL");
        }

        for operation in [
            ToolOperation::Reload,
            ToolOperation::Unload,
            ToolOperation::Bind,
            ToolOperation::Resolve,
            ToolOperation::Export,
            ToolOperation::Survey,
            ToolOperation::Validate,
            ToolOperation::Audit,
        ] {
            assert!(!operation.is_crudl(), "{operation:?} should not be CRUDL");
        }
    }
}
