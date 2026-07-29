use crate::manifest::{
    read_plugin_metadata, title_block_profiles_environment, validate_manifest,
    validate_plugin_license, validate_source_distribution_evidence, McpbManifest, PackageMode,
    PackageTarget, PREVIEW_READ_ONLY_TOOL_COUNT,
};
#[cfg(test)]
use crate::manifest::{
    OWNER_DISTRIBUTION_APPROVAL_SCHEMA, SOURCE_LOCK_SBOM, THIRD_PARTY_LICENSES,
    THIRD_PARTY_LICENSE_POLICY, THIRD_PARTY_LICENSE_PROVENANCE, WINDOWS_SOURCE_CLOSURE_SBOM,
};
use crate::package::{
    embedded_preview_activation_files, is_package_archive_file_path, reject_release_gitignore,
    PreviewActivationFileBinding, PreviewActivationPackageBinding, XrefPackageBinding,
    PREVIEW_ACTIVATION_BINDING_PACKAGE_PATH, PREVIEW_ACTIVATION_BINDING_SCHEMA_VERSION,
    PREVIEW_ACTIVATION_CATALOGUE_PACKAGE_PATH, PREVIEW_ACTIVATION_DIRECTORY,
    XREF_PACKAGE_BINDING_SCHEMA_VERSION,
};
use crate::process_tree::ProcessTree;
use anyhow::{anyhow, Context, Result};
use autocad_mcp::certification::XREF_MUTATION_OPERATIONS;
use autocad_mcp::certification::{
    validate_xref_certification_bundle, xref_sha256_bytes, xref_sha256_file,
    XrefCertificationAttestation, XrefCertificationEvidence, XrefCertificationManifest,
};
use plugin_validate::{validate_documentation_provenance, validate_packaged_structure};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use zip::ZipArchive;

#[cfg(not(test))]
const SUBPROCESS_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(test)]
const SUBPROCESS_TIMEOUT: Duration = Duration::from_secs(2);

#[cfg(not(test))]
pub(crate) const MAX_EXTRACTED_BYTES: u64 = 256 * 1024 * 1024;
#[cfg(test)]
pub(crate) const MAX_EXTRACTED_BYTES: u64 = 8 * 1024 * 1024;
#[cfg(not(test))]
pub(crate) const MAX_EXTRACTED_FILE_BYTES: u64 = 64 * 1024 * 1024;
#[cfg(test)]
pub(crate) const MAX_EXTRACTED_FILE_BYTES: u64 = 4 * 1024 * 1024;
#[cfg(not(test))]
const MAX_ARCHIVE_ENTRIES: usize = 4096;
#[cfg(test)]
const MAX_ARCHIVE_ENTRIES: usize = 128;
#[cfg(not(test))]
const MAX_CENTRAL_DIRECTORY_BYTES: u64 = 1024 * 1024;
#[cfg(test)]
const MAX_CENTRAL_DIRECTORY_BYTES: u64 = 16 * 1024;
#[cfg(not(test))]
const MAX_CAPTURED_OUTPUT_BYTES: u64 = 4 * 1024 * 1024;
#[cfg(test)]
const MAX_CAPTURED_OUTPUT_BYTES: u64 = 256 * 1024;
#[cfg(not(test))]
const MAX_MCP_FRAME_BYTES: u64 = 8 * 1024 * 1024;
#[cfg(test)]
const MAX_MCP_FRAME_BYTES: u64 = 256 * 1024;
#[cfg(not(test))]
const MAX_MCP_SESSION_OUTPUT_BYTES: u64 = 16 * 1024 * 1024;
#[cfg(test)]
const MAX_MCP_SESSION_OUTPUT_BYTES: u64 = 512 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExpectedToolContract {
    name: &'static str,
    description: &'static str,
    input_schema_sha256: &'static str,
    read_only_hint: bool,
    destructive_hint: bool,
    idempotent_hint: bool,
    open_world_hint: bool,
}

const fn tool_contract(
    name: &'static str,
    description: &'static str,
    input_schema_sha256: &'static str,
    read_only_hint: bool,
    destructive_hint: bool,
    idempotent_hint: bool,
) -> ExpectedToolContract {
    ExpectedToolContract {
        name,
        description,
        input_schema_sha256,
        read_only_hint,
        destructive_hint,
        idempotent_hint,
        open_world_hint: true,
    }
}

const EXPECTED_CALLABLE_TOOLS: [ExpectedToolContract; 51] = [
    tool_contract(
        "list_layers",
        "List all layers in a DWG or DXF drawing. Returns expanded LayerRecord fields: handle, name, color_index, frozen, locked, off, is_plottable, xref_dependent, is_current, line_type, line_weight, xref_block_record_handle, xref_name, xref_path, xref_is_overlay, material_handle, and plotstyle_handle.",
        "7abc4c71b8a1c7c3d0c60dfeb1b4376b0539dff50de814d2f8203477fad417ea",
        true,
        false,
        true,
    ),
    tool_contract(
        "get_layer",
        "Get one layer by handle or name from a DWG or DXF drawing. Returns the expanded LayerRecord fields: handle, name, color_index, frozen, locked, off, is_plottable, xref_dependent, is_current, line_type, line_weight, xref_block_record_handle, xref_name, xref_path, xref_is_overlay, material_handle, and plotstyle_handle.",
        "70c20f6eb339aa12f4b2fe0cf4ecefab4db2d30ebcf470defcbe292afcd3b232",
        true,
        false,
        true,
    ),
    tool_contract(
        "create_layer",
        "Create a host-owned layer in a DWG or DXF drawing with writable layer properties: color_index, frozen, locked, off, is_plottable, line_type, and line_weight. Native DXF writes run on all supported hosts; DWG writes require Windows with AutoCAD accoreconsole.",
        "adc8825bc4738cfb7765eef1e78e9015a146ed13ccf5fc4a4eb4ee283f2e6dc5",
        false,
        false,
        true,
    ),
    tool_contract(
        "update_layer",
        "Update writable layer properties: color_index, frozen, locked, off, is_plottable, line_type, and line_weight. Handles are preferred; expected guards reject stale state. Xref-dependent host overrides are property-specific; DXF xref-dependent line_type updates remain unsupported.",
        "305615ebac484ff17ba4aa429d89017c6e75706aec3cfa1804db072b12db66e7",
        false,
        true,
        true,
    ),
    tool_contract(
        "rename_layer",
        "Rename one host-owned layer by handle or name. Rejects protected and xref-dependent layers and preserves represented entity membership.",
        "085e2489bc93a5b8d3a286b8e19765548e12923fe09da71d09b7d431fd25fd50",
        false,
        true,
        true,
    ),
    tool_contract(
        "delete_layer",
        "Safely delete one unused host-owned layer by handle or name. Rejects layer 0, DEFPOINTS, xref-dependent layers, the current layer, and layers with content.",
        "64a759c61a781fa183b4d89d0bf7705336f9547bc4d4e870cc7eefeaa17016e2",
        false,
        true,
        true,
    ),
    tool_contract(
        "attach_xref",
        "Attach a source DWG as a direct attachment or overlay and atomically create its initial instance. Windows with a package-mode-admitted full AutoCAD runtime is required; Preview activation is candidate-only.",
        "1fa906304301ca2dddf56ce68bd2586dbdd10cf55f96c2c90956730c0bd8c1d7",
        false,
        false,
        true,
    ),
    tool_contract(
        "get_xref",
        "Get one direct XREF attachment definition by block-record handle, case-insensitive name, or a matching pair.",
        "a0af3b92ff84efb0a97792a4293757e52e3c013a110e8495e595ceedbdba1fe1",
        true,
        false,
        true,
    ),
    tool_contract(
        "update_xref",
        "Update writable properties of one direct XREF attachment using optional stale-state guards. Windows with a package-mode-admitted full AutoCAD runtime is required; Preview activation is candidate-only.",
        "3dfe910bfaa19eb3acdbc52d31e4f722633a9396a45a199e543bcb5548884d43",
        false,
        true,
        false,
    ),
    tool_contract(
        "detach_xref",
        "Detach one direct XREF attachment and delete all of its instances after optional exact-scope guards pass. Windows with a package-mode-admitted full AutoCAD runtime is required; Preview activation is candidate-only.",
        "2a5e015b734c75030eef4fcffa2570afef0b3f8675ec2250ac0d2d5f0c07de69",
        false,
        true,
        true,
    ),
    tool_contract(
        "list_xrefs",
        "List direct XREF attachment definitions in a DWG or DXF drawing as complete attachment records sorted by numeric handle.",
        "54911ec65817e12e63cd562a73012852aa74da171bd2ab38fa099600845eb954",
        true,
        false,
        true,
    ),
    tool_contract(
        "insert_xref_instance",
        "Insert another instance of an existing direct XREF attachment with explicit or deterministic placement. Windows with a package-mode-admitted full AutoCAD runtime is required; Preview activation is candidate-only.",
        "5e0eb458c89828bfce6655d047c2f51ef3f712a15b62d72fe5eef4bba454a710",
        false,
        false,
        false,
    ),
    tool_contract(
        "get_xref_instance",
        "Get one placed XREF instance by its entity handle from a DWG or DXF drawing.",
        "aa6edfb1af5f16a8c47060727ed503500997d7b79092d268529adbcb25621db4",
        true,
        false,
        true,
    ),
    tool_contract(
        "update_xref_instance",
        "Update writable placement properties of one XREF instance while preserving its attachment and owner. Windows with a package-mode-admitted full AutoCAD runtime is required; Preview activation is candidate-only.",
        "873276a98557efc9c45e90f893abc6523db0f56b1a3e70a3cefc33aa8f5014fb",
        false,
        true,
        true,
    ),
    tool_contract(
        "delete_xref_instance",
        "Delete one XREF instance by entity handle while leaving its attachment definition intact. Windows with a package-mode-admitted full AutoCAD runtime is required; Preview activation is candidate-only.",
        "4b908c9129985b0497a8ccd075f6a84fc571301f39126764c5820a09d3256831",
        false,
        true,
        true,
    ),
    tool_contract(
        "list_xref_instances",
        "List placed instances of direct XREF attachments, with optional attachment, owner, layer, and visibility filters, sorted by numeric handle.",
        "b2e7a22076aa68cf0a3157d22dd31c8184746a37e56677fbb627edcde79dc8bc",
        true,
        false,
        true,
    ),
    tool_contract(
        "reload_xref",
        "Reload one direct XREF attachment from its source and reconcile retained layer overrides. Windows with a package-mode-admitted full AutoCAD runtime is required; Preview activation is candidate-only.",
        "59181912bb226bc0faaee518a0364d3919435d0d4eeaf07f441ae8542af78a79",
        false,
        true,
        false,
    ),
    tool_contract(
        "unload_xref",
        "Unload one direct XREF attachment without removing its definition or instances. Windows with a package-mode-admitted full AutoCAD runtime is required; Preview activation is candidate-only.",
        "c47e705c03685314d4fc219ac51a44c91224adf76cbca26b27bc164f91e7f49f",
        false,
        true,
        true,
    ),
    tool_contract(
        "bind_xref",
        "Bind one direct XREF into the host with explicit symbol and dependency strategies and complete mapping evidence. Windows with a package-mode-admitted full AutoCAD runtime is required; Preview activation is candidate-only.",
        "4227ed443c81d91a20dba1563617cea65bddcb3e2300953e841b733cb41d7138",
        false,
        true,
        true,
    ),
    tool_contract(
        "resolve_xref_path",
        "Resolve one direct XREF's saved path deterministically against its immediate host and optional ordered search paths.",
        "5d59c0569ad3018ee782edae60d2eeff5bb34c293efbf2f6170921806229e862",
        true,
        false,
        true,
    ),
    tool_contract(
        "list_xref_dependencies",
        "Traverse direct and propagated XREF dependencies with deterministic pre-order output and explicit truncation metadata.",
        "8b1f0e012baf0904a8b1be66593e78575ae5756ec6c94a1477246d23a1216083",
        true,
        false,
        true,
    ),
    tool_contract(
        "list_blocks",
        "List all user-defined block definitions in a DWG or DXF drawing. Returns a JSON array with name, has_attributes, and description fields.",
        "7abc4c71b8a1c7c3d0c60dfeb1b4376b0539dff50de814d2f8203477fad417ea",
        true,
        false,
        true,
    ),
    tool_contract(
        "get_drawing",
        "Read a closed DWG drawing summary, including decoded version, units, metadata, availability-qualified saved-header model/paper geometry and current UCS state, current named resources, and resource counts.",
        "1df652b273976a3edceef4b20dc6244afb8cb319bc77a36f3e3a0794a9926072",
        true,
        false,
        true,
    ),
    tool_contract(
        "list_entities",
        "List drawing entities in deterministic numeric-handle order with exact optional type, layer, owner, and visibility filters, reason-bearing bounds/detail availability, and proven dynamic-block linkage for INSERTs. Returns a bounded envelope; offset defaults to 0, limit defaults to 200, and the maximum limit is 1000.",
        "a1397bee1fa3ee15d31665d251957ec0e5e15402777f5c679af89e696a7620ea",
        true,
        false,
        true,
    ),
    tool_contract(
        "get_entity",
        "Get one drawing entity by its stable hexadecimal handle. Returns common identity, direct-owner context, layer, display, availability-qualified bounds, and bounded type-specific detail, including proven dynamic-block linkage for INSERTs.",
        "93bf22fd854eb5077535b817e2eedc89ddb43bc2759a935d3c2ed8c11151f48d",
        true,
        false,
        true,
    ),
    tool_contract(
        "list_block_definitions",
        "List every block definition in deterministic numeric-handle order, including anonymous, layout, XREF, and XREF-dependent BLOCK_RECORDs with explicit classification and retained structural context.",
        "1df652b273976a3edceef4b20dc6244afb8cb319bc77a36f3e3a0794a9926072",
        true,
        false,
        true,
    ),
    tool_contract(
        "get_block_definition",
        "Get one block definition by handle or case-insensitive name. If both identities are supplied they must resolve to the same BLOCK_RECORD.",
        "9fd5b1f8882bfae8092dfb2fb28c1b32858ea0538ac8242d20e77d2f979344a2",
        true,
        false,
        true,
    ),
    tool_contract(
        "list_block_inserts",
        "List ordinary host block INSERT/MINSERT entities in deterministic numeric-handle order with definition identity, proven dynamic-block linkage, direct-owner context, placement, array, and attribute data. XREF instances are excluded.",
        "1df652b273976a3edceef4b20dc6244afb8cb319bc77a36f3e3a0794a9926072",
        true,
        false,
        true,
    ),
    tool_contract(
        "get_block_insert",
        "Get one ordinary host block INSERT/MINSERT entity by handle with definition identity, proven dynamic-block linkage, direct-owner context, placement, array, and attribute data. XREF instances are excluded.",
        "c6d87fa9b45dfd291ca80198f688258e1a4c08a1e8ff6d8ce79e6d59f2da3d9b",
        true,
        false,
        true,
    ),
    tool_contract(
        "read_title_blocks",
        "Read title-block attributes from all attributed INSERT entities in a DWG or DXF drawing. Unique tags are returned in attributes (tag → scalar); duplicate normalized tags are returned without data loss in attribute_arrays (tag → values in source order). Set attribute_value_mode=arrays to return every tag as an array. Duplicate tags produce a successful partial result with structured warnings, not a whole-drawing failure.",
        "8541f9c5682fe953f9a5de7c0f1bfa7d045db37fafaace87ca7bab2cb72e4309",
        true,
        false,
        true,
    ),
    tool_contract(
        "dump_text",
        "Dump all TEXT and MTEXT entities from a DWG or DXF drawing. Returns a JSON array with text_type, value, layer, x, and y fields.",
        "7abc4c71b8a1c7c3d0c60dfeb1b4376b0539dff50de814d2f8203477fad417ea",
        true,
        false,
        true,
    ),
    tool_contract(
        "list_text",
        "List TEXT and MTEXT entities in deterministic numeric-handle order with exact optional text_types, layer, owner_handle, and semantic owner_type+owner_name filters, plus stable identity, direct-owner context, 3D placement, style, visibility, and type-specific geometry.",
        "bd8b83a1430fe7a7a0aea8f5a29cd6bcca9e243a7ce104a86ca9da1b124b55db",
        true,
        false,
        true,
    ),
    tool_contract(
        "get_text",
        "Get one TEXT or MTEXT entity by its stable hexadecimal handle with direct-owner context, 3D placement, style, visibility, and type-specific geometry.",
        "144b777c1ace5b98376d1ea64d6560f95009fb57796acdc5711e4b4aa058dbb1",
        true,
        false,
        true,
    ),
    tool_contract(
        "write_title_block",
        "Write title-block attributes in place in a DWG or native ASCII DXF drawing. Accepts canonical field names (e.g. 'revision', 'drawing_number') and maps them to the correct DXF attribute tags for the detected profile. Duplicate canonical request keys are rejected after trimming and case normalization. A duplicate drawing tag blocks the write only when a requested field maps to that tag; duplicate unrequested tags do not. Fails loudly if the drawing contains no recognised title-block profile — never guesses. DWG files require accoreconsole (Windows only); native ASCII DXF files use a pure-Rust patcher on any platform.",
        "ec2e598377abb643f555fb7bc7a23e25f1c6da72243b6ee2449ee801b51759d5",
        false,
        true,
        true,
    ),
    tool_contract(
        "list_layouts",
        "List all layouts in a DWG or DXF drawing. Returns a JSON array with name, is_model, tab_order, paper_width_mm, and paper_height_mm per layout. Paper dimensions are copied from stored plot settings; 0.0 means the drawing reader has no usable physical paper size for that layout. Call this before plot_to_pdf to discover available layout names.",
        "7abc4c71b8a1c7c3d0c60dfeb1b4376b0539dff50de814d2f8203477fad417ea",
        true,
        false,
        true,
    ),
    tool_contract(
        "get_layout",
        "Get one layout by handle or case-insensitive name with backing block-record identity, limits, nullable extents, insertion base, UCS, last-active paper-space viewport handle, and embedded plot settings. Empty-layout extents are returned as null. If both identities are supplied they must agree.",
        "07eee28890fe1c60b4c4b5c76103dcfae44f11bd0da4666f2eb8646ead53ef94",
        true,
        false,
        true,
    ),
    tool_contract(
        "list_layout_viewports",
        "List paper-space VIEWPORT entities in deterministic numeric-handle order, optionally filtered by layout handle or name. These are layout-owned entities, not VPORT table rows; is_last_active_for_layout identifies the layout's last-active viewport, while unavailable reader fields are null.",
        "b026155cb6ac0d9a96d7978bc667b8bda61c407b3a0885c7ceada9d6f48e4db1",
        true,
        false,
        true,
    ),
    tool_contract(
        "get_layout_viewport",
        "Get one paper-space VIEWPORT entity by its stable hexadecimal handle with resolved layout identity, display rectangle, view geometry, scale, clipping, render mode, and frozen layers. Unrecoverable is_on and custom_scale values are null; zero scale operands yield a null model_to_paper_scale.",
        "f5b61468cbe29b7e58e6ba8934fb370ee8968252ae06750bed4356a9f7e19105",
        true,
        false,
        true,
    ),
    tool_contract(
        "list_plot_settings",
        "List standalone named PLOTSETTINGS objects in deterministic numeric-handle order with device, media, margins, plot area, scale, rotation, style, shade, and flag data. Layout-embedded settings remain on get_layout.",
        "1df652b273976a3edceef4b20dc6244afb8cb319bc77a36f3e3a0794a9926072",
        true,
        false,
        true,
    ),
    tool_contract(
        "get_plot_setting",
        "Get one standalone named PLOTSETTINGS object by handle or case-insensitive page-setup name. If both identities are supplied they must agree.",
        "86a3c1f8193cddace502861417977a8bb193923eb349ca770637a2756b76c174",
        true,
        false,
        true,
    ),
    tool_contract(
        "list_linetypes",
        "List linetype table records in deterministic numeric-handle order with stable identity, current and standard state, description, pattern length, alignment, XREF dependency, and retained signed dash, space, and dot lengths.",
        "1df652b273976a3edceef4b20dc6244afb8cb319bc77a36f3e3a0794a9926072",
        true,
        false,
        true,
    ),
    tool_contract(
        "get_linetype",
        "Get one linetype table record by handle or case-insensitive name. If both identities are supplied they must agree.",
        "dd50b120a4602895f29178f778084b6906910b13970185dee3dd81c4985b99b4",
        true,
        false,
        true,
    ),
    tool_contract(
        "list_text_styles",
        "List text-style table records in deterministic numeric-handle order with stable identity, current and standard state, font files, height, width factor, oblique angle, generation flags, annotation state, and XREF dependency.",
        "1df652b273976a3edceef4b20dc6244afb8cb319bc77a36f3e3a0794a9926072",
        true,
        false,
        true,
    ),
    tool_contract(
        "get_text_style",
        "Get one text-style table record by handle or case-insensitive name. If both identities are supplied they must agree.",
        "dd50b120a4602895f29178f778084b6906910b13970185dee3dd81c4985b99b4",
        true,
        false,
        true,
    ),
    tool_contract(
        "list_dimension_styles",
        "List dimension-style table records in deterministic numeric-handle order with stable identity, current and standard state, scale, line, text, unit, tolerance, and handle-reference data retained by the parser.",
        "1df652b273976a3edceef4b20dc6244afb8cb319bc77a36f3e3a0794a9926072",
        true,
        false,
        true,
    ),
    tool_contract(
        "get_dimension_style",
        "Get one dimension-style table record by handle or case-insensitive name. If both identities are supplied they must agree.",
        "dd50b120a4602895f29178f778084b6906910b13970185dee3dd81c4985b99b4",
        true,
        false,
        true,
    ),
    tool_contract(
        "list_named_views",
        "List named VIEW table records in deterministic numeric-handle order with stable identity, center, dimensions, target, direction, twist, lens, and clipping distances.",
        "1df652b273976a3edceef4b20dc6244afb8cb319bc77a36f3e3a0794a9926072",
        true,
        false,
        true,
    ),
    tool_contract(
        "get_named_view",
        "Get one named VIEW table record by handle or case-insensitive name. If both identities are supplied they must agree.",
        "dd50b120a4602895f29178f778084b6906910b13970185dee3dd81c4985b99b4",
        true,
        false,
        true,
    ),
    tool_contract(
        "list_named_ucs",
        "List named UCS table records in deterministic numeric-handle order with stable identity, origin, and X/Y/Z axes.",
        "1df652b273976a3edceef4b20dc6244afb8cb319bc77a36f3e3a0794a9926072",
        true,
        false,
        true,
    ),
    tool_contract(
        "get_named_ucs",
        "Get one named UCS table record by handle or case-insensitive name. If both identities are supplied they must agree.",
        "dd50b120a4602895f29178f778084b6906910b13970185dee3dd81c4985b99b4",
        true,
        false,
        true,
    ),
    tool_contract(
        "plot_to_pdf",
        "Plot a DWG layout to an absolute PDF output path via accoreconsole. The layout must have a DWG To PDF.pc3 (or equivalent file-plotter) page setup already configured in the drawing. Use list_layouts to discover layout names. Windows only — returns an error on non-Windows platforms.",
        "c1eab155a528e8646bf59a40aa7477713ab02a8a0bbd7f7bdad4b60c6f71bf73",
        false,
        true,
        false,
    ),
];

#[cfg(test)]
const PUBLIC_XREF_TOOLS: [&str; 15] = [
    "attach_xref",
    "get_xref",
    "update_xref",
    "detach_xref",
    "list_xrefs",
    "insert_xref_instance",
    "get_xref_instance",
    "update_xref_instance",
    "delete_xref_instance",
    "list_xref_instances",
    "reload_xref",
    "unload_xref",
    "bind_xref",
    "resolve_xref_path",
    "list_xref_dependencies",
];
const RESERVED_XREF_CLIP_TOOLS: [&str; 5] = [
    "list_xref_clips",
    "get_xref_clip",
    "create_xref_clip",
    "update_xref_clip",
    "delete_xref_clip",
];
const OBSOLETE_XREF_TOOLS: [&str; 2] = ["open_xref", "rename_xref"];
const XREF_CERTIFIED_ARG_PATH_ENV: &str = "AUTOCAD_MCP_XREF_CERTIFIED_ARG_PATH";
const XREF_CERTIFIED_ARG_PACKAGE_PATH: &str =
    "plugin/resources/xref-certification/certified-profile.arg";
const XREF_ATTACHMENT_RECORD_KEYS: [&str; 8] = [
    "handle",
    "name",
    "saved_path",
    "path_mode",
    "reference_type",
    "load_state",
    "instance_count",
    "definition_base_point",
];

#[derive(Clone, Copy, Debug, PartialEq)]
enum XrefSmokePointAvailability {
    Available { x: f64, y: f64, z: f64 },
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct XrefSmokeRecord<'a> {
    handle: &'a str,
    name: &'a str,
    saved_path: &'a str,
    path_mode: &'a str,
    reference_type: &'a str,
    load_state: &'a str,
    instance_count: u64,
    definition_base_point: XrefSmokePointAvailability,
}

const EXPECTED_XREF_RECORDS: [XrefSmokeRecord<'static>; 3] = [
    XrefSmokeRecord {
        handle: "F",
        name: "SITE_MODEL",
        saved_path: "refs/site.dwg",
        path_mode: "relative",
        reference_type: "attachment",
        load_state: "unavailable",
        instance_count: 2,
        definition_base_point: XrefSmokePointAvailability::Available {
            x: 1.0,
            y: 2.0,
            z: 3.0,
        },
    },
    XrefSmokeRecord {
        handle: "10",
        name: "GRID_OVERLAY",
        saved_path: "refs/grid.dwg",
        path_mode: "relative",
        reference_type: "overlay",
        load_state: "unavailable",
        instance_count: 1,
        definition_base_point: XrefSmokePointAvailability::Available {
            x: 0.0,
            y: 0.0,
            z: 0.0,
        },
    },
    XrefSmokeRecord {
        handle: "11",
        name: "EMPTY_PATH",
        saved_path: "",
        path_mode: "unsupported",
        reference_type: "attachment",
        load_state: "unavailable",
        instance_count: 1,
        definition_base_point: XrefSmokePointAvailability::Available {
            x: -1.0,
            y: -2.0,
            z: -3.0,
        },
    },
];

pub struct SmokeOptions {
    pub package_path: PathBuf,
    pub fixture_path: Option<PathBuf>,
    pub require_executable: bool,
    pub require_lsp_executable: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DistributionEvidenceMode {
    ExactCompiled,
    ApprovalBound,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ModeRequirement {
    Required(PackageMode),
    OwnerApproval(PackageMode),
}

struct StaticPackage {
    manifest: McpbManifest,
    target: PackageTarget,
    mode: PackageMode,
}

#[derive(Debug)]
pub struct SmokeReport {
    pub executable_ran: bool,
    pub lsp_executable_ran: bool,
}

/// A statically validated Windows Preview MCPB unpacked into an
/// evaluator-owned directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedPreviewEvaluationPackage {
    pub package_name: String,
    pub package_version: String,
    pub binary_path: PathBuf,
    pub package_sha256: String,
    pub manifest_sha256: String,
    pub binary_sha256: String,
    pub activation_catalogue_sha256: String,
    pub activation_binding_sha256: String,
}

/// Exercise an unpackaged AutoCAD MCP binary through the same stdio lifecycle
/// Claude Desktop uses, together with the release CLI surface.
///
/// This gate is intentionally independent of package certification so it can
/// run against an ordinary release build on native macOS and Windows hosts.
pub fn smoke_desktop_binary(binary_path: &Path, fixture_path: &Path) -> Result<()> {
    if !binary_path.is_file() {
        return Err(anyhow!(
            "desktop smoke binary must exist and be a file: {}",
            binary_path.display()
        ));
    }
    if !fixture_path.is_file() {
        return Err(anyhow!(
            "desktop smoke fixture must exist and be a file: {}",
            fixture_path.display()
        ));
    }

    let binary = std::fs::canonicalize(binary_path).with_context(|| {
        format!(
            "canonicalize binary path for Claude Desktop smoke: {}",
            binary_path.display()
        )
    })?;
    let fixture = canonical_fixture_path(fixture_path)?;
    run_executable_smoke(&binary, &fixture, PackageMode::Release)
}

/// Exercise an already-built AutoLISP LSP binary through initialize, shutdown,
/// and exit over native stdio without requiring an MCPB.
pub fn smoke_lsp_binary(binary_path: &Path) -> Result<()> {
    if !binary_path.is_file() {
        return Err(anyhow!(
            "LSP smoke binary must exist and be a file: {}",
            binary_path.display()
        ));
    }
    let binary = std::fs::canonicalize(binary_path).with_context(|| {
        format!(
            "canonicalize binary path for AutoLISP LSP smoke: {}",
            binary_path.display()
        )
    })?;
    run_lsp_executable_smoke(&binary)
}

pub fn smoke_package(options: SmokeOptions) -> Result<SmokeReport> {
    let temp = tempfile::tempdir()?;
    extract_package(&options.package_path, temp.path())?;
    let package = validate_extracted_package(
        temp.path(),
        DistributionEvidenceMode::ExactCompiled,
        options.require_lsp_executable,
        None,
    )?;
    let manifest = package.manifest;
    let package_target = package.target;
    let package_mode = package.mode;
    let lsp_path = temp.path().join("plugin/.lsp.json");
    let has_lsp_config = lsp_path.is_file();
    if options.require_lsp_executable && !has_lsp_config {
        return Err(anyhow!(
            "plugin/.lsp.json is required for LSP executable smoke"
        ));
    }

    let host_target = host_target();
    if host_target != Some(package_target) {
        if options.require_executable || options.require_lsp_executable {
            return Err(anyhow!(
                "package target {:?} does not match host target {:?}",
                package_target,
                host_target
            ));
        }
        return Ok(SmokeReport {
            executable_ran: false,
            lsp_executable_ran: false,
        });
    }

    let mut executable_ran = false;
    if options.require_executable || options.fixture_path.is_some() {
        let fixture_path = match options.fixture_path {
            Some(path) if path.is_file() => Some(canonical_fixture_path(&path)?),
            Some(path) if options.require_executable => {
                return Err(anyhow!(
                    "fixture path must exist and be a file for executable smoke: {}",
                    path.display()
                ));
            }
            None if options.require_executable => {
                return Err(anyhow!("fixture path is required for executable smoke"));
            }
            Some(_) | None => None,
        };

        if let Some(fixture_path) = fixture_path {
            run_executable_smoke(
                &temp.path().join(&manifest.server.entry_point),
                &fixture_path,
                package_mode,
            )?;
            executable_ran = true;
        }
    }

    let mut lsp_executable_ran = false;
    if options.require_lsp_executable {
        let lsp_binary = temp.path().join(lsp_binary_path(package_target));
        run_lsp_executable_smoke(&lsp_binary)?;
        lsp_executable_ran = true;
    }

    Ok(SmokeReport {
        executable_ran,
        lsp_executable_ran,
    })
}

/// Extract and statically validate the exact Windows Preview package selected
/// by a licensed-host evaluation plan.
///
/// `extraction_root` must already exist and be empty. This keeps temporary
/// storage ownership with the evaluator instead of silently allocating an
/// unmanaged system temporary directory.
pub fn prepare_preview_evaluation_package(
    package_path: &Path,
    expected_package_sha256: &str,
    extraction_root: &Path,
) -> Result<PreparedPreviewEvaluationPackage> {
    if !package_path.is_file() {
        return Err(anyhow!(
            "Preview evaluation MCPB must exist and be a file: {}",
            package_path.display()
        ));
    }
    if !extraction_root.is_dir() {
        return Err(anyhow!(
            "Preview evaluation extraction root must already exist: {}",
            extraction_root.display()
        ));
    }
    if std::fs::read_dir(extraction_root)
        .with_context(|| {
            format!(
                "inspect Preview evaluation extraction root {}",
                extraction_root.display()
            )
        })?
        .next()
        .is_some()
    {
        return Err(anyhow!(
            "Preview evaluation extraction root must be empty: {}",
            extraction_root.display()
        ));
    }

    let mut package_file =
        File::open(package_path).with_context(|| format!("open {}", package_path.display()))?;
    let package_sha256 = sha256_open_file(&mut package_file)?;
    if package_sha256 != expected_package_sha256 {
        return Err(anyhow!(
            "opened Preview MCPB digest does not match the evaluation plan"
        ));
    }
    extract_mcpb_from_open_file(&mut package_file, extraction_root)?;
    let package = validate_extracted_package(
        extraction_root,
        DistributionEvidenceMode::ExactCompiled,
        true,
        Some(ModeRequirement::Required(PackageMode::Preview)),
    )?;
    if package.target != PackageTarget::WindowsX64 {
        return Err(anyhow!(
            "Preview AutoCAD evaluation requires a Windows x64 MCPB"
        ));
    }

    let manifest_path = extraction_root.join("manifest.json");
    let binary_path = extraction_root.join(&package.manifest.server.entry_point);
    let activation_catalogue = extraction_root.join(PREVIEW_ACTIVATION_CATALOGUE_PACKAGE_PATH);
    let activation_binding = extraction_root.join(PREVIEW_ACTIVATION_BINDING_PACKAGE_PATH);
    Ok(PreparedPreviewEvaluationPackage {
        package_name: package.manifest.name,
        package_version: package.manifest.version,
        package_sha256,
        manifest_sha256: xref_sha256_file(&manifest_path)?,
        binary_sha256: xref_sha256_file(&binary_path)?,
        activation_catalogue_sha256: xref_sha256_file(&activation_catalogue)?,
        activation_binding_sha256: xref_sha256_file(&activation_binding)?,
        binary_path,
    })
}

fn sha256_open_file(file: &mut File) -> Result<String> {
    file.seek(SeekFrom::Start(0))
        .context("rewind MCPB before hashing")?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).context("hash opened MCPB")?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    file.seek(SeekFrom::Start(0))
        .context("rewind MCPB after hashing")?;
    Ok(format!("{:x}", digest.finalize()))
}

/// Validate an approval-bound MCPB extracted from the verifier's already-open
/// artifact handle. Distribution-evidence bytes are reconciled by the approval
/// verifier; every other static package policy is shared with ordinary package
/// smoke.
pub(crate) fn validate_approval_package(
    root: &Path,
    expected_release_version: &str,
    expected_mode: PackageMode,
) -> Result<PackageTarget> {
    let package = validate_extracted_package(
        root,
        DistributionEvidenceMode::ApprovalBound,
        true,
        Some(ModeRequirement::OwnerApproval(expected_mode)),
    )?;
    if package.manifest.version != expected_release_version {
        return Err(anyhow!(
            "approval-bound MCPB version {} does not match owner approval release version {expected_release_version}",
            package.manifest.version
        ));
    }
    Ok(package.target)
}

pub(crate) fn validate_unbound_preview_package(root: &Path) -> Result<PackageTarget> {
    validate_extracted_package(
        root,
        DistributionEvidenceMode::ApprovalBound,
        true,
        Some(ModeRequirement::Required(PackageMode::Preview)),
    )
    .map(|package| package.target)
}

fn validate_extracted_package(
    root: &Path,
    distribution_evidence: DistributionEvidenceMode,
    require_lsp: bool,
    mode_requirement: Option<ModeRequirement>,
) -> Result<StaticPackage> {
    let manifest_path = root.join("manifest.json");
    let manifest_bytes = std::fs::read(&manifest_path)
        .with_context(|| format!("read {}", manifest_path.display()))?;
    let manifest_value = distribution_approval::parse_strict_json(&manifest_bytes)
        .with_context(|| format!("strictly parse {}", manifest_path.display()))?;
    let manifest: McpbManifest = serde_json::from_value(manifest_value)
        .with_context(|| format!("validate closed schema for {}", manifest_path.display()))?;
    let target = infer_target(&manifest)?;
    let mode = validate_manifest(&manifest, target)?;
    if let Some(requirement) = mode_requirement {
        let expected = match requirement {
            ModeRequirement::Required(expected) | ModeRequirement::OwnerApproval(expected) => {
                expected
            }
        };
        if expected != mode {
            return match requirement {
                ModeRequirement::OwnerApproval(_) => Err(anyhow!(
                "approval-bound MCPB mode {mode:?} does not match owner approval mode {expected:?}"
            )),
                ModeRequirement::Required(_) => Err(anyhow!(
                    "MCPB mode {mode:?} does not match required mode {expected:?}"
                )),
            };
        }
    }
    validate_static_contents(
        root,
        &manifest,
        target,
        distribution_evidence,
        require_lsp,
        mode,
    )?;
    Ok(StaticPackage {
        manifest,
        target,
        mode,
    })
}

fn canonical_fixture_path(path: &Path) -> Result<PathBuf> {
    std::fs::canonicalize(path).with_context(|| {
        format!(
            "canonicalize fixture path for executable smoke: {}",
            path.display()
        )
    })
}

fn lsp_binary_path(target: PackageTarget) -> &'static str {
    match target {
        PackageTarget::WindowsX64 => "plugin/bin/autolisp-lsp.exe",
        PackageTarget::MacosArm64 => "plugin/bin/autolisp-lsp",
    }
}

fn lsp_command(target: PackageTarget) -> &'static str {
    match target {
        PackageTarget::WindowsX64 => "${CLAUDE_PLUGIN_ROOT}/bin/autolisp-lsp.exe",
        PackageTarget::MacosArm64 => "${CLAUDE_PLUGIN_ROOT}/bin/autolisp-lsp",
    }
}

fn validate_lsp_contents(root: &Path, target: PackageTarget) -> Result<()> {
    let lsp_path = root.join("plugin/.lsp.json");
    if !lsp_path.exists() {
        return Ok(());
    }
    let bytes = std::fs::read(&lsp_path).with_context(|| format!("read {}", lsp_path.display()))?;
    let value = distribution_approval::parse_strict_json(&bytes)
        .with_context(|| format!("strictly parse {}", lsp_path.display()))?;
    let server = value
        .get("autolisp-lsp")
        .ok_or_else(|| anyhow!("plugin/.lsp.json missing autolisp-lsp entry"))?;
    let expected_command = lsp_command(target);
    if server.get("command").and_then(Value::as_str) != Some(expected_command) {
        return Err(anyhow!(
            "plugin/.lsp.json autolisp-lsp command must be {expected_command}"
        ));
    }
    if server["extensionToLanguage"][".lsp"] != "autolisp" {
        return Err(anyhow!("plugin/.lsp.json must map .lsp to autolisp"));
    }
    if server.get("transport").and_then(Value::as_str) != Some("stdio") {
        return Err(anyhow!(
            "plugin/.lsp.json autolisp-lsp transport must be stdio"
        ));
    }
    if !server
        .get("args")
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty)
    {
        return Err(anyhow!(
            "plugin/.lsp.json autolisp-lsp args must be an empty array"
        ));
    }
    let top = value
        .as_object()
        .ok_or_else(|| anyhow!("plugin/.lsp.json must be an object"))?;
    if top.keys().map(String::as_str).collect::<BTreeSet<_>>() != BTreeSet::from(["autolisp-lsp"]) {
        return Err(anyhow!(
            "plugin/.lsp.json must contain exactly the autolisp-lsp server"
        ));
    }
    let server_object = server
        .as_object()
        .ok_or_else(|| anyhow!("plugin/.lsp.json autolisp-lsp entry must be an object"))?;
    if server_object
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != BTreeSet::from(["args", "command", "extensionToLanguage", "transport"])
    {
        return Err(anyhow!(
            "plugin/.lsp.json autolisp-lsp fields do not match the closed descriptor"
        ));
    }
    let extension_map = server["extensionToLanguage"]
        .as_object()
        .ok_or_else(|| anyhow!("plugin/.lsp.json extensionToLanguage must be an object"))?;
    if extension_map.len() != 1 {
        return Err(anyhow!(
            "plugin/.lsp.json must map exactly .lsp to autolisp"
        ));
    }
    let expected = lsp_binary_path(target);
    if !root.join(expected).is_file() {
        return Err(anyhow!("missing {expected} for plugin/.lsp.json"));
    }
    Ok(())
}

fn run_lsp_executable_smoke(binary: &Path) -> Result<()> {
    #[cfg(unix)]
    ensure_unix_executable(binary)?;

    let label = "autolisp-lsp initialize";
    let mut command = Command::new(binary);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }

    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawn {label}"))?;
    let mut process_tree = match ProcessTree::new(&child) {
        Ok(process_tree) => process_tree,
        Err(e) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(e).with_context(|| format!("contain process tree for {label}"));
        }
    };
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("failed to capture stdin for {label}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("failed to capture stdout for {label}"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("failed to capture stderr for {label}"))?;
    let frame_rx = spawn_lsp_frame_reader(stdout, label);
    let mut stderr = StreamCapture::Pending(spawn_stream_reader(stderr, label, "stderr"));

    if let Err(e) = write_lsp_message(
        &mut stdin,
        &serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "processId": null,
                "rootUri": null,
                "capabilities": {}
            }
        }),
    ) {
        terminate_child(&mut child, &mut process_tree);
        let _ = child.wait();
        return Err(e).context("write autolisp-lsp initialize request");
    }

    let deadline = Instant::now() + SUBPROCESS_TIMEOUT;
    let response = loop {
        if let Some(status) = child.try_wait()? {
            process_tree.terminate();
            let _ = poll_stream_capture(&mut stderr);
            return Err(anyhow!(
                "{label} exited before initialize response with status {status}: stderr: {}",
                String::from_utf8_lossy(&current_stream_bytes(&stderr))
            ));
        }
        match frame_rx.try_recv() {
            Ok(Ok(frame)) => break frame,
            Ok(Err(e)) => {
                terminate_child(&mut child, &mut process_tree);
                let _ = child.wait();
                return Err(e);
            }
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => {
                terminate_child(&mut child, &mut process_tree);
                let _ = child.wait();
                return Err(anyhow!(
                    "{label} stdout reader disconnected before returning a frame"
                ));
            }
        }
        let _ = poll_stream_capture(&mut stderr);
        if Instant::now() >= deadline {
            terminate_child(&mut child, &mut process_tree);
            let _ = child.wait();
            return Err(anyhow!(
                "{label} timed out after {:?}: stderr: {}",
                SUBPROCESS_TIMEOUT,
                String::from_utf8_lossy(&current_stream_bytes(&stderr))
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    };

    if let Err(e) = validate_lsp_initialize_response(&response) {
        terminate_child(&mut child, &mut process_tree);
        let _ = child.wait();
        return Err(e);
    }
    if let Err(e) = write_lsp_message(
        &mut stdin,
        &serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "shutdown"}),
    ) {
        terminate_child(&mut child, &mut process_tree);
        let _ = child.wait();
        return Err(e).context("write autolisp-lsp shutdown request");
    }
    if let Err(e) = write_lsp_message(
        &mut stdin,
        &serde_json::json!({"jsonrpc": "2.0", "method": "exit"}),
    ) {
        terminate_child(&mut child, &mut process_tree);
        let _ = child.wait();
        return Err(e).context("write autolisp-lsp exit notification");
    }
    drop(stdin);

    let shutdown_deadline = Instant::now() + SUBPROCESS_TIMEOUT;
    loop {
        if child.try_wait()?.is_some() {
            process_tree.terminate();
            return Ok(());
        }
        if Instant::now() >= shutdown_deadline {
            terminate_child(&mut child, &mut process_tree);
            let _ = child.wait();
            return Err(anyhow!(
                "{label} did not exit after shutdown within {:?}",
                SUBPROCESS_TIMEOUT
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn extract_package(package_path: &Path, dest: &Path) -> Result<()> {
    let mut file =
        File::open(package_path).with_context(|| format!("open {}", package_path.display()))?;
    extract_mcpb_from_open_file(&mut file, dest)
}

/// Extract one MCPB from an already-open artifact handle.
///
/// This helper is used only by ordinary package smoke. Approval verification
/// extracts from its immutable snapshot during the authoritative inventory
/// scan, so its static tree and artifact bindings share the same byte pass.
fn extract_mcpb_from_open_file(file: &mut File, dest: &Path) -> Result<()> {
    validate_mcpb_central_directory_open(file)?;
    file.seek(SeekFrom::Start(0))
        .context("rewind MCPB after central-directory validation")?;
    let mut archive = ZipArchive::new(file).context("open MCPB central directory")?;
    if archive.len() > MAX_ARCHIVE_ENTRIES {
        return Err(anyhow!(
            "archive contains too many entries: {} exceeds max {MAX_ARCHIVE_ENTRIES}",
            archive.len()
        ));
    }
    let mut total_extracted = 0_u64;
    let mut seen_paths = BTreeSet::new();

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let enclosed = file
            .enclosed_name()
            .ok_or_else(|| anyhow!("unsafe zip path: {}", file.name()))?
            .to_path_buf();
        validate_mcpb_relative_path(&enclosed)?;
        let entry_name = file.name().to_string();
        if !seen_paths.insert(enclosed.clone()) {
            return Err(anyhow!("duplicate zip path: {}", enclosed.display()));
        }
        let target = dest.join(enclosed);

        if file.is_dir() {
            std::fs::create_dir_all(&target)?;
            continue;
        }

        let expected_size = file.size();
        if expected_size > MAX_EXTRACTED_FILE_BYTES {
            return Err(anyhow!(
                "extracted file too large: {entry_name} is {expected_size} bytes, max {MAX_EXTRACTED_FILE_BYTES}"
            ));
        }
        if total_extracted.saturating_add(expected_size) > MAX_EXTRACTED_BYTES {
            return Err(anyhow!(
                "extracted package too large: extracting {entry_name} would exceed max {MAX_EXTRACTED_BYTES} bytes"
            ));
        }

        let parent = target
            .parent()
            .ok_or_else(|| anyhow!("zip path has no parent: {entry_name}"))?;
        std::fs::create_dir_all(parent)?;
        let mut out =
            File::create(&target).with_context(|| format!("extract {}", target.display()))?;
        let copied = copy_zip_entry_bounded(&mut file, &mut out, &entry_name, &mut total_extracted)
            .with_context(|| format!("write extracted file {}", target.display()))?;
        if copied != expected_size {
            return Err(anyhow!(
                "zip entry size mismatch for {entry_name}: header declared {expected_size} bytes, extracted {copied} bytes"
            ));
        }

        #[cfg(unix)]
        if let Some(mode) = file.unix_mode() {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(mode))?;
        }
    }
    Ok(())
}

pub(crate) fn validate_mcpb_central_directory_open(file: &mut File) -> Result<()> {
    let archive_len = file.metadata()?.len();
    let search_len = archive_len.min(66_000) as usize;
    if search_len < 22 {
        return Ok(());
    }

    file.seek(SeekFrom::End(-(search_len as i64)))?;
    let mut tail = vec![0_u8; search_len];
    file.read_exact(&mut tail)?;

    let Some(eocd) = tail
        .windows(4)
        .rposition(|window| window == [0x50, 0x4b, 0x05, 0x06])
    else {
        return Ok(());
    };
    if eocd + 22 > tail.len() {
        return Ok(());
    }

    let total_entries = u16_le(&tail[eocd + 10..eocd + 12]);
    let central_size = u32_le(&tail[eocd + 12..eocd + 16]);
    let central_offset = u32_le(&tail[eocd + 16..eocd + 20]);
    if total_entries == u16::MAX || central_size == u32::MAX || central_offset == u32::MAX {
        return Err(anyhow!(
            "ZIP64 MCPB archives are not supported by release smoke"
        ));
    }

    let total_entries = total_entries as usize;
    if total_entries > MAX_ARCHIVE_ENTRIES {
        return Err(anyhow!(
            "archive contains too many entries: {total_entries} exceeds max {MAX_ARCHIVE_ENTRIES}"
        ));
    }

    let central_offset = central_offset as u64;
    let central_size = central_size as u64;
    if central_size > MAX_CENTRAL_DIRECTORY_BYTES {
        return Err(anyhow!(
            "ZIP central directory too large: {central_size} bytes exceeds max {MAX_CENTRAL_DIRECTORY_BYTES}"
        ));
    }
    if central_offset.saturating_add(central_size) > archive_len {
        return Err(anyhow!("ZIP central directory points outside the archive"));
    }

    file.seek(SeekFrom::Start(central_offset))?;
    let mut central = vec![0_u8; central_size as usize];
    file.read_exact(&mut central)?;

    let mut names = BTreeSet::new();
    let mut cursor = 0_usize;
    for _ in 0..total_entries {
        if cursor + 46 > central.len() {
            return Err(anyhow!("truncated ZIP central directory"));
        }
        if central[cursor..cursor + 4] != [0x50, 0x4b, 0x01, 0x02] {
            return Err(anyhow!("invalid ZIP central directory entry"));
        }
        let name_len = u16_le(&central[cursor + 28..cursor + 30]) as usize;
        let extra_len = u16_le(&central[cursor + 30..cursor + 32]) as usize;
        let comment_len = u16_le(&central[cursor + 32..cursor + 34]) as usize;
        let name_start = cursor + 46;
        let name_end = name_start + name_len;
        let entry_end = name_end + extra_len + comment_len;
        if entry_end > central.len() {
            return Err(anyhow!("truncated ZIP central directory entry"));
        }

        let name = String::from_utf8_lossy(&central[name_start..name_end]).to_string();
        if !names.insert(name.clone()) {
            return Err(anyhow!("duplicate zip path: {name}"));
        }
        cursor = entry_end;
    }

    Ok(())
}

fn validate_mcpb_relative_path(path: &Path) -> Result<()> {
    reject_release_gitignore(path)?;
    for component in path.components() {
        match component {
            Component::Normal(_) => {}
            Component::CurDir | Component::ParentDir => {
                return Err(anyhow!(
                    "ambiguous zip path is not allowed: {}",
                    path.display()
                ));
            }
            Component::Prefix(_) | Component::RootDir => {
                return Err(anyhow!("unsafe zip path: {}", path.display()));
            }
        }
    }
    Ok(())
}

fn u16_le(bytes: &[u8]) -> u16 {
    u16::from_le_bytes(bytes.try_into().expect("slice length checked by caller"))
}

fn u32_le(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().expect("slice length checked by caller"))
}

fn copy_zip_entry_bounded<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    entry_name: &str,
    total_extracted: &mut u64,
) -> Result<u64> {
    let mut file_extracted = 0_u64;
    let mut buffer = [0_u8; 8192];

    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            return Ok(file_extracted);
        }

        let read = read as u64;
        if file_extracted.saturating_add(read) > MAX_EXTRACTED_FILE_BYTES {
            return Err(anyhow!(
                "extracted file too large: {entry_name} exceeds max {MAX_EXTRACTED_FILE_BYTES} bytes"
            ));
        }
        if total_extracted.saturating_add(read) > MAX_EXTRACTED_BYTES {
            return Err(anyhow!(
                "extracted package too large: {entry_name} would exceed max {MAX_EXTRACTED_BYTES} bytes"
            ));
        }

        writer.write_all(&buffer[..read as usize])?;
        file_extracted += read;
        *total_extracted += read;
    }
}

fn infer_target(manifest: &McpbManifest) -> Result<PackageTarget> {
    match manifest.compatibility.platforms.as_slice() {
        [platform] if platform == "darwin" => Ok(PackageTarget::MacosArm64),
        [platform] if platform == "win32" => Ok(PackageTarget::WindowsX64),
        platforms => Err(anyhow!(
            "unsupported MCPB compatibility.platforms: {:?}",
            platforms
        )),
    }
}

fn validate_static_contents(
    root: &Path,
    manifest: &McpbManifest,
    package_target: PackageTarget,
    distribution_evidence: DistributionEvidenceMode,
    require_lsp: bool,
    package_mode: PackageMode,
) -> Result<()> {
    require_file(root, "manifest.json")?;
    require_file(root, "plugin/.claude-plugin/plugin.json")?;
    require_file(root, "plugin/.mcp.json")?;
    if require_lsp {
        require_file(root, "plugin/.lsp.json")?;
    }
    require_file(root, "plugin/LICENSE")?;
    require_file(root, "plugin/.third-party/third-party-license-policy.json")?;
    require_file(
        root,
        "plugin/.third-party/third-party-license-provenance.json",
    )?;
    require_file(root, "plugin/.third-party/source-lock.spdx.json")?;
    require_file(root, "plugin/.third-party/source-closure-windows.spdx.json")?;
    require_file(root, "plugin/THIRD_PARTY_LICENSES.txt")?;
    require_file(root, "plugin/owner-distribution-approval.schema.json")?;
    require_file(root, "plugin/CHANGELOG.md")?;
    require_file(root, "plugin/skills/autocad-mcp/SKILL.md")?;
    require_file(root, "plugin/skills/autolisp/SKILL.md")?;
    require_file(
        root,
        "plugin/skills/autolisp/references/documentation-provenance.json",
    )?;
    let plugin_dir = root.join("plugin");
    let structure_errors = validate_packaged_structure(&plugin_dir);
    if !structure_errors.is_empty() {
        return Err(anyhow!(
            "packaged plugin structure validation failed: {}",
            structure_errors.join("; ")
        ));
    }
    let plugin_metadata = read_plugin_metadata(&plugin_dir)
        .context("read packaged plugin metadata for license validation")?;
    validate_plugin_license(&plugin_dir, &plugin_metadata)?;
    if distribution_evidence == DistributionEvidenceMode::ExactCompiled {
        validate_source_distribution_evidence(&plugin_dir)?;
    }
    let provenance_errors = validate_documentation_provenance(&plugin_dir);
    if !provenance_errors.is_empty() {
        return Err(anyhow!(
            "packaged plugin documentation provenance validation failed: {}",
            provenance_errors.join("; ")
        ));
    }
    if manifest.license != plugin_metadata.license {
        return Err(anyhow!(
            "MCPB manifest license must match plugin metadata license"
        ));
    }
    validate_manifest_plugin_identity(manifest, &plugin_metadata, package_mode)?;
    if distribution_evidence == DistributionEvidenceMode::ApprovalBound {
        validate_approval_manifest_environment(manifest, package_target, package_mode)?;
    }
    validate_mcp_contents(root, package_target)?;
    require_file(root, &manifest.server.entry_point)
        .with_context(|| format!("missing binary at {}", manifest.server.entry_point))?;

    let skills_dir = root.join("plugin/skills");
    let mut has_skill = false;
    if skills_dir.is_dir() {
        for entry in std::fs::read_dir(&skills_dir)
            .with_context(|| format!("read {}", skills_dir.display()))?
        {
            let entry = entry?;
            if entry.path().join("SKILL.md").is_file() {
                has_skill = true;
                break;
            }
        }
    }
    if !has_skill {
        return Err(anyhow!("missing plugin/skills/*/SKILL.md"));
    }
    validate_xref_release_contents(root, manifest, package_target, package_mode)?;
    validate_lsp_contents(root, package_target)?;
    validate_package_allowlist(root, package_target)?;
    Ok(())
}

fn validate_approval_manifest_environment(
    manifest: &McpbManifest,
    target: PackageTarget,
    package_mode: PackageMode,
) -> Result<()> {
    let mut expected = title_block_profiles_environment();
    if matches!(
        (target, package_mode),
        (PackageTarget::WindowsX64, PackageMode::Release)
    ) {
        expected.insert(
            XREF_CERTIFIED_ARG_PATH_ENV.to_owned(),
            Value::String(format!("${{__dirname}}/{XREF_CERTIFIED_ARG_PACKAGE_PATH}")),
        );
    }
    if manifest.server.mcp_config.env != expected {
        return Err(anyhow!(
            "approval-bound MCPB server environment does not exactly match the target policy"
        ));
    }
    Ok(())
}

fn validate_manifest_plugin_identity(
    manifest: &McpbManifest,
    plugin: &crate::manifest::PluginMetadata,
    package_mode: PackageMode,
) -> Result<()> {
    if manifest.name != package_mode.manifest_name(&plugin.name)
        || manifest.version != plugin.version
        || manifest.description != package_mode.manifest_description(&plugin.description)
        || manifest.author.name != plugin.author_name
    {
        return Err(anyhow!(
            "MCPB manifest identity metadata does not match the packaged plugin and package mode"
        ));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PluginMcpDocument {
    #[serde(rename = "mcpServers")]
    mcp_servers: BTreeMap<String, PluginMcpServer>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PluginMcpServer {
    command: String,
    args: Vec<String>,
}

fn validate_mcp_contents(root: &Path, _target: PackageTarget) -> Result<()> {
    let path = root.join("plugin/.mcp.json");
    let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    let value = distribution_approval::parse_strict_json(&bytes)
        .with_context(|| format!("strictly parse {}", path.display()))?;
    let document: PluginMcpDocument = serde_json::from_value(value)
        .with_context(|| format!("validate closed schema for {}", path.display()))?;
    if document.mcp_servers.len() != 1 {
        return Err(anyhow!(
            "plugin/.mcp.json must contain exactly the autocad-mcp server"
        ));
    }
    let server = document
        .mcp_servers
        .get("autocad-mcp")
        .ok_or_else(|| anyhow!("plugin/.mcp.json missing autocad-mcp server"))?;
    if server.command != "${CLAUDE_PLUGIN_ROOT}/bin/autocad-mcp" {
        return Err(anyhow!(
            "plugin/.mcp.json autocad-mcp command must be ${{CLAUDE_PLUGIN_ROOT}}/bin/autocad-mcp"
        ));
    }
    if server.args != ["serve"] {
        return Err(anyhow!(
            "plugin/.mcp.json autocad-mcp args must launch serve explicitly"
        ));
    }
    Ok(())
}

fn validate_package_allowlist(root: &Path, target: PackageTarget) -> Result<()> {
    let mut files = BTreeSet::new();
    for entry in walkdir::WalkDir::new(root).follow_links(false) {
        let entry = entry.context("walk extracted MCPB for closed file allowlist")?;
        if entry.path() == root {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(root)
            .expect("walked path is rooted below extracted MCPB");
        if entry.file_type().is_symlink() {
            return Err(anyhow!(
                "MCPB allowlist forbids symlink {}",
                relative.display()
            ));
        }
        if entry.file_type().is_file() {
            if !is_package_archive_file_path(relative, target) {
                return Err(anyhow!(
                    "MCPB contains file outside the closed package allowlist: {}",
                    relative.display()
                ));
            }
            files.insert(relative.to_path_buf());
        } else if !entry.file_type().is_dir() {
            return Err(anyhow!(
                "MCPB contains non-regular entry {}",
                relative.display()
            ));
        }
    }
    if files.is_empty() {
        return Err(anyhow!("MCPB closed package allowlist contains no files"));
    }
    Ok(())
}

fn validate_xref_release_contents(
    root: &Path,
    manifest: &McpbManifest,
    package_target: PackageTarget,
    package_mode: PackageMode,
) -> Result<()> {
    let private_directory = root.join("plugin/resources/xref-certification");
    let preview_directory = root.join(PREVIEW_ACTIVATION_DIRECTORY);
    if package_mode == PackageMode::Preview {
        if private_directory.exists() {
            return Err(anyhow!(
                "Preview package must not contain the private XREF certification subtree"
            ));
        }
        return validate_xref_preview_contents(root, manifest, package_target);
    }
    if preview_directory.exists() {
        return Err(anyhow!(
            "Release package must not contain the public Preview activation subtree"
        ));
    }
    #[cfg(test)]
    if package_target == PackageTarget::WindowsX64 {
        let skill_path = root.join("plugin/skills/autocad-mcp/SKILL.md");
        let skill = std::fs::read_to_string(&skill_path)
            .with_context(|| format!("read {}", skill_path.display()))?;
        if !XREF_MUTATION_OPERATIONS
            .iter()
            .any(|operation| skill.contains(operation.as_str()))
        {
            return Ok(());
        }
    }
    if package_target == PackageTarget::WindowsX64 {
        return Err(anyhow!(
            "Windows Release package smoke is unavailable until the package-safe statement, signature verification, and closed package-safe binding are implemented"
        ));
    }
    if package_target != PackageTarget::WindowsX64 {
        if manifest.server.mcp_config.env != title_block_profiles_environment() {
            return Err(anyhow!(
                "non-Windows Release MCPB server environment must contain only the title-block profiles binding"
            ));
        }
        return Ok(());
    }

    let expected_arg = format!("${{__dirname}}/{XREF_CERTIFIED_ARG_PACKAGE_PATH}");
    if manifest
        .server
        .mcp_config
        .env
        .get(XREF_CERTIFIED_ARG_PATH_ENV)
        .and_then(Value::as_str)
        != Some(expected_arg.as_str())
    {
        return Err(anyhow!(
            "Windows XREF package must bind {XREF_CERTIFIED_ARG_PATH_ENV} to {expected_arg}"
        ));
    }

    let directory = root.join("plugin/resources/xref-certification");
    let certified_arg = directory.join("certified-profile.arg");
    let certification_manifest = directory.join("manifest.json");
    let release_evidence = directory.join("release-evidence.json");
    let transaction_evidence = directory.join("transaction-evidence.json");
    let attestation = directory.join("attestation.json");
    let binding = directory.join("package-binding.json");
    for (path, label) in [
        (&certified_arg, "certified-profile.arg"),
        (&certification_manifest, "manifest.json"),
        (&release_evidence, "release-evidence.json"),
        (&transaction_evidence, "transaction-evidence.json"),
        (&attestation, "attestation.json"),
        (&binding, "package-binding.json"),
    ] {
        if !path.is_file() {
            return Err(anyhow!("missing XREF certification artifact {label}"));
        }
    }
    if std::fs::metadata(&certified_arg)?.len() == 0 {
        return Err(anyhow!("packaged certified AutoCAD ARG profile is empty"));
    }

    let certification_manifest_value =
        XrefCertificationManifest::from_json(&std::fs::read_to_string(&certification_manifest)?)?;
    let release_evidence_value =
        XrefCertificationEvidence::from_json(&std::fs::read_to_string(&release_evidence)?)?;
    let transaction_evidence_value =
        XrefCertificationEvidence::from_json(&std::fs::read_to_string(&transaction_evidence)?)?;
    let attestation_value =
        XrefCertificationAttestation::from_json(&std::fs::read_to_string(&attestation)?)?;
    validate_xref_certification_bundle(
        &certification_manifest_value,
        &release_evidence_value,
        &transaction_evidence_value,
        &attestation_value,
    )
    .context("validate packaged strict XREF certification bundle")?;

    let binding_bytes = std::fs::read(&binding)?;
    let binding_json = distribution_approval::parse_strict_json(&binding_bytes)
        .context("strictly parse XREF package binding JSON")?;
    let binding_value: XrefPackageBinding = serde_json::from_value(binding_json)
        .context("parse XREF package binding as the closed schema")?;
    let release_binary = root.join(&manifest.server.entry_point);
    validate_xref_package_binding(
        &binding_value,
        &XrefPackageBindingPaths {
            certified_arg: &certified_arg,
            certification_manifest: &certification_manifest,
            release_evidence: &release_evidence,
            transaction_evidence: &transaction_evidence,
            attestation: &attestation,
            release_binary: &release_binary,
        },
        &attestation_value.release_binary_sha256,
        &release_evidence_value.binary_sha256,
    )?;
    Ok(())
}

fn validate_xref_preview_contents(
    root: &Path,
    manifest: &McpbManifest,
    package_target: PackageTarget,
) -> Result<()> {
    if package_target != PackageTarget::WindowsX64 {
        return Err(anyhow!("Preview packages require windows-x64"));
    }
    if manifest.server.mcp_config.env != title_block_profiles_environment() {
        return Err(anyhow!(
            "Preview package server environment must contain only the title-block profiles binding; activation remains package-owned"
        ));
    }

    let directory = root.join(PREVIEW_ACTIVATION_DIRECTORY);
    if !directory.is_dir() {
        return Err(anyhow!(
            "missing public Preview activation resource directory"
        ));
    }

    let expected_files = embedded_preview_activation_files()?;
    let mut actual_paths = BTreeSet::new();
    let mut actual_directories = BTreeSet::new();
    for entry in walkdir::WalkDir::new(&directory).follow_links(false) {
        let entry = entry.context("walk public Preview activation resource directory")?;
        if entry.path() == directory {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(&directory)
            .expect("walked Preview activation path is below its root");
        if entry.file_type().is_symlink() {
            return Err(anyhow!(
                "public Preview activation bundle forbids symlink {}",
                relative.display()
            ));
        }
        if entry.file_type().is_file() {
            let relative = relative
                .to_str()
                .ok_or_else(|| anyhow!("Preview activation path is not UTF-8"))?
                .replace('\\', "/");
            actual_paths.insert(relative);
        } else if entry.file_type().is_dir() {
            let relative = relative
                .to_str()
                .ok_or_else(|| anyhow!("Preview activation directory path is not UTF-8"))?
                .replace('\\', "/");
            actual_directories.insert(relative);
        } else if !entry.file_type().is_dir() {
            return Err(anyhow!(
                "public Preview activation bundle contains non-regular entry {}",
                relative.display()
            ));
        }
    }
    let mut expected_paths = expected_files.keys().cloned().collect::<BTreeSet<_>>();
    expected_paths.insert("package-binding.json".to_owned());
    let mut expected_directories = BTreeSet::new();
    for path in &expected_paths {
        let mut parent = Path::new(path).parent();
        while let Some(directory) = parent.filter(|directory| !directory.as_os_str().is_empty()) {
            expected_directories.insert(
                directory
                    .to_str()
                    .expect("embedded activation paths are validated as UTF-8")
                    .replace('\\', "/"),
            );
            parent = directory.parent();
        }
    }
    if actual_paths != expected_paths || actual_directories != expected_directories {
        return Err(anyhow!(
            "public Preview activation directory does not match the exact closed inventory; expected_files={expected_paths:?}, actual_files={actual_paths:?}, expected_directories={expected_directories:?}, actual_directories={actual_directories:?}"
        ));
    }

    let mut expected_inventory = Vec::with_capacity(expected_files.len());
    for (relative_path, expected_bytes) in &expected_files {
        let archived_path = directory.join(relative_path);
        let archived_bytes = std::fs::read(&archived_path).with_context(|| {
            format!("read Preview activation asset {}", archived_path.display())
        })?;
        if archived_bytes.as_slice() != expected_bytes.as_slice() {
            return Err(anyhow!(
                "public Preview activation asset differs from the embedded binary bundle: {relative_path}"
            ));
        }
        expected_inventory.push(PreviewActivationFileBinding {
            path: relative_path.clone(),
            sha256: xref_sha256_bytes(&archived_bytes),
        });
    }

    let binding_path = root.join(PREVIEW_ACTIVATION_BINDING_PACKAGE_PATH);
    let binding_bytes = std::fs::read(&binding_path)?;
    let binding_json = distribution_approval::parse_strict_json(&binding_bytes)
        .context("strictly parse public Preview activation package binding JSON")?;
    let binding: PreviewActivationPackageBinding = serde_json::from_value(binding_json)
        .context("parse public Preview activation package binding as the closed schema")?;
    if binding.schema_version != PREVIEW_ACTIVATION_BINDING_SCHEMA_VERSION {
        return Err(anyhow!(
            "Preview activation package binding schema_version {} is unsupported",
            binding.schema_version
        ));
    }
    let catalogue_sha256 = xref_sha256_file(&root.join(PREVIEW_ACTIVATION_CATALOGUE_PACKAGE_PATH))?;
    if binding.preview_binary_sha256 != xref_sha256_file(&root.join(&manifest.server.entry_point))?
        || binding.catalogue_sha256 != catalogue_sha256
        || binding.files != expected_inventory
    {
        return Err(anyhow!(
            "public Preview activation package binding does not match the archived binary, catalogue, and sorted file inventory"
        ));
    }
    Ok(())
}

struct XrefPackageBindingPaths<'a> {
    certified_arg: &'a Path,
    certification_manifest: &'a Path,
    release_evidence: &'a Path,
    transaction_evidence: &'a Path,
    attestation: &'a Path,
    release_binary: &'a Path,
}

fn validate_xref_package_binding(
    binding: &XrefPackageBinding,
    paths: &XrefPackageBindingPaths<'_>,
    attested_release_binary_sha256: &str,
    evidenced_release_binary_sha256: &str,
) -> Result<()> {
    if binding.schema_version != XREF_PACKAGE_BINDING_SCHEMA_VERSION {
        return Err(anyhow!(
            "XREF package binding schema_version {} is unsupported",
            binding.schema_version
        ));
    }
    for (field, expected, path) in [
        (
            "certified_arg_sha256",
            binding.certified_arg_sha256.as_str(),
            paths.certified_arg,
        ),
        (
            "manifest_sha256",
            binding.manifest_sha256.as_str(),
            paths.certification_manifest,
        ),
        (
            "release_evidence_sha256",
            binding.release_evidence_sha256.as_str(),
            paths.release_evidence,
        ),
        (
            "transaction_evidence_sha256",
            binding.transaction_evidence_sha256.as_str(),
            paths.transaction_evidence,
        ),
        (
            "attestation_sha256",
            binding.attestation_sha256.as_str(),
            paths.attestation,
        ),
        (
            "release_binary_sha256",
            binding.release_binary_sha256.as_str(),
            paths.release_binary,
        ),
    ] {
        if xref_sha256_file(path)? != expected {
            return Err(anyhow!("XREF package binding digest mismatch for {field}"));
        }
    }
    if binding.release_binary_sha256 != attested_release_binary_sha256
        || binding.release_binary_sha256 != evidenced_release_binary_sha256
    {
        return Err(anyhow!(
            "packaged binary digest does not match XREF certification release evidence and attestation"
        ));
    }
    Ok(())
}

fn require_file(root: &Path, rel: &str) -> Result<()> {
    let path = root.join(rel);
    if path.is_file() {
        Ok(())
    } else {
        Err(anyhow!("missing package file: {rel}"))
    }
}

fn mode_command(binary: &Path, subcommand: &str, package_mode: PackageMode) -> Command {
    let mut command = Command::new(binary);
    command.arg(subcommand);
    if package_mode == PackageMode::Preview {
        command.arg("--experimental");
    }
    command
}

fn validate_preview_plain_tool_surface(value: &Value) -> Result<()> {
    let tools = value
        .as_array()
        .ok_or_else(|| anyhow!("Preview plain list-tools stdout must be a JSON array"))?;
    if tools.len() != PREVIEW_READ_ONLY_TOOL_COUNT {
        return Err(anyhow!(
            "Preview plain list-tools must expose exactly {PREVIEW_READ_ONLY_TOOL_COUNT} read-only tools; got {}",
            tools.len()
        ));
    }
    for tool in tools {
        let name = tool
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
            .ok_or_else(|| {
                anyhow!("Preview plain list-tools entries must contain nonempty string names")
            })?;
        if XREF_MUTATION_OPERATIONS
            .iter()
            .any(|operation| operation.as_str() == name)
        {
            return Err(anyhow!(
                "Preview plain list-tools must not expose XREF mutation tool {name}"
            ));
        }
        if tool
            .pointer("/annotations/readOnlyHint")
            .and_then(Value::as_bool)
            != Some(true)
        {
            return Err(anyhow!(
                "Preview plain list-tools entry {name} must declare annotations.readOnlyHint=true"
            ));
        }
    }
    Ok(())
}

fn run_executable_smoke(
    binary: &Path,
    fixture_path: &Path,
    package_mode: PackageMode,
) -> Result<()> {
    #[cfg(unix)]
    ensure_unix_executable(binary)?;

    match package_mode {
        PackageMode::Release => {
            let mut experimental_command = Command::new(binary);
            experimental_command.args(["list-tools", "--experimental"]);
            let output = run_with_timeout(
                &mut experimental_command,
                "list-tools --experimental rejection",
                SUBPROCESS_TIMEOUT,
            )
            .with_context(|| {
                format!(
                    "run {} list-tools --experimental rejection probe",
                    binary.display()
                )
            })?;
            if output.status.success() {
                return Err(anyhow!(
                    "Release binary must reject list-tools --experimental"
                ));
            }
        }
        PackageMode::Preview => {
            let mut plain_command = Command::new(binary);
            plain_command.arg("list-tools");
            let output = run_with_timeout(
                &mut plain_command,
                "Preview plain list-tools",
                SUBPROCESS_TIMEOUT,
            )
            .with_context(|| format!("run {} plain list-tools", binary.display()))?;
            if !output.status.success() {
                return Err(anyhow!(
                    "Preview plain list-tools failed with status {}: {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
            let tools: Value = serde_json::from_slice(&output.stdout).with_context(|| {
                format!(
                    "parse Preview plain list-tools stdout as JSON: {}",
                    String::from_utf8_lossy(&output.stdout)
                )
            })?;
            validate_preview_plain_tool_surface(&tools)?;
        }
    }

    let mut list_command = mode_command(binary, "list-tools", package_mode);
    let list_output = run_with_timeout(&mut list_command, "list-tools", SUBPROCESS_TIMEOUT)
        .with_context(|| format!("run {} list-tools", binary.display()))?;
    if !list_output.status.success() {
        return Err(anyhow!(
            "list-tools failed with status {}: {}",
            list_output.status,
            String::from_utf8_lossy(&list_output.stderr)
        ));
    }
    let tools: Value = serde_json::from_slice(&list_output.stdout).with_context(|| {
        format!(
            "parse list-tools stdout as JSON: {}",
            String::from_utf8_lossy(&list_output.stdout)
        )
    })?;
    validate_tool_surface(&tools)?;

    let params = serde_json::json!({ "drawing_path": fixture_path }).to_string();
    let params_directory = tempfile::Builder::new()
        .prefix("autocad mcp params \u{03bb} ")
        .tempdir()
        .context("create temporary CLI params directory")?;
    let params_path = params_directory.path().join("list layouts params.json");
    std::fs::write(&params_path, params.as_bytes()).with_context(|| {
        format!(
            "write strict UTF-8 CLI params file {}",
            params_path.display()
        )
    })?;
    let mut call_command = mode_command(binary, "call", package_mode);
    call_command
        .args(["list_layouts", "--params-file"])
        .arg(&params_path);
    let call_output = run_with_timeout(
        &mut call_command,
        "call list_layouts --params-file",
        SUBPROCESS_TIMEOUT,
    )
    .with_context(|| {
        format!(
            "run {} call list_layouts --params-file {}",
            binary.display(),
            params_path.display()
        )
    })?;
    if !call_output.status.success() {
        return Err(anyhow!(
            "call list_layouts --params-file failed with status {}: {}",
            call_output.status,
            String::from_utf8_lossy(&call_output.stderr)
        ));
    }
    let layouts: Value = serde_json::from_slice(&call_output.stdout).with_context(|| {
        format!(
            "parse list_layouts stdout as JSON: {}",
            String::from_utf8_lossy(&call_output.stdout)
        )
    })?;
    validate_portable_layout_smoke_records(&layouts)?;

    let mut layer_command = mode_command(binary, "call", package_mode);
    layer_command.args(["list_layers", &params]);
    let layer_output = run_with_timeout(&mut layer_command, "call list_layers", SUBPROCESS_TIMEOUT)
        .with_context(|| format!("run {} call list_layers", binary.display()))?;
    if !layer_output.status.success() {
        return Err(anyhow!(
            "call list_layers failed with status {}: {}",
            layer_output.status,
            String::from_utf8_lossy(&layer_output.stderr)
        ));
    }
    let layers: Value = serde_json::from_slice(&layer_output.stdout).with_context(|| {
        format!(
            "parse list_layers stdout as JSON: {}",
            String::from_utf8_lossy(&layer_output.stdout)
        )
    })?;
    validate_portable_layer_smoke_records(&layers)?;

    let mut xref_command = mode_command(binary, "call", package_mode);
    xref_command.args(["list_xrefs", &params]);
    let xref_output = run_with_timeout(&mut xref_command, "call list_xrefs", SUBPROCESS_TIMEOUT)
        .with_context(|| format!("run {} call list_xrefs", binary.display()))?;
    if !xref_output.status.success() {
        return Err(anyhow!(
            "call list_xrefs failed with status {}: {}",
            xref_output.status,
            String::from_utf8_lossy(&xref_output.stderr)
        ));
    }
    let xrefs: Value = serde_json::from_slice(&xref_output.stdout).with_context(|| {
        format!(
            "parse list_xrefs stdout as JSON: {}",
            String::from_utf8_lossy(&xref_output.stdout)
        )
    })?;
    validate_xref_records(&xrefs)?;

    let xref_instances = invoke_cli_tool_json(
        binary,
        package_mode,
        "list_xref_instances",
        serde_json::json!({ "drawing_path": fixture_path }),
    )?;
    validate_xref_instance_smoke_records(&xref_instances)?;
    if fixture_path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("dxf"))
    {
        run_portable_layer_write_smoke(
            binary,
            package_mode,
            fixture_path,
            &layouts,
            &layers,
            &xrefs,
            &xref_instances,
        )?;
    }
    run_mcp_stdio_smoke(binary, fixture_path, package_mode)?;
    Ok(())
}

fn run_portable_layer_write_smoke(
    binary: &Path,
    package_mode: PackageMode,
    fixture_path: &Path,
    layouts_before: &Value,
    layers_before: &Value,
    xrefs_before: &Value,
    xref_instances_before: &Value,
) -> Result<()> {
    let temp = tempfile::tempdir().context("create portable layer write smoke directory")?;
    let drawing = temp.path().join("portable-layer-write-smoke.dxf");
    std::fs::copy(fixture_path, &drawing).with_context(|| {
        format!(
            "copy {} for portable layer write smoke",
            fixture_path.display()
        )
    })?;
    let drawing = std::fs::canonicalize(&drawing)
        .context("canonicalize portable layer write smoke drawing")?;
    if drawing == fixture_path {
        return Err(anyhow!(
            "portable layer write smoke copy must not identify the source fixture"
        ));
    }
    let source_bytes_before = std::fs::read(fixture_path)
        .context("read source fixture before portable layer write smoke")?;
    let drawing_bytes_before =
        std::fs::read(&drawing).context("read copied drawing before portable layer write smoke")?;
    let mut drawing_sha256 = xref_sha256_file(&drawing)
        .context("hash copied drawing before portable layer write smoke")?;
    if drawing_bytes_before != source_bytes_before {
        return Err(anyhow!(
            "portable layer write smoke copy does not match the source fixture"
        ));
    }

    let existing_names = layers_before
        .as_array()
        .ok_or_else(|| anyhow!("list_layers stdout must be a JSON array"))?
        .iter()
        .filter_map(|layer| layer.get("name").and_then(Value::as_str))
        .map(str::to_ascii_lowercase)
        .collect::<BTreeSet<_>>();
    let (layer_name, renamed_name) = (0_u16..=u16::MAX)
        .map(|suffix| {
            let name = if suffix == 0 {
                "AUTOCAD_MCP_PORTABLE_SMOKE".to_owned()
            } else {
                format!("AUTOCAD_MCP_PORTABLE_SMOKE_{suffix}")
            };
            let renamed = format!("{name}_RENAMED");
            (name, renamed)
        })
        .find(|(name, renamed)| {
            !existing_names.contains(&name.to_ascii_lowercase())
                && !existing_names.contains(&renamed.to_ascii_lowercase())
        })
        .ok_or_else(|| anyhow!("could not select an unused portable layer smoke name pair"))?;

    let created = invoke_cli_tool_json(
        binary,
        package_mode,
        "create_layer",
        serde_json::json!({
            "drawing_path": drawing,
            "name": layer_name,
            "properties": {
                "color_index": 3,
                "locked": true,
                "is_plottable": false,
                "line_weight": {
                    "kind": "value",
                    "hundredths_mm": 35
                }
            }
        }),
    )?;
    let created_layer = require_portable_layer_result(&created, "create_layer", "ok", &drawing)?;
    let handle = created_layer
        .get("handle")
        .and_then(Value::as_str)
        .filter(|handle| !handle.is_empty())
        .ok_or_else(|| anyhow!("create_layer smoke result must contain a nonempty handle"))?
        .to_owned();
    if created_layer.get("name").and_then(Value::as_str) != Some(layer_name.as_str())
        || created_layer.get("color_index").and_then(Value::as_u64) != Some(3)
        || created_layer.get("line_type").and_then(Value::as_str) != Some("Continuous")
        || created_layer.get("frozen").and_then(Value::as_bool) != Some(false)
        || created_layer.get("locked").and_then(Value::as_bool) != Some(true)
        || created_layer.get("off").and_then(Value::as_bool) != Some(false)
        || created_layer.get("is_plottable").and_then(Value::as_bool) != Some(false)
        || created_layer
            .pointer("/line_weight/kind")
            .and_then(Value::as_str)
            != Some("value")
        || created_layer
            .pointer("/line_weight/hundredths_mm")
            .and_then(Value::as_u64)
            != Some(35)
    {
        return Err(anyhow!(
            "create_layer smoke result does not contain the requested properties"
        ));
    }
    require_portable_layer_persisted(
        binary,
        package_mode,
        &drawing,
        &handle,
        created_layer,
        "create_layer",
    )?;
    require_portable_drawing_changed(&drawing, &mut drawing_sha256, "create_layer")?;

    let updated = invoke_cli_tool_json(
        binary,
        package_mode,
        "update_layer",
        serde_json::json!({
            "drawing_path": drawing,
            "handle": handle,
            "name": null,
            "expected_handle": handle,
            "expected_name": layer_name,
            "properties": {
                "color_index": 5,
                "locked": false,
                "off": true
            }
        }),
    )?;
    let updated_layer = require_portable_layer_result(&updated, "update_layer", "ok", &drawing)?;
    if updated_layer.get("handle").and_then(Value::as_str) != Some(handle.as_str())
        || updated_layer.get("name").and_then(Value::as_str) != Some(layer_name.as_str())
        || updated_layer.get("color_index").and_then(Value::as_u64) != Some(5)
        || updated_layer.get("line_type").and_then(Value::as_str) != Some("Continuous")
        || updated_layer.get("frozen").and_then(Value::as_bool) != Some(false)
        || updated_layer.get("locked").and_then(Value::as_bool) != Some(false)
        || updated_layer.get("off").and_then(Value::as_bool) != Some(true)
        || updated_layer.get("is_plottable").and_then(Value::as_bool) != Some(false)
        || updated_layer
            .pointer("/line_weight/kind")
            .and_then(Value::as_str)
            != Some("value")
        || updated_layer
            .pointer("/line_weight/hundredths_mm")
            .and_then(Value::as_u64)
            != Some(35)
    {
        return Err(anyhow!(
            "update_layer smoke result does not preserve and apply the requested properties"
        ));
    }
    require_portable_layer_persisted(
        binary,
        package_mode,
        &drawing,
        &handle,
        updated_layer,
        "update_layer",
    )?;
    require_portable_drawing_changed(&drawing, &mut drawing_sha256, "update_layer")?;

    let renamed = invoke_cli_tool_json(
        binary,
        package_mode,
        "rename_layer",
        serde_json::json!({
            "drawing_path": drawing,
            "handle": handle,
            "name": null,
            "expected_handle": handle,
            "expected_name": layer_name,
            "new_name": renamed_name
        }),
    )?;
    let renamed_layer = require_portable_layer_result(&renamed, "rename_layer", "ok", &drawing)?;
    if renamed_layer.get("handle").and_then(Value::as_str) != Some(handle.as_str())
        || renamed_layer.get("name").and_then(Value::as_str) != Some(renamed_name.as_str())
        || renamed_layer.get("color_index").and_then(Value::as_u64) != Some(5)
        || renamed_layer.get("line_type").and_then(Value::as_str) != Some("Continuous")
        || renamed_layer.get("frozen").and_then(Value::as_bool) != Some(false)
        || renamed_layer.get("locked").and_then(Value::as_bool) != Some(false)
        || renamed_layer.get("off").and_then(Value::as_bool) != Some(true)
        || renamed_layer.get("is_plottable").and_then(Value::as_bool) != Some(false)
        || renamed_layer
            .pointer("/line_weight/kind")
            .and_then(Value::as_str)
            != Some("value")
        || renamed_layer
            .pointer("/line_weight/hundredths_mm")
            .and_then(Value::as_u64)
            != Some(35)
    {
        return Err(anyhow!(
            "rename_layer smoke result does not preserve the updated layer properties"
        ));
    }
    require_portable_layer_persisted(
        binary,
        package_mode,
        &drawing,
        &handle,
        renamed_layer,
        "rename_layer",
    )?;
    require_portable_drawing_changed(&drawing, &mut drawing_sha256, "rename_layer")?;

    let deleted = invoke_cli_tool_json(
        binary,
        package_mode,
        "delete_layer",
        serde_json::json!({
            "drawing_path": drawing,
            "handle": handle,
            "name": null,
            "expected_handle": handle,
            "expected_name": renamed_name
        }),
    )?;
    let deleted_layer =
        require_portable_layer_result(&deleted, "delete_layer", "deleted", &drawing)?;
    if deleted_layer.get("handle").and_then(Value::as_str) != Some(handle.as_str())
        || deleted_layer.get("name").and_then(Value::as_str) != Some(renamed_name.as_str())
    {
        return Err(anyhow!(
            "delete_layer smoke result does not identify the renamed layer"
        ));
    }
    require_portable_drawing_changed(&drawing, &mut drawing_sha256, "delete_layer")?;

    for (tool, expected) in [
        ("list_layouts", layouts_before),
        ("list_layers", layers_before),
        ("list_xrefs", xrefs_before),
        ("list_xref_instances", xref_instances_before),
    ] {
        let actual = invoke_cli_tool_json(
            binary,
            package_mode,
            tool,
            serde_json::json!({ "drawing_path": drawing }),
        )?;
        if &actual != expected {
            return Err(anyhow!(
                "{tool} changed after the portable create/update/rename/delete layer cycle"
            ));
        }
    }
    let source_bytes_after = std::fs::read(fixture_path)
        .context("read source fixture after portable layer write smoke")?;
    if source_bytes_after != source_bytes_before {
        return Err(anyhow!(
            "portable layer write smoke modified the source fixture"
        ));
    }
    let drawing_bytes_after =
        std::fs::read(&drawing).context("read copied drawing after portable layer write smoke")?;
    require_ascii_dxf_restored_except_handseed(
        &source_bytes_before,
        &drawing_bytes_after,
        &handle,
    )?;
    Ok(())
}

fn invoke_cli_tool_json(
    binary: &Path,
    package_mode: PackageMode,
    tool: &str,
    params: Value,
) -> Result<Value> {
    let params = serde_json::to_string(&params)
        .with_context(|| format!("serialize {tool} portable smoke params"))?;
    let label = format!("call {tool}");
    let mut command = mode_command(binary, "call", package_mode);
    command.args([tool, &params]);
    let output = run_with_timeout(&mut command, &label, SUBPROCESS_TIMEOUT)
        .with_context(|| format!("run {} {label}", binary.display()))?;
    if !output.status.success() {
        return Err(anyhow!(
            "{label} failed with status {}: stdout={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    serde_json::from_slice(&output.stdout).with_context(|| {
        format!(
            "parse {label} stdout as JSON: {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn require_portable_layer_result<'a>(
    result: &'a Value,
    tool: &str,
    expected_status: &str,
    expected_drawing: &Path,
) -> Result<&'a Value> {
    if result.get("status").and_then(Value::as_str) != Some(expected_status) {
        return Err(anyhow!(
            "{tool} smoke result must contain status={expected_status}"
        ));
    }
    if result.get("drawing").and_then(Value::as_str)
        != Some(expected_drawing.to_string_lossy().as_ref())
    {
        return Err(anyhow!(
            "{tool} smoke result does not identify the copied drawing"
        ));
    }
    result
        .get("layer")
        .filter(|layer| layer.is_object())
        .ok_or_else(|| anyhow!("{tool} smoke result must contain a layer object"))
}

fn require_portable_layer_persisted(
    binary: &Path,
    package_mode: PackageMode,
    drawing: &Path,
    handle: &str,
    expected: &Value,
    mutation: &str,
) -> Result<()> {
    let actual = invoke_cli_tool_json(
        binary,
        package_mode,
        "get_layer",
        serde_json::json!({
            "drawing_path": drawing,
            "handle": handle,
            "name": null
        }),
    )?;
    if &actual != expected {
        return Err(anyhow!(
            "{mutation} response does not match the independently re-read layer"
        ));
    }
    Ok(())
}

fn require_portable_drawing_changed(
    drawing: &Path,
    previous_sha256: &mut String,
    mutation: &str,
) -> Result<()> {
    let actual = xref_sha256_file(drawing)
        .with_context(|| format!("hash copied drawing after {mutation}"))?;
    if actual == *previous_sha256 {
        return Err(anyhow!(
            "{mutation} did not change the copied drawing bytes"
        ));
    }
    *previous_sha256 = actual;
    Ok(())
}

#[derive(Debug)]
struct RawAsciiDxfPair<'a> {
    code: u16,
    value: &'a [u8],
    value_start: usize,
    value_end: usize,
}

#[derive(Debug)]
struct DxfHandseed {
    value: u64,
    value_start: usize,
    value_end: usize,
}

fn parse_raw_ascii_dxf_pairs<'a>(bytes: &'a [u8], label: &str) -> Result<Vec<RawAsciiDxfPair<'a>>> {
    if bytes.is_empty() {
        return Err(anyhow!("{label} is empty"));
    }

    let mut lines = Vec::new();
    let mut line_start = 0;
    while line_start < bytes.len() {
        let newline = bytes[line_start..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|offset| line_start + offset);
        let raw_end = newline.unwrap_or(bytes.len());
        let mut content_end = raw_end;
        if content_end > line_start && bytes[content_end - 1] == b'\r' {
            if newline.is_none() {
                return Err(anyhow!("{label} ends with a bare carriage return"));
            }
            content_end -= 1;
        }
        if bytes[line_start..content_end].contains(&b'\r') {
            return Err(anyhow!("{label} contains a bare carriage return"));
        }
        lines.push((line_start, content_end));
        let Some(newline) = newline else {
            break;
        };
        line_start = newline + 1;
    }

    if lines.len() % 2 != 0 {
        return Err(anyhow!(
            "{label} must contain complete ASCII DXF group-code/value line pairs"
        ));
    }

    let mut pairs = Vec::with_capacity(lines.len() / 2);
    for (pair_index, lines) in lines.chunks_exact(2).enumerate() {
        let (code_start, code_end) = lines[0];
        let (value_start, value_end) = lines[1];
        let code_line = std::str::from_utf8(&bytes[code_start..code_end]).map_err(|_| {
            anyhow!("{label} pair {pair_index} group-code line must contain ASCII text")
        })?;
        let code = code_line.trim_matches([' ', '\t']);
        if code.is_empty() || !code.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(anyhow!(
                "{label} pair {pair_index} has invalid group code `{code_line}`"
            ));
        }
        let code = code.parse::<u16>().map_err(|_| {
            anyhow!("{label} pair {pair_index} group code `{code_line}` is out of range")
        })?;
        if code > 1071 {
            return Err(anyhow!(
                "{label} pair {pair_index} group code {code} exceeds the ASCII DXF range"
            ));
        }
        pairs.push(RawAsciiDxfPair {
            code,
            value: &bytes[value_start..value_end],
            value_start,
            value_end,
        });
    }
    Ok(pairs)
}

fn parse_canonical_upper_hex(value: &[u8], label: &str) -> Result<u64> {
    let text = std::str::from_utf8(value)
        .map_err(|_| anyhow!("{label} must contain ASCII hexadecimal"))?;
    if text.is_empty()
        || (text.len() > 1 && text.starts_with('0'))
        || !text
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'A'..=b'F'))
    {
        return Err(anyhow!(
            "{label} must be canonical uppercase hexadecimal without a prefix, whitespace, or leading zeroes"
        ));
    }
    let value = u64::from_str_radix(text, 16)
        .map_err(|_| anyhow!("{label} canonical hexadecimal value is outside the u64 range"))?;
    if value == 0 {
        return Err(anyhow!("{label} must be nonzero"));
    }
    Ok(value)
}

fn locate_ascii_dxf_handseed(bytes: &[u8], label: &str) -> Result<DxfHandseed> {
    let pairs = parse_raw_ascii_dxf_pairs(bytes, label)?;
    let mut open_section = None;
    let mut header_range = None;
    let mut index = 0;
    while index < pairs.len() {
        let pair = &pairs[index];
        if pair.code == 0 && pair.value == b"SECTION" {
            if open_section.is_some() {
                return Err(anyhow!("{label} contains nested SECTION records"));
            }
            let section_name = pairs.get(index + 1).ok_or_else(|| {
                anyhow!("{label} SECTION record is missing its group-2 section name")
            })?;
            if section_name.code != 2 {
                return Err(anyhow!(
                    "{label} SECTION record must be followed by a group-2 section name"
                ));
            }
            open_section = Some((section_name.value == b"HEADER", index + 2));
            index += 2;
            continue;
        }
        if pair.code == 0 && pair.value == b"ENDSEC" {
            let (is_header, section_start) = open_section
                .take()
                .ok_or_else(|| anyhow!("{label} contains ENDSEC outside a SECTION"))?;
            if is_header && header_range.replace((section_start, index)).is_some() {
                return Err(anyhow!("{label} contains more than one HEADER section"));
            }
        }
        index += 1;
    }
    if open_section.is_some() {
        return Err(anyhow!("{label} contains an unterminated SECTION"));
    }
    let (header_start, header_end) =
        header_range.ok_or_else(|| anyhow!("{label} must contain exactly one HEADER section"))?;

    let declarations = pairs
        .iter()
        .enumerate()
        .filter(|(_, pair)| pair.code == 9 && pair.value == b"$HANDSEED")
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    let declaration = match declarations.as_slice() {
        [declaration] => *declaration,
        [] => {
            return Err(anyhow!(
                "{label} must contain exactly one HEADER $HANDSEED variable"
            ))
        }
        _ => return Err(anyhow!("{label} must not repeat the $HANDSEED variable")),
    };
    if declaration < header_start || declaration >= header_end {
        return Err(anyhow!("{label} $HANDSEED variable must be in HEADER"));
    }

    let variable_end = (declaration + 1..header_end)
        .find(|candidate| pairs[*candidate].code == 9)
        .unwrap_or(header_end);
    let values = (declaration + 1..variable_end)
        .filter(|candidate| pairs[*candidate].code == 5)
        .collect::<Vec<_>>();
    let value_index = match values.as_slice() {
        [value] => *value,
        [] => {
            return Err(anyhow!(
                "{label} HEADER $HANDSEED must contain exactly one group-5 value"
            ))
        }
        _ => {
            return Err(anyhow!(
                "{label} HEADER $HANDSEED must not repeat its group-5 value"
            ))
        }
    };
    let value_pair = &pairs[value_index];
    let value = parse_canonical_upper_hex(value_pair.value, &format!("{label} HEADER $HANDSEED"))?;
    Ok(DxfHandseed {
        value,
        value_start: value_pair.value_start,
        value_end: value_pair.value_end,
    })
}

fn require_ascii_dxf_restored_except_handseed(
    before: &[u8],
    after: &[u8],
    created_handle: &str,
) -> Result<()> {
    let before_handseed = locate_ascii_dxf_handseed(before, "source ASCII DXF")?;
    let after_handseed = locate_ascii_dxf_handseed(after, "restored ASCII DXF")?;
    let created_handle =
        parse_canonical_upper_hex(created_handle.as_bytes(), "created layer handle")?;

    if after_handseed.value < before_handseed.value {
        return Err(anyhow!(
            "restored ASCII DXF $HANDSEED {:X} regressed below source value {:X}",
            after_handseed.value,
            before_handseed.value
        ));
    }
    if after_handseed.value <= created_handle {
        return Err(anyhow!(
            "restored ASCII DXF $HANDSEED {:X} must remain above created layer handle {created_handle:X}",
            after_handseed.value
        ));
    }

    if before[..before_handseed.value_start] != after[..after_handseed.value_start]
        || before[before_handseed.value_end..] != after[after_handseed.value_end..]
    {
        return Err(anyhow!(
            "portable layer write smoke did not restore the copied ASCII DXF byte-for-byte outside the single HEADER $HANDSEED group-5 value"
        ));
    }
    Ok(())
}

fn run_mcp_stdio_smoke(
    binary: &Path,
    fixture_path: &Path,
    package_mode: PackageMode,
) -> Result<()> {
    let label = "Claude Desktop MCP stdio";
    let mut command = mode_command(binary, "serve", package_mode);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }

    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawn {label} server {}", binary.display()))?;
    let mut process_tree = match ProcessTree::new(&child) {
        Ok(process_tree) => process_tree,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error).with_context(|| format!("contain process tree for {label}"));
        }
    };
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("failed to capture stdin for {label}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("failed to capture stdout for {label}"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("failed to capture stderr for {label}"))?;
    let response_rx = spawn_mcp_line_reader(stdout, label);
    let mut stderr = StreamCapture::Pending(spawn_stream_reader(stderr, label, "stderr"));

    let session_result = exercise_mcp_stdio_session(
        &mut child,
        &mut stdin,
        &response_rx,
        &mut stderr,
        fixture_path,
    );
    drop(stdin);

    if let Err(error) = session_result {
        terminate_child(&mut child, &mut process_tree);
        let _ = child.wait();
        let _ = poll_stream_capture(&mut stderr);
        return Err(error).with_context(|| {
            format!(
                "{label} session failed; stderr: {}",
                String::from_utf8_lossy(&current_stream_bytes(&stderr))
            )
        });
    }

    wait_for_mcp_shutdown(&mut child, &mut process_tree, &mut stderr, label)
}

fn exercise_mcp_stdio_session(
    child: &mut Child,
    stdin: &mut ChildStdin,
    response_rx: &mpsc::Receiver<Result<Vec<u8>>>,
    stderr: &mut StreamCapture,
    fixture_path: &Path,
) -> Result<()> {
    write_mcp_message(
        stdin,
        &serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {
                    "name": "release-packager-claude-desktop-smoke",
                    "version": env!("CARGO_PKG_VERSION")
                }
            }
        }),
    )
    .context("write MCP initialize request")?;
    let initialize = receive_mcp_response(child, response_rx, stderr, 1, "initialize response")?;
    validate_mcp_initialize_response(&initialize)?;

    write_mcp_message(
        stdin,
        &serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }),
    )
    .context("write MCP initialized notification")?;

    write_mcp_message(
        stdin,
        &serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }),
    )
    .context("write MCP tools/list request")?;
    let tools = receive_mcp_response(child, response_rx, stderr, 2, "tools/list response")?;
    validate_mcp_response_envelope(&tools, 2, "tools/list")?;
    validate_tool_surface(&tools["result"]["tools"]).context("validate MCP tools/list surface")?;

    write_mcp_message(
        stdin,
        &serde_json::json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "list_layouts",
                "arguments": {
                    "drawing_path": fixture_path
                }
            }
        }),
    )
    .context("write MCP tools/call request")?;
    let tool_call = receive_mcp_response(child, response_rx, stderr, 3, "tools/call response")?;
    let layouts = validate_mcp_read_tool_response(&tool_call, 3, "list_layouts")?;
    validate_portable_layout_smoke_records(&layouts)
}

fn write_mcp_message(stdin: &mut impl Write, value: &Value) -> Result<()> {
    serde_json::to_writer(&mut *stdin, value)?;
    stdin.write_all(b"\n")?;
    stdin.flush()?;
    Ok(())
}

fn receive_mcp_response(
    child: &mut Child,
    response_rx: &mpsc::Receiver<Result<Vec<u8>>>,
    stderr: &mut StreamCapture,
    expected_id: u64,
    label: &str,
) -> Result<Value> {
    let deadline = Instant::now() + SUBPROCESS_TIMEOUT;
    loop {
        match response_rx.try_recv() {
            Ok(Ok(line)) => {
                let response: Value = serde_json::from_slice(&line).with_context(|| {
                    format!("parse {label} as JSON: {}", String::from_utf8_lossy(&line))
                })?;
                if response["id"] != expected_id {
                    return Err(anyhow!(
                        "{label} must contain id {expected_id}; got {}",
                        response["id"]
                    ));
                }
                return Ok(response);
            }
            Ok(Err(error)) => return Err(error),
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => {
                return Err(anyhow!(
                    "MCP stdout reader disconnected before receiving {label}"
                ));
            }
        }

        if let Some(status) = child.try_wait()? {
            let _ = poll_stream_capture(stderr);
            return Err(anyhow!(
                "MCP server exited with {status} before {label}; stderr: {}",
                String::from_utf8_lossy(&current_stream_bytes(stderr))
            ));
        }
        poll_stream_capture(stderr)?;
        if Instant::now() >= deadline {
            return Err(anyhow!("{label} timed out after {:?}", SUBPROCESS_TIMEOUT));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn validate_mcp_response_envelope(response: &Value, id: u64, label: &str) -> Result<()> {
    if response["jsonrpc"] != "2.0" {
        return Err(anyhow!("{label} response must contain jsonrpc 2.0"));
    }
    if response["id"] != id {
        return Err(anyhow!("{label} response must contain id {id}"));
    }
    if let Some(error) = response.get("error") {
        return Err(anyhow!("{label} returned an MCP protocol error: {error}"));
    }
    if !response["result"].is_object() {
        return Err(anyhow!("{label} response result must be an object"));
    }
    Ok(())
}

fn validate_mcp_initialize_response(response: &Value) -> Result<()> {
    validate_mcp_response_envelope(response, 1, "initialize")?;
    if response["result"]["protocolVersion"]
        .as_str()
        .filter(|version| !version.is_empty())
        .is_none()
    {
        return Err(anyhow!(
            "initialize response must contain a nonempty protocolVersion"
        ));
    }
    if !response["result"]["capabilities"]["tools"].is_object() {
        return Err(anyhow!(
            "initialize response must advertise the MCP tools capability"
        ));
    }
    let server_info = &response["result"]["serverInfo"];
    if !server_info.is_object() {
        return Err(anyhow!(
            "initialize response must contain a serverInfo object"
        ));
    }
    if server_info["name"] != autocad_mcp::server::SERVER_NAME {
        return Err(anyhow!(
            "initialize response serverInfo.name must be {}",
            autocad_mcp::server::SERVER_NAME
        ));
    }
    if server_info["version"] != autocad_mcp::server::SERVER_VERSION {
        return Err(anyhow!(
            "initialize response serverInfo.version must be {}",
            autocad_mcp::server::SERVER_VERSION
        ));
    }
    Ok(())
}

fn validate_mcp_read_tool_response(response: &Value, id: u64, tool_name: &str) -> Result<Value> {
    validate_mcp_response_envelope(response, id, "tools/call")?;
    if response["result"]["isError"].as_bool() == Some(true) {
        return Err(anyhow!(
            "MCP {tool_name} returned a tool-level error: {}",
            response["result"]
        ));
    }
    let content = response["result"]["content"]
        .as_array()
        .ok_or_else(|| anyhow!("MCP {tool_name} result.content must be an array"))?;
    let text = content
        .iter()
        .find(|item| item["type"] == "text")
        .and_then(|item| item["text"].as_str())
        .ok_or_else(|| anyhow!("MCP {tool_name} result must contain text content"))?;
    let value: Value = serde_json::from_str(text)
        .with_context(|| format!("parse MCP {tool_name} text content as JSON"))?;
    if !value.is_array() {
        return Err(anyhow!("MCP {tool_name} text content must be a JSON array"));
    }
    Ok(value)
}

fn spawn_mcp_line_reader<R>(stream: R, label: &str) -> mpsc::Receiver<Result<Vec<u8>>>
where
    R: Read + Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    let label = label.to_string();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stream);
        let mut total = 0_u64;
        loop {
            let mut line = Vec::new();
            let read = match reader.read_until(b'\n', &mut line) {
                Ok(read) => read,
                Err(error) => {
                    let _ =
                        tx.send(Err(error).with_context(|| {
                            format!("read newline-delimited MCP stdout for {label}")
                        }));
                    return;
                }
            };
            if read == 0 {
                return;
            }
            total = total.saturating_add(read as u64);
            if line.len() as u64 > MAX_MCP_FRAME_BYTES {
                let _ = tx.send(Err(anyhow!(
                    "MCP stdout frame for {label} exceeds max {MAX_MCP_FRAME_BYTES} bytes"
                )));
                return;
            }
            if total > MAX_MCP_SESSION_OUTPUT_BYTES {
                let _ = tx.send(Err(anyhow!(
                    "MCP stdout for {label} exceeds max {MAX_MCP_SESSION_OUTPUT_BYTES} bytes"
                )));
                return;
            }
            while matches!(line.last(), Some(b'\n' | b'\r')) {
                line.pop();
            }
            if line.is_empty() {
                continue;
            }
            if tx.send(Ok(line)).is_err() {
                return;
            }
        }
    });
    rx
}

fn wait_for_mcp_shutdown(
    child: &mut Child,
    process_tree: &mut ProcessTree,
    stderr: &mut StreamCapture,
    label: &str,
) -> Result<()> {
    let deadline = Instant::now() + SUBPROCESS_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait()? {
            process_tree.terminate();
            let drain_deadline = Instant::now() + Duration::from_millis(500);
            while matches!(stderr, StreamCapture::Pending(_)) && Instant::now() < drain_deadline {
                poll_stream_capture(stderr)?;
                std::thread::sleep(Duration::from_millis(10));
            }
            if !status.success() {
                return Err(anyhow!(
                    "{label} server exited with {status} after stdin closed; stderr: {}",
                    String::from_utf8_lossy(&current_stream_bytes(stderr))
                ));
            }
            return Ok(());
        }
        poll_stream_capture(stderr)?;
        if Instant::now() >= deadline {
            terminate_child(child, process_tree);
            let _ = child.wait();
            return Err(anyhow!(
                "{label} server did not exit after stdin closed within {:?}",
                SUBPROCESS_TIMEOUT
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn write_lsp_message(stdin: &mut impl Write, value: &Value) -> Result<()> {
    let body = serde_json::to_vec(value)?;
    write!(stdin, "Content-Length: {}\r\n\r\n", body.len())?;
    stdin.write_all(&body)?;
    stdin.flush()?;
    Ok(())
}

fn validate_lsp_initialize_response(response: &[u8]) -> Result<()> {
    let value: Value = serde_json::from_slice(response).with_context(|| {
        format!(
            "parse autolisp-lsp initialize response as JSON: {}",
            String::from_utf8_lossy(response)
        )
    })?;
    if value["jsonrpc"] != "2.0" {
        return Err(anyhow!(
            "autolisp-lsp initialize response must contain jsonrpc 2.0"
        ));
    }
    if value["id"] != 1 {
        return Err(anyhow!(
            "autolisp-lsp initialize response must contain id 1"
        ));
    }
    if !value["result"]["capabilities"].is_object() {
        return Err(anyhow!(
            "autolisp-lsp initialize response result.capabilities must be an object"
        ));
    }
    let server_info = &value["result"]["serverInfo"];
    let server_name = server_info["name"]
        .as_str()
        .ok_or_else(|| anyhow!("autolisp-lsp initialize response missing serverInfo.name"))?;
    if server_name != "autolisp-lsp" {
        return Err(anyhow!(
            "autolisp-lsp initialize response serverInfo.name must be autolisp-lsp"
        ));
    }
    Ok(())
}

fn spawn_lsp_frame_reader<R>(mut stream: R, label: &str) -> mpsc::Receiver<Result<Vec<u8>>>
where
    R: Read + Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    let label = label.to_string();
    std::thread::spawn(move || {
        let result = read_first_lsp_frame(&mut stream, &label);
        let _ = tx.send(result);
    });
    rx
}

fn read_first_lsp_frame<R: Read>(stream: &mut R, label: &str) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        if let Some(frame) = parse_lsp_frame(&output)? {
            return Ok(frame);
        }
        let read = stream
            .read(&mut buffer)
            .with_context(|| format!("read stdout for {label}"))?;
        if read == 0 {
            return Err(anyhow!(
                "stdout closed before complete LSP frame for {label}: {}",
                String::from_utf8_lossy(&output)
            ));
        }
        let next_len = output.len().saturating_add(read);
        if next_len as u64 > MAX_CAPTURED_OUTPUT_BYTES {
            return Err(anyhow!(
                "stdout too large for {label}: exceeds max {MAX_CAPTURED_OUTPUT_BYTES} bytes"
            ));
        }
        output.extend_from_slice(&buffer[..read]);
    }
}

fn parse_lsp_frame(output: &[u8]) -> Result<Option<Vec<u8>>> {
    let Some(header_end) = output.windows(4).position(|window| window == b"\r\n\r\n") else {
        return Ok(None);
    };
    let header = std::str::from_utf8(&output[..header_end])
        .context("parse LSP response headers as UTF-8")?;
    let mut content_length = None;
    for line in header.split("\r\n") {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            content_length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .context("parse LSP Content-Length")?,
            );
            break;
        }
    }
    let content_length =
        content_length.ok_or_else(|| anyhow!("LSP response missing Content-Length header"))?;
    let body_start = header_end + 4;
    let body_end = body_start.saturating_add(content_length);
    if output.len() < body_end {
        return Ok(None);
    }
    Ok(Some(output[body_start..body_end].to_vec()))
}

#[derive(Debug)]
struct ProcessOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

enum StreamCapture {
    Pending(mpsc::Receiver<Result<Vec<u8>>>),
    Done(Vec<u8>),
}

fn run_with_timeout(
    command: &mut Command,
    label: &str,
    timeout: Duration,
) -> Result<ProcessOutput> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }

    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawn {label}"))?;
    let mut process_tree = match ProcessTree::new(&child) {
        Ok(process_tree) => process_tree,
        Err(e) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(e).with_context(|| format!("contain process tree for {label}"));
        }
    };
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("failed to capture stdout for {label}"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("failed to capture stderr for {label}"))?;
    let mut stdout = StreamCapture::Pending(spawn_stream_reader(stdout, label, "stdout"));
    let mut stderr = StreamCapture::Pending(spawn_stream_reader(stderr, label, "stderr"));
    let deadline = Instant::now() + timeout;
    let mut status = None;
    let mut drain_deadline = None;

    loop {
        if let Err(e) = poll_stream_capture(&mut stdout) {
            terminate_child(&mut child, &mut process_tree);
            let _ = child.wait();
            return Err(e);
        }
        if let Err(e) = poll_stream_capture(&mut stderr) {
            terminate_child(&mut child, &mut process_tree);
            let _ = child.wait();
            return Err(e);
        }

        if status.is_none() {
            if let Some(child_status) = child.try_wait()? {
                status = Some(child_status);
                process_tree.terminate();
                drain_deadline = Some(Instant::now() + Duration::from_millis(500));
            }
        }

        if let (Some(status), StreamCapture::Done(_), StreamCapture::Done(_)) =
            (status, &stdout, &stderr)
        {
            return Ok(ProcessOutput {
                status,
                stdout: take_stream_capture(stdout),
                stderr: take_stream_capture(stderr),
            });
        }

        let now = Instant::now();
        if status.is_none() && now >= deadline {
            terminate_child(&mut child, &mut process_tree);
            let _ = child.wait();
            return Err(anyhow!("{label} timed out after {:?}", timeout));
        }
        if let Some(deadline) = drain_deadline {
            if now >= deadline {
                process_tree.terminate();
                return Err(anyhow!(
                    "{label} output streams did not close after process exit"
                ));
            }
        }

        std::thread::sleep(Duration::from_millis(10));
    }
}

fn spawn_stream_reader<R>(
    mut stream: R,
    label: &str,
    stream_name: &str,
) -> mpsc::Receiver<Result<Vec<u8>>>
where
    R: Read + Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    let label = label.to_string();
    let stream_name = stream_name.to_string();
    std::thread::spawn(move || {
        let result = read_stream_bounded(&mut stream, &label, &stream_name);
        let _ = tx.send(result);
    });
    rx
}

fn read_stream_bounded<R: Read>(stream: &mut R, label: &str, stream_name: &str) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = stream
            .read(&mut buffer)
            .with_context(|| format!("read {stream_name} for {label}"))?;
        if read == 0 {
            return Ok(output);
        }
        let next_len = output.len().saturating_add(read);
        if next_len as u64 > MAX_CAPTURED_OUTPUT_BYTES {
            return Err(anyhow!(
                "{stream_name} too large for {label}: exceeds max {MAX_CAPTURED_OUTPUT_BYTES} bytes"
            ));
        }
        output.extend_from_slice(&buffer[..read]);
    }
}

fn poll_stream_capture(capture: &mut StreamCapture) -> Result<()> {
    let StreamCapture::Pending(rx) = capture else {
        return Ok(());
    };
    match rx.try_recv() {
        Ok(Ok(bytes)) => {
            *capture = StreamCapture::Done(bytes);
            Ok(())
        }
        Ok(Err(e)) => Err(e),
        Err(mpsc::TryRecvError::Empty) => Ok(()),
        Err(mpsc::TryRecvError::Disconnected) => Err(anyhow!(
            "output reader thread disconnected before returning output"
        )),
    }
}

fn take_stream_capture(capture: StreamCapture) -> Vec<u8> {
    match capture {
        StreamCapture::Done(bytes) => bytes,
        StreamCapture::Pending(_) => unreachable!("stream capture must be complete"),
    }
}

fn current_stream_bytes(capture: &StreamCapture) -> Vec<u8> {
    match capture {
        StreamCapture::Done(bytes) => bytes.clone(),
        StreamCapture::Pending(_) => Vec::new(),
    }
}

fn terminate_child(child: &mut Child, process_tree: &mut ProcessTree) {
    process_tree.terminate();
    let _ = child.kill();
}

fn validate_tool_annotations(item: &Value, expected: ExpectedToolContract) -> Result<()> {
    let annotations = item
        .get("annotations")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            anyhow!(
                "list-tools entry {} requires an annotations object",
                expected.name
            )
        })?;
    let expected_keys = BTreeSet::from([
        "destructiveHint",
        "idempotentHint",
        "openWorldHint",
        "readOnlyHint",
    ]);
    let actual_keys = annotations
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if actual_keys != expected_keys {
        return Err(anyhow!(
            "list-tools entry {} annotations must contain exactly the four camelCase MCP hint keys; got {actual_keys:?}",
            expected.name
        ));
    }

    for (key, expected_value) in [
        ("readOnlyHint", expected.read_only_hint),
        ("destructiveHint", expected.destructive_hint),
        ("idempotentHint", expected.idempotent_hint),
        ("openWorldHint", expected.open_world_hint),
    ] {
        let actual = annotations
            .get(key)
            .and_then(Value::as_bool)
            .ok_or_else(|| {
                anyhow!(
                    "list-tools entry {} annotation {key} must be a non-null Boolean",
                    expected.name
                )
            })?;
        if actual != expected_value {
            return Err(anyhow!(
                "list-tools entry {} annotation {key} must be {expected_value}; got {actual}",
                expected.name
            ));
        }
    }
    Ok(())
}

fn canonical_json_sha256(value: &Value) -> Result<String> {
    fn canonicalize(value: &Value) -> Value {
        match value {
            Value::Array(items) => Value::Array(items.iter().map(canonicalize).collect()),
            Value::Object(object) => {
                let mut entries = object.iter().collect::<Vec<_>>();
                entries.sort_by_key(|(key, _)| *key);
                Value::Object(
                    entries
                        .into_iter()
                        .map(|(key, value)| (key.clone(), canonicalize(value)))
                        .collect(),
                )
            }
            scalar => scalar.clone(),
        }
    }

    let canonical = serde_json::to_vec(&canonicalize(value))
        .context("serialize canonical JSON for a tool contract fingerprint")?;
    Ok(xref_sha256_bytes(&canonical))
}

fn validate_tool_interface(item: &Value, expected: ExpectedToolContract) -> Result<()> {
    let description = item
        .get("description")
        .and_then(Value::as_str)
        .filter(|description| !description.trim().is_empty())
        .ok_or_else(|| {
            anyhow!(
                "list-tools entry {} requires a nonempty string description",
                expected.name
            )
        })?;
    if description != expected.description {
        return Err(anyhow!(
            "list-tools entry {} description drifted from the frozen runtime contract",
            expected.name
        ));
    }

    let input_schema = item
        .get("inputSchema")
        .filter(|schema| schema.is_object())
        .ok_or_else(|| {
            anyhow!(
                "list-tools entry {} requires an inputSchema object",
                expected.name
            )
        })?;
    if input_schema.get("$schema").and_then(Value::as_str)
        != Some("https://json-schema.org/draft/2020-12/schema")
    {
        return Err(anyhow!(
            "list-tools entry {} inputSchema must declare JSON Schema Draft 2020-12",
            expected.name
        ));
    }
    jsonschema::draft202012::meta::validate(input_schema).map_err(|error| {
        anyhow!(
            "list-tools entry {} inputSchema is not valid JSON Schema Draft 2020-12: {error}",
            expected.name
        )
    })?;
    let actual_sha256 = canonical_json_sha256(input_schema)?;
    if actual_sha256 != expected.input_schema_sha256 {
        return Err(anyhow!(
            "list-tools entry {} inputSchema drifted from the frozen runtime contract: expected sha256={}, got sha256={actual_sha256}",
            expected.name,
            expected.input_schema_sha256
        ));
    }

    Ok(())
}

fn validate_tool_surface(value: &Value) -> Result<()> {
    let tools = value
        .as_array()
        .ok_or_else(|| anyhow!("list-tools stdout must be a JSON array"))?;
    let expected = EXPECTED_CALLABLE_TOOLS
        .iter()
        .map(|tool| tool.name)
        .collect::<BTreeSet<_>>();
    let reserved = RESERVED_XREF_CLIP_TOOLS
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let obsolete = OBSOLETE_XREF_TOOLS.iter().copied().collect::<BTreeSet<_>>();
    let mut actual = BTreeSet::new();
    let mut duplicates = BTreeSet::new();
    let mut named_tools = Vec::with_capacity(tools.len());
    for item in tools {
        let name = item
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("list-tools entries must contain string name fields"))?;
        if !actual.insert(name) {
            duplicates.insert(name);
        }
        named_tools.push((name, item));
    }

    if let Some(name) = actual.intersection(&reserved).next() {
        return Err(anyhow!(
            "list-tools output contains reserved XREF clip tool {name}"
        ));
    }
    if let Some(name) = actual.intersection(&obsolete).next() {
        return Err(anyhow!(
            "list-tools output contains obsolete XREF tool {name}"
        ));
    }
    if let Some(unexpected) = actual.difference(&expected).next() {
        return Err(anyhow!(
            "list-tools output contains unexpected tool {unexpected}"
        ));
    }
    if let Some(duplicate) = duplicates.first() {
        return Err(anyhow!(
            "list-tools output contains duplicate tool {duplicate}"
        ));
    }
    if let Some(missing) = expected.difference(&actual).next() {
        return Err(anyhow!(
            "list-tools output missing expected callable tool {missing}"
        ));
    }
    if actual.len() != EXPECTED_CALLABLE_TOOLS.len() {
        return Err(anyhow!(
            "list-tools output must contain exactly {} tools; got {}",
            EXPECTED_CALLABLE_TOOLS.len(),
            actual.len()
        ));
    }

    for contract in EXPECTED_CALLABLE_TOOLS {
        let item = named_tools
            .iter()
            .find_map(|(name, item)| (*name == contract.name).then_some(*item))
            .expect("complete unique tool inventory was checked above");
        validate_tool_annotations(item, contract)?;
        validate_tool_interface(item, contract)?;
    }

    Ok(())
}

/// Validate the complete frozen MCP tool contract used by package smoke.
///
/// The value is the `tools` array returned by an MCP `tools/list` response.
pub fn validate_preview_evaluation_tool_surface(value: &Value) -> Result<()> {
    validate_tool_surface(value)
}

fn expected_portable_layout_smoke_records() -> Value {
    serde_json::json!([
        {
            "name": "Sheet A",
            "is_model": false,
            "tab_order": 1,
            "paper_width_mm": 0.0,
            "paper_height_mm": 0.0
        }
    ])
}

fn validate_portable_layout_smoke_records(value: &Value) -> Result<()> {
    let expected = expected_portable_layout_smoke_records();
    if value != &expected {
        return Err(anyhow!(
            "list_layouts stdout must exactly match the ordered nonempty portable-evidence fixture projection; got {value}"
        ));
    }
    Ok(())
}

fn expected_portable_layer_smoke_records() -> Value {
    serde_json::json!([
        {
            "handle": "7",
            "name": "0",
            "color_index": 7,
            "line_type": "Continuous",
            "line_weight": {"kind": "default"},
            "frozen": false,
            "locked": false,
            "off": false,
            "is_plottable": true,
            "xref_dependent": false,
            "xref_block_record_handle": null,
            "xref_name": null,
            "xref_path": null,
            "xref_is_overlay": null,
            "material_handle": null,
            "plotstyle_handle": null,
            "is_current": true
        },
        {
            "handle": "8",
            "name": "XREF_LAYER",
            "color_index": 7,
            "line_type": "Continuous",
            "line_weight": {"kind": "default"},
            "frozen": false,
            "locked": false,
            "off": false,
            "is_plottable": true,
            "xref_dependent": false,
            "xref_block_record_handle": null,
            "xref_name": null,
            "xref_path": null,
            "xref_is_overlay": null,
            "material_handle": null,
            "plotstyle_handle": null,
            "is_current": false
        }
    ])
}

fn validate_portable_layer_smoke_records(value: &Value) -> Result<()> {
    let expected = expected_portable_layer_smoke_records();
    if value != &expected {
        return Err(anyhow!(
            "list_layers stdout must exactly match the ordered nonempty portable-evidence fixture projection; got {value}"
        ));
    }
    Ok(())
}

fn compare_canonical_numeric_handles(left: &str, right: &str) -> Ordering {
    left.len().cmp(&right.len()).then_with(|| left.cmp(right))
}

fn validate_xref_point_availability(
    value: &Value,
    record_index: usize,
) -> Result<XrefSmokePointAvailability> {
    let object = value.as_object().ok_or_else(|| {
        anyhow!(
            "list_xrefs record {record_index} definition_base_point must be an availability object"
        )
    })?;
    let state = object.get("state").and_then(Value::as_str).ok_or_else(|| {
        anyhow!("list_xrefs record {record_index} definition_base_point.state must be a string")
    })?;

    match state {
        "available" => {
            let expected_keys = ["point", "state"];
            if object.len() != expected_keys.len()
                || !expected_keys.iter().all(|key| object.contains_key(*key))
            {
                return Err(anyhow!(
                    "list_xrefs record {record_index} available definition_base_point must contain exactly state and point"
                ));
            }
            let point = object["point"].as_object().ok_or_else(|| {
                anyhow!(
                    "list_xrefs record {record_index} definition_base_point.point must be an object"
                )
            })?;
            let point_keys = ["x", "y", "z"];
            if point.len() != point_keys.len()
                || !point_keys.iter().all(|key| point.contains_key(*key))
            {
                return Err(anyhow!(
                    "list_xrefs record {record_index} definition_base_point.point must contain exactly x, y, and z"
                ));
            }
            let coordinate = |key: &str| {
                point[key].as_f64().ok_or_else(|| {
                    anyhow!(
                        "list_xrefs record {record_index} definition_base_point.point.{key} must be a number"
                    )
                })
            };
            Ok(XrefSmokePointAvailability::Available {
                x: coordinate("x")?,
                y: coordinate("y")?,
                z: coordinate("z")?,
            })
        }
        "unavailable" => {
            if object.len() != 1 {
                return Err(anyhow!(
                    "list_xrefs record {record_index} unavailable definition_base_point must contain exactly state"
                ));
            }
            Ok(XrefSmokePointAvailability::Unavailable)
        }
        _ => Err(anyhow!(
            "list_xrefs record {record_index} definition_base_point.state must be available or unavailable"
        )),
    }
}

fn validate_xref_records(value: &Value) -> Result<()> {
    let records = value
        .as_array()
        .ok_or_else(|| anyhow!("list_xrefs stdout must be a JSON array"))?;
    let mut actual = Vec::with_capacity(records.len());
    let mut previous_handle = None;
    for (index, record) in records.iter().enumerate() {
        let object = record
            .as_object()
            .ok_or_else(|| anyhow!("list_xrefs record {index} must be a JSON object"))?;
        for obsolete in ["path", "is_overlay"] {
            if object.contains_key(obsolete) {
                return Err(anyhow!(
                    "list_xrefs record {index} must not contain obsolete field {obsolete}"
                ));
            }
        }
        if object.len() != XREF_ATTACHMENT_RECORD_KEYS.len()
            || !XREF_ATTACHMENT_RECORD_KEYS
                .iter()
                .all(|key| object.contains_key(*key))
        {
            let actual_keys = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
            return Err(anyhow!(
                "list_xrefs record {index} must contain exactly the keys {:?}; got {:?}",
                XREF_ATTACHMENT_RECORD_KEYS,
                actual_keys
            ));
        }

        let handle = object["handle"]
            .as_str()
            .ok_or_else(|| anyhow!("list_xrefs record {index} handle must be a string"))?;
        if handle.is_empty()
            || handle.starts_with('0')
            || !handle
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'A'..=b'F'))
        {
            return Err(anyhow!(
                "list_xrefs record {index} handle must be canonical uppercase hexadecimal without a prefix or leading zeroes"
            ));
        }
        if let Some(previous) = previous_handle {
            if compare_canonical_numeric_handles(previous, handle) != Ordering::Less {
                return Err(anyhow!(
                    "list_xrefs records must be in ascending numeric handle order; record {index} handle {handle} follows {previous}"
                ));
            }
        }
        previous_handle = Some(handle);

        for key in ["name", "saved_path"] {
            if !object[key].is_string() {
                return Err(anyhow!("list_xrefs record {index} {key} must be a string"));
            }
        }

        match object["path_mode"].as_str() {
            Some("absolute" | "relative" | "filename_only" | "url" | "unsupported") => {}
            _ => {
                return Err(anyhow!(
                    "list_xrefs record {index} path_mode must be absolute, relative, filename_only, url, or unsupported"
                ));
            }
        }
        match object["reference_type"].as_str() {
            Some("attachment" | "overlay") => {}
            _ => {
                return Err(anyhow!(
                    "list_xrefs record {index} reference_type must be attachment or overlay"
                ));
            }
        }
        match object["load_state"].as_str() {
            Some("loaded" | "unloaded" | "unavailable") => {}
            _ => {
                return Err(anyhow!(
                    "list_xrefs record {index} load_state must be loaded, unloaded, or unavailable"
                ));
            }
        }
        let instance_count = object["instance_count"].as_u64().ok_or_else(|| {
            anyhow!("list_xrefs record {index} instance_count must be an unsigned integer")
        })?;
        let definition_base_point =
            validate_xref_point_availability(&object["definition_base_point"], index)?;

        actual.push(XrefSmokeRecord {
            handle,
            name: object["name"]
                .as_str()
                .expect("XREF name was validated above"),
            saved_path: object["saved_path"]
                .as_str()
                .expect("XREF saved path was validated above"),
            path_mode: object["path_mode"]
                .as_str()
                .expect("XREF path mode was validated above"),
            reference_type: object["reference_type"]
                .as_str()
                .expect("XREF reference type was validated above"),
            load_state: object["load_state"]
                .as_str()
                .expect("XREF load state was validated above"),
            instance_count,
            definition_base_point,
        });
    }

    if actual.as_slice() != EXPECTED_XREF_RECORDS.as_slice() {
        return Err(anyhow!(
            "list_xrefs stdout must exactly match the ordered portable-evidence fixture records; got {:?}",
            actual
        ));
    }

    Ok(())
}

fn expected_xref_instance_smoke_records() -> Value {
    serde_json::json!([
        {
            "handle": "20",
            "attachment_handle": "10",
            "attachment_name": "GRID_OVERLAY",
            "owner_handle": "A1",
            "owner_type": "paper_space",
            "owner_name": "Sheet A",
            "layer_handle": "8",
            "layer_name": "XREF_LAYER",
            "insertion_point": {"x": 100.0, "y": 200.0, "z": 0.0},
            "scale": {"x": 1.0, "y": 1.0, "z": 1.0},
            "rotation_degrees": 90.0,
            "normal": {"x": 0.0, "y": 0.0, "z": 1.0},
            "visibility": "visible",
            "placement_kind": "rectangular_array",
            "array": {
                "rows": 2,
                "columns": 3,
                "row_spacing": 10.0,
                "column_spacing": 20.0
            },
            "unit_scaling": {
                "state": "available",
                "source_units": {"value": "meters", "basis": "drawing"},
                "host_units": {"value": "meters", "basis": "drawing"},
                "factor": 1.0,
                "effective_scale": {"x": 1.0, "y": 1.0, "z": 1.0}
            }
        },
        {
            "handle": "30",
            "attachment_handle": "11",
            "attachment_name": "EMPTY_PATH",
            "owner_handle": "A0",
            "owner_type": "model_space",
            "owner_name": "Model",
            "layer_handle": "8",
            "layer_name": "XREF_LAYER",
            "insertion_point": {"x": 0.0, "y": 0.0, "z": 0.0},
            "scale": {"x": 1.0, "y": 1.0, "z": 1.0},
            "rotation_degrees": 0.0,
            "normal": {"x": 0.0, "y": 0.0, "z": 1.0},
            "visibility": "hidden",
            "placement_kind": "single",
            "array": null,
            "unit_scaling": {"state": "unavailable"}
        },
        {
            "handle": "F0",
            "attachment_handle": "F",
            "attachment_name": "SITE_MODEL",
            "owner_handle": "A2",
            "owner_type": "block_definition",
            "owner_name": "DETAIL_SYMBOL",
            "layer_handle": "8",
            "layer_name": "XREF_LAYER",
            "insertion_point": {"x": 5.0, "y": 6.0, "z": 7.0},
            "scale": {"x": 2.0, "y": 3.0, "z": 4.0},
            "rotation_degrees": 45.0,
            "normal": {"x": 0.0, "y": 0.0, "z": 1.0},
            "visibility": "visible",
            "placement_kind": "rectangular_array",
            "array": {
                "rows": 1,
                "columns": 1,
                "row_spacing": 0.0,
                "column_spacing": 0.0
            },
            "unit_scaling": {
                "state": "available",
                "source_units": {"value": "millimeters", "basis": "drawing"},
                "host_units": {"value": "meters", "basis": "drawing"},
                "factor": 0.001,
                "effective_scale": {"x": 0.002, "y": 0.003, "z": 0.004}
            }
        },
        {
            "handle": "100",
            "attachment_handle": "F",
            "attachment_name": "SITE_MODEL",
            "owner_handle": "A0",
            "owner_type": "model_space",
            "owner_name": "Model",
            "layer_handle": "7",
            "layer_name": "0",
            "insertion_point": {"x": 10.0, "y": 20.0, "z": 30.0},
            "scale": {"x": 1.0, "y": 1.0, "z": 1.0},
            "rotation_degrees": 0.0,
            "normal": {"x": 0.0, "y": 0.0, "z": 1.0},
            "visibility": "visible",
            "placement_kind": "single",
            "array": null,
            "unit_scaling": {
                "state": "available",
                "source_units": {"value": "millimeters", "basis": "drawing"},
                "host_units": {"value": "meters", "basis": "drawing"},
                "factor": 0.001,
                "effective_scale": {"x": 0.001, "y": 0.001, "z": 0.001}
            }
        }
    ])
}

fn validate_xref_instance_smoke_records(value: &Value) -> Result<()> {
    if !value.is_array() {
        return Err(anyhow!("list_xref_instances stdout must be a JSON array"));
    }

    let expected = expected_xref_instance_smoke_records();
    if value != &expected {
        return Err(anyhow!(
            "list_xref_instances stdout must exactly match the ordered four-record portable-evidence fixture projection, including every attachment, owner, layer, transform, visibility, array, and unit-scaling field; got {value}"
        ));
    }

    Ok(())
}

#[cfg(unix)]
fn ensure_unix_executable(binary: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let metadata =
        std::fs::metadata(binary).with_context(|| format!("stat {}", binary.display()))?;
    if metadata.permissions().mode() & 0o100 == 0 {
        return Err(anyhow!("binary is not executable: {}", binary.display()));
    }
    Ok(())
}

fn host_target() -> Option<PackageTarget> {
    if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        Some(PackageTarget::MacosArm64)
    } else if cfg!(all(target_os = "windows", target_arch = "x86_64")) {
        Some(PackageTarget::WindowsX64)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{
        manifest_for, manifest_for_mode, McpbManifest, PackageTarget, PluginMetadata,
        PROJECT_LICENSE, PROJECT_LICENSE_TEXT,
    };
    use crate::package::{create_package, PackageOptions};
    use std::io::Write;
    use std::path::Path;
    use zip::write::SimpleFileOptions as FileOptions;

    #[test]
    fn preview_evaluation_hashes_the_open_package_handle() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("candidate.mcpb");
        std::fs::write(&path, b"exact preview candidate bytes").unwrap();
        let mut file = File::open(path).unwrap();
        assert_eq!(
            sha256_open_file(&mut file).unwrap(),
            xref_sha256_bytes(b"exact preview candidate bytes")
        );
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"exact preview candidate bytes");
    }

    #[test]
    fn preview_evaluation_rejects_a_digest_mismatch_before_extraction() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("candidate.mcpb");
        let extraction = directory.path().join("extracted");
        std::fs::write(&path, b"unexpected candidate bytes").unwrap();
        std::fs::create_dir(&extraction).unwrap();

        let error = prepare_preview_evaluation_package(&path, &"0".repeat(64), &extraction)
            .expect_err("mismatched candidate digest");
        assert!(error.to_string().contains("does not match"));
        assert_eq!(std::fs::read_dir(extraction).unwrap().count(), 0);
    }

    fn metadata() -> PluginMetadata {
        PluginMetadata {
            name: "autocad-mcp".to_string(),
            version: "0.0.1".to_string(),
            description: "A rust-backed AutoLISP MCP".to_string(),
            license: "GPL-3.0-or-later".to_string(),
            author_name: "andagni".to_string(),
        }
    }

    #[cfg(unix)]
    fn write_release_introspection_binary(path: &Path) {
        let canonical = XREF_MUTATION_OPERATIONS.map(|operation| operation.as_str());
        let build_identity = autocad_mcp::certification::xref_certification_build_identity();
        let certified_arg_sha256 =
            autocad_mcp::ops::xref_runtime::certified_arg_sha256_build_value().map(str::to_owned);
        let certified_arg_policy_id = (!build_identity.certified_arg_policy_id.is_empty())
            .then_some(build_identity.certified_arg_policy_id.clone());
        let certified_arg_policy_sha256 = (!build_identity.certified_arg_policy_sha256.is_empty())
            .then_some(build_identity.certified_arg_policy_sha256.clone());
        let activation_catalogue_sha256 =
            autocad_mcp::activation::activation_catalogue_sha256().unwrap();
        let info = serde_json::json!({
            "schema_version": 4,
            "experimental_support": false,
            "activation_catalogue_sha256": activation_catalogue_sha256,
            "certified_arg_sha256": certified_arg_sha256,
            "certified_arg_policy_id": certified_arg_policy_id,
            "certified_arg_policy_sha256": certified_arg_policy_sha256,
            "certification_failpoints_enabled":
                build_identity.certification_failpoints_enabled,
            "crt_linkage": autocad_mcp::certification::xref_certification_crt_linkage(),
            "artifact_sha256":
                autocad_mcp::certification::xref_embedded_artifact_sha256(),
            "title_block_profile_registry_sha256":
                autocad_mcp::ops::profiles::title_block_profile_registry_sha256(),
            "title_block_profiles":
                autocad_mcp::certification::embedded_certification_profile_definitions(),
            "build_identity": build_identity,
            "xref_mutation_tools": canonical,
        });
        let tools = canonical
            .iter()
            .map(|name| serde_json::json!({"name": name}))
            .collect::<Vec<_>>();
        let script = format!(
            "#!/bin/sh\ncase \"$1\" in\n  xref-certification-info) printf '%s\\n' '{}' ;;\n  list-tools) [ \"$2\" = \"--experimental\" ] && exit 2; printf '%s\\n' '{}' ;;\n  *) exit 2 ;;\nesac\n",
            serde_json::to_string(&info).unwrap(),
            serde_json::to_string(&tools).unwrap(),
        );
        std::fs::write(path, script).unwrap();
    }

    const TEST_AUTOLISP_SKILL: &[u8] = b"# Test AutoLISP skill\n";
    const TEST_AUTOLISP_GUIDE: &[u8] = b"# Test guide\n";
    const TEST_AUTOLISP_INDEX: &[u8] = br#"{"schema_version":1,"symbols":[{"name":"sample","kind":"builtin","signature":"(sample)","summary":"A sample symbol.","detail":null,"source":"plugin/skills/autolisp/references/guide.md","completion":true}]}"#;

    #[derive(Clone, Copy)]
    enum DocumentationFixture {
        Valid,
        MissingSkillDirectory,
        MissingLedger,
        TamperedGuide,
        UnapprovedReferenceFile,
        EmbeddedOwnerApproval,
    }

    fn write_package(
        path: &Path,
        manifest: &McpbManifest,
        binary: Option<&str>,
        lsp_json: Option<&str>,
        lsp_binary: Option<&str>,
    ) {
        write_package_with_license(
            path,
            manifest,
            binary,
            lsp_json,
            lsp_binary,
            PROJECT_LICENSE,
            PROJECT_LICENSE_TEXT,
        );
    }

    fn write_package_with_license(
        path: &Path,
        manifest: &McpbManifest,
        binary: Option<&str>,
        lsp_json: Option<&str>,
        lsp_binary: Option<&str>,
        plugin_license: &str,
        license_text: &[u8],
    ) {
        write_package_with_license_and_documentation(
            path,
            manifest,
            binary,
            lsp_json,
            lsp_binary,
            plugin_license,
            license_text,
            DocumentationFixture::Valid,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn write_package_with_license_and_documentation(
        path: &Path,
        manifest: &McpbManifest,
        binary: Option<&str>,
        lsp_json: Option<&str>,
        lsp_binary: Option<&str>,
        plugin_license: &str,
        license_text: &[u8],
        documentation: DocumentationFixture,
    ) {
        let file = std::fs::File::create(path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = FileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .unix_permissions(0o644);
        let executable_options = FileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .unix_permissions(0o755);

        let manifest_json = serde_json::to_vec_pretty(manifest).unwrap();
        zip.start_file("manifest.json", options).unwrap();
        zip.write_all(&manifest_json).unwrap();
        zip.start_file("plugin/.claude-plugin/plugin.json", options)
            .unwrap();
        let plugin_json = serde_json::json!({
            "name": "autocad-mcp",
            "description": "A rust-backed AutoLISP MCP",
            "version": "0.0.1",
            "license": plugin_license,
            "author": {"name": "andagni"}
        });
        zip.write_all(&serde_json::to_vec(&plugin_json).unwrap())
            .unwrap();
        zip.start_file("plugin/.mcp.json", options).unwrap();
        zip.write_all(
            br#"{"mcpServers":{"autocad-mcp":{"command":"${CLAUDE_PLUGIN_ROOT}/bin/autocad-mcp","args":["serve"]}}}"#,
        )
        .unwrap();
        if let Some(lsp_json) = lsp_json {
            zip.start_file("plugin/.lsp.json", options).unwrap();
            zip.write_all(lsp_json.as_bytes()).unwrap();
        }
        zip.start_file("plugin/skills/autocad-mcp/SKILL.md", options)
            .unwrap();
        zip.write_all(b"# Test\n").unwrap();
        if !matches!(documentation, DocumentationFixture::MissingSkillDirectory) {
            zip.start_file("plugin/skills/autolisp/SKILL.md", options)
                .unwrap();
            zip.write_all(TEST_AUTOLISP_SKILL).unwrap();
            zip.start_file(
                "plugin/skills/autolisp/references/autolisp-lsp-index.json",
                options,
            )
            .unwrap();
            zip.write_all(TEST_AUTOLISP_INDEX).unwrap();
            zip.start_file("plugin/skills/autolisp/references/guide.md", options)
                .unwrap();
            if matches!(documentation, DocumentationFixture::TamperedGuide) {
                zip.write_all(b"# Tampered guide\n").unwrap();
            } else {
                zip.write_all(TEST_AUTOLISP_GUIDE).unwrap();
            }
            if !matches!(documentation, DocumentationFixture::MissingLedger) {
                let provenance = serde_json::json!({
                    "schema_version": 1,
                    "reference_root": "plugin/skills/autolisp",
                    "copyright_holder": "andagni",
                    "license": "GPL-3.0-or-later",
                    "sources": [{
                        "id": "official-factual-reference",
                        "title": "Official factual reference",
                        "url": "https://example.test/reference",
                        "version": "reviewed snapshot 1",
                        "reviewed_on": "2026-07-26",
                        "rights_basis": "facts_only_no_source_expression_redistributed"
                    }],
                    "artifacts": [
                        {
                            "path": "SKILL.md",
                            "sha256": xref_sha256_bytes(TEST_AUTOLISP_SKILL),
                            "kind": "markdown",
                            "disposition": "first_party_factual_synthesis",
                            "source_ids": ["official-factual-reference"]
                        },
                        {
                            "path": "references/autolisp-lsp-index.json",
                            "sha256": xref_sha256_bytes(TEST_AUTOLISP_INDEX),
                            "kind": "autolisp_lsp_index",
                            "disposition": "first_party_curated_index",
                            "source_ids": ["official-factual-reference"]
                        },
                        {
                            "path": "references/guide.md",
                            "sha256": xref_sha256_bytes(TEST_AUTOLISP_GUIDE),
                            "kind": "markdown",
                            "disposition": "first_party_factual_synthesis",
                            "source_ids": ["official-factual-reference"]
                        }
                    ]
                });
                zip.start_file(
                    "plugin/skills/autolisp/references/documentation-provenance.json",
                    options,
                )
                .unwrap();
                zip.write_all(&serde_json::to_vec_pretty(&provenance).unwrap())
                    .unwrap();
            }
            if matches!(documentation, DocumentationFixture::UnapprovedReferenceFile) {
                zip.start_file("plugin/skills/autolisp/references/unreviewed.json", options)
                    .unwrap();
                zip.write_all(b"{}\n").unwrap();
            }
        }
        write_test_distribution_evidence(&mut zip, options);
        if matches!(documentation, DocumentationFixture::EmbeddedOwnerApproval) {
            zip.start_file("plugin/release-approval.json", options)
                .unwrap();
            zip.write_all(br#"{"schema_version":2,"kind":"owner_distribution_approval"}"#)
                .unwrap();
        }
        zip.start_file("plugin/LICENSE", options).unwrap();
        zip.write_all(license_text).unwrap();
        zip.start_file("plugin/CHANGELOG.md", options).unwrap();
        zip.write_all(b"# Changelog\n").unwrap();
        if let Some(binary) = binary {
            zip.start_file(&manifest.server.entry_point, executable_options)
                .unwrap();
            zip.write_all(binary.as_bytes()).unwrap();
        }
        if let Some(lsp_binary) = lsp_binary {
            let lsp_entry = match manifest.compatibility.platforms.as_slice() {
                [platform] if platform == "win32" => "plugin/bin/autolisp-lsp.exe",
                _ => "plugin/bin/autolisp-lsp",
            };
            zip.start_file(lsp_entry, executable_options).unwrap();
            zip.write_all(lsp_binary.as_bytes()).unwrap();
        }
        zip.finish().unwrap();
    }

    fn write_test_distribution_evidence(
        zip: &mut zip::ZipWriter<std::fs::File>,
        options: FileOptions,
    ) {
        zip.start_file(
            "plugin/.third-party/third-party-license-policy.json",
            options,
        )
        .unwrap();
        zip.write_all(THIRD_PARTY_LICENSE_POLICY).unwrap();
        zip.start_file("plugin/.third-party/source-lock.spdx.json", options)
            .unwrap();
        zip.write_all(SOURCE_LOCK_SBOM).unwrap();
        zip.start_file(
            "plugin/.third-party/source-closure-windows.spdx.json",
            options,
        )
        .unwrap();
        zip.write_all(WINDOWS_SOURCE_CLOSURE_SBOM).unwrap();
        zip.start_file(
            "plugin/.third-party/third-party-license-provenance.json",
            options,
        )
        .unwrap();
        zip.write_all(THIRD_PARTY_LICENSE_PROVENANCE).unwrap();
        zip.start_file("plugin/THIRD_PARTY_LICENSES.txt", options)
            .unwrap();
        zip.write_all(THIRD_PARTY_LICENSES).unwrap();
        zip.start_file("plugin/owner-distribution-approval.schema.json", options)
            .unwrap();
        zip.write_all(OWNER_DISTRIBUTION_APPROVAL_SCHEMA).unwrap();
    }

    fn write_duplicate_name_zip(path: &Path) {
        fn push_u16(bytes: &mut Vec<u8>, value: u16) {
            bytes.extend_from_slice(&value.to_le_bytes());
        }

        fn push_u32(bytes: &mut Vec<u8>, value: u32) {
            bytes.extend_from_slice(&value.to_le_bytes());
        }

        fn push_local_file(bytes: &mut Vec<u8>, name: &str) -> u32 {
            let offset = bytes.len() as u32;
            push_u32(bytes, 0x0403_4b50);
            push_u16(bytes, 20);
            push_u16(bytes, 0);
            push_u16(bytes, 0);
            push_u16(bytes, 0);
            push_u16(bytes, 0);
            push_u32(bytes, 0);
            push_u32(bytes, 0);
            push_u32(bytes, 0);
            push_u16(bytes, name.len() as u16);
            push_u16(bytes, 0);
            bytes.extend_from_slice(name.as_bytes());
            offset
        }

        fn push_central_file(bytes: &mut Vec<u8>, name: &str, local_offset: u32) {
            push_u32(bytes, 0x0201_4b50);
            push_u16(bytes, 0x0314);
            push_u16(bytes, 20);
            push_u16(bytes, 0);
            push_u16(bytes, 0);
            push_u16(bytes, 0);
            push_u16(bytes, 0);
            push_u32(bytes, 0);
            push_u32(bytes, 0);
            push_u32(bytes, 0);
            push_u16(bytes, name.len() as u16);
            push_u16(bytes, 0);
            push_u16(bytes, 0);
            push_u16(bytes, 0);
            push_u16(bytes, 0);
            push_u32(bytes, 0x0180_0000);
            push_u32(bytes, local_offset);
            bytes.extend_from_slice(name.as_bytes());
        }

        let name = "manifest.json";
        let mut bytes = Vec::new();
        let first_offset = push_local_file(&mut bytes, name);
        let second_offset = push_local_file(&mut bytes, name);
        let central_offset = bytes.len() as u32;
        push_central_file(&mut bytes, name, first_offset);
        push_central_file(&mut bytes, name, second_offset);
        let central_size = bytes.len() as u32 - central_offset;
        push_u32(&mut bytes, 0x0605_4b50);
        push_u16(&mut bytes, 0);
        push_u16(&mut bytes, 0);
        push_u16(&mut bytes, 2);
        push_u16(&mut bytes, 2);
        push_u32(&mut bytes, central_size);
        push_u32(&mut bytes, central_offset);
        push_u16(&mut bytes, 0);

        std::fs::write(path, bytes).unwrap();
    }

    fn write_zip_with_large_declared_central_directory(path: &Path) {
        fn push_u16(bytes: &mut Vec<u8>, value: u16) {
            bytes.extend_from_slice(&value.to_le_bytes());
        }

        fn push_u32(bytes: &mut Vec<u8>, value: u32) {
            bytes.extend_from_slice(&value.to_le_bytes());
        }

        let central_size = MAX_CENTRAL_DIRECTORY_BYTES as usize + 1;
        let mut bytes = vec![0_u8; central_size];
        push_u32(&mut bytes, 0x0605_4b50);
        push_u16(&mut bytes, 0);
        push_u16(&mut bytes, 0);
        push_u16(&mut bytes, 1);
        push_u16(&mut bytes, 1);
        push_u32(&mut bytes, central_size as u32);
        push_u32(&mut bytes, 0);
        push_u16(&mut bytes, 0);

        std::fs::write(path, bytes).unwrap();
    }

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .find(|candidate| {
                std::fs::read_to_string(candidate.join("Cargo.toml"))
                    .map(|manifest| manifest.lines().any(|line| line.trim() == "[workspace]"))
                    .unwrap_or(false)
            })
            .expect("release-packager must be contained by a Cargo workspace")
            .to_path_buf()
    }

    fn zip_names(path: &Path) -> Vec<String> {
        let file = std::fs::File::open(path).unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();
        let mut names = Vec::new();
        for i in 0..archive.len() {
            names.push(archive.by_index(i).unwrap().name().to_string());
        }
        names.sort();
        names
    }

    #[test]
    fn xref_package_binding_json_has_a_closed_required_shape() {
        let binding = XrefPackageBinding {
            schema_version: XREF_PACKAGE_BINDING_SCHEMA_VERSION,
            release_binary_sha256: "0".repeat(64),
            certified_arg_sha256: "1".repeat(64),
            manifest_sha256: "2".repeat(64),
            release_evidence_sha256: "3".repeat(64),
            transaction_evidence_sha256: "4".repeat(64),
            attestation_sha256: "5".repeat(64),
        };
        let value = serde_json::to_value(&binding).unwrap();
        serde_json::from_value::<XrefPackageBinding>(value.clone()).unwrap();

        for field in [
            "schema_version",
            "release_binary_sha256",
            "certified_arg_sha256",
            "manifest_sha256",
            "release_evidence_sha256",
            "transaction_evidence_sha256",
            "attestation_sha256",
        ] {
            let mut missing = value.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(
                serde_json::from_value::<XrefPackageBinding>(missing).is_err(),
                "missing field {field} was accepted"
            );
        }

        let mut extra = value;
        extra
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_owned(), Value::Bool(true));
        assert!(serde_json::from_value::<XrefPackageBinding>(extra).is_err());
    }

    fn preview_activation_tree() -> (
        tempfile::TempDir,
        McpbManifest,
        PreviewActivationPackageBinding,
    ) {
        let root = tempfile::tempdir().unwrap();
        let manifest =
            manifest_for_mode(PackageTarget::WindowsX64, PackageMode::Preview, &metadata());
        let binary_path = root.path().join(&manifest.server.entry_point);
        std::fs::create_dir_all(binary_path.parent().unwrap()).unwrap();
        std::fs::write(&binary_path, b"Preview binary").unwrap();

        let directory = root.path().join(PREVIEW_ACTIVATION_DIRECTORY);
        let files = embedded_preview_activation_files().unwrap();
        let mut inventory = Vec::new();
        for (relative_path, bytes) in &files {
            let path = directory.join(relative_path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, bytes).unwrap();
            inventory.push(PreviewActivationFileBinding {
                path: relative_path.clone(),
                sha256: xref_sha256_bytes(bytes),
            });
        }
        let binding = PreviewActivationPackageBinding {
            schema_version: PREVIEW_ACTIVATION_BINDING_SCHEMA_VERSION,
            preview_binary_sha256: xref_sha256_file(&binary_path).unwrap(),
            catalogue_sha256: xref_sha256_bytes(
                files.get("autocad-activation-catalogue.json").unwrap(),
            ),
            files: inventory,
        };
        std::fs::write(
            root.path().join(PREVIEW_ACTIVATION_BINDING_PACKAGE_PATH),
            serde_json::to_vec_pretty(&binding).unwrap(),
        )
        .unwrap();
        (root, manifest, binding)
    }

    #[test]
    fn preview_activation_binding_json_has_a_closed_v2_shape() {
        let (_root, _manifest, binding) = preview_activation_tree();
        let value = serde_json::to_value(&binding).unwrap();
        serde_json::from_value::<PreviewActivationPackageBinding>(value.clone()).unwrap();
        for field in [
            "schema_version",
            "preview_binary_sha256",
            "catalogue_sha256",
            "files",
        ] {
            let mut missing = value.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(
                serde_json::from_value::<PreviewActivationPackageBinding>(missing).is_err(),
                "missing field {field} was accepted"
            );
        }
        let mut extra = value;
        extra
            .as_object_mut()
            .unwrap()
            .insert("support_claim".to_owned(), Value::Bool(true));
        assert!(serde_json::from_value::<PreviewActivationPackageBinding>(extra).is_err());
    }

    #[test]
    fn static_preview_activation_smoke_rejects_additions_missing_files_and_digest_drift() {
        let (root, manifest, _) = preview_activation_tree();
        validate_xref_preview_contents(root.path(), &manifest, PackageTarget::WindowsX64).unwrap();
        std::fs::write(
            root.path()
                .join(PREVIEW_ACTIVATION_DIRECTORY)
                .join("unexpected.json"),
            b"{}",
        )
        .unwrap();
        let error =
            validate_xref_preview_contents(root.path(), &manifest, PackageTarget::WindowsX64)
                .unwrap_err();
        assert!(
            error.to_string().contains("exact closed inventory"),
            "got: {error:#}"
        );

        let (root, manifest, _) = preview_activation_tree();
        std::fs::create_dir_all(
            root.path()
                .join(PREVIEW_ACTIVATION_DIRECTORY)
                .join("unexpected-empty-directory"),
        )
        .unwrap();
        let error =
            validate_xref_preview_contents(root.path(), &manifest, PackageTarget::WindowsX64)
                .unwrap_err();
        assert!(
            error.to_string().contains("exact closed inventory"),
            "got: {error:#}"
        );

        let (root, manifest, binding) = preview_activation_tree();
        let missing_path = root
            .path()
            .join(PREVIEW_ACTIVATION_DIRECTORY)
            .join(&binding.files[1].path);
        std::fs::remove_file(missing_path).unwrap();
        let error =
            validate_xref_preview_contents(root.path(), &manifest, PackageTarget::WindowsX64)
                .unwrap_err();
        assert!(
            error.to_string().contains("exact closed inventory"),
            "got: {error:#}"
        );

        let (root, manifest, mut binding) = preview_activation_tree();
        binding.catalogue_sha256 = "0".repeat(64);
        std::fs::write(
            root.path().join(PREVIEW_ACTIVATION_BINDING_PACKAGE_PATH),
            serde_json::to_vec_pretty(&binding).unwrap(),
        )
        .unwrap();
        let error =
            validate_xref_preview_contents(root.path(), &manifest, PackageTarget::WindowsX64)
                .unwrap_err();
        assert!(
            error.to_string().contains("does not match"),
            "got: {error:#}"
        );

        let (root, manifest, _) = preview_activation_tree();
        let binding_path = root.path().join(PREVIEW_ACTIVATION_BINDING_PACKAGE_PATH);
        let binding = std::fs::read_to_string(&binding_path).unwrap().replacen(
            "\"schema_version\": 2,",
            "\"schema_version\": 2, \"schema_version\": 2,",
            1,
        );
        std::fs::write(&binding_path, binding).unwrap();
        let error =
            validate_xref_preview_contents(root.path(), &manifest, PackageTarget::WindowsX64)
                .unwrap_err();
        assert!(
            format!("{error:#}").contains("duplicate JSON key"),
            "got: {error:#}"
        );
    }

    #[test]
    fn release_static_smoke_rejects_preview_activation_assets() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join(PREVIEW_ACTIVATION_DIRECTORY)).unwrap();
        let manifest = manifest_for(PackageTarget::WindowsX64, &metadata());
        let error = validate_xref_release_contents(
            root.path(),
            &manifest,
            PackageTarget::WindowsX64,
            PackageMode::Release,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("must not contain the public Preview activation subtree"),
            "got: {error:#}"
        );
    }

    #[test]
    fn static_xref_binding_validation_rehashes_every_archived_file() {
        let dir = tempfile::tempdir().unwrap();
        let certified_arg = dir.path().join("certified-profile.arg");
        let certification_manifest = dir.path().join("manifest.json");
        let release_evidence = dir.path().join("release-evidence.json");
        let transaction_evidence = dir.path().join("transaction-evidence.json");
        let attestation = dir.path().join("attestation.json");
        let release_binary = dir.path().join("autocad-mcp.exe");
        for (path, bytes) in [
            (&certified_arg, b"certified arg".as_slice()),
            (&certification_manifest, b"manifest".as_slice()),
            (&release_evidence, b"release evidence".as_slice()),
            (&transaction_evidence, b"transaction evidence".as_slice()),
            (&attestation, b"attestation".as_slice()),
            (&release_binary, b"release binary".as_slice()),
        ] {
            std::fs::write(path, bytes).unwrap();
        }
        let paths = XrefPackageBindingPaths {
            certified_arg: &certified_arg,
            certification_manifest: &certification_manifest,
            release_evidence: &release_evidence,
            transaction_evidence: &transaction_evidence,
            attestation: &attestation,
            release_binary: &release_binary,
        };
        let binding = XrefPackageBinding {
            schema_version: XREF_PACKAGE_BINDING_SCHEMA_VERSION,
            release_binary_sha256: xref_sha256_file(&release_binary).unwrap(),
            certified_arg_sha256: xref_sha256_file(&certified_arg).unwrap(),
            manifest_sha256: xref_sha256_file(&certification_manifest).unwrap(),
            release_evidence_sha256: xref_sha256_file(&release_evidence).unwrap(),
            transaction_evidence_sha256: xref_sha256_file(&transaction_evidence).unwrap(),
            attestation_sha256: xref_sha256_file(&attestation).unwrap(),
        };
        let certified_binary = binding.release_binary_sha256.clone();
        validate_xref_package_binding(&binding, &paths, &certified_binary, &certified_binary)
            .unwrap();

        for field in [
            "release_binary_sha256",
            "certified_arg_sha256",
            "manifest_sha256",
            "release_evidence_sha256",
            "transaction_evidence_sha256",
            "attestation_sha256",
        ] {
            let mut stale = binding.clone();
            match field {
                "release_binary_sha256" => stale.release_binary_sha256 = "0".repeat(64),
                "certified_arg_sha256" => stale.certified_arg_sha256 = "0".repeat(64),
                "manifest_sha256" => stale.manifest_sha256 = "0".repeat(64),
                "release_evidence_sha256" => stale.release_evidence_sha256 = "0".repeat(64),
                "transaction_evidence_sha256" => stale.transaction_evidence_sha256 = "0".repeat(64),
                "attestation_sha256" => stale.attestation_sha256 = "0".repeat(64),
                _ => unreachable!(),
            }
            let error =
                validate_xref_package_binding(&stale, &paths, &certified_binary, &certified_binary)
                    .unwrap_err();
            assert!(error.to_string().contains(field), "got: {error:#}");
        }

        let mut wrong_schema = binding.clone();
        wrong_schema.schema_version += 1;
        let error = validate_xref_package_binding(
            &wrong_schema,
            &paths,
            &certified_binary,
            &certified_binary,
        )
        .unwrap_err();
        assert!(error.to_string().contains("schema_version"));

        let error =
            validate_xref_package_binding(&binding, &paths, &"f".repeat(64), &certified_binary)
                .unwrap_err();
        assert!(error
            .to_string()
            .contains("release evidence and attestation"));
    }

    fn accepted_tool_payload() -> Value {
        use autocad_mcp::server::AutocadServer;

        let canonical = serde_json::to_value(AutocadServer::tool_router().list_all()).unwrap();
        let canonical = canonical.as_array().unwrap();
        Value::Array(
            EXPECTED_CALLABLE_TOOLS
                .iter()
                .map(|expected| {
                    canonical
                        .iter()
                        .find(|tool| tool["name"] == expected.name)
                        .unwrap()
                        .clone()
                })
                .collect(),
        )
    }

    #[test]
    fn mcp_initialize_response_requires_protocol_tools_and_server_info() {
        let accepted = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "autocad-mcp", "version": "0.0.1"}
            }
        });
        validate_mcp_initialize_response(&accepted).unwrap();

        for path in ["protocolVersion", "tools", "serverInfo"] {
            let mut invalid = accepted.clone();
            match path {
                "protocolVersion" => invalid["result"]["protocolVersion"] = Value::Null,
                "tools" => invalid["result"]["capabilities"]["tools"] = Value::Null,
                "serverInfo" => invalid["result"]["serverInfo"] = Value::Null,
                _ => unreachable!(),
            }
            let error = validate_mcp_initialize_response(&invalid).unwrap_err();
            assert!(error.to_string().contains(path), "got: {error:#}");
        }

        for (field, wrong) in [("name", "rmcp"), ("version", "1.7.0")] {
            let mut invalid = accepted.clone();
            invalid["result"]["serverInfo"][field] = Value::String(wrong.to_owned());
            let error = validate_mcp_initialize_response(&invalid).unwrap_err();
            assert!(error.to_string().contains(field), "got: {error:#}");
        }
    }

    #[test]
    fn mcp_read_tool_response_rejects_errors_and_non_array_text() {
        let accepted = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 3,
            "result": {
                "content": [{"type": "text", "text": "[{\"name\":\"Model\"}]"}],
                "isError": false
            }
        });
        validate_mcp_read_tool_response(&accepted, 3, "list_layouts").unwrap();

        let mut tool_error = accepted.clone();
        tool_error["result"]["isError"] = Value::Bool(true);
        let error = validate_mcp_read_tool_response(&tool_error, 3, "list_layouts").unwrap_err();
        assert!(error.to_string().contains("tool-level error"));

        let mut wrong_shape = accepted;
        wrong_shape["result"]["content"][0]["text"] = Value::String("{}".to_string());
        let error = validate_mcp_read_tool_response(&wrong_shape, 3, "list_layouts").unwrap_err();
        assert!(error.to_string().contains("JSON array"));
    }

    fn conforming_xref_payload() -> Value {
        serde_json::json!([
            {
                "handle": "F",
                "name": "SITE_MODEL",
                "saved_path": "refs/site.dwg",
                "path_mode": "relative",
                "reference_type": "attachment",
                "load_state": "unavailable",
                "instance_count": 2,
                "definition_base_point": {
                    "state": "available",
                    "point": {"x": 1.0, "y": 2.0, "z": 3.0}
                }
            },
            {
                "handle": "10",
                "name": "GRID_OVERLAY",
                "saved_path": "refs/grid.dwg",
                "path_mode": "relative",
                "reference_type": "overlay",
                "load_state": "unavailable",
                "instance_count": 1,
                "definition_base_point": {
                    "state": "available",
                    "point": {"x": 0.0, "y": 0.0, "z": 0.0}
                }
            },
            {
                "handle": "11",
                "name": "EMPTY_PATH",
                "saved_path": "",
                "path_mode": "unsupported",
                "reference_type": "attachment",
                "load_state": "unavailable",
                "instance_count": 1,
                "definition_base_point": {
                    "state": "available",
                    "point": {"x": -1.0, "y": -2.0, "z": -3.0}
                }
            }
        ])
    }

    #[test]
    fn accepted_tool_surface_has_51_tools_and_exactly_15_public_xref_names() {
        let accepted = accepted_tool_payload();
        validate_tool_surface(&accepted).unwrap();
        assert_eq!(EXPECTED_CALLABLE_TOOLS.len(), 51);
        assert_eq!(PUBLIC_XREF_TOOLS.len(), 15);
        assert_eq!(
            XREF_MUTATION_OPERATIONS.len(),
            9,
            "internal request validation must not become a tenth mutation operation"
        );
        assert_eq!(
            EXPECTED_CALLABLE_TOOLS
                .iter()
                .filter(|tool| tool.read_only_hint)
                .count(),
            36
        );
        assert_eq!(
            EXPECTED_CALLABLE_TOOLS
                .iter()
                .filter(|tool| tool.destructive_hint)
                .count(),
            12
        );
        assert_eq!(
            EXPECTED_CALLABLE_TOOLS
                .iter()
                .filter(|tool| !tool.idempotent_hint)
                .count(),
            4
        );
        assert!(EXPECTED_CALLABLE_TOOLS
            .iter()
            .all(|tool| tool.open_world_hint));
        let expected_xrefs = EXPECTED_CALLABLE_TOOLS
            .iter()
            .map(|tool| tool.name)
            .filter(|name| name.contains("xref"))
            .collect::<BTreeSet<_>>();
        let public_xrefs = PUBLIC_XREF_TOOLS.iter().copied().collect::<BTreeSet<_>>();
        assert_eq!(expected_xrefs, public_xrefs);

        let mut missing_xref_tool = accepted.clone();
        missing_xref_tool
            .as_array_mut()
            .unwrap()
            .retain(|tool| tool["name"] != "get_xref_instance");
        let err = validate_tool_surface(&missing_xref_tool).unwrap_err();
        assert!(
            err.to_string()
                .contains("missing expected callable tool get_xref_instance"),
            "got: {err:#}"
        );

        for reserved in RESERVED_XREF_CLIP_TOOLS {
            let mut payload = accepted.clone();
            payload
                .as_array_mut()
                .unwrap()
                .push(serde_json::json!({ "name": reserved }));
            let err = validate_tool_surface(&payload).unwrap_err();
            assert!(
                err.to_string().contains("reserved XREF clip tool"),
                "got: {err:#}"
            );
        }

        for obsolete in OBSOLETE_XREF_TOOLS {
            let mut payload = accepted.clone();
            payload
                .as_array_mut()
                .unwrap()
                .push(serde_json::json!({ "name": obsolete }));
            let err = validate_tool_surface(&payload).unwrap_err();
            assert!(
                err.to_string().contains("obsolete XREF tool"),
                "got: {err:#}"
            );
        }

        let mut unknown = accepted.clone();
        unknown
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({ "name": "inspect_xref_graph" }));
        let err = validate_tool_surface(&unknown).unwrap_err();
        assert!(
            err.to_string()
                .contains("unexpected tool inspect_xref_graph"),
            "got: {err:#}"
        );

        let mut duplicate = accepted;
        duplicate
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({ "name": "list_xrefs" }));
        let err = validate_tool_surface(&duplicate).unwrap_err();
        assert!(
            err.to_string().contains("duplicate tool list_xrefs"),
            "got: {err:#}"
        );
    }

    #[test]
    fn tool_surface_rejects_missing_null_non_boolean_wrong_and_extra_annotation_fields() {
        let mut missing_object = accepted_tool_payload();
        missing_object[0]
            .as_object_mut()
            .unwrap()
            .remove("annotations");
        let error = validate_tool_surface(&missing_object).unwrap_err();
        assert!(
            error.to_string().contains("requires an annotations object"),
            "got: {error:#}"
        );

        let mut missing_key = accepted_tool_payload();
        missing_key[0]["annotations"]
            .as_object_mut()
            .unwrap()
            .remove("readOnlyHint");
        let error = validate_tool_surface(&missing_key).unwrap_err();
        assert!(
            error.to_string().contains("exactly the four camelCase"),
            "got: {error:#}"
        );

        let mut null_value = accepted_tool_payload();
        null_value[0]["annotations"]["readOnlyHint"] = Value::Null;
        let error = validate_tool_surface(&null_value).unwrap_err();
        assert!(
            error.to_string().contains("must be a non-null Boolean"),
            "got: {error:#}"
        );

        let mut non_boolean_value = accepted_tool_payload();
        non_boolean_value[0]["annotations"]["readOnlyHint"] = Value::String("true".to_owned());
        let error = validate_tool_surface(&non_boolean_value).unwrap_err();
        assert!(
            error.to_string().contains("must be a non-null Boolean"),
            "got: {error:#}"
        );

        let mut wrong_value = accepted_tool_payload();
        wrong_value[0]["annotations"]["readOnlyHint"] = Value::Bool(false);
        let error = validate_tool_surface(&wrong_value).unwrap_err();
        assert!(
            error.to_string().contains("readOnlyHint must be true"),
            "got: {error:#}"
        );

        let mut extra_key = accepted_tool_payload();
        extra_key[0]["annotations"]
            .as_object_mut()
            .unwrap()
            .insert("read_only_hint".to_owned(), Value::Bool(true));
        let error = validate_tool_surface(&extra_key).unwrap_err();
        assert!(
            error.to_string().contains("exactly the four camelCase"),
            "got: {error:#}"
        );

        let mut inventory_error_after_bad_annotations = accepted_tool_payload();
        inventory_error_after_bad_annotations[0]["annotations"]["readOnlyHint"] =
            Value::Bool(false);
        inventory_error_after_bad_annotations
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({ "name": "get_xref_clip" }));
        let error = validate_tool_surface(&inventory_error_after_bad_annotations).unwrap_err();
        assert!(
            error.to_string().contains("reserved XREF clip tool"),
            "inventory errors must precede annotation errors: {error:#}"
        );
    }

    #[test]
    fn tool_surface_rejects_missing_malformed_and_drifted_descriptions_and_schemas() {
        let mut missing_description = accepted_tool_payload();
        missing_description[0]
            .as_object_mut()
            .unwrap()
            .remove("description");
        let error = validate_tool_surface(&missing_description).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("requires a nonempty string description"),
            "got: {error:#}"
        );

        for malformed in [Value::Null, Value::String("   ".to_owned())] {
            let mut malformed_description = accepted_tool_payload();
            malformed_description[0]["description"] = malformed;
            let error = validate_tool_surface(&malformed_description).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("requires a nonempty string description"),
                "got: {error:#}"
            );
        }

        let mut drifted_description = accepted_tool_payload();
        drifted_description[0]["description"] =
            Value::String("A different but nonempty description.".to_owned());
        let error = validate_tool_surface(&drifted_description).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("description drifted from the frozen runtime contract"),
            "got: {error:#}"
        );

        let mut missing_schema = accepted_tool_payload();
        missing_schema[0]
            .as_object_mut()
            .unwrap()
            .remove("inputSchema");
        let error = validate_tool_surface(&missing_schema).unwrap_err();
        assert!(
            error.to_string().contains("requires an inputSchema object"),
            "got: {error:#}"
        );

        let mut non_object_schema = accepted_tool_payload();
        non_object_schema[0]["inputSchema"] = Value::Array(Vec::new());
        let error = validate_tool_surface(&non_object_schema).unwrap_err();
        assert!(
            error.to_string().contains("requires an inputSchema object"),
            "got: {error:#}"
        );

        let mut missing_draft = accepted_tool_payload();
        missing_draft[0]["inputSchema"]
            .as_object_mut()
            .unwrap()
            .remove("$schema");
        let error = validate_tool_surface(&missing_draft).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("must declare JSON Schema Draft 2020-12"),
            "got: {error:#}"
        );

        let mut malformed_schema = accepted_tool_payload();
        malformed_schema[0]["inputSchema"]["type"] = serde_json::json!(7);
        let error = validate_tool_surface(&malformed_schema).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("is not valid JSON Schema Draft 2020-12"),
            "got: {error:#}"
        );

        let mut drifted_schema = accepted_tool_payload();
        drifted_schema[0]["inputSchema"]["$comment"] =
            Value::String("Valid schema drift".to_owned());
        let error = validate_tool_surface(&drifted_schema).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("inputSchema drifted from the frozen runtime contract"),
            "got: {error:#}"
        );
    }

    #[test]
    fn portable_layout_smoke_requires_the_exact_nonempty_fixture_projection() {
        let accepted = expected_portable_layout_smoke_records();
        validate_portable_layout_smoke_records(&accepted).unwrap();
        assert!(!accepted.as_array().unwrap().is_empty());

        let empty = serde_json::json!([]);
        let error = validate_portable_layout_smoke_records(&empty).unwrap_err();
        assert!(
            error.to_string().contains("exactly match"),
            "got: {error:#}"
        );

        let mut wrong_record = accepted.clone();
        wrong_record[0]["is_model"] = Value::Bool(true);
        let error = validate_portable_layout_smoke_records(&wrong_record).unwrap_err();
        assert!(
            error.to_string().contains("exactly match"),
            "got: {error:#}"
        );

        let mut extra_field = accepted;
        extra_field[0]["unexpected"] = Value::Bool(true);
        let error = validate_portable_layout_smoke_records(&extra_field).unwrap_err();
        assert!(
            error.to_string().contains("exactly match"),
            "got: {error:#}"
        );
    }

    #[test]
    fn portable_layer_smoke_requires_the_exact_nonempty_fixture_projection() {
        let accepted = expected_portable_layer_smoke_records();
        validate_portable_layer_smoke_records(&accepted).unwrap();
        assert_eq!(accepted.as_array().unwrap().len(), 2);

        let empty = serde_json::json!([]);
        let error = validate_portable_layer_smoke_records(&empty).unwrap_err();
        assert!(
            error.to_string().contains("exactly match"),
            "got: {error:#}"
        );

        let mut wrong_record = accepted.clone();
        wrong_record[1]["name"] = Value::String("WRONG_LAYER".to_owned());
        let error = validate_portable_layer_smoke_records(&wrong_record).unwrap_err();
        assert!(
            error.to_string().contains("exactly match"),
            "got: {error:#}"
        );

        let mut missing_record = accepted;
        missing_record.as_array_mut().unwrap().pop();
        let error = validate_portable_layer_smoke_records(&missing_record).unwrap_err();
        assert!(
            error.to_string().contains("exactly match"),
            "got: {error:#}"
        );
    }

    #[test]
    fn xref_record_smoke_requires_the_accepted_shape() {
        validate_xref_records(&conforming_xref_payload()).unwrap();

        let mut missing_saved_path = conforming_xref_payload();
        missing_saved_path[0]
            .as_object_mut()
            .unwrap()
            .remove("saved_path");
        let mut stale_path = conforming_xref_payload();
        stale_path[0]
            .as_object_mut()
            .unwrap()
            .insert("path".to_string(), serde_json::json!("refs/site.dwg"));
        let mut prefixed_handle = conforming_xref_payload();
        prefixed_handle[0]["handle"] = "0xF".into();
        let mut lowercase_handle = conforming_xref_payload();
        lowercase_handle[0]["handle"] = "f".into();
        let mut invalid_path_mode = conforming_xref_payload();
        invalid_path_mode[0]["path_mode"] = "host_relative".into();
        let mut invalid_reference_type = conforming_xref_payload();
        invalid_reference_type[0]["reference_type"] = "nested".into();
        let mut invalid_load_state = conforming_xref_payload();
        invalid_load_state[0]["load_state"] = "unresolved".into();
        let mut invalid_instance_count = conforming_xref_payload();
        invalid_instance_count[0]["instance_count"] = (-1).into();
        let mut invalid_base_point = conforming_xref_payload();
        invalid_base_point[0]["definition_base_point"]["extra"] = true.into();

        let invalid = [
            (serde_json::json!({}), "must be a JSON array"),
            (
                serde_json::json!([]),
                "must exactly match the ordered portable-evidence fixture records",
            ),
            (missing_saved_path, "must contain exactly the keys"),
            (stale_path, "must not contain obsolete field path"),
            (prefixed_handle, "uppercase hexadecimal without a prefix"),
            (lowercase_handle, "uppercase hexadecimal without a prefix"),
            (
                invalid_path_mode,
                "path_mode must be absolute, relative, filename_only, url, or unsupported",
            ),
            (
                invalid_reference_type,
                "reference_type must be attachment or overlay",
            ),
            (
                invalid_load_state,
                "load_state must be loaded, unloaded, or unavailable",
            ),
            (
                invalid_instance_count,
                "instance_count must be an unsigned integer",
            ),
            (
                invalid_base_point,
                "available definition_base_point must contain exactly state and point",
            ),
        ];

        for (payload, expected) in invalid {
            let err = validate_xref_records(&payload).unwrap_err();
            assert!(err.to_string().contains(expected), "got: {err:#}");
        }
    }

    #[test]
    fn xref_record_smoke_requires_exact_fixture_records_in_numeric_handle_order() {
        let mut reversed = conforming_xref_payload();
        reversed.as_array_mut().unwrap().reverse();
        let err = validate_xref_records(&reversed).unwrap_err();
        assert!(
            err.to_string().contains("ascending numeric handle order"),
            "got: {err:#}"
        );

        let mut lexically_sorted = conforming_xref_payload();
        lexically_sorted
            .as_array_mut()
            .unwrap()
            .sort_by(|left, right| {
                left["handle"]
                    .as_str()
                    .unwrap()
                    .cmp(right["handle"].as_str().unwrap())
            });
        let err = validate_xref_records(&lexically_sorted).unwrap_err();
        assert!(
            err.to_string().contains("ascending numeric handle order"),
            "got: {err:#}"
        );

        let mut missing_attachment = conforming_xref_payload();
        missing_attachment.as_array_mut().unwrap().pop();
        let err = validate_xref_records(&missing_attachment).unwrap_err();
        assert!(
            err.to_string().contains("must exactly match"),
            "got: {err:#}"
        );

        let mut duplicate_attachment = conforming_xref_payload();
        duplicate_attachment[1] = duplicate_attachment[0].clone();
        let err = validate_xref_records(&duplicate_attachment).unwrap_err();
        assert!(
            err.to_string().contains("ascending numeric handle order"),
            "got: {err:#}"
        );

        let mut wrong_overlay_saved_path = conforming_xref_payload();
        wrong_overlay_saved_path[1]["saved_path"] = "refs/wrong.dwg".into();
        let err = validate_xref_records(&wrong_overlay_saved_path).unwrap_err();
        assert!(
            err.to_string().contains("must exactly match"),
            "got: {err:#}"
        );
    }

    #[test]
    fn xref_instance_smoke_requires_exact_full_fixture_projection() {
        fn collect_object_field_paths(value: &Value, prefix: &str, paths: &mut Vec<String>) {
            match value {
                Value::Array(values) => {
                    for (index, value) in values.iter().enumerate() {
                        collect_object_field_paths(value, &format!("{prefix}/{index}"), paths);
                    }
                }
                Value::Object(object) => {
                    for (key, value) in object {
                        let path = format!("{prefix}/{key}");
                        paths.push(path.clone());
                        collect_object_field_paths(value, &path, paths);
                    }
                }
                _ => {}
            }
        }

        let accepted = expected_xref_instance_smoke_records();
        validate_xref_instance_smoke_records(&accepted).unwrap();

        let mut field_paths = Vec::new();
        collect_object_field_paths(&accepted, "", &mut field_paths);
        for path in field_paths {
            let (parent_path, key) = path.rsplit_once('/').unwrap();
            let mut missing_field = accepted.clone();
            let parent = if parent_path.is_empty() {
                &mut missing_field
            } else {
                missing_field.pointer_mut(parent_path).unwrap()
            };
            parent.as_object_mut().unwrap().remove(key).unwrap();
            let error = validate_xref_instance_smoke_records(&missing_field).unwrap_err();
            assert!(
                error.to_string().contains("must exactly match"),
                "missing {path}: {error:#}"
            );
        }

        for (pointer, replacement) in [
            ("/0/attachment_name", serde_json::json!("WRONG_ATTACHMENT")),
            ("/0/owner_type", serde_json::json!("model_space")),
            ("/0/layer_handle", serde_json::json!("7")),
            ("/0/insertion_point/x", serde_json::json!(101.0)),
            ("/0/scale/y", serde_json::json!(2.0)),
            ("/0/rotation_degrees", serde_json::json!(0.0)),
            ("/0/normal/z", serde_json::json!(-1.0)),
            ("/0/visibility", serde_json::json!("hidden")),
            ("/0/placement_kind", serde_json::json!("single")),
            ("/0/array/rows", serde_json::json!(1)),
            ("/0/unit_scaling/factor", serde_json::json!(0.001)),
        ] {
            let mut wrong_value = accepted.clone();
            *wrong_value.pointer_mut(pointer).unwrap() = replacement;
            let error = validate_xref_instance_smoke_records(&wrong_value).unwrap_err();
            assert!(
                error.to_string().contains("must exactly match"),
                "wrong {pointer}: {error:#}"
            );
        }

        let mut extra_field = accepted.clone();
        extra_field[0]["unexpected"] = Value::Bool(true);
        assert!(validate_xref_instance_smoke_records(&extra_field).is_err());

        let mut wrong_order = accepted;
        wrong_order.as_array_mut().unwrap().swap(0, 1);
        assert!(validate_xref_instance_smoke_records(&wrong_order).is_err());
    }

    fn portable_restoration_dxf(seed: &str, layer_records: &str) -> Vec<u8> {
        format!(
            "  0\nSECTION\n  2\nHEADER\n  9\n$ACADVER\n  1\nAC1027\n  9\n$HANDSEED\n  5\n{seed}\n  0\nENDSEC\n  0\nSECTION\n  2\nTABLES\n{layer_records}  0\nENDSEC\n  0\nEOF\n"
        )
        .into_bytes()
    }

    const PORTABLE_LAYERS_AB: &str =
        "  0\nLAYER\n  5\n10\n  2\nFIRST\n  0\nLAYER\n  5\n11\n  2\nSECOND\n";
    const PORTABLE_LAYERS_BA: &str =
        "  0\nLAYER\n  5\n11\n  2\nSECOND\n  0\nLAYER\n  5\n10\n  2\nFIRST\n";

    #[test]
    fn portable_dxf_restoration_allows_only_a_canonical_monotonic_handseed() {
        let before = portable_restoration_dxf("FF", PORTABLE_LAYERS_AB);
        let after = portable_restoration_dxf("100", PORTABLE_LAYERS_AB);
        require_ascii_dxf_restored_except_handseed(&before, &after, "FF").unwrap();

        let unchanged = portable_restoration_dxf("100", PORTABLE_LAYERS_AB);
        require_ascii_dxf_restored_except_handseed(&unchanged, &unchanged, "FF").unwrap();

        let before_crlf = String::from_utf8(before).unwrap().replace('\n', "\r\n");
        let after_crlf = String::from_utf8(after).unwrap().replace('\n', "\r\n");
        require_ascii_dxf_restored_except_handseed(
            before_crlf.as_bytes(),
            after_crlf.as_bytes(),
            "FF",
        )
        .unwrap();
    }

    #[test]
    fn portable_dxf_restoration_rejects_layer_reordering_and_unrelated_pair_drift() {
        let before = portable_restoration_dxf("20", PORTABLE_LAYERS_AB);

        let reordered = portable_restoration_dxf("21", PORTABLE_LAYERS_BA);
        let error =
            require_ascii_dxf_restored_except_handseed(&before, &reordered, "20").unwrap_err();
        assert!(
            error.to_string().contains("byte-for-byte outside"),
            "got: {error:#}"
        );

        let changed_layer =
            portable_restoration_dxf("21", &PORTABLE_LAYERS_AB.replace("FIRST", "UNRELATED"));
        let error =
            require_ascii_dxf_restored_except_handseed(&before, &changed_layer, "20").unwrap_err();
        assert!(
            error.to_string().contains("byte-for-byte outside"),
            "got: {error:#}"
        );

        let reformatted_group_code =
            String::from_utf8(portable_restoration_dxf("21", PORTABLE_LAYERS_AB))
                .unwrap()
                .replacen("$HANDSEED\n  5\n", "$HANDSEED\n5\n", 1);
        let error = require_ascii_dxf_restored_except_handseed(
            &before,
            reformatted_group_code.as_bytes(),
            "20",
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("byte-for-byte outside"),
            "got: {error:#}"
        );
    }

    #[test]
    fn portable_dxf_restoration_rejects_malformed_or_unsafe_handseed_changes() {
        let before = portable_restoration_dxf("20", PORTABLE_LAYERS_AB);
        let valid_after =
            String::from_utf8(portable_restoration_dxf("21", PORTABLE_LAYERS_AB)).unwrap();
        let duplicate_variable = valid_after.replacen(
            "$HANDSEED\n  5\n21\n",
            "$HANDSEED\n  5\n21\n  9\n$HANDSEED\n  5\n22\n",
            1,
        );
        let repeated_value =
            valid_after.replacen("$HANDSEED\n  5\n21\n", "$HANDSEED\n  5\n21\n  5\n22\n", 1);
        let wrong_value_code =
            valid_after.replacen("$HANDSEED\n  5\n21\n", "$HANDSEED\n  1\n21\n", 1);

        for (after, expected) in [
            (
                portable_restoration_dxf("2a", PORTABLE_LAYERS_AB),
                "canonical uppercase hexadecimal",
            ),
            (
                portable_restoration_dxf("021", PORTABLE_LAYERS_AB),
                "canonical uppercase hexadecimal",
            ),
            (
                portable_restoration_dxf("1F", PORTABLE_LAYERS_AB),
                "regressed below source value",
            ),
            (
                portable_restoration_dxf("20", PORTABLE_LAYERS_AB),
                "must remain above created layer handle",
            ),
            (duplicate_variable.into_bytes(), "must not repeat"),
            (repeated_value.into_bytes(), "must not repeat"),
            (
                wrong_value_code.into_bytes(),
                "must contain exactly one group-5 value",
            ),
        ] {
            let error =
                require_ascii_dxf_restored_except_handseed(&before, &after, "20").unwrap_err();
            assert!(error.to_string().contains(expected), "got: {error:#}");
        }
    }

    #[test]
    fn static_smoke_rejects_unsafe_zip_paths() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("package.mcpb");
        let file = std::fs::File::create(&package).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        zip.start_file("../manifest.json", options).unwrap();
        zip.write_all(b"{}\n").unwrap();
        zip.finish().unwrap();

        let err = smoke_package(SmokeOptions {
            package_path: package,
            fixture_path: None,
            require_executable: false,
            require_lsp_executable: false,
        })
        .unwrap_err();

        assert!(err.to_string().contains("unsafe zip path"), "got: {err:#}");
    }

    #[test]
    fn static_smoke_rejects_too_many_zip_entries() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("package.mcpb");
        let file = std::fs::File::create(&package).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        for i in 0..=MAX_ARCHIVE_ENTRIES {
            zip.start_file(format!("entry-{i}.txt"), options).unwrap();
            zip.write_all(b"").unwrap();
        }
        zip.finish().unwrap();

        let err = smoke_package(SmokeOptions {
            package_path: package,
            fixture_path: None,
            require_executable: false,
            require_lsp_executable: false,
        })
        .unwrap_err();

        assert!(err.to_string().contains("too many entries"), "got: {err:#}");
    }

    #[test]
    fn static_smoke_rejects_large_central_directory() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("package.mcpb");
        write_zip_with_large_declared_central_directory(&package);

        let err = smoke_package(SmokeOptions {
            package_path: package,
            fixture_path: None,
            require_executable: false,
            require_lsp_executable: false,
        })
        .unwrap_err();

        assert!(
            err.to_string().contains("central directory too large"),
            "got: {err:#}"
        );
    }

    #[test]
    fn static_smoke_rejects_duplicate_zip_paths() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("package.mcpb");
        write_duplicate_name_zip(&package);

        let err = smoke_package(SmokeOptions {
            package_path: package,
            fixture_path: None,
            require_executable: false,
            require_lsp_executable: false,
        })
        .unwrap_err();

        assert!(
            err.to_string().contains("duplicate zip path"),
            "got: {err:#}"
        );
    }

    #[test]
    fn static_smoke_rejects_ambiguous_zip_paths() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("package.mcpb");
        let file = std::fs::File::create(&package).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        zip.start_file("./manifest.json", options).unwrap();
        zip.write_all(b"{}\n").unwrap();
        zip.finish().unwrap();

        let err = smoke_package(SmokeOptions {
            package_path: package,
            fixture_path: None,
            require_executable: false,
            require_lsp_executable: false,
        })
        .unwrap_err();

        assert!(
            err.to_string().contains("ambiguous zip path"),
            "got: {err:#}"
        );
    }

    #[test]
    fn static_smoke_rejects_gitignore_at_any_depth() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("package.mcpb");
        let file = std::fs::File::create(&package).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        zip.start_file("plugin/skills/autocad-mcp/.gitignore", options)
            .unwrap();
        zip.write_all(b"*\n").unwrap();
        zip.finish().unwrap();

        let error = smoke_package(SmokeOptions {
            package_path: package,
            fixture_path: None,
            require_executable: false,
            require_lsp_executable: false,
        })
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("must not contain a .gitignore path"),
            "got: {error:#}"
        );
    }

    #[test]
    fn static_smoke_rejects_oversized_zip_entry() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("package.mcpb");
        let file = std::fs::File::create(&package).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        zip.start_file("manifest.json", options).unwrap();
        zip.write_all(&vec![b'x'; MAX_EXTRACTED_FILE_BYTES as usize + 1])
            .unwrap();
        zip.finish().unwrap();

        let err = smoke_package(SmokeOptions {
            package_path: package,
            fixture_path: None,
            require_executable: false,
            require_lsp_executable: false,
        })
        .unwrap_err();

        assert!(
            err.to_string().contains("extracted file too large"),
            "got: {err:#}"
        );
    }

    #[test]
    fn static_smoke_rejects_oversized_total_extraction() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("package.mcpb");
        let file = std::fs::File::create(&package).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        for i in 0..=MAX_EXTRACTED_BYTES / MAX_EXTRACTED_FILE_BYTES {
            zip.start_file(format!("file-{i}.txt"), options).unwrap();
            zip.write_all(&vec![b'x'; MAX_EXTRACTED_FILE_BYTES as usize])
                .unwrap();
        }
        zip.finish().unwrap();

        let err = smoke_package(SmokeOptions {
            package_path: package,
            fixture_path: None,
            require_executable: false,
            require_lsp_executable: false,
        })
        .unwrap_err();

        assert!(
            err.to_string().contains("extracted package too large"),
            "got: {err:#}"
        );
    }

    #[test]
    fn static_smoke_succeeds_for_macos_package() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("package.mcpb");
        let manifest = manifest_for(PackageTarget::MacosArm64, &metadata());
        write_package(&package, &manifest, Some("fake binary\n"), None, None);

        let report = smoke_package(SmokeOptions {
            package_path: package,
            fixture_path: None,
            require_executable: false,
            require_lsp_executable: false,
        })
        .unwrap();

        assert!(!report.executable_ran);
    }

    #[test]
    fn static_smoke_rejects_an_embedded_owner_approval_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("package.mcpb");
        let manifest = manifest_for(PackageTarget::MacosArm64, &metadata());
        write_package_with_license_and_documentation(
            &package,
            &manifest,
            Some("fake binary\n"),
            None,
            None,
            PROJECT_LICENSE,
            PROJECT_LICENSE_TEXT,
            DocumentationFixture::EmbeddedOwnerApproval,
        );

        let error = smoke_package(SmokeOptions {
            package_path: package,
            fixture_path: None,
            require_executable: false,
            require_lsp_executable: false,
        })
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("approval instance must not be present"),
            "{error:#}"
        );
    }

    #[test]
    fn static_smoke_rejects_autolisp_documentation_without_provenance_ledger() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("package.mcpb");
        let manifest = manifest_for(PackageTarget::MacosArm64, &metadata());
        write_package_with_license_and_documentation(
            &package,
            &manifest,
            Some("fake binary\n"),
            None,
            None,
            PROJECT_LICENSE,
            PROJECT_LICENSE_TEXT,
            DocumentationFixture::MissingLedger,
        );

        let error = smoke_package(SmokeOptions {
            package_path: package,
            fixture_path: None,
            require_executable: false,
            require_lsp_executable: false,
        })
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("missing package file: plugin/skills/autolisp/references/documentation-provenance.json"),
            "got: {error:#}"
        );
    }

    #[test]
    fn static_smoke_rejects_missing_autolisp_skill_directory() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("package.mcpb");
        let manifest = manifest_for(PackageTarget::MacosArm64, &metadata());
        write_package_with_license_and_documentation(
            &package,
            &manifest,
            Some("fake binary\n"),
            None,
            None,
            PROJECT_LICENSE,
            PROJECT_LICENSE_TEXT,
            DocumentationFixture::MissingSkillDirectory,
        );

        let error = smoke_package(SmokeOptions {
            package_path: package,
            fixture_path: None,
            require_executable: false,
            require_lsp_executable: false,
        })
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("missing package file: plugin/skills/autolisp/SKILL.md"),
            "got: {error:#}"
        );
    }

    #[test]
    fn static_smoke_rejects_reference_bytes_drifted_from_provenance_ledger() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("package.mcpb");
        let manifest = manifest_for(PackageTarget::MacosArm64, &metadata());
        write_package_with_license_and_documentation(
            &package,
            &manifest,
            Some("fake binary\n"),
            None,
            None,
            PROJECT_LICENSE,
            PROJECT_LICENSE_TEXT,
            DocumentationFixture::TamperedGuide,
        );

        let error = smoke_package(SmokeOptions {
            package_path: package,
            fixture_path: None,
            require_executable: false,
            require_lsp_executable: false,
        })
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("artifact \"references/guide.md\" byte digest mismatch"),
            "got: {error:#}"
        );
    }

    #[test]
    fn static_smoke_rejects_an_unapproved_file_below_the_autolisp_skill() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("package.mcpb");
        let manifest = manifest_for(PackageTarget::MacosArm64, &metadata());
        write_package_with_license_and_documentation(
            &package,
            &manifest,
            Some("fake binary\n"),
            None,
            None,
            PROJECT_LICENSE,
            PROJECT_LICENSE_TEXT,
            DocumentationFixture::UnapprovedReferenceFile,
        );

        let error = smoke_package(SmokeOptions {
            package_path: package,
            fixture_path: None,
            require_executable: false,
            require_lsp_executable: false,
        })
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("unapproved file exists below the AutoLISP skill"),
            "got: {error:#}"
        );
    }

    #[test]
    fn static_smoke_rejects_empty_plugin_license() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("package.mcpb");
        let manifest = manifest_for(PackageTarget::MacosArm64, &metadata());
        write_package_with_license(
            &package,
            &manifest,
            Some("fake binary\n"),
            None,
            None,
            PROJECT_LICENSE,
            b"",
        );

        let error = smoke_package(SmokeOptions {
            package_path: package,
            fixture_path: None,
            require_executable: false,
            require_lsp_executable: false,
        })
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("plugin LICENSE must be nonempty"),
            "got: {error:#}"
        );
    }

    #[test]
    fn static_smoke_rejects_plugin_manifest_license_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("package.mcpb");
        let manifest = manifest_for(PackageTarget::MacosArm64, &metadata());
        write_package_with_license(
            &package,
            &manifest,
            Some("fake binary\n"),
            None,
            None,
            "GPL-3.0-only",
            b"license\n",
        );

        let error = smoke_package(SmokeOptions {
            package_path: package,
            fixture_path: None,
            require_executable: false,
            require_lsp_executable: false,
        })
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("plugin license must be GPL-3.0-or-later"),
            "got: {error:#}"
        );
    }

    #[test]
    fn static_smoke_rejects_noncanonical_plugin_license_text() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("package.mcpb");
        let manifest = manifest_for(PackageTarget::MacosArm64, &metadata());
        write_package_with_license(
            &package,
            &manifest,
            Some("fake binary\n"),
            None,
            None,
            PROJECT_LICENSE,
            b"license\n",
        );

        let error = smoke_package(SmokeOptions {
            package_path: package,
            fixture_path: None,
            require_executable: false,
            require_lsp_executable: false,
        })
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("must match the canonical repository GPLv3 text"),
            "got: {error:#}"
        );
    }

    #[test]
    fn static_smoke_accepts_lsp_config_when_binary_present() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("package.mcpb");
        let manifest = manifest_for(PackageTarget::MacosArm64, &metadata());
        write_package(
            &package,
            &manifest,
            Some("fake binary\n"),
            Some(
                r#"{"autolisp-lsp":{"command":"${CLAUDE_PLUGIN_ROOT}/bin/autolisp-lsp","args":[],"extensionToLanguage":{".lsp":"autolisp"},"transport":"stdio"}}"#,
            ),
            Some("#!/bin/sh\nexit 0\n"),
        );

        let report = smoke_package(SmokeOptions {
            package_path: package,
            fixture_path: None,
            require_executable: false,
            require_lsp_executable: false,
        })
        .unwrap();
        assert!(!report.executable_ran);
        assert!(!report.lsp_executable_ran);
    }

    #[test]
    fn static_smoke_rejects_lsp_config_without_binary() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("package.mcpb");
        let manifest = manifest_for(PackageTarget::MacosArm64, &metadata());
        write_package(
            &package,
            &manifest,
            Some("fake binary\n"),
            Some(
                r#"{"autolisp-lsp":{"command":"${CLAUDE_PLUGIN_ROOT}/bin/autolisp-lsp","args":[],"extensionToLanguage":{".lsp":"autolisp"},"transport":"stdio"}}"#,
            ),
            None,
        );

        let err = smoke_package(SmokeOptions {
            package_path: package,
            fixture_path: None,
            require_executable: false,
            require_lsp_executable: false,
        })
        .unwrap_err();
        assert!(err.to_string().contains("missing plugin/bin/autolisp-lsp"));
    }

    #[test]
    fn static_smoke_rejects_lsp_config_with_wrong_server_key() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("package.mcpb");
        let manifest = manifest_for(PackageTarget::MacosArm64, &metadata());
        write_package(
            &package,
            &manifest,
            Some("fake binary\n"),
            Some(
                r#"{"other-lsp":{"command":"${CLAUDE_PLUGIN_ROOT}/bin/autolisp-lsp","args":[],"extensionToLanguage":{".lsp":"autolisp"},"transport":"stdio"}}"#,
            ),
            Some("#!/bin/sh\nexit 0\n"),
        );

        let err = smoke_package(SmokeOptions {
            package_path: package,
            fixture_path: None,
            require_executable: false,
            require_lsp_executable: false,
        })
        .unwrap_err();
        assert!(
            err.to_string().contains("missing autolisp-lsp entry"),
            "got: {err:#}"
        );
    }

    #[test]
    fn static_smoke_rejects_lsp_config_with_wrong_language_mapping() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("package.mcpb");
        let manifest = manifest_for(PackageTarget::MacosArm64, &metadata());
        write_package(
            &package,
            &manifest,
            Some("fake binary\n"),
            Some(
                r#"{"autolisp-lsp":{"command":"${CLAUDE_PLUGIN_ROOT}/bin/autolisp-lsp","args":[],"extensionToLanguage":{".lsp":"plaintext"},"transport":"stdio"}}"#,
            ),
            Some("#!/bin/sh\nexit 0\n"),
        );

        let err = smoke_package(SmokeOptions {
            package_path: package,
            fixture_path: None,
            require_executable: false,
            require_lsp_executable: false,
        })
        .unwrap_err();
        assert!(
            err.to_string().contains("must map .lsp to autolisp"),
            "got: {err:#}"
        );
    }

    #[test]
    fn static_smoke_rejects_lsp_config_with_non_stdio_transport() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("package.mcpb");
        let manifest = manifest_for(PackageTarget::MacosArm64, &metadata());
        write_package(
            &package,
            &manifest,
            Some("fake binary\n"),
            Some(
                r#"{"autolisp-lsp":{"command":"${CLAUDE_PLUGIN_ROOT}/bin/autolisp-lsp","args":[],"extensionToLanguage":{".lsp":"autolisp"},"transport":"tcp"}}"#,
            ),
            Some("#!/bin/sh\nexit 0\n"),
        );

        let err = smoke_package(SmokeOptions {
            package_path: package,
            fixture_path: None,
            require_executable: false,
            require_lsp_executable: false,
        })
        .unwrap_err();
        assert!(
            err.to_string().contains("transport must be stdio"),
            "got: {err:#}"
        );
    }

    #[test]
    fn static_smoke_rejects_lsp_config_with_missing_transport() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("package.mcpb");
        let manifest = manifest_for(PackageTarget::MacosArm64, &metadata());
        write_package(
            &package,
            &manifest,
            Some("fake binary\n"),
            Some(
                r#"{"autolisp-lsp":{"command":"${CLAUDE_PLUGIN_ROOT}/bin/autolisp-lsp","args":[],"extensionToLanguage":{".lsp":"autolisp"}}}"#,
            ),
            Some("#!/bin/sh\nexit 0\n"),
        );

        let err = smoke_package(SmokeOptions {
            package_path: package,
            fixture_path: None,
            require_executable: false,
            require_lsp_executable: false,
        })
        .unwrap_err();
        assert!(
            err.to_string().contains("transport must be stdio"),
            "got: {err:#}"
        );
    }

    #[test]
    fn static_smoke_rejects_lsp_config_with_non_string_transport() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("package.mcpb");
        let manifest = manifest_for(PackageTarget::MacosArm64, &metadata());
        write_package(
            &package,
            &manifest,
            Some("fake binary\n"),
            Some(
                r#"{"autolisp-lsp":{"command":"${CLAUDE_PLUGIN_ROOT}/bin/autolisp-lsp","args":[],"extensionToLanguage":{".lsp":"autolisp"},"transport":true}}"#,
            ),
            Some("#!/bin/sh\nexit 0\n"),
        );

        let err = smoke_package(SmokeOptions {
            package_path: package,
            fixture_path: None,
            require_executable: false,
            require_lsp_executable: false,
        })
        .unwrap_err();
        assert!(
            err.to_string().contains("transport must be stdio"),
            "got: {err:#}"
        );
    }

    #[test]
    fn static_smoke_rejects_lsp_config_with_missing_command() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("package.mcpb");
        let manifest = manifest_for(PackageTarget::MacosArm64, &metadata());
        write_package(
            &package,
            &manifest,
            Some("fake binary\n"),
            Some(
                r#"{"autolisp-lsp":{"args":[],"extensionToLanguage":{".lsp":"autolisp"},"transport":"stdio"}}"#,
            ),
            Some("#!/bin/sh\nexit 0\n"),
        );

        let err = smoke_package(SmokeOptions {
            package_path: package,
            fixture_path: None,
            require_executable: false,
            require_lsp_executable: false,
        })
        .unwrap_err();
        assert!(err.to_string().contains("command must be"), "got: {err:#}");
    }

    #[test]
    fn static_smoke_rejects_lsp_config_with_wrong_command() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("package.mcpb");
        let manifest = manifest_for(PackageTarget::MacosArm64, &metadata());
        write_package(
            &package,
            &manifest,
            Some("fake binary\n"),
            Some(
                r#"{"autolisp-lsp":{"command":"${CLAUDE_PLUGIN_ROOT}/bin/other-lsp","args":[],"extensionToLanguage":{".lsp":"autolisp"},"transport":"stdio"}}"#,
            ),
            Some("#!/bin/sh\nexit 0\n"),
        );

        let err = smoke_package(SmokeOptions {
            package_path: package,
            fixture_path: None,
            require_executable: false,
            require_lsp_executable: false,
        })
        .unwrap_err();
        assert!(err.to_string().contains("command must be"), "got: {err:#}");
    }

    #[test]
    fn static_smoke_rejects_lsp_config_with_non_string_command() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("package.mcpb");
        let manifest = manifest_for(PackageTarget::MacosArm64, &metadata());
        write_package(
            &package,
            &manifest,
            Some("fake binary\n"),
            Some(
                r#"{"autolisp-lsp":{"command":true,"args":[],"extensionToLanguage":{".lsp":"autolisp"},"transport":"stdio"}}"#,
            ),
            Some("#!/bin/sh\nexit 0\n"),
        );

        let err = smoke_package(SmokeOptions {
            package_path: package,
            fixture_path: None,
            require_executable: false,
            require_lsp_executable: false,
        })
        .unwrap_err();
        assert!(err.to_string().contains("command must be"), "got: {err:#}");
    }

    #[test]
    fn lsp_initialize_response_requires_jsonrpc_id_capabilities_and_server_name() {
        for response in [
            br#"{"id":1,"result":{"capabilities":{},"serverInfo":{"name":"autolisp-lsp"}}}"#
                .as_slice(),
            br#"{"jsonrpc":"2.0","id":2,"result":{"capabilities":{},"serverInfo":{"name":"autolisp-lsp"}}}"#
                .as_slice(),
            br#"{"jsonrpc":"2.0","id":1,"result":{"serverInfo":{"name":"autolisp-lsp"}}}"#
                .as_slice(),
            br#"{"jsonrpc":"2.0","id":1,"result":{"capabilities":[],"serverInfo":{"name":"autolisp-lsp"}}}"#
                .as_slice(),
            br#"{"jsonrpc":"2.0","id":1,"result":{"capabilities":{},"serverInfo":{"name":"other-lsp"}}}"#
                .as_slice(),
        ] {
            let err = validate_lsp_initialize_response(response).unwrap_err();
            assert!(
                err.to_string().contains("initialize response"),
                "got: {err:#}"
            );
        }

        validate_lsp_initialize_response(
            br#"{"jsonrpc":"2.0","id":1,"result":{"capabilities":{},"serverInfo":{"name":"autolisp-lsp"}}}"#,
        )
        .unwrap();
    }

    #[test]
    fn native_lsp_smoke_rejects_a_missing_binary() {
        let dir = tempfile::tempdir().unwrap();
        let error = smoke_lsp_binary(&dir.path().join("missing-lsp")).unwrap_err();
        assert!(
            error.to_string().contains("must exist and be a file"),
            "{error:#}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn native_lsp_smoke_runs_initialize_shutdown_and_exit() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("autolisp-lsp");
        std::fs::write(
            &binary,
            r#"#!/bin/sh
body='{"jsonrpc":"2.0","id":1,"result":{"capabilities":{},"serverInfo":{"name":"autolisp-lsp","version":"0.0.1"}}}'
printf 'Content-Length: %s\r\n\r\n%s' "${#body}" "$body"
cat >/dev/null
"#,
        )
        .unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
        smoke_lsp_binary(&binary).unwrap();
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn required_lsp_executable_smoke_succeeds_with_fake_packaged_binary() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("package.mcpb");
        let manifest = manifest_for(PackageTarget::MacosArm64, &metadata());
        write_package(
            &package,
            &manifest,
            Some("fake binary\n"),
            Some(
                r#"{"autolisp-lsp":{"command":"${CLAUDE_PLUGIN_ROOT}/bin/autolisp-lsp","args":[],"extensionToLanguage":{".lsp":"autolisp"},"transport":"stdio"}}"#,
            ),
            Some(
                r#"#!/bin/sh
body='{"jsonrpc":"2.0","id":1,"result":{"capabilities":{},"serverInfo":{"name":"autolisp-lsp","version":"0.0.1"}}}'
printf 'Content-Length: %s\r\n\r\n%s' "${#body}" "$body"
cat >/dev/null
"#,
            ),
        );

        let report = smoke_package(SmokeOptions {
            package_path: package,
            fixture_path: None,
            require_executable: false,
            require_lsp_executable: true,
        })
        .unwrap();
        assert!(!report.executable_ran);
        assert!(report.lsp_executable_ran);
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn required_lsp_executable_smoke_runs_when_optional_fixture_is_invalid() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("package.mcpb");
        let manifest = manifest_for(PackageTarget::MacosArm64, &metadata());
        write_package(
            &package,
            &manifest,
            Some("fake binary\n"),
            Some(
                r#"{"autolisp-lsp":{"command":"${CLAUDE_PLUGIN_ROOT}/bin/autolisp-lsp","args":[],"extensionToLanguage":{".lsp":"autolisp"},"transport":"stdio"}}"#,
            ),
            Some(
                r#"#!/bin/sh
body='{"jsonrpc":"2.0","id":1,"result":{"capabilities":{},"serverInfo":{"name":"autolisp-lsp","version":"0.0.1"}}}'
printf 'Content-Length: %s\r\n\r\n%s' "${#body}" "$body"
cat >/dev/null
"#,
            ),
        );

        let report = smoke_package(SmokeOptions {
            package_path: package,
            fixture_path: Some(dir.path().join("missing-fixture.dxf")),
            require_executable: false,
            require_lsp_executable: true,
        })
        .unwrap();
        assert!(!report.executable_ran);
        assert!(report.lsp_executable_ran);
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn required_lsp_executable_smoke_rejects_invalid_stdout_from_running_binary() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("package.mcpb");
        let manifest = manifest_for(PackageTarget::MacosArm64, &metadata());
        write_package(
            &package,
            &manifest,
            Some("fake binary\n"),
            Some(
                r#"{"autolisp-lsp":{"command":"${CLAUDE_PLUGIN_ROOT}/bin/autolisp-lsp","args":[],"extensionToLanguage":{".lsp":"autolisp"},"transport":"stdio"}}"#,
            ),
            Some(
                r#"#!/bin/sh
printf 'Content-Length: nope\r\n\r\n'
sleep 5
"#,
            ),
        );

        let start = std::time::Instant::now();
        let err = smoke_package(SmokeOptions {
            package_path: package,
            fixture_path: None,
            require_executable: false,
            require_lsp_executable: true,
        })
        .unwrap_err();
        let elapsed = start.elapsed();

        assert!(
            elapsed < std::time::Duration::from_secs(3),
            "elapsed: {elapsed:?}, error: {err:#}"
        );
        let err = format!("{err:#}");
        assert!(err.contains("Content-Length"), "got: {err}");
    }

    #[test]
    fn required_lsp_executable_errors_when_lsp_config_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("package.mcpb");
        let manifest = manifest_for(PackageTarget::MacosArm64, &metadata());
        write_package(&package, &manifest, Some("fake binary\n"), None, None);

        let err = smoke_package(SmokeOptions {
            package_path: package,
            fixture_path: None,
            require_executable: false,
            require_lsp_executable: true,
        })
        .unwrap_err();
        assert!(err.to_string().contains("plugin/.lsp.json"), "got: {err:#}");
    }

    #[cfg(unix)]
    #[test]
    fn generated_macos_v1_package_contains_lsp_artifacts_and_static_smokes() {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("autocad-mcp");
        let lsp_binary = dir.path().join("autolisp-lsp");
        write_release_introspection_binary(&binary);
        std::fs::write(&lsp_binary, "fake lsp binary\n").unwrap();
        let package = create_package(PackageOptions {
            mode: PackageMode::Release,
            target: PackageTarget::MacosArm64,
            plugin_dir: repo_root().join("plugin"),
            schema_root: repo_root().join("tests/fixtures/plugin-example"),
            binary_path: binary,
            lsp_binary_path: Some(lsp_binary),
            out_dir: dir.path().join("dist"),
        })
        .unwrap();

        let names = zip_names(&package);
        assert!(names.contains(&"plugin/.lsp.json".to_string()), "{names:?}");
        assert!(
            names.contains(&"plugin/bin/autolisp-lsp".to_string()),
            "{names:?}"
        );

        let report = smoke_package(SmokeOptions {
            package_path: package,
            fixture_path: None,
            require_executable: false,
            require_lsp_executable: false,
        })
        .unwrap();

        assert!(!report.executable_ran);
        assert!(!report.lsp_executable_ran);
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn generated_macos_v1_package_passes_required_lsp_smoke() {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("autocad-mcp");
        let lsp_binary = dir.path().join("autolisp-lsp");
        write_release_introspection_binary(&binary);
        std::fs::write(
            &lsp_binary,
            r#"#!/bin/sh
body='{"jsonrpc":"2.0","id":1,"result":{"capabilities":{},"serverInfo":{"name":"autolisp-lsp","version":"0.0.1"}}}'
printf 'Content-Length: %s\r\n\r\n%s' "${#body}" "$body"
cat >/dev/null
"#,
        )
        .unwrap();

        let package = create_package(PackageOptions {
            mode: PackageMode::Release,
            target: PackageTarget::MacosArm64,
            plugin_dir: repo_root().join("plugin"),
            schema_root: repo_root().join("tests/fixtures/plugin-example"),
            binary_path: binary,
            lsp_binary_path: Some(lsp_binary),
            out_dir: dir.path().join("dist"),
        })
        .unwrap();

        let report = smoke_package(SmokeOptions {
            package_path: package,
            fixture_path: None,
            require_executable: false,
            require_lsp_executable: true,
        })
        .unwrap();

        assert!(!report.executable_ran);
        assert!(report.lsp_executable_ran);
    }

    #[test]
    fn generated_windows_release_package_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("autocad-mcp.exe");
        let lsp_binary = dir.path().join("autolisp-lsp.exe");
        std::fs::write(&binary, "fake binary\n").unwrap();
        std::fs::write(&lsp_binary, "fake lsp binary\n").unwrap();
        let out_dir = dir.path().join("dist");
        let error = create_package(PackageOptions {
            mode: PackageMode::Release,
            target: PackageTarget::WindowsX64,
            plugin_dir: repo_root().join("plugin"),
            schema_root: repo_root().join("tests/fixtures/plugin-example"),
            binary_path: binary,
            lsp_binary_path: Some(lsp_binary),
            out_dir: out_dir.clone(),
        })
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("Windows Release packaging is unavailable"),
            "got: {error:#}"
        );
        assert!(!out_dir.exists());
    }

    #[test]
    fn mode_validation_preserves_caller_context_before_static_contracts() {
        let root = tempfile::tempdir().unwrap();
        let manifest =
            manifest_for_mode(PackageTarget::WindowsX64, PackageMode::Preview, &metadata());
        std::fs::write(
            root.path().join("manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();

        let error =
            validate_approval_package(root.path(), "1.0.0", PackageMode::Release).unwrap_err();
        assert_eq!(
            error.to_string(),
            "approval-bound MCPB mode Preview does not match owner approval mode Release"
        );

        let error = validate_extracted_package(
            root.path(),
            DistributionEvidenceMode::ExactCompiled,
            true,
            Some(ModeRequirement::Required(PackageMode::Release)),
        )
        .err()
        .expect("cross-mode exact-compiled validation must fail");
        assert_eq!(
            error.to_string(),
            "MCPB mode Preview does not match required mode Release"
        );

        let error =
            validate_approval_package(root.path(), "0.0.1", PackageMode::Preview).unwrap_err();
        assert!(
            error.to_string().contains("missing package file"),
            "matching Preview mode must advance into the common static contract: {error:#}"
        );
    }

    #[test]
    fn static_smoke_catches_missing_manifest_entry_binary() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("package.mcpb");
        let manifest = manifest_for(PackageTarget::MacosArm64, &metadata());
        write_package(&package, &manifest, None, None, None);

        let err = smoke_package(SmokeOptions {
            package_path: package,
            fixture_path: None,
            require_executable: false,
            require_lsp_executable: false,
        })
        .unwrap_err();

        assert!(err.to_string().contains("missing binary"), "got: {err:#}");
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    #[test]
    fn required_executable_smoke_errors_on_host_target_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("package.mcpb");
        let target = match host_target() {
            Some(PackageTarget::MacosArm64) => PackageTarget::WindowsX64,
            Some(PackageTarget::WindowsX64) | None => PackageTarget::MacosArm64,
        };
        let manifest = manifest_for(target, &metadata());
        write_package(&package, &manifest, Some("fake binary\n"), None, None);

        let err = smoke_package(SmokeOptions {
            package_path: package,
            fixture_path: Some(dir.path().join("fixture.dxf")),
            require_executable: true,
            require_lsp_executable: false,
        })
        .unwrap_err();

        assert!(
            err.to_string().contains("does not match host target"),
            "got: {err:#}"
        );
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn static_smoke_rejects_current_windows_release_before_host_skip() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("package.mcpb");
        let manifest = manifest_for(PackageTarget::WindowsX64, &metadata());
        write_package(&package, &manifest, Some("fake binary\n"), None, None);

        let error = smoke_package(SmokeOptions {
            package_path: package,
            fixture_path: Some(dir.path().join("fixture.dxf")),
            require_executable: false,
            require_lsp_executable: false,
        })
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("Windows Release MCPB version must be stable and at least 1.0.0"),
            "{error:#}"
        );
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn required_executable_smoke_errors_when_fixture_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("package.mcpb");
        let manifest = manifest_for(PackageTarget::MacosArm64, &metadata());
        write_package(
            &package,
            &manifest,
            Some(
                r#"#!/bin/sh
exit 42
"#,
            ),
            None,
            None,
        );

        let err = smoke_package(SmokeOptions {
            package_path: package,
            fixture_path: Some(dir.path().join("missing.dxf")),
            require_executable: true,
            require_lsp_executable: false,
        })
        .unwrap_err();

        assert!(err.to_string().contains("fixture path"), "got: {err:#}");
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn non_required_executable_smoke_skips_when_fixture_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("package.mcpb");
        let manifest = manifest_for(PackageTarget::MacosArm64, &metadata());
        write_package(
            &package,
            &manifest,
            Some(
                r#"#!/bin/sh
exit 42
"#,
            ),
            None,
            None,
        );

        let report = smoke_package(SmokeOptions {
            package_path: package,
            fixture_path: Some(dir.path().join("missing.dxf")),
            require_executable: false,
            require_lsp_executable: false,
        })
        .unwrap();

        assert!(!report.executable_ran);
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn required_executable_smoke_errors_when_fixture_is_directory() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("package.mcpb");
        let fixture_dir = dir.path().join("fixture-dir");
        std::fs::create_dir(&fixture_dir).unwrap();
        let manifest = manifest_for(PackageTarget::MacosArm64, &metadata());
        write_package(
            &package,
            &manifest,
            Some(
                r#"#!/bin/sh
exit 42
"#,
            ),
            None,
            None,
        );

        let err = smoke_package(SmokeOptions {
            package_path: package,
            fixture_path: Some(fixture_dir),
            require_executable: true,
            require_lsp_executable: false,
        })
        .unwrap_err();

        assert!(err.to_string().contains("fixture path"), "got: {err:#}");
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn non_required_executable_smoke_skips_when_fixture_is_directory() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("package.mcpb");
        let fixture_dir = dir.path().join("fixture-dir");
        std::fs::create_dir(&fixture_dir).unwrap();
        let manifest = manifest_for(PackageTarget::MacosArm64, &metadata());
        write_package(
            &package,
            &manifest,
            Some(
                r#"#!/bin/sh
exit 42
"#,
            ),
            None,
            None,
        );

        let report = smoke_package(SmokeOptions {
            package_path: package,
            fixture_path: Some(fixture_dir),
            require_executable: false,
            require_lsp_executable: false,
        })
        .unwrap();

        assert!(!report.executable_ran);
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn executable_smoke_times_out_hung_binary() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("package.mcpb");
        let fixture = dir.path().join("fixture.dxf");
        std::fs::write(&fixture, "fixture\n").unwrap();
        let manifest = manifest_for(PackageTarget::MacosArm64, &metadata());
        write_package(
            &package,
            &manifest,
            Some(
                r#"#!/bin/sh
sleep 5
"#,
            ),
            None,
            None,
        );

        let err = smoke_package(SmokeOptions {
            package_path: package,
            fixture_path: Some(fixture),
            require_executable: true,
            require_lsp_executable: false,
        })
        .unwrap_err();

        let err = format!("{err:#}");
        assert!(err.contains("timed out"), "got: {err}");
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn executable_smoke_rejects_oversized_stdout() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("package.mcpb");
        let fixture = dir.path().join("fixture.dxf");
        std::fs::write(&fixture, "fixture\n").unwrap();
        let manifest = manifest_for(PackageTarget::MacosArm64, &metadata());
        let binary_script = format!(
            "#!/bin/sh\nprintf '%0{}d' 0\nexit 0\n",
            MAX_CAPTURED_OUTPUT_BYTES + 1
        );
        write_package(&package, &manifest, Some(&binary_script), None, None);

        let err = smoke_package(SmokeOptions {
            package_path: package,
            fixture_path: Some(fixture),
            require_executable: true,
            require_lsp_executable: false,
        })
        .unwrap_err();

        let err = format!("{err:#}");
        assert!(err.contains("stdout too large"), "got: {err}");
    }

    #[cfg(unix)]
    #[test]
    fn executable_check_requires_owner_execute_bit() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("binary");
        std::fs::write(&binary, "fake binary\n").unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o011)).unwrap();

        let err = ensure_unix_executable(&binary).unwrap_err();

        assert!(
            err.to_string().contains("binary is not executable"),
            "got: {err:#}"
        );
    }

    #[test]
    fn existing_relative_fixture_path_is_canonicalized_before_executable_calls() {
        let relative_dir = tempfile::Builder::new()
            .prefix("release-packager-relative-fixture-")
            .tempdir_in(".")
            .unwrap();
        let stored_fixture = relative_dir.path().join("fixture.dxf");
        std::fs::write(&stored_fixture, "fixture\n").unwrap();
        let expected = std::fs::canonicalize(&stored_fixture).unwrap();
        let current_dir = std::fs::canonicalize(std::env::current_dir().unwrap()).unwrap();
        let fixture = expected.strip_prefix(current_dir).unwrap().to_path_buf();
        assert!(!fixture.is_absolute(), "got: {}", fixture.display());

        let canonical = canonical_fixture_path(&fixture).unwrap();

        assert!(canonical.is_absolute(), "got: {}", canonical.display());
        assert_eq!(canonical, expected);
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn executable_smoke_does_not_wait_on_inherited_output_handles() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("package.mcpb");
        let fixture = dir.path().join("fixture.dxf");
        std::fs::write(&fixture, "fixture\n").unwrap();
        let manifest = manifest_for(PackageTarget::MacosArm64, &metadata());
        write_package(
            &package,
            &manifest,
            Some(
                r#"#!/bin/sh
if [ "$1" = "list-tools" ]; then
  [ -n "$2" ] && exit 2
  (sleep 5) &
  exit 0
fi
exit 2
"#,
            ),
            None,
            None,
        );

        let start = std::time::Instant::now();
        let err = smoke_package(SmokeOptions {
            package_path: package,
            fixture_path: Some(fixture),
            require_executable: true,
            require_lsp_executable: false,
        })
        .unwrap_err();
        let elapsed = start.elapsed();

        assert!(
            elapsed < std::time::Duration::from_secs(3),
            "elapsed: {elapsed:?}, error: {err:#}"
        );
        let err = format!("{err:#}");
        assert!(
            err.contains("parse list-tools stdout")
                || err.contains("missing expected callable tool")
                || err.contains("output streams did not close"),
            "got: {err}"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_run_with_timeout_rejects_oversized_stdout() {
        let mut command = Command::new("cmd");
        command.args([
            "/C",
            "for /L %i in (1,1,6000) do @echo xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        ]);

        let err =
            run_with_timeout(&mut command, "oversized stdout", SUBPROCESS_TIMEOUT).unwrap_err();

        let err = format!("{err:#}");
        assert!(err.contains("stdout too large"), "got: {err}");
    }

    #[cfg(windows)]
    #[test]
    fn windows_run_with_timeout_terminates_process_tree_after_direct_child_exit() {
        let mut command = Command::new("cmd");
        command.args([
            "/C",
            "start /B cmd /C \"ping -n 6 127.0.0.1 >NUL\" & exit /B 0",
        ]);

        let start = std::time::Instant::now();
        let output =
            run_with_timeout(&mut command, "descendant handle", SUBPROCESS_TIMEOUT).unwrap();
        let elapsed = start.elapsed();

        assert!(
            elapsed < std::time::Duration::from_secs(3),
            "elapsed: {elapsed:?}"
        );
        assert!(output.status.success());
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn executable_smoke_succeeds_with_xref_fixture_and_fake_packaged_binary() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("package.mcpb");
        let source_fixture = repo_root().join("tests/fixtures/xrefs/portable-evidence-ascii.dxf");
        assert!(
            source_fixture.is_file(),
            "missing fixture: {}",
            source_fixture.display()
        );
        let relative_dir = tempfile::Builder::new()
            .prefix("release-packager-relative-smoke-")
            .tempdir_in(".")
            .unwrap();
        let stored_fixture = relative_dir.path().join("portable-evidence-ascii.dxf");
        std::fs::copy(&source_fixture, &stored_fixture).unwrap();
        let canonical_fixture = std::fs::canonicalize(&stored_fixture).unwrap();
        let current_dir = std::fs::canonicalize(std::env::current_dir().unwrap()).unwrap();
        let fixture = canonical_fixture
            .strip_prefix(current_dir)
            .unwrap()
            .to_path_buf();
        assert!(!fixture.is_absolute(), "got: {}", fixture.display());
        let target = host_target().expect("unix test host should map to an MVP target");
        let manifest = manifest_for(target, &metadata());
        let binary_script = r#"#!/bin/sh
AUTOCAD_MCP_TOOLS_JSON=$(cat <<'AUTOCAD_MCP_TOOLS_JSON_END'
__TOOLS__
AUTOCAD_MCP_TOOLS_JSON_END
)
if [ "$1" = "serve" ]; then
  while IFS= read -r request; do
    case "$request" in
      *'"method":"initialize"'*)
        printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"autocad-mcp","version":"0.0.1"}}}'
        ;;
      *'"method":"tools/list"'*)
        printf '{"jsonrpc":"2.0","id":2,"result":{"tools":%s}}\n' "$AUTOCAD_MCP_TOOLS_JSON"
        ;;
      *'"method":"tools/call"'*)
        printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":__MCP_LAYOUTS_TEXT__}],"isError":false}}'
        ;;
    esac
  done
  exit 0
fi
if [ "$1" = "list-tools" ]; then
  [ -n "$2" ] && exit 2
  printf '%s\n' "$AUTOCAD_MCP_TOOLS_JSON"
  exit 0
fi
if [ "$1" = "call" ]; then
  if [ "$3" = "--params-file" ]; then
    params=$(cat "$4") || exit 3
  else
    params=$3
  fi
  case "$params" in
    *'"drawing_path":"/'*) ;;
    *) exit 3 ;;
  esac
  drawing_path=$(printf '%s\n' "$params" | sed -n 's/.*"drawing_path":"\([^"]*\)".*/\1/p')
  [ -n "$drawing_path" ] || exit 3
  source_path_file="$0.source-path"
  state_file="$0.layer-state"
fi
if [ "$1" = "call" ] && [ "$2" = "list_layouts" ]; then
  if [ ! -f "$source_path_file" ]; then
    printf '%s\n' "$drawing_path" > "$source_path_file"
  fi
  printf '%s\n' '__CLI_LAYOUTS__'
  exit 0
fi
if [ "$1" = "call" ] && [ "$2" = "list_layers" ]; then
  printf '%s\n' '__CLI_LAYERS__'
  exit 0
fi
if [ "$1" = "call" ] && [ "$2" = "list_xrefs" ]; then
  printf '%s\n' '[{"handle":"F","name":"SITE_MODEL","saved_path":"refs/site.dwg","path_mode":"relative","reference_type":"attachment","load_state":"unavailable","instance_count":2,"definition_base_point":{"state":"available","point":{"x":1.0,"y":2.0,"z":3.0}}},{"handle":"10","name":"GRID_OVERLAY","saved_path":"refs/grid.dwg","path_mode":"relative","reference_type":"overlay","load_state":"unavailable","instance_count":1,"definition_base_point":{"state":"available","point":{"x":0.0,"y":0.0,"z":0.0}}},{"handle":"11","name":"EMPTY_PATH","saved_path":"","path_mode":"unsupported","reference_type":"attachment","load_state":"unavailable","instance_count":1,"definition_base_point":{"state":"available","point":{"x":-1.0,"y":-2.0,"z":-3.0}}}]'
  exit 0
fi
if [ "$1" = "call" ] && [ "$2" = "list_xref_instances" ]; then
  printf '%s\n' '__XREF_INSTANCES__'
  exit 0
fi
if [ "$1" = "call" ] && [ "$2" = "create_layer" ]; then
  [ "$drawing_path" != "$(cat "$source_path_file")" ] || exit 4
  sed '/^\$HANDSEED$/ { n; n; s/^200$/201/; }' "$drawing_path" > "$drawing_path.next" || exit 5
  mv "$drawing_path.next" "$drawing_path" || exit 5
  printf '%s\n' 'create-layer-smoke-marker' >> "$drawing_path"
  printf '%s\n' 'created' > "$state_file"
  printf '{"status":"ok","drawing":"%s","layer":{"handle":"20","name":"AUTOCAD_MCP_PORTABLE_SMOKE","color_index":3,"line_type":"Continuous","line_weight":{"kind":"value","hundredths_mm":35},"frozen":false,"locked":true,"off":false,"is_plottable":false,"xref_dependent":false,"xref_block_record_handle":null,"xref_name":null,"xref_path":null,"xref_is_overlay":null,"material_handle":null,"plotstyle_handle":null,"is_current":false}}\n' "$drawing_path"
  exit 0
fi
if [ "$1" = "call" ] && [ "$2" = "update_layer" ]; then
  [ "$(cat "$state_file")" = "created" ] || exit 5
  sed 's/^create-layer-smoke-marker$/update-layer-smoke-marker/' "$drawing_path" > "$drawing_path.next" || exit 5
  mv "$drawing_path.next" "$drawing_path" || exit 5
  printf '%s\n' 'updated' > "$state_file"
  printf '{"status":"ok","drawing":"%s","layer":{"handle":"20","name":"AUTOCAD_MCP_PORTABLE_SMOKE","color_index":5,"line_type":"Continuous","line_weight":{"kind":"value","hundredths_mm":35},"frozen":false,"locked":false,"off":true,"is_plottable":false,"xref_dependent":false,"xref_block_record_handle":null,"xref_name":null,"xref_path":null,"xref_is_overlay":null,"material_handle":null,"plotstyle_handle":null,"is_current":false}}\n' "$drawing_path"
  exit 0
fi
if [ "$1" = "call" ] && [ "$2" = "rename_layer" ]; then
  [ "$(cat "$state_file")" = "updated" ] || exit 5
  sed 's/^update-layer-smoke-marker$/rename-layer-smoke-marker/' "$drawing_path" > "$drawing_path.next" || exit 5
  mv "$drawing_path.next" "$drawing_path" || exit 5
  printf '%s\n' 'renamed' > "$state_file"
  printf '{"status":"ok","drawing":"%s","layer":{"handle":"20","name":"AUTOCAD_MCP_PORTABLE_SMOKE_RENAMED","color_index":5,"line_type":"Continuous","line_weight":{"kind":"value","hundredths_mm":35},"frozen":false,"locked":false,"off":true,"is_plottable":false,"xref_dependent":false,"xref_block_record_handle":null,"xref_name":null,"xref_path":null,"xref_is_overlay":null,"material_handle":null,"plotstyle_handle":null,"is_current":false}}\n' "$drawing_path"
  exit 0
fi
if [ "$1" = "call" ] && [ "$2" = "delete_layer" ]; then
  [ "$(cat "$state_file")" = "renamed" ] || exit 5
  sed '/^rename-layer-smoke-marker$/d' "$drawing_path" > "$drawing_path.next" || exit 5
  mv "$drawing_path.next" "$drawing_path" || exit 5
  printf '%s\n' 'deleted' > "$state_file"
  printf '{"status":"deleted","drawing":"%s","layer":{"handle":"20","name":"AUTOCAD_MCP_PORTABLE_SMOKE_RENAMED"}}\n' "$drawing_path"
  exit 0
fi
if [ "$1" = "call" ] && [ "$2" = "get_layer" ]; then
  case "$(cat "$state_file")" in
    created)
      printf '%s\n' '{"handle":"20","name":"AUTOCAD_MCP_PORTABLE_SMOKE","color_index":3,"line_type":"Continuous","line_weight":{"kind":"value","hundredths_mm":35},"frozen":false,"locked":true,"off":false,"is_plottable":false,"xref_dependent":false,"xref_block_record_handle":null,"xref_name":null,"xref_path":null,"xref_is_overlay":null,"material_handle":null,"plotstyle_handle":null,"is_current":false}'
      ;;
    updated)
      printf '%s\n' '{"handle":"20","name":"AUTOCAD_MCP_PORTABLE_SMOKE","color_index":5,"line_type":"Continuous","line_weight":{"kind":"value","hundredths_mm":35},"frozen":false,"locked":false,"off":true,"is_plottable":false,"xref_dependent":false,"xref_block_record_handle":null,"xref_name":null,"xref_path":null,"xref_is_overlay":null,"material_handle":null,"plotstyle_handle":null,"is_current":false}'
      ;;
    renamed)
      printf '%s\n' '{"handle":"20","name":"AUTOCAD_MCP_PORTABLE_SMOKE_RENAMED","color_index":5,"line_type":"Continuous","line_weight":{"kind":"value","hundredths_mm":35},"frozen":false,"locked":false,"off":true,"is_plottable":false,"xref_dependent":false,"xref_block_record_handle":null,"xref_name":null,"xref_path":null,"xref_is_overlay":null,"material_handle":null,"plotstyle_handle":null,"is_current":false}'
      ;;
    *) exit 5 ;;
  esac
  exit 0
fi
exit 2
"#
        .replace("__TOOLS__", &accepted_tool_payload().to_string())
        .replace(
            "__MCP_LAYOUTS_TEXT__",
            &serde_json::to_string(&expected_portable_layout_smoke_records().to_string()).unwrap(),
        )
        .replace(
            "__CLI_LAYOUTS__",
            &expected_portable_layout_smoke_records().to_string(),
        )
        .replace(
            "__CLI_LAYERS__",
            &expected_portable_layer_smoke_records().to_string(),
        )
        .replace(
            "__XREF_INSTANCES__",
            &expected_xref_instance_smoke_records().to_string(),
        );
        write_package(&package, &manifest, Some(&binary_script), None, None);

        let report = smoke_package(SmokeOptions {
            package_path: package,
            fixture_path: Some(fixture),
            require_executable: true,
            require_lsp_executable: false,
        })
        .unwrap();

        assert!(report.executable_ran);
    }
}
