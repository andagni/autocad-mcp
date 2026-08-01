---
name: autocad-mcp
description: >
  Read and edit AutoCAD drawings (DWG and DXF), manage XREF attachments and
  instances, and plot DWG layouts to PDF through the shipped autocad-mcp tool
  suite. Covers MCP access through autocad-mcp serve and direct CLI access
  through autocad-mcp call.
when_to_use: >
  Trigger on requests involving .dwg or .dxf drawing operations: title blocks,
  layers, XREF attachments, XREF instances and dependencies, blocks, text,
  layouts, or PDF plots. Do not use this skill to write AutoLISP
  routines or DCL dialogs.
---

# AutoCAD MCP Operations Skill

Use this skill for shipped drawing operations performed by the `autocad-mcp`
tool suite. Use `autolisp` for AutoLISP authoring.

Do not use this skill to write AutoLISP routines or DCL dialogs. Arbitrary AutoLISP is a contributor/expert technique for designing future operations, not the normal drafter-facing path for supported read, write, or plot workflows.

## Invocation Modes

The product has one canonical 51-tool contract through MCP and direct CLI, with
an explicit Preview exposure boundary.

- MCP: connect a supported local client to `autocad-mcp serve`, then call the
  tools directly.
- CLI: run `autocad-mcp call <tool-name> <json-params>` for scripting,
  headless workflows, and repeatable automation.
- Discovery: run `autocad-mcp list-tools` to print the current tool schemas.

A Release binary is compiled without the `preview` feature. Its plain `serve`
exposes all 51 certified tools and `serve --experimental` is an unknown option.
A Preview-capable binary exposes exactly the 36 `readOnlyHint=true` tools
through plain `serve`; `serve --experimental` explicitly opts into all 51,
including the 15 state-changing tools. A visibly marked Preview MCPB supplies
that flag in its manifest. Preview plain `list-tools` and `call` follow the same
36-tool boundary; use their `--experimental` option for full-surface discovery
or direct dispatch. Release rejects every such experimental option.

The flag changes MCP and direct-CLI tool exposure only. It never bypasses a
tool's platform, AutoCAD, ARG/profile, capability, transaction,
immutable-source snapshot, race, preservation, verification, or retry checks.
Preview has no separate mutation-root restriction: every `drawing_path`, source
path, and output path continues to follow the ordinary per-tool contract below.
Preview build, package smoke, and clean-host results are development evidence,
not Windows AutoCAD certification or Release evidence.

Every `drawing_path` is an absolute local path.
`plot_to_pdf.output` is an absolute local PDF path.
Every top-level request object is closed: omit inapplicable optional inputs and
do not send unknown keys or JSON `null` values. The `properties` maps for
attachment and instance update are the only open nested objects; their keys are
handled by exhaustive runtime property classifiers.

## Default Workflow

Read before mutating or plotting.

- Run `read_title_blocks` before `write_title_block`.
- Run `list_layers` before layer mutations.
- Run `list_xrefs` before targeted attachment operations when identity is
  unknown, then use the returned attachment handle.
- Run `list_xref_instances` before targeted instance operations when identity
  is unknown, then use the returned instance handle.
- Run `list_layouts` before `plot_to_pdf`.
- Stop if current drawing state, identity, or destructive scope does not match
  the requested operation.
- Do not guess title-block profiles, raw tags, layout names, layer identity,
  attachment identity, instance identity, unit assumptions, or output paths.

## Tool Contract

| Tool | Required parameters | Optional parameters | Output summary | Platform / notes |
|---|---|---|---|---|
| `list_layers` | `drawing_path` | none | JSON array of expanded LayerRecord objects | DWG and DXF read on all supported hosts |
| `get_layer` | `drawing_path` | `handle`, `name` | One expanded LayerRecord selected by handle or name | DWG and DXF read on all supported hosts; handle is preferred |
| `create_layer` | `drawing_path`, `name` | `properties` | Layer create evidence with the persisted layer record | Native-DXF write on all supported hosts; Windows-only DWG write through accoreconsole |
| `update_layer` | `drawing_path`, `properties` | `handle`, `name`, `expected_handle`, `expected_name` | Layer update evidence with the persisted layer record | Property mutation with stale-state guards |
| `rename_layer` | `drawing_path`, `new_name` | `handle`, `name`, `expected_handle`, `expected_name` | Layer rename evidence with the persisted layer record | Rejects protected and xref-dependent layers |
| `delete_layer` | `drawing_path` | `handle`, `name`, `expected_handle`, `expected_name` | Layer delete evidence | Rejects protected, current, dependent, content-bearing, and unverified-reference layers |
| `list_xrefs` | `drawing_path` | none | JSON array of complete XrefAttachmentRecord objects | DWG and DXF read on all supported hosts; direct attachments only |
| `get_xref` | `drawing_path` | `handle`, `name` | One complete XrefAttachmentRecord | DWG and DXF read on all supported hosts; handle is preferred |
| `attach_xref` | `drawing_path`, `xref_path`, `reference_type` | `name`, `search_paths`, `placement`, `unit_assumptions` | Attached evidence with persisted attachment and initial instance | Windows with AutoCAD for DWG and DXF hosts; source files unchanged |
| `update_xref` | `drawing_path`, `properties` | `handle`, `name`, `expected_handle`, `expected_name`, `layer_reconciliation`, `unit_assumptions`, `search_paths` | Updated evidence with persisted attachment and conditional reconciliation | Windows with AutoCAD for DWG and DXF hosts; source files unchanged |
| `detach_xref` | `drawing_path` | `handle`, `name`, `expected_handle`, `expected_name`, `expected_instance_count`, `expected_instance_handles` | Detached evidence with pre-detach attachment and deleted instance handles | Destructive Windows AutoCAD mutation; source files unchanged |
| `list_xref_instances` | `drawing_path` | `attachment_handle`, `attachment_name`, `owner_handle`, `owner_type`, `owner_name`, `layer_handle`, `layer_name`, `visibility` | JSON array of complete XrefInstanceRecord objects | DWG and DXF read on all supported hosts; exact filters only |
| `get_xref_instance` | `drawing_path`, `handle` | none | One complete XrefInstanceRecord | DWG and DXF read on all supported hosts; persisted handle required |
| `insert_xref_instance` | `drawing_path` | `attachment_handle`, `attachment_name`, `expected_attachment_handle`, `placement`, `unit_assumptions` | Inserted evidence with persisted instance | Windows with AutoCAD for DWG and DXF hosts; source files unchanged |
| `update_xref_instance` | `drawing_path`, `handle`, `properties` | `expected_attachment_handle`, `expected_owner_handle` | Updated evidence with persisted instance | Windows with AutoCAD for DWG and DXF hosts; owner and attachment cannot change |
| `delete_xref_instance` | `drawing_path`, `handle` | `expected_attachment_handle`, `expected_owner_handle` | Deleted evidence with the pre-delete instance | Destructive Windows AutoCAD mutation; attachment is retained |
| `reload_xref` | `drawing_path` | `handle`, `name`, `expected_handle`, `expected_name`, `search_paths`, `layer_reconciliation`, `unit_assumptions` | Loaded evidence with persisted attachment and reconciliation | Windows with AutoCAD for DWG and DXF hosts; source files unchanged |
| `unload_xref` | `drawing_path` | `handle`, `name`, `expected_handle`, `expected_name` | Unloaded evidence with persisted attachment | Windows with AutoCAD for DWG and DXF hosts; idempotent |
| `bind_xref` | `drawing_path`, `symbol_strategy`, `dependency_strategy` | `handle`, `name`, `expected_handle`, `expected_name`, `expected_instance_count`, `expected_instance_handles`, `search_paths` | Bound block, instance, symbol, dependency, and overlay-exclusion mappings | Destructive Windows AutoCAD mutation; source files unchanged |
| `resolve_xref_path` | `drawing_path` | `handle`, `name`, `search_paths` | One XREF path-resolution record | DWG and DXF read on all supported hosts; unresolved state is successful data |
| `list_xref_dependencies` | `drawing_path` | `handle`, `name`, `search_paths`, `max_depth`, `max_nodes` | Dependency traversal envelope with limit evidence | DWG and DXF read on all supported hosts; nested identity uses attachment chains |
| `get_drawing` | `drawing_path` | none | One closed drawing summary with availability-tagged saved-header model/paper geometry and current UCS, spaces, resource counts, and current settings | DWG only on all supported hosts; DXF is unavailable for the expanded read surface |
| `list_entities` | `drawing_path` | `entity_types`, `layer`, `owner_handle`, `include_invisible`, `offset`, `limit` | Bounded entity envelope with post-filter total, tagged direct-owner context, reason-bearing bounds/detail, and proven INSERT dynamic linkage | DWG only on all supported hosts; exact filters; limit defaults to 200 and must be 1–1000 |
| `get_entity` | `drawing_path`, `handle` | none | One common entity record with tagged direct-owner context, reason-bearing bounds/detail, and proven INSERT dynamic linkage | DWG only on all supported hosts; persisted handle required |
| `list_block_definitions` | `drawing_path` | none | Deterministic array of expanded block-definition records | DWG only on all supported hosts; includes layout and XREF context |
| `get_block_definition` | `drawing_path` | `handle`, `name` | One expanded block-definition record selected by handle or name | DWG only on all supported hosts; selectors are cross-checked when both are supplied |
| `list_block_inserts` | `drawing_path` | none | Deterministic ordinary INSERT/MINSERT array with tagged direct-owner context and proven dynamic linkage | DWG only on all supported hosts; XREF instances are excluded |
| `get_block_insert` | `drawing_path`, `handle` | none | One ordinary INSERT/MINSERT record with tagged direct-owner context, proven dynamic linkage, placement, and attributes | DWG only on all supported hosts; XREF instances are rejected |
| `list_text` | `drawing_path` | `text_types`, `layer`, `owner_handle`, `owner_type`, `owner_name` | Deterministic array of handle-bearing TEXT and MTEXT records with tagged direct-owner context | DWG only on all supported hosts; exact filters and cross-checked owner selector union |
| `get_text` | `drawing_path`, `handle` | none | One TEXT or MTEXT record with tagged direct-owner context | DWG only on all supported hosts; non-text handles are rejected |
| `get_layout` | `drawing_path` | `handle`, `name` | One expanded layout record selected by handle or name | DWG only on all supported hosts; selectors are cross-checked when both are supplied |
| `list_layout_viewports` | `drawing_path` | `layout_handle`, `layout_name` | Deterministic array of paper-space viewport records | DWG only on all supported hosts; optional exact layout scope |
| `get_layout_viewport` | `drawing_path`, `handle` | none | One paper-space viewport record with resolved layout ownership | DWG only on all supported hosts; persisted viewport handle required |
| `list_plot_settings` | `drawing_path` | none | Deterministic array of standalone named plot-setting records | DWG only on all supported hosts; embedded layout settings remain on layouts |
| `get_plot_setting` | `drawing_path` | `handle`, `name` | One standalone named plot-setting record | DWG only on all supported hosts; selectors are cross-checked when both are supplied |
| `list_linetypes` | `drawing_path` | none | Deterministic array of expanded linetype records | DWG only on all supported hosts |
| `get_linetype` | `drawing_path` | `handle`, `name` | One expanded linetype record | DWG only on all supported hosts; selectors are cross-checked when both are supplied |
| `list_text_styles` | `drawing_path` | none | Deterministic array of expanded text-style records | DWG only on all supported hosts |
| `get_text_style` | `drawing_path` | `handle`, `name` | One expanded text-style record | DWG only on all supported hosts; selectors are cross-checked when both are supplied |
| `list_dimension_styles` | `drawing_path` | none | Deterministic array of expanded dimension-style records | DWG only on all supported hosts |
| `get_dimension_style` | `drawing_path` | `handle`, `name` | One expanded dimension-style record | DWG only on all supported hosts; selectors are cross-checked when both are supplied |
| `list_named_views` | `drawing_path` | none | Deterministic array of named-view records | DWG only on all supported hosts |
| `get_named_view` | `drawing_path` | `handle`, `name` | One named-view record | DWG only on all supported hosts; selectors are cross-checked when both are supplied |
| `list_named_ucs` | `drawing_path` | none | Deterministic array of named UCS records | DWG only on all supported hosts |
| `get_named_ucs` | `drawing_path` | `handle`, `name` | One named UCS record | DWG only on all supported hosts; selectors are cross-checked when both are supplied |
| `list_blocks` | `drawing_path` | none | JSON array of user-defined block definitions | DWG and DXF read on all supported hosts |
| `read_title_blocks` | `drawing_path` | `attribute_value_mode` | JSON array of attributed title-block candidates and values; duplicate tags are returned as arrays and reported as partial structured warnings | DWG and DXF read on all supported hosts; value mode is `split` by default or `arrays` |
| `dump_text` | `drawing_path` | none | JSON array of TEXT and MTEXT content | DWG and DXF read on all supported hosts |
| `write_title_block` | `drawing_path`, `fields` | none | Title-block write evidence with target and attribute counts | Release Windows-only DWG write through accoreconsole; Preview Windows-only AC1032 DWG write through the bounded acadrust preservation oracle; native-DXF write on all supported hosts |
| `list_layouts` | `drawing_path` | none | JSON array of layouts and paper sizes | DWG and DXF read on all supported hosts; run before plotting |
| `plot_to_pdf` | `drawing_path`, `layout`, `output` | none | Plot evidence with the output PDF path | Windows only; DWG only; existing file-plotter page setup required |

## CLI Examples

Each CLI call is one shell-safe line with a single-quoted JSON object and uses
the same parameter names as MCP. Examples that supply `unit_assumptions` assume
the corresponding source and host roles are unitless or otherwise assumable.
The block shows Release syntax. For a state-changing Preview call, insert
`--experimental` after `call`; plain Preview calls expose only read-only tools,
and Release rejects that flag.

```bash
autocad-mcp call list_layers '{"drawing_path":"/abs/project/A101.dwg"}'
autocad-mcp call get_layer '{"drawing_path":"/abs/project/A101.dwg","handle":"10"}'
autocad-mcp call create_layer '{"drawing_path":"/abs/project/A101.dxf","name":"ANNO","properties":{"color_index":3,"locked":true}}'
autocad-mcp call update_layer '{"drawing_path":"/abs/project/A101.dxf","handle":"10","expected_name":"ANNO","properties":{"off":true}}'
autocad-mcp call rename_layer '{"drawing_path":"/abs/project/A101.dxf","handle":"10","expected_name":"ANNO","new_name":"NOTES"}'
autocad-mcp call delete_layer '{"drawing_path":"/abs/project/A101.dxf","handle":"10","expected_name":"NOTES"}'
autocad-mcp call list_xrefs '{"drawing_path":"/abs/project/A101.dwg"}'
autocad-mcp call get_xref '{"drawing_path":"/abs/project/A101.dwg","handle":"2A"}'
autocad-mcp call attach_xref '{"drawing_path":"C:/project/A101.dwg","xref_path":"../refs/site.dwg","name":"SITE","reference_type":"attachment","search_paths":["C:/project/shared"],"unit_assumptions":{"source_units":"millimeters","host_units":"millimeters"}}'
autocad-mcp call update_xref '{"drawing_path":"C:/project/A101.dwg","handle":"2A","expected_handle":"2A","properties":{"xref_path":"../refs/site-r2.dwg"},"search_paths":["C:/project/shared"],"layer_reconciliation":{"mode":"drawing_policy","properties":[]},"unit_assumptions":{"source_units":"millimeters","host_units":"millimeters"}}'
autocad-mcp call detach_xref '{"drawing_path":"C:/project/A101.dwg","handle":"2A","expected_handle":"2A","expected_instance_count":2,"expected_instance_handles":["40","41"]}'
autocad-mcp call list_xref_instances '{"drawing_path":"/abs/project/A101.dwg","attachment_handle":"2A"}'
autocad-mcp call get_xref_instance '{"drawing_path":"/abs/project/A101.dwg","handle":"40"}'
autocad-mcp call insert_xref_instance '{"drawing_path":"C:/project/A101.dwg","attachment_handle":"2A","expected_attachment_handle":"2A","placement":{"layer_name":"0","insertion_point":{"x":0.0,"y":0.0,"z":0.0},"scale":{"x":1.0,"y":1.0,"z":1.0},"rotation_degrees":0.0,"normal":{"x":0.0,"y":0.0,"z":1.0},"visibility":"visible"}}'
autocad-mcp call update_xref_instance '{"drawing_path":"C:/project/A101.dwg","handle":"40","expected_attachment_handle":"2A","expected_owner_handle":"1F","properties":{"visibility":"hidden","rotation_degrees":90.0}}'
autocad-mcp call delete_xref_instance '{"drawing_path":"C:/project/A101.dwg","handle":"40","expected_attachment_handle":"2A","expected_owner_handle":"1F"}'
autocad-mcp call reload_xref '{"drawing_path":"C:/project/A101.dwg","handle":"2A","expected_handle":"2A","search_paths":["C:/project/shared"],"layer_reconciliation":{"mode":"preserve_host","properties":[]}}'
autocad-mcp call unload_xref '{"drawing_path":"C:/project/A101.dwg","handle":"2A","expected_handle":"2A"}'
autocad-mcp call bind_xref '{"drawing_path":"C:/project/A101.dwg","handle":"2A","expected_handle":"2A","expected_instance_count":2,"expected_instance_handles":["40","41"],"symbol_strategy":"prefix","dependency_strategy":"reject_nested","search_paths":["C:/project/shared"]}'
autocad-mcp call resolve_xref_path '{"drawing_path":"/abs/project/A101.dwg","handle":"2A","search_paths":["/abs/project/shared"]}'
autocad-mcp call list_xref_dependencies '{"drawing_path":"/abs/project/A101.dwg","handle":"2A","search_paths":["/abs/project/shared"],"max_depth":32,"max_nodes":10000}'
autocad-mcp call get_drawing '{"drawing_path":"/abs/project/A101.dwg"}'
autocad-mcp call list_entities '{"drawing_path":"/abs/project/A101.dwg","entity_types":["LINE","CIRCLE"],"layer":"A-WALL","include_invisible":false,"offset":0,"limit":200}'
autocad-mcp call get_entity '{"drawing_path":"/abs/project/A101.dwg","handle":"40"}'
autocad-mcp call list_block_definitions '{"drawing_path":"/abs/project/A101.dwg"}'
autocad-mcp call get_block_definition '{"drawing_path":"/abs/project/A101.dwg","name":"TITLE_BLOCK"}'
autocad-mcp call list_block_inserts '{"drawing_path":"/abs/project/A101.dwg"}'
autocad-mcp call get_block_insert '{"drawing_path":"/abs/project/A101.dwg","handle":"52"}'
autocad-mcp call list_text '{"drawing_path":"/abs/project/A101.dwg","text_types":["TEXT","MTEXT"],"layer":"ANNO","owner_handle":"1F","owner_type":"model_space","owner_name":"Model"}'
autocad-mcp call get_text '{"drawing_path":"/abs/project/A101.dwg","handle":"61"}'
autocad-mcp call get_layout '{"drawing_path":"/abs/project/A101.dwg","name":"Layout1"}'
autocad-mcp call list_layout_viewports '{"drawing_path":"/abs/project/A101.dwg","layout_name":"Layout1"}'
autocad-mcp call get_layout_viewport '{"drawing_path":"/abs/project/A101.dwg","handle":"70"}'
autocad-mcp call list_plot_settings '{"drawing_path":"/abs/project/A101.dwg"}'
autocad-mcp call get_plot_setting '{"drawing_path":"/abs/project/A101.dwg","name":"A1 PDF"}'
autocad-mcp call list_linetypes '{"drawing_path":"/abs/project/A101.dwg"}'
autocad-mcp call get_linetype '{"drawing_path":"/abs/project/A101.dwg","name":"DASHED"}'
autocad-mcp call list_text_styles '{"drawing_path":"/abs/project/A101.dwg"}'
autocad-mcp call get_text_style '{"drawing_path":"/abs/project/A101.dwg","name":"NOTES"}'
autocad-mcp call list_dimension_styles '{"drawing_path":"/abs/project/A101.dwg"}'
autocad-mcp call get_dimension_style '{"drawing_path":"/abs/project/A101.dwg","name":"ISO-25"}'
autocad-mcp call list_named_views '{"drawing_path":"/abs/project/A101.dwg"}'
autocad-mcp call get_named_view '{"drawing_path":"/abs/project/A101.dwg","name":"Overall"}'
autocad-mcp call list_named_ucs '{"drawing_path":"/abs/project/A101.dwg"}'
autocad-mcp call get_named_ucs '{"drawing_path":"/abs/project/A101.dwg","name":"SITE"}'
autocad-mcp call list_blocks '{"drawing_path":"/abs/project/A101.dwg"}'
autocad-mcp call read_title_blocks '{"drawing_path":"/abs/project/A101.dwg"}'
autocad-mcp call dump_text '{"drawing_path":"/abs/project/A101.dwg"}'
autocad-mcp call write_title_block '{"drawing_path":"/abs/project/A101.dwg","fields":{"revision":"P02","drawing_number":"ABC-001"}}'
autocad-mcp call list_layouts '{"drawing_path":"/abs/project/A101.dwg"}'
autocad-mcp call plot_to_pdf '{"drawing_path":"/abs/project/A101.dwg","layout":"Layout1","output":"/abs/project/out/A101.pdf"}'
```

## Expanded Read Guidance

The canonical inventory is exactly 51 tools. A plain Preview server exposes its
36 read-only rows; the Preview MCPB's explicit experimental launch and a
Release server expose all 51. Use `get_drawing` for drawing-level
context, then use deterministic list tools to discover canonical handles before
targeted gets. `list_entities` filters before pagination; use a limit from 1 to
1000 and follow `offset` against the returned post-filter `total`.

`get_drawing.geometry` reports separately availability-tagged model-space and
header-level paper-space insertion base, extents, and limits. Each space uses
`source: "saved_header"`; the values are not recomputed from entities.
`get_drawing.current_ucs` separately reports saved-header model-space and
paper-space UCS name and availability-tagged basis. Do not infer a coordinate
reference system from these values. Duplicate block-record handles or a
contradictory header model-space identity fail closed. Space classification
uses the shared LAYOUT-object join, not block-name inference alone.

Rich entity, ordinary block-insert, and text records keep `owner_handle`
separate from the shared tagged `owner_context`. A null owner handle has a null
context. A non-null owner is either `available` with `owner_type` and
`owner_name`, or `unavailable` with `unresolved_owner` or
`missing_paper_space_layout`. Available owner types are `model_space`,
`paper_space`, `block_definition`, and `entity`; duplicate or contradictory
owner facts fail the read.

Entity bounds and detail use closed availability reasons; do not interpret an
unavailable bound as an empty entity. ATTDEF prompt/style and ATTRIB style are
`parser_defaulted` where the pinned DWG builder does not retain them. INSERT
detail and ordinary block-insert records share a bounded `dynamic_block`
projection. `state: "available"` proves the originating definition and,
where present, its single visibility parameter. `link_not_proven` does not
prove the block is static. The active visibility choice is always
`parser_not_retained`; do not infer it from hidden entities or state-member
sets.

TABLE, MULTILEADER, and 3DSOLID bounds and type-specific detail remain
unsupported until representative committed DWG decoder proof exists. Do not
interpret their common entity inventory records as decoded geometry. SHAPE and
TOLERANCE bounds and 2D polyline bounds affected by bulge, width, thickness,
fitting, or a non-world normal are likewise unavailable as
`unreliable_model_projection`. DIMENSION and LEADER use that reason because
the modeled boxes omit rendered annotation and arrow extents. If an INSERT
scale equals the selected parser backend's `1e-12` clamp sentinel, the generic
entity and ordinary block-insert reads fail because the original saved value
cannot be recovered.

HELIX detail contains only its saved axis base, start, axis vector, radius,
turn count, turn height, handedness, and constraint. Its bounds remain
`unreliable_model_projection`; do not treat the embedded spline control hull as
qualified curve extrema. ACAD_SURFACE records preserve their decoded subtype
name but remain inventory-only with `unsupported_entity_type` bounds and
unsupported detail.

Unscoped INSERT, TEXT/MTEXT, and VIEWPORT lists validate their applicable
semantic-handle domains. Exact scoped text queries validate only the selected
raw records. Targeted entity, text, and viewport reads validate the requested
identity, including collisions with valid nested ATTRIB handles, without
failing on unrelated malformed handles elsewhere.
Direct XREF-definition evidence is either XREF flag, overlay flag, or a
nonempty saved XREF path; path-only definitions are excluded from ordinary
blocks and ordinary inserts.

`list_text` filters are exact. `text_types` is a non-empty array of `TEXT`
and/or `MTEXT`; `layer` and `owner_name` use CAD case-insensitive equality.
Owner selection must use `{}`, `{owner_handle}`, `{owner_type, owner_name}`, or
all three. When all three are present, the handle and semantic owner must
agree. Expanded exact name and type filters reject surrounding whitespace
rather than trimming it.
The result remains an array, and `dump_text` remains unchanged.

Expanded layout limits must be finite and ordered. The exact AutoCAD
empty-layout extents sentinel is returned as `null`; other inverted or
non-finite extents fail. Layouts and viewport records expose last-active
viewport identity, not a primary-viewport claim. Viewport on/off remains
unavailable in the public contract pending separate qualification, even though
the selected backend retains that bit; custom scale also remains unavailable.
A zero viewport scale operand returns `null`; negative or non-finite operands
fail, and no guessed `1.0` is substituted. Plot scale factors still require
finite positive operands. Expanded layout/viewport model-paper classification
uses the shared semantic owner resolver and rejects contradictory header facts;
legacy `list_layouts` remains unchanged.

All 24 tools in this expanded read family are DWG-only on every supported host.
Do not call them with DXF input. Paired Tier 1 evidence showed that the pinned
reader baseline and selected backend both produce corrupted DXF BLOCK_RECORD
classification and units and that expanded records diverge from the matching
DWG. This boundary does not change the remaining 27 tools from the original
surface: their documented DWG/DXF read and native-DXF contracts remain
available.

`BlockDefinitionRecord` deliberately omits `base_point` until an externally
produced modern DWG with a nonzero ordinary-block base and an independent
oracle qualifies the selected backend's value. Do not infer or substitute
zero. Do not advertise TABLESTYLE list/get tools. The selected reader can
decode TABLESTYLE objects from DXF but leaves DWG TABLESTYLE payloads opaque,
so there is no reliable cross-format table-style read contract in this 51-tool
surface.

## XREF Mutation Validation

There is no public mutation-preflight tool. Submit the intended request directly
to its mutation tool. Each mutation performs its own schema, context-free,
filesystem, drawing, platform, AutoCAD, capability, identity, guard, locking,
preservation, verification, and recovery checks. Initialization and admission
are server responsibilities, not a preparatory agent workflow.

## XREF Identity And Ownership

Attachment handles and instance handles are canonical uppercase hexadecimal
strings. Use handles first because attachment names are mutable. A name is an
ergonomic, case-insensitive selector; when a handle and name are both supplied,
both must independently resolve to the same direct attachment.

`list_xrefs`, `get_xref`, and every attachment mutation address direct
attachments owned by `drawing_path`. A nested attachment belongs to its
immediate host drawing, not the root drawing used to discover it. To mutate a
nested attachment, set `drawing_path` to that immediate host drawing and use
the attachment handle from that host. Dependency observations are read-only and
use the complete numeric `attachment_chain` as identity.

An XREF instance is one persisted block-reference entity. Use its returned
instance handle for get, update, and delete. An MINSERT rectangular array is one
instance resource; its cells do not have synthesized handles. Instance
placement is expressed in the selected owner's coordinates. Owner or attachment
reassignment is not an update: insert a replacement instance, verify it, then
delete the old instance.

## XREF Paths And Source State

`xref_path` is accepted only by attach and as the `xref_path` property of an
attachment update. It resolves from the immediate host drawing, never the
process working directory. It must resolve to a readable DWG source. A saved
path is stored in the accepted form and is never resource identity.

`search_paths` is an ordered, transient list used only by the tools that expose
it. It affects source and dependency resolution but is never persisted into the
host drawing. Use `resolve_xref_path` to inspect the selected candidate and
`list_xref_dependencies` to inspect the nested graph before source-dependent
mutations.

`unit_assumptions` contains conditional `source_units` and `host_units` profile
defaults. Supply only the roles the inspected graph proves are assumable; do
not use assumptions to override known units or unknown persisted unit codes.
Attach, source-path update, reload, and some instance insertions may require
them. Missing required assumptions fail rather than consulting ambient AutoCAD
defaults.

`layer_reconciliation` is accepted by reload and by update only when
`properties.xref_path` is present. Modes are `drawing_policy`, `preserve_host`,
`source_authoritative`, and `synchronize`. Only `synchronize` takes a non-empty
`properties` list. Search paths, unit assumptions, reconciliation state, and
other profile settings are isolated operation inputs, not ambient user state.

Every XREF operation treats the referenced source drawing and every source
dependency as immutable. Attach, path update, reload, detach, instance
mutations, unload, and bind may mutate only the requested host drawing. They
must never save, rename, move, overwrite, or delete a source file.

## XREF Mutation Guards

All XREF mutations require Windows with AutoCAD, including DXF-host mutations.
XREF reads and graph/path inspection support DWG and DXF on all build targets.
A host mutation is all-or-nothing and returns persisted verification evidence;
it never reports partial success.

Preview exposure does not loosen those requirements. Its package-owned
candidate catalogue and all row-specific ARG/policy pairs are
binary/package-bound; the exact pair selected for one process is evaluation
input, not a certified production profile. Catalogue inclusion, candidate
selection, probe success, and package smoke are not maintained-support or
certification claims, and no Preview package contains private certification
evidence. The guarded TxF install, exclusive original-source snapshot handles,
deterministic source/host race checks, unique token-scoped profile lifecycle,
preservation, and persisted verification paths are shared with Release.

Use `expected_handle` and `expected_name` after reviewing an existing
attachment. For destructive detach and bind, also use
`expected_instance_count` and `expected_instance_handles`; the handle array is
the exact reviewed deletion/conversion scope, while the count alone cannot
detect same-count replacement. Use `expected_attachment_handle` and
`expected_owner_handle` when updating or deleting an instance. Do not proceed
through a stale guard, locked-instance, unsupported-owner, incomplete graph, or
unproven preservation failure.

The XREF clip lifecycle remains reserved. Existing clip data may be preserved
only when the active AutoCAD verifier proves the operation; otherwise the
mutation fails before changing the host.

## XREF Retry Rules

`mutation_state_unknown` is the only uncertain-commit XREF code. Never retry
automatically after that code or after transport loss when execution may have
crossed the commit point. Inspect the host first with `get_xref` or
`list_xrefs` for attachment operations and `get_xref_instance` or
`list_xref_instances` for instance operations.

Current state is not a durable receipt. Creation can be indistinguishable from
a concurrent creation, absence after deletion or detach does not prove who
removed the target, and bind mappings cannot be reconstructed after the XREF
is gone. When the readback does not prove one outcome, reconciliation is
inconclusive: stop for operator recovery and do not retry. An absent target is
not success for delete, detach, or bind; attach retains collision behavior;
insert remains non-idempotent; unload is idempotent.

## Layer And Title-Block Writes

Layer write tools and `write_title_block` mutate the requested drawing in
place. Copy the host first if the original file must be preserved.

Layer handles are preferred because layer names are mutable. Use
`expected_handle` and `expected_name` when protecting against stale state.
`0` and `DEFPOINTS` are protected by name after identity resolution for rename
and delete. Do not freeze the current layer. Do not delete layers with content
or unverified references.

Writable layer properties are
`color_index`, `frozen`, `locked`, `off`, `is_plottable`, `line_type`, and
`line_weight`. Recognized unsupported/read-only layer property keys fail with
`code=unsupported_layer_property`; unknown property keys fail with
`code=invalid_layer_property`.

Xref-dependent `update_layer` allows host overrides for `color_index`, `frozen`,
`locked`, `off`, `is_plottable`, and `line_weight`; DXF xref-dependent
`line_type` updates are unsupported. Xref-dependent `rename_layer` and
`delete_layer` remain rejected.

Release DWG layer and title-block writes require Windows with AutoCAD. Preview
DWG layer writes retain that requirement, but Preview `write_title_block` uses
the pure-Rust acadrust backend without launching AutoCAD when the locked source
is AC1032 and passes its closed preservation oracle. The oracle rejects XREFs,
unqualified entities, objects, sections, or diagnostics; verifies every
invariant DWG section byte-for-byte; requires native field-complete
`CadDocument` equality after normalizing the admitted HANDSEED/allocator
transition; and installs only the verified digest through the guarded Windows
transaction. A successful response reports
`backend = acadrust_preview`, the writer receipt, and the guarded-install
receipt. An error with `installation_may_have_occurred = true` requires
operator reconciliation and must not be retried automatically.

Supported native ASCII DXF layer and title-block writes use the existing
pure-Rust patch path on all supported hosts. Title-block `fields` are canonical
field names, not raw DXF attribute tags. If profile resolution fails, stop
rather than guessing and ask the administrator to configure a reviewed
profile.
`read_title_blocks` may succeed with `structuredContent.status = partial` when
an INSERT has duplicate normalized tags; consume every ordered value from
`attribute_arrays` rather than choosing one. A write is blocked before its
first mutation when any requested raw tag is missing or duplicated on a target
INSERT. A duplicate tag that is not requested does not by itself block other
mapped fields from being written.

## Plot Guidance

`plot_to_pdf` accepts DWG input only. DXF plotting is unsupported in the MVP.
Run `list_layouts`, confirm the exact layout, and provide an absolute `.pdf`
output path. Plotting requires Windows, AutoCAD `accoreconsole`, and an existing
file-plotter page setup on the requested layout.

## Unsupported Title-Block Profiles

There is no drafter-facing title-block survey or profile-registration tool. If
profile resolution fails, stop, report the unsupported variant, and direct the
user to their administrator. Do not try to survey, author, validate, activate,
or select a profile through MCP; those are offline administrator and server
configuration responsibilities.

Repeated drafter-facing workflows that require manual AutoLISP or shell work are post-v1 tool candidates when they occur more than once or block release validation.

## LSP And Editor Support

Stage 5+ v1 release packages include `plugin/.lsp.json` and a platform-specific `autolisp-lsp` binary. This is editor support for `.lsp` authoring. It is not a drawing-operation path and does not replace `autocad-mcp` tools.

## Failure Posture

Fail loud and report the stable `code=<reason_code>` value. Do not bypass
identity, stale-state, destructive-scope, platform, format, source-graph,
locking, preservation, or verification failures. Do not replace shipped
drawing operations with hand-written AutoLISP.
