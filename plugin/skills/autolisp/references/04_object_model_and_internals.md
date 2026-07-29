# 04 — Drawing Object Boundaries

This file supplies the object-model distinctions needed to inspect or design an
AutoLISP operation without flattening the drawing into an unsafe generic map.
It does not describe the DWG binary format.

## Keep four questions separate

For every object touched by a routine, ask:

1. **What is it?** A graphical entity, table record, dictionary, xrecord, or
   another non-graphical object.
2. **Who owns it?** A drawing space, block definition, dictionary, or another
   database object.
3. **How is it identified?** A session-scoped entity name, a persisted handle,
   or an application-level key.
4. **What data may this operation change?** Only the fields named by the
   operation's contract.

Two objects with similar association lists can have different mutation rules.
Type and ownership checks belong before a write, not after one fails.

## Entity names and handles have different jobs

AutoLISP entity functions operate on entity names from the current drawing
session. A handle is persisted drawing data that can be resolved with
`handent`, but resolution may return no object.

Do not store a raw entity name for later sessions. Do not treat a handle as a
globally stable identity across drawing composition, XREF, bind, cloning, or
other ownership-changing workflows. Persist enough domain context to detect
that the target is no longer the same logical object.

## Symbol tables are typed stores

Layers, linetypes, text styles, block definitions, and other named records live
in symbol tables. Use table lookup functions to discover a record and
`tblobjname` when an entity name is required for further inspection.

A routine must know which record type it expects. It must not treat an absent
record as permission to synthesize a default unless creation is explicitly part
of the operation.

For AutoCAD-MCP layer mutation, preservation is the governing rule: unsupported
table data causes a closed failure rather than a lossy rewrite. AutoLISP helpers
should follow the same principle.

## Dictionaries are ownership structures

The named-object dictionary is an entry point to non-graphical application
data. Dictionary entries should be traversed and changed with dictionary
operations, not by treating the dictionary's association list as an ordinary
entity payload.

An xrecord is appropriate for structured application data that needs a database
owner but is not naturally attached to one graphical entity. Give every newly
created non-graphical object an intended owner and verify that the ownership
link exists.

Names used inside shared drawing dictionaries are part of an interoperability
contract. Prefix project-owned keys and handle collisions explicitly.

## Xdata belongs to a registered application

Xdata is attached to an object under an application name. Register the
application name before writing and request only the applications the routine
needs when reading.

Do not rewrite another application's xdata. Preserve unrequested data, keep
ordering and repetition where the application's schema requires them, and
version the project-owned payload if its meaning may evolve.

An entity reference stored in application data must define its drawing scope.
If the referenced object can live in another drawing or XREF, a local handle
alone is not a sufficient cross-drawing identity.

## Ownership affects user-visible behavior

Before changing a nested object, walk outward:

- an attribute is owned by a block reference;
- a block reference belongs to a drawing space;
- an entity inside a block definition can be shared by many references; and
- a dictionary record may be shared application state rather than drawing
  geometry.

Return layout or space attribution when it is needed to interpret an entity.
For repeated title-block tags, retain the ordered values rather than converting
the set into a scalar map.

XREF objects also carry relationship state. Read APIs must report contradictory
or incomplete state explicitly; mutation APIs must not infer a safe transaction
from a partial object view.

## Preserve what the operation does not own

Association lists can contain extension dictionaries, reactors, application
data, ownership links, and fields unknown to the current routine. A safe edit:

- begins with the latest complete representation available;
- validates the exact object and owner;
- changes only contract-owned fields;
- retains all other data in its original order when ordering matters;
- writes through the API intended for that object class; and
- reads back enough state to verify the semantic result.

If the API cannot preserve encountered data, stop before writing. Silent
normalization is not a substitute for preservation.

## Project anchors

- `crates/autocad-mcp/src/ops/owners.rs`
- `crates/autocad-mcp/src/ops/blocks.rs`
- `crates/autocad-mcp/src/ops/title_blocks.rs`
- `crates/autocad-mcp/src/ops/layer_io.rs`

## Sources

API details were checked on 2026-07-26 against Autodesk's
[non-graphical object overview](https://help.autodesk.com/cloudhelp/2026/ENU/AutoCAD-LT-AutoLISP/files/GUID-984A6964-E801-4C22-8E41-BF3D05CD122F.htm),
[dictionary-object guidance](https://help.autodesk.com/cloudhelp/2026/ENU/AutoCAD-AutoLISP/files/GUID-24E52678-513E-4322-8070-B23C8945DC3D.htm),
[xdata overview](https://help.autodesk.com/cloudhelp/2026/ENU/AutoCAD-AutoLISP/files/GUID-A94BC605-5517-437F-A6FE-D3EB8116A01A.htm),
and Autodesk's [Xrecords reference](https://help.autodesk.com/view/OARX/2026/ENU/?guid=GUID-94F52FE1-941B-483E-B12D-B2AFDC172C20).
