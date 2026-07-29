# 03 — AutoLISP Review Hazards

Use this as a focused review list. It records failure classes that matter to
AutoCAD-MCP work; it is not a historical catalogue of AutoLISP behavior.

## Language-shape mistakes

AutoLISP is its own language. Code that merely resembles another Lisp is not
acceptable.

Review for:

- unsupported Common Lisp forms or parameter syntax;
- unbalanced parentheses outside strings and comments;
- a helper invoked without a declared load path;
- temporary variables omitted from the local list;
- public symbols without a project prefix; and
- a command entry point that leaks its final value to the command line.

The repository validator checks a bounded set of these patterns. Its result is
advisory for warnings and cannot prove runtime correctness.

## State restoration mistakes

Any modified system variable, open dialog, file handle, undo scope, selection
set, or COM reference needs an owner and cleanup rule.

Common review failures are:

- capture occurs after the first mutation;
- cleanup exists on success but not in the error handler;
- the error handler tries to close a resource that never opened;
- one routine overwrites a caller-owned global error handler;
- cleanup performs additional drawing mutations; or
- a nested operation closes an undo scope owned by its caller.

Make acquisition state explicit rather than inferring it from a value that
might also be a valid user value.

## Command-processor mistakes

Editor commands are stateful prompt protocols. Flag:

- command names or options that are not written in the internationalized
  built-in form;
- omitted terminators or implicit prompt answers;
- reliance on the current layer, selection, UCS, object snap, or dialog state;
- a sequence tested only in full AutoCAD but deployed to a console host; and
- unchecked continuation after an unexpected prompt or timeout.

Prefer a native object operation when it represents the same bounded change
without driving prompts.

## Database-shape mistakes

An entity list is not a fixed-position record and not a one-value dictionary.
Reject code that:

- reads by list offset instead of DXF group code;
- treats a missing optional group as an impossible state;
- collapses repeated groups or duplicate attribute tags;
- reconstructs a whole object while discarding unknown fields;
- changes a field without checking object type and owner;
- assumes a database-wide selection belongs to one space;
- mixes indexed color with true-color data without a defined policy; or
- writes a point without naming its coordinate system.

For title-block reads, repeated normalized tags are successful partial data:
return all values and a structured warning. For title-block writes, ambiguity
blocks only a requested field that maps to the repeated tag.

## Host and capability mistakes

API availability follows the actual host, not the filename extension or the
developer's machine. Review for:

- use of an Application object where only the current-drawing entity API is
  available;
- use of editor-only functions against an ObjectDBX document;
- unverified version-specific ProgIDs;
- a Windows-only path presented as portable;
- an AutoCAD-backed mutation presented as a format-only operation; and
- a local modeled test presented as native AutoCAD evidence.

Read `06_execution_contexts_and_headless.md` and keep the unsupported case
explicit.

## Completion checklist

Before accepting an AutoLISP change:

1. Identify the exact host and supported AutoCAD release.
2. Trace all state acquired or changed across success and failure.
3. Check every object access for type, ownership, space, and multiplicity.
4. Check all coordinates for an explicit source and destination system.
5. Run `autolisp-validate` on each changed `.lsp` file.
6. Test the operation in the host needed to support the claim.
7. Keep the claim narrower than the evidence.

## Project anchors

- `crates/autolisp-validate/src/lib.rs`
- `crates/autolisp-validate/tests/cli.rs`
- `crates/autocad-mcp/src/taxonomy.rs`
- `crates/autocad-mcp/src/ops/title_blocks.rs`

## Sources

API details were checked on 2026-07-26 against Autodesk's
[AutoLISP Developer's Guide](https://help.autodesk.com/cloudhelp/2026/ENU/AutoCAD-AutoLISP/files/GUID-265AADB3-FB89-4D34-AA9D-6ADF70FF7D4B.htm),
[error-handling overview](https://help.autodesk.com/cloudhelp/2026/ENU/AutoCAD-AutoLISP/files/GUID-027AD2E0-5AC5-48DA-B451-112B7EECE40F.htm),
and [entity-data overview](https://help.autodesk.com/cloudhelp/2026/ENU/AutoCAD-AutoLISP/files/GUID-B150646B-5F8F-460A-A5D6-AF7BD467B638.htm).
