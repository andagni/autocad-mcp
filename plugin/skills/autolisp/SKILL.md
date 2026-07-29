---
name: autolisp
description: Write, review, debug, and validate AutoLISP or DCL for AutoCAD-MCP using the shipped guidance and autolisp-validate development tool.
---

# AutoLISP Skill

Use this skill when a task requires AutoLISP or DCL source.
Use `autocad-mcp` for shipped read, write, and plot operations. Handwritten
AutoLISP is appropriate when the requested behavior is outside that public tool
surface.
Do not replace a shipped
`autocad-mcp` operation with hand-written AutoLISP during normal drawing work.

## Working sequence

1. Read the target project's loader, command entry points, and existing naming
   conventions.
2. State the intended host: full AutoCAD, an AutoCAD console process, or a
   source-only validation environment.
3. List every drawing mutation, system variable, external file, and non-built-in
   function the routine will use.
4. Keep the worker independent of prompts where practical. Add a `c:` wrapper
   only when interactive input is required.
5. Localize temporary bindings after `/` in each `defun`.
6. Restore changed state and close any undo boundary on success, cancellation,
   and error paths.
7. Validate every changed `.lsp` file and inspect warnings in the context of the
   real input range:

   ```text
   autolisp-validate path/to/file.lsp
   ```

   From this repository, the equivalent development command is
   `cargo run -p autolisp-validate -- path/to/file.lsp`.

The validator reports parenthesis errors and a deliberately small set of
AutoLISP-specific convention hazards. A clean result is not execution evidence;
run host-dependent code in the exact supported AutoCAD environment.

## Choosing an API

- Use the entity functions for current-drawing records when their contract
  covers the operation.
- In full AutoCAD on Windows, ActiveX may be appropriate after explicit
  `(vl-load-com)` initialization.
- Do not assume an interactive application object, dialog, editor selection, or
  prompt is available in a console process.
- Keep launch, file-opening, save, and exit behavior outside the drawing worker
  so they can be verified separately.

See `references/06_execution_contexts_and_headless.md` before writing code that
must run without the full UI.

## Command shape

A command should make ownership of state visible. This small shape is a review
aid, not a drop-in implementation:

```lisp
(defun c:ACMCP_SAMPLE (/ *error* previous_echo)
  (setq previous_echo (getvar "CMDECHO"))

  (defun *error* (message)
    (if previous_echo
      (setvar "CMDECHO" previous_echo))
    (if (and message
             (not (wcmatch (strcase message) "*CANCEL*,*QUIT*,*EXIT*")))
      (prompt (strcat "\nACMCP_SAMPLE failed: " message)))
    (princ))

  (setvar "CMDECHO" 0)
  ;; Call a separately tested worker here.
  (setvar "CMDECHO" previous_echo)
  (princ))
```

Adapt the cleanup to the resources the real routine acquires. If the command
starts an undo group, opens a file, loads a dialog, or creates a COM object, its
cleanup path must own that resource explicitly.

## DCL boundary

For a DCL dialog:

- give each interactive tile a unique `key`;
- resolve the DCL file path rather than relying on an undeclared support path;
- reject a failed `load_dialog` or `new_dialog`;
- set initial state and callbacks before entering the dialog loop;
- copy accepted values out before applying drawing changes; and
- unload every successfully loaded dialog.

Read `references/05_dcl_dialogs.md` and
`references/dcl/reference-dcl-summary.md` for the maintained subset. Consult the
current Autodesk reference for attributes or platform support not documented
there.

## Reference routing

| Need | File |
|---|---|
| Command structure and cleanup | `references/01_core_playbook.md` |
| Entities and selection sets | `references/02_entity_and_selection_cookbook.md` |
| Validator-backed failure patterns | `references/03_pitfalls_and_failure_modes.md` |
| Persistent drawing records | `references/04_object_model_and_internals.md` |
| DCL integration | `references/05_dcl_dialogs.md` |
| GUI and console boundaries | `references/06_execution_contexts_and_headless.md` |
| DCL names used by this skill | `references/dcl/reference-dcl-summary.md` |
| Source and rights record | `references/README.md` and `references/documentation-provenance.json` |
