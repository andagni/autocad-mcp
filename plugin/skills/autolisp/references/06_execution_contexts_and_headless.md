# Execution contexts and console workers

Host capabilities are inputs to an AutoLISP design. Do not detect them halfway
through a mutation and improvise a different path.

## Full AutoCAD

An interactive Windows session can expose the AutoCAD application object and
its active document. Code using that surface should:

- call `(vl-load-com)` itself;
- acquire the objects it needs once;
- distinguish model space from paper space explicitly;
- release objects whose lifetime it owns; and
- keep prompt and selection behavior in an interactive wrapper.

ActiveX access from AutoLISP is a Windows-only product surface. The official
reference for `vlax-get-acad-object` records that platform boundary:
<https://help.autodesk.com/cloudhelp/2024/ENU/AutoCAD-AutoLISP-Reference/files/GUID-53DB599B-641D-45DD-A201-604942A4596C.htm>.

## AutoCAD console process

A console worker must not require a visible window, a user response, or an
interactive application-object path. Prefer current-drawing entity operations
when they cover the task. If an AutoCAD command is essential, prove that exact
command sequence in the supported console release and remove every prompt.

Keep the worker separate from the launcher:

1. The launcher selects the executable and drawing, creates any temporary
   script, and starts the process.
2. The script loads one known AutoLISP file and invokes one worker with explicit
   values.
3. The worker performs drawing logic without discovering paths or reading
   undeclared global state.
4. The script saves or discards changes deliberately and exits.
5. The launcher evaluates exit status, bounded completion, and retained output.

AutoCAD-MCP's engine code owns its production `accoreconsole` launch contract.
In particular, filesystem-canonical paths and command-line paths are separate
representations on Windows. A caller should not recreate that launch behavior
in ad hoc AutoLISP.

## Offline source validation

`autolisp-validate` and the AutoLISP language server run without AutoCAD. They
can check syntax shape, curated symbol help, and selected conventions. They
cannot establish:

- whether a function exists in the target AutoCAD version;
- whether an editor command is available in a console host;
- whether a DCL file loads;
- whether a mutation persists correctly; or
- whether cleanup succeeds after a host exception.

Those claims require a test in the matching AutoCAD host.

## Design for more than one host

If one operation must support interactive and console execution, put shared
drawing logic in a prompt-free worker. Use thin host adapters for:

- obtaining input;
- choosing or opening a drawing;
- starting and ending undo or transaction state;
- deciding save behavior; and
- reporting results.

Pass paths and values into the worker. Avoid hidden support-file dependencies,
fixed AutoCAD install paths, and versioned COM identifiers unless the supported
release contract explicitly binds them.

## Sources

The Windows scope and application-object details were checked against
Autodesk's current ActiveX documentation; the console boundary and launch
requirements come from
`crates/autocad-mcp/src/engine.rs` and the repository's Windows certification
contracts.
