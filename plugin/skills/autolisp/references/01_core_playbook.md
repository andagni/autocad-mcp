# 01 — AutoLISP Command Lifecycle

This file describes the minimum structure expected of AutoLISP in this project.
It is intentionally narrower than a language tutorial.

## Start with the product boundary

Use an existing `autocad-mcp` tool when it already performs the requested read,
write, or plot operation. Write AutoLISP only for a genuinely custom operation
or for a project that explicitly owns an AutoLISP integration.

Before writing a routine, record:

- the host: full AutoCAD, `accoreconsole`, or another supported environment;
- the drawing and objects that may change;
- every system variable or global binding that may change;
- the success signal and the failure signal;
- the undo mechanism available in that host; and
- every external file or function that must be loaded.

Read `06_execution_contexts_and_headless.md` before selecting ActiveX or editor
commands. Code intended for the current drawing can often stay on the native
entity API.

## A command has one owner and one cleanup path

A public command is a `defun` whose name starts with `c:`. Put all temporary
bindings after `/` in its parameter list. Choose a project prefix for public
commands, helpers, and deliberate globals.

The following read-only example shows local state, failure cleanup, and a quiet
exit:

```lisp
(defun c:AMCP-COUNT-TEXT (/ *error* prior_cmdecho selection)
  (setq prior_cmdecho (getvar "CMDECHO"))

  (defun *error* (message)
    (if prior_cmdecho
      (setvar "CMDECHO" prior_cmdecho))
    (if message
      (princ (strcat "\nAMCP-COUNT-TEXT failed: " message)))
    (princ))

  (setvar "CMDECHO" 0)
  (setq selection (ssget "_X" '((0 . "TEXT,MTEXT"))))

  (if selection
    (princ (strcat "\nText objects: " (itoa (sslength selection))))
    (princ "\nText objects: 0"))

  (setq selection nil)
  (setvar "CMDECHO" prior_cmdecho)
  (princ))
```

Do not copy this envelope mechanically into a mutating routine. A mutation also
needs an undo boundary that is valid in its execution context, plus cleanup for
every resource it acquires.

## Design cleanup before the main operation

Treat cleanup as a small ledger:

| Resource | Capture | Normal completion | Error completion |
|---|---|---|---|
| System variable | Read before changing it | Restore saved value | Restore saved value |
| Selection set | Store in a local | Set local to `nil` | Set local to `nil` when acquired |
| Dialog or file | Keep its returned identifier | Close or unload | Close or unload if open |
| Undo scope | Mark whether it opened | Close once | Close only if it opened |
| COM object | Keep a local reference | Release where required | Release where required |

An error handler should do bounded cleanup and report useful context. Do not
place new drawing work in the handler. For an isolated call that may fail,
consider `vl-catch-all-apply` and inspect its result rather than routing every
expected condition through the command-wide handler.

## Keep database work separate from prompting

Split a substantial command into:

1. a thin command entry point that gathers or validates input;
2. a worker that accepts explicit values and performs the operation; and
3. a formatter that reports the result.

This makes the worker reusable by a script and makes the drawing operation
testable without simulating an interactive prompt sequence. The worker must not
discover undeclared files or project helpers at runtime.

## Use editor commands deliberately

`command` drives AutoCAD's command processor. Its behavior depends on prompt
order, current drawing state, and host capabilities. When it is necessary:

- use the internationalized built-in command form, such as `"_.REGEN"`;
- supply every required option and terminator explicitly;
- save and restore any system variable used to control command behavior;
- keep the call inside a function; and
- test the exact sequence in the intended host.

Prefer direct entity operations for bounded current-drawing changes when they
express the operation without depending on prompts. Do not assume that a
sequence proven in full AutoCAD will behave the same way in a console host.

## Completion checks

Before declaring a routine ready:

- confirm all temporary bindings are local;
- confirm success and error paths restore the same captured state;
- confirm a mutating routine has one valid undo story;
- confirm each function exists in the target AutoCAD environment;
- confirm external dependencies have an explicit load path;
- run the repository validator on every changed `.lsp` file; and
- perform a host test for behavior that depends on AutoCAD.

From the repository root:

```text
cargo run --locked -p autolisp-validate -- path/to/routine.lsp
```

The validator is a static convention check, not an AutoCAD execution
certificate. Review warnings in the context of the routine's inputs and host.

## Project anchors

- `crates/autolisp-validate/src/lib.rs`
- `crates/autolisp-validate/tests/commands/standalone_command.lsp`
- `plugin/skills/autolisp/references/06_execution_contexts_and_headless.md`

## Sources

API details were checked on 2026-07-26 against Autodesk's
[AutoLISP Developer's Guide](https://help.autodesk.com/cloudhelp/2026/ENU/AutoCAD-AutoLISP/files/GUID-265AADB3-FB89-4D34-AA9D-6ADF70FF7D4B.htm),
[error-handling overview](https://help.autodesk.com/cloudhelp/2026/ENU/AutoCAD-AutoLISP/files/GUID-027AD2E0-5AC5-48DA-B451-112B7EECE40F.htm),
and [`command` reference](https://help.autodesk.com/cloudhelp/2026/ENU/AutoCAD-AutoLISP-Reference/files/GUID-1C989B35-2C5A-47EC-A0C9-71998EDFB157.htm).
