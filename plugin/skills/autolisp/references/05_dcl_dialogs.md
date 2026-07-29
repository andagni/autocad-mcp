# DCL dialog integration

DCL describes a modal dialog's layout. AutoLISP loads that description, assigns
initial values and actions, waits for a terminal action, and then applies the
accepted values. Keep drawing mutation outside the dialog session.

## Split layout from behavior

The `.dcl` file owns tile structure and stable keys:

```dcl
acmcp_note : dialog {
  label = "Drawing note";
  : edit_box {
    key = "note";
    label = "Text:";
    edit_width = 30;
  }
  : text {
    key = "message";
    label = "";
  }
  ok_cancel;
}
```

The `.lsp` file owns path resolution, state, callbacks, and the result. This
example returns the accepted string or `nil`:

```lisp
(defun acmcp:request-note (dcl-path / dialog-id outcome note)
  (setq dialog-id (load_dialog dcl-path))
  (cond
    ((< dialog-id 0)
      (prompt "\nUnable to load the DCL file."))
    ((not (new_dialog "acmcp_note" dialog-id))
      (prompt "\nThe requested dialog is not defined.")
      (unload_dialog dialog-id))
    (T
      (setq note "")
      (set_tile "note" note)
      (action_tile
        "accept"
        "(setq note (get_tile \"note\"))(done_dialog 1)")
      (action_tile "cancel" "(done_dialog 0)")
      (setq outcome (start_dialog))
      (unload_dialog dialog-id)
      (if (= outcome 1)
        note))))
```

AutoLISP uses dynamic binding, so the action expression can assign the active
function's local `note` while this function is waiting in `start_dialog`. Do not
turn dialog state into a global unless it must outlive the driver call.

## Review the lifecycle as resource ownership

The driver owns four transitions:

1. `load_dialog` either supplies an identifier or fails.
2. `new_dialog` either instantiates the named definition or fails.
3. initialization and `action_tile` calls prepare the active dialog.
4. `start_dialog` returns only after an action terminates the dialog; the driver
   then calls `unload_dialog`.

Only unload an identifier that was successfully loaded. If later setup grows
more complex, make one cleanup path responsible for unloading it.

An accept action should read and validate all required values before closing.
If validation fails, write a short message to a dedicated text tile and leave
the dialog open. After `start_dialog` returns an accepted status, pass the
collected values to a separate worker.

## Values and callbacks

- Tile values cross the DCL boundary as strings. Parse them deliberately before
  numeric work.
- An `action_tile` action is AutoLISP source stored as a string and evaluated
  when the tile activates. Keep it short.
- `$value`, `$key`, `$reason`, `$data`, `$x`, and `$y` are callback-context
  variables whose usefulness depends on the tile and event. Do not assume every
  one is populated for every action.
- Keys are the contract between the DCL and AutoLISP files. Treat a key change
  like an interface change.

For list controls, place `start_list`, each `add_list`, and `end_list` next to
one another so incomplete updates are easy to spot. For image controls, bracket
drawing calls with `start_image` and `end_image`.

## Failure checklist

- The DCL path is explicit and exists on the target host.
- The definition name passed to `new_dialog` matches the DCL declaration.
- Every action and runtime tile call names an existing key.
- Initial values are set after `new_dialog` and before `start_dialog`.
- Accept reads required values before `done_dialog`.
- Cancel does not invoke the drawing worker.
- A loaded dialog is unloaded on every return path.
- Drawing commands and prompts run only after the dialog has closed.
- Platform support is checked against the exact AutoCAD edition and version.

## Sources

Function names, lifecycle details, and callback variables were checked on
2026-07-26 against:

- Autodesk, “About the Function Sequence to Display and Work with a Dialog
  (DCL),”
  <https://help.autodesk.com/cloudhelp/2026/ENU/AutoCAD-AutoLISP/files/GUID-FD32ADB3-F16E-42AA-BD37-53259B824AAB.htm>.
- Autodesk, “action_tile (AutoLISP/DCL),”
  <https://help.autodesk.com/view/ACDLT/2025/ENU/?guid=GUID-A9E2C14E-1352-4C7B-89F0-C86D3A86B19D>.
