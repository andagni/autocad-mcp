# Maintained DCL vocabulary

This is a compact routing aid for the DCL used by the AutoLISP skill. It is not
a substitute for the versioned Autodesk DCL reference. Confirm edition and
platform support there before using a name outside this maintained subset.

## Structure

| Name | Project use |
|---|---|
| `dialog` | Root definition for one modal dialog |
| `row`, `column` | Arrange children on one axis |
| `boxed_row`, `boxed_column` | Arrange children with a visible group boundary |
| `radio_row`, `radio_column` | Hold a mutually exclusive set of radio buttons |
| `spacer`, `spacer_0`, `spacer_1` | Add or reserve layout space |

## Input and display

| Name | Project use |
|---|---|
| `button` | Trigger an action |
| `edit_box` | Edit one string value |
| `list_box` | Choose from a visible list |
| `popup_list` | Choose from a compact drop-down list |
| `radio_button` | Select one member of a radio group |
| `toggle` | Represent a two-state choice |
| `slider` | Select a value over a bounded range |
| `text` | Show non-editable text |
| `image`, `image_button` | Display or interact with tile graphics |

The predefined `ok_only`, `ok_cancel`, and related exit clusters provide the
standard `accept` and `cancel` actions. Prefer them unless the dialog has a
reviewed reason to own custom exit controls.

## Frequently used attributes

| Attribute | Review question |
|---|---|
| `key` | Does every runtime call use the same unique key? |
| `label` | Is the displayed caption clear and stable? |
| `value` | Is the initial string valid for this tile? |
| `width`, `height` | Is an explicit size actually required? |
| `edit_width` | Is the editable region wide enough for expected input? |
| `is_enabled` | Should the tile accept input at startup? |
| `is_default`, `is_cancel` | Does keyboard acceptance/cancellation reach the intended action? |
| `multiple_select` | Does the list parser handle more than one selected index? |
| `min_value`, `max_value`, `small_increment`, `big_increment` | Are slider limits and steps mutually consistent? |
| `tabs`, `fixed_width_font` | Is list-column presentation intentional? |

Do not copy an attribute onto an unrelated tile merely because it exists. The
official per-tile reference is authoritative for applicability.

## Runtime calls

| Call family | Responsibility |
|---|---|
| `load_dialog`, `new_dialog`, `start_dialog`, `done_dialog`, `unload_dialog` | Own the dialog lifetime |
| `action_tile` | Associate a tile key with a deferred AutoLISP action |
| `get_tile`, `set_tile`, `get_attr`, `mode_tile` | Read or alter active tile state |
| `start_list`, `add_list`, `end_list` | Replace or update list content |
| `client_data_tile` | Attach application-managed string data to a tile |
| `start_image`, `fill_image`, `vector_image`, `slide_image`, `end_image` | Draw within an image tile |
| `dimx_tile`, `dimy_tile` | Read image-tile dimensions |

Every bracketed call family must be balanced: a started list or image update
must be ended, and every successfully loaded dialog must be unloaded.

## Syntax reminders

- A named dialog definition uses `name : dialog { ... }`.
- A child tile uses `: tile_name { ... }`.
- Attribute assignments end with `;`.
- String literals are quoted.
- `//` begins a DCL comment.
- Names and values are case-sensitive where the product reference says they
  are; preserve exact keys across DCL and AutoLISP.

## Source

Names and applicability were checked against Autodesk's DCL reference and
dialog lifecycle documentation, accessed 2026-07-26:

- <https://help.autodesk.com/cloudhelp/2026/ENU/AutoCAD-AutoLISP/files/GUID-FD32ADB3-F16E-42AA-BD37-53259B824AAB.htm>
- <https://help.autodesk.com/cloudhelp/2024/ENU/AutoCAD-AutoLISP-Reference/files/GUID-B2125253-ABE7-4005-9218-72AAF551F442.htm>
- <https://help.autodesk.com/cloudhelp/2026/ENU/AutoCAD-AutoLISP-Reference/files/GUID-F8F5A79B-9A05-4E25-A6FC-9720216BA3E7.htm>
