# 02 — Safe Current-Drawing Entity Work

Use this file when a routine must inspect or make a bounded change to objects in
the drawing that AutoLISP is currently executing against.

## Read object data without inventing structure

`entget` returns an association list for the requested object. Each entry is
identified by a DXF group code, but a code's meaning still depends on the object
type. Read by code and handle absence explicitly; do not depend on list
position.

```lisp
(defun amcp:object-layer (object-name / object-data layer-cell)
  (setq object-data (entget object-name)
        layer-cell (and object-data (assoc 8 object-data)))
  (if layer-cell
    (cdr layer-cell)
    nil))
```

The object name is valid only in the current drawing session. If later work
needs to locate the same object again, record a stable domain identifier or a
handle and be prepared for lookup to fail.

Do not flatten repeated group codes into a single map entry. Repetition can be
meaningful, so an inspection result should retain source order where order
matters.

## Select narrowly

Give `ssget` a filter whenever the operation has a known object type, layer, or
other filterable property. Build a filter with `list` and `cons` when a value is
held in a variable.

```lisp
(defun amcp:text-on-layer (layer-name / filter)
  (setq filter
        (list
          (cons 0 "TEXT")
          (cons 8 layer-name)))
  (ssget "_X" filter))
```

Treat a `nil` result as an empty result unless the operation's contract says
that absence is an error. Iterate with `sslength` and `ssname`; release the
selection-set binding when processing is complete.

A database-wide selection can include objects from more than one drawing
space. If space or layout is part of the question, inspect and return that
attribution rather than assuming all results belong to the current view.

## Modify the smallest possible field

The safe editing pattern is:

1. read the object immediately before mutation;
2. validate type, owner, space, and any operation-specific preconditions;
3. replace only the intended association-list entry;
4. submit the complete preserved list to `entmod`;
5. treat a failed return as failure; and
6. read the object again to verify the intended semantic result.

For example, changing an existing layer field can be expressed without
rebuilding unrelated object data:

```lisp
(defun amcp:move-to-layer (object-name target-layer / before layer-cell after)
  (setq before (entget object-name)
        layer-cell (and before (assoc 8 before)))
  (if layer-cell
    (progn
      (setq after
            (subst
              (cons 8 target-layer)
              layer-cell
              before))
      (if (entmod after)
        (entupd object-name)
        nil))
    nil))
```

This example assumes the target layer and object are appropriate for the
calling operation. A production routine must make those preconditions
explicit. Do not use a generic “replace group” helper for point groups or other
values whose list shape differs from an atomic dotted pair.

Color is a multi-field property. Before changing an indexed color, inspect
true-color and color-book data as well. Prefer the shipped layer tools when they
cover the request because their preservation and conflict rules are tested.

## Create only from a complete, reviewed schema

`entmake` accepts object-definition data and returns `nil` when creation fails.
Do not guess mandatory fields or subclass data. Start from a reviewed schema for
the exact object type and target release, check the return value, and then
locate and verify the created object.

Creation code must also define:

- the intended owner and drawing space;
- units and coordinate system;
- dependencies such as layers, styles, or block definitions;
- cleanup if a later step fails; and
- how the operation participates in undo.

When the required schema is uncertain, fail with an actionable explanation
instead of emitting a partial object list.

## Keep coordinate systems visible

State the coordinate system of every input and output point. `trans` converts
between the current UCS, WCS, display coordinates, and an object's OCS. Pass an
entity name when conversion must use that object's coordinate system.

Do not combine user-picked points, stored entity points, and output coordinates
until their systems agree. For displacement vectors, call `trans` in vector
mode rather than treating the value as a location.

## Preserve multiplicity and ownership

Block attributes are ordered subobjects. Attribute tags can repeat after
normalization. A reader must retain every value, and a writer must reject an
ambiguous requested tag rather than selecting one silently. This matches the
project's scalar-plus-array title-block contract.

Edits inside a block definition can affect multiple inserts. Confirm whether
the selected object is an insert, an attribute owned by an insert, or an object
owned by a block definition before mutating it.

Structural fields, reactors, extension dictionaries, and unknown groups are
not spare data. Preserve them unless the operation owns a documented
transformation for them.

## Project anchors

- `crates/autocad-mcp/src/ops/entities.rs`
- `crates/autocad-mcp/src/ops/title_blocks.rs`
- `crates/autocad-mcp/src/server.rs`
- `crates/autocad-mcp/tests/integration.rs`

## Sources

API details were checked on 2026-07-26 against Autodesk's
[entity-data overview](https://help.autodesk.com/cloudhelp/2026/ENU/AutoCAD-AutoLISP/files/GUID-B150646B-5F8F-460A-A5D6-AF7BD467B638.htm),
[`entget` reference](https://help.autodesk.com/cloudhelp/2026/ENU/AutoCAD-LT-AutoLISP-Reference/files/GUID-12540DAE-C84B-4BDB-AEEC-DDFE5BE3C42A.htm),
[selection-filter guidance](https://help.autodesk.com/cloudhelp/2026/ENU/AutoCAD-LT-AutoLISP/files/GUID-7BE77062-C359-4D01-915B-69CF672C653B.htm),
and [coordinate transformations](https://help.autodesk.com/cloudhelp/2026/ENU/AutoCAD-AutoLISP/files/GUID-0F0B833D-78ED-4491-9918-9481793ED10B.htm).
