# XREF read fixtures

This directory contains two project-maintained ASCII DXF fixtures. Their
construction bases and exact hashes are recorded in
`tests/fixture-provenance.json`.

The admitted binary fixture boundary is exactly
`portable-evidence-ascii.dxf` and `non-utf8-ansi-1252.dxf`. Each fixture proves
only the exact persisted read behavior named under its matching heading below;
neither is general certification for another DXF or DWG producer. The
dependency descriptors below `graph/` are synthetic JSON contracts documented
by `graph/README.md`, not drawing fixtures.

## `portable-evidence-ascii.dxf`

This hand-authored AC1027 ASCII DXF is the complete portable success fixture.
Its table, block, and entity records are intentionally not in numeric handle
order. It proves:

- distinct owner-linked `BLOCK_RECORD` identities and `BLOCK` definitions;
- direct attachment (`70 & 4`), direct overlay (`70 & 8`), and external/nested
  attachment (`70 & 4` plus externally-dependent bit `16`) membership;
- rejection of a path-only ordinary block as XREF membership evidence;
- exact relative and explicitly empty saved paths;
- non-zero definition base points;
- model-space, paper-space, and named-block instance owners;
- exact layer handles/names, insertion points, scales, rotations, normals, and
  entity visibility;
- an ordinary `INSERT`, a 2x3 rectangular array, and an explicit 1x1 array;
- numeric attachment and instance ordering.

DXF persists a command-created MINSERT as an `INSERT` entity carrying groups
`70`, `71`, `44`, and `45`. Explicit presence of those groups is the persisted
class evidence used here, including for the 1x1 array whose counts alone would
otherwise be indistinguishable from a single insert.

The direct attachment records sort to handles `F`, `10`, and `11`. Their
instance handles sort to `20`, `30`, `F0`, and `100`.

The public attachment records represented by this fixture are:

| Handle | Name | Saved path | Path mode | Type | Instances | Base point |
|---|---|---|---|---|---:|---|
| `F` | `SITE_MODEL` | `refs/site.dwg` | `relative` | `attachment` | 2 | `{1,2,3}` |
| `10` | `GRID_OVERLAY` | `refs/grid.dwg` | `relative` | `overlay` | 1 | `{0,0,0}` |
| `11` | `EMPTY_PATH` | empty string | `unsupported` | `attachment` | 1 | `{-1,-2,-3}` |

Every record also has `load_state:"unavailable"`. The complete closed
attachment shape is `handle`, `name`, `saved_path`, `path_mode`,
`reference_type`, `load_state`, `instance_count`, and
`definition_base_point`; the obsolete `path` field is not present.

The four public instance records are intentionally split across model space,
paper space, and a named block definition. Filters have deterministic evidence:

- attachment `F` selects `F0`, then `100`;
- attachment name `GRID_OVERLAY` selects `20`;
- paper-space ownership selects `20`;
- layer `XREF_LAYER` selects `20`, `30`, then `F0`;
- hidden visibility selects `30`.

The referenced source files are deliberately absent. Resolving attachment `F`
therefore returns `resolution_state:"not_found"` with no resolved path, basis,
or search-path index. A dependency traversal rooted at `F` contains one root
occurrence with `inspection_state:"not_resolved"`. This proves the public
missing-source read shape without claiming nested-source inspection evidence.

## `non-utf8-ansi-1252.dxf`

This hand-authored AC1015 ASCII DXF declares `$DWGCODEPAGE=ANSI_1252`. The
stored attachment name `CAFÉ_SITE` and path `réfs/site.dwg` contain accented
characters in the file (`CAF\xC9_SITE` and `r\xE9fs/site.dwg`), so the file is
deliberately invalid UTF-8.

The source text is maintained conceptually as Unicode and encoded with:

```sh
iconv -f WINDOWS-1252 -t UTF-8 non-utf8-ansi-1252.dxf > /tmp/xref-source.utf8
iconv -f UTF-8 -t WINDOWS-1252 /tmp/xref-source.utf8 \
  > non-utf8-ansi-1252.dxf
```

This fixture proves that the local code-pair adapter honors the declared code
page instead of decoding arbitrary bytes as UTF-8.

## DWG boundary

No DWG file is checked in for this task. A DWG emitted solely by the same
acadrust version under test would be a round-trip exercise, not independent
persisted provenance, and must not be presented as a supported DWG fixture.
The code rereads the public low-level DWG object stream from the same captured
byte snapshot to recover `BlockHeaderData`, owner-linked structural markers,
and the discarded xref-dependent bit. DWG base point and load state are exposed
only when that adapter completes; otherwise their evidence remains unavailable
or the affected XREF fails closed.
