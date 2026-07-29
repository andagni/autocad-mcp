# AutoLISP reference index

This directory contains the reference material shipped with the AutoLISP skill
and language server. Load only the document relevant to the current task.

| File | Purpose |
|---|---|
| `01_core_playbook.md` | Command boundaries, local state, cleanup, and review |
| `02_entity_and_selection_cookbook.md` | Current-drawing entity and selection operations |
| `03_pitfalls_and_failure_modes.md` | The small hazard set enforced or highlighted by `autolisp-validate` |
| `04_object_model_and_internals.md` | Choosing among entities, tables, dictionaries, xrecords, and xdata |
| `05_dcl_dialogs.md` | Connecting one modal DCL dialog to an AutoLISP worker |
| `06_execution_contexts_and_headless.md` | Keeping GUI assumptions out of console workers |
| `dcl/reference-dcl-summary.md` | Maintained DCL vocabulary and runtime calls |
| `autolisp-lsp-index.json` | Curated hover and completion records |
| `documentation-provenance.json` | Exact file hashes and source-use declarations |

## Authority

Target-project source, loaders, tests, and supported-host contracts outrank this
general guidance. Verify unfamiliar functions and version-sensitive behavior
against the current product reference and the exact AutoCAD release in scope.

The language server index is a convenience, not a complete AutoLISP
specification. Likewise, `autolisp-validate` performs static checks only; it
does not prove that AutoCAD can load or execute a routine.

## Provenance and licence

`documentation-provenance.json` records:

- every shipped AutoLISP skill/reference file;
- the SHA-256 of its exact bytes;
- its disposition and outbound licence; and
- each external source's limited role.

Package creation and package smoke validate that inventory. Adding or changing a
reference requires an explicit ledger update; an unrecorded file or stale hash
fails closed.

The superseded reference set was removed rather than relicensed. It had no
per-file inbound-rights record, included transformed Autodesk Help tables, and
described itself as derived from a community FAQ whose redistribution terms did
not permit excerpting or adaptation.

## External factual references

- Autodesk, “Functions Reference (AutoLISP),”
  <https://help.autodesk.com/cloudhelp/2025/ENU/AutoCAD-LT-AutoLISP-Reference/files/GUID-4CEE5072-8817-4920-8A2D-7060F5E16547.htm>.
- Autodesk, “AutoLISP Developer's Guide,”
  <https://help.autodesk.com/cloudhelp/2026/ENU/AutoCAD-AutoLISP/files/GUID-265AADB3-FB89-4D34-AA9D-6ADF70FF7D4B.htm>.
- Autodesk, “DCL Tiles Reference,”
  <https://help.autodesk.com/cloudhelp/2026/ENU/AutoCAD-AutoLISP-Reference/files/GUID-F8F5A79B-9A05-4E25-A6FC-9720216BA3E7.htm>.
- Autodesk copyright permission policy,
  <https://www.autodesk.com/company/legal-notices-trademarks/intellectual-property/copyright>.
- `comp.cad.autocad` AutoLISP FAQ v2.28 archive,
  <https://groups.google.com/g/alt.cad.autocad/c/lEV9RPpQV9k>.

URLs were reviewed on 2026-07-26. Autodesk, AutoCAD, and AutoLISP are marks of
Autodesk, Inc. AutoCAD-MCP is not sponsored, endorsed, or affiliated with
Autodesk.
