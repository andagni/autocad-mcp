# Tier 1 — Required Open-Licence Corpus

Tier 1 is a committed, non-optional gate. Its exact ordered inventory and byte
digests are defined in `manifest.json`; ignored sibling files are never part of
the gate. Each drawing has an exact exception in `tests/.gitignore`.

## ACadSharp fixtures

- Project: [DomCR/ACadSharp](https://github.com/DomCR/ACadSharp)
- Pinned snapshot: `b7fa6a99c2399b71931d7591a3eded99f6a958ad`
- Upstream paths:
  - `samples/dynamic-blocks/BLOCKVISIBILITYPARAMETER.dwg`
  - `samples/dynamic-blocks/BLOCKVISIBILITYPARAMETER.dxf`
- Local paths: the matching files under `acadsharp/dynamic-blocks/`
- Licence: MIT, copyright 2021 Albert Domenech; the complete pinned notice is
  retained at `acadsharp/LICENSE`.
- Original introduction: ACadSharp commit
  `a42674099bd4d3fdcc16ba8f5b52a365fe179a2a`.
- Local modifications: none; both local files are byte-identical to the pinned
  upstream snapshot.
- Purpose: exercise paired binary DWG and ASCII DXF parsing and a read/write/read
  round trip that preserves entity-type counts and the layer-name set, using a
  nontrivial dynamic-block sample.

The SHA-256 digests are recorded in `manifest.json`. To update either file,
review the upstream licence at the proposed new pin, fetch the exact upstream
path, verify the bytes and provenance, update the pin and digest together, and
run the Tier-1 gate before review.

## Generic project fixture

`project/generic-title-block-ascii.dxf` is generated from the two INSERT
definitions in the ignored
`regenerate_synthetic_project_profile_fixture` regression. The target INSERT
uses the generic `AUTOCAD_MCP_GENERIC` profile and inert example values; the
other INSERT is a nonmatching control.

The fixture exercises the production survey schema, redaction, profile
resolution, and scoped ASCII-DXF title-block mutation. Its byte digest is
pinned in `manifest.json` and in the repository-wide fixture-provenance ledger.
Regeneration must update both digests and pass the same profile, survey,
mutation, and entity-count/layer-set round-trip assertions in one review.

## Excluded candidates

The locally cached NextGIS primitive corpus is not redistributable on the
evidence currently available. Its actual upstream repository is
[`nextgis/dwg_samples`](https://github.com/nextgis/dwg_samples), which has no
`LICENSE`, `COPYING`, or `NOTICE` file in the reviewed history. Those files
remain ignored and are not part of Tier 1.
