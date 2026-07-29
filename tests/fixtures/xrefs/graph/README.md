# XREF dependency graph descriptors

These JSON files describe virtual dependency graphs for the pure traversal
engine. They are documentation and review fixtures, not CAD files. Paths and
filesystem identities are synthetic labels supplied by an injected test
provider.

Each descriptor has `descriptor_version: 1` and a `scenarios` array. A
scenario records the minimum source graph facts needed to explain its expected
pre-order chains, terminal states, cycle target, or first truncation. Handle
arrays use canonical hexadecimal strings and are ordered numerically where
ordering is part of the scenario.

The descriptors intentionally abbreviate `XrefAttachmentRecord` fields that do
not affect graph behavior. The unit tests construct complete public attachment
records and assert exact `XrefDependencyRecord` and traversal-envelope output.

`unsupported` entries are provider outcomes for readable paths whose complete
child set cannot be proven. No unsupported or proxy DWG/DXF binary is
fabricated here; those formats require separately certified evidence.

Files:

- `traversal.json`: numeric depth-first pre-order and overlay propagation.
- `cycles-and-diamonds.json`: ancestry identity cycles and repeated expansion.
- `states-and-limits.json`: terminal source states and deterministic limits.
