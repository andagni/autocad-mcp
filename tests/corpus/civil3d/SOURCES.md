# Tier 3 — Civil 3D Tutorial Drawings

The files in this directory are Autodesk's property, are gitignored, and must not be committed to this repository.

## Description & Purpose

These drawings contain live Civil 3D proxy objects (e.g. corridors `AeccDbCorridor`, alignments, surfaces, pipe networks). They are used to validate that `acadrust` reads past unknown proxy blobs without panicking.

## Acquisition Instructions

After locating them on a machine with Civil 3D installed (version 2019 or onwards), copy the entire `Drawings\` directory to `tests/corpus/civil3d/`.

### Source Location
On a default Windows installation, the files reside at:
`C:\Program Files\Autodesk\AutoCAD <version>\C3D\Help\Civil Tutorials\Drawings\`

*Note: Please document the source path and Civil 3D version actually used below if you copy them here.*
