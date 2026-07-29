# Tier 2 — Autodesk Sample Files

The files in this directory are Autodesk's property, are gitignored, and must not be committed to this repository.

## Download Sources

1. **Official AutoCAD Sample Files (~89 files)**
   - **URL:** [AutoCAD Sample Files Support Page](https://knowledge.autodesk.com/support/autocad/downloads/caas/downloads/content/autocad-sample-files.html)
   - **Contents:** Annotation scaling, multileaders, civil examples, architectural plans, mechanical assemblies, and a color wheel.

2. **AutoCAD Mechanical Sample Files**
   - **URL:** [AutoCAD Mechanical Sample Files Support Page](https://www.autodesk.com/support/technical/article/caas/tsarticles/ts/5FT67coP41xn6vjfEgyGQo.html)
   - **Contents:** Gear assemblies, robot cells, and structural members (useful for 3D solid/ACIS SAB coverage).

## Repositories & Relocations

1. **ACadSharp AEC Objects**
   - **Source:** Originally located at `samples/aec_objects/` in [ACadSharp](https://github.com/DomCR/ACadSharp).
   - **Relocation Rationale:** Relocated to `tests/corpus/autodesk/aec_objects/` upon fetch as it contains ObjectARX proxy content (`AecObjects.dwg`) which makes it Tier 2 material.
