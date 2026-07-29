# AutoCAD MCP

AutoCAD MCP is a local Model Context Protocol server for inspecting and
changing AutoCAD DWG and DXF drawings. The same Rust binary supports:

- MCP clients through `autocad-mcp serve`
- command-line discovery through `autocad-mcp list-tools`
- scripted calls through `autocad-mcp call <tool> <json-params>`

Claude Desktop runs the server locally as a stdio subprocess. AutoCAD MCP does
not need to expose a localhost port, and protocol messages never leave the
local process boundary merely to reach the server.

This repository also contains the AutoLISP language server and validator,
the bounded drawing reader and writer libraries, bundled Claude skills, and
the tooling used to validate, qualify, package, and reproduce distributions.

## Distribution status

This repository contains development source and candidate tooling.
No public MCPB or Windows Release has been approved for distribution. The
first planned binary distribution is a visibly marked, non-certifying Windows
x64 Preview accompanied by its exact build-source artifact. A local executable
or locally generated MCPB is development output, not evidence of signing,
clean-host acceptance, owner approval, native AutoCAD qualification, or
Release status.

The first public binary tranche is Windows Preview only. macOS packaging is
deferred platform work, and Linux is a build-supported read-only horizon
rather than a package target. Publication of repository source and approval of
a binary distribution are separate events.

## Platform capabilities

| Capability | macOS arm64 | Windows x64 |
|---|---:|---:|
| Core DWG and DXF read routes | Yes | Yes |
| Rich drawing, entity, block, layout, text, and symbol inspection | DWG only | DWG only |
| Supported native-DXF writes | Implemented | Implemented |
| DWG layer and title-block writes | No | Implemented with admitted full AutoCAD; distribution qualification pending |
| XREF mutations | No | Preview opt-in candidate; Release is qualification-gated |
| PDF plotting (DWG only) | No | Implemented with admitted full AutoCAD; distribution qualification pending |

Windows is the intended production host for engine-backed tools. The
implementation contains the nine XREF mutation contracts, guarded TxF install,
exclusive source-snapshot resolution, deterministic race drivers, per-launch
unique profile lifecycle, and a Windows AutoCAD backend. This is an
implementation candidate, not a release claim: the exact native Windows/NTFS
transaction regression, strict release and instrumented XREF lanes, package-safe
evidence join, and clean-host acceptance must pass before Release. TxF is deprecated
by Microsoft, so an unavailable transaction facility fails closed rather than
falling back to an unguarded replacement.

Preview activation admits only catalogue-listed full AutoCAD on Windows x64
with the exact `en-US` product-language tuple for AutoCAD 2018 through 2027.
That is an evaluation window, not a support claim. The planned
maintained-support range is AutoCAD 2024 through 2027, but no row is supported
until its required native evidence and signed Release qualification exist.
AutoCAD LT, OEM, Civil 3D, Map 3D, specialist toolsets, other locales, and
uncatalogued releases are not admitted. macOS supports local development, read
workflows, and supported native-DXF writes; its MCPB is outside the first
public binary tranche.

Windows packaging has two explicit modes. Preview accepts only a closed,
stable-form pre-1.0 version written `0.minor.patch`; Preview packages generated
from this source use `0.0.1` and are visibly marked as evaluation artifacts,
not Release candidates or certification results. Release requires a closed
stable-form version whose major component is at least 1, making `1.0.0` the
first eligible version, and requires every
native AutoCAD, private-evidence join, package-privacy, signing, dependency, and
clean-host gate. A Preview-capable binary exposes only the 36 read-only tools
through plain `serve`; `serve --experimental` opts into all 51, including the
15 state-changing tools. The default binary flavor is compiled without that
option, rejects it as unknown, and exposes all 51 tools through plain `serve`.
That CLI shape does not make a local build a qualified or distributable
Release. Only a Release package with the required external qualification may
describe that surface as certified; Windows Release packaging fails closed
before archive creation.

The Preview flag changes tool exposure, not operation safety. Engine-backed
calls use the process-selected catalogue row and its exact row-specific
ARG/policy. Every state-changing call uses its applicable platform and engine
admission, TxF transaction, immutable-source snapshot, race, preservation,
verification, and retry paths. Preview introduces no separate mutation-root
restriction; the documented absolute host/source path contracts are
authoritative.

The rich structured inspection routes are deliberately DWG-only on every build
target. The selected reader dependency is acadrust 0.4.1. Fixture evidence
does not establish reliable DXF BLOCK_RECORD classification, units, or rich
field projection, so DXF access is limited to the core read routes.

### Structured read contract highlights

`get_drawing` reports model-space and header-level paper-space geometry exactly
as saved in the drawing header. Each insertion base, extent, and limit is
availability-tagged rather than replaced with guessed geometry, and each space
has separately availability-tagged current-UCS header state. These records use
`source: "saved_header"`; they are not geometry-derived measurements or a
coordinate-reference-system inference. Duplicate block-record handles or a
header model-space handle that contradicts the selected block record fail the
summary rather than producing inconsistent space counts. Space classification
uses the same LAYOUT-object join as entity ownership, including nonstandard
paper-space block names.

Rich text, ordinary block-insert, and generic entity records use one direct
owner contract. `owner_handle` is a separate canonical handle.
`owner_context` is `null` only for a null owner handle; otherwise it is tagged
as either `state: "available"` with `owner_type` and `owner_name`, or
`state: "unavailable"` with reason `unresolved_owner` or
`missing_paper_space_layout`. Available owner types are `model_space`,
`paper_space`, `block_definition`, and `entity`.

`list_text` accepts exact optional `text_types`, `layer`, and direct-owner
filters. Owner selection must use no owner fields, `owner_handle` alone,
`owner_type` plus `owner_name`, or all three; when all three are supplied they
must agree. Exact entity, text, block, layout, plot-setting, and symbol names
reject surrounding whitespace rather than silently changing selector identity.
The result is a deterministic JSON array. `dump_text` provides the compact text
projection; `list_text` provides the rich filtered records.

`read_title_blocks` returns unique tags as scalar `attributes` by default and
keeps every duplicate normalized tag value in ordered `attribute_arrays`.
Duplicate tags are successful partial MCP data with structured warnings, not a
whole-drawing read failure; `attribute_value_mode: "arrays"` returns every tag
as an array. `write_title_block` checks every requested tag's multiplicity
before mutation. A duplicate unrequested tag does not by itself block another
mapped field from being written.

Generic entity bounds and unsupported detail carry closed availability
reasons; parser-defaulted ATTDEF/ATTRIB strings are not presented as persisted
data. Generic INSERT detail and ordinary block-insert records share bounded,
deterministic dynamic-block linkage. The originating definition and visibility
parameter are returned only when proven. The selected visibility state is
explicitly unavailable because the pinned reader does not retain it. TABLE,
MULTILEADER, and 3DSOLID detail and bounds are explicitly unsupported until
representative committed decoder proof exists. SHAPE and TOLERANCE bounds, plus
DIMENSION and LEADER bounds, and 2D polyline bounds with bulges, width,
thickness, fitted geometry, or a non-world normal, are
`unreliable_model_projection` rather than approximate boxes. A parser-clamped
INSERT scale fails closed because its saved value cannot be recovered.
HELIX detail exposes its bounded saved axis, start, radius, turn, handedness,
and constraint fields, while its spline-control-hull bounds remain
`unreliable_model_projection`. ACAD_SURFACE entities preserve their decoded
subtype name but remain inventory-only: bounds are `unsupported_entity_type`
and detail is explicitly unsupported. Bounds support is exhaustively
allowlisted, so an unreviewed backend variant cannot silently publish a box.
Unscoped entity, block-insert, text, and viewport lists validate their
applicable semantic-handle domains, so a cross-type collision cannot
masquerade as a stable listed identity. Exact scoped text queries validate only
the selected raw records, and targeted entity, text, and viewport reads do not
fail because of unrelated malformed handles. Valid handles on ATTRIB records
nested under INSERTs participate in target-collision checks. A nonempty
saved XREF path is direct
attachment-definition evidence even when the pinned parser did not retain
either XREF flag.

Layout reads reject inverted limits and malformed extents, while the
exact AutoCAD empty-layout extent sentinel is returned as `null`. Layout and
viewport records expose last-active viewport identity rather than calling it
primary. Viewport on/off is unavailable in the public contract pending
separate qualification, even though the selected backend retains that bit;
custom scale is also unavailable. Zero scale operands produce `null`, while
negative or non-finite operands fail. Plot scale factors require finite
positive operands. Layout and viewport classification
uses the shared semantic owner resolver even when the header model-space
handle is unavailable, and contradictory header/owner facts fail closed. The
compact `list_layouts` projection is available alongside the rich layout,
plot-setting, and viewport routes.

### Internal mutation validation

There is no public mutation-preflight tool. Each mutation performs its own
schema, context-free, filesystem, drawing, platform, AutoCAD, capability,
identity, guard, locking, preservation, verification, and recovery checks.
Initialization and admission are server responsibilities rather than
preparatory MCP work for a drafter or agent.

Title-block corpus surveying is likewise absent from the drafter-facing MCP and
generic `call` surfaces. Administrators use the separate
`autocad-mcp admin title-block` namespace described below.

### Administrator title-block profiles

The embedded title-block registry is the default. An administrator can
survey a private corpus, cluster exact fingerprints, validate an extend-only
profiles file, and verify it against digest-bound representative drawings:

```text
autocad-mcp admin title-block survey --root /absolute/corpus --input /absolute/corpus/project --corpus-tier 2 --output survey.jsonl
autocad-mcp admin title-block cluster --survey survey.jsonl --output clusters.json
autocad-mcp admin title-block validate --profiles /absolute/config/title-block-profiles.json
autocad-mcp admin title-block verify --profiles /absolute/config/title-block-profiles.json --witnesses /absolute/private/profile-witnesses.json
```

Survey values are redacted unless `--include-values` is explicit; clustering
never propagates them. These commands are offline administrator conveniences,
not MCP tools, and verification does not mutate drawings or activate the file.
Survey output is strict JSON Lines with `survey_schema: 1`, safe
corpus-relative drawing identifiers, exact drawing digests, tiers, formats,
and normalized candidate fingerprints. Cluster output has
`cluster_schema: 1`, binds the exact survey digest, and contains no observed
attribute values. A profiles file has `profile_pack_schema: 1`, a pack ID and
version, `title_block_schema: 1`, and one or more exact block-name plus sorted
attribute-tag fingerprints with canonical field mappings. A private witness
file has `profile_witness_schema: 1` and binds each profile to at least one
absolute representative drawing and exact digest. Validation is extend-only:
administrator profiles cannot collide with or replace embedded profiles.
Verification rehashes each witness before and after reading, requires an exact
fingerprint match and unique mapped tags, and emits value-free results.

Activate one reviewed file for `serve` or direct `call` with:

```text
autocad-mcp serve --title-block-profiles /absolute/config/title-block-profiles.json
```

`AUTOCAD_MCP_TITLE_BLOCK_PROFILES` is the optional fallback; an explicit
`--title-block-profiles` value wins, and an unset or empty environment value
uses embedded profiles only. Loading is fail-closed and happens once before the
server starts. There is no hot reload, MCP registration tool, caller-selected
profile ID, or embedded-profile override. Preview requires
`--experimental` to expose mutation tools; Release does not define that option.

Generated MCPB packages present the same setting as an optional
`title_block_profiles` file chooser. A successful administrator-profile write
reports its profile authority, pack ID, version, and exact file digest.
Administrator profiles enable local operation; they do not become embedded,
maintained-support, or AutoCAD-certification claims.

## Prerequisites

- The Rust toolchain pinned by `rust-toolchain.toml`
- A concrete Claude Desktop version; clean-host evidence records the exact
  numeric version tested
- Windows x64 and a catalogue-admitted full AutoCAD installation for
  engine-backed Preview evaluation
- A local drawing path readable by the user running Claude Desktop

AutoCAD is not required for the committed portable-DXF smoke test or for
read-only development.

## Build the local server

From the repository root:

```text
cargo build --locked --release -p autocad-mcp
```

That command creates a local binary with the Release CLI shape: plain `serve`
exposes all 51 tools and `serve --experimental` is not defined. It does not
create an approved Release; Windows Release packaging rejects the missing
qualification and package-safe binding. Building a local Preview-capable
binary is explicit:

```text
cargo build --locked --release -p autocad-mcp --features preview
```

For that flavor, plain `serve` exposes only the 36 read-only tools. Add
`--experimental` only when intentionally opting into all 51. Preview
`list-tools` and `call` follow the same boundary and accept that option for
full-surface discovery or direct dispatch. Rebuilding either flavor at the
default target path replaces the preceding executable; package validation
independently rejects a binary whose flavor does not match its requested
`PackageMode`.

The resulting executable is:

- macOS: `target/release/autocad-mcp`
- Windows: `target\release\autocad-mcp.exe`

Test the exact executable through a Claude Desktop-equivalent stdio lifecycle:

```text
cargo run --locked -p release-packager -- desktop-smoke --binary target/release/autocad-mcp --fixture tests/fixtures/xrefs/portable-evidence-ascii.dxf
```

On Windows PowerShell, use:

```text
cargo run --locked -p release-packager -- desktop-smoke --binary target\release\autocad-mcp.exe --fixture tests\fixtures\xrefs\portable-evidence-ascii.dxf
```

For the default, non-Preview local binary, this gate checks:

1. the CLI tool inventory and read contracts;
2. MCP `initialize` and the initialized notification;
3. MCP `tools/list` with the complete 51-tool annotation contract;
4. an MCP `tools/call` read against an absolute fixture path; and
5. clean server exit when the client closes stdin.

A pass proves the native executable's local protocol and process lifecycle. It
does not prove installation in the Claude Desktop application or any operation
that requires AutoCAD. `desktop-smoke` is not the Preview-flavor gate. Preview
package smoke validates both exposures: plain `serve` must discover exactly the
36 read-only tools, while the package's explicit `serve --experimental` launch
must discover the complete 51. Neither result is native AutoCAD certification.

## Connect a development build to Claude Desktop

Use an absolute executable path. Do not configure Claude Desktop to run
`cargo`, depend on a shell profile, or resolve a repository-relative path.

### Windows

Open Claude Desktop's developer configuration and add:

```json
{
  "mcpServers": {
    "autocad-mcp": {
      "command": "C:\\absolute\\path\\to\\AutoCAD-MCP\\target\\release\\autocad-mcp.exe",
      "args": ["serve"]
    }
  }
}
```

When that executable was built with `--features preview`, this
configuration is the read-only 36-tool Preview surface. To opt into the full
Preview surface, change the exact argument array to:

```json
["serve", "--experimental"]
```

A binary built without the `preview` feature rejects that second argument; do
not add it to a Release configuration.

For a manually configured executable, append
`"--title-block-profiles", "C:\\absolute\\config\\title-block-profiles.json"`
to the argument array when a reviewed administrator profiles file is required.
The environment fallback above is equivalent, but the explicit argument takes
precedence.

The file is normally:

```text
%APPDATA%\Claude\claude_desktop_config.json
```

Engine-backed mutation is selected lazily from the exact 64-bit
`HKLM\Software\Autodesk\AutoCAD` installation rows in the package-owned
activation catalogue. Ambient `PATH` and directory-name scanning are not
activation authorities. A Preview `serve --experimental` process may select
one full-AutoCAD Windows x64 `en-US` candidate from 2018 through 2027 and pins
that exact engine/profile/locale for its lifetime. This is Preview evaluation,
not a maintained-support or Release claim. Only add the exact override when
automatic registry selection is unsuitable:

```json
{
  "mcpServers": {
    "autocad-mcp": {
      "command": "C:\\absolute\\path\\to\\autocad-mcp.exe",
      "args": ["serve", "--experimental"],
      "env": {
        "AUTOCAD_MCP_ACCORECONSOLE_PATH": "C:\\Program Files\\Autodesk\\AutoCAD 2026\\accoreconsole.exe"
      }
    }
  }
}
```

The override must name an existing absolute `accoreconsole.exe` path on a fixed
local Windows drive and belong to one otherwise eligible registered catalogue
row. Network and mapped-drive engine installs are not activation candidates;
this bounds engine startup observations and is unrelated to drawing/source
paths, which follow their documented absolute-path contracts. The override
constrains selection and never widens admission; every defect fails without
fallback. Omit the environment entry rather than setting it to an empty string.

`--engine-probe auto|off|on` is a serve-only advisory Core Console warm-up
policy. Preview `serve --experimental` defaults to `auto`; plain Preview and
Release default to `off`. `on` requests the probe for either mutation-enabled
server flavor, while plain read-only Preview rejects `on`; `auto` schedules
only for Preview experimental, and `off` disables it.
`list-tools` and direct `call` do not accept this option.

An enabled probe is scheduled only after the client sends the MCP initialized
notification, then waits a short grace period. An earlier engine-backed request
cancels a merely scheduled probe and owns activation; if the probe is already
running, foreground work cancels it and waits only within its bounded cleanup
policy. A pathological local OS observation can outlive that coordination
window; if it is still performing the shared lifetime engine selection,
foreground work waits for that same selection rather than starting a competing
selection or falling back to another AutoCAD version.
The probe never mutates a user drawing and its success or failure never grants
or removes admission. Catalogue inclusion, candidate selection, and probe
success are Preview evaluation facts, not maintained-support or certification
claims.

### macOS

Add the corresponding absolute path:

```json
{
  "mcpServers": {
    "autocad-mcp": {
      "command": "/absolute/path/to/AutoCAD-MCP/target/release/autocad-mcp",
      "args": ["serve"]
    }
  }
}
```

The file is normally:

```text
~/Library/Application Support/Claude/claude_desktop_config.json
```

Completely quit and restart Claude Desktop after changing either configuration.
The server should then appear in Claude Desktop's MCP or extension UI.
Menu names and locations can change between client versions; use the official
Claude Desktop documentation linked below for the installed version.

## Developer-only macOS package smoke (deferred)

The first publication tranche does not distribute a macOS MCPB. The commands
below provide a developer-only packaging and smoke capability; their output is
not signed, notarized, clean-host accepted, owner-approved, or
distribution-eligible.

Build both local binaries, create the MCPB, and execute static, MCP, CLI, and
LSP smoke against the extracted package:

```text
cargo build --locked --release -p autocad-mcp -p autolisp-lsp
cargo run --locked -p release-packager -- package --target macos-arm64 --binary target/release/autocad-mcp --lsp-binary target/release/autolisp-lsp --out-dir dist
cargo run --locked -p release-packager -- smoke --package dist/autocad-mcp-macos-arm64.mcpb --fixture tests/fixtures/xrefs/portable-evidence-ascii.dxf --require-executable --require-lsp-executable
```

The resulting development file is:

```text
dist/autocad-mcp-macos-arm64.mcpb
```

For local developer testing only, install it using the custom-extension flow
documented for the installed Claude Desktop version. At the time this
procedure was reviewed, the path was:

```text
Settings > Extensions > Advanced settings > Install Extension
```

Select the `.mcpb`, complete the installation, and restart Claude Desktop if
required. This local exercise does not satisfy the deferred macOS distribution
or acceptance gates.

Windows binaries and Windows packages must be built and executable-smoked on a
native Windows x64 host. The repository's Windows-native workflow performs the
three-flavor binary build, stdio lifecycle gate, and non-uploaded Preview
package smoke without AutoCAD. Creation of a Release Windows MCPB additionally
requires the exact native AutoCAD qualification set, package-safe binding,
dependency approval, executable signing and timestamp verification, package
privacy checks, and clean-host acceptance. Missing Release evidence fails
before archive creation.

## Run the repository development gate

Install the tracked hooks once for each checkout:

```text
git config --local core.hooksPath .githooks
```

Run the complete platform-independent source gate with:

```text
cargo run --locked -p xtask -- local-gate
```

The gate runs repository-wide formatting, dependency evidence, warnings-denied
Clippy, default and feature-specific tests, and plugin/repository policy. The
tracked pre-push hook repeats that gate for the exact clean checked-out commit,
then seals and verifies both Release and Preview source candidates. It is a
source-quality gate, not Windows-native AutoCAD, signing, package installation,
or clean-host evidence.

## Run Windows-specific tests without AutoCAD

On a native Windows development machine, run the same repository-owned test
inventory used by Windows CI:

```text
cargo run --locked -p xtask -- windows-native-tests
```

This runs the semantic and guarded-rename suites serially. AutoCAD is not
required or launched, even if it is installed. GitHub Actions is the primary
clean-host CI entrypoint and selects the suites independently with
`--suite semantic` and `--suite guarded-rename`.

## Build the Windows Preview desktop extension

Run this exact lane from a clean checkout on native Windows x64. The two target
output directories must not already exist:

```text
cargo run --locked -p xtask -- windows-certification-build-preflight --arg tests/fixtures/windows_certification/public-development-profile.arg --arg-policy tests/fixtures/windows_certification/public-development-arg-policy.json --output-dir target/windows-certification-preflight
cargo run --locked -p release-packager -- package --target windows-x64 --binary target/windows-certification-preflight/artifacts/preview/autocad-mcp.exe --lsp-binary target/windows-certification-preflight/artifacts/release/autolisp-lsp.exe --out-dir target/windows-preview-package --preview
cargo run --locked -p release-packager -- smoke --package target/windows-preview-package/autocad-mcp-windows-x64-preview.mcpb --fixture tests/fixtures/xrefs/portable-evidence-ascii.dxf --require-executable --require-lsp-executable
```

The resulting evaluation artifact is:

```text
target/windows-preview-package/autocad-mcp-windows-x64-preview.mcpb
```

Its MCPB identity is visibly Preview, its version is `0.0.1` under the closed
`0.minor.patch` Preview policy, and its manifest launches
`serve --experimental`. It also contains the exact staged
`autolisp-lsp.exe`, and package smoke requires that language server to complete
its native initialize/shutdown lifecycle. The exact checked-in 2018–2027
candidate catalogue and all ten closed ARG/policy pairs are embedded in the
binary, staged in the package, and joined by a closed
binary/catalogue/per-file digest binding. No private certification manifest,
evidence, case tree, retained PDF, signed Release qualification, or Release
package binding is included. The native workflow leaves the package in
runner-local `target/` storage and does not upload it.

A passing build/package smoke proves only the exact native binary flavor,
package structure, 51-tool opted-in protocol lifecycle, and portable read call.
It does not run AutoCAD, prove any mutation, certify the public ARG for
production, satisfy Release signing/privacy gates, or turn a `0.0.1`
Preview into a Release candidate.

## Run the licensed-host Preview E2E evaluation

On a native Windows x64 development machine with one licensed full-AutoCAD
installation selected by an exact activation-catalogue row, prepare the strict
private plan and choose a new fixed-local work directory that does not yet
exist. Then run:

```text
cargo run --locked -p xtask -- preview-autocad-e2e --plan C:\absolute\private\preview-autocad-e2e-plan.json --work-dir C:\absolute\private\runs\preview-e2e-001
```

The runner validates the exact Preview MCPB, registered
`accoreconsole.exe`, optional administrator title-block profiles, and six
AC1032 inputs before creating the work directory. It then runs the package's
`serve --experimental` lifecycle, validates all 51 tool contracts, exercises
the fixed read, title-block, layer, plot, and XREF cases, and launches a second
`--engine-probe off` session to reread the persisted mutations. Raw stderr,
staged private drawings, and the retained PDF stay under the explicitly chosen
work directory; the normalized report is
`preview-autocad-e2e-report.json`.

The strict plan has `schema_version: 1`,
`artifact_kind: "preview_autocad_e2e_plan"`, and
`authority: "candidate_only_no_support_claim"`. It binds the package digest,
one activation-catalogue target, one registered Core Console executable and
fixed file version, optional administrator profiles, and the fixed read,
title-block, layer, plot, and XREF cases. It is not a general script and cannot
supply methods, environment variables, or timeouts. Duplicate keys, unknown
fields, unsafe identifiers, malformed digests, mismatched package or engine
bytes, non-fresh work directories, and unowned output paths fail before
evaluation. The report is a candidate-only result and cannot claim
certification, maintained support, publication approval, or Release
qualification.
A pass is an exact local Preview evaluation. It is not certification,
maintained-version qualification, publication approval, or a Release support
claim.

This licensed AutoCAD lane is deliberately not a GitHub Actions job. GitHub
Actions is responsible for the Windows-specific tests that do not require
AutoCAD; repository-portable linting and tests run locally.

For a remotely retained signed review candidate, manually dispatch
`Windows Preview signed review candidate` against `main`, enter the exact
checked-out commit and reviewed signer thumbprint, and explicitly confirm the
live protected-Environment audit. The repository owner must first protect the
`preview-signing` Environment and configure its exact certificate,
certificate-digest, signer-thumbprint, password, and HTTPS timestamp inputs.
Immediately before dispatch, verify its main-only branch policy, required
reviewer, no-administrator-bypass setting, Environment-scoped values, and the
absence of same-named repository or organization fallbacks. The workflow includes
separate no-secret build and package/review jobs around an isolated
no-checkout signing job. It assembles the final upload MCPB before smoking and
extracting that exact path, rechecks both archived executables' bytes, signer,
and timestamp, and retains a seven-day Actions review artifact. Two subsequent
isolated jobs validate the downloaded manifest with the lockfile-pinned
official MCPB CLI and attach supplemental GitHub provenance to the exact
review files. Every job independently requires the fixed repository, server,
main ref, dispatch event, and both owner actor identities before doing any
work, so an individual downstream-job rerun cannot bypass the origin guard.
The validator does not repack or sign the MCPB, and the GitHub attestation is
workflow-origin evidence rather than distribution approval.

That upload is deliberately not a GitHub Release. Its
`review-only/unsigned-development-preflight.json` is development trace output;
the separately retained
`distribution-evidence/windows-x64-preview-build.json` is the final
post-signing Preview build attestation. Publication is blocked until that
exact retained candidate also has a clean-host receipt and detached owner
approval delivered through an authenticated non-repository handoff and
accepted by the current-distribution selector. The official MCPB validation
and supplemental GitHub provenance do not satisfy either of those gates.

## Clean-host Claude Desktop acceptance

Automated stdio smoke is client-equivalent, but it is not a substitute for
testing the actual desktop application. Preview publication requires the
following closed Windows acceptance sequence for the exact signed MCPB.

1. Use a clean Windows x86-64 OS user or machine without this extension
   installed.
2. Record the concrete numeric Claude Desktop and Windows versions. “Latest”
   is not a reproducible version identity.
3. Confirm the extension is absent before installation.
4. Completely quit any running Claude Desktop instance.
5. Install the candidate `.mcpb` through the Extension Developer UI.
6. Confirm the extension is enabled and reports a connected server.
7. Start a new conversation and confirm `autocad-mcp` exposes exactly 51
   tools.
8. Ask Claude to read the public paired DXF fixture
   `tests/corpus/open/acadsharp/dynamic-blocks/BLOCKVISIBILITYPARAMETER.dxf`.
   Approve the read tool and require a result without a protocol-level error.
9. Repeat the read check with
   `tests/corpus/open/acadsharp/dynamic-blocks/BLOCKVISIBILITYPARAMETER.dwg`.
10. Completely quit Claude Desktop and confirm no `autocad-mcp` process
    remains.
11. Reopen Claude Desktop and repeat tool discovery to verify restart and
    reconnection behavior.
12. Uninstall the extension through Claude Desktop and completely quit it.
13. Reopen Claude Desktop and confirm the extension and server are absent.

After quitting Claude Desktop, also check Task Manager or PowerShell:

   ```powershell
   Get-Process autocad-mcp -ErrorAction SilentlyContinue
   ```

The command must return no server process.

The publication receipt fixes the DXF bytes to SHA-256
`c615664945db8ccc91b55f77e6359a15da4f7e6f30dbd8800d2d2b94029dffac`
and the DWG bytes to SHA-256
`be1e24ea0cd5194d0c57935b5018123b7cc981331172a1a2ca7cecc2d9a18e4f`.
Do not substitute a private drawing or record paths, usernames, device names,
prompts, responses, logs, AutoCAD installation details, or free-text notes in
the receipt.

Once every check above passes, create the closed receipt at a fresh detached
path:

```text
cargo run --locked -p release-packager -- create-preview-clean-host-receipt \
  --mcpb <exact-signed-preview.mcpb> \
  --client-version <numeric-Claude-Desktop-version> \
  --host-os-version <numeric-Windows-version> \
  --completed-utc <YYYY-MM-DDTHH:MM:SSZ> \
  --output <fresh/windows-x64-preview-clean-host.json>
```

The command rehashes the MCPB and both contained executables before emitting
the receipt. A failed or incomplete acceptance attempt produces no
publication-eligible receipt; retain any diagnostics privately.

### Deferred macOS acceptance notes

1. Verify the package opens without asking the user to bypass Gatekeeper.
2. Confirm read tools work.
3. Confirm Windows-only tools return an explicit unsupported-platform error
   rather than disconnecting the MCP server.

The structured receipt is Preview evidence for the exact Windows candidate
only. It does not satisfy Release certification, signing, AutoCAD-host
qualification, macOS acceptance, or future-client compatibility.

## Select and publish an approved Preview

After the projection audit, signed Windows review, clean-host acceptance, and
owner approval all exist for the same source identity, emit the private
current-distribution result:

```text
cargo run --locked -p xtask -- current-distribution-verify \
  --candidate-dir <exact-preview-source-candidate> \
  --approval <owner-distribution-approval.json> \
  --mcpb <autocad-mcp-windows-x64-preview.mcpb> \
  --source-closure-sbom <windows-x64-preview-source-closure.spdx.json> \
  --build-attestation <windows-x64-preview-build.json> \
  --clean-host-receipt <windows-x64-preview-clean-host.json> \
  > <detached-handoff/current-distribution-verification.json>
```

The detached handoff must have the exact nine-file pre-signing inventory
before sealing:

1. `autocad-mcp-windows-x64-preview.mcpb`;
2. `autocad-mcp-windows-x64-preview-build-source.zip`;
3. `distribution-evidence/windows-x64-preview-source-closure.spdx.json`;
4. `distribution-evidence/windows-x64-preview-build.json`;
5. `distribution-evidence/windows-x64-preview-clean-host.json`;
6. `owner-distribution-approval.json`;
7. the owner-private `publication-candidate-receipt.json`;
8. `current-distribution-verification.json`; and
9. `SHA256SUMS.txt`.

`SHA256SUMS.txt` binds the first six public files using their flat downloadable
release-asset names rather than internal `distribution-evidence/` paths.
Sealing adds `preview-publication-handoff.json`. The projection receipt,
current-distribution result, and signed handoff are private selection records,
not release assets.

Seal and independently verify the handoff with an owner-selected Ed25519 trust
anchor:

```text
chmod 700 <detached-handoff>
find <detached-handoff> -type d -exec chmod 700 {} +
find <detached-handoff> -type f -exec chmod 600 {} +

cargo run --locked -p release-packager -- seal-preview-publication-handoff \
  --repository <source-repository> \
  --handoff-dir <detached-handoff> \
  --key-id <owner-key-id> \
  --private-key-file <detached-raw-32-byte-private-key>

cargo run --locked -p release-packager -- verify-preview-publication-handoff \
  --repository <source-repository> \
  --handoff-dir <detached-handoff> \
  --key-id <owner-key-id> \
  --public-key <64-lowercase-hex-characters>
```

Handoff sealing currently requires macOS and a regular, single-link private-key
file owned by the effective user, with owner-only mode bits and no extended ACL
entries. The handoff root and every directory must be owned by the effective
user with mode `0700`; every file must be an owner-owned, single-link regular
file with mode `0600`; no handoff entry may have an extended ACL. Inspect and
remove any ACLs before sealing (for example, with `ls -le` and the
platform-appropriate `chmod -N`) rather than relying on mode bits alone. Other
Unix hosts and Windows cannot seal until equivalent owner/ACL admission is
implemented.

Canonical-envelope parsing and Ed25519 verification are portable primitives,
but complete handoff verification is authority-local. The supplied source must
be the canonical primary common checkout with authoritative `main` checked
out—not a linked worktree or copied/stale clone—and it must retain the exact
path, Git-directory identity, commit, and tree bound during sealing.

Only after a separate publication authorization, use a clean one-commit
projection with `main` checked out:

```text
cargo run --locked -p release-packager -- publish-preview-prerelease \
  --handoff-dir <detached-handoff> \
  --source-repository <clean-private-source-repository> \
  --projection <clean-one-commit-public-projection> \
  --github-cli <absolute-canonical-path-to-gh> \
  --key-id <owner-key-id> \
  --public-key <64-lowercase-hex-characters> \
  --serial <positive-integer> \
  --exclusive-write-window-confirmed
```

Set `GH_TOKEN` only in the publisher process environment. The command does not
accept the token as an argument, persist it in its command model, or write it to
the handoff, projection, receipt, or logs.

The publisher is fixed to `github.com/andagni/autocad-mcp`, its `main` ref, and
the neutral authenticated publisher identity `andagni`. Live publication
revalidates that the destination exists, is public, active, non-forked, and has
the required default branch and remote inventory. The supplied clean private
source repository must be the canonical primary common checkout with
authoritative `main` at the exact commit and tree named by the projection
receipt; linked worktrees and copied or stale clones are rejected. The
deterministic public projection must have the exact root commit, tree, metadata,
and message required by the projection design. The handoff and process-owned
upload staging directory must remain detached from both repositories.

Before mutation, the publisher scans every release page, including drafts, to
prove the Preview tag is unused and checks that the installed GitHub CLI
supports release-integrity verification. It creates one draft, copies the seven
already verified public assets into anonymous owner-only file handles in a
fresh owner-only staging directory, and uploads those stable handles over
standard input through the created release's exact ID and validated absolute
upload URL; it never asks `gh` to reopen a mutable handoff or named staging path
or select a draft by tag. The owner-selected `gh` executable is supplied by
absolute path and rechecked around each token-bearing command; each invocation
uses a cleared environment and fresh private configuration directory. Local
Git inspection uses the system Git with a closed environment. The command then
re-verifies the exact assets, source, projection, complete one-branch remote
inventory, repository, principal, tag absence, and immutable-release setting
immediately before publishing. It never deletes, overwrites, clobbers, or
implicitly resumes a release, and removes the process-owned staging directory
on every exit path.

GitHub does not provide a conditional publish operation that atomically binds
the inspected draft, asset inventory, tag absence, and immutable-release
setting. The confirmation flag therefore asserts an externally enforced
single-writer interval over the canonical source checkout, public projection,
detached handoff and retained staged handles; repository visibility, archive,
disabled, default-branch, remote-main, and other-branch state; releases; the
exact tag; and repository or organization immutability settings for the whole
command. Do not invoke the publisher if another local process, writer, or
administrator can mutate that state during the interval. Failures before PATCH
dispatch leave a draft; after dispatch, the command reconciles the exact
immutable result, exact draft, or an explicit terminal ambiguous outcome and
never retries publication.

## Troubleshooting

### Server does not appear

- Confirm `command` is an absolute path and points to the executable, not its
  containing directory.
- Confirm `args` matches the package flavor exactly: Release uses `["serve"]`;
  Preview uses `["serve", "--experimental"]`. A manually configured
  administrator profiles path follows those arguments as
  `["--title-block-profiles", "<absolute JSON path>"]`; an MCPB file selection
  uses the environment binding instead.
- Validate `claude_desktop_config.json` as JSON. Windows backslashes must be
  escaped.
- Run `autocad-mcp list-tools` directly.
- Run `release-packager desktop-smoke` against the same binary.
- Completely quit Claude Desktop before reopening it.

### Server disconnects immediately

- Run `autocad-mcp serve` in a terminal and check stderr.
- Do not print wrappers, banners, or diagnostics to stdout; stdout is reserved
  for newline-delimited MCP messages.
- Confirm the executable architecture matches the host.
- On macOS, check the executable's trust and quarantine state through the
  normal organizational signing/notarization process.
- On Windows, check endpoint-protection and application-control events before
  changing policy.

### Tools appear but drawing calls fail

- Supply an absolute drawing path.
- Confirm Claude Desktop's user can read the drawing and its parent directory.
- Work on an authorized copy when testing write operations.
- For Windows engine-backed tools, verify AutoCAD is installed and
  `accoreconsole.exe` is discoverable.
- A macOS package intentionally cannot perform DWG writes, XREF mutations, or
  PDF plotting.

### Logs

Where supported by the installed client version, Claude Desktop MCP logs are
normally stored under:

- macOS: `~/Library/Logs/Claude`
- Windows: `%APPDATA%\Claude\logs`

The general `mcp.log` records connection failures, while
`mcp-server-autocad-mcp.log` captures the server's stderr. Some Claude Desktop
versions also expose extension logs in their settings UI.

## Repository layout

- `crates/autocad-mcp/` owns the server, CLI, tool contracts, platform
  activation, and native certification harnesses.
- `crates/autocad-reader/` and `crates/autocad-writer/` own the bounded drawing
  decode and mutation boundaries.
- `crates/autolisp-lsp/` and `crates/autolisp-validate/` provide AutoLISP
  language tooling.
- `crates/distribution/approval/` owns distribution approval and handoff
  contracts plus their machine-readable schemas.
- `crates/distribution/evidence/`,
  `crates/distribution/plugin-validation/`,
  `crates/distribution/qualification/`, and
  `crates/distribution/packager/` own dependency evidence, shipped-plugin
  validation, qualification primitives, reproducible packaging, and the
  pinned supplemental MCPB validator.
- `crates/xtask/` orchestrates cross-crate local CI and candidate sealing.
- `plugin/` contains the package source, MCP/LSP descriptors, and bundled
  skills.

Official references:

- [Claude Desktop local MCP servers](https://support.claude.com/en/articles/10949351-getting-started-with-local-mcp-servers-on-claude-desktop)
- [MCPB format and tooling](https://github.com/modelcontextprotocol/mcpb)
- [Connecting local MCP servers](https://modelcontextprotocol.io/docs/develop/connect-local-servers)
