# Changelog

## 0.0.1 Preview

- Added the Windows x64 Preview MCPB with a visibly experimental 2018–2027
  activation catalogue.
- Bundled the AutoLISP language server and require its native protocol smoke
  alongside the MCP server.
- Expose the 36 read-only tools by default and the complete 51-tool surface
  only through the Preview package's explicit experimental launch mode.
- Added an offline administrator workflow for surveying, clustering, validating,
  and verifying extend-only title-block profiles. Servers can load one reviewed
  file with `--title-block-profiles` or
  `AUTOCAD_MCP_TITLE_BLOCK_PROFILES`; MCPB packages expose the same optional
  file setting.

This Preview is evaluation software. It is not an AutoCAD-certified Release,
and mutation availability remains subject to the runtime and drawing-specific
admission checks reported by each tool.
