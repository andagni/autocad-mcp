use crate::{DistributionMode, GitObjectFormat};
use std::fmt;

pub const WINDOWS_X86_64_TARGET: &str = "x86_64-pc-windows-msvc";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildRecipeError {
    detail: String,
}

impl BuildRecipeError {
    fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }
}

impl fmt::Display for BuildRecipeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.detail)
    }
}

impl std::error::Error for BuildRecipeError {}

/// Render the only Windows x86_64 build recipe admitted by the initial
/// distribution contract.
///
/// This establishes canonical recipe bytes for an approval-bound Rust
/// toolchain and Git source commit. It does not execute the recipe or attest
/// that a native Windows build or AutoCAD acceptance run succeeded.
pub fn render_windows_x86_64_build_recipe(
    toolchain: &str,
    git_object_format: GitObjectFormat,
    source_commit: &str,
    package_mode: DistributionMode,
) -> Result<Vec<u8>, BuildRecipeError> {
    validate_toolchain(toolchain)?;
    validate_source_commit(git_object_format, source_commit)?;

    let toolchain_regex = toolchain.replace('.', "[.]");
    let (build_commands, expected_executables) = match package_mode {
        DistributionMode::Release => (
            format!(
                "cargo +{toolchain} build --locked --offline --release --target {WINDOWS_X86_64_TARGET} -p autocad-mcp --bin autocad-mcp --no-default-features -p autolisp-lsp --bin autolisp-lsp\n\n\
                 if ($LASTEXITCODE -ne 0) {{ throw \"offline two-product Release build failed with exit code $LASTEXITCODE\" }}"
            ),
            format!(
                "target\\{WINDOWS_X86_64_TARGET}\\release\\autocad-mcp.exe\n\
                 target\\{WINDOWS_X86_64_TARGET}\\release\\autolisp-lsp.exe"
            ),
        ),
        DistributionMode::Preview => (
            format!(
                "cargo +{toolchain} build --locked --offline --release --target {WINDOWS_X86_64_TARGET} --target-dir target-release -p autocad-mcp --bin autocad-mcp --no-default-features -p autolisp-lsp --bin autolisp-lsp\n\n\
                 if ($LASTEXITCODE -ne 0) {{ throw \"offline two-product Release build for the Preview LSP failed with exit code $LASTEXITCODE\" }}\n\n\
                 cargo +{toolchain} build --locked --offline --release --target {WINDOWS_X86_64_TARGET} --target-dir target-preview -p autocad-mcp --bin autocad-mcp --no-default-features --features preview\n\n\
                 if ($LASTEXITCODE -ne 0) {{ throw \"offline Preview server build failed with exit code $LASTEXITCODE\" }}"
            ),
            format!(
                "target-preview\\{WINDOWS_X86_64_TARGET}\\release\\autocad-mcp.exe\n\
                 target-release\\{WINDOWS_X86_64_TARGET}\\release\\autolisp-lsp.exe"
            ),
        ),
    };
    Ok(format!(
        "AutoCAD-MCP deterministic Windows x86_64 source build\n\
         =====================================================\n\n\
         This archive contains the exact clean Git source at the commit recorded in\n\
         source-bundle-manifest.json and the target-specific registry source closure.\n\
         It does not contain signing keys, certificates, private ARG material, or an\n\
         AutoCAD host certification result. Archive construction does not replace the\n\
         required Windows-only acceptance gate: extract this archive on a clean Windows\n\
         host with an empty Cargo home and complete the build below before release.\n\n\
         Prerequisites:\n\
         - Windows x86_64 with the MSVC C++ build tools and Windows SDK\n\
         - rustup with Rust toolchain {toolchain} already installed\n\
         - extract at a short ASCII path such as C:\\acmcp-source\n\
         - no network access is required after extracting this archive\n\n\
         From PowerShell in the extracted archive root:\n\n\
         $ErrorActionPreference = \"Stop\"\n\
         Remove-Item Env:CARGO_* -ErrorAction SilentlyContinue\n\
         Remove-Item Env:RUSTC -ErrorAction SilentlyContinue\n\
         Remove-Item Env:RUSTC_BOOTSTRAP -ErrorAction SilentlyContinue\n\
         Remove-Item Env:RUSTC_WRAPPER -ErrorAction SilentlyContinue\n\
         Remove-Item Env:RUSTC_WORKSPACE_WRAPPER -ErrorAction SilentlyContinue\n\
         Remove-Item Env:RUSTDOC -ErrorAction SilentlyContinue\n\
         Remove-Item Env:RUSTDOCFLAGS -ErrorAction SilentlyContinue\n\
         Remove-Item Env:RUSTFLAGS -ErrorAction SilentlyContinue\n\
         Remove-Item Env:RUSTUP_TOOLCHAIN -ErrorAction SilentlyContinue\n\
         Remove-Item Env:AUTOCAD_MCP_* -ErrorAction SilentlyContinue\n\
         $bundleRoot = (Get-Location).Path\n\
         $cargoConfigCursor = [System.IO.DirectoryInfo]$bundleRoot\n\
         while ($null -ne $cargoConfigCursor) {{\n\
           foreach ($cargoConfigName in @(\"config\", \"config.toml\")) {{\n\
             $cargoConfigPath = Join-Path (Join-Path $cargoConfigCursor.FullName \".cargo\") $cargoConfigName\n\
             if (Test-Path -LiteralPath $cargoConfigPath) {{ throw \"ambient Cargo configuration is forbidden: $cargoConfigPath\" }}\n\
           }}\n\
           $cargoConfigCursor = $cargoConfigCursor.Parent\n\
         }}\n\
         $isolatedCargoHome = Join-Path $bundleRoot \".cargo-home\"\n\
         if (Test-Path -LiteralPath $isolatedCargoHome) {{ throw \"isolated Cargo home already exists: $isolatedCargoHome\" }}\n\
         New-Item -ItemType Directory -Path $isolatedCargoHome -ErrorAction Stop | Out-Null\n\
         $env:CARGO_HOME = $isolatedCargoHome\n\
         $rustcVersion = & rustc +{toolchain} --version\n\
         if ($LASTEXITCODE -ne 0 -or $rustcVersion -notmatch '^rustc {toolchain_regex}(?: |$)') {{ throw \"required rustc {toolchain} is not installed: $rustcVersion\" }}\n\
         $cargoVersion = & cargo +{toolchain} --version\n\
         if ($LASTEXITCODE -ne 0 -or $cargoVersion -notmatch '^cargo {toolchain_regex}(?: |$)') {{ throw \"required cargo {toolchain} is not installed: $cargoVersion\" }}\n\
         Set-Location workspace\n\
         $env:AUTOCAD_MCP_SOURCE_COMMIT = \"{source_commit}\"\n\
         $env:CARGO_NET_OFFLINE = \"true\"\n\
         $env:CARGO_INCREMENTAL = \"0\"\n\
         $env:CARGO_ENCODED_RUSTFLAGS = \"-C$([char]0x1f)target-feature=+crt-static\"\n\
         {build_commands}\n\n\
         Expected executables:\n\
         {expected_executables}\n"
    )
    .into_bytes())
}

fn validate_toolchain(toolchain: &str) -> Result<(), BuildRecipeError> {
    let components = toolchain.split('.').collect::<Vec<_>>();
    if components.len() == 3
        && components.iter().all(|component| {
            !component.is_empty()
                && component.bytes().all(|byte| byte.is_ascii_digit())
                && (component.len() == 1 || !component.starts_with('0'))
        })
    {
        Ok(())
    } else {
        Err(BuildRecipeError::new(format!(
            "Windows build recipe requires an exact numeric Rust release, got {toolchain:?}"
        )))
    }
}

fn validate_source_commit(
    git_object_format: GitObjectFormat,
    source_commit: &str,
) -> Result<(), BuildRecipeError> {
    let expected_length = match git_object_format {
        GitObjectFormat::Sha1 => 40,
        GitObjectFormat::Sha256 => 64,
    };
    if source_commit.len() == expected_length
        && source_commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(BuildRecipeError::new(format!(
            "Windows build recipe requires a lowercase {expected_length}-hex Git commit for {git_object_format:?}, got {source_commit:?}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renderer_is_deterministic_and_preserves_the_closed_build_contract() {
        let commit = "a".repeat(40);
        let first = render_windows_x86_64_build_recipe(
            "1.97.0",
            GitObjectFormat::Sha1,
            &commit,
            DistributionMode::Release,
        )
        .unwrap();
        let second = render_windows_x86_64_build_recipe(
            "1.97.0",
            GitObjectFormat::Sha1,
            &commit,
            DistributionMode::Release,
        )
        .unwrap();
        assert_eq!(first, second);

        let text = String::from_utf8(first).unwrap();
        assert!(text.contains("$env:CARGO_INCREMENTAL = \"0\""));
        assert!(text.contains(
            "$env:CARGO_ENCODED_RUSTFLAGS = \"-C$([char]0x1f)target-feature=+crt-static\""
        ));
        let exact_build = "cargo +1.97.0 build --locked --offline --release --target x86_64-pc-windows-msvc -p autocad-mcp --bin autocad-mcp --no-default-features -p autolisp-lsp --bin autolisp-lsp";
        assert!(text.contains(exact_build));
        assert_eq!(text.matches("cargo +1.97.0 build ").count(), 1);
    }

    #[test]
    fn preview_renderer_enables_only_the_server_preview_feature() {
        let text = String::from_utf8(
            render_windows_x86_64_build_recipe(
                "1.97.0",
                GitObjectFormat::Sha1,
                &"a".repeat(40),
                DistributionMode::Preview,
            )
            .unwrap(),
        )
        .unwrap();
        let exact_release_build = "cargo +1.97.0 build --locked --offline --release --target x86_64-pc-windows-msvc --target-dir target-release -p autocad-mcp --bin autocad-mcp --no-default-features -p autolisp-lsp --bin autolisp-lsp";
        let exact_preview_build = "cargo +1.97.0 build --locked --offline --release --target x86_64-pc-windows-msvc --target-dir target-preview -p autocad-mcp --bin autocad-mcp --no-default-features --features preview";
        assert!(text.contains(exact_release_build));
        assert!(text.contains(exact_preview_build));
        assert_eq!(text.matches("--features preview").count(), 1);
        assert_eq!(text.matches("cargo +1.97.0 build ").count(), 2);
        assert!(text.contains("target-preview\\x86_64-pc-windows-msvc\\release\\autocad-mcp.exe"));
        assert!(text.contains("target-release\\x86_64-pc-windows-msvc\\release\\autolisp-lsp.exe"));
    }

    #[test]
    fn renderer_rejects_noncanonical_identity_inputs() {
        let sha1 = "a".repeat(40);
        assert!(render_windows_x86_64_build_recipe(
            "stable",
            GitObjectFormat::Sha1,
            &sha1,
            DistributionMode::Release,
        )
        .is_err());
        assert!(render_windows_x86_64_build_recipe(
            "1.097.0",
            GitObjectFormat::Sha1,
            &sha1,
            DistributionMode::Release,
        )
        .is_err());
        assert!(render_windows_x86_64_build_recipe(
            "1.97.0",
            GitObjectFormat::Sha256,
            &sha1,
            DistributionMode::Release,
        )
        .is_err());
        assert!(render_windows_x86_64_build_recipe(
            "1.97.0",
            GitObjectFormat::Sha1,
            &"A".repeat(40),
            DistributionMode::Release,
        )
        .is_err());
    }
}
