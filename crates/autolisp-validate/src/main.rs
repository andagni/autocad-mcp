use autolisp_validate::{check_source, Severity};
use std::{env, fs, process};

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("Usage: autolisp-validate <file.lsp> [file.lsp ...]");
        process::exit(2);
    }

    let mut total_errors = 0usize;
    let mut total_warnings = 0usize;

    for path in &args {
        let text = match fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("ERROR: {path}: {e}");
                total_errors += 1;
                continue;
            }
        };

        let report = check_source(&text, path);
        for diagnostic in &report.diagnostics {
            let kind = match diagnostic.severity {
                Severity::Error => "ERROR",
                Severity::Warning => "WARN",
            };
            println!(
                "{}:{}: {}: {}",
                diagnostic.path, diagnostic.line, kind, diagnostic.message
            );
        }
        total_errors += report.errors();
        total_warnings += report.warnings();
    }

    eprintln!(
        "Checked {} file(s): {} error(s), {} warning(s).",
        args.len(),
        total_errors,
        total_warnings
    );

    if total_errors > 0 {
        process::exit(1);
    }
}
