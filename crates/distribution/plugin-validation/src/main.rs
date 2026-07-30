use std::path::Path;
use std::process;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 2 {
        eprintln!("Usage: plugin-validate <plugin-dir> <schema-root>");
        eprintln!("  e.g. plugin-validate plugin crates/distribution/plugin-validation/schemas");
        process::exit(2);
    }
    let plugin_dir = Path::new(&args[0]);
    let schema_root = Path::new(&args[1]);

    let report = plugin_validate::validate_plugin(plugin_dir, schema_root);

    eprintln!("plugin-validate: {} error(s).", report.errors);
    if report.errors > 0 {
        process::exit(1);
    }
}
