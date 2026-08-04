use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use autocad_writer::portable_plot::{
    compile_portable_scene, deliver_portable_pdf, PlotCompleteness, PortableDeliveryFidelity,
    PortableOutputPolicy, PortablePlotDeliveryOptions, PortablePlotLimits, PortableResourceBundle,
    PortableWorkerLimits, ResourceDigest,
};
use autocad_writer::{DrawingFormat, DrawingSnapshot};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct QualificationSummary {
    schema_version: u32,
    drawings_discovered: usize,
    drawings_reader_admitted: usize,
    drawings_without_paper_layouts: usize,
    paper_layouts_discovered: usize,
    complete_outputs: usize,
    partial_outputs: usize,
    semantic_complete: usize,
    semantic_partial: usize,
    semantic_rejected: usize,
    semantic_failures_by_code: BTreeMap<String, usize>,
    diagnostics_by_code: BTreeMap<String, usize>,
    failures_by_code: BTreeMap<String, usize>,
}

impl QualificationSummary {
    fn new(drawings_discovered: usize) -> Self {
        Self {
            schema_version: 1,
            drawings_discovered,
            drawings_reader_admitted: 0,
            drawings_without_paper_layouts: 0,
            paper_layouts_discovered: 0,
            complete_outputs: 0,
            partial_outputs: 0,
            semantic_complete: 0,
            semantic_partial: 0,
            semantic_rejected: 0,
            semantic_failures_by_code: BTreeMap::new(),
            diagnostics_by_code: BTreeMap::new(),
            failures_by_code: BTreeMap::new(),
        }
    }

    fn failure(&mut self, code: &str) {
        *self.failures_by_code.entry(code.to_string()).or_default() += 1;
    }

    fn semantic_failure(&mut self, code: &str) {
        *self
            .semantic_failures_by_code
            .entry(code.to_string())
            .or_default() += 1;
    }

    fn semantic_receipt(
        &mut self,
        compilation: &autocad_writer::portable_plot::PortableSceneCompilation,
    ) {
        match compilation.receipt().fidelity().completeness() {
            PlotCompleteness::Complete => self.semantic_complete += 1,
            PlotCompleteness::Partial => self.semantic_partial += 1,
            PlotCompleteness::Rejected => self.semantic_rejected += 1,
        }
        for (code, count) in compilation.receipt().fidelity().diagnostic_counts() {
            *self.diagnostics_by_code.entry(code.clone()).or_default() += count;
        }
    }
}

fn main() {
    match qualify() {
        Ok(summary) => println!(
            "{}",
            serde_json::to_string(&summary).expect("qualification summary is serializable")
        ),
        Err(code) => {
            println!(
                "{}",
                serde_json::json!({
                    "schema_version": 1,
                    "fatal_error": code,
                })
            );
            std::process::exit(1);
        }
    }
}

fn qualify() -> Result<QualificationSummary, &'static str> {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    let [input_root, output_root, worker] = arguments.as_slice() else {
        return Err("qualification_arguments_invalid");
    };
    let input_root = canonical_directory(Path::new(input_root))?;
    let output_root = canonical_directory(Path::new(output_root))?;
    let worker = std::fs::canonicalize(worker).map_err(|_| "worker_invalid")?;
    if !worker.is_file() {
        return Err("worker_invalid");
    }
    let mut drawings = Vec::new();
    discover_drawings(&input_root, &mut drawings)?;
    drawings.sort();
    let mut summary = QualificationSummary::new(drawings.len());
    for drawing in drawings {
        qualify_drawing(&drawing, &output_root, &worker, &mut summary);
    }
    Ok(summary)
}

fn canonical_directory(path: &Path) -> Result<PathBuf, &'static str> {
    if !path.is_absolute() {
        return Err("qualification_arguments_invalid");
    }
    let path = std::fs::canonicalize(path).map_err(|_| "qualification_directory_invalid")?;
    if !path.is_dir() {
        return Err("qualification_directory_invalid");
    }
    Ok(path)
}

fn discover_drawings(root: &Path, drawings: &mut Vec<PathBuf>) -> Result<(), &'static str> {
    let mut entries = std::fs::read_dir(root)
        .map_err(|_| "corpus_traversal_failed")?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "corpus_traversal_failed")?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let file_type = entry.file_type().map_err(|_| "corpus_traversal_failed")?;
        if file_type.is_symlink() {
            return Err("corpus_symlink_rejected");
        }
        if file_type.is_dir() {
            discover_drawings(&entry.path(), drawings)?;
        } else if file_type.is_file()
            && entry
                .path()
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| extension.eq_ignore_ascii_case("dwg"))
        {
            drawings.push(entry.path());
        }
    }
    Ok(())
}

fn qualify_drawing(
    drawing: &Path,
    output_root: &Path,
    worker: &Path,
    summary: &mut QualificationSummary,
) {
    let bytes = match std::fs::read(drawing) {
        Ok(bytes) => bytes,
        Err(_) => {
            summary.failure("source_read_failed");
            return;
        }
    };
    let source_digest = ResourceDigest::of(&bytes);
    let bytes: Arc<[u8]> = Arc::from(bytes);
    let snapshot = autocad_reader::DrawingSnapshot::new(
        autocad_reader::DrawingFormat::Dwg,
        Arc::clone(&bytes),
    );
    let reader = match autocad_reader::Reader::open_snapshot(snapshot) {
        Ok(reader) => reader,
        Err(_) => {
            summary.failure("reader_admission_failed");
            return;
        }
    };
    let layouts = match reader.list_layouts() {
        Ok(layouts) => layouts
            .into_iter()
            .filter(|layout| !layout.is_model)
            .collect::<Vec<_>>(),
        Err(_) => {
            summary.failure("layout_inventory_failed");
            return;
        }
    };
    summary.drawings_reader_admitted += 1;
    if layouts.is_empty() {
        summary.drawings_without_paper_layouts += 1;
        return;
    }
    summary.paper_layouts_discovered += layouts.len();
    for layout in layouts {
        match compile_portable_scene(
            &DrawingSnapshot::new(DrawingFormat::Dwg, Arc::clone(&bytes)),
            &layout.name,
            PortablePlotLimits::default(),
        ) {
            Ok(compilation) => summary.semantic_receipt(&compilation),
            Err(error) => summary.semantic_failure(error.code()),
        }
        let output = output_root.join(output_identity(source_digest, &layout.name));
        match deliver_portable_pdf(
            worker,
            drawing,
            &layout.name,
            PortableResourceBundle::new(),
            &output,
            PortableWorkerLimits::default(),
            PortablePlotDeliveryOptions::new(
                PortableDeliveryFidelity::AllowPartialDevelopment,
                PortableOutputPolicy::CreateNew,
            ),
        ) {
            Ok(receipt) => match receipt.completeness() {
                PlotCompleteness::Complete => summary.complete_outputs += 1,
                PlotCompleteness::Partial => summary.partial_outputs += 1,
                PlotCompleteness::Rejected => summary.failure("rejected_output_returned"),
            },
            Err(error) => summary.failure(error.code()),
        }
    }
}

fn output_identity(source: ResourceDigest, layout: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(source.bytes());
    digest.update([0]);
    digest.update(layout.as_bytes());
    format!("{:x}.pdf", digest.finalize())
}
