use std::path::Path;
use std::time::Duration;

use autocad_writer::portable_plot::{
    deliver_portable_pdf, run_portable_worker, PlotCompleteness, PortableDeliveryFidelity,
    PortableOutputPolicy, PortablePlotDeliveryOptions, PortableResourceBundle,
    PortableWorkerLimits, PortableWorkerRequest, ResourceDigest,
};
use autocad_writer::{DrawingFormat, DrawingSnapshot};

fn synthetic_plot_source() -> Vec<u8> {
    let mut document = acadrust::CadDocument::new();
    for object in document.objects.values_mut() {
        if let acadrust::objects::ObjectType::Layout(layout) = object {
            if layout.name == "Layout1" {
                layout.paper_width = 297.0;
                layout.paper_height = 210.0;
            }
        }
    }
    document
        .add_entity_to_layout(
            acadrust::entities::EntityType::Line(acadrust::entities::Line::from_coords(
                10.0, 10.0, 0.0, 100.0, 80.0, 0.0,
            )),
            "Layout1",
        )
        .unwrap();
    acadrust::DwgWriter::write_to_vec(&document).unwrap()
}

#[test]
fn worker_process_returns_pdf_with_mandatory_partial_receipt() {
    let source = synthetic_plot_source();
    let reader_snapshot =
        autocad_reader::DrawingSnapshot::new(autocad_reader::DrawingFormat::Dwg, source.clone());
    let session = autocad_reader::Reader::open_snapshot(reader_snapshot).unwrap();
    let layout = session
        .get_layout(&autocad_reader::contract::LayoutSelector {
            name: Some("Layout1".to_owned()),
            ..Default::default()
        })
        .unwrap();
    let request = PortableWorkerRequest::new(
        DrawingSnapshot::new(DrawingFormat::Dwg, source),
        layout.name,
    )
    .unwrap();
    let output = run_portable_worker(
        Path::new(env!("CARGO_BIN_EXE_portable-plot-worker")),
        &request,
        PortableWorkerLimits::default(),
    )
    .unwrap();
    let receipt: serde_json::Value =
        serde_json::from_str(output.receipt().json()).expect("worker receipt must be JSON");
    assert_eq!(receipt["schema_version"], 2);
    assert_eq!(receipt["profile"], "portable_2d_v1");
    assert_eq!(receipt["encoder"], "krilla-0.8.2-pdf-1.4");
    assert_eq!(receipt["completeness"], "partial");
    assert_eq!(receipt["partial_output"], true);
    assert!(receipt["fidelity"]["diagnostic_counts"].is_object());
    assert!(receipt["limits"]["display_list"].is_object());
    assert!(receipt["source"]["sha256"].is_string());
    let pdf = output.pdf_bytes();
    assert!(pdf.starts_with(b"%PDF-1.4"));
    assert!(pdf.ends_with(b"%%EOF"));
    assert_eq!(output.receipt().completeness(), PlotCompleteness::Partial);
    assert_eq!(output.receipt().pdf_sha256(), ResourceDigest::of(pdf));
    assert_eq!(receipt["output"]["pdf_bytes"], pdf.len());
    assert_eq!(
        receipt["output"]["pdf_sha256"],
        ResourceDigest::of(pdf).to_hex()
    );
}

#[test]
fn delivery_is_policy_gated_source_bound_and_atomic() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source.dwg");
    let output = directory.path().join("output.pdf");
    let source_bytes = synthetic_plot_source();
    std::fs::write(&source, &source_bytes).unwrap();
    let worker = Path::new(env!("CARGO_BIN_EXE_portable-plot-worker"));

    let complete_only = deliver_portable_pdf(
        worker,
        &source,
        "Layout1",
        PortableResourceBundle::new(),
        &output,
        PortableWorkerLimits::default(),
        PortablePlotDeliveryOptions::new(
            PortableDeliveryFidelity::CompleteOnly,
            PortableOutputPolicy::CreateNew,
        ),
    )
    .unwrap_err();
    assert_eq!(complete_only.code(), "portable_delivery_fidelity_rejected");
    assert!(!output.exists());

    let receipt = deliver_portable_pdf(
        worker,
        &source,
        "Layout1",
        PortableResourceBundle::new(),
        &output,
        PortableWorkerLimits::default(),
        PortablePlotDeliveryOptions::new(
            PortableDeliveryFidelity::AllowPartialDevelopment,
            PortableOutputPolicy::CreateNew,
        ),
    )
    .unwrap();
    let pdf = std::fs::read(&output).unwrap();
    assert_eq!(receipt.completeness(), PlotCompleteness::Partial);
    assert_eq!(receipt.source_sha256(), ResourceDigest::of(&source_bytes));
    assert_eq!(receipt.pdf_sha256(), ResourceDigest::of(&pdf));
    assert_eq!(receipt.source_bytes(), source_bytes.len());
    assert_eq!(receipt.pdf_bytes(), pdf.len());
    assert!(receipt.source_identity_revalidated());
    assert!(receipt.atomic_output_committed());
    assert!(!receipt.output_replaced());
    assert_eq!(std::fs::read(&source).unwrap(), source_bytes);

    let exists = deliver_portable_pdf(
        worker,
        &source,
        "Layout1",
        PortableResourceBundle::new(),
        &output,
        PortableWorkerLimits::default(),
        PortablePlotDeliveryOptions::new(
            PortableDeliveryFidelity::AllowPartialDevelopment,
            PortableOutputPolicy::CreateNew,
        ),
    )
    .unwrap_err();
    assert_eq!(exists.code(), "portable_delivery_output_exists");
    assert_eq!(std::fs::read(&output).unwrap(), pdf);

    let replaced = deliver_portable_pdf(
        worker,
        &source,
        "Layout1",
        PortableResourceBundle::new(),
        &output,
        PortableWorkerLimits::default(),
        PortablePlotDeliveryOptions::new(
            PortableDeliveryFidelity::AllowPartialDevelopment,
            PortableOutputPolicy::ReplaceExisting,
        ),
    )
    .unwrap();
    assert!(replaced.output_replaced());
    assert_eq!(replaced.pdf_sha256(), ResourceDigest::of(&pdf));
    assert!(std::fs::read_dir(directory.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".autocad-mcp-portable-plot-")
    }));
}

#[test]
fn worker_deadline_terminates_before_returning_any_candidate() {
    let source = synthetic_plot_source();
    let request =
        PortableWorkerRequest::new(DrawingSnapshot::new(DrawingFormat::Dwg, source), "Layout1")
            .unwrap();
    let error = run_portable_worker(
        Path::new(env!("CARGO_BIN_EXE_portable-plot-worker")),
        &request,
        PortableWorkerLimits {
            wall_time: Duration::from_nanos(1),
            ..PortableWorkerLimits::default()
        },
    )
    .unwrap_err();
    assert_eq!(error.code(), "portable_worker_timeout");
}

#[cfg(target_os = "macos")]
#[test]
fn darwin_physical_footprint_ceiling_terminates_the_worker() {
    let source = synthetic_plot_source();
    let request =
        PortableWorkerRequest::new(DrawingSnapshot::new(DrawingFormat::Dwg, source), "Layout1")
            .unwrap();
    let error = run_portable_worker(
        Path::new(env!("CARGO_BIN_EXE_portable-plot-worker")),
        &request,
        PortableWorkerLimits {
            maximum_memory_bytes: 1,
            ..PortableWorkerLimits::default()
        },
    )
    .unwrap_err();
    assert_eq!(error.code(), "portable_worker_memory_limit_exceeded");
}

#[cfg(unix)]
#[test]
fn noncooperating_source_change_is_detected_before_output_commit() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source.dwg");
    let output = directory.path().join("output.pdf");
    let source_bytes = synthetic_plot_source();
    std::fs::write(&source, &source_bytes).unwrap();
    let changed_source = source.clone();
    let mut changed_bytes = source_bytes;
    *changed_bytes.last_mut().unwrap() ^= 1;
    let writer = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        std::fs::write(changed_source, changed_bytes).unwrap();
    });
    let result = deliver_portable_pdf(
        Path::new(env!("CARGO_BIN_EXE_portable-plot-worker")),
        &source,
        "Layout1",
        PortableResourceBundle::new(),
        &output,
        PortableWorkerLimits::default(),
        PortablePlotDeliveryOptions::new(
            PortableDeliveryFidelity::AllowPartialDevelopment,
            PortableOutputPolicy::CreateNew,
        ),
    );
    writer.join().unwrap();
    assert_eq!(
        result.unwrap_err().code(),
        "portable_delivery_source_changed"
    );
    assert!(!output.exists());
}

#[test]
fn tracked_public_dwg_rejects_unusable_paper_geometry_without_output() {
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/corpus/open/acadsharp/dynamic-blocks/BLOCKVISIBILITYPARAMETER.dwg");
    let bytes = std::fs::read(&source).unwrap();
    let reader = autocad_reader::Reader::open_snapshot(autocad_reader::DrawingSnapshot::new(
        autocad_reader::DrawingFormat::Dwg,
        bytes,
    ))
    .unwrap();
    let layouts = reader
        .list_layouts()
        .unwrap()
        .into_iter()
        .filter(|layout| !layout.is_model)
        .collect::<Vec<_>>();
    assert_eq!(layouts.len(), 2);
    let outputs = tempfile::tempdir().unwrap();
    for (index, layout) in layouts.into_iter().enumerate() {
        let output = outputs.path().join(format!("layout-{index}.pdf"));
        let error = deliver_portable_pdf(
            Path::new(env!("CARGO_BIN_EXE_portable-plot-worker")),
            &source,
            &layout.name,
            PortableResourceBundle::new(),
            &output,
            PortableWorkerLimits::default(),
            PortablePlotDeliveryOptions::new(
                PortableDeliveryFidelity::AllowPartialDevelopment,
                PortableOutputPolicy::CreateNew,
            ),
        )
        .unwrap_err();
        assert_eq!(error.code(), "portable_worker_semantic_failure");
        assert!(!output.exists());
    }
}
