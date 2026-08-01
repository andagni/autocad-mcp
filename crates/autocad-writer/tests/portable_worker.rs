use std::io::Write;
use std::process::{Command, Stdio};

use sha2::{Digest, Sha256};

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
    let snapshot =
        autocad_reader::DrawingSnapshot::new(autocad_reader::DrawingFormat::Dwg, source.clone());
    let session = autocad_reader::Reader::open_snapshot(snapshot).unwrap();
    let layout = session
        .get_layout(&autocad_reader::contract::LayoutSelector {
            name: Some("Layout1".to_owned()),
            ..Default::default()
        })
        .unwrap();
    let layout_bytes = layout.name.as_bytes();
    let mut request = Vec::new();
    request.extend_from_slice(b"P2D1");
    request.push(1);
    request.push(1);
    request.extend_from_slice(&u32::try_from(layout_bytes.len()).unwrap().to_be_bytes());
    request.extend_from_slice(&u64::try_from(source.len()).unwrap().to_be_bytes());
    request.extend_from_slice(&Sha256::digest(&source));
    request.extend_from_slice(layout_bytes);
    request.extend_from_slice(&source);

    let mut child = Command::new(env!("CARGO_BIN_EXE_portable-plot-worker"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&request).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "worker failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response = output.stdout;
    assert!(response.len() > 17);
    assert_eq!(&response[..4], b"P2DO");
    assert_eq!(response[4], 0);
    let body_length =
        usize::try_from(u64::from_be_bytes(response[5..13].try_into().unwrap())).unwrap();
    assert_eq!(response.len(), 13 + body_length);
    let body = &response[13..];
    let receipt_length =
        usize::try_from(u32::from_be_bytes(body[..4].try_into().unwrap())).unwrap();
    let receipt_end = 4 + receipt_length;
    let receipt: serde_json::Value =
        serde_json::from_slice(&body[4..receipt_end]).expect("worker receipt must be JSON");
    assert_eq!(receipt["schema_version"], 1);
    assert_eq!(receipt["profile"], "portable_2d_v1");
    assert_eq!(receipt["encoder"], "krilla-0.8.2-pdf-1.4");
    assert_eq!(receipt["completeness"], "partial");
    assert_eq!(receipt["partial_output"], true);
    assert!(receipt["fidelity"]["diagnostic_counts"].is_object());
    assert!(receipt["limits"]["display_list"].is_object());
    assert!(receipt["source"]["sha256"].is_string());
    let pdf = &body[receipt_end..];
    assert!(pdf.starts_with(b"%PDF-1.4"));
    assert!(pdf.ends_with(b"%%EOF"));
}
