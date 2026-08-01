use std::sync::Arc;

use write_fonts::{types::Tag, FontBuilder};

/// Repository-authored deterministic TrueType fixture with `.notdef` and `A`.
///
/// The fixture is generated from table primitives rather than copied from a
/// third-party font. It is deliberately tiny and exists only to qualify the
/// shaping, embedding, and independent-raster test path.
pub(crate) fn qualification_font() -> Arc<[u8]> {
    let mut builder = FontBuilder::new();
    builder
        .add_raw(Tag::new(b"head"), head())
        .add_raw(Tag::new(b"hhea"), hhea())
        .add_raw(Tag::new(b"maxp"), maxp())
        .add_raw(Tag::new(b"hmtx"), hmtx())
        .add_raw(Tag::new(b"cmap"), cmap())
        .add_raw(Tag::new(b"loca"), loca())
        .add_raw(Tag::new(b"glyf"), glyf())
        .add_raw(Tag::new(b"post"), post());
    Arc::from(builder.build())
}

fn head() -> Vec<u8> {
    let mut table = Vec::with_capacity(54);
    push_u32(&mut table, 0x0001_0000);
    push_u32(&mut table, 0x0001_0000);
    push_u32(&mut table, 0);
    push_u32(&mut table, 0x5F0F_3CF5);
    push_u16(&mut table, 0);
    push_u16(&mut table, 1_000);
    push_u64(&mut table, 0);
    push_u64(&mut table, 0);
    push_i16(&mut table, 0);
    push_i16(&mut table, 0);
    push_i16(&mut table, 500);
    push_i16(&mut table, 700);
    push_u16(&mut table, 0);
    push_u16(&mut table, 8);
    push_i16(&mut table, 2);
    push_i16(&mut table, 1);
    push_i16(&mut table, 0);
    assert_eq!(table.len(), 54);
    table
}

fn hhea() -> Vec<u8> {
    let mut table = Vec::with_capacity(36);
    push_u32(&mut table, 0x0001_0000);
    push_i16(&mut table, 800);
    push_i16(&mut table, -200);
    push_i16(&mut table, 0);
    push_u16(&mut table, 600);
    push_i16(&mut table, 0);
    push_i16(&mut table, 100);
    push_i16(&mut table, 500);
    push_i16(&mut table, 1);
    push_i16(&mut table, 0);
    push_i16(&mut table, 0);
    for _ in 0..4 {
        push_i16(&mut table, 0);
    }
    push_i16(&mut table, 0);
    push_u16(&mut table, 2);
    assert_eq!(table.len(), 36);
    table
}

fn maxp() -> Vec<u8> {
    let mut table = Vec::with_capacity(32);
    push_u32(&mut table, 0x0001_0000);
    for value in [2, 3, 1, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0] {
        push_u16(&mut table, value);
    }
    assert_eq!(table.len(), 32);
    table
}

fn hmtx() -> Vec<u8> {
    let mut table = Vec::with_capacity(8);
    for _ in 0..2 {
        push_u16(&mut table, 600);
        push_i16(&mut table, 0);
    }
    table
}

fn cmap() -> Vec<u8> {
    let mut table = Vec::with_capacity(44);
    push_u16(&mut table, 0);
    push_u16(&mut table, 1);
    push_u16(&mut table, 3);
    push_u16(&mut table, 1);
    push_u32(&mut table, 12);

    push_u16(&mut table, 4);
    push_u16(&mut table, 32);
    push_u16(&mut table, 0);
    push_u16(&mut table, 4);
    push_u16(&mut table, 4);
    push_u16(&mut table, 1);
    push_u16(&mut table, 0);
    push_u16(&mut table, 0x0041);
    push_u16(&mut table, 0xFFFF);
    push_u16(&mut table, 0);
    push_u16(&mut table, 0x0041);
    push_u16(&mut table, 0xFFFF);
    push_i16(&mut table, -64);
    push_i16(&mut table, 1);
    push_u16(&mut table, 0);
    push_u16(&mut table, 0);
    assert_eq!(table.len(), 44);
    table
}

fn loca() -> Vec<u8> {
    let mut table = Vec::with_capacity(12);
    push_u32(&mut table, 0);
    push_u32(&mut table, 0);
    push_u32(&mut table, 22);
    table
}

fn glyf() -> Vec<u8> {
    let mut table = Vec::with_capacity(22);
    push_i16(&mut table, 1);
    push_i16(&mut table, 0);
    push_i16(&mut table, 0);
    push_i16(&mut table, 500);
    push_i16(&mut table, 700);
    push_u16(&mut table, 2);
    push_u16(&mut table, 0);
    table.extend_from_slice(&[0x31, 0x21, 0x03]);
    push_i16(&mut table, 500);
    table.push(250);
    push_i16(&mut table, 700);
    assert_eq!(table.len(), 22);
    table
}

fn post() -> Vec<u8> {
    let mut table = Vec::with_capacity(32);
    push_u32(&mut table, 0x0003_0000);
    push_u32(&mut table, 0);
    push_i16(&mut table, -75);
    push_i16(&mut table, 50);
    for _ in 0..5 {
        push_u32(&mut table, 0);
    }
    assert_eq!(table.len(), 32);
    table
}

fn push_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn push_i16(output: &mut Vec<u8>, value: i16) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn push_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn push_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_be_bytes());
}

#[test]
fn generated_fixture_is_parseable_and_maps_a_to_glyph_one() {
    let bytes = qualification_font();
    let face = rustybuzz::Face::from_slice(&bytes, 0).unwrap();
    let mut buffer = rustybuzz::UnicodeBuffer::new();
    buffer.push_str("A");
    let shaped = rustybuzz::shape(&face, &[], buffer);
    assert_eq!(shaped.glyph_infos().len(), 1);
    assert_eq!(shaped.glyph_infos()[0].glyph_id, 1);
    assert_eq!(face.units_per_em(), 1_000);
}
