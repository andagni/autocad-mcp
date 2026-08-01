use std::collections::BTreeMap;
use std::io::Read;

use flate2::read::ZlibDecoder;

use super::{
    PlotStyleDocument, PlotStyleDocumentRule, PlotStyleLineCap, PlotStyleLineJoin, PlotStyleRgb,
    PlotStyleSchema, PlotStyleUseObject,
};
use crate::portable_plot::PortablePlotError;

const CTB_PREFIX: &[u8; 48] = b"PIAFILEVERSION_2.0,CTBVER1,compress\r\npmzlibcodec";
const CTB_HEADER_BYTES: usize = 60;
const MAX_SOURCE_BYTES: usize = 4 * 1024 * 1024;
const MAX_DECODED_BYTES: usize = 8 * 1024 * 1024;
const MAX_LINES: usize = 32_768;
const MAX_NESTING: usize = 3;
const MAX_SCALAR_BYTES: usize = 4_096;
const MAX_LINEWEIGHTS: usize = 256;
const STYLE_COUNT: usize = 255;

const OBJECT_COLOR: i32 = -1;
const OBJECT_COLOR_2: i32 = -1_006_632_961;
const COLOR_BY_LAYER: u8 = 0xc0;
const COLOR_BY_BLOCK: u8 = 0xc1;
const COLOR_RGB: u8 = 0xc2;
const COLOR_ACI: u8 = 0xc3;

pub(super) fn decode(bytes: &[u8]) -> Result<PlotStyleDocument, PortablePlotError> {
    let decoded = decode_container(bytes)?;
    let body = validate_text_body(&decoded)?;
    let tree = parse_tree(body)?;
    let raw = parse_raw_document(&tree)?;
    admit_semantics(raw)
}

fn decode_container(bytes: &[u8]) -> Result<Vec<u8>, PortablePlotError> {
    if bytes.len() < CTB_HEADER_BYTES
        || bytes.len() > MAX_SOURCE_BYTES
        || &bytes[..CTB_PREFIX.len()] != CTB_PREFIX
    {
        return Err(invalid());
    }
    let expected_adler = read_u32(bytes, 48)?;
    let decoded_len = usize::try_from(read_u32(bytes, 52)?).map_err(|_| invalid())?;
    let compressed_len = usize::try_from(read_u32(bytes, 56)?).map_err(|_| invalid())?;
    if decoded_len == 0
        || decoded_len > MAX_DECODED_BYTES
        || compressed_len == 0
        || compressed_len > MAX_SOURCE_BYTES - CTB_HEADER_BYTES
        || CTB_HEADER_BYTES
            .checked_add(compressed_len)
            .filter(|expected| *expected == bytes.len())
            .is_none()
    {
        return Err(invalid());
    }
    let compressed = &bytes[CTB_HEADER_BYTES..];
    if adler32(compressed) != expected_adler {
        return Err(invalid());
    }

    let mut decoder = ZlibDecoder::new(compressed);
    let mut decoded = Vec::with_capacity(decoded_len.min(64 * 1024));
    {
        let mut limited = (&mut decoder).take((MAX_DECODED_BYTES + 1) as u64);
        limited.read_to_end(&mut decoded).map_err(|_| invalid())?;
    }
    if decoded.len() != decoded_len
        || decoded.len() > MAX_DECODED_BYTES
        || usize::try_from(decoder.total_in()).map_err(|_| invalid())? != compressed_len
    {
        return Err(invalid());
    }
    Ok(decoded)
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, PortablePlotError> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or_else(invalid)?
        .try_into()
        .map_err(|_| invalid())?;
    Ok(u32::from_le_bytes(value))
}

fn adler32(bytes: &[u8]) -> u32 {
    const MODULUS: u32 = 65_521;
    let mut low = 1_u32;
    let mut high = 0_u32;
    for byte in bytes {
        low = (low + u32::from(*byte)) % MODULUS;
        high = (high + low) % MODULUS;
    }
    (high << 16) | low
}

fn validate_text_body(decoded: &[u8]) -> Result<&str, PortablePlotError> {
    let (&last, body) = decoded.split_last().ok_or_else(invalid)?;
    if last != 0 || body.contains(&0) || body.is_empty() {
        return Err(invalid());
    }
    for (index, byte) in body.iter().copied().enumerate() {
        match byte {
            b'\n' | 0x20..=0x7e => {}
            b'\r' if body.get(index + 1) == Some(&b'\n') => {}
            _ => return Err(invalid()),
        }
    }
    std::str::from_utf8(body).map_err(|_| invalid())
}

#[derive(Debug)]
enum CtbValue {
    Scalar(String),
    Map(CtbMap),
}

type CtbMap = BTreeMap<String, CtbValue>;

fn parse_tree(body: &str) -> Result<CtbMap, PortablePlotError> {
    let lines = body.split_terminator('\n').collect::<Vec<_>>();
    if lines.is_empty() || lines.len() > MAX_LINES {
        return Err(invalid());
    }
    let mut index = 0;
    let result = parse_map(&lines, &mut index, 0, false)?;
    if index != lines.len() {
        return Err(invalid());
    }
    Ok(result)
}

fn parse_map(
    lines: &[&str],
    index: &mut usize,
    depth: usize,
    expect_close: bool,
) -> Result<CtbMap, PortablePlotError> {
    if depth > MAX_NESTING {
        return Err(invalid());
    }
    let mut result = CtbMap::new();
    while *index < lines.len() {
        let line = lines[*index].strip_suffix('\r').unwrap_or(lines[*index]);
        *index += 1;
        let trimmed = line.trim_matches(' ');
        if trimmed.is_empty() || trimmed.len() > MAX_SCALAR_BYTES + 80 {
            return Err(invalid());
        }
        if trimmed == "}" {
            return if expect_close {
                Ok(result)
            } else {
                Err(invalid())
            };
        }
        let (key, value) = if let Some(key) = trimmed.strip_suffix('{') {
            let key = key.trim_end_matches(' ');
            validate_key(key)?;
            if depth == MAX_NESTING {
                return Err(invalid());
            }
            (
                key.to_owned(),
                CtbValue::Map(parse_map(lines, index, depth + 1, true)?),
            )
        } else {
            let (key, value) = trimmed.split_once('=').ok_or_else(invalid)?;
            let key = key.trim_end_matches(' ');
            validate_key(key)?;
            let value = value.trim_matches(' ');
            if value.is_empty() || value.len() > MAX_SCALAR_BYTES {
                return Err(invalid());
            }
            (key.to_owned(), CtbValue::Scalar(value.to_owned()))
        };
        if result.insert(key, value).is_some() {
            return Err(invalid());
        }
    }
    if expect_close {
        Err(invalid())
    } else {
        Ok(result)
    }
}

fn validate_key(key: &str) -> Result<(), PortablePlotError> {
    if key.is_empty()
        || key.len() > 64
        || !key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(invalid());
    }
    Ok(())
}

#[derive(Debug)]
struct RawDocument {
    scale_factor: f64,
    apply_factor: bool,
    display_units: i64,
    styles: Vec<RawStyle>,
    lineweights: Vec<f64>,
}

#[derive(Debug)]
struct RawStyle {
    color: i32,
    mode_color: Option<i32>,
    color_policy: u32,
    physical_pen_number: i64,
    virtual_pen_number: i64,
    screen: i64,
    linepattern_size: f64,
    linetype: i64,
    adaptive_linetype: bool,
    lineweight: usize,
    fill_style: i64,
    end_style: i64,
    join_style: i64,
}

fn parse_raw_document(root: &CtbMap) -> Result<RawDocument, PortablePlotError> {
    require_exact_keys(
        root,
        &[
            "description",
            "aci_table_available",
            "scale_factor",
            "apply_factor",
            "custom_lineweight_display_units",
            "aci_table",
            "plot_style",
            "custom_lineweight_table",
        ],
    )?;
    parse_string(scalar(root, "description")?)?;
    if !parse_bool(scalar(root, "aci_table_available")?)? {
        return Err(invalid());
    }
    let scale_factor = parse_f64(scalar(root, "scale_factor")?)?;
    let apply_factor = parse_bool(scalar(root, "apply_factor")?)?;
    let display_units = parse_i64(scalar(root, "custom_lineweight_display_units")?)?;

    let aci_table = mapping(root, "aci_table")?;
    if aci_table.len() != STYLE_COUNT {
        return Err(invalid());
    }
    for index in 0..STYLE_COUNT {
        parse_string(scalar(aci_table, &index.to_string())?)?;
    }

    let plot_styles = mapping(root, "plot_style")?;
    if plot_styles.len() != STYLE_COUNT {
        return Err(invalid());
    }
    let mut styles = Vec::with_capacity(STYLE_COUNT);
    for index in 0..STYLE_COUNT {
        styles.push(parse_raw_style(mapping(plot_styles, &index.to_string())?)?);
    }

    let table = mapping(root, "custom_lineweight_table")?;
    if table.is_empty() || table.len() > MAX_LINEWEIGHTS {
        return Err(invalid());
    }
    let mut lineweights = Vec::with_capacity(table.len());
    for index in 0..table.len() {
        let value = parse_f64(scalar(table, &index.to_string())?)?;
        if !value.is_finite() || value < 0.0 {
            return Err(invalid());
        }
        lineweights.push(value);
    }
    if lineweights[0] != 0.0 {
        return Err(invalid());
    }

    Ok(RawDocument {
        scale_factor,
        apply_factor,
        display_units,
        styles,
        lineweights,
    })
}

fn parse_raw_style(style: &CtbMap) -> Result<RawStyle, PortablePlotError> {
    const FIELDS: &[&str] = &[
        "name",
        "localized_name",
        "description",
        "color",
        "mode_color",
        "color_policy",
        "physical_pen_number",
        "virtual_pen_number",
        "screen",
        "linepattern_size",
        "linetype",
        "adaptive_linetype",
        "lineweight",
        "fill_style",
        "end_style",
        "join_style",
    ];
    reject_unknown_keys(style, FIELDS)?;
    for field in ["name", "localized_name", "description"] {
        parse_string(scalar(style, field)?)?;
    }
    Ok(RawStyle {
        color: parse_i32(scalar(style, "color")?)?,
        mode_color: optional_scalar(style, "mode_color")?
            .map(parse_i32)
            .transpose()?,
        color_policy: parse_u32(scalar(style, "color_policy")?)?,
        physical_pen_number: parse_i64(scalar(style, "physical_pen_number")?)?,
        virtual_pen_number: parse_i64(scalar(style, "virtual_pen_number")?)?,
        screen: parse_i64(scalar(style, "screen")?)?,
        linepattern_size: parse_f64(scalar(style, "linepattern_size")?)?,
        linetype: parse_i64(scalar(style, "linetype")?)?,
        adaptive_linetype: parse_bool(scalar(style, "adaptive_linetype")?)?,
        lineweight: parse_usize(scalar(style, "lineweight")?)?,
        fill_style: parse_i64(scalar(style, "fill_style")?)?,
        end_style: parse_i64(scalar(style, "end_style")?)?,
        join_style: parse_i64(scalar(style, "join_style")?)?,
    })
}

fn admit_semantics(raw: RawDocument) -> Result<PlotStyleDocument, PortablePlotError> {
    if !raw.scale_factor.is_finite() || raw.scale_factor <= 0.0 {
        return Err(invalid());
    }
    if raw.apply_factor {
        return Err(unsupported());
    }
    if !matches!(raw.display_units, 0 | 1) {
        return Err(invalid());
    }

    let mut styles = BTreeMap::new();
    for (index, raw_style) in raw.styles.into_iter().enumerate() {
        let rule = admit_style(raw_style, &raw.lineweights)?;
        styles.insert((index + 1).to_string(), rule);
    }
    Ok(PlotStyleDocument {
        schema: PlotStyleSchema::PortableCtbV1,
        styles,
    })
}

fn admit_style(
    raw: RawStyle,
    lineweights: &[f64],
) -> Result<PlotStyleDocumentRule, PortablePlotError> {
    if raw.color_policy & !0b111 != 0
        || raw.physical_pen_number < 0
        || raw.virtual_pen_number < 0
        || !(0..=100).contains(&raw.screen)
        || !raw.linepattern_size.is_finite()
        || raw.linepattern_size <= 0.0
        || !(0..=31).contains(&raw.linetype)
        || !(64..=73).contains(&raw.fill_style)
        || !matches!(raw.end_style, 0..=4)
        || !matches!(raw.join_style, 0..=3 | 5)
        || raw.lineweight >= lineweights.len()
    {
        return Err(invalid());
    }
    if raw.color_policy & 0b001 != 0
        || raw.color_policy & 0b100 != 0
        || raw.physical_pen_number != 0
        || raw.virtual_pen_number != 0
        || raw.screen != 100
        || raw.linepattern_size != 0.5
        || raw.linetype != 31
        || raw.adaptive_linetype
        || raw.fill_style != 73
        || raw.end_style == 3
        || raw.join_style == 3
    {
        return Err(unsupported());
    }

    let color = admit_color(raw.color, raw.mode_color)?;
    let line_cap = match raw.end_style {
        0 => PlotStyleLineCap::Butt,
        1 => PlotStyleLineCap::Square,
        2 => PlotStyleLineCap::Round,
        4 => PlotStyleLineCap::UseObject,
        _ => return Err(unsupported()),
    };
    let line_join = match raw.join_style {
        0 => PlotStyleLineJoin::Miter,
        1 => PlotStyleLineJoin::Bevel,
        2 => PlotStyleLineJoin::Round,
        5 => PlotStyleLineJoin::UseObject,
        _ => return Err(unsupported()),
    };
    Ok(PlotStyleDocumentRule {
        color,
        grayscale: raw.color_policy & 0b010 != 0,
        screening_percent: 100,
        lineweight_mm: (lineweights[raw.lineweight] != 0.0).then_some(lineweights[raw.lineweight]),
        line_cap,
        line_join,
        linetype: PlotStyleUseObject::UseObject,
        fill_style: PlotStyleUseObject::UseObject,
        dither: false,
    })
}

fn admit_color(
    color: i32,
    mode_color: Option<i32>,
) -> Result<Option<PlotStyleRgb>, PortablePlotError> {
    if matches!(color, OBJECT_COLOR | OBJECT_COLOR_2) {
        if mode_color.is_some_and(|mode| !matches!(mode, OBJECT_COLOR | OBJECT_COLOR_2)) {
            return Err(invalid());
        }
        return Ok(None);
    }

    let color_type = (color as u32 >> 24) as u8;
    match color_type {
        COLOR_RGB | COLOR_ACI => {}
        COLOR_BY_LAYER | COLOR_BY_BLOCK => return Err(unsupported()),
        _ => return Err(invalid()),
    }
    let mode = mode_color.ok_or_else(invalid)? as u32;
    match (mode >> 24) as u8 {
        COLOR_RGB => Ok(Some(PlotStyleRgb {
            red: ((mode >> 16) & 0xff) as u8,
            green: ((mode >> 8) & 0xff) as u8,
            blue: (mode & 0xff) as u8,
        })),
        COLOR_BY_LAYER | COLOR_BY_BLOCK | COLOR_ACI => Err(unsupported()),
        _ => Err(invalid()),
    }
}

fn require_exact_keys(map: &CtbMap, keys: &[&str]) -> Result<(), PortablePlotError> {
    reject_unknown_keys(map, keys)?;
    if keys.iter().any(|key| !map.contains_key(*key)) {
        return Err(invalid());
    }
    Ok(())
}

fn reject_unknown_keys(map: &CtbMap, keys: &[&str]) -> Result<(), PortablePlotError> {
    if map.keys().any(|key| !keys.contains(&key.as_str())) {
        return Err(invalid());
    }
    Ok(())
}

fn scalar<'a>(map: &'a CtbMap, key: &str) -> Result<&'a str, PortablePlotError> {
    match map.get(key) {
        Some(CtbValue::Scalar(value)) => Ok(value),
        _ => Err(invalid()),
    }
}

fn optional_scalar<'a>(map: &'a CtbMap, key: &str) -> Result<Option<&'a str>, PortablePlotError> {
    match map.get(key) {
        Some(CtbValue::Scalar(value)) => Ok(Some(value)),
        Some(CtbValue::Map(_)) => Err(invalid()),
        None => Ok(None),
    }
}

fn mapping<'a>(map: &'a CtbMap, key: &str) -> Result<&'a CtbMap, PortablePlotError> {
    match map.get(key) {
        Some(CtbValue::Map(value)) => Ok(value),
        _ => Err(invalid()),
    }
}

fn parse_string(value: &str) -> Result<&str, PortablePlotError> {
    value.strip_prefix('"').ok_or_else(invalid)
}

fn parse_bool(value: &str) -> Result<bool, PortablePlotError> {
    match value {
        "TRUE" => Ok(true),
        "FALSE" => Ok(false),
        _ => Err(invalid()),
    }
}

fn parse_i32(value: &str) -> Result<i32, PortablePlotError> {
    value.parse().map_err(|_| invalid())
}

fn parse_i64(value: &str) -> Result<i64, PortablePlotError> {
    value.parse().map_err(|_| invalid())
}

fn parse_u32(value: &str) -> Result<u32, PortablePlotError> {
    value.parse().map_err(|_| invalid())
}

fn parse_usize(value: &str) -> Result<usize, PortablePlotError> {
    value.parse().map_err(|_| invalid())
}

fn parse_f64(value: &str) -> Result<f64, PortablePlotError> {
    value.parse().map_err(|_| invalid())
}

fn invalid() -> PortablePlotError {
    PortablePlotError::new(
        "plot_style_resource_invalid",
        "CTB framing or closed-schema validation failed",
    )
}

fn unsupported() -> PortablePlotError {
    PortablePlotError::new(
        "plot_style_semantics_unsupported",
        "CTB requests plot-style semantics outside portable_ctb_v1",
    )
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::Arc;

    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use serde_json::{json, Map, Value};

    use super::*;
    use crate::portable_plot::{LineCap, LineJoin, ResourceDigest, SceneColor};

    fn supported_body(first_style_overrides: &[(&str, &str)]) -> String {
        let mut body = String::from(
            "description=\"portable\naci_table_available=TRUE\nscale_factor=1.0\napply_factor=FALSE\ncustom_lineweight_display_units=0\naci_table{\n",
        );
        for index in 0..STYLE_COUNT {
            body.push_str(&format!(" {index}=\"Color_{}\n", index + 1));
        }
        body.push_str("}\nplot_style{\n");
        for index in 0..STYLE_COUNT {
            let mut fields = BTreeMap::from([
                ("name", format!("\"Color_{}", index + 1)),
                ("localized_name", format!("\"Color_{}", index + 1)),
                ("description", "\"".to_owned()),
                ("color", OBJECT_COLOR.to_string()),
                ("color_policy", "0".to_owned()),
                ("physical_pen_number", "0".to_owned()),
                ("virtual_pen_number", "0".to_owned()),
                ("screen", "100".to_owned()),
                ("linepattern_size", "0.5".to_owned()),
                ("linetype", "31".to_owned()),
                ("adaptive_linetype", "FALSE".to_owned()),
                ("lineweight", "0".to_owned()),
                ("fill_style", "73".to_owned()),
                ("end_style", "4".to_owned()),
                ("join_style", "5".to_owned()),
            ]);
            if index == 0 {
                for (key, value) in first_style_overrides {
                    fields.insert(*key, (*value).to_owned());
                }
            }
            body.push_str(&format!(" {index}{{\n"));
            for key in [
                "name",
                "localized_name",
                "description",
                "color",
                "mode_color",
                "color_policy",
                "physical_pen_number",
                "virtual_pen_number",
                "screen",
                "linepattern_size",
                "linetype",
                "adaptive_linetype",
                "lineweight",
                "fill_style",
                "end_style",
                "join_style",
            ] {
                if let Some(value) = fields.get(key) {
                    body.push_str(&format!("  {key}={value}\n"));
                }
            }
            body.push_str(" }\n");
        }
        body.push_str("}\ncustom_lineweight_table{\n 0=0.0\n 1=0.35\n}\n");
        body
    }

    fn encode_body(body: &[u8]) -> Arc<[u8]> {
        let mut decoded = body.to_vec();
        decoded.push(0);
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&decoded).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut output = Vec::new();
        output.extend_from_slice(CTB_PREFIX);
        output.extend_from_slice(&adler32(&compressed).to_le_bytes());
        output.extend_from_slice(&u32::try_from(decoded.len()).unwrap().to_le_bytes());
        output.extend_from_slice(&u32::try_from(compressed.len()).unwrap().to_le_bytes());
        output.extend_from_slice(&compressed);
        output.into()
    }

    fn normalized_bytes(first: Value) -> Arc<[u8]> {
        let mut styles = Map::new();
        for index in 1..=STYLE_COUNT {
            styles.insert(
                index.to_string(),
                if index == 1 {
                    first.clone()
                } else {
                    json!({
                        "color": null,
                        "grayscale": false,
                        "screening_percent": 100,
                        "lineweight_mm": null,
                        "line_cap": "use_object",
                        "line_join": "use_object",
                        "linetype": "use_object",
                        "fill_style": "use_object",
                        "dither": false
                    })
                },
            );
        }
        serde_json::to_vec(&json!({"schema": "portable_ctb_v1", "styles": styles}))
            .unwrap()
            .into()
    }

    fn error_code(bytes: Arc<[u8]>) -> &'static str {
        let digest = ResourceDigest::of(&bytes);
        super::super::PlotStyleResource::from_ctb("test.ctb", bytes, digest)
            .unwrap_err()
            .code()
    }

    #[test]
    fn supported_ctb_is_digest_bound_and_canonicalizes_with_normalized_json() {
        let ctb = encode_body(
            supported_body(&[
                ("color", "-1039392200"),
                ("mode_color", "-1039392200"),
                ("color_policy", "2"),
                ("lineweight", "1"),
                ("end_style", "2"),
                ("join_style", "1"),
            ])
            .as_bytes(),
        );
        let digest = ResourceDigest::of(&ctb);
        assert_eq!(
            super::super::PlotStyleResource::from_ctb(
                "styles/test.ctb",
                ctb.clone(),
                ResourceDigest::of(b"different"),
            )
            .unwrap_err()
            .code(),
            "resource_digest_mismatch"
        );
        let resource =
            super::super::PlotStyleResource::from_ctb("styles/test.ctb", ctb, digest).unwrap();
        assert_eq!(resource.digest(), digest);
        assert_eq!(resource.source_format(), "autodesk_ctb_v1");
        let rule = resource.style(1).unwrap();
        assert_eq!(rule.color, Some(SceneColor::rgb(12, 34, 56)));
        assert!(rule.grayscale);
        assert_eq!(rule.line_cap, Some(LineCap::Round));
        assert_eq!(rule.line_join, Some(LineJoin::Bevel));

        let normalized = normalized_bytes(json!({
            "color": {"red": 12, "green": 34, "blue": 56},
            "grayscale": true,
            "screening_percent": 100,
            "lineweight_mm": 0.35,
            "line_cap": "round",
            "line_join": "bevel",
            "linetype": "use_object",
            "fill_style": "use_object",
            "dither": false
        }));
        let normalized_digest = ResourceDigest::of(&normalized);
        let normalized =
            super::super::PlotStyleResource::new("styles/test.json", normalized, normalized_digest)
                .unwrap();
        assert_eq!(resource.semantic_digest(), normalized.semantic_digest());
        assert_ne!(resource.digest(), normalized.digest());
    }

    #[test]
    fn source_metadata_changes_do_not_change_semantic_digest() {
        let first = encode_body(supported_body(&[]).as_bytes());
        let second_body =
            supported_body(&[]).replacen("description=\"portable", "description=\"other", 1);
        let second = encode_body(second_body.as_bytes());
        let first_resource = super::super::PlotStyleResource::from_ctb(
            "one.ctb",
            first.clone(),
            ResourceDigest::of(&first),
        )
        .unwrap();
        let second_resource = super::super::PlotStyleResource::from_ctb(
            "two.ctb",
            second.clone(),
            ResourceDigest::of(&second),
        )
        .unwrap();
        assert_ne!(first_resource.digest(), second_resource.digest());
        assert_eq!(
            first_resource.semantic_digest(),
            second_resource.semantic_digest()
        );
    }

    #[test]
    fn container_and_text_fail_closed() {
        let valid = encode_body(supported_body(&[]).as_bytes());
        let mut bad_prefix = valid.to_vec();
        bad_prefix[0] ^= 1;
        assert_eq!(error_code(bad_prefix.into()), "plot_style_resource_invalid");

        let mut bad_adler = valid.to_vec();
        bad_adler[48] ^= 1;
        assert_eq!(error_code(bad_adler.into()), "plot_style_resource_invalid");

        let mut bad_decoded_len = valid.to_vec();
        bad_decoded_len[52..56].copy_from_slice(&1_u32.to_le_bytes());
        assert_eq!(
            error_code(bad_decoded_len.into()),
            "plot_style_resource_invalid"
        );

        let mut trailing = valid.to_vec();
        trailing.push(0);
        assert_eq!(error_code(trailing.into()), "plot_style_resource_invalid");

        let mut oversized_decoded_len = valid.to_vec();
        oversized_decoded_len[52..56]
            .copy_from_slice(&u32::try_from(MAX_DECODED_BYTES + 1).unwrap().to_le_bytes());
        assert_eq!(
            error_code(oversized_decoded_len.into()),
            "plot_style_resource_invalid"
        );

        let mut invalid_zlib = valid.to_vec();
        *invalid_zlib.last_mut().unwrap() ^= 1;
        let checksum = adler32(&invalid_zlib[CTB_HEADER_BYTES..]);
        invalid_zlib[48..52].copy_from_slice(&checksum.to_le_bytes());
        assert_eq!(
            error_code(invalid_zlib.into()),
            "plot_style_resource_invalid"
        );

        let missing_nul = {
            let body = supported_body(&[]);
            let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(body.as_bytes()).unwrap();
            let compressed = encoder.finish().unwrap();
            let mut bytes = Vec::from(CTB_PREFIX.as_slice());
            bytes.extend_from_slice(&adler32(&compressed).to_le_bytes());
            bytes.extend_from_slice(&u32::try_from(body.len()).unwrap().to_le_bytes());
            bytes.extend_from_slice(&u32::try_from(compressed.len()).unwrap().to_le_bytes());
            bytes.extend_from_slice(&compressed);
            Arc::from(bytes)
        };
        assert_eq!(error_code(missing_nul), "plot_style_resource_invalid");

        let mut non_ascii = supported_body(&[]).into_bytes();
        non_ascii[0] = 0x80;
        assert_eq!(
            error_code(encode_body(&non_ascii)),
            "plot_style_resource_invalid"
        );

        let mut interior_nul = supported_body(&[]).into_bytes();
        interior_nul.insert(1, 0);
        assert_eq!(
            error_code(encode_body(&interior_nul)),
            "plot_style_resource_invalid"
        );
    }

    #[test]
    fn grammar_and_tables_fail_closed() {
        for body in [
            supported_body(&[]).replacen(
                "description=\"portable\n",
                "description=\"portable\ndescription=\"duplicate\n",
                1,
            ),
            supported_body(&[]).replacen("description=\"portable\n", "unknown=1\n", 1),
            supported_body(&[]).replacen(" 254{\n", " 0254{\n", 1),
            supported_body(&[]).replacen(" 1=0.35\n", " 2=0.35\n", 1),
            supported_body(&[]).replacen(" 0=0.0\n", " 0=0.1\n", 1),
            supported_body(&[]).replacen("  lineweight=0\n", "  lineweight=99\n", 1),
            supported_body(&[]).replacen("  name=\"Color_1\n", "", 1),
            supported_body(&[]).replacen(
                "  name=\"Color_1\n",
                "  name=\"Color_1\n  unrecognized=1\n",
                1,
            ),
        ] {
            assert_eq!(
                error_code(encode_body(body.as_bytes())),
                "plot_style_resource_invalid"
            );
        }
    }

    #[test]
    fn every_unimplemented_control_rejects_as_unsupported() {
        let cases = [
            vec![("color_policy", "1")],
            vec![("color_policy", "4")],
            vec![("physical_pen_number", "1")],
            vec![("virtual_pen_number", "1")],
            vec![("screen", "99")],
            vec![("linepattern_size", "0.7")],
            vec![("linetype", "1")],
            vec![("adaptive_linetype", "TRUE")],
            vec![("fill_style", "64")],
            vec![("end_style", "3")],
            vec![("join_style", "3")],
            vec![("color", "-1073741824"), ("mode_color", "-1040187391")],
        ];
        for overrides in cases {
            let bytes = encode_body(supported_body(&overrides).as_bytes());
            assert_eq!(error_code(bytes), "plot_style_semantics_unsupported");
        }

        let applied = supported_body(&[]).replacen("apply_factor=FALSE", "apply_factor=TRUE", 1);
        assert_eq!(
            error_code(encode_body(applied.as_bytes())),
            "plot_style_semantics_unsupported"
        );
    }

    #[test]
    fn contradictory_or_out_of_domain_controls_are_invalid() {
        let cases = [
            vec![("color_policy", "8")],
            vec![("physical_pen_number", "-1")],
            vec![("screen", "101")],
            vec![("linepattern_size", "NaN")],
            vec![("linetype", "32")],
            vec![("fill_style", "74")],
            vec![("end_style", "5")],
            vec![("join_style", "4")],
            vec![("color", "0")],
            vec![("color", "-1039392200")],
            vec![("color", "-1"), ("mode_color", "-1039392200")],
        ];
        for overrides in cases {
            assert_eq!(
                error_code(encode_body(supported_body(&overrides).as_bytes())),
                "plot_style_resource_invalid"
            );
        }
    }
}
