use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use super::validate_bundle_identity;
use crate::portable_plot::{PortablePlotError, ResourceDigest};

mod composite;
mod shx;

pub(crate) use composite::ShxCompositeFace;
pub use composite::ShxCompositeFontResource;

const MAX_SOURCE_BYTES: usize = 16 * 1024 * 1024;
const MAX_GLYPHS: usize = 65_536;
const MAX_COMMANDS: usize = 1_000_000;

/// One immutable normalized SHX stroke-font resource.
///
/// The resource admits either the closed `portable_shx_v1` semantic JSON
/// contract or a bounded raw SHX subset. It never resolves host paths.
#[derive(Debug, Clone)]
pub struct ShxStrokeFontResource {
    logical_identity: String,
    bytes: Arc<[u8]>,
    digest: ResourceDigest,
    source_format: &'static str,
    semantic_digest: ResourceDigest,
    cap_height: f64,
    descent: f64,
    glyphs: BTreeMap<char, ShxStrokeGlyph>,
    legacy_code_points: BTreeMap<u16, char>,
}

/// Caller-controlled policy for bounded raw SHX admission.
///
/// Printable ASCII and Autodesk's documented legacy symbol slots are mapped
/// canonically. Every other legacy character identity must be supplied here;
/// no host code page is inferred.
#[derive(Debug, Clone, Default)]
pub struct ShxAdmissionOptions {
    legacy_code_points: BTreeMap<u16, char>,
}

impl ShxAdmissionOptions {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add one exact legacy shape-code to Unicode mapping.
    pub fn with_legacy_code_point(
        mut self,
        shape_code: u16,
        character: char,
    ) -> Result<Self, PortablePlotError> {
        if shape_code == 0
            || self.legacy_code_points.contains_key(&shape_code)
            || self
                .legacy_code_points
                .values()
                .any(|value| *value == character)
        {
            return Err(invalid_resource(
                "raw SHX legacy character mappings must have unique nonzero codes and Unicode targets",
            ));
        }
        self.legacy_code_points.insert(shape_code, character);
        Ok(self)
    }

    pub(crate) fn legacy_code_points(&self) -> &BTreeMap<u16, char> {
        &self.legacy_code_points
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ShxStrokeGlyph {
    advance: f64,
    maximum_error: f64,
    commands: Vec<ShxStrokeCommand>,
}

impl ShxStrokeGlyph {
    pub(crate) fn advance(&self) -> f64 {
        self.advance
    }

    pub(crate) fn maximum_error(&self) -> f64 {
        self.maximum_error
    }

    pub(crate) fn commands(&self) -> &[ShxStrokeCommand] {
        &self.commands
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum ShxStrokeCommand {
    MoveTo {
        x: f64,
        y: f64,
    },
    LineTo {
        x: f64,
        y: f64,
    },
    QuadTo {
        control: [f64; 2],
        end: [f64; 2],
    },
    CubicTo {
        control_1: [f64; 2],
        control_2: [f64; 2],
        end: [f64; 2],
    },
    Close,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StrokeFontDocument {
    schema: StrokeFontSchema,
    cap_height: f64,
    descent: f64,
    #[serde(deserialize_with = "deserialize_unique_glyphs")]
    glyphs: BTreeMap<String, StrokeGlyphDocument>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum StrokeFontSchema {
    PortableShxV1,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StrokeGlyphDocument {
    advance: f64,
    maximum_error: f64,
    commands: Vec<StrokeCommandDocument>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum StrokeCommandDocument {
    MoveTo {
        x: f64,
        y: f64,
    },
    LineTo {
        x: f64,
        y: f64,
    },
    QuadTo {
        control: [f64; 2],
        end: [f64; 2],
    },
    CubicTo {
        control_1: [f64; 2],
        control_2: [f64; 2],
        end: [f64; 2],
    },
    Close,
}

fn deserialize_unique_glyphs<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, StrokeGlyphDocument>, D::Error>
where
    D: Deserializer<'de>,
{
    struct UniqueGlyphsVisitor;

    impl<'de> Visitor<'de> for UniqueGlyphsVisitor {
        type Value = BTreeMap<String, StrokeGlyphDocument>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a glyph object with unique canonical Unicode keys")
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut glyphs = BTreeMap::new();
            while let Some((key, glyph)) = map.next_entry()? {
                if glyphs.insert(key, glyph).is_some() {
                    return Err(de::Error::custom("duplicate stroke-font glyph key"));
                }
            }
            Ok(glyphs)
        }
    }

    deserializer.deserialize_map(UniqueGlyphsVisitor)
}

impl ShxStrokeFontResource {
    /// Admit normalized, digest-bound `portable_shx_v1` JSON bytes.
    pub fn new(
        logical_identity: impl Into<String>,
        bytes: impl Into<Arc<[u8]>>,
        expected_digest: ResourceDigest,
    ) -> Result<Self, PortablePlotError> {
        let (logical_identity, bytes) =
            validate_source(logical_identity.into(), bytes.into(), expected_digest)?;
        let document: StrokeFontDocument = serde_json::from_slice(&bytes).map_err(|_| {
            PortablePlotError::new(
                "stroke_font_resource_invalid",
                "stroke-font bytes do not conform to the closed portable_shx_v1 schema",
            )
        })?;
        Self::from_document(
            logical_identity,
            bytes,
            expected_digest,
            "portable_shx_v1",
            document,
            BTreeMap::new(),
        )
    }

    /// Admit a bounded raw AutoCAD SHX font without resolving any host path.
    pub fn from_shx(
        logical_identity: impl Into<String>,
        bytes: impl Into<Arc<[u8]>>,
        expected_digest: ResourceDigest,
        options: &ShxAdmissionOptions,
    ) -> Result<Self, PortablePlotError> {
        let (logical_identity, bytes) =
            validate_source(logical_identity.into(), bytes.into(), expected_digest)?;
        let decoded = shx::decode(&bytes, options)?;
        Self::from_document(
            logical_identity,
            bytes,
            expected_digest,
            decoded.source_format,
            decoded.document,
            options.legacy_code_points.clone(),
        )
    }

    fn from_document(
        logical_identity: String,
        bytes: Arc<[u8]>,
        digest: ResourceDigest,
        source_format: &'static str,
        document: StrokeFontDocument,
        legacy_code_points: BTreeMap<u16, char>,
    ) -> Result<Self, PortablePlotError> {
        let (cap_height, descent, glyphs, semantic_digest) = validate_document(document)?;
        Ok(Self {
            logical_identity,
            bytes,
            digest,
            source_format,
            semantic_digest,
            cap_height,
            descent,
            glyphs,
            legacy_code_points,
        })
    }

    pub fn logical_identity(&self) -> &str {
        &self.logical_identity
    }

    /// Digest of the exact normalized source bytes supplied by the caller.
    pub fn digest(&self) -> ResourceDigest {
        self.digest
    }

    /// Stable identifier for the admitted semantic encoding.
    pub fn source_format(&self) -> &'static str {
        self.source_format
    }

    /// Digest of the canonical normalized stroke-font semantics.
    pub fn semantic_digest(&self) -> ResourceDigest {
        self.semantic_digest
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn shared_bytes(&self) -> Arc<[u8]> {
        Arc::clone(&self.bytes)
    }

    pub(crate) fn legacy_code_points(&self) -> &BTreeMap<u16, char> {
        &self.legacy_code_points
    }

    pub(crate) fn cap_height(&self) -> f64 {
        self.cap_height
    }

    pub(crate) fn descent(&self) -> f64 {
        self.descent
    }

    pub(crate) fn glyph(&self, character: char) -> Option<&ShxStrokeGlyph> {
        self.glyphs.get(&character)
    }
}

fn validate_source(
    logical_identity: String,
    bytes: Arc<[u8]>,
    expected_digest: ResourceDigest,
) -> Result<(String, Arc<[u8]>), PortablePlotError> {
    validate_bundle_identity(&logical_identity)?;
    if bytes.is_empty() {
        return Err(PortablePlotError::new(
            "stroke_font_resource_empty",
            "stroke-font resources must contain at least one byte",
        ));
    }
    if bytes.len() > MAX_SOURCE_BYTES {
        return Err(budget_exceeded(
            "stroke-font source bytes exceed the fixed admission budget",
        ));
    }
    if ResourceDigest::of(&bytes) != expected_digest {
        return Err(PortablePlotError::new(
            "resource_digest_mismatch",
            "stroke-font bytes do not match their immutable SHA-256 binding",
        ));
    }
    Ok((logical_identity, bytes))
}

fn validate_document(
    mut document: StrokeFontDocument,
) -> Result<(f64, f64, BTreeMap<char, ShxStrokeGlyph>, ResourceDigest), PortablePlotError> {
    if document.schema != StrokeFontSchema::PortableShxV1
        || !finite_positive(document.cap_height)
        || !document.descent.is_finite()
        || document.descent < 0.0
        || document.glyphs.is_empty()
        || document.glyphs.len() > MAX_GLYPHS
    {
        return Err(invalid_resource(
            "portable_shx_v1 metrics and glyph inventory are invalid",
        ));
    }
    document.cap_height = normalize_zero(document.cap_height);
    document.descent = normalize_zero(document.descent);

    let mut glyphs = BTreeMap::new();
    let mut command_count = 0_usize;
    for (key, raw) in &mut document.glyphs {
        let scalar = u32::from_str_radix(key, 16).map_err(|_| {
            invalid_resource("portable_shx_v1 glyph keys must be canonical Unicode scalars")
        })?;
        let character = char::from_u32(scalar).ok_or_else(|| {
            invalid_resource("portable_shx_v1 glyph keys must be canonical Unicode scalars")
        })?;
        if *key != format!("{scalar:04X}")
            || !raw.advance.is_finite()
            || raw.advance < 0.0
            || !raw.maximum_error.is_finite()
            || raw.maximum_error < 0.0
            || (raw.commands.is_empty() && raw.maximum_error != 0.0)
        {
            return Err(invalid_resource(
                "portable_shx_v1 glyph metrics or canonical keys are invalid",
            ));
        }
        command_count = command_count
            .checked_add(raw.commands.len())
            .ok_or_else(|| budget_exceeded("stroke-font command accounting overflowed"))?;
        if command_count > MAX_COMMANDS {
            return Err(budget_exceeded(
                "portable_shx_v1 commands exceed the fixed admission budget",
            ));
        }
        raw.advance = normalize_zero(raw.advance);
        raw.maximum_error = normalize_zero(raw.maximum_error);
        validate_and_normalize_commands(&mut raw.commands)?;
        let commands = raw.commands.iter().map(ShxStrokeCommand::from).collect();
        if glyphs
            .insert(
                character,
                ShxStrokeGlyph {
                    advance: raw.advance,
                    maximum_error: raw.maximum_error,
                    commands,
                },
            )
            .is_some()
        {
            return Err(invalid_resource(
                "portable_shx_v1 glyph identities must be unique",
            ));
        }
    }

    let canonical = serde_json::to_vec(&document)
        .map_err(|_| invalid_resource("portable_shx_v1 semantics could not be canonicalized"))?;
    Ok((
        document.cap_height,
        document.descent,
        glyphs,
        ResourceDigest::of(&canonical),
    ))
}

fn validate_and_normalize_commands(
    commands: &mut [StrokeCommandDocument],
) -> Result<(), PortablePlotError> {
    let mut active_subpath = false;
    for command in commands {
        command.normalize()?;
        match command {
            StrokeCommandDocument::MoveTo { .. } => active_subpath = true,
            StrokeCommandDocument::LineTo { .. }
            | StrokeCommandDocument::QuadTo { .. }
            | StrokeCommandDocument::CubicTo { .. }
                if !active_subpath =>
            {
                return Err(invalid_resource(
                    "portable_shx_v1 drawing commands require an active subpath",
                ));
            }
            StrokeCommandDocument::Close if !active_subpath => {
                return Err(invalid_resource(
                    "portable_shx_v1 close commands require an active subpath",
                ));
            }
            StrokeCommandDocument::Close => active_subpath = false,
            _ => {}
        }
    }
    Ok(())
}

impl StrokeCommandDocument {
    fn normalize(&mut self) -> Result<(), PortablePlotError> {
        match self {
            Self::MoveTo { x, y } | Self::LineTo { x, y } => {
                normalize_coordinates(std::slice::from_mut(x))?;
                normalize_coordinates(std::slice::from_mut(y))?;
            }
            Self::QuadTo { control, end } => {
                normalize_coordinates(control)?;
                normalize_coordinates(end)?;
            }
            Self::CubicTo {
                control_1,
                control_2,
                end,
            } => {
                normalize_coordinates(control_1)?;
                normalize_coordinates(control_2)?;
                normalize_coordinates(end)?;
            }
            Self::Close => {}
        }
        Ok(())
    }
}

fn normalize_coordinates(coordinates: &mut [f64]) -> Result<(), PortablePlotError> {
    if coordinates.iter().any(|value| !value.is_finite()) {
        return Err(invalid_resource(
            "portable_shx_v1 command coordinates must be finite",
        ));
    }
    for value in coordinates {
        *value = normalize_zero(*value);
    }
    Ok(())
}

impl From<&StrokeCommandDocument> for ShxStrokeCommand {
    fn from(value: &StrokeCommandDocument) -> Self {
        match value {
            StrokeCommandDocument::MoveTo { x, y } => Self::MoveTo { x: *x, y: *y },
            StrokeCommandDocument::LineTo { x, y } => Self::LineTo { x: *x, y: *y },
            StrokeCommandDocument::QuadTo { control, end } => Self::QuadTo {
                control: *control,
                end: *end,
            },
            StrokeCommandDocument::CubicTo {
                control_1,
                control_2,
                end,
            } => Self::CubicTo {
                control_1: *control_1,
                control_2: *control_2,
                end: *end,
            },
            StrokeCommandDocument::Close => Self::Close,
        }
    }
}

fn normalize_zero(value: f64) -> f64 {
    if value == 0.0 {
        0.0
    } else {
        value
    }
}

fn finite_positive(value: f64) -> bool {
    value.is_finite() && value > 0.0
}

fn invalid_resource(message: &'static str) -> PortablePlotError {
    PortablePlotError::new("stroke_font_resource_invalid", message)
}

fn budget_exceeded(message: &'static str) -> PortablePlotError {
    PortablePlotError::new("stroke_font_resource_budget_exceeded", message)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn bytes(value: serde_json::Value) -> Arc<[u8]> {
        Arc::from(serde_json::to_vec(&value).unwrap())
    }

    fn resource(value: serde_json::Value) -> Result<ShxStrokeFontResource, PortablePlotError> {
        let bytes = bytes(value);
        ShxStrokeFontResource::new(
            "fonts/simplex.portable-shx.json",
            bytes.clone(),
            ResourceDigest::of(&bytes),
        )
    }

    fn valid_document() -> serde_json::Value {
        json!({
            "schema": "portable_shx_v1",
            "cap_height": 10.0,
            "descent": 2.0,
            "glyphs": {
                "0020": { "advance": 4.0, "maximum_error": 0.0, "commands": [] },
                "0041": {
                    "advance": 8.0,
                    "maximum_error": 0.01,
                    "commands": [
                        { "op": "move_to", "x": 0.0, "y": 0.0 },
                        { "op": "line_to", "x": 4.0, "y": 10.0 },
                        { "op": "line_to", "x": 8.0, "y": 0.0 }
                    ]
                }
            }
        })
    }

    #[test]
    fn normalized_resource_binds_exact_and_semantic_digests() {
        let compact = bytes(valid_document());
        let pretty: Arc<[u8]> = Arc::from(
            serde_json::to_string_pretty(&valid_document())
                .unwrap()
                .into_bytes(),
        );
        let first = ShxStrokeFontResource::new(
            "fonts/simplex-a.json",
            compact.clone(),
            ResourceDigest::of(&compact),
        )
        .unwrap();
        let second = ShxStrokeFontResource::new(
            "fonts/simplex-b.json",
            pretty.clone(),
            ResourceDigest::of(&pretty),
        )
        .unwrap();
        assert_ne!(first.digest(), second.digest());
        assert_eq!(first.semantic_digest(), second.semantic_digest());
        assert_eq!(first.source_format(), "portable_shx_v1");
        assert_eq!(first.cap_height(), 10.0);
        assert_eq!(first.descent(), 2.0);
        assert_eq!(first.glyph('A').unwrap().commands().len(), 3);
    }

    #[test]
    fn malformed_metrics_keys_topology_and_digest_fail_closed() {
        let mut invalid = valid_document();
        invalid["cap_height"] = json!(0.0);
        assert_eq!(
            resource(invalid).unwrap_err().code(),
            "stroke_font_resource_invalid"
        );

        let mut invalid = valid_document();
        invalid["glyphs"]["41"] = invalid["glyphs"]["0041"].take();
        invalid["glyphs"].as_object_mut().unwrap().remove("0041");
        assert_eq!(
            resource(invalid).unwrap_err().code(),
            "stroke_font_resource_invalid"
        );

        let mut invalid = valid_document();
        invalid["glyphs"]["0041"]["commands"] = json!([{ "op": "line_to", "x": 1.0, "y": 1.0 }]);
        assert_eq!(
            resource(invalid).unwrap_err().code(),
            "stroke_font_resource_invalid"
        );

        let source = bytes(valid_document());
        assert_eq!(
            ShxStrokeFontResource::new(
                "fonts/simplex.json",
                source,
                ResourceDigest::of(b"different"),
            )
            .unwrap_err()
            .code(),
            "resource_digest_mismatch"
        );
    }

    #[test]
    fn duplicate_glyph_keys_and_open_commands_are_rejected() {
        let duplicate = br#"{
            "schema":"portable_shx_v1",
            "cap_height":10.0,
            "descent":0.0,
            "glyphs":{
                "0041":{"advance":8.0,"maximum_error":0.0,"commands":[]},
                "0041":{"advance":9.0,"maximum_error":0.0,"commands":[]}
            }
        }"#;
        let duplicate: Arc<[u8]> = Arc::from(&duplicate[..]);
        assert_eq!(
            ShxStrokeFontResource::new(
                "fonts/simplex.json",
                duplicate.clone(),
                ResourceDigest::of(&duplicate),
            )
            .unwrap_err()
            .code(),
            "stroke_font_resource_invalid"
        );

        let mut open = valid_document();
        open["glyphs"]["0041"]["commands"][0]["extra"] = json!(true);
        assert_eq!(
            resource(open).unwrap_err().code(),
            "stroke_font_resource_invalid"
        );
    }
}
