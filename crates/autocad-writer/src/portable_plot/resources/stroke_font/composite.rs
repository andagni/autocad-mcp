use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use super::super::validate_bundle_identity;
use crate::portable_plot::{PortablePlotError, ResourceDigest};

const MAX_SOURCE_BYTES: usize = 16 * 1024 * 1024;
const MAX_MAPPINGS: usize = 65_536;

/// One immutable Unicode-to-face mapping for an SHX primary/big-font pair.
///
/// Characters absent from the mapping select the same scalar in the primary
/// face. The resource never infers a code page or falls back based on glyph
/// coverage.
#[derive(Debug, Clone)]
pub struct ShxCompositeFontResource {
    logical_identity: String,
    bytes: Arc<[u8]>,
    digest: ResourceDigest,
    semantic_digest: ResourceDigest,
    mappings: BTreeMap<char, ShxCompositeGlyphSelection>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ShxCompositeFace {
    Primary,
    Big,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ShxCompositeGlyphSelection {
    face: ShxCompositeFace,
    glyph: char,
}

impl ShxCompositeGlyphSelection {
    pub(crate) const fn face(self) -> ShxCompositeFace {
        self.face
    }

    pub(crate) const fn glyph(self) -> char {
        self.glyph
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CompositeFontDocument {
    schema: CompositeFontSchema,
    #[serde(deserialize_with = "deserialize_unique_mappings")]
    glyphs: BTreeMap<String, CompositeGlyphDocument>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum CompositeFontSchema {
    PortableShxCompositeV1,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CompositeGlyphDocument {
    font: CompositeFaceDocument,
    glyph: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum CompositeFaceDocument {
    Primary,
    Big,
}

fn deserialize_unique_mappings<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, CompositeGlyphDocument>, D::Error>
where
    D: Deserializer<'de>,
{
    struct UniqueMappingsVisitor;

    impl<'de> Visitor<'de> for UniqueMappingsVisitor {
        type Value = BTreeMap<String, CompositeGlyphDocument>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a composite glyph object with unique Unicode keys")
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut mappings = BTreeMap::new();
            while let Some((key, mapping)) = map.next_entry()? {
                if mappings.insert(key, mapping).is_some() {
                    return Err(de::Error::custom("duplicate composite glyph key"));
                }
            }
            Ok(mappings)
        }
    }

    deserializer.deserialize_map(UniqueMappingsVisitor)
}

impl ShxCompositeFontResource {
    /// Admit a closed, digest-bound `portable_shx_composite_v1` mapping.
    pub fn new(
        logical_identity: impl Into<String>,
        bytes: impl Into<Arc<[u8]>>,
        expected_digest: ResourceDigest,
    ) -> Result<Self, PortablePlotError> {
        let logical_identity = logical_identity.into();
        let bytes = bytes.into();
        validate_bundle_identity(&logical_identity)?;
        if bytes.is_empty() {
            return Err(invalid_resource(
                "SHX composite mappings must contain at least one byte",
            ));
        }
        if bytes.len() > MAX_SOURCE_BYTES {
            return Err(budget_exceeded(
                "SHX composite mapping bytes exceed the fixed admission budget",
            ));
        }
        if ResourceDigest::of(&bytes) != expected_digest {
            return Err(PortablePlotError::new(
                "resource_digest_mismatch",
                "SHX composite mapping bytes do not match their immutable SHA-256 binding",
            ));
        }
        let document: CompositeFontDocument = serde_json::from_slice(&bytes).map_err(|_| {
            invalid_resource(
                "SHX composite mapping bytes do not conform to portable_shx_composite_v1",
            )
        })?;
        let (mappings, semantic_digest) = validate_document(&document)?;
        Ok(Self {
            logical_identity,
            bytes,
            digest: expected_digest,
            semantic_digest,
            mappings,
        })
    }

    pub fn logical_identity(&self) -> &str {
        &self.logical_identity
    }

    pub fn digest(&self) -> ResourceDigest {
        self.digest
    }

    pub fn source_format(&self) -> &'static str {
        "portable_shx_composite_v1"
    }

    pub fn semantic_digest(&self) -> ResourceDigest {
        self.semantic_digest
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn selection(&self, character: char) -> ShxCompositeGlyphSelection {
        self.mappings
            .get(&character)
            .copied()
            .unwrap_or(ShxCompositeGlyphSelection {
                face: ShxCompositeFace::Primary,
                glyph: character,
            })
    }
}

fn validate_document(
    document: &CompositeFontDocument,
) -> Result<(BTreeMap<char, ShxCompositeGlyphSelection>, ResourceDigest), PortablePlotError> {
    if document.schema != CompositeFontSchema::PortableShxCompositeV1 {
        return Err(invalid_resource("unsupported SHX composite mapping schema"));
    }
    if document.glyphs.len() > MAX_MAPPINGS {
        return Err(budget_exceeded(
            "SHX composite mappings exceed the fixed entry budget",
        ));
    }
    let mut mappings = BTreeMap::new();
    for (source, mapping) in &document.glyphs {
        let source = canonical_scalar(source)?;
        let glyph = canonical_scalar(&mapping.glyph)?;
        let face = match mapping.font {
            CompositeFaceDocument::Primary => ShxCompositeFace::Primary,
            CompositeFaceDocument::Big => ShxCompositeFace::Big,
        };
        if mappings
            .insert(source, ShxCompositeGlyphSelection { face, glyph })
            .is_some()
        {
            return Err(invalid_resource(
                "SHX composite source characters must be unique",
            ));
        }
    }
    let canonical = serde_json::to_vec(document)
        .map_err(|_| invalid_resource("SHX composite semantics could not be canonicalized"))?;
    Ok((mappings, ResourceDigest::of(&canonical)))
}

fn canonical_scalar(value: &str) -> Result<char, PortablePlotError> {
    let scalar = u32::from_str_radix(value, 16).map_err(|_| {
        invalid_resource("SHX composite glyph identities must be canonical Unicode scalars")
    })?;
    let character = char::from_u32(scalar).ok_or_else(|| {
        invalid_resource("SHX composite glyph identities must be canonical Unicode scalars")
    })?;
    if value != format!("{scalar:04X}") {
        return Err(invalid_resource(
            "SHX composite glyph identities must be canonical Unicode scalars",
        ));
    }
    Ok(character)
}

fn invalid_resource(message: &'static str) -> PortablePlotError {
    PortablePlotError::new("stroke_font_composite_resource_invalid", message)
}

fn budget_exceeded(message: &'static str) -> PortablePlotError {
    PortablePlotError::new("stroke_font_composite_resource_budget_exceeded", message)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn bytes(value: serde_json::Value) -> Arc<[u8]> {
        Arc::from(serde_json::to_vec(&value).unwrap())
    }

    fn valid_document() -> serde_json::Value {
        json!({
            "schema": "portable_shx_composite_v1",
            "glyphs": {
                "0042": { "font": "primary", "glyph": "0041" },
                "4E00": { "font": "big", "glyph": "4E8C" }
            }
        })
    }

    fn resource(value: serde_json::Value) -> Result<ShxCompositeFontResource, PortablePlotError> {
        let bytes = bytes(value);
        ShxCompositeFontResource::new(
            "fonts/latin-cjk.composite.json",
            bytes.clone(),
            ResourceDigest::of(&bytes),
        )
    }

    #[test]
    fn exact_and_semantic_digests_are_distinct_and_selection_is_explicit() {
        let compact = bytes(valid_document());
        let pretty: Arc<[u8]> = Arc::from(
            serde_json::to_string_pretty(&valid_document())
                .unwrap()
                .into_bytes(),
        );
        let first = ShxCompositeFontResource::new(
            "fonts/first.json",
            compact.clone(),
            ResourceDigest::of(&compact),
        )
        .unwrap();
        let second = ShxCompositeFontResource::new(
            "fonts/second.json",
            pretty.clone(),
            ResourceDigest::of(&pretty),
        )
        .unwrap();
        assert_ne!(first.digest(), second.digest());
        assert_eq!(first.semantic_digest(), second.semantic_digest());
        assert_eq!(first.source_format(), "portable_shx_composite_v1");
        assert_eq!(
            first.selection('A'),
            ShxCompositeGlyphSelection {
                face: ShxCompositeFace::Primary,
                glyph: 'A'
            }
        );
        assert_eq!(first.selection('B').glyph(), 'A');
        assert_eq!(first.selection('一').face(), ShxCompositeFace::Big);
        assert_eq!(first.selection('一').glyph(), '二');
    }

    #[test]
    fn schema_scalars_duplicates_unknown_fields_and_digest_fail_closed() {
        let mut invalid = valid_document();
        invalid["glyphs"]["41"] = invalid["glyphs"]["0042"].take();
        invalid["glyphs"].as_object_mut().unwrap().remove("0042");
        assert_eq!(
            resource(invalid).unwrap_err().code(),
            "stroke_font_composite_resource_invalid"
        );

        let mut invalid = valid_document();
        invalid["glyphs"]["0042"]["glyph"] = json!("D800");
        assert_eq!(
            resource(invalid).unwrap_err().code(),
            "stroke_font_composite_resource_invalid"
        );

        let mut invalid = valid_document();
        invalid["glyphs"]["0042"]["extra"] = json!(true);
        assert_eq!(
            resource(invalid).unwrap_err().code(),
            "stroke_font_composite_resource_invalid"
        );

        let duplicate: Arc<[u8]> = Arc::from(
            br#"{"schema":"portable_shx_composite_v1","glyphs":{"0041":{"font":"primary","glyph":"0041"},"0041":{"font":"big","glyph":"0042"}}}"#
                .as_slice(),
        );
        assert_eq!(
            ShxCompositeFontResource::new(
                "fonts/duplicate.json",
                duplicate.clone(),
                ResourceDigest::of(&duplicate),
            )
            .unwrap_err()
            .code(),
            "stroke_font_composite_resource_invalid"
        );

        let source = bytes(valid_document());
        assert_eq!(
            ShxCompositeFontResource::new(
                "fonts/mismatch.json",
                source,
                ResourceDigest::of(b"different"),
            )
            .unwrap_err()
            .code(),
            "resource_digest_mismatch"
        );
    }
}
