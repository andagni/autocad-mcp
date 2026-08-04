use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

mod ctb;
mod stroke_font;

pub use stroke_font::{ShxAdmissionOptions, ShxCompositeFontResource, ShxStrokeFontResource};
pub(crate) use stroke_font::{ShxCompositeFace, ShxStrokeCommand, ShxStrokeGlyph};

use super::{
    FontId, FontResource, ImageColorSpace, ImageResource, LineCap, LineJoin, PortablePlotError,
    ResourceDigest, SceneColor,
};
use crate::{DrawingFormat, DrawingSnapshot};

/// Immutable resources supplied explicitly for one portable compilation.
///
/// Keys are drawing-facing logical identities. They are matched
/// case-insensitively after separator normalization; no key is ever opened as
/// a host path.
#[derive(Debug, Clone, Default)]
pub struct PortableResourceBundle {
    fonts: BTreeMap<String, FontBinding>,
    fallback_font: Option<FontBinding>,
    stroke_fonts: BTreeMap<String, StrokeFontBinding>,
    composite_stroke_fonts: BTreeMap<CompositeFontKey, CompositeFontBinding>,
    images: BTreeMap<String, ImageBinding>,
    plot_styles: BTreeMap<String, PlotStyleBinding>,
    xrefs: BTreeMap<String, XrefBinding>,
}

#[derive(Debug, Clone)]
struct FontBinding {
    resource: FontResource,
}

#[derive(Debug, Clone)]
struct StrokeFontBinding {
    resource: ShxStrokeFontResource,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CompositeFontKey {
    primary: String,
    big: String,
}

#[derive(Debug, Clone)]
struct CompositeFontBinding {
    resource: ShxCompositeFontResource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct StrokeFontId(u32);

impl StrokeFontId {
    pub(crate) const fn new(value: u32) -> Self {
        Self(value)
    }

    pub(crate) const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CompositeFontId(u32);

impl CompositeFontId {
    pub(crate) const fn new(value: u32) -> Self {
        Self(value)
    }

    pub(crate) const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FontResolution {
    Exact,
    Fallback,
}

#[derive(Debug, Clone)]
struct ImageBinding {
    resource: ImageResource,
}

#[derive(Debug, Clone)]
struct PlotStyleBinding {
    resource: PlotStyleResource,
}

/// One immutable, digest-bound plot-style resource.
///
/// [`PlotStyleResource::new`] admits the repository-owned `portable_ctb_v1`
/// JSON schema. [`PlotStyleResource::from_ctb`] admits a deliberately narrow
/// subset of Autodesk CTB after bounded decompression and closed-schema
/// validation. Both paths canonicalize to the same semantic representation;
/// unsupported CTB controls cannot be silently discarded.
#[derive(Debug, Clone)]
pub struct PlotStyleResource {
    logical_identity: String,
    bytes: Arc<[u8]>,
    digest: ResourceDigest,
    source_format: &'static str,
    semantic_digest: ResourceDigest,
    styles: BTreeMap<u16, PlotStyleRule>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct PlotStyleRule {
    pub(crate) color: Option<SceneColor>,
    pub(crate) grayscale: bool,
    pub(crate) screening_percent: u8,
    pub(crate) lineweight_points: Option<f64>,
    pub(crate) line_cap: Option<LineCap>,
    pub(crate) line_join: Option<LineJoin>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PlotStyleDocument {
    schema: PlotStyleSchema,
    #[serde(deserialize_with = "deserialize_unique_plot_styles")]
    styles: BTreeMap<String, PlotStyleDocumentRule>,
}

fn deserialize_unique_plot_styles<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, PlotStyleDocumentRule>, D::Error>
where
    D: Deserializer<'de>,
{
    struct UniquePlotStylesVisitor;

    impl<'de> Visitor<'de> for UniquePlotStylesVisitor {
        type Value = BTreeMap<String, PlotStyleDocumentRule>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a plot-style object with unique ACI keys")
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut styles = BTreeMap::new();
            while let Some((key, rule)) = map.next_entry()? {
                if styles.insert(key, rule).is_some() {
                    return Err(de::Error::custom("duplicate ACI plot-style key"));
                }
            }
            Ok(styles)
        }
    }

    deserializer.deserialize_map(UniquePlotStylesVisitor)
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum PlotStyleSchema {
    PortableCtbV1,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PlotStyleDocumentRule {
    pub(super) color: Option<PlotStyleRgb>,
    pub(super) grayscale: bool,
    pub(super) screening_percent: u8,
    pub(super) lineweight_mm: Option<f64>,
    pub(super) line_cap: PlotStyleLineCap,
    pub(super) line_join: PlotStyleLineJoin,
    pub(super) linetype: PlotStyleUseObject,
    pub(super) fill_style: PlotStyleUseObject,
    pub(super) dither: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PlotStyleRgb {
    pub(super) red: u8,
    pub(super) green: u8,
    pub(super) blue: u8,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum PlotStyleLineCap {
    UseObject,
    Butt,
    Round,
    Square,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum PlotStyleLineJoin {
    UseObject,
    Miter,
    Round,
    Bevel,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum PlotStyleUseObject {
    UseObject,
}

impl PlotStyleResource {
    /// Admit a normalized `portable_ctb_v1` JSON resource.
    pub fn new(
        logical_identity: impl Into<String>,
        bytes: impl Into<Arc<[u8]>>,
        expected_digest: ResourceDigest,
    ) -> Result<Self, PortablePlotError> {
        let logical_identity = logical_identity.into();
        let bytes = bytes.into();
        validate_bundle_identity(&logical_identity)?;
        if ResourceDigest::of(&bytes) != expected_digest {
            return Err(PortablePlotError::new(
                "resource_digest_mismatch",
                "plot-style bytes do not match their immutable SHA-256 binding",
            ));
        }
        let document: PlotStyleDocument = serde_json::from_slice(&bytes).map_err(|_| {
            PortablePlotError::new(
                "plot_style_resource_invalid",
                "plot-style bytes do not conform to the portable_ctb_v1 schema",
            )
        })?;
        Self::from_document(
            logical_identity,
            bytes,
            expected_digest,
            "portable_ctb_v1",
            document,
        )
    }

    /// Admit an Autodesk CTB resource without resolving any host path.
    pub fn from_ctb(
        logical_identity: impl Into<String>,
        bytes: impl Into<Arc<[u8]>>,
        expected_digest: ResourceDigest,
    ) -> Result<Self, PortablePlotError> {
        let logical_identity = logical_identity.into();
        let bytes = bytes.into();
        validate_bundle_identity(&logical_identity)?;
        if ResourceDigest::of(&bytes) != expected_digest {
            return Err(PortablePlotError::new(
                "resource_digest_mismatch",
                "CTB bytes do not match their immutable SHA-256 binding",
            ));
        }
        let document = ctb::decode(&bytes)?;
        Self::from_document(
            logical_identity,
            bytes,
            expected_digest,
            "autodesk_ctb_v1",
            document,
        )
    }

    fn from_document(
        logical_identity: String,
        bytes: Arc<[u8]>,
        digest: ResourceDigest,
        source_format: &'static str,
        document: PlotStyleDocument,
    ) -> Result<Self, PortablePlotError> {
        let (styles, semantic_digest) = validate_plot_style_document(document)?;
        Ok(Self {
            logical_identity,
            bytes,
            digest,
            source_format,
            semantic_digest,
            styles,
        })
    }

    pub fn logical_identity(&self) -> &str {
        &self.logical_identity
    }

    /// Digest of the exact bytes supplied by the caller.
    pub fn digest(&self) -> ResourceDigest {
        self.digest
    }

    /// Stable identifier for the admitted source encoding.
    pub fn source_format(&self) -> &'static str {
        self.source_format
    }

    /// Digest of the canonical portable plot-style semantics.
    pub fn semantic_digest(&self) -> ResourceDigest {
        self.semantic_digest
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn shared_bytes(&self) -> Arc<[u8]> {
        Arc::clone(&self.bytes)
    }

    pub(crate) fn style(&self, aci: u16) -> Option<PlotStyleRule> {
        self.styles.get(&aci).copied()
    }
}

#[derive(Serialize)]
struct CanonicalPlotStyleDocument<'a> {
    schema: PlotStyleSchema,
    styles: &'a BTreeMap<u16, PlotStyleDocumentRule>,
}

fn validate_plot_style_document(
    document: PlotStyleDocument,
) -> Result<(BTreeMap<u16, PlotStyleRule>, ResourceDigest), PortablePlotError> {
    if document.schema != PlotStyleSchema::PortableCtbV1 || document.styles.len() != 255 {
        return Err(PortablePlotError::new(
            "plot_style_resource_invalid",
            "portable_ctb_v1 must define exactly the ACI styles 1 through 255",
        ));
    }
    let mut raw_styles = BTreeMap::new();
    for (key, rule) in document.styles {
        let index = key.parse::<u16>().map_err(|_| {
            PortablePlotError::new(
                "plot_style_resource_invalid",
                "portable_ctb_v1 style keys must be canonical ACI integers",
            )
        })?;
        if !(1..=255).contains(&index)
            || key != index.to_string()
            || raw_styles.insert(index, rule).is_some()
        {
            return Err(PortablePlotError::new(
                "plot_style_resource_invalid",
                "portable_ctb_v1 must define exactly the ACI styles 1 through 255",
            ));
        }
    }

    let mut styles = BTreeMap::new();
    for index in 1_u16..=255 {
        let raw = raw_styles.get(&index).ok_or_else(|| {
            PortablePlotError::new(
                "plot_style_resource_invalid",
                "portable_ctb_v1 is missing an ACI style",
            )
        })?;
        if raw.screening_percent > 100
            || raw
                .lineweight_mm
                .is_some_and(|value| !value.is_finite() || value < 0.0)
            || raw.dither
            || raw.linetype != PlotStyleUseObject::UseObject
            || raw.fill_style != PlotStyleUseObject::UseObject
        {
            return Err(PortablePlotError::new(
                    "plot_style_semantics_unsupported",
                    "portable_ctb_v1 admits screening, grayscale, colour, lineweight, cap, and join overrides only",
                ));
        }
        let lineweight_points = raw.lineweight_mm.map(|value| value * 72.0 / 25.4);
        if lineweight_points.is_some_and(|value| !value.is_finite()) {
            return Err(PortablePlotError::new(
                "plot_style_semantics_unsupported",
                "portable_ctb_v1 lineweight conversion must remain finite in PDF points",
            ));
        }
        styles.insert(
            index,
            PlotStyleRule {
                color: raw
                    .color
                    .as_ref()
                    .map(|color| SceneColor::rgb(color.red, color.green, color.blue)),
                grayscale: raw.grayscale,
                screening_percent: raw.screening_percent,
                lineweight_points,
                line_cap: match raw.line_cap {
                    PlotStyleLineCap::UseObject => None,
                    PlotStyleLineCap::Butt => Some(LineCap::Butt),
                    PlotStyleLineCap::Round => Some(LineCap::Round),
                    PlotStyleLineCap::Square => Some(LineCap::Square),
                },
                line_join: match raw.line_join {
                    PlotStyleLineJoin::UseObject => None,
                    PlotStyleLineJoin::Miter => Some(LineJoin::Miter),
                    PlotStyleLineJoin::Round => Some(LineJoin::Round),
                    PlotStyleLineJoin::Bevel => Some(LineJoin::Bevel),
                },
            },
        );
    }
    let canonical = serde_json::to_vec(&CanonicalPlotStyleDocument {
        schema: PlotStyleSchema::PortableCtbV1,
        styles: &raw_styles,
    })
    .map_err(|_| {
        PortablePlotError::new(
            "plot_style_resource_invalid",
            "portable plot-style semantics could not be canonicalized",
        )
    })?;
    Ok((styles, ResourceDigest::of(&canonical)))
}

/// A digest-checked immutable drawing snapshot admitted as an XREF member.
#[derive(Debug, Clone)]
pub struct XrefResource {
    logical_identity: String,
    snapshot: DrawingSnapshot,
    digest: ResourceDigest,
}

impl XrefResource {
    pub fn new(
        logical_identity: impl Into<String>,
        snapshot: DrawingSnapshot,
        expected_digest: ResourceDigest,
    ) -> Result<Self, PortablePlotError> {
        let logical_identity = logical_identity.into();
        validate_bundle_identity(&logical_identity)?;
        if ResourceDigest::of(&snapshot.bytes()) != expected_digest {
            return Err(PortablePlotError::new(
                "resource_digest_mismatch",
                "XREF bytes do not match their immutable SHA-256 binding",
            ));
        }
        Ok(Self {
            logical_identity,
            snapshot,
            digest: expected_digest,
        })
    }

    pub fn logical_identity(&self) -> &str {
        &self.logical_identity
    }

    pub fn snapshot(&self) -> &DrawingSnapshot {
        &self.snapshot
    }

    pub fn digest(&self) -> ResourceDigest {
        self.digest
    }
}

#[derive(Debug, Clone)]
struct XrefBinding {
    resource: XrefResource,
}

/// Path-free source material used to reconstruct an admitted bundle in the
/// dedicated worker. Every variant carries the exact caller-supplied bytes
/// and both byte and semantic bindings where the resource format has a
/// normalized semantic representation.
#[derive(Debug, Clone)]
pub(crate) enum PortableResourceTransport {
    Font {
        binding_identity: String,
        fallback: bool,
        logical_identity: String,
        face_index: u32,
        digest: ResourceDigest,
        bytes: Arc<[u8]>,
    },
    StrokeFont {
        binding_identity: String,
        logical_identity: String,
        source_format: String,
        semantic_digest: ResourceDigest,
        legacy_code_points: BTreeMap<u16, char>,
        digest: ResourceDigest,
        bytes: Arc<[u8]>,
    },
    CompositeStrokeFont {
        primary_binding_identity: String,
        big_binding_identity: String,
        logical_identity: String,
        semantic_digest: ResourceDigest,
        digest: ResourceDigest,
        bytes: Arc<[u8]>,
    },
    Image {
        binding_identity: String,
        logical_identity: String,
        width: u32,
        height: u32,
        color_space: ImageColorSpace,
        digest: ResourceDigest,
        bytes: Arc<[u8]>,
    },
    PlotStyle {
        binding_identity: String,
        logical_identity: String,
        source_format: String,
        semantic_digest: ResourceDigest,
        digest: ResourceDigest,
        bytes: Arc<[u8]>,
    },
    Xref {
        binding_identity: String,
        logical_identity: String,
        format: DrawingFormat,
        digest: ResourceDigest,
        bytes: Arc<[u8]>,
    },
}

impl PortableResourceBundle {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn bind_font(
        &mut self,
        drawing_identity: impl Into<String>,
        resource: FontResource,
    ) -> Result<(), PortablePlotError> {
        let drawing_identity = drawing_identity.into();
        let key = canonical_drawing_identity(&drawing_identity)?;
        if self.fonts.insert(key, FontBinding { resource }).is_some() {
            return Err(PortablePlotError::new(
                "resource_identity_duplicate",
                "font drawing identities must be unique after canonicalization",
            ));
        }
        Ok(())
    }

    /// Bind the one caller-authorized font used only when no exact drawing
    /// identity is present.
    ///
    /// Resolution through this binding is always surfaced as substituted
    /// fidelity by the semantic compiler. The bundle never discovers or opens
    /// a host font on its own.
    pub fn bind_fallback_font(&mut self, resource: FontResource) -> Result<(), PortablePlotError> {
        if self.fallback_font.is_some() {
            return Err(PortablePlotError::new(
                "resource_identity_duplicate",
                "a portable resource bundle may contain at most one fallback font",
            ));
        }
        self.fallback_font = Some(FontBinding { resource });
        Ok(())
    }

    /// Bind normalized SHX stroke semantics to one exact drawing font
    /// identity. Outline-font fallback is never consulted for this map.
    pub fn bind_shx_stroke_font(
        &mut self,
        drawing_identity: impl Into<String>,
        resource: ShxStrokeFontResource,
    ) -> Result<(), PortablePlotError> {
        let drawing_identity = drawing_identity.into();
        let key = canonical_drawing_identity(&drawing_identity)?;
        if self.stroke_fonts.contains_key(&key) {
            return Err(PortablePlotError::new(
                "resource_identity_duplicate",
                "SHX stroke-font drawing identities must be unique after canonicalization",
            ));
        }
        self.stroke_fonts
            .insert(key, StrokeFontBinding { resource });
        Ok(())
    }

    /// Bind one immutable Unicode selector map to an exact SHX primary and
    /// big-font drawing-identity pair.
    pub fn bind_shx_composite_font(
        &mut self,
        primary_drawing_identity: impl Into<String>,
        big_drawing_identity: impl Into<String>,
        resource: ShxCompositeFontResource,
    ) -> Result<(), PortablePlotError> {
        let primary = canonical_drawing_identity(&primary_drawing_identity.into())?;
        let big = canonical_drawing_identity(&big_drawing_identity.into())?;
        if primary == big {
            return Err(PortablePlotError::new(
                "stroke_font_composite_resource_invalid",
                "SHX composite primary and big-font identities must be distinct",
            ));
        }
        let key = CompositeFontKey { primary, big };
        if self.composite_stroke_fonts.contains_key(&key) {
            return Err(PortablePlotError::new(
                "resource_identity_duplicate",
                "SHX composite font pairs must be unique after canonicalization",
            ));
        }
        self.composite_stroke_fonts
            .insert(key, CompositeFontBinding { resource });
        Ok(())
    }

    pub fn bind_image(
        &mut self,
        drawing_identity: impl Into<String>,
        resource: ImageResource,
    ) -> Result<(), PortablePlotError> {
        let drawing_identity = drawing_identity.into();
        let key = canonical_drawing_identity(&drawing_identity)?;
        if self.images.insert(key, ImageBinding { resource }).is_some() {
            return Err(PortablePlotError::new(
                "resource_identity_duplicate",
                "image drawing identities must be unique after canonicalization",
            ));
        }
        Ok(())
    }

    pub fn bind_plot_style(
        &mut self,
        drawing_identity: impl Into<String>,
        resource: PlotStyleResource,
    ) -> Result<(), PortablePlotError> {
        let drawing_identity = drawing_identity.into();
        let key = canonical_drawing_identity(&drawing_identity)?;
        if self
            .plot_styles
            .insert(key, PlotStyleBinding { resource })
            .is_some()
        {
            return Err(PortablePlotError::new(
                "resource_identity_duplicate",
                "plot-style drawing identities must be unique after canonicalization",
            ));
        }
        Ok(())
    }

    pub fn bind_xref(
        &mut self,
        drawing_identity: impl Into<String>,
        resource: XrefResource,
    ) -> Result<(), PortablePlotError> {
        let drawing_identity = drawing_identity.into();
        let key = canonical_drawing_identity(&drawing_identity)?;
        if self.xrefs.insert(key, XrefBinding { resource }).is_some() {
            return Err(PortablePlotError::new(
                "resource_identity_duplicate",
                "XREF drawing identities must be unique after canonicalization",
            ));
        }
        Ok(())
    }

    pub fn font_count(&self) -> usize {
        self.fonts.len() + usize::from(self.fallback_font.is_some())
    }

    pub fn shx_stroke_font_count(&self) -> usize {
        self.stroke_fonts.len()
    }

    pub fn shx_composite_font_count(&self) -> usize {
        self.composite_stroke_fonts.len()
    }

    pub fn image_count(&self) -> usize {
        self.images.len()
    }

    pub fn plot_style_count(&self) -> usize {
        self.plot_styles.len()
    }

    pub fn xref_count(&self) -> usize {
        self.xrefs.len()
    }

    pub(crate) fn transport_entries(&self) -> Vec<PortableResourceTransport> {
        let mut entries = Vec::with_capacity(
            self.font_count()
                + self.shx_stroke_font_count()
                + self.shx_composite_font_count()
                + self.image_count()
                + self.plot_style_count()
                + self.xref_count(),
        );
        entries.extend(self.fonts.iter().map(|(binding_identity, binding)| {
            PortableResourceTransport::Font {
                binding_identity: binding_identity.clone(),
                fallback: false,
                logical_identity: binding.resource.logical_identity().to_string(),
                face_index: binding.resource.face_index(),
                digest: binding.resource.digest(),
                bytes: binding.resource.shared_bytes(),
            }
        }));
        if let Some(binding) = &self.fallback_font {
            entries.push(PortableResourceTransport::Font {
                binding_identity: String::new(),
                fallback: true,
                logical_identity: binding.resource.logical_identity().to_string(),
                face_index: binding.resource.face_index(),
                digest: binding.resource.digest(),
                bytes: binding.resource.shared_bytes(),
            });
        }
        entries.extend(self.stroke_fonts.iter().map(|(binding_identity, binding)| {
            PortableResourceTransport::StrokeFont {
                binding_identity: binding_identity.clone(),
                logical_identity: binding.resource.logical_identity().to_string(),
                source_format: binding.resource.source_format().to_string(),
                semantic_digest: binding.resource.semantic_digest(),
                legacy_code_points: binding.resource.legacy_code_points().clone(),
                digest: binding.resource.digest(),
                bytes: binding.resource.shared_bytes(),
            }
        }));
        entries.extend(self.composite_stroke_fonts.iter().map(|(key, binding)| {
            PortableResourceTransport::CompositeStrokeFont {
                primary_binding_identity: key.primary.clone(),
                big_binding_identity: key.big.clone(),
                logical_identity: binding.resource.logical_identity().to_string(),
                semantic_digest: binding.resource.semantic_digest(),
                digest: binding.resource.digest(),
                bytes: binding.resource.shared_bytes(),
            }
        }));
        entries.extend(self.images.iter().map(|(binding_identity, binding)| {
            PortableResourceTransport::Image {
                binding_identity: binding_identity.clone(),
                logical_identity: binding.resource.logical_identity().to_string(),
                width: binding.resource.width(),
                height: binding.resource.height(),
                color_space: binding.resource.color_space(),
                digest: binding.resource.digest(),
                bytes: binding.resource.shared_bytes(),
            }
        }));
        entries.extend(self.plot_styles.iter().map(|(binding_identity, binding)| {
            PortableResourceTransport::PlotStyle {
                binding_identity: binding_identity.clone(),
                logical_identity: binding.resource.logical_identity().to_string(),
                source_format: binding.resource.source_format().to_string(),
                semantic_digest: binding.resource.semantic_digest(),
                digest: binding.resource.digest(),
                bytes: binding.resource.shared_bytes(),
            }
        }));
        entries.extend(self.xrefs.iter().map(|(binding_identity, binding)| {
            PortableResourceTransport::Xref {
                binding_identity: binding_identity.clone(),
                logical_identity: binding.resource.logical_identity().to_string(),
                format: binding.resource.snapshot().format(),
                digest: binding.resource.digest(),
                bytes: binding.resource.snapshot().bytes(),
            }
        }));
        entries
    }

    pub(crate) fn resolve_font(
        &self,
        drawing_identity: &str,
    ) -> Result<Option<(FontId, &FontResource, FontResolution)>, PortablePlotError> {
        let key = canonical_drawing_identity(drawing_identity)?;
        if let Some((matched, binding)) = self.fonts.get_key_value(&key) {
            let index = self
                .fonts
                .keys()
                .position(|candidate| candidate == matched)
                .expect("matched BTreeMap key must remain present");
            return Ok(Some((
                FontId::new(
                    u32::try_from(index + 1)
                        .expect("resource count is bounded below the u32 identifier space"),
                ),
                &binding.resource,
                FontResolution::Exact,
            )));
        }
        Ok(self.fallback_font.as_ref().map(|binding| {
            (
                FontId::new(
                    u32::try_from(self.fonts.len() + 1)
                        .expect("resource count is bounded below the u32 identifier space"),
                ),
                &binding.resource,
                FontResolution::Fallback,
            )
        }))
    }

    pub(crate) fn font_by_id(&self, id: FontId) -> Option<&FontResource> {
        let index = usize::try_from(id.get()).ok()?.checked_sub(1)?;
        if index < self.fonts.len() {
            self.fonts
                .values()
                .nth(index)
                .map(|binding| &binding.resource)
        } else if index == self.fonts.len() {
            self.fallback_font.as_ref().map(|binding| &binding.resource)
        } else {
            None
        }
    }

    pub(crate) fn resolve_shx_stroke_font(
        &self,
        drawing_identity: &str,
    ) -> Result<Option<(StrokeFontId, &ShxStrokeFontResource)>, PortablePlotError> {
        let key = canonical_drawing_identity(drawing_identity)?;
        Ok(self
            .stroke_fonts
            .get_key_value(&key)
            .map(|(matched, binding)| {
                let index = self
                    .stroke_fonts
                    .keys()
                    .position(|candidate| candidate == matched)
                    .expect("matched BTreeMap key must remain present");
                (
                    StrokeFontId::new(
                        u32::try_from(index + 1)
                            .expect("resource count is bounded below the u32 identifier space"),
                    ),
                    &binding.resource,
                )
            }))
    }

    pub(crate) fn shx_stroke_font_by_id(&self, id: StrokeFontId) -> Option<&ShxStrokeFontResource> {
        let index = usize::try_from(id.get()).ok()?.checked_sub(1)?;
        self.stroke_fonts
            .values()
            .nth(index)
            .map(|binding| &binding.resource)
    }

    pub(crate) fn resolve_shx_composite_font(
        &self,
        primary_drawing_identity: &str,
        big_drawing_identity: &str,
    ) -> Result<Option<(CompositeFontId, &ShxCompositeFontResource)>, PortablePlotError> {
        let key = CompositeFontKey {
            primary: canonical_drawing_identity(primary_drawing_identity)?,
            big: canonical_drawing_identity(big_drawing_identity)?,
        };
        Ok(self
            .composite_stroke_fonts
            .get_key_value(&key)
            .map(|(matched, binding)| {
                let index = self
                    .composite_stroke_fonts
                    .keys()
                    .position(|candidate| candidate == matched)
                    .expect("matched BTreeMap key must remain present");
                (
                    CompositeFontId::new(
                        u32::try_from(index + 1)
                            .expect("resource count is bounded below the u32 identifier space"),
                    ),
                    &binding.resource,
                )
            }))
    }

    pub(crate) fn shx_composite_font_by_id(
        &self,
        id: CompositeFontId,
    ) -> Option<&ShxCompositeFontResource> {
        let index = usize::try_from(id.get()).ok()?.checked_sub(1)?;
        self.composite_stroke_fonts
            .values()
            .nth(index)
            .map(|binding| &binding.resource)
    }

    pub(crate) fn resolve_xref(
        &self,
        drawing_identity: &str,
    ) -> Result<Option<&XrefResource>, PortablePlotError> {
        let key = canonical_drawing_identity(drawing_identity)?;
        Ok(self.xrefs.get(&key).map(|binding| &binding.resource))
    }

    pub(crate) fn resolve_plot_style(
        &self,
        drawing_identity: &str,
    ) -> Result<Option<&PlotStyleResource>, PortablePlotError> {
        let key = canonical_drawing_identity(drawing_identity)?;
        Ok(self.plot_styles.get(&key).map(|binding| &binding.resource))
    }

    pub(crate) fn total_bytes(&self) -> Result<usize, PortablePlotError> {
        let mut total = 0_usize;
        for binding in self.fonts.values() {
            total = total
                .checked_add(binding.resource.bytes().len())
                .ok_or_else(|| {
                    PortablePlotError::new(
                        "resource_bundle_budget_exceeded",
                        "resource byte accounting overflowed",
                    )
                })?;
        }
        if let Some(binding) = &self.fallback_font {
            total = total
                .checked_add(binding.resource.bytes().len())
                .ok_or_else(|| {
                    PortablePlotError::new(
                        "resource_bundle_budget_exceeded",
                        "resource byte accounting overflowed",
                    )
                })?;
        }
        for binding in self.stroke_fonts.values() {
            total = total
                .checked_add(binding.resource.bytes().len())
                .ok_or_else(|| {
                    PortablePlotError::new(
                        "resource_bundle_budget_exceeded",
                        "resource byte accounting overflowed",
                    )
                })?;
        }
        for binding in self.composite_stroke_fonts.values() {
            total = total
                .checked_add(binding.resource.bytes().len())
                .ok_or_else(|| {
                    PortablePlotError::new(
                        "resource_bundle_budget_exceeded",
                        "resource byte accounting overflowed",
                    )
                })?;
        }
        for binding in self.images.values() {
            total = total
                .checked_add(binding.resource.bytes().len())
                .ok_or_else(|| {
                    PortablePlotError::new(
                        "resource_bundle_budget_exceeded",
                        "resource byte accounting overflowed",
                    )
                })?;
        }
        for binding in self.plot_styles.values() {
            total = total
                .checked_add(binding.resource.bytes().len())
                .ok_or_else(|| {
                    PortablePlotError::new(
                        "resource_bundle_budget_exceeded",
                        "resource byte accounting overflowed",
                    )
                })?;
        }
        for binding in self.xrefs.values() {
            total = total
                .checked_add(binding.resource.snapshot.bytes().len())
                .ok_or_else(|| {
                    PortablePlotError::new(
                        "resource_bundle_budget_exceeded",
                        "resource byte accounting overflowed",
                    )
                })?;
        }
        Ok(total)
    }
}

fn canonical_drawing_identity(value: &str) -> Result<String, PortablePlotError> {
    validate_bundle_identity(value)?;
    let normalized = value.trim().replace('\\', "/");
    let basename = normalized
        .rsplit('/')
        .next()
        .filter(|component| !component.is_empty())
        .ok_or_else(|| {
            PortablePlotError::new(
                "resource_identity_invalid",
                "drawing resource identities must contain a bounded final component",
            )
        })?;
    Ok(basename.to_ascii_lowercase())
}

fn validate_bundle_identity(value: &str) -> Result<(), PortablePlotError> {
    if value.trim().is_empty()
        || value.len() > 512
        || value.contains(['\r', '\n', '\0'])
        || value.split(['/', '\\']).any(|component| component == "..")
    {
        return Err(PortablePlotError::new(
            "resource_identity_invalid",
            "drawing resource identities must be bounded logical references without traversal",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::DrawingFormat;
    use serde_json::{json, Map, Value};

    use super::*;

    #[test]
    fn bindings_are_case_and_separator_insensitive_without_host_io() {
        let bytes: Arc<[u8]> = Arc::from(&b"font"[..]);
        let resource = FontResource::new(
            "fonts/regular",
            bytes.clone(),
            0,
            ResourceDigest::of(&bytes),
        )
        .unwrap();
        let mut bundle = PortableResourceBundle::new();
        bundle
            .bind_font(r"C:\CAD\Fonts\Example.TTF", resource)
            .unwrap();
        let (id, matched, resolution) = bundle
            .resolve_font("/different/root/example.ttf")
            .unwrap()
            .unwrap();
        assert_eq!(id, FontId::new(1));
        assert_eq!(matched.logical_identity(), "fonts/regular");
        assert_eq!(resolution, FontResolution::Exact);
    }

    #[test]
    fn fallback_font_is_explicit_unique_and_ordered_after_exact_bindings() {
        let exact_bytes: Arc<[u8]> = Arc::from(&b"exact"[..]);
        let fallback_bytes: Arc<[u8]> = Arc::from(&b"fallback"[..]);
        let exact = FontResource::new(
            "fonts/exact",
            exact_bytes.clone(),
            0,
            ResourceDigest::of(&exact_bytes),
        )
        .unwrap();
        let fallback = || {
            FontResource::new(
                "fonts/fallback",
                fallback_bytes.clone(),
                0,
                ResourceDigest::of(&fallback_bytes),
            )
            .unwrap()
        };
        let mut bundle = PortableResourceBundle::new();
        bundle.bind_font("exact.ttf", exact).unwrap();
        bundle.bind_fallback_font(fallback()).unwrap();

        let (exact_id, _, exact_resolution) = bundle.resolve_font("EXACT.TTF").unwrap().unwrap();
        assert_eq!(exact_id, FontId::new(1));
        assert_eq!(exact_resolution, FontResolution::Exact);
        let (fallback_id, matched, fallback_resolution) =
            bundle.resolve_font("missing.ttf").unwrap().unwrap();
        assert_eq!(fallback_id, FontId::new(2));
        assert_eq!(matched.logical_identity(), "fonts/fallback");
        assert_eq!(fallback_resolution, FontResolution::Fallback);
        assert_eq!(bundle.font_by_id(fallback_id).unwrap().bytes(), b"fallback");
        assert_eq!(bundle.font_count(), 2);
        assert_eq!(
            bundle.total_bytes().unwrap(),
            exact_bytes.len() + fallback_bytes.len()
        );
        assert_eq!(
            bundle
                .bind_fallback_font(
                    FontResource::new(
                        "fonts/replacement",
                        Arc::<[u8]>::from(&b"replacement"[..]),
                        0,
                        ResourceDigest::of(b"replacement"),
                    )
                    .unwrap(),
                )
                .unwrap_err()
                .code(),
            "resource_identity_duplicate"
        );
        assert_eq!(bundle.font_by_id(fallback_id).unwrap().bytes(), b"fallback");
    }

    #[test]
    fn shx_stroke_font_binding_is_exact_deterministic_and_non_destructive() {
        let resource = |logical_identity: &str, advance: f64| {
            let bytes: Arc<[u8]> = Arc::from(
                serde_json::to_vec(&json!({
                    "schema": "portable_shx_v1",
                    "cap_height": 10.0,
                    "descent": 2.0,
                    "glyphs": {
                        "0041": {
                            "advance": advance,
                            "maximum_error": 0.0,
                            "commands": [
                                { "op": "move_to", "x": 0.0, "y": 0.0 },
                                { "op": "line_to", "x": 4.0, "y": 10.0 }
                            ]
                        }
                    }
                }))
                .unwrap(),
            );
            ShxStrokeFontResource::new(logical_identity, bytes.clone(), ResourceDigest::of(&bytes))
                .unwrap()
        };
        let original = resource("fonts/simplex-v1.json", 8.0);
        let original_bytes = original.bytes().len();
        let mut bundle = PortableResourceBundle::new();
        bundle
            .bind_shx_stroke_font(r"C:\CAD\Fonts\SIMPLEX.SHX", original)
            .unwrap();

        let (id, matched) = bundle
            .resolve_shx_stroke_font("/other/root/simplex.shx")
            .unwrap()
            .unwrap();
        assert_eq!(id, StrokeFontId::new(1));
        assert_eq!(matched.logical_identity(), "fonts/simplex-v1.json");
        assert_eq!(bundle.shx_stroke_font_count(), 1);
        assert_eq!(bundle.total_bytes().unwrap(), original_bytes);
        assert_eq!(
            bundle
                .bind_shx_stroke_font("simplex.shx", resource("fonts/replacement.json", 9.0))
                .unwrap_err()
                .code(),
            "resource_identity_duplicate"
        );
        assert_eq!(
            bundle.shx_stroke_font_by_id(id).unwrap().logical_identity(),
            "fonts/simplex-v1.json"
        );
    }

    #[test]
    fn shx_composite_pair_binding_is_exact_deterministic_and_non_destructive() {
        let resource = |logical_identity: &str, target: &str| {
            let bytes: Arc<[u8]> = Arc::from(
                serde_json::to_vec(&json!({
                    "schema": "portable_shx_composite_v1",
                    "glyphs": {
                        "4E00": { "font": "big", "glyph": target }
                    }
                }))
                .unwrap(),
            );
            ShxCompositeFontResource::new(
                logical_identity,
                bytes.clone(),
                ResourceDigest::of(&bytes),
            )
            .unwrap()
        };
        let original = resource("fonts/latin-cjk-v1.json", "4E00");
        let original_bytes = original.bytes().len();
        let mut bundle = PortableResourceBundle::new();
        bundle
            .bind_shx_composite_font(
                r"C:\CAD\Fonts\SIMPLEX.SHX",
                r"C:\CAD\Fonts\ASIAN.SHX",
                original,
            )
            .unwrap();

        let (id, matched) = bundle
            .resolve_shx_composite_font("/other/simplex.shx", "/other/asian.shx")
            .unwrap()
            .unwrap();
        assert_eq!(id, CompositeFontId::new(1));
        assert_eq!(matched.logical_identity(), "fonts/latin-cjk-v1.json");
        assert_eq!(bundle.shx_composite_font_count(), 1);
        assert_eq!(bundle.total_bytes().unwrap(), original_bytes);
        assert_eq!(
            bundle
                .bind_shx_composite_font(
                    "simplex.shx",
                    "ASIAN.SHX",
                    resource("fonts/replacement.json", "4E8C"),
                )
                .unwrap_err()
                .code(),
            "resource_identity_duplicate"
        );
        assert_eq!(
            bundle
                .shx_composite_font_by_id(id)
                .unwrap()
                .logical_identity(),
            "fonts/latin-cjk-v1.json"
        );
        assert_eq!(
            bundle
                .bind_shx_composite_font(
                    "same.shx",
                    "/other/SAME.SHX",
                    resource("fonts/same.json", "4E00"),
                )
                .unwrap_err()
                .code(),
            "stroke_font_composite_resource_invalid"
        );
    }

    #[test]
    fn canonical_collisions_and_parent_traversal_reject() {
        let bytes: Arc<[u8]> = Arc::from(&b"font"[..]);
        let make_resource = || {
            FontResource::new(
                "fonts/regular",
                bytes.clone(),
                0,
                ResourceDigest::of(&bytes),
            )
            .unwrap()
        };
        let mut bundle = PortableResourceBundle::new();
        bundle
            .bind_font("one/EXAMPLE.ttf", make_resource())
            .unwrap();
        assert_eq!(
            bundle
                .bind_font("two/example.TTF", make_resource())
                .unwrap_err()
                .code(),
            "resource_identity_duplicate"
        );
        assert_eq!(
            bundle
                .bind_font("../escape.ttf", make_resource())
                .unwrap_err()
                .code(),
            "resource_identity_invalid"
        );
    }

    #[test]
    fn xref_snapshot_digest_is_checked() {
        let bytes: Arc<[u8]> = Arc::from(&b"dwg"[..]);
        let snapshot = DrawingSnapshot::new(DrawingFormat::Dwg, bytes);
        assert_eq!(
            XrefResource::new("xref/one.dwg", snapshot, ResourceDigest::of(b"other"))
                .unwrap_err()
                .code(),
            "resource_digest_mismatch"
        );
    }

    fn normalized_ctb_bytes(mutator: impl FnOnce(&mut Map<String, Value>)) -> Arc<[u8]> {
        let mut styles = Map::new();
        for index in 1..=255 {
            styles.insert(
                index.to_string(),
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
                }),
            );
        }
        mutator(&mut styles);
        serde_json::to_vec(&json!({
            "schema": "portable_ctb_v1",
            "styles": styles
        }))
        .unwrap()
        .into()
    }

    #[test]
    fn normalized_ctb_is_digest_bound_complete_and_bundle_resolvable() {
        let bytes = normalized_ctb_bytes(|styles| {
            styles.insert(
                "7".to_string(),
                json!({
                    "color": {"red": 0, "green": 0, "blue": 0},
                    "grayscale": false,
                    "screening_percent": 50,
                    "lineweight_mm": 0.35,
                    "line_cap": "round",
                    "line_join": "bevel",
                    "linetype": "use_object",
                    "fill_style": "use_object",
                    "dither": false
                }),
            );
        });
        let digest = ResourceDigest::of(&bytes);
        let resource = PlotStyleResource::new("styles/mono", bytes, digest).unwrap();
        assert_eq!(resource.source_format(), "portable_ctb_v1");
        let rule = resource.style(7).unwrap();
        assert_eq!(rule.color, Some(SceneColor::BLACK));
        assert_eq!(rule.screening_percent, 50);
        assert_eq!(rule.line_cap, Some(LineCap::Round));
        assert_eq!(rule.line_join, Some(LineJoin::Bevel));
        assert!((rule.lineweight_points.unwrap() - 0.35 * 72.0 / 25.4).abs() < 1.0e-12);

        let mut bundle = PortableResourceBundle::new();
        bundle.bind_plot_style("MONO.CTB", resource).unwrap();
        assert_eq!(
            bundle
                .resolve_plot_style("plotters/mono.ctb")
                .unwrap()
                .unwrap()
                .digest(),
            digest
        );
    }

    #[test]
    fn normalized_ctb_rejects_incomplete_or_unimplemented_semantics() {
        let incomplete = normalized_ctb_bytes(|styles| {
            styles.remove("255");
        });
        assert_eq!(
            PlotStyleResource::new(
                "incomplete",
                incomplete.clone(),
                ResourceDigest::of(&incomplete)
            )
            .unwrap_err()
            .code(),
            "plot_style_resource_invalid"
        );

        let dithered = normalized_ctb_bytes(|styles| {
            styles["1"]["dither"] = json!(true);
        });
        assert_eq!(
            PlotStyleResource::new("dithered", dithered.clone(), ResourceDigest::of(&dithered))
                .unwrap_err()
                .code(),
            "plot_style_semantics_unsupported"
        );

        let complete = normalized_ctb_bytes(|_| {});
        let parsed: Value = serde_json::from_slice(&complete).unwrap();
        let duplicate_rule = serde_json::to_string(&parsed["styles"]["1"]).unwrap();
        let mut duplicate = String::from_utf8(complete.to_vec()).unwrap();
        let insertion = duplicate.find("\"styles\":{").unwrap() + "\"styles\":{".len();
        duplicate.insert_str(insertion, &format!("\"1\":{duplicate_rule},"));
        let duplicate: Arc<[u8]> = duplicate.into_bytes().into();
        assert_eq!(
            PlotStyleResource::new(
                "duplicate",
                duplicate.clone(),
                ResourceDigest::of(&duplicate)
            )
            .unwrap_err()
            .code(),
            "plot_style_resource_invalid"
        );

        let overflowing_lineweight = normalized_ctb_bytes(|styles| {
            styles["1"]["lineweight_mm"] = json!(1.0e308);
        });
        assert_eq!(
            PlotStyleResource::new(
                "overflowing-lineweight",
                overflowing_lineweight.clone(),
                ResourceDigest::of(&overflowing_lineweight)
            )
            .unwrap_err()
            .code(),
            "plot_style_semantics_unsupported"
        );
    }
}
