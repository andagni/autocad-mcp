use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;
use std::sync::Arc;

use sha2::{Digest, Sha256};

use super::{Affine2, Point2, PortablePlotError, SourceHandle};

pub const PDF_1_4_MAX_PAGE_POINTS: f64 = 14_400.0;

/// Explicit resource and expansion limits recorded with every plot receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisplayListLimits {
    pub max_output_bytes: usize,
    pub max_nodes: usize,
    pub max_expanded_nodes: usize,
    pub max_path_commands: usize,
    pub max_expanded_path_commands: usize,
    pub max_glyphs: usize,
    pub max_expanded_glyphs: usize,
    pub max_text_bytes: usize,
    pub max_font_bytes: usize,
    pub max_groups: usize,
    pub max_group_depth: usize,
    pub max_graphics_state_depth: usize,
    pub max_images: usize,
    pub max_image_bytes: usize,
    pub max_image_pixels: usize,
}

impl Default for DisplayListLimits {
    fn default() -> Self {
        Self {
            max_output_bytes: 64 * 1024 * 1024,
            max_nodes: 250_000,
            max_expanded_nodes: 1_000_000,
            max_path_commands: 2_000_000,
            max_expanded_path_commands: 8_000_000,
            max_glyphs: 1_000_000,
            max_expanded_glyphs: 4_000_000,
            max_text_bytes: 16 * 1024 * 1024,
            max_font_bytes: 64 * 1024 * 1024,
            max_groups: 100_000,
            max_group_depth: 64,
            max_graphics_state_depth: 128,
            max_images: 1_024,
            max_image_bytes: 256 * 1024 * 1024,
            max_image_pixels: 200_000_000,
        }
    }
}

/// Validated page dimensions in PDF points.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PageGeometry {
    width: f64,
    height: f64,
}

impl PageGeometry {
    pub fn new(width: f64, height: f64) -> Result<Self, PortablePlotError> {
        if !finite_positive(width)
            || !finite_positive(height)
            || width > PDF_1_4_MAX_PAGE_POINTS
            || height > PDF_1_4_MAX_PAGE_POINTS
        {
            return Err(PortablePlotError::new(
                "page_geometry_invalid",
                "page dimensions must be finite positive PDF points no larger than 14,400",
            ));
        }
        Ok(Self { width, height })
    }

    pub fn width(self) -> f64 {
        self.width
    }

    pub fn height(self) -> f64 {
        self.height
    }
}

/// Immutable SHA-256 binding for a binary plot resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResourceDigest([u8; 32]);

impl ResourceDigest {
    pub fn of(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    pub fn from_hex(value: &str) -> Result<Self, PortablePlotError> {
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(PortablePlotError::new(
                "resource_digest_invalid",
                "resource SHA-256 digests must contain exactly 64 hexadecimal digits",
            ));
        }
        let mut bytes = [0_u8; 32];
        for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
            let digits = std::str::from_utf8(chunk).map_err(|_| {
                PortablePlotError::new(
                    "resource_digest_invalid",
                    "resource SHA-256 digests must contain exactly 64 hexadecimal digits",
                )
            })?;
            bytes[index] = u8::from_str_radix(digits, 16).map_err(|_| {
                PortablePlotError::new(
                    "resource_digest_invalid",
                    "resource SHA-256 digests must contain exactly 64 hexadecimal digits",
                )
            })?;
        }
        Ok(Self(bytes))
    }

    pub fn bytes(self) -> [u8; 32] {
        self.0
    }

    pub fn to_hex(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(64);
        for byte in self.0 {
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        output
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FontId(u32);

impl FontId {
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ImageId(u32);

impl ImageId {
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GroupId(u32);

impl GroupId {
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Debug, Clone)]
pub struct FontResource {
    logical_identity: String,
    bytes: Arc<[u8]>,
    face_index: u32,
    digest: ResourceDigest,
}

impl FontResource {
    pub fn new(
        logical_identity: impl Into<String>,
        bytes: impl Into<Arc<[u8]>>,
        face_index: u32,
        expected_digest: ResourceDigest,
    ) -> Result<Self, PortablePlotError> {
        let logical_identity = logical_identity.into();
        let bytes = bytes.into();
        validate_resource_identity(&logical_identity)?;
        if bytes.is_empty() {
            return Err(PortablePlotError::new(
                "font_resource_empty",
                "font resources must contain at least one byte",
            ));
        }
        if ResourceDigest::of(&bytes) != expected_digest {
            return Err(PortablePlotError::new(
                "resource_digest_mismatch",
                "font bytes do not match their immutable SHA-256 binding",
            ));
        }
        Ok(Self {
            logical_identity,
            bytes,
            face_index,
            digest: expected_digest,
        })
    }

    pub fn logical_identity(&self) -> &str {
        &self.logical_identity
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn shared_bytes(&self) -> Arc<[u8]> {
        Arc::clone(&self.bytes)
    }

    pub fn face_index(&self) -> u32 {
        self.face_index
    }

    pub fn digest(&self) -> ResourceDigest {
        self.digest
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageColorSpace {
    Gray8,
    Rgb8,
    Rgba8,
}

impl ImageColorSpace {
    fn components(self) -> usize {
        match self {
            Self::Gray8 => 1,
            Self::Rgb8 => 3,
            Self::Rgba8 => 4,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ImageResource {
    logical_identity: String,
    width: u32,
    height: u32,
    color_space: ImageColorSpace,
    bytes: Arc<[u8]>,
    digest: ResourceDigest,
}

impl ImageResource {
    pub fn new(
        logical_identity: impl Into<String>,
        width: u32,
        height: u32,
        color_space: ImageColorSpace,
        bytes: impl Into<Arc<[u8]>>,
        expected_digest: ResourceDigest,
    ) -> Result<Self, PortablePlotError> {
        let logical_identity = logical_identity.into();
        let bytes = bytes.into();
        validate_resource_identity(&logical_identity)?;
        let expected_len = usize::try_from(width)
            .ok()
            .and_then(|width| {
                usize::try_from(height)
                    .ok()
                    .and_then(|height| width.checked_mul(height))
            })
            .and_then(|pixels| pixels.checked_mul(color_space.components()))
            .ok_or_else(|| {
                PortablePlotError::new(
                    "image_geometry_invalid",
                    "image dimensions overflow the addressable pixel buffer",
                )
            })?;
        if width == 0 || height == 0 || bytes.len() != expected_len {
            return Err(PortablePlotError::new(
                "image_geometry_invalid",
                "image dimensions, colour space, and decoded byte count must agree",
            ));
        }
        if ResourceDigest::of(&bytes) != expected_digest {
            return Err(PortablePlotError::new(
                "resource_digest_mismatch",
                "image bytes do not match their immutable SHA-256 binding",
            ));
        }
        Ok(Self {
            logical_identity,
            width,
            height,
            color_space,
            bytes,
            digest: expected_digest,
        })
    }

    pub fn logical_identity(&self) -> &str {
        &self.logical_identity
    }

    pub fn width(&self) -> u32 {
        self.width
    }

    pub fn height(&self) -> u32 {
        self.height
    }

    pub fn color_space(&self) -> ImageColorSpace {
        self.color_space
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn shared_bytes(&self) -> Arc<[u8]> {
        Arc::clone(&self.bytes)
    }

    pub fn digest(&self) -> ResourceDigest {
        self.digest
    }
}

fn validate_resource_identity(value: &str) -> Result<(), PortablePlotError> {
    if value.is_empty()
        || value.len() > 256
        || value.contains(['\r', '\n'])
        || value.starts_with('/')
        || value.contains('\\')
        || value.split('/').any(|component| component == "..")
    {
        return Err(PortablePlotError::new(
            "resource_identity_invalid",
            "resource identities must be bounded logical names, not host paths",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SceneColor {
    red: u8,
    green: u8,
    blue: u8,
    alpha: u8,
}

impl SceneColor {
    pub const BLACK: Self = Self::rgb(0, 0, 0);
    pub const WHITE: Self = Self::rgb(255, 255, 255);

    pub const fn rgb(red: u8, green: u8, blue: u8) -> Self {
        Self {
            red,
            green,
            blue,
            alpha: 255,
        }
    }

    pub const fn rgba(red: u8, green: u8, blue: u8, alpha: u8) -> Self {
        Self {
            red,
            green,
            blue,
            alpha,
        }
    }

    pub const fn red(self) -> u8 {
        self.red
    }

    pub const fn green(self) -> u8 {
        self.green
    }

    pub const fn blue(self) -> u8 {
        self.blue
    }

    pub const fn alpha(self) -> u8 {
        self.alpha
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FillRule {
    NonZero,
    EvenOdd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fill {
    color: SceneColor,
    rule: FillRule,
}

impl Fill {
    pub const fn new(color: SceneColor, rule: FillRule) -> Self {
        Self { color, rule }
    }

    pub const fn color(self) -> SceneColor {
        self.color
    }

    pub const fn rule(self) -> FillRule {
        self.rule
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineCap {
    Butt,
    Round,
    Square,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineJoin {
    Miter,
    Round,
    Bevel,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DashPattern {
    elements: Vec<f64>,
    offset: f64,
}

impl DashPattern {
    pub fn new(elements: Vec<f64>, offset: f64) -> Result<Self, PortablePlotError> {
        if !offset.is_finite()
            || elements
                .iter()
                .any(|element| !element.is_finite() || *element < 0.0)
        {
            return Err(PortablePlotError::new(
                "dash_pattern_invalid",
                "dash lengths must be finite and non-negative and the offset must be finite",
            ));
        }
        if !elements.is_empty() {
            let cycle = elements.iter().try_fold(0.0_f64, |sum, element| {
                let next = sum + *element;
                next.is_finite().then_some(next)
            });
            if cycle.is_none_or(|cycle| cycle <= 0.0) {
                return Err(PortablePlotError::new(
                    "dash_pattern_invalid",
                    "a non-empty dash pattern must have finite positive total advance",
                ));
            }
        }
        Ok(Self { elements, offset })
    }

    pub fn elements(&self) -> &[f64] {
        &self.elements
    }

    pub fn offset(&self) -> f64 {
        self.offset
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Stroke {
    color: SceneColor,
    width: f64,
    miter_limit: f64,
    cap: LineCap,
    join: LineJoin,
    dash: Option<DashPattern>,
}

impl Stroke {
    pub fn new(
        color: SceneColor,
        width: f64,
        miter_limit: f64,
        cap: LineCap,
        join: LineJoin,
        dash: Option<DashPattern>,
    ) -> Result<Self, PortablePlotError> {
        if !width.is_finite() || width < 0.0 || !finite_positive(miter_limit) {
            return Err(PortablePlotError::new(
                "stroke_invalid",
                "stroke width must be finite and nonnegative and the miter limit must be finite and positive",
            ));
        }
        Ok(Self {
            color,
            width,
            miter_limit,
            cap,
            join,
            dash,
        })
    }

    pub fn color(&self) -> SceneColor {
        self.color
    }

    pub fn width(&self) -> f64 {
        self.width
    }

    pub fn miter_limit(&self) -> f64 {
        self.miter_limit
    }

    pub fn cap(&self) -> LineCap {
        self.cap
    }

    pub fn join(&self) -> LineJoin {
        self.join
    }

    pub fn dash(&self) -> Option<&DashPattern> {
        self.dash.as_ref()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum PathCommand {
    MoveTo(Point2),
    LineTo(Point2),
    QuadTo {
        control: Point2,
        end: Point2,
    },
    CubicTo {
        control_1: Point2,
        control_2: Point2,
        end: Point2,
    },
    Close,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScenePath {
    commands: Vec<PathCommand>,
}

impl ScenePath {
    pub fn new(commands: Vec<PathCommand>) -> Result<Self, PortablePlotError> {
        validate_path_topology(&commands)?;
        Ok(Self { commands })
    }

    pub fn polyline(
        points: impl IntoIterator<Item = Point2>,
        closed: bool,
    ) -> Result<Self, PortablePlotError> {
        let mut points = points.into_iter();
        let first = points.next().ok_or_else(|| {
            PortablePlotError::new("path_invalid", "paths must contain at least one point")
        })?;
        let mut commands = vec![PathCommand::MoveTo(first)];
        commands.extend(points.map(PathCommand::LineTo));
        if closed {
            commands.push(PathCommand::Close);
        }
        Self::new(commands)
    }

    pub fn rectangle(
        left: f64,
        top: f64,
        right: f64,
        bottom: f64,
    ) -> Result<Self, PortablePlotError> {
        if ![left, top, right, bottom].into_iter().all(f64::is_finite)
            || right <= left
            || bottom <= top
        {
            return Err(PortablePlotError::new(
                "path_invalid",
                "rectangle bounds must be finite and ordered",
            ));
        }
        Self::new(vec![
            PathCommand::MoveTo(Point2::new(left, top)?),
            PathCommand::LineTo(Point2::new(right, top)?),
            PathCommand::LineTo(Point2::new(right, bottom)?),
            PathCommand::LineTo(Point2::new(left, bottom)?),
            PathCommand::Close,
        ])
    }

    pub fn commands(&self) -> &[PathCommand] {
        &self.commands
    }
}

fn validate_path_topology(commands: &[PathCommand]) -> Result<(), PortablePlotError> {
    if commands.is_empty() || !matches!(commands.first(), Some(PathCommand::MoveTo(_))) {
        return Err(PortablePlotError::new(
            "path_invalid",
            "paths must be non-empty and begin with MoveTo",
        ));
    }
    let mut active_subpath = false;
    for command in commands {
        match command {
            PathCommand::MoveTo(_) => active_subpath = true,
            PathCommand::LineTo(_) | PathCommand::QuadTo { .. } | PathCommand::CubicTo { .. }
                if !active_subpath =>
            {
                return Err(PortablePlotError::new(
                    "path_invalid",
                    "drawing commands require an active subpath",
                ));
            }
            PathCommand::Close if !active_subpath => {
                return Err(PortablePlotError::new(
                    "path_invalid",
                    "Close requires an active subpath",
                ));
            }
            PathCommand::Close => active_subpath = false,
            _ => {}
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct ClipPath {
    path: ScenePath,
    rule: FillRule,
}

impl ClipPath {
    pub const fn new(path: ScenePath, rule: FillRule) -> Self {
        Self { path, rule }
    }

    pub fn path(&self) -> &ScenePath {
        &self.path
    }

    pub fn rule(&self) -> FillRule {
        self.rule
    }
}

#[derive(Debug, Clone)]
pub struct PathNode {
    path: ScenePath,
    fill: Option<Fill>,
    stroke: Option<Stroke>,
    source_handle: Option<SourceHandle>,
}

impl PathNode {
    pub fn new(
        path: ScenePath,
        fill: Option<Fill>,
        stroke: Option<Stroke>,
        source_handle: Option<SourceHandle>,
    ) -> Result<Self, PortablePlotError> {
        if fill.is_none() && stroke.is_none() {
            return Err(PortablePlotError::new(
                "display_list_structure_invalid",
                "path nodes must select at least one fill or stroke",
            ));
        }
        Ok(Self {
            path,
            fill,
            stroke,
            source_handle,
        })
    }

    pub fn path(&self) -> &ScenePath {
        &self.path
    }

    pub fn fill(&self) -> Option<Fill> {
        self.fill
    }

    pub fn stroke(&self) -> Option<&Stroke> {
        self.stroke.as_ref()
    }

    pub fn source_handle(&self) -> Option<&SourceHandle> {
        self.source_handle.as_ref()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PositionedGlyph {
    glyph_id: u32,
    x_advance: f64,
    y_advance: f64,
    x_offset: f64,
    y_offset: f64,
    text_range: Range<usize>,
}

impl PositionedGlyph {
    pub fn new(
        glyph_id: u32,
        x_advance: f64,
        y_advance: f64,
        x_offset: f64,
        y_offset: f64,
        text_range: Range<usize>,
    ) -> Result<Self, PortablePlotError> {
        if glyph_id > u32::from(u16::MAX)
            || ![x_advance, y_advance, x_offset, y_offset]
                .into_iter()
                .all(f64::is_finite)
        {
            return Err(PortablePlotError::new(
                "glyph_invalid",
                "glyph IDs must fit the PDF CID range and metrics must be finite",
            ));
        }
        Ok(Self {
            glyph_id,
            x_advance,
            y_advance,
            x_offset,
            y_offset,
            text_range,
        })
    }

    pub fn glyph_id(&self) -> u32 {
        self.glyph_id
    }

    pub fn x_advance(&self) -> f64 {
        self.x_advance
    }

    pub fn y_advance(&self) -> f64 {
        self.y_advance
    }

    pub fn x_offset(&self) -> f64 {
        self.x_offset
    }

    pub fn y_offset(&self) -> f64 {
        self.y_offset
    }

    pub fn text_range(&self) -> Range<usize> {
        self.text_range.clone()
    }
}

#[derive(Debug, Clone)]
pub struct GlyphRun {
    font: FontId,
    font_size: f64,
    origin: Point2,
    transform: Affine2,
    text: String,
    glyphs: Vec<PositionedGlyph>,
    fill: Fill,
    source_handle: Option<SourceHandle>,
}

impl GlyphRun {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        font: FontId,
        font_size: f64,
        origin: Point2,
        transform: Affine2,
        text: String,
        glyphs: Vec<PositionedGlyph>,
        fill: Fill,
        source_handle: Option<SourceHandle>,
    ) -> Result<Self, PortablePlotError> {
        if !finite_positive(font_size) || font_size > PDF_1_4_MAX_PAGE_POINTS {
            return Err(PortablePlotError::new(
                "glyph_run_invalid",
                "glyph-run font size must be finite, positive, and PDF bounded",
            ));
        }
        for glyph in &glyphs {
            let range = glyph.text_range();
            if range.start > range.end
                || range.end > text.len()
                || !text.is_char_boundary(range.start)
                || !text.is_char_boundary(range.end)
            {
                return Err(PortablePlotError::new(
                    "glyph_run_invalid",
                    "glyph text ranges must identify UTF-8 boundaries in the source run",
                ));
            }
        }
        Ok(Self {
            font,
            font_size,
            origin,
            transform,
            text,
            glyphs,
            fill,
            source_handle,
        })
    }

    pub fn font(&self) -> FontId {
        self.font
    }

    pub fn font_size(&self) -> f64 {
        self.font_size
    }

    pub fn origin(&self) -> Point2 {
        self.origin
    }

    pub fn transform(&self) -> Affine2 {
        self.transform
    }

    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn glyphs(&self) -> &[PositionedGlyph] {
        &self.glyphs
    }

    pub fn fill(&self) -> Fill {
        self.fill
    }

    pub fn source_handle(&self) -> Option<&SourceHandle> {
        self.source_handle.as_ref()
    }
}

#[derive(Debug, Clone)]
pub struct ImageNode {
    image: ImageId,
    transform: Affine2,
    opacity: u8,
    source_handle: Option<SourceHandle>,
}

impl ImageNode {
    pub const fn new(
        image: ImageId,
        transform: Affine2,
        opacity: u8,
        source_handle: Option<SourceHandle>,
    ) -> Self {
        Self {
            image,
            transform,
            opacity,
            source_handle,
        }
    }

    pub fn image(&self) -> ImageId {
        self.image
    }

    pub fn transform(&self) -> Affine2 {
        self.transform
    }

    pub fn opacity(&self) -> u8 {
        self.opacity
    }

    pub fn source_handle(&self) -> Option<&SourceHandle> {
        self.source_handle.as_ref()
    }
}

#[derive(Debug, Clone)]
pub struct InlineGroup {
    transform: Affine2,
    clip: Option<ClipPath>,
    opacity: u8,
    nodes: Vec<DisplayNode>,
}

impl InlineGroup {
    pub const fn new(
        transform: Affine2,
        clip: Option<ClipPath>,
        opacity: u8,
        nodes: Vec<DisplayNode>,
    ) -> Self {
        Self {
            transform,
            clip,
            opacity,
            nodes,
        }
    }

    pub fn transform(&self) -> Affine2 {
        self.transform
    }

    pub fn clip(&self) -> Option<&ClipPath> {
        self.clip.as_ref()
    }

    pub fn opacity(&self) -> u8 {
        self.opacity
    }

    pub fn nodes(&self) -> &[DisplayNode] {
        &self.nodes
    }
}

#[derive(Debug, Clone)]
pub struct GroupInstance {
    group: GroupId,
    transform: Affine2,
    opacity: u8,
    source_handle: Option<SourceHandle>,
}

impl GroupInstance {
    pub const fn new(
        group: GroupId,
        transform: Affine2,
        opacity: u8,
        source_handle: Option<SourceHandle>,
    ) -> Self {
        Self {
            group,
            transform,
            opacity,
            source_handle,
        }
    }

    pub fn group(&self) -> GroupId {
        self.group
    }

    pub fn transform(&self) -> Affine2 {
        self.transform
    }

    pub fn opacity(&self) -> u8 {
        self.opacity
    }

    pub fn source_handle(&self) -> Option<&SourceHandle> {
        self.source_handle.as_ref()
    }
}

#[derive(Debug, Clone)]
pub enum DisplayNode {
    Path(PathNode),
    GlyphRun(GlyphRun),
    Image(ImageNode),
    InlineGroup(InlineGroup),
    GroupInstance(GroupInstance),
}

#[derive(Debug, Clone)]
pub struct ReusableGroup {
    nodes: Vec<DisplayNode>,
}

impl ReusableGroup {
    pub const fn new(nodes: Vec<DisplayNode>) -> Self {
        Self { nodes }
    }

    pub fn nodes(&self) -> &[DisplayNode] {
        &self.nodes
    }
}

/// Backend-neutral bounded display list with top-left, positive-y-down page space.
#[derive(Debug, Clone)]
pub struct DisplayList {
    page: PageGeometry,
    fonts: BTreeMap<FontId, FontResource>,
    images: BTreeMap<ImageId, ImageResource>,
    groups: BTreeMap<GroupId, ReusableGroup>,
    nodes: Vec<DisplayNode>,
}

impl DisplayList {
    pub fn new(page: PageGeometry) -> Self {
        Self {
            page,
            fonts: BTreeMap::new(),
            images: BTreeMap::new(),
            groups: BTreeMap::new(),
            nodes: Vec::new(),
        }
    }

    pub fn page(&self) -> PageGeometry {
        self.page
    }

    pub fn fonts(&self) -> &BTreeMap<FontId, FontResource> {
        &self.fonts
    }

    pub fn images(&self) -> &BTreeMap<ImageId, ImageResource> {
        &self.images
    }

    pub fn groups(&self) -> &BTreeMap<GroupId, ReusableGroup> {
        &self.groups
    }

    pub fn nodes(&self) -> &[DisplayNode] {
        &self.nodes
    }

    pub fn insert_font(
        &mut self,
        id: FontId,
        resource: FontResource,
    ) -> Result<(), PortablePlotError> {
        if self.fonts.insert(id, resource).is_some() {
            return Err(PortablePlotError::new(
                "display_list_structure_invalid",
                "font identifiers must be unique",
            ));
        }
        Ok(())
    }

    pub fn insert_image(
        &mut self,
        id: ImageId,
        resource: ImageResource,
    ) -> Result<(), PortablePlotError> {
        if self.images.insert(id, resource).is_some() {
            return Err(PortablePlotError::new(
                "display_list_structure_invalid",
                "image identifiers must be unique",
            ));
        }
        Ok(())
    }

    pub fn insert_group(
        &mut self,
        id: GroupId,
        group: ReusableGroup,
    ) -> Result<(), PortablePlotError> {
        if self.groups.insert(id, group).is_some() {
            return Err(PortablePlotError::new(
                "display_list_structure_invalid",
                "reusable group identifiers must be unique",
            ));
        }
        Ok(())
    }

    pub fn push(&mut self, node: DisplayNode) {
        self.nodes.push(node);
    }

    pub fn validate(
        &self,
        limits: DisplayListLimits,
    ) -> Result<DisplayListUsage, PortablePlotError> {
        validate_limits(limits)?;
        if self.groups.len() > limits.max_groups {
            return Err(budget_error("reusable_groups", limits.max_groups));
        }
        if self.images.len() > limits.max_images {
            return Err(budget_error("images", limits.max_images));
        }

        let mut usage = DisplayListUsage {
            groups: self.groups.len(),
            images: self.images.len(),
            ..DisplayListUsage::default()
        };
        for resource in self.fonts.values() {
            usage.font_bytes = checked_add(
                usage.font_bytes,
                resource.bytes().len(),
                "font_bytes",
                limits.max_font_bytes,
            )?;
        }
        for resource in self.images.values() {
            usage.image_bytes = checked_add(
                usage.image_bytes,
                resource.bytes().len(),
                "image_bytes",
                limits.max_image_bytes,
            )?;
            let pixels = usize::try_from(resource.width())
                .ok()
                .and_then(|width| {
                    usize::try_from(resource.height())
                        .ok()
                        .and_then(|height| width.checked_mul(height))
                })
                .ok_or_else(|| budget_error("image_pixels", limits.max_image_pixels))?;
            usage.image_pixels = checked_add(
                usage.image_pixels,
                pixels,
                "image_pixels",
                limits.max_image_pixels,
            )?;
        }

        validate_definitions(self, &mut usage, limits)?;
        validate_group_graph(self, limits)?;
        validate_expansion(self, &mut usage, limits)?;
        Ok(usage)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DisplayListUsage {
    pub nodes: usize,
    pub expanded_nodes: usize,
    pub path_commands: usize,
    pub expanded_path_commands: usize,
    pub glyphs: usize,
    pub expanded_glyphs: usize,
    pub text_bytes: usize,
    pub font_bytes: usize,
    pub groups: usize,
    pub images: usize,
    pub expanded_images: usize,
    pub image_bytes: usize,
    pub image_pixels: usize,
    pub maximum_group_depth: usize,
    pub maximum_graphics_state_depth: usize,
}

fn validate_limits(limits: DisplayListLimits) -> Result<(), PortablePlotError> {
    let values = [
        limits.max_output_bytes,
        limits.max_nodes,
        limits.max_expanded_nodes,
        limits.max_path_commands,
        limits.max_expanded_path_commands,
        limits.max_glyphs,
        limits.max_expanded_glyphs,
        limits.max_text_bytes,
        limits.max_font_bytes,
        limits.max_groups,
        limits.max_group_depth,
        limits.max_graphics_state_depth,
        limits.max_images,
        limits.max_image_bytes,
        limits.max_image_pixels,
    ];
    if values.contains(&0) {
        return Err(PortablePlotError::new(
            "display_list_limits_invalid",
            "all display-list limits must be positive",
        ));
    }
    Ok(())
}

fn validate_definitions(
    scene: &DisplayList,
    usage: &mut DisplayListUsage,
    limits: DisplayListLimits,
) -> Result<(), PortablePlotError> {
    let mut pending = vec![(scene.nodes(), 0_usize)];
    pending.extend(scene.groups().values().map(|group| (group.nodes(), 0)));
    while let Some((nodes, depth)) = pending.pop() {
        if depth > limits.max_graphics_state_depth {
            return Err(budget_error(
                "graphics_state_depth",
                limits.max_graphics_state_depth,
            ));
        }
        usage.maximum_graphics_state_depth = usage.maximum_graphics_state_depth.max(depth);
        for node in nodes {
            usage.nodes = checked_add(usage.nodes, 1, "nodes", limits.max_nodes)?;
            match node {
                DisplayNode::Path(node) => {
                    usage.path_commands = checked_add(
                        usage.path_commands,
                        node.path().commands().len(),
                        "path_commands",
                        limits.max_path_commands,
                    )?;
                }
                DisplayNode::GlyphRun(run) => {
                    if !scene.fonts().contains_key(&run.font()) {
                        return Err(structure_error(
                            "glyph runs must reference a defined font resource",
                        ));
                    }
                    usage.glyphs = checked_add(
                        usage.glyphs,
                        run.glyphs().len(),
                        "glyphs",
                        limits.max_glyphs,
                    )?;
                    usage.text_bytes = checked_add(
                        usage.text_bytes,
                        run.text().len(),
                        "text_bytes",
                        limits.max_text_bytes,
                    )?;
                }
                DisplayNode::Image(node) => {
                    if !scene.images().contains_key(&node.image()) {
                        return Err(structure_error(
                            "image nodes must reference a defined image resource",
                        ));
                    }
                }
                DisplayNode::InlineGroup(group) => {
                    if let Some(clip) = group.clip() {
                        usage.path_commands = checked_add(
                            usage.path_commands,
                            clip.path().commands().len(),
                            "path_commands",
                            limits.max_path_commands,
                        )?;
                    }
                    pending.push((group.nodes(), depth + 1));
                }
                DisplayNode::GroupInstance(instance) => {
                    if !scene.groups().contains_key(&instance.group()) {
                        return Err(structure_error(
                            "group instances must reference a defined reusable group",
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

fn validate_group_graph(
    scene: &DisplayList,
    limits: DisplayListLimits,
) -> Result<(), PortablePlotError> {
    let mut dependencies = BTreeMap::<GroupId, BTreeSet<GroupId>>::new();
    for (group_id, group) in scene.groups() {
        let mut group_dependencies = BTreeSet::new();
        let mut pending = vec![group.nodes()];
        while let Some(nodes) = pending.pop() {
            for node in nodes {
                match node {
                    DisplayNode::InlineGroup(group) => pending.push(group.nodes()),
                    DisplayNode::GroupInstance(instance) => {
                        group_dependencies.insert(instance.group());
                    }
                    DisplayNode::Path(_) | DisplayNode::GlyphRun(_) | DisplayNode::Image(_) => {}
                }
            }
        }
        dependencies.insert(*group_id, group_dependencies);
    }

    let mut complete = BTreeSet::new();
    for root in scene.groups().keys().copied() {
        if complete.contains(&root) {
            continue;
        }
        let mut active = BTreeSet::new();
        let mut stack = vec![(root, false, 1_usize)];
        while let Some((group, exiting, depth)) = stack.pop() {
            if exiting {
                active.remove(&group);
                complete.insert(group);
                continue;
            }
            if complete.contains(&group) {
                continue;
            }
            if depth > limits.max_group_depth {
                return Err(budget_error("group_depth", limits.max_group_depth));
            }
            if !active.insert(group) {
                return Err(structure_error(
                    "reusable group references must form an acyclic graph",
                ));
            }
            stack.push((group, true, depth));
            let group_dependencies = dependencies
                .get(&group)
                .ok_or_else(|| structure_error("group graph contains an unknown reusable group"))?;
            for dependency in group_dependencies.iter().rev().copied() {
                if active.contains(&dependency) {
                    return Err(structure_error(
                        "reusable group references must form an acyclic graph",
                    ));
                }
                stack.push((dependency, false, depth + 1));
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct ExpansionFrame<'a> {
    node: &'a DisplayNode,
    transform: Affine2,
    group_depth: usize,
    graphics_depth: usize,
}

fn validate_expansion(
    scene: &DisplayList,
    usage: &mut DisplayListUsage,
    limits: DisplayListLimits,
) -> Result<(), PortablePlotError> {
    let mut pending = scene
        .nodes()
        .iter()
        .rev()
        .map(|node| ExpansionFrame {
            node,
            transform: Affine2::identity(),
            group_depth: 0,
            graphics_depth: 0,
        })
        .collect::<Vec<_>>();
    while let Some(frame) = pending.pop() {
        if frame.group_depth > limits.max_group_depth {
            return Err(budget_error("group_depth", limits.max_group_depth));
        }
        if frame.graphics_depth > limits.max_graphics_state_depth {
            return Err(budget_error(
                "graphics_state_depth",
                limits.max_graphics_state_depth,
            ));
        }
        usage.maximum_group_depth = usage.maximum_group_depth.max(frame.group_depth);
        usage.maximum_graphics_state_depth =
            usage.maximum_graphics_state_depth.max(frame.graphics_depth);
        usage.expanded_nodes = checked_add(
            usage.expanded_nodes,
            1,
            "expanded_nodes",
            limits.max_expanded_nodes,
        )?;

        match frame.node {
            DisplayNode::Path(node) => {
                validate_transformed_path(node.path(), frame.transform)?;
                usage.expanded_path_commands = checked_add(
                    usage.expanded_path_commands,
                    node.path().commands().len(),
                    "expanded_path_commands",
                    limits.max_expanded_path_commands,
                )?;
            }
            DisplayNode::GlyphRun(run) => {
                let combined = run.transform().then(frame.transform)?;
                combined.transform_point(run.origin())?;
                usage.expanded_glyphs = checked_add(
                    usage.expanded_glyphs,
                    run.glyphs().len(),
                    "expanded_glyphs",
                    limits.max_expanded_glyphs,
                )?;
            }
            DisplayNode::Image(node) => {
                let combined = node.transform().then(frame.transform)?;
                for corner in [
                    Point2::new(0.0, 0.0)?,
                    Point2::new(1.0, 0.0)?,
                    Point2::new(1.0, 1.0)?,
                    Point2::new(0.0, 1.0)?,
                ] {
                    combined.transform_point(corner)?;
                }
                usage.expanded_images = checked_add(
                    usage.expanded_images,
                    1,
                    "expanded_images",
                    limits.max_expanded_nodes,
                )?;
            }
            DisplayNode::InlineGroup(group) => {
                let combined = group.transform().then(frame.transform)?;
                if let Some(clip) = group.clip() {
                    validate_transformed_path(clip.path(), combined)?;
                    usage.expanded_path_commands = checked_add(
                        usage.expanded_path_commands,
                        clip.path().commands().len(),
                        "expanded_path_commands",
                        limits.max_expanded_path_commands,
                    )?;
                }
                pending.extend(group.nodes().iter().rev().map(|node| ExpansionFrame {
                    node,
                    transform: combined,
                    group_depth: frame.group_depth,
                    graphics_depth: frame.graphics_depth + 1,
                }));
            }
            DisplayNode::GroupInstance(instance) => {
                let combined = instance.transform().then(frame.transform)?;
                let group = scene.groups().get(&instance.group()).ok_or_else(|| {
                    structure_error("group expansion referenced an unknown reusable group")
                })?;
                pending.extend(group.nodes().iter().rev().map(|node| ExpansionFrame {
                    node,
                    transform: combined,
                    group_depth: frame.group_depth + 1,
                    graphics_depth: frame.graphics_depth + 1,
                }));
            }
        }
    }
    Ok(())
}

fn validate_transformed_path(
    path: &ScenePath,
    transform: Affine2,
) -> Result<(), PortablePlotError> {
    for command in path.commands() {
        match command {
            PathCommand::MoveTo(point) | PathCommand::LineTo(point) => {
                transform.transform_point(*point)?;
            }
            PathCommand::QuadTo { control, end } => {
                transform.transform_point(*control)?;
                transform.transform_point(*end)?;
            }
            PathCommand::CubicTo {
                control_1,
                control_2,
                end,
            } => {
                transform.transform_point(*control_1)?;
                transform.transform_point(*control_2)?;
                transform.transform_point(*end)?;
            }
            PathCommand::Close => {}
        }
    }
    Ok(())
}

fn checked_add(
    current: usize,
    amount: usize,
    label: &'static str,
    maximum: usize,
) -> Result<usize, PortablePlotError> {
    let next = current
        .checked_add(amount)
        .ok_or_else(|| budget_error(label, maximum))?;
    if next > maximum {
        return Err(budget_error(label, maximum));
    }
    Ok(next)
}

fn budget_error(label: &'static str, maximum: usize) -> PortablePlotError {
    PortablePlotError::new(
        "display_list_budget_exceeded",
        format!("{label} exceeds the configured maximum of {maximum}"),
    )
}

fn structure_error(message: &'static str) -> PortablePlotError {
    PortablePlotError::new("display_list_structure_invalid", message)
}

fn finite_positive(value: f64) -> bool {
    value.is_finite() && value > 0.0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn point(x: f64, y: f64) -> Point2 {
        Point2::new(x, y).unwrap()
    }

    fn line_node() -> DisplayNode {
        DisplayNode::Path(
            PathNode::new(
                ScenePath::polyline([point(0.0, 0.0), point(1.0, 1.0)], false).unwrap(),
                None,
                Some(
                    Stroke::new(
                        SceneColor::BLACK,
                        0.25,
                        10.0,
                        LineCap::Butt,
                        LineJoin::Miter,
                        None,
                    )
                    .unwrap(),
                ),
                None,
            )
            .unwrap(),
        )
    }

    fn scene() -> DisplayList {
        DisplayList::new(PageGeometry::new(595.0, 842.0).unwrap())
    }

    #[test]
    fn page_geometry_is_finite_positive_and_pdf_bounded() {
        for value in [0.0, -1.0, f64::NAN, f64::INFINITY, 14_400.1] {
            assert_eq!(
                PageGeometry::new(value, 1.0).unwrap_err().code(),
                "page_geometry_invalid"
            );
        }
    }

    #[test]
    fn dot_linetypes_are_valid_but_zero_advance_cycles_are_not() {
        assert_eq!(
            DashPattern::new(vec![0.0, 2.0], 0.0).unwrap().elements(),
            &[0.0, 2.0]
        );
        assert_eq!(
            DashPattern::new(vec![0.0, 0.0], 0.0).unwrap_err().code(),
            "dash_pattern_invalid"
        );
    }

    #[test]
    fn path_topology_and_paint_are_explicit() {
        assert_eq!(
            ScenePath::new(vec![PathCommand::LineTo(point(1.0, 1.0))])
                .unwrap_err()
                .code(),
            "path_invalid"
        );
        assert_eq!(
            PathNode::new(
                ScenePath::polyline([point(0.0, 0.0)], false).unwrap(),
                None,
                None,
                None,
            )
            .unwrap_err()
            .code(),
            "display_list_structure_invalid"
        );
    }

    #[test]
    fn resource_digest_bindings_are_enforced() {
        let bytes: Arc<[u8]> = Arc::from(&b"font"[..]);
        let wrong = ResourceDigest::of(b"other");
        assert_eq!(
            FontResource::new("font/regular", bytes.clone(), 0, wrong)
                .unwrap_err()
                .code(),
            "resource_digest_mismatch"
        );
        let digest = ResourceDigest::of(&bytes);
        assert_eq!(
            FontResource::new("font/regular", bytes, 0, digest)
                .unwrap()
                .digest(),
            digest
        );
    }

    #[test]
    fn image_dimensions_and_decoded_bytes_must_agree() {
        let bytes: Arc<[u8]> = Arc::from(&[0_u8; 3][..]);
        let digest = ResourceDigest::of(&bytes);
        assert_eq!(
            ImageResource::new("image", 2, 1, ImageColorSpace::Rgb8, bytes, digest)
                .unwrap_err()
                .code(),
            "image_geometry_invalid"
        );
    }

    #[test]
    fn duplicate_and_unknown_resource_ids_reject() {
        let mut scene = scene();
        let bytes: Arc<[u8]> = Arc::from(&b"font"[..]);
        let digest = ResourceDigest::of(&bytes);
        scene
            .insert_font(
                FontId::new(1),
                FontResource::new("one", bytes.clone(), 0, digest).unwrap(),
            )
            .unwrap();
        assert_eq!(
            scene
                .insert_font(
                    FontId::new(1),
                    FontResource::new("two", bytes, 0, digest).unwrap(),
                )
                .unwrap_err()
                .code(),
            "display_list_structure_invalid"
        );

        scene.push(DisplayNode::Image(ImageNode::new(
            ImageId::new(99),
            Affine2::identity(),
            255,
            None,
        )));
        assert_eq!(
            scene
                .validate(DisplayListLimits::default())
                .unwrap_err()
                .code(),
            "display_list_structure_invalid"
        );
    }

    #[test]
    fn reusable_group_cycles_reject_without_recursive_validation() {
        let mut scene = scene();
        scene
            .insert_group(
                GroupId::new(1),
                ReusableGroup::new(vec![DisplayNode::GroupInstance(GroupInstance::new(
                    GroupId::new(2),
                    Affine2::identity(),
                    255,
                    None,
                ))]),
            )
            .unwrap();
        scene
            .insert_group(
                GroupId::new(2),
                ReusableGroup::new(vec![DisplayNode::GroupInstance(GroupInstance::new(
                    GroupId::new(1),
                    Affine2::identity(),
                    255,
                    None,
                ))]),
            )
            .unwrap();
        assert_eq!(
            scene
                .validate(DisplayListLimits::default())
                .unwrap_err()
                .code(),
            "display_list_structure_invalid"
        );
    }

    #[test]
    fn definition_and_expansion_usage_are_accounted_separately() {
        let mut scene = scene();
        scene
            .insert_group(GroupId::new(1), ReusableGroup::new(vec![line_node()]))
            .unwrap();
        for _ in 0..3 {
            scene.push(DisplayNode::GroupInstance(GroupInstance::new(
                GroupId::new(1),
                Affine2::identity(),
                255,
                None,
            )));
        }
        let usage = scene.validate(DisplayListLimits::default()).unwrap();
        assert_eq!(usage.nodes, 4);
        assert_eq!(usage.path_commands, 2);
        assert_eq!(usage.expanded_nodes, 6);
        assert_eq!(usage.expanded_path_commands, 6);
    }

    #[test]
    fn every_budget_accepts_its_boundary_and_rejects_the_next_item() {
        let mut scene = scene();
        scene.push(line_node());
        let limits = DisplayListLimits {
            max_nodes: 1,
            max_path_commands: 2,
            max_expanded_nodes: 1,
            max_expanded_path_commands: 2,
            ..DisplayListLimits::default()
        };
        scene.validate(limits).unwrap();
        scene.push(line_node());
        assert_eq!(
            scene.validate(limits).unwrap_err().code(),
            "display_list_budget_exceeded"
        );
    }

    #[test]
    fn graphics_state_depth_is_iteratively_bounded() {
        let mut node = line_node();
        for _ in 0..4 {
            node = DisplayNode::InlineGroup(InlineGroup::new(
                Affine2::identity(),
                None,
                255,
                vec![node],
            ));
        }
        let mut scene = scene();
        scene.push(node);
        let limits = DisplayListLimits {
            max_graphics_state_depth: 3,
            ..DisplayListLimits::default()
        };
        assert_eq!(
            scene.validate(limits).unwrap_err().code(),
            "display_list_budget_exceeded"
        );
    }

    #[test]
    fn transformed_coordinate_overflow_rejects_during_expansion() {
        let huge = Affine2::scale(f64::MAX, 1.0).unwrap();
        let mut scene = scene();
        let overflowing_line = DisplayNode::Path(
            PathNode::new(
                ScenePath::polyline([point(0.0, 0.0), point(2.0, 1.0)], false).unwrap(),
                None,
                Some(
                    Stroke::new(
                        SceneColor::BLACK,
                        0.25,
                        10.0,
                        LineCap::Butt,
                        LineJoin::Miter,
                        None,
                    )
                    .unwrap(),
                ),
                None,
            )
            .unwrap(),
        );
        scene.push(DisplayNode::InlineGroup(InlineGroup::new(
            huge,
            None,
            255,
            vec![overflowing_line],
        )));
        assert_eq!(
            scene
                .validate(DisplayListLimits::default())
                .unwrap_err()
                .code(),
            "non_finite_arithmetic"
        );
    }

    #[test]
    fn btree_resource_and_group_iteration_is_stable_by_identifier() {
        let mut scene = scene();
        scene
            .insert_group(GroupId::new(9), ReusableGroup::new(Vec::new()))
            .unwrap();
        scene
            .insert_group(GroupId::new(2), ReusableGroup::new(Vec::new()))
            .unwrap();
        assert_eq!(
            scene.groups().keys().map(|id| id.get()).collect::<Vec<_>>(),
            vec![2, 9]
        );
    }

    #[test]
    fn glyph_ranges_must_follow_utf8_boundaries() {
        let glyph = PositionedGlyph::new(1, 1.0, 0.0, 0.0, 0.0, 1..2).unwrap();
        assert_eq!(
            GlyphRun::new(
                FontId::new(1),
                10.0,
                point(0.0, 0.0),
                Affine2::identity(),
                "é".to_string(),
                vec![glyph],
                Fill::new(SceneColor::BLACK, FillRule::NonZero),
                None,
            )
            .unwrap_err()
            .code(),
            "glyph_run_invalid"
        );
    }

    #[test]
    fn logical_resource_identity_cannot_be_an_absolute_or_parent_path() {
        let bytes: Arc<[u8]> = Arc::from(&b"font"[..]);
        let digest = ResourceDigest::of(&bytes);
        for identity in ["/private/font.ttf", "../font.ttf", "a\\font.ttf"] {
            assert_eq!(
                FontResource::new(identity, bytes.clone(), 0, digest)
                    .unwrap_err()
                    .code(),
                "resource_identity_invalid"
            );
        }
    }
}
