use std::collections::{BTreeMap, BTreeSet};

use ::krilla::configure::{ConfigurationBuilder, PdfVersion};
use ::krilla::geom::{Path, PathBuilder, Point, Transform};
use ::krilla::graphic::Graphic;
use ::krilla::num::NormalizedF32;
use ::krilla::page::PageSettings;
use ::krilla::paint::{
    Fill as KrillaFill, FillRule as KrillaFillRule, LineCap as KrillaLineCap,
    LineJoin as KrillaLineJoin, Stroke as KrillaStroke, StrokeDash,
};
use ::krilla::surface::Surface;
use ::krilla::text::{Font, GlyphId, KrillaGlyph};
use ::krilla::{Data, Document, SerializeSettings};

use super::{
    Affine2, DisplayList, DisplayListLimits, DisplayNode, Fill, FillRule, FontId, GlyphRun,
    GroupId, GroupInstance, InlineGroup, LineCap, LineJoin, PathCommand, PathNode,
    PortablePlotError, ReusableGroup, SceneColor, ScenePath, Stroke,
};

/// Deterministic development PDF bytes produced from a validated display list.
#[derive(Debug, Clone)]
pub struct PortablePdf {
    bytes: Vec<u8>,
}

impl PortablePdf {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn encoder(&self) -> &'static str {
        "krilla-0.8.2-pdf-1.4"
    }
}

/// Encode one already-semantic, backend-neutral scene as a bounded PDF.
///
/// This performs no file installation and activates no MCP/runtime surface.
pub fn encode_portable_pdf(
    scene: &DisplayList,
    limits: DisplayListLimits,
) -> Result<PortablePdf, PortablePlotError> {
    scene.validate(limits)?;
    reject_image_nodes(scene)?;

    let configuration = ConfigurationBuilder::new()
        .with_version(PdfVersion::Pdf14)
        .finish()
        .map_err(|_| {
            PortablePlotError::new(
                "portable_pdf_configuration_failed",
                "Krilla rejected the fixed PDF 1.4 configuration",
            )
        })?;
    let settings = SerializeSettings {
        pretty: false,
        compress_content_streams: true,
        no_device_cs: false,
        ascii_compatible: false,
        xmp_metadata: false,
        cmyk_profile: None,
        configuration,
        enable_tagging: false,
        ..SerializeSettings::default()
    };
    let mut document = Document::new_with(settings);
    let fonts = load_fonts(scene)?;
    let page = scene.page();
    let page_settings = PageSettings::from_wh(to_f32(page.width())?, to_f32(page.height())?)
        .ok_or_else(|| {
            PortablePlotError::new(
                "portable_pdf_page_rejected",
                "Krilla rejected validated page dimensions",
            )
        })?;
    let mut page = document.start_page_with(page_settings);
    {
        let mut surface = page.surface();
        let mut graphics = BTreeMap::new();
        let mut visiting = BTreeSet::new();
        for group_id in scene.groups().keys().copied() {
            prepare_group(
                group_id,
                scene,
                &fonts,
                &mut surface,
                &mut graphics,
                &mut visiting,
                limits.max_group_depth,
            )?;
        }
        render_nodes(&mut surface, scene.nodes(), &fonts, &graphics)?;
        surface.finish();
    }
    page.finish();

    let bytes = document.finish().map_err(|_| {
        PortablePlotError::new(
            "portable_pdf_encode_failed",
            "Krilla could not serialize the validated display list",
        )
    })?;
    if bytes.len() > limits.max_output_bytes {
        return Err(PortablePlotError::new(
            "portable_pdf_size_budget_exceeded",
            "serialized PDF exceeds the configured output byte limit",
        ));
    }
    if !bytes.starts_with(b"%PDF-1.4") || !bytes.ends_with(b"%%EOF") {
        return Err(PortablePlotError::new(
            "portable_pdf_envelope_invalid",
            "encoded output does not have the required PDF 1.4 envelope",
        ));
    }
    Ok(PortablePdf { bytes })
}

fn load_fonts(scene: &DisplayList) -> Result<BTreeMap<FontId, Font>, PortablePlotError> {
    scene
        .fonts()
        .iter()
        .map(|(id, resource)| {
            let font = Font::new(Data::from(resource.bytes().to_vec()), resource.face_index())
                .ok_or_else(|| {
                    PortablePlotError::new(
                        "portable_pdf_font_rejected",
                        "Krilla rejected a validated digest-bound font resource",
                    )
                })?;
            Ok((*id, font))
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn prepare_group(
    group_id: GroupId,
    scene: &DisplayList,
    fonts: &BTreeMap<FontId, Font>,
    surface: &mut Surface<'_>,
    graphics: &mut BTreeMap<GroupId, Graphic>,
    visiting: &mut BTreeSet<GroupId>,
    max_depth: usize,
) -> Result<(), PortablePlotError> {
    if graphics.contains_key(&group_id) {
        return Ok(());
    }
    if !visiting.insert(group_id) || visiting.len() > max_depth {
        return Err(PortablePlotError::new(
            "display_list_structure_invalid",
            "reusable group dependencies are cyclic or exceed the configured depth",
        ));
    }
    let group = scene.groups().get(&group_id).ok_or_else(|| {
        PortablePlotError::new(
            "display_list_structure_invalid",
            "group preparation referenced an unknown definition",
        )
    })?;
    let mut dependencies = BTreeSet::new();
    collect_group_dependencies(group.nodes(), &mut dependencies);
    for dependency in dependencies {
        prepare_group(
            dependency, scene, fonts, surface, graphics, visiting, max_depth,
        )?;
    }
    let mut stream_builder = surface.stream_builder();
    {
        let mut group_surface = stream_builder.surface();
        render_nodes(&mut group_surface, group.nodes(), fonts, graphics)?;
        group_surface.finish();
    }
    graphics.insert(group_id, Graphic::new(stream_builder.finish(), false));
    visiting.remove(&group_id);
    Ok(())
}

fn collect_group_dependencies(nodes: &[DisplayNode], output: &mut BTreeSet<GroupId>) {
    let mut pending = nodes.iter().collect::<Vec<_>>();
    while let Some(node) = pending.pop() {
        match node {
            DisplayNode::InlineGroup(group) => pending.extend(group.nodes()),
            DisplayNode::GroupInstance(instance) => {
                output.insert(instance.group());
            }
            DisplayNode::Path(_) | DisplayNode::GlyphRun(_) | DisplayNode::Image(_) => {}
        }
    }
}

fn render_nodes(
    surface: &mut Surface<'_>,
    nodes: &[DisplayNode],
    fonts: &BTreeMap<FontId, Font>,
    graphics: &BTreeMap<GroupId, Graphic>,
) -> Result<(), PortablePlotError> {
    for node in nodes {
        match node {
            DisplayNode::Path(path) => render_path(surface, path)?,
            DisplayNode::GlyphRun(run) => render_glyph_run(surface, run, fonts)?,
            DisplayNode::InlineGroup(group) => {
                render_inline_group(surface, group, fonts, graphics)?
            }
            DisplayNode::GroupInstance(instance) => {
                render_group_instance(surface, instance, graphics)?
            }
            DisplayNode::Image(_) => {
                return Err(PortablePlotError::new(
                    "portable_pdf_image_encoding_unsupported",
                    "validated raw images do not yet have a Krilla colour-space adapter",
                ))
            }
        }
    }
    Ok(())
}

fn render_path(surface: &mut Surface<'_>, node: &PathNode) -> Result<(), PortablePlotError> {
    let path = build_path(node.path())?;
    surface.set_fill(node.fill().map(fill));
    surface.set_stroke(node.stroke().map(stroke).transpose()?);
    surface.draw_path(&path);
    Ok(())
}

fn render_glyph_run(
    surface: &mut Surface<'_>,
    run: &GlyphRun,
    fonts: &BTreeMap<FontId, Font>,
) -> Result<(), PortablePlotError> {
    let font = fonts.get(&run.font()).ok_or_else(|| {
        PortablePlotError::new(
            "display_list_structure_invalid",
            "glyph run references an unknown loaded font",
        )
    })?;
    let glyphs = run
        .glyphs()
        .iter()
        .map(|glyph| {
            Ok(KrillaGlyph::new(
                GlyphId::new(glyph.glyph_id()),
                to_f32(glyph.x_advance())?,
                to_f32(glyph.x_offset())?,
                to_f32(glyph.y_offset())?,
                to_f32(glyph.y_advance())?,
                glyph.text_range(),
                None,
            ))
        })
        .collect::<Result<Vec<_>, PortablePlotError>>()?;
    surface.set_fill(Some(fill(run.fill())));
    surface.set_stroke(None);
    let transformed = run.transform() != Affine2::identity();
    if transformed {
        surface.push_transform(&transform(run.transform())?);
    }
    surface.draw_glyphs(
        Point::from_xy(to_f32(run.origin().x())?, to_f32(run.origin().y())?),
        &glyphs,
        font.clone(),
        run.text(),
        to_f32(run.font_size())?,
        false,
    );
    if transformed {
        surface.pop();
    }
    Ok(())
}

fn render_inline_group(
    surface: &mut Surface<'_>,
    group: &InlineGroup,
    fonts: &BTreeMap<FontId, Font>,
    graphics: &BTreeMap<GroupId, Graphic>,
) -> Result<(), PortablePlotError> {
    let clip = group
        .clip()
        .map(|clip| Ok((build_path(clip.path())?, fill_rule(clip.rule()))))
        .transpose()?;
    let transformed = group.transform() != Affine2::identity();
    let opacified = group.opacity() != u8::MAX;
    if transformed {
        surface.push_transform(&transform(group.transform())?);
    }
    if let Some((path, rule)) = &clip {
        surface.push_clip_path(path, rule);
    }
    if opacified {
        surface.push_opacity(normalized(group.opacity()));
    }
    let result = render_nodes(surface, group.nodes(), fonts, graphics);
    if opacified {
        surface.pop();
    }
    if clip.is_some() {
        surface.pop();
    }
    if transformed {
        surface.pop();
    }
    result
}

fn render_group_instance(
    surface: &mut Surface<'_>,
    instance: &GroupInstance,
    graphics: &BTreeMap<GroupId, Graphic>,
) -> Result<(), PortablePlotError> {
    let graphic = graphics.get(&instance.group()).ok_or_else(|| {
        PortablePlotError::new(
            "display_list_structure_invalid",
            "group instance references an unknown prepared graphic",
        )
    })?;
    let transformed = instance.transform() != Affine2::identity();
    let opacified = instance.opacity() != u8::MAX;
    if transformed {
        surface.push_transform(&transform(instance.transform())?);
    }
    if opacified {
        surface.push_opacity(normalized(instance.opacity()));
    }
    surface.draw_graphic(graphic.clone());
    if opacified {
        surface.pop();
    }
    if transformed {
        surface.pop();
    }
    Ok(())
}

fn build_path(path: &ScenePath) -> Result<Path, PortablePlotError> {
    let mut builder = PathBuilder::new();
    for command in path.commands() {
        match command {
            PathCommand::MoveTo(point) => builder.move_to(to_f32(point.x())?, to_f32(point.y())?),
            PathCommand::LineTo(point) => builder.line_to(to_f32(point.x())?, to_f32(point.y())?),
            PathCommand::QuadTo { control, end } => builder.quad_to(
                to_f32(control.x())?,
                to_f32(control.y())?,
                to_f32(end.x())?,
                to_f32(end.y())?,
            ),
            PathCommand::CubicTo {
                control_1,
                control_2,
                end,
            } => builder.cubic_to(
                to_f32(control_1.x())?,
                to_f32(control_1.y())?,
                to_f32(control_2.x())?,
                to_f32(control_2.y())?,
                to_f32(end.x())?,
                to_f32(end.y())?,
            ),
            PathCommand::Close => builder.close(),
        }
    }
    builder.finish().ok_or_else(|| {
        PortablePlotError::new(
            "portable_pdf_path_rejected",
            "Krilla rejected a path that passed display-list validation",
        )
    })
}

fn fill(value: Fill) -> KrillaFill {
    KrillaFill {
        paint: color(value.color()).into(),
        opacity: normalized(value.color().alpha()),
        rule: fill_rule(value.rule()),
    }
}

fn stroke(value: &Stroke) -> Result<KrillaStroke, PortablePlotError> {
    Ok(KrillaStroke {
        paint: color(value.color()).into(),
        width: to_f32(value.width())?,
        miter_limit: to_f32(value.miter_limit())?,
        line_cap: match value.cap() {
            LineCap::Butt => KrillaLineCap::Butt,
            LineCap::Round => KrillaLineCap::Round,
            LineCap::Square => KrillaLineCap::Square,
        },
        line_join: match value.join() {
            LineJoin::Miter => KrillaLineJoin::Miter,
            LineJoin::Round => KrillaLineJoin::Round,
            LineJoin::Bevel => KrillaLineJoin::Bevel,
        },
        opacity: normalized(value.color().alpha()),
        dash: value
            .dash()
            .map(|dash| {
                Ok(StrokeDash {
                    array: dash
                        .elements()
                        .iter()
                        .map(|value| to_f32(*value))
                        .collect::<Result<Vec<_>, _>>()?,
                    offset: to_f32(dash.offset())?,
                })
            })
            .transpose()?,
    })
}

fn fill_rule(value: FillRule) -> KrillaFillRule {
    match value {
        FillRule::NonZero => KrillaFillRule::NonZero,
        FillRule::EvenOdd => KrillaFillRule::EvenOdd,
    }
}

fn color(value: SceneColor) -> ::krilla::color::rgb::Color {
    ::krilla::color::rgb::Color::new(value.red(), value.green(), value.blue())
}

fn normalized(value: u8) -> NormalizedF32 {
    NormalizedF32::new(f32::from(value) / 255.0).expect("u8 opacity is normalized")
}

fn transform(value: Affine2) -> Result<Transform, PortablePlotError> {
    let [m11, m12, m21, m22, tx, ty] = value.components();
    Ok(Transform::from_row(
        to_f32(m11)?,
        to_f32(m21)?,
        to_f32(m12)?,
        to_f32(m22)?,
        to_f32(tx)?,
        to_f32(ty)?,
    ))
}

fn to_f32(value: f64) -> Result<f32, PortablePlotError> {
    let converted = value as f32;
    if !converted.is_finite() {
        return Err(PortablePlotError::new(
            "portable_pdf_numeric_conversion_failed",
            "validated scene value is outside Krilla's finite f32 range",
        ));
    }
    Ok(converted)
}

fn reject_image_nodes(scene: &DisplayList) -> Result<(), PortablePlotError> {
    let mut pending = scene.nodes().iter().collect::<Vec<_>>();
    pending.extend(scene.groups().values().flat_map(ReusableGroup::nodes));
    while let Some(node) = pending.pop() {
        match node {
            DisplayNode::Image(_) => {
                return Err(PortablePlotError::new(
                    "portable_pdf_image_encoding_unsupported",
                    "validated raw images do not yet have a Krilla colour-space adapter",
                ))
            }
            DisplayNode::InlineGroup(group) => pending.extend(group.nodes()),
            DisplayNode::Path(_) | DisplayNode::GlyphRun(_) | DisplayNode::GroupInstance(_) => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "portable-plot-qualification")]
    use crate::portable_plot::{
        test_font::qualification_font, FontResource, PositionedGlyph, ResourceDigest,
    };
    use crate::portable_plot::{
        ClipPath, DisplayNode, Fill, GroupId, GroupInstance, InlineGroup, PageGeometry, PathNode,
        Point2, ReusableGroup, ScenePath, Stroke,
    };
    #[cfg(feature = "portable-plot-qualification")]
    use hayro::hayro_interpret::InterpreterSettings;
    #[cfg(feature = "portable-plot-qualification")]
    use hayro::hayro_syntax::Pdf;
    #[cfg(feature = "portable-plot-qualification")]
    use hayro::vello_cpu::color::palette::css::WHITE;
    #[cfg(feature = "portable-plot-qualification")]
    use hayro::{render, RenderCache, RenderSettings};

    fn simple_scene() -> DisplayList {
        let mut scene = DisplayList::new(PageGeometry::new(200.0, 100.0).unwrap());
        let path = ScenePath::polyline(
            [
                Point2::new(10.0, 10.0).unwrap(),
                Point2::new(190.0, 90.0).unwrap(),
            ],
            false,
        )
        .unwrap();
        scene.push(DisplayNode::Path(
            PathNode::new(
                path,
                None,
                Some(
                    Stroke::new(
                        SceneColor::BLACK,
                        0.5,
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
        ));
        scene
    }

    #[test]
    fn pdf_1_4_envelope_and_repeat_bytes_are_deterministic() {
        let scene = simple_scene();
        let first = encode_portable_pdf(&scene, DisplayListLimits::default()).unwrap();
        let second = encode_portable_pdf(&scene, DisplayListLimits::default()).unwrap();
        assert!(first.bytes().starts_with(b"%PDF-1.4"));
        assert!(first.bytes().ends_with(b"%%EOF"));
        assert_eq!(first.bytes(), second.bytes());
    }

    #[test]
    fn output_budget_is_enforced_after_serialization() {
        let scene = simple_scene();
        let limits = DisplayListLimits {
            max_output_bytes: 8,
            ..DisplayListLimits::default()
        };
        assert_eq!(
            encode_portable_pdf(&scene, limits).unwrap_err().code(),
            "portable_pdf_size_budget_exceeded"
        );
    }

    #[cfg(feature = "portable-plot-qualification")]
    fn rasterize(pdf: &[u8]) -> hayro::vello_cpu::Pixmap {
        let document = Pdf::new(pdf.to_vec()).unwrap();
        assert_eq!(document.pages().len(), 1);
        render(
            &document.pages()[0],
            &RenderCache::new(),
            &InterpreterSettings::default(),
            &RenderSettings {
                x_scale: 1.0,
                y_scale: 1.0,
                bg_color: WHITE,
                ..RenderSettings::default()
            },
        )
    }

    #[cfg(feature = "portable-plot-qualification")]
    fn nonwhite_pixels(pixmap: &hayro::vello_cpu::Pixmap) -> usize {
        pixmap
            .data_as_u8_slice()
            .chunks_exact(4)
            .filter(|pixel| pixel[..3].iter().any(|component| *component < 245))
            .count()
    }

    // Hayro is deliberately qualification-only: it gives the Krilla output
    // an implementation-independent raster oracle without entering ordinary
    // source-quality or product compilation graphs.
    #[cfg(feature = "portable-plot-qualification")]
    #[test]
    fn independent_raster_oracle_observes_vector_geometry() {
        let mut scene = DisplayList::new(PageGeometry::new(64.0, 48.0).unwrap());
        scene.push(DisplayNode::Path(
            PathNode::new(
                ScenePath::rectangle(8.0, 8.0, 24.0, 24.0).unwrap(),
                Some(Fill::new(SceneColor::BLACK, FillRule::NonZero)),
                None,
                None,
            )
            .unwrap(),
        ));
        let pdf = encode_portable_pdf(&scene, DisplayListLimits::default()).unwrap();
        let raster = rasterize(pdf.bytes());
        assert_eq!((raster.width(), raster.height()), (64, 48));
        assert_eq!(nonwhite_pixels(&raster), 256);
    }

    #[cfg(feature = "portable-plot-qualification")]
    #[test]
    fn generated_font_glyph_is_embedded_and_independently_rasterized() {
        let mut scene = DisplayList::new(PageGeometry::new(64.0, 48.0).unwrap());
        let font = qualification_font();
        let digest = ResourceDigest::of(&font);
        scene
            .insert_font(
                FontId::new(1),
                FontResource::new("qualification/font.ttf", font, 0, digest).unwrap(),
            )
            .unwrap();
        scene.push(DisplayNode::GlyphRun(
            GlyphRun::new(
                FontId::new(1),
                24.0,
                Point2::new(8.0, 32.0).unwrap(),
                Affine2::identity(),
                "A".to_owned(),
                vec![PositionedGlyph::new(1, 0.6, 0.0, 0.0, 0.0, 0..1).unwrap()],
                Fill::new(SceneColor::BLACK, FillRule::NonZero),
                None,
            )
            .unwrap(),
        ));
        let pdf = encode_portable_pdf(&scene, DisplayListLimits::default()).unwrap();
        let parsed = lopdf::Document::load_mem(pdf.bytes()).unwrap();
        assert!(parsed.objects.values().any(|object| {
            object
                .as_dict()
                .ok()
                .and_then(|dictionary| dictionary.get(b"Type").ok())
                .is_some_and(|kind| kind.as_name().ok() == Some(b"Font"))
        }));
        let raster = rasterize(pdf.bytes());
        let pixels = nonwhite_pixels(&raster);
        assert!(
            (50..=220).contains(&pixels),
            "unexpected glyph raster coverage: {pixels}"
        );
    }

    #[test]
    fn reusable_groups_clips_transforms_and_opacity_encode_and_parse() {
        let mut scene = DisplayList::new(PageGeometry::new(200.0, 100.0).unwrap());
        let filled = DisplayNode::Path(
            PathNode::new(
                ScenePath::rectangle(0.0, 0.0, 50.0, 50.0).unwrap(),
                Some(Fill::new(SceneColor::rgb(12, 34, 56), FillRule::EvenOdd)),
                None,
                None,
            )
            .unwrap(),
        );
        scene
            .insert_group(GroupId::new(7), ReusableGroup::new(vec![filled]))
            .unwrap();
        let clip = ClipPath::new(
            ScenePath::rectangle(10.0, 10.0, 90.0, 90.0).unwrap(),
            FillRule::NonZero,
        );
        scene.push(DisplayNode::InlineGroup(InlineGroup::new(
            Affine2::translation(crate::portable_plot::Vector2::new(5.0, 3.0).unwrap()),
            Some(clip),
            192,
            vec![DisplayNode::GroupInstance(GroupInstance::new(
                GroupId::new(7),
                Affine2::scale(1.5, 0.5).unwrap(),
                224,
                None,
            ))],
        )));
        let pdf = encode_portable_pdf(&scene, DisplayListLimits::default()).unwrap();
        assert!(pdf.bytes().starts_with(b"%PDF-1.4"));
        assert!(pdf.bytes().ends_with(b"%%EOF"));
    }

    #[cfg(feature = "portable-plot-qualification")]
    #[test]
    fn independent_parser_accepts_the_structural_pdf_contract() {
        let pdf = encode_portable_pdf(&simple_scene(), DisplayListLimits::default()).unwrap();
        let parsed = lopdf::Document::load_mem(pdf.bytes()).unwrap();
        assert_eq!(parsed.version, "1.4");
        assert_eq!(parsed.get_pages().len(), 1);
    }
}
