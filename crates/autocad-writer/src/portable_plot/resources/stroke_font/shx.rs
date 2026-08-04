use std::collections::{BTreeMap, BTreeSet};
use std::f64::consts::{PI, TAU};

use super::{
    invalid_resource, StrokeCommandDocument, StrokeFontDocument, StrokeFontSchema,
    StrokeGlyphDocument,
};
use crate::portable_plot::PortablePlotError;

const SHAPES_1_0_HEADER: &[u8] = b"AutoCAD-86 shapes 1.0\r\n\x1a";
const SHAPES_1_1_HEADER: &[u8] = b"AutoCAD-86 shapes 1.1\r\n\x1a";
const UNIFONT_1_0_HEADER: &[u8] = b"AutoCAD-86 unifont 1.0\r\n\x1a";
const BIGFONT_HEADER_PREFIX: &[u8] = b"AutoCAD-86 bigfont ";

const MAX_RECORDS: usize = 65_536;
const MAX_GLYPH_BYTES: usize = 2_000;
const MAX_INFO_BYTES: usize = 4_096;
const MAX_SUBSHAPE_DEPTH: usize = 16;
const MAX_STEPS_PER_GLYPH: usize = 32_768;
const MAX_TOTAL_STEPS: usize = 2_000_000;
const MAX_SCALE: f64 = 1.0e9;
const MAX_COORDINATE: f64 = 1.0e12;
const ARC_SEGMENT_SWEEP: f64 = PI / 8.0;

pub(super) struct DecodedShx {
    pub(super) source_format: &'static str,
    pub(super) document: StrokeFontDocument,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FontFamily {
    Shapes,
    Unifont,
}

struct ParsedFont {
    source_format: &'static str,
    family: FontFamily,
    cap_height: f64,
    descent: f64,
    programs: BTreeMap<u16, Vec<u8>>,
    characters: BTreeMap<char, u16>,
}

pub(super) fn decode(
    bytes: &[u8],
    options: &super::ShxAdmissionOptions,
) -> Result<DecodedShx, PortablePlotError> {
    let parsed = if let Some(body) = bytes.strip_prefix(UNIFONT_1_0_HEADER) {
        parse_unifont(body)?
    } else if let Some(body) = bytes.strip_prefix(SHAPES_1_0_HEADER) {
        parse_shapes(body, "autocad_shx_shapes_1_0", options)?
    } else if let Some(body) = bytes.strip_prefix(SHAPES_1_1_HEADER) {
        parse_shapes(body, "autocad_shx_shapes_1_1", options)?
    } else if bytes.starts_with(BIGFONT_HEADER_PREFIX) {
        return Err(unsupported(
            "raw SHX big-font containers require the composite big-font admission contract",
        ));
    } else {
        return Err(unsupported(
            "raw SHX bytes do not use an admitted AutoCAD-86 font header and version",
        ));
    };
    normalize(parsed)
}

fn parse_shapes(
    bytes: &[u8],
    source_format: &'static str,
    options: &super::ShxAdmissionOptions,
) -> Result<ParsedFont, PortablePlotError> {
    let mut cursor = Cursor::new(bytes);
    let start = cursor.read_u16()?;
    let end = cursor.read_u16()?;
    let count = usize::from(cursor.read_u16()?);
    if start > end || count == 0 || count > MAX_RECORDS {
        return Err(invalid());
    }

    let mut references = Vec::with_capacity(count);
    let mut seen = BTreeSet::new();
    for _ in 0..count {
        let code = cursor.read_u16()?;
        let length = usize::from(cursor.read_u16()?);
        if code < start
            || code > end
            || length == 0
            || length > MAX_GLYPH_BYTES
            || !seen.insert(code)
        {
            return Err(invalid());
        }
        references.push((code, length));
    }

    let mut records = BTreeMap::new();
    for (code, length) in references {
        records.insert(code, cursor.take(length)?.to_vec());
    }
    cursor.finish()?;

    let info = records.remove(&0).ok_or_else(|| {
        unsupported("raw SHX shape collections without font record 0 are not text fonts")
    })?;
    let (cap_height, descent) = parse_shapes_info(&info)?;
    let programs = parse_program_records(records)?;
    let characters = legacy_character_map(&programs, options)?;
    if characters.is_empty() {
        return Err(unsupported(
            "raw legacy SHX fonts must contain at least one canonical or explicitly mapped character",
        ));
    }
    Ok(ParsedFont {
        source_format,
        family: FontFamily::Shapes,
        cap_height,
        descent,
        programs,
        characters,
    })
}

fn parse_unifont(bytes: &[u8]) -> Result<ParsedFont, PortablePlotError> {
    let mut cursor = Cursor::new(bytes);
    let count = usize::try_from(cursor.read_u32()?).map_err(|_| invalid())?;
    let info_length = usize::from(cursor.read_u16()?);
    if !(2..=MAX_RECORDS).contains(&count) || info_length == 0 || info_length > MAX_INFO_BYTES {
        return Err(invalid());
    }
    let info = cursor.take(info_length)?;
    let (cap_height, descent) = parse_unifont_info(info)?;

    let mut programs = BTreeMap::new();
    let mut characters = BTreeMap::new();
    for _ in 1..count {
        let code = cursor.read_u16()?;
        let length = usize::from(cursor.read_u16()?);
        if code == 0 || length == 0 || length > MAX_GLYPH_BYTES || programs.contains_key(&code) {
            return Err(invalid());
        }
        let character = char::from_u32(u32::from(code)).ok_or_else(invalid)?;
        let program = split_program(cursor.take(length)?)?;
        if characters.insert(character, code).is_some() {
            return Err(invalid());
        }
        programs.insert(code, program);
    }
    cursor.finish()?;
    if programs.is_empty() {
        return Err(invalid());
    }
    Ok(ParsedFont {
        source_format: "autocad_shx_unifont_1_0",
        family: FontFamily::Unifont,
        cap_height,
        descent,
        programs,
        characters,
    })
}

fn parse_shapes_info(bytes: &[u8]) -> Result<(f64, f64), PortablePlotError> {
    let nul = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(invalid)?;
    validate_name(&bytes[..nul])?;
    let tail = bytes.get(nul + 1..).ok_or_else(invalid)?;
    if tail.len() != 4 || tail[0] == 0 || !matches!(tail[2], 0 | 2) || tail[3] != 0 {
        return Err(invalid());
    }
    Ok((f64::from(tail[0]), f64::from(tail[1])))
}

fn parse_unifont_info(bytes: &[u8]) -> Result<(f64, f64), PortablePlotError> {
    let nul = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(invalid)?;
    validate_name(&bytes[..nul])?;
    let tail = bytes.get(nul + 1..).ok_or_else(invalid)?;
    if tail.len() != 6 || tail[0] == 0 || !matches!(tail[2], 0 | 2) || tail[5] != 0 {
        return Err(invalid());
    }
    if tail[3] != 0 {
        return Err(unsupported(
            "raw SHX unifont admission supports only direct Unicode encoding 0",
        ));
    }
    if tail[4] != 0 {
        return Err(unsupported(
            "raw SHX unifont embedding restrictions prohibit semantic expansion",
        ));
    }
    Ok((f64::from(tail[0]), f64::from(tail[1])))
}

fn validate_name(bytes: &[u8]) -> Result<(), PortablePlotError> {
    if bytes.is_empty()
        || bytes.len() > 255
        || !bytes.iter().all(|byte| matches!(*byte, b' '..=b'~'))
    {
        return Err(invalid());
    }
    Ok(())
}

fn parse_program_records(
    records: BTreeMap<u16, Vec<u8>>,
) -> Result<BTreeMap<u16, Vec<u8>>, PortablePlotError> {
    records
        .into_iter()
        .map(|(code, bytes)| Ok((code, split_program(&bytes)?)))
        .collect()
}

fn split_program(bytes: &[u8]) -> Result<Vec<u8>, PortablePlotError> {
    let nul = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(invalid)?;
    if nul > 0 {
        validate_name(&bytes[..nul])?;
    }
    let program = bytes.get(nul + 1..).ok_or_else(invalid)?;
    if program.is_empty() {
        return Err(invalid());
    }
    Ok(program.to_vec())
}

fn legacy_character_map(
    programs: &BTreeMap<u16, Vec<u8>>,
    options: &super::ShxAdmissionOptions,
) -> Result<BTreeMap<char, u16>, PortablePlotError> {
    let mut result = BTreeMap::new();
    let mut by_code = BTreeMap::new();
    for code in 0x20_u16..=0x7e {
        if programs.contains_key(&code) {
            let character = char::from_u32(u32::from(code)).expect("printable ASCII is Unicode");
            insert_character_mapping(&mut result, &mut by_code, code, character)?;
        }
    }
    for (code, character) in [(256, '\u{00b0}'), (257, '\u{00b1}'), (258, '\u{2205}')] {
        if programs.contains_key(&code) {
            insert_character_mapping(&mut result, &mut by_code, code, character)?;
        }
    }

    for (&code, &character) in options.legacy_code_points() {
        if !programs.contains_key(&code) {
            return Err(invalid_resource(
                "raw SHX legacy character mappings must reference present shape codes",
            ));
        }
        if let Some(canonical) = canonical_legacy_character(code) {
            if canonical != character {
                return Err(invalid_resource(
                    "raw SHX legacy character mappings cannot contradict canonical identities",
                ));
            }
        }
        insert_character_mapping(&mut result, &mut by_code, code, character)?;
    }
    Ok(result)
}

fn canonical_legacy_character(code: u16) -> Option<char> {
    match code {
        0x20..=0x7e => char::from_u32(u32::from(code)),
        256 => Some('\u{00b0}'),
        257 => Some('\u{00b1}'),
        258 => Some('\u{2205}'),
        _ => None,
    }
}

fn insert_character_mapping(
    result: &mut BTreeMap<char, u16>,
    by_code: &mut BTreeMap<u16, char>,
    code: u16,
    character: char,
) -> Result<(), PortablePlotError> {
    if let Some(existing) = by_code.get(&code) {
        if *existing == character {
            return Ok(());
        }
        return Err(invalid());
    }
    if result.insert(character, code).is_some() {
        return Err(invalid_resource(
            "raw SHX character mappings must have unique Unicode targets",
        ));
    }
    by_code.insert(code, character);
    Ok(())
}

fn normalize(parsed: ParsedFont) -> Result<DecodedShx, PortablePlotError> {
    let mut glyphs = BTreeMap::new();
    let mut total_steps = 0_usize;
    for (character, code) in parsed.characters.iter().map(|(key, value)| (*key, *value)) {
        let mut interpreter = Interpreter::new(parsed.family, &parsed.programs);
        interpreter.execute(code)?;
        if !interpreter.stack.is_empty() {
            return Err(invalid_resource(
                "raw SHX glyphs must balance the four-deep position stack",
            ));
        }
        total_steps = total_steps
            .checked_add(interpreter.steps)
            .ok_or_else(budget_exceeded)?;
        if total_steps > MAX_TOTAL_STEPS {
            return Err(budget_exceeded());
        }
        let baseline_tolerance = parsed.cap_height.max(1.0) * 1.0e-9;
        if interpreter.point[1].abs() > baseline_tolerance
            || interpreter.point[0] < -baseline_tolerance
        {
            return Err(unsupported(
                "raw SHX glyphs must finish with a nonnegative horizontal advance",
            ));
        }
        let advance = if interpreter.point[0].abs() <= baseline_tolerance {
            0.0
        } else {
            interpreter.point[0]
        };
        glyphs.insert(
            format!("{:04X}", u32::from(character)),
            StrokeGlyphDocument {
                advance,
                maximum_error: interpreter.maximum_error,
                commands: interpreter.commands,
            },
        );
    }
    Ok(DecodedShx {
        source_format: parsed.source_format,
        document: StrokeFontDocument {
            schema: StrokeFontSchema::PortableShxV1,
            cap_height: parsed.cap_height,
            descent: parsed.descent,
            glyphs,
        },
    })
}

struct Interpreter<'a> {
    family: FontFamily,
    programs: &'a BTreeMap<u16, Vec<u8>>,
    active: Vec<u16>,
    point: [f64; 2],
    path_point: Option<[f64; 2]>,
    pen_down: bool,
    scale: f64,
    stack: Vec<[f64; 2]>,
    commands: Vec<StrokeCommandDocument>,
    maximum_error: f64,
    steps: usize,
}

impl<'a> Interpreter<'a> {
    fn new(family: FontFamily, programs: &'a BTreeMap<u16, Vec<u8>>) -> Self {
        Self {
            family,
            programs,
            active: Vec::new(),
            point: [0.0, 0.0],
            path_point: None,
            pen_down: true,
            scale: 1.0,
            stack: Vec::new(),
            commands: Vec::new(),
            maximum_error: 0.0,
            steps: 0,
        }
    }

    fn execute(&mut self, code: u16) -> Result<(), PortablePlotError> {
        if self.active.len() >= MAX_SUBSHAPE_DEPTH {
            return Err(budget_exceeded());
        }
        if self.active.contains(&code) {
            return Err(invalid_resource(
                "raw SHX subshape references must be acyclic",
            ));
        }
        let program = self
            .programs
            .get(&code)
            .ok_or_else(|| invalid_resource("raw SHX subshape references must resolve exactly"))?;
        self.active.push(code);
        let result = self.execute_program(program);
        self.active.pop();
        result
    }

    fn execute_program(&mut self, program: &[u8]) -> Result<(), PortablePlotError> {
        let mut cursor = 0_usize;
        while cursor < program.len() {
            self.step()?;
            let command = take_byte(program, &mut cursor)?;
            if command == 0 {
                return if cursor == program.len() {
                    Ok(())
                } else {
                    Err(invalid_resource(
                        "raw SHX glyph data cannot follow the end-of-shape marker",
                    ))
                };
            }
            if command > 0x0f {
                let length = f64::from(command >> 4) * self.scale;
                let direction = usize::from(command & 0x0f);
                let [dx, dy] = DIRECTION_VECTORS[direction];
                self.displace(dx * length, dy * length)?;
                continue;
            }
            match command {
                1 => self.pen_down = true,
                2 => self.pen_down = false,
                3 => {
                    let factor = take_nonzero_byte(program, &mut cursor)?;
                    self.set_scale(self.scale / f64::from(factor))?;
                }
                4 => {
                    let factor = take_nonzero_byte(program, &mut cursor)?;
                    self.set_scale(self.scale * f64::from(factor))?;
                }
                5 => {
                    if self.stack.len() == 4 {
                        return Err(invalid_resource(
                            "raw SHX position stack exceeds four locations",
                        ));
                    }
                    self.stack.push(self.point);
                }
                6 => {
                    self.point = self
                        .stack
                        .pop()
                        .ok_or_else(|| invalid_resource("raw SHX position stack underflowed"))?;
                    check_point(self.point)?;
                }
                7 => {
                    let subshape = match self.family {
                        FontFamily::Shapes => u16::from(take_byte(program, &mut cursor)?),
                        FontFamily::Unifont => take_u16_be(program, &mut cursor)?,
                    };
                    if subshape == 0 {
                        return Err(invalid_resource(
                            "raw SHX subshape references must be nonzero",
                        ));
                    }
                    self.execute(subshape)?;
                }
                8 => {
                    let dx = f64::from(take_i8(program, &mut cursor)?) * self.scale;
                    let dy = f64::from(take_i8(program, &mut cursor)?) * self.scale;
                    self.displace(dx, dy)?;
                }
                9 => loop {
                    self.step()?;
                    let dx = take_i8(program, &mut cursor)?;
                    let dy = take_i8(program, &mut cursor)?;
                    if dx == 0 && dy == 0 {
                        break;
                    }
                    self.displace(f64::from(dx) * self.scale, f64::from(dy) * self.scale)?;
                },
                10 => self.octant_arc(program, &mut cursor)?,
                11 => self.fractional_arc(program, &mut cursor)?,
                12 => {
                    let dx = take_i8(program, &mut cursor)?;
                    let dy = take_i8(program, &mut cursor)?;
                    let bulge = take_i8(program, &mut cursor)?;
                    self.bulge_arc(dx, dy, bulge)?;
                }
                13 => loop {
                    self.step()?;
                    let dx = take_i8(program, &mut cursor)?;
                    let dy = take_i8(program, &mut cursor)?;
                    if dx == 0 && dy == 0 {
                        break;
                    }
                    let bulge = take_i8(program, &mut cursor)?;
                    self.bulge_arc(dx, dy, bulge)?;
                },
                14 => skip_command(program, &mut cursor, self.family)?,
                _ => {
                    return Err(invalid_resource(
                        "raw SHX glyphs contain an unsupported command code",
                    ));
                }
            }
        }
        Err(invalid_resource(
            "raw SHX glyphs must end with an exact end-of-shape marker",
        ))
    }

    fn step(&mut self) -> Result<(), PortablePlotError> {
        self.steps = self.steps.checked_add(1).ok_or_else(budget_exceeded)?;
        if self.steps > MAX_STEPS_PER_GLYPH {
            return Err(budget_exceeded());
        }
        Ok(())
    }

    fn set_scale(&mut self, value: f64) -> Result<(), PortablePlotError> {
        if !value.is_finite() || value <= 0.0 || value > MAX_SCALE {
            return Err(invalid_resource(
                "raw SHX vector scale is zero, non-finite, or outside the fixed range",
            ));
        }
        self.scale = value;
        Ok(())
    }

    fn displace(&mut self, dx: f64, dy: f64) -> Result<(), PortablePlotError> {
        let next = [self.point[0] + dx, self.point[1] + dy];
        check_point(next)?;
        if self.pen_down && next != self.point {
            self.begin_ink()?;
            self.commands.push(StrokeCommandDocument::LineTo {
                x: next[0],
                y: next[1],
            });
            self.path_point = Some(next);
        }
        self.point = next;
        Ok(())
    }

    fn begin_ink(&mut self) -> Result<(), PortablePlotError> {
        check_point(self.point)?;
        if self.path_point != Some(self.point) {
            self.commands.push(StrokeCommandDocument::MoveTo {
                x: self.point[0],
                y: self.point[1],
            });
            self.path_point = Some(self.point);
        }
        Ok(())
    }

    fn octant_arc(&mut self, program: &[u8], cursor: &mut usize) -> Result<(), PortablePlotError> {
        let radius = f64::from(take_nonzero_byte(program, cursor)?) * self.scale;
        let flag = take_i8(program, cursor)?;
        let raw = flag as u8;
        let start_octant = u32::from((raw >> 4) & 0x07);
        let mut count = u32::from(raw & 0x07);
        if count == 0 {
            count = 8;
        }
        let direction = if flag < 0 { -1.0 } else { 1.0 };
        let start_angle = f64::from(start_octant) * PI / 4.0;
        let sweep = direction * f64::from(count) * PI / 4.0;
        self.circular_arc(radius, start_angle, sweep)
    }

    fn fractional_arc(
        &mut self,
        program: &[u8],
        cursor: &mut usize,
    ) -> Result<(), PortablePlotError> {
        let start_offset = u32::from(take_byte(program, cursor)?);
        let end_offset = u32::from(take_byte(program, cursor)?);
        let high_radius = u32::from(take_byte(program, cursor)?);
        let low_radius = u32::from(take_byte(program, cursor)?);
        let radius_units = high_radius * 256 + low_radius;
        let flag = take_i8(program, cursor)?;
        if radius_units == 0 {
            return Err(invalid());
        }
        let raw = flag as u8;
        let start_octant = u32::from((raw >> 4) & 0x07);
        let mut count = u32::from(raw & 0x07);
        if count == 0 {
            count = 8;
        }
        if end_offset != 0 {
            count = count.checked_sub(1).ok_or_else(invalid)?;
        }
        let direction = if flag < 0 { -1.0 } else { 1.0 };
        let offset_unit = (PI / 4.0) / 256.0;
        let start_angle =
            f64::from(start_octant) * PI / 4.0 + direction * f64::from(start_offset) * offset_unit;
        let sweep_units = f64::from(count) * PI / 4.0 + f64::from(end_offset) * offset_unit
            - f64::from(start_offset) * offset_unit;
        if sweep_units <= 0.0 || sweep_units > TAU {
            return Err(invalid());
        }
        self.circular_arc(
            f64::from(radius_units) * self.scale,
            start_angle,
            direction * sweep_units,
        )
    }

    fn bulge_arc(&mut self, dx: i8, dy: i8, bulge: i8) -> Result<(), PortablePlotError> {
        if dx == i8::MIN || dy == i8::MIN || bulge == i8::MIN {
            return Err(invalid_resource(
                "raw SHX bulge arcs cannot use the reserved -128 value",
            ));
        }
        let displacement = [f64::from(dx) * self.scale, f64::from(dy) * self.scale];
        if displacement == [0.0, 0.0] {
            return Err(invalid());
        }
        if bulge == 0 {
            return self.displace(displacement[0], displacement[1]);
        }
        let end = [
            self.point[0] + displacement[0],
            self.point[1] + displacement[1],
        ];
        check_point(end)?;
        let chord = displacement[0].hypot(displacement[1]);
        let normalized_bulge = f64::from(bulge) / 127.0;
        let center_offset = chord * (1.0 - normalized_bulge.powi(2)) / (4.0 * normalized_bulge);
        let midpoint = [
            (self.point[0] + end[0]) / 2.0,
            (self.point[1] + end[1]) / 2.0,
        ];
        let left = [-displacement[1] / chord, displacement[0] / chord];
        let center = [
            midpoint[0] + left[0] * center_offset,
            midpoint[1] + left[1] * center_offset,
        ];
        check_point(center)?;
        let radius = (self.point[0] - center[0]).hypot(self.point[1] - center[1]);
        let start_angle = (self.point[1] - center[1]).atan2(self.point[0] - center[0]);
        let sweep = 4.0 * normalized_bulge.atan();
        self.emit_arc(center, radius, start_angle, sweep, end)
    }

    fn circular_arc(
        &mut self,
        radius: f64,
        start_angle: f64,
        sweep: f64,
    ) -> Result<(), PortablePlotError> {
        if !radius.is_finite()
            || radius <= 0.0
            || radius > MAX_COORDINATE
            || !start_angle.is_finite()
            || !sweep.is_finite()
            || sweep == 0.0
            || sweep.abs() > TAU
        {
            return Err(invalid());
        }
        let center = [
            self.point[0] - radius * start_angle.cos(),
            self.point[1] - radius * start_angle.sin(),
        ];
        check_point(center)?;
        let end_angle = start_angle + sweep;
        let end = if (sweep.abs() - TAU).abs() <= f64::EPSILON * 16.0 {
            self.point
        } else {
            [
                center[0] + radius * end_angle.cos(),
                center[1] + radius * end_angle.sin(),
            ]
        };
        self.emit_arc(center, radius, start_angle, sweep, end)
    }

    fn emit_arc(
        &mut self,
        center: [f64; 2],
        radius: f64,
        start_angle: f64,
        sweep: f64,
        end: [f64; 2],
    ) -> Result<(), PortablePlotError> {
        check_point(end)?;
        if !self.pen_down {
            self.point = end;
            return Ok(());
        }
        self.begin_ink()?;
        let segments = (sweep.abs() / ARC_SEGMENT_SWEEP).ceil().max(1.0) as usize;
        let delta = sweep / segments as f64;
        let error = 2.0 * radius * delta.abs().powi(4) / 384.0;
        if !error.is_finite() {
            return Err(invalid());
        }
        self.maximum_error = self.maximum_error.max(error);
        for segment in 0..segments {
            let angle_0 = start_angle + delta * segment as f64;
            let angle_1 = angle_0 + delta;
            let point_0 = if segment == 0 {
                self.point
            } else {
                [
                    center[0] + radius * angle_0.cos(),
                    center[1] + radius * angle_0.sin(),
                ]
            };
            let point_1 = if segment + 1 == segments {
                end
            } else {
                [
                    center[0] + radius * angle_1.cos(),
                    center[1] + radius * angle_1.sin(),
                ]
            };
            let derivative_0 = [-radius * angle_0.sin(), radius * angle_0.cos()];
            let derivative_1 = [-radius * angle_1.sin(), radius * angle_1.cos()];
            let control_1 = [
                point_0[0] + derivative_0[0] * delta / 3.0,
                point_0[1] + derivative_0[1] * delta / 3.0,
            ];
            let control_2 = [
                point_1[0] - derivative_1[0] * delta / 3.0,
                point_1[1] - derivative_1[1] * delta / 3.0,
            ];
            check_point(control_1)?;
            check_point(control_2)?;
            check_point(point_1)?;
            self.commands.push(StrokeCommandDocument::CubicTo {
                control_1,
                control_2,
                end: point_1,
            });
            self.path_point = Some(point_1);
        }
        self.point = end;
        Ok(())
    }
}

const DIRECTION_VECTORS: [[f64; 2]; 16] = [
    [1.0, 0.0],
    [1.0, 0.5],
    [1.0, 1.0],
    [0.5, 1.0],
    [0.0, 1.0],
    [-0.5, 1.0],
    [-1.0, 1.0],
    [-1.0, 0.5],
    [-1.0, 0.0],
    [-1.0, -0.5],
    [-1.0, -1.0],
    [-0.5, -1.0],
    [0.0, -1.0],
    [0.5, -1.0],
    [1.0, -1.0],
    [1.0, -0.5],
];

fn skip_command(
    program: &[u8],
    cursor: &mut usize,
    family: FontFamily,
) -> Result<(), PortablePlotError> {
    let command = take_byte(program, cursor)?;
    if command > 0x0f {
        return Ok(());
    }
    match command {
        0 | 1 | 2 | 5 | 6 | 14 => {}
        3 | 4 => {
            take_byte(program, cursor)?;
        }
        7 => match family {
            FontFamily::Shapes => {
                take_byte(program, cursor)?;
            }
            FontFamily::Unifont => {
                take_u16_be(program, cursor)?;
            }
        },
        8 => {
            take_byte(program, cursor)?;
            take_byte(program, cursor)?;
        }
        9 => loop {
            let x = take_byte(program, cursor)?;
            let y = take_byte(program, cursor)?;
            if x == 0 && y == 0 {
                break;
            }
        },
        10 => {
            take_byte(program, cursor)?;
            take_byte(program, cursor)?;
        }
        11 => {
            take_exact(program, cursor, 5)?;
        }
        12 => {
            take_exact(program, cursor, 3)?;
        }
        13 => loop {
            let x = take_byte(program, cursor)?;
            let y = take_byte(program, cursor)?;
            if x == 0 && y == 0 {
                break;
            }
            take_byte(program, cursor)?;
        },
        _ => return Err(invalid()),
    }
    Ok(())
}

fn take_exact<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> Result<&'a [u8], PortablePlotError> {
    let end = cursor.checked_add(length).ok_or_else(invalid)?;
    let result = bytes.get(*cursor..end).ok_or_else(invalid)?;
    *cursor = end;
    Ok(result)
}

fn take_byte(bytes: &[u8], cursor: &mut usize) -> Result<u8, PortablePlotError> {
    Ok(take_exact(bytes, cursor, 1)?[0])
}

fn take_nonzero_byte(bytes: &[u8], cursor: &mut usize) -> Result<u8, PortablePlotError> {
    let byte = take_byte(bytes, cursor)?;
    if byte == 0 {
        Err(invalid())
    } else {
        Ok(byte)
    }
}

fn take_i8(bytes: &[u8], cursor: &mut usize) -> Result<i8, PortablePlotError> {
    Ok(take_byte(bytes, cursor)? as i8)
}

fn take_u16_be(bytes: &[u8], cursor: &mut usize) -> Result<u16, PortablePlotError> {
    let value: [u8; 2] = take_exact(bytes, cursor, 2)?
        .try_into()
        .map_err(|_| invalid())?;
    Ok(u16::from_be_bytes(value))
}

fn check_point(point: [f64; 2]) -> Result<(), PortablePlotError> {
    if point
        .iter()
        .any(|coordinate| !coordinate.is_finite() || coordinate.abs() > MAX_COORDINATE)
    {
        return Err(invalid_resource(
            "raw SHX geometry is non-finite or outside the fixed coordinate range",
        ));
    }
    Ok(())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], PortablePlotError> {
        take_exact(self.bytes, &mut self.position, length)
    }

    fn read_u16(&mut self) -> Result<u16, PortablePlotError> {
        let value: [u8; 2] = self.take(2)?.try_into().map_err(|_| invalid())?;
        Ok(u16::from_le_bytes(value))
    }

    fn read_u32(&mut self) -> Result<u32, PortablePlotError> {
        let value: [u8; 4] = self.take(4)?.try_into().map_err(|_| invalid())?;
        Ok(u32::from_le_bytes(value))
    }

    fn finish(self) -> Result<(), PortablePlotError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(invalid())
        }
    }
}

fn invalid() -> PortablePlotError {
    invalid_resource("raw SHX bytes do not conform to the bounded admission contract")
}

fn unsupported(message: &'static str) -> PortablePlotError {
    PortablePlotError::new("stroke_font_shx_unsupported", message)
}

fn budget_exceeded() -> PortablePlotError {
    PortablePlotError::new(
        "stroke_font_resource_budget_exceeded",
        "raw SHX admission exceeds a fixed parsing or expansion budget",
    )
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::portable_plot::ResourceDigest;

    fn record(program: &[u8]) -> Vec<u8> {
        let mut result = vec![0];
        result.extend_from_slice(program);
        result
    }

    fn unifont_with_info(info: Vec<u8>, glyphs: &[(u16, Vec<u8>)]) -> Arc<[u8]> {
        let mut bytes = UNIFONT_1_0_HEADER.to_vec();
        bytes.extend_from_slice(&u32::try_from(glyphs.len() + 1).unwrap().to_le_bytes());
        bytes.extend_from_slice(&u16::try_from(info.len()).unwrap().to_le_bytes());
        bytes.extend_from_slice(&info);
        for (code, data) in glyphs {
            bytes.extend_from_slice(&code.to_le_bytes());
            bytes.extend_from_slice(&u16::try_from(data.len()).unwrap().to_le_bytes());
            bytes.extend_from_slice(data);
        }
        Arc::from(bytes)
    }

    fn unifont(glyphs: &[(u16, Vec<u8>)]) -> Arc<[u8]> {
        unifont_with_info(
            [b"Test Unicode".as_slice(), &[0, 10, 2, 2, 0, 0, 0]].concat(),
            glyphs,
        )
    }

    fn shapes(glyphs: &[(u16, Vec<u8>)]) -> Arc<[u8]> {
        let info = [b"Test Legacy".as_slice(), &[0, 10, 2, 2, 0]].concat();
        let mut records = vec![(0_u16, info)];
        records.extend(glyphs.iter().cloned());
        let end = records.iter().map(|(code, _)| *code).max().unwrap();
        let mut bytes = SHAPES_1_0_HEADER.to_vec();
        bytes.extend_from_slice(&0_u16.to_le_bytes());
        bytes.extend_from_slice(&end.to_le_bytes());
        bytes.extend_from_slice(&u16::try_from(records.len()).unwrap().to_le_bytes());
        for (code, data) in &records {
            bytes.extend_from_slice(&code.to_le_bytes());
            bytes.extend_from_slice(&u16::try_from(data.len()).unwrap().to_le_bytes());
        }
        for (_, data) in records {
            bytes.extend_from_slice(&data);
        }
        Arc::from(bytes)
    }

    fn simple_a() -> Vec<u8> {
        // Two ink vectors followed by a pen-up advance to (8, 0).
        record(&[0x42, 0x4a, 2, 8, 8, 0, 0])
    }

    fn space() -> Vec<u8> {
        record(&[2, 8, 4, 0, 0])
    }

    fn admit(
        bytes: Arc<[u8]>,
        options: &super::super::ShxAdmissionOptions,
    ) -> Result<super::super::ShxStrokeFontResource, PortablePlotError> {
        super::super::ShxStrokeFontResource::from_shx(
            "fonts/test.shx",
            bytes.clone(),
            ResourceDigest::of(&bytes),
            options,
        )
    }

    #[test]
    fn unifont_admission_binds_exact_source_and_canonical_semantics() {
        let first_bytes = unifont(&[(0x20, space()), (0x41, simple_a())]);
        let first = admit(first_bytes.clone(), &Default::default()).unwrap();
        assert_eq!(first.source_format(), "autocad_shx_unifont_1_0");
        assert_eq!(first.digest(), ResourceDigest::of(&first_bytes));
        assert_eq!(first.cap_height(), 10.0);
        assert_eq!(first.descent(), 2.0);
        assert_eq!(first.glyph(' ').unwrap().advance(), 4.0);
        assert!(first.glyph(' ').unwrap().commands().is_empty());
        assert_eq!(first.glyph('A').unwrap().advance(), 8.0);
        assert_eq!(first.glyph('A').unwrap().commands().len(), 3);

        let renamed = unifont_with_info(
            [b"Renamed".as_slice(), &[0, 10, 2, 2, 0, 0, 0]].concat(),
            &[(0x20, space()), (0x41, simple_a())],
        );
        let second = admit(renamed, &Default::default()).unwrap();
        assert_ne!(first.digest(), second.digest());
        assert_eq!(first.semantic_digest(), second.semantic_digest());
    }

    #[test]
    fn legacy_admission_uses_canonical_and_explicit_character_mappings() {
        let bytes = shapes(&[(0x41, simple_a()), (0x80, simple_a()), (256, simple_a())]);
        let options = super::super::ShxAdmissionOptions::new()
            .with_legacy_code_point(0x80, '\u{20ac}')
            .unwrap();
        let resource = admit(bytes, &options).unwrap();
        assert_eq!(resource.source_format(), "autocad_shx_shapes_1_0");
        assert!(resource.glyph('A').is_some());
        assert!(resource.glyph('\u{20ac}').is_some());
        assert!(resource.glyph('\u{00b0}').is_some());
        assert_eq!(resource.legacy_code_points().get(&0x80), Some(&'\u{20ac}'));
    }

    #[test]
    fn every_documented_command_family_is_interpreted_or_skipped_exactly() {
        let programs = BTreeMap::from([
            // Subshape: scale, push/pop, vector, pen-up return, balanced end.
            (1, vec![3, 2, 4, 2, 5, 0x20, 6, 2, 8, 4, 0, 1, 0]),
            // Parent: skip a vertical-only displacement, call subshape, then
            // direct/poly displacements and each arc family before ending.
            (
                65,
                vec![
                    14, 8, 99, 99, 7, 1, 8, 1, 0, 9, 1, 0, 0, 0, 10, 2, 1, 11, 0, 0, 0, 2, 1, 12,
                    2, 0, 0, 13, 2, 0, 0, 0, 0, 0,
                ],
            ),
        ]);
        let mut interpreter = Interpreter::new(FontFamily::Shapes, &programs);
        interpreter.execute(65).unwrap();
        assert!(interpreter
            .commands
            .iter()
            .any(|command| matches!(command, StrokeCommandDocument::CubicTo { .. })));
        assert!(interpreter.maximum_error > 0.0);
        assert!(interpreter.point[0] < 99.0);
        assert!(interpreter.stack.is_empty());
    }

    #[test]
    fn malformed_containers_mappings_and_embedding_fail_closed() {
        let bytes = unifont(&[(0x41, simple_a())]);
        let mut truncated = bytes.to_vec();
        truncated.pop();
        let truncated: Arc<[u8]> = Arc::from(truncated);
        assert_eq!(
            admit(truncated, &Default::default()).unwrap_err().code(),
            "stroke_font_resource_invalid"
        );

        let restricted = unifont_with_info(
            [b"Restricted".as_slice(), &[0, 10, 2, 2, 0, 1, 0]].concat(),
            &[(0x41, simple_a())],
        );
        assert_eq!(
            admit(restricted, &Default::default()).unwrap_err().code(),
            "stroke_font_shx_unsupported"
        );

        let legacy = shapes(&[(0x41, simple_a())]);
        let absent = super::super::ShxAdmissionOptions::new()
            .with_legacy_code_point(0x80, '\u{20ac}')
            .unwrap();
        assert_eq!(
            admit(legacy.clone(), &absent).unwrap_err().code(),
            "stroke_font_resource_invalid"
        );
        let contradictory = super::super::ShxAdmissionOptions::new()
            .with_legacy_code_point(0x41, 'B')
            .unwrap();
        assert_eq!(
            admit(legacy, &contradictory).unwrap_err().code(),
            "stroke_font_resource_invalid"
        );
    }

    #[test]
    fn malformed_programs_cycles_stack_and_digest_fail_closed() {
        let cycle = shapes(&[(0x41, record(&[7, 66, 0])), (66, record(&[7, 65, 0]))]);
        assert_eq!(
            admit(cycle, &Default::default()).unwrap_err().code(),
            "stroke_font_resource_invalid"
        );

        let stack = shapes(&[(0x41, record(&[5, 0]))]);
        assert_eq!(
            admit(stack, &Default::default()).unwrap_err().code(),
            "stroke_font_resource_invalid"
        );

        let zero_scale = shapes(&[(0x41, record(&[3, 0, 0]))]);
        assert_eq!(
            admit(zero_scale, &Default::default()).unwrap_err().code(),
            "stroke_font_resource_invalid"
        );

        let malformed_skip = shapes(&[(0x41, record(&[14, 8, 1, 0]))]);
        assert_eq!(
            admit(malformed_skip, &Default::default())
                .unwrap_err()
                .code(),
            "stroke_font_resource_invalid"
        );

        let bytes = unifont(&[(0x41, simple_a())]);
        assert_eq!(
            super::super::ShxStrokeFontResource::from_shx(
                "fonts/test.shx",
                bytes,
                ResourceDigest::of(b"different"),
                &Default::default(),
            )
            .unwrap_err()
            .code(),
            "resource_digest_mismatch"
        );
    }

    #[test]
    fn plain_shape_and_bigfont_families_are_explicitly_unsupported() {
        let mut plain = SHAPES_1_0_HEADER.to_vec();
        plain.extend_from_slice(&1_u16.to_le_bytes());
        plain.extend_from_slice(&1_u16.to_le_bytes());
        plain.extend_from_slice(&1_u16.to_le_bytes());
        plain.extend_from_slice(&1_u16.to_le_bytes());
        plain.extend_from_slice(&3_u16.to_le_bytes());
        plain.extend_from_slice(&[0, 0x10, 0]);
        let plain: Arc<[u8]> = Arc::from(plain);
        assert_eq!(
            admit(plain, &Default::default()).unwrap_err().code(),
            "stroke_font_shx_unsupported"
        );

        let bigfont: Arc<[u8]> = Arc::from(b"AutoCAD-86 bigfont 1.0\r\n\x1a".as_slice());
        assert_eq!(
            admit(bigfont, &Default::default()).unwrap_err().code(),
            "stroke_font_shx_unsupported"
        );
    }
}
