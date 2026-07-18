//! Exact-HIR, literal-anchored capture-count reducer for the pinned Rebar
//! `# noqa` grep family.
//!
//! This module is deliberately private while the proof kernel is exercised in
//! isolation. It recognizes three exact HIRs; it is not a general regular
//! expression optimizer.

use core::fmt;

use regex_syntax::hir::{Capture, Class, Hir, HirKind, Repetition};

const ASCII_SPACE_RANGES: &[(u32, u32)] = &[(0x09, 0x0D), (0x20, 0x20)];
const UNICODE_SPACE_RANGES: &[(u32, u32)] = &[
    (0x09, 0x0D),
    (0x20, 0x20),
    (0x85, 0x85),
    (0xA0, 0xA0),
    (0x1680, 0x1680),
    (0x2000, 0x200A),
    (0x2028, 0x2029),
    (0x202F, 0x202F),
    (0x205F, 0x205F),
    (0x3000, 0x3000),
];
const ASCII_SEPARATOR_RANGES: &[(u32, u32)] = &[(0x09, 0x0D), (0x20, 0x20), (0x2C, 0x2C)];
const UNICODE_SEPARATOR_RANGES: &[(u32, u32)] = &[
    (0x09, 0x0D),
    (0x20, 0x20),
    (0x2C, 0x2C),
    (0x85, 0x85),
    (0xA0, 0xA0),
    (0x1680, 0x1680),
    (0x2000, 0x200A),
    (0x2028, 0x2029),
    (0x202F, 0x202F),
    (0x205F, 0x205F),
    (0x3000, 0x3000),
];

/// Exact recognized syntax and reducer route.
#[allow(
    clippy::enum_variant_names,
    reason = "the route names state both whitespace semantics and prefix participation"
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum NoqaVariant {
    /// `\s*` is ASCII-only and participates as capture 1.
    AsciiLeading,
    /// The match begins at `# ` and has no leading capture.
    AsciiNoLeading,
    /// `\s*` uses the pinned Unicode `White_Space` class and participates.
    UnicodeLeading,
}

impl NoqaVariant {
    const fn schema_captures(self) -> usize {
        match self {
            Self::AsciiNoLeading => 3,
            Self::AsciiLeading | Self::UnicodeLeading => 5,
        }
    }

    const fn base_captures(self) -> usize {
        match self {
            Self::AsciiNoLeading => 1,
            Self::AsciiLeading | Self::UnicodeLeading => 3,
        }
    }

    const fn unicode_space(self) -> bool {
        matches!(self, Self::UnicodeLeading)
    }
}

/// Exact construction budget for HIR inspection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct NoqaBuildLimits {
    pub max_work: usize,
}

impl Default for NoqaBuildLimits {
    fn default() -> Self {
        Self { max_work: 4_096 }
    }
}

/// Metered exact-HIR inspection receipt.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct NoqaBuildAccounting {
    pub work: usize,
    pub hir_nodes: usize,
    pub literal_bytes: usize,
    pub class_ranges: usize,
}

/// Prospective HIR inspection refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum NoqaBuildError {
    WorkLimit { required: usize, limit: usize },
    Overflow,
}

impl fmt::Display for NoqaBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WorkLimit { required, limit } => write!(
                formatter,
                "noqa HIR inspection needs {required} work, limit is {limit}"
            ),
            Self::Overflow => formatter.write_str("noqa HIR inspection accounting overflowed"),
        }
    }
}

impl std::error::Error for NoqaBuildError {}

/// Immutable exact-shape plan. It contains no compiled automaton or dynamic
/// storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct NoqaPlan {
    variant: NoqaVariant,
    build: NoqaBuildAccounting,
}

impl NoqaPlan {
    /// Inspect one HIR. `Ok(None)` is an exact typed non-selection, not a
    /// partially compatible plan.
    pub(super) fn inspect(
        hir: &Hir,
        limits: NoqaBuildLimits,
    ) -> Result<Option<Self>, NoqaBuildError> {
        let mut inspector = Inspector::new(limits.max_work);
        let variant = inspector.inspect_root(hir)?;
        Ok(variant.map(|variant| Self {
            variant,
            build: inspector.accounting,
        }))
    }

    pub(super) const fn variant(self) -> NoqaVariant {
        self.variant
    }

    pub(super) const fn build_accounting(self) -> NoqaBuildAccounting {
        self.build
    }

    /// Count participating captures over bstr-compatible lines. Empty input
    /// has no lines. LF is removed, and the CR immediately preceding LF is
    /// removed; a lone CR remains part of its line.
    pub(super) fn count_captures(
        self,
        haystack: &[u8],
        limits: NoqaRunLimits,
    ) -> Result<NoqaRunOutcome, NoqaRunError> {
        if haystack.is_empty() {
            return Ok(NoqaRunOutcome {
                capture_count: 0,
                report: NoqaRunReport {
                    bounds: NoqaUpperBounds::ZERO,
                    actual: NoqaActualCounters::default(),
                },
            });
        }

        // The line census is itself admitted before its first byte read.
        require(NoqaResource::Work, haystack.len(), limits.max_work)?;
        require(
            NoqaResource::SequentialBytes,
            haystack.len(),
            limits.max_sequential_bytes,
        )?;
        let census = census_lines(haystack)?;
        let bounds = upper_bounds(self.variant, haystack.len(), census)?;

        // All candidate, replay, and reduction work is admitted before the
        // second traversal begins.
        require(NoqaResource::Work, bounds.work, limits.max_work)?;
        require(
            NoqaResource::SequentialBytes,
            bounds.sequential_bytes,
            limits.max_sequential_bytes,
        )?;
        require(
            NoqaResource::CaptureEvents,
            bounds.capture_events,
            limits.max_capture_events,
        )?;
        require(
            NoqaResource::CaptureCount,
            bounds.capture_count,
            limits.max_capture_count,
        )?;

        let mut actual = NoqaActualCounters {
            lines: census.lines,
            ..NoqaActualCounters::default()
        };
        for_each_line(haystack, |line| {
            reduce_line(self.variant, line, &mut actual)
        })?;
        let capture_count = actual.capture_count;
        Ok(NoqaRunOutcome {
            capture_count,
            report: NoqaRunReport { bounds, actual },
        })
    }
}

/// Complete prospective execution limits.
#[allow(
    clippy::struct_field_names,
    reason = "every field is an independently enforced maximum in the public limit identity"
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct NoqaRunLimits {
    pub max_work: usize,
    pub max_sequential_bytes: usize,
    pub max_capture_events: usize,
    pub max_capture_count: usize,
}

impl Default for NoqaRunLimits {
    fn default() -> Self {
        Self {
            max_work: 512 * 1_048_576,
            max_sequential_bytes: 384 * 1_048_576,
            max_capture_events: 1_000_000_000,
            max_capture_count: 1_000_000_000,
        }
    }
}

/// Resource named by a prospective execution refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum NoqaResource {
    Work,
    SequentialBytes,
    CaptureEvents,
    CaptureCount,
}

/// Prospective execution refusal. No candidate has been examined when any of
/// these errors is returned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum NoqaRunError {
    Resource {
        resource: NoqaResource,
        required: usize,
        limit: usize,
    },
    Overflow,
}

impl fmt::Display for NoqaRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resource {
                resource,
                required,
                limit,
            } => write!(
                formatter,
                "noqa reducer needs {required} {resource:?}, limit is {limit}"
            ),
            Self::Overflow => formatter.write_str("noqa reducer accounting overflowed"),
        }
    }
}

impl std::error::Error for NoqaRunError {}

/// Route-specific whole-input upper bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct NoqaUpperBounds {
    pub haystack_bytes: usize,
    pub line_bytes: usize,
    pub lines: usize,
    pub literal_candidates: usize,
    pub work: usize,
    pub sequential_bytes: usize,
    pub capture_events: usize,
    pub capture_count: usize,
}

impl NoqaUpperBounds {
    const ZERO: Self = Self {
        haystack_bytes: 0,
        line_bytes: 0,
        lines: 0,
        literal_candidates: 0,
        work: 0,
        sequential_bytes: 0,
        capture_events: 0,
        capture_count: 0,
    };
}

/// Scalar actual counters. The reducer owns no dynamic scratch.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct NoqaActualCounters {
    pub lines: usize,
    pub candidate_positions: usize,
    pub literal_candidates: usize,
    pub matches: usize,
    pub coded_matches: usize,
    pub capture_events: usize,
    pub capture_count: usize,
}

/// Successful execution receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct NoqaRunReport {
    pub bounds: NoqaUpperBounds,
    pub actual: NoqaActualCounters,
}

/// Reduced value and complete receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct NoqaRunOutcome {
    pub capture_count: usize,
    pub report: NoqaRunReport,
}

#[derive(Clone, Copy)]
struct LineCensus {
    bytes: usize,
    lines: usize,
}

fn census_lines(haystack: &[u8]) -> Result<LineCensus, NoqaRunError> {
    let mut start = 0_usize;
    let mut bytes = 0_usize;
    let mut lines = 0_usize;
    for (index, byte) in haystack.iter().copied().enumerate() {
        if byte != b'\n' {
            continue;
        }
        let raw_length = index.checked_sub(start).ok_or(NoqaRunError::Overflow)?;
        let preceding = index
            .checked_sub(1)
            .and_then(|previous| haystack.get(previous));
        let stripped = usize::from(raw_length > 0 && preceding == Some(&b'\r'));
        let line_bytes = raw_length
            .checked_sub(stripped)
            .ok_or(NoqaRunError::Overflow)?;
        bytes = add(bytes, line_bytes)?;
        lines = add(lines, 1)?;
        start = add(index, 1)?;
    }
    if start < haystack.len() {
        let trailing = haystack
            .len()
            .checked_sub(start)
            .ok_or(NoqaRunError::Overflow)?;
        bytes = add(bytes, trailing)?;
        lines = add(lines, 1)?;
    }
    Ok(LineCensus { bytes, lines })
}

fn upper_bounds(
    variant: NoqaVariant,
    haystack_bytes: usize,
    census: LineCensus,
) -> Result<NoqaUpperBounds, NoqaRunError> {
    let candidates = census.bytes / 2;
    // Manual literal scan: <=2B byte checks. Case checks: <=4C. The
    // remaining route-specific replay bounds are ASCII-leading <=5B,
    // ASCII-no-leading <=3B, and Unicode-leading <=9B. Reducer/control is
    // <=2C+2. Sequential accounting charges the corresponding byte visits.
    let (work_bytes_factor, sequential_bytes_factor) = match variant {
        NoqaVariant::AsciiLeading => (7, 4),
        NoqaVariant::AsciiNoLeading => (5, 3),
        NoqaVariant::UnicodeLeading => (11, 8),
    };
    let work = checked_sum(&[
        haystack_bytes,
        mul(census.bytes, work_bytes_factor)?,
        mul(candidates, 6)?,
        2,
    ])?;
    let sequential_bytes = checked_sum(&[
        haystack_bytes,
        mul(census.bytes, sequential_bytes_factor)?,
        mul(candidates, 4)?,
    ])?;
    let capture_count = mul(candidates, variant.schema_captures())?;
    let capture_events = add(census.lines, capture_count)?;
    Ok(NoqaUpperBounds {
        haystack_bytes,
        line_bytes: census.bytes,
        lines: census.lines,
        literal_candidates: candidates,
        work,
        sequential_bytes,
        capture_events,
        capture_count,
    })
}

fn for_each_line(
    haystack: &[u8],
    mut visit: impl FnMut(&[u8]) -> Result<(), NoqaRunError>,
) -> Result<(), NoqaRunError> {
    let mut start = 0_usize;
    while start < haystack.len() {
        let mut end = start;
        while end < haystack.len() && haystack[end] != b'\n' {
            end = add(end, 1)?;
        }
        let mut content_end = end;
        let previous = content_end
            .checked_sub(1)
            .filter(|_| end < haystack.len() && content_end > start);
        if previous.and_then(|index| haystack.get(index)) == Some(&b'\r') {
            content_end = previous.ok_or(NoqaRunError::Overflow)?;
        }
        visit(&haystack[start..content_end])?;
        if end == haystack.len() {
            break;
        }
        start = add(end, 1)?;
    }
    Ok(())
}

fn reduce_line(
    variant: NoqaVariant,
    line: &[u8],
    actual: &mut NoqaActualCounters,
) -> Result<(), NoqaRunError> {
    let mut cursor = 0_usize;
    let mut scan = 0_usize;
    while scan < line.len() {
        actual.candidate_positions = add(actual.candidate_positions, 1)?;
        let next = scan.checked_add(1).and_then(|index| line.get(index));
        if line[scan] != b'#' || next != Some(&b' ') {
            scan = add(scan, 1)?;
            continue;
        }
        actual.literal_candidates = add(actual.literal_candidates, 1)?;
        let Some(base_end) = noqa_base_end(line, scan) else {
            scan = add(scan, 1)?;
            continue;
        };
        let (end, coded) = noqa_end(line, base_end, variant.unicode_space())?;
        let start = match variant {
            NoqaVariant::AsciiNoLeading => scan,
            NoqaVariant::AsciiLeading => leading_ascii_start(line, scan, cursor)?,
            NoqaVariant::UnicodeLeading => leading_unicode_start(line, scan, cursor)?,
        };
        if start < cursor {
            return Err(NoqaRunError::Overflow);
        }
        actual.matches = add(actual.matches, 1)?;
        if coded {
            actual.coded_matches = add(actual.coded_matches, 1)?;
        }
        let coded_captures = if coded { 2 } else { 0 };
        let participating = add(variant.base_captures(), coded_captures)?;
        actual.capture_count = add(actual.capture_count, participating)?;
        actual.capture_events = add(actual.capture_events, participating)?;
        cursor = end;
        scan = end;
    }
    actual.capture_events = add(actual.capture_events, 1)?;
    Ok(())
}

fn noqa_base_end(line: &[u8], start: usize) -> Option<usize> {
    let letters_start = start.checked_add(2)?;
    let end = start.checked_add(6)?;
    let letters = line.get(letters_start..end)?;
    if matches!(
        letters,
        [b'n' | b'N', b'o' | b'O', b'q' | b'Q', b'a' | b'A']
    ) {
        Some(end)
    } else {
        None
    }
}

fn noqa_end(
    line: &[u8],
    base_end: usize,
    unicode_space: bool,
) -> Result<(usize, bool), NoqaRunError> {
    if line.get(base_end) != Some(&b':') {
        return Ok((base_end, false));
    }
    let mut code_start = add(base_end, 1)?;
    if let Some(width) = space_forward(line, code_start, unicode_space) {
        code_start = add(code_start, width)?;
    }
    Ok(parse_codes(line, code_start, unicode_space)?.map_or((base_end, false), |end| (end, true)))
}

fn parse_codes(
    line: &[u8],
    mut cursor: usize,
    unicode_space: bool,
) -> Result<Option<usize>, NoqaRunError> {
    let mut committed = None;
    loop {
        let uppercase_start = cursor;
        while line.get(cursor).is_some_and(u8::is_ascii_uppercase) {
            cursor = add(cursor, 1)?;
        }
        if cursor == uppercase_start {
            break;
        }
        let digit_start = cursor;
        while line.get(cursor).is_some_and(u8::is_ascii_digit) {
            cursor = add(cursor, 1)?;
        }
        if cursor == digit_start {
            break;
        }
        committed = Some(cursor);
        loop {
            if line.get(cursor) == Some(&b',') {
                cursor = add(cursor, 1)?;
                committed = Some(cursor);
                continue;
            }
            let Some(width) = space_forward(line, cursor, unicode_space) else {
                break;
            };
            cursor = add(cursor, width)?;
            committed = Some(cursor);
        }
    }
    Ok(committed)
}

fn leading_ascii_start(
    line: &[u8],
    mut cursor: usize,
    floor: usize,
) -> Result<usize, NoqaRunError> {
    while cursor > floor {
        let previous = cursor.checked_sub(1).ok_or(NoqaRunError::Overflow)?;
        if !is_ascii_space(line[previous]) {
            break;
        }
        cursor = previous;
    }
    Ok(cursor)
}

fn leading_unicode_start(
    line: &[u8],
    mut cursor: usize,
    floor: usize,
) -> Result<usize, NoqaRunError> {
    while cursor > floor {
        let Some(width) = unicode_space_backward(line, cursor, floor) else {
            break;
        };
        cursor = cursor.checked_sub(width).ok_or(NoqaRunError::Overflow)?;
    }
    Ok(cursor)
}

const fn is_ascii_space(byte: u8) -> bool {
    matches!(byte, b'\t'..=b'\r' | b' ')
}

fn space_forward(input: &[u8], start: usize, unicode: bool) -> Option<usize> {
    let first = *input.get(start)?;
    if is_ascii_space(first) {
        return Some(1);
    }
    if !unicode {
        return None;
    }
    match input.get(start..) {
        Some([0xC2, 0x85 | 0xA0, ..]) => Some(2),
        Some(
            [0xE1, 0x9A, 0x80, ..]
            | [0xE2, 0x80, 0x80..=0x8A | 0xA8 | 0xA9 | 0xAF, ..]
            | [0xE2, 0x81, 0x9F, ..]
            | [0xE3, 0x80, 0x80, ..],
        ) => Some(3),
        _ => None,
    }
}

fn unicode_space_backward(input: &[u8], end: usize, floor: usize) -> Option<usize> {
    let distance = end.checked_sub(floor)?;
    let previous = end.checked_sub(1)?;
    if distance >= 1 && is_ascii_space(*input.get(previous)?) {
        return Some(1);
    }
    let two_start = end.checked_sub(2)?;
    if distance >= 2 && matches!(input.get(two_start..end)?, [0xC2, 0x85 | 0xA0]) {
        return Some(2);
    }
    let three_start = end.checked_sub(3)?;
    if distance >= 3
        && matches!(
            input.get(three_start..end)?,
            [0xE1, 0x9A, 0x80]
                | [0xE2, 0x80, 0x80..=0x8A | 0xA8 | 0xA9 | 0xAF]
                | [0xE2, 0x81, 0x9F]
                | [0xE3, 0x80, 0x80]
        )
    {
        return Some(3);
    }
    None
}

fn require(resource: NoqaResource, required: usize, limit: usize) -> Result<(), NoqaRunError> {
    if required > limit {
        return Err(NoqaRunError::Resource {
            resource,
            required,
            limit,
        });
    }
    Ok(())
}

fn add(left: usize, right: usize) -> Result<usize, NoqaRunError> {
    left.checked_add(right).ok_or(NoqaRunError::Overflow)
}

fn mul(left: usize, right: usize) -> Result<usize, NoqaRunError> {
    left.checked_mul(right).ok_or(NoqaRunError::Overflow)
}

fn checked_sum(values: &[usize]) -> Result<usize, NoqaRunError> {
    values
        .iter()
        .try_fold(0_usize, |sum, value| add(sum, *value))
}

struct Inspector {
    limit: usize,
    accounting: NoqaBuildAccounting,
}

impl Inspector {
    const fn new(limit: usize) -> Self {
        Self {
            limit,
            accounting: NoqaBuildAccounting {
                work: 0,
                hir_nodes: 0,
                literal_bytes: 0,
                class_ranges: 0,
            },
        }
    }

    fn inspect_root(&mut self, hir: &Hir) -> Result<Option<NoqaVariant>, NoqaBuildError> {
        let Some(children) = self.concat(hir)? else {
            return Ok(None);
        };
        match children {
            [prefix_hir, body_hir] => {
                let Some(prefix) = self.capture(prefix_hir)? else {
                    return Ok(None);
                };
                let Some(body) = self.capture(body_hir)? else {
                    return Ok(None);
                };
                let variant = match (
                    prefix.index,
                    prefix.name.as_deref(),
                    body.index,
                    body.name.as_deref(),
                ) {
                    (1, None, 2, None) => NoqaVariant::AsciiLeading,
                    (1, Some("spaces"), 2, Some("noqa")) => NoqaVariant::UnicodeLeading,
                    _ => return Ok(None),
                };
                if !self.prefix(prefix, variant)? || !self.body(&body.sub, variant, 3, 4)? {
                    return Ok(None);
                }
                Ok(Some(variant))
            }
            [_, _, _, _, _, _] => {
                let variant = NoqaVariant::AsciiNoLeading;
                if self.body_children(children, variant, 1, 2)? {
                    Ok(Some(variant))
                } else {
                    Ok(None)
                }
            }
            _ => Ok(None),
        }
    }

    fn prefix(&mut self, capture: &Capture, variant: NoqaVariant) -> Result<bool, NoqaBuildError> {
        let Some(repetition) = self.repetition(&capture.sub)? else {
            return Ok(false);
        };
        if !repeat_is(repetition, 0, None) {
            return Ok(false);
        }
        let ranges = if variant.unicode_space() {
            UNICODE_SPACE_RANGES
        } else {
            ASCII_SPACE_RANGES
        };
        self.exact_class(&repetition.sub, variant.unicode_space(), ranges)
    }

    fn body(
        &mut self,
        hir: &Hir,
        variant: NoqaVariant,
        codes_index: u32,
        inner_index: u32,
    ) -> Result<bool, NoqaBuildError> {
        let Some(children) = self.concat(hir)? else {
            return Ok(false);
        };
        self.body_children(children, variant, codes_index, inner_index)
    }

    fn body_children(
        &mut self,
        children: &[Hir],
        variant: NoqaVariant,
        codes_index: u32,
        inner_index: u32,
    ) -> Result<bool, NoqaBuildError> {
        let [literal, n, o, q, a, suffix] = children else {
            return Ok(false);
        };
        let unicode = variant.unicode_space();
        if !self.literal(literal, b"# ")?
            || !self.ascii_pair(n, unicode, b'N', b'n')?
            || !self.ascii_pair(o, unicode, b'O', b'o')?
            || !self.ascii_pair(q, unicode, b'Q', b'q')?
            || !self.ascii_pair(a, unicode, b'A', b'a')?
        {
            return Ok(false);
        }
        let Some(optional) = self.repetition(suffix)? else {
            return Ok(false);
        };
        if !repeat_is(optional, 0, Some(1)) {
            return Ok(false);
        }
        let Some(suffix_children) = self.concat(&optional.sub)? else {
            return Ok(false);
        };
        let [colon, optional_space, codes_hir] = suffix_children else {
            return Ok(false);
        };
        if !self.literal(colon, b":")? {
            return Ok(false);
        }
        let Some(optional_space) = self.repetition(optional_space)? else {
            return Ok(false);
        };
        let space_ranges = if unicode {
            UNICODE_SPACE_RANGES
        } else {
            ASCII_SPACE_RANGES
        };
        if !repeat_is(optional_space, 0, Some(1))
            || !self.exact_class(&optional_space.sub, unicode, space_ranges)?
        {
            return Ok(false);
        }
        let Some(codes) = self.capture(codes_hir)? else {
            return Ok(false);
        };
        if codes.index != codes_index || codes.name.as_deref() != (unicode.then_some("codes")) {
            return Ok(false);
        }
        self.codes(&codes.sub, unicode, inner_index)
    }

    fn codes(
        &mut self,
        hir: &Hir,
        unicode: bool,
        inner_index: u32,
    ) -> Result<bool, NoqaBuildError> {
        let Some(outer) = self.repetition(hir)? else {
            return Ok(false);
        };
        if !repeat_is(outer, 1, None) {
            return Ok(false);
        }
        let Some(inner) = self.capture(&outer.sub)? else {
            return Ok(false);
        };
        if inner.index != inner_index || inner.name.is_some() {
            return Ok(false);
        }
        let Some(parts) = self.concat(&inner.sub)? else {
            return Ok(false);
        };
        let [uppercase, digits, optional_separators] = parts else {
            return Ok(false);
        };
        if !self.repeated_class(uppercase, unicode, 1, None, &[(b'A'.into(), b'Z'.into())])?
            || !self.repeated_class(digits, unicode, 1, None, &[(b'0'.into(), b'9'.into())])?
        {
            return Ok(false);
        }
        let Some(optional) = self.repetition(optional_separators)? else {
            return Ok(false);
        };
        if !repeat_is(optional, 0, Some(1)) {
            return Ok(false);
        }
        let Some(one_or_more) = self.repetition(&optional.sub)? else {
            return Ok(false);
        };
        let separator_ranges = if unicode {
            UNICODE_SEPARATOR_RANGES
        } else {
            ASCII_SEPARATOR_RANGES
        };
        if !repeat_is(one_or_more, 1, None) {
            return Ok(false);
        }
        self.exact_class(&one_or_more.sub, unicode, separator_ranges)
    }

    fn repeated_class(
        &mut self,
        hir: &Hir,
        unicode: bool,
        min: u32,
        max: Option<u32>,
        ranges: &[(u32, u32)],
    ) -> Result<bool, NoqaBuildError> {
        let Some(repetition) = self.repetition(hir)? else {
            return Ok(false);
        };
        if !repeat_is(repetition, min, max) {
            return Ok(false);
        }
        self.exact_class(&repetition.sub, unicode, ranges)
    }

    fn ascii_pair(
        &mut self,
        hir: &Hir,
        unicode: bool,
        upper: u8,
        lower: u8,
    ) -> Result<bool, NoqaBuildError> {
        self.exact_class(
            hir,
            unicode,
            &[
                (u32::from(upper), u32::from(upper)),
                (u32::from(lower), u32::from(lower)),
            ],
        )
    }

    fn exact_class(
        &mut self,
        hir: &Hir,
        unicode: bool,
        expected: &[(u32, u32)],
    ) -> Result<bool, NoqaBuildError> {
        let kind = self.kind(hir)?;
        match (unicode, kind) {
            (false, HirKind::Class(Class::Bytes(class))) => {
                self.ranges(class.ranges().len())?;
                Ok(class
                    .ranges()
                    .iter()
                    .map(|range| (u32::from(range.start()), u32::from(range.end())))
                    .eq(expected.iter().copied()))
            }
            (true, HirKind::Class(Class::Unicode(class))) => {
                self.ranges(class.ranges().len())?;
                Ok(class
                    .ranges()
                    .iter()
                    .map(|range| (u32::from(range.start()), u32::from(range.end())))
                    .eq(expected.iter().copied()))
            }
            _ => Ok(false),
        }
    }

    fn concat<'h>(&mut self, hir: &'h Hir) -> Result<Option<&'h [Hir]>, NoqaBuildError> {
        Ok(match self.kind(hir)? {
            HirKind::Concat(children) => Some(children),
            _ => None,
        })
    }

    fn capture<'h>(&mut self, hir: &'h Hir) -> Result<Option<&'h Capture>, NoqaBuildError> {
        Ok(match self.kind(hir)? {
            HirKind::Capture(capture) => Some(capture),
            _ => None,
        })
    }

    fn repetition<'h>(&mut self, hir: &'h Hir) -> Result<Option<&'h Repetition>, NoqaBuildError> {
        Ok(match self.kind(hir)? {
            HirKind::Repetition(repetition) => Some(repetition),
            _ => None,
        })
    }

    fn literal(&mut self, hir: &Hir, expected: &[u8]) -> Result<bool, NoqaBuildError> {
        let kind = self.kind(hir)?;
        let HirKind::Literal(literal) = kind else {
            return Ok(false);
        };
        self.charge(literal.0.len())?;
        self.accounting.literal_bytes = self
            .accounting
            .literal_bytes
            .checked_add(literal.0.len())
            .ok_or(NoqaBuildError::Overflow)?;
        Ok(literal.0.as_ref() == expected)
    }

    fn kind<'h>(&mut self, hir: &'h Hir) -> Result<&'h HirKind, NoqaBuildError> {
        self.charge(1)?;
        self.accounting.hir_nodes = self
            .accounting
            .hir_nodes
            .checked_add(1)
            .ok_or(NoqaBuildError::Overflow)?;
        Ok(hir.kind())
    }

    fn ranges(&mut self, count: usize) -> Result<(), NoqaBuildError> {
        self.charge(count)?;
        self.accounting.class_ranges = self
            .accounting
            .class_ranges
            .checked_add(count)
            .ok_or(NoqaBuildError::Overflow)?;
        Ok(())
    }

    fn charge(&mut self, amount: usize) -> Result<(), NoqaBuildError> {
        let required = self
            .accounting
            .work
            .checked_add(amount)
            .ok_or(NoqaBuildError::Overflow)?;
        if required > self.limit {
            return Err(NoqaBuildError::WorkLimit {
                required,
                limit: self.limit,
            });
        }
        self.accounting.work = required;
        Ok(())
    }
}

fn repeat_is(repetition: &Repetition, min: u32, max: Option<u32>) -> bool {
    repetition.min == min && repetition.max == max && repetition.greedy
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::bytes::RegexBuilder;
    use regex_syntax::ParserBuilder;

    const REAL: &str = r"(\s*)((?:# [Nn][Oo][Qq][Aa])(?::\s?(([A-Z]+[0-9]+(?:[,\s]+)?)+))?)";
    const TWEAKED: &str = r"(?:# [Nn][Oo][Qq][Aa])(?::\s?(([A-Z]+[0-9]+(?:[,\s]+)?)+))?";
    const WILD: &str =
        r"(?P<spaces>\s*)(?P<noqa>(?i:# noqa)(?::\s?(?P<codes>([A-Z]+[0-9]+(?:[,\s]+)?)+))?)";

    fn plan(pattern: &str, unicode: bool) -> NoqaPlan {
        let hir = ParserBuilder::new()
            .unicode(unicode)
            .build()
            .parse(pattern)
            .expect("fixture parses");
        NoqaPlan::inspect(&hir, NoqaBuildLimits::default())
            .expect("inspection fits")
            .expect("fixture is eligible")
    }

    fn reference_count(pattern: &str, unicode: bool, haystack: &[u8]) -> usize {
        let regex = RegexBuilder::new(pattern)
            .unicode(unicode)
            .build()
            .expect("reference compiles");
        let mut count = 0_usize;
        for_each_line(haystack, |line| {
            for captures in regex.captures_iter(line) {
                let participating = (0..captures.len())
                    .filter(|index| captures.get(*index).is_some())
                    .count();
                count = count
                    .checked_add(participating)
                    .expect("reference fixture count fits");
            }
            Ok(())
        })
        .expect("fixture dimensions fit");
        count
    }

    fn assert_differential(pattern: &str, unicode: bool, haystack: &[u8]) {
        let plan = plan(pattern, unicode);
        let actual = plan
            .count_captures(haystack, NoqaRunLimits::default())
            .expect("fixture fits");
        assert_eq!(
            actual.capture_count,
            reference_count(pattern, unicode, haystack)
        );
        assert!(actual.report.actual.capture_count <= actual.report.bounds.capture_count);
        assert!(actual.report.actual.capture_events <= actual.report.bounds.capture_events);
        assert!(actual.report.actual.literal_candidates <= actual.report.bounds.literal_candidates);
    }

    #[test]
    fn exact_hir_routes_and_build_preflight() {
        for (pattern, unicode, variant) in [
            (REAL, false, NoqaVariant::AsciiLeading),
            (TWEAKED, false, NoqaVariant::AsciiNoLeading),
            (WILD, true, NoqaVariant::UnicodeLeading),
        ] {
            let hir = ParserBuilder::new()
                .unicode(unicode)
                .build()
                .parse(pattern)
                .expect("fixture parses");
            let admitted = NoqaPlan::inspect(&hir, NoqaBuildLimits::default())
                .expect("inspection fits")
                .expect("fixture eligible");
            assert_eq!(admitted.variant(), variant);
            let exact = admitted.build_accounting().work;
            assert!(
                NoqaPlan::inspect(&hir, NoqaBuildLimits { max_work: exact })
                    .expect("exact limit admits")
                    .is_some()
            );
            let one_below = exact.checked_sub(1).expect("positive build work");
            assert_eq!(
                NoqaPlan::inspect(
                    &hir,
                    NoqaBuildLimits {
                        max_work: one_below,
                    },
                ),
                Err(NoqaBuildError::WorkLimit {
                    required: exact,
                    limit: one_below,
                })
            );
        }

        let near_miss = ParserBuilder::new()
            .unicode(false)
            .build()
            .parse(r"# [Nn][Oo][Qq][Bb]")
            .expect("near miss parses");
        assert!(
            NoqaPlan::inspect(&near_miss, NoqaBuildLimits::default())
                .expect("inspection fits")
                .is_none()
        );
    }

    #[test]
    fn empty_has_no_lines_and_zero_bounds() {
        for (pattern, unicode) in [(REAL, false), (TWEAKED, false), (WILD, true)] {
            let outcome = plan(pattern, unicode)
                .count_captures(
                    b"",
                    NoqaRunLimits {
                        max_work: 0,
                        max_sequential_bytes: 0,
                        max_capture_events: 0,
                        max_capture_count: 0,
                    },
                )
                .expect("empty input is free");
            assert_eq!(outcome.capture_count, 0);
            assert_eq!(outcome.report.bounds, NoqaUpperBounds::ZERO);
        }
    }

    #[test]
    fn focused_adversaries_match_upstream() {
        let cases: &[&[u8]] = &[
            b"# noqa: A1\r\n\r# noqa: B2\r# noqa\n",
            b"\xFF# noqa: A1,\x80B2\n# noqa: A1\xC2 B2\n",
            b"\xC2\xA0# noqa:\xC2\xA0A1\xE2\x80\x80B2\n\xE3\x80\x80# noqa\n",
            b"# # noqa# noqa: A1# noqa\n# noqb # NOQA: Z9\n",
            b"# noqa: nope\n# noqa: A1, FOO # noqa\n# noqa:\n",
            b"# noqa: A1,\r\n# noqa: B2\rC3\r# noqa\n",
            b"# noqa: A1,B2 C3\tD4\n# noqa: A1FOO # noqa: X7\n",
        ];
        for haystack in cases {
            assert_differential(REAL, false, haystack);
            assert_differential(TWEAKED, false, haystack);
            assert_differential(WILD, true, haystack);
        }
    }

    #[test]
    fn suffix_commit_retains_separators_but_rolls_back_failed_token() {
        assert_eq!(
            parse_codes(b"A1, FOO", 0, false).expect("indices fit"),
            Some(4)
        );
        assert_eq!(
            parse_codes(b"A1FOO", 0, false).expect("indices fit"),
            Some(2)
        );
        assert_eq!(
            noqa_end(b"# noqa: FOO", 6, false).expect("indices fit"),
            (6, false)
        );
        assert_eq!(
            noqa_end(b"# noqa: A1, FOO", 6, false).expect("indices fit"),
            (12, true)
        );
    }

    #[test]
    fn exact_and_one_below_run_preflight() {
        let plan = plan(WILD, true);
        let haystack = b"\xC2\xA0# noqa: A1, B2\r\n# noqa\n";
        let admitted = plan
            .count_captures(haystack, NoqaRunLimits::default())
            .expect("fixture admitted");
        let bounds = admitted.report.bounds;
        for (resource, required) in [
            (NoqaResource::Work, bounds.work),
            (NoqaResource::SequentialBytes, bounds.sequential_bytes),
            (NoqaResource::CaptureEvents, bounds.capture_events),
            (NoqaResource::CaptureCount, bounds.capture_count),
        ] {
            let one_below = required.checked_sub(1).expect("positive run bound");
            let mut exact = NoqaRunLimits::default();
            match resource {
                NoqaResource::Work => exact.max_work = required,
                NoqaResource::SequentialBytes => exact.max_sequential_bytes = required,
                NoqaResource::CaptureEvents => exact.max_capture_events = required,
                NoqaResource::CaptureCount => exact.max_capture_count = required,
            }
            plan.count_captures(haystack, exact)
                .expect("exact limit admits");
            let mut below = NoqaRunLimits::default();
            match resource {
                NoqaResource::Work => below.max_work = one_below,
                NoqaResource::SequentialBytes => below.max_sequential_bytes = one_below,
                NoqaResource::CaptureEvents => below.max_capture_events = one_below,
                NoqaResource::CaptureCount => below.max_capture_count = one_below,
            }
            assert_eq!(
                plan.count_captures(haystack, below),
                Err(NoqaRunError::Resource {
                    resource,
                    required,
                    limit: one_below,
                })
            );
        }
    }

    #[test]
    #[ignore = "requires FRE_NOQA_HARD_CORPUS"]
    fn hard_wild_noqa_no_clock_canary() {
        let path = std::env::var_os("FRE_NOQA_HARD_CORPUS")
            .expect("FRE_NOQA_HARD_CORPUS names the authenticated raw corpus");
        let haystack = std::fs::read(path).expect("hard corpus is readable");
        let outcome = plan(WILD, true)
            .count_captures(&haystack, NoqaRunLimits::default())
            .expect("hard corpus stays inside locked ceilings");
        assert_eq!(outcome.capture_count, 84);
        assert_eq!(outcome.report.actual.matches, 20);
        assert_eq!(outcome.report.actual.coded_matches, 12);
        assert_eq!(
            outcome.report.bounds,
            NoqaUpperBounds {
                haystack_bytes: 32_514_526,
                line_bytes: 31_623_613,
                lines: 890_906,
                literal_candidates: 15_811_806,
                work: 475_245_107,
                sequential_bytes: 348_750_654,
                capture_events: 79_949_936,
                capture_count: 79_059_030,
            }
        );
    }
}
