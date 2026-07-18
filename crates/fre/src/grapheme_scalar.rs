//! Structural admission for the ordered scalar grammar used by the pinned
//! grapheme benchmark. The executable reducer lives in `fre-kernels`; this
//! module proves that canonical HIR has exactly the deterministic grammar the
//! reducer implements.

use regex_syntax::hir::{Class, ClassUnicode, ClassUnicodeRange, Hir, HirKind};

#[derive(Clone, Debug)]
pub(super) struct Classes<'a> {
    pub control: &'a ClassUnicode,
    pub prepend: &'a ClassUnicode,
    pub l: &'a ClassUnicode,
    pub v: &'a ClassUnicode,
    pub lv: &'a ClassUnicode,
    pub lvt: &'a ClassUnicode,
    pub t: &'a ClassUnicode,
    pub ri: &'a ClassUnicode,
    pub extended_pictographic: &'a ClassUnicode,
    pub extend: &'a ClassUnicode,
    pub generic: &'a ClassUnicode,
    pub tail: &'a ClassUnicode,
    pub any: &'a ClassUnicode,
    pub spacing_mark_ranges: usize,
}

#[derive(Clone, Debug)]
pub(super) struct Inspection<'a> {
    pub classes: Classes<'a>,
    pub work: usize,
    pub hir_nodes: usize,
    pub captures: usize,
}

#[derive(Clone, Debug)]
pub(super) enum InspectionOutcome<'a> {
    Eligible(Inspection<'a>),
    Ineligible {
        work: usize,
        hir_nodes: usize,
        captures: usize,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InspectionError {
    WorkLimit { needed: usize, limit: usize },
    Overflow,
}

/// Recognize one ordered, greedy scalar grammar after treating captures as
/// transparent whole-match annotations. Every HIR/range visit and every
/// structural comparison is charged before it runs. Near misses retain their
/// complete attempted work for the later-plan report.
pub(super) fn inspect(hir: &Hir, limit: usize) -> Result<InspectionOutcome<'_>, InspectionError> {
    let mut accounting = InspectionAccounting::default();
    account_hir(hir, limit, &mut accounting)?;
    let Some(mut classes) = inspect_shape(hir, limit, &mut accounting)? else {
        return Ok(accounting.ineligible());
    };
    if !validate_class_relationships(&classes, limit, &mut accounting)? {
        return Ok(accounting.ineligible());
    }
    reserve_spacing_derivation(&classes, limit, &mut accounting)?;
    classes.spacing_mark_ranges = SpacingMarkRanges::new(&classes).count();
    if classes.spacing_mark_ranges == 0 {
        return Ok(accounting.ineligible());
    }
    Ok(InspectionOutcome::Eligible(Inspection {
        classes,
        work: accounting.work,
        hir_nodes: accounting.hir_nodes,
        captures: accounting.captures,
    }))
}

macro_rules! shape_some {
    ($expression:expr) => {
        match $expression? {
            Some(value) => value,
            None => return Ok(None),
        }
    };
}

#[allow(
    clippy::too_many_lines,
    reason = "the recognized grammar is kept in source order for auditable exact-shape admission"
)]
fn inspect_shape<'a>(
    hir: &'a Hir,
    limit: usize,
    accounting: &mut InspectionAccounting,
) -> Result<Option<Classes<'a>>, InspectionError> {
    let root = shape_some!(alternation(hir, limit, accounting));
    if !exact_len(root.len(), 4, limit, accounting)? {
        return Ok(None);
    }
    let (crlf, control_hir, main_hir, any_hir) = (&root[0], &root[1], &root[2], &root[3]);
    if !is_literal(crlf, b"\r\n", limit, accounting)? {
        return Ok(None);
    }
    let control = shape_some!(unicode_class(control_hir, limit, accounting));
    let any = shape_some!(unicode_class(any_hir, limit, accounting));

    let main = shape_some!(concat(main_hir, limit, accounting));
    if !exact_len(main.len(), 3, limit, accounting)? {
        return Ok(None);
    }
    let (prepend_hir, core_hir, tail_hir) = (&main[0], &main[1], &main[2]);
    let prepend_hir = shape_some!(repetition(prepend_hir, 0, None, limit, accounting));
    let prepend = shape_some!(unicode_class(prepend_hir, limit, accounting));
    let tail_hir = shape_some!(repetition(tail_hir, 0, None, limit, accounting));
    let tail = shape_some!(unicode_class(tail_hir, limit, accounting));

    let core = shape_some!(alternation(core_hir, limit, accounting));
    if !exact_len(core.len(), 4, limit, accounting)? {
        return Ok(None);
    }
    let (hangul_hir, ri_hir, emoji_hir, generic_hir) = (&core[0], &core[1], &core[2], &core[3]);
    let generic = shape_some!(unicode_class(generic_hir, limit, accounting));

    let hangul = shape_some!(alternation(hangul_hir, limit, accounting));
    if !exact_len(hangul.len(), 3, limit, accounting)? {
        return Ok(None);
    }
    let (lvt_sequence_hir, l_run_hir, t_run_hir) = (&hangul[0], &hangul[1], &hangul[2]);
    let lvt_sequence = shape_some!(concat(lvt_sequence_hir, limit, accounting));
    if !exact_len(lvt_sequence.len(), 3, limit, accounting)? {
        return Ok(None);
    }
    let (l_prefix_hir, v_or_syllable_hir, t_suffix_hir) =
        (&lvt_sequence[0], &lvt_sequence[1], &lvt_sequence[2]);
    let l_prefix = shape_some!(repetition(l_prefix_hir, 0, None, limit, accounting));
    let l = shape_some!(unicode_class(l_prefix, limit, accounting));
    let t_suffix = shape_some!(repetition(t_suffix_hir, 0, None, limit, accounting));
    let t = shape_some!(unicode_class(t_suffix, limit, accounting));
    let l_run = shape_some!(repetition(l_run_hir, 1, None, limit, accounting));
    let l_again = shape_some!(unicode_class(l_run, limit, accounting));
    let t_run = shape_some!(repetition(t_run_hir, 1, None, limit, accounting));
    let t_again = shape_some!(unicode_class(t_run, limit, accounting));
    if !classes_equal(l_again, l, limit, accounting)?
        || !classes_equal(t_again, t, limit, accounting)?
    {
        return Ok(None);
    }

    let v_or_syllable = shape_some!(alternation(v_or_syllable_hir, limit, accounting));
    if !exact_len(v_or_syllable.len(), 3, limit, accounting)? {
        return Ok(None);
    }
    let (v_run_hir, lv_v_hir, trailing_syllable_hir) =
        (&v_or_syllable[0], &v_or_syllable[1], &v_or_syllable[2]);
    let v_run = shape_some!(repetition(v_run_hir, 1, None, limit, accounting));
    let v = shape_some!(unicode_class(v_run, limit, accounting));
    let lv_v = shape_some!(concat(lv_v_hir, limit, accounting));
    if !exact_len(lv_v.len(), 2, limit, accounting)? {
        return Ok(None);
    }
    let lv = shape_some!(unicode_class(&lv_v[0], limit, accounting));
    let optional_v = shape_some!(repetition(&lv_v[1], 0, None, limit, accounting));
    let optional_v = shape_some!(unicode_class(optional_v, limit, accounting));
    if !classes_equal(optional_v, v, limit, accounting)? {
        return Ok(None);
    }
    let lvt = shape_some!(unicode_class(trailing_syllable_hir, limit, accounting));

    let ri_pair = shape_some!(concat(ri_hir, limit, accounting));
    if !exact_len(ri_pair.len(), 2, limit, accounting)? {
        return Ok(None);
    }
    let ri = shape_some!(unicode_class(&ri_pair[0], limit, accounting));
    let second_ri = shape_some!(unicode_class(&ri_pair[1], limit, accounting));
    if !classes_equal(second_ri, ri, limit, accounting)? {
        return Ok(None);
    }

    let emoji = shape_some!(concat(emoji_hir, limit, accounting));
    if !exact_len(emoji.len(), 2, limit, accounting)? {
        return Ok(None);
    }
    let extended_pictographic = shape_some!(unicode_class(&emoji[0], limit, accounting));
    let emoji_suffix = shape_some!(repetition(&emoji[1], 0, None, limit, accounting));
    let emoji_suffix = shape_some!(concat(emoji_suffix, limit, accounting));
    if !exact_len(emoji_suffix.len(), 3, limit, accounting)? {
        return Ok(None);
    }
    let extend_hir = shape_some!(repetition(&emoji_suffix[0], 0, None, limit, accounting));
    let extend = shape_some!(unicode_class(extend_hir, limit, accounting));
    if !is_literal(&emoji_suffix[1], "\u{200D}".as_bytes(), limit, accounting)? {
        return Ok(None);
    }
    let repeated_pictographic = shape_some!(unicode_class(&emoji_suffix[2], limit, accounting));
    if !classes_equal(
        repeated_pictographic,
        extended_pictographic,
        limit,
        accounting,
    )? {
        return Ok(None);
    }

    Ok(Some(Classes {
        control,
        prepend,
        l,
        v,
        lv,
        lvt,
        t,
        ri,
        extended_pictographic,
        extend,
        generic,
        tail,
        any,
        spacing_mark_ranges: 0,
    }))
}

fn validate_class_relationships(
    classes: &Classes<'_>,
    limit: usize,
    accounting: &mut InspectionAccounting,
) -> Result<bool, InspectionError> {
    let any_ranges = classes.any.ranges();
    charge(accounting, limit, 3)?;
    if any_ranges.len() != 1 || any_ranges[0].start() != '\0' || any_ranges[0].end() != char::MAX {
        return Ok(false);
    }

    let gcb = [
        classes.control,
        classes.prepend,
        classes.l,
        classes.v,
        classes.lv,
        classes.lvt,
        classes.t,
        classes.ri,
        classes.extend,
    ];
    for (index, left) in gcb.iter().enumerate() {
        charge(accounting, limit, 1)?;
        let Some(right_classes) = gcb.get(index.saturating_add(1)..) else {
            return Ok(false);
        };
        for right in right_classes {
            charge(accounting, limit, 1)?;
            if classes_overlap(left, right, limit, accounting)? {
                return Ok(false);
            }
        }
        if classes_overlap(left, classes.extended_pictographic, limit, accounting)? {
            return Ok(false);
        }
        for scalar in ['\r', '\n', '\u{200D}'] {
            if class_contains(left, scalar, limit, accounting)? {
                return Ok(false);
            }
        }
    }
    for scalar in ['\r', '\n', '\u{200D}'] {
        if class_contains(classes.extended_pictographic, scalar, limit, accounting)? {
            return Ok(false);
        }
    }

    if classes_overlap(classes.generic, classes.control, limit, accounting)?
        || class_contains(classes.generic, '\r', limit, accounting)?
        || class_contains(classes.generic, '\n', limit, accounting)?
    {
        return Ok(false);
    }
    let generic_scalars = class_scalar_count(classes.generic, limit, accounting)?;
    let control_scalars = class_scalar_count(classes.control, limit, accounting)?;
    let partition_scalars = generic_scalars
        .checked_add(control_scalars)
        .and_then(|value| value.checked_add(2))
        .ok_or(InspectionError::Overflow)?;
    if partition_scalars != 0x11_0000 - 0x800 {
        return Ok(false);
    }

    if !class_subset(classes.extend, classes.tail, limit, accounting)?
        || !class_contains(classes.tail, '\u{200D}', limit, accounting)?
        || classes_overlap(
            classes.tail,
            classes.extended_pictographic,
            limit,
            accounting,
        )?
    {
        return Ok(false);
    }
    for other in [
        classes.control,
        classes.prepend,
        classes.l,
        classes.v,
        classes.lv,
        classes.lvt,
        classes.t,
        classes.ri,
    ] {
        if classes_overlap(classes.tail, other, limit, accounting)? {
            return Ok(false);
        }
    }
    if class_contains(classes.tail, '\r', limit, accounting)?
        || class_contains(classes.tail, '\n', limit, accounting)?
    {
        return Ok(false);
    }
    Ok(true)
}

fn classes_overlap(
    left: &ClassUnicode,
    right: &ClassUnicode,
    limit: usize,
    accounting: &mut InspectionAccounting,
) -> Result<bool, InspectionError> {
    let mut left_index = 0;
    let mut right_index = 0;
    while left_index < left.ranges().len() && right_index < right.ranges().len() {
        charge(accounting, limit, 3)?;
        let left_range = &left.ranges()[left_index];
        let right_range = &right.ranges()[right_index];
        if left_range.end() < right_range.start() {
            left_index = left_index.saturating_add(1);
        } else if right_range.end() < left_range.start() {
            right_index = right_index.saturating_add(1);
        } else {
            return Ok(true);
        }
    }
    Ok(false)
}

fn class_contains(
    class: &ClassUnicode,
    scalar: char,
    limit: usize,
    accounting: &mut InspectionAccounting,
) -> Result<bool, InspectionError> {
    for range in class.ranges() {
        charge(accounting, limit, 2)?;
        if scalar < range.start() {
            return Ok(false);
        }
        if scalar <= range.end() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn class_subset(
    subset: &ClassUnicode,
    superset: &ClassUnicode,
    limit: usize,
    accounting: &mut InspectionAccounting,
) -> Result<bool, InspectionError> {
    let mut super_index = 0;
    for range in subset.ranges() {
        loop {
            charge(accounting, limit, 3)?;
            let Some(super_range) = superset.ranges().get(super_index) else {
                return Ok(false);
            };
            if super_range.end() < range.start() {
                super_index = super_index
                    .checked_add(1)
                    .ok_or(InspectionError::Overflow)?;
                continue;
            }
            if super_range.start() > range.start() || super_range.end() < range.end() {
                return Ok(false);
            }
            break;
        }
    }
    Ok(true)
}

fn class_scalar_count(
    class: &ClassUnicode,
    limit: usize,
    accounting: &mut InspectionAccounting,
) -> Result<usize, InspectionError> {
    let mut total = 0_usize;
    for range in class.ranges() {
        charge(accounting, limit, 1)?;
        let start = u32::from(range.start());
        let end = u32::from(range.end());
        let count = end
            .checked_sub(start)
            .and_then(|value| value.checked_add(1))
            .ok_or(InspectionError::Overflow)?;
        let mut count = usize::try_from(count).map_err(|_| InspectionError::Overflow)?;
        if start <= 0xD7FF && end >= 0xE000 {
            count = count.checked_sub(0x800).ok_or(InspectionError::Overflow)?;
        }
        total = total.checked_add(count).ok_or(InspectionError::Overflow)?;
    }
    Ok(total)
}

fn classes_equal(
    left: &ClassUnicode,
    right: &ClassUnicode,
    limit: usize,
    accounting: &mut InspectionAccounting,
) -> Result<bool, InspectionError> {
    charge(accounting, limit, 1)?;
    if left.ranges().len() != right.ranges().len() {
        return Ok(false);
    }
    for (left, right) in left.ranges().iter().zip(right.ranges()) {
        charge(accounting, limit, 2)?;
        if left.start() != right.start() || left.end() != right.end() {
            return Ok(false);
        }
    }
    Ok(true)
}

fn exact_len(
    actual: usize,
    expected: usize,
    limit: usize,
    accounting: &mut InspectionAccounting,
) -> Result<bool, InspectionError> {
    charge(accounting, limit, 1)?;
    Ok(actual == expected)
}

fn transparent<'a>(
    mut hir: &'a Hir,
    limit: usize,
    accounting: &mut InspectionAccounting,
) -> Result<&'a Hir, InspectionError> {
    loop {
        charge(accounting, limit, 2)?;
        let HirKind::Capture(capture) = hir.kind() else {
            return Ok(hir);
        };
        hir = capture.sub.as_ref();
    }
}

fn alternation<'a>(
    hir: &'a Hir,
    limit: usize,
    accounting: &mut InspectionAccounting,
) -> Result<Option<&'a [Hir]>, InspectionError> {
    charge(accounting, limit, 1)?;
    Ok(match transparent(hir, limit, accounting)?.kind() {
        HirKind::Alternation(parts) => Some(parts),
        _ => None,
    })
}

fn concat<'a>(
    hir: &'a Hir,
    limit: usize,
    accounting: &mut InspectionAccounting,
) -> Result<Option<&'a [Hir]>, InspectionError> {
    charge(accounting, limit, 1)?;
    Ok(match transparent(hir, limit, accounting)?.kind() {
        HirKind::Concat(parts) => Some(parts),
        _ => None,
    })
}

fn unicode_class<'a>(
    hir: &'a Hir,
    limit: usize,
    accounting: &mut InspectionAccounting,
) -> Result<Option<&'a ClassUnicode>, InspectionError> {
    charge(accounting, limit, 2)?;
    Ok(match transparent(hir, limit, accounting)?.kind() {
        HirKind::Class(Class::Unicode(class)) if !class.ranges().is_empty() => Some(class),
        _ => None,
    })
}

fn repetition<'a>(
    hir: &'a Hir,
    min: u32,
    max: Option<u32>,
    limit: usize,
    accounting: &mut InspectionAccounting,
) -> Result<Option<&'a Hir>, InspectionError> {
    charge(accounting, limit, 4)?;
    Ok(match transparent(hir, limit, accounting)?.kind() {
        HirKind::Repetition(repetition)
            if repetition.min == min && repetition.max == max && repetition.greedy =>
        {
            Some(repetition.sub.as_ref())
        }
        _ => None,
    })
}

fn is_literal(
    hir: &Hir,
    expected: &[u8],
    limit: usize,
    accounting: &mut InspectionAccounting,
) -> Result<bool, InspectionError> {
    charge(accounting, limit, 2)?;
    let HirKind::Literal(literal) = transparent(hir, limit, accounting)?.kind() else {
        return Ok(false);
    };
    if literal.0.len() != expected.len() {
        return Ok(false);
    }
    for (actual, expected) in literal.0.iter().zip(expected) {
        charge(accounting, limit, 1)?;
        if actual != expected {
            return Ok(false);
        }
    }
    Ok(true)
}

#[derive(Default)]
struct InspectionAccounting {
    work: usize,
    hir_nodes: usize,
    captures: usize,
    class_ranges: usize,
}

impl InspectionAccounting {
    const fn ineligible(&self) -> InspectionOutcome<'static> {
        InspectionOutcome::Ineligible {
            work: self.work,
            hir_nodes: self.hir_nodes,
            captures: self.captures,
        }
    }
}

fn account_hir(
    hir: &Hir,
    limit: usize,
    accounting: &mut InspectionAccounting,
) -> Result<(), InspectionError> {
    charge(accounting, limit, 2)?;
    accounting.hir_nodes = accounting
        .hir_nodes
        .checked_add(1)
        .ok_or(InspectionError::Overflow)?;
    match hir.kind() {
        HirKind::Capture(capture) => {
            accounting.captures = accounting
                .captures
                .checked_add(1)
                .ok_or(InspectionError::Overflow)?;
            account_hir(capture.sub.as_ref(), limit, accounting)
        }
        HirKind::Repetition(repetition) => account_hir(repetition.sub.as_ref(), limit, accounting),
        HirKind::Concat(parts) | HirKind::Alternation(parts) => {
            for part in parts {
                charge(accounting, limit, 1)?;
                account_hir(part, limit, accounting)?;
            }
            Ok(())
        }
        HirKind::Class(Class::Unicode(class)) => {
            for _ in class.ranges() {
                charge(accounting, limit, 1)?;
                accounting.class_ranges = accounting
                    .class_ranges
                    .checked_add(1)
                    .ok_or(InspectionError::Overflow)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn charge(
    accounting: &mut InspectionAccounting,
    limit: usize,
    units: usize,
) -> Result<(), InspectionError> {
    let needed = accounting
        .work
        .checked_add(units)
        .ok_or(InspectionError::Overflow)?;
    if needed > limit {
        return Err(InspectionError::WorkLimit { needed, limit });
    }
    accounting.work = needed;
    Ok(())
}

fn reserve_spacing_derivation(
    classes: &Classes<'_>,
    limit: usize,
    accounting: &mut InspectionAccounting,
) -> Result<(), InspectionError> {
    // The allocation-free subtraction iterator is traversed once to bind its
    // exact output count and once by the kernel build. Each pass performs at
    // most sixteen decisions/comparisons per tail, Extend, or singleton ZWJ
    // range. Reserve both passes before either begins.
    let inputs = classes
        .tail
        .ranges()
        .len()
        .checked_add(classes.extend.ranges().len())
        .and_then(|value| value.checked_add(1))
        .ok_or(InspectionError::Overflow)?;
    let units = inputs.checked_mul(32).ok_or(InspectionError::Overflow)?;
    charge(accounting, limit, units)
}

pub(super) struct SpacingMarkRanges<'a> {
    tail: &'a [ClassUnicodeRange],
    extend: &'a [ClassUnicodeRange],
    tail_index: usize,
    extend_index: usize,
    zwj_pending: bool,
    current: Option<(char, char)>,
}

impl<'a> SpacingMarkRanges<'a> {
    fn new(classes: &'a Classes<'a>) -> Self {
        Self {
            tail: classes.tail.ranges(),
            extend: classes.extend.ranges(),
            tail_index: 0,
            extend_index: 0,
            zwj_pending: true,
            current: None,
        }
    }

    fn exclusion(&self) -> Option<(char, char, bool)> {
        let extend = self.extend.get(self.extend_index);
        let zwj = self.zwj_pending.then_some(('\u{200D}', '\u{200D}'));
        match (extend, zwj) {
            (Some(range), Some((start, end))) if range.start() < start => {
                Some((range.start(), range.end(), false))
            }
            (Some(_) | None, Some((start, end))) => Some((start, end, true)),
            (Some(range), None) => Some((range.start(), range.end(), false)),
            (None, None) => None,
        }
    }

    fn advance_exclusion(&mut self, zwj: bool) {
        if zwj {
            self.zwj_pending = false;
        } else {
            self.extend_index = self.extend_index.saturating_add(1);
        }
    }
}

pub(super) fn spacing_mark_ranges<'a>(classes: &'a Classes<'a>) -> SpacingMarkRanges<'a> {
    SpacingMarkRanges::new(classes)
}

impl Iterator for SpacingMarkRanges<'_> {
    type Item = ClassUnicodeRange;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.current.is_none() {
                let range = self.tail.get(self.tail_index)?;
                self.tail_index = self.tail_index.saturating_add(1);
                self.current = Some((range.start(), range.end()));
            }
            let (start, end) = self.current?;
            let Some((excluded_start, excluded_end, is_zwj)) = self.exclusion() else {
                self.current = None;
                return Some(ClassUnicodeRange::new(start, end));
            };
            if excluded_end < start {
                self.advance_exclusion(is_zwj);
                continue;
            }
            if excluded_start > end {
                self.current = None;
                return Some(ClassUnicodeRange::new(start, end));
            }
            self.advance_exclusion(is_zwj);
            let remainder_start = scalar_after(excluded_end);
            if excluded_start > start {
                self.current = remainder_start
                    .filter(|next| *next <= end)
                    .map(|next| (next, end));
                let before = scalar_before(excluded_start)?;
                return Some(ClassUnicodeRange::new(start, before));
            }
            self.current = remainder_start
                .filter(|next| *next <= end)
                .map(|next| (next, end));
        }
    }
}

fn scalar_after(scalar: char) -> Option<char> {
    let mut next = u32::from(scalar).checked_add(1)?;
    if next == 0xD800 {
        next = 0xE000;
    }
    char::from_u32(next)
}

fn scalar_before(scalar: char) -> Option<char> {
    let mut previous = u32::from(scalar).checked_sub(1)?;
    if previous == 0xDFFF {
        previous = 0xD7FF;
    }
    char::from_u32(previous)
}

#[cfg(test)]
mod tests {
    use regex_syntax::hir::{Class, ClassUnicode, ClassUnicodeRange, Hir};

    use fre_syntax::{CanonicalPattern, CompatibilityProfile, ParseRequest, RustProfile};

    use super::{InspectionError, InspectionOutcome, inspect};

    const GRAPHEME: &str = r"(?x)
\p{gcb=CR} \p{gcb=LF}
|
\p{gcb=Control}
|
\p{gcb=Prepend}*
(
  (
    (\p{gcb=L}* (\p{gcb=V}+ | \p{gcb=LV} \p{gcb=V}* | \p{gcb=LVT}) \p{gcb=T}*)
    |
    \p{gcb=L}+
    |
    \p{gcb=T}+
  )
  |
  \p{gcb=RI} \p{gcb=RI}
  |
  \p{Extended_Pictographic} (\p{gcb=Extend}* \p{gcb=ZWJ} \p{Extended_Pictographic})*
  |
  [^\p{gcb=Control} \p{gcb=CR} \p{gcb=LF}]
)
[\p{gcb=Extend} \p{gcb=ZWJ} \p{gcb=SpacingMark}]*
|
\p{Any}
";

    fn parsed_hir(pattern: &str) -> Hir {
        let profile = CompatibilityProfile::RustBytes(RustProfile::rebar_1_12_4());
        let parsed = fre_syntax::parse(ParseRequest::rust(pattern.to_owned(), profile)).unwrap();
        let CanonicalPattern::Rust(rust) = parsed.pattern else {
            panic!("Rust request produced another canonical pattern");
        };
        rust.hir
    }

    fn outcome_work(outcome: &InspectionOutcome<'_>) -> usize {
        match outcome {
            InspectionOutcome::Eligible(inspection) => inspection.work,
            InspectionOutcome::Ineligible { work, .. } => *work,
        }
    }

    fn assert_exact_and_one_below(hir: &Hir, expect_eligible: bool) -> usize {
        let unlimited = inspect(hir, usize::MAX).unwrap();
        assert_eq!(
            matches!(unlimited, InspectionOutcome::Eligible(_)),
            expect_eligible
        );
        let work = outcome_work(&unlimited);
        assert!(work > 0);
        let exact = inspect(hir, work).unwrap();
        assert_eq!(outcome_work(&exact), work);
        assert_eq!(
            matches!(exact, InspectionOutcome::Eligible(_)),
            expect_eligible
        );
        let one_below = work.checked_sub(1).unwrap();
        assert!(matches!(
            inspect(hir, one_below),
            Err(InspectionError::WorkLimit { needed, limit })
                if needed == work && limit == one_below
        ));
        work
    }

    #[test]
    fn pinned_grapheme_hir_is_admitted() {
        let profile = CompatibilityProfile::RustBytes(RustProfile::rebar_1_12_4());
        let parsed = fre_syntax::parse(ParseRequest::rust(GRAPHEME.to_owned(), profile)).unwrap();
        let CanonicalPattern::Rust(rust) = parsed.pattern else {
            panic!("Rust request produced another canonical pattern");
        };
        let InspectionOutcome::Eligible(inspection) = inspect(&rust.hir, usize::MAX).unwrap()
        else {
            panic!("expected eligible shape")
        };
        assert_eq!(
            inspection.hir_nodes,
            usize::try_from(parsed.summary.hir_nodes).unwrap()
        );
        assert_eq!(
            inspection.captures,
            usize::try_from(parsed.summary.captures).unwrap()
        );
        assert!(inspection.work > 1_454);
    }

    #[test]
    fn eligible_inspection_has_an_exact_prospective_work_boundary() {
        assert_exact_and_one_below(&parsed_hir(GRAPHEME), true);
    }

    #[test]
    fn near_miss_and_malformed_shapes_retain_charged_work() {
        let near_miss = GRAPHEME.replacen(r"\p{Any}", "a", 1);
        let near_miss_work = assert_exact_and_one_below(&parsed_hir(&near_miss), false);

        let malformed = GRAPHEME.replacen(r"\p{gcb=RI} \p{gcb=RI}", r"\p{gcb=RI}", 1);
        let malformed_work = assert_exact_and_one_below(&parsed_hir(&malformed), false);
        assert_ne!(near_miss_work, malformed_work);
    }

    #[test]
    fn large_ineligible_classes_charge_every_range_before_shape_rejection() {
        let small = Hir::class(Class::Unicode(ClassUnicode::new([
            ClassUnicodeRange::new('\u{1000}', '\u{1000}'),
            ClassUnicodeRange::new('\u{1002}', '\u{1002}'),
        ])));
        let ranges = (0..512_u32).map(|index| {
            let scalar = char::from_u32(0x1_0000 + index * 2).unwrap();
            ClassUnicodeRange::new(scalar, scalar)
        });
        let large = Hir::class(Class::Unicode(ClassUnicode::new(ranges)));
        let small_work = assert_exact_and_one_below(&small, false);
        let large_work = assert_exact_and_one_below(&large, false);
        assert_eq!(large_work - small_work, 510);
    }
}
