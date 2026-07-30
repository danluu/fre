//! Direct search for one greedy class repetition between matching word
//! boundaries.
//!
//! The admitted HIR is exactly `\b CLASS{min,max} \b` (modulo transparent
//! captures), with either the ASCII boundary plus a byte class or the Unicode
//! boundary plus a Unicode scalar class. The class need not be the word
//! property: boundaries are evaluated against the complete original
//! haystack, independently of class membership.

use fre_exact_alloc::{CopyError, ExactVec};
use regex_syntax::hir::{Class, Hir, HirKind, Look};

use crate::{
    Match, SearchLimits, SearchWindow,
    unicode_word_run::{Accounting, Error},
};

pub(crate) const PLAN_ID: &str = "bounded-word-class-linear-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BoundaryMode {
    Ascii,
    Unicode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ScalarRange {
    start: char,
    end: char,
}

#[derive(Debug)]
enum ClassMatcher {
    Bytes([u64; 4]),
    Unicode {
        ascii_words: [u64; 2],
        ranges: ExactVec<ScalarRange>,
    },
}

/// Immutable, allocation-free-at-search-time native plan.
#[derive(Debug)]
pub(crate) struct Plan {
    mode: BoundaryMode,
    class: ClassMatcher,
    minimum_units: usize,
    maximum_units: Option<usize>,
    storage_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InspectionError {
    WorkLimit { needed: u64, limit: u64 },
    ArithmeticOverflow(&'static str),
}

#[derive(Clone, Copy, Debug)]
enum InspectedClass<'a> {
    Bytes(&'a regex_syntax::hir::ClassBytes),
    Unicode(&'a regex_syntax::hir::ClassUnicode),
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Inspection<'a> {
    mode: BoundaryMode,
    class: InspectedClass<'a>,
    minimum_units: usize,
    maximum_units: Option<usize>,
    planner_work: u64,
    storage_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BoundaryPoint {
    byte: usize,
    units: usize,
}

#[derive(Clone, Copy, Debug)]
struct BoundaryCursor {
    position: usize,
    units: usize,
    run_end: usize,
    done: bool,
}

impl BoundaryCursor {
    const fn new(run_start: usize, run_end: usize) -> Self {
        Self {
            position: run_start,
            units: 0,
            run_end,
            done: false,
        }
    }

    fn next(
        &mut self,
        plan: &Plan,
        haystack: &[u8],
        accounting: &mut Accounting,
        limits: SearchLimits,
    ) -> Result<Option<BoundaryPoint>, Error> {
        while !self.done {
            let point = BoundaryPoint {
                byte: self.position,
                units: self.units,
            };
            if self.position == self.run_end {
                self.done = true;
            } else {
                let width = plan.known_member_width(haystack, self.position, self.run_end);
                charge(accounting, limits)?;
                accounting.bytes_examined = accounting.bytes_examined.saturating_add(width);
                accounting.scalars_decoded = accounting.scalars_decoded.saturating_add(1);
                self.position =
                    self.position
                        .checked_add(width)
                        .ok_or(Error::WorkLimitExceeded {
                            needed: u64::MAX,
                            limit: limits.max_work,
                        })?;
                self.units = self.units.checked_add(1).ok_or(Error::WorkLimitExceeded {
                    needed: u64::MAX,
                    limit: limits.max_work,
                })?;
            }
            charge(accounting, limits)?;
            if plan.is_word_boundary(haystack, point.byte) {
                return Ok(Some(point));
            }
        }
        Ok(None)
    }
}

impl Inspection<'_> {
    pub(crate) const fn planner_work(self) -> u64 {
        self.planner_work
    }

    pub(crate) const fn storage_bytes(self) -> usize {
        self.storage_bytes
    }

    pub(crate) fn build(self) -> Result<Plan, crate::BuildError> {
        let class = match self.class {
            InspectedClass::Bytes(class) => {
                let mut words = [0_u64; 4];
                for range in class.ranges() {
                    set_byte_range(&mut words, range.start(), range.end());
                }
                ClassMatcher::Bytes(words)
            }
            InspectedClass::Unicode(class) => {
                let mut ranges = ExactVec::try_with_capacity(class.ranges().len()).map_err(
                    |error| match error {
                        CopyError::LayoutOverflow => crate::BuildError::InternalInvariant(
                            "bounded word-class Unicode range layout overflowed",
                        ),
                        CopyError::AllocationFailed => crate::BuildError::AllocationFailed {
                            structure: "bounded word-class Unicode ranges",
                            additional: class.ranges().len(),
                        },
                    },
                )?;
                let mut ascii_words = [0_u64; 2];
                for range in class.ranges() {
                    ranges
                        .try_push(ScalarRange {
                            start: range.start(),
                            end: range.end(),
                        })
                        .map_err(|_| {
                            crate::BuildError::InternalInvariant(
                                "exact Unicode range owner exhausted its admitted capacity",
                            )
                        })?;
                    set_unicode_ascii_range(&mut ascii_words, range.start(), range.end());
                }
                ClassMatcher::Unicode {
                    ascii_words,
                    ranges,
                }
            }
        };
        Ok(Plan {
            mode: self.mode,
            class,
            minimum_units: self.minimum_units,
            maximum_units: self.maximum_units,
            storage_bytes: self.storage_bytes,
        })
    }
}

impl Plan {
    #[allow(
        clippy::unused_self,
        reason = "the facade obtains the runtime identity from the retained plan variant"
    )]
    pub(crate) const fn plan_id(&self) -> &'static str {
        PLAN_ID
    }

    pub(crate) const fn storage_bytes(&self) -> usize {
        self.storage_bytes
    }

    pub(crate) fn find_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, Accounting), Error> {
        self.search_window(haystack, window, limits, true)
    }

    pub(crate) fn shortest_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<usize>, Accounting), Error> {
        self.search_window(haystack, window, limits, false)
            .map(|(matched, accounting)| (matched.map(Match::end), accounting))
    }

    fn search_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
        greedy: bool,
    ) -> Result<(Option<Match>, Accounting), Error> {
        validate_window(haystack, window)?;
        let mut accounting = Accounting {
            work: 0,
            bytes_examined: 0,
            scalars_decoded: 0,
        };
        let mut position = window.start();
        while position < window.end() {
            let (admitted, mut width, run_word) =
                self.classify_unit(haystack, position, window.end(), &mut accounting, limits)?;
            if !admitted {
                position = position
                    .checked_add(width)
                    .ok_or(Error::WorkLimitExceeded {
                        needed: u64::MAX,
                        limit: limits.max_work,
                    })?;
                continue;
            }

            let run_start = position;
            let mut run_units = 0_usize;
            let mut homogeneous_wordness = true;
            loop {
                run_units = run_units.checked_add(1).ok_or(Error::WorkLimitExceeded {
                    needed: u64::MAX,
                    limit: limits.max_work,
                })?;
                position = position
                    .checked_add(width)
                    .ok_or(Error::WorkLimitExceeded {
                        needed: u64::MAX,
                        limit: limits.max_work,
                    })?;
                if position >= window.end() {
                    break;
                }
                let (next_admitted, next_width, next_word) =
                    self.classify_unit(haystack, position, window.end(), &mut accounting, limits)?;
                if !next_admitted {
                    break;
                }
                homogeneous_wordness &= next_word == run_word;
                width = next_width;
            }

            if run_units >= self.minimum_units
                && let Some(matched) = self.search_class_run(
                    haystack,
                    run_start,
                    position,
                    run_units,
                    homogeneous_wordness,
                    &mut accounting,
                    limits,
                    greedy,
                )?
            {
                return Ok((Some(matched), accounting));
            }
        }
        Ok((None, accounting))
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the two monotone cursors share the caller's exact search ledger"
    )]
    fn search_class_run(
        &self,
        haystack: &[u8],
        run_start: usize,
        run_end: usize,
        run_units: usize,
        homogeneous_wordness: bool,
        accounting: &mut Accounting,
        limits: SearchLimits,
        greedy: bool,
    ) -> Result<Option<Match>, Error> {
        if homogeneous_wordness {
            if self
                .maximum_units
                .is_some_and(|maximum| run_units > maximum)
            {
                return Ok(None);
            }
            charge(accounting, limits)?;
            if !self.is_word_boundary(haystack, run_start) {
                return Ok(None);
            }
            charge(accounting, limits)?;
            return Ok(self.is_word_boundary(haystack, run_end).then_some(Match {
                start: run_start,
                end: run_end,
            }));
        }

        let mut starts = BoundaryCursor::new(run_start, run_end);
        let mut candidate = starts.next(self, haystack, accounting, limits)?;
        let mut ends = BoundaryCursor::new(run_start, run_end);

        while let Some(end) = ends.next(self, haystack, accounting, limits)? {
            let Some(latest_start) = end.units.checked_sub(self.minimum_units) else {
                continue;
            };
            let earliest_start = self
                .maximum_units
                .map_or(0, |maximum| end.units.saturating_sub(maximum));
            while candidate.is_some_and(|start| start.units < earliest_start) {
                candidate = starts.next(self, haystack, accounting, limits)?;
            }
            let Some(start) = candidate else {
                return Ok(None);
            };
            if start.units >= run_units || start.units > latest_start {
                continue;
            }
            if !greedy {
                return Ok(Some(Match {
                    start: start.byte,
                    end: end.byte,
                }));
            }

            let final_unit = self.maximum_units.map_or(run_units, |maximum| {
                start.units.saturating_add(maximum).min(run_units)
            });
            let mut selected_end = end.byte;
            while let Some(later) = ends.next(self, haystack, accounting, limits)? {
                if later.units > final_unit {
                    break;
                }
                selected_end = later.byte;
            }
            return Ok(Some(Match {
                start: start.byte,
                end: selected_end,
            }));
        }
        Ok(None)
    }

    fn classify_unit(
        &self,
        haystack: &[u8],
        position: usize,
        end: usize,
        accounting: &mut Accounting,
        limits: SearchLimits,
    ) -> Result<(bool, usize, bool), Error> {
        charge(accounting, limits)?;
        match &self.class {
            ClassMatcher::Bytes(words) => {
                accounting.bytes_examined = accounting.bytes_examined.saturating_add(1);
                accounting.scalars_decoded = accounting.scalars_decoded.saturating_add(1);
                let byte = haystack[position];
                Ok((byte_set_contains(*words, byte), 1, is_ascii_word(byte)))
            }
            ClassMatcher::Unicode {
                ascii_words,
                ranges,
            } => {
                let Some((scalar, width)) = decode_first(&haystack[position..end]) else {
                    accounting.bytes_examined = accounting.bytes_examined.saturating_add(1);
                    return Ok((false, 1, false));
                };
                accounting.bytes_examined = accounting.bytes_examined.saturating_add(width);
                accounting.scalars_decoded = accounting.scalars_decoded.saturating_add(1);
                let admitted = if scalar.is_ascii() {
                    let byte = u8::try_from(u32::from(scalar))
                        .expect("an ASCII scalar fits exactly in one byte");
                    ascii_set_contains(*ascii_words, byte)
                } else {
                    unicode_ranges_contain(ranges, scalar)
                };
                Ok((admitted, width, admitted && is_unicode_word(scalar)))
            }
        }
    }

    fn known_member_width(&self, haystack: &[u8], position: usize, end: usize) -> usize {
        match self.mode {
            BoundaryMode::Ascii => 1,
            BoundaryMode::Unicode => decode_first(&haystack[position..end])
                .map(|(_, width)| width)
                .expect("a retained Unicode class run contains only decoded scalars"),
        }
    }

    fn is_word_boundary(&self, haystack: &[u8], position: usize) -> bool {
        match self.mode {
            BoundaryMode::Ascii => {
                let before = position
                    .checked_sub(1)
                    .and_then(|index| haystack.get(index))
                    .is_some_and(|&byte| is_ascii_word(byte));
                let after = haystack
                    .get(position)
                    .is_some_and(|&byte| is_ascii_word(byte));
                before != after
            }
            BoundaryMode::Unicode => {
                let before = decode_last(&haystack[..position])
                    .is_some_and(|(scalar, _)| is_unicode_word(scalar));
                let after = decode_first(&haystack[position..])
                    .is_some_and(|(scalar, _)| is_unicode_word(scalar));
                before != after
            }
        }
    }
}

/// Inspect one exact root without allocating or retaining borrowed HIR data.
///
/// Unsupported shapes return `Ok(None)`. Crossing the caller's planner bound
/// is a typed refusal even when the eventual shape would have been
/// unsupported, so every visited node/range remains covered by the published
/// construction budget.
#[allow(
    clippy::too_many_lines,
    reason = "one allocation-free structural proof keeps every shape and range charge adjacent"
)]
pub(crate) fn inspect(
    hir: &Hir,
    max_planner_work: u64,
) -> Result<Option<Inspection<'_>>, InspectionError> {
    let mut work = 0_u64;
    let root = peel_captures(hir, &mut work, max_planner_work)?;
    let HirKind::Concat(parts) = root.kind() else {
        return Ok(None);
    };
    charge_build(
        &mut work,
        u64::try_from(parts.len())
            .map_err(|_| InspectionError::ArithmeticOverflow("concat length"))?,
        max_planner_work,
    )?;
    let [start, repeated, end] = parts.as_slice() else {
        return Ok(None);
    };
    let start = peel_captures(start, &mut work, max_planner_work)?;
    let end = peel_captures(end, &mut work, max_planner_work)?;
    let mode = match (start.kind(), end.kind()) {
        (HirKind::Look(Look::WordAscii), HirKind::Look(Look::WordAscii)) => BoundaryMode::Ascii,
        (HirKind::Look(Look::WordUnicode), HirKind::Look(Look::WordUnicode)) => {
            BoundaryMode::Unicode
        }
        _ => return Ok(None),
    };
    let repeated = peel_captures(repeated, &mut work, max_planner_work)?;
    let HirKind::Repetition(repetition) = repeated.kind() else {
        return Ok(None);
    };
    charge_build(&mut work, 1, max_planner_work)?;
    if repetition.min == 0 || !repetition.greedy {
        return Ok(None);
    }
    let minimum_units = usize::try_from(repetition.min)
        .map_err(|_| InspectionError::ArithmeticOverflow("minimum repetition"))?;
    let maximum_units = repetition
        .max
        .map(usize::try_from)
        .transpose()
        .map_err(|_| InspectionError::ArithmeticOverflow("maximum repetition"))?;
    let class = peel_captures(&repetition.sub, &mut work, max_planner_work)?;
    let inspected = match (mode, class.kind()) {
        (BoundaryMode::Ascii, HirKind::Class(Class::Bytes(class))) => {
            let range_count = u64::try_from(class.ranges().len())
                .map_err(|_| InspectionError::ArithmeticOverflow("byte class ranges"))?;
            let members = class.ranges().iter().try_fold(0_u64, |total, range| {
                let width = u64::from(range.end())
                    .checked_sub(u64::from(range.start()))
                    .and_then(|value| value.checked_add(1))
                    .ok_or(InspectionError::ArithmeticOverflow("byte class members"))?;
                total
                    .checked_add(width)
                    .ok_or(InspectionError::ArithmeticOverflow("byte class members"))
            })?;
            charge_build(&mut work, range_count, max_planner_work)?;
            charge_build(&mut work, members, max_planner_work)?;
            InspectedClass::Bytes(class)
        }
        (BoundaryMode::Unicode, HirKind::Class(Class::Unicode(class))) => {
            let range_count = u64::try_from(class.ranges().len())
                .map_err(|_| InspectionError::ArithmeticOverflow("Unicode class ranges"))?;
            // One range inspection and one exact retained-range copy.
            let range_work =
                range_count
                    .checked_mul(2)
                    .ok_or(InspectionError::ArithmeticOverflow(
                        "Unicode class range work",
                    ))?;
            charge_build(&mut work, range_work, max_planner_work)?;
            let ascii_members =
                class.ranges().iter().try_fold(0_u64, |total, range| {
                    let start = u32::from(range.start());
                    let end = u32::from(range.end()).min(0x7F);
                    if start > end {
                        Ok(total)
                    } else {
                        let width = end
                            .checked_sub(start)
                            .and_then(|value| value.checked_add(1))
                            .ok_or(InspectionError::ArithmeticOverflow(
                                "Unicode ASCII-class members",
                            ))?;
                        total.checked_add(u64::from(width)).ok_or(
                            InspectionError::ArithmeticOverflow("Unicode ASCII-class members"),
                        )
                    }
                })?;
            charge_build(&mut work, ascii_members, max_planner_work)?;
            InspectedClass::Unicode(class)
        }
        _ => return Ok(None),
    };
    let range_bytes = match inspected {
        InspectedClass::Bytes(_) => 0,
        InspectedClass::Unicode(class) => class
            .ranges()
            .len()
            .checked_mul(core::mem::size_of::<ScalarRange>())
            .ok_or(InspectionError::ArithmeticOverflow(
                "Unicode class retained bytes",
            ))?,
    };
    let storage_bytes = core::mem::size_of::<Plan>()
        .checked_add(range_bytes)
        .ok_or(InspectionError::ArithmeticOverflow(
            "bounded word-class plan storage",
        ))?;
    Ok(Some(Inspection {
        mode,
        class: inspected,
        minimum_units,
        maximum_units,
        planner_work: work,
        storage_bytes,
    }))
}

fn peel_captures<'a>(
    mut hir: &'a Hir,
    work: &mut u64,
    limit: u64,
) -> Result<&'a Hir, InspectionError> {
    loop {
        charge_build(work, 1, limit)?;
        let HirKind::Capture(capture) = hir.kind() else {
            return Ok(hir);
        };
        hir = &capture.sub;
    }
}

fn charge_build(work: &mut u64, amount: u64, limit: u64) -> Result<(), InspectionError> {
    let needed = work
        .checked_add(amount)
        .ok_or(InspectionError::ArithmeticOverflow("planner work"))?;
    if needed > limit {
        return Err(InspectionError::WorkLimit { needed, limit });
    }
    *work = needed;
    Ok(())
}

fn validate_window(haystack: &[u8], window: SearchWindow) -> Result<(), Error> {
    if window.start() > window.end() || window.end() > haystack.len() {
        return Err(Error::InvalidWindow {
            start: window.start(),
            end: window.end(),
            haystack_len: haystack.len(),
        });
    }
    Ok(())
}

fn charge(accounting: &mut Accounting, limits: SearchLimits) -> Result<(), Error> {
    let needed = accounting.work.saturating_add(1);
    if needed > limits.max_work {
        return Err(Error::WorkLimitExceeded {
            needed,
            limit: limits.max_work,
        });
    }
    accounting.work = needed;
    Ok(())
}

fn set_byte_range(words: &mut [u64; 4], start: u8, end: u8) {
    let mut byte = start;
    loop {
        let word = usize::from(byte) / 64;
        let bit = usize::from(byte) % 64;
        words[word] |= 1_u64 << bit;
        if byte == end {
            break;
        }
        byte = byte
            .checked_add(1)
            .expect("a nonterminal byte-class member is below 255");
    }
}

fn set_unicode_ascii_range(words: &mut [u64; 2], start: char, end: char) {
    let start = u32::from(start);
    let end = u32::from(end).min(0x7F);
    if start > end {
        return;
    }
    for codepoint in start..=end {
        let byte = u8::try_from(codepoint).expect("the range was clipped to ASCII");
        let word = usize::from(byte) / 64;
        let bit = usize::from(byte) % 64;
        words[word] |= 1_u64 << bit;
    }
}

fn byte_set_contains(words: [u64; 4], byte: u8) -> bool {
    let word = usize::from(byte) / 64;
    let bit = usize::from(byte) % 64;
    words[word] & (1_u64 << bit) != 0
}

fn ascii_set_contains(words: [u64; 2], byte: u8) -> bool {
    let word = usize::from(byte) / 64;
    let bit = usize::from(byte) % 64;
    words[word] & (1_u64 << bit) != 0
}

fn unicode_ranges_contain(ranges: &[ScalarRange], scalar: char) -> bool {
    let index = ranges.partition_point(|range| range.end < scalar);
    ranges.get(index).is_some_and(|range| range.start <= scalar)
}

fn is_ascii_word(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
}

fn is_unicode_word(scalar: char) -> bool {
    if scalar.is_ascii() {
        return scalar == '_' || scalar.is_ascii_alphanumeric();
    }
    regex_syntax::try_is_word_character(scalar)
        .expect("fre enables regex-syntax's Unicode Perl tables")
}

fn decode_first(bytes: &[u8]) -> Option<(char, usize)> {
    let first = *bytes.first()?;
    if first.is_ascii() {
        return Some((char::from(first), 1));
    }
    let width = match first {
        0xC2..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF4 => 4,
        _ => return None,
    };
    let scalar = core::str::from_utf8(bytes.get(..width)?)
        .ok()?
        .chars()
        .next()?;
    Some((scalar, width))
}

fn decode_last(bytes: &[u8]) -> Option<(char, usize)> {
    let mut start = bytes.len().checked_sub(1)?;
    let lower = bytes.len().saturating_sub(4);
    while start > lower && matches!(bytes[start], 0x80..=0xBF) {
        start = start.checked_sub(1)?;
    }
    let (scalar, width) = decode_first(&bytes[start..])?;
    (start.checked_add(width) == Some(bytes.len())).then_some((scalar, width))
}

#[cfg(test)]
mod tests {
    use regex_syntax::ParserBuilder;

    use super::{PLAN_ID, inspect};
    use crate::{SearchLimits, SearchWindow};

    fn plan(pattern: &str, unicode: bool) -> super::Plan {
        let hir = ParserBuilder::new()
            .unicode(unicode)
            .utf8(false)
            .build()
            .parse(pattern)
            .expect("test pattern");
        inspect(&hir, u64::MAX)
            .expect("inspection")
            .expect("eligible shape")
            .build()
            .expect("plan build")
    }

    #[test]
    fn exact_shape_and_existing_unbounded_word_shape_are_structurally_visible() {
        let bounded = plan(r"(?-u:\b[A-Za-z]{3,9}\b)", false);
        assert_eq!(bounded.plan_id(), PLAN_ID);
        let unicode = plan(r"\b\p{L}{2,8}\b", true);
        assert_eq!(unicode.plan_id(), PLAN_ID);
        // The facade orders the established exact-word route first, but this
        // inspector remains a complete proof for arbitrary unbounded classes.
        let unbounded = plan(r"\b\p{L}{2,}\b", true);
        assert_eq!(unbounded.plan_id(), PLAN_ID);
    }

    #[test]
    fn mixed_wordness_uses_leftmost_start_and_greedy_boundary_end() {
        let plan = plan(r"(?-u:\b[A/_-]{2,5}\b)", false);
        let haystack = b" A-A/A.";
        let matched = plan
            .find_window(
                haystack,
                SearchWindow::full(haystack),
                SearchLimits::unlimited(),
            )
            .expect("search")
            .0
            .expect("match");
        assert_eq!(matched.range(), 1..6);
    }

    #[test]
    fn malformed_unicode_bytes_are_nonmembers_and_nonword_context() {
        let plan = plan(r"\b\p{L}{2,8}\b", true);
        let haystack = [0xFF, b'a', b'b', 0xCE, 0xFF, b'c', b'd'];
        let first = plan
            .find_window(
                &haystack,
                SearchWindow::full(&haystack),
                SearchLimits::unlimited(),
            )
            .expect("search")
            .0
            .expect("first match");
        assert_eq!(first.range(), 1..3);
    }
}
