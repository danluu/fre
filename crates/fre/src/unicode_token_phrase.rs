//! Direct complete-span visitation for a Unicode token phrase.
//!
//! The construction proof accepts exactly
//! `\b\w+\s+LITERAL\s+\w+\b` under Unicode semantics. Execution uses the
//! required literal as an anchor and decodes only its adjacent token runs.
//! Ordinary search and materializing span APIs remain on their incumbent
//! plan; this sidecar is exposed only through complete-span visitation.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "the operation preflight bounds the simple linear counters"
)]

use core::fmt;

use memchr::memmem::Finder;
use regex_syntax::{
    ParserBuilder,
    hir::{Class, ClassUnicode, Hir, HirKind, Look},
};

/// Stable identity of the construction-proved Unicode token phrase.
pub const PLAN_ID: &str = "unicode-token-phrase.literal-anchor.v1";
/// Stable identity of direct complete-span visitation.
pub const SPAN_VISIT_OPERATION_ID: &str = "unicode-token-phrase.literal-anchor-span-visit.v1";

const MAX_LITERAL_BYTES: usize = 64;
const FIXED_WORK: u64 = 32;

/// Source-independent identity retained by the sidecar.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Identity {
    pub plan_id: &'static str,
    pub operation_id: &'static str,
    pub literal_bytes: usize,
    pub unicode: bool,
    pub greedy: bool,
    pub complete_word_boundaries: bool,
    pub non_overlapping: bool,
}

/// Prospective envelope checked before the first source read or callback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpperBounds {
    pub input_bytes: usize,
    pub source_reads: u64,
    pub work: u64,
    pub finder_calls: usize,
    pub anchor_candidates: usize,
    pub decode_attempts: usize,
    pub match_events: usize,
    pub count: u64,
    pub span_sum: u64,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

/// Exact no-clock counters from one traversal.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Actual {
    pub source_reads: u64,
    pub work: u64,
    pub finder_calls: usize,
    pub anchor_candidates: usize,
    pub decode_attempts: usize,
    pub matches: usize,
    pub span_sum: u64,
    pub scratch_bytes: usize,
}

/// Closed receipt for one direct traversal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Accounting {
    pub identity: Identity,
    pub upper_bounds: UpperBounds,
    pub actual: Actual,
}

/// Resource limits checked prospectively.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    pub max_input_bytes: usize,
    pub max_source_reads: u64,
    pub max_work: u64,
    pub max_finder_calls: usize,
    pub max_anchor_candidates: usize,
    pub max_decode_attempts: usize,
    pub max_match_events: usize,
    pub max_count: u64,
    pub max_span_sum: u64,
    pub max_scratch_bytes: usize,
    pub max_persistent_bytes: usize,
    pub max_peak_bytes: usize,
}

impl Limits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_input_bytes: usize::MAX,
            max_source_reads: u64::MAX,
            max_work: u64::MAX,
            max_finder_calls: usize::MAX,
            max_anchor_candidates: usize::MAX,
            max_decode_attempts: usize::MAX,
            max_match_events: usize::MAX,
            max_count: u64::MAX,
            max_span_sum: u64::MAX,
            max_scratch_bytes: usize::MAX,
            max_persistent_bytes: usize::MAX,
            max_peak_bytes: usize::MAX,
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_input_bytes: 64 * 1024 * 1024,
            max_source_reads: 1024 * 1024 * 1024,
            max_work: 2_000_000_000,
            max_finder_calls: 64 * 1024 * 1024,
            max_anchor_candidates: 64 * 1024 * 1024,
            max_decode_attempts: 512 * 1024 * 1024,
            max_match_events: 64 * 1024 * 1024,
            max_count: 64 * 1024 * 1024,
            max_span_sum: 64 * 1024 * 1024,
            max_scratch_bytes: 0,
            max_persistent_bytes: 0,
            max_peak_bytes: 0,
        }
    }
}

/// Checked refusal from direct visitation.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    ArithmeticOverflow { computation: &'static str },
    InputBytesLimit { needed: usize, limit: usize },
    SourceReadsLimit { needed: u64, limit: u64 },
    WorkLimit { needed: u64, limit: u64 },
    FinderCallLimit { needed: usize, limit: usize },
    AnchorCandidateLimit { needed: usize, limit: usize },
    DecodeAttemptLimit { needed: usize, limit: usize },
    MatchEventLimit { needed: usize, limit: usize },
    CountLimit { needed: u64, limit: u64 },
    SpanSumLimit { needed: u64, limit: u64 },
    ScratchLimit { needed: usize, limit: usize },
    PersistentLimit { needed: usize, limit: usize },
    PeakLimit { needed: usize, limit: usize },
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Unicode token-phrase traversal failed: {self:?}")
    }
}

impl std::error::Error for Error {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Span {
    pub start: usize,
    pub end: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct VisitResult {
    pub matches: usize,
    pub span_sum: u64,
    pub accounting: Accounting,
}

/// Inline plan copied only after the HIR proof succeeds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Plan {
    literal: [u8; MAX_LITERAL_BYTES],
    literal_len: u8,
}

impl Plan {
    fn literal(&self) -> &[u8] {
        &self.literal[..usize::from(self.literal_len)]
    }

    pub(crate) const fn identity(self) -> Identity {
        Identity {
            plan_id: PLAN_ID,
            operation_id: SPAN_VISIT_OPERATION_ID,
            literal_bytes: self.literal_len as usize,
            unicode: true,
            greedy: true,
            complete_word_boundaries: true,
            non_overlapping: true,
        }
    }

    fn upper_bounds(self, input_bytes: usize) -> Result<UpperBounds, Error> {
        let literal_bytes = usize::from(self.literal_len);
        let anchor_candidates = input_bytes / literal_bytes;
        let finder_calls = anchor_candidates
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow {
                computation: "finder-call bound",
            })?;
        // Each non-overlapping anchor can contribute at most its neighboring
        // word and whitespace runs. Those neighboring runs form a bounded-
        // overlap interval family. Eight attempts per source byte leaves room
        // for failed endpoint probes and the duplicated transition probe.
        let decode_attempts = input_bytes
            .checked_mul(8)
            .and_then(|value| value.checked_add(anchor_candidates.saturating_mul(8)))
            .ok_or(Error::ArithmeticOverflow {
                computation: "decode-attempt bound",
            })?;
        let source_reads = u64::try_from(input_bytes)
            .ok()
            .and_then(|finder| {
                u64::try_from(decode_attempts)
                    .ok()
                    .and_then(|attempts| attempts.checked_mul(4))
                    .and_then(|decode| finder.checked_add(decode))
            })
            .ok_or(Error::ArithmeticOverflow {
                computation: "source-read bound",
            })?;
        let work = FIXED_WORK
            .checked_add(source_reads)
            .and_then(|value| {
                u64::try_from(anchor_candidates)
                    .ok()
                    .and_then(|anchors| anchors.checked_mul(4))
                    .and_then(|anchors| value.checked_add(anchors))
            })
            .ok_or(Error::ArithmeticOverflow {
                computation: "work bound",
            })?;
        let minimum_match_bytes =
            literal_bytes
                .checked_add(4)
                .ok_or(Error::ArithmeticOverflow {
                    computation: "minimum match width",
                })?;
        let match_events = input_bytes / minimum_match_bytes;
        let count = u64::try_from(match_events).map_err(|_| Error::ArithmeticOverflow {
            computation: "match-event count",
        })?;
        let span_sum = u64::try_from(input_bytes).map_err(|_| Error::ArithmeticOverflow {
            computation: "span-sum bound",
        })?;
        Ok(UpperBounds {
            input_bytes,
            source_reads,
            work,
            finder_calls,
            anchor_candidates,
            decode_attempts,
            match_events,
            count,
            span_sum,
            scratch_bytes: 0,
            persistent_bytes: 0,
            peak_bytes: 0,
        })
    }

    fn preflight(self, input_bytes: usize, limits: Limits) -> Result<UpperBounds, Error> {
        let upper = self.upper_bounds(input_bytes)?;
        macro_rules! refuse {
            ($field:ident, $limit:ident, $variant:ident) => {
                if upper.$field > limits.$limit {
                    return Err(Error::$variant {
                        needed: upper.$field,
                        limit: limits.$limit,
                    });
                }
            };
        }
        refuse!(input_bytes, max_input_bytes, InputBytesLimit);
        refuse!(source_reads, max_source_reads, SourceReadsLimit);
        refuse!(work, max_work, WorkLimit);
        refuse!(finder_calls, max_finder_calls, FinderCallLimit);
        refuse!(
            anchor_candidates,
            max_anchor_candidates,
            AnchorCandidateLimit
        );
        refuse!(decode_attempts, max_decode_attempts, DecodeAttemptLimit);
        refuse!(match_events, max_match_events, MatchEventLimit);
        refuse!(count, max_count, CountLimit);
        refuse!(span_sum, max_span_sum, SpanSumLimit);
        refuse!(scratch_bytes, max_scratch_bytes, ScratchLimit);
        refuse!(persistent_bytes, max_persistent_bytes, PersistentLimit);
        refuse!(peak_bytes, max_peak_bytes, PeakLimit);
        Ok(upper)
    }

    pub(crate) fn visit_spans<F>(
        self,
        haystack: &[u8],
        limits: Limits,
        mut visitor: F,
    ) -> Result<VisitResult, Error>
    where
        F: FnMut(Span),
    {
        let upper = self.preflight(haystack.len(), limits)?;
        let literal = self.literal();
        let finder = Finder::new(literal);
        let mut actual = Actual {
            source_reads: u64::try_from(haystack.len()).map_err(|_| Error::ArithmeticOverflow {
                computation: "finder source bytes",
            })?,
            work: FIXED_WORK,
            ..Actual::default()
        };
        let mut search_from = 0_usize;
        let mut consumed_through = 0_usize;
        loop {
            actual.finder_calls += 1;
            let Some(relative) = finder.find(&haystack[search_from..]) else {
                break;
            };
            let literal_start = search_from + relative;
            search_from = literal_start + literal.len();
            actual.anchor_candidates += 1;
            if literal_start < consumed_through {
                continue;
            }
            let Some((start, end)) =
                phrase_span(haystack, literal_start, literal.len(), &mut actual)
            else {
                continue;
            };
            if start < consumed_through {
                continue;
            }
            actual.matches += 1;
            let width = end - start;
            actual.span_sum = actual
                .span_sum
                .checked_add(u64::try_from(width).map_err(|_| Error::ArithmeticOverflow {
                    computation: "match width",
                })?)
                .ok_or(Error::ArithmeticOverflow {
                    computation: "span sum",
                })?;
            visitor(Span { start, end });
            consumed_through = end;
        }
        actual.source_reads = actual
            .source_reads
            .checked_add(
                u64::try_from(actual.decode_attempts)
                    .map_err(|_| Error::ArithmeticOverflow {
                        computation: "decode attempts as source reads",
                    })?
                    .checked_mul(4)
                    .ok_or(Error::ArithmeticOverflow {
                        computation: "decode source reads",
                    })?,
            )
            .ok_or(Error::ArithmeticOverflow {
                computation: "complete source reads",
            })?;
        actual.work = actual
            .work
            .checked_add(actual.source_reads)
            .and_then(|value| {
                u64::try_from(actual.anchor_candidates)
                    .ok()
                    .and_then(|anchors| anchors.checked_mul(4))
                    .and_then(|anchors| value.checked_add(anchors))
            })
            .ok_or(Error::ArithmeticOverflow {
                computation: "actual work",
            })?;
        debug_assert!(actual.source_reads <= upper.source_reads);
        debug_assert!(actual.work <= upper.work);
        debug_assert!(actual.finder_calls <= upper.finder_calls);
        debug_assert!(actual.anchor_candidates <= upper.anchor_candidates);
        debug_assert!(actual.decode_attempts <= upper.decode_attempts);
        debug_assert!(actual.matches <= upper.match_events);
        debug_assert!(actual.span_sum <= upper.span_sum);
        Ok(VisitResult {
            matches: actual.matches,
            span_sum: actual.span_sum,
            accounting: Accounting {
                identity: self.identity(),
                upper_bounds: upper,
                actual,
            },
        })
    }
}

fn phrase_span(
    haystack: &[u8],
    literal_start: usize,
    literal_len: usize,
    actual: &mut Actual,
) -> Option<(usize, usize)> {
    let literal_end = literal_start.checked_add(literal_len)?;

    let mut cursor = literal_start;
    let mut spaces = 0_usize;
    while let Some((scalar, start)) = decode_last_counted(haystack, cursor, actual) {
        if !is_unicode_space(scalar) {
            break;
        }
        spaces += 1;
        cursor = start;
    }
    if spaces == 0 {
        return None;
    }
    let mut words = 0_usize;
    while let Some((scalar, start)) = decode_last_counted(haystack, cursor, actual) {
        if !is_unicode_word(scalar) {
            break;
        }
        words += 1;
        cursor = start;
    }
    if words == 0 {
        return None;
    }
    let match_start = cursor;
    if !unicode_boundary_counted(haystack, match_start, actual) {
        return None;
    }

    cursor = literal_end;
    spaces = 0;
    while let Some((scalar, end)) = decode_first_counted(haystack, cursor, actual) {
        if !is_unicode_space(scalar) {
            break;
        }
        spaces += 1;
        cursor = end;
    }
    if spaces == 0 {
        return None;
    }
    words = 0;
    while let Some((scalar, end)) = decode_first_counted(haystack, cursor, actual) {
        if !is_unicode_word(scalar) {
            break;
        }
        words += 1;
        cursor = end;
    }
    (words > 0 && unicode_boundary_counted(haystack, cursor, actual))
        .then_some((match_start, cursor))
}

fn unicode_boundary_counted(haystack: &[u8], position: usize, actual: &mut Actual) -> bool {
    actual.decode_attempts += 2;
    let word_before = decode_last_for_boundary(&haystack[..position]).is_some_and(is_unicode_word);
    let word_after = decode_first(&haystack[position..])
        .map(|(scalar, _)| scalar)
        .is_some_and(is_unicode_word);
    word_before != word_after
}

// Match regex-automata's reverse Unicode-boundary decoding: at most three
// continuation bytes are inspected and a valid leading scalar is classified
// even when an extra trailing continuation byte makes the whole suffix
// malformed. The consuming word-run decoder remains strict.
fn decode_last_for_boundary(bytes: &[u8]) -> Option<char> {
    let floor = bytes.len().saturating_sub(4);
    let mut start = bytes.len().checked_sub(1)?;
    while start > floor && bytes[start] & 0xC0 == 0x80 {
        start -= 1;
    }
    decode_first(bytes.get(start..)?).map(|(scalar, _)| scalar)
}

fn decode_first_counted(
    haystack: &[u8],
    position: usize,
    actual: &mut Actual,
) -> Option<(char, usize)> {
    actual.decode_attempts += 1;
    let (scalar, width) = decode_first(haystack.get(position..)?)?;
    Some((scalar, position + width))
}

fn decode_last_counted(
    haystack: &[u8],
    position: usize,
    actual: &mut Actual,
) -> Option<(char, usize)> {
    actual.decode_attempts += 1;
    let (scalar, width) = decode_last(haystack.get(..position)?)?;
    Some((scalar, position - width))
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
    let last = *bytes.last()?;
    if last.is_ascii() {
        return Some((char::from(last), 1));
    }
    let floor = bytes.len().saturating_sub(4);
    let mut start = bytes.len() - 1;
    while start > floor && bytes[start] & 0xC0 == 0x80 {
        start -= 1;
    }
    let source = core::str::from_utf8(bytes.get(start..)?).ok()?;
    let mut scalars = source.chars();
    let scalar = scalars.next()?;
    scalars
        .next()
        .is_none()
        .then_some((scalar, bytes.len() - start))
}

fn is_unicode_word(scalar: char) -> bool {
    if scalar.is_ascii() {
        return scalar == '_' || scalar.is_ascii_alphanumeric();
    }
    regex_syntax::try_is_word_character(scalar)
        .expect("fre enables regex-syntax's Unicode Perl tables")
}

const fn is_unicode_space(scalar: char) -> bool {
    matches!(
        scalar,
        '\u{9}'..='\u{d}'
            | '\u{20}'
            | '\u{85}'
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'..='\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
    )
}

/// Successful or declined HIR proof with cumulative planner work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InspectionOutcome {
    Eligible { plan: Plan, planner_work: u64 },
    Ineligible { planner_work: u64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InspectionError {
    WorkLimit {
        actual: u64,
        needed: u64,
        limit: u64,
    },
    ArithmeticOverflow,
}

struct Meter {
    work: u64,
    limit: u64,
}

impl Meter {
    const fn new(work: u64, limit: u64) -> Self {
        Self { work, limit }
    }

    fn charge(&mut self, units: usize) -> Result<(), InspectionError> {
        let units = u64::try_from(units).map_err(|_| InspectionError::ArithmeticOverflow)?;
        let needed = self
            .work
            .checked_add(units)
            .ok_or(InspectionError::ArithmeticOverflow)?;
        if needed > self.limit {
            return Err(InspectionError::WorkLimit {
                actual: self.work,
                needed,
                limit: self.limit,
            });
        }
        self.work = needed;
        Ok(())
    }
}

pub(crate) fn inspect(
    hir: &Hir,
    initial_work: u64,
    limit: u64,
) -> Result<InspectionOutcome, InspectionError> {
    let mut meter = Meter::new(initial_work, limit);
    let root = transparent(hir, &mut meter)?;
    let HirKind::Concat(parts) = root.kind() else {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: meter.work,
        });
    };
    meter.charge(parts.len())?;
    let [
        left_boundary,
        left_word,
        left_space,
        literal,
        right_space,
        right_word,
        right_boundary,
    ] = parts.as_slice()
    else {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: meter.work,
        });
    };
    if !unicode_boundary(left_boundary, &mut meter)?
        || !unicode_boundary(right_boundary, &mut meter)?
    {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: meter.work,
        });
    }
    let word_class = parsed_class(r"\w")?;
    let space_class = parsed_class(r"\s")?;
    if !greedy_plus_class(left_word, &word_class, &mut meter)?
        || !greedy_plus_class(right_word, &word_class, &mut meter)?
        || !greedy_plus_class(left_space, &space_class, &mut meter)?
        || !greedy_plus_class(right_space, &space_class, &mut meter)?
    {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: meter.work,
        });
    }
    let literal = transparent(literal, &mut meter)?;
    let HirKind::Literal(literal) = literal.kind() else {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: meter.work,
        });
    };
    meter.charge(literal.0.len())?;
    if literal.0.is_empty() || literal.0.len() > MAX_LITERAL_BYTES {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: meter.work,
        });
    }
    let Ok(text) = core::str::from_utf8(&literal.0) else {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: meter.work,
        });
    };
    if !text.chars().all(is_unicode_word) {
        return Ok(InspectionOutcome::Ineligible {
            planner_work: meter.work,
        });
    }
    let mut bytes = [0_u8; MAX_LITERAL_BYTES];
    bytes[..literal.0.len()].copy_from_slice(&literal.0);
    Ok(InspectionOutcome::Eligible {
        plan: Plan {
            literal: bytes,
            literal_len: u8::try_from(literal.0.len())
                .map_err(|_| InspectionError::ArithmeticOverflow)?,
        },
        planner_work: meter.work,
    })
}

fn transparent<'a>(hir: &'a Hir, meter: &mut Meter) -> Result<&'a Hir, InspectionError> {
    let mut current = hir;
    loop {
        meter.charge(1)?;
        match current.kind() {
            HirKind::Capture(capture) => current = &capture.sub,
            _ => return Ok(current),
        }
    }
}

fn unicode_boundary(hir: &Hir, meter: &mut Meter) -> Result<bool, InspectionError> {
    let hir = transparent(hir, meter)?;
    meter.charge(1)?;
    Ok(matches!(hir.kind(), HirKind::Look(Look::WordUnicode)))
}

fn greedy_plus_class(
    hir: &Hir,
    expected: &ClassUnicode,
    meter: &mut Meter,
) -> Result<bool, InspectionError> {
    let hir = transparent(hir, meter)?;
    let HirKind::Repetition(repetition) = hir.kind() else {
        return Ok(false);
    };
    meter.charge(1)?;
    if repetition.min != 1 || repetition.max.is_some() || !repetition.greedy {
        return Ok(false);
    }
    let sub = transparent(&repetition.sub, meter)?;
    let HirKind::Class(Class::Unicode(class)) = sub.kind() else {
        return Ok(false);
    };
    meter.charge(class.ranges().len())?;
    Ok(class == expected)
}

fn parsed_class(pattern: &str) -> Result<ClassUnicode, InspectionError> {
    let mut parser = ParserBuilder::new().unicode(true).utf8(false).build();
    let hir = parser
        .parse(pattern)
        .map_err(|_| InspectionError::ArithmeticOverflow)?;
    let HirKind::Class(Class::Unicode(class)) = hir.kind() else {
        return Err(InspectionError::ArithmeticOverflow);
    };
    Ok(class.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hir(pattern: &str) -> Hir {
        ParserBuilder::new()
            .unicode(true)
            .utf8(false)
            .build()
            .parse(pattern)
            .unwrap()
    }

    fn plan(pattern: &str) -> Plan {
        match inspect(&hir(pattern), 0, u64::MAX).unwrap() {
            InspectionOutcome::Eligible { plan, .. } => plan,
            InspectionOutcome::Ineligible { .. } => panic!("pattern was ineligible"),
        }
    }

    #[test]
    fn exact_hir_is_required() {
        assert_eq!(plan(r"\b\w+\s+Холмс\s+\w+\b").literal(), "Холмс".as_bytes());
        for pattern in [
            r"\w+\s+Холмс\s+\w+",
            r"\b\w*\s+Холмс\s+\w+\b",
            r"\b\w+\s*Холмс\s+\w+\b",
            r"(?-u:\b\w+\s+Holmes\s+\w+\b)",
        ] {
            assert!(matches!(
                inspect(&hir(pattern), 0, u64::MAX).unwrap(),
                InspectionOutcome::Ineligible { .. }
            ));
        }
    }

    #[test]
    fn visitor_matches_regex_bytes_on_unicode_and_malformed_sources() {
        let pattern = r"\b\w+\s+β\s+\w+\b";
        let plan = plan(pattern);
        let oracle = regex::bytes::RegexBuilder::new(pattern)
            .unicode(true)
            .build()
            .unwrap();
        let sources: &[&[u8]] = &[
            "один β два; three β four".as_bytes(),
            "x\u{3000}β\u{a0}Ж!".as_bytes(),
            b"a \x80 beta b a \xce\xb2 z \xff",
            b"a \xce\xb2 b c \xce\xb2 d",
            b"_\t\xce\xb2\n9",
            b"\xcc\x81\x80a \xce\xb2 b",
            b"a \xce\xb2 b\x80x",
        ];
        for source in sources {
            let expected = oracle
                .find_iter(source)
                .map(|matched| (matched.start(), matched.end()))
                .collect::<Vec<_>>();
            let mut actual = Vec::new();
            let result = plan
                .visit_spans(source, Limits::unlimited(), |span| {
                    actual.push((span.start, span.end));
                })
                .unwrap();
            assert_eq!(actual, expected, "{source:?}");
            assert_eq!(result.matches, expected.len());
        }
    }

    #[test]
    fn refusal_precedes_callbacks() {
        let plan = plan(r"\b\w+\s+x\s+\w+\b");
        let mut limits = Limits::unlimited();
        limits.max_input_bytes = 4;
        let mut callbacks = 0;
        assert!(matches!(
            plan.visit_spans(b"a x b", limits, |_| callbacks += 1),
            Err(Error::InputBytesLimit { .. })
        ));
        assert_eq!(callbacks, 0);
    }
}
