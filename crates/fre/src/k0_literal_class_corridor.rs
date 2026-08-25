//! Exact ordinary projections for an unanchored literal/class corridor.
//!
//! Construction accepts the capture-transparent byte HIR `L C* R` or
//! `L C+ R`, where both literals are nonempty and no longer than eight bytes,
//! the repetition is greedy and unbounded, and `C` is the exact byte universe
//! minus one barrier. Every literal byte must belong to `C`. This makes an
//! exact left literal part of one maximal `C` run, whose end is found directly
//! with `memchr(barrier, ...)`. If the earliest left literal in that run has no
//! admissible right literal after it, no later left literal in the same run can
//! match either, so unsuccessful runs can be skipped without losing source
//! order.
//!
//! Predicate execution accepts any admissible right literal. Span execution
//! preserves greedy priority by selecting the rightmost overlapping right
//! literal in the maximal run belonging to the globally earliest successful
//! left literal. Captures are transparent because this optional sidecar owns
//! only ordinary value APIs; every accounted, bounded, capture-sensitive, or
//! otherwise nonordinary surface remains with canonical K0.

use memchr::{memchr, memrchr};
use regex_syntax::hir::{Class, ClassBytes, Hir, HirKind};

pub(crate) const MAX_LITERAL_BYTES: usize = 8;

/// The direct route is intended to remove long-input K0 setup and replay.
/// Short calls decline before inspecting source so canonical K0 retains the
/// measured small-input path.
pub(crate) const MIN_INPUT_BYTES: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InlineLiteral {
    bytes: [u8; MAX_LITERAL_BYTES],
    len: u8,
}

impl InlineLiteral {
    fn new(bytes: &[u8]) -> Result<Option<Self>, InspectionError> {
        if bytes.is_empty() || bytes.len() > MAX_LITERAL_BYTES {
            return Ok(None);
        }
        let mut stored = [0_u8; MAX_LITERAL_BYTES];
        stored[..bytes.len()].copy_from_slice(bytes);
        Ok(Some(Self {
            bytes: stored,
            len: u8::try_from(bytes.len()).map_err(|_| InspectionError::ArithmeticOverflow)?,
        }))
    }

    const fn len(self) -> usize {
        self.len as usize
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len()]
    }
}

/// Small immutable proof retained beside canonical K0.
///
/// The excluded byte represents the exact admitted 255-member class. Together
/// with two bounded literals, their lengths, and the repetition minimum, it is
/// sufficient to replay the complete ordinary result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Plan {
    left: InlineLiteral,
    right: InlineLiteral,
    barrier: u8,
    positive: bool,
}

impl Plan {
    pub(crate) const fn minimum_input_bytes(&self) -> usize {
        MIN_INPUT_BYTES
    }

    /// Attempt the exact ordinary full-input existence projection.
    ///
    /// `None` is a performance decline made before source inspection. Once
    /// the input-size gate admits a call, the returned boolean is complete.
    #[inline]
    pub(crate) fn try_ordinary_is_match_full(&self, haystack: &[u8]) -> Option<bool> {
        if haystack.len() < self.minimum_input_bytes() {
            return None;
        }
        Some(self.is_match_full(haystack))
    }

    /// Attempt the exact ordinary full-input leftmost-first span projection.
    ///
    /// `None` is a performance decline made before source inspection. The
    /// inner option is the complete selected match once the size gate admits
    /// the call.
    #[inline]
    pub(crate) fn try_ordinary_find_full(
        &self,
        haystack: &[u8],
    ) -> Option<Option<(usize, usize)>> {
        if haystack.len() < self.minimum_input_bytes() {
            return None;
        }
        Some(self.find_full(haystack))
    }

    fn is_match_full(&self, haystack: &[u8]) -> bool {
        let mut search_start = 0_usize;
        while let Some(left_start) = self.find_left(haystack, search_start) {
            let Some(left_end) = left_start.checked_add(self.left.len()) else {
                return false;
            };
            let run_end = self.maximal_run_end(haystack, left_end);
            let Some(right_floor) = self.right_floor(left_end) else {
                return false;
            };
            if self
                .find_right_forward(haystack, right_floor, run_end)
                .is_some()
            {
                return true;
            }

            // Every left byte is in C, so a left literal cannot cross the
            // barrier at `run_end`. With no admissible R after this run's
            // earliest L, later L occurrences in the run have only a smaller
            // suffix search window and cannot match.
            let Some(next) = run_end.checked_add(1) else {
                return false;
            };
            search_start = next;
        }
        false
    }

    fn find_full(&self, haystack: &[u8]) -> Option<(usize, usize)> {
        let mut search_start = 0_usize;
        while let Some(left_start) = self.find_left(haystack, search_start) {
            let left_end = left_start.checked_add(self.left.len())?;
            let run_end = self.maximal_run_end(haystack, left_end);
            let right_floor = self.right_floor(left_end)?;
            if let Some(right_start) =
                self.find_right_reverse(haystack, right_floor, run_end)
            {
                let match_end = right_start.checked_add(self.right.len())?;
                return Some((left_start, match_end));
            }
            search_start = run_end.checked_add(1)?;
        }
        None
    }

    /// Find the next exact left literal in source order, retaining overlaps.
    fn find_left(&self, haystack: &[u8], from: usize) -> Option<usize> {
        find_literal_forward(haystack, self.left.as_slice(), from, haystack.len())
    }

    fn maximal_run_end(&self, haystack: &[u8], mut position: usize) -> usize {
        position = memchr(self.barrier, &haystack[position..])
            .and_then(|relative| position.checked_add(relative))
            .unwrap_or(haystack.len());
        position
    }

    fn right_floor(&self, left_end: usize) -> Option<usize> {
        if self.positive {
            left_end.checked_add(1)
        } else {
            Some(left_end)
        }
    }

    /// Predicate priority is irrelevant, so accept the first complete suffix.
    fn find_right_forward(
        &self,
        haystack: &[u8],
        floor: usize,
        run_end: usize,
    ) -> Option<usize> {
        find_literal_forward(haystack, self.right.as_slice(), floor, run_end)
    }

    /// Greedy C repetition selects the last possible R start. Searching lead
    /// bytes one position at a time retains overlapping suffix occurrences.
    fn find_right_reverse(
        &self,
        haystack: &[u8],
        floor: usize,
        run_end: usize,
    ) -> Option<usize> {
        let right = self.right.as_slice();
        let last_start = run_end.checked_sub(right.len())?;
        if floor > last_start {
            return None;
        }
        let mut search_end = last_start.checked_add(1)?;
        loop {
            let relative = memrchr(right[0], haystack.get(floor..search_end)?)?;
            let candidate = floor.checked_add(relative)?;
            let candidate_end = candidate.checked_add(right.len())?;
            if haystack.get(candidate..candidate_end) == Some(right) {
                return Some(candidate);
            }
            if candidate == floor {
                return None;
            }
            search_end = candidate;
        }
    }
}

/// Find an exact nonempty literal at an overlapping source-order start in the
/// half-open region `from..end`.
fn find_literal_forward(
    haystack: &[u8],
    literal: &[u8],
    from: usize,
    end: usize,
) -> Option<usize> {
    let last_start = end.checked_sub(literal.len())?;
    if from > last_start {
        return None;
    }
    let mut search_start = from;
    loop {
        let relative = memchr(literal[0], haystack.get(search_start..=last_start)?)?;
        let candidate = search_start.checked_add(relative)?;
        let candidate_end = candidate.checked_add(literal.len())?;
        if haystack.get(candidate..candidate_end) == Some(literal) {
            return Some(candidate);
        }
        search_start = candidate.checked_add(1)?;
        if search_start > last_start {
            return None;
        }
    }
}

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

struct Budget {
    actual: u64,
    limit: u64,
}

impl Budget {
    const fn new(actual: u64, limit: u64) -> Self {
        Self { actual, limit }
    }

    fn charge(&mut self, amount: u64) -> Result<(), InspectionError> {
        let needed = self
            .actual
            .checked_add(amount)
            .ok_or(InspectionError::ArithmeticOverflow)?;
        if needed > self.limit {
            return Err(InspectionError::WorkLimit {
                actual: self.actual,
                needed,
                limit: self.limit,
            });
        }
        self.actual = needed;
        Ok(())
    }
}

/// Inspect an optional ordinary-only K0 corridor sidecar.
///
/// `initial_work` is cumulative work already spent by the owning planner.
/// Every successful charge is reflected in the returned receipt, and a hard
/// limit or arithmetic failure publishes no partial plan.
#[cold]
pub(crate) fn inspect(
    hir: &Hir,
    initial_work: u64,
    work_limit: u64,
) -> Result<InspectionOutcome, InspectionError> {
    let mut budget = Budget::new(initial_work, work_limit);
    let root = transparent(hir, &mut budget)?;
    let HirKind::Concat(parts) = root.kind() else {
        return ineligible(budget);
    };
    budget.charge(1)?;
    let [left_hir, repeated_hir, right_hir] = parts.as_slice() else {
        return ineligible(budget);
    };

    let Some(left) = literal(left_hir, &mut budget)? else {
        return ineligible(budget);
    };

    let repeated = transparent(repeated_hir, &mut budget)?;
    let HirKind::Repetition(repetition) = repeated.kind() else {
        return ineligible(budget);
    };
    budget.charge(1)?;
    if repetition.min > 1 || repetition.max.is_some() || !repetition.greedy {
        return ineligible(budget);
    }
    let positive = repetition.min == 1;

    let repeated = transparent(repetition.sub.as_ref(), &mut budget)?;
    let HirKind::Class(Class::Bytes(class)) = repeated.kind() else {
        return ineligible(budget);
    };
    budget.charge(1)?;
    if class.ranges().is_empty() {
        return ineligible(budget);
    }
    let class_words = class_words(class, &mut budget)?;
    let Some(barrier) = unique_excluded_byte(class_words, &mut budget)? else {
        return ineligible(budget);
    };

    let Some(right) = literal(right_hir, &mut budget)? else {
        return ineligible(budget);
    };

    for &byte in left.as_slice().iter().chain(right.as_slice()) {
        budget.charge(1)?;
        if !contains(class_words, byte) {
            return ineligible(budget);
        }
    }

    Ok(InspectionOutcome::Eligible {
        plan: Plan {
            left,
            right,
            barrier,
            positive,
        },
        planner_work: budget.actual,
    })
}

fn ineligible(budget: Budget) -> Result<InspectionOutcome, InspectionError> {
    Ok(InspectionOutcome::Ineligible {
        planner_work: budget.actual,
    })
}

fn literal(
    hir: &Hir,
    budget: &mut Budget,
) -> Result<Option<InlineLiteral>, InspectionError> {
    let hir = transparent(hir, budget)?;
    let HirKind::Literal(literal) = hir.kind() else {
        return Ok(None);
    };
    budget.charge(1)?;
    budget
        .charge(u64::try_from(literal.0.len()).map_err(|_| InspectionError::ArithmeticOverflow)?)?;
    InlineLiteral::new(literal.0.as_ref())
}

fn class_words(class: &ClassBytes, budget: &mut Budget) -> Result<[u64; 4], InspectionError> {
    let mut words = [0_u64; 4];
    for range in class.ranges() {
        let population = u64::from(range.end())
            .checked_sub(u64::from(range.start()))
            .and_then(|width| width.checked_add(1))
            .ok_or(InspectionError::ArithmeticOverflow)?;
        budget.charge(population)?;
        for byte in range.start()..=range.end() {
            let index = usize::from(byte);
            words[index / 64] |= 1_u64 << (index % 64);
        }
    }
    Ok(words)
}

fn unique_excluded_byte(
    words: [u64; 4],
    budget: &mut Budget,
) -> Result<Option<u8>, InspectionError> {
    let mut excluded = None;
    for value in u16::from(u8::MIN)..=u16::from(u8::MAX) {
        budget.charge(1)?;
        let byte = u8::try_from(value).map_err(|_| InspectionError::ArithmeticOverflow)?;
        if contains(words, byte) {
            continue;
        }
        if excluded.replace(byte).is_some() {
            return Ok(None);
        }
    }
    Ok(excluded)
}

fn transparent<'a>(mut hir: &'a Hir, budget: &mut Budget) -> Result<&'a Hir, InspectionError> {
    loop {
        budget.charge(1)?;
        let HirKind::Capture(capture) = hir.kind() else {
            return Ok(hir);
        };
        hir = capture.sub.as_ref();
    }
}

#[inline]
fn contains(words: [u64; 4], byte: u8) -> bool {
    let index = usize::from(byte);
    words[index / 64] & (1_u64 << (index % 64)) != 0
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        reason = "bounded exhaustive generators and directed fixture offsets"
    )]

    use regex::bytes::RegexBuilder;
    use regex_syntax::ParserBuilder;

    use super::{InspectionOutcome, MIN_INPUT_BYTES, Plan, inspect};

    fn plan(pattern: &str) -> Plan {
        let hir = ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse(pattern)
            .unwrap();
        let InspectionOutcome::Eligible { plan, .. } =
            inspect(&hir, 0, u64::MAX).unwrap()
        else {
            panic!("expected eligible corridor for {pattern:?}");
        };
        plan
    }

    fn assert_same_as_oracle(pattern: &str, haystack: &[u8]) {
        let plan = plan(pattern);
        let oracle = RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap();
        let expected = oracle
            .find(haystack)
            .map(|matched| (matched.start(), matched.end()));
        assert_eq!(
            plan.find_full(haystack),
            expected,
            "span differed for pattern={pattern:?}, haystack={haystack:?}",
        );
        assert_eq!(
            plan.is_match_full(haystack),
            expected.is_some(),
            "existence differed for pattern={pattern:?}, haystack={haystack:?}",
        );
    }

    fn exhaustive(pattern: &str, alphabet: &[u8], maximum_length: usize) {
        let plan = plan(pattern);
        let oracle = RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap();
        let mut frontier = vec![Vec::new()];
        for length in 0..=maximum_length {
            for haystack in &frontier {
                let expected = oracle
                    .find(haystack)
                    .map(|matched| (matched.start(), matched.end()));
                assert_eq!(
                    plan.find_full(haystack),
                    expected,
                    "span differed at length {length}: pattern={pattern:?}, haystack={haystack:?}",
                );
                assert_eq!(
                    plan.is_match_full(haystack),
                    expected.is_some(),
                    "existence differed at length {length}: pattern={pattern:?}, haystack={haystack:?}",
                );
            }
            let mut next = Vec::new();
            for prefix in frontier {
                for &byte in alphabet {
                    let mut haystack = prefix.clone();
                    haystack.push(byte);
                    next.push(haystack);
                }
            }
            frontier = next;
        }
    }

    #[test]
    fn star_plus_barriers_overlaps_and_invalid_bytes_match_the_oracle() {
        for (pattern, haystack) in [
            (r"(?-u:a[^\n]*b)", b"ab".as_slice()),
            (r"(?-u:a[^\n]+b)", b"ab".as_slice()),
            (r"(?-u:a[^\n]+b)", b"aab".as_slice()),
            (r"(?-u:a[^\n]*aba)", b"aababa".as_slice()),
            (r"(?-u:ab[^\n]*bc)", b"!abcabcyabcbc!".as_slice()),
            (
                r"(?-u:BEGIN.*END)",
                b"BEGIN no\nEND BEGINyesEND".as_slice(),
            ),
            (
                r"(?-u:\xFF[^\n]*\xFE)",
                &[0, 0xff, 0x80, 0xfe, 0],
            ),
        ] {
            assert_same_as_oracle(pattern, haystack);
        }

        let overlap = plan(r"(?-u:a[^\n]*aba)");
        assert_eq!(overlap.find_full(b"aababa"), Some((0, 6)));
        let barrier = plan(r"(?-u:BEGIN.*END)");
        assert_eq!(
            barrier.find_full(b"BEGIN no\nEND BEGINyesEND"),
            Some((13, 24)),
        );
    }

    #[test]
    fn small_alphabets_are_exhaustive_against_regex_bytes() {
        exhaustive(r"(?-u:a[^\n]*b)", b"ab\n", 7);
        exhaustive(r"(?-u:a[^\n]+b)", b"ab\n", 7);
        exhaustive(r"(?-u:aa[^\n]*aa)", b"ab\n", 7);
        exhaustive(r"(?-u:((ab))([^\n]*)((bc)))", b"abc\n", 7);
        exhaustive(r"(?-u:\xFF[^\n]*\xFE)", &[b'\n', 0xfe, 0xff], 6);
    }

    #[test]
    fn ordinary_gate_declines_only_before_source_inspection() {
        let plan = plan(r"(?-u:BEGIN.*END)");
        let below = vec![b'x'; MIN_INPUT_BYTES - 1];
        assert_eq!(plan.try_ordinary_is_match_full(&below), None);
        assert_eq!(plan.try_ordinary_find_full(&below), None);

        let mut admitted = vec![b'x'; MIN_INPUT_BYTES];
        let suffix = b"BEGINEND";
        let start = admitted.len() - suffix.len();
        admitted[start..].copy_from_slice(suffix);
        assert_eq!(plan.try_ordinary_is_match_full(&admitted), Some(true));
        assert_eq!(
            plan.try_ordinary_find_full(&admitted),
            Some(Some((start, admitted.len())))
        );

        let absent = vec![b'x'; MIN_INPUT_BYTES];
        assert_eq!(plan.try_ordinary_is_match_full(&absent), Some(false));
        assert_eq!(plan.try_ordinary_find_full(&absent), Some(None));
    }

    #[test]
    fn inspection_is_narrow_capture_transparent_and_metered() {
        let captured = ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse(r"((ab))([^\n]*)((bc))")
            .unwrap();
        let InspectionOutcome::Eligible { planner_work, plan } =
            inspect(&captured, 0, u64::MAX).unwrap()
        else {
            panic!("capture-transparent byte corridor should be eligible");
        };
        assert_eq!(plan.find_full(b"!abacbcbc!"), Some((1, 9)));
        assert!(matches!(
            inspect(&captured, 0, planner_work - 1),
            Err(super::InspectionError::WorkLimit { needed, limit, .. })
                if needed == planner_work && limit == planner_work - 1
        ));

        let initial_work = 17;
        let InspectionOutcome::Eligible {
            planner_work: cumulative,
            ..
        } = inspect(&captured, initial_work, u64::MAX).unwrap()
        else {
            panic!("prior work must not change eligibility");
        };
        assert_eq!(cumulative, planner_work + initial_work);
        assert_eq!(
            inspect(&captured, u64::MAX, u64::MAX),
            Err(super::InspectionError::ArithmeticOverflow)
        );
        assert!(core::mem::size_of::<Plan>() <= 20);
    }

    #[test]
    fn nearby_or_nonbyte_languages_are_rejected() {
        for pattern in [
            r"(?-u:a[^\n]{0,3}b)",
            r"(?-u:a[^\n]*?b)",
            r"(?-u:a[^\n]?b)",
            r"(?-u:a[ab]*b)",
            r"(?-u:a[^\n]*\n)",
            r"(?-u:a[^\n]*b[0-9])",
            r"(?-u:a[^\n]*b|a[^\n]*a)",
            r"a.b",
            r"(?-u:[^\n]*b)",
            r"(?-u:a[^\n]*)",
        ] {
            let hir = ParserBuilder::new()
                .unicode(false)
                .utf8(false)
                .build()
                .parse(pattern)
                .unwrap();
            assert!(
                matches!(
                    inspect(&hir, 0, u64::MAX).unwrap(),
                    InspectionOutcome::Ineligible { .. }
                ),
                "unexpectedly admitted {pattern:?}",
            );
        }

        let long = ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse(r"123456789[^\n]*0")
            .unwrap();
        assert!(matches!(
            inspect(&long, 0, u64::MAX).unwrap(),
            InspectionOutcome::Ineligible { .. }
        ));
    }

}
