//! Direct search for finite positive greedy byte-class run sequences.
//!
//! The admitted HIR is a root concatenation of two through sixteen
//! `CLASS{min,max}` terms. Capture chains may wrap the root concatenation,
//! each immediate repetition term, or each repetition's single-byte class
//! body; captures around a proper subsequence concatenation are not flattened.
//! Every bound is finite and positive, every repetition is greedy, at least
//! one bound is variable, and adjacent classes are disjoint. The last
//! condition makes each greedy boundary deterministic: a byte consumed by one
//! run can never be returned to its successor. Non-adjacent classes may
//! overlap.
//!
//! Search scans physical runs of the first class. Within one such run, only
//! its earliest suffix of at most the first maximum can reach the disjoint
//! successor; every earlier start stops at its maximum while still inside the
//! first class, and every later eligible start reaches the same successor
//! boundary.
//! The tail is therefore verified once per first-class run instead of once per
//! member. For one immutable plan this is O(N), with a complete
//! source-independent bound of `N * (maximum_tail_width + 16)` charged by the
//! shared byte-class work meter. Fixed products remain with their established
//! incumbent plans; every structurally eligible variable product is admitted,
//! including small products that the earlier finite-language plans decline.

use fre_exact_alloc::{CopyError, ExactBoxOrUsize};
use fre_kernels::{
    BYTE_SET_BLOCK_BYTES, BYTE_SET_CLASSIFIER_BUILD_WORK, ByteSet256, ByteSetClassifier,
    DispatchPolicy, SimdDispatchContext,
};
use regex_syntax::hir::{Class, Hir, HirKind};

use crate::pure_byte_class_repeat::{Error as SeekError, SetSeek, WorkMeter, validate_window};
use crate::{Match, SearchLimits, SearchWindow};

pub const PLAN_ID: &str = "bounded-byte-class-sequence-search-v1";

const MAX_RUNS: usize = 16;
const NODE_INSPECTION_WORK: u64 = 1;
const RANGE_INSPECTION_WORK: u64 = 1;
const MEMBER_INSERTION_WORK: u64 = 1;
const ADJACENT_DISJOINT_WORD_WORK: u64 = 4;
const LEAF_SELECTION_WORK: u64 = 1;

/// Operation selected for a bounded byte-class sequence search.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Exists,
    EarliestEnd,
    SelectedEnd,
    Span,
}

/// Exact successful-search effects for one bounded byte-class sequence
/// invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Accounting {
    /// Immutable implementation identity for this plan.
    pub plan_id: &'static str,
    /// Operation whose result and effects were measured.
    pub operation: Operation,
    /// Bytes in the validated search window.
    pub input_bytes: usize,
    /// Exact charged abstract source classifications.
    pub source_reads: u64,
    /// Source-independent conservative work ceiling.
    pub work_upper_bound: u64,
    /// Exact work charged by the shared meter.
    pub actual_work: u64,
    /// Exact number of first-run candidate seeks.
    pub candidate_scans: u64,
    /// Exact number of physical first/tail run scans.
    pub run_scans: u64,
    /// Exact number of emitted match events, zero or one for one search.
    pub match_events: u64,
}

/// Search failure from one already-selected bounded byte-class sequence plan.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    InvalidWindow,
    WorkLimit { needed: u64, limit: u64 },
    CounterOverflow { counter: &'static str },
}

impl core::fmt::Display for Error {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidWindow => {
                formatter.write_str("invalid bounded byte-class sequence search window")
            }
            Self::WorkLimit { needed, limit } => write!(
                formatter,
                "bounded byte-class sequence needs work unit {needed}, exceeding {limit}"
            ),
            Self::CounterOverflow { counter } => {
                write!(formatter, "bounded byte-class sequence {counter} counter overflowed")
            }
        }
    }
}

impl std::error::Error for Error {}

impl From<SeekError> for Error {
    fn from(error: SeekError) -> Self {
        match error {
            SeekError::InvalidWindow => Self::InvalidWindow,
            SeekError::WorkLimit { needed, limit } => Self::WorkLimit { needed, limit },
        }
    }
}

type SearchError = Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InspectionError {
    WorkLimit { needed: u64, limit: u64 },
    ArithmeticOverflow,
}

#[derive(Clone, Copy)]
struct Run {
    words: [u64; 4],
    minimum: usize,
    maximum: usize,
}

impl Run {
    const EMPTY: Self = Self {
        words: [0; 4],
        minimum: 0,
        maximum: 0,
    };

    fn contains(self, byte: u8) -> bool {
        let word = usize::from(byte >> 6);
        let bit = u32::from(byte & 63);
        self.words[word] & (1_u64 << bit) != 0
    }

    fn overlaps(self, other: Self) -> bool {
        self.words
            .iter()
            .zip(other.words)
            .any(|(left, right)| left & right != 0)
    }

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "four 64-bit bitmap cardinalities sum to at most the fixed 256-byte domain"
    )]
    fn cardinality(self) -> u32 {
        self.words.iter().map(|word| word.count_ones()).sum()
    }
}

pub(crate) struct Inspection {
    runs: [Run; MAX_RUNS],
    run_count: usize,
    total_minimum: usize,
    total_maximum: usize,
    first_seek: SetSeek,
    first_run_end_seek: SetSeek,
    classifier_words: Option<[u64; 4]>,
    planner_work: u64,
}

pub(crate) enum InspectionOutcome {
    Eligible(Inspection),
    Ineligible { planner_work: u64 },
}

impl InspectionOutcome {
    pub(crate) const fn planner_work(&self) -> u64 {
        match self {
            Self::Eligible(inspection) => inspection.planner_work,
            Self::Ineligible { planner_work } => *planner_work,
        }
    }
}

struct Owner {
    runs: [Run; MAX_RUNS],
    run_count: usize,
    total_minimum: usize,
    total_maximum: usize,
    first_seek: SetSeek,
    first_run_end_seek: SetSeek,
    classifier: Option<ByteSetClassifier>,
}

pub(crate) struct Plan {
    owner: ExactBoxOrUsize<Owner>,
}

struct SearchState {
    span: Option<(usize, usize)>,
    meter: WorkMeter,
    candidate_scans: u64,
    run_scans: u64,
}

impl Plan {
    #[cold]
    fn build(
        runs: [Run; MAX_RUNS],
        run_count: usize,
        total_minimum: usize,
        total_maximum: usize,
        first_seek: SetSeek,
        first_run_end_seek: SetSeek,
        classifier_words: Option<[u64; 4]>,
        dispatch: SimdDispatchContext,
    ) -> Result<Self, CopyError> {
        let classifier = classifier_words.map(|words| {
            dispatch
                .byte_set_classifier(ByteSet256::from_words(words), DispatchPolicy::Auto)
                .expect("automatic byte-set dispatch retains a scalar fallback")
        });
        let owner = ExactBoxOrUsize::try_from_boxed(Owner {
            runs,
            run_count,
            total_minimum,
            total_maximum,
            first_seek,
            first_run_end_seek,
            classifier,
        })?;
        Ok(Self { owner })
    }

    fn owner(&self) -> &Owner {
        self.owner
            .boxed()
            .expect("the bounded byte-class sequence retains its exact owner")
    }

    pub(crate) const fn storage_bytes() -> usize {
        core::mem::size_of::<Self>()
            .checked_add(core::mem::size_of::<Owner>())
            .expect("the fixed bounded byte-class sequence layouts fit usize")
    }

    pub(crate) fn is_match_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(bool, Accounting), SearchError> {
        let state = self.search(haystack, window, limits, true)?;
        let matched = state.span.is_some();
        let accounting = self.finish_accounting(Operation::Exists, window, &state);
        Ok((matched, accounting))
    }

    pub(crate) fn is_match_window_value(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<bool, SearchError> {
        self.search(haystack, window, limits, true)
            .map(|state| state.span.is_some())
    }

    pub(crate) fn earliest_end_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<usize>, Accounting), SearchError> {
        let state = self.search(haystack, window, limits, true)?;
        let end = state.span.map(|(_, end)| end);
        let accounting = self.finish_accounting(Operation::EarliestEnd, window, &state);
        Ok((end, accounting))
    }

    pub(crate) fn selected_end_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<usize>, Accounting), SearchError> {
        let state = self.search(haystack, window, limits, false)?;
        let end = state.span.map(|(_, end)| end);
        let accounting = self.finish_accounting(Operation::SelectedEnd, window, &state);
        Ok((end, accounting))
    }

    pub(crate) fn find_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, Accounting), SearchError> {
        let state = self.search(haystack, window, limits, false)?;
        let matched = state.span.map(|(start, end)| Match { start, end });
        let accounting = self.finish_accounting(Operation::Span, window, &state);
        Ok((matched, accounting))
    }

    fn search(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
        shortest_last: bool,
    ) -> Result<SearchState, SearchError> {
        validate_window(haystack, window)?;
        let owner = self.owner();
        let mut meter = WorkMeter::new(limits.max_work);
        let Some(last_start) = window.end().checked_sub(owner.total_minimum) else {
            return Ok(SearchState {
                span: None,
                meter,
                candidate_scans: 0,
                run_scans: 0,
            });
        };
        if last_start < window.start() {
            return Ok(SearchState {
                span: None,
                meter,
                candidate_scans: 0,
                run_scans: 0,
            });
        }
        let candidate_end = last_start
            .checked_add(1)
            .expect("a last start before the window end advances once");
        let mut position = window.start();
        let mut candidate_scans = 0_u64;
        let mut run_scans = 0_u64;
        while position < candidate_end {
            candidate_scans = candidate_scans
                .checked_add(1)
                .ok_or(Error::CounterOverflow {
                    counter: "candidate-scan",
                })?;
            let Some(run_start) = owner.first_seek.seek(
                haystack,
                position,
                candidate_end,
                &mut meter,
                owner.classifier.as_ref(),
            )?
            else {
                break;
            };
            run_scans = run_scans.checked_add(1).ok_or(Error::CounterOverflow {
                counter: "run-scan",
            })?;
            let after_run_start = run_start
                .checked_add(1)
                .expect("a first-run member before the window end advances once");
            let run_end = owner
                .first_run_end_seek
                .seek(
                    haystack,
                    after_run_start,
                    window.end(),
                    &mut meter,
                    owner.classifier.as_ref(),
                )?
                .unwrap_or(window.end());
            let first = owner.runs[0];
            let run_length = run_end - run_start;
            if run_length >= first.minimum {
                let start = run_end.saturating_sub(first.maximum).max(run_start);
                if let Some(end) = owner.verify_tail(
                    haystack,
                    run_end,
                    window.end(),
                    shortest_last,
                    &mut meter,
                    &mut run_scans,
                )? {
                    return Ok(SearchState {
                        span: Some((start, end)),
                        meter,
                        candidate_scans,
                        run_scans,
                    });
                }
            }
            if run_end == window.end() {
                break;
            }
            position = run_end
                .checked_add(1)
                .expect("a first-run boundary before the window end advances once");
        }
        Ok(SearchState {
            span: None,
            meter,
            candidate_scans,
            run_scans,
        })
    }

    fn finish_accounting(
        &self,
        operation: Operation,
        window: SearchWindow,
        state: &SearchState,
    ) -> Accounting {
        let input_bytes = window.end() - window.start();
        let owner = self.owner();
        let maximum_tail_width = owner
            .total_maximum
            .saturating_sub(owner.runs[0].maximum);
        let per_candidate = maximum_tail_width.saturating_add(BYTE_SET_BLOCK_BYTES);
        let work_upper_bound = u64::try_from(input_bytes)
            .unwrap_or(u64::MAX)
            .saturating_mul(u64::try_from(per_candidate).unwrap_or(u64::MAX));
        debug_assert!(state.meter.consumed() <= work_upper_bound);
        Accounting {
            plan_id: PLAN_ID,
            operation,
            input_bytes,
            source_reads: state.meter.consumed(),
            work_upper_bound,
            actual_work: state.meter.consumed(),
            candidate_scans: state.candidate_scans,
            run_scans: state.run_scans,
            match_events: u64::from(state.span.is_some()),
        }
    }
}

impl Owner {
    fn verify_tail(
        &self,
        haystack: &[u8],
        start: usize,
        end: usize,
        shortest_last: bool,
        meter: &mut WorkMeter,
        run_scans: &mut u64,
    ) -> Result<Option<usize>, SearchError> {
        let mut position = start;
        let runs = &self.runs[..self.run_count];
        for (index, &run) in runs.iter().enumerate().skip(1) {
            *run_scans = run_scans.checked_add(1).ok_or(Error::CounterOverflow {
                counter: "run-scan",
            })?;
            let maximum = if shortest_last && index + 1 == runs.len() {
                run.minimum
            } else {
                run.maximum
            };
            let mut consumed = 0_usize;
            while consumed < maximum && position < end {
                meter.charge(1)?;
                if !run.contains(haystack[position]) {
                    break;
                }
                position = position
                    .checked_add(1)
                    .expect("a position before the window end advances once");
                consumed = consumed
                    .checked_add(1)
                    .expect("one run cannot exceed its finite maximum");
            }
            if consumed < run.minimum {
                return Ok(None);
            }
        }
        Ok(Some(position))
    }
}

impl Inspection {
    #[cold]
    pub(crate) fn build(self, dispatch: SimdDispatchContext) -> Result<Plan, CopyError> {
        Plan::build(
            self.runs,
            self.run_count,
            self.total_minimum,
            self.total_maximum,
            self.first_seek,
            self.first_run_end_seek,
            self.classifier_words,
            dispatch,
        )
    }
}

#[cold]
pub(crate) fn inspect(
    hir: &Hir,
    initial_work: u64,
    max_planner_work: u64,
) -> Result<InspectionOutcome, InspectionError> {
    let mut work = initial_work;
    let root = peel_captures(hir, &mut work, max_planner_work)?;
    let HirKind::Concat(parts) = root.kind() else {
        return Ok(InspectionOutcome::Ineligible { planner_work: work });
    };
    if !(2..=MAX_RUNS).contains(&parts.len()) {
        return Ok(InspectionOutcome::Ineligible { planner_work: work });
    }

    let mut runs = [Run::EMPTY; MAX_RUNS];
    let mut total_minimum = 0_usize;
    let mut total_maximum = 0_usize;
    let mut has_variable_bound = false;
    for (index, part) in parts.iter().enumerate() {
        let Some(run) = inspect_run(part, &mut work, max_planner_work)? else {
            return Ok(InspectionOutcome::Ineligible { planner_work: work });
        };
        if index != 0 {
            charge_planner(
                &mut work,
                ADJACENT_DISJOINT_WORD_WORK,
                max_planner_work,
            )?;
            if runs[index - 1].overlaps(run) {
                return Ok(InspectionOutcome::Ineligible { planner_work: work });
            }
        }
        let Some((next_total_minimum, next_total_maximum)) =
            checked_width_totals(total_minimum, total_maximum, run)
        else {
            return Ok(InspectionOutcome::Ineligible { planner_work: work });
        };
        total_minimum = next_total_minimum;
        total_maximum = next_total_maximum;
        has_variable_bound |= run.minimum != run.maximum;
        runs[index] = run;
    }
    if !has_variable_bound {
        return Ok(InspectionOutcome::Ineligible { planner_work: work });
    }

    let first = runs[0];
    let cardinality = first.cardinality();
    if cardinality == 0 {
        return Ok(InspectionOutcome::Ineligible { planner_work: work });
    }
    let complement = first.words.map(|word| !word);
    let run_end_cardinality = 256_u32 - cardinality;
    charge_planner(&mut work, LEAF_SELECTION_WORK, max_planner_work)?;
    charge_planner(&mut work, LEAF_SELECTION_WORK, max_planner_work)?;
    let first_seek = SetSeek::build(first.words, cardinality, false);
    let member_classified = first_seek.requires_classifier();
    let first_run_end_seek =
        SetSeek::build(complement, run_end_cardinality, member_classified);
    let run_end_classified = first_run_end_seek.requires_classifier();
    let classifier_words = if member_classified || run_end_classified {
        charge_planner(
            &mut work,
            u64::try_from(BYTE_SET_CLASSIFIER_BUILD_WORK)
                .expect("the fixed classifier build charge fits u64"),
            max_planner_work,
        )?;
        if member_classified {
            Some(first.words)
        } else {
            Some(complement)
        }
    } else {
        None
    };
    Ok(InspectionOutcome::Eligible(Inspection {
        runs,
        run_count: parts.len(),
        total_minimum,
        total_maximum,
        first_seek,
        first_run_end_seek,
        classifier_words,
        planner_work: work,
    }))
}

fn checked_width_totals(
    total_minimum: usize,
    total_maximum: usize,
    run: Run,
) -> Option<(usize, usize)> {
    Some((
        total_minimum.checked_add(run.minimum)?,
        total_maximum.checked_add(run.maximum)?,
    ))
}

fn inspect_run(
    hir: &Hir,
    work: &mut u64,
    max_planner_work: u64,
) -> Result<Option<Run>, InspectionError> {
    let hir = peel_captures(hir, work, max_planner_work)?;
    let HirKind::Repetition(repetition) = hir.kind() else {
        return Ok(None);
    };
    let Some(maximum) = repetition.max else {
        return Ok(None);
    };
    if repetition.min == 0 || maximum < repetition.min || !repetition.greedy {
        return Ok(None);
    }
    let body = peel_captures(&repetition.sub, work, max_planner_work)?;
    let mut words = [0_u64; 4];
    match body.kind() {
        HirKind::Class(Class::Bytes(class)) => {
            for range in class.ranges() {
                charge_planner(work, RANGE_INSPECTION_WORK, max_planner_work)?;
                for byte in range.start()..=range.end() {
                    charge_planner(work, MEMBER_INSERTION_WORK, max_planner_work)?;
                    let word = usize::from(byte >> 6);
                    let bit = u32::from(byte & 63);
                    words[word] |= 1_u64 << bit;
                }
            }
        }
        HirKind::Literal(literal) if literal.0.len() == 1 => {
            charge_planner(work, MEMBER_INSERTION_WORK, max_planner_work)?;
            let byte = literal.0[0];
            let word = usize::from(byte >> 6);
            let bit = u32::from(byte & 63);
            words[word] |= 1_u64 << bit;
        }
        _ => return Ok(None),
    }
    if words.iter().all(|word| *word == 0) {
        return Ok(None);
    }
    let Ok(minimum) = usize::try_from(repetition.min) else {
        return Ok(None);
    };
    let Ok(maximum) = usize::try_from(maximum) else {
        return Ok(None);
    };
    Ok(Some(Run {
        words,
        minimum,
        maximum,
    }))
}

#[inline(never)]
#[cold]
fn peel_captures<'h>(
    mut hir: &'h Hir,
    work: &mut u64,
    max_planner_work: u64,
) -> Result<&'h Hir, InspectionError> {
    loop {
        charge_planner(work, NODE_INSPECTION_WORK, max_planner_work)?;
        let HirKind::Capture(capture) = hir.kind() else {
            return Ok(hir);
        };
        hir = &capture.sub;
    }
}

#[cold]
fn charge_planner(
    work: &mut u64,
    additional: u64,
    limit: u64,
) -> Result<(), InspectionError> {
    let needed = work
        .checked_add(additional)
        .ok_or(InspectionError::ArithmeticOverflow)?;
    if needed > limit {
        return Err(InspectionError::WorkLimit { needed, limit });
    }
    *work = needed;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::PLAN_ID;
    use crate::pure_byte_class_repeat::SetSeek;
    use crate::{
        BuildError, BuildLimits, PlanKind, PortableBuilder, PortableFindIterLimits, PortablePlan,
        SearchAccounting, SearchError as FacadeSearchError, SearchLimits, SearchWindow,
    };
    use crate::{
        BoundedByteClassSequenceAccounting as Accounting,
        BoundedByteClassSequenceOperation as Operation,
        BoundedByteClassSequenceSearchError as Error,
    };

    fn build(pattern: &str) -> crate::PortableRegex {
        PortableBuilder::new(pattern)
            .unicode(false)
            .build()
            .expect("the bounded byte-class sequence should build")
    }

    fn span(matched: Option<crate::Match>) -> Option<(usize, usize)> {
        matched.map(|matched| (matched.start(), matched.end()))
    }

    fn accounting(accounting: SearchAccounting) -> Accounting {
        assert_eq!(accounting.plan(), PlanKind::BoundedByteClassSequence);
        let accounting = match accounting {
            SearchAccounting::BoundedByteClassSequence(accounting) => accounting,
            other => panic!("expected bounded sequence accounting, got {other:?}"),
        };
        assert_eq!(accounting.source_reads, accounting.actual_work);
        accounting
    }

    #[test]
    fn selects_variable_sequences_with_deterministic_boundaries() {
        for pattern in [
            "a{1,2}b{1,2}",
            "(?-u:[A-Z]){1,3}(?-u:[a-z]){2,5}(?-u:[0-9]){1,2}",
            "(?-u:[abcd]){1,3}(?-u:[WXYZ]){1,3}",
            "(?-u:[ab]){1,4}(?-u:[cd]){1,4}(?-u:[ab]){1,4}",
            "((?-u:[A-Z]){1,3})((?-u:[a-z]){2,5})",
            "((?-u:[A-Z]){1,3}(?-u:[a-z]){2,5})",
            "(?-u:([A-Z])){1,3}(?-u:[a-z]){2,5}",
            r"(?-u:[\x80-\x83]){1,32}(?-u:[A-D]){1,32}",
            r"(?-u:[\x00-\xFE]){1,32}(?-u:\xFF){1,32}",
            "a{1,4096}(?-u:[B-D]){1,4096}",
        ] {
            let regex = build(pattern);
            assert_eq!(
                regex.build_report().plan,
                PlanKind::BoundedByteClassSequence
            );
            assert_eq!(regex.runtime_implementation_id(), PLAN_ID, "{pattern}");
        }

        for pattern in [
            "(?-u:[abcdefgh]){1,4}(?-u:[hijklmno]){1,4}",
            "(?-u:[abcdefgh]){1,4}?(?-u:[WXYZ]){1,4}",
            "(?-u:[ab])+(?-u:[cd]){1,4}",
            "(?-u:[ab]){2}(?-u:[cd]){2}",
            "((?-u:[A-Z]){1,3}(?-u:[a-z]){2,5})(?-u:[0-9]){1,2}",
            r"(?-u:[\x00-\xFF]){1,32}A{1,32}",
        ] {
            assert_ne!(build(pattern).runtime_implementation_id(), PLAN_ID, "{pattern}");
        }
    }

    #[test]
    fn contiguous_first_run_keeps_range_seeks_identity_and_accounting() {
        let regex = build("(?-u:[A-Z]){1,32}(?-u:[a-z]){1,32}");
        assert_eq!(regex.runtime_implementation_id(), PLAN_ID);
        let PortablePlan::BoundedByteClassSequence(plan) = &regex.plan else {
            panic!("one bounded range sequence should retain the sequence plan");
        };
        assert_eq!(
            plan.owner().first_seek,
            SetSeek::Range {
                origin: b'A',
                maximum_delta: b'Z'.wrapping_sub(b'A'),
                inverted: false,
            }
        );
        assert_eq!(
            plan.owner().first_run_end_seek,
            SetSeek::Range {
                origin: b'A',
                maximum_delta: b'Z'.wrapping_sub(b'A'),
                inverted: true,
            }
        );
        assert!(plan.owner().classifier.is_none());

        let haystack = b"................................ABCxyz!";
        let (matched, receipt) = regex
            .find(haystack, SearchLimits::unlimited())
            .expect("one bounded range sequence should search");
        assert_eq!(span(matched), Some((32, 38)));
        let receipt = accounting(receipt);
        assert_eq!(receipt.plan_id, PLAN_ID);
        assert_eq!(receipt.operation, Operation::Span);
        assert_eq!(receipt.source_reads, receipt.actual_work);
        assert!(receipt.actual_work <= receipt.work_upper_bound);

        let small = build("(?-u:[ab]){1,8}(?-u:[CD]){1,8}");
        let PortablePlan::BoundedByteClassSequence(plan) = &small.plan else {
            panic!("one small bounded sequence should retain the sequence plan");
        };
        assert_eq!(plan.owner().first_seek, SetSeek::Two(b'a', b'b'));
        assert_eq!(
            plan.owner().first_run_end_seek,
            SetSeek::Range {
                origin: b'a',
                maximum_delta: 1,
                inverted: true,
            }
        );
        assert!(plan.owner().classifier.is_none());

        let small_holey = build("(?-u:[ac]){1,8}(?-u:[BD]){1,8}");
        let PortablePlan::BoundedByteClassSequence(plan) = &small_holey.plan else {
            panic!("one small holey sequence should retain the sequence plan");
        };
        assert_eq!(plan.owner().first_seek, SetSeek::Two(b'a', b'c'));
        assert_eq!(
            plan.owner().first_run_end_seek,
            SetSeek::Classified { inverted: false }
        );
        let classifier = plan
            .owner()
            .classifier
            .as_ref()
            .expect("a holey first-run complement needs the generic classifier");
        assert!(!classifier.set().contains(b'a'));
        assert!(classifier.set().contains(b'b'));
        assert!(!classifier.set().contains(b'c'));
    }

    #[test]
    fn admits_sixteen_runs_and_refuses_seventeen() {
        let pair = "(?-u:[ab]){1,2}(?-u:[CD]){1,2}";
        let sixteen = pair.repeat(8);
        let sixteen = build(&sixteen);
        assert_eq!(
            sixteen.build_report().plan,
            PlanKind::BoundedByteClassSequence
        );
        assert_eq!(sixteen.runtime_implementation_id(), PLAN_ID);

        let seventeen = format!("{}(?-u:[xy]){{1,2}}", pair.repeat(8));
        assert_ne!(build(&seventeen).runtime_implementation_id(), PLAN_ID);
    }

    #[test]
    fn exhaustive_windows_and_iteration_match_the_bytes_oracle() {
        let patterns = [
            "a{1,2}b{1,2}",
            "(?-u:[abcd]){1,3}(?-u:[WXYZ]){1,3}",
            "(?-u:[ab]){1,4}(?-u:[cd]){1,4}(?-u:[ab]){1,4}",
        ];
        let alphabet = [b'a', b'b', b'd', b'W', b'Z', b'c', b'x'];
        for pattern in patterns {
            let fre = build(pattern);
            assert_eq!(fre.runtime_implementation_id(), PLAN_ID);
            let oracle = regex::bytes::RegexBuilder::new(pattern)
                .unicode(false)
                .build()
                .unwrap();
            for length in 0_u32..=5 {
                let cases = alphabet.len().pow(length);
                for encoded in 0..cases {
                    let mut value = encoded;
                    let mut haystack = vec![0_u8; usize::try_from(length).unwrap()];
                    for byte in &mut haystack {
                        *byte = alphabet[value % alphabet.len()];
                        value /= alphabet.len();
                    }
                    for start in 0..=haystack.len() {
                        for end in start..=haystack.len() {
                            let window = SearchWindow::new(start, end);
                            let source = &haystack[start..end];
                            let expected = oracle
                                .find(source)
                                .map(|matched| (start + matched.start(), start + matched.end()));
                            let expected_shortest =
                                oracle.shortest_match(source).map(|finish| start + finish);
                            let (exists, search_accounting) = fre
                                .is_match_window(&haystack, window, SearchLimits::unlimited())
                                .unwrap();
                            assert_eq!(exists, expected.is_some());
                            let accounting = accounting(search_accounting);
                            assert_eq!(accounting.plan_id, PLAN_ID);
                            assert!(accounting.actual_work <= accounting.work_upper_bound);
                            assert_eq!(
                                fre.is_match_window_value(
                                    &haystack,
                                    window,
                                    SearchLimits::unlimited(),
                                )
                                .unwrap(),
                                expected.is_some(),
                            );
                            assert_eq!(
                                fre.shortest_match_window(
                                    &haystack,
                                    window,
                                    SearchLimits::unlimited(),
                                )
                                .unwrap()
                                .0,
                                expected_shortest,
                            );
                            assert_eq!(
                                span(
                                    fre.find_window(
                                        &haystack,
                                        window,
                                        SearchLimits::unlimited(),
                                    )
                                    .unwrap()
                                    .0,
                                ),
                                expected,
                            );
                            assert_eq!(
                                span(
                                    fre.find_window_value(
                                        &haystack,
                                        window,
                                        SearchLimits::unlimited(),
                                    )
                                    .unwrap(),
                                ),
                                expected,
                            );
                        }
                    }
                    let expected = oracle
                        .find_iter(&haystack)
                        .map(|matched| (matched.start(), matched.end()))
                        .collect::<Vec<_>>();
                    let actual = fre
                        .find_iter(&haystack, PortableFindIterLimits::unlimited())
                        .unwrap()
                        .map(|matched| {
                            let matched = matched.unwrap();
                            (matched.start(), matched.end())
                        })
                        .collect::<Vec<_>>();
                    assert_eq!(actual, expected, "{pattern} {haystack:?}");
                }
            }
        }
    }

    #[test]
    fn capped_first_run_retries_the_next_leftmost_candidate() {
        let pattern = "(?-u:[abcd]){1,3}(?-u:[WXYZ]){1,3}";
        let regex = build(pattern);
        assert_eq!(regex.runtime_implementation_id(), PLAN_ID);
        let haystack = b"aaaaW";
        assert_eq!(
            span(regex.find(haystack, SearchLimits::unlimited()).unwrap().0),
            Some((1, 5)),
        );
    }

    #[test]
    fn facade_labels_every_sequence_operation_and_error() {
        let regex = build("(?-u:[abcd]){1,3}(?-u:[WXYZ]){1,3}");
        let haystack = b"xxaaWZxx";

        let exists = accounting(
            regex
                .is_match(haystack, SearchLimits::unlimited())
                .unwrap()
                .1,
        );
        assert_eq!(exists.operation, Operation::Exists);
        let earliest = accounting(
            regex
                .shortest_match(haystack, SearchLimits::unlimited())
                .unwrap()
                .1,
        );
        assert_eq!(earliest.operation, Operation::EarliestEnd);
        let selected = accounting(
            regex
                .selected_end(haystack, SearchLimits::unlimited())
                .unwrap()
                .1,
        );
        assert_eq!(selected.operation, Operation::SelectedEnd);
        let found = accounting(regex.find(haystack, SearchLimits::unlimited()).unwrap().1);
        assert_eq!(found.operation, Operation::Span);

        let error = regex
            .is_match(
                haystack,
                SearchLimits {
                    max_work: 0,
                    max_scratch_bytes: 0,
                },
            )
            .unwrap_err();
        assert!(matches!(
            &error,
            FacadeSearchError::BoundedByteClassSequence(Error::WorkLimit { limit: 0, .. })
        ));
        assert!(error.to_string().contains("bounded byte-class sequence"));
        let source = std::error::Error::source(&error).expect("sequence error source");
        assert!(source.to_string().contains("bounded byte-class sequence"));
    }

    #[test]
    fn classified_first_run_stream_closes_its_linear_envelope() {
        let regex = build("(?-u:[abcd]){1,3}(?-u:[WXYZ]){1,3}");
        let mut haystack = Vec::new();
        for _ in 0..64 {
            haystack.extend_from_slice(b"xaax");
        }
        let (matched, measured) = regex
            .find(&haystack, SearchLimits::unlimited())
            .unwrap();
        assert!(matched.is_none());
        let measured = accounting(measured);
        assert!(measured.candidate_scans > 1);
        assert!(measured.actual_work <= measured.work_upper_bound);
    }

    #[test]
    fn exact_search_and_construction_limits_close() {
        let pattern = "(?-u:[abcd]){1,3}(?-u:[WXYZ]){1,3}";
        let haystack = b"xxaaaQzaaWZxx";
        let regex = build(pattern);
        let PortablePlan::BoundedByteClassSequence(plan) = &regex.plan else {
            panic!("expected bounded sequence plan");
        };
        let window = SearchWindow::new(1, haystack.len() - 1);

        for operation in [
            Operation::Exists,
            Operation::EarliestEnd,
            Operation::SelectedEnd,
            Operation::Span,
        ] {
            let measured = match operation {
                Operation::Exists => accounting(
                    regex
                        .is_match_window(haystack, window, SearchLimits::unlimited())
                        .unwrap()
                        .1,
                ),
                Operation::EarliestEnd => accounting(
                    regex
                        .shortest_match_window(haystack, window, SearchLimits::unlimited())
                        .unwrap()
                        .1,
                ),
                Operation::SelectedEnd => plan
                    .selected_end_window(haystack, window, SearchLimits::unlimited())
                    .unwrap()
                    .1,
                Operation::Span => accounting(
                    regex
                        .find_window(haystack, window, SearchLimits::unlimited())
                        .unwrap()
                        .1,
                ),
            };
            assert!(measured.actual_work > 0);
            assert!(measured.actual_work <= measured.work_upper_bound);

            let exact = SearchLimits {
                max_work: measured.actual_work,
                max_scratch_bytes: 0,
            };
            let exact_accounting = match operation {
                Operation::Exists => {
                    accounting(regex.is_match_window(haystack, window, exact).unwrap().1)
                }
                Operation::EarliestEnd => accounting(
                    regex
                        .shortest_match_window(haystack, window, exact)
                        .unwrap()
                        .1,
                ),
                Operation::SelectedEnd => {
                    plan.selected_end_window(haystack, window, exact).unwrap().1
                }
                Operation::Span => {
                    accounting(regex.find_window(haystack, window, exact).unwrap().1)
                }
            };
            assert_eq!(exact_accounting.actual_work, measured.actual_work);

            let one_below = SearchLimits {
                max_work: measured.actual_work - 1,
                max_scratch_bytes: 0,
            };
            let error = match operation {
                Operation::Exists => regex
                    .is_match_window(haystack, window, one_below)
                    .unwrap_err(),
                Operation::EarliestEnd => regex
                    .shortest_match_window(haystack, window, one_below)
                    .unwrap_err(),
                Operation::SelectedEnd => plan
                    .selected_end_window(haystack, window, one_below)
                    .unwrap_err()
                    .into(),
                Operation::Span => regex.find_window(haystack, window, one_below).unwrap_err(),
            };
            assert!(matches!(
                error,
                FacadeSearchError::BoundedByteClassSequence(Error::WorkLimit { limit, .. })
                    if limit == measured.actual_work - 1
            ));
        }

        let measured_build = regex.build_report().clone();
        let mut exact_limits = BuildLimits::default();
        exact_limits.max_planner_work = measured_build.planner_work;
        exact_limits.max_persistent_bytes = measured_build.charged_persistent_bytes;
        let exact = PortableBuilder::new(pattern)
            .unicode(false)
            .limits(exact_limits)
            .build()
            .unwrap();
        assert_eq!(exact.build_report().planner_work, measured_build.planner_work);
        assert_eq!(
            exact.build_report().charged_persistent_bytes,
            measured_build.charged_persistent_bytes
        );

        let mut planner_refusal = exact_limits;
        planner_refusal.max_planner_work = measured_build.planner_work - 1;
        assert!(matches!(
            PortableBuilder::new(pattern)
                .unicode(false)
                .limits(planner_refusal)
                .build(),
            Err(BuildError::PlannerWorkLimit { limit, .. })
                if limit == measured_build.planner_work - 1
        ));

        let mut persistent_refusal = exact_limits;
        persistent_refusal.max_persistent_bytes = measured_build.charged_persistent_bytes - 1;
        assert!(matches!(
            PortableBuilder::new(pattern)
                .unicode(false)
                .limits(persistent_refusal)
                .build(),
            Err(BuildError::PersistentBytesLimit { limit, .. })
                if limit == measured_build.charged_persistent_bytes - 1
        ));
    }

    #[test]
    fn invalid_window_is_rejected_before_source_reads() {
        let regex = build("(?-u:[abcd]){1,3}(?-u:[WXYZ]){1,3}");
        assert!(matches!(
            regex.find_window(
                b"abc",
                SearchWindow::new(2, 1),
                SearchLimits {
                    max_work: 0,
                    max_scratch_bytes: 0,
                },
            ),
            Err(FacadeSearchError::BoundedByteClassSequence(Error::InvalidWindow))
        ));
    }

    #[test]
    fn representational_width_overflow_is_ineligible_not_a_planner_error() {
        let run = super::Run {
            words: [1, 0, 0, 0],
            minimum: 1,
            maximum: 2,
        };
        assert_eq!(super::checked_width_totals(0, 0, run), Some((1, 2)));
        assert_eq!(super::checked_width_totals(usize::MAX, 0, run), None);
        assert_eq!(super::checked_width_totals(0, usize::MAX, run), None);

        let mut planner_work = u64::MAX;
        assert_eq!(
            super::charge_planner(&mut planner_work, 1, u64::MAX),
            Err(super::InspectionError::ArithmeticOverflow)
        );
    }

    #[cfg(target_pointer_width = "32")]
    #[test]
    fn cumulative_u32_bounds_fall_back_with_planner_work_preserved() {
        use regex_syntax::ParserBuilder;

        let hir = ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse("(?-u:[ab]){4294967295}(?-u:[CD]){4294967295}")
            .expect("source-valid maximum u32 repetition bounds");
        let outcome = super::inspect(&hir, 7, u64::MAX).expect("representational fallback");
        assert!(matches!(
            outcome,
            super::InspectionOutcome::Ineligible { planner_work } if planner_work >= 7
        ));
    }
}
