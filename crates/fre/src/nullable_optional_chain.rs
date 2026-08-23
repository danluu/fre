//! Direct search for nullable one-byte optional chains with a required tail.
//!
//! The admitted HIR is exactly `P0{0,m0} ... Pn{0,mn} T`, where every
//! predicate `P` consumes one byte, every finite maximum is positive, the
//! sum of the maxima is at most [`MAX_OPTIONAL_STAGES`], and `T` is one
//! nonempty exact byte literal. Every `P` must reject the first byte of `T`.
//! This tail-head barrier prevents a higher-priority optional path from
//! consuming and bypassing the first tail occurrence. Captures may wrap the
//! root, a repetition, or its one-byte body because this facade's operations
//! are capture-free. No look assertion or other topology is erased.
//!
//! Since every prefix stage is optional, every occurrence of `T` is a match.
//! The tail-head barrier also prevents a higher-priority prefix path from
//! bypassing the first occurrence, so existence and upstream earliest-end
//! queries are one literal search. It also proves that a later occurrence
//! cannot have an earlier start: such a prefix would have to cross and consume
//! the first occurrence's head byte. For a span, a backward predecessor mask
//! therefore recovers the earliest start attached to that first occurrence,
//! whose literal end is the selected endpoint for every greedy/lazy mixture.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "unchecked bit arithmetic stays within certified fixed domains"
)]

use fre_kernels::{LiteralBuildLimits, LiteralError, LiteralPlan, LiteralSearchLimits};
use regex_syntax::hir::{Class, Hir, HirKind};

use crate::{BuildError, Match, SearchLimits, SearchWindow, charge_planner, reserve_planner};

pub const PLAN_ID: &str = "nullable-optional-chain-required-tail.v1";
pub(crate) const MAX_OPTIONAL_STAGES: usize = 64;

const EMPTY_BYTE_PREDECESSORS: [u64; 256] = [0; 256];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Exists,
    EarliestEnd,
    SelectedEnd,
    Span,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Accounting {
    pub plan_id: &'static str,
    pub operation: Operation,
    pub input_bytes: usize,
    pub optional_stages: usize,
    pub tail_bytes: usize,
    pub candidate_visits: usize,
    pub finder_calls: usize,
    pub finder_linear_terms: u64,
    pub backward_steps: usize,
    pub replay_cells: usize,
    /// Peak scratch bytes admitted for the selected direct-prefix operation.
    ///
    /// Direct required-tail plans have a deliberately small, fixed scratch
    /// ceiling. Keeping this counter narrow lets it occupy padding in the hot
    /// accounting record instead of increasing every search result's size.
    pub scratch_bytes: u16,
    /// Peak scratch bytes actually instantiated on this execution path.
    pub actual_scratch_bytes: u16,
    pub work_upper_bound: u64,
    pub actual_work: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    InvalidWindow,
    WorkLimit { needed: u64, limit: u64 },
    ScratchLimit { needed: usize, limit: usize },
    Literal(LiteralError),
    ArithmeticOverflow { computation: &'static str },
    InternalInvariant { detail: &'static str },
}

impl core::fmt::Display for Error {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidWindow => formatter.write_str("invalid nullable required-tail window"),
            Self::WorkLimit { needed, limit } => write!(
                formatter,
                "nullable required-tail search needs {needed} work, exceeding {limit}",
            ),
            Self::ScratchLimit { needed, limit } => write!(
                formatter,
                "nullable required-tail search needs {needed} scratch bytes, exceeding {limit}",
            ),
            Self::Literal(error) => core::fmt::Display::fmt(error, formatter),
            Self::ArithmeticOverflow { computation } => {
                write!(formatter, "nullable required-tail overflow in {computation}")
            }
            Self::InternalInvariant { detail } => {
                write!(formatter, "nullable required-tail invariant failed: {detail}")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Literal(error) => Some(error),
            Self::InvalidWindow
            | Self::WorkLimit { .. }
            | Self::ScratchLimit { .. }
            | Self::ArithmeticOverflow { .. }
            | Self::InternalInvariant { .. } => None,
        }
    }
}

impl From<LiteralError> for Error {
    fn from(value: LiteralError) -> Self {
        Self::Literal(value)
    }
}

#[derive(Clone, Copy)]
struct Predicate {
    words: [u64; 4],
}

impl Predicate {
    const EMPTY: Self = Self { words: [0; 4] };

    fn contains(self, byte: u8) -> bool {
        let word = usize::from(byte >> 6);
        let bit = u32::from(byte & 63);
        self.words[word] & (1_u64 << bit) != 0
    }

    fn cardinality(self) -> u64 {
        self.words
            .iter()
            .map(|word| u64::from(word.count_ones()))
            .sum()
    }
}

pub(crate) struct Inspection {
    byte_predecessors: [u64; 256],
    optional_stages: usize,
    tail: Vec<u8>,
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

#[derive(Debug)]
pub(crate) struct Plan {
    byte_predecessors: [u64; 256],
    optional_stages: u8,
    tail: LiteralPlan,
}

#[derive(Default)]
struct Actual {
    candidate_visits: usize,
    finder_calls: usize,
    finder_linear_terms: u64,
    backward_steps: usize,
    replay_cells: usize,
}

impl Inspection {
    pub(crate) fn plan_storage_bytes(&self) -> Result<usize, BuildError> {
        projected_plan_storage_bytes(self.tail.len())
    }

    pub(crate) fn build(self, limits: LiteralBuildLimits) -> Result<Plan, LiteralError> {
        let tail = LiteralPlan::new(&self.tail, limits)?;
        Ok(Plan {
            byte_predecessors: self.byte_predecessors,
            optional_stages: u8::try_from(self.optional_stages)
                .expect("admitted optional stage count fits u8"),
            tail,
        })
    }
}

impl Plan {
    pub(crate) fn storage_bytes(&self) -> Result<usize, BuildError> {
        projected_plan_storage_bytes(self.tail.storage_bytes())
    }

    fn optional_stages(&self) -> usize {
        usize::from(self.optional_stages)
    }

    /// Try the Rust-compatible full-input existence projection without
    /// constructing the facade's diagnostic execution counters.
    ///
    /// The outer `Option` is a performance-policy decline. It is resolved
    /// before the literal finder can inspect the haystack, so the ordinary
    /// facade can replay the unchanged checked path and preserve its exact
    /// arithmetic failure. The inner result is the authoritative literal
    /// finder's result.
    #[inline]
    pub(crate) fn is_match_full_unlimited_value(
        &self,
        haystack: &[u8],
    ) -> Option<Result<bool, Error>> {
        ordinary_exists_work_is_representable(haystack.len(), self.tail.needle().len())?;
        Some(
            self.tail
                .find(haystack, LiteralSearchLimits::unlimited())
                .map(|(matched, _)| matched.is_some())
                .map_err(Error::from),
        )
    }

    pub(crate) fn is_match_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(bool, Accounting), Error> {
        let (tail, actual, upper) = self.first_tail(haystack, window, limits)?;
        let accounting = self.accounting(Operation::Exists, window, actual, upper)?;
        Ok((tail.is_some(), accounting))
    }

    pub(crate) fn is_match_window_value(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<bool, Error> {
        self.first_tail(haystack, window, limits)
            .map(|(tail, _, _)| tail.is_some())
    }

    pub(crate) fn earliest_end_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<usize>, Accounting), Error> {
        let (tail, actual, upper) = self.first_tail(haystack, window, limits)?;
        let accounting = self.accounting(Operation::EarliestEnd, window, actual, upper)?;
        Ok((tail.map(|(_, end)| end), accounting))
    }

    pub(crate) fn earliest_end_window_value(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<Option<usize>, Error> {
        self.first_tail(haystack, window, limits)
            .map(|(tail, _, _)| tail.map(|(_, end)| end))
    }

    pub(crate) fn selected_end_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<usize>, Accounting), Error> {
        let (matched, actual, upper) = self.search_span(haystack, window, limits)?;
        let accounting = self.accounting(Operation::SelectedEnd, window, actual, upper)?;
        Ok((matched.map(|matched| matched.end), accounting))
    }

    pub(crate) fn find_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, Accounting), Error> {
        let (matched, actual, upper) = self.search_span(haystack, window, limits)?;
        let accounting = self.accounting(Operation::Span, window, actual, upper)?;
        Ok((matched, accounting))
    }

    pub(crate) fn find_window_value(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<Option<Match>, Error> {
        self.search_span(haystack, window, limits)
            .map(|(matched, _, _)| matched)
    }

    fn first_tail(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<(usize, usize)>, Actual, u64), Error> {
        validate_window(haystack, window)?;
        let upper = self.literal_work_upper_bound(window)?;
        enforce_work(upper, limits)?;
        let mut actual = Actual::default();
        let found = self.find_tail(haystack, window.start(), window.end(), &mut actual)?;
        Ok((found, actual, upper))
    }

    fn search_span(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, Actual, u64), Error> {
        validate_window(haystack, window)?;
        let upper = self.work_upper_bound(window)?;
        enforce_work(upper, limits)?;
        let mut actual = Actual::default();
        let Some((first_tail, tail_end)) =
            self.find_tail(haystack, window.start(), window.end(), &mut actual)?
        else {
            return Ok((None, actual, upper));
        };
        actual.candidate_visits = 1;
        let start = self.earliest_start_for_tail(
            haystack,
            window.start(),
            first_tail,
            &mut actual,
        );
        Ok((Some(Match { start, end: tail_end }), actual, upper))
    }

    fn find_tail(
        &self,
        haystack: &[u8],
        start: usize,
        end: usize,
        actual: &mut Actual,
    ) -> Result<Option<(usize, usize)>, Error> {
        actual.finder_calls = actual.finder_calls.saturating_add(1);
        let (matched, accounting) = self.tail.find_window(
            haystack,
            fre_kernels::Window::new(start, end),
            LiteralSearchLimits::unlimited(),
        )?;
        actual.finder_linear_terms = actual
            .finder_linear_terms
            .checked_add(u64::try_from(accounting.linear_terms).map_err(|_| {
                Error::ArithmeticOverflow {
                    computation: "finder linear terms conversion",
                }
            })?)
            .ok_or(Error::ArithmeticOverflow {
                computation: "cumulative finder linear terms",
            })?;
        Ok(matched)
    }

    fn earliest_start_for_tail(
        &self,
        haystack: &[u8],
        window_start: usize,
        tail_start: usize,
        actual: &mut Actual,
    ) -> usize {
        let mut source = tail_start;
        let mut before_stage = self.optional_stages();
        while source > window_start && before_stage != 0 {
            actual.backward_steps = actual.backward_steps.saturating_add(1);
            let byte = haystack[source - 1];
            let predecessors = self.byte_predecessors[usize::from(byte)]
                & low_stage_mask(before_stage);
            if predecessors == 0 {
                break;
            }
            let stage = usize::try_from(u64::BITS - 1 - predecessors.leading_zeros())
                .expect("one u64 bit index fits usize");
            before_stage = stage;
            source -= 1;
        }
        source
    }

    fn work_upper_bound(&self, window: SearchWindow) -> Result<u64, Error> {
        let input = window
            .end()
            .checked_sub(window.start())
            .ok_or(Error::InvalidWindow)?;
        let stages = self.optional_stages();
        let tail = self.tail.needle().len();
        let finder_terms = input
            .checked_add(tail)
            .ok_or(Error::ArithmeticOverflow {
                computation: "finder work bound",
            })?;
        let backward = stages;
        let replay = 0usize;
        let finder_terms = u64::try_from(finder_terms).map_err(|_| Error::ArithmeticOverflow {
            computation: "finder work bound conversion",
        })?;
        let backward = u64::try_from(backward).map_err(|_| Error::ArithmeticOverflow {
            computation: "backward work bound conversion",
        })?;
        let replay = u64::try_from(replay).map_err(|_| Error::ArithmeticOverflow {
            computation: "replay work bound conversion",
        })?;
        finder_terms
            .checked_add(backward)
            .and_then(|total| total.checked_add(replay))
            .ok_or(Error::ArithmeticOverflow {
                computation: "search work bound sum",
            })
    }

    fn literal_work_upper_bound(&self, window: SearchWindow) -> Result<u64, Error> {
        let input = window
            .end()
            .checked_sub(window.start())
            .ok_or(Error::InvalidWindow)?;
        let terms = input
            .checked_add(self.tail.needle().len())
            .ok_or(Error::ArithmeticOverflow {
                computation: "literal-only work bound",
            })?;
        u64::try_from(terms).map_err(|_| Error::ArithmeticOverflow {
            computation: "literal-only work bound conversion",
        })
    }

    fn accounting(
        &self,
        operation: Operation,
        window: SearchWindow,
        actual: Actual,
        work_upper_bound: u64,
    ) -> Result<Accounting, Error> {
        let structural = actual
            .backward_steps
            .checked_add(actual.replay_cells)
            .ok_or(Error::ArithmeticOverflow {
                computation: "actual structural work",
            })?;
        let actual_work = actual
            .finder_linear_terms
            .checked_add(u64::try_from(structural).map_err(|_| Error::ArithmeticOverflow {
                computation: "actual structural work conversion",
            })?)
            .ok_or(Error::ArithmeticOverflow {
                computation: "actual search work",
            })?;
        if actual_work > work_upper_bound {
            return Err(Error::InternalInvariant {
                detail: "actual work exceeded its source-independent bound",
            });
        }
        Ok(Accounting {
            plan_id: PLAN_ID,
            operation,
            input_bytes: window.end().saturating_sub(window.start()),
            optional_stages: self.optional_stages(),
            tail_bytes: self.tail.needle().len(),
            candidate_visits: actual.candidate_visits,
            finder_calls: actual.finder_calls,
            finder_linear_terms: actual.finder_linear_terms,
            backward_steps: actual.backward_steps,
            replay_cells: actual.replay_cells,
            scratch_bytes: 0,
            actual_scratch_bytes: 0,
            work_upper_bound,
            actual_work,
        })
    }
}

pub(crate) fn inspect(
    hir: &Hir,
    initial_work: u64,
    max_planner_work: u64,
) -> Result<InspectionOutcome, BuildError> {
    let mut work = initial_work;
    let root = peel_captures(hir, &mut work, max_planner_work)?;
    let HirKind::Concat(parts) = root.kind() else {
        return Ok(InspectionOutcome::Ineligible { planner_work: work });
    };
    if parts.len() < 2 {
        return Ok(InspectionOutcome::Ineligible { planner_work: work });
    }
    charge_planner(
        &mut work,
        u64::try_from(parts.len()).unwrap_or(u64::MAX),
        max_planner_work,
    )?;
    let Some((tail_node, prefix)) = parts.split_last() else {
        return Ok(InspectionOutcome::Ineligible { planner_work: work });
    };
    let tail_node = peel_captures(tail_node, &mut work, max_planner_work)?;
    let HirKind::Literal(literal) = tail_node.kind() else {
        return Ok(InspectionOutcome::Ineligible { planner_work: work });
    };
    if literal.0.is_empty() {
        return Ok(InspectionOutcome::Ineligible { planner_work: work });
    }

    let mut byte_predecessors = EMPTY_BYTE_PREDECESSORS;
    let mut optional_stages = 0usize;
    for part in prefix {
        let part = peel_captures(part, &mut work, max_planner_work)?;
        let HirKind::Repetition(repetition) = part.kind() else {
            return Ok(InspectionOutcome::Ineligible { planner_work: work });
        };
        charge_planner(&mut work, 1, max_planner_work)?;
        let Some(maximum) = repetition.max else {
            return Ok(InspectionOutcome::Ineligible { planner_work: work });
        };
        if repetition.min != 0 || maximum == 0 {
            return Ok(InspectionOutcome::Ineligible { planner_work: work });
        }
        let maximum = usize::try_from(maximum).map_err(|_| {
            BuildError::InternalInvariant("optional-chain maximum does not fit usize")
        })?;
        let Some(next_stages) = optional_stages.checked_add(maximum) else {
            return Ok(InspectionOutcome::Ineligible { planner_work: work });
        };
        if next_stages > MAX_OPTIONAL_STAGES {
            return Ok(InspectionOutcome::Ineligible { planner_work: work });
        }
        let body = peel_captures(&repetition.sub, &mut work, max_planner_work)?;
        let Some(predicate) = inspect_predicate(body, &mut work, max_planner_work)? else {
            return Ok(InspectionOutcome::Ineligible { planner_work: work });
        };
        charge_planner(&mut work, 1, max_planner_work)?;
        if predicate.contains(literal.0[0]) {
            return Ok(InspectionOutcome::Ineligible { planner_work: work });
        }
        let stage_work = u64::try_from(maximum)
            .ok()
            .and_then(|maximum| {
                maximum.checked_mul(257_u64.saturating_add(predicate.cardinality()))
            })
            .ok_or(BuildError::InternalInvariant(
                "optional-chain predecessor construction work overflowed",
            ))?;
        charge_planner(&mut work, stage_work, max_planner_work)?;
        for stage in optional_stages..next_stages {
            let stage_bit = 1_u64 << stage;
            for byte in u8::MIN..=u8::MAX {
                if predicate.contains(byte) {
                    byte_predecessors[usize::from(byte)] |= stage_bit;
                }
            }
        }
        optional_stages = next_stages;
    }
    if optional_stages == 0 {
        return Ok(InspectionOutcome::Ineligible { planner_work: work });
    }
    let mut tail = Vec::new();
    reserve_planner(
        &mut tail,
        literal.0.len(),
        &mut work,
        max_planner_work,
        "nullable optional-chain tail",
    )?;
    tail.extend_from_slice(&literal.0);
    charge_planner(
        &mut work,
        u64::try_from(literal.0.len()).unwrap_or(u64::MAX),
        max_planner_work,
    )?;
    Ok(InspectionOutcome::Eligible(Inspection {
        byte_predecessors,
        optional_stages,
        tail,
        planner_work: work,
    }))
}

fn projected_plan_storage_bytes(tail_bytes: usize) -> Result<usize, BuildError> {
    core::mem::size_of::<Plan>()
        .checked_add(tail_bytes)
        .ok_or(BuildError::PersistentBytesOverflow)
}

fn inspect_predicate(
    hir: &Hir,
    work: &mut u64,
    max_planner_work: u64,
) -> Result<Option<Predicate>, BuildError> {
    let mut predicate = Predicate::EMPTY;
    match hir.kind() {
        HirKind::Class(Class::Bytes(class)) => {
            for range in class.ranges() {
                let members = usize::from(range.end())
                    .checked_sub(usize::from(range.start()))
                    .and_then(|width| width.checked_add(1))
                    .ok_or(BuildError::InternalInvariant(
                        "optional-chain byte range length overflowed",
                    ))?;
                charge_planner(
                    work,
                    u64::try_from(members).unwrap_or(u64::MAX),
                    max_planner_work,
                )?;
                for byte in range.start()..=range.end() {
                    let word = usize::from(byte >> 6);
                    let bit = u32::from(byte & 63);
                    predicate.words[word] |= 1_u64 << bit;
                }
            }
        }
        HirKind::Literal(literal) if literal.0.len() == 1 => {
            charge_planner(work, 1, max_planner_work)?;
            let byte = literal.0[0];
            let word = usize::from(byte >> 6);
            let bit = u32::from(byte & 63);
            predicate.words[word] |= 1_u64 << bit;
        }
        _ => return Ok(None),
    }
    Ok((predicate.words != [0; 4]).then_some(predicate))
}

fn peel_captures<'a>(
    mut hir: &'a Hir,
    work: &mut u64,
    max_planner_work: u64,
) -> Result<&'a Hir, BuildError> {
    loop {
        charge_planner(work, 1, max_planner_work)?;
        let HirKind::Capture(capture) = hir.kind() else {
            return Ok(hir);
        };
        hir = &capture.sub;
    }
}

fn low_stage_mask(before_stage: usize) -> u64 {
    if before_stage >= MAX_OPTIONAL_STAGES {
        u64::MAX
    } else {
        (1_u64 << before_stage).saturating_sub(1)
    }
}

fn ordinary_exists_work_is_representable(input_bytes: usize, tail_bytes: usize) -> Option<()> {
    let finder_terms = input_bytes.checked_add(tail_bytes)?;
    u64::try_from(finder_terms).ok().map(|_| ())
}

fn validate_window(haystack: &[u8], window: SearchWindow) -> Result<(), Error> {
    if window.start() > window.end() || window.end() > haystack.len() {
        return Err(Error::InvalidWindow);
    }
    Ok(())
}

fn enforce_work(needed: u64, limits: SearchLimits) -> Result<(), Error> {
    if needed > limits.max_work {
        return Err(Error::WorkLimit {
            needed,
            limit: limits.max_work,
        });
    }
    Ok(())
}

#[cfg(test)]
mod ordinary_exists_value_tests {
    use super::ordinary_exists_work_is_representable;

    #[test]
    fn admission_matches_the_canonical_literal_bound_at_address_space_edges() {
        assert!(ordinary_exists_work_is_representable(0, 1).is_some());
        assert!(ordinary_exists_work_is_representable(4096, 8).is_some());
        assert!(ordinary_exists_work_is_representable(usize::MAX - 1, 1).is_some());
        assert!(ordinary_exists_work_is_representable(usize::MAX, 1).is_none());
    }
}
