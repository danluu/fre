//! Direct search for finite greedy byte-class run sequences.
//!
//! The admitted HIR is a root concatenation of two through sixteen byte-class
//! terms, optionally preceded by exactly one absolute-start look. A term is
//! either a bare single-byte class/literal, treated as a fixed `1..1` run, or a
//! finite greedy `CLASS{min,max}` repetition. The ordinary form has two
//! positive leading runs; a suffix beginning at the third or a later run may
//! have zero minima when every maximum is positive.
//! One sealed exception is admitted after the first or a later required run: a
//! single greedy `CLASS{0,M}` followed by a fixed-width required byte/class.
//! That successor is the final required run, and the preceding required class
//! is disjoint from both corridor classes. A disjoint successor follows the
//! ordinary sequential verifier. When the bridge and successor overlap,
//! backtracking is confined to selecting one split inside the nullable run; it
//! can never escape into the prefix. Capture chains may wrap the root
//! concatenation, each immediate term, or each repetition's single-byte class
//! body; captures around a proper subsequence concatenation are not flattened.
//! At least one bound is variable. Every other boundary whose successor is
//! required has disjoint classes, making
//! the ordinary required prefix deterministic: a byte consumed by one run
//! cannot be returned to its required successor. Outside the one sealed
//! corridor, the nullable region is a terminal suffix, so it cannot invalidate
//! the prefix and no later required run can force it to give bytes back.
//! Boundaries into and within that suffix may overlap because an
//! already-successful match never backtracks merely to redistribute bytes
//! among greedy optional runs. Other non-adjacent classes may overlap as well.
//!
//! Search scans physical runs of the first class. Within one such run, only
//! its earliest suffix of at most the first maximum can reach the disjoint
//! successor; every earlier start stops at its maximum while still inside the
//! first class, and every later eligible start reaches the same successor
//! boundary.
//! A three-run sealed corridor, optionally followed by nullable suffix runs,
//! whose fixed successor is disjoint from both preceding classes may instead
//! select that successor as its search anchor.
//! This is limited to a one-to-three-byte successor that is strictly smaller
//! than the first class. Successor candidates are visited in source order and
//! the two bounded runs are recovered backwards. Pairwise disjointness makes
//! the first successful successor the leftmost match: an earlier successor
//! cannot occur inside either preceding run, so a later match cannot begin on
//! its left. After a fixed number of failed successor probes, search resumes
//! with the ordinary first-run scanner immediately after the last probe. This
//! bounds dense-decoy overhead without rescanning or skipping a possible
//! match.
//! The tail is therefore verified once per first-class run instead of once per
//! member. Ordinarily a positive second run makes that physical-run collapse
//! valid even when a later tail run is nullable. When the second run is the
//! sealed corridor, disjointness of the first class from both corridor classes
//! proves the same fact: a capped earlier start stops on another first-class
//! byte and fails, while every viable suffix reaches the physical run end. For
//! one immutable plan this is O(N), with a complete
//! source-independent bound of `N * (maximum_verification_width + 16)` charged
//! by the shared byte-class work meter. Fixed products remain with their
//! established incumbent plans; every structurally eligible variable product
//! is admitted, including small products that the earlier finite-language
//! plans decline.
//! An absolute-start plan instead evaluates exactly one candidate at byte zero:
//! it scans the first run only to its finite maximum and verifies the tail from
//! that exact boundary. A window beginning after zero cannot satisfy the
//! haystack-global look and returns no match without reading the source.

use fre_exact_alloc::{CopyError, ExactBoxOrUsize};
use fre_kernels::{
    BYTE_SET_BLOCK_BYTES, BYTE_SET_CLASSIFIER_BUILD_WORK, ByteSet256, ByteSetClassifier,
    DispatchPolicy, SimdDispatchContext,
};
use regex_syntax::hir::{Class, Hir, HirKind, Look};

use crate::pure_byte_class_repeat::{Error as SeekError, SetSeek, WorkMeter, validate_window};
use crate::{Match, SearchLimits, SearchWindow};

pub const PLAN_ID: &str = "bounded-byte-class-sequence-search-v2";

const MAX_RUNS: usize = 16;
const TAIL_ANCHOR_PROBE_LIMIT: u64 = 1;
const NODE_INSPECTION_WORK: u64 = 1;
const RANGE_INSPECTION_WORK: u64 = 1;
const MEMBER_INSERTION_WORK: u64 = 1;
const ADJACENT_DISJOINT_WORD_WORK: u64 = 4;
const BRIDGE_SEAL_WORD_WORK: u64 = 4;
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
    /// Exact number of selected-anchor candidate seeks.
    pub candidate_scans: u64,
    /// Exact number of bounded run verifications.
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SealedBridge {
    index: usize,
    overlaps_successor: bool,
}

impl SealedBridge {
    fn overlap_index(self) -> Option<usize> {
        self.overlaps_successor.then_some(self.index)
    }
}

pub(crate) struct Inspection {
    runs: [Run; MAX_RUNS],
    run_count: usize,
    total_minimum: usize,
    total_maximum: usize,
    anchored_start: bool,
    sealed_bridge: Option<SealedBridge>,
    tail_seek: Option<SetSeek>,
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
    last_required_run: usize,
    total_minimum: usize,
    total_maximum: usize,
    anchored_start: bool,
    sealed_bridge: Option<SealedBridge>,
    tail_seek: Option<SetSeek>,
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
        anchored_start: bool,
        sealed_bridge: Option<SealedBridge>,
        tail_seek: Option<SetSeek>,
        first_seek: SetSeek,
        first_run_end_seek: SetSeek,
        classifier_words: Option<[u64; 4]>,
        dispatch: SimdDispatchContext,
    ) -> Result<Self, CopyError> {
        let retained_runs = &runs[..run_count];
        let last_required_run = retained_runs
            .iter()
            .rposition(|run| run.minimum != 0)
            .expect("a bounded sequence has at least one required run");
        debug_assert!(last_required_run >= 1);
        if let Some(seal) = sealed_bridge {
            let bridge = seal.index;
            let successor = bridge
                .checked_add(1)
                .expect("a corridor successor fits the bounded run array");
            debug_assert!(bridge >= 1);
            debug_assert_eq!(last_required_run, successor);
            debug_assert!(retained_runs[..bridge]
                .iter()
                .all(|run| run.minimum != 0));
            debug_assert_eq!(retained_runs[bridge].minimum, 0);
            debug_assert_eq!(retained_runs[successor].minimum, 1);
            debug_assert_eq!(retained_runs[successor].maximum, 1);
            debug_assert_eq!(
                retained_runs[bridge].overlaps(retained_runs[successor]),
                seal.overlaps_successor
            );
        } else {
            debug_assert!(retained_runs[..=last_required_run]
                .iter()
                .all(|run| run.minimum != 0));
        }
        let nullable_suffix_start = last_required_run
            .checked_add(1)
            .expect("the final required run lies within the retained run array");
        debug_assert!(retained_runs[nullable_suffix_start..]
            .iter()
            .all(|run| run.minimum == 0));
        if tail_seek.is_some() {
            debug_assert!(!anchored_start);
            debug_assert_eq!(last_required_run, 2);
            debug_assert_eq!(
                sealed_bridge,
                Some(SealedBridge {
                    index: 1,
                    overlaps_successor: false,
                })
            );
            debug_assert!(retained_runs[2].cardinality() < retained_runs[0].cardinality());
            debug_assert!((1..=3).contains(&retained_runs[2].cardinality()));
        }
        let classifier = classifier_words.map(|words| {
            dispatch
                .byte_set_classifier(ByteSet256::from_words(words), DispatchPolicy::Auto)
                .expect("automatic byte-set dispatch retains a scalar fallback")
        });
        let owner = ExactBoxOrUsize::try_from_boxed(Owner {
            runs,
            run_count,
            last_required_run,
            total_minimum,
            total_maximum,
            anchored_start,
            sealed_bridge,
            tail_seek,
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

    /// Count ordinary non-overlapping selected matches at or after `start`.
    ///
    /// The original haystack remains intact so the admitted absolute-start
    /// look keeps its global context. Construction proves every selected span
    /// has positive width, so each search resumes at its selected end. When
    /// the complete tail admits the report-free work bound, that admission is
    /// monotone for every remaining suffix and the loop enters the unmetered
    /// value engine directly. An arithmetically exceptional tail retains the
    /// established unlimited value path and its typed failure behavior.
    #[inline(never)]
    pub(crate) fn ordinary_count_selected_ends_at(
        &self,
        haystack: &[u8],
        start: usize,
    ) -> Result<u64, SearchError> {
        let initial = SearchWindow::new(start, haystack.len());
        validate_window(haystack, initial)?;
        let direct = self.unmetered_work_fits(initial);
        let mut cursor = start;
        let mut count = 0_u64;
        loop {
            let window = SearchWindow::new(cursor, haystack.len());
            let selected_end = if direct {
                self.search_value(haystack, window, false)
                    .map(|(_, end)| end)
            } else {
                self.find_window_value(haystack, window, SearchLimits::unlimited())?
                    .map(|matched| matched.end())
            };
            let Some(selected_end) = selected_end else {
                return Ok(count);
            };
            debug_assert!(
                selected_end > cursor,
                "a bounded byte-class sequence has positive selected width",
            );
            cursor = selected_end;
            count = count.checked_add(1).ok_or(Error::CounterOverflow {
                counter: "ordinary selected-match count",
            })?;
        }
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
        if limits == SearchLimits::unlimited() {
            validate_window(haystack, window)?;
            if self.unmetered_work_fits(window) {
                return Ok(self.search_value(haystack, window, true).is_some());
            }
        }
        self.search(haystack, window, limits, true)
            .map(|state| state.span.is_some())
    }

    pub(crate) fn find_window_value(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<Option<Match>, SearchError> {
        if limits == SearchLimits::unlimited() {
            validate_window(haystack, window)?;
            if self.unmetered_work_fits(window) {
                return Ok(self
                    .search_value(haystack, window, false)
                    .map(|(start, end)| Match { start, end }));
            }
        }
        self.find_window(haystack, window, limits)
            .map(|(matched, _)| matched)
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

    pub(crate) fn earliest_end_window_value(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<Option<usize>, SearchError> {
        if limits == SearchLimits::unlimited() {
            validate_window(haystack, window)?;
            if self.unmetered_work_fits(window) {
                return Ok(self
                    .search_value(haystack, window, true)
                    .map(|(_, end)| end));
            }
        }
        self.earliest_end_window(haystack, window, limits)
            .map(|(end, _)| end)
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
        if owner.anchored_start {
            return self.search_anchored(haystack, window, limits, shortest_last);
        }
        let meter = WorkMeter::new(limits.max_work);
        if owner.tail_seek.is_some() {
            return self.search_tail_anchored(haystack, window, shortest_last, meter);
        }
        self.search_forward(
            haystack,
            window,
            window.start(),
            shortest_last,
            meter,
            0,
            0,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "adaptive handoff keeps the exact cursor and counters adjacent"
    )]
    fn search_forward(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        mut position: usize,
        shortest_last: bool,
        mut meter: WorkMeter,
        mut candidate_scans: u64,
        mut run_scans: u64,
    ) -> Result<SearchState, SearchError> {
        let owner = self.owner();
        let Some(last_start) = window.end().checked_sub(owner.total_minimum) else {
            return Ok(SearchState {
                span: None,
                meter,
                candidate_scans,
                run_scans,
            });
        };
        if last_start < position {
            return Ok(SearchState {
                span: None,
                meter,
                candidate_scans,
                run_scans,
            });
        }
        let candidate_end = last_start
            .checked_add(1)
            .expect("a last start before the window end advances once");
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

    fn search_tail_anchored(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        shortest_last: bool,
        mut meter: WorkMeter,
    ) -> Result<SearchState, SearchError> {
        let owner = self.owner();
        let tail_seek = owner
            .tail_seek
            .expect("the tail-anchored path retains its small successor seek");
        let Some(mut position) = window.start().checked_add(owner.runs[0].minimum) else {
            return Ok(SearchState {
                span: None,
                meter,
                candidate_scans: 0,
                run_scans: 0,
            });
        };
        if position >= window.end() {
            return Ok(SearchState {
                span: None,
                meter,
                candidate_scans: 0,
                run_scans: 0,
            });
        }

        let mut candidate_scans = 0_u64;
        let mut run_scans = 0_u64;
        let mut failed_probes = 0_u64;
        while position < window.end() {
            candidate_scans = candidate_scans
                .checked_add(1)
                .ok_or(Error::CounterOverflow {
                    counter: "candidate-scan",
                })?;
            let Some(successor) = tail_seek.seek(
                haystack,
                position,
                window.end(),
                &mut meter,
                None,
            )?
            else {
                break;
            };
            run_scans = run_scans.checked_add(2).ok_or(Error::CounterOverflow {
                counter: "run-scan",
            })?;
            if let Some(span) = owner.verify_tail_anchor(
                haystack,
                window.start(),
                successor,
                window.end(),
                shortest_last,
                &mut meter,
                &mut run_scans,
            )? {
                return Ok(SearchState {
                    span: Some(span),
                    meter,
                    candidate_scans,
                    run_scans,
                });
            }
            position = successor
                .checked_add(1)
                .expect("a successor candidate before the window end advances once");
            failed_probes = failed_probes
                .checked_add(1)
                .ok_or(Error::CounterOverflow {
                    counter: "tail-probe",
                })?;
            if failed_probes == TAIL_ANCHOR_PROBE_LIMIT {
                return self.search_forward(
                    haystack,
                    window,
                    position,
                    shortest_last,
                    meter,
                    candidate_scans,
                    run_scans,
                );
            }
        }
        Ok(SearchState {
            span: None,
            meter,
            candidate_scans,
            run_scans,
        })
    }

    fn search_anchored(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
        shortest_last: bool,
    ) -> Result<SearchState, SearchError> {
        let owner = self.owner();
        let mut meter = WorkMeter::new(limits.max_work);
        if window.start() != 0 || window.end() < owner.total_minimum {
            return Ok(SearchState {
                span: None,
                meter,
                candidate_scans: 0,
                run_scans: 0,
            });
        }

        let first = owner.runs[0];
        let mut position = 0_usize;
        let mut consumed = 0_usize;
        while consumed < first.maximum && position < window.end() {
            meter.charge(1)?;
            if !first.contains(haystack[position]) {
                break;
            }
            position = position
                .checked_add(1)
                .expect("an anchored position before the window end advances once");
            consumed = consumed
                .checked_add(1)
                .expect("the finite anchored first run cannot exceed its maximum");
        }
        let mut run_scans = 1_u64;
        let span = if consumed < first.minimum {
            None
        } else {
            owner
                .verify_tail(
                    haystack,
                    position,
                    window.end(),
                    shortest_last,
                    &mut meter,
                    &mut run_scans,
                )?
                .map(|end| (0, end))
        };
        Ok(SearchState {
            span,
            meter,
            candidate_scans: 1,
            run_scans,
        })
    }

    fn unmetered_work_fits(&self, window: SearchWindow) -> bool {
        let owner = self.owner();
        let input_bytes = window
            .end()
            .checked_sub(window.start())
            .expect("the caller validated ordered window bounds");
        let maximum_verification_width = if owner.tail_seek.is_some() {
            owner.total_maximum
        } else {
            let Some(width) = owner
                .total_maximum
                .checked_sub(owner.runs[0].maximum)
            else {
                return false;
            };
            width
        };
        let Some(per_candidate) = maximum_verification_width.checked_add(BYTE_SET_BLOCK_BYTES)
        else {
            return false;
        };
        u64::try_from(input_bytes)
            .ok()
            .and_then(|input| {
                u64::try_from(per_candidate)
                    .ok()
                    .and_then(|per_candidate| input.checked_mul(per_candidate))
            })
            .is_some()
    }

    fn search_value(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        shortest_last: bool,
    ) -> Option<(usize, usize)> {
        let owner = self.owner();
        if owner.anchored_start {
            return self.search_anchored_value(haystack, window, shortest_last);
        }
        if owner.tail_seek.is_some() {
            return self.search_tail_anchored_value(haystack, window, shortest_last);
        }
        self.search_forward_value(haystack, window, window.start(), shortest_last)
    }

    fn search_forward_value(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        mut position: usize,
        shortest_last: bool,
    ) -> Option<(usize, usize)> {
        let owner = self.owner();
        let last_start = window.end().checked_sub(owner.total_minimum)?;
        if last_start < position {
            return None;
        }
        let candidate_end = last_start
            .checked_add(1)
            .expect("a last start before the window end advances once");
        while position < candidate_end {
            let Some(run_start) = owner.first_seek.seek_unmetered(
                haystack,
                position,
                candidate_end,
                owner.classifier.as_ref(),
            ) else {
                break;
            };
            let after_run_start = run_start
                .checked_add(1)
                .expect("a first-run member before the window end advances once");
            let run_end = owner
                .first_run_end_seek
                .seek_unmetered(
                    haystack,
                    after_run_start,
                    window.end(),
                    owner.classifier.as_ref(),
                )
                .unwrap_or(window.end());
            let first = owner.runs[0];
            let run_length = run_end
                .checked_sub(run_start)
                .expect("the first-run end cannot precede its start");
            if run_length >= first.minimum {
                let start = run_end.saturating_sub(first.maximum).max(run_start);
                if let Some(end) =
                    owner.verify_tail_value(haystack, run_end, window.end(), shortest_last)
                {
                    return Some((start, end));
                }
            }
            if run_end == window.end() {
                break;
            }
            position = run_end
                .checked_add(1)
                .expect("a first-run boundary before the window end advances once");
        }
        None
    }

    fn search_tail_anchored_value(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        shortest_last: bool,
    ) -> Option<(usize, usize)> {
        let owner = self.owner();
        let tail_seek = owner
            .tail_seek
            .expect("the tail-anchored path retains its small successor seek");
        let mut position = window.start().checked_add(owner.runs[0].minimum)?;
        let mut failed_probes = 0_u64;
        while position < window.end() {
            let Some(successor) =
                tail_seek.seek_unmetered(haystack, position, window.end(), None)
            else {
                break;
            };
            if let Some(span) = owner.verify_tail_anchor_value(
                haystack,
                window.start(),
                successor,
                window.end(),
                shortest_last,
            ) {
                return Some(span);
            }
            position = successor
                .checked_add(1)
                .expect("a successor candidate before the window end advances once");
            failed_probes = failed_probes
                .checked_add(1)
                .expect("the fixed tail-probe budget fits u64");
            if failed_probes == TAIL_ANCHOR_PROBE_LIMIT {
                return self.search_forward_value(haystack, window, position, shortest_last);
            }
        }
        None
    }

    fn search_anchored_value(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        shortest_last: bool,
    ) -> Option<(usize, usize)> {
        let owner = self.owner();
        if window.start() != 0 || window.end() < owner.total_minimum {
            return None;
        }
        let first = owner.runs[0];
        let mut position = 0_usize;
        let mut consumed = 0_usize;
        while consumed < first.maximum && position < window.end() {
            if !first.contains(haystack[position]) {
                break;
            }
            position = position
                .checked_add(1)
                .expect("an anchored position before the window end advances once");
            consumed = consumed
                .checked_add(1)
                .expect("the finite anchored first run cannot exceed its maximum");
        }
        if consumed < first.minimum {
            return None;
        }
        owner
            .verify_tail_value(haystack, position, window.end(), shortest_last)
            .map(|end| (0, end))
    }

    fn finish_accounting(
        &self,
        operation: Operation,
        window: SearchWindow,
        state: &SearchState,
    ) -> Accounting {
        let input_bytes = window.end() - window.start();
        let owner = self.owner();
        let maximum_verification_width = if owner.tail_seek.is_some() {
            owner.total_maximum
        } else {
            owner
                .total_maximum
                .saturating_sub(owner.runs[0].maximum)
        };
        let per_candidate = maximum_verification_width.saturating_add(BYTE_SET_BLOCK_BYTES);
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
    fn verify_tail_anchor_value(
        &self,
        haystack: &[u8],
        window_start: usize,
        successor: usize,
        end: usize,
        shortest_last: bool,
    ) -> Option<(usize, usize)> {
        debug_assert!(self.tail_seek.is_some());
        debug_assert_eq!(self.last_required_run, 2);
        let first = self.runs[0];
        let bridge = self.runs[1];
        debug_assert!(first.minimum != 0);
        debug_assert_eq!(bridge.minimum, 0);
        debug_assert!(!first.overlaps(bridge));
        debug_assert!(!first.overlaps(self.runs[2]));
        debug_assert!(!bridge.overlaps(self.runs[2]));

        let mut position = successor;
        let mut consumed = 0_usize;
        while consumed < bridge.maximum && position > window_start {
            let previous = position
                .checked_sub(1)
                .expect("a reverse bridge cursor after the window start retreats once");
            if !bridge.contains(haystack[previous]) {
                break;
            }
            position = previous;
            consumed = consumed
                .checked_add(1)
                .expect("one reverse bridge cannot exceed its finite maximum");
        }

        consumed = 0;
        while consumed < first.maximum && position > window_start {
            let previous = position
                .checked_sub(1)
                .expect("a reverse first-run cursor after the window start retreats once");
            if !first.contains(haystack[previous]) {
                break;
            }
            position = previous;
            consumed = consumed
                .checked_add(1)
                .expect("one reverse first run cannot exceed its finite maximum");
        }
        if consumed < first.minimum {
            return None;
        }

        let mut selected_end = successor
            .checked_add(1)
            .expect("a successor before the window end advances once");
        if shortest_last {
            return Some((position, selected_end));
        }
        for &run in self.runs[..self.run_count].iter().skip(3) {
            debug_assert_eq!(run.minimum, 0);
            let mut suffix_consumed = 0_usize;
            while suffix_consumed < run.maximum && selected_end < end {
                if !run.contains(haystack[selected_end]) {
                    break;
                }
                selected_end = selected_end
                    .checked_add(1)
                    .expect("a nullable suffix cursor before the window end advances once");
                suffix_consumed = suffix_consumed
                    .checked_add(1)
                    .expect("one nullable suffix cannot exceed its finite maximum");
            }
        }
        Some((position, selected_end))
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the reverse verifier receives one immutable window and the shared exact counters"
    )]
    fn verify_tail_anchor(
        &self,
        haystack: &[u8],
        window_start: usize,
        successor: usize,
        end: usize,
        shortest_last: bool,
        meter: &mut WorkMeter,
        run_scans: &mut u64,
    ) -> Result<Option<(usize, usize)>, SearchError> {
        debug_assert!(self.tail_seek.is_some());
        debug_assert_eq!(self.last_required_run, 2);
        let first = self.runs[0];
        let bridge = self.runs[1];
        debug_assert!(first.minimum != 0);
        debug_assert_eq!(bridge.minimum, 0);
        debug_assert!(!first.overlaps(bridge));
        debug_assert!(!first.overlaps(self.runs[2]));
        debug_assert!(!bridge.overlaps(self.runs[2]));

        let mut position = successor;
        let mut consumed = 0_usize;
        while consumed < bridge.maximum && position > window_start {
            let previous = position
                .checked_sub(1)
                .expect("a reverse bridge cursor after the window start retreats once");
            meter.charge(1)?;
            if !bridge.contains(haystack[previous]) {
                break;
            }
            position = previous;
            consumed = consumed
                .checked_add(1)
                .expect("one reverse bridge cannot exceed its finite maximum");
        }

        consumed = 0;
        while consumed < first.maximum && position > window_start {
            let previous = position
                .checked_sub(1)
                .expect("a reverse first-run cursor after the window start retreats once");
            meter.charge(1)?;
            if !first.contains(haystack[previous]) {
                break;
            }
            position = previous;
            consumed = consumed
                .checked_add(1)
                .expect("one reverse first run cannot exceed its finite maximum");
        }
        if consumed < first.minimum {
            return Ok(None);
        }

        let mut selected_end = successor
            .checked_add(1)
            .expect("a successor before the window end advances once");
        if shortest_last {
            return Ok(Some((position, selected_end)));
        }
        for &run in self.runs[..self.run_count].iter().skip(3) {
            debug_assert_eq!(run.minimum, 0);
            *run_scans = run_scans.checked_add(1).ok_or(Error::CounterOverflow {
                counter: "run-scan",
            })?;
            let mut suffix_consumed = 0_usize;
            while suffix_consumed < run.maximum && selected_end < end {
                meter.charge(1)?;
                if !run.contains(haystack[selected_end]) {
                    break;
                }
                selected_end = selected_end
                    .checked_add(1)
                    .expect("a nullable suffix cursor before the window end advances once");
                suffix_consumed = suffix_consumed
                    .checked_add(1)
                    .expect("one nullable suffix cannot exceed its finite maximum");
            }
        }
        Ok(Some((position, selected_end)))
    }

    /// Select one valid split between a nullable greedy class and its
    /// overlapping fixed-width successor. The earliest-end operation chooses
    /// the first valid split; selected-end/span retain regex greediness by
    /// choosing the last valid split before the nullable run stops or reaches
    /// its maximum. Each candidate boundary loads its byte exactly once.
    fn verify_overlap_corridor_value(
        &self,
        haystack: &[u8],
        position: usize,
        end: usize,
        bridge_index: usize,
        shortest: bool,
    ) -> Option<usize> {
        let bridge = self.runs[bridge_index];
        let successor_index = bridge_index
            .checked_add(1)
            .expect("a corridor successor fits the bounded run array");
        let successor = self.runs[successor_index];
        debug_assert_eq!(bridge.minimum, 0);
        debug_assert_eq!((successor.minimum, successor.maximum), (1, 1));
        let mut consumed = 0_usize;
        let mut selected = None;
        loop {
            let candidate = position
                .checked_add(consumed)
                .expect("a bounded corridor candidate fits its validated window");
            if candidate >= end {
                break;
            }
            let byte = haystack[candidate];
            if successor.contains(byte) {
                let after = candidate
                    .checked_add(1)
                    .expect("a corridor successor before the window end advances once");
                if shortest {
                    return Some(after);
                }
                selected = Some(after);
            }
            if consumed == bridge.maximum || !bridge.contains(byte) {
                break;
            }
            consumed = consumed
                .checked_add(1)
                .expect("one corridor cannot exceed its finite maximum");
        }
        selected
    }

    fn verify_overlap_corridor(
        &self,
        haystack: &[u8],
        position: usize,
        end: usize,
        bridge_index: usize,
        shortest: bool,
        meter: &mut WorkMeter,
    ) -> Result<Option<usize>, SearchError> {
        let bridge = self.runs[bridge_index];
        let successor_index = bridge_index
            .checked_add(1)
            .expect("a corridor successor fits the bounded run array");
        let successor = self.runs[successor_index];
        debug_assert_eq!(bridge.minimum, 0);
        debug_assert_eq!((successor.minimum, successor.maximum), (1, 1));
        let mut consumed = 0_usize;
        let mut selected = None;
        loop {
            let candidate = position
                .checked_add(consumed)
                .expect("a bounded corridor candidate fits its validated window");
            if candidate >= end {
                break;
            }
            meter.charge(1)?;
            let byte = haystack[candidate];
            if successor.contains(byte) {
                let after = candidate
                    .checked_add(1)
                    .expect("a corridor successor before the window end advances once");
                if shortest {
                    return Ok(Some(after));
                }
                selected = Some(after);
            }
            if consumed == bridge.maximum || !bridge.contains(byte) {
                break;
            }
            consumed = consumed
                .checked_add(1)
                .expect("one corridor cannot exceed its finite maximum");
        }
        Ok(selected)
    }

    fn verify_tail_value(
        &self,
        haystack: &[u8],
        start: usize,
        end: usize,
        shortest_last: bool,
    ) -> Option<usize> {
        let mut position = start;
        let runs = &self.runs[..self.run_count];
        let Some(overlap_bridge) = self
            .sealed_bridge
            .and_then(SealedBridge::overlap_index)
        else {
            for (index, &run) in runs.iter().enumerate().skip(1) {
                let shortest_terminal = shortest_last && index == self.last_required_run;
                let maximum = if shortest_terminal {
                    run.minimum
                } else {
                    run.maximum
                };
                let mut consumed = 0_usize;
                while consumed < maximum && position < end {
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
                    return None;
                }
                if shortest_terminal {
                    return Some(position);
                }
            }
            return Some(position);
        };
        let mut index = 1_usize;
        while index < runs.len() {
            if index == overlap_bridge {
                position = self.verify_overlap_corridor_value(
                    haystack,
                    position,
                    end,
                    overlap_bridge,
                    shortest_last,
                )?;
                if shortest_last {
                    return Some(position);
                }
                index = index
                    .checked_add(2)
                    .expect("a corridor and successor fit the bounded run array");
                continue;
            }
            let run = runs[index];
            let shortest_terminal = shortest_last && index == self.last_required_run;
            let maximum = if shortest_terminal {
                run.minimum
            } else {
                run.maximum
            };
            let mut consumed = 0_usize;
            while consumed < maximum && position < end {
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
                return None;
            }
            if shortest_terminal {
                return Some(position);
            }
            index = index
                .checked_add(1)
                .expect("one run fits the bounded run array");
        }
        Some(position)
    }

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
        let Some(overlap_bridge) = self
            .sealed_bridge
            .and_then(SealedBridge::overlap_index)
        else {
            for (index, &run) in runs.iter().enumerate().skip(1) {
                *run_scans = run_scans.checked_add(1).ok_or(Error::CounterOverflow {
                    counter: "run-scan",
                })?;
                let shortest_terminal = shortest_last && index == self.last_required_run;
                let maximum = if shortest_terminal {
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
                if shortest_terminal {
                    return Ok(Some(position));
                }
            }
            return Ok(Some(position));
        };
        let mut index = 1_usize;
        while index < runs.len() {
            if index == overlap_bridge {
                *run_scans = run_scans.checked_add(2).ok_or(Error::CounterOverflow {
                    counter: "run-scan",
                })?;
                let Some(next) = self.verify_overlap_corridor(
                    haystack,
                    position,
                    end,
                    overlap_bridge,
                    shortest_last,
                    meter,
                )? else {
                    return Ok(None);
                };
                position = next;
                if shortest_last {
                    return Ok(Some(position));
                }
                index = index
                    .checked_add(2)
                    .expect("a corridor and successor fit the bounded run array");
                continue;
            }
            let run = runs[index];
            *run_scans = run_scans.checked_add(1).ok_or(Error::CounterOverflow {
                counter: "run-scan",
            })?;
            let shortest_terminal = shortest_last && index == self.last_required_run;
            let maximum = if shortest_terminal {
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
            if shortest_terminal {
                return Ok(Some(position));
            }
            index = index
                .checked_add(1)
                .expect("one run fits the bounded run array");
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
            self.anchored_start,
            self.sealed_bridge,
            self.tail_seek,
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
    let HirKind::Concat(root_parts) = root.kind() else {
        return Ok(InspectionOutcome::Ineligible { planner_work: work });
    };
    let parts = root_parts.as_slice();
    let (anchored_start, parts) = match parts.split_first() {
        Some((first, rest)) if matches!(first.kind(), HirKind::Look(Look::Start)) => {
            charge_planner(
                &mut work,
                NODE_INSPECTION_WORK,
                max_planner_work,
            )?;
            (true, rest)
        }
        _ => (false, parts),
    };
    if !(2..=MAX_RUNS).contains(&parts.len()) {
        return Ok(InspectionOutcome::Ineligible { planner_work: work });
    }

    let mut runs = [Run::EMPTY; MAX_RUNS];
    let mut total_minimum = 0_usize;
    let mut total_maximum = 0_usize;
    let mut has_variable_bound = false;
    let mut nullable_suffix_start = None;
    let mut sealed_bridge = None;
    let mut last_adjacent_overlap = false;
    for (index, part) in parts.iter().enumerate() {
        let Some(run) = inspect_run(part, index >= 1, &mut work, max_planner_work)? else {
            return Ok(InspectionOutcome::Ineligible { planner_work: work });
        };
        if index != 0 {
            charge_planner(
                &mut work,
                ADJACENT_DISJOINT_WORD_WORK,
                max_planner_work,
            )?;
            let previous = runs[index - 1];
            let adjacent_overlap = previous.overlaps(run);
            if run.minimum == 0 {
                if nullable_suffix_start.is_none() {
                    nullable_suffix_start = Some(index);
                }
            } else if let Some(nullable_start) = nullable_suffix_start {
                let bridge = index
                    .checked_sub(1)
                    .expect("a required successor has one preceding run");
                // Admit exactly one sealed nullable bridge. The fixed-width
                // successor closes it before any optional terminal suffix.
                // Its predecessor was already checked against the bridge at
                // the prior charged boundary; one extra four-word comparison
                // seals that predecessor from the successor too. Only an
                // overlapping bridge/successor pair needs the split scanner.
                if sealed_bridge.is_some()
                    || nullable_start != bridge
                    || bridge == 0
                    || run.minimum != 1
                    || run.maximum != 1
                    || last_adjacent_overlap
                {
                    return Ok(InspectionOutcome::Ineligible { planner_work: work });
                }
                charge_planner(
                    &mut work,
                    BRIDGE_SEAL_WORD_WORK,
                    max_planner_work,
                )?;
                let predecessor_index = bridge
                    .checked_sub(1)
                    .expect("a sealed corridor has one required predecessor");
                let predecessor = runs[predecessor_index];
                if predecessor.overlaps(run) {
                    return Ok(InspectionOutcome::Ineligible { planner_work: work });
                }
                sealed_bridge = Some(SealedBridge {
                    index: bridge,
                    overlaps_successor: adjacent_overlap,
                });
                nullable_suffix_start = None;
            } else {
                // Once a corridor has closed, its successor is the final
                // required run. A later required run could force the local
                // greedy split to backtrack again.
                if sealed_bridge.is_some() || adjacent_overlap {
                    return Ok(InspectionOutcome::Ineligible { planner_work: work });
                }
            }
            last_adjacent_overlap = adjacent_overlap;
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
    // A nullable second run is safe only when the following fixed successor
    // closes the sealed corridor. Without that successor, physical-first-run
    // collapse could skip the earlier capped match inside a long first run.
    if nullable_suffix_start == Some(1) {
        return Ok(InspectionOutcome::Ineligible { planner_work: work });
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
    let tail_seek = if !anchored_start {
        sealed_bridge.and_then(|bridge| {
            if bridge.index != 1 || bridge.overlaps_successor {
                return None;
            }
            let successor = runs[2];
            let successor_cardinality = successor.cardinality();
            if !(1..=3).contains(&successor_cardinality)
                || successor_cardinality >= cardinality
            {
                return None;
            }
            Some((successor, successor_cardinality))
        })
    } else {
        None
    };
    let tail_seek = if let Some((successor, successor_cardinality)) = tail_seek {
        charge_planner(&mut work, LEAF_SELECTION_WORK, max_planner_work)?;
        let seek = SetSeek::build(successor.words, successor_cardinality, false);
        debug_assert!(!seek.requires_classifier());
        Some(seek)
    } else {
        None
    };
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
        anchored_start,
        sealed_bridge,
        tail_seek,
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
    allow_zero_minimum: bool,
    work: &mut u64,
    max_planner_work: u64,
) -> Result<Option<Run>, InspectionError> {
    let hir = peel_captures(hir, work, max_planner_work)?;
    let (body, minimum, maximum) = match hir.kind() {
        HirKind::Repetition(repetition) => {
            let Some(maximum) = repetition.max else {
                return Ok(None);
            };
            if maximum == 0
                || maximum < repetition.min
                || !repetition.greedy
                || (repetition.min == 0 && !allow_zero_minimum)
            {
                return Ok(None);
            }
            let Ok(minimum) = usize::try_from(repetition.min) else {
                return Ok(None);
            };
            let Ok(maximum) = usize::try_from(maximum) else {
                return Ok(None);
            };
            (
                peel_captures(&repetition.sub, work, max_planner_work)?,
                minimum,
                maximum,
            )
        }
        HirKind::Class(_) | HirKind::Literal(_) => (hir, 1, 1),
        _ => return Ok(None),
    };
    let mut words = [0_u64; 4];
    match body.kind() {
        HirKind::Class(Class::Bytes(class)) => {
            for range in class.ranges() {
                charge_planner(work, RANGE_INSPECTION_WORK, max_planner_work)?;
                for byte in range.start()..=range.end() {
                    charge_planner(work, MEMBER_INSERTION_WORK, max_planner_work)?;
                    let bitmap_index = usize::from(byte >> 6);
                    let bit = u32::from(byte & 63);
                    words[bitmap_index] |= 1_u64 << bit;
                }
            }
        }
        HirKind::Literal(literal) if literal.0.len() == 1 => {
            charge_planner(work, MEMBER_INSERTION_WORK, max_planner_work)?;
            let byte = literal.0[0];
            let bitmap_index = usize::from(byte >> 6);
            let bit = u32::from(byte & 63);
            words[bitmap_index] |= 1_u64 << bit;
        }
        _ => return Ok(None),
    }
    if words.iter().all(|word| *word == 0) {
        return Ok(None);
    }
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

    fn oracle_earliest_end(regex: &regex::bytes::Regex, haystack: &[u8]) -> Option<usize> {
        (0..=haystack.len()).find(|&end| regex.is_match(&haystack[..end]))
    }

    #[test]
    fn selects_variable_sequences_with_deterministic_boundaries() {
        for pattern in [
            "a{1,2}b{1,2}",
            "(?-u:[QX])(?-u:[a-z_]){19,20}(?-u:[0-9])?",
            "(?-u:[ab])(?-u:[CD]){1,2}",
            "(?-u:[ab]){1,2}(?-u:[CD])(?-u:[xy])?",
            "(?-u:[ab])(?-u:[CD]){1,2}(?-u:[xy])?(?-u:[CD]){0,2}",
            "(?-u:[ab])(?-u:[CD]){1,2}(?-u:[CD])?",
            "(?-u:[ab])(?-u:[CD]){1,2}(?-u:[xy])?(?-u:[xy])?",
            "(?-u:[ab]){1,2}(?-u:[CD])?(?-u:[xy])",
            "(?-u:[Aa])(?-u:[Bb]){1,2}(?-u:[Cc])?(?-u:[Dd])",
            "(?-u:[\\x00\\x80\\xFE\\xFF])(?-u:[\\x20-\\x7E]){2,3}(?-u:[0-9])?",
            "(?-u:[A-Z]){1,3}(?-u:[a-z]){2,5}(?-u:[0-9]){1,2}",
            "(?-u:[abcd]){1,3}(?-u:[WXYZ]){1,3}",
            "(?-u:[ab]){1,4}(?-u:[cd]){1,4}(?-u:[ab]){1,4}",
            "((?-u:[A-Z]){1,3})((?-u:[a-z]){2,5})",
            "((?-u:[A-Z]){1,3}(?-u:[a-z]){2,5})",
            "(?-u:([A-Z])){1,3}(?-u:[a-z]){2,5}",
            r"(?-u:[\x80-\x83]){1,32}(?-u:[A-D]){1,32}",
            r"(?-u:[\x00-\xFE]){1,32}(?-u:\xFF){1,32}",
            "a{1,4096}(?-u:[B-D]){1,4096}",
            "(?-u:[Aa])(?-u:[Cc]){1,2}(?-u:[Bb]){0,3}(?-u:[Bb])",
            "(?-u:[QX])(?-u:[0-2]){1,3}(?-u:[a-c]){0,4}(?-u:[b-d])",
            "(?-u:[Aa])(?-u:[Cc]){1,2}(?-u:[Bb]){0,3}B",
            "A(?-u:[C]){1,2}(?-u:[ab]){0,3}(?-u:[ab])(?-u:[xy])?",
            "(A)((?-u:[C]){1,2})((?-u:[ab]){0,3})(?-u:([ab]))",
            "(?-u:[AQ])(?-u:[ab]){0,3}(?-u:[ab])",
            "(?-u:[WZ]){1,3}(?-u:[ab]){0,2}(?-u:[bd])(?-u:[xy])?",
            // regex-syntax erases the zero-width middle repetition, leaving
            // two ordinary bounded byte-class runs.
            "(?-u:[ab]){1,2}(?-u:[CD]){0}(?-u:[xy])",
            r"(?-u:\x01[\x30-\x40]{0,64}\x40)",
            r"\A(?-u:\x01[\x30-\x40]{0,64}\x40)",
            r"\A(?-u:[WZ]){1,3}(?-u:[ab]){0,2}(?-u:[bd])(?-u:[xy])?",
            r"(?-u:[\x10-\x17]){1,3}(?-u:[\x40-\x5F]){0,3}(?-u:\x7A)",
            r"(?-u:[\x10-\x17]){1,3}(?-u:[\x40-\x5F]){0,11}(?-u:\x7A)",
            r"\A(?-u:[\x10-\x17]){1,3}(?-u:[\x40-\x5F]){0,11}(?-u:\x7A)",
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
            "(?-u:[ab])?(?-u:[CD]){1,2}(?-u:[xy])",
            "(?-u:[Aa])(?-u:[Bb]){1,2}(?-u:[Cc])?(?-u:[Bb])",
            "A(?-u:[ab]){1,2}(?-u:[ab]){0,3}(?-u:[ab])",
            "A(?-u:[c]){1,2}(?-u:[ab]){0,3}(?-u:[b]){1,2}",
            "A(?-u:[b]){1,2}(?-u:[ac]){0,3}(?-u:[bc])",
            "A(?-u:[C])(?-u:[ab]){0,3}(?-u:[ab])(?-u:[xy]){0,2}(?-u:[xy])",
            "(?-u:[AQ])(?-u:[ab]){0,3}",
            "(?-u:[ab]){1,3}(?-u:[ab]){0,3}(?-u:[ab])",
            "(?-u:[b]){1,3}(?-u:[ac]){0,3}(?-u:[bc])",
            "(?-u:[AQ])(?-u:[ab]){0,3}(?-u:[b]){1,2}",
            r"\z(?-u:[AQ])(?-u:[ab]){0,3}(?-u:[ab])",
            r"(?-u:[AQ])\A(?-u:[ab]){0,3}(?-u:[ab])",
            r"\A(?-u:\b)(?-u:[AQ])(?-u:[ab]){0,3}(?-u:[ab])",
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
            .find_accounted(haystack, SearchLimits::unlimited())
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
            "(?-u:[ab])(?-u:[cd]){1,2}",
            "(?-u:[ab]){1,2}(?-u:[cd])(?-u:[WZ])?",
            "(?-u:[ab])(?-u:[cd]){1,2}(?-u:[WZ])?",
            "(?-u:[ab]){1,2}(?-u:[cd]){1,2}(?-u:[WZ]){0,2}(?-u:[ab])?",
            "(?-u:[ab])(?-u:[cd]){1,2}(?-u:[WZ])?(?-u:[cd]){0,2}",
            "(?-u:[ab])(?-u:[cd]){1,2}(?-u:[cd])?(?-u:[cd])?",
            "(?-u:[abcd]){1,3}(?-u:[WXYZ]){1,3}",
            "(?-u:[ab]){1,4}(?-u:[cd]){1,4}(?-u:[ab]){1,4}",
            "(?-u:[W])(?-u:[Zc])(?-u:[ab]){0,2}(?-u:[ab])",
            "(?-u:[W])(?-u:[Zc])(?-u:[ab]){0,2}(?-u:[bd])",
            "(?-u:[W])(?-u:[Zc]){1,2}(?-u:[ab]){0,2}(?-u:[ab])",
            "(?-u:[W])(?-u:[ab]){0,2}(?-u:[ab])",
            "(?-u:[WZ]){1,3}(?-u:[ab]){0,2}(?-u:[bd])",
            "(?-u:[W])(?-u:[ab]){0,2}(?-u:[d])",
            "(?-u:[WZ]){1,3}(?-u:[ab]){0,2}(?-u:[d])",
        ];
        let alphabet = [b'a', b'b', b'd', b'W', b'Z', b'c', b'x'];
        for pattern in patterns {
            let fre = build(pattern);
            assert_eq!(fre.runtime_implementation_id(), PLAN_ID);
            let PortablePlan::BoundedByteClassSequence(plan) = &fre.plan else {
                panic!("one admitted sequence should retain its sequence plan");
            };
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
                                oracle_earliest_end(&oracle, source).map(|finish| start + finish);
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
                                plan.selected_end_window(
                                    &haystack,
                                    window,
                                    SearchLimits::unlimited(),
                                )
                                .unwrap()
                                .0,
                                expected.map(|(_, finish)| finish),
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
    fn ordinary_count_matches_upstream_selected_iteration_for_every_start() {
        fn selected_count(
            regex: &regex::bytes::Regex,
            haystack: &[u8],
            start: usize,
        ) -> u64 {
            let mut cursor = start;
            let mut count = 0_u64;
            while let Some(matched) = regex.find_at(haystack, cursor) {
                assert!(matched.end() > cursor);
                cursor = matched.end();
                count = count.checked_add(1).unwrap();
            }
            count
        }

        let cases: [(&str, &[u8]); 5] = [
            (r"(?-u:[ab]){1,2}(?-u:[CD]){1,2}", b"aCD!"),
            (
                r"(?-u:[ab])(?-u:[CD])(?-u:[ab]){0,2}",
                b"aCb!",
            ),
            (
                r"(?-u:[WZ]){1,3}(?-u:[ab]){0,2}(?-u:[bd])",
                b"WZabd!",
            ),
            (
                r"(?-u:[WZ]){1,3}(?-u:[ab]){0,2}(?-u:[d])",
                b"WZabd!",
            ),
            (
                r"\A(?-u:[ab]){1,2}(?-u:[CD]){1,2}",
                b"aCD!",
            ),
        ];
        for (pattern, alphabet) in cases {
            let fre = build(pattern);
            let PortablePlan::BoundedByteClassSequence(plan) = &fre.plan else {
                panic!("expected bounded sequence plan for {pattern:?}");
            };
            let upstream = regex::bytes::RegexBuilder::new(pattern)
                .unicode(false)
                .build()
                .unwrap();
            let mut ordinary = fre.ordinary_session().unwrap();
            for length in 0_u32..=5 {
                let haystack_count = alphabet.len().pow(length);
                for encoded in 0..haystack_count {
                    let mut value = encoded;
                    let mut haystack = vec![0_u8; usize::try_from(length).unwrap()];
                    for byte in &mut haystack {
                        *byte = alphabet[value % alphabet.len()];
                        value /= alphabet.len();
                    }
                    for start in 0..=haystack.len() {
                        let expected = selected_count(&upstream, &haystack, start);
                        assert_eq!(
                            plan.ordinary_count_selected_ends_at(&haystack, start),
                            Ok(expected),
                            "direct count: pattern={pattern:?}, haystack={haystack:?}, start={start}",
                        );
                        assert_eq!(
                            ordinary.count_positive_width_selected_ends_at(
                                &haystack,
                                start,
                            ),
                            Ok(Some(expected)),
                            "facade count: pattern={pattern:?}, haystack={haystack:?}, start={start}",
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn ordinary_count_advances_by_the_selected_greedy_end() {
        let fre = build(r"(?-u:[ab])(?-u:[CD])(?-u:[ab]){0,2}");
        let PortablePlan::BoundedByteClassSequence(plan) = &fre.plan else {
            panic!("expected bounded sequence plan");
        };
        let haystack = b"aCaC";

        let mut earliest_cursor = 0_usize;
        let mut earliest_count = 0_u64;
        while let Some(end) = fre
            .shortest_match_at_value(
                haystack,
                earliest_cursor,
                SearchLimits::unlimited(),
            )
            .unwrap()
        {
            assert!(end > earliest_cursor);
            earliest_cursor = end;
            earliest_count = earliest_count.checked_add(1).unwrap();
        }
        assert_eq!(earliest_count, 2);
        assert_eq!(
            plan.ordinary_count_selected_ends_at(haystack, 0),
            Ok(1),
        );
        assert_eq!(
            fre.ordinary_session()
                .unwrap()
                .count_positive_width_selected_ends_at(haystack, 0),
            Ok(Some(1)),
        );
    }

    #[test]
    fn ordinary_count_preserves_absolute_start_and_invalid_windows() {
        let fre = build(r"\A(?-u:[ab]){1,2}(?-u:[CD]){1,2}");
        let PortablePlan::BoundedByteClassSequence(plan) = &fre.plan else {
            panic!("expected bounded sequence plan");
        };
        let haystack = b"aCaC";
        assert_eq!(plan.ordinary_count_selected_ends_at(haystack, 0), Ok(1));
        assert_eq!(plan.ordinary_count_selected_ends_at(haystack, 2), Ok(0));
        assert_eq!(
            plan.ordinary_count_selected_ends_at(haystack, haystack.len()),
            Ok(0),
        );
        assert_eq!(
            plan.ordinary_count_selected_ends_at(haystack, usize::MAX),
            Err(Error::InvalidWindow),
        );

        let mut ordinary = fre.ordinary_session().unwrap();
        assert_eq!(
            ordinary.count_positive_width_selected_ends_at(haystack, 0),
            Ok(Some(1)),
        );
        assert_eq!(
            ordinary.count_positive_width_selected_ends_at(haystack, 2),
            Ok(Some(0)),
        );
        assert_eq!(
            ordinary.count_positive_width_selected_ends_at(
                haystack,
                usize::MAX,
            ),
            Err(FacadeSearchError::BoundedByteClassSequence(
                Error::InvalidWindow,
            )),
        );
    }

    #[test]
    fn exhaustive_absolute_start_corridors_match_global_window_semantics() {
        let patterns = [
            r"\A(?-u:[W])(?-u:[ab]){0,2}(?-u:[ab])",
            r"\A(?-u:[WZ]){1,3}(?-u:[ab]){0,2}(?-u:[bd])",
            r"\A(?-u:[WZ]){1,3}(?-u:[ab]){0,2}(?-u:[d])",
        ];
        let alphabet = [b'a', b'b', b'd', b'W', b'Z', b'x'];
        for pattern in patterns {
            let fre = build(pattern);
            assert_eq!(fre.runtime_implementation_id(), PLAN_ID);
            let PortablePlan::BoundedByteClassSequence(plan) = &fre.plan else {
                panic!("one anchored corridor should retain its sequence plan");
            };
            assert!(plan.owner().anchored_start);
            let seal = plan
                .owner()
                .sealed_bridge
                .expect("one anchored pattern retains a sealed bridge");
            assert_eq!(seal.index, 1);
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
                            let (expected, expected_shortest) = if start == 0 {
                                (
                                    oracle
                                        .find(&haystack[..end])
                                        .map(|matched| (matched.start(), matched.end())),
                                    oracle_earliest_end(&oracle, &haystack[..end]),
                                )
                            } else {
                                (None, None)
                            };
                            let (exists, search_accounting) = fre
                                .is_match_window(
                                    &haystack,
                                    window,
                                    SearchLimits::unlimited(),
                                )
                                .unwrap();
                            assert_eq!(exists, expected.is_some());
                            let search_accounting = accounting(search_accounting);
                            assert!(
                                search_accounting.actual_work
                                    <= search_accounting.work_upper_bound
                            );
                            if start != 0 {
                                assert_eq!(search_accounting.actual_work, 0);
                                assert_eq!(search_accounting.candidate_scans, 0);
                                assert_eq!(search_accounting.run_scans, 0);
                            }
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
                                plan.selected_end_window(
                                    &haystack,
                                    window,
                                    SearchLimits::unlimited(),
                                )
                                .unwrap()
                                .0,
                                expected.map(|(_, finish)| finish),
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
    fn nullable_tail_preserves_shortest_and_greedy_selected_ends() {
        let regex = build("(?-u:[ab]){1,3}(?-u:[CD]){1,2}(?-u:[xy])?");
        assert_eq!(regex.runtime_implementation_id(), PLAN_ID);
        let haystack = b"aaCCx";
        assert_eq!(
            regex
                .shortest_match(haystack, SearchLimits::unlimited())
                .unwrap()
                .0,
            Some(3),
        );
        assert_eq!(
            span(regex.find_accounted(haystack, SearchLimits::unlimited()).unwrap().0),
            Some((0, 5)),
        );

        // An unsealed nullable second run would invalidate the
        // physical-first-run collapse when the optional suffix accepts before
        // that run ends.
        let declined = build("(?-u:[ab]){1,3}(?-u:[CD])?");
        assert_ne!(declined.runtime_implementation_id(), PLAN_ID);
        assert_eq!(
            span(
                declined
                    .find_accounted(b"aaaa", SearchLimits::unlimited())
                    .unwrap()
                    .0,
            ),
            Some((0, 3)),
        );

        // A required run after a nullable bridge can require backtracking a
        // preceding greedy run across that bridge. Such interiors stay with
        // the complete incumbent executor.
        let bridged = build("(?-u:[Aa])(?-u:[Bb]){1,2}(?-u:[Cc])?(?-u:[Bb])");
        assert_ne!(bridged.runtime_implementation_id(), PLAN_ID);
        assert_eq!(
            span(bridged.find_accounted(b"ABB", SearchLimits::unlimited()).unwrap().0),
            Some((0, 3)),
        );

        // Once the complete required prefix has succeeded, overlapping
        // optional runs cannot force a greedy predecessor to backtrack.
        let overlapping = build(
            "(?-u:[ab])(?-u:[CD]){1,2}(?-u:[CD])?(?-u:[CD])?",
        );
        assert_eq!(overlapping.runtime_implementation_id(), PLAN_ID);
        assert_eq!(
            overlapping
                .shortest_match(b"aCCCC", SearchLimits::unlimited())
                .unwrap()
                .0,
            Some(2),
        );
        assert_eq!(
            span(
                overlapping
                    .find_accounted(b"aCCCC", SearchLimits::unlimited())
                    .unwrap()
                    .0
            ),
            Some((0, 5)),
        );
    }

    #[test]
    fn sealed_overlap_corridor_uses_earliest_and_greedy_backtracking_splits() {
        let pattern = "A(?-u:[CD])(?-u:[B]){0,3}(?-u:[B])(?-u:[xy])?";
        let regex = build(pattern);
        assert_eq!(regex.runtime_implementation_id(), PLAN_ID);
        let PortablePlan::BoundedByteClassSequence(plan) = &regex.plan else {
            panic!("one sealed overlap corridor should retain the sequence plan");
        };
        assert_eq!(
            plan.owner().sealed_bridge,
            Some(super::SealedBridge {
                index: 2,
                overlaps_successor: true,
            })
        );

        for (haystack, greedy_end) in [
            (&b"ACB"[..], 3),
            (&b"ACBB"[..], 4),
            (&b"ACBBBB"[..], 6),
            (&b"!ACBBBBy!"[..], 8),
        ] {
            let expected_start = usize::from(haystack.first() == Some(&b'!'));
            assert!(regex
                .is_match_accounted(haystack, SearchLimits::unlimited())
                .unwrap()
                .0);
            assert_eq!(
                regex
                    .shortest_match(haystack, SearchLimits::unlimited())
                    .unwrap()
                    .0,
                Some(expected_start + 3),
            );
            assert_eq!(
                plan.selected_end_window(
                    haystack,
                    SearchWindow::full(haystack),
                    SearchLimits::unlimited(),
                )
                .unwrap()
                .0,
                Some(greedy_end),
            );
            assert_eq!(
                span(regex.find_accounted(haystack, SearchLimits::unlimited()).unwrap().0),
                Some((expected_start, greedy_end)),
            );
            assert_eq!(
                span(
                    regex
                        .find_value(haystack, SearchLimits::unlimited())
                        .unwrap(),
                ),
                Some((expected_start, greedy_end)),
            );
        }

        let partial = build(
            "(?-u:[Q])(?-u:[CD])(?-u:[ab]){0,3}(?-u:[bd])(?-u:[xy])?",
        );
        assert_eq!(partial.runtime_implementation_id(), PLAN_ID);
        assert_eq!(
            span(
                partial
                    .find_accounted(b"QCaaabx", SearchLimits::unlimited())
                    .unwrap()
                    .0,
            ),
            Some((0, 7)),
        );
        assert_eq!(
            partial
                .shortest_match(b"QCaaabx", SearchLimits::unlimited())
                .unwrap()
                .0,
            Some(6),
        );
    }

    #[test]
    fn sealed_second_run_corridor_collapses_variable_first_class_runs() {
        let pattern =
            "(?-u:[AQ]){1,3}(?-u:[B]){0,3}(?-u:[B])(?-u:[xy])?";
        let regex = build(pattern);
        assert_eq!(regex.runtime_implementation_id(), PLAN_ID);
        let PortablePlan::BoundedByteClassSequence(plan) = &regex.plan else {
            panic!("a sealed second-run corridor should retain the sequence plan");
        };
        assert_eq!(
            plan.owner().sealed_bridge,
            Some(super::SealedBridge {
                index: 1,
                overlaps_successor: true,
            })
        );

        for (haystack, expected_start, shortest_end, greedy_end) in [
            (&b"AB"[..], 0, 2, 2),
            (&b"AAABBBB"[..], 0, 4, 7),
            (&b"AAAAAB"[..], 2, 6, 6),
            (&b"!QQBBBBy!"[..], 1, 4, 8),
        ] {
            assert!(regex
                .is_match_accounted(haystack, SearchLimits::unlimited())
                .unwrap()
                .0);
            assert_eq!(
                regex
                    .shortest_match(haystack, SearchLimits::unlimited())
                    .unwrap()
                    .0,
                Some(shortest_end),
            );
            assert_eq!(
                plan.selected_end_window(
                    haystack,
                    SearchWindow::full(haystack),
                    SearchLimits::unlimited(),
                )
                .unwrap()
                .0,
                Some(greedy_end),
            );
            assert_eq!(
                span(regex.find_accounted(haystack, SearchLimits::unlimited()).unwrap().0),
                Some((expected_start, greedy_end)),
            );
            assert_eq!(
                span(
                    regex
                        .find_value(haystack, SearchLimits::unlimited())
                        .unwrap(),
                ),
                Some((expected_start, greedy_end)),
            );
        }
    }

    #[test]
    fn sealed_disjoint_bridge_uses_the_selective_tail_anchor() {
        let pattern =
            "(?-u:[WZ]){1,3}(?-u:[ab]){0,3}(?-u:[d])(?-u:[xy])?";
        let regex = build(pattern);
        assert_eq!(regex.runtime_implementation_id(), PLAN_ID);
        let PortablePlan::BoundedByteClassSequence(plan) = &regex.plan else {
            panic!("a sealed disjoint bridge should retain the sequence plan");
        };
        assert_eq!(
            plan.owner().sealed_bridge,
            Some(super::SealedBridge {
                index: 1,
                overlaps_successor: false,
            })
        );
        assert_eq!(plan.owner().tail_seek, Some(SetSeek::One(b'd')));

        for (haystack, expected_start, shortest_end, greedy_end) in [
            (&b"Wd"[..], 0, 2, 2),
            (&b"WWWaaadxy"[..], 0, 7, 8),
            (&b"ZZbdx"[..], 0, 4, 5),
            (&b"WWWWd"[..], 1, 5, 5),
        ] {
            assert_eq!(
                regex
                    .shortest_match(haystack, SearchLimits::unlimited())
                    .unwrap()
                    .0,
                Some(shortest_end),
            );
            assert_eq!(
                plan.selected_end_window(
                    haystack,
                    SearchWindow::full(haystack),
                    SearchLimits::unlimited(),
                )
                .unwrap()
                .0,
                Some(greedy_end),
            );
            assert_eq!(
                span(regex.find_accounted(haystack, SearchLimits::unlimited()).unwrap().0),
                Some((expected_start, greedy_end)),
            );
            assert_eq!(
                span(
                    regex
                        .find_value(haystack, SearchLimits::unlimited())
                        .unwrap(),
                ),
                Some((expected_start, greedy_end)),
            );
        }

        assert!(!regex
            .is_match_accounted(b"WWaaaad", SearchLimits::unlimited())
            .unwrap()
            .0);
    }

    #[test]
    fn tail_anchor_falls_forward_after_dense_failed_successors() {
        let pattern = r"(?-u:[\x10-\x17]){1,3}(?-u:[\x40-\x5f]){0,3}(?-u:\x7a)";
        let regex = build(pattern);
        let PortablePlan::BoundedByteClassSequence(plan) = &regex.plan else {
            panic!("one disjoint corridor should retain the sequence plan");
        };
        assert_eq!(plan.owner().tail_seek, Some(SetSeek::One(0x7a)));

        let haystack = [
            vec![0x7a_u8; 9],
            vec![0x12_u8, 0x16, 0x45, 0x45, 0x7a],
        ]
        .concat();
        let (matched, receipt) = regex
            .find_accounted(&haystack, SearchLimits::unlimited())
            .expect("the dense-successor fallback should search");
        assert_eq!(span(matched), Some((9, 14)));
        let receipt = accounting(receipt);
        assert!(receipt.candidate_scans > super::TAIL_ANCHOR_PROBE_LIMIT);
        assert!(receipt.actual_work <= receipt.work_upper_bound);
        assert_eq!(
            span(
                regex
                    .find_value(&haystack, SearchLimits::unlimited())
                    .expect("the unmetered dense-successor fallback should search"),
            ),
            Some((9, 14)),
        );
    }

    #[test]
    fn tail_anchor_requires_a_smaller_disjoint_successor() {
        for pattern in [
            "(?-u:[WZ]){1,16}(?-u:[ab]){0,16}(?-u:[de])",
            r"(?-u:[\x10-\x17]){1,3}(?-u:[\x40-\x5f]){0,3}(?-u:[\x5a\x7a])",
            r"\A(?-u:[\x10-\x17]){1,3}(?-u:[\x40-\x5f]){0,3}(?-u:\x7a)",
        ] {
            let regex = build(pattern);
            let PortablePlan::BoundedByteClassSequence(plan) = &regex.plan else {
                panic!("one bounded corridor should retain the sequence plan");
            };
            assert_eq!(plan.owner().tail_seek, None, "{pattern}");
        }
    }

    #[test]
    fn tail_anchor_search_and_construction_limits_are_exact() {
        let pattern = r"(?-u:[\x10-\x17]){1,3}(?-u:[\x40-\x5f]){0,11}(?-u:\x7a)";
        let haystack = [
            vec![0x7a_u8, 0xa0, 0x7a, 0xb0],
            vec![0x12_u8, 0x16, 0x45, 0x45, 0x45, 0x7a],
        ]
        .concat();
        let regex = build(pattern);
        let PortablePlan::BoundedByteClassSequence(plan) = &regex.plan else {
            panic!("one disjoint corridor should retain the sequence plan");
        };
        assert_eq!(plan.owner().tail_seek, Some(SetSeek::One(0x7a)));

        let (matched, measured) = regex
            .find_accounted(&haystack, SearchLimits::unlimited())
            .expect("the tail anchor should search");
        assert_eq!(span(matched), Some((4, 10)));
        let measured = accounting(measured);
        assert!(measured.actual_work > 0);
        assert!(measured.actual_work <= measured.work_upper_bound);

        let exact_search = SearchLimits {
            max_work: measured.actual_work,
            max_scratch_bytes: 0,
        };
        let (matched, exact) = regex
            .find_accounted(&haystack, exact_search)
            .expect("the exact tail-anchor work limit should close");
        assert_eq!(span(matched), Some((4, 10)));
        assert_eq!(accounting(exact).actual_work, measured.actual_work);

        let one_below_search = SearchLimits {
            max_work: measured.actual_work - 1,
            max_scratch_bytes: 0,
        };
        assert!(matches!(
            regex.find_accounted(&haystack, one_below_search),
            Err(FacadeSearchError::BoundedByteClassSequence(
                Error::WorkLimit { limit, .. }
            )) if limit == measured.actual_work - 1
        ));

        let measured_build = regex.build_report().clone();
        let mut exact_limits = BuildLimits::default();
        exact_limits.max_planner_work = measured_build.planner_work;
        exact_limits.max_persistent_bytes = measured_build.charged_persistent_bytes;
        let exact = PortableBuilder::new(pattern)
            .unicode(false)
            .limits(exact_limits)
            .build()
            .expect("the exact tail-anchor build limits should close");
        assert_eq!(exact.runtime_implementation_id(), PLAN_ID);
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
    fn absolute_start_scans_exactly_one_first_run_candidate() {
        let pattern =
            r"\A(?-u:[AQ]){2,3}(?-u:[B]){0,3}(?-u:[B])(?-u:[xy])?";
        let regex = build(pattern);
        assert_eq!(regex.runtime_implementation_id(), PLAN_ID);
        let PortablePlan::BoundedByteClassSequence(plan) = &regex.plan else {
            panic!("an absolute-start corridor should retain the sequence plan");
        };
        assert!(plan.owner().anchored_start);
        assert_eq!(
            plan.owner().sealed_bridge,
            Some(super::SealedBridge {
                index: 1,
                overlaps_successor: true,
            })
        );

        for (haystack, shortest_end, greedy_end) in [
            (&b"AAB"[..], 3, 3),
            (&b"AAABBBB"[..], 4, 7),
            (&b"QQBBBBy"[..], 3, 7),
        ] {
            assert_eq!(
                regex
                    .shortest_match(haystack, SearchLimits::unlimited())
                    .unwrap()
                    .0,
                Some(shortest_end),
            );
            assert_eq!(
                span(regex.find_accounted(haystack, SearchLimits::unlimited()).unwrap().0),
                Some((0, greedy_end)),
            );
        }

        for haystack in [&b"AB"[..], &b"AAAAAB"[..], &b"!AAB"[..]] {
            assert!(!regex
                .is_match_accounted(haystack, SearchLimits::unlimited())
                .unwrap()
                .0);
            assert_eq!(
                regex
                    .find_value(haystack, SearchLimits::unlimited())
                    .unwrap(),
                None,
            );
        }

        let haystack = b"AAABBBB";
        let window = SearchWindow::new(1, haystack.len());
        let (matched, receipt) = regex
            .find_window(haystack, window, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(matched, None);
        let receipt = accounting(receipt);
        assert_eq!(receipt.actual_work, 0);
        assert_eq!(receipt.candidate_scans, 0);
        assert_eq!(receipt.run_scans, 0);
        assert_eq!(
            regex
                .find_window_value(haystack, window, SearchLimits::unlimited())
                .unwrap(),
            None,
        );
    }

    #[test]
    fn noncontiguous_first_run_value_scanner_crosses_block_edges() {
        let regex = build(r"(?-u:[aceg]){1,32}(?-u:[WZ]){1,2}");
        assert_eq!(regex.runtime_implementation_id(), PLAN_ID);
        for run_length in [15_usize, 16, 17, 31, 32] {
            let matched = [vec![b'a'; run_length], vec![b'W']].concat();
            assert!(
                regex
                    .is_match_value(&matched, SearchLimits::unlimited())
                    .unwrap()
            );
            assert_eq!(
                span(
                    regex
                        .find_value(&matched, SearchLimits::unlimited())
                        .unwrap()
                ),
                Some((0, run_length + 1)),
            );

            let absent = vec![b'a'; run_length];
            assert!(
                !regex
                    .is_match_value(&absent, SearchLimits::unlimited())
                    .unwrap()
            );
            assert_eq!(
                regex
                    .find_value(&absent, SearchLimits::unlimited())
                    .unwrap(),
                None,
            );
        }
    }

    #[test]
    fn capped_first_run_retries_the_next_leftmost_candidate() {
        let pattern = "(?-u:[abcd]){1,3}(?-u:[WXYZ]){1,3}";
        let regex = build(pattern);
        assert_eq!(regex.runtime_implementation_id(), PLAN_ID);
        let haystack = b"aaaaW";
        assert_eq!(
            span(regex.find_accounted(haystack, SearchLimits::unlimited()).unwrap().0),
            Some((1, 5)),
        );
    }

    #[test]
    fn facade_labels_every_sequence_operation_and_error() {
        let regex = build("(?-u:[abcd]){1,3}(?-u:[WXYZ]){1,3}");
        let haystack = b"xxaaWZxx";

        let exists = accounting(
            regex
                .is_match_accounted(haystack, SearchLimits::unlimited())
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
        let found = accounting(
            regex
                .find_accounted(haystack, SearchLimits::unlimited())
                .unwrap()
                .1,
        );
        assert_eq!(found.operation, Operation::Span);

        let error = regex
            .is_match_accounted(
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
            .find_accounted(&haystack, SearchLimits::unlimited())
            .unwrap();
        assert!(matched.is_none());
        let measured = accounting(measured);
        assert!(measured.candidate_scans > 1);
        assert!(measured.actual_work <= measured.work_upper_bound);
    }

    #[test]
    fn exact_search_and_construction_limits_close() {
        let pattern = "(?-u:[abcd])(?-u:[WXYZ]){1,3}(?-u:[mn])?";
        let haystack = b"xxaQzaWZmx";
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
    fn anchored_disjoint_bridge_search_and_planner_limits_are_exact() {
        let pattern =
            r"\A(?-u:[\x10-\x17]){1,3}(?-u:[\x40-\x5F]){0,11}(?-u:\x7A)";
        let haystack = [
            vec![0x10_u8, 0x11, 0x12],
            vec![0x40_u8; 5],
            vec![0x7A_u8],
        ]
        .concat();
        let haystack = haystack.as_slice();
        let regex = build(pattern);
        let PortablePlan::BoundedByteClassSequence(plan) = &regex.plan else {
            panic!("one anchored disjoint bridge should retain the sequence plan");
        };
        assert!(plan.owner().anchored_start);
        assert_eq!(
            plan.owner().sealed_bridge,
            Some(super::SealedBridge {
                index: 1,
                overlaps_successor: false,
            })
        );
        let window = SearchWindow::full(haystack);

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
            let exact_work = match operation {
                Operation::Exists => accounting(
                    regex.is_match_window(haystack, window, exact).unwrap().1,
                )
                .actual_work,
                Operation::EarliestEnd => accounting(
                    regex
                        .shortest_match_window(haystack, window, exact)
                        .unwrap()
                        .1,
                )
                .actual_work,
                Operation::SelectedEnd => plan
                    .selected_end_window(haystack, window, exact)
                    .unwrap()
                    .1
                    .actual_work,
                Operation::Span => accounting(
                    regex.find_window(haystack, window, exact).unwrap().1,
                )
                .actual_work,
            };
            assert_eq!(exact_work, measured.actual_work);

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
                Operation::Span => regex
                    .find_window(haystack, window, one_below)
                    .unwrap_err(),
            };
            assert!(matches!(
                error,
                FacadeSearchError::BoundedByteClassSequence(Error::WorkLimit { limit, .. })
                    if limit == measured.actual_work - 1
            ));
        }

        let report = regex.build_report().clone();
        let mut exact_limits = BuildLimits::default();
        exact_limits.max_planner_work = report.planner_work;
        exact_limits.max_persistent_bytes = report.charged_persistent_bytes;
        let exact = PortableBuilder::new(pattern)
            .unicode(false)
            .limits(exact_limits)
            .build()
            .unwrap();
        assert_eq!(exact.build_report().planner_work, report.planner_work);
        assert_eq!(
            exact.build_report().charged_persistent_bytes,
            report.charged_persistent_bytes
        );

        let mut one_below = exact_limits;
        one_below.max_planner_work = report.planner_work - 1;
        assert!(matches!(
            PortableBuilder::new(pattern)
                .unicode(false)
                .limits(one_below)
                .build(),
            Err(BuildError::PlannerWorkLimit { limit, .. })
                if limit == report.planner_work - 1
        ));

        let mut persistent_one_below = exact_limits;
        persistent_one_below.max_persistent_bytes = report.charged_persistent_bytes - 1;
        assert!(matches!(
            PortableBuilder::new(pattern)
                .unicode(false)
                .limits(persistent_one_below)
                .build(),
            Err(BuildError::PersistentBytesLimit { limit, .. })
                if limit == report.charged_persistent_bytes - 1
        ));
    }

    #[test]
    fn invalid_window_is_rejected_before_source_reads() {
        let regex = build("(?-u:[abcd])(?-u:[WXYZ]){1,3}(?-u:[mn])?");
        let zero_work = SearchLimits {
            max_work: 0,
            max_scratch_bytes: 0,
        };
        let (too_short, accounting) = regex.find_accounted(b"a", zero_work).unwrap();
        assert_eq!(too_short, None);
        assert_eq!(accounting.work_or_linear_terms(), 0);
        assert!(matches!(
            regex.find_window(
                b"abc",
                SearchWindow::new(2, 1),
                zero_work,
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
