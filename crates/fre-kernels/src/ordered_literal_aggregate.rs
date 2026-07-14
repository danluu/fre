//! Linear whole-haystack reducers for ordered finite byte languages.
//!
//! A tempting implementation is `aho_corasick::AhoCorasick::find_iter` with
//! `LeftmostFirst`. That is semantically correct, but not a linear aggregate
//! traversal: after a lower-priority short prefix wins, the iterator restarts
//! at its end and can rescan an arbitrarily long decision horizon. For
//! `[a{M}b, a]` on `a{N}`, that takes `Theta(N * M)` DFA transitions.
//!
//! This module instead builds a dense, byte-class-compressed Aho-Corasick DFA
//! over the reversed literals. One right-to-left transition reports the first
//! ordered literal starting at each byte position. A bounded dynamic-program
//! ring then implements the regex iterator's initial/progressed empty-match
//! states. Search takes exactly `N` DFA transitions and `N + 1` reducer steps,
//! plus `O(min(N, longest_literal))` explicitly bounded scratch.

use core::{fmt, mem::size_of};
use std::collections::VecDeque;

const UNSET: u32 = u32::MAX;
const CACHE_FORMAT_VERSION: u32 = 1;
const LENGTH_PREFIX_BYTES: usize = size_of::<u64>();

/// Stable strategy identity shared by both operation-typed plans.
pub const ALGORITHM_ID: &str = "ordered-literal-aggregate.reverse-dense-ac-dp.v1";
/// Stable identity for the count-specialized plan.
pub const COUNT_PLAN_ID: &str = "ordered-literal-aggregate.count.reverse-dense-ac-dp.v1";
/// Stable identity for the span-sum-specialized plan.
pub const SPAN_SUM_PLAN_ID: &str = "ordered-literal-aggregate.span-sum.reverse-dense-ac-dp.v1";

/// Whole-operation reducer selected at construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    /// Count successive non-overlapping matches.
    Count,
    /// Sum the lengths of successive non-overlapping matches.
    SpanSum,
}

/// Alternative-selection rule represented by the cache identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MatchSemantics {
    /// Earliest start, then lowest ordered pattern index at that start.
    LeftmostFirst,
}

/// Successive-match rule represented by the cache identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IterationSemantics {
    /// Successive matches do not overlap.
    NonOverlapping,
}

/// Empty-match and character-boundary profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundarySemantics {
    /// Unicode is off, each byte is one unit, and an empty adjacent to the
    /// previous match end is suppressed before advancing one byte boundary.
    EveryByteUnicodeOffSuppressAdjacentEmpty,
    /// Unicode is off and every admitted alternative is nonempty, so empty
    /// advancement is outside the certified language.
    NonemptyOnlyUnicodeOff,
}

/// Immutable matching profile represented by the cache identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Semantics {
    pub match_semantics: MatchSemantics,
    pub iteration_semantics: IterationSemantics,
    pub boundary_semantics: BoundarySemantics,
}

impl Semantics {
    const RUST_BYTES_UNICODE_OFF: Self = Self {
        match_semantics: MatchSemantics::LeftmostFirst,
        iteration_semantics: IterationSemantics::NonOverlapping,
        boundary_semantics: BoundarySemantics::EveryByteUnicodeOffSuppressAdjacentEmpty,
    };
}

/// Complete, collision-free semantic plan identity borrowed from a plan.
///
/// Construction and operation limits are intentionally excluded. A cache may
/// reuse compiled semantics under different caller limits only after checking
/// the retained [`BuildAccounting`] and fresh operation preflight against the
/// new limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheIdentity<'a> {
    /// Stable implementation/algorithm identifier.
    pub algorithm_id: &'static str,
    /// Stable operation-specific plan identifier.
    pub plan_id: &'static str,
    /// Reducer specialization.
    pub operation: Operation,
    /// Cache serialization format.
    pub cache_format_version: u32,
    /// Dense transition cell representation.
    pub transition_kind: &'static str,
    /// Traversal and reducer representation.
    pub traversal_kind: &'static str,
    /// Exact matching profile.
    pub semantics: Semantics,
    /// Count followed by length-prefixed patterns, preserving all bytes,
    /// order, duplicates and empty alternatives.
    pub encoded_patterns: &'a [u8],
}

/// Limits checked before constructing a reversed dense DFA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildLimits {
    pub max_patterns: usize,
    pub max_pattern_bytes: usize,
    pub max_identity_bytes: usize,
    pub max_trie_states: usize,
    pub max_dfa_cells: usize,
    pub max_build_work: u64,
    pub max_scratch_bytes: usize,
    pub max_persistent_bytes: usize,
    pub max_peak_bytes: usize,
}

impl BuildLimits {
    /// Disable caller-selected caps while retaining checked arithmetic,
    /// `u32` representation limits and fallible reservations.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_patterns: usize::MAX,
            max_pattern_bytes: usize::MAX,
            max_identity_bytes: usize::MAX,
            max_trie_states: usize::MAX,
            max_dfa_cells: usize::MAX,
            max_build_work: u64::MAX,
            max_scratch_bytes: usize::MAX,
            max_persistent_bytes: usize::MAX,
            max_peak_bytes: usize::MAX,
        }
    }
}

impl Default for BuildLimits {
    fn default() -> Self {
        Self {
            max_patterns: 4_096,
            max_pattern_bytes: 4 * 1024 * 1024,
            max_identity_bytes: 8 * 1024 * 1024,
            max_trie_states: 1_048_576,
            max_dfa_cells: 32 * 1024 * 1024,
            max_build_work: 64 * 1024 * 1024,
            max_scratch_bytes: 32 * 1024 * 1024,
            max_persistent_bytes: 192 * 1024 * 1024,
            max_peak_bytes: 224 * 1024 * 1024,
        }
    }
}

/// Auditable preflight and observed construction accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildAccounting {
    pub patterns: usize,
    pub pattern_bytes: usize,
    pub identity_bytes: usize,
    pub identity_capacity_bytes: usize,
    pub alphabet_classes: usize,
    pub trie_states_upper_bound: usize,
    pub trie_states_actual: usize,
    pub dfa_cells_upper_bound: usize,
    pub dfa_cells_actual: usize,
    pub build_work_upper_bound: u64,
    pub max_pattern_bytes: usize,
    pub min_nonempty_pattern_bytes: Option<usize>,
    pub has_empty_pattern: bool,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

/// Limits checked before allocating reducer scratch or traversing input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceLimits {
    pub max_transitions: usize,
    pub max_match_events: usize,
    pub max_count: u64,
    pub max_span_sum: u64,
    pub max_reducer_steps: usize,
    /// Maximum DP ring entries initialized before the reverse traversal.
    pub max_ring_initializations: usize,
    /// Maximum transitions plus reducer positions plus ring initialization.
    pub max_total_work: usize,
    pub max_scratch_bytes: usize,
    pub max_peak_bytes: usize,
}

impl ReduceLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_transitions: usize::MAX,
            max_match_events: usize::MAX,
            max_count: u64::MAX,
            max_span_sum: u64::MAX,
            max_reducer_steps: usize::MAX,
            max_ring_initializations: usize::MAX,
            max_total_work: usize::MAX,
            max_scratch_bytes: usize::MAX,
            max_peak_bytes: usize::MAX,
        }
    }
}

impl Default for ReduceLimits {
    fn default() -> Self {
        Self {
            max_transitions: 128 * 1024 * 1024,
            max_match_events: 128 * 1024 * 1024,
            max_count: 128 * 1024 * 1024,
            max_span_sum: 128 * 1024 * 1024,
            max_reducer_steps: 128 * 1024 * 1024 + 1,
            max_ring_initializations: 64 * 1024 * 1024,
            max_total_work: 320 * 1024 * 1024,
            max_scratch_bytes: 64 * 1024 * 1024,
            max_peak_bytes: 256 * 1024 * 1024,
        }
    }
}

/// Bounds accepted before a complete reducer starts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceUpperBounds {
    pub haystack_bytes: usize,
    pub transitions: usize,
    pub match_events: usize,
    pub count: u64,
    pub span_sum: u64,
    pub reducer_steps: usize,
    pub ring_entries: usize,
    pub ring_initializations: usize,
    pub total_work: usize,
    /// Logical before reservation, observed capacity after reservation.
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

/// Counters published only after a complete successful reduction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceActualCounters {
    pub transitions: usize,
    pub reducer_steps: usize,
    pub ring_initializations: usize,
    pub total_work: usize,
    pub match_events: u64,
    pub count: Option<u64>,
    pub span_sum: Option<u64>,
    pub scratch_bytes: usize,
    pub peak_bytes: usize,
}

/// Complete operation certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceAccounting<'a> {
    pub identity: CacheIdentity<'a>,
    pub upper_bounds: ReduceUpperBounds,
    pub actual: ReduceActualCounters,
}

/// Complete count result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountResult<'a> {
    pub count: u64,
    pub accounting: ReduceAccounting<'a>,
}

/// Complete checked span-sum result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpanSumResult<'a> {
    pub span_sum: u64,
    pub accounting: ReduceAccounting<'a>,
}

/// Typed construction refusal. No plan is published on error.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BuildError {
    EmptyPatternSet,
    PatternLimit {
        needed: usize,
        limit: usize,
    },
    PatternBytesLimit {
        needed: usize,
        limit: usize,
    },
    IdentityBytesLimit {
        needed: usize,
        limit: usize,
    },
    TrieStatesLimit {
        needed: usize,
        limit: usize,
    },
    DfaCellsLimit {
        needed: usize,
        limit: usize,
    },
    WorkLimit {
        needed: u64,
        limit: u64,
    },
    ScratchLimit {
        needed: usize,
        limit: usize,
    },
    PersistentLimit {
        needed: usize,
        limit: usize,
    },
    PeakLimit {
        needed: usize,
        limit: usize,
    },
    RepresentationLimit {
        structure: &'static str,
        needed: usize,
    },
    AllocationFailed {
        structure: &'static str,
        additional: usize,
    },
    /// A private construction invariant failed before an uncharged growth.
    InternalInvariant {
        detail: &'static str,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPatternSet => write!(f, "ordered literal plans need at least one pattern"),
            Self::PatternLimit { needed, limit } => {
                write!(f, "need {needed} patterns, limit {limit}")
            }
            Self::PatternBytesLimit { needed, limit } => {
                write!(f, "need {needed} pattern bytes, limit {limit}")
            }
            Self::IdentityBytesLimit { needed, limit } => {
                write!(f, "need {needed} identity bytes, limit {limit}")
            }
            Self::TrieStatesLimit { needed, limit } => {
                write!(f, "need {needed} trie states, limit {limit}")
            }
            Self::DfaCellsLimit { needed, limit } => {
                write!(f, "need {needed} DFA cells, limit {limit}")
            }
            Self::WorkLimit { needed, limit } => {
                write!(f, "need {needed} build work, limit {limit}")
            }
            Self::ScratchLimit { needed, limit } => {
                write!(f, "need {needed} build scratch bytes, limit {limit}")
            }
            Self::PersistentLimit { needed, limit } => {
                write!(f, "need {needed} persistent bytes, limit {limit}")
            }
            Self::PeakLimit { needed, limit } => {
                write!(f, "need {needed} build peak bytes, limit {limit}")
            }
            Self::RepresentationLimit { structure, needed } => write!(
                f,
                "{structure} needs {needed} entries, exceeding u32 representation"
            ),
            Self::AllocationFailed {
                structure,
                additional,
            } => write!(f, "failed to reserve {additional} entries for {structure}"),
            Self::ArithmeticOverflow { computation } => {
                write!(f, "arithmetic overflow computing {computation}")
            }
            Self::InternalInvariant { detail } => {
                write!(f, "internal construction invariant failed: {detail}")
            }
        }
    }
}

impl std::error::Error for BuildError {}

/// Typed complete-operation refusal. No partial reducer value is returned.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ReduceError {
    TransitionLimit {
        needed: usize,
        limit: usize,
    },
    MatchEventsLimit {
        needed: usize,
        limit: usize,
    },
    CountLimit {
        needed: u64,
        limit: u64,
    },
    SpanSumLimit {
        needed: u64,
        limit: u64,
    },
    ReducerStepsLimit {
        needed: usize,
        limit: usize,
    },
    RingInitializationLimit {
        needed: usize,
        limit: usize,
    },
    TotalWorkLimit {
        needed: usize,
        limit: usize,
    },
    ScratchLimit {
        needed: usize,
        limit: usize,
    },
    PeakLimit {
        needed: usize,
        limit: usize,
    },
    AllocationFailed {
        structure: &'static str,
        additional: usize,
    },
    /// A private DFA/ring invariant failed before an aliased lookup.
    InternalInvariant {
        detail: &'static str,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
}

impl fmt::Display for ReduceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TransitionLimit { needed, limit } => {
                write!(f, "need {needed} transitions, limit {limit}")
            }
            Self::MatchEventsLimit { needed, limit } => {
                write!(f, "may emit {needed} matches, limit {limit}")
            }
            Self::CountLimit { needed, limit } => write!(f, "count may be {needed}, limit {limit}"),
            Self::SpanSumLimit { needed, limit } => {
                write!(f, "span sum may be {needed}, limit {limit}")
            }
            Self::ReducerStepsLimit { needed, limit } => {
                write!(f, "need {needed} reducer steps, limit {limit}")
            }
            Self::RingInitializationLimit { needed, limit } => {
                write!(f, "need {needed} ring initializations, limit {limit}")
            }
            Self::TotalWorkLimit { needed, limit } => {
                write!(f, "need {needed} total work units, limit {limit}")
            }
            Self::ScratchLimit { needed, limit } => {
                write!(f, "need {needed} reducer scratch bytes, limit {limit}")
            }
            Self::PeakLimit { needed, limit } => {
                write!(f, "need {needed} reducer peak bytes, limit {limit}")
            }
            Self::AllocationFailed {
                structure,
                additional,
            } => write!(f, "failed to reserve {additional} entries for {structure}"),
            Self::ArithmeticOverflow { computation } => {
                write!(f, "arithmetic overflow computing {computation}")
            }
            Self::InternalInvariant { detail } => {
                write!(f, "internal reducer invariant failed: {detail}")
            }
        }
    }
}

impl std::error::Error for ReduceError {}

#[derive(Debug)]
struct DenseReverseDfa {
    byte_classes: [u16; 256],
    alphabet_classes: usize,
    transitions: Vec<u32>,
    output_pattern: Vec<u32>,
    output_length: Vec<u32>,
}

impl DenseReverseDfa {
    #[inline]
    fn next(&self, state: u32, byte: u8) -> u32 {
        let state = usize::try_from(state).expect("u32 state always fits usize");
        let class = usize::from(self.byte_classes[usize::from(byte)]);
        let cell = state
            .checked_mul(self.alphabet_classes)
            .and_then(|base| base.checked_add(class))
            .expect("constructed DFA state and class address a retained cell");
        self.transitions[cell]
    }

    #[inline]
    fn output(&self, state: u32) -> Option<(u32, usize)> {
        let state = usize::try_from(state).expect("u32 state always fits usize");
        let pattern = self.output_pattern[state];
        (pattern != UNSET).then(|| {
            let length = usize::try_from(self.output_length[state])
                .expect("u32 pattern length always fits usize");
            (pattern, length)
        })
    }
}

#[derive(Debug)]
struct PlanCore {
    dfa: DenseReverseDfa,
    encoded_patterns: Vec<u8>,
    build: BuildAccounting,
}

/// Deliberately non-`Clone`, count-specialized immutable plan.
#[derive(Debug)]
pub struct OrderedLiteralCountPlan {
    core: PlanCore,
}

/// Deliberately non-`Clone`, span-sum-specialized immutable plan.
#[derive(Debug)]
pub struct OrderedLiteralSpanSumPlan {
    core: PlanCore,
}

impl OrderedLiteralCountPlan {
    /// Build an ordered finite-byte-language count plan.
    pub fn build<P: AsRef<[u8]>>(patterns: &[P], limits: BuildLimits) -> Result<Self, BuildError> {
        PlanCore::build(patterns, limits, size_of::<Self>()).map(|core| Self { core })
    }

    #[must_use]
    pub const fn build_accounting(&self) -> BuildAccounting {
        self.core.build
    }

    #[must_use]
    pub fn cache_identity(&self) -> CacheIdentity<'_> {
        self.core.identity(Operation::Count)
    }

    /// Count the complete Rust-bytes, Unicode-off `find_iter` sequence.
    pub fn count<'a>(
        &'a self,
        haystack: &[u8],
        limits: ReduceLimits,
    ) -> Result<CountResult<'a>, ReduceError> {
        let mut upper = self
            .core
            .preflight_reduce::<CountState>(haystack.len(), false, limits)?;
        let mut ring = reserve_ring::<CountState>(upper.ring_entries, "count DP ring")?;
        self.core.finish_scratch_preflight(
            &mut upper,
            ring.capacity(),
            size_of::<CountState>(),
            limits,
        )?;
        ring.resize(upper.ring_entries, CountState::default());
        let actual = self.core.execute_count(haystack, &mut ring, upper)?;
        Ok(CountResult {
            count: actual.match_events,
            accounting: ReduceAccounting {
                identity: self.cache_identity(),
                upper_bounds: upper,
                actual,
            },
        })
    }
}

impl OrderedLiteralSpanSumPlan {
    /// Build an ordered finite-byte-language span-sum plan.
    pub fn build<P: AsRef<[u8]>>(patterns: &[P], limits: BuildLimits) -> Result<Self, BuildError> {
        PlanCore::build(patterns, limits, size_of::<Self>()).map(|core| Self { core })
    }

    #[must_use]
    pub const fn build_accounting(&self) -> BuildAccounting {
        self.core.build
    }

    #[must_use]
    pub fn cache_identity(&self) -> CacheIdentity<'_> {
        self.core.identity(Operation::SpanSum)
    }

    /// Sum all selected non-overlapping match spans with checked arithmetic.
    pub fn span_sum<'a>(
        &'a self,
        haystack: &[u8],
        limits: ReduceLimits,
    ) -> Result<SpanSumResult<'a>, ReduceError> {
        let mut upper = self
            .core
            .preflight_reduce::<SpanState>(haystack.len(), true, limits)?;
        let mut ring = reserve_ring::<SpanState>(upper.ring_entries, "span-sum DP ring")?;
        self.core.finish_scratch_preflight(
            &mut upper,
            ring.capacity(),
            size_of::<SpanState>(),
            limits,
        )?;
        ring.resize(upper.ring_entries, SpanState::default());
        let actual = self.core.execute_span(haystack, &mut ring, upper)?;
        let span_sum = actual
            .span_sum
            .expect("span plan always publishes a span sum");
        Ok(SpanSumResult {
            span_sum,
            accounting: ReduceAccounting {
                identity: self.cache_identity(),
                upper_bounds: upper,
                actual,
            },
        })
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct CountState {
    initial: u64,
    progressed: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct SpanState {
    initial_count: u64,
    progressed_count: u64,
    span_sum: u64,
}

impl PlanCore {
    fn identity(&self, operation: Operation) -> CacheIdentity<'_> {
        let plan_id = match operation {
            Operation::Count => COUNT_PLAN_ID,
            Operation::SpanSum => SPAN_SUM_PLAN_ID,
        };
        CacheIdentity {
            algorithm_id: ALGORITHM_ID,
            plan_id,
            operation,
            cache_format_version: CACHE_FORMAT_VERSION,
            transition_kind: "byte-class-compressed dense u32 reverse AC DFA",
            traversal_kind: "single reverse DFA pass plus bounded initial/progressed DP ring",
            semantics: Semantics::RUST_BYTES_UNICODE_OFF,
            encoded_patterns: &self.encoded_patterns,
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "construction keeps allocation/capacity checks adjacent to every owned buffer"
    )]
    fn build<P: AsRef<[u8]>>(
        patterns: &[P],
        limits: BuildLimits,
        inline_bytes: usize,
    ) -> Result<Self, BuildError> {
        let preflight = preflight_build(patterns, limits, inline_bytes)?;
        let mut encoded_patterns = reserve_vec::<u8>(preflight.identity_bytes, "cache identity")?;
        encode_patterns(patterns, preflight.identity_bytes, &mut encoded_patterns)?;

        let mut transitions =
            reserve_vec::<u32>(preflight.dfa_cells_upper_bound, "DFA transitions")?;
        let mut output_pattern =
            reserve_vec::<u32>(preflight.trie_states_upper_bound, "DFA output patterns")?;
        let mut output_length =
            reserve_vec::<u32>(preflight.trie_states_upper_bound, "DFA output lengths")?;
        let mut terminal = reserve_vec::<u32>(preflight.trie_states_upper_bound, "trie terminals")?;
        let mut failure = reserve_vec::<u32>(preflight.trie_states_upper_bound, "failure links")?;
        let mut queue = VecDeque::<u32>::new();
        queue
            .try_reserve_exact(preflight.trie_states_upper_bound)
            .map_err(|_| BuildError::AllocationFailed {
                structure: "failure-link queue",
                additional: preflight.trie_states_upper_bound,
            })?;
        let mut pattern_lengths = reserve_vec::<u32>(patterns.len(), "pattern lengths")?;

        let persistent_bytes = inline_bytes
            .checked_add(capacity_bytes(&transitions)?)
            .and_then(|bytes| bytes.checked_add(capacity_bytes(&output_pattern).ok()?))
            .and_then(|bytes| bytes.checked_add(capacity_bytes(&output_length).ok()?))
            .and_then(|bytes| bytes.checked_add(encoded_patterns.capacity()))
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "observed persistent capacity",
            })?;
        let queue_bytes = queue.capacity().checked_mul(size_of::<u32>()).ok_or(
            BuildError::ArithmeticOverflow {
                computation: "failure queue capacity bytes",
            },
        )?;
        let scratch_bytes = capacity_bytes(&terminal)?
            .checked_add(capacity_bytes(&failure)?)
            .and_then(|bytes| bytes.checked_add(queue_bytes))
            .and_then(|bytes| bytes.checked_add(capacity_bytes(&pattern_lengths).ok()?))
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "observed build scratch",
            })?;
        let peak_bytes =
            persistent_bytes
                .checked_add(scratch_bytes)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "observed build peak",
                })?;
        check_observed_build_limits(persistent_bytes, scratch_bytes, peak_bytes, limits)?;

        add_state(
            preflight.alphabet_classes,
            &mut transitions,
            &mut output_pattern,
            &mut output_length,
            &mut terminal,
            &mut failure,
        )?;
        for (pattern_index, pattern) in patterns.iter().enumerate() {
            let bytes = pattern.as_ref();
            let pattern_id =
                u32::try_from(pattern_index).map_err(|_| BuildError::RepresentationLimit {
                    structure: "pattern identifiers",
                    needed: patterns.len(),
                })?;
            let pattern_len =
                u32::try_from(bytes.len()).map_err(|_| BuildError::RepresentationLimit {
                    structure: "pattern length",
                    needed: bytes.len(),
                })?;
            checked_push(&mut pattern_lengths, pattern_len, "pattern length capacity")?;
            let mut state = 0_usize;
            for &byte in bytes.iter().rev() {
                let class = usize::from(preflight.byte_classes[usize::from(byte)]);
                let cell = state
                    .checked_mul(preflight.alphabet_classes)
                    .and_then(|base| base.checked_add(class))
                    .ok_or(BuildError::ArithmeticOverflow {
                        computation: "trie transition cell",
                    })?;
                let next = transitions[cell];
                if next == UNSET {
                    let new_state = output_pattern.len();
                    let new_state_u32 =
                        u32::try_from(new_state).map_err(|_| BuildError::RepresentationLimit {
                            structure: "trie states",
                            needed: new_state,
                        })?;
                    add_state(
                        preflight.alphabet_classes,
                        &mut transitions,
                        &mut output_pattern,
                        &mut output_length,
                        &mut terminal,
                        &mut failure,
                    )?;
                    transitions[cell] = new_state_u32;
                    state = new_state;
                } else {
                    state = usize::try_from(next).expect("u32 state always fits usize");
                }
            }
            terminal[state] = terminal[state].min(pattern_id);
        }

        output_pattern[0] = terminal[0];
        if output_pattern[0] != UNSET {
            output_length[0] = pattern_lengths
                [usize::try_from(output_pattern[0]).expect("u32 pattern ID fits usize")];
        }
        for root_cell in transitions.iter_mut().take(preflight.alphabet_classes) {
            let next = *root_cell;
            if next == UNSET {
                *root_cell = 0;
            } else if next != 0 {
                let next_index = usize::try_from(next).expect("u32 state always fits usize");
                failure[next_index] = 0;
                checked_queue_push(&mut queue, next)?;
            }
        }

        while let Some(state_u32) = queue.pop_front() {
            let state = usize::try_from(state_u32).expect("u32 state always fits usize");
            let fail = usize::try_from(failure[state]).expect("u32 state always fits usize");
            let inherited = output_pattern[fail];
            output_pattern[state] = terminal[state].min(inherited);
            if output_pattern[state] != UNSET {
                let pattern =
                    usize::try_from(output_pattern[state]).expect("u32 pattern ID fits usize");
                output_length[state] = pattern_lengths[pattern];
            }
            for class in 0..preflight.alphabet_classes {
                let cell = state
                    .checked_mul(preflight.alphabet_classes)
                    .and_then(|base| base.checked_add(class))
                    .ok_or(BuildError::ArithmeticOverflow {
                        computation: "failure transition cell",
                    })?;
                let next = transitions[cell];
                let fail_cell = fail
                    .checked_mul(preflight.alphabet_classes)
                    .and_then(|base| base.checked_add(class))
                    .ok_or(BuildError::ArithmeticOverflow {
                        computation: "failure target cell",
                    })?;
                if next == UNSET {
                    transitions[cell] = transitions[fail_cell];
                } else {
                    let next_index = usize::try_from(next).expect("u32 state always fits usize");
                    failure[next_index] = transitions[fail_cell];
                    checked_queue_push(&mut queue, next)?;
                }
            }
        }

        let trie_states_actual = output_pattern.len();
        let dfa_cells_actual = trie_states_actual
            .checked_mul(preflight.alphabet_classes)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "actual DFA cells",
            })?;
        debug_assert_eq!(transitions.len(), dfa_cells_actual);
        let build = BuildAccounting {
            patterns: patterns.len(),
            pattern_bytes: preflight.pattern_bytes,
            identity_bytes: preflight.identity_bytes,
            identity_capacity_bytes: encoded_patterns.capacity(),
            alphabet_classes: preflight.alphabet_classes,
            trie_states_upper_bound: preflight.trie_states_upper_bound,
            trie_states_actual,
            dfa_cells_upper_bound: preflight.dfa_cells_upper_bound,
            dfa_cells_actual,
            build_work_upper_bound: preflight.build_work_upper_bound,
            max_pattern_bytes: preflight.max_pattern_bytes,
            min_nonempty_pattern_bytes: preflight.min_nonempty_pattern_bytes,
            has_empty_pattern: preflight.has_empty_pattern,
            scratch_bytes,
            persistent_bytes,
            peak_bytes,
        };
        Ok(Self {
            dfa: DenseReverseDfa {
                byte_classes: preflight.byte_classes,
                alphabet_classes: preflight.alphabet_classes,
                transitions,
                output_pattern,
                output_length,
            },
            encoded_patterns,
            build,
        })
    }

    fn preflight_reduce<T>(
        &self,
        haystack_len: usize,
        check_span: bool,
        limits: ReduceLimits,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        let transitions = haystack_len;
        let reducer_steps = haystack_len
            .checked_add(1)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "reverse reducer positions",
            })?;
        let match_events = if self.build.has_empty_pattern {
            reducer_steps
        } else {
            let minimum =
                self.build
                    .min_nonempty_pattern_bytes
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "missing nonempty minimum",
                    })?;
            haystack_len
                .checked_div(minimum)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "nonempty event quotient",
                })?
        };
        let count = u64::try_from(match_events).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "match-event upper bound as u64",
        })?;
        let span_sum =
            u64::try_from(haystack_len).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "span upper bound as u64",
            })?;
        let ring_entries = self
            .build
            .max_pattern_bytes
            .min(haystack_len)
            .checked_add(1)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "DP ring entries",
            })?;
        let ring_initializations = ring_entries;
        let total_work = transitions
            .checked_add(reducer_steps)
            .and_then(|work| work.checked_add(ring_initializations))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "total reducer work",
            })?;
        let scratch_bytes =
            ring_entries
                .checked_mul(size_of::<T>())
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "logical DP scratch",
                })?;
        let peak_bytes = self
            .build
            .persistent_bytes
            .checked_add(scratch_bytes)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "logical reducer peak",
            })?;
        let upper = ReduceUpperBounds {
            haystack_bytes: haystack_len,
            transitions,
            match_events,
            count,
            span_sum,
            reducer_steps,
            ring_entries,
            ring_initializations,
            total_work,
            scratch_bytes,
            persistent_bytes: self.build.persistent_bytes,
            peak_bytes,
        };
        check_reduce_limits(upper, check_span, limits)?;
        Ok(upper)
    }

    fn finish_scratch_preflight(
        &self,
        upper: &mut ReduceUpperBounds,
        capacity: usize,
        element_size: usize,
        limits: ReduceLimits,
    ) -> Result<(), ReduceError> {
        upper.scratch_bytes =
            capacity
                .checked_mul(element_size)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "observed DP scratch",
                })?;
        upper.peak_bytes = self
            .build
            .persistent_bytes
            .checked_add(upper.scratch_bytes)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "observed reducer peak",
            })?;
        if upper.scratch_bytes > limits.max_scratch_bytes {
            return Err(ReduceError::ScratchLimit {
                needed: upper.scratch_bytes,
                limit: limits.max_scratch_bytes,
            });
        }
        if upper.peak_bytes > limits.max_peak_bytes {
            return Err(ReduceError::PeakLimit {
                needed: upper.peak_bytes,
                limit: limits.max_peak_bytes,
            });
        }
        Ok(())
    }

    fn execute_count(
        &self,
        haystack: &[u8],
        ring: &mut [CountState],
        upper: ReduceUpperBounds,
    ) -> Result<ReduceActualCounters, ReduceError> {
        validate_ring(ring.len(), upper.ring_entries)?;
        let mut state = 0_u32;
        let mut next_initial = 0_u64;
        for position in (0..=haystack.len()).rev() {
            if position < haystack.len() {
                state = self.dfa.next(state, haystack[position]);
            }
            let value = match self.dfa.output(state) {
                None => CountState {
                    initial: next_initial,
                    progressed: next_initial,
                },
                Some((_, 0)) => CountState {
                    initial: next_initial.checked_add(1).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "actual empty count",
                        },
                    )?,
                    progressed: next_initial,
                },
                Some((_, length)) => {
                    let target = checked_dp_target(
                        position,
                        length,
                        haystack.len(),
                        self.build.max_pattern_bytes,
                        ring.len(),
                    )?;
                    let slot =
                        target
                            .checked_rem(ring.len())
                            .ok_or(ReduceError::ArithmeticOverflow {
                                computation: "count DP target ring slot",
                            })?;
                    let future = ring[slot].progressed;
                    let count = future
                        .checked_add(1)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "actual nonempty count",
                        })?;
                    CountState {
                        initial: count,
                        progressed: count,
                    }
                }
            };
            let slot = position
                .checked_rem(ring.len())
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "count DP current ring slot",
                })?;
            ring[slot] = value;
            next_initial = value.initial;
        }
        debug_assert!(next_initial <= upper.count);
        Ok(ReduceActualCounters {
            transitions: haystack.len(),
            reducer_steps: upper.reducer_steps,
            ring_initializations: ring.len(),
            total_work: upper.total_work,
            match_events: next_initial,
            count: Some(next_initial),
            span_sum: None,
            scratch_bytes: upper.scratch_bytes,
            peak_bytes: upper.peak_bytes,
        })
    }

    fn execute_span(
        &self,
        haystack: &[u8],
        ring: &mut [SpanState],
        upper: ReduceUpperBounds,
    ) -> Result<ReduceActualCounters, ReduceError> {
        validate_ring(ring.len(), upper.ring_entries)?;
        let mut state = 0_u32;
        let mut next_initial = SpanState::default();
        for position in (0..=haystack.len()).rev() {
            if position < haystack.len() {
                state = self.dfa.next(state, haystack[position]);
            }
            let value = match self.dfa.output(state) {
                None => SpanState {
                    initial_count: next_initial.initial_count,
                    progressed_count: next_initial.initial_count,
                    span_sum: next_initial.span_sum,
                },
                Some((_, 0)) => SpanState {
                    initial_count: next_initial.initial_count.checked_add(1).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "actual span empty count",
                        },
                    )?,
                    progressed_count: next_initial.initial_count,
                    span_sum: next_initial.span_sum,
                },
                Some((_, length)) => {
                    let target = checked_dp_target(
                        position,
                        length,
                        haystack.len(),
                        self.build.max_pattern_bytes,
                        ring.len(),
                    )?;
                    let slot =
                        target
                            .checked_rem(ring.len())
                            .ok_or(ReduceError::ArithmeticOverflow {
                                computation: "span DP target ring slot",
                            })?;
                    let future = ring[slot];
                    let initial_count = future.progressed_count.checked_add(1).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "actual span match count",
                        },
                    )?;
                    let length =
                        u64::try_from(length).map_err(|_| ReduceError::ArithmeticOverflow {
                            computation: "actual span length as u64",
                        })?;
                    let span_sum = future.span_sum.checked_add(length).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "actual span sum",
                        },
                    )?;
                    SpanState {
                        initial_count,
                        progressed_count: initial_count,
                        span_sum,
                    }
                }
            };
            let slot = position
                .checked_rem(ring.len())
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "span DP current ring slot",
                })?;
            ring[slot] = value;
            next_initial = value;
        }
        debug_assert!(next_initial.initial_count <= upper.count);
        debug_assert!(next_initial.span_sum <= upper.span_sum);
        Ok(ReduceActualCounters {
            transitions: haystack.len(),
            reducer_steps: upper.reducer_steps,
            ring_initializations: ring.len(),
            total_work: upper.total_work,
            match_events: next_initial.initial_count,
            count: Some(next_initial.initial_count),
            span_sum: Some(next_initial.span_sum),
            scratch_bytes: upper.scratch_bytes,
            peak_bytes: upper.peak_bytes,
        })
    }
}

#[derive(Clone, Copy)]
struct BuildPreflight {
    byte_classes: [u16; 256],
    alphabet_classes: usize,
    pattern_bytes: usize,
    identity_bytes: usize,
    trie_states_upper_bound: usize,
    dfa_cells_upper_bound: usize,
    build_work_upper_bound: u64,
    max_pattern_bytes: usize,
    min_nonempty_pattern_bytes: Option<usize>,
    has_empty_pattern: bool,
}

#[allow(
    clippy::too_many_lines,
    reason = "one ordered preflight makes every construction allocation derivable before reserve"
)]
fn preflight_build<P: AsRef<[u8]>>(
    patterns: &[P],
    limits: BuildLimits,
    inline_bytes: usize,
) -> Result<BuildPreflight, BuildError> {
    if patterns.is_empty() {
        return Err(BuildError::EmptyPatternSet);
    }
    if patterns.len() > limits.max_patterns {
        return Err(BuildError::PatternLimit {
            needed: patterns.len(),
            limit: limits.max_patterns,
        });
    }
    if patterns.len() > usize::try_from(u32::MAX).unwrap_or(usize::MAX) {
        return Err(BuildError::RepresentationLimit {
            structure: "pattern identifiers",
            needed: patterns.len(),
        });
    }
    let mut pattern_bytes = 0_usize;
    let mut max_pattern_bytes = 0_usize;
    let mut min_nonempty_pattern_bytes = None;
    let mut has_empty_pattern = false;
    let mut used = [false; 256];
    for pattern in patterns {
        let bytes = pattern.as_ref();
        pattern_bytes =
            pattern_bytes
                .checked_add(bytes.len())
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "pattern bytes",
                })?;
        max_pattern_bytes = max_pattern_bytes.max(bytes.len());
        if bytes.is_empty() {
            has_empty_pattern = true;
        } else {
            min_nonempty_pattern_bytes = Some(
                min_nonempty_pattern_bytes.map_or(bytes.len(), |old: usize| old.min(bytes.len())),
            );
        }
        for &byte in bytes {
            used[usize::from(byte)] = true;
        }
    }
    if pattern_bytes > limits.max_pattern_bytes {
        return Err(BuildError::PatternBytesLimit {
            needed: pattern_bytes,
            limit: limits.max_pattern_bytes,
        });
    }
    if max_pattern_bytes > usize::try_from(u32::MAX).unwrap_or(usize::MAX) {
        return Err(BuildError::RepresentationLimit {
            structure: "pattern length",
            needed: max_pattern_bytes,
        });
    }
    let identity_bytes = LENGTH_PREFIX_BYTES
        .checked_add(patterns.len().checked_mul(LENGTH_PREFIX_BYTES).ok_or(
            BuildError::ArithmeticOverflow {
                computation: "identity length prefixes",
            },
        )?)
        .and_then(|bytes| bytes.checked_add(pattern_bytes))
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "identity bytes",
        })?;
    if identity_bytes > limits.max_identity_bytes {
        return Err(BuildError::IdentityBytesLimit {
            needed: identity_bytes,
            limit: limits.max_identity_bytes,
        });
    }
    let trie_states_upper_bound =
        pattern_bytes
            .checked_add(1)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "trie-state upper bound",
            })?;
    if trie_states_upper_bound > limits.max_trie_states {
        return Err(BuildError::TrieStatesLimit {
            needed: trie_states_upper_bound,
            limit: limits.max_trie_states,
        });
    }
    if trie_states_upper_bound > usize::try_from(u32::MAX).unwrap_or(usize::MAX) {
        return Err(BuildError::RepresentationLimit {
            structure: "trie states",
            needed: trie_states_upper_bound,
        });
    }
    let mut byte_classes = [0_u16; 256];
    let used_count = used.iter().filter(|&&present| present).count();
    let alphabet_classes = if used_count == 256 {
        256
    } else {
        used_count
            .checked_add(1)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "alphabet classes",
            })?
    };
    let mut next_class = 0_u16;
    for (byte, &present) in used.iter().enumerate() {
        if present {
            byte_classes[byte] = next_class;
            next_class = next_class
                .checked_add(1)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "byte classes",
                })?;
        }
    }
    if used_count < 256 {
        for (byte, &present) in used.iter().enumerate() {
            if !present {
                byte_classes[byte] = next_class;
            }
        }
    }
    let dfa_cells_upper_bound = trie_states_upper_bound
        .checked_mul(alphabet_classes)
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "DFA-cell upper bound",
        })?;
    if dfa_cells_upper_bound > limits.max_dfa_cells {
        return Err(BuildError::DfaCellsLimit {
            needed: dfa_cells_upper_bound,
            limit: limits.max_dfa_cells,
        });
    }
    // One abstract unit dominates one byte/class/state/cell visit or one
    // scalar vector/queue/output write. Factors cover: three fixed 256-byte
    // class passes; stats, identity and reversed insertion byte visits; trie
    // row initialization plus failure-table processing; and all per-state and
    // per-pattern pushes/output propagation. Allocation byte capacity is
    // charged separately below.
    let fixed_class_work = 256_usize
        .checked_mul(3)
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "fixed byte-class work",
        })?;
    let work_usize = dfa_cells_upper_bound
        .checked_mul(3)
        .and_then(|work| work.checked_add(pattern_bytes.checked_mul(4)?))
        .and_then(|work| work.checked_add(trie_states_upper_bound.checked_mul(8)?))
        .and_then(|work| work.checked_add(patterns.len().checked_mul(4)?))
        .and_then(|work| work.checked_add(identity_bytes))
        .and_then(|work| work.checked_add(fixed_class_work))
        .and_then(|work| work.checked_add(32))
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "build-work upper bound",
        })?;
    let build_work_upper_bound =
        u64::try_from(work_usize).map_err(|_| BuildError::ArithmeticOverflow {
            computation: "build work as u64",
        })?;
    if build_work_upper_bound > limits.max_build_work {
        return Err(BuildError::WorkLimit {
            needed: build_work_upper_bound,
            limit: limits.max_build_work,
        });
    }
    let persistent_requested = inline_bytes
        .checked_add(dfa_cells_upper_bound.checked_mul(size_of::<u32>()).ok_or(
            BuildError::ArithmeticOverflow {
                computation: "transition bytes",
            },
        )?)
        .and_then(|bytes| {
            let output_cell_bytes = size_of::<u32>().checked_mul(2)?;
            bytes.checked_add(trie_states_upper_bound.checked_mul(output_cell_bytes)?)
        })
        .and_then(|bytes| bytes.checked_add(identity_bytes))
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "requested persistent bytes",
        })?;
    let scratch_state_bytes =
        size_of::<u32>()
            .checked_mul(3)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "scratch bytes per trie state",
            })?;
    let scratch_requested = trie_states_upper_bound
        .checked_mul(scratch_state_bytes)
        .and_then(|bytes| bytes.checked_add(patterns.len().checked_mul(size_of::<u32>())?))
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "requested build scratch",
        })?;
    let peak_requested = persistent_requested.checked_add(scratch_requested).ok_or(
        BuildError::ArithmeticOverflow {
            computation: "requested build peak",
        },
    )?;
    check_observed_build_limits(
        persistent_requested,
        scratch_requested,
        peak_requested,
        limits,
    )?;
    Ok(BuildPreflight {
        byte_classes,
        alphabet_classes,
        pattern_bytes,
        identity_bytes,
        trie_states_upper_bound,
        dfa_cells_upper_bound,
        build_work_upper_bound,
        max_pattern_bytes,
        min_nonempty_pattern_bytes,
        has_empty_pattern,
    })
}

fn check_observed_build_limits(
    persistent: usize,
    scratch: usize,
    peak: usize,
    limits: BuildLimits,
) -> Result<(), BuildError> {
    if scratch > limits.max_scratch_bytes {
        return Err(BuildError::ScratchLimit {
            needed: scratch,
            limit: limits.max_scratch_bytes,
        });
    }
    if persistent > limits.max_persistent_bytes {
        return Err(BuildError::PersistentLimit {
            needed: persistent,
            limit: limits.max_persistent_bytes,
        });
    }
    if peak > limits.max_peak_bytes {
        return Err(BuildError::PeakLimit {
            needed: peak,
            limit: limits.max_peak_bytes,
        });
    }
    Ok(())
}

fn check_reduce_limits(
    upper: ReduceUpperBounds,
    check_span: bool,
    limits: ReduceLimits,
) -> Result<(), ReduceError> {
    if upper.transitions > limits.max_transitions {
        return Err(ReduceError::TransitionLimit {
            needed: upper.transitions,
            limit: limits.max_transitions,
        });
    }
    if upper.match_events > limits.max_match_events {
        return Err(ReduceError::MatchEventsLimit {
            needed: upper.match_events,
            limit: limits.max_match_events,
        });
    }
    if upper.count > limits.max_count {
        return Err(ReduceError::CountLimit {
            needed: upper.count,
            limit: limits.max_count,
        });
    }
    if check_span && upper.span_sum > limits.max_span_sum {
        return Err(ReduceError::SpanSumLimit {
            needed: upper.span_sum,
            limit: limits.max_span_sum,
        });
    }
    if upper.reducer_steps > limits.max_reducer_steps {
        return Err(ReduceError::ReducerStepsLimit {
            needed: upper.reducer_steps,
            limit: limits.max_reducer_steps,
        });
    }
    if upper.ring_initializations > limits.max_ring_initializations {
        return Err(ReduceError::RingInitializationLimit {
            needed: upper.ring_initializations,
            limit: limits.max_ring_initializations,
        });
    }
    if upper.total_work > limits.max_total_work {
        return Err(ReduceError::TotalWorkLimit {
            needed: upper.total_work,
            limit: limits.max_total_work,
        });
    }
    if upper.scratch_bytes > limits.max_scratch_bytes {
        return Err(ReduceError::ScratchLimit {
            needed: upper.scratch_bytes,
            limit: limits.max_scratch_bytes,
        });
    }
    if upper.peak_bytes > limits.max_peak_bytes {
        return Err(ReduceError::PeakLimit {
            needed: upper.peak_bytes,
            limit: limits.max_peak_bytes,
        });
    }
    Ok(())
}

fn add_state(
    alphabet_classes: usize,
    transitions: &mut Vec<u32>,
    output_pattern: &mut Vec<u32>,
    output_length: &mut Vec<u32>,
    terminal: &mut Vec<u32>,
    failure: &mut Vec<u32>,
) -> Result<(), BuildError> {
    let transition_end =
        transitions
            .len()
            .checked_add(alphabet_classes)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "next DFA row end",
            })?;
    if transition_end > transitions.capacity()
        || output_pattern.len() >= output_pattern.capacity()
        || output_length.len() >= output_length.capacity()
        || terminal.len() >= terminal.capacity()
        || failure.len() >= failure.capacity()
    {
        return Err(BuildError::InternalInvariant {
            detail: "pre-reserved trie/DFA capacity dominates every state growth",
        });
    }
    transitions.extend(std::iter::repeat_n(UNSET, alphabet_classes));
    output_pattern.push(UNSET);
    output_length.push(0);
    terminal.push(UNSET);
    failure.push(0);
    Ok(())
}

fn encode_patterns<P: AsRef<[u8]>>(
    patterns: &[P],
    expected_bytes: usize,
    encoded: &mut Vec<u8>,
) -> Result<(), BuildError> {
    if encoded.capacity() < expected_bytes {
        return Err(BuildError::InternalInvariant {
            detail: "identity reservation covers the complete encoding",
        });
    }
    let count = u64::try_from(patterns.len()).map_err(|_| BuildError::ArithmeticOverflow {
        computation: "identity pattern count",
    })?;
    encoded.extend_from_slice(&count.to_le_bytes());
    for pattern in patterns {
        let bytes = pattern.as_ref();
        let length = u64::try_from(bytes.len()).map_err(|_| BuildError::ArithmeticOverflow {
            computation: "identity pattern length",
        })?;
        encoded.extend_from_slice(&length.to_le_bytes());
        encoded.extend_from_slice(bytes);
    }
    if encoded.len() != expected_bytes {
        return Err(BuildError::InternalInvariant {
            detail: "identity encoding length equals preflight",
        });
    }
    Ok(())
}

fn checked_push<T>(values: &mut Vec<T>, value: T, detail: &'static str) -> Result<(), BuildError> {
    if values.len() >= values.capacity() {
        return Err(BuildError::InternalInvariant { detail });
    }
    values.push(value);
    Ok(())
}

fn checked_queue_push(queue: &mut VecDeque<u32>, value: u32) -> Result<(), BuildError> {
    if queue.len() >= queue.capacity() {
        return Err(BuildError::InternalInvariant {
            detail: "failure queue reservation covers all trie states",
        });
    }
    queue.push_back(value);
    Ok(())
}

fn reserve_vec<T>(additional: usize, structure: &'static str) -> Result<Vec<T>, BuildError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(additional)
        .map_err(|_| BuildError::AllocationFailed {
            structure,
            additional,
        })?;
    Ok(values)
}

fn reserve_ring<T>(additional: usize, structure: &'static str) -> Result<Vec<T>, ReduceError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(additional)
        .map_err(|_| ReduceError::AllocationFailed {
            structure,
            additional,
        })?;
    Ok(values)
}

fn capacity_bytes<T>(values: &Vec<T>) -> Result<usize, BuildError> {
    values
        .capacity()
        .checked_mul(size_of::<T>())
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "vector capacity bytes",
        })
}

fn validate_ring(actual: usize, expected: usize) -> Result<(), ReduceError> {
    if actual == 0 || actual != expected {
        return Err(ReduceError::InternalInvariant {
            detail: "DP ring is nonempty and has the preflight length",
        });
    }
    Ok(())
}

fn checked_dp_target(
    position: usize,
    length: usize,
    haystack_len: usize,
    max_pattern_len: usize,
    ring_len: usize,
) -> Result<usize, ReduceError> {
    if length == 0 || length > max_pattern_len || length >= ring_len {
        return Err(ReduceError::InternalInvariant {
            detail: "DFA nonempty output length fits the compiled width and DP ring",
        });
    }
    let target = position
        .checked_add(length)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "DP target position",
        })?;
    if target > haystack_len {
        return Err(ReduceError::InternalInvariant {
            detail: "DFA output cannot extend past the haystack",
        });
    }
    Ok(target)
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use regex::bytes::{Regex, RegexBuilder};

    use super::{
        BuildError, BuildLimits, OrderedLiteralCountPlan, OrderedLiteralSpanSumPlan, ReduceError,
        ReduceLimits,
    };

    fn regex(patterns: &[Vec<u8>]) -> Regex {
        let mut source = String::from("(?:");
        for (index, pattern) in patterns.iter().enumerate() {
            if index != 0 {
                source.push('|');
            }
            for &byte in pattern {
                write!(&mut source, "\\x{byte:02X}").unwrap();
            }
        }
        source.push(')');
        RegexBuilder::new(&source).unicode(false).build().unwrap()
    }

    fn words(alphabet: &[u8], maximum_len: usize) -> Vec<Vec<u8>> {
        let mut all = vec![Vec::new()];
        let mut level = vec![Vec::new()];
        for _ in 0..maximum_len {
            let mut next = Vec::new();
            for prefix in &level {
                for &byte in alphabet {
                    let mut word = prefix.clone();
                    word.push(byte);
                    next.push(word);
                }
            }
            all.extend(next.iter().cloned());
            level = next;
        }
        all
    }

    fn pattern_lists(universe: &[Vec<u8>], maximum_len: usize) -> Vec<Vec<Vec<u8>>> {
        let mut all = Vec::new();
        let mut level = vec![Vec::new()];
        for _ in 0..maximum_len {
            let mut next = Vec::new();
            for prefix in &level {
                for pattern in universe {
                    let mut list = prefix.clone();
                    list.push(pattern.clone());
                    next.push(list);
                }
            }
            all.extend(next.iter().cloned());
            level = next;
        }
        all
    }

    fn plan_sequence(plan: &OrderedLiteralCountPlan, haystack: &[u8]) -> Vec<(u32, usize, usize)> {
        let positions = haystack.len().checked_add(1).unwrap();
        let mut choices = vec![None; positions];
        let mut state = 0_u32;
        for position in (0..=haystack.len()).rev() {
            if position < haystack.len() {
                state = plan.core.dfa.next(state, haystack[position]);
            }
            choices[position] = plan.core.dfa.output(state);
        }
        let mut matches = Vec::new();
        let mut start = 0_usize;
        let mut last_end = None;
        while start <= haystack.len() {
            let Some(position) =
                (start..=haystack.len()).find(|&position| choices[position].is_some())
            else {
                break;
            };
            let (pattern, length) = choices[position].unwrap();
            if length == 0 && last_end == Some(position) {
                start = position.checked_add(1).unwrap();
                continue;
            }
            let end = position.checked_add(length).unwrap();
            matches.push((pattern, position, end));
            start = end;
            last_end = Some(end);
        }
        matches
    }

    fn choice_at_start(plan: &OrderedLiteralCountPlan, haystack: &[u8]) -> Option<(u32, usize)> {
        let mut state = 0_u32;
        for &byte in haystack.iter().rev() {
            state = plan.core.dfa.next(state, byte);
        }
        plan.core.dfa.output(state)
    }

    #[test]
    fn directed_empty_prefix_duplicate_and_invalid_byte_sequences() {
        let cases: &[(&[&[u8]], &[u8])] = &[
            (&[b"a", b""], b"a"),
            (&[b"", b"a"], b"a"),
            (&[b"aa", b"a", b""], b"aaa"),
            (&[b"", b"", b"a"], b"aa"),
            (&[b"a", b"a"], b"aa"),
            (&[b"ab", b"a"], b"ababa"),
            (&[b"a", b"ab"], b"ababa"),
            (&[b"\xFF\x00", b"\xFF", b""], b"\xFF\x00\xFF\x80"),
        ];
        for &(patterns, haystack) in cases {
            let owned = patterns
                .iter()
                .map(|pattern| pattern.to_vec())
                .collect::<Vec<_>>();
            let oracle = regex(&owned);
            let expected = oracle
                .find_iter(haystack)
                .map(|matched| (matched.start(), matched.end()))
                .collect::<Vec<_>>();
            let plan = OrderedLiteralCountPlan::build(&owned, BuildLimits::unlimited()).unwrap();
            let actual = plan_sequence(&plan, haystack)
                .into_iter()
                .map(|(_, start, end)| (start, end))
                .collect::<Vec<_>>();
            assert_eq!(
                actual, expected,
                "patterns={owned:?}, haystack={haystack:?}"
            );
        }
    }

    #[test]
    fn exhaustive_small_ordered_languages_match_regex_bytes_1_12_4() {
        let universe = vec![
            b"".to_vec(),
            b"a".to_vec(),
            b"b".to_vec(),
            b"\xFF".to_vec(),
            b"aa".to_vec(),
            b"ab".to_vec(),
        ];
        let languages = pattern_lists(&universe, 3);
        let haystacks = words(b"\x00a\xFF", 4);
        for patterns in languages {
            let oracle = regex(&patterns);
            let count_plan =
                OrderedLiteralCountPlan::build(&patterns, BuildLimits::unlimited()).unwrap();
            let span_plan =
                OrderedLiteralSpanSumPlan::build(&patterns, BuildLimits::unlimited()).unwrap();
            for haystack in &haystacks {
                let expected = oracle
                    .find_iter(haystack)
                    .map(|matched| (matched.start(), matched.end()))
                    .collect::<Vec<_>>();
                let sequence = plan_sequence(&count_plan, haystack);
                let actual = sequence
                    .iter()
                    .map(|&(_, start, end)| (start, end))
                    .collect::<Vec<_>>();
                assert_eq!(
                    actual, expected,
                    "patterns={patterns:?}, haystack={haystack:?}"
                );
                let count = count_plan
                    .count(haystack, ReduceLimits::unlimited())
                    .unwrap();
                let span = span_plan
                    .span_sum(haystack, ReduceLimits::unlimited())
                    .unwrap();
                let expected_span = expected
                    .iter()
                    .map(|&(start, end)| u64::try_from(end - start).unwrap())
                    .sum::<u64>();
                assert_eq!(
                    count.count,
                    u64::try_from(expected.len()).unwrap(),
                    "patterns={patterns:?}, haystack={haystack:?}"
                );
                assert_eq!(
                    span.span_sum, expected_span,
                    "patterns={patterns:?}, haystack={haystack:?}"
                );
                assert_eq!(span.accounting.actual.match_events, count.count);
                assert_eq!(count.accounting.actual.transitions, haystack.len());
                assert_eq!(count.accounting.actual.reducer_steps, haystack.len() + 1);
            }
        }
    }

    #[test]
    fn cache_identity_preserves_order_duplicates_empties_and_bytes() {
        let first = OrderedLiteralCountPlan::build(
            &[b"".as_slice(), b"\xFF".as_slice(), b"\xFF".as_slice()],
            BuildLimits::unlimited(),
        )
        .unwrap();
        let second = OrderedLiteralCountPlan::build(
            &[b"\xFF".as_slice(), b"".as_slice(), b"\xFF".as_slice()],
            BuildLimits::unlimited(),
        )
        .unwrap();
        assert_ne!(
            first.cache_identity().encoded_patterns,
            second.cache_identity().encoded_patterns
        );
        assert_ne!(first.cache_identity().plan_id, super::SPAN_SUM_PLAN_ID);
    }

    #[test]
    fn output_priority_covers_root_terminal_and_failure_inheritance() {
        let root = OrderedLiteralCountPlan::build(
            &[b"x".as_slice(), b"".as_slice(), b"".as_slice()],
            BuildLimits::unlimited(),
        )
        .unwrap();
        assert_eq!(choice_at_start(&root, b""), Some((1, 0)));

        let terminal_beats_empty = OrderedLiteralCountPlan::build(
            &[b"a".as_slice(), b"".as_slice()],
            BuildLimits::unlimited(),
        )
        .unwrap();
        assert_eq!(choice_at_start(&terminal_beats_empty, b"a"), Some((0, 1)));
        let empty_beats_terminal = OrderedLiteralCountPlan::build(
            &[b"".as_slice(), b"a".as_slice()],
            BuildLimits::unlimited(),
        )
        .unwrap();
        assert_eq!(choice_at_start(&empty_beats_terminal, b"a"), Some((0, 0)));

        let terminal_beats_failure = OrderedLiteralCountPlan::build(
            &[b"ab".as_slice(), b"a".as_slice()],
            BuildLimits::unlimited(),
        )
        .unwrap();
        assert_eq!(
            choice_at_start(&terminal_beats_failure, b"ab"),
            Some((0, 2))
        );
        let failure_beats_terminal = OrderedLiteralCountPlan::build(
            &[b"a".as_slice(), b"ab".as_slice()],
            BuildLimits::unlimited(),
        )
        .unwrap();
        assert_eq!(
            choice_at_start(&failure_beats_terminal, b"ab"),
            Some((0, 1))
        );
    }

    #[test]
    fn empty_only_empty_haystack_has_zero_transitions_and_one_position() {
        let count = OrderedLiteralCountPlan::build(&[b""], BuildLimits::unlimited()).unwrap();
        let span = OrderedLiteralSpanSumPlan::build(&[b""], BuildLimits::unlimited()).unwrap();
        let counted = count.count(b"", ReduceLimits::unlimited()).unwrap();
        let summed = span.span_sum(b"", ReduceLimits::unlimited()).unwrap();
        assert_eq!(counted.count, 1);
        assert_eq!(summed.span_sum, 0);
        assert_eq!(counted.accounting.actual.transitions, 0);
        assert_eq!(counted.accounting.actual.reducer_steps, 1);
        assert_eq!(counted.accounting.actual.ring_initializations, 1);
        assert_eq!(counted.accounting.actual.total_work, 2);
    }

    #[test]
    fn single_pattern_results_match_exact_literal_aggregate() {
        use crate::{LiteralAggregateBuildLimits, LiteralAggregatePlan};

        for needle in [b"".as_slice(), b"a", b"aa", b"\xFF\x00"] {
            let ordered_count =
                OrderedLiteralCountPlan::build(&[needle], BuildLimits::unlimited()).unwrap();
            let ordered_span =
                OrderedLiteralSpanSumPlan::build(&[needle], BuildLimits::unlimited()).unwrap();
            let exact =
                LiteralAggregatePlan::build(needle, LiteralAggregateBuildLimits::unlimited())
                    .unwrap();
            for haystack in words(b"\x00a\xFF", 4) {
                assert_eq!(
                    ordered_count
                        .count(&haystack, ReduceLimits::unlimited())
                        .unwrap()
                        .count,
                    exact
                        .count(&haystack, crate::LiteralAggregateReduceLimits::unlimited())
                        .unwrap()
                        .count
                );
                assert_eq!(
                    ordered_span
                        .span_sum(&haystack, ReduceLimits::unlimited())
                        .unwrap()
                        .span_sum,
                    exact
                        .span_sum(&haystack, crate::LiteralAggregateReduceLimits::unlimited())
                        .unwrap()
                        .span_sum
                );
            }
        }
    }

    fn exact_build_limits(plan: &OrderedLiteralCountPlan) -> BuildLimits {
        let build = plan.build_accounting();
        BuildLimits {
            max_patterns: build.patterns,
            max_pattern_bytes: build.pattern_bytes,
            max_identity_bytes: build.identity_bytes,
            max_trie_states: build.trie_states_upper_bound,
            max_dfa_cells: build.dfa_cells_upper_bound,
            max_build_work: build.build_work_upper_bound,
            max_scratch_bytes: build.scratch_bytes,
            max_persistent_bytes: build.persistent_bytes,
            max_peak_bytes: build.peak_bytes,
        }
    }

    #[test]
    fn every_build_limit_has_exact_and_one_below_behavior() {
        let patterns = [
            b"".as_slice(),
            b"ab".as_slice(),
            b"a".as_slice(),
            b"\xFF\x00".as_slice(),
        ];
        let baseline = OrderedLiteralCountPlan::build(&patterns, BuildLimits::unlimited()).unwrap();
        let exact = exact_build_limits(&baseline);
        OrderedLiteralCountPlan::build(&patterns, exact).unwrap();

        let cases = [
            (
                BuildLimits {
                    max_patterns: exact.max_patterns.checked_sub(1).unwrap(),
                    ..exact
                },
                "patterns",
            ),
            (
                BuildLimits {
                    max_pattern_bytes: exact.max_pattern_bytes.checked_sub(1).unwrap(),
                    ..exact
                },
                "pattern bytes",
            ),
            (
                BuildLimits {
                    max_identity_bytes: exact.max_identity_bytes.checked_sub(1).unwrap(),
                    ..exact
                },
                "identity",
            ),
            (
                BuildLimits {
                    max_trie_states: exact.max_trie_states.checked_sub(1).unwrap(),
                    ..exact
                },
                "trie states",
            ),
            (
                BuildLimits {
                    max_dfa_cells: exact.max_dfa_cells.checked_sub(1).unwrap(),
                    ..exact
                },
                "DFA cells",
            ),
            (
                BuildLimits {
                    max_build_work: exact.max_build_work.checked_sub(1).unwrap(),
                    ..exact
                },
                "build work",
            ),
            (
                BuildLimits {
                    max_scratch_bytes: exact.max_scratch_bytes.checked_sub(1).unwrap(),
                    ..exact
                },
                "scratch",
            ),
            (
                BuildLimits {
                    max_persistent_bytes: exact.max_persistent_bytes.checked_sub(1).unwrap(),
                    ..exact
                },
                "persistent",
            ),
            (
                BuildLimits {
                    max_peak_bytes: exact.max_peak_bytes.checked_sub(1).unwrap(),
                    ..exact
                },
                "peak",
            ),
        ];
        for (limits, label) in cases {
            assert!(
                OrderedLiteralCountPlan::build(&patterns, limits).is_err(),
                "one-below {label} unexpectedly built"
            );
        }
    }

    fn exact_reduce_limits(upper: super::ReduceUpperBounds, max_span_sum: u64) -> ReduceLimits {
        ReduceLimits {
            max_transitions: upper.transitions,
            max_match_events: upper.match_events,
            max_count: upper.count,
            max_span_sum,
            max_reducer_steps: upper.reducer_steps,
            max_ring_initializations: upper.ring_initializations,
            max_total_work: upper.total_work,
            max_scratch_bytes: upper.scratch_bytes,
            max_peak_bytes: upper.peak_bytes,
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "table-like exact/one-below assertions keep every public reducer limit visible"
    )]
    fn every_reducer_limit_has_exact_and_one_below_behavior() {
        let patterns = [b"ab".as_slice(), b"a".as_slice(), b"".as_slice()];
        let haystack = b"ababxaba";
        let count_plan =
            OrderedLiteralCountPlan::build(&patterns, BuildLimits::unlimited()).unwrap();
        let span_plan =
            OrderedLiteralSpanSumPlan::build(&patterns, BuildLimits::unlimited()).unwrap();
        let count = count_plan
            .count(haystack, ReduceLimits::unlimited())
            .unwrap();
        let span = span_plan
            .span_sum(haystack, ReduceLimits::unlimited())
            .unwrap();
        let count_exact = exact_reduce_limits(count.accounting.upper_bounds, u64::MAX);
        let span_exact = exact_reduce_limits(
            span.accounting.upper_bounds,
            span.accounting.upper_bounds.span_sum,
        );
        count_plan.count(haystack, count_exact).unwrap();
        span_plan.span_sum(haystack, span_exact).unwrap();

        assert!(matches!(
            count_plan.count(
                haystack,
                ReduceLimits {
                    max_transitions: count_exact.max_transitions.checked_sub(1).unwrap(),
                    ..count_exact
                }
            ),
            Err(ReduceError::TransitionLimit { .. })
        ));
        assert!(matches!(
            count_plan.count(
                haystack,
                ReduceLimits {
                    max_match_events: count_exact.max_match_events.checked_sub(1).unwrap(),
                    ..count_exact
                }
            ),
            Err(ReduceError::MatchEventsLimit { .. })
        ));
        assert!(matches!(
            count_plan.count(
                haystack,
                ReduceLimits {
                    max_count: count_exact.max_count.checked_sub(1).unwrap(),
                    ..count_exact
                }
            ),
            Err(ReduceError::CountLimit { .. })
        ));
        assert!(matches!(
            count_plan.count(
                haystack,
                ReduceLimits {
                    max_reducer_steps: count_exact.max_reducer_steps.checked_sub(1).unwrap(),
                    ..count_exact
                }
            ),
            Err(ReduceError::ReducerStepsLimit { .. })
        ));
        assert!(matches!(
            count_plan.count(
                haystack,
                ReduceLimits {
                    max_ring_initializations: count_exact
                        .max_ring_initializations
                        .checked_sub(1)
                        .unwrap(),
                    ..count_exact
                }
            ),
            Err(ReduceError::RingInitializationLimit { .. })
        ));
        assert!(matches!(
            count_plan.count(
                haystack,
                ReduceLimits {
                    max_total_work: count_exact.max_total_work.checked_sub(1).unwrap(),
                    ..count_exact
                }
            ),
            Err(ReduceError::TotalWorkLimit { .. })
        ));
        assert!(matches!(
            count_plan.count(
                haystack,
                ReduceLimits {
                    max_scratch_bytes: count_exact.max_scratch_bytes.checked_sub(1).unwrap(),
                    ..count_exact
                }
            ),
            Err(ReduceError::ScratchLimit { .. })
        ));
        assert!(matches!(
            count_plan.count(
                haystack,
                ReduceLimits {
                    max_peak_bytes: count_exact.max_peak_bytes.checked_sub(1).unwrap(),
                    ..count_exact
                }
            ),
            Err(ReduceError::PeakLimit { .. })
        ));
        assert!(matches!(
            span_plan.span_sum(
                haystack,
                ReduceLimits {
                    max_span_sum: span_exact.max_span_sum.checked_sub(1).unwrap(),
                    ..span_exact
                }
            ),
            Err(ReduceError::SpanSumLimit { .. })
        ));
    }

    #[test]
    fn quadratic_restart_adversary_has_exact_linear_transition_scaling() {
        let mut long = vec![b'a'; 4_096];
        long.push(b'b');
        let patterns = [long.as_slice(), b"a".as_slice()];
        let plan = OrderedLiteralCountPlan::build(&patterns, BuildLimits::unlimited()).unwrap();
        let first = plan
            .count(&vec![b'a'; 8_192], ReduceLimits::unlimited())
            .unwrap();
        let second = plan
            .count(&vec![b'a'; 16_384], ReduceLimits::unlimited())
            .unwrap();
        assert_eq!(first.count, 8_192);
        assert_eq!(second.count, 16_384);
        assert_eq!(first.accounting.actual.transitions, 8_192);
        assert_eq!(second.accounting.actual.transitions, 16_384);
        assert_eq!(
            first.accounting.upper_bounds.scratch_bytes,
            second.accounting.upper_bounds.scratch_bytes
        );
    }

    #[test]
    fn fixed_pattern_fixed_haystack_and_joint_scaling_are_explicit() {
        fn long_pattern(width: usize) -> Vec<u8> {
            let mut pattern = vec![b'a'; width.checked_sub(1).unwrap()];
            pattern.push(b'b');
            pattern
        }

        let fixed_pattern = long_pattern(32);
        let plan = OrderedLiteralCountPlan::build(
            &[fixed_pattern.as_slice(), b"a".as_slice()],
            BuildLimits::unlimited(),
        )
        .unwrap();
        let n1 = plan
            .count(&vec![b'a'; 1_024], ReduceLimits::unlimited())
            .unwrap();
        let n2 = plan
            .count(&vec![b'a'; 2_048], ReduceLimits::unlimited())
            .unwrap();
        assert_eq!(
            n2.accounting.actual.transitions,
            n1.accounting.actual.transitions.checked_mul(2).unwrap()
        );
        assert_eq!(
            n1.accounting.actual.ring_initializations,
            n2.accounting.actual.ring_initializations
        );

        let width8 = long_pattern(8);
        let width32 = long_pattern(32);
        let p8 = OrderedLiteralCountPlan::build(&[width8], BuildLimits::unlimited()).unwrap();
        let p32 = OrderedLiteralCountPlan::build(&[width32], BuildLimits::unlimited()).unwrap();
        let fixed_n8 = p8
            .count(&vec![b'a'; 4_096], ReduceLimits::unlimited())
            .unwrap();
        let fixed_n32 = p32
            .count(&vec![b'a'; 4_096], ReduceLimits::unlimited())
            .unwrap();
        assert_eq!(fixed_n8.accounting.actual.transitions, 4_096);
        assert_eq!(fixed_n32.accounting.actual.transitions, 4_096);
        assert_eq!(fixed_n8.accounting.actual.ring_initializations, 9);
        assert_eq!(fixed_n32.accounting.actual.ring_initializations, 33);

        let joint16 = long_pattern(16);
        let joint32 = long_pattern(32);
        let joint_plan16 =
            OrderedLiteralCountPlan::build(&[joint16], BuildLimits::unlimited()).unwrap();
        let joint_plan32 =
            OrderedLiteralCountPlan::build(&[joint32], BuildLimits::unlimited()).unwrap();
        let j1 = joint_plan16
            .count(&vec![b'a'; 1_024], ReduceLimits::unlimited())
            .unwrap();
        let j2 = joint_plan32
            .count(&vec![b'a'; 2_048], ReduceLimits::unlimited())
            .unwrap();
        assert_eq!(
            j2.accounting.actual.transitions,
            j1.accounting.actual.transitions.checked_mul(2).unwrap()
        );
        assert_eq!(j1.accounting.actual.ring_initializations, 17);
        assert_eq!(j2.accounting.actual.ring_initializations, 33);
    }

    #[test]
    fn empty_pattern_set_is_a_typed_refusal() {
        assert!(matches!(
            OrderedLiteralCountPlan::build::<&[u8]>(&[], BuildLimits::unlimited()),
            Err(BuildError::EmptyPatternSet)
        ));
    }
}
