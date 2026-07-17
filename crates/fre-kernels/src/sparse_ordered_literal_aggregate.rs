//! Sparse linear reducers for large ordered finite byte languages.
//!
//! Literals are inserted in reverse into a trie whose sorted outgoing edges
//! are retained in compressed-sparse-row form. Aho-Corasick failure links make
//! one right-to-left haystack traversal report the lowest source-index literal
//! starting at every position. The same bounded dynamic-program ring as the
//! dense ordered-literal kernel then implements successive non-overlapping
//! leftmost-first matches.
//!
//! Construction accepts a cloneable iterable rather than a materialized
//! `Vec<Vec<u8>>`. This lets a facade make the required validation, identity
//! and insertion passes directly over a root literal HIR. Every retained and
//! temporary vector is fallibly reserved. `build_work` is an exact charge in
//! the documented abstract model: one unit per yielded pattern and explicit
//! byte visit, per sibling comparison, per created temporary state or edge, per CSR
//! node or edge visit, per failure-BFS state or edge visit, per failure hop,
//! per sparse binary-search comparison, and per final state degree scan. A
//! charge is checked before the corresponding work.

use core::{cmp::Ordering, fmt, mem::size_of};

const UNSET: u32 = u32::MAX;
const TARGET_MASK: u32 = 0x00FF_FFFF;
const MAX_REPRESENTABLE_STATES: usize = 0x0100_0000;
const CACHE_FORMAT_VERSION: u32 = 1;
const LENGTH_PREFIX_BYTES: usize = size_of::<u64>();

/// Stable strategy identity shared by both operation-typed plans.
pub const ALGORITHM_ID: &str = "ordered-literal-aggregate.reverse-sparse-ac-dp.v1";
/// Stable identity for the count-specialized plan.
pub const COUNT_PLAN_ID: &str = "ordered-literal-aggregate.count.reverse-sparse-ac-dp.v1";
/// Stable identity for the span-sum-specialized plan.
pub const SPAN_SUM_PLAN_ID: &str = "ordered-literal-aggregate.span-sum.reverse-sparse-ac-dp.v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Count,
    SpanSum,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MatchSemantics {
    LeftmostFirst,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IterationSemantics {
    NonOverlapping,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundarySemantics {
    EveryByteUnicodeOffSuppressAdjacentEmpty,
}

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheIdentity<'a> {
    pub algorithm_id: &'static str,
    pub plan_id: &'static str,
    pub operation: Operation,
    pub cache_format_version: u32,
    pub transition_kind: &'static str,
    pub traversal_kind: &'static str,
    pub semantics: Semantics,
    pub encoded_patterns: &'a [u8],
}

/// Limits for one sparse reversed-automaton construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildLimits {
    pub max_patterns: usize,
    pub max_pattern_bytes: usize,
    pub max_identity_bytes: usize,
    pub max_trie_states: usize,
    pub max_sparse_edges: usize,
    pub max_build_work: u64,
    pub max_scratch_bytes: usize,
    pub max_persistent_bytes: usize,
    pub max_peak_bytes: usize,
}

impl BuildLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_patterns: usize::MAX,
            max_pattern_bytes: usize::MAX,
            max_identity_bytes: usize::MAX,
            max_trie_states: usize::MAX,
            max_sparse_edges: usize::MAX,
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
            max_patterns: 1_000_000,
            max_pattern_bytes: 4 * 1024 * 1024,
            max_identity_bytes: 8 * 1024 * 1024,
            max_trie_states: 4_194_304,
            max_sparse_edges: 4_194_303,
            max_build_work: 64 * 1024 * 1024,
            max_scratch_bytes: 32 * 1024 * 1024,
            max_persistent_bytes: 64 * 1024 * 1024,
            max_peak_bytes: 96 * 1024 * 1024,
        }
    }
}

/// Exact charged work and observed vector-capacity accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildAccounting {
    pub patterns: usize,
    pub pattern_bytes: usize,
    pub identity_bytes: usize,
    pub identity_capacity_bytes: usize,
    pub trie_states_upper_bound: usize,
    pub trie_states_actual: usize,
    pub sparse_edges_upper_bound: usize,
    pub sparse_edges_actual: usize,
    pub build_work: u64,
    pub max_pattern_bytes: usize,
    pub min_nonempty_pattern_bytes: Option<usize>,
    pub has_empty_pattern: bool,
    pub max_edge_search_checks: usize,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceLimits {
    pub max_transitions: usize,
    pub max_edge_lookups: usize,
    pub max_edge_search_checks: u64,
    pub max_failure_steps: usize,
    pub max_match_events: usize,
    pub max_count: u64,
    pub max_span_sum: u64,
    pub max_reducer_steps: usize,
    pub max_ring_initializations: usize,
    pub max_total_work: u64,
    pub max_scratch_bytes: usize,
    pub max_peak_bytes: usize,
}

impl ReduceLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_transitions: usize::MAX,
            max_edge_lookups: usize::MAX,
            max_edge_search_checks: u64::MAX,
            max_failure_steps: usize::MAX,
            max_match_events: usize::MAX,
            max_count: u64::MAX,
            max_span_sum: u64::MAX,
            max_reducer_steps: usize::MAX,
            max_ring_initializations: usize::MAX,
            max_total_work: u64::MAX,
            max_scratch_bytes: usize::MAX,
            max_peak_bytes: usize::MAX,
        }
    }
}

impl Default for ReduceLimits {
    fn default() -> Self {
        Self {
            max_transitions: 128 * 1024 * 1024,
            max_edge_lookups: 256 * 1024 * 1024,
            max_edge_search_checks: 2 * 1024 * 1024 * 1024,
            max_failure_steps: 128 * 1024 * 1024,
            max_match_events: 128 * 1024 * 1024,
            max_count: 128 * 1024 * 1024,
            max_span_sum: 128 * 1024 * 1024,
            max_reducer_steps: 128 * 1024 * 1024 + 1,
            max_ring_initializations: 64 * 1024 * 1024,
            max_total_work: 3 * 1024 * 1024 * 1024,
            max_scratch_bytes: 64 * 1024 * 1024,
            max_peak_bytes: 128 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceUpperBounds {
    pub haystack_bytes: usize,
    pub transitions: usize,
    pub edge_lookups: usize,
    pub edge_search_checks: u64,
    pub failure_steps: usize,
    pub match_events: usize,
    pub count: u64,
    pub span_sum: u64,
    pub reducer_steps: usize,
    pub ring_entries: usize,
    pub ring_initializations: usize,
    pub total_work: u64,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceActualCounters {
    pub transitions: usize,
    pub edge_lookups: usize,
    pub edge_search_checks: u64,
    pub failure_steps: usize,
    pub reducer_steps: usize,
    pub ring_initializations: usize,
    pub total_work: u64,
    pub match_events: u64,
    pub count: Option<u64>,
    pub span_sum: Option<u64>,
    pub scratch_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceAccounting<'a> {
    pub identity: CacheIdentity<'a>,
    pub upper_bounds: ReduceUpperBounds,
    pub actual: ReduceActualCounters,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountResult<'a> {
    pub count: u64,
    pub accounting: ReduceAccounting<'a>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpanSumResult<'a> {
    pub span_sum: u64,
    pub accounting: ReduceAccounting<'a>,
}

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
    SparseEdgesLimit {
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
    InputChanged {
        pass: &'static str,
    },
    InternalInvariant {
        detail: &'static str,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sparse ordered-literal build refusal: {self:?}")
    }
}

impl std::error::Error for BuildError {}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ReduceError {
    TransitionLimit {
        needed: usize,
        limit: usize,
    },
    EdgeLookupLimit {
        needed: usize,
        limit: usize,
    },
    EdgeSearchChecksLimit {
        needed: u64,
        limit: u64,
    },
    FailureStepsLimit {
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
        needed: u64,
        limit: u64,
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
    InternalInvariant {
        detail: &'static str,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
}

impl fmt::Display for ReduceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sparse ordered-literal reduce refusal: {self:?}")
    }
}

impl std::error::Error for ReduceError {}

#[derive(Clone, Copy, Debug)]
struct Output {
    pattern: u32,
    length: u32,
}

impl Output {
    fn min_priority(self, other: Self) -> Self {
        if self.pattern <= other.pattern {
            self
        } else {
            other
        }
    }
}

#[derive(Debug)]
struct SparseReverseAc {
    offsets: Vec<u32>,
    edges: Vec<u32>,
    failure: Vec<u32>,
    output: Vec<Output>,
}

#[derive(Default)]
struct SearchCounters {
    edge_lookups: usize,
    edge_search_checks: u64,
    failure_steps: usize,
}

impl SparseReverseAc {
    fn state_count(&self) -> usize {
        self.output.len()
    }

    fn edge_with_work(
        &self,
        state: u32,
        byte: u8,
        work: &mut BuildWork,
    ) -> Result<Option<u32>, BuildError> {
        let state = usize::try_from(state).expect("u32 state fits usize");
        let start = usize::try_from(self.offsets[state]).expect("u32 edge offset fits usize");
        let next_state = state
            .checked_add(1)
            .expect("a represented state has a following CSR offset");
        let end = usize::try_from(self.offsets[next_state]).expect("u32 edge offset fits usize");
        let mut low = start;
        let mut high = end;
        while low < high {
            work.charge(1)?;
            let middle = low
                .checked_add(
                    high.checked_sub(low)
                        .expect("binary-search bounds are ordered")
                        / 2,
                )
                .expect("binary-search midpoint remains within the edge slice");
            match edge_byte(self.edges[middle]).cmp(&byte) {
                Ordering::Less => {
                    low = middle
                        .checked_add(1)
                        .expect("binary-search midpoint is below the slice end");
                }
                Ordering::Equal => return Ok(Some(edge_target(self.edges[middle]))),
                Ordering::Greater => high = middle,
            }
        }
        Ok(None)
    }

    fn edge_counted(&self, state: u32, byte: u8, counters: &mut SearchCounters) -> Option<u32> {
        counters.edge_lookups = counters
            .edge_lookups
            .checked_add(1)
            .expect("preflight proves at most two sparse lookups per input byte");
        let state = usize::try_from(state).expect("u32 state fits usize");
        let start = usize::try_from(self.offsets[state]).expect("u32 edge offset fits usize");
        let next_state = state
            .checked_add(1)
            .expect("a represented state has a following CSR offset");
        let end = usize::try_from(self.offsets[next_state]).expect("u32 edge offset fits usize");
        let mut low = start;
        let mut high = end;
        while low < high {
            counters.edge_search_checks = counters
                .edge_search_checks
                .checked_add(1)
                .expect("preflight proves sparse comparison accounting fits u64");
            let middle = low
                .checked_add(
                    high.checked_sub(low)
                        .expect("binary-search bounds are ordered")
                        / 2,
                )
                .expect("binary-search midpoint remains within the edge slice");
            match edge_byte(self.edges[middle]).cmp(&byte) {
                Ordering::Less => {
                    low = middle
                        .checked_add(1)
                        .expect("binary-search midpoint is below the slice end");
                }
                Ordering::Equal => return Some(edge_target(self.edges[middle])),
                Ordering::Greater => high = middle,
            }
        }
        None
    }

    fn next(&self, mut state: u32, byte: u8, counters: &mut SearchCounters) -> u32 {
        loop {
            if let Some(next) = self.edge_counted(state, byte, counters) {
                return next;
            }
            if state == 0 {
                return 0;
            }
            state = self.failure[usize::try_from(state).expect("u32 state fits usize")];
            counters.failure_steps = counters
                .failure_steps
                .checked_add(1)
                .expect("AC depth amortization proves at most one failure per input byte");
        }
    }

    fn output(&self, state: u32) -> Option<(u32, usize)> {
        let output = self.output[usize::try_from(state).expect("u32 state fits usize")];
        (output.pattern != UNSET).then(|| {
            (
                output.pattern,
                usize::try_from(output.length).expect("u32 length fits usize"),
            )
        })
    }
}

#[derive(Debug)]
struct PlanCore {
    automaton: SparseReverseAc,
    encoded_patterns: Vec<u8>,
    build: BuildAccounting,
}

#[derive(Debug)]
pub struct SparseOrderedLiteralCountPlan {
    core: PlanCore,
}

#[derive(Debug)]
pub struct SparseOrderedLiteralSpanSumPlan {
    core: PlanCore,
}

impl SparseOrderedLiteralCountPlan {
    /// Build directly from a stable, reusable, cloneable pattern iterable.
    pub fn build<I, P>(patterns: I, limits: BuildLimits) -> Result<Self, BuildError>
    where
        I: Clone + IntoIterator<Item = P>,
        P: AsRef<[u8]>,
    {
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

impl SparseOrderedLiteralSpanSumPlan {
    /// Build directly from a stable, reusable, cloneable pattern iterable.
    pub fn build<I, P>(patterns: I, limits: BuildLimits) -> Result<Self, BuildError>
    where
        I: Clone + IntoIterator<Item = P>,
        P: AsRef<[u8]>,
    {
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
        Ok(SpanSumResult {
            span_sum: actual.span_sum.expect("span plan publishes span sum"),
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

#[derive(Clone, Copy, Debug)]
struct RawNode {
    first_edge: u32,
    terminal_pattern_or_queue_next: u32,
    terminal_length: u32,
}

impl RawNode {
    const EMPTY: Self = Self {
        first_edge: UNSET,
        terminal_pattern_or_queue_next: UNSET,
        terminal_length: 0,
    };
}

#[derive(Clone, Copy, Debug)]
struct RawEdge {
    packed: u32,
    next_sibling: u32,
}

#[derive(Clone, Copy, Debug)]
struct BuildPreflight {
    patterns: usize,
    pattern_bytes: usize,
    identity_bytes: usize,
    trie_states_upper_bound: usize,
    sparse_edges_upper_bound: usize,
    max_pattern_bytes: usize,
    min_nonempty_pattern_bytes: Option<usize>,
    has_empty_pattern: bool,
}

#[derive(Debug)]
struct BuildWork {
    used: u64,
    limit: u64,
}

impl BuildWork {
    const fn new(limit: u64) -> Self {
        Self { used: 0, limit }
    }

    fn charge(&mut self, units: usize) -> Result<(), BuildError> {
        let units = u64::try_from(units).map_err(|_| BuildError::ArithmeticOverflow {
            computation: "construction charge as u64",
        })?;
        let needed = self
            .used
            .checked_add(units)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "construction work",
            })?;
        if needed > self.limit {
            return Err(BuildError::WorkLimit {
                needed,
                limit: self.limit,
            });
        }
        self.used = needed;
        Ok(())
    }
}

impl PlanCore {
    fn identity(&self, operation: Operation) -> CacheIdentity<'_> {
        CacheIdentity {
            algorithm_id: ALGORITHM_ID,
            plan_id: match operation {
                Operation::Count => COUNT_PLAN_ID,
                Operation::SpanSum => SPAN_SUM_PLAN_ID,
            },
            operation,
            cache_format_version: CACHE_FORMAT_VERSION,
            transition_kind: "sorted sparse-CSR byte edges plus u32 failure links",
            traversal_kind: "single reverse sparse-AC pass plus bounded initial/progressed DP ring",
            semantics: Semantics::RUST_BYTES_UNICODE_OFF,
            encoded_patterns: &self.encoded_patterns,
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "construction keeps all exact work and capacity checks adjacent"
    )]
    fn build<I, P>(
        patterns: I,
        limits: BuildLimits,
        inline_bytes: usize,
    ) -> Result<Self, BuildError>
    where
        I: Clone + IntoIterator<Item = P>,
        P: AsRef<[u8]>,
    {
        let mut work = BuildWork::new(limits.max_build_work);
        let preflight = preflight_build(patterns.clone(), limits, &mut work)?;

        let logical_scratch = preflight
            .trie_states_upper_bound
            .checked_mul(size_of::<RawNode>())
            .and_then(|bytes| {
                bytes.checked_add(
                    preflight
                        .sparse_edges_upper_bound
                        .checked_mul(size_of::<RawEdge>())?,
                )
            })
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "logical build scratch",
            })?;
        check_scratch(logical_scratch, limits)?;
        let persistent_floor = inline_bytes.checked_add(preflight.identity_bytes).ok_or(
            BuildError::ArithmeticOverflow {
                computation: "persistent floor",
            },
        )?;
        check_persistent_peak(persistent_floor, logical_scratch, limits)?;

        let mut encoded_patterns = reserve_vec::<u8>(preflight.identity_bytes, "cache identity")?;
        encode_patterns(
            patterns.clone(),
            preflight,
            &mut encoded_patterns,
            &mut work,
        )?;
        let mut raw_nodes =
            reserve_vec::<RawNode>(preflight.trie_states_upper_bound, "temporary trie nodes")?;
        let mut raw_edges =
            reserve_vec::<RawEdge>(preflight.sparse_edges_upper_bound, "temporary trie edges")?;
        work.charge(1)?;
        checked_push(&mut raw_nodes, RawNode::EMPTY, "root node reservation")?;

        let scratch_bytes = capacity_bytes(&raw_nodes)?
            .checked_add(capacity_bytes(&raw_edges)?)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "observed build scratch",
            })?;
        check_scratch(scratch_bytes, limits)?;
        let persistent_floor = inline_bytes
            .checked_add(encoded_patterns.capacity())
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "observed persistent floor",
            })?;
        check_persistent_peak(persistent_floor, scratch_bytes, limits)?;

        insert_patterns(
            patterns,
            preflight,
            &encoded_patterns,
            &mut raw_nodes,
            &mut raw_edges,
            &mut work,
        )?;
        let state_count = raw_nodes.len();
        let edge_count = raw_edges.len();

        let offset_count = state_count
            .checked_add(1)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "CSR offset count",
            })?;
        let requested_persistent = inline_bytes
            .checked_add(encoded_patterns.capacity())
            .and_then(|bytes| bytes.checked_add(offset_count.checked_mul(size_of::<u32>())?))
            .and_then(|bytes| bytes.checked_add(edge_count.checked_mul(size_of::<u32>())?))
            .and_then(|bytes| bytes.checked_add(state_count.checked_mul(size_of::<u32>())?))
            .and_then(|bytes| bytes.checked_add(state_count.checked_mul(size_of::<Output>())?))
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "requested sparse persistent bytes",
            })?;
        check_persistent_peak(requested_persistent, scratch_bytes, limits)?;

        let mut offsets = reserve_vec::<u32>(offset_count, "CSR offsets")?;
        let mut edges = reserve_vec::<u32>(edge_count, "CSR edges")?;
        let mut failure = reserve_vec::<u32>(state_count, "failure links")?;
        let mut output = reserve_vec::<Output>(state_count, "outputs")?;

        let persistent_bytes = inline_bytes
            .checked_add(encoded_patterns.capacity())
            .and_then(|bytes| bytes.checked_add(capacity_bytes(&offsets).ok()?))
            .and_then(|bytes| bytes.checked_add(capacity_bytes(&edges).ok()?))
            .and_then(|bytes| bytes.checked_add(capacity_bytes(&failure).ok()?))
            .and_then(|bytes| bytes.checked_add(capacity_bytes(&output).ok()?))
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "observed sparse persistent bytes",
            })?;
        let peak_bytes = check_persistent_peak(persistent_bytes, scratch_bytes, limits)?;

        for node in &raw_nodes {
            work.charge(1)?;
            checked_push(
                &mut output,
                Output {
                    pattern: node.terminal_pattern_or_queue_next,
                    length: node.terminal_length,
                },
                "output reservation",
            )?;
            checked_push(&mut failure, 0, "failure reservation")?;
        }
        for node in &raw_nodes {
            work.charge(1)?;
            checked_push(
                &mut offsets,
                u32::try_from(edges.len()).map_err(|_| BuildError::RepresentationLimit {
                    structure: "CSR edge offsets",
                    needed: edges.len(),
                })?,
                "CSR offset reservation",
            )?;
            let mut edge = node.first_edge;
            while edge != UNSET {
                work.charge(1)?;
                let raw = raw_edges[usize::try_from(edge).expect("u32 edge fits usize")];
                checked_push(&mut edges, raw.packed, "CSR edge reservation")?;
                edge = raw.next_sibling;
            }
        }
        checked_push(
            &mut offsets,
            u32::try_from(edges.len()).map_err(|_| BuildError::RepresentationLimit {
                structure: "CSR edge offsets",
                needed: edges.len(),
            })?,
            "terminal CSR offset reservation",
        )?;
        if edges.len() != edge_count {
            return Err(BuildError::InternalInvariant {
                detail: "CSR contains every temporary edge exactly once",
            });
        }

        let mut automaton = SparseReverseAc {
            offsets,
            edges,
            failure,
            output,
        };
        build_failure_links(&mut automaton, &mut raw_nodes, &mut work)?;

        let max_edge_search_checks = max_search_checks(&automaton, &mut work)?;
        let build = BuildAccounting {
            patterns: preflight.patterns,
            pattern_bytes: preflight.pattern_bytes,
            identity_bytes: preflight.identity_bytes,
            identity_capacity_bytes: encoded_patterns.capacity(),
            trie_states_upper_bound: preflight.trie_states_upper_bound,
            trie_states_actual: state_count,
            sparse_edges_upper_bound: preflight.sparse_edges_upper_bound,
            sparse_edges_actual: edge_count,
            build_work: work.used,
            max_pattern_bytes: preflight.max_pattern_bytes,
            min_nonempty_pattern_bytes: preflight.min_nonempty_pattern_bytes,
            has_empty_pattern: preflight.has_empty_pattern,
            max_edge_search_checks,
            scratch_bytes,
            persistent_bytes,
            peak_bytes,
        };
        Ok(Self {
            automaton,
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
        let failure_steps = haystack_len;
        let edge_lookups = haystack_len
            .checked_mul(2)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "sparse edge lookups",
            })?;
        let edge_search_checks = u64::try_from(edge_lookups)
            .ok()
            .and_then(|lookups| {
                lookups.checked_mul(u64::try_from(self.build.max_edge_search_checks).ok()?)
            })
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "sparse edge search checks",
            })?;
        let reducer_steps = haystack_len
            .checked_add(1)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "reverse reducer positions",
            })?;
        let match_events = if self.build.has_empty_pattern {
            reducer_steps
        } else {
            haystack_len
                .checked_div(self.build.min_nonempty_pattern_bytes.ok_or(
                    ReduceError::InternalInvariant {
                        detail: "nonempty language retains a minimum length",
                    },
                )?)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "nonempty event quotient",
                })?
        };
        let count = u64::try_from(match_events).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "match events as u64",
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
        let total_work = u64::try_from(transitions)
            .ok()
            .and_then(|work| work.checked_add(u64::try_from(edge_lookups).ok()?))
            .and_then(|work| work.checked_add(edge_search_checks))
            .and_then(|work| work.checked_add(u64::try_from(failure_steps).ok()?))
            .and_then(|work| work.checked_add(u64::try_from(reducer_steps).ok()?))
            .and_then(|work| work.checked_add(u64::try_from(ring_initializations).ok()?))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "sparse reducer total work",
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
            edge_lookups,
            edge_search_checks,
            failure_steps,
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
        check_reduce_limits(*upper, false, limits)
    }

    fn execute_count(
        &self,
        haystack: &[u8],
        ring: &mut [CountState],
        upper: ReduceUpperBounds,
    ) -> Result<ReduceActualCounters, ReduceError> {
        validate_ring(ring.len(), upper.ring_entries)?;
        let mut state = 0_u32;
        let mut search = SearchCounters::default();
        let mut next_initial = 0_u64;
        let mut current_slot =
            haystack
                .len()
                .checked_rem(ring.len())
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "initial count DP ring slot",
                })?;
        for position in (0..=haystack.len()).rev() {
            if position < haystack.len() {
                state = self.automaton.next(state, haystack[position], &mut search);
            }
            let value = match self.automaton.output(state) {
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
                    let target = checked_dp_target_slot(
                        position,
                        current_slot,
                        length,
                        haystack.len(),
                        self.build.max_pattern_bytes,
                        ring.len(),
                    )?;
                    let count = ring[target].progressed.checked_add(1).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "actual nonempty count",
                        },
                    )?;
                    CountState {
                        initial: count,
                        progressed: count,
                    }
                }
            };
            ring[current_slot] = value;
            next_initial = value.initial;
            if position != 0 {
                current_slot = previous_dp_ring_slot(current_slot, ring.len())?;
            }
        }
        Self::finish_actual(&search, next_initial, Some(next_initial), None, upper)
    }

    fn execute_span(
        &self,
        haystack: &[u8],
        ring: &mut [SpanState],
        upper: ReduceUpperBounds,
    ) -> Result<ReduceActualCounters, ReduceError> {
        validate_ring(ring.len(), upper.ring_entries)?;
        let mut state = 0_u32;
        let mut search = SearchCounters::default();
        let mut next_initial = SpanState::default();
        let mut current_slot =
            haystack
                .len()
                .checked_rem(ring.len())
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "initial span-sum DP ring slot",
                })?;
        for position in (0..=haystack.len()).rev() {
            if position < haystack.len() {
                state = self.automaton.next(state, haystack[position], &mut search);
            }
            let value = match self.automaton.output(state) {
                None => SpanState {
                    initial_count: next_initial.initial_count,
                    progressed_count: next_initial.initial_count,
                    span_sum: next_initial.span_sum,
                },
                Some((_, 0)) => SpanState {
                    initial_count: next_initial.initial_count.checked_add(1).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "actual empty span count",
                        },
                    )?,
                    progressed_count: next_initial.initial_count,
                    span_sum: next_initial.span_sum,
                },
                Some((_, length)) => {
                    let target = checked_dp_target_slot(
                        position,
                        current_slot,
                        length,
                        haystack.len(),
                        self.build.max_pattern_bytes,
                        ring.len(),
                    )?;
                    let future = ring[target];
                    let count = future.progressed_count.checked_add(1).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "actual nonempty span count",
                        },
                    )?;
                    let length =
                        u64::try_from(length).map_err(|_| ReduceError::ArithmeticOverflow {
                            computation: "actual span length as u64",
                        })?;
                    SpanState {
                        initial_count: count,
                        progressed_count: count,
                        span_sum: future.span_sum.checked_add(length).ok_or(
                            ReduceError::ArithmeticOverflow {
                                computation: "actual span sum",
                            },
                        )?,
                    }
                }
            };
            ring[current_slot] = value;
            next_initial = value;
            if position != 0 {
                current_slot = previous_dp_ring_slot(current_slot, ring.len())?;
            }
        }
        Self::finish_actual(
            &search,
            next_initial.initial_count,
            Some(next_initial.initial_count),
            Some(next_initial.span_sum),
            upper,
        )
    }

    fn finish_actual(
        search: &SearchCounters,
        match_events: u64,
        count: Option<u64>,
        span_sum: Option<u64>,
        upper: ReduceUpperBounds,
    ) -> Result<ReduceActualCounters, ReduceError> {
        let total_work = u64::try_from(upper.transitions)
            .ok()
            .and_then(|work| work.checked_add(u64::try_from(search.edge_lookups).ok()?))
            .and_then(|work| work.checked_add(search.edge_search_checks))
            .and_then(|work| work.checked_add(u64::try_from(search.failure_steps).ok()?))
            .and_then(|work| work.checked_add(u64::try_from(upper.reducer_steps).ok()?))
            .and_then(|work| work.checked_add(u64::try_from(upper.ring_initializations).ok()?))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "actual sparse reducer work",
            })?;
        if search.edge_lookups > upper.edge_lookups
            || search.edge_search_checks > upper.edge_search_checks
            || search.failure_steps > upper.failure_steps
            || total_work > upper.total_work
        {
            return Err(ReduceError::InternalInvariant {
                detail: "amortized sparse-AC counters fit their admitted bounds",
            });
        }
        Ok(ReduceActualCounters {
            transitions: upper.transitions,
            edge_lookups: search.edge_lookups,
            edge_search_checks: search.edge_search_checks,
            failure_steps: search.failure_steps,
            reducer_steps: upper.reducer_steps,
            ring_initializations: upper.ring_initializations,
            total_work,
            match_events,
            count,
            span_sum,
            scratch_bytes: upper.scratch_bytes,
            peak_bytes: upper.peak_bytes,
        })
    }
}

fn preflight_build<I, P>(
    patterns: I,
    limits: BuildLimits,
    work: &mut BuildWork,
) -> Result<BuildPreflight, BuildError>
where
    I: IntoIterator<Item = P>,
    P: AsRef<[u8]>,
{
    let mut count = 0_usize;
    let mut pattern_bytes = 0_usize;
    let mut max_pattern_bytes = 0_usize;
    let mut min_nonempty_pattern_bytes = None;
    let mut has_empty_pattern = false;
    for pattern in patterns {
        work.charge(1)?;
        count = count.checked_add(1).ok_or(BuildError::ArithmeticOverflow {
            computation: "pattern count",
        })?;
        if count > limits.max_patterns {
            return Err(BuildError::PatternLimit {
                needed: count,
                limit: limits.max_patterns,
            });
        }
        let bytes = pattern.as_ref();
        work.charge(bytes.len())?;
        pattern_bytes =
            pattern_bytes
                .checked_add(bytes.len())
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "pattern bytes",
                })?;
        if pattern_bytes > limits.max_pattern_bytes {
            return Err(BuildError::PatternBytesLimit {
                needed: pattern_bytes,
                limit: limits.max_pattern_bytes,
            });
        }
        max_pattern_bytes = max_pattern_bytes.max(bytes.len());
        if bytes.is_empty() {
            has_empty_pattern = true;
        } else {
            min_nonempty_pattern_bytes = Some(
                min_nonempty_pattern_bytes.map_or(bytes.len(), |old: usize| old.min(bytes.len())),
            );
        }
    }
    if count == 0 {
        return Err(BuildError::EmptyPatternSet);
    }
    check_pattern_representation(count, max_pattern_bytes)?;
    let identity_bytes = LENGTH_PREFIX_BYTES
        .checked_add(count.checked_mul(LENGTH_PREFIX_BYTES).ok_or(
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
                computation: "trie state upper bound",
            })?;
    if trie_states_upper_bound > limits.max_trie_states {
        return Err(BuildError::TrieStatesLimit {
            needed: trie_states_upper_bound,
            limit: limits.max_trie_states,
        });
    }
    if trie_states_upper_bound > MAX_REPRESENTABLE_STATES {
        return Err(BuildError::RepresentationLimit {
            structure: "packed sparse trie states",
            needed: trie_states_upper_bound,
        });
    }
    let sparse_edges_upper_bound = pattern_bytes;
    if sparse_edges_upper_bound > limits.max_sparse_edges {
        return Err(BuildError::SparseEdgesLimit {
            needed: sparse_edges_upper_bound,
            limit: limits.max_sparse_edges,
        });
    }
    Ok(BuildPreflight {
        patterns: count,
        pattern_bytes,
        identity_bytes,
        trie_states_upper_bound,
        sparse_edges_upper_bound,
        max_pattern_bytes,
        min_nonempty_pattern_bytes,
        has_empty_pattern,
    })
}

fn check_pattern_representation(count: usize, max_pattern_bytes: usize) -> Result<(), BuildError> {
    if count > usize::try_from(u32::MAX).unwrap_or(usize::MAX) {
        return Err(BuildError::RepresentationLimit {
            structure: "pattern identifiers",
            needed: count,
        });
    }
    if max_pattern_bytes > usize::try_from(u32::MAX).unwrap_or(usize::MAX) {
        return Err(BuildError::RepresentationLimit {
            structure: "pattern lengths",
            needed: max_pattern_bytes,
        });
    }
    Ok(())
}

fn encode_patterns<I, P>(
    patterns: I,
    expected: BuildPreflight,
    encoded: &mut Vec<u8>,
    work: &mut BuildWork,
) -> Result<(), BuildError>
where
    I: IntoIterator<Item = P>,
    P: AsRef<[u8]>,
{
    work.charge(LENGTH_PREFIX_BYTES)?;
    checked_extend(
        encoded,
        &u64::try_from(expected.patterns)
            .map_err(|_| BuildError::ArithmeticOverflow {
                computation: "identity pattern count",
            })?
            .to_le_bytes(),
        "identity reservation",
    )?;
    let mut count = 0_usize;
    let mut bytes_seen = 0_usize;
    let mut max_pattern_bytes = 0_usize;
    let mut min_nonempty_pattern_bytes = None;
    let mut has_empty_pattern = false;
    for pattern in patterns {
        work.charge(1)?;
        count = count.checked_add(1).ok_or(BuildError::ArithmeticOverflow {
            computation: "identity pattern count",
        })?;
        let bytes = pattern.as_ref();
        max_pattern_bytes = max_pattern_bytes.max(bytes.len());
        if bytes.is_empty() {
            has_empty_pattern = true;
        } else {
            min_nonempty_pattern_bytes = Some(
                min_nonempty_pattern_bytes.map_or(bytes.len(), |old: usize| old.min(bytes.len())),
            );
        }
        work.charge(bytes.len())?;
        bytes_seen = bytes_seen
            .checked_add(bytes.len())
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "encoded pattern bytes",
            })?;
        let length = u64::try_from(bytes.len()).map_err(|_| BuildError::ArithmeticOverflow {
            computation: "identity pattern length",
        })?;
        work.charge(LENGTH_PREFIX_BYTES)?;
        checked_extend(encoded, &length.to_le_bytes(), "identity reservation")?;
        checked_extend(encoded, bytes, "identity reservation")?;
    }
    if count != expected.patterns
        || bytes_seen != expected.pattern_bytes
        || max_pattern_bytes != expected.max_pattern_bytes
        || min_nonempty_pattern_bytes != expected.min_nonempty_pattern_bytes
        || has_empty_pattern != expected.has_empty_pattern
        || encoded.len() != expected.identity_bytes
    {
        return Err(BuildError::InputChanged { pass: "identity" });
    }
    Ok(())
}

fn insert_patterns<I, P>(
    patterns: I,
    expected: BuildPreflight,
    encoded: &[u8],
    nodes: &mut Vec<RawNode>,
    edges: &mut Vec<RawEdge>,
    work: &mut BuildWork,
) -> Result<(), BuildError>
where
    I: IntoIterator<Item = P>,
    P: AsRef<[u8]>,
{
    let mut count = 0_usize;
    let mut identity_offset = LENGTH_PREFIX_BYTES;
    for pattern in patterns {
        work.charge(1)?;
        let bytes = pattern.as_ref();
        work.charge(LENGTH_PREFIX_BYTES)?;
        let length_end = identity_offset.checked_add(LENGTH_PREFIX_BYTES).ok_or(
            BuildError::ArithmeticOverflow {
                computation: "identity validation length",
            },
        )?;
        let stored_length = encoded
            .get(identity_offset..length_end)
            .ok_or(BuildError::InputChanged { pass: "trie" })?;
        let stored_length = usize::try_from(u64::from_le_bytes(
            stored_length
                .try_into()
                .map_err(|_| BuildError::InputChanged { pass: "trie" })?,
        ))
        .map_err(|_| BuildError::InputChanged { pass: "trie" })?;
        identity_offset = length_end;
        let bytes_end =
            identity_offset
                .checked_add(stored_length)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "identity validation bytes",
                })?;
        let stored = encoded
            .get(identity_offset..bytes_end)
            .ok_or(BuildError::InputChanged { pass: "trie" })?;
        if stored_length != bytes.len() {
            return Err(BuildError::InputChanged { pass: "trie" });
        }
        for (&left, &right) in stored.iter().zip(bytes) {
            work.charge(1)?;
            if left != right {
                return Err(BuildError::InputChanged { pass: "trie" });
            }
        }
        identity_offset = bytes_end;
        let pattern_id = u32::try_from(count).map_err(|_| BuildError::RepresentationLimit {
            structure: "pattern identifiers",
            needed: count,
        })?;
        let length = u32::try_from(bytes.len()).map_err(|_| BuildError::RepresentationLimit {
            structure: "pattern lengths",
            needed: bytes.len(),
        })?;
        let mut state = 0_u32;
        for &byte in bytes.iter().rev() {
            work.charge(1)?;
            state = child_or_insert(state, byte, nodes, edges, work)?;
        }
        work.charge(1)?;
        let terminal = &mut nodes[usize::try_from(state).expect("u32 state fits usize")];
        if pattern_id < terminal.terminal_pattern_or_queue_next {
            terminal.terminal_pattern_or_queue_next = pattern_id;
            terminal.terminal_length = length;
        }
        count = count.checked_add(1).ok_or(BuildError::ArithmeticOverflow {
            computation: "inserted pattern count",
        })?;
    }
    if count != expected.patterns || identity_offset != encoded.len() {
        return Err(BuildError::InputChanged { pass: "trie" });
    }
    Ok(())
}

fn child_or_insert(
    state: u32,
    byte: u8,
    nodes: &mut Vec<RawNode>,
    edges: &mut Vec<RawEdge>,
    work: &mut BuildWork,
) -> Result<u32, BuildError> {
    let state_index = usize::try_from(state).expect("u32 state fits usize");
    let mut previous = UNSET;
    let mut current = nodes[state_index].first_edge;
    while current != UNSET {
        work.charge(1)?;
        let edge_index = usize::try_from(current).expect("u32 edge fits usize");
        let existing = edge_byte(edges[edge_index].packed);
        match existing.cmp(&byte) {
            Ordering::Less => {
                previous = current;
                current = edges[edge_index].next_sibling;
            }
            Ordering::Equal => return Ok(edge_target(edges[edge_index].packed)),
            Ordering::Greater => break,
        }
    }
    work.charge(2)?;
    let target = u32::try_from(nodes.len()).map_err(|_| BuildError::RepresentationLimit {
        structure: "packed sparse trie states",
        needed: nodes.len(),
    })?;
    if target > TARGET_MASK {
        let needed = nodes
            .len()
            .checked_add(1)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "packed trie state refusal",
            })?;
        return Err(BuildError::RepresentationLimit {
            structure: "packed sparse trie states",
            needed,
        });
    }
    let edge_id = u32::try_from(edges.len()).map_err(|_| BuildError::RepresentationLimit {
        structure: "temporary sparse edges",
        needed: edges.len(),
    })?;
    checked_push(nodes, RawNode::EMPTY, "temporary trie node reservation")?;
    checked_push(
        edges,
        RawEdge {
            packed: pack_edge(byte, target),
            next_sibling: current,
        },
        "temporary trie edge reservation",
    )?;
    if previous == UNSET {
        nodes[state_index].first_edge = edge_id;
    } else {
        edges[usize::try_from(previous).expect("u32 edge fits usize")].next_sibling = edge_id;
    }
    Ok(target)
}

fn build_failure_links(
    automaton: &mut SparseReverseAc,
    raw_nodes: &mut [RawNode],
    work: &mut BuildWork,
) -> Result<(), BuildError> {
    let mut head = UNSET;
    let mut tail = UNSET;
    let root_start = usize::try_from(automaton.offsets[0]).expect("u32 offset fits usize");
    let root_end = usize::try_from(automaton.offsets[1]).expect("u32 offset fits usize");
    for edge_index in root_start..root_end {
        work.charge(1)?;
        let child = edge_target(automaton.edges[edge_index]);
        enqueue(raw_nodes, &mut head, &mut tail, child);
    }
    while let Some(state) = dequeue(raw_nodes, &mut head, &mut tail)? {
        work.charge(1)?;
        let state_index = usize::try_from(state).expect("u32 state fits usize");
        let inherited = automaton.output
            [usize::try_from(automaton.failure[state_index]).expect("u32 state fits usize")];
        automaton.output[state_index] = automaton.output[state_index].min_priority(inherited);
        let start = usize::try_from(automaton.offsets[state_index]).expect("u32 offset fits usize");
        let next_state = state_index
            .checked_add(1)
            .expect("a represented state has a following CSR offset");
        let end = usize::try_from(automaton.offsets[next_state]).expect("u32 offset fits usize");
        for edge_index in start..end {
            work.charge(1)?;
            let packed = automaton.edges[edge_index];
            let byte = edge_byte(packed);
            let child = edge_target(packed);
            let mut candidate = automaton.failure[state_index];
            let failure = loop {
                if let Some(found) = automaton.edge_with_work(candidate, byte, work)? {
                    break found;
                }
                if candidate == 0 {
                    break 0;
                }
                work.charge(1)?;
                candidate =
                    automaton.failure[usize::try_from(candidate).expect("u32 state fits usize")];
            };
            automaton.failure[usize::try_from(child).expect("u32 state fits usize")] = failure;
            enqueue(raw_nodes, &mut head, &mut tail, child);
        }
    }
    Ok(())
}

fn enqueue(nodes: &mut [RawNode], head: &mut u32, tail: &mut u32, state: u32) {
    let state_index = usize::try_from(state).expect("u32 state fits usize");
    nodes[state_index].terminal_pattern_or_queue_next = UNSET;
    if *tail == UNSET {
        *head = state;
    } else {
        nodes[usize::try_from(*tail).expect("u32 state fits usize")]
            .terminal_pattern_or_queue_next = state;
    }
    *tail = state;
}

fn dequeue(nodes: &[RawNode], head: &mut u32, tail: &mut u32) -> Result<Option<u32>, BuildError> {
    if *head == UNSET {
        if *tail != UNSET {
            return Err(BuildError::InternalInvariant {
                detail: "intrusive failure queue has consistent empty ends",
            });
        }
        return Ok(None);
    }
    let state = *head;
    *head =
        nodes[usize::try_from(state).expect("u32 state fits usize")].terminal_pattern_or_queue_next;
    if *head == UNSET {
        *tail = UNSET;
    }
    Ok(Some(state))
}

fn max_search_checks(
    automaton: &SparseReverseAc,
    work: &mut BuildWork,
) -> Result<usize, BuildError> {
    let mut maximum = 0_usize;
    for state in 0..automaton.state_count() {
        work.charge(1)?;
        let start = usize::try_from(automaton.offsets[state]).expect("u32 offset fits usize");
        let next_state = state
            .checked_add(1)
            .expect("a represented state has a following CSR offset");
        let end = usize::try_from(automaton.offsets[next_state]).expect("u32 offset fits usize");
        let degree = end
            .checked_sub(start)
            .ok_or(BuildError::InternalInvariant {
                detail: "CSR offsets are monotonic",
            })?;
        let checks = if degree == 0 {
            0
        } else {
            usize::try_from(
                usize::BITS
                    .checked_sub(degree.leading_zeros())
                    .expect("a nonzero degree has a positive bit width"),
            )
            .expect("bit width fits usize")
        };
        maximum = maximum.max(checks);
    }
    Ok(maximum)
}

fn check_scratch(needed: usize, limits: BuildLimits) -> Result<(), BuildError> {
    if needed > limits.max_scratch_bytes {
        return Err(BuildError::ScratchLimit {
            needed,
            limit: limits.max_scratch_bytes,
        });
    }
    Ok(())
}

fn check_persistent_peak(
    persistent: usize,
    scratch: usize,
    limits: BuildLimits,
) -> Result<usize, BuildError> {
    if persistent > limits.max_persistent_bytes {
        return Err(BuildError::PersistentLimit {
            needed: persistent,
            limit: limits.max_persistent_bytes,
        });
    }
    let peak = persistent
        .checked_add(scratch)
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "build peak bytes",
        })?;
    if peak > limits.max_peak_bytes {
        return Err(BuildError::PeakLimit {
            needed: peak,
            limit: limits.max_peak_bytes,
        });
    }
    Ok(peak)
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
    if upper.edge_lookups > limits.max_edge_lookups {
        return Err(ReduceError::EdgeLookupLimit {
            needed: upper.edge_lookups,
            limit: limits.max_edge_lookups,
        });
    }
    if upper.edge_search_checks > limits.max_edge_search_checks {
        return Err(ReduceError::EdgeSearchChecksLimit {
            needed: upper.edge_search_checks,
            limit: limits.max_edge_search_checks,
        });
    }
    if upper.failure_steps > limits.max_failure_steps {
        return Err(ReduceError::FailureStepsLimit {
            needed: upper.failure_steps,
            limit: limits.max_failure_steps,
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

#[inline]
fn pack_edge(byte: u8, target: u32) -> u32 {
    (u32::from(byte) << 24) | target
}

#[inline]
const fn edge_byte(packed: u32) -> u8 {
    packed.to_be_bytes()[0]
}

#[inline]
const fn edge_target(packed: u32) -> u32 {
    packed & TARGET_MASK
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

fn checked_push<T>(values: &mut Vec<T>, value: T, detail: &'static str) -> Result<(), BuildError> {
    if values.len() >= values.capacity() {
        return Err(BuildError::InternalInvariant { detail });
    }
    values.push(value);
    Ok(())
}

fn checked_extend(
    values: &mut Vec<u8>,
    bytes: &[u8],
    detail: &'static str,
) -> Result<(), BuildError> {
    let end = values
        .len()
        .checked_add(bytes.len())
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "vector extension length",
        })?;
    if end > values.capacity() {
        return Err(BuildError::InternalInvariant { detail });
    }
    values.extend_from_slice(bytes);
    Ok(())
}

fn validate_ring(actual: usize, expected: usize) -> Result<(), ReduceError> {
    if actual == 0 || actual != expected {
        return Err(ReduceError::InternalInvariant {
            detail: "DP ring has its admitted nonzero length",
        });
    }
    Ok(())
}

fn checked_dp_target_slot(
    position: usize,
    current_slot: usize,
    length: usize,
    haystack_len: usize,
    max_pattern_len: usize,
    ring_len: usize,
) -> Result<usize, ReduceError> {
    if current_slot >= ring_len || length == 0 || length > max_pattern_len || length >= ring_len {
        return Err(ReduceError::InternalInvariant {
            detail: "automaton output fits the admitted DP ring",
        });
    }
    let target = position
        .checked_add(length)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "DP target position",
        })?;
    if target > haystack_len {
        return Err(ReduceError::InternalInvariant {
            detail: "automaton output ends within the haystack",
        });
    }
    let unwrapped = current_slot
        .checked_add(length)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "DP target ring slot",
        })?;
    Ok(if unwrapped >= ring_len {
        unwrapped
            .checked_sub(ring_len)
            .expect("wrapped DP slot is at least one ring length")
    } else {
        unwrapped
    })
}

fn previous_dp_ring_slot(current_slot: usize, ring_len: usize) -> Result<usize, ReduceError> {
    if current_slot >= ring_len {
        return Err(ReduceError::InternalInvariant {
            detail: "current DP slot fits the ring",
        });
    }
    Ok(if current_slot == 0 {
        ring_len
            .checked_sub(1)
            .ok_or(ReduceError::InternalInvariant {
                detail: "DP ring is nonempty",
            })?
    } else {
        current_slot
            .checked_sub(1)
            .expect("nonzero DP slot has a predecessor")
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        reason = "small fixtures and exact one-below adversaries use values whose positivity and capacity are established in each test"
    )]

    use core::mem::size_of;
    use std::fmt::Write as _;

    use regex::bytes::{Regex, RegexBuilder};

    use super::{
        BuildError, BuildLimits, ReduceError, ReduceLimits, SparseOrderedLiteralCountPlan,
        SparseOrderedLiteralSpanSumPlan,
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

    fn sequence(plan: &SparseOrderedLiteralCountPlan, haystack: &[u8]) -> Vec<(u32, usize, usize)> {
        let mut choices = vec![None; haystack.len() + 1];
        let mut state = 0_u32;
        let mut counters = super::SearchCounters::default();
        for position in (0..=haystack.len()).rev() {
            if position < haystack.len() {
                state = plan
                    .core
                    .automaton
                    .next(state, haystack[position], &mut counters);
            }
            choices[position] = plan.core.automaton.output(state);
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
                start = position + 1;
                continue;
            }
            let end = position + length;
            matches.push((pattern, position, end));
            start = end;
            last_end = Some(end);
        }
        matches
    }

    fn choice_at_start(
        plan: &SparseOrderedLiteralCountPlan,
        haystack: &[u8],
    ) -> Option<(u32, usize)> {
        let mut state = 0_u32;
        let mut counters = super::SearchCounters::default();
        for &byte in haystack.iter().rev() {
            state = plan.core.automaton.next(state, byte, &mut counters);
        }
        plan.core.automaton.output(state)
    }

    #[test]
    fn prefixes_duplicates_failure_chains_empty_and_arbitrary_bytes_match_regex() {
        let cases: &[(&[&[u8]], &[u8])] = &[
            (&[b"ab", b"a", b"ab"], b"ababa"),
            (&[b"a", b"ab", b"a"], b"ababa"),
            (&[b"abab", b"bab", b"ab", b"b"], b"xababab"),
            (&[b"", b"aa", b"a"], b"aaa"),
            (&[b"aa", b"", b"a"], b"aaa"),
            (&[b"\xFF\x00", b"\xFF", b"\x80"], b"\xFF\x00\x80\xFF"),
        ];
        for &(patterns, haystack) in cases {
            let owned = patterns
                .iter()
                .map(|pattern| pattern.to_vec())
                .collect::<Vec<_>>();
            let expected = regex(&owned)
                .find_iter(haystack)
                .map(|matched| (matched.start(), matched.end()))
                .collect::<Vec<_>>();
            let plan = SparseOrderedLiteralCountPlan::build(
                patterns.iter().copied(),
                BuildLimits::unlimited(),
            )
            .unwrap();
            let actual = sequence(&plan, haystack)
                .into_iter()
                .map(|(_, start, end)| (start, end))
                .collect::<Vec<_>>();
            assert_eq!(
                actual, expected,
                "patterns={patterns:?}, haystack={haystack:?}"
            );
            assert_eq!(
                plan.count(haystack, ReduceLimits::unlimited())
                    .unwrap()
                    .count,
                u64::try_from(expected.len()).unwrap()
            );
            let expected_span_sum = expected
                .iter()
                .map(|(start, end)| u64::try_from(end - start).unwrap())
                .sum::<u64>();
            let span = SparseOrderedLiteralSpanSumPlan::build(
                patterns.iter().copied(),
                BuildLimits::unlimited(),
            )
            .unwrap();
            assert_eq!(
                span.span_sum(haystack, ReduceLimits::unlimited())
                    .unwrap()
                    .span_sum,
                expected_span_sum
            );
        }
    }

    #[test]
    fn source_index_priority_covers_terminal_and_failure_outputs() {
        let long_first = SparseOrderedLiteralCountPlan::build(
            [b"ab".as_slice(), b"a".as_slice()],
            BuildLimits::unlimited(),
        )
        .unwrap();
        assert_eq!(choice_at_start(&long_first, b"ab"), Some((0, 2)));

        let short_first = SparseOrderedLiteralCountPlan::build(
            [b"a".as_slice(), b"ab".as_slice()],
            BuildLimits::unlimited(),
        )
        .unwrap();
        assert_eq!(choice_at_start(&short_first, b"ab"), Some((0, 1)));

        let duplicates = SparseOrderedLiteralCountPlan::build(
            [b"abc".as_slice(), b"abc".as_slice()],
            BuildLimits::unlimited(),
        )
        .unwrap();
        assert_eq!(choice_at_start(&duplicates, b"abc"), Some((0, 3)));
    }

    #[test]
    fn cloneable_borrowed_iterator_needs_no_nested_owned_pattern_vector() {
        let patterns = [b"alpha".as_slice(), b"beta".as_slice(), b"a".as_slice()];
        let iterable = patterns.iter().copied();
        let count =
            SparseOrderedLiteralCountPlan::build(iterable.clone(), BuildLimits::unlimited())
                .unwrap();
        let span =
            SparseOrderedLiteralSpanSumPlan::build(iterable, BuildLimits::unlimited()).unwrap();
        assert_eq!(
            count
                .count(b"alpha beta alpha", ReduceLimits::unlimited())
                .unwrap()
                .count,
            3
        );
        assert_eq!(
            span.span_sum(b"alpha beta alpha", ReduceLimits::unlimited())
                .unwrap()
                .span_sum,
            14
        );
    }

    fn generated_patterns(count: usize) -> Vec<[u8; 8]> {
        (0..count)
            .map(|index| {
                let value = u64::try_from(index).unwrap().wrapping_mul(0x9E37_79B9);
                value.to_le_bytes()
            })
            .collect()
    }

    #[test]
    fn sparse_storage_and_work_scale_linearly_without_dense_alphabet_rows() {
        let small_patterns = generated_patterns(1_024);
        let large_patterns = generated_patterns(2_048);
        let small =
            SparseOrderedLiteralCountPlan::build(small_patterns.iter(), BuildLimits::unlimited())
                .unwrap();
        let large =
            SparseOrderedLiteralCountPlan::build(large_patterns.iter(), BuildLimits::unlimited())
                .unwrap();
        let a = small.build_accounting();
        let b = large.build_accounting();
        assert_eq!(a.sparse_edges_actual + 1, a.trie_states_actual);
        assert_eq!(b.sparse_edges_actual + 1, b.trie_states_actual);
        assert!(b.persistent_bytes < a.persistent_bytes * 3);
        assert!(b.build_work < a.build_work * 3);
        assert!(b.max_edge_search_checks <= 9);
        let dense_transition_bytes = b.trie_states_actual * 256 * size_of::<u32>();
        assert!(b.persistent_bytes * 16 < dense_transition_bytes);
    }

    #[test]
    fn root_fanout_binary_search_bound_covers_power_of_two_edges() {
        for (fanout, expected_checks) in [(127_usize, 7), (128, 8), (255, 8), (256, 9)] {
            let patterns = (0..fanout)
                .map(|byte| [b'x', u8::try_from(byte).unwrap()])
                .collect::<Vec<_>>();
            let plan =
                SparseOrderedLiteralCountPlan::build(patterns.iter(), BuildLimits::unlimited())
                    .unwrap();
            assert_eq!(
                plan.build_accounting().max_edge_search_checks,
                expected_checks,
                "fanout={fanout}"
            );
            let result = plan
                .count(b"xxx\x00x\x7F\xFF", ReduceLimits::unlimited())
                .unwrap();
            assert!(
                result.accounting.actual.edge_search_checks
                    <= result.accounting.upper_bounds.edge_search_checks
            );
            assert!(
                result.accounting.actual.total_work <= result.accounting.upper_bounds.total_work
            );
        }
    }

    fn exact_build_limits(plan: &SparseOrderedLiteralCountPlan) -> BuildLimits {
        let build = plan.build_accounting();
        BuildLimits {
            max_patterns: build.patterns,
            max_pattern_bytes: build.pattern_bytes,
            max_identity_bytes: build.identity_bytes,
            max_trie_states: build.trie_states_upper_bound,
            max_sparse_edges: build.sparse_edges_upper_bound,
            max_build_work: build.build_work,
            max_scratch_bytes: build.scratch_bytes,
            max_persistent_bytes: build.persistent_bytes,
            max_peak_bytes: build.peak_bytes,
        }
    }

    #[test]
    fn every_build_dimension_has_exact_limit_and_one_below() {
        let patterns = [
            b"".as_slice(),
            b"ababa".as_slice(),
            b"aba".as_slice(),
            b"\xFF\x00".as_slice(),
        ];
        let baseline = SparseOrderedLiteralCountPlan::build(
            patterns.iter().copied(),
            BuildLimits::unlimited(),
        )
        .unwrap();
        let exact = exact_build_limits(&baseline);
        SparseOrderedLiteralCountPlan::build(patterns.iter().copied(), exact).unwrap();
        macro_rules! assert_one_below {
            ($field:ident, $variant:ident) => {{
                let limit = exact.$field.checked_sub(1).unwrap();
                let error = SparseOrderedLiteralCountPlan::build(
                    patterns.iter().copied(),
                    BuildLimits {
                        $field: limit,
                        ..exact
                    },
                )
                .unwrap_err();
                assert!(
                    matches!(error, BuildError::$variant { limit: actual, .. } if actual == limit),
                    "one-below {} returned {error:?}",
                    stringify!($field)
                );
            }};
        }
        assert_one_below!(max_patterns, PatternLimit);
        assert_one_below!(max_pattern_bytes, PatternBytesLimit);
        assert_one_below!(max_identity_bytes, IdentityBytesLimit);
        assert_one_below!(max_trie_states, TrieStatesLimit);
        assert_one_below!(max_sparse_edges, SparseEdgesLimit);
        assert_one_below!(max_build_work, WorkLimit);
        assert_one_below!(max_scratch_bytes, ScratchLimit);
        assert_one_below!(max_persistent_bytes, PersistentLimit);
        assert_one_below!(max_peak_bytes, PeakLimit);
    }

    fn exact_reduce_limits(upper: super::ReduceUpperBounds, max_span_sum: u64) -> ReduceLimits {
        ReduceLimits {
            max_transitions: upper.transitions,
            max_edge_lookups: upper.edge_lookups,
            max_edge_search_checks: upper.edge_search_checks,
            max_failure_steps: upper.failure_steps,
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
        reason = "all sparse reducer limits remain explicit in the exact/one-below table"
    )]
    fn every_reduce_dimension_has_exact_limit_and_one_below() {
        let patterns = [b"ababa".as_slice(), b"aba".as_slice(), b"a".as_slice()];
        let haystack = b"xxababababax";
        let count = SparseOrderedLiteralCountPlan::build(
            patterns.iter().copied(),
            BuildLimits::unlimited(),
        )
        .unwrap();
        let span = SparseOrderedLiteralSpanSumPlan::build(
            patterns.iter().copied(),
            BuildLimits::unlimited(),
        )
        .unwrap();
        let counted = count.count(haystack, ReduceLimits::unlimited()).unwrap();
        let summed = span.span_sum(haystack, ReduceLimits::unlimited()).unwrap();
        let count_exact = exact_reduce_limits(counted.accounting.upper_bounds, u64::MAX);
        let span_exact = exact_reduce_limits(
            summed.accounting.upper_bounds,
            summed.accounting.upper_bounds.span_sum,
        );
        count.count(haystack, count_exact).unwrap();
        span.span_sum(haystack, span_exact).unwrap();

        assert!(matches!(
            count.count(
                haystack,
                ReduceLimits {
                    max_transitions: count_exact.max_transitions - 1,
                    ..count_exact
                }
            ),
            Err(ReduceError::TransitionLimit { .. })
        ));
        assert!(matches!(
            count.count(
                haystack,
                ReduceLimits {
                    max_edge_lookups: count_exact.max_edge_lookups - 1,
                    ..count_exact
                }
            ),
            Err(ReduceError::EdgeLookupLimit { .. })
        ));
        assert!(matches!(
            count.count(
                haystack,
                ReduceLimits {
                    max_edge_search_checks: count_exact.max_edge_search_checks - 1,
                    ..count_exact
                }
            ),
            Err(ReduceError::EdgeSearchChecksLimit { .. })
        ));
        assert!(matches!(
            count.count(
                haystack,
                ReduceLimits {
                    max_failure_steps: count_exact.max_failure_steps - 1,
                    ..count_exact
                }
            ),
            Err(ReduceError::FailureStepsLimit { .. })
        ));
        assert!(matches!(
            count.count(
                haystack,
                ReduceLimits {
                    max_match_events: count_exact.max_match_events - 1,
                    ..count_exact
                }
            ),
            Err(ReduceError::MatchEventsLimit { .. })
        ));
        assert!(matches!(
            count.count(
                haystack,
                ReduceLimits {
                    max_count: count_exact.max_count - 1,
                    ..count_exact
                }
            ),
            Err(ReduceError::CountLimit { .. })
        ));
        assert!(matches!(
            span.span_sum(
                haystack,
                ReduceLimits {
                    max_span_sum: span_exact.max_span_sum - 1,
                    ..span_exact
                }
            ),
            Err(ReduceError::SpanSumLimit { .. })
        ));
        assert!(matches!(
            count.count(
                haystack,
                ReduceLimits {
                    max_reducer_steps: count_exact.max_reducer_steps - 1,
                    ..count_exact
                }
            ),
            Err(ReduceError::ReducerStepsLimit { .. })
        ));
        assert!(matches!(
            count.count(
                haystack,
                ReduceLimits {
                    max_ring_initializations: count_exact.max_ring_initializations - 1,
                    ..count_exact
                }
            ),
            Err(ReduceError::RingInitializationLimit { .. })
        ));
        assert!(matches!(
            count.count(
                haystack,
                ReduceLimits {
                    max_total_work: count_exact.max_total_work - 1,
                    ..count_exact
                }
            ),
            Err(ReduceError::TotalWorkLimit { .. })
        ));
        assert!(matches!(
            count.count(
                haystack,
                ReduceLimits {
                    max_scratch_bytes: count_exact.max_scratch_bytes - 1,
                    ..count_exact
                }
            ),
            Err(ReduceError::ScratchLimit { .. })
        ));
        assert!(matches!(
            count.count(
                haystack,
                ReduceLimits {
                    max_peak_bytes: count_exact.max_peak_bytes - 1,
                    ..count_exact
                }
            ),
            Err(ReduceError::PeakLimit { .. })
        ));
    }

    #[test]
    fn upper_bound_covers_failure_chain_and_manual_binary_search_counters() {
        let patterns = [
            b"aaaaaaaaab".as_slice(),
            b"aaaaaaaab".as_slice(),
            b"aaaaaaab".as_slice(),
            b"baaaaaaa".as_slice(),
        ];
        let plan = SparseOrderedLiteralCountPlan::build(
            patterns.iter().copied(),
            BuildLimits::unlimited(),
        )
        .unwrap();
        let result = plan
            .count(b"aaaaaaaaaaaaaaaaaaaa", ReduceLimits::unlimited())
            .unwrap();
        let actual = result.accounting.actual;
        let upper = result.accounting.upper_bounds;
        assert!(actual.edge_lookups <= upper.edge_lookups);
        assert!(actual.edge_search_checks <= upper.edge_search_checks);
        assert!(actual.failure_steps <= upper.failure_steps);
        assert!(actual.total_work <= upper.total_work);
        assert_eq!(upper.edge_lookups, upper.haystack_bytes * 2);
    }
}
