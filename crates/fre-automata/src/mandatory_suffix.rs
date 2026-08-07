//! Bounded graph-only proof of one exact mandatory byte suffix.
//!
//! The analysis starts at every start-reachable accepting state and walks the
//! Thompson graph backwards. Zero-width closure is completed before each byte
//! layer, conservatively treating every validated assertion edge like epsilon.
//! Dropping assertion predicates forms a language superset: it can hide a
//! useful common suffix, but cannot invent one. A layer is retained only when
//! every productive incoming consuming edge in that relaxed graph is the same
//! singleton byte. Consequently, the published byte string occurs immediately
//! before acceptance on every semantic accepting path.
//!
//! The candidate is tied to the exact [`RawPlan`] supplied here; a consumer
//! must build and search that same immutable plan.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "checked resource arithmetic and validated CSR/index invariants guard the remaining bounded indexing"
)]

use crate::{EdgeKind, RawPlan, StateRole};

/// Stable identity for the proof and its accounting convention.
pub const MANDATORY_SUFFIX_ACCOUNTING_ID: &str = "fre.automata.mandatory-suffix.v2";
/// Stable identity for the optional universal-corridor proof and accounting.
pub const MANDATORY_SUFFIX_UNIVERSAL_FINITE_CORRIDOR_ACCOUNTING_ID: &str =
    "fre.automata.mandatory-suffix-universal-finite-corridor.v1";
/// Maximum exact suffix bytes representable inline by this implementation.
pub const MAX_MANDATORY_SUFFIX_BYTES: usize = 32;
/// Hard maximum prefix depth inspected by the optional universal corridor.
pub const MAX_MANDATORY_SUFFIX_UNIVERSAL_CORRIDOR_PREFIX_BYTES: usize = 65_536;
/// Default number of exact suffix bytes requested.
pub const DEFAULT_MANDATORY_SUFFIX_MAX_BYTES: usize = 16;
/// Default maximum abstract work for one optional analysis.
pub const DEFAULT_MANDATORY_SUFFIX_MAX_WORK: u64 = 2_000_000;
/// Default maximum cumulative logical scratch-allocation items.
pub const DEFAULT_MANDATORY_SUFFIX_MAX_ALLOCATION_ITEMS: usize = 262_144;
/// Default maximum number of fallible scratch reservation attempts.
pub const DEFAULT_MANDATORY_SUFFIX_MAX_ALLOCATION_ATTEMPTS: usize = 32;

/// Independent hard ceilings for one optional exact-suffix proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_field_names,
    reason = "explicit max prefixes distinguish independent hard analysis ceilings"
)]
pub struct MandatorySuffixAnalysisLimits {
    /// Maximum suffix bytes retained, capped by [`MAX_MANDATORY_SUFFIX_BYTES`].
    pub max_suffix_bytes: usize,
    /// Exact abstract graph operations.
    pub max_work: u64,
    /// Cumulative logical vector slots requested by the analysis.
    pub max_allocation_items: usize,
    /// Fallible scratch reservation calls admitted by the analysis.
    pub max_allocation_attempts: usize,
}

impl Default for MandatorySuffixAnalysisLimits {
    fn default() -> Self {
        Self {
            max_suffix_bytes: DEFAULT_MANDATORY_SUFFIX_MAX_BYTES,
            max_work: DEFAULT_MANDATORY_SUFFIX_MAX_WORK,
            max_allocation_items: DEFAULT_MANDATORY_SUFFIX_MAX_ALLOCATION_ITEMS,
            max_allocation_attempts: DEFAULT_MANDATORY_SUFFIX_MAX_ALLOCATION_ATTEMPTS,
        }
    }
}

/// A separately limited resource consumed by mandatory-suffix analysis.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MandatorySuffixResource {
    /// Requested inline suffix length.
    SuffixBytes,
    /// Abstract graph-analysis work.
    Work,
    /// Cumulative logical vector slots requested.
    AllocationItems,
    /// Fallible scratch reservation calls.
    AllocationAttempts,
}

/// Static malformed-graph reason found before a proof was published.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MandatorySuffixGraphIssue {
    /// The state table is empty.
    Empty,
    /// A state or edge table cannot be represented in the raw plan's `u32` space.
    IndexSpaceExceeded,
    /// The declared start state is outside the state table.
    StartOutOfRange,
    /// The graph contains no accepting state.
    MissingAccept,
    /// The CSR offset table has the wrong length or terminal offset.
    OffsetShape,
    /// Parallel edge tables have different lengths.
    EdgeTableShape,
    /// CSR offsets are reversed or outside the edge tables.
    EdgeOffset,
    /// An edge target is outside the state table.
    EdgeTargetOutOfRange,
    /// A state role has an incompatible number or kind of outgoing edges.
    StateRoleEdges,
    /// An edge has a non-canonical byte payload.
    EdgePayload,
    /// A future state or edge kind is not supported by this proof.
    UnsupportedGraphKind,
}

/// Transactional reason why no exact suffix was published.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MandatorySuffixDeclineReason {
    /// The raw graph is malformed for this standalone analysis.
    MalformedGraph(MandatorySuffixGraphIssue),
    /// One declared hard ceiling was exceeded.
    Resource {
        /// Limited resource.
        resource: MandatorySuffixResource,
        /// First value that would exceed the limit.
        needed: u64,
        /// Declared limit.
        limit: u64,
    },
    /// A fallible scratch reservation failed.
    Allocation {
        /// Named allocation site.
        structure: &'static str,
        /// Additional logical elements requested.
        additional: usize,
    },
    /// Checked address or resource arithmetic overflowed.
    ArithmeticOverflow {
        /// Named computation.
        computation: &'static str,
    },
    /// Legacy assertion refusal retained for API compatibility.
    ///
    /// The current proof conservatively relaxes every validated assertion and
    /// does not emit this reason.
    AssertionsPresent,
    /// No accepting state is reachable from the declared start.
    EmptyLanguage,
    /// An accepting path can consume no byte at the suffix boundary.
    NullableLanguage,
    /// The first backward byte layer is not one common singleton byte.
    AmbiguousSuffixLayer,
    /// A valid graph violated an internal proof invariant.
    InternalInvariant {
        /// Named invariant.
        detail: &'static str,
    },
}

/// Why a completed proof stopped after retaining its nonempty suffix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MandatorySuffixStopReason {
    /// The requested inline byte bound was reached.
    MaximumBytes,
    /// A shorter accepting path reached the graph start before another byte.
    StartBoundary,
    /// The next byte layer contained a range or more than one byte value.
    AmbiguousLayer,
}

/// Exact work and allocation facts completed before success or decline.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MandatorySuffixAnalysisStats {
    accounting_id: &'static str,
    work: u64,
    allocation_items: usize,
    allocation_attempts: usize,
    states: usize,
    edges: usize,
    reachable_states: usize,
    reachable_accepting_states: usize,
    completed_suffix_layers: usize,
    candidates: usize,
    retained_bytes: usize,
    assertion_edges: usize,
}

impl MandatorySuffixAnalysisStats {
    /// Stable identity of the algorithm and accounting convention.
    #[must_use]
    pub const fn accounting_id(self) -> &'static str {
        self.accounting_id
    }

    /// Exact abstract work completed.
    ///
    /// The convention charges one unit per validated or traversed graph item,
    /// initialized/reset logical vector slot, bounded queue insertion/removal,
    /// derived layer, and copied candidate byte. Fixed scalar bookkeeping is
    /// free. The accounting identifier versions this convention.
    #[must_use]
    pub const fn work(self) -> u64 {
        self.work
    }

    /// Cumulative logical vector slots successfully requested.
    #[must_use]
    pub const fn allocation_items(self) -> usize {
        self.allocation_items
    }

    /// Fallible scratch reservation calls completed or attempted.
    #[must_use]
    pub const fn allocation_attempts(self) -> usize {
        self.allocation_attempts
    }

    /// Raw graph states observed after shape validation.
    #[must_use]
    pub const fn states(self) -> usize {
        self.states
    }

    /// Raw graph edges observed after shape validation.
    #[must_use]
    pub const fn edges(self) -> usize {
        self.edges
    }

    /// States reachable structurally from the declared start.
    #[must_use]
    pub const fn reachable_states(self) -> usize {
        self.reachable_states
    }

    /// Accepting states reachable from the declared start.
    #[must_use]
    pub const fn reachable_accepting_states(self) -> usize {
        self.reachable_accepting_states
    }

    /// Fully proved singleton byte layers.
    #[must_use]
    pub const fn completed_suffix_layers(self) -> usize {
        self.completed_suffix_layers
    }

    /// Inline candidates retained by a completed analysis (zero or one).
    #[must_use]
    pub const fn candidates(self) -> usize {
        self.candidates
    }

    /// Exact logical suffix bytes retained by the completed candidate.
    #[must_use]
    pub const fn retained_bytes(self) -> usize {
        self.retained_bytes
    }

    /// Assertion edges observed during complete graph validation and treated
    /// conservatively as zero-width edges by the structural proof.
    #[must_use]
    pub const fn assertion_edges(self) -> usize {
        self.assertion_edges
    }

    /// Whether this receipt is internally consistent and within `limits`.
    #[must_use]
    pub fn closes(self, limits: MandatorySuffixAnalysisLimits) -> bool {
        self.accounting_id == MANDATORY_SUFFIX_ACCOUNTING_ID
            && self.work <= limits.max_work
            && self.allocation_items <= limits.max_allocation_items
            && self.allocation_attempts <= limits.max_allocation_attempts
            && self.reachable_states <= self.states
            && self.assertion_edges <= self.edges
            && self.reachable_accepting_states <= self.reachable_states
            && self.completed_suffix_layers <= limits.max_suffix_bytes
            && self.candidates <= 1
            && ((self.candidates == 1
                && self.retained_bytes > 0
                && self.retained_bytes == self.completed_suffix_layers)
                || (self.candidates == 0 && self.retained_bytes == 0))
    }
}

/// One exact byte suffix shared by every accepting path of the analyzed plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MandatorySuffixCandidate {
    bytes: [u8; MAX_MANDATORY_SUFFIX_BYTES],
    len: u8,
}

/// A finite prefix-width corridor whose every byte string reaches the exact
/// retained mandatory-suffix frontier.
///
/// This certificate is deliberately stronger than a finite maximum. For
/// every byte length in the inclusive interval, every possible byte string
/// has an assertion-free path from the raw start state to the suffix
/// frontier. It is tied to the same immutable [`RawPlan`] as the suffix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MandatorySuffixUniversalFiniteCorridor {
    minimum_prefix_bytes: usize,
    maximum_prefix_bytes: usize,
}

impl MandatorySuffixUniversalFiniteCorridor {
    /// Smallest universally accepted prefix width.
    #[must_use]
    pub const fn minimum_prefix_bytes(self) -> usize {
        self.minimum_prefix_bytes
    }

    /// Largest universally accepted prefix width.
    #[must_use]
    pub const fn maximum_prefix_bytes(self) -> usize {
        self.maximum_prefix_bytes
    }
}

/// Exact resource receipt for one independent universal-corridor attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MandatorySuffixUniversalFiniteCorridorStats {
    accounting_id: &'static str,
    work: u64,
    allocation_items: usize,
    allocation_attempts: usize,
}

impl MandatorySuffixUniversalFiniteCorridorStats {
    /// Stable identity of this independent proof and accounting convention.
    #[must_use]
    pub const fn accounting_id(self) -> &'static str {
        self.accounting_id
    }

    /// Exact abstract work completed, including re-authentication of the
    /// suffix frontier against the supplied immutable raw plan.
    #[must_use]
    pub const fn work(self) -> u64 {
        self.work
    }

    /// Cumulative logical scratch-vector slots requested.
    #[must_use]
    pub const fn allocation_items(self) -> usize {
        self.allocation_items
    }

    /// Fallible scratch reservation attempts completed or attempted.
    #[must_use]
    pub const fn allocation_attempts(self) -> usize {
        self.allocation_attempts
    }

    /// Whether this independent receipt closes under `limits`.
    #[must_use]
    pub fn closes(self, limits: MandatorySuffixAnalysisLimits) -> bool {
        self.accounting_id == MANDATORY_SUFFIX_UNIVERSAL_FINITE_CORRIDOR_ACCOUNTING_ID
            && self.work <= limits.max_work
            && self.allocation_items <= limits.max_allocation_items
            && self.allocation_attempts <= limits.max_allocation_attempts
    }
}

/// Transactional reason no universal finite corridor was published.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MandatorySuffixUniversalFiniteCorridorDeclineReason {
    /// Suffix-frontier authentication or corridor traversal declined.
    Analysis(MandatorySuffixDeclineReason),
    /// The graph is valid but the requested corridor is not pointwise
    /// universal under this conservative proof.
    NotUniversal,
    /// Requested maximum prefix depth exceeds the implementation hard cap.
    PrefixDepthLimit {
        /// Requested maximum prefix bytes.
        needed: usize,
        /// Hard implementation maximum.
        limit: usize,
    },
    /// Independent corridor accounting failed to close.
    InternalReceiptInvariant,
}

/// Completed universal corridor tied to one re-authenticated exact suffix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MandatorySuffixUniversalFiniteCorridorReport {
    candidate: MandatorySuffixCandidate,
    corridor: MandatorySuffixUniversalFiniteCorridor,
    stats: MandatorySuffixUniversalFiniteCorridorStats,
}

impl MandatorySuffixUniversalFiniteCorridorReport {
    /// Exact suffix whose saved pre-suffix frontier the corridor reaches.
    #[must_use]
    pub const fn candidate(self) -> MandatorySuffixCandidate {
        self.candidate
    }

    /// Pointwise-universal finite prefix corridor.
    #[must_use]
    pub const fn corridor(self) -> MandatorySuffixUniversalFiniteCorridor {
        self.corridor
    }

    /// Exact independent proof accounting.
    #[must_use]
    pub const fn stats(self) -> MandatorySuffixUniversalFiniteCorridorStats {
        self.stats
    }
}

/// Closed universal-corridor refusal with exact completed accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MandatorySuffixUniversalFiniteCorridorDecline {
    reason: MandatorySuffixUniversalFiniteCorridorDeclineReason,
    stats: MandatorySuffixUniversalFiniteCorridorStats,
}

impl MandatorySuffixUniversalFiniteCorridorDecline {
    /// Why no corridor was published.
    #[must_use]
    pub const fn reason(self) -> MandatorySuffixUniversalFiniteCorridorDeclineReason {
        self.reason
    }

    /// Exact independent proof accounting.
    #[must_use]
    pub const fn stats(self) -> MandatorySuffixUniversalFiniteCorridorStats {
        self.stats
    }
}

/// Transactional result of one independent universal-corridor attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MandatorySuffixUniversalFiniteCorridorAnalysis {
    /// The exact suffix frontier and every requested prefix width were proved.
    Complete(MandatorySuffixUniversalFiniteCorridorReport),
    /// No partial corridor may be consumed.
    Declined(MandatorySuffixUniversalFiniteCorridorDecline),
}

impl MandatorySuffixUniversalFiniteCorridorAnalysis {
    /// Accounting shared by complete and declined outcomes.
    #[must_use]
    pub const fn stats(&self) -> MandatorySuffixUniversalFiniteCorridorStats {
        match self {
            Self::Complete(report) => report.stats(),
            Self::Declined(decline) => decline.stats(),
        }
    }
}

impl MandatorySuffixCandidate {
    /// Required bytes in forward haystack order.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    /// Number of required suffix bytes.
    #[must_use]
    pub fn len(self) -> usize {
        usize::from(self.len)
    }

    /// The candidate is always nonempty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }
}

/// Completed optional analysis and its exact structural suffix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MandatorySuffixAnalysisReport {
    candidate: MandatorySuffixCandidate,
    stop_reason: MandatorySuffixStopReason,
    stats: MandatorySuffixAnalysisStats,
}

impl MandatorySuffixAnalysisReport {
    /// Nonempty exact suffix proved against the supplied raw graph.
    #[must_use]
    pub const fn candidate(self) -> MandatorySuffixCandidate {
        self.candidate
    }

    /// Boundary that stopped safe extension of the suffix.
    #[must_use]
    pub const fn stop_reason(self) -> MandatorySuffixStopReason {
        self.stop_reason
    }

    /// Exact completed accounting.
    #[must_use]
    pub const fn stats(self) -> MandatorySuffixAnalysisStats {
        self.stats
    }
}

/// Closed decline receipt retaining the work completed before refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MandatorySuffixAnalysisDecline {
    reason: MandatorySuffixDeclineReason,
    stats: MandatorySuffixAnalysisStats,
}

impl MandatorySuffixAnalysisDecline {
    /// Exact reason no suffix report was published.
    #[must_use]
    pub const fn reason(self) -> MandatorySuffixDeclineReason {
        self.reason
    }

    /// Exact completed accounting.
    #[must_use]
    pub const fn stats(self) -> MandatorySuffixAnalysisStats {
        self.stats
    }
}

/// Transactional result of one optional mandatory-suffix analysis.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MandatorySuffixAnalysis {
    /// A nonempty exact suffix and a closed receipt were published.
    Complete(MandatorySuffixAnalysisReport),
    /// No partial candidate may be consumed; inspect the closed decline receipt.
    Declined(MandatorySuffixAnalysisDecline),
}

impl MandatorySuffixAnalysis {
    /// Accounting shared by successful and declined outcomes.
    #[must_use]
    pub const fn stats(&self) -> MandatorySuffixAnalysisStats {
        match self {
            Self::Complete(report) => report.stats(),
            Self::Declined(decline) => decline.stats(),
        }
    }
}

/// Analyze one raw Thompson graph for an exact mandatory byte suffix.
///
/// No source syntax, haystack, timing signal, or expected result participates
/// in this proof. Validated assertions are conservatively relaxed as epsilon,
/// so the structural language examined here is a superset of the semantic
/// language. Malformed, empty, relaxed-nullable, ambiguous at the first byte,
/// and resource-limited graphs decline transactionally.
#[must_use]
pub fn analyze_mandatory_suffix(
    raw: &RawPlan,
    limits: MandatorySuffixAnalysisLimits,
) -> MandatorySuffixAnalysis {
    let mut budget = Budget::new(limits);
    let outcome = analyze_mandatory_suffix_inner(raw, &mut budget);
    match outcome {
        Ok(inner) => {
            let candidate = inner.candidate;
            budget.stats.completed_suffix_layers = candidate.len();
            budget.stats.candidates = 1;
            budget.stats.retained_bytes = candidate.len();
            if !budget.stats.closes(limits) {
                return decline(
                    MandatorySuffixDeclineReason::InternalInvariant {
                        detail: "mandatory-suffix completion receipt did not close",
                    },
                    budget.stats,
                );
            }
            MandatorySuffixAnalysis::Complete(MandatorySuffixAnalysisReport {
                candidate,
                stop_reason: inner.stop_reason,
                stats: budget.stats,
            })
        }
        Err(reason) => {
            let reason = if budget.stats.closes(limits) {
                reason
            } else {
                MandatorySuffixDeclineReason::InternalInvariant {
                    detail: "mandatory-suffix decline receipt did not close",
                }
            };
            decline(reason, budget.stats)
        }
    }
}

/// Independently re-authenticate an exact mandatory suffix frontier and prove
/// that every byte string at every requested finite prefix width reaches it.
///
/// This analysis has a separate v1 receipt. It never augments or consumes a
/// completed [`MandatorySuffixAnalysis`] receipt, so callers can first retain
/// the generic suffix and then spend only otherwise-available optional work
/// on this stronger certificate. Its work intentionally includes the complete
/// second suffix/frontier authentication as well as the corridor traversal.
#[must_use]
pub fn analyze_mandatory_suffix_universal_finite_corridor(
    raw: &RawPlan,
    limits: MandatorySuffixAnalysisLimits,
    minimum_match_bytes: usize,
    maximum_match_bytes: usize,
) -> MandatorySuffixUniversalFiniteCorridorAnalysis {
    let mut budget = Budget::new(limits);
    let inner = match analyze_mandatory_suffix_inner(raw, &mut budget) {
        Ok(inner) => inner,
        Err(reason) => {
            return decline_universal_finite_corridor(
                MandatorySuffixUniversalFiniteCorridorDeclineReason::Analysis(reason),
                corridor_stats(budget.stats),
                limits,
            );
        }
    };
    budget.stats.completed_suffix_layers = inner.candidate.len();
    budget.stats.candidates = 1;
    budget.stats.retained_bytes = inner.candidate.len();
    if let Some(maximum_prefix_bytes) = maximum_match_bytes.checked_sub(inner.candidate.len()) {
        if maximum_prefix_bytes > MAX_MANDATORY_SUFFIX_UNIVERSAL_CORRIDOR_PREFIX_BYTES {
            return decline_universal_finite_corridor(
                MandatorySuffixUniversalFiniteCorridorDeclineReason::PrefixDepthLimit {
                    needed: maximum_prefix_bytes,
                    limit: MAX_MANDATORY_SUFFIX_UNIVERSAL_CORRIDOR_PREFIX_BYTES,
                },
                corridor_stats(budget.stats),
                limits,
            );
        }
    }
    let corridor = match prove_universal_finite_corridor(
        raw,
        &inner.frontier,
        inner.candidate.len(),
        FiniteCorridorRequest {
            minimum_match_bytes,
            maximum_match_bytes,
        },
        &mut budget,
    ) {
        Ok(Some(corridor)) => corridor,
        Ok(None) => {
            return decline_universal_finite_corridor(
                MandatorySuffixUniversalFiniteCorridorDeclineReason::NotUniversal,
                corridor_stats(budget.stats),
                limits,
            );
        }
        Err(reason) => {
            return decline_universal_finite_corridor(
                MandatorySuffixUniversalFiniteCorridorDeclineReason::Analysis(reason),
                corridor_stats(budget.stats),
                limits,
            );
        }
    };
    let stats = corridor_stats(budget.stats);
    if !budget.stats.closes(limits) || !stats.closes(limits) {
        return decline_universal_finite_corridor(
            MandatorySuffixUniversalFiniteCorridorDeclineReason::InternalReceiptInvariant,
            stats,
            limits,
        );
    }
    MandatorySuffixUniversalFiniteCorridorAnalysis::Complete(
        MandatorySuffixUniversalFiniteCorridorReport {
            candidate: inner.candidate,
            corridor,
            stats,
        },
    )
}

const fn corridor_stats(
    stats: MandatorySuffixAnalysisStats,
) -> MandatorySuffixUniversalFiniteCorridorStats {
    MandatorySuffixUniversalFiniteCorridorStats {
        accounting_id: MANDATORY_SUFFIX_UNIVERSAL_FINITE_CORRIDOR_ACCOUNTING_ID,
        work: stats.work,
        allocation_items: stats.allocation_items,
        allocation_attempts: stats.allocation_attempts,
    }
}

fn decline_universal_finite_corridor(
    reason: MandatorySuffixUniversalFiniteCorridorDeclineReason,
    stats: MandatorySuffixUniversalFiniteCorridorStats,
    limits: MandatorySuffixAnalysisLimits,
) -> MandatorySuffixUniversalFiniteCorridorAnalysis {
    let reason = if stats.closes(limits) {
        reason
    } else {
        MandatorySuffixUniversalFiniteCorridorDeclineReason::InternalReceiptInvariant
    };
    MandatorySuffixUniversalFiniteCorridorAnalysis::Declined(
        MandatorySuffixUniversalFiniteCorridorDecline { reason, stats },
    )
}

const fn decline(
    reason: MandatorySuffixDeclineReason,
    stats: MandatorySuffixAnalysisStats,
) -> MandatorySuffixAnalysis {
    MandatorySuffixAnalysis::Declined(MandatorySuffixAnalysisDecline { reason, stats })
}

#[derive(Debug)]
struct MandatorySuffixInner {
    candidate: MandatorySuffixCandidate,
    stop_reason: MandatorySuffixStopReason,
    frontier: Vec<usize>,
}

fn analyze_mandatory_suffix_inner(
    raw: &RawPlan,
    budget: &mut Budget,
) -> Result<MandatorySuffixInner, MandatorySuffixDeclineReason> {
    if budget.limits.max_suffix_bytes == 0
        || budget.limits.max_suffix_bytes > MAX_MANDATORY_SUFFIX_BYTES
    {
        return Err(MandatorySuffixDeclineReason::Resource {
            resource: MandatorySuffixResource::SuffixBytes,
            needed: if budget.limits.max_suffix_bytes == 0 {
                1
            } else {
                to_u64(
                    budget.limits.max_suffix_bytes,
                    "mandatory-suffix requested bytes",
                )?
            },
            limit: if budget.limits.max_suffix_bytes == 0 {
                0
            } else {
                to_u64(MAX_MANDATORY_SUFFIX_BYTES, "mandatory-suffix inline bytes")?
            },
        });
    }
    validate_shape(raw, budget)?;
    let reachable = build_reachable(raw, budget)?;
    let incoming = Incoming::build(raw, budget)?;
    let states = raw.roles.len();
    let mut frontier = budget.empty(states, "mandatory-suffix frontier")?;
    for (state, &role) in raw.roles.iter().enumerate() {
        budget.charge(1)?;
        if role == StateRole::Accept && reachable[state] {
            budget.push_bounded(
                &mut frontier,
                state,
                states,
                "mandatory-suffix reachable accepts",
            )?;
            budget.stats.reachable_accepting_states = budget
                .stats
                .reachable_accepting_states
                .checked_add(1)
                .ok_or(MandatorySuffixDeclineReason::ArithmeticOverflow {
                    computation: "mandatory-suffix reachable accepting states",
                })?;
        }
    }
    if frontier.is_empty() {
        return Err(MandatorySuffixDeclineReason::EmptyLanguage);
    }

    let mut next = budget.empty(states, "mandatory-suffix next frontier")?;
    let mut closure_stack = budget.empty(states, "mandatory-suffix closure stack")?;
    let mut closure_seen = budget.filled(states, 0_u8, "mandatory-suffix closure membership")?;
    let mut next_seen = budget.filled(states, 0_u8, "mandatory-suffix next membership")?;
    let mut reverse_bytes = [0_u8; MAX_MANDATORY_SUFFIX_BYTES];

    for depth in 0..budget.limits.max_suffix_bytes {
        budget.charge(1)?;
        closure_stack.clear();
        next.clear();
        let reset_work = to_u64(
            states
                .checked_mul(2)
                .ok_or(MandatorySuffixDeclineReason::ArithmeticOverflow {
                    computation: "mandatory-suffix membership reset",
                })?,
            "mandatory-suffix membership reset work",
        )?;
        // Admit and charge both full-table writes before mutating either
        // table, so a resource decline never under-reports completed work.
        budget.charge(reset_work)?;
        closure_seen.fill(0);
        next_seen.fill(0);
        for &state in &frontier {
            if closure_seen[state] == 0 {
                closure_seen[state] = 1;
                budget.push_bounded(
                    &mut closure_stack,
                    state,
                    states,
                    "mandatory-suffix closure seeds",
                )?;
            }
        }

        let mut layer_byte = None;
        let mut reached_start = false;
        let mut ambiguous = false;
        while let Some(target) = closure_stack.pop() {
            budget.charge(1)?;
            if target == to_usize(raw.start, "mandatory-suffix start")? {
                reached_start = true;
                continue;
            }
            for incoming_edge in incoming.row(target)? {
                budget.charge(1)?;
                let source = to_usize(incoming_edge.source, "mandatory-suffix source")?;
                if !reachable[source] {
                    continue;
                }
                let edge = to_usize(incoming_edge.edge, "mandatory-suffix edge")?;
                match raw.roles[source] {
                    StateRole::Split => {
                        if !raw.edge_kinds[edge].is_zero_width() {
                            return Err(MandatorySuffixDeclineReason::InternalInvariant {
                                detail: "validated split retained a consuming edge",
                            });
                        }
                        if closure_seen[source] == 0 {
                            closure_seen[source] = 1;
                            budget.push_bounded(
                                &mut closure_stack,
                                source,
                                states,
                                "mandatory-suffix zero-width closure",
                            )?;
                        }
                    }
                    StateRole::Consume => {
                        let start = raw.byte_starts[edge];
                        let end = raw.byte_ends[edge];
                        if start != end || layer_byte.is_some_and(|byte| byte != start) {
                            ambiguous = true;
                        } else {
                            layer_byte = Some(start);
                        }
                        if next_seen[source] == 0 {
                            next_seen[source] = 1;
                            budget.push_bounded(
                                &mut next,
                                source,
                                states,
                                "mandatory-suffix byte frontier",
                            )?;
                        }
                    }
                    StateRole::Accept => {
                        return Err(MandatorySuffixDeclineReason::InternalInvariant {
                            detail: "validated accept state appeared as an edge source",
                        });
                    }
                }
            }
        }

        if reached_start {
            if depth == 0 {
                return Err(MandatorySuffixDeclineReason::NullableLanguage);
            }
            return finish_mandatory_suffix_candidate(
                &reverse_bytes,
                depth,
                MandatorySuffixStopReason::StartBoundary,
                frontier,
                budget,
            );
        }
        if ambiguous {
            if depth == 0 {
                return Err(MandatorySuffixDeclineReason::AmbiguousSuffixLayer);
            }
            return finish_mandatory_suffix_candidate(
                &reverse_bytes,
                depth,
                MandatorySuffixStopReason::AmbiguousLayer,
                frontier,
                budget,
            );
        }
        let byte = layer_byte.ok_or(MandatorySuffixDeclineReason::InternalInvariant {
            detail: "reachable reverse frontier had neither start nor consuming predecessor",
        })?;
        reverse_bytes[depth] = byte;
        budget.stats.completed_suffix_layers =
            depth
                .checked_add(1)
                .ok_or(MandatorySuffixDeclineReason::ArithmeticOverflow {
                    computation: "mandatory-suffix completed layers",
                })?;
        core::mem::swap(&mut frontier, &mut next);
    }

    finish_mandatory_suffix_candidate(
        &reverse_bytes,
        budget.limits.max_suffix_bytes,
        MandatorySuffixStopReason::MaximumBytes,
        frontier,
        budget,
    )
}

fn finish_mandatory_suffix_candidate(
    reverse_bytes: &[u8; MAX_MANDATORY_SUFFIX_BYTES],
    len: usize,
    stop_reason: MandatorySuffixStopReason,
    frontier: Vec<usize>,
    budget: &mut Budget,
) -> Result<MandatorySuffixInner, MandatorySuffixDeclineReason> {
    let candidate = make_candidate(reverse_bytes, len, budget)?;
    Ok(MandatorySuffixInner {
        candidate,
        stop_reason,
        frontier,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FiniteCorridorRequest {
    minimum_match_bytes: usize,
    maximum_match_bytes: usize,
}

/// Prove a deliberately strong, path-stable universal corridor.
///
/// Every state retained in `current` is reachable after every possible byte
/// string of the current width. Epsilon closure preserves that invariant. A
/// consuming state advances it only when all 256 bytes go to one common
/// target. Reaching the exact reverse-analysis frontier therefore proves that
/// every string of that width can begin the retained suffix. Treating frontier
/// states as terminal prevents suffix bytes from being mistaken for prefix
/// bytes. Requiring every requested width rejects finite languages with holes.
/// Equivalent non-canonical NFAs that distribute one full alphabet across
/// multiple consuming states conservatively decline rather than weakening the
/// pointwise invariant.
fn prove_universal_finite_corridor(
    raw: &RawPlan,
    frontier: &[usize],
    suffix_bytes: usize,
    request: FiniteCorridorRequest,
    budget: &mut Budget,
) -> Result<Option<MandatorySuffixUniversalFiniteCorridor>, MandatorySuffixDeclineReason> {
    if budget.stats.assertion_edges != 0
        || request.minimum_match_bytes == 0
        || request.minimum_match_bytes > request.maximum_match_bytes
        || suffix_bytes > request.minimum_match_bytes
    {
        return Ok(None);
    }
    let minimum_prefix_bytes = request.minimum_match_bytes - suffix_bytes;
    let maximum_prefix_bytes = request.maximum_match_bytes.checked_sub(suffix_bytes).ok_or(
        MandatorySuffixDeclineReason::ArithmeticOverflow {
            computation: "mandatory-suffix universal corridor maximum prefix",
        },
    )?;
    if maximum_prefix_bytes > MAX_MANDATORY_SUFFIX_UNIVERSAL_CORRIDOR_PREFIX_BYTES {
        return Ok(None);
    }
    let Some(layer_count) = maximum_prefix_bytes.checked_add(1) else {
        return Ok(None);
    };
    let Ok(minimum_layer_work) = u64::try_from(layer_count) else {
        return Ok(None);
    };
    let remaining_work = budget.limits.max_work.saturating_sub(budget.stats.work);
    if minimum_layer_work > remaining_work {
        let needed = budget.stats.work.checked_add(minimum_layer_work).ok_or(
            MandatorySuffixDeclineReason::ArithmeticOverflow {
                computation: "mandatory-suffix universal corridor minimum layer work",
            },
        )?;
        return Err(MandatorySuffixDeclineReason::Resource {
            resource: MandatorySuffixResource::Work,
            needed,
            limit: budget.limits.max_work,
        });
    }

    let states = raw.roles.len();
    let mut frontier_members = budget.filled(
        states,
        0_u8,
        "mandatory-suffix universal corridor frontier membership",
    )?;
    for &state in frontier {
        budget.charge(1)?;
        let member = frontier_members.get_mut(state).ok_or(
            MandatorySuffixDeclineReason::InternalInvariant {
                detail: "mandatory-suffix frontier escaped the validated state table",
            },
        )?;
        *member = 1;
    }

    let mut current = budget.empty(states, "mandatory-suffix universal corridor current")?;
    let start = to_usize(raw.start, "mandatory-suffix universal corridor start")?;
    budget.push_bounded(
        &mut current,
        start,
        states,
        "mandatory-suffix universal corridor root",
    )?;
    let mut next = budget.empty(states, "mandatory-suffix universal corridor next")?;
    let mut closure_stack =
        budget.empty(states, "mandatory-suffix universal corridor closure stack")?;
    let mut closure_seen = budget.filled(
        states,
        0_u8,
        "mandatory-suffix universal corridor closure membership",
    )?;
    let mut next_seen = budget.filled(
        states,
        0_u8,
        "mandatory-suffix universal corridor next membership",
    )?;

    for width in 0..=maximum_prefix_bytes {
        budget.charge(1)?;
        closure_stack.clear();
        next.clear();
        let reset_work = to_u64(
            states
                .checked_mul(2)
                .ok_or(MandatorySuffixDeclineReason::ArithmeticOverflow {
                    computation: "mandatory-suffix universal corridor membership reset",
                })?,
            "mandatory-suffix universal corridor reset work",
        )?;
        budget.charge(reset_work)?;
        closure_seen.fill(0);
        next_seen.fill(0);
        for &state in &current {
            if closure_seen[state] == 0 {
                closure_seen[state] = 1;
                budget.push_bounded(
                    &mut closure_stack,
                    state,
                    states,
                    "mandatory-suffix universal corridor closure seeds",
                )?;
            }
        }

        let mut reached_frontier = false;
        while let Some(state) = closure_stack.pop() {
            budget.charge(1)?;
            if frontier_members[state] != 0 {
                reached_frontier = true;
                continue;
            }
            match raw.roles[state] {
                StateRole::Split => {
                    for edge in state_edges(raw, state)? {
                        budget.charge(1)?;
                        if raw.edge_kinds[edge] != EdgeKind::Epsilon {
                            return Err(MandatorySuffixDeclineReason::InternalInvariant {
                                detail: "assertion-free universal corridor retained a non-epsilon split",
                            });
                        }
                        let target = to_usize(
                            raw.edge_targets[edge],
                            "mandatory-suffix universal corridor epsilon target",
                        )?;
                        if closure_seen[target] == 0 {
                            closure_seen[target] = 1;
                            budget.push_bounded(
                                &mut closure_stack,
                                target,
                                states,
                                "mandatory-suffix universal corridor epsilon closure",
                            )?;
                        }
                    }
                }
                StateRole::Consume => {
                    if let Some(target) = universal_consume_target(raw, state, budget)? {
                        if next_seen[target] == 0 {
                            next_seen[target] = 1;
                            budget.push_bounded(
                                &mut next,
                                target,
                                states,
                                "mandatory-suffix universal corridor byte target",
                            )?;
                        }
                    }
                }
                StateRole::Accept => {}
            }
        }

        if width >= minimum_prefix_bytes && !reached_frontier {
            return Ok(None);
        }
        if width == maximum_prefix_bytes {
            return Ok(Some(MandatorySuffixUniversalFiniteCorridor {
                minimum_prefix_bytes,
                maximum_prefix_bytes,
            }));
        }
        core::mem::swap(&mut current, &mut next);
    }

    Err(MandatorySuffixDeclineReason::InternalInvariant {
        detail: "universal finite corridor escaped its inclusive width loop",
    })
}

fn universal_consume_target(
    raw: &RawPlan,
    state: usize,
    budget: &mut Budget,
) -> Result<Option<usize>, MandatorySuffixDeclineReason> {
    let mut target = None;
    let mut coverage = [0_u64; 4];
    for edge in state_edges(raw, state)? {
        budget.charge(1)?;
        if raw.edge_kinds[edge] != EdgeKind::ByteRange {
            return Err(MandatorySuffixDeclineReason::InternalInvariant {
                detail: "validated universal corridor consume retained a non-byte edge",
            });
        }
        let edge_target = raw.edge_targets[edge];
        if target.is_some_and(|retained| retained != edge_target) {
            return Ok(None);
        }
        target = Some(edge_target);
        insert_universal_byte_range(
            &mut coverage,
            raw.byte_starts[edge],
            raw.byte_ends[edge],
        );
    }
    if coverage != [u64::MAX; 4] {
        return Ok(None);
    }
    target
        .map(|target| to_usize(target, "mandatory-suffix universal corridor byte target"))
        .transpose()
}

fn insert_universal_byte_range(words: &mut [u64; 4], start: u8, end: u8) {
    let first_word = usize::from(start / 64);
    let last_word = usize::from(end / 64);
    for word in first_word..=last_word {
        let lower = if word == first_word {
            u32::from(start % 64)
        } else {
            0
        };
        let upper = if word == last_word {
            u32::from(end % 64)
        } else {
            63
        };
        let lower_mask = u64::MAX << lower;
        let upper_mask = u64::MAX >> (63 - upper);
        words[word] |= lower_mask & upper_mask;
    }
}

fn make_candidate(
    reverse_bytes: &[u8; MAX_MANDATORY_SUFFIX_BYTES],
    len: usize,
    budget: &mut Budget,
) -> Result<MandatorySuffixCandidate, MandatorySuffixDeclineReason> {
    if len == 0 || len > MAX_MANDATORY_SUFFIX_BYTES {
        return Err(MandatorySuffixDeclineReason::InternalInvariant {
            detail: "mandatory suffix candidate length escaped its inline bound",
        });
    }
    budget.charge(to_u64(len, "mandatory-suffix candidate bytes")?)?;
    let mut bytes = [0_u8; MAX_MANDATORY_SUFFIX_BYTES];
    for index in 0..len {
        bytes[index] = reverse_bytes[len - index - 1];
    }
    Ok(MandatorySuffixCandidate {
        bytes,
        len: u8::try_from(len).map_err(|_| MandatorySuffixDeclineReason::ArithmeticOverflow {
            computation: "mandatory-suffix candidate length",
        })?,
    })
}

#[derive(Clone, Copy, Debug)]
struct IncomingEdge {
    source: u32,
    edge: u32,
}

#[derive(Debug)]
struct Incoming {
    offsets: Vec<usize>,
    edges: Vec<IncomingEdge>,
}

impl Incoming {
    fn build(raw: &RawPlan, budget: &mut Budget) -> Result<Self, MandatorySuffixDeclineReason> {
        let states = raw.roles.len();
        let edge_count = raw.edge_targets.len();
        let mut counts = budget.filled(states, 0_usize, "mandatory-suffix incoming counts")?;
        for &target in &raw.edge_targets {
            budget.charge(1)?;
            let target = to_usize(target, "mandatory-suffix incoming target")?;
            counts[target] = counts[target].checked_add(1).ok_or(
                MandatorySuffixDeclineReason::ArithmeticOverflow {
                    computation: "mandatory-suffix incoming count",
                },
            )?;
        }
        let offset_slots =
            states
                .checked_add(1)
                .ok_or(MandatorySuffixDeclineReason::ArithmeticOverflow {
                    computation: "mandatory-suffix incoming offset slots",
                })?;
        let mut offsets =
            budget.filled(offset_slots, 0_usize, "mandatory-suffix incoming offsets")?;
        for state in 0..states {
            budget.charge(1)?;
            offsets[state + 1] = offsets[state].checked_add(counts[state]).ok_or(
                MandatorySuffixDeclineReason::ArithmeticOverflow {
                    computation: "mandatory-suffix incoming offset",
                },
            )?;
        }
        if offsets[states] != edge_count {
            return Err(MandatorySuffixDeclineReason::InternalInvariant {
                detail: "incoming offsets did not cover every validated edge",
            });
        }
        let mut cursor = budget.filled(states, 0_usize, "mandatory-suffix incoming cursors")?;
        for state in 0..states {
            budget.charge(1)?;
            cursor[state] = offsets[state];
        }
        let mut edges = budget.filled(
            edge_count,
            IncomingEdge { source: 0, edge: 0 },
            "mandatory-suffix incoming edges",
        )?;
        for source in 0..states {
            let source_u32 = u32::try_from(source).map_err(|_| {
                MandatorySuffixDeclineReason::ArithmeticOverflow {
                    computation: "mandatory-suffix incoming source",
                }
            })?;
            for edge in state_edges(raw, source)? {
                budget.charge(1)?;
                let target = to_usize(raw.edge_targets[edge], "mandatory-suffix incoming target")?;
                let slot = cursor[target];
                edges[slot] = IncomingEdge {
                    source: source_u32,
                    edge: u32::try_from(edge).map_err(|_| {
                        MandatorySuffixDeclineReason::ArithmeticOverflow {
                            computation: "mandatory-suffix incoming edge",
                        }
                    })?,
                };
                cursor[target] = slot.checked_add(1).ok_or(
                    MandatorySuffixDeclineReason::ArithmeticOverflow {
                        computation: "mandatory-suffix incoming cursor",
                    },
                )?;
            }
        }
        Ok(Self { offsets, edges })
    }

    fn row(&self, target: usize) -> Result<&[IncomingEdge], MandatorySuffixDeclineReason> {
        let next =
            target
                .checked_add(1)
                .ok_or(MandatorySuffixDeclineReason::ArithmeticOverflow {
                    computation: "mandatory-suffix incoming next target",
                })?;
        let begin = self.offsets.get(target).copied().ok_or(
            MandatorySuffixDeclineReason::InternalInvariant {
                detail: "incoming row escaped its offset table",
            },
        )?;
        let end = self.offsets.get(next).copied().ok_or(
            MandatorySuffixDeclineReason::InternalInvariant {
                detail: "incoming row escaped its terminal offset",
            },
        )?;
        self.edges
            .get(begin..end)
            .ok_or(MandatorySuffixDeclineReason::InternalInvariant {
                detail: "incoming row escaped its edge table",
            })
    }
}

fn build_reachable(
    raw: &RawPlan,
    budget: &mut Budget,
) -> Result<Vec<bool>, MandatorySuffixDeclineReason> {
    let states = raw.roles.len();
    let mut reachable = budget.filled(states, false, "mandatory-suffix reachable states")?;
    let mut stack = budget.empty(states, "mandatory-suffix reachability stack")?;
    let start = to_usize(raw.start, "mandatory-suffix reachable start")?;
    reachable[start] = true;
    budget.stats.reachable_states = 1;
    budget.push_bounded(
        &mut stack,
        start,
        states,
        "mandatory-suffix reachability root",
    )?;
    while let Some(source) = stack.pop() {
        budget.charge(1)?;
        for edge in state_edges(raw, source)? {
            budget.charge(1)?;
            let target = to_usize(raw.edge_targets[edge], "mandatory-suffix reachable target")?;
            if !reachable[target] {
                reachable[target] = true;
                budget.stats.reachable_states =
                    budget.stats.reachable_states.checked_add(1).ok_or(
                        MandatorySuffixDeclineReason::ArithmeticOverflow {
                            computation: "mandatory-suffix reachable state count",
                        },
                    )?;
                budget.push_bounded(&mut stack, target, states, "mandatory-suffix reachability")?;
            }
        }
    }
    Ok(reachable)
}

#[derive(Clone, Copy, Debug)]
struct Budget {
    limits: MandatorySuffixAnalysisLimits,
    stats: MandatorySuffixAnalysisStats,
}

impl Budget {
    const fn new(limits: MandatorySuffixAnalysisLimits) -> Self {
        Self {
            limits,
            stats: MandatorySuffixAnalysisStats {
                accounting_id: MANDATORY_SUFFIX_ACCOUNTING_ID,
                work: 0,
                allocation_items: 0,
                allocation_attempts: 0,
                states: 0,
                edges: 0,
                reachable_states: 0,
                reachable_accepting_states: 0,
                completed_suffix_layers: 0,
                candidates: 0,
                retained_bytes: 0,
                assertion_edges: 0,
            },
        }
    }

    fn charge(&mut self, amount: u64) -> Result<(), MandatorySuffixDeclineReason> {
        let needed = self.stats.work.checked_add(amount).ok_or(
            MandatorySuffixDeclineReason::ArithmeticOverflow {
                computation: "mandatory-suffix work",
            },
        )?;
        if needed > self.limits.max_work {
            return Err(MandatorySuffixDeclineReason::Resource {
                resource: MandatorySuffixResource::Work,
                needed,
                limit: self.limits.max_work,
            });
        }
        self.stats.work = needed;
        Ok(())
    }

    fn reserve<T>(
        &mut self,
        values: &mut Vec<T>,
        additional: usize,
        structure: &'static str,
    ) -> Result<(), MandatorySuffixDeclineReason> {
        if additional == 0 {
            return Ok(());
        }
        let needed = self.stats.allocation_items.checked_add(additional).ok_or(
            MandatorySuffixDeclineReason::ArithmeticOverflow {
                computation: "mandatory-suffix allocation items",
            },
        )?;
        if needed > self.limits.max_allocation_items {
            return Err(resource_usize(
                MandatorySuffixResource::AllocationItems,
                needed,
                self.limits.max_allocation_items,
            )?);
        }
        let attempts = self.stats.allocation_attempts.checked_add(1).ok_or(
            MandatorySuffixDeclineReason::ArithmeticOverflow {
                computation: "mandatory-suffix allocation attempts",
            },
        )?;
        if attempts > self.limits.max_allocation_attempts {
            return Err(resource_usize(
                MandatorySuffixResource::AllocationAttempts,
                attempts,
                self.limits.max_allocation_attempts,
            )?);
        }
        self.stats.allocation_attempts = attempts;
        values.try_reserve_exact(additional).map_err(|_| {
            MandatorySuffixDeclineReason::Allocation {
                structure,
                additional,
            }
        })?;
        self.stats.allocation_items = needed;
        Ok(())
    }

    fn empty<T>(
        &mut self,
        capacity: usize,
        structure: &'static str,
    ) -> Result<Vec<T>, MandatorySuffixDeclineReason> {
        let mut values = Vec::new();
        self.reserve(&mut values, capacity, structure)?;
        Ok(values)
    }

    fn filled<T: Clone>(
        &mut self,
        length: usize,
        value: T,
        structure: &'static str,
    ) -> Result<Vec<T>, MandatorySuffixDeclineReason> {
        let mut values = self.empty(length, structure)?;
        self.charge(to_u64(length, "mandatory-suffix initialized items")?)?;
        values.resize(length, value);
        Ok(values)
    }

    fn push_bounded<T>(
        &mut self,
        values: &mut Vec<T>,
        value: T,
        capacity: usize,
        _structure: &'static str,
    ) -> Result<(), MandatorySuffixDeclineReason> {
        self.charge(1)?;
        if values.len() >= capacity {
            return Err(MandatorySuffixDeclineReason::InternalInvariant {
                detail: "bounded mandatory-suffix vector exceeded state cardinality",
            });
        }
        values.push(value);
        Ok(())
    }
}

fn resource_usize(
    resource: MandatorySuffixResource,
    needed: usize,
    limit: usize,
) -> Result<MandatorySuffixDeclineReason, MandatorySuffixDeclineReason> {
    Ok(MandatorySuffixDeclineReason::Resource {
        resource,
        needed: to_u64(needed, "mandatory-suffix resource need")?,
        limit: to_u64(limit, "mandatory-suffix resource limit")?,
    })
}

fn to_u64(value: usize, computation: &'static str) -> Result<u64, MandatorySuffixDeclineReason> {
    u64::try_from(value)
        .map_err(|_| MandatorySuffixDeclineReason::ArithmeticOverflow { computation })
}

fn to_usize(value: u32, computation: &'static str) -> Result<usize, MandatorySuffixDeclineReason> {
    usize::try_from(value)
        .map_err(|_| MandatorySuffixDeclineReason::ArithmeticOverflow { computation })
}

#[allow(
    clippy::too_many_lines,
    reason = "one bounded pass validates every raw graph table before proof construction"
)]
fn validate_shape(raw: &RawPlan, budget: &mut Budget) -> Result<(), MandatorySuffixDeclineReason> {
    budget.charge(1)?;
    let states = raw.roles.len();
    if states == 0 {
        return Err(MandatorySuffixDeclineReason::MalformedGraph(
            MandatorySuffixGraphIssue::Empty,
        ));
    }
    let edges = raw.edge_targets.len();
    if u32::try_from(states).is_err() || u32::try_from(edges).is_err() {
        return Err(MandatorySuffixDeclineReason::MalformedGraph(
            MandatorySuffixGraphIssue::IndexSpaceExceeded,
        ));
    }
    let start = to_usize(raw.start, "mandatory-suffix start index")?;
    if start >= states {
        return Err(MandatorySuffixDeclineReason::MalformedGraph(
            MandatorySuffixGraphIssue::StartOutOfRange,
        ));
    }
    if raw.edge_kinds.len() != edges
        || raw.byte_starts.len() != edges
        || raw.byte_ends.len() != edges
    {
        return Err(MandatorySuffixDeclineReason::MalformedGraph(
            MandatorySuffixGraphIssue::EdgeTableShape,
        ));
    }
    if raw.edge_offsets.len()
        != states
            .checked_add(1)
            .ok_or(MandatorySuffixDeclineReason::ArithmeticOverflow {
                computation: "mandatory-suffix offset slots",
            })?
        || raw.edge_offsets.first() != Some(&0)
        || raw
            .edge_offsets
            .last()
            .and_then(|&offset| usize::try_from(offset).ok())
            != Some(edges)
    {
        return Err(MandatorySuffixDeclineReason::MalformedGraph(
            MandatorySuffixGraphIssue::OffsetShape,
        ));
    }
    budget.stats.states = states;
    budget.stats.edges = edges;

    let mut has_accept = false;
    for state in 0..states {
        budget.charge(1)?;
        let row = state_edges(raw, state)?;
        match raw.roles[state] {
            StateRole::Accept if !row.is_empty() => {
                return Err(MandatorySuffixDeclineReason::MalformedGraph(
                    MandatorySuffixGraphIssue::StateRoleEdges,
                ));
            }
            StateRole::Accept => has_accept = true,
            StateRole::Split | StateRole::Consume => {}
        }
        for edge in row {
            budget.charge(1)?;
            let target = raw.edge_targets.get(edge).copied().ok_or(
                MandatorySuffixDeclineReason::MalformedGraph(
                    MandatorySuffixGraphIssue::EdgeTableShape,
                ),
            )?;
            if to_usize(target, "mandatory-suffix edge target")? >= states {
                return Err(MandatorySuffixDeclineReason::MalformedGraph(
                    MandatorySuffixGraphIssue::EdgeTargetOutOfRange,
                ));
            }
            let kind =
                *raw.edge_kinds
                    .get(edge)
                    .ok_or(MandatorySuffixDeclineReason::MalformedGraph(
                        MandatorySuffixGraphIssue::EdgeTableShape,
                    ))?;
            let start_byte =
                *raw.byte_starts
                    .get(edge)
                    .ok_or(MandatorySuffixDeclineReason::MalformedGraph(
                        MandatorySuffixGraphIssue::EdgeTableShape,
                    ))?;
            let end_byte =
                *raw.byte_ends
                    .get(edge)
                    .ok_or(MandatorySuffixDeclineReason::MalformedGraph(
                        MandatorySuffixGraphIssue::EdgeTableShape,
                    ))?;
            match raw.roles[state] {
                StateRole::Accept => {
                    return Err(MandatorySuffixDeclineReason::InternalInvariant {
                        detail: "validated accept state retained an edge",
                    });
                }
                StateRole::Consume => {
                    if kind != EdgeKind::ByteRange {
                        return Err(MandatorySuffixDeclineReason::MalformedGraph(
                            MandatorySuffixGraphIssue::StateRoleEdges,
                        ));
                    }
                    if start_byte > end_byte {
                        return Err(MandatorySuffixDeclineReason::MalformedGraph(
                            MandatorySuffixGraphIssue::EdgePayload,
                        ));
                    }
                }
                StateRole::Split => {
                    if kind == EdgeKind::ByteRange || !kind.is_zero_width() {
                        return Err(MandatorySuffixDeclineReason::MalformedGraph(
                            MandatorySuffixGraphIssue::StateRoleEdges,
                        ));
                    }
                    if start_byte != 0 || end_byte != 0 {
                        return Err(MandatorySuffixDeclineReason::MalformedGraph(
                            MandatorySuffixGraphIssue::EdgePayload,
                        ));
                    }
                    if kind != EdgeKind::Epsilon {
                        if kind.assertion_bit().is_none() {
                            return Err(MandatorySuffixDeclineReason::MalformedGraph(
                                MandatorySuffixGraphIssue::UnsupportedGraphKind,
                            ));
                        }
                        budget.stats.assertion_edges =
                            budget.stats.assertion_edges.checked_add(1).ok_or(
                                MandatorySuffixDeclineReason::ArithmeticOverflow {
                                    computation: "mandatory-suffix assertion edges",
                                },
                            )?;
                    }
                }
            }
        }
    }
    if !has_accept {
        return Err(MandatorySuffixDeclineReason::MalformedGraph(
            MandatorySuffixGraphIssue::MissingAccept,
        ));
    }
    Ok(())
}

fn state_edges(
    raw: &RawPlan,
    state: usize,
) -> Result<core::ops::Range<usize>, MandatorySuffixDeclineReason> {
    let begin = raw.edge_offsets.get(state).copied().ok_or(
        MandatorySuffixDeclineReason::MalformedGraph(MandatorySuffixGraphIssue::OffsetShape),
    )?;
    let next = state
        .checked_add(1)
        .ok_or(MandatorySuffixDeclineReason::ArithmeticOverflow {
            computation: "mandatory-suffix next state",
        })?;
    let end =
        raw.edge_offsets
            .get(next)
            .copied()
            .ok_or(MandatorySuffixDeclineReason::MalformedGraph(
                MandatorySuffixGraphIssue::OffsetShape,
            ))?;
    let begin = to_usize(begin, "mandatory-suffix row start")?;
    let end = to_usize(end, "mandatory-suffix row end")?;
    if begin > end || end > raw.edge_targets.len() {
        return Err(MandatorySuffixDeclineReason::MalformedGraph(
            MandatorySuffixGraphIssue::EdgeOffset,
        ));
    }
    Ok(begin..end)
}

#[cfg(test)]
mod tests {
    use super::*;

    type Edge = (u32, EdgeKind, u8, u8);

    fn raw(start: u32, roles: &[StateRole], rows: &[&[Edge]]) -> RawPlan {
        assert_eq!(roles.len(), rows.len());
        let mut edge_offsets = Vec::with_capacity(rows.len() + 1);
        let mut edge_targets = Vec::new();
        let mut edge_kinds = Vec::new();
        let mut byte_starts = Vec::new();
        let mut byte_ends = Vec::new();
        edge_offsets.push(0);
        for row in rows {
            for &(target, kind, byte_start, byte_end) in *row {
                edge_targets.push(target);
                edge_kinds.push(kind);
                byte_starts.push(byte_start);
                byte_ends.push(byte_end);
            }
            edge_offsets.push(u32::try_from(edge_targets.len()).unwrap());
        }
        RawPlan {
            start,
            roles: roles.to_vec(),
            edge_offsets,
            edge_targets,
            edge_kinds,
            byte_starts,
            byte_ends,
        }
    }

    fn byte(target: u32, value: u8) -> Edge {
        (target, EdgeKind::ByteRange, value, value)
    }

    fn epsilon(target: u32) -> Edge {
        (target, EdgeKind::Epsilon, 0, 0)
    }

    fn assertion(target: u32, kind: EdgeKind) -> Edge {
        assert!(kind.assertion_bit().is_some());
        (target, kind, 0, 0)
    }

    fn assertions() -> [EdgeKind; 18] {
        [
            EdgeKind::AssertHaystackStart,
            EdgeKind::AssertHaystackEnd,
            EdgeKind::AssertLineStartLf,
            EdgeKind::AssertLineEndLf,
            EdgeKind::AssertLineStartCrlf,
            EdgeKind::AssertLineEndCrlf,
            EdgeKind::AssertWordAscii,
            EdgeKind::AssertWordAsciiNegate,
            EdgeKind::AssertWordStartAscii,
            EdgeKind::AssertWordEndAscii,
            EdgeKind::AssertWordStartHalfAscii,
            EdgeKind::AssertWordEndHalfAscii,
            EdgeKind::AssertWordUnicode,
            EdgeKind::AssertWordUnicodeNegate,
            EdgeKind::AssertWordStartUnicode,
            EdgeKind::AssertWordEndUnicode,
            EdgeKind::AssertWordStartHalfUnicode,
            EdgeKind::AssertWordEndHalfUnicode,
        ]
    }

    fn complete(
        plan: &RawPlan,
        limits: MandatorySuffixAnalysisLimits,
    ) -> MandatorySuffixAnalysisReport {
        match analyze_mandatory_suffix(plan, limits) {
            MandatorySuffixAnalysis::Complete(report) => report,
            MandatorySuffixAnalysis::Declined(decline) => {
                panic!("unexpected decline: {:?}", decline.reason())
            }
        }
    }

    fn complete_with_corridor(
        plan: &RawPlan,
        minimum_match_bytes: usize,
        maximum_match_bytes: usize,
        limits: MandatorySuffixAnalysisLimits,
    ) -> MandatorySuffixUniversalFiniteCorridorReport {
        match analyze_mandatory_suffix_universal_finite_corridor(
            plan,
            limits,
            minimum_match_bytes,
            maximum_match_bytes,
        ) {
            MandatorySuffixUniversalFiniteCorridorAnalysis::Complete(report) => report,
            MandatorySuffixUniversalFiniteCorridorAnalysis::Declined(decline) => {
                panic!("unexpected corridor-analysis decline: {:?}", decline.reason())
            }
        }
    }

    fn declined_corridor(
        plan: &RawPlan,
        minimum_match_bytes: usize,
        maximum_match_bytes: usize,
        limits: MandatorySuffixAnalysisLimits,
    ) -> MandatorySuffixUniversalFiniteCorridorDecline {
        match analyze_mandatory_suffix_universal_finite_corridor(
            plan,
            limits,
            minimum_match_bytes,
            maximum_match_bytes,
        ) {
            MandatorySuffixUniversalFiniteCorridorAnalysis::Complete(report) => {
                panic!("unexpected universal corridor: {:?}", report.corridor())
            }
            MandatorySuffixUniversalFiniteCorridorAnalysis::Declined(decline) => decline,
        }
    }

    fn declined(plan: &RawPlan) -> MandatorySuffixAnalysisDecline {
        match analyze_mandatory_suffix(plan, MandatorySuffixAnalysisLimits::default()) {
            MandatorySuffixAnalysis::Complete(report) => {
                panic!("unexpected candidate: {:?}", report.candidate().as_bytes())
            }
            MandatorySuffixAnalysis::Declined(decline) => decline,
        }
    }

    #[test]
    fn exact_literal_is_returned_in_forward_order() {
        let plan = raw(
            0,
            &[
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Accept,
            ],
            &[&[byte(1, b'a')], &[byte(2, b'b')], &[byte(3, b'c')], &[]],
        );
        let report = complete(&plan, MandatorySuffixAnalysisLimits::default());
        assert_eq!(report.candidate().as_bytes(), b"abc");
        assert_eq!(
            report.stop_reason(),
            MandatorySuffixStopReason::StartBoundary
        );
        assert!(
            report
                .stats()
                .closes(MandatorySuffixAnalysisLimits::default())
        );
        assert_eq!(
            report.stats().accounting_id(),
            MANDATORY_SUFFIX_ACCOUNTING_ID,
        );
    }

    #[test]
    fn full_byte_prefix_corridor_is_proved_at_every_requested_width() {
        let full = |target| (target, EdgeKind::ByteRange, 0, u8::MAX);
        // Every byte string of length one, two, or three reaches state 4,
        // which is the retained entry frontier for the exact suffix `Z`.
        let plan = raw(
            0,
            &[
                StateRole::Consume,
                StateRole::Split,
                StateRole::Consume,
                StateRole::Split,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Accept,
            ],
            &[
                &[full(1)],
                &[epsilon(2), epsilon(4)],
                &[full(3)],
                &[epsilon(5), epsilon(4)],
                &[byte(6, b'Z')],
                &[full(4)],
                &[],
            ],
        );
        let report = complete_with_corridor(
            &plan,
            2,
            4,
            MandatorySuffixAnalysisLimits::default(),
        );
        assert_eq!(report.candidate().as_bytes(), b"Z");
        let corridor = report.corridor();
        assert_eq!(corridor.minimum_prefix_bytes(), 1);
        assert_eq!(corridor.maximum_prefix_bytes(), 3);
        assert!(
            report
                .stats()
                .closes(MandatorySuffixAnalysisLimits::default())
        );
        assert_eq!(
            report.stats().accounting_id(),
            MANDATORY_SUFFIX_UNIVERSAL_FINITE_CORRIDOR_ACCOUNTING_ID,
        );

        let fragmented = raw(
            0,
            &[StateRole::Consume, StateRole::Consume, StateRole::Accept],
            &[
                &[
                    (1, EdgeKind::ByteRange, 0, 63),
                    (1, EdgeKind::ByteRange, 64, 127),
                    (1, EdgeKind::ByteRange, 128, 191),
                    (1, EdgeKind::ByteRange, 192, u8::MAX),
                ],
                &[byte(2, b'Z')],
                &[],
            ],
        );
        let fragmented = complete_with_corridor(
            &fragmented,
            2,
            2,
            MandatorySuffixAnalysisLimits::default(),
        );
        assert_eq!(fragmented.candidate().as_bytes(), b"Z");
        assert_eq!(
            fragmented.corridor(),
            MandatorySuffixUniversalFiniteCorridor {
                minimum_prefix_bytes: 1,
                maximum_prefix_bytes: 1,
            },
            "same-target byte ranges may jointly cover the full domain",
        );

        let nullable_prefix = raw(
            0,
            &[
                StateRole::Split,
                StateRole::Consume,
                StateRole::Split,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Accept,
            ],
            &[
                &[epsilon(1), epsilon(4)],
                &[full(2)],
                &[epsilon(3), epsilon(4)],
                &[full(4)],
                &[byte(5, b'Z')],
                &[],
            ],
        );
        let nullable_prefix = complete_with_corridor(
            &nullable_prefix,
            1,
            3,
            MandatorySuffixAnalysisLimits::default(),
        );
        assert_eq!(nullable_prefix.candidate().as_bytes(), b"Z");
        let corridor = nullable_prefix.corridor();
        assert_eq!(corridor.minimum_prefix_bytes(), 0);
        assert_eq!(corridor.maximum_prefix_bytes(), 2);
    }

    #[test]
    fn universal_corridor_rejects_length_holes_and_cross_state_byte_unions() {
        let full = |target| (target, EdgeKind::ByteRange, 0, u8::MAX);
        let holes = raw(
            0,
            &[
                StateRole::Split,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Accept,
            ],
            &[
                &[epsilon(1), epsilon(2)],
                &[full(5)],
                &[full(3)],
                &[full(4)],
                &[full(5)],
                &[byte(6, b'Z')],
                &[],
            ],
        );
        assert_eq!(
            complete(&holes, MandatorySuffixAnalysisLimits::default())
                .candidate()
                .as_bytes(),
            b"Z",
        );
        let holes = declined_corridor(
            &holes,
            2,
            4,
            MandatorySuffixAnalysisLimits::default(),
        );
        assert_eq!(
            holes.reason(),
            MandatorySuffixUniversalFiniteCorridorDeclineReason::NotUniversal,
        );

        // The two sources jointly cover 256 bytes, but neither source is
        // pointwise universal. Unioning their ranges would lose correlation
        // across successive bytes and would be unsound.
        let correlated_halves = raw(
            0,
            &[
                StateRole::Split,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Accept,
            ],
            &[
                &[epsilon(1), epsilon(3)],
                &[(2, EdgeKind::ByteRange, 0, 0x7f)],
                &[(5, EdgeKind::ByteRange, 0, 0x7f)],
                &[(4, EdgeKind::ByteRange, 0x80, u8::MAX)],
                &[(5, EdgeKind::ByteRange, 0x80, u8::MAX)],
                &[byte(6, b'Z')],
                &[],
            ],
        );
        assert_eq!(
            complete(
                &correlated_halves,
                MandatorySuffixAnalysisLimits::default(),
            )
            .candidate()
            .as_bytes(),
            b"Z",
        );
        let correlated_halves = declined_corridor(
            &correlated_halves,
            3,
            3,
            MandatorySuffixAnalysisLimits::default(),
        );
        assert_eq!(
            correlated_halves.reason(),
            MandatorySuffixUniversalFiniteCorridorDeclineReason::NotUniversal,
        );

        let differing_targets = raw(
            0,
            &[
                StateRole::Consume,
                StateRole::Split,
                StateRole::Split,
                StateRole::Consume,
                StateRole::Accept,
            ],
            &[
                &[
                    (1, EdgeKind::ByteRange, 0, 0x7f),
                    (2, EdgeKind::ByteRange, 0x80, u8::MAX),
                ],
                &[epsilon(3)],
                &[epsilon(3)],
                &[byte(4, b'Z')],
                &[],
            ],
        );
        assert_eq!(
            complete(
                &differing_targets,
                MandatorySuffixAnalysisLimits::default(),
            )
            .candidate()
            .as_bytes(),
            b"Z",
        );
        let differing_targets = declined_corridor(
            &differing_targets,
            2,
            2,
            MandatorySuffixAnalysisLimits::default(),
        );
        assert_eq!(
            differing_targets.reason(),
            MandatorySuffixUniversalFiniteCorridorDeclineReason::NotUniversal,
            "full coverage split across distinct targets conservatively declines",
        );
    }

    #[test]
    fn universal_corridor_refuses_narrow_ranges_and_assertions() {
        let narrow = raw(
            0,
            &[StateRole::Consume, StateRole::Consume, StateRole::Accept],
            &[
                &[(1, EdgeKind::ByteRange, 0, u8::MAX - 1)],
                &[byte(2, b'Z')],
                &[],
            ],
        );
        assert_eq!(
            complete(&narrow, MandatorySuffixAnalysisLimits::default())
                .candidate()
                .as_bytes(),
            b"Z",
        );
        let narrow = declined_corridor(
            &narrow,
            2,
            2,
            MandatorySuffixAnalysisLimits::default(),
        );
        assert_eq!(
            narrow.reason(),
            MandatorySuffixUniversalFiniteCorridorDeclineReason::NotUniversal,
        );

        let asserted = raw(
            0,
            &[
                StateRole::Split,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Accept,
            ],
            &[
                &[assertion(1, EdgeKind::AssertHaystackStart)],
                &[(2, EdgeKind::ByteRange, 0, u8::MAX)],
                &[byte(3, b'Z')],
                &[],
            ],
        );
        let asserted_suffix = complete(&asserted, MandatorySuffixAnalysisLimits::default());
        assert_eq!(asserted_suffix.candidate().as_bytes(), b"Z");
        assert_eq!(asserted_suffix.stats().assertion_edges(), 1);
        let asserted = declined_corridor(
            &asserted,
            2,
            2,
            MandatorySuffixAnalysisLimits::default(),
        );
        assert_eq!(
            asserted.reason(),
            MandatorySuffixUniversalFiniteCorridorDeclineReason::NotUniversal,
        );
    }

    #[test]
    fn corridor_resource_refusal_preserves_the_generic_suffix() {
        let plan = raw(
            0,
            &[StateRole::Consume, StateRole::Consume, StateRole::Accept],
            &[
                &[(1, EdgeKind::ByteRange, 0, u8::MAX)],
                &[byte(2, b'Z')],
                &[],
            ],
        );
        let generic = complete(&plan, MandatorySuffixAnalysisLimits::default());
        let limits = MandatorySuffixAnalysisLimits {
            max_work: generic.stats().work(),
            ..MandatorySuffixAnalysisLimits::default()
        };
        let refused = declined_corridor(&plan, 2, 2, limits);
        assert!(matches!(
            refused.reason(),
            MandatorySuffixUniversalFiniteCorridorDeclineReason::Analysis(
                MandatorySuffixDeclineReason::Resource {
                    resource: MandatorySuffixResource::Work,
                    ..
                }
            )
        ));
        assert!(refused.stats().closes(limits));

        let depth_refused = declined_corridor(
            &plan,
            2,
            MAX_MANDATORY_SUFFIX_UNIVERSAL_CORRIDOR_PREFIX_BYTES + 2,
            MandatorySuffixAnalysisLimits::default(),
        );
        assert_eq!(
            depth_refused.reason(),
            MandatorySuffixUniversalFiniteCorridorDeclineReason::PrefixDepthLimit {
                needed: MAX_MANDATORY_SUFFIX_UNIVERSAL_CORRIDOR_PREFIX_BYTES + 1,
                limit: MAX_MANDATORY_SUFFIX_UNIVERSAL_CORRIDOR_PREFIX_BYTES,
            },
        );
    }

    #[test]
    fn universal_corridor_exact_and_one_below_resource_receipts_close() {
        let plan = raw(
            0,
            &[StateRole::Consume, StateRole::Consume, StateRole::Accept],
            &[
                &[(1, EdgeKind::ByteRange, 0, u8::MAX)],
                &[byte(2, b'Z')],
                &[],
            ],
        );
        let generous = MandatorySuffixAnalysisLimits::default();
        let report = complete_with_corridor(&plan, 2, 2, generous);
        let stats = report.stats();
        assert!(stats.closes(generous));
        assert_ne!(stats.work(), 0);
        assert_ne!(stats.allocation_items(), 0);
        assert_ne!(stats.allocation_attempts(), 0);

        let exact_limits = MandatorySuffixAnalysisLimits {
            max_work: stats.work(),
            max_allocation_items: stats.allocation_items(),
            max_allocation_attempts: stats.allocation_attempts(),
            ..generous
        };
        let exact = complete_with_corridor(&plan, 2, 2, exact_limits);
        assert_eq!(exact.candidate().as_bytes(), b"Z");
        assert_eq!(exact.corridor().minimum_prefix_bytes(), 1);
        assert_eq!(exact.corridor().maximum_prefix_bytes(), 1);
        assert!(exact.stats().closes(exact_limits));

        let one_below = [
            (
                MandatorySuffixAnalysisLimits {
                    max_work: stats.work() - 1,
                    ..generous
                },
                MandatorySuffixResource::Work,
            ),
            (
                MandatorySuffixAnalysisLimits {
                    max_allocation_items: stats.allocation_items() - 1,
                    ..generous
                },
                MandatorySuffixResource::AllocationItems,
            ),
            (
                MandatorySuffixAnalysisLimits {
                    max_allocation_attempts: stats.allocation_attempts() - 1,
                    ..generous
                },
                MandatorySuffixResource::AllocationAttempts,
            ),
        ];
        for (limits, expected_resource) in one_below {
            let MandatorySuffixUniversalFiniteCorridorAnalysis::Declined(decline) =
                analyze_mandatory_suffix_universal_finite_corridor(&plan, limits, 2, 2)
            else {
                panic!("one-below universal-corridor ceiling unexpectedly completed")
            };
            assert!(matches!(
                decline.reason(),
                MandatorySuffixUniversalFiniteCorridorDeclineReason::Analysis(
                    MandatorySuffixDeclineReason::Resource { resource, .. }
                ) if resource == expected_resource
            ));
            assert!(decline.stats().closes(limits));
        }
    }

    #[test]
    fn longest_common_suffix_stops_before_an_ambiguous_layer() {
        let plan = raw(
            0,
            &[
                StateRole::Split,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Accept,
            ],
            &[
                &[epsilon(1), epsilon(2)],
                &[byte(3, b'a')],
                &[byte(3, b'b')],
                &[byte(4, b'c')],
                &[],
            ],
        );
        let report = complete(&plan, MandatorySuffixAnalysisLimits::default());
        assert_eq!(report.candidate().as_bytes(), b"c");
        assert_eq!(
            report.stop_reason(),
            MandatorySuffixStopReason::AmbiguousLayer
        );
    }

    #[test]
    fn first_ambiguous_layer_declines_transactionally() {
        for plan in [
            raw(
                0,
                &[StateRole::Consume, StateRole::Accept],
                &[&[(1, EdgeKind::ByteRange, b'a', b'b')], &[]],
            ),
            raw(
                0,
                &[
                    StateRole::Split,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Accept,
                ],
                &[
                    &[epsilon(1), epsilon(2)],
                    &[byte(3, b'a')],
                    &[byte(3, b'b')],
                    &[],
                ],
            ),
        ] {
            assert_eq!(
                declined(&plan).reason(),
                MandatorySuffixDeclineReason::AmbiguousSuffixLayer
            );
        }
    }

    #[test]
    fn multiple_accepts_and_epsilon_cycles_remain_sound() {
        let multiple = raw(
            0,
            &[
                StateRole::Split,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Accept,
                StateRole::Accept,
            ],
            &[
                &[epsilon(1), epsilon(2)],
                &[byte(3, b'x')],
                &[byte(4, b'x')],
                &[],
                &[],
            ],
        );
        assert_eq!(
            complete(&multiple, MandatorySuffixAnalysisLimits::default())
                .candidate()
                .as_bytes(),
            b"x"
        );

        let cycle = raw(
            0,
            &[StateRole::Consume, StateRole::Split, StateRole::Accept],
            &[&[byte(1, b'a')], &[epsilon(0), epsilon(2)], &[]],
        );
        let report = complete(&cycle, MandatorySuffixAnalysisLimits::default());
        assert_eq!(report.candidate().as_bytes(), b"a");
        assert_eq!(
            report.stop_reason(),
            MandatorySuffixStopReason::StartBoundary
        );
    }

    #[test]
    fn explicit_byte_bound_publishes_only_proved_tail() {
        let plan = raw(
            0,
            &[
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Accept,
            ],
            &[&[byte(1, b'a')], &[byte(2, b'b')], &[byte(3, b'c')], &[]],
        );
        let limits = MandatorySuffixAnalysisLimits {
            max_suffix_bytes: 2,
            ..MandatorySuffixAnalysisLimits::default()
        };
        let report = complete(&plan, limits);
        assert_eq!(report.candidate().as_bytes(), b"bc");
        assert_eq!(
            report.stop_reason(),
            MandatorySuffixStopReason::MaximumBytes
        );
        assert!(report.stats().closes(limits));
    }

    #[test]
    fn empty_and_relaxed_nullable_graphs_decline() {
        let empty = raw(0, &[StateRole::Split, StateRole::Accept], &[&[], &[]]);
        assert_eq!(
            declined(&empty).reason(),
            MandatorySuffixDeclineReason::EmptyLanguage
        );

        let nullable = raw(
            0,
            &[StateRole::Split, StateRole::Accept],
            &[&[epsilon(1)], &[]],
        );
        assert_eq!(
            declined(&nullable).reason(),
            MandatorySuffixDeclineReason::NullableLanguage
        );

        for kind in assertions() {
            let plan = raw(
                0,
                &[StateRole::Split, StateRole::Accept],
                &[&[assertion(1, kind)], &[]],
            );
            let decline = declined(&plan);
            assert_eq!(
                decline.reason(),
                MandatorySuffixDeclineReason::NullableLanguage
            );
            assert_eq!(decline.stats().assertion_edges(), 1);
        }
    }

    #[test]
    fn every_assertion_kind_is_relaxed_before_and_after_the_suffix() {
        for kind in assertions() {
            let before = raw(
                0,
                &[StateRole::Split, StateRole::Consume, StateRole::Accept],
                &[&[assertion(1, kind)], &[byte(2, b'z')], &[]],
            );
            let before = complete(&before, MandatorySuffixAnalysisLimits::default());
            assert_eq!(before.candidate().as_bytes(), b"z");
            assert_eq!(
                before.stop_reason(),
                MandatorySuffixStopReason::StartBoundary
            );
            assert_eq!(before.stats().assertion_edges(), 1);

            let after = raw(
                0,
                &[StateRole::Consume, StateRole::Split, StateRole::Accept],
                &[&[byte(1, b'z')], &[assertion(2, kind)], &[]],
            );
            let after = complete(&after, MandatorySuffixAnalysisLimits::default());
            assert_eq!(after.candidate().as_bytes(), b"z");
            assert_eq!(
                after.stop_reason(),
                MandatorySuffixStopReason::StartBoundary
            );
            assert_eq!(after.stats().assertion_edges(), 1);
        }
    }

    #[test]
    fn unreachable_assertions_are_counted_without_blocking_a_suffix() {
        let plan = raw(
            0,
            &[StateRole::Consume, StateRole::Accept, StateRole::Split],
            &[
                &[byte(1, b'z')],
                &[],
                &[assertion(1, EdgeKind::AssertHaystackStart)],
            ],
        );
        let report = complete(&plan, MandatorySuffixAnalysisLimits::default());
        assert_eq!(report.candidate().as_bytes(), b"z");
        assert_eq!(report.stats().assertion_edges(), 1);
    }

    #[test]
    fn assertion_relaxation_can_only_make_the_suffix_proof_more_conservative() {
        let plan = raw(
            0,
            &[
                StateRole::Split,
                StateRole::Consume,
                StateRole::Split,
                StateRole::Consume,
                StateRole::Accept,
            ],
            &[
                &[epsilon(1), epsilon(2)],
                &[byte(4, b'a')],
                &[assertion(3, EdgeKind::AssertHaystackStart)],
                &[byte(4, b'b')],
                &[],
            ],
        );
        let decline = declined(&plan);
        assert_eq!(
            decline.reason(),
            MandatorySuffixDeclineReason::AmbiguousSuffixLayer
        );
        assert_eq!(decline.stats().assertion_edges(), 1);
    }

    #[test]
    fn malformed_graph_classes_are_typed() {
        let cases = [
            (
                RawPlan {
                    start: 0,
                    roles: vec![],
                    edge_offsets: vec![0],
                    edge_targets: vec![],
                    edge_kinds: vec![],
                    byte_starts: vec![],
                    byte_ends: vec![],
                },
                MandatorySuffixGraphIssue::Empty,
            ),
            (
                raw(1, &[StateRole::Accept], &[&[]]),
                MandatorySuffixGraphIssue::StartOutOfRange,
            ),
            (
                raw(0, &[StateRole::Split], &[&[]]),
                MandatorySuffixGraphIssue::MissingAccept,
            ),
        ];
        for (plan, issue) in cases {
            assert_eq!(
                declined(&plan).reason(),
                MandatorySuffixDeclineReason::MalformedGraph(issue)
            );
        }

        let mut offsets = raw(0, &[StateRole::Accept], &[&[]]);
        offsets.edge_offsets = vec![1, 0];
        assert_eq!(
            declined(&offsets).reason(),
            MandatorySuffixDeclineReason::MalformedGraph(MandatorySuffixGraphIssue::OffsetShape)
        );

        let mut edge_shape = raw(
            0,
            &[StateRole::Consume, StateRole::Accept],
            &[&[byte(1, b'a')], &[]],
        );
        edge_shape.byte_ends.clear();
        assert_eq!(
            declined(&edge_shape).reason(),
            MandatorySuffixDeclineReason::MalformedGraph(MandatorySuffixGraphIssue::EdgeTableShape)
        );

        let mut edge_offset = raw(
            0,
            &[StateRole::Consume, StateRole::Split, StateRole::Accept],
            &[&[byte(2, b'a')], &[], &[]],
        );
        edge_offset.edge_offsets = vec![0, 1, 0, 1];
        assert_eq!(
            declined(&edge_offset).reason(),
            MandatorySuffixDeclineReason::MalformedGraph(MandatorySuffixGraphIssue::EdgeOffset)
        );

        let bad_target = raw(
            0,
            &[StateRole::Consume, StateRole::Accept],
            &[&[byte(9, b'a')], &[]],
        );
        assert_eq!(
            declined(&bad_target).reason(),
            MandatorySuffixDeclineReason::MalformedGraph(
                MandatorySuffixGraphIssue::EdgeTargetOutOfRange
            )
        );

        let bad_role = raw(
            0,
            &[StateRole::Split, StateRole::Accept],
            &[&[byte(1, b'a')], &[]],
        );
        assert_eq!(
            declined(&bad_role).reason(),
            MandatorySuffixDeclineReason::MalformedGraph(MandatorySuffixGraphIssue::StateRoleEdges)
        );

        let bad_payload = raw(
            0,
            &[StateRole::Split, StateRole::Accept],
            &[&[(1, EdgeKind::Epsilon, 1, 1)], &[]],
        );
        assert_eq!(
            declined(&bad_payload).reason(),
            MandatorySuffixDeclineReason::MalformedGraph(MandatorySuffixGraphIssue::EdgePayload)
        );

        let accept_edges = raw(
            0,
            &[StateRole::Accept, StateRole::Accept],
            &[&[epsilon(1)], &[]],
        );
        assert_eq!(
            declined(&accept_edges).reason(),
            MandatorySuffixDeclineReason::MalformedGraph(MandatorySuffixGraphIssue::StateRoleEdges)
        );

        let reversed_range = raw(
            0,
            &[StateRole::Consume, StateRole::Accept],
            &[&[(1, EdgeKind::ByteRange, b'z', b'a')], &[]],
        );
        assert_eq!(
            declined(&reversed_range).reason(),
            MandatorySuffixDeclineReason::MalformedGraph(MandatorySuffixGraphIssue::EdgePayload)
        );
    }

    #[test]
    fn exact_and_one_below_resource_receipts_close() {
        let plan = raw(
            0,
            &[StateRole::Consume, StateRole::Split, StateRole::Accept],
            &[
                &[byte(1, b'z')],
                &[assertion(2, EdgeKind::AssertHaystackEnd)],
                &[],
            ],
        );
        let generous = MandatorySuffixAnalysisLimits::default();
        let report = complete(&plan, generous);
        let stats = report.stats();
        assert!(stats.closes(generous));
        assert_eq!(
            stats.accounting_id(),
            "fre.automata.mandatory-suffix.v2"
        );
        assert_eq!(stats.assertion_edges(), 1);
        assert_eq!(stats.retained_bytes(), 1);

        for limited in [MandatorySuffixAnalysisLimits {
            max_work: stats.work(),
            max_allocation_items: stats.allocation_items(),
            max_allocation_attempts: stats.allocation_attempts(),
            ..generous
        }] {
            let exact = complete(&plan, limited);
            assert_eq!(exact.candidate().as_bytes(), b"z");
            assert!(exact.stats().closes(limited));
        }

        let one_below = [
            MandatorySuffixAnalysisLimits {
                max_work: stats.work() - 1,
                ..generous
            },
            MandatorySuffixAnalysisLimits {
                max_allocation_items: stats.allocation_items() - 1,
                ..generous
            },
            MandatorySuffixAnalysisLimits {
                max_allocation_attempts: stats.allocation_attempts() - 1,
                ..generous
            },
        ];
        for (index, limits) in one_below.into_iter().enumerate() {
            let MandatorySuffixAnalysis::Declined(decline) =
                analyze_mandatory_suffix(&plan, limits)
            else {
                panic!("one-below resource ceiling unexpectedly completed")
            };
            assert!(matches!(
                decline.reason(),
                MandatorySuffixDeclineReason::Resource { .. }
            ));
            assert!(decline.stats().closes(limits));
            if index == 0 {
                assert_eq!(decline.stats().completed_suffix_layers(), 1);
                assert_eq!(decline.stats().candidates(), 0);
                assert_eq!(decline.stats().retained_bytes(), 0);
            }
        }
    }

    #[test]
    fn invalid_inline_bounds_decline_without_allocating() {
        let plan = raw(
            0,
            &[StateRole::Consume, StateRole::Accept],
            &[&[byte(1, b'a')], &[]],
        );
        for max_suffix_bytes in [0, MAX_MANDATORY_SUFFIX_BYTES + 1] {
            let limits = MandatorySuffixAnalysisLimits {
                max_suffix_bytes,
                ..MandatorySuffixAnalysisLimits::default()
            };
            let MandatorySuffixAnalysis::Declined(decline) =
                analyze_mandatory_suffix(&plan, limits)
            else {
                panic!("invalid inline bound unexpectedly completed")
            };
            assert_eq!(decline.stats().allocation_attempts(), 0);
            assert!(matches!(
                decline.reason(),
                MandatorySuffixDeclineReason::Resource {
                    resource: MandatorySuffixResource::SuffixBytes,
                    ..
                }
            ));
        }
    }
}
