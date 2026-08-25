//! Bounded graph proof for mandatory consuming-state byte cuts.
//!
//! A candidate published by this module is a consuming state that dominates
//! the artificial accepting exit of the productive Thompson graph. Every
//! semantic match therefore visits that exact state. The byte class retains
//! only productive outgoing ranges from the state, so every match consumes a
//! member of the class there. Assertions are traversed conservatively as
//! zero-width graph edges: ignoring their truth can remove useful dominators,
//! but cannot invent a dominator or byte that excludes a semantic match.
//!
//! The maximum-before fact is computed on the productive graph's SCC
//! condensation. A consuming edge inside a relevant SCC makes the distance
//! unbounded; otherwise longest-path propagation yields the exact structural
//! maximum number of bytes consumed before entering the candidate root.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "checked resource arithmetic and validated CSR/byte-domain invariants guard the remaining indexing and bitmap operations"
)]

use core::{cmp::Ordering, mem::size_of};

use crate::{EdgeKind, RawPlan, StateRole};

/// Stable identity for this mandatory-cut proof and its accounting rules.
pub const MANDATORY_CUT_ACCOUNTING_ID: &str = "fre.automata.mandatory-cut.v2";
/// Default maximum abstract work for one optional mandatory-cut analysis.
pub const DEFAULT_MANDATORY_CUT_MAX_WORK: u64 = 2_000_000;
/// Default maximum cumulative logical scratch-allocation items.
pub const DEFAULT_MANDATORY_CUT_MAX_ALLOCATION_ITEMS: usize = 262_144;
/// Default maximum number of fallible scratch reservation attempts.
pub const DEFAULT_MANDATORY_CUT_MAX_ALLOCATION_ATTEMPTS: usize = 262_144;

/// Independent hard ceilings for one optional mandatory-cut proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_field_names,
    reason = "explicit max prefixes distinguish independent hard analysis ceilings"
)]
pub struct MandatoryCutAnalysisLimits {
    /// Exact abstract graph operations.
    pub max_work: u64,
    /// Cumulative logical vector slots requested by the analysis.
    pub max_allocation_items: usize,
    /// Fallible scratch reservation calls admitted by the analysis.
    pub max_allocation_attempts: usize,
}

impl Default for MandatoryCutAnalysisLimits {
    fn default() -> Self {
        Self {
            max_work: DEFAULT_MANDATORY_CUT_MAX_WORK,
            max_allocation_items: DEFAULT_MANDATORY_CUT_MAX_ALLOCATION_ITEMS,
            max_allocation_attempts: DEFAULT_MANDATORY_CUT_MAX_ALLOCATION_ATTEMPTS,
        }
    }
}

/// A separately limited resource consumed by mandatory-cut analysis.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MandatoryCutResource {
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
pub enum MandatoryCutGraphIssue {
    /// The state table is empty.
    Empty,
    /// A state or edge table cannot be indexed by the raw plan's `u32` space.
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

/// Transactional reason why no mandatory-cut report was published.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MandatoryCutDeclineReason {
    /// The raw graph is malformed for this standalone analysis.
    MalformedGraph(MandatoryCutGraphIssue),
    /// One declared hard ceiling was exceeded.
    Resource {
        /// Limited resource.
        resource: MandatoryCutResource,
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
    /// A valid graph violated an internal proof invariant.
    InternalInvariant {
        /// Named invariant.
        detail: &'static str,
    },
}

/// Exact work and allocation facts completed before success or decline.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MandatoryCutAnalysisStats {
    accounting_id: &'static str,
    work: u64,
    allocation_items: usize,
    allocation_attempts: usize,
    states: usize,
    edges: usize,
    productive_states: usize,
    accepting_states: usize,
    mandatory_roots: usize,
    candidates: usize,
    retained_bytes: usize,
    context_assertions: bool,
}

impl MandatoryCutAnalysisStats {
    /// Stable identity of the algorithm and accounting convention.
    #[must_use]
    pub const fn accounting_id(self) -> &'static str {
        self.accounting_id
    }

    /// Exact abstract work completed.
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

    /// Start-reachable states that can also reach an accept.
    #[must_use]
    pub const fn productive_states(self) -> usize {
        self.productive_states
    }

    /// Reachable accepting states in the productive graph.
    #[must_use]
    pub const fn accepting_states(self) -> usize {
        self.accepting_states
    }

    /// Consuming dominators inspected during inline candidate selection.
    #[must_use]
    pub const fn mandatory_roots(self) -> usize {
        self.mandatory_roots
    }

    /// Inline candidates retained by a completed analysis (zero or one).
    #[must_use]
    pub const fn candidates(self) -> usize {
        self.candidates
    }

    /// Physical bytes retained by the completed inline candidate.
    #[must_use]
    pub const fn retained_bytes(self) -> usize {
        self.retained_bytes
    }

    /// Whether one or more assertion edges were conservatively relaxed.
    #[must_use]
    pub const fn context_assertions(self) -> bool {
        self.context_assertions
    }

    /// Whether this receipt is internally consistent and within `limits`.
    #[must_use]
    pub fn closes(self, limits: MandatoryCutAnalysisLimits) -> bool {
        let retained_bytes = match self.candidates {
            0 => 0,
            1 => size_of::<MandatoryCutCandidate>(),
            _ => return false,
        };
        self.accounting_id == MANDATORY_CUT_ACCOUNTING_ID
            && self.work <= limits.max_work
            && self.allocation_items <= limits.max_allocation_items
            && self.allocation_attempts <= limits.max_allocation_attempts
            && self.productive_states <= self.states
            && self.accepting_states <= self.productive_states
            && self.candidates <= self.mandatory_roots
            && self.retained_bytes == retained_bytes
    }
}

/// Exact maximum consumed distance along every relevant productive walk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaximumConsumedDistance {
    /// Every relevant walk consumes at most this many bytes.
    Finite(u32),
    /// A consuming cycle lies on a relevant walk.
    Unbounded,
}

/// One immutable byte class required at a mandatory consuming root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MandatoryCutByteClass {
    words: [u64; 4],
}

impl MandatoryCutByteClass {
    /// Four little-endian-by-byte-membership bitmap words.
    #[must_use]
    pub const fn words(self) -> [u64; 4] {
        self.words
    }

    /// Number of member bytes in `0..=255`.
    #[must_use]
    pub fn cardinality(self) -> u16 {
        self.words
            .into_iter()
            .map(u64::count_ones)
            .try_fold(0_u16, |total, count| {
                total.checked_add(u16::try_from(count).ok()?)
            })
            .expect("a 256-bit byte class cardinality fits u16")
    }

    /// Whether `byte` belongs to this necessary class.
    #[must_use]
    pub fn contains(self, byte: u8) -> bool {
        let word = usize::from(byte / 64);
        let bit = u32::from(byte % 64);
        self.words[word] & (1_u64 << bit) != 0
    }
}

/// One consuming root visited by every structurally accepting graph path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MandatoryCutCandidate {
    root_state: u32,
    byte_class: MandatoryCutByteClass,
    maximum_before_root: MaximumConsumedDistance,
}

impl MandatoryCutCandidate {
    /// Mandatory consuming state in the supplied raw graph.
    #[must_use]
    pub const fn root_state(self) -> u32 {
        self.root_state
    }

    /// Necessary byte class consumed when the path leaves this root.
    #[must_use]
    pub const fn byte_class(self) -> MandatoryCutByteClass {
        self.byte_class
    }

    /// Exact maximum bytes consumed before entering this root.
    #[must_use]
    pub const fn maximum_before_root(self) -> MaximumConsumedDistance {
        self.maximum_before_root
    }
}

/// Completed optional analysis and its best structural candidate, if any.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MandatoryCutAnalysisReport {
    candidate: Option<MandatoryCutCandidate>,
    stats: MandatoryCutAnalysisStats,
}

impl MandatoryCutAnalysisReport {
    /// Best candidate in stable source-independent structural cost order.
    #[must_use]
    pub const fn candidate(self) -> Option<MandatoryCutCandidate> {
        self.candidate
    }

    /// Exact completed accounting.
    #[must_use]
    pub const fn stats(&self) -> MandatoryCutAnalysisStats {
        self.stats
    }
}

/// Closed decline receipt retaining the work completed before refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MandatoryCutAnalysisDecline {
    reason: MandatoryCutDeclineReason,
    stats: MandatoryCutAnalysisStats,
}

impl MandatoryCutAnalysisDecline {
    /// Exact reason no candidate report was published.
    #[must_use]
    pub const fn reason(self) -> MandatoryCutDeclineReason {
        self.reason
    }

    /// Exact completed accounting.
    #[must_use]
    pub const fn stats(self) -> MandatoryCutAnalysisStats {
        self.stats
    }
}

/// Transactional result of one optional mandatory-cut analysis.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MandatoryCutAnalysis {
    /// The complete productive graph was analyzed. The candidate may be absent
    /// when the language is empty, nullable, or has no consuming dominator.
    Complete(MandatoryCutAnalysisReport),
    /// No candidate may be consumed; inspect the closed decline receipt.
    Declined(MandatoryCutAnalysisDecline),
}

impl MandatoryCutAnalysis {
    /// Accounting shared by successful and declined outcomes.
    #[must_use]
    pub const fn stats(&self) -> MandatoryCutAnalysisStats {
        match self {
            Self::Complete(report) => report.stats(),
            Self::Declined(decline) => decline.stats(),
        }
    }
}

/// One completed mandatory-cut proof bound to exactly the immutable raw plan
/// that it analyzed.
///
/// This value is intentionally neither `Clone` nor `Copy`. A downstream graph
/// proof may consume it once, and the retained shared borrow prevents safe
/// mutation of the raw plan until that continuation completes. The raw plan is
/// not accepted again by the continuation API, so a caller cannot substitute a
/// different graph while reusing the candidate.
#[derive(Debug)]
pub struct MandatoryCutContinuation<'a> {
    raw: &'a RawPlan,
    report: MandatoryCutAnalysisReport,
}

impl<'a> MandatoryCutContinuation<'a> {
    /// Best candidate selected from the bound raw plan.
    #[must_use]
    pub const fn candidate(&self) -> Option<MandatoryCutCandidate> {
        self.report.candidate()
    }

    /// Exact completed accounting for the prerequisite proof.
    #[must_use]
    pub const fn stats(&self) -> MandatoryCutAnalysisStats {
        self.report.stats()
    }

    pub(crate) const fn into_parts(self) -> (&'a RawPlan, MandatoryCutAnalysisReport) {
        (self.raw, self.report)
    }
}

/// Result of requesting a continuation-capable mandatory-cut proof.
#[derive(Debug)]
pub enum MandatoryCutContinuationAnalysis<'a> {
    /// The complete proof and its immutable raw-plan binding.
    Complete(MandatoryCutContinuation<'a>),
    /// The prerequisite proof declined with its ordinary closed receipt.
    Declined(MandatoryCutAnalysisDecline),
}

impl MandatoryCutContinuationAnalysis<'_> {
    /// Accounting shared by successful and declined outcomes.
    #[must_use]
    pub const fn stats(&self) -> MandatoryCutAnalysisStats {
        match self {
            Self::Complete(continuation) => continuation.stats(),
            Self::Declined(decline) => decline.stats(),
        }
    }
}

/// Analyze a raw plan once and retain authority for one bound continuation.
///
/// The graph algorithm and receipt are identical to [`analyze_mandatory_cut`].
/// Only a completed report is wrapped in an immutable borrow so a downstream
/// proof can reuse it without rerunning dominator and distance analysis.
#[must_use]
pub fn analyze_mandatory_cut_continuation(
    raw: &RawPlan,
    limits: MandatoryCutAnalysisLimits,
) -> MandatoryCutContinuationAnalysis<'_> {
    match analyze_mandatory_cut(raw, limits) {
        MandatoryCutAnalysis::Complete(report) => {
            MandatoryCutContinuationAnalysis::Complete(MandatoryCutContinuation { raw, report })
        }
        MandatoryCutAnalysis::Declined(decline) => {
            MandatoryCutContinuationAnalysis::Declined(decline)
        }
    }
}

/// Analyze a raw Thompson graph for independently mandatory consuming roots.
///
/// No source syntax, haystack, timing signal, or expected result participates
/// in the proof or its stable ordering. A malformed graph or exhausted limit
/// returns a closed decline without exposing partial candidates.
///
/// The returned state index is a structural fact about this exact `raw` graph;
/// A runtime route must bind it to the immutable automaton constructed from
/// the same graph rather than pair it with an arbitrary plan.
#[must_use]
pub fn analyze_mandatory_cut(
    raw: &RawPlan,
    limits: MandatoryCutAnalysisLimits,
) -> MandatoryCutAnalysis {
    let mut budget = Budget::new(limits);
    match analyze_mandatory_cut_inner(raw, &mut budget) {
        Ok(candidate) => {
            budget.stats.candidates = usize::from(u8::from(candidate.is_some()));
            budget.stats.retained_bytes = match candidate {
                Some(_) => size_of::<MandatoryCutCandidate>(),
                None => 0,
            };
            if !budget.stats.closes(limits) {
                return MandatoryCutAnalysis::Declined(MandatoryCutAnalysisDecline {
                    reason: MandatoryCutDeclineReason::InternalInvariant {
                        detail: "mandatory-cut completion receipt did not close",
                    },
                    stats: budget.stats,
                });
            }
            MandatoryCutAnalysis::Complete(MandatoryCutAnalysisReport {
                candidate,
                stats: budget.stats,
            })
        }
        Err(reason) => {
            let reason = if budget.stats.closes(limits) {
                reason
            } else {
                MandatoryCutDeclineReason::InternalInvariant {
                    detail: "mandatory-cut decline receipt did not close",
                }
            };
            MandatoryCutAnalysis::Declined(MandatoryCutAnalysisDecline {
                reason,
                stats: budget.stats,
            })
        }
    }
}

fn analyze_mandatory_cut_inner(
    raw: &RawPlan,
    budget: &mut Budget,
) -> Result<Option<MandatoryCutCandidate>, MandatoryCutDeclineReason> {
    validate_shape(raw, budget)?;
    let graph = ProductiveGraph::build(raw, budget)?;
    budget.stats.accepting_states = graph.accepts.len();
    if graph.accepts.is_empty() {
        return Ok(None);
    }
    let start = to_usize(raw.start, "mandatory-cut singleton start")?;
    let productive_start_incoming = graph
        .incoming
        .by_target
        .get(start)
        .ok_or(MandatoryCutDeclineReason::InternalInvariant {
            detail: "mandatory-cut singleton start lost its incoming row",
        })?
        .iter()
        .try_fold(false, |present, edge| {
            budget.charge(1)?;
            let source = to_usize(edge.source, "mandatory-cut singleton incoming source")?;
            Ok::<_, MandatoryCutDeclineReason>(
                present || graph.productive.get(source) == Some(&true),
            )
        })?;
    if graph.productive.get(start) == Some(&true)
        && raw.roles.get(start) == Some(&StateRole::Consume)
        && !productive_start_incoming
    {
        let byte_class = first_byte_class(raw, &graph.productive, start, budget)?;
        // A productive consuming start with no productive incoming edge is
        // itself a mandatory root at exact consumed distance zero. When its
        // productive byte class is a singleton, no later root can outrank it:
        // cardinality and finite distance are both already at their non-empty
        // minima. Publish that exact stable winner without constructing
        // dominator or SCC-distance tables.
        if byte_class.cardinality() == 1 {
            budget.stats.mandatory_roots = 1;
            budget.charge(1)?;
            return Ok(Some(MandatoryCutCandidate {
                root_state: raw.start,
                byte_class,
                maximum_before_root: MaximumConsumedDistance::Finite(0),
            }));
        }
    }
    let dominators = DominatorFacts::build(raw, &graph, budget)?;
    let distances = DistanceFacts::build(raw, &graph, budget)?;
    select_mandatory_cut(raw, &graph, &dominators, &distances, budget)
}

fn compare_candidates(left: MandatoryCutCandidate, right: MandatoryCutCandidate) -> Ordering {
    let distance_rank = |distance| match distance {
        MaximumConsumedDistance::Finite(maximum) => (false, maximum),
        MaximumConsumedDistance::Unbounded => (true, u32::MAX),
    };
    left.byte_class
        .cardinality()
        .cmp(&right.byte_class.cardinality())
        .then_with(|| {
            distance_rank(left.maximum_before_root).cmp(&distance_rank(right.maximum_before_root))
        })
        .then_with(|| left.root_state.cmp(&right.root_state))
        .then_with(|| left.byte_class.words.cmp(&right.byte_class.words))
}

#[derive(Clone, Copy, Debug)]
struct Budget {
    limits: MandatoryCutAnalysisLimits,
    stats: MandatoryCutAnalysisStats,
}

impl Budget {
    const fn new(limits: MandatoryCutAnalysisLimits) -> Self {
        Self {
            limits,
            stats: MandatoryCutAnalysisStats {
                accounting_id: MANDATORY_CUT_ACCOUNTING_ID,
                work: 0,
                allocation_items: 0,
                allocation_attempts: 0,
                states: 0,
                edges: 0,
                productive_states: 0,
                accepting_states: 0,
                mandatory_roots: 0,
                candidates: 0,
                retained_bytes: 0,
                context_assertions: false,
            },
        }
    }

    fn charge(&mut self, amount: u64) -> Result<(), MandatoryCutDeclineReason> {
        let needed = self.stats.work.checked_add(amount).ok_or(
            MandatoryCutDeclineReason::ArithmeticOverflow {
                computation: "mandatory-cut work",
            },
        )?;
        if needed > self.limits.max_work {
            return Err(MandatoryCutDeclineReason::Resource {
                resource: MandatoryCutResource::Work,
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
    ) -> Result<(), MandatoryCutDeclineReason> {
        if additional == 0 {
            return Ok(());
        }
        let needed = self.stats.allocation_items.checked_add(additional).ok_or(
            MandatoryCutDeclineReason::ArithmeticOverflow {
                computation: "mandatory-cut allocation items",
            },
        )?;
        if needed > self.limits.max_allocation_items {
            let reason = resource_usize(
                MandatoryCutResource::AllocationItems,
                needed,
                self.limits.max_allocation_items,
            )?;
            return Err(reason);
        }
        let attempts = self.stats.allocation_attempts.checked_add(1).ok_or(
            MandatoryCutDeclineReason::ArithmeticOverflow {
                computation: "mandatory-cut allocation attempts",
            },
        )?;
        if attempts > self.limits.max_allocation_attempts {
            let reason = resource_usize(
                MandatoryCutResource::AllocationAttempts,
                attempts,
                self.limits.max_allocation_attempts,
            )?;
            return Err(reason);
        }
        self.stats.allocation_attempts = attempts;
        values.try_reserve_exact(additional).map_err(|_| {
            MandatoryCutDeclineReason::Allocation {
                structure,
                additional,
            }
        })?;
        self.stats.allocation_items = needed;
        Ok(())
    }

    fn push<T>(
        &mut self,
        values: &mut Vec<T>,
        value: T,
        structure: &'static str,
    ) -> Result<(), MandatoryCutDeclineReason> {
        self.reserve(values, 1, structure)?;
        self.charge(1)?;
        values.push(value);
        Ok(())
    }

    fn filled<T: Clone>(
        &mut self,
        length: usize,
        value: T,
        structure: &'static str,
    ) -> Result<Vec<T>, MandatoryCutDeclineReason> {
        let mut values = Vec::new();
        self.reserve(&mut values, length, structure)?;
        self.charge(to_u64(length, "mandatory-cut initialized items")?)?;
        values.resize(length, value);
        Ok(values)
    }
}

fn resource_usize(
    resource: MandatoryCutResource,
    needed: usize,
    limit: usize,
) -> Result<MandatoryCutDeclineReason, MandatoryCutDeclineReason> {
    Ok(MandatoryCutDeclineReason::Resource {
        resource,
        needed: to_u64(needed, "mandatory-cut resource need")?,
        limit: to_u64(limit, "mandatory-cut resource limit")?,
    })
}

fn to_u64(value: usize, computation: &'static str) -> Result<u64, MandatoryCutDeclineReason> {
    u64::try_from(value).map_err(|_| MandatoryCutDeclineReason::ArithmeticOverflow { computation })
}

fn to_usize(value: u32, computation: &'static str) -> Result<usize, MandatoryCutDeclineReason> {
    usize::try_from(value)
        .map_err(|_| MandatoryCutDeclineReason::ArithmeticOverflow { computation })
}

#[allow(
    clippy::too_many_lines,
    reason = "one bounded pass validates every raw graph table before proof construction"
)]
fn validate_shape(raw: &RawPlan, budget: &mut Budget) -> Result<(), MandatoryCutDeclineReason> {
    budget.charge(1)?;
    let states = raw.roles.len();
    if states == 0 {
        return Err(MandatoryCutDeclineReason::MalformedGraph(
            MandatoryCutGraphIssue::Empty,
        ));
    }
    let edges = raw.edge_targets.len();
    if u32::try_from(states).is_err() || u32::try_from(edges).is_err() {
        return Err(MandatoryCutDeclineReason::MalformedGraph(
            MandatoryCutGraphIssue::IndexSpaceExceeded,
        ));
    }
    let start = to_usize(raw.start, "mandatory-cut start index")?;
    if start >= states {
        return Err(MandatoryCutDeclineReason::MalformedGraph(
            MandatoryCutGraphIssue::StartOutOfRange,
        ));
    }
    if raw.edge_kinds.len() != edges
        || raw.byte_starts.len() != edges
        || raw.byte_ends.len() != edges
    {
        return Err(MandatoryCutDeclineReason::MalformedGraph(
            MandatoryCutGraphIssue::EdgeTableShape,
        ));
    }
    if raw.edge_offsets.len()
        != states
            .checked_add(1)
            .ok_or(MandatoryCutDeclineReason::ArithmeticOverflow {
                computation: "mandatory-cut offset slots",
            })?
        || raw.edge_offsets.first() != Some(&0)
        || raw
            .edge_offsets
            .last()
            .and_then(|&offset| usize::try_from(offset).ok())
            != Some(edges)
    {
        return Err(MandatoryCutDeclineReason::MalformedGraph(
            MandatoryCutGraphIssue::OffsetShape,
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
                return Err(MandatoryCutDeclineReason::MalformedGraph(
                    MandatoryCutGraphIssue::StateRoleEdges,
                ));
            }
            StateRole::Accept => has_accept = true,
            StateRole::Split | StateRole::Consume => {}
        }
        for edge in row {
            budget.charge(1)?;
            let target = raw.edge_targets.get(edge).copied().ok_or(
                MandatoryCutDeclineReason::MalformedGraph(MandatoryCutGraphIssue::EdgeTableShape),
            )?;
            if to_usize(target, "mandatory-cut edge target")? >= states {
                return Err(MandatoryCutDeclineReason::MalformedGraph(
                    MandatoryCutGraphIssue::EdgeTargetOutOfRange,
                ));
            }
            let kind =
                *raw.edge_kinds
                    .get(edge)
                    .ok_or(MandatoryCutDeclineReason::MalformedGraph(
                        MandatoryCutGraphIssue::EdgeTableShape,
                    ))?;
            let start_byte =
                *raw.byte_starts
                    .get(edge)
                    .ok_or(MandatoryCutDeclineReason::MalformedGraph(
                        MandatoryCutGraphIssue::EdgeTableShape,
                    ))?;
            let end_byte =
                *raw.byte_ends
                    .get(edge)
                    .ok_or(MandatoryCutDeclineReason::MalformedGraph(
                        MandatoryCutGraphIssue::EdgeTableShape,
                    ))?;
            match raw.roles[state] {
                StateRole::Accept => {
                    return Err(MandatoryCutDeclineReason::InternalInvariant {
                        detail: "validated accept state retained an edge",
                    });
                }
                StateRole::Consume => {
                    if kind != EdgeKind::ByteRange {
                        return Err(MandatoryCutDeclineReason::MalformedGraph(
                            MandatoryCutGraphIssue::StateRoleEdges,
                        ));
                    }
                    if start_byte > end_byte {
                        return Err(MandatoryCutDeclineReason::MalformedGraph(
                            MandatoryCutGraphIssue::EdgePayload,
                        ));
                    }
                }
                StateRole::Split => {
                    if kind == EdgeKind::ByteRange || !kind.is_zero_width() {
                        return Err(MandatoryCutDeclineReason::MalformedGraph(
                            MandatoryCutGraphIssue::StateRoleEdges,
                        ));
                    }
                    if start_byte != 0 || end_byte != 0 {
                        return Err(MandatoryCutDeclineReason::MalformedGraph(
                            MandatoryCutGraphIssue::EdgePayload,
                        ));
                    }
                    if kind != EdgeKind::Epsilon {
                        if kind.assertion_bit().is_none() {
                            return Err(MandatoryCutDeclineReason::MalformedGraph(
                                MandatoryCutGraphIssue::UnsupportedGraphKind,
                            ));
                        }
                        budget.stats.context_assertions = true;
                    }
                }
            }
        }
    }
    if !has_accept {
        return Err(MandatoryCutDeclineReason::MalformedGraph(
            MandatoryCutGraphIssue::MissingAccept,
        ));
    }
    Ok(())
}

fn state_edges(
    raw: &RawPlan,
    state: usize,
) -> Result<core::ops::Range<usize>, MandatoryCutDeclineReason> {
    let begin =
        raw.edge_offsets
            .get(state)
            .copied()
            .ok_or(MandatoryCutDeclineReason::MalformedGraph(
                MandatoryCutGraphIssue::OffsetShape,
            ))?;
    let end = raw
        .edge_offsets
        .get(
            state
                .checked_add(1)
                .ok_or(MandatoryCutDeclineReason::ArithmeticOverflow {
                    computation: "mandatory-cut next state",
                })?,
        )
        .copied()
        .ok_or(MandatoryCutDeclineReason::MalformedGraph(
            MandatoryCutGraphIssue::OffsetShape,
        ))?;
    let begin = to_usize(begin, "mandatory-cut row start")?;
    let end = to_usize(end, "mandatory-cut row end")?;
    if begin > end || end > raw.edge_targets.len() {
        return Err(MandatoryCutDeclineReason::MalformedGraph(
            MandatoryCutGraphIssue::EdgeOffset,
        ));
    }
    Ok(begin..end)
}

#[derive(Clone, Copy, Debug)]
struct IncomingEdge {
    source: u32,
}

#[derive(Debug)]
struct Incoming {
    by_target: Vec<Vec<IncomingEdge>>,
}

impl Incoming {
    fn build(raw: &RawPlan, budget: &mut Budget) -> Result<Self, MandatoryCutDeclineReason> {
        let mut by_target =
            budget.filled(raw.roles.len(), Vec::new(), "mandatory-cut incoming rows")?;
        for source in 0..raw.roles.len() {
            let source_u32 = u32::try_from(source).map_err(|_| {
                MandatoryCutDeclineReason::ArithmeticOverflow {
                    computation: "mandatory-cut incoming source",
                }
            })?;
            for edge in state_edges(raw, source)? {
                budget.charge(1)?;
                let target = to_usize(raw.edge_targets[edge], "mandatory-cut incoming target")?;
                let row =
                    by_target
                        .get_mut(target)
                        .ok_or(MandatoryCutDeclineReason::MalformedGraph(
                            MandatoryCutGraphIssue::EdgeTargetOutOfRange,
                        ))?;
                budget.push(
                    row,
                    IncomingEdge { source: source_u32 },
                    "mandatory-cut incoming edges",
                )?;
            }
        }
        Ok(Self { by_target })
    }
}

#[derive(Debug)]
struct ProductiveGraph {
    incoming: Incoming,
    productive: Vec<bool>,
    accepts: Vec<usize>,
    reverse_postorder: Vec<usize>,
}

impl ProductiveGraph {
    fn build(raw: &RawPlan, budget: &mut Budget) -> Result<Self, MandatoryCutDeclineReason> {
        let incoming = Incoming::build(raw, budget)?;
        let states = raw.roles.len();
        let start = to_usize(raw.start, "mandatory-cut productive start")?;
        let mut reachable = budget.filled(states, false, "mandatory-cut reachable states")?;
        let mut stack = Vec::new();
        reachable[start] = true;
        budget.push(&mut stack, start, "mandatory-cut reachability stack")?;
        let mut accepts = Vec::new();
        while let Some(state) = stack.pop() {
            budget.charge(1)?;
            if raw.roles[state] == StateRole::Accept {
                budget.push(&mut accepts, state, "mandatory-cut accepting states")?;
                continue;
            }
            for edge in state_edges(raw, state)? {
                budget.charge(1)?;
                let target = to_usize(
                    raw.edge_targets[edge],
                    "mandatory-cut reachable edge target",
                )?;
                if !reachable[target] {
                    reachable[target] = true;
                    budget.push(&mut stack, target, "mandatory-cut reachability stack")?;
                }
            }
        }

        if accepts.is_empty() {
            return Ok(Self {
                incoming,
                productive: budget.filled(
                    states,
                    false,
                    "mandatory-cut empty productive states",
                )?,
                accepts,
                reverse_postorder: Vec::new(),
            });
        }

        let mut coreachable = budget.filled(states, false, "mandatory-cut coreachable states")?;
        stack.clear();
        for &accept in &accepts {
            coreachable[accept] = true;
            budget.push(&mut stack, accept, "mandatory-cut coreachability stack")?;
        }
        while let Some(state) = stack.pop() {
            budget.charge(1)?;
            for &edge in incoming.by_target.get(state).ok_or(
                MandatoryCutDeclineReason::InternalInvariant {
                    detail: "incoming row missing for validated target",
                },
            )? {
                budget.charge(1)?;
                let source = to_usize(edge.source, "mandatory-cut coreachable source")?;
                if !coreachable[source] {
                    coreachable[source] = true;
                    budget.push(&mut stack, source, "mandatory-cut coreachability stack")?;
                }
            }
        }

        let mut productive = budget.filled(states, false, "mandatory-cut productive states")?;
        for state in 0..states {
            budget.charge(1)?;
            productive[state] = reachable[state] && coreachable[state];
            if productive[state] {
                budget.stats.productive_states =
                    budget.stats.productive_states.checked_add(1).ok_or(
                        MandatoryCutDeclineReason::ArithmeticOverflow {
                            computation: "mandatory-cut productive state count",
                        },
                    )?;
            }
        }
        let reverse_postorder = productive_reverse_postorder(raw, &productive, start, budget)?;
        Ok(Self {
            incoming,
            productive,
            accepts,
            reverse_postorder,
        })
    }
}

fn productive_reverse_postorder(
    raw: &RawPlan,
    productive: &[bool],
    start: usize,
    budget: &mut Budget,
) -> Result<Vec<usize>, MandatoryCutDeclineReason> {
    let exit = raw.roles.len();
    let node_count = exit
        .checked_add(1)
        .ok_or(MandatoryCutDeclineReason::ArithmeticOverflow {
            computation: "mandatory-cut artificial exit",
        })?;
    let mut visited = budget.filled(node_count, false, "mandatory-cut reverse-postorder marks")?;
    let mut stack = Vec::new();
    let mut postorder = Vec::new();
    visited[start] = true;
    budget.push(
        &mut stack,
        (start, false),
        "mandatory-cut reverse-postorder stack",
    )?;
    while let Some((node, expanded)) = stack.pop() {
        budget.charge(1)?;
        if expanded {
            budget.push(&mut postorder, node, "mandatory-cut reverse postorder")?;
            continue;
        }
        budget.push(
            &mut stack,
            (node, true),
            "mandatory-cut reverse-postorder stack",
        )?;
        if node == exit {
            continue;
        }
        match raw.roles[node] {
            StateRole::Accept => {
                if !visited[exit] {
                    visited[exit] = true;
                    budget.push(
                        &mut stack,
                        (exit, false),
                        "mandatory-cut reverse-postorder stack",
                    )?;
                }
            }
            StateRole::Split | StateRole::Consume => {
                for edge in state_edges(raw, node)?.rev() {
                    budget.charge(1)?;
                    let target = to_usize(
                        raw.edge_targets[edge],
                        "mandatory-cut reverse-postorder target",
                    )?;
                    if productive.get(target) == Some(&true) && !visited[target] {
                        visited[target] = true;
                        budget.push(
                            &mut stack,
                            (target, false),
                            "mandatory-cut reverse-postorder stack",
                        )?;
                    }
                }
            }
        }
    }
    if !visited[exit] {
        return Err(MandatoryCutDeclineReason::InternalInvariant {
            detail: "productive graph did not reach its artificial exit",
        });
    }
    budget.charge(to_u64(
        postorder.len() / 2,
        "mandatory-cut reverse-postorder swaps",
    )?)?;
    postorder.reverse();
    Ok(postorder)
}

#[derive(Debug)]
struct DominatorFacts {
    immediate: Vec<usize>,
    start: usize,
    exit: usize,
}

impl DominatorFacts {
    fn build(
        raw: &RawPlan,
        graph: &ProductiveGraph,
        budget: &mut Budget,
    ) -> Result<Self, MandatoryCutDeclineReason> {
        let exit = raw.roles.len();
        let node_count =
            exit.checked_add(1)
                .ok_or(MandatoryCutDeclineReason::ArithmeticOverflow {
                    computation: "mandatory-cut dominator nodes",
                })?;
        let start = to_usize(raw.start, "mandatory-cut dominator start")?;
        let mut position =
            budget.filled(node_count, usize::MAX, "mandatory-cut dominator positions")?;
        for (index, &node) in graph.reverse_postorder.iter().enumerate() {
            budget.charge(1)?;
            *position
                .get_mut(node)
                .ok_or(MandatoryCutDeclineReason::InternalInvariant {
                    detail: "reverse-postorder node escaped dominator positions",
                })? = index;
        }
        let mut immediate =
            budget.filled(node_count, usize::MAX, "mandatory-cut immediate dominators")?;
        immediate[start] = start;
        loop {
            budget.charge(1)?;
            let mut changed = false;
            for &node in graph.reverse_postorder.iter().skip(1) {
                budget.charge(1)?;
                let mut next = None;
                if node == exit {
                    for &predecessor in &graph.accepts {
                        consider_dominator_predecessor(
                            predecessor,
                            &mut next,
                            &immediate,
                            &position,
                            budget,
                        )?;
                    }
                } else {
                    for &edge in graph.incoming.by_target.get(node).ok_or(
                        MandatoryCutDeclineReason::InternalInvariant {
                            detail: "dominator target lost its incoming row",
                        },
                    )? {
                        budget.charge(1)?;
                        let predecessor = to_usize(edge.source, "mandatory-cut dominator source")?;
                        if graph.productive.get(predecessor) != Some(&true) {
                            continue;
                        }
                        consider_dominator_predecessor(
                            predecessor,
                            &mut next,
                            &immediate,
                            &position,
                            budget,
                        )?;
                    }
                }
                let next = next.ok_or(MandatoryCutDeclineReason::InternalInvariant {
                    detail: "productive dominator node had no initialized predecessor",
                })?;
                if immediate[node] != next {
                    immediate[node] = next;
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        Ok(Self {
            immediate,
            start,
            exit,
        })
    }
}

fn consider_dominator_predecessor(
    predecessor: usize,
    next: &mut Option<usize>,
    immediate: &[usize],
    position: &[usize],
    budget: &mut Budget,
) -> Result<(), MandatoryCutDeclineReason> {
    budget.charge(1)?;
    if immediate
        .get(predecessor)
        .copied()
        .ok_or(MandatoryCutDeclineReason::InternalInvariant {
            detail: "dominator predecessor escaped its table",
        })?
        == usize::MAX
    {
        return Ok(());
    }
    *next = Some(match *next {
        None => predecessor,
        Some(current) => intersect_dominators(current, predecessor, immediate, position, budget)?,
    });
    Ok(())
}

fn intersect_dominators(
    mut left: usize,
    mut right: usize,
    immediate: &[usize],
    position: &[usize],
    budget: &mut Budget,
) -> Result<usize, MandatoryCutDeclineReason> {
    while left != right {
        while position
            .get(left)
            .copied()
            .ok_or(MandatoryCutDeclineReason::InternalInvariant {
                detail: "left dominator escaped its position table",
            })?
            > position
                .get(right)
                .copied()
                .ok_or(MandatoryCutDeclineReason::InternalInvariant {
                    detail: "right dominator escaped its position table",
                })?
        {
            budget.charge(1)?;
            left = *immediate
                .get(left)
                .ok_or(MandatoryCutDeclineReason::InternalInvariant {
                    detail: "left dominator escaped its parent table",
                })?;
        }
        while position
            .get(right)
            .copied()
            .ok_or(MandatoryCutDeclineReason::InternalInvariant {
                detail: "right dominator escaped its position table",
            })?
            > position
                .get(left)
                .copied()
                .ok_or(MandatoryCutDeclineReason::InternalInvariant {
                    detail: "left dominator escaped its position table",
                })?
        {
            budget.charge(1)?;
            right = *immediate
                .get(right)
                .ok_or(MandatoryCutDeclineReason::InternalInvariant {
                    detail: "right dominator escaped its parent table",
                })?;
        }
    }
    Ok(left)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ComponentEdge {
    target: u32,
    consumed: u8,
}

#[derive(Debug)]
struct DistanceFacts {
    component: Vec<u32>,
    max_before: Vec<u32>,
    unbounded_before: Vec<bool>,
}

impl DistanceFacts {
    fn before(&self, state: usize) -> Result<MaximumConsumedDistance, MandatoryCutDeclineReason> {
        let component = self.component.get(state).copied().ok_or(
            MandatoryCutDeclineReason::InternalInvariant {
                detail: "mandatory root escaped its distance component table",
            },
        )?;
        let component = to_usize(component, "mandatory-cut distance component")?;
        if self.unbounded_before.get(component).copied().ok_or(
            MandatoryCutDeclineReason::InternalInvariant {
                detail: "distance component escaped its unbounded table",
            },
        )? {
            Ok(MaximumConsumedDistance::Unbounded)
        } else {
            Ok(MaximumConsumedDistance::Finite(
                self.max_before.get(component).copied().ok_or(
                    MandatoryCutDeclineReason::InternalInvariant {
                        detail: "distance component escaped its maximum table",
                    },
                )?,
            ))
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "SCC construction and exact distance propagation share one bounded condensation"
    )]
    fn build(
        raw: &RawPlan,
        graph: &ProductiveGraph,
        budget: &mut Budget,
    ) -> Result<Self, MandatoryCutDeclineReason> {
        let exit = raw.roles.len();
        let node_count =
            exit.checked_add(1)
                .ok_or(MandatoryCutDeclineReason::ArithmeticOverflow {
                    computation: "mandatory-cut distance nodes",
                })?;
        let mut component =
            budget.filled(node_count, u32::MAX, "mandatory-cut distance components")?;
        let mut component_count = 0usize;
        let mut stack = Vec::new();
        for &root in &graph.reverse_postorder {
            budget.charge(1)?;
            if component[root] != u32::MAX {
                continue;
            }
            let component_id = u32::try_from(component_count).map_err(|_| {
                MandatoryCutDeclineReason::ArithmeticOverflow {
                    computation: "mandatory-cut component id",
                }
            })?;
            component_count = component_count.checked_add(1).ok_or(
                MandatoryCutDeclineReason::ArithmeticOverflow {
                    computation: "mandatory-cut component count",
                },
            )?;
            component[root] = component_id;
            budget.push(&mut stack, root, "mandatory-cut component stack")?;
            while let Some(node) = stack.pop() {
                budget.charge(1)?;
                if node == exit {
                    for &predecessor in &graph.accepts {
                        budget.charge(1)?;
                        if component[predecessor] == u32::MAX {
                            component[predecessor] = component_id;
                            budget.push(
                                &mut stack,
                                predecessor,
                                "mandatory-cut component stack",
                            )?;
                        }
                    }
                } else {
                    for &edge in graph.incoming.by_target.get(node).ok_or(
                        MandatoryCutDeclineReason::InternalInvariant {
                            detail: "component target lost its incoming row",
                        },
                    )? {
                        budget.charge(1)?;
                        let predecessor = to_usize(edge.source, "mandatory-cut component source")?;
                        if graph.productive.get(predecessor) == Some(&true)
                            && component[predecessor] == u32::MAX
                        {
                            component[predecessor] = component_id;
                            budget.push(
                                &mut stack,
                                predecessor,
                                "mandatory-cut component stack",
                            )?;
                        }
                    }
                }
            }
        }

        let mut outgoing =
            budget.filled(component_count, Vec::new(), "mandatory-cut component rows")?;
        let mut positive_cycle =
            budget.filled(component_count, false, "mandatory-cut positive-cycle flags")?;
        for state in 0..raw.roles.len() {
            if graph.productive.get(state) != Some(&true) {
                continue;
            }
            budget.charge(1)?;
            let source_component = to_usize(
                *component
                    .get(state)
                    .ok_or(MandatoryCutDeclineReason::InternalInvariant {
                        detail: "productive state lost its component",
                    })?,
                "mandatory-cut source component",
            )?;
            for edge in state_edges(raw, state)? {
                budget.charge(1)?;
                let target = to_usize(raw.edge_targets[edge], "mandatory-cut component target")?;
                if graph.productive.get(target) != Some(&true) {
                    continue;
                }
                let target_component = to_usize(
                    *component
                        .get(target)
                        .ok_or(MandatoryCutDeclineReason::InternalInvariant {
                            detail: "productive target lost its component",
                        })?,
                    "mandatory-cut target component",
                )?;
                let consumed = match raw.roles[state] {
                    StateRole::Consume => 1,
                    StateRole::Split => 0,
                    StateRole::Accept => {
                        return Err(MandatoryCutDeclineReason::InternalInvariant {
                            detail: "accept state retained a validated outgoing edge",
                        });
                    }
                };
                if source_component == target_component {
                    if consumed == 1 {
                        positive_cycle[source_component] = true;
                    }
                    continue;
                }
                if source_component >= target_component {
                    return Err(MandatoryCutDeclineReason::InternalInvariant {
                        detail: "component ids are not in condensation order",
                    });
                }
                budget.push(
                    outgoing.get_mut(source_component).ok_or(
                        MandatoryCutDeclineReason::InternalInvariant {
                            detail: "source component lost its outgoing row",
                        },
                    )?,
                    ComponentEdge {
                        target: u32::try_from(target_component).map_err(|_| {
                            MandatoryCutDeclineReason::ArithmeticOverflow {
                                computation: "mandatory-cut target component id",
                            }
                        })?,
                        consumed,
                    },
                    "mandatory-cut component edges",
                )?;
            }
            if raw.roles[state] == StateRole::Accept {
                let target_component = to_usize(
                    *component
                        .get(exit)
                        .ok_or(MandatoryCutDeclineReason::InternalInvariant {
                            detail: "artificial exit lost its component",
                        })?,
                    "mandatory-cut exit component",
                )?;
                if source_component >= target_component {
                    return Err(MandatoryCutDeclineReason::InternalInvariant {
                        detail: "accept component does not precede exit component",
                    });
                }
                budget.push(
                    outgoing.get_mut(source_component).ok_or(
                        MandatoryCutDeclineReason::InternalInvariant {
                            detail: "accept component lost its outgoing row",
                        },
                    )?,
                    ComponentEdge {
                        target: u32::try_from(target_component).map_err(|_| {
                            MandatoryCutDeclineReason::ArithmeticOverflow {
                                computation: "mandatory-cut exit component id",
                            }
                        })?,
                        consumed: 0,
                    },
                    "mandatory-cut component edges",
                )?;
            }
        }

        let mut max_before = budget.filled(
            component_count,
            0_u32,
            "mandatory-cut maximum-before distances",
        )?;
        let mut has_before = budget.filled(
            component_count,
            false,
            "mandatory-cut before-reachability flags",
        )?;
        let mut unbounded_before = budget.filled(
            component_count,
            false,
            "mandatory-cut unbounded-before flags",
        )?;
        let start = to_usize(raw.start, "mandatory-cut distance start")?;
        let start_component = to_usize(
            *component
                .get(start)
                .ok_or(MandatoryCutDeclineReason::InternalInvariant {
                    detail: "start state lost its component",
                })?,
            "mandatory-cut start component",
        )?;
        has_before[start_component] = true;
        for source in 0..component_count {
            budget.charge(1)?;
            if !has_before[source] {
                continue;
            }
            unbounded_before[source] |= positive_cycle[source];
            for &edge in
                outgoing
                    .get(source)
                    .ok_or(MandatoryCutDeclineReason::InternalInvariant {
                        detail: "distance source lost its outgoing row",
                    })?
            {
                budget.charge(1)?;
                let target = to_usize(edge.target, "mandatory-cut distance target")?;
                has_before[target] = true;
                unbounded_before[target] |= unbounded_before[source];
                let distance = max_before[source]
                    .checked_add(u32::from(edge.consumed))
                    .ok_or(MandatoryCutDeclineReason::ArithmeticOverflow {
                        computation: "mandatory-cut maximum-before distance",
                    })?;
                max_before[target] = max_before[target].max(distance);
            }
        }
        Ok(Self {
            component,
            max_before,
            unbounded_before,
        })
    }
}

fn select_mandatory_cut(
    raw: &RawPlan,
    graph: &ProductiveGraph,
    dominators: &DominatorFacts,
    distances: &DistanceFacts,
    budget: &mut Budget,
) -> Result<Option<MandatoryCutCandidate>, MandatoryCutDeclineReason> {
    let mut best = None;
    let mut node = dominators.exit;
    for _ in 0..dominators.immediate.len() {
        budget.charge(1)?;
        node = *dominators.immediate.get(node).ok_or(
            MandatoryCutDeclineReason::InternalInvariant {
                detail: "dominator chain escaped its node table",
            },
        )?;
        if node == usize::MAX {
            return Err(MandatoryCutDeclineReason::InternalInvariant {
                detail: "dominator chain reached an uninitialized node",
            });
        }
        if node < raw.roles.len() && raw.roles[node] == StateRole::Consume {
            budget.stats.mandatory_roots = budget.stats.mandatory_roots.checked_add(1).ok_or(
                MandatoryCutDeclineReason::ArithmeticOverflow {
                    computation: "mandatory-cut root count",
                },
            )?;
            let root_state =
                u32::try_from(node).map_err(|_| MandatoryCutDeclineReason::ArithmeticOverflow {
                    computation: "mandatory-cut root state",
                })?;
            let candidate = MandatoryCutCandidate {
                root_state,
                byte_class: first_byte_class(raw, &graph.productive, node, budget)?,
                maximum_before_root: distances.before(node)?,
            };
            budget.charge(1)?;
            if best
                .as_ref()
                .is_none_or(|current| compare_candidates(candidate, *current) == Ordering::Less)
            {
                best = Some(candidate);
            }
        }
        if node == dominators.start {
            return Ok(best);
        }
    }
    Err(MandatoryCutDeclineReason::InternalInvariant {
        detail: "dominator chain did not terminate at the start",
    })
}

fn first_byte_class(
    raw: &RawPlan,
    productive: &[bool],
    root: usize,
    budget: &mut Budget,
) -> Result<MandatoryCutByteClass, MandatoryCutDeclineReason> {
    if raw.roles.get(root) != Some(&StateRole::Consume) {
        return Err(MandatoryCutDeclineReason::InternalInvariant {
            detail: "mandatory byte class root is not consuming",
        });
    }
    let mut words = [0_u64; 4];
    for edge in state_edges(raw, root)? {
        budget.charge(1)?;
        let target = to_usize(raw.edge_targets[edge], "mandatory-cut byte-class target")?;
        if productive.get(target) != Some(&true) {
            continue;
        }
        let start = raw.byte_starts[edge];
        let end = raw.byte_ends[edge];
        for byte in start..=end {
            budget.charge(1)?;
            let index = usize::from(byte);
            words[index / 64] |= 1_u64 << (index % 64);
        }
    }
    budget.charge(4)?;
    let cardinality = words.iter().try_fold(0_u16, |total, word| {
        total.checked_add(u16::try_from(word.count_ones()).ok()?)
    });
    let cardinality = cardinality.ok_or(MandatoryCutDeclineReason::InternalInvariant {
        detail: "mandatory byte-class cardinality overflowed",
    })?;
    if cardinality == 0 {
        return Err(MandatoryCutDeclineReason::InternalInvariant {
            detail: "productive mandatory root has an empty byte class",
        });
    }
    Ok(MandatoryCutByteClass { words })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        reason = "small exhaustive graph dimensions and byte domains are fixed by each test"
    )]

    use super::*;

    type TestEdge = (u32, EdgeKind, u8, u8);

    const fn epsilon(target: u32) -> TestEdge {
        (target, EdgeKind::Epsilon, 0, 0)
    }

    const fn zero_width(target: u32, kind: EdgeKind) -> TestEdge {
        (target, kind, 0, 0)
    }

    const fn byte(target: u32, value: u8) -> TestEdge {
        (target, EdgeKind::ByteRange, value, value)
    }

    const fn byte_range(target: u32, start: u8, end: u8) -> TestEdge {
        (target, EdgeKind::ByteRange, start, end)
    }

    fn raw(start: u32, roles: Vec<StateRole>, rows: Vec<Vec<TestEdge>>) -> RawPlan {
        assert_eq!(roles.len(), rows.len());
        let mut edge_offsets = Vec::with_capacity(rows.len().saturating_add(1));
        let mut edge_targets = Vec::new();
        let mut edge_kinds = Vec::new();
        let mut byte_starts = Vec::new();
        let mut byte_ends = Vec::new();
        edge_offsets.push(0);
        for row in rows {
            for (target, kind, start, end) in row {
                edge_targets.push(target);
                edge_kinds.push(kind);
                byte_starts.push(start);
                byte_ends.push(end);
            }
            edge_offsets.push(u32::try_from(edge_targets.len()).expect("test edge count"));
        }
        RawPlan {
            start,
            roles,
            edge_offsets,
            edge_targets,
            edge_kinds,
            byte_starts,
            byte_ends,
        }
    }

    fn complete(raw: &RawPlan) -> MandatoryCutAnalysisReport {
        complete_with_limits(raw, MandatoryCutAnalysisLimits::default())
    }

    fn complete_with_limits(
        raw: &RawPlan,
        limits: MandatoryCutAnalysisLimits,
    ) -> MandatoryCutAnalysisReport {
        match analyze_mandatory_cut(raw, limits) {
            MandatoryCutAnalysis::Complete(report) => report,
            MandatoryCutAnalysis::Declined(decline) => {
                panic!("unexpected mandatory-cut decline: {decline:?}")
            }
        }
    }

    fn candidate(report: MandatoryCutAnalysisReport, root: u32) -> MandatoryCutCandidate {
        let candidate = report
            .candidate()
            .unwrap_or_else(|| panic!("missing mandatory root {root}"));
        assert_eq!(candidate.root_state(), root);
        candidate
    }

    fn target_reachable_avoiding(raw: &RawPlan, target: u32, removed: Option<u32>) -> bool {
        if removed == Some(raw.start) {
            return false;
        }
        let mut stack = vec![raw.start];
        let mut seen = vec![false; raw.roles.len()];
        while let Some(state) = stack.pop() {
            if removed == Some(state) {
                continue;
            }
            if state == target {
                return true;
            }
            let state_index = usize::try_from(state).expect("test state");
            if seen[state_index] {
                continue;
            }
            seen[state_index] = true;
            for edge in state_edges(raw, state_index).expect("test row") {
                let next = raw.edge_targets[edge];
                if removed != Some(next) {
                    stack.push(next);
                }
            }
        }
        false
    }

    fn accept_reachable_avoiding(raw: &RawPlan, removed: Option<u32>) -> bool {
        raw.roles.iter().enumerate().any(|(state, role)| {
            *role == StateRole::Accept
                && target_reachable_avoiding(
                    raw,
                    u32::try_from(state).expect("test accept"),
                    removed,
                )
        })
    }

    fn can_reach(raw: &RawPlan, start: u32, target: u32) -> bool {
        let mut stack = vec![start];
        let mut seen = vec![false; raw.roles.len()];
        while let Some(state) = stack.pop() {
            if state == target {
                return true;
            }
            let state_index = usize::try_from(state).expect("test state");
            if seen[state_index] {
                continue;
            }
            seen[state_index] = true;
            for edge in state_edges(raw, state_index).expect("test row") {
                stack.push(raw.edge_targets[edge]);
            }
        }
        false
    }

    fn brute_roots(raw: &RawPlan) -> Vec<u32> {
        if !accept_reachable_avoiding(raw, None) {
            return Vec::new();
        }
        raw.roles
            .iter()
            .enumerate()
            .filter(|(state, role)| {
                **role == StateRole::Consume
                    && !accept_reachable_avoiding(
                        raw,
                        Some(u32::try_from(*state).expect("test state")),
                    )
            })
            .map(|(state, _)| u32::try_from(state).expect("test state"))
            .collect()
    }

    fn brute_byte_class(raw: &RawPlan, root: u32) -> MandatoryCutByteClass {
        let root = usize::try_from(root).expect("test root");
        let mut words = [0_u64; 4];
        for edge in state_edges(raw, root).expect("test root row") {
            let target = raw.edge_targets[edge];
            let reaches_accept = raw.roles.iter().enumerate().any(|(accept, role)| {
                *role == StateRole::Accept
                    && can_reach(raw, target, u32::try_from(accept).expect("test accept"))
            });
            if !reaches_accept {
                continue;
            }
            for byte in raw.byte_starts[edge]..=raw.byte_ends[edge] {
                let word = usize::from(byte / 64);
                let bit = u32::from(byte % 64);
                words[word] |= 1_u64 << bit;
            }
        }
        MandatoryCutByteClass { words }
    }

    fn relax_distances(raw: &RawPlan, root: u32, distances: &[Option<u32>]) -> Vec<Option<u32>> {
        let mut next = distances.to_vec();
        for source in 0..raw.roles.len() {
            let source_u32 = u32::try_from(source).expect("test source");
            if !target_reachable_avoiding(raw, source_u32, None)
                || !can_reach(raw, source_u32, root)
            {
                continue;
            }
            let Some(distance) = distances[source] else {
                continue;
            };
            let distance = distance
                .checked_add(u32::from(raw.roles[source] == StateRole::Consume))
                .expect("small test distance");
            for edge in state_edges(raw, source).expect("test row") {
                let target = raw.edge_targets[edge];
                if !can_reach(raw, target, root) {
                    continue;
                }
                let target = usize::try_from(target).expect("test target");
                next[target] = Some(next[target].map_or(distance, |old| old.max(distance)));
            }
        }
        next
    }

    fn brute_max_before(raw: &RawPlan, root: u32) -> MaximumConsumedDistance {
        let start = usize::try_from(raw.start).expect("test start");
        let root_index = usize::try_from(root).expect("test root");
        let mut distances = vec![None; raw.roles.len()];
        distances[start] = Some(0);
        for _ in 1..raw.roles.len() {
            distances = relax_distances(raw, root, &distances);
        }
        let bounded = distances[root_index].expect("mandatory root reachable");
        let extra = relax_distances(raw, root, &distances);
        if extra.iter().zip(&distances).any(|(next, old)| next > old) {
            MaximumConsumedDistance::Unbounded
        } else {
            MaximumConsumedDistance::Finite(bounded)
        }
    }

    fn brute_candidate(raw: &RawPlan) -> Option<MandatoryCutCandidate> {
        brute_roots(raw)
            .into_iter()
            .map(|root_state| MandatoryCutCandidate {
                root_state,
                byte_class: brute_byte_class(raw, root_state),
                maximum_before_root: brute_max_before(raw, root_state),
            })
            .min_by(|left, right| compare_candidates(*left, *right))
    }

    fn assert_decline_resource(
        raw: &RawPlan,
        limits: MandatoryCutAnalysisLimits,
        resource: MandatoryCutResource,
    ) {
        let analysis = analyze_mandatory_cut(raw, limits);
        assert!(analysis.stats().closes(limits));
        let MandatoryCutAnalysis::Declined(decline) = analysis else {
            panic!("limited proof unexpectedly completed")
        };
        assert!(matches!(
            decline.reason(),
            MandatoryCutDeclineReason::Resource {
                resource: actual,
                ..
            } if actual == resource
        ));
    }

    #[test]
    fn variable_prefix_publishes_exact_root_class_and_bound() {
        let graph = raw(
            0,
            vec![
                StateRole::Split,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Accept,
            ],
            vec![
                vec![epsilon(1), epsilon(2)],
                vec![byte(4, b'x')],
                vec![byte(3, b'y')],
                vec![byte(4, b'z')],
                vec![byte(5, b'7')],
                vec![],
            ],
        );
        let report = complete(&graph);
        let root = candidate(report, 4);
        assert_eq!(
            root.maximum_before_root(),
            MaximumConsumedDistance::Finite(2)
        );
        assert_eq!(root.byte_class().cardinality(), 1);
        assert!(root.byte_class().contains(b'7'));
        assert!(!root.byte_class().contains(b'x'));
    }

    #[test]
    fn every_assertion_kind_is_the_epsilon_overapproximation() {
        const ASSERTIONS: [EdgeKind; 18] = [
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
        ];
        let epsilon_graph = raw(
            0,
            vec![StateRole::Split, StateRole::Consume, StateRole::Accept],
            vec![vec![epsilon(1)], vec![byte(2, b'a')], vec![]],
        );
        let expected = complete(&epsilon_graph).candidate();
        for kind in ASSERTIONS {
            let graph = raw(
                0,
                vec![StateRole::Split, StateRole::Consume, StateRole::Accept],
                vec![vec![zero_width(1, kind)], vec![byte(2, b'a')], vec![]],
            );
            let report = complete(&graph);
            assert!(report.stats().context_assertions(), "{kind:?}");
            assert_eq!(report.candidate(), expected, "{kind:?}");
        }
    }

    #[test]
    fn assertion_bypass_cannot_invent_a_dominator() {
        let bypass = raw(
            0,
            vec![StateRole::Split, StateRole::Accept, StateRole::Consume],
            vec![
                vec![zero_width(1, EdgeKind::AssertWordAscii), epsilon(2)],
                vec![],
                vec![byte(1, b'a')],
            ],
        );
        let report = complete(&bypass);
        assert!(report.stats().context_assertions());
        assert_eq!(report.candidate(), None);
    }

    #[test]
    fn productive_byte_class_excludes_dead_outgoing_ranges() {
        let graph = raw(
            0,
            vec![StateRole::Consume, StateRole::Accept, StateRole::Consume],
            vec![
                vec![byte(1, b'a'), byte_range(2, b'x', b'z')],
                vec![],
                vec![byte(2, b'q')],
            ],
        );
        let class = candidate(complete(&graph), 0).byte_class();
        assert_eq!(class.cardinality(), 1);
        assert!(class.contains(b'a'));
        for byte in b'x'..=b'z' {
            assert!(!class.contains(byte));
        }
    }

    #[test]
    fn consumed_distance_distinguishes_byte_and_zero_width_cycles() {
        let consuming_cycle = raw(
            0,
            vec![
                StateRole::Split,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Accept,
            ],
            vec![
                vec![epsilon(1), epsilon(2)],
                vec![byte(0, b'x')],
                vec![byte(3, b'a')],
                vec![],
            ],
        );
        assert_eq!(
            candidate(complete(&consuming_cycle), 2).maximum_before_root(),
            MaximumConsumedDistance::Unbounded
        );

        let zero_width_cycle = raw(
            0,
            vec![StateRole::Split, StateRole::Consume, StateRole::Accept],
            vec![vec![epsilon(0), epsilon(1)], vec![byte(2, b'a')], vec![]],
        );
        assert_eq!(
            candidate(complete(&zero_width_cycle), 1).maximum_before_root(),
            MaximumConsumedDistance::Finite(0)
        );
    }

    #[test]
    fn every_three_state_graph_matches_independent_cyclic_oracles() {
        const STATES: usize = 3;
        const ROLE_VARIANTS: usize = 27;
        for mut role_code in 0..ROLE_VARIANTS {
            let mut roles = Vec::with_capacity(STATES);
            for _ in 0..STATES {
                roles.push(match role_code % 3 {
                    0 => StateRole::Split,
                    1 => StateRole::Consume,
                    _ => StateRole::Accept,
                });
                role_code /= 3;
            }
            if !roles.contains(&StateRole::Accept) {
                continue;
            }
            let pairs = (0..STATES)
                .filter(|&source| roles[source] != StateRole::Accept)
                .flat_map(|source| (0..STATES).map(move |target| (source, target)))
                .collect::<Vec<_>>();
            let edge_variants = 1_usize
                .checked_shl(u32::try_from(pairs.len()).expect("test edge count"))
                .expect("test edge variants");
            for edge_mask in 0..edge_variants {
                let mut rows = vec![Vec::new(); STATES];
                for (edge, &(source, target)) in pairs.iter().enumerate() {
                    if edge_mask & (1_usize << edge) == 0 {
                        continue;
                    }
                    let target = u32::try_from(target).expect("test target");
                    rows[source].push(if roles[source] == StateRole::Consume {
                        byte(
                            target,
                            b'a'.checked_add(u8::try_from(source).expect("test source"))
                                .expect("test byte"),
                        )
                    } else {
                        epsilon(target)
                    });
                }
                for start in 0..STATES {
                    let graph = raw(
                        u32::try_from(start).expect("test start"),
                        roles.clone(),
                        rows.clone(),
                    );
                    let report = complete(&graph);
                    let expected_roots = brute_roots(&graph);
                    let expected_candidate = brute_candidate(&graph);
                    let expected_inspected_roots = if expected_candidate.is_some_and(|candidate| {
                        candidate.root_state() == graph.start
                            && candidate.byte_class().cardinality() == 1
                            && candidate.maximum_before_root() == MaximumConsumedDistance::Finite(0)
                    }) {
                        1
                    } else {
                        expected_roots.len()
                    };
                    assert_eq!(
                        report.stats().mandatory_roots(),
                        expected_inspected_roots,
                        "roles={roles:?} edge={edge_mask:#x} start={start}"
                    );
                    assert_eq!(
                        report.candidate(),
                        expected_candidate,
                        "roles={roles:?} edge={edge_mask:#x} start={start}"
                    );
                    assert!(report.stats().closes(MandatoryCutAnalysisLimits::default()));
                    if let Some(candidate) = report.candidate() {
                        assert_eq!(
                            graph.roles[usize::try_from(candidate.root_state())
                                .expect("test candidate root")],
                            StateRole::Consume
                        );
                        assert_ne!(candidate.byte_class().cardinality(), 0);
                    }
                }
            }
        }
    }

    #[test]
    fn empty_language_completes_without_candidates() {
        let graph = raw(
            0,
            vec![StateRole::Consume, StateRole::Consume, StateRole::Accept],
            vec![vec![byte(1, b'a')], vec![byte(1, b'b')], vec![]],
        );
        let report = complete(&graph);
        assert_eq!(report.candidate(), None);
        assert_eq!(report.stats().accepting_states(), 0);
    }

    #[test]
    fn long_chain_selects_inline_without_a_candidate_cap() {
        const CONSUMING: usize = 256;
        let mut roles = vec![StateRole::Consume; CONSUMING];
        roles.push(StateRole::Accept);
        let mut rows = Vec::with_capacity(roles.len());
        for state in 0..CONSUMING {
            rows.push(vec![byte(
                u32::try_from(state.saturating_add(1)).expect("test target"),
                b'x',
            )]);
        }
        rows.push(Vec::new());
        let report = complete(&raw(0, roles, rows));
        assert_eq!(report.stats().mandatory_roots(), 1);
        assert_eq!(candidate(report, 0).byte_class().cardinality(), 1);
    }

    #[test]
    fn singleton_start_incoming_scan_is_exactly_charged() {
        let graph = raw(
            0,
            vec![StateRole::Consume, StateRole::Accept, StateRole::Consume],
            vec![vec![byte(1, b'a')], vec![], vec![byte(0, b'z')]],
        );
        let full = complete(&graph);
        assert_eq!(candidate(full, 0).byte_class().cardinality(), 1);

        // After the incoming-edge inspection, the shortcut has seven work
        // units left: one productive start edge, one singleton byte, four
        // bitmap words, and one selected-root charge. A limit eight below the
        // complete receipt therefore stops exactly on the incoming edge.
        let max_work = full
            .stats()
            .work()
            .checked_sub(8)
            .expect("shortcut work includes its charged suffix");
        let limits = MandatoryCutAnalysisLimits {
            max_work,
            ..MandatoryCutAnalysisLimits::default()
        };
        let MandatoryCutAnalysis::Declined(decline) = analyze_mandatory_cut(&graph, limits) else {
            panic!("uncharged singleton-start incoming scan")
        };
        assert_eq!(
            decline.reason(),
            MandatoryCutDeclineReason::Resource {
                resource: MandatoryCutResource::Work,
                needed: max_work.checked_add(1).expect("small test work"),
                limit: max_work,
            }
        );
        assert_eq!(decline.stats().accepting_states(), 1);
        assert!(decline.stats().closes(limits));
    }

    #[test]
    fn broad_productive_start_falls_through_to_a_later_singleton() {
        let graph = raw(
            0,
            vec![StateRole::Consume, StateRole::Consume, StateRole::Accept],
            vec![vec![byte_range(1, b'a', b'b')], vec![byte(2, b'x')], vec![]],
        );
        let report = complete(&graph);
        assert_eq!(report.stats().mandatory_roots(), 2);
        let selected = candidate(report, 1);
        assert_eq!(selected.byte_class().cardinality(), 1);
        assert_eq!(
            selected.maximum_before_root(),
            MaximumConsumedDistance::Finite(1)
        );
    }

    #[test]
    fn exact_and_one_below_resource_boundaries_close() {
        let graph = raw(
            0,
            vec![StateRole::Consume, StateRole::Accept],
            vec![vec![byte(1, b'a')], vec![]],
        );
        let baseline = complete(&graph);
        let stats = baseline.stats();
        let exact = MandatoryCutAnalysisLimits {
            max_work: stats.work(),
            max_allocation_items: stats.allocation_items(),
            max_allocation_attempts: stats.allocation_attempts(),
        };
        let exact_report = complete_with_limits(&graph, exact);
        assert_eq!(exact_report, baseline);
        assert!(stats.closes(exact));

        for max_work in 0..stats.work() {
            assert_decline_resource(
                &graph,
                MandatoryCutAnalysisLimits {
                    max_work,
                    ..MandatoryCutAnalysisLimits::default()
                },
                MandatoryCutResource::Work,
            );
        }
        for max_allocation_items in 0..stats.allocation_items() {
            assert_decline_resource(
                &graph,
                MandatoryCutAnalysisLimits {
                    max_allocation_items,
                    ..MandatoryCutAnalysisLimits::default()
                },
                MandatoryCutResource::AllocationItems,
            );
        }
        for max_allocation_attempts in 0..stats.allocation_attempts() {
            assert_decline_resource(
                &graph,
                MandatoryCutAnalysisLimits {
                    max_allocation_attempts,
                    ..MandatoryCutAnalysisLimits::default()
                },
                MandatoryCutResource::AllocationAttempts,
            );
        }
    }

    fn assert_malformed(graph: &RawPlan, issue: MandatoryCutGraphIssue) {
        let limits = MandatoryCutAnalysisLimits::default();
        let analysis = analyze_mandatory_cut(graph, limits);
        assert!(analysis.stats().closes(limits));
        let MandatoryCutAnalysis::Declined(decline) = analysis else {
            panic!("malformed proof unexpectedly completed")
        };
        assert_eq!(
            decline.reason(),
            MandatoryCutDeclineReason::MalformedGraph(issue)
        );
        assert!(decline.stats().work() > 0);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one table-driven test enumerates each independently malformed raw-plan dimension"
    )]
    fn malformed_raw_plans_decline_without_publication() {
        assert_malformed(
            &RawPlan {
                start: 0,
                roles: Vec::new(),
                edge_offsets: Vec::new(),
                edge_targets: Vec::new(),
                edge_kinds: Vec::new(),
                byte_starts: Vec::new(),
                byte_ends: Vec::new(),
            },
            MandatoryCutGraphIssue::Empty,
        );

        let valid = raw(
            0,
            vec![StateRole::Consume, StateRole::Accept],
            vec![vec![byte(1, b'a')], vec![]],
        );
        let mut graph = valid.clone();
        graph.start = 2;
        assert_malformed(&graph, MandatoryCutGraphIssue::StartOutOfRange);

        let graph = raw(0, vec![StateRole::Consume], vec![vec![byte(0, b'a')]]);
        assert_malformed(&graph, MandatoryCutGraphIssue::MissingAccept);

        let mut graph = valid.clone();
        graph.edge_offsets.pop();
        assert_malformed(&graph, MandatoryCutGraphIssue::OffsetShape);

        let mut graph = valid.clone();
        graph.edge_offsets[1] = 2;
        assert_malformed(&graph, MandatoryCutGraphIssue::EdgeOffset);

        let mut graph = valid.clone();
        graph.edge_kinds.pop();
        assert_malformed(&graph, MandatoryCutGraphIssue::EdgeTableShape);

        let mut graph = valid.clone();
        graph.edge_targets[0] = 2;
        assert_malformed(&graph, MandatoryCutGraphIssue::EdgeTargetOutOfRange);

        let graph = raw(0, vec![StateRole::Accept], vec![vec![epsilon(0)]]);
        assert_malformed(&graph, MandatoryCutGraphIssue::StateRoleEdges);

        let graph = raw(
            0,
            vec![StateRole::Accept, StateRole::Consume],
            vec![vec![], vec![epsilon(0)]],
        );
        assert_malformed(&graph, MandatoryCutGraphIssue::StateRoleEdges);

        let graph = raw(
            0,
            vec![StateRole::Split, StateRole::Accept],
            vec![vec![byte(1, b'a')], vec![]],
        );
        assert_malformed(&graph, MandatoryCutGraphIssue::StateRoleEdges);

        let graph = raw(
            0,
            vec![StateRole::Consume, StateRole::Accept],
            vec![vec![byte_range(1, b'z', b'a')], vec![]],
        );
        assert_malformed(&graph, MandatoryCutGraphIssue::EdgePayload);

        let graph = raw(
            0,
            vec![StateRole::Split, StateRole::Accept],
            vec![vec![(1, EdgeKind::Epsilon, 1, 0)], vec![]],
        );
        assert_malformed(&graph, MandatoryCutGraphIssue::EdgePayload);
    }
}
