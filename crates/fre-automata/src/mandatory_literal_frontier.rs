//! Bounded complete literal frontiers below a mandatory consuming root.
//!
//! This analysis starts from the independently proven root selected by
//! [`analyze_mandatory_cut`]. For roots too broad for the existing one-to-three
//! byte scanners, it enumerates every productive graph trace until either an
//! accepting state or four consumed bytes. The retained literals form a
//! prefix antichain: every structurally accepting trace below the root starts
//! with at least one retained literal. Assertions are conservatively relaxed
//! as zero-width edges, so this can add impossible traces but cannot omit a
//! semantic match.
//!
//! The result is only a graph proof. In particular, it does not authorize an
//! unconditional auxiliary haystack pass. A runtime owner must additionally
//! prove replacement-only admission or advance an authoritative continuation
//! cursor past the region searched by a packed literal kernel.
//!
//! Frontier work charges one unit for each initialized slot, graph role, graph
//! edge, expanded byte, configuration comparison/insertion, prefix-antichain
//! comparison/insertion, retained-literal accounting visit, and deterministic
//! ordering comparison/swap. Checked conversions and scalar receipt writes do
//! not carry a separate work charge. The nested mandatory-cut receipt remains
//! separate so its accounting convention is not counted twice.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "checked resource arithmetic and validated CSR/byte-domain invariants guard the remaining indexing and fixed-width operations"
)]

use core::{cmp::Ordering, mem::size_of};

use crate::{
    EdgeKind, MandatoryCutAnalysis, MandatoryCutAnalysisLimits,
    MandatoryCutAnalysisStats, MandatoryCutDeclineReason, MaximumConsumedDistance, RawPlan,
    StateRole, analyze_mandatory_cut,
};

/// Stable identity for this frontier proof and its accounting convention.
pub const MANDATORY_LITERAL_FRONTIER_ACCOUNTING_ID: &str =
    "fre.automata.mandatory-literal-frontier.v1";
/// Shortest literal useful to a packed literal-set scanner.
pub const MIN_MANDATORY_LITERAL_FRONTIER_BYTES: usize = 2;
/// Longest literal inspected by this first bounded proof.
pub const MAX_MANDATORY_LITERAL_FRONTIER_BYTES: usize = 4;
/// Largest selected mandatory-root class admitted by this proof.
pub const MAX_MANDATORY_LITERAL_FRONTIER_ROOT_BYTES: usize = 32;
/// Largest retained prefix antichain.
pub const MAX_MANDATORY_LITERAL_FRONTIER_LITERALS: usize = 32;
/// Largest retained literal arena.
pub const MAX_MANDATORY_LITERAL_FRONTIER_TOTAL_BYTES: usize =
    MAX_MANDATORY_LITERAL_FRONTIER_BYTES * MAX_MANDATORY_LITERAL_FRONTIER_LITERALS;
/// Default maximum abstract frontier work, excluding nested cut analysis.
pub const DEFAULT_MANDATORY_LITERAL_FRONTIER_MAX_WORK: u64 = 2_000_000;
/// Default maximum cumulative logical frontier allocation items.
pub const DEFAULT_MANDATORY_LITERAL_FRONTIER_MAX_ALLOCATION_ITEMS: usize = 262_144;
/// Default maximum frontier allocation attempts.
pub const DEFAULT_MANDATORY_LITERAL_FRONTIER_MAX_ALLOCATION_ATTEMPTS: usize = 262_144;
/// Default maximum distinct `(state, literal-prefix)` configurations.
pub const DEFAULT_MANDATORY_LITERAL_FRONTIER_MAX_CONFIGURATIONS: usize = 8_192;

/// Independent limits for one optional frontier proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MandatoryLiteralFrontierAnalysisLimits {
    /// Limits for the prerequisite mandatory-cut proof.
    pub mandatory_cut: MandatoryCutAnalysisLimits,
    /// Exact abstract work in the frontier proof itself.
    pub max_work: u64,
    /// Cumulative logical vector slots requested by the frontier proof.
    pub max_allocation_items: usize,
    /// Fallible vector reservation attempts in the frontier proof.
    pub max_allocation_attempts: usize,
    /// Distinct graph/prefix configurations admitted.
    pub max_configurations: usize,
    /// Retained literal count, additionally capped by the implementation maximum.
    pub max_literals: usize,
    /// Literal width, additionally capped by the implementation maximum.
    pub max_literal_bytes: usize,
    /// Retained arena bytes, additionally capped by the implementation maximum.
    pub max_total_literal_bytes: usize,
}

impl Default for MandatoryLiteralFrontierAnalysisLimits {
    fn default() -> Self {
        Self {
            mandatory_cut: MandatoryCutAnalysisLimits::default(),
            max_work: DEFAULT_MANDATORY_LITERAL_FRONTIER_MAX_WORK,
            max_allocation_items: DEFAULT_MANDATORY_LITERAL_FRONTIER_MAX_ALLOCATION_ITEMS,
            max_allocation_attempts: DEFAULT_MANDATORY_LITERAL_FRONTIER_MAX_ALLOCATION_ATTEMPTS,
            max_configurations: DEFAULT_MANDATORY_LITERAL_FRONTIER_MAX_CONFIGURATIONS,
            max_literals: MAX_MANDATORY_LITERAL_FRONTIER_LITERALS,
            max_literal_bytes: MAX_MANDATORY_LITERAL_FRONTIER_BYTES,
            max_total_literal_bytes: MAX_MANDATORY_LITERAL_FRONTIER_TOTAL_BYTES,
        }
    }
}

impl MandatoryLiteralFrontierAnalysisLimits {
    const fn literal_limit(self) -> usize {
        if self.max_literals < MAX_MANDATORY_LITERAL_FRONTIER_LITERALS {
            self.max_literals
        } else {
            MAX_MANDATORY_LITERAL_FRONTIER_LITERALS
        }
    }

    const fn width_limit(self) -> usize {
        if self.max_literal_bytes < MAX_MANDATORY_LITERAL_FRONTIER_BYTES {
            self.max_literal_bytes
        } else {
            MAX_MANDATORY_LITERAL_FRONTIER_BYTES
        }
    }

    const fn byte_limit(self) -> usize {
        if self.max_total_literal_bytes < MAX_MANDATORY_LITERAL_FRONTIER_TOTAL_BYTES {
            self.max_total_literal_bytes
        } else {
            MAX_MANDATORY_LITERAL_FRONTIER_TOTAL_BYTES
        }
    }
}

/// A separately limited frontier resource.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MandatoryLiteralFrontierResource {
    /// Abstract graph and construction work.
    Work,
    /// Cumulative logical vector slots requested.
    AllocationItems,
    /// Fallible vector reservation attempts.
    AllocationAttempts,
    /// Distinct graph/prefix configurations.
    Configurations,
    /// Prefix-antichain members.
    Literals,
    /// Bytes in one retained literal.
    LiteralWidth,
    /// Bytes in the complete retained literal arena.
    LiteralBytes,
}

/// Why a valid graph completed without publishing a frontier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MandatoryLiteralFrontierStopReason {
    /// A complete candidate was published.
    Candidate,
    /// The prerequisite proof found no mandatory consuming root.
    NoMandatoryRoot,
    /// The selected root belongs to the existing one-to-three-byte incumbent.
    ExistingSmallRootClass {
        /// Number of productive bytes leaving the root.
        cardinality: u16,
    },
    /// The selected root exceeds this prototype's fixed expansion ceiling.
    RootClassTooWide {
        /// Number of productive bytes leaving the root.
        cardinality: u16,
    },
    /// Some accepting trace is too short for the packed-literal contract.
    ShortAcceptingTrace {
        /// Consumed bytes in the short trace.
        bytes: u8,
    },
}

/// Transactional reason why no completed report was published.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MandatoryLiteralFrontierDeclineReason {
    /// The prerequisite mandatory-cut proof declined.
    MandatoryCut(MandatoryCutDeclineReason),
    /// One declared or fixed hard ceiling was exceeded.
    Resource {
        /// Limited resource.
        resource: MandatoryLiteralFrontierResource,
        /// First value that would exceed the effective limit.
        needed: u64,
        /// Effective declared or fixed limit.
        limit: u64,
    },
    /// A fallible frontier allocation failed.
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
    /// A validated graph violated an internal proof invariant.
    InternalInvariant {
        /// Named invariant.
        detail: &'static str,
    },
}

/// Exact accounting completed by the prerequisite and frontier analyses.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MandatoryLiteralFrontierAnalysisStats {
    accounting_id: &'static str,
    mandatory_cut: MandatoryCutAnalysisStats,
    work: u64,
    allocation_items: usize,
    allocation_attempts: usize,
    states: usize,
    edges: usize,
    productive_states: usize,
    configurations: usize,
    raw_literals: usize,
    retained_literals: usize,
    retained_literal_bytes: usize,
    maximum_literal_bytes: usize,
    candidates: usize,
    candidate_storage_bytes: usize,
    context_assertions: bool,
}

impl MandatoryLiteralFrontierAnalysisStats {
    /// Stable identity of the frontier algorithm and accounting convention.
    #[must_use]
    pub const fn accounting_id(self) -> &'static str {
        self.accounting_id
    }

    /// Exact nested mandatory-cut accounting.
    #[must_use]
    pub const fn mandatory_cut(self) -> MandatoryCutAnalysisStats {
        self.mandatory_cut
    }

    /// Exact abstract frontier work, excluding nested cut work.
    #[must_use]
    pub const fn work(self) -> u64 {
        self.work
    }

    /// Cumulative logical frontier allocation items.
    #[must_use]
    pub const fn allocation_items(self) -> usize {
        self.allocation_items
    }

    /// Frontier allocation attempts.
    #[must_use]
    pub const fn allocation_attempts(self) -> usize {
        self.allocation_attempts
    }

    /// Raw graph states observed.
    #[must_use]
    pub const fn states(self) -> usize {
        self.states
    }

    /// Raw graph edges observed.
    #[must_use]
    pub const fn edges(self) -> usize {
        self.edges
    }

    /// States that can reach an accept under assertion relaxation.
    #[must_use]
    pub const fn productive_states(self) -> usize {
        self.productive_states
    }

    /// Distinct graph/prefix configurations retained for traversal.
    #[must_use]
    pub const fn configurations(self) -> usize {
        self.configurations
    }

    /// Accepting or width-capped traces offered to prefix canonicalization.
    #[must_use]
    pub const fn raw_literals(self) -> usize {
        self.raw_literals
    }

    /// Prefix-antichain members retained when analysis stopped.
    #[must_use]
    pub const fn retained_literals(self) -> usize {
        self.retained_literals
    }

    /// Bytes in the retained prefix antichain when analysis stopped.
    #[must_use]
    pub const fn retained_literal_bytes(self) -> usize {
        self.retained_literal_bytes
    }

    /// Longest retained literal when analysis stopped.
    #[must_use]
    pub const fn maximum_literal_bytes(self) -> usize {
        self.maximum_literal_bytes
    }

    /// Completed owned candidates, zero or one.
    #[must_use]
    pub const fn candidates(self) -> usize {
        self.candidates
    }

    /// Exact physical bytes retained by a completed candidate.
    #[must_use]
    pub const fn candidate_storage_bytes(self) -> usize {
        self.candidate_storage_bytes
    }

    /// Whether assertion edges were conservatively relaxed in the frontier pass.
    #[must_use]
    pub const fn context_assertions(self) -> bool {
        self.context_assertions
    }

    /// Whether this receipt is internally consistent and within `limits`.
    #[must_use]
    pub fn closes(self, limits: MandatoryLiteralFrontierAnalysisLimits) -> bool {
        let candidate_storage_closes = match self.candidates {
            0 => self.candidate_storage_bytes == 0,
            1 => {
                self.candidate_storage_bytes >= size_of::<MandatoryLiteralFrontierCandidate>()
                    && self.retained_literals != 0
                    && self.maximum_literal_bytes >= MIN_MANDATORY_LITERAL_FRONTIER_BYTES
            }
            _ => false,
        };
        let literal_shape_closes = match self
            .retained_literals
            .checked_mul(MIN_MANDATORY_LITERAL_FRONTIER_BYTES)
        {
            Some(0) => self.retained_literal_bytes == 0 && self.maximum_literal_bytes == 0,
            Some(minimum_bytes) => {
                self.retained_literal_bytes >= minimum_bytes
                    && self.maximum_literal_bytes >= MIN_MANDATORY_LITERAL_FRONTIER_BYTES
                    && self.maximum_literal_bytes <= self.retained_literal_bytes
            }
            None => false,
        };
        self.accounting_id == MANDATORY_LITERAL_FRONTIER_ACCOUNTING_ID
            && self.mandatory_cut.closes(limits.mandatory_cut)
            && self.work <= limits.max_work
            && self.allocation_items <= limits.max_allocation_items
            && self.allocation_attempts <= limits.max_allocation_attempts
            && self.productive_states <= self.states
            && self.configurations <= limits.max_configurations
            && self.retained_literals <= self.raw_literals
            && self.retained_literals <= limits.literal_limit()
            && self.retained_literal_bytes <= limits.byte_limit()
            && self.maximum_literal_bytes <= limits.width_limit()
            && literal_shape_closes
            && candidate_storage_closes
    }
}

/// Immutable complete prefix cover below one mandatory consuming root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MandatoryLiteralFrontierCandidate {
    root_state: u32,
    maximum_before_root: MaximumConsumedDistance,
    offsets: Vec<u16>,
    bytes: Vec<u8>,
}

impl MandatoryLiteralFrontierCandidate {
    /// Mandatory consuming state in the supplied raw graph.
    #[must_use]
    pub const fn root_state(&self) -> u32 {
        self.root_state
    }

    /// Exact maximum bytes consumed before entering the root.
    #[must_use]
    pub const fn maximum_before_root(&self) -> MaximumConsumedDistance {
        self.maximum_before_root
    }

    /// Number of retained prefix-antichain literals.
    #[must_use]
    pub fn len(&self) -> usize {
        self.offsets.len().saturating_sub(1)
    }

    /// Whether the frontier contains no literals.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Literal at `index`, in deterministic lexicographic order.
    #[must_use]
    pub fn literal(&self, index: usize) -> Option<&[u8]> {
        let start = usize::from(*self.offsets.get(index)?);
        let end = usize::from(*self.offsets.get(index.checked_add(1)?)?);
        self.bytes.get(start..end)
    }

    /// Iterate literals in deterministic lexicographic order.
    #[must_use]
    pub fn iter(&self) -> MandatoryLiteralFrontierIter<'_> {
        MandatoryLiteralFrontierIter {
            candidate: self,
            index: 0,
        }
    }

    /// Exact owned bytes including vector capacities and the inline header.
    #[must_use]
    pub fn storage_bytes(&self) -> usize {
        size_of::<Self>()
            .saturating_add(self.offsets.capacity().saturating_mul(size_of::<u16>()))
            .saturating_add(self.bytes.capacity())
    }
}

/// Borrowing iterator over one immutable frontier.
#[derive(Clone, Debug)]
pub struct MandatoryLiteralFrontierIter<'a> {
    candidate: &'a MandatoryLiteralFrontierCandidate,
    index: usize,
}

impl<'a> Iterator for MandatoryLiteralFrontierIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        let literal = self.candidate.literal(self.index)?;
        self.index = self.index.saturating_add(1);
        Some(literal)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.candidate.len().saturating_sub(self.index);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for MandatoryLiteralFrontierIter<'_> {}

impl<'a> IntoIterator for &'a MandatoryLiteralFrontierCandidate {
    type Item = &'a [u8];
    type IntoIter = MandatoryLiteralFrontierIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Completed optional analysis and its candidate, if admitted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MandatoryLiteralFrontierAnalysisReport {
    candidate: Option<MandatoryLiteralFrontierCandidate>,
    stop_reason: MandatoryLiteralFrontierStopReason,
    stats: MandatoryLiteralFrontierAnalysisStats,
}

impl MandatoryLiteralFrontierAnalysisReport {
    /// Complete candidate, if the graph and incumbent gate admitted one.
    #[must_use]
    pub const fn candidate(&self) -> Option<&MandatoryLiteralFrontierCandidate> {
        self.candidate.as_ref()
    }

    /// Semantic or incumbent reason analysis stopped.
    #[must_use]
    pub const fn stop_reason(&self) -> MandatoryLiteralFrontierStopReason {
        self.stop_reason
    }

    /// Exact completed accounting.
    #[must_use]
    pub const fn stats(&self) -> MandatoryLiteralFrontierAnalysisStats {
        self.stats
    }
}

/// Closed decline receipt retaining work completed before refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MandatoryLiteralFrontierAnalysisDecline {
    reason: MandatoryLiteralFrontierDeclineReason,
    stats: MandatoryLiteralFrontierAnalysisStats,
}

impl MandatoryLiteralFrontierAnalysisDecline {
    /// Exact reason no report was published.
    #[must_use]
    pub const fn reason(self) -> MandatoryLiteralFrontierDeclineReason {
        self.reason
    }

    /// Exact completed accounting.
    #[must_use]
    pub const fn stats(self) -> MandatoryLiteralFrontierAnalysisStats {
        self.stats
    }
}

/// Transactional result of one optional frontier analysis.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MandatoryLiteralFrontierAnalysis {
    /// The graph and incumbent gate were completely analyzed.
    Complete(MandatoryLiteralFrontierAnalysisReport),
    /// No candidate may be consumed; inspect the closed decline receipt.
    Declined(MandatoryLiteralFrontierAnalysisDecline),
}

impl MandatoryLiteralFrontierAnalysis {
    /// Accounting shared by successful and declined outcomes.
    #[must_use]
    pub const fn stats(&self) -> MandatoryLiteralFrontierAnalysisStats {
        match self {
            Self::Complete(report) => report.stats(),
            Self::Declined(decline) => decline.stats(),
        }
    }
}

/// Prove a bounded complete literal frontier below a mandatory graph root.
///
/// This function reruns and binds the prerequisite cut proof to this exact
/// `RawPlan`; callers cannot pair a candidate from another graph. It only
/// fills the gap after the existing one-to-three-byte mandatory-cut scanners.
/// All limits and ordering decisions are graph-derived and source-independent.
#[must_use]
pub fn analyze_mandatory_literal_frontier(
    raw: &RawPlan,
    limits: MandatoryLiteralFrontierAnalysisLimits,
) -> MandatoryLiteralFrontierAnalysis {
    let mut budget = Budget::new(limits, raw.roles.len(), raw.edge_targets.len());
    let cut = analyze_mandatory_cut(raw, limits.mandatory_cut);
    budget.stats.mandatory_cut = cut.stats();
    let cut_report = match cut {
        MandatoryCutAnalysis::Complete(report) => report,
        MandatoryCutAnalysis::Declined(decline) => {
            return decline_result(
                &budget,
                MandatoryLiteralFrontierDeclineReason::MandatoryCut(decline.reason()),
            );
        }
    };
    let Some(root) = cut_report.candidate() else {
        return complete_result(
            budget,
            None,
            MandatoryLiteralFrontierStopReason::NoMandatoryRoot,
        );
    };
    let cardinality = root.byte_class().cardinality();
    if cardinality <= 3 {
        return complete_result(
            budget,
            None,
            MandatoryLiteralFrontierStopReason::ExistingSmallRootClass { cardinality },
        );
    }
    if usize::from(cardinality) > MAX_MANDATORY_LITERAL_FRONTIER_ROOT_BYTES {
        return complete_result(
            budget,
            None,
            MandatoryLiteralFrontierStopReason::RootClassTooWide { cardinality },
        );
    }
    if limits.width_limit() < MIN_MANDATORY_LITERAL_FRONTIER_BYTES {
        let reason = match resource_usize(
            MandatoryLiteralFrontierResource::LiteralWidth,
            MIN_MANDATORY_LITERAL_FRONTIER_BYTES,
            limits.width_limit(),
        ) {
            Ok(reason) | Err(reason) => reason,
        };
        return decline_result(
            &budget,
            reason,
        );
    }

    match analyze_frontier_inner(raw, root.root_state(), &mut budget) {
        Ok(FrontierOutcome::Candidate(literals)) => {
            let maximum_before_root = root.maximum_before_root();
            match build_candidate(root.root_state(), maximum_before_root, &literals, &mut budget) {
                Ok(candidate) => complete_result(
                    budget,
                    Some(candidate),
                    MandatoryLiteralFrontierStopReason::Candidate,
                ),
                Err(reason) => decline_result(&budget, reason),
            }
        }
        Ok(FrontierOutcome::Short(bytes)) => complete_result(
            budget,
            None,
            MandatoryLiteralFrontierStopReason::ShortAcceptingTrace { bytes },
        ),
        Err(reason) => decline_result(&budget, reason),
    }
}

fn complete_result(
    mut budget: Budget,
    candidate: Option<MandatoryLiteralFrontierCandidate>,
    stop_reason: MandatoryLiteralFrontierStopReason,
) -> MandatoryLiteralFrontierAnalysis {
    budget.stats.candidates = usize::from(u8::from(candidate.is_some()));
    budget.stats.candidate_storage_bytes = candidate
        .as_ref()
        .map_or(0, MandatoryLiteralFrontierCandidate::storage_bytes);
    let reason_matches = candidate.is_some()
        == matches!(stop_reason, MandatoryLiteralFrontierStopReason::Candidate);
    if !reason_matches || !budget.stats.closes(budget.limits) {
        return MandatoryLiteralFrontierAnalysis::Declined(
            MandatoryLiteralFrontierAnalysisDecline {
                reason: MandatoryLiteralFrontierDeclineReason::InternalInvariant {
                    detail: "mandatory-literal-frontier completion receipt did not close",
                },
                stats: budget.stats,
            },
        );
    }
    MandatoryLiteralFrontierAnalysis::Complete(MandatoryLiteralFrontierAnalysisReport {
        candidate,
        stop_reason,
        stats: budget.stats,
    })
}

fn decline_result(
    budget: &Budget,
    reason: MandatoryLiteralFrontierDeclineReason,
) -> MandatoryLiteralFrontierAnalysis {
    let reason = if budget.stats.closes(budget.limits) {
        reason
    } else {
        MandatoryLiteralFrontierDeclineReason::InternalInvariant {
            detail: "mandatory-literal-frontier decline receipt did not close",
        }
    };
    MandatoryLiteralFrontierAnalysis::Declined(MandatoryLiteralFrontierAnalysisDecline {
        reason,
        stats: budget.stats,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Literal {
    bytes: [u8; MAX_MANDATORY_LITERAL_FRONTIER_BYTES],
    len: u8,
}

impl Literal {
    const fn empty() -> Self {
        Self {
            bytes: [0; MAX_MANDATORY_LITERAL_FRONTIER_BYTES],
            len: 0,
        }
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    fn pushed(self, byte: u8) -> Option<Self> {
        let index = usize::from(self.len);
        if index >= self.bytes.len() {
            return None;
        }
        let mut next = self;
        next.bytes[index] = byte;
        next.len = next.len.checked_add(1)?;
        Some(next)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Configuration {
    state: u32,
    literal: Literal,
}

enum FrontierOutcome {
    Candidate(Vec<Literal>),
    Short(u8),
}

#[allow(
    clippy::too_many_lines,
    reason = "one bounded traversal handles each validated Thompson role while retaining a single transactional frontier"
)]
fn analyze_frontier_inner(
    raw: &RawPlan,
    root: u32,
    budget: &mut Budget,
) -> Result<FrontierOutcome, MandatoryLiteralFrontierDeclineReason> {
    let productive = productive_states(raw, budget)?;
    let root_index = to_usize(root, "mandatory-literal-frontier root index")?;
    if !productive.get(root_index).copied().unwrap_or(false) {
        return Err(MandatoryLiteralFrontierDeclineReason::InternalInvariant {
            detail: "mandatory root is not productive",
        });
    }

    let mut configurations = Vec::new();
    push_configuration(
        &mut configurations,
        Configuration {
            state: root,
            literal: Literal::empty(),
        },
        budget,
    )?;
    let mut cursor = 0_usize;
    let mut literals = Vec::new();
    let width_limit = budget.limits.width_limit();
    while cursor < configurations.len() {
        budget.charge(1)?;
        let configuration = configurations[cursor];
        cursor = cursor.checked_add(1).ok_or(
            MandatoryLiteralFrontierDeclineReason::ArithmeticOverflow {
                computation: "mandatory-literal-frontier configuration cursor",
            },
        )?;
        let state = to_usize(configuration.state, "mandatory-literal-frontier state index")?;
        match raw.roles[state] {
            StateRole::Accept => {
                if usize::from(configuration.literal.len)
                    < MIN_MANDATORY_LITERAL_FRONTIER_BYTES
                {
                    snapshot_literals(&literals, budget)?;
                    return Ok(FrontierOutcome::Short(configuration.literal.len));
                }
                retain_literal(configuration.literal, &mut literals, budget)?;
            }
            StateRole::Split => {
                let (start, end) = state_edges(raw, state)?;
                for edge in start..end {
                    budget.charge(1)?;
                    if raw.edge_kinds[edge] != EdgeKind::Epsilon {
                        budget.stats.context_assertions = true;
                    }
                    let target = to_usize(
                        raw.edge_targets[edge],
                        "mandatory-literal-frontier split target",
                    )?;
                    if productive[target] {
                        push_configuration(
                            &mut configurations,
                            Configuration {
                                state: raw.edge_targets[edge],
                                literal: configuration.literal,
                            },
                            budget,
                        )?;
                    }
                }
            }
            StateRole::Consume => {
                let (start, end) = state_edges(raw, state)?;
                for edge in start..end {
                    budget.charge(1)?;
                    let target = to_usize(
                        raw.edge_targets[edge],
                        "mandatory-literal-frontier consume target",
                    )?;
                    if !productive[target] {
                        continue;
                    }
                    for byte in raw.byte_starts[edge]..=raw.byte_ends[edge] {
                        budget.charge(1)?;
                        let literal = configuration.literal.pushed(byte).ok_or(
                            MandatoryLiteralFrontierDeclineReason::InternalInvariant {
                                detail: "literal expanded beyond the effective width",
                            },
                        )?;
                        if usize::from(literal.len) == width_limit {
                            retain_literal(literal, &mut literals, budget)?;
                        } else {
                            push_configuration(
                                &mut configurations,
                                Configuration {
                                    state: raw.edge_targets[edge],
                                    literal,
                                },
                                budget,
                            )?;
                        }
                    }
                }
            }
        }
    }
    snapshot_literals(&literals, budget)?;
    if literals.is_empty() {
        return Err(MandatoryLiteralFrontierDeclineReason::InternalInvariant {
            detail: "productive mandatory root produced no frontier literals",
        });
    }
    Ok(FrontierOutcome::Candidate(literals))
}

fn state_edges(
    raw: &RawPlan,
    state: usize,
) -> Result<(usize, usize), MandatoryLiteralFrontierDeclineReason> {
    let start = to_usize(
        raw.edge_offsets[state],
        "mandatory-literal-frontier edge start",
    )?;
    let end = to_usize(
        raw.edge_offsets[state + 1],
        "mandatory-literal-frontier edge end",
    )?;
    Ok((start, end))
}

#[allow(
    clippy::too_many_lines,
    reason = "one bounded construction builds reverse CSR and its accept-reachability bitmap under a shared exact budget"
)]
fn productive_states(
    raw: &RawPlan,
    budget: &mut Budget,
) -> Result<Vec<bool>, MandatoryLiteralFrontierDeclineReason> {
    let states = raw.roles.len();
    let edges = raw.edge_targets.len();
    let mut incoming_counts = budget.filled(
        states,
        0_usize,
        "mandatory-literal-frontier incoming counts",
    )?;
    for &target in &raw.edge_targets {
        budget.charge(1)?;
        let target = to_usize(target, "mandatory-literal-frontier incoming target")?;
        incoming_counts[target] = incoming_counts[target].checked_add(1).ok_or(
            MandatoryLiteralFrontierDeclineReason::ArithmeticOverflow {
                computation: "mandatory-literal-frontier incoming count",
            },
        )?;
    }

    let offset_length = states.checked_add(1).ok_or(
        MandatoryLiteralFrontierDeclineReason::ArithmeticOverflow {
            computation: "mandatory-literal-frontier incoming offset length",
        },
    )?;
    let mut incoming_offsets = budget.filled(
        offset_length,
        0_usize,
        "mandatory-literal-frontier incoming offsets",
    )?;
    for state in 0..states {
        budget.charge(1)?;
        incoming_offsets[state + 1] = incoming_offsets[state]
            .checked_add(incoming_counts[state])
            .ok_or(
                MandatoryLiteralFrontierDeclineReason::ArithmeticOverflow {
                    computation: "mandatory-literal-frontier incoming prefix sum",
                },
            )?;
    }
    if incoming_offsets[states] != edges {
        return Err(MandatoryLiteralFrontierDeclineReason::InternalInvariant {
            detail: "validated incoming edge total changed",
        });
    }
    let mut incoming = budget.filled(
        edges,
        0_u32,
        "mandatory-literal-frontier incoming sources",
    )?;
    let mut cursors = Vec::new();
    budget.reserve(
        &mut cursors,
        states,
        "mandatory-literal-frontier incoming cursors",
    )?;
    budget.charge(to_u64(states, "mandatory-literal-frontier cursor copies")?)?;
    cursors.extend_from_slice(&incoming_offsets[..states]);
    for source in 0..states {
        let (start, end) = state_edges(raw, source)?;
        for edge in start..end {
            budget.charge(1)?;
            let target = to_usize(
                raw.edge_targets[edge],
                "mandatory-literal-frontier reverse target",
            )?;
            let slot = cursors[target];
            incoming[slot] = u32::try_from(source).map_err(|_| {
                MandatoryLiteralFrontierDeclineReason::ArithmeticOverflow {
                    computation: "mandatory-literal-frontier reverse source",
                }
            })?;
            cursors[target] = slot.checked_add(1).ok_or(
                MandatoryLiteralFrontierDeclineReason::ArithmeticOverflow {
                    computation: "mandatory-literal-frontier reverse cursor",
                },
            )?;
        }
    }

    let mut productive = budget.filled(
        states,
        false,
        "mandatory-literal-frontier productive bitmap",
    )?;
    let mut queue = Vec::new();
    for (state, role) in raw.roles.iter().enumerate() {
        budget.charge(1)?;
        if *role == StateRole::Accept {
            productive[state] = true;
            budget.push(
                &mut queue,
                u32::try_from(state).map_err(|_| {
                    MandatoryLiteralFrontierDeclineReason::ArithmeticOverflow {
                        computation: "mandatory-literal-frontier accept state",
                    }
                })?,
                "mandatory-literal-frontier productive queue",
            )?;
        }
    }
    let mut queue_cursor = 0_usize;
    while queue_cursor < queue.len() {
        budget.charge(1)?;
        let state = to_usize(
            queue[queue_cursor],
            "mandatory-literal-frontier productive queue state",
        )?;
        queue_cursor = queue_cursor.checked_add(1).ok_or(
            MandatoryLiteralFrontierDeclineReason::ArithmeticOverflow {
                computation: "mandatory-literal-frontier productive queue cursor",
            },
        )?;
        for &source in &incoming[incoming_offsets[state]..incoming_offsets[state + 1]] {
            budget.charge(1)?;
            let source = to_usize(source, "mandatory-literal-frontier productive source")?;
            if !productive[source] {
                productive[source] = true;
                budget.push(
                    &mut queue,
                    u32::try_from(source).map_err(|_| {
                        MandatoryLiteralFrontierDeclineReason::ArithmeticOverflow {
                            computation: "mandatory-literal-frontier productive source state",
                        }
                    })?,
                    "mandatory-literal-frontier productive queue",
                )?;
            }
        }
    }
    let mut productive_states = 0_usize;
    for &value in &productive {
        budget.charge(1)?;
        if value {
            productive_states = productive_states.checked_add(1).ok_or(
                MandatoryLiteralFrontierDeclineReason::ArithmeticOverflow {
                    computation: "mandatory-literal-frontier productive state count",
                },
            )?;
        }
    }
    budget.stats.productive_states = productive_states;
    Ok(productive)
}

fn push_configuration(
    configurations: &mut Vec<Configuration>,
    configuration: Configuration,
    budget: &mut Budget,
) -> Result<(), MandatoryLiteralFrontierDeclineReason> {
    for existing in configurations.iter() {
        budget.charge(1)?;
        if *existing == configuration {
            return Ok(());
        }
    }
    let needed = configurations.len().checked_add(1).ok_or(
        MandatoryLiteralFrontierDeclineReason::ArithmeticOverflow {
            computation: "mandatory-literal-frontier configuration count",
        },
    )?;
    if needed > budget.limits.max_configurations {
        return Err(resource_usize(
            MandatoryLiteralFrontierResource::Configurations,
            needed,
            budget.limits.max_configurations,
        )?);
    }
    budget.push(
        configurations,
        configuration,
        "mandatory-literal-frontier configurations",
    )?;
    budget.stats.configurations = needed;
    Ok(())
}

fn retain_literal(
    literal: Literal,
    literals: &mut Vec<Literal>,
    budget: &mut Budget,
) -> Result<(), MandatoryLiteralFrontierDeclineReason> {
    budget.stats.raw_literals = budget.stats.raw_literals.checked_add(1).ok_or(
        MandatoryLiteralFrontierDeclineReason::ArithmeticOverflow {
            computation: "mandatory-literal-frontier raw literal count",
        },
    )?;
    let mut index = 0_usize;
    while index < literals.len() {
        budget.charge(1)?;
        if is_prefix(literals[index], literal) {
            snapshot_literals(literals, budget)?;
            return Ok(());
        }
        if is_prefix(literal, literals[index]) {
            budget.charge(1)?;
            literals.swap_remove(index);
        } else {
            index = index.checked_add(1).ok_or(
                MandatoryLiteralFrontierDeclineReason::ArithmeticOverflow {
                    computation: "mandatory-literal-frontier literal cursor",
                },
            )?;
        }
    }
    let needed_literals = literals.len().checked_add(1).ok_or(
        MandatoryLiteralFrontierDeclineReason::ArithmeticOverflow {
            computation: "mandatory-literal-frontier retained literal count",
        },
    )?;
    let literal_limit = budget.limits.literal_limit();
    if needed_literals > literal_limit {
        snapshot_literals(literals, budget)?;
        return Err(resource_usize(
            MandatoryLiteralFrontierResource::Literals,
            needed_literals,
            literal_limit,
        )?);
    }
    let mut retained_bytes = usize::from(literal.len);
    for item in literals.iter() {
        budget.charge(1)?;
        retained_bytes = retained_bytes.checked_add(usize::from(item.len)).ok_or(
            MandatoryLiteralFrontierDeclineReason::ArithmeticOverflow {
                computation: "mandatory-literal-frontier retained literal bytes",
            },
        )?;
    }
    let byte_limit = budget.limits.byte_limit();
    if retained_bytes > byte_limit {
        snapshot_literals(literals, budget)?;
        return Err(resource_usize(
            MandatoryLiteralFrontierResource::LiteralBytes,
            retained_bytes,
            byte_limit,
        )?);
    }
    budget.push(
        literals,
        literal,
        "mandatory-literal-frontier literal antichain",
    )?;
    snapshot_literals(literals, budget)?;
    Ok(())
}

fn is_prefix(prefix: Literal, value: Literal) -> bool {
    prefix.len <= value.len && value.as_slice().starts_with(prefix.as_slice())
}

fn snapshot_literals(
    literals: &[Literal],
    budget: &mut Budget,
) -> Result<(), MandatoryLiteralFrontierDeclineReason> {
    let mut retained_literal_bytes = 0_usize;
    let mut maximum_literal_bytes = 0_usize;
    for literal in literals {
        budget.charge(1)?;
        let width = usize::from(literal.len);
        retained_literal_bytes = retained_literal_bytes.checked_add(width).ok_or(
            MandatoryLiteralFrontierDeclineReason::ArithmeticOverflow {
                computation: "mandatory-literal-frontier receipt literal bytes",
            },
        )?;
        maximum_literal_bytes = maximum_literal_bytes.max(width);
    }
    budget.stats.retained_literals = literals.len();
    budget.stats.retained_literal_bytes = retained_literal_bytes;
    budget.stats.maximum_literal_bytes = maximum_literal_bytes;
    Ok(())
}

fn build_candidate(
    root_state: u32,
    maximum_before_root: MaximumConsumedDistance,
    literals: &[Literal],
    budget: &mut Budget,
) -> Result<MandatoryLiteralFrontierCandidate, MandatoryLiteralFrontierDeclineReason> {
    let mut ordered = Vec::new();
    budget.reserve(
        &mut ordered,
        literals.len(),
        "mandatory-literal-frontier ordered literals",
    )?;
    for &literal in literals {
        budget.charge(1)?;
        ordered.push(literal);
    }
    for current in 1..ordered.len() {
        let mut position = current;
        while position > 0 {
            budget.charge(1)?;
            if compare_literals(ordered[position - 1], ordered[position]) != Ordering::Greater {
                break;
            }
            budget.charge(1)?;
            ordered.swap(position - 1, position);
            position -= 1;
        }
    }

    let offset_count = ordered.len().checked_add(1).ok_or(
        MandatoryLiteralFrontierDeclineReason::ArithmeticOverflow {
            computation: "mandatory-literal-frontier candidate offset count",
        },
    )?;
    let mut total_bytes = 0_usize;
    for literal in &ordered {
        budget.charge(1)?;
        total_bytes = total_bytes
            .checked_add(usize::from(literal.len))
            .ok_or(
                MandatoryLiteralFrontierDeclineReason::ArithmeticOverflow {
                    computation: "mandatory-literal-frontier candidate byte count",
                },
            )?;
    }
    let mut offsets = Vec::new();
    budget.reserve(
        &mut offsets,
        offset_count,
        "mandatory-literal-frontier candidate offsets",
    )?;
    let mut bytes = Vec::new();
    budget.reserve(
        &mut bytes,
        total_bytes,
        "mandatory-literal-frontier candidate bytes",
    )?;
    offsets.push(0_u16);
    for literal in ordered {
        budget.charge(1)?;
        bytes.extend_from_slice(literal.as_slice());
        offsets.push(u16::try_from(bytes.len()).map_err(|_| {
            MandatoryLiteralFrontierDeclineReason::ArithmeticOverflow {
                computation: "mandatory-literal-frontier candidate offset",
            }
        })?);
    }
    Ok(MandatoryLiteralFrontierCandidate {
        root_state,
        maximum_before_root,
        offsets,
        bytes,
    })
}

fn compare_literals(left: Literal, right: Literal) -> Ordering {
    left.as_slice().cmp(right.as_slice())
}

#[derive(Clone, Copy, Debug)]
struct Budget {
    limits: MandatoryLiteralFrontierAnalysisLimits,
    stats: MandatoryLiteralFrontierAnalysisStats,
}

impl Budget {
    fn new(
        limits: MandatoryLiteralFrontierAnalysisLimits,
        states: usize,
        edges: usize,
    ) -> Self {
        Self {
            limits,
            stats: MandatoryLiteralFrontierAnalysisStats {
                accounting_id: MANDATORY_LITERAL_FRONTIER_ACCOUNTING_ID,
                mandatory_cut: MandatoryCutAnalysisStats::default(),
                work: 0,
                allocation_items: 0,
                allocation_attempts: 0,
                states,
                edges,
                productive_states: 0,
                configurations: 0,
                raw_literals: 0,
                retained_literals: 0,
                retained_literal_bytes: 0,
                maximum_literal_bytes: 0,
                candidates: 0,
                candidate_storage_bytes: 0,
                context_assertions: false,
            },
        }
    }

    fn charge(&mut self, amount: u64) -> Result<(), MandatoryLiteralFrontierDeclineReason> {
        let needed = self.stats.work.checked_add(amount).ok_or(
            MandatoryLiteralFrontierDeclineReason::ArithmeticOverflow {
                computation: "mandatory-literal-frontier work",
            },
        )?;
        if needed > self.limits.max_work {
            return Err(MandatoryLiteralFrontierDeclineReason::Resource {
                resource: MandatoryLiteralFrontierResource::Work,
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
    ) -> Result<(), MandatoryLiteralFrontierDeclineReason> {
        if additional == 0 {
            return Ok(());
        }
        let needed = self.stats.allocation_items.checked_add(additional).ok_or(
            MandatoryLiteralFrontierDeclineReason::ArithmeticOverflow {
                computation: "mandatory-literal-frontier allocation items",
            },
        )?;
        if needed > self.limits.max_allocation_items {
            return Err(resource_usize(
                MandatoryLiteralFrontierResource::AllocationItems,
                needed,
                self.limits.max_allocation_items,
            )?);
        }
        let attempts = self.stats.allocation_attempts.checked_add(1).ok_or(
            MandatoryLiteralFrontierDeclineReason::ArithmeticOverflow {
                computation: "mandatory-literal-frontier allocation attempts",
            },
        )?;
        if attempts > self.limits.max_allocation_attempts {
            return Err(resource_usize(
                MandatoryLiteralFrontierResource::AllocationAttempts,
                attempts,
                self.limits.max_allocation_attempts,
            )?);
        }
        self.stats.allocation_attempts = attempts;
        values.try_reserve_exact(additional).map_err(|_| {
            MandatoryLiteralFrontierDeclineReason::Allocation {
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
    ) -> Result<(), MandatoryLiteralFrontierDeclineReason> {
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
    ) -> Result<Vec<T>, MandatoryLiteralFrontierDeclineReason> {
        let mut values = Vec::new();
        self.reserve(&mut values, length, structure)?;
        self.charge(to_u64(
            length,
            "mandatory-literal-frontier initialized items",
        )?)?;
        values.resize(length, value);
        Ok(values)
    }
}

fn resource_usize(
    resource: MandatoryLiteralFrontierResource,
    needed: usize,
    limit: usize,
) -> Result<MandatoryLiteralFrontierDeclineReason, MandatoryLiteralFrontierDeclineReason> {
    Ok(MandatoryLiteralFrontierDeclineReason::Resource {
        resource,
        needed: to_u64(needed, "mandatory-literal-frontier resource need")?,
        limit: to_u64(limit, "mandatory-literal-frontier resource limit")?,
    })
}

fn to_u64(
    value: usize,
    computation: &'static str,
) -> Result<u64, MandatoryLiteralFrontierDeclineReason> {
    u64::try_from(value)
        .map_err(|_| MandatoryLiteralFrontierDeclineReason::ArithmeticOverflow { computation })
}

fn to_usize(
    value: u32,
    computation: &'static str,
) -> Result<usize, MandatoryLiteralFrontierDeclineReason> {
    usize::try_from(value)
        .map_err(|_| MandatoryLiteralFrontierDeclineReason::ArithmeticOverflow { computation })
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestEdge = (u32, EdgeKind, u8, u8);

    const fn epsilon(target: u32) -> TestEdge {
        (target, EdgeKind::Epsilon, 0, 0)
    }

    const fn assertion(target: u32) -> TestEdge {
        (target, EdgeKind::AssertWordAscii, 0, 0)
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

    fn four_by_four() -> RawPlan {
        raw(
            0,
            vec![
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Accept,
            ],
            vec![
                vec![byte(1, b'a'), byte(2, b'b'), byte(3, b'c'), byte(4, b'd')],
                vec![byte(5, b'1')],
                vec![byte(5, b'2')],
                vec![byte(5, b'3')],
                vec![byte(5, b'4')],
                vec![],
            ],
        )
    }

    fn complete(
        graph: &RawPlan,
        limits: MandatoryLiteralFrontierAnalysisLimits,
    ) -> MandatoryLiteralFrontierAnalysisReport {
        match analyze_mandatory_literal_frontier(graph, limits) {
            MandatoryLiteralFrontierAnalysis::Complete(report) => report,
            MandatoryLiteralFrontierAnalysis::Declined(decline) => {
                panic!("unexpected frontier decline: {decline:?}")
            }
        }
    }

    fn candidate(
        graph: &RawPlan,
    ) -> (MandatoryLiteralFrontierAnalysisReport, MandatoryLiteralFrontierCandidate) {
        let report = complete(graph, MandatoryLiteralFrontierAnalysisLimits::default());
        let candidate = report.candidate().expect("frontier candidate").clone();
        (report, candidate)
    }

    fn literals(candidate: &MandatoryLiteralFrontierCandidate) -> Vec<Vec<u8>> {
        candidate.iter().map(<[u8]>::to_vec).collect()
    }

    #[test]
    fn publishes_complete_deterministic_two_byte_frontier() {
        let (report, frontier) = candidate(&four_by_four());
        assert_eq!(frontier.root_state(), 0);
        assert_eq!(
            frontier.maximum_before_root(),
            MaximumConsumedDistance::Finite(0)
        );
        assert_eq!(
            literals(&frontier),
            vec![b"a1".to_vec(), b"b2".to_vec(), b"c3".to_vec(), b"d4".to_vec()]
        );
        assert_eq!(report.stop_reason(), MandatoryLiteralFrontierStopReason::Candidate);
        assert!(report.stats().closes(MandatoryLiteralFrontierAnalysisLimits::default()));
    }

    #[test]
    fn carries_finite_and_unbounded_root_positions() {
        let finite = raw(
            0,
            vec![
                StateRole::Split,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Consume,
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
                vec![byte(5, b'a'), byte(6, b'b'), byte(7, b'c'), byte(8, b'd')],
                vec![byte(9, b'1')],
                vec![byte(9, b'2')],
                vec![byte(9, b'3')],
                vec![byte(9, b'4')],
                vec![],
            ],
        );
        assert_eq!(
            candidate(&finite).1.maximum_before_root(),
            MaximumConsumedDistance::Finite(2)
        );

        let unbounded = raw(
            0,
            vec![
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Accept,
            ],
            vec![
                vec![byte_range(0, 0, 255), byte_range(1, 0, 255)],
                vec![byte(2, b'a'), byte(3, b'b'), byte(4, b'c'), byte(5, b'd')],
                vec![byte(6, b'1')],
                vec![byte(6, b'2')],
                vec![byte(6, b'3')],
                vec![byte(6, b'4')],
                vec![],
            ],
        );
        let frontier = candidate(&unbounded).1;
        assert_eq!(frontier.root_state(), 1);
        assert_eq!(
            frontier.maximum_before_root(),
            MaximumConsumedDistance::Unbounded
        );
    }

    #[test]
    fn ignores_dead_ranges_and_terminates_zero_width_cycles() {
        let dead = raw(
            0,
            vec![
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Accept,
            ],
            vec![
                vec![
                    byte(1, b'a'),
                    byte(2, b'b'),
                    byte(3, b'c'),
                    byte(4, b'd'),
                    byte_range(5, 0, 255),
                ],
                vec![byte(6, b'1')],
                vec![byte(6, b'2')],
                vec![byte(6, b'3')],
                vec![byte(6, b'4')],
                vec![byte_range(5, 0, 255)],
                vec![],
            ],
        );
        assert_eq!(literals(&candidate(&dead).1).len(), 4);

        let cycle = raw(
            0,
            vec![
                StateRole::Consume,
                StateRole::Split,
                StateRole::Consume,
                StateRole::Accept,
            ],
            vec![
                vec![byte(1, b'a'), byte(1, b'b'), byte(1, b'c'), byte(1, b'd')],
                vec![assertion(1), epsilon(2)],
                vec![byte_range(3, 0, 7)],
                vec![],
            ],
        );
        let (report, frontier) = candidate(&cycle);
        assert_eq!(frontier.len(), 32);
        assert!(report.stats().context_assertions());
        assert!(report.stats().configurations() < 64);
    }

    #[test]
    fn short_accepting_trace_refuses_the_entire_cover() {
        let graph = raw(
            0,
            vec![StateRole::Consume, StateRole::Accept],
            vec![vec![byte_range(1, b'a', b'd')], vec![]],
        );
        let report = complete(&graph, MandatoryLiteralFrontierAnalysisLimits::default());
        assert!(report.candidate().is_none());
        assert_eq!(
            report.stop_reason(),
            MandatoryLiteralFrontierStopReason::ShortAcceptingTrace { bytes: 1 }
        );
    }

    #[test]
    fn width_cap_publishes_productive_prefixes_without_reaching_accept() {
        let mut roles = vec![StateRole::Consume; 17];
        roles.push(StateRole::Accept);
        let mut rows = vec![Vec::new(); roles.len()];
        for branch in 0_usize..4 {
            let first = 1 + branch * 4;
            rows[0].push(byte(
                u32::try_from(first).expect("test branch state"),
                b'a' + u8::try_from(branch).expect("test branch byte"),
            ));
            rows[first].push(byte(
                u32::try_from(first + 1).expect("test chain state"),
                b'1',
            ));
            rows[first + 1].push(byte(
                u32::try_from(first + 2).expect("test chain state"),
                b'2',
            ));
            rows[first + 2].push(byte(
                u32::try_from(first + 3).expect("test chain state"),
                b'3',
            ));
            rows[first + 3].push(byte(17, b'4'));
        }
        let frontier = candidate(&raw(0, roles, rows)).1;
        assert_eq!(
            literals(&frontier),
            vec![
                b"a123".to_vec(),
                b"b123".to_vec(),
                b"c123".to_vec(),
                b"d123".to_vec(),
            ]
        );
    }

    #[test]
    fn canonicalization_uses_prefixes_not_internal_substrings() {
        let limits = MandatoryLiteralFrontierAnalysisLimits::default();
        let mut budget = Budget::new(limits, 1, 0);
        budget.stats.mandatory_cut = analyze_mandatory_cut(&four_by_four(), limits.mandatory_cut).stats();
        let literal = |bytes: &[u8]| {
            let mut literal = Literal::empty();
            for &byte in bytes {
                literal = literal.pushed(byte).expect("bounded test literal");
            }
            literal
        };
        let mut set = Vec::new();
        retain_literal(literal(b"abc"), &mut set, &mut budget).expect("retain abc");
        retain_literal(literal(b"ab"), &mut set, &mut budget).expect("replace by prefix");
        retain_literal(literal(b"abcd"), &mut set, &mut budget).expect("covered extension");
        retain_literal(literal(b"bc"), &mut set, &mut budget).expect("retain non-prefix");
        assert_eq!(set.len(), 2);
        assert!(set.iter().any(|item| item.as_slice() == b"ab"));
        assert!(set.iter().any(|item| item.as_slice() == b"bc"));
    }

    #[test]
    fn work_decline_during_snapshot_preserves_prior_closed_antichain_receipt() {
        let graph = four_by_four();
        let limits = MandatoryLiteralFrontierAnalysisLimits::default();
        let mut budget = Budget::new(limits, graph.roles.len(), graph.edge_targets.len());
        budget.stats.mandatory_cut = analyze_mandatory_cut(&graph, limits.mandatory_cut).stats();
        let literal = |bytes: &[u8]| {
            let mut literal = Literal::empty();
            for &byte in bytes {
                literal = literal.pushed(byte).expect("bounded test literal");
            }
            literal
        };
        let mut set = Vec::new();
        retain_literal(literal(b"abc"), &mut set, &mut budget).expect("initial snapshot");
        assert_eq!(budget.stats.retained_literals(), 1);
        assert_eq!(budget.stats.retained_literal_bytes(), 3);
        assert_eq!(budget.stats.maximum_literal_bytes(), 3);

        // Replacing `abc` with `ab` charges two prefix decisions and one
        // insertion before snapshotting. Permit exactly those three units so
        // the first snapshot visit fails after the scratch antichain changed.
        budget.limits.max_work = budget.stats.work().checked_add(3).expect("test work limit");
        let result = retain_literal(literal(b"ab"), &mut set, &mut budget);
        assert!(matches!(
            result,
            Err(MandatoryLiteralFrontierDeclineReason::Resource {
                resource: MandatoryLiteralFrontierResource::Work,
                ..
            })
        ));
        assert_eq!(set.len(), 1);
        assert_eq!(set[0].as_slice(), b"ab");
        assert_eq!(budget.stats.retained_literals(), 1);
        assert_eq!(budget.stats.retained_literal_bytes(), 3);
        assert_eq!(budget.stats.maximum_literal_bytes(), 3);
        assert!(budget.stats.closes(budget.limits));
    }

    #[test]
    fn exhaustive_two_byte_languages_match_independent_prefix_oracle() {
        for masks in 0_u8..81 {
            let mut value = masks;
            let mut rows = Vec::new();
            rows.push(vec![byte(1, b'a'), byte(2, b'b'), byte(3, b'c'), byte(4, b'd')]);
            let mut accepted = Vec::new();
            for branch in 0_u8..4 {
                let mask = value % 3 + 1;
                value /= 3;
                let mut row = Vec::new();
                if mask & 1 != 0 {
                    row.push(byte(5, b'0'));
                    accepted.push(vec![b'a' + branch, b'0']);
                }
                if mask & 2 != 0 {
                    row.push(byte(5, b'1'));
                    accepted.push(vec![b'a' + branch, b'1']);
                }
                rows.push(row);
            }
            rows.push(Vec::new());
            let graph = raw(
                0,
                vec![
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Accept,
                ],
                rows,
            );
            let frontier = candidate(&graph).1;
            for trace in &accepted {
                assert!(
                    frontier.iter().any(|literal| trace.starts_with(literal)),
                    "language {masks}, trace {trace:?}, frontier {:?}",
                    literals(&frontier)
                );
            }
            for literal in frontier.iter() {
                assert!(accepted.iter().any(|trace| trace.starts_with(literal)));
            }
        }
    }

    fn assert_resource(
        graph: &RawPlan,
        limits: MandatoryLiteralFrontierAnalysisLimits,
        expected: MandatoryLiteralFrontierResource,
    ) {
        let analysis = analyze_mandatory_literal_frontier(graph, limits);
        assert!(analysis.stats().closes(limits), "{analysis:?}");
        let MandatoryLiteralFrontierAnalysis::Declined(decline) = analysis else {
            panic!("limited frontier unexpectedly completed")
        };
        assert!(matches!(
            decline.reason(),
            MandatoryLiteralFrontierDeclineReason::Resource { resource, .. }
                if resource == expected
        ));
    }

    #[test]
    fn exact_and_one_below_resource_boundaries_close() {
        let graph = four_by_four();
        let baseline_limits = MandatoryLiteralFrontierAnalysisLimits::default();
        let baseline = complete(&graph, baseline_limits);
        let stats = baseline.stats();
        let exact = MandatoryLiteralFrontierAnalysisLimits {
            max_work: stats.work(),
            max_allocation_items: stats.allocation_items(),
            max_allocation_attempts: stats.allocation_attempts(),
            max_configurations: stats.configurations(),
            max_literals: stats.retained_literals(),
            max_literal_bytes: stats.maximum_literal_bytes(),
            max_total_literal_bytes: stats.retained_literal_bytes(),
            ..baseline_limits
        };
        let exact_report = complete(&graph, exact);
        assert_eq!(exact_report.candidate(), baseline.candidate());
        assert!(exact_report.stats().closes(exact));

        assert_resource(
            &graph,
            MandatoryLiteralFrontierAnalysisLimits {
                max_work: stats.work() - 1,
                ..baseline_limits
            },
            MandatoryLiteralFrontierResource::Work,
        );
        assert_resource(
            &graph,
            MandatoryLiteralFrontierAnalysisLimits {
                max_allocation_items: stats.allocation_items() - 1,
                ..baseline_limits
            },
            MandatoryLiteralFrontierResource::AllocationItems,
        );
        assert_resource(
            &graph,
            MandatoryLiteralFrontierAnalysisLimits {
                max_allocation_attempts: stats.allocation_attempts() - 1,
                ..baseline_limits
            },
            MandatoryLiteralFrontierResource::AllocationAttempts,
        );
        assert_resource(
            &graph,
            MandatoryLiteralFrontierAnalysisLimits {
                max_configurations: stats.configurations() - 1,
                ..baseline_limits
            },
            MandatoryLiteralFrontierResource::Configurations,
        );
        assert_resource(
            &graph,
            MandatoryLiteralFrontierAnalysisLimits {
                max_literals: stats.retained_literals() - 1,
                ..baseline_limits
            },
            MandatoryLiteralFrontierResource::Literals,
        );
        assert_resource(
            &graph,
            MandatoryLiteralFrontierAnalysisLimits {
                max_literal_bytes: MIN_MANDATORY_LITERAL_FRONTIER_BYTES - 1,
                ..baseline_limits
            },
            MandatoryLiteralFrontierResource::LiteralWidth,
        );
        assert_resource(
            &graph,
            MandatoryLiteralFrontierAnalysisLimits {
                max_total_literal_bytes: stats.retained_literal_bytes() - 1,
                ..baseline_limits
            },
            MandatoryLiteralFrontierResource::LiteralBytes,
        );
    }

    #[test]
    fn candidate_storage_receipt_uses_actual_capacities() {
        let (report, frontier) = candidate(&four_by_four());
        let expected = size_of::<MandatoryLiteralFrontierCandidate>()
            + frontier.offsets.capacity() * size_of::<u16>()
            + frontier.bytes.capacity();
        assert_eq!(frontier.storage_bytes(), expected);
        assert_eq!(report.stats().candidate_storage_bytes(), expected);
    }

    #[test]
    fn incumbent_and_fixed_wide_gates_do_no_frontier_work() {
        let small = raw(
            0,
            vec![StateRole::Consume, StateRole::Accept],
            vec![vec![byte_range(1, b'a', b'c')], vec![]],
        );
        let report = complete(&small, MandatoryLiteralFrontierAnalysisLimits::default());
        assert_eq!(
            report.stop_reason(),
            MandatoryLiteralFrontierStopReason::ExistingSmallRootClass { cardinality: 3 }
        );
        assert_eq!(report.stats().work(), 0);

        let wide = raw(
            0,
            vec![StateRole::Consume, StateRole::Accept],
            vec![vec![byte_range(1, 0, 32)], vec![]],
        );
        let report = complete(&wide, MandatoryLiteralFrontierAnalysisLimits::default());
        assert_eq!(
            report.stop_reason(),
            MandatoryLiteralFrontierStopReason::RootClassTooWide { cardinality: 33 }
        );
        assert_eq!(report.stats().work(), 0);
    }

    #[test]
    fn malformed_graph_decline_is_bound_to_nested_cut_receipt() {
        let graph = RawPlan {
            start: 0,
            roles: vec![],
            edge_offsets: vec![],
            edge_targets: vec![],
            edge_kinds: vec![],
            byte_starts: vec![],
            byte_ends: vec![],
        };
        let limits = MandatoryLiteralFrontierAnalysisLimits::default();
        let analysis = analyze_mandatory_literal_frontier(&graph, limits);
        assert!(analysis.stats().closes(limits));
        let MandatoryLiteralFrontierAnalysis::Declined(decline) = analysis else {
            panic!("malformed graph unexpectedly completed")
        };
        assert!(matches!(
            decline.reason(),
            MandatoryLiteralFrontierDeclineReason::MandatoryCut(
                MandatoryCutDeclineReason::MalformedGraph(_)
            )
        ));
    }
}
