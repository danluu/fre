//! Bounded graph-only correlated prefix, suffix, and interior literals.
//!
//! Unlike independent per-position byte unions, each retained literal keeps
//! the bytes chosen along one Thompson path together. Assertions are followed
//! conservatively as zero-width edges. This can add impossible literals when
//! an assertion cannot hold, but it cannot remove a literal required by an
//! accepting path. Early acceptance, frontier growth, allocation failure, or
//! a resource ceiling returns the last completely derived shallower set.
//! Interior groups additionally carry a consuming-state dominator proof: every
//! accepting graph path visits the group's root, so every match contains one
//! (not necessarily every) literal in that correlated group.

use core::hash::Hash;
use std::collections::HashSet;

use fre_automata::{EdgeKind, RawPlan, StateRole};

/// Maximum concrete byte depth retained in either direction.
pub(crate) const MAX_REQUIRED_LITERAL_DEPTH: usize = 8;
/// Maximum correlated sequences retained in one direction.
pub(crate) const MAX_REQUIRED_LITERAL_SEQUENCES: usize = 2_048;
/// Maximum bytes across the published prefix and suffix sequence sets.
pub(crate) const MAX_REQUIRED_LITERAL_TOTAL_BYTES: usize = 32_768;
/// Maximum abstract work across both directional analyses.
pub(crate) const MAX_REQUIRED_LITERAL_WORK: u64 = 2_000_000;
/// Maximum logical allocation items across both directional analyses.
pub(crate) const MAX_REQUIRED_LITERAL_ALLOCATION_ITEMS: usize = 262_144;
/// Maximum distinct `(state, literal)` pairs in one layer.
pub(crate) const MAX_REQUIRED_LITERAL_FRONTIER_ITEMS: usize = 8_192;
/// Maximum independently mandatory interior literal groups retained.
pub(crate) const MAX_REQUIRED_INTERIOR_CANDIDATES: usize = 8;
/// Maximum dominator roots whose local literals are inspected.
pub(crate) const MAX_REQUIRED_INTERIOR_SEEDS: usize = 128;
/// Fair-share work ceiling for one interior root's local expansion.
pub(crate) const MAX_REQUIRED_INTERIOR_CANDIDATE_WORK: u64 = 250_000;
/// Fair-share logical allocation ceiling for one interior root's expansion.
pub(crate) const MAX_REQUIRED_INTERIOR_CANDIDATE_ALLOCATION_ITEMS: usize = 32_768;
/// Independent work ceiling for the optional mandatory-line cut proof.
pub(crate) const MAX_REQUIRED_LINE_CUT_WORK: u64 = 2_000_000;
/// Independent logical allocation ceiling for the optional line cut proof.
pub(crate) const MAX_REQUIRED_LINE_CUT_ALLOCATION_ITEMS: usize = 262_144;

/// One concrete byte sequence, stored inline for compact native handoff.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct RequiredLiteral {
    bytes: [u8; MAX_REQUIRED_LITERAL_DEPTH],
    len: u8,
}

#[allow(dead_code, reason = "structural handoff for native code generation")]
impl RequiredLiteral {
    #[must_use]
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

/// One direction of the bounded universal-path proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RequiredLiteralSet {
    literals: Box<[RequiredLiteral]>,
    depth: u8,
    derivation_work: u64,
    allocation_items: usize,
    resource_limited: bool,
    shortened: bool,
    context_assertions: bool,
}

#[allow(dead_code, reason = "structural handoff for native code generation")]
impl RequiredLiteralSet {
    fn unavailable(budget: &Budget, shortened: bool) -> Self {
        Self {
            literals: Box::new([]),
            depth: 0,
            derivation_work: budget.work,
            allocation_items: budget.allocation_items,
            resource_limited: budget.resource_limited,
            shortened,
            context_assertions: budget.context_assertions,
        }
    }

    #[must_use]
    pub(crate) fn literals(&self) -> &[RequiredLiteral] {
        &self.literals
    }

    #[must_use]
    pub(crate) fn depth(&self) -> usize {
        usize::from(self.depth)
    }

    #[must_use]
    pub(crate) const fn derivation_work(&self) -> u64 {
        self.derivation_work
    }

    #[must_use]
    pub(crate) const fn allocation_items(&self) -> usize {
        self.allocation_items
    }

    #[must_use]
    pub(crate) const fn resource_limited(&self) -> bool {
        self.resource_limited
    }

    #[must_use]
    pub(crate) const fn shortened(&self) -> bool {
        self.shortened
    }

    #[must_use]
    pub(crate) const fn context_assertions(&self) -> bool {
        self.context_assertions
    }

    fn literal_bytes(&self) -> usize {
        self.literals.len().saturating_mul(self.depth())
    }
}

/// Exact maximum consumed-byte distance for a productive graph walk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MaximumConsumedDistance {
    /// Every relevant walk consumes at most this many bytes.
    Finite(u32),
    /// A consuming cycle lies on a relevant walk, so no finite maximum exists.
    Unbounded,
}

/// One contextual line assertion crossed by every structurally accepting
/// path. The proof is graph-only: removing every edge of `kind` makes every
/// accept unreachable from the Thompson start state.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum RequiredLineCutKind {
    ConfiguredStart,
    ConfiguredEnd,
    CrlfStart,
    CrlfEnd,
}

impl RequiredLineCutKind {
    const ALL: [Self; 4] = [
        Self::ConfiguredStart,
        Self::ConfiguredEnd,
        Self::CrlfStart,
        Self::CrlfEnd,
    ];

    const fn edge(self) -> EdgeKind {
        match self {
            Self::ConfiguredStart => EdgeKind::AssertLineStartLf,
            Self::ConfiguredEnd => EdgeKind::AssertLineEndLf,
            Self::CrlfStart => EdgeKind::AssertLineStartCrlf,
            Self::CrlfEnd => EdgeKind::AssertLineEndCrlf,
        }
    }

    pub(crate) const fn scanner_cardinality(self) -> u8 {
        match self {
            Self::ConfiguredStart | Self::ConfiguredEnd => 1,
            Self::CrlfStart | Self::CrlfEnd => 2,
        }
    }
}

/// A complete line-cut proof and a conservative maximum consumed distance
/// from match start to the assertion boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RequiredLineCut {
    kind: RequiredLineCutKind,
    maximum_before: MaximumConsumedDistance,
}

impl RequiredLineCut {
    #[must_use]
    pub(crate) const fn kind(self) -> RequiredLineCutKind {
        self.kind
    }

    #[must_use]
    pub(crate) const fn maximum_before(self) -> MaximumConsumedDistance {
        self.maximum_before
    }
}

/// One independently mandatory interior group.
///
/// The literals inside a group are alternatives: every match contains at
/// least one of them beginning at an occurrence of `root_state`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RequiredInteriorCandidate {
    root_state: u32,
    literals: RequiredLiteralSet,
    max_before_root: MaximumConsumedDistance,
    max_through_accept: MaximumConsumedDistance,
}

#[allow(dead_code, reason = "structural handoff for native code generation")]
impl RequiredInteriorCandidate {
    #[must_use]
    pub(crate) const fn root_state(&self) -> u32 {
        self.root_state
    }

    #[must_use]
    pub(crate) fn literals(&self) -> &[RequiredLiteral] {
        self.literals.literals()
    }

    #[must_use]
    pub(crate) fn depth(&self) -> usize {
        self.literals.depth()
    }

    /// Maximum bytes consumed before entering this root. Walks may revisit the
    /// root; such a consuming cycle is conservatively reported as unbounded.
    #[must_use]
    pub(crate) const fn max_before_root(&self) -> MaximumConsumedDistance {
        self.max_before_root
    }

    /// Maximum bytes consumed from this root through an accept, including the
    /// byte consumed by the root itself.
    #[must_use]
    pub(crate) const fn max_through_accept(&self) -> MaximumConsumedDistance {
        self.max_through_accept
    }

    #[must_use]
    pub(crate) const fn literal_set(&self) -> &RequiredLiteralSet {
        &self.literals
    }

    fn literal_bytes(&self) -> usize {
        self.literals.literal_bytes()
    }
}

/// Bounded collection of independently mandatory interior groups.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RequiredInteriorLiterals {
    candidates: Box<[RequiredInteriorCandidate]>,
    line_cuts: Box<[RequiredLineCut]>,
    derivation_work: u64,
    allocation_items: usize,
    resource_limited: bool,
    context_assertions: bool,
}

#[allow(dead_code, reason = "structural handoff for native code generation")]
impl RequiredInteriorLiterals {
    fn unavailable(budget: &Budget) -> Self {
        Self {
            candidates: Box::new([]),
            line_cuts: Box::new([]),
            derivation_work: budget.work,
            allocation_items: budget.allocation_items,
            resource_limited: budget.resource_limited,
            context_assertions: budget.context_assertions,
        }
    }

    #[must_use]
    pub(crate) fn candidates(&self) -> &[RequiredInteriorCandidate] {
        &self.candidates
    }

    /// Every independently proved mandatory exact line-assertion kind.
    /// Target lowering chooses among them using the actual entry strategy;
    /// notably, a full-window start cut may be a no-op while an end cut pays.
    #[must_use]
    pub(crate) fn line_cuts(&self) -> &[RequiredLineCut] {
        &self.line_cuts
    }

    #[must_use]
    pub(crate) const fn derivation_work(&self) -> u64 {
        self.derivation_work
    }

    #[must_use]
    pub(crate) const fn allocation_items(&self) -> usize {
        self.allocation_items
    }

    #[must_use]
    pub(crate) const fn resource_limited(&self) -> bool {
        self.resource_limited
    }

    #[must_use]
    pub(crate) const fn context_assertions(&self) -> bool {
        self.context_assertions
    }

    fn literal_bytes(&self) -> usize {
        self.candidates.iter().fold(0usize, |total, candidate| {
            total.saturating_add(candidate.literal_bytes())
        })
    }
}

/// Correlated literals available to native lowering.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RequiredLiterals {
    prefix: RequiredLiteralSet,
    suffix: RequiredLiteralSet,
    interior: RequiredInteriorLiterals,
}

#[allow(dead_code, reason = "structural handoff for native code generation")]
impl RequiredLiterals {
    pub(crate) fn unavailable() -> Self {
        let budget = Budget::new(0, 0);
        Self {
            prefix: RequiredLiteralSet::unavailable(&budget, false),
            suffix: RequiredLiteralSet::unavailable(&budget, false),
            interior: RequiredInteriorLiterals::unavailable(&budget),
        }
    }

    #[must_use]
    pub(crate) const fn prefix(&self) -> &RequiredLiteralSet {
        &self.prefix
    }

    #[must_use]
    pub(crate) const fn suffix(&self) -> &RequiredLiteralSet {
        &self.suffix
    }

    #[must_use]
    pub(crate) const fn interior(&self) -> &RequiredInteriorLiterals {
        &self.interior
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_field_names,
    reason = "explicit max prefixes distinguish hard analysis ceilings from usage counters"
)]
pub(crate) struct RequiredLiteralLimits {
    pub(crate) max_depth: usize,
    pub(crate) max_sequences: usize,
    pub(crate) max_total_bytes: usize,
    pub(crate) max_work: u64,
    pub(crate) max_allocation_items: usize,
    pub(crate) max_frontier_items: usize,
    pub(crate) max_interior_candidates: usize,
    pub(crate) max_interior_seeds: usize,
    pub(crate) max_candidate_work: u64,
    pub(crate) max_candidate_allocation_items: usize,
    pub(crate) max_line_cut_work: u64,
    pub(crate) max_line_cut_allocation_items: usize,
}

impl Default for RequiredLiteralLimits {
    fn default() -> Self {
        Self {
            max_depth: MAX_REQUIRED_LITERAL_DEPTH,
            max_sequences: MAX_REQUIRED_LITERAL_SEQUENCES,
            max_total_bytes: MAX_REQUIRED_LITERAL_TOTAL_BYTES,
            max_work: MAX_REQUIRED_LITERAL_WORK,
            max_allocation_items: MAX_REQUIRED_LITERAL_ALLOCATION_ITEMS,
            max_frontier_items: MAX_REQUIRED_LITERAL_FRONTIER_ITEMS,
            max_interior_candidates: MAX_REQUIRED_INTERIOR_CANDIDATES,
            max_interior_seeds: MAX_REQUIRED_INTERIOR_SEEDS,
            max_candidate_work: MAX_REQUIRED_INTERIOR_CANDIDATE_WORK,
            max_candidate_allocation_items: MAX_REQUIRED_INTERIOR_CANDIDATE_ALLOCATION_ITEMS,
            max_line_cut_work: MAX_REQUIRED_LINE_CUT_WORK,
            max_line_cut_allocation_items: MAX_REQUIRED_LINE_CUT_ALLOCATION_ITEMS,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Budget {
    max_work: u64,
    max_allocation_items: usize,
    work: u64,
    allocation_items: usize,
    resource_limited: bool,
    context_assertions: bool,
}

impl Budget {
    const fn new(max_work: u64, max_allocation_items: usize) -> Self {
        Self {
            max_work,
            max_allocation_items,
            work: 0,
            allocation_items: 0,
            resource_limited: false,
            context_assertions: false,
        }
    }

    fn charge(&mut self, amount: u64) -> bool {
        let Some(next) = self.work.checked_add(amount) else {
            self.resource_limited = true;
            return false;
        };
        if next > self.max_work {
            self.resource_limited = true;
            return false;
        }
        self.work = next;
        true
    }

    fn reserve_vec<T>(&mut self, values: &mut Vec<T>, additional: usize) -> bool {
        let Some(next) = self.allocation_items.checked_add(additional) else {
            self.resource_limited = true;
            return false;
        };
        if next > self.max_allocation_items || values.try_reserve(additional).is_err() {
            self.resource_limited = true;
            return false;
        }
        self.allocation_items = next;
        true
    }

    fn reserve_set<T>(&mut self, values: &mut HashSet<T>, additional: usize) -> bool
    where
        T: Eq + Hash,
    {
        let Some(next) = self.allocation_items.checked_add(additional) else {
            self.resource_limited = true;
            return false;
        };
        if next > self.max_allocation_items || values.try_reserve(additional).is_err() {
            self.resource_limited = true;
            return false;
        }
        self.allocation_items = next;
        true
    }

    fn push<T>(&mut self, values: &mut Vec<T>, value: T) -> bool {
        if !self.reserve_vec(values, 1) {
            return false;
        }
        values.push(value);
        true
    }

    fn absorb_usage(
        &mut self,
        work: u64,
        allocation_items: usize,
        resource_limited: bool,
        context_assertions: bool,
    ) -> bool {
        let Some(work) = self.work.checked_add(work) else {
            self.resource_limited = true;
            return false;
        };
        let Some(allocation_items) = self.allocation_items.checked_add(allocation_items) else {
            self.resource_limited = true;
            return false;
        };
        if work > self.max_work || allocation_items > self.max_allocation_items {
            self.resource_limited = true;
            return false;
        }
        self.work = work;
        self.allocation_items = allocation_items;
        self.resource_limited |= resource_limited;
        self.context_assertions |= context_assertions;
        true
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct LiteralPath {
    state: u32,
    bytes: [u8; MAX_REQUIRED_LITERAL_DEPTH],
    len: u8,
}

impl LiteralPath {
    const fn initial(state: u32) -> Self {
        Self {
            state,
            bytes: [0; MAX_REQUIRED_LITERAL_DEPTH],
            len: 0,
        }
    }

    fn append(self, state: u32, byte: u8, max_depth: usize) -> Option<Self> {
        let len = usize::from(self.len);
        if len >= max_depth || len >= MAX_REQUIRED_LITERAL_DEPTH {
            return None;
        }
        let mut next = self;
        next.state = state;
        next.bytes[len] = byte;
        next.len = u8::try_from(len.checked_add(1)?).ok()?;
        Some(next)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Direction {
    Prefix,
    Suffix,
}

#[derive(Debug)]
struct Layer {
    boundary: bool,
    next: Vec<LiteralPath>,
}

#[derive(Clone, Copy, Debug)]
struct IncomingEdge {
    source: u32,
    edge: u32,
}

#[derive(Debug)]
struct Incoming {
    by_target: Vec<Vec<IncomingEdge>>,
}

/// Derive both directions under one explicit total resource envelope.
pub(crate) fn derive(raw: &RawPlan) -> RequiredLiterals {
    derive_with_limits(raw, RequiredLiteralLimits::default())
}

fn derive_with_limits(raw: &RawPlan, limits: RequiredLiteralLimits) -> RequiredLiterals {
    let limits = RequiredLiteralLimits {
        max_depth: limits.max_depth.min(MAX_REQUIRED_LITERAL_DEPTH),
        ..limits
    };
    let prefix = derive_prefix(raw, limits);
    let suffix_limits = RequiredLiteralLimits {
        max_total_bytes: limits
            .max_total_bytes
            .saturating_sub(prefix.literal_bytes()),
        max_work: limits.max_work.saturating_sub(prefix.derivation_work()),
        max_allocation_items: limits
            .max_allocation_items
            .saturating_sub(prefix.allocation_items()),
        ..limits
    };
    let suffix = derive_suffix(raw, suffix_limits);
    let interior_limits = RequiredLiteralLimits {
        max_total_bytes: suffix_limits
            .max_total_bytes
            .saturating_sub(suffix.literal_bytes()),
        max_work: suffix_limits
            .max_work
            .saturating_sub(suffix.derivation_work()),
        max_allocation_items: suffix_limits
            .max_allocation_items
            .saturating_sub(suffix.allocation_items()),
        ..limits
    };
    let interior = derive_interior(raw, interior_limits);
    RequiredLiterals {
        prefix,
        suffix,
        interior,
    }
}

fn derive_prefix(raw: &RawPlan, limits: RequiredLiteralLimits) -> RequiredLiteralSet {
    let mut budget = Budget::new(limits.max_work, limits.max_allocation_items);
    if !validate_shape(raw, &mut budget) || limits.max_depth == 0 {
        return RequiredLiteralSet::unavailable(&budget, false);
    }
    let mut frontier = Vec::new();
    if !budget.push(&mut frontier, LiteralPath::initial(raw.start)) {
        return RequiredLiteralSet::unavailable(&budget, true);
    }
    derive_layers(raw, None, None, Direction::Prefix, frontier, limits, budget)
}

fn derive_suffix(raw: &RawPlan, limits: RequiredLiteralLimits) -> RequiredLiteralSet {
    let mut budget = Budget::new(limits.max_work, limits.max_allocation_items);
    if !validate_shape(raw, &mut budget) || limits.max_depth == 0 {
        return RequiredLiteralSet::unavailable(&budget, false);
    }
    let Some(incoming) = Incoming::build(raw, &mut budget) else {
        return RequiredLiteralSet::unavailable(&budget, true);
    };
    let mut frontier = Vec::new();
    for (state, role) in raw.roles.iter().copied().enumerate() {
        if !budget.charge(1) {
            return RequiredLiteralSet::unavailable(&budget, true);
        }
        if role == StateRole::Accept {
            let Some(state) = u32::try_from(state).ok() else {
                return RequiredLiteralSet::unavailable(&budget, true);
            };
            if !budget.push(&mut frontier, LiteralPath::initial(state)) {
                return RequiredLiteralSet::unavailable(&budget, true);
            }
        }
    }
    if frontier.is_empty() {
        return RequiredLiteralSet::unavailable(&budget, false);
    }
    derive_layers(
        raw,
        Some(&incoming),
        None,
        Direction::Suffix,
        frontier,
        limits,
        budget,
    )
}

#[derive(Debug)]
struct ProductiveGraph {
    incoming: Incoming,
    productive: Vec<bool>,
    accepts: Vec<usize>,
    reverse_postorder: Vec<usize>,
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
    max_after: Vec<u32>,
    unbounded_after: Vec<bool>,
}

impl DistanceFacts {
    fn before(&self, state: usize) -> Option<MaximumConsumedDistance> {
        let component = usize::try_from(*self.component.get(state)?).ok()?;
        if *self.unbounded_before.get(component)? {
            Some(MaximumConsumedDistance::Unbounded)
        } else {
            Some(MaximumConsumedDistance::Finite(
                *self.max_before.get(component)?,
            ))
        }
    }

    fn after(&self, state: usize) -> Option<MaximumConsumedDistance> {
        let component = usize::try_from(*self.component.get(state)?).ok()?;
        if *self.unbounded_after.get(component)? {
            Some(MaximumConsumedDistance::Unbounded)
        } else {
            Some(MaximumConsumedDistance::Finite(
                *self.max_after.get(component)?,
            ))
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InteriorSeed {
    root: u32,
    first_byte_cardinality: u16,
}

#[allow(
    clippy::too_many_lines,
    reason = "transactional interior derivation keeps one visible resource envelope"
)]
fn derive_interior(raw: &RawPlan, limits: RequiredLiteralLimits) -> RequiredInteriorLiterals {
    let line_cuts = derive_line_cuts_independent(raw, limits);
    let mut interior = derive_interior_literals(raw, limits);
    interior.line_cuts = line_cuts;
    interior
}

fn derive_interior_literals(
    raw: &RawPlan,
    limits: RequiredLiteralLimits,
) -> RequiredInteriorLiterals {
    let mut budget = Budget::new(limits.max_work, limits.max_allocation_items);
    if limits.max_depth == 0 || limits.max_interior_candidates == 0 {
        return RequiredInteriorLiterals::unavailable(&budget);
    }
    let Some(graph) = ProductiveGraph::build(raw, &mut budget) else {
        return RequiredInteriorLiterals::unavailable(&budget);
    };
    if graph.accepts.is_empty() {
        return RequiredInteriorLiterals::unavailable(&budget);
    }
    let Some(roots) = mandatory_consume_roots(raw, &graph, &mut budget) else {
        return RequiredInteriorLiterals::unavailable(&budget);
    };
    let Some(distances) = DistanceFacts::build(raw, &graph, &mut budget) else {
        return RequiredInteriorLiterals::unavailable(&budget);
    };

    let mut seeds = Vec::new();
    for root in roots {
        let Some(first_byte_cardinality) = first_byte_cardinality(
            raw,
            &graph.productive,
            usize::try_from(root).ok(),
            &mut budget,
        ) else {
            return RequiredInteriorLiterals::unavailable(&budget);
        };
        if !budget.push(
            &mut seeds,
            InteriorSeed {
                root,
                first_byte_cardinality,
            },
        ) {
            return RequiredInteriorLiterals::unavailable(&budget);
        }
    }
    seeds.sort_unstable_by_key(|seed| (seed.first_byte_cardinality, seed.root));
    if seeds.len() > limits.max_interior_seeds {
        seeds.truncate(limits.max_interior_seeds);
        budget.resource_limited = true;
    }

    let mut candidates = Vec::new();
    for seed in seeds {
        let remaining_work = budget.max_work.saturating_sub(budget.work);
        let remaining_allocation = budget
            .max_allocation_items
            .saturating_sub(budget.allocation_items);
        let local_limits = RequiredLiteralLimits {
            max_work: remaining_work.min(limits.max_candidate_work),
            max_allocation_items: remaining_allocation.min(limits.max_candidate_allocation_items),
            ..limits
        };
        if local_limits.max_work == 0 || local_limits.max_allocation_items == 0 {
            budget.resource_limited = true;
            break;
        }
        let literal_set = derive_prefix_from_root(raw, seed.root, &graph.productive, local_limits);
        let usage = (
            literal_set.derivation_work(),
            literal_set.allocation_items(),
            literal_set.resource_limited(),
            literal_set.context_assertions(),
        );
        if !budget.absorb_usage(usage.0, usage.1, usage.2, usage.3) {
            break;
        }
        if literal_set.literals().is_empty() || !is_selective(&literal_set) {
            continue;
        }
        let root = usize::try_from(seed.root).ok();
        let (Some(max_before_root), Some(max_through_accept)) = (
            root.and_then(|root| distances.before(root)),
            root.and_then(|root| distances.after(root)),
        ) else {
            budget.resource_limited = true;
            break;
        };
        let candidate = RequiredInteriorCandidate {
            root_state: seed.root,
            literals: literal_set,
            max_before_root,
            max_through_accept,
        };
        if !budget.push(&mut candidates, candidate) {
            break;
        }
        candidates.sort_unstable_by(compare_candidates);
        while candidates.len() > limits.max_interior_candidates
            || interior_candidate_bytes(&candidates) > limits.max_total_bytes
        {
            candidates.pop();
            budget.resource_limited = true;
        }
    }
    finish_interior(candidates, &budget)
}

fn finish_interior(
    candidates: Vec<RequiredInteriorCandidate>,
    budget: &Budget,
) -> RequiredInteriorLiterals {
    RequiredInteriorLiterals {
        candidates: candidates.into_boxed_slice(),
        line_cuts: Box::new([]),
        derivation_work: budget.work,
        allocation_items: budget.allocation_items,
        resource_limited: budget.resource_limited,
        context_assertions: budget.context_assertions,
    }
}

/// Run the optional line proof under a fully independent envelope. In
/// particular, graphs too expensive for retained literal derivation may still
/// yield a useful line cut, while line-proof failure cannot alter established
/// literal candidates, counters, or resource flags.
fn derive_line_cuts_independent(
    raw: &RawPlan,
    limits: RequiredLiteralLimits,
) -> Box<[RequiredLineCut]> {
    let mut budget = Budget::new(
        limits.max_line_cut_work,
        limits.max_line_cut_allocation_items,
    );
    let Some(graph) = ProductiveGraph::build(raw, &mut budget) else {
        return Box::new([]);
    };
    if graph.accepts.is_empty() {
        return Box::new([]);
    }
    let Some(distances) = DistanceFacts::build(raw, &graph, &mut budget) else {
        return Box::new([]);
    };
    derive_line_cuts(raw, &graph, &distances, &mut budget)
        .unwrap_or_default()
        .into_boxed_slice()
}

/// Proves that every productive start-to-accept path crosses one exact line
/// assertion kind. Reachability is recomputed with that kind removed, so this
/// remains valid across duplicated assertion states, alternations, and graph
/// rewrites. The distance is deliberately taken from the full graph: paths
/// that crossed an earlier assertion may only enlarge it, which is safe for
/// subsequent start-window narrowing.
fn derive_line_cuts(
    raw: &RawPlan,
    graph: &ProductiveGraph,
    distances: &DistanceFacts,
    budget: &mut Budget,
) -> Option<Vec<RequiredLineCut>> {
    let states = raw.roles.len();
    let start = usize::try_from(raw.start).ok()?;
    let mut reachable = bounded_vec(states, false, budget)?;
    let mut stack = Vec::new();
    if !budget.reserve_vec(&mut stack, states) {
        return None;
    }
    let mut cuts = Vec::new();
    if !budget.reserve_vec(&mut cuts, RequiredLineCutKind::ALL.len()) {
        return None;
    }

    for kind in RequiredLineCutKind::ALL {
        budget.charge(u64::try_from(states).ok()?).then_some(())?;
        reachable.fill(false);
        stack.clear();
        reachable[start] = true;
        stack.push(start);

        let mut bypasses_cut = false;
        while let Some(state) = stack.pop() {
            if !budget.charge(1) {
                return None;
            }
            if raw.roles.get(state) == Some(&StateRole::Accept) {
                bypasses_cut = true;
                break;
            }
            for edge in state_edges(raw, state)? {
                if !budget.charge(1) {
                    return None;
                }
                if raw.edge_kinds.get(edge) == Some(&kind.edge()) {
                    continue;
                }
                let target = usize::try_from(*raw.edge_targets.get(edge)?).ok()?;
                if graph.productive.get(target) == Some(&true) && !reachable[target] {
                    reachable[target] = true;
                    stack.push(target);
                }
            }
        }
        if bypasses_cut {
            continue;
        }

        let mut maximum_before = MaximumConsumedDistance::Finite(0);
        let mut crossed = false;
        for (source, &source_reachable) in reachable.iter().enumerate() {
            if !source_reachable || graph.productive.get(source) != Some(&true) {
                continue;
            }
            if !budget.charge(1) {
                return None;
            }
            for edge in state_edges(raw, source)? {
                if !budget.charge(1) {
                    return None;
                }
                if raw.edge_kinds.get(edge) != Some(&kind.edge()) {
                    continue;
                }
                let target = usize::try_from(*raw.edge_targets.get(edge)?).ok()?;
                if graph.productive.get(target) != Some(&true) {
                    continue;
                }
                crossed = true;
                maximum_before = maximum_distance(
                    maximum_before,
                    distances.before(source)?,
                );
            }
        }
        if !crossed {
            // Productive start-to-accept paths exist, and none bypassed this
            // cut. Failing to find a first cut therefore means the bounded
            // proof did not complete consistently; decline conservatively.
            budget.resource_limited = true;
            return None;
        }

        cuts.push(RequiredLineCut {
            kind,
            maximum_before,
        });
    }
    Some(cuts)
}

fn maximum_distance(
    left: MaximumConsumedDistance,
    right: MaximumConsumedDistance,
) -> MaximumConsumedDistance {
    match (left, right) {
        (MaximumConsumedDistance::Unbounded, _)
        | (_, MaximumConsumedDistance::Unbounded) => MaximumConsumedDistance::Unbounded,
        (MaximumConsumedDistance::Finite(left), MaximumConsumedDistance::Finite(right)) => {
            MaximumConsumedDistance::Finite(left.max(right))
        }
    }
}

fn derive_prefix_from_root(
    raw: &RawPlan,
    root: u32,
    productive: &[bool],
    limits: RequiredLiteralLimits,
) -> RequiredLiteralSet {
    let mut budget = Budget::new(limits.max_work, limits.max_allocation_items);
    let mut frontier = Vec::new();
    if !budget.push(&mut frontier, LiteralPath::initial(root)) {
        return RequiredLiteralSet::unavailable(&budget, true);
    }
    derive_layers(
        raw,
        None,
        Some(productive),
        Direction::Prefix,
        frontier,
        limits,
        budget,
    )
}

fn first_byte_cardinality(
    raw: &RawPlan,
    productive: &[bool],
    root: Option<usize>,
    budget: &mut Budget,
) -> Option<u16> {
    let root = root?;
    if raw.roles.get(root) != Some(&StateRole::Consume) {
        return None;
    }
    let mut bytes = [false; 256];
    for edge in state_edges(raw, root)? {
        if !budget.charge(1) || raw.edge_kinds.get(edge) != Some(&EdgeKind::ByteRange) {
            return None;
        }
        let target = usize::try_from(*raw.edge_targets.get(edge)?).ok()?;
        if productive.get(target) != Some(&true) {
            continue;
        }
        let (&start, &end) = (raw.byte_starts.get(edge)?, raw.byte_ends.get(edge)?);
        if start > end {
            return None;
        }
        for byte in start..=end {
            if !budget.charge(1) {
                return None;
            }
            bytes[usize::from(byte)] = true;
        }
    }
    u16::try_from(bytes.iter().filter(|&&present| present).count()).ok()
}

fn is_selective(set: &RequiredLiteralSet) -> bool {
    let depth = set.depth();
    if depth == 0 {
        return false;
    }
    let domain = 1_u128 << depth.saturating_mul(8);
    u128::try_from(set.literals().len()).is_ok_and(|count| count < domain)
}

fn candidate_selectivity_score(candidate: &RequiredInteriorCandidate) -> u128 {
    let shift = MAX_REQUIRED_LITERAL_DEPTH
        .saturating_sub(candidate.depth())
        .saturating_mul(8);
    u128::try_from(candidate.literals().len())
        .unwrap_or(u128::MAX)
        .checked_shl(u32::try_from(shift).unwrap_or(u32::MAX))
        .unwrap_or(u128::MAX)
}

fn distance_rank(distance: MaximumConsumedDistance) -> (bool, u32) {
    match distance {
        MaximumConsumedDistance::Finite(maximum) => (false, maximum),
        MaximumConsumedDistance::Unbounded => (true, u32::MAX),
    }
}

fn compare_candidates(
    left: &RequiredInteriorCandidate,
    right: &RequiredInteriorCandidate,
) -> core::cmp::Ordering {
    candidate_selectivity_score(left)
        .cmp(&candidate_selectivity_score(right))
        .then_with(|| right.depth().cmp(&left.depth()))
        .then_with(|| left.literals().len().cmp(&right.literals().len()))
        .then_with(|| {
            distance_rank(left.max_before_root()).cmp(&distance_rank(right.max_before_root()))
        })
        .then_with(|| {
            distance_rank(left.max_through_accept()).cmp(&distance_rank(right.max_through_accept()))
        })
        .then_with(|| left.root_state.cmp(&right.root_state))
        .then_with(|| left.literals().cmp(right.literals()))
}

fn interior_candidate_bytes(candidates: &[RequiredInteriorCandidate]) -> usize {
    candidates.iter().fold(0usize, |total, candidate| {
        total.saturating_add(candidate.literal_bytes())
    })
}

fn bounded_vec<T: Clone>(length: usize, value: T, budget: &mut Budget) -> Option<Vec<T>> {
    let mut values = Vec::new();
    if !budget.reserve_vec(&mut values, length) {
        return None;
    }
    values.resize(length, value);
    Some(values)
}

impl ProductiveGraph {
    #[allow(
        clippy::too_many_lines,
        reason = "one bounded traversal jointly validates reachability and productivity"
    )]
    fn build(raw: &RawPlan, budget: &mut Budget) -> Option<Self> {
        if !validate_shape(raw, budget) {
            return None;
        }
        let incoming = Incoming::build(raw, budget)?;
        let states = raw.roles.len();
        let start = usize::try_from(raw.start).ok()?;
        let mut reachable = bounded_vec(states, false, budget)?;
        let mut stack = Vec::new();
        reachable[start] = true;
        if !budget.push(&mut stack, start) {
            return None;
        }
        let mut accepts = Vec::new();
        while let Some(state) = stack.pop() {
            if !budget.charge(1) {
                return None;
            }
            let edges = state_edges(raw, state)?;
            match raw.roles.get(state).copied()? {
                StateRole::Accept => {
                    if !edges.is_empty() || !budget.push(&mut accepts, state) {
                        return None;
                    }
                }
                StateRole::Split => {
                    for edge in edges {
                        if !budget.charge(1) {
                            return None;
                        }
                        let kind = *raw.edge_kinds.get(edge)?;
                        if !zero_width(kind, budget)
                            || raw.byte_starts.get(edge) != Some(&0)
                            || raw.byte_ends.get(edge) != Some(&0)
                        {
                            return None;
                        }
                        let target = usize::try_from(*raw.edge_targets.get(edge)?).ok()?;
                        if !reachable[target] {
                            reachable[target] = true;
                            if !budget.push(&mut stack, target) {
                                return None;
                            }
                        }
                    }
                }
                StateRole::Consume => {
                    for edge in edges {
                        if !budget.charge(1)
                            || raw.edge_kinds.get(edge) != Some(&EdgeKind::ByteRange)
                        {
                            return None;
                        }
                        let (&start_byte, &end_byte) =
                            (raw.byte_starts.get(edge)?, raw.byte_ends.get(edge)?);
                        if start_byte > end_byte {
                            return None;
                        }
                        let target = usize::try_from(*raw.edge_targets.get(edge)?).ok()?;
                        if !reachable[target] {
                            reachable[target] = true;
                            if !budget.push(&mut stack, target) {
                                return None;
                            }
                        }
                    }
                }
                _ => return None,
            }
        }

        if accepts.is_empty() {
            return Some(Self {
                incoming,
                productive: bounded_vec(states, false, budget)?,
                accepts,
                reverse_postorder: Vec::new(),
            });
        }

        let mut coreachable = bounded_vec(states, false, budget)?;
        stack.clear();
        for &accept in &accepts {
            coreachable[accept] = true;
            if !budget.push(&mut stack, accept) {
                return None;
            }
        }
        while let Some(state) = stack.pop() {
            if !budget.charge(1) {
                return None;
            }
            for &edge in incoming.by_target.get(state)? {
                if !budget.charge(1) {
                    return None;
                }
                let source = usize::try_from(edge.source).ok()?;
                if !coreachable[source] {
                    coreachable[source] = true;
                    if !budget.push(&mut stack, source) {
                        return None;
                    }
                }
            }
        }

        let mut productive = bounded_vec(states, false, budget)?;
        for state in 0..states {
            if !budget.charge(1) {
                return None;
            }
            productive[state] = reachable[state] && coreachable[state];
        }
        accepts.retain(|&state| productive[state]);
        let reverse_postorder = productive_reverse_postorder(raw, &productive, start, budget)?;
        Some(Self {
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
) -> Option<Vec<usize>> {
    let exit = raw.roles.len();
    let node_count = exit.checked_add(1)?;
    let mut visited = bounded_vec(node_count, false, budget)?;
    let mut stack = Vec::new();
    let mut postorder = Vec::new();
    visited[start] = true;
    if !budget.push(&mut stack, (start, false)) {
        return None;
    }
    while let Some((node, expanded)) = stack.pop() {
        if !budget.charge(1) {
            return None;
        }
        if expanded {
            if !budget.push(&mut postorder, node) {
                return None;
            }
            continue;
        }
        if !budget.push(&mut stack, (node, true)) {
            return None;
        }
        if node == exit {
            continue;
        }
        match raw.roles.get(node).copied()? {
            StateRole::Accept => {
                if !visited[exit] {
                    visited[exit] = true;
                    if !budget.push(&mut stack, (exit, false)) {
                        return None;
                    }
                }
            }
            StateRole::Split | StateRole::Consume => {
                for edge in state_edges(raw, node)?.rev() {
                    if !budget.charge(1) {
                        return None;
                    }
                    let target = usize::try_from(*raw.edge_targets.get(edge)?).ok()?;
                    if productive.get(target) == Some(&true) && !visited[target] {
                        visited[target] = true;
                        if !budget.push(&mut stack, (target, false)) {
                            return None;
                        }
                    }
                }
            }
            _ => return None,
        }
    }
    if !visited.get(exit).copied().unwrap_or(false) {
        return None;
    }
    postorder.reverse();
    Some(postorder)
}

fn mandatory_consume_roots(
    raw: &RawPlan,
    graph: &ProductiveGraph,
    budget: &mut Budget,
) -> Option<Vec<u32>> {
    let exit = raw.roles.len();
    let node_count = exit.checked_add(1)?;
    let start = usize::try_from(raw.start).ok()?;
    let mut position = bounded_vec(node_count, usize::MAX, budget)?;
    for (index, &node) in graph.reverse_postorder.iter().enumerate() {
        if !budget.charge(1) {
            return None;
        }
        *position.get_mut(node)? = index;
    }
    let mut immediate = bounded_vec(node_count, usize::MAX, budget)?;
    immediate[start] = start;
    loop {
        if !budget.charge(1) {
            return None;
        }
        let mut changed = false;
        for &node in graph.reverse_postorder.iter().skip(1) {
            if !budget.charge(1) {
                return None;
            }
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
                for &edge in graph.incoming.by_target.get(node)? {
                    if !budget.charge(1) {
                        return None;
                    }
                    let predecessor = usize::try_from(edge.source).ok()?;
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
            let next = next?;
            if immediate[node] != next {
                immediate[node] = next;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    let mut roots = Vec::new();
    let mut node = exit;
    for _ in 0..node_count {
        if !budget.charge(1) {
            return None;
        }
        node = *immediate.get(node)?;
        if node == usize::MAX {
            return None;
        }
        if node < raw.roles.len()
            && raw.roles.get(node) == Some(&StateRole::Consume)
            && !budget.push(&mut roots, u32::try_from(node).ok()?)
        {
            return None;
        }
        if node == start {
            return Some(roots);
        }
    }
    None
}

fn consider_dominator_predecessor(
    predecessor: usize,
    next: &mut Option<usize>,
    immediate: &[usize],
    position: &[usize],
    budget: &mut Budget,
) -> Option<()> {
    if !budget.charge(1) {
        return None;
    }
    if immediate.get(predecessor).copied()? == usize::MAX {
        return Some(());
    }
    *next = Some(match *next {
        None => predecessor,
        Some(current) => intersect_dominators(current, predecessor, immediate, position, budget)?,
    });
    Some(())
}

fn intersect_dominators(
    mut left: usize,
    mut right: usize,
    immediate: &[usize],
    position: &[usize],
    budget: &mut Budget,
) -> Option<usize> {
    while left != right {
        while position.get(left)? > position.get(right)? {
            if !budget.charge(1) {
                return None;
            }
            left = *immediate.get(left)?;
        }
        while position.get(right)? > position.get(left)? {
            if !budget.charge(1) {
                return None;
            }
            right = *immediate.get(right)?;
        }
    }
    Some(left)
}

impl DistanceFacts {
    #[allow(
        clippy::too_many_lines,
        reason = "SCC construction and paired distance proofs share one bounded condensation"
    )]
    fn build(raw: &RawPlan, graph: &ProductiveGraph, budget: &mut Budget) -> Option<Self> {
        let exit = raw.roles.len();
        let node_count = exit.checked_add(1)?;
        let mut component = bounded_vec(node_count, u32::MAX, budget)?;
        let mut component_count = 0usize;
        let mut stack = Vec::new();
        for &root in &graph.reverse_postorder {
            if !budget.charge(1) {
                return None;
            }
            if component[root] != u32::MAX {
                continue;
            }
            let component_id = u32::try_from(component_count).ok()?;
            component_count = component_count.checked_add(1)?;
            component[root] = component_id;
            if !budget.push(&mut stack, root) {
                return None;
            }
            while let Some(node) = stack.pop() {
                if !budget.charge(1) {
                    return None;
                }
                if node == exit {
                    for &predecessor in &graph.accepts {
                        if !budget.charge(1) {
                            return None;
                        }
                        if component[predecessor] == u32::MAX {
                            component[predecessor] = component_id;
                            if !budget.push(&mut stack, predecessor) {
                                return None;
                            }
                        }
                    }
                } else {
                    for &edge in graph.incoming.by_target.get(node)? {
                        if !budget.charge(1) {
                            return None;
                        }
                        let predecessor = usize::try_from(edge.source).ok()?;
                        if graph.productive.get(predecessor) == Some(&true)
                            && component[predecessor] == u32::MAX
                        {
                            component[predecessor] = component_id;
                            if !budget.push(&mut stack, predecessor) {
                                return None;
                            }
                        }
                    }
                }
            }
        }

        let mut outgoing = bounded_vec(component_count, Vec::new(), budget)?;
        let mut positive_cycle = bounded_vec(component_count, false, budget)?;
        for state in 0..raw.roles.len() {
            if graph.productive.get(state) != Some(&true) {
                continue;
            }
            if !budget.charge(1) {
                return None;
            }
            let role = *raw.roles.get(state)?;
            let source_component = usize::try_from(*component.get(state)?).ok()?;
            for edge in state_edges(raw, state)? {
                if !budget.charge(1) {
                    return None;
                }
                let target = usize::try_from(*raw.edge_targets.get(edge)?).ok()?;
                if graph.productive.get(target) != Some(&true) {
                    continue;
                }
                let target_component = usize::try_from(*component.get(target)?).ok()?;
                let consumed = match role {
                    StateRole::Consume => 1,
                    StateRole::Split => 0,
                    _ => return None,
                };
                if source_component == target_component {
                    if consumed == 1 {
                        positive_cycle[source_component] = true;
                    }
                    continue;
                }
                // Kosaraju component discovery follows condensation order.
                if source_component >= target_component {
                    return None;
                }
                let row = outgoing.get_mut(source_component)?;
                if !budget.push(
                    row,
                    ComponentEdge {
                        target: u32::try_from(target_component).ok()?,
                        consumed,
                    },
                ) {
                    return None;
                }
            }
            if role == StateRole::Accept {
                let target_component = usize::try_from(*component.get(exit)?).ok()?;
                if source_component >= target_component {
                    return None;
                }
                let row = outgoing.get_mut(source_component)?;
                if !budget.push(
                    row,
                    ComponentEdge {
                        target: u32::try_from(target_component).ok()?,
                        consumed: 0,
                    },
                ) {
                    return None;
                }
            }
        }

        let mut max_before = bounded_vec(component_count, 0_u32, budget)?;
        let mut has_before = bounded_vec(component_count, false, budget)?;
        let mut unbounded_before = bounded_vec(component_count, false, budget)?;
        let start_component =
            usize::try_from(*component.get(usize::try_from(raw.start).ok()?)?).ok()?;
        has_before[start_component] = true;
        for source in 0..component_count {
            if !budget.charge(1) {
                return None;
            }
            if !has_before[source] {
                continue;
            }
            unbounded_before[source] |= positive_cycle[source];
            for &edge in outgoing.get(source)? {
                if !budget.charge(1) {
                    return None;
                }
                let target = usize::try_from(edge.target).ok()?;
                has_before[target] = true;
                unbounded_before[target] |= unbounded_before[source];
                let distance = max_before[source].checked_add(u32::from(edge.consumed))?;
                max_before[target] = max_before[target].max(distance);
            }
        }

        let mut max_after = bounded_vec(component_count, 0_u32, budget)?;
        let mut has_after = bounded_vec(component_count, false, budget)?;
        let mut unbounded_after = bounded_vec(component_count, false, budget)?;
        let exit_component = usize::try_from(*component.get(exit)?).ok()?;
        has_after[exit_component] = true;
        for source in (0..component_count).rev() {
            if !budget.charge(1) {
                return None;
            }
            for &edge in outgoing.get(source)? {
                if !budget.charge(1) {
                    return None;
                }
                let target = usize::try_from(edge.target).ok()?;
                if !has_after[target] {
                    continue;
                }
                has_after[source] = true;
                unbounded_after[source] |= unbounded_after[target];
                let distance = max_after[target].checked_add(u32::from(edge.consumed))?;
                max_after[source] = max_after[source].max(distance);
            }
            if has_after[source] {
                unbounded_after[source] |= positive_cycle[source];
            }
        }

        Some(Self {
            component,
            max_before,
            unbounded_before,
            max_after,
            unbounded_after,
        })
    }
}

fn derive_layers(
    raw: &RawPlan,
    incoming: Option<&Incoming>,
    productive: Option<&[bool]>,
    direction: Direction,
    mut frontier: Vec<LiteralPath>,
    limits: RequiredLiteralLimits,
    mut budget: Budget,
) -> RequiredLiteralSet {
    let mut published: Option<(u8, Box<[RequiredLiteral]>)> = None;
    for depth in 0..limits.max_depth {
        let layer = match direction {
            Direction::Prefix => prefix_layer(raw, productive, &frontier, limits, &mut budget),
            Direction::Suffix => suffix_layer(
                raw,
                incoming.expect("suffix analysis has incoming edges"),
                &frontier,
                limits,
                &mut budget,
            ),
        };
        let Some(layer) = layer else {
            return finish_set(published, &budget, true);
        };
        if layer.boundary || layer.next.is_empty() {
            return finish_set(published, &budget, depth < limits.max_depth);
        }
        let Some(literals) = publish_literals(&layer.next, direction, limits, &mut budget) else {
            return finish_set(published, &budget, true);
        };
        let next_depth = u8::try_from(depth.saturating_add(1)).unwrap_or(u8::MAX);
        published = Some((next_depth, literals));
        frontier = layer.next;
    }
    finish_set(published, &budget, false)
}

fn finish_set(
    published: Option<(u8, Box<[RequiredLiteral]>)>,
    budget: &Budget,
    shortened: bool,
) -> RequiredLiteralSet {
    let Some((depth, literals)) = published else {
        return RequiredLiteralSet::unavailable(budget, shortened);
    };
    RequiredLiteralSet {
        literals,
        depth,
        derivation_work: budget.work,
        allocation_items: budget.allocation_items,
        resource_limited: budget.resource_limited,
        shortened,
        context_assertions: budget.context_assertions,
    }
}

fn prefix_layer(
    raw: &RawPlan,
    productive: Option<&[bool]>,
    frontier: &[LiteralPath],
    limits: RequiredLiteralLimits,
    budget: &mut Budget,
) -> Option<Layer> {
    let mut stack = Vec::new();
    for &path in frontier {
        if !budget.push(&mut stack, path) {
            return None;
        }
    }
    let mut seen = HashSet::new();
    let mut consuming = Vec::new();
    while let Some(path) = stack.pop() {
        if !budget.charge(1) {
            return None;
        }
        if !insert_unique(&mut seen, path, limits, budget)? {
            continue;
        }
        let state = usize::try_from(path.state).ok()?;
        if productive.is_some_and(|states| states.get(state) != Some(&true)) {
            continue;
        }
        match raw.roles.get(state).copied()? {
            StateRole::Accept => {
                return Some(Layer {
                    boundary: true,
                    next: Vec::new(),
                });
            }
            StateRole::Consume => {
                if !budget.push(&mut consuming, path) {
                    return None;
                }
            }
            StateRole::Split => {
                for edge in state_edges(raw, state)? {
                    if !budget.charge(1) {
                        return None;
                    }
                    let kind = *raw.edge_kinds.get(edge)?;
                    if !zero_width(kind, budget) {
                        return None;
                    }
                    let target = *raw.edge_targets.get(edge)?;
                    if productive.is_some_and(|states| {
                        usize::try_from(target)
                            .ok()
                            .and_then(|target| states.get(target))
                            != Some(&true)
                    }) {
                        continue;
                    }
                    let next = LiteralPath {
                        state: target,
                        ..path
                    };
                    if !budget.push(&mut stack, next) {
                        return None;
                    }
                }
            }
            _ => return None,
        }
    }

    let mut next = Vec::new();
    let mut next_seen = HashSet::new();
    for path in consuming {
        let state = usize::try_from(path.state).ok()?;
        for edge in state_edges(raw, state)? {
            if !budget.charge(1) || raw.edge_kinds.get(edge) != Some(&EdgeKind::ByteRange) {
                return None;
            }
            let (&start, &end, &target) = (
                raw.byte_starts.get(edge)?,
                raw.byte_ends.get(edge)?,
                raw.edge_targets.get(edge)?,
            );
            if start > end {
                return None;
            }
            if productive.is_some_and(|states| {
                usize::try_from(target)
                    .ok()
                    .and_then(|target| states.get(target))
                    != Some(&true)
            }) {
                continue;
            }
            for byte in start..=end {
                if !budget.charge(1) {
                    return None;
                }
                let appended = path.append(target, byte, limits.max_depth)?;
                push_unique(&mut next, &mut next_seen, appended, limits, budget)?;
            }
        }
    }
    Some(Layer {
        boundary: false,
        next,
    })
}

fn suffix_layer(
    raw: &RawPlan,
    incoming: &Incoming,
    frontier: &[LiteralPath],
    limits: RequiredLiteralLimits,
    budget: &mut Budget,
) -> Option<Layer> {
    let mut stack = Vec::new();
    for &path in frontier {
        if !budget.push(&mut stack, path) {
            return None;
        }
    }
    let mut seen = HashSet::new();
    let mut consuming = Vec::new();
    while let Some(path) = stack.pop() {
        if !budget.charge(1) {
            return None;
        }
        if !insert_unique(&mut seen, path, limits, budget)? {
            continue;
        }
        if path.state == raw.start {
            return Some(Layer {
                boundary: true,
                next: Vec::new(),
            });
        }
        let state = usize::try_from(path.state).ok()?;
        for &edge in incoming.by_target.get(state)? {
            if !budget.charge(1) {
                return None;
            }
            let source = usize::try_from(edge.source).ok()?;
            let edge_index = usize::try_from(edge.edge).ok()?;
            let kind = *raw.edge_kinds.get(edge_index)?;
            match raw.roles.get(source).copied()? {
                StateRole::Split if zero_width(kind, budget) => {
                    let next = LiteralPath {
                        state: edge.source,
                        ..path
                    };
                    if !budget.push(&mut stack, next) {
                        return None;
                    }
                }
                StateRole::Consume if kind == EdgeKind::ByteRange => {
                    if !budget.push(&mut consuming, (path, edge)) {
                        return None;
                    }
                }
                _ => return None,
            }
        }
    }

    let mut next = Vec::new();
    let mut next_seen = HashSet::new();
    for (path, edge) in consuming {
        let edge_index = usize::try_from(edge.edge).ok()?;
        let (&start, &end) = (
            raw.byte_starts.get(edge_index)?,
            raw.byte_ends.get(edge_index)?,
        );
        if start > end {
            return None;
        }
        for byte in start..=end {
            if !budget.charge(1) {
                return None;
            }
            let appended = path.append(edge.source, byte, limits.max_depth)?;
            push_unique(&mut next, &mut next_seen, appended, limits, budget)?;
        }
    }
    Some(Layer {
        boundary: false,
        next,
    })
}

fn insert_unique(
    seen: &mut HashSet<LiteralPath>,
    path: LiteralPath,
    limits: RequiredLiteralLimits,
    budget: &mut Budget,
) -> Option<bool> {
    if !budget.charge(1) {
        return None;
    }
    if seen.contains(&path) {
        return Some(false);
    }
    if seen.len() >= limits.max_frontier_items || !budget.reserve_set(seen, 1) {
        budget.resource_limited = true;
        return None;
    }
    Some(seen.insert(path))
}

fn push_unique(
    paths: &mut Vec<LiteralPath>,
    seen: &mut HashSet<LiteralPath>,
    path: LiteralPath,
    limits: RequiredLiteralLimits,
    budget: &mut Budget,
) -> Option<()> {
    if !insert_unique(seen, path, limits, budget)? {
        return Some(());
    }
    if paths.len() >= limits.max_frontier_items || !budget.push(paths, path) {
        budget.resource_limited = true;
        return None;
    }
    Some(())
}

fn publish_literals(
    frontier: &[LiteralPath],
    direction: Direction,
    limits: RequiredLiteralLimits,
    budget: &mut Budget,
) -> Option<Box<[RequiredLiteral]>> {
    let mut literals = Vec::new();
    for &path in frontier {
        if !budget.charge(1) || !budget.reserve_vec(&mut literals, 1) {
            return None;
        }
        let mut bytes = path.bytes;
        if direction == Direction::Suffix {
            bytes[..usize::from(path.len)].reverse();
        }
        literals.push(RequiredLiteral {
            bytes,
            len: path.len,
        });
    }
    literals.sort_unstable();
    literals.dedup();
    let depth = literals
        .first()
        .map_or(0, |literal| usize::from(literal.len));
    let total_bytes = literals.len().checked_mul(depth)?;
    if literals.is_empty()
        || literals.len() > limits.max_sequences
        || total_bytes > limits.max_total_bytes
    {
        budget.resource_limited = true;
        return None;
    }
    Some(literals.into_boxed_slice())
}

impl Incoming {
    fn build(raw: &RawPlan, budget: &mut Budget) -> Option<Self> {
        let mut by_target = Vec::new();
        if !budget.reserve_vec(&mut by_target, raw.roles.len()) {
            return None;
        }
        by_target.resize_with(raw.roles.len(), Vec::new);
        for source in 0..raw.roles.len() {
            let source_u32 = u32::try_from(source).ok()?;
            for edge in state_edges(raw, source)? {
                if !budget.charge(1) {
                    return None;
                }
                let target = usize::try_from(*raw.edge_targets.get(edge)?).ok()?;
                let row = by_target.get_mut(target)?;
                if !budget.push(
                    row,
                    IncomingEdge {
                        source: source_u32,
                        edge: u32::try_from(edge).ok()?,
                    },
                ) {
                    return None;
                }
            }
        }
        Some(Self { by_target })
    }
}

fn validate_shape(raw: &RawPlan, budget: &mut Budget) -> bool {
    if !budget.charge(1) {
        return false;
    }
    let edges = raw.edge_targets.len();
    let start = usize::try_from(raw.start).ok();
    start.is_some_and(|start| start < raw.roles.len())
        && raw.edge_offsets.len() == raw.roles.len().saturating_add(1)
        && raw.edge_kinds.len() == edges
        && raw.byte_starts.len() == edges
        && raw.byte_ends.len() == edges
        && raw
            .edge_targets
            .iter()
            .all(|&target| usize::try_from(target).is_ok_and(|target| target < raw.roles.len()))
}

fn state_edges(raw: &RawPlan, state: usize) -> Option<core::ops::Range<usize>> {
    let begin = usize::try_from(*raw.edge_offsets.get(state)?).ok()?;
    let end = usize::try_from(*raw.edge_offsets.get(state.checked_add(1)?)?).ok()?;
    (begin <= end && end <= raw.edge_targets.len()).then_some(begin..end)
}

fn zero_width(kind: EdgeKind, budget: &mut Budget) -> bool {
    if kind == EdgeKind::Epsilon {
        return true;
    }
    let assertion = matches!(
        kind,
        EdgeKind::AssertHaystackStart
            | EdgeKind::AssertHaystackEnd
            | EdgeKind::AssertLineStartLf
            | EdgeKind::AssertLineEndLf
            | EdgeKind::AssertLineStartCrlf
            | EdgeKind::AssertLineEndCrlf
            | EdgeKind::AssertWordAscii
            | EdgeKind::AssertWordAsciiNegate
            | EdgeKind::AssertWordStartAscii
            | EdgeKind::AssertWordEndAscii
            | EdgeKind::AssertWordStartHalfAscii
            | EdgeKind::AssertWordEndHalfAscii
            | EdgeKind::AssertWordUnicode
            | EdgeKind::AssertWordUnicodeNegate
            | EdgeKind::AssertWordStartUnicode
            | EdgeKind::AssertWordEndUnicode
            | EdgeKind::AssertWordStartHalfUnicode
            | EdgeKind::AssertWordEndHalfUnicode
    );
    if assertion {
        budget.context_assertions = true;
    }
    assertion
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use fre_automata::{Automaton, CompileLimits as AutomatonLimits};
    use fre_lower::{LowerLimits, OperationSemantics};
    use fre_syntax::{CanonicalPattern, CompatibilityProfile, ParseRequest, RustProfile};

    use super::*;
    use crate::{
        CompileMode,
        dfa::DeterminizeLimits,
        program::{CompiledProgram, OutputContract},
    };

    fn lower(pattern: &str) -> RawPlan {
        let parsed = fre_syntax::parse(ParseRequest::rust(
            pattern.to_owned(),
            CompatibilityProfile::RustBytes(RustProfile::default()),
        ))
        .unwrap_or_else(|error| panic!("parse {pattern:?}: {error}"));
        let CanonicalPattern::Rust(parsed) = parsed.pattern else {
            panic!("Rust parse returned a non-Rust pattern");
        };
        let raw = fre_lower::lower_raw_general(
            &parsed,
            OperationSemantics::CaptureFree,
            LowerLimits::default(),
        )
        .unwrap_or_else(|error| panic!("lower {pattern:?}: {error}"))
        .into_plan();
        Automaton::from_raw(raw.clone(), AutomatonLimits::default())
            .unwrap_or_else(|error| panic!("validate {pattern:?}: {error}"));
        raw
    }

    fn compile(pattern: &str) -> CompiledProgram {
        let raw = lower(pattern);
        let automaton = Automaton::from_raw(raw.clone(), AutomatonLimits::default())
            .expect("validated test graph");
        CompiledProgram::build(
            raw,
            automaton,
            OutputContract::Span,
            CompileMode::Optimizing,
            DeterminizeLimits::default(),
            usize::MAX,
        )
        .expect("compile test graph")
    }

    fn literal_bytes(set: &RequiredLiteralSet) -> Vec<Vec<u8>> {
        set.literals()
            .iter()
            .map(|literal| literal.as_bytes().to_vec())
            .collect()
    }

    fn interior_literal_bytes(candidate: &RequiredInteriorCandidate) -> Vec<Vec<u8>> {
        candidate
            .literals()
            .iter()
            .map(|literal| literal.as_bytes().to_vec())
            .collect()
    }

    fn line_cut(
        interior: &RequiredInteriorLiterals,
        kind: RequiredLineCutKind,
    ) -> Option<RequiredLineCut> {
        interior
            .line_cuts()
            .iter()
            .copied()
            .find(|cut| cut.kind() == kind)
    }

    type TestEdge = (u32, EdgeKind, u8, u8);

    fn epsilon(target: u32) -> TestEdge {
        (target, EdgeKind::Epsilon, 0, 0)
    }

    fn assertion(target: u32) -> TestEdge {
        (target, EdgeKind::AssertWordAscii, 0, 0)
    }

    fn line_assertion(target: u32, kind: EdgeKind) -> TestEdge {
        assert!(matches!(
            kind,
            EdgeKind::AssertLineStartLf
                | EdgeKind::AssertLineEndLf
                | EdgeKind::AssertLineStartCrlf
                | EdgeKind::AssertLineEndCrlf
        ));
        (target, kind, 0, 0)
    }

    fn byte(target: u32, value: u8) -> TestEdge {
        (target, EdgeKind::ByteRange, value, value)
    }

    fn byte_range(target: u32, start: u8, end: u8) -> TestEdge {
        (target, EdgeKind::ByteRange, start, end)
    }

    fn hand_raw(start: u32, roles: Vec<StateRole>, rows: Vec<Vec<TestEdge>>) -> RawPlan {
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
        let raw = RawPlan {
            start,
            roles,
            edge_offsets,
            edge_targets,
            edge_kinds,
            byte_starts,
            byte_ends,
        };
        Automaton::from_raw(raw.clone(), AutomatonLimits::default())
            .expect("hand-built test graph validates");
        raw
    }

    fn brute_mandatory_consume_roots(raw: &RawPlan) -> Vec<u32> {
        let mut roots = raw
            .roles
            .iter()
            .enumerate()
            .filter(|(state, role)| {
                **role == StateRole::Consume
                    && !accept_reachable_avoiding(raw, u32::try_from(*state).ok())
            })
            .map(|(state, _)| u32::try_from(state).expect("test state"))
            .collect::<Vec<_>>();
        roots.sort_unstable();
        roots
    }

    fn accept_reachable_avoiding(raw: &RawPlan, removed: Option<u32>) -> bool {
        if removed == Some(raw.start) {
            return false;
        }
        let mut stack = vec![raw.start];
        let mut seen = HashSet::new();
        while let Some(state) = stack.pop() {
            if Some(state) == removed || !seen.insert(state) {
                continue;
            }
            let state_index = usize::try_from(state).expect("test state");
            if raw.roles[state_index] == StateRole::Accept {
                return true;
            }
            for edge in state_edges(raw, state_index).expect("test row") {
                let target = raw.edge_targets[edge];
                if Some(target) != removed {
                    stack.push(target);
                }
            }
        }
        false
    }

    fn production_mandatory_consume_roots(raw: &RawPlan) -> Vec<u32> {
        let mut budget = Budget::new(
            MAX_REQUIRED_LITERAL_WORK,
            MAX_REQUIRED_LITERAL_ALLOCATION_ITEMS,
        );
        let graph = ProductiveGraph::build(raw, &mut budget).expect("productive graph");
        let mut roots =
            mandatory_consume_roots(raw, &graph, &mut budget).expect("completed dominator proof");
        roots.sort_unstable();
        roots
    }

    fn accepting_path_avoids_candidate(
        raw: &RawPlan,
        candidate: &RequiredInteriorCandidate,
    ) -> bool {
        let depth = candidate.depth();
        assert!(depth > 0);
        let mut stack = vec![(raw.start, Vec::<u8>::new())];
        let mut seen = HashSet::new();
        while let Some((state, suffix)) = stack.pop() {
            if !seen.insert((state, suffix.clone())) {
                continue;
            }
            let state_index = usize::try_from(state).expect("test state");
            match raw.roles[state_index] {
                StateRole::Accept => return true,
                StateRole::Split => {
                    for edge in state_edges(raw, state_index).expect("test row") {
                        stack.push((raw.edge_targets[edge], suffix.clone()));
                    }
                }
                StateRole::Consume => {
                    for edge in state_edges(raw, state_index).expect("test row") {
                        for consumed in raw.byte_starts[edge]..=raw.byte_ends[edge] {
                            let mut next_suffix = suffix.clone();
                            next_suffix.push(consumed);
                            if candidate
                                .literals()
                                .iter()
                                .any(|literal| next_suffix.ends_with(literal.as_bytes()))
                            {
                                continue;
                            }
                            if next_suffix.len() >= depth {
                                next_suffix.remove(0);
                            }
                            stack.push((raw.edge_targets[edge], next_suffix));
                        }
                    }
                }
                _ => panic!("unknown test role"),
            }
        }
        false
    }

    fn assert_interior_candidates_sound(raw: &RawPlan, required: &RequiredLiterals) {
        for candidate in required.interior().candidates() {
            assert!(
                !accepting_path_avoids_candidate(raw, candidate),
                "accepting path avoids root {} candidate {:?}",
                candidate.root_state(),
                interior_literal_bytes(candidate),
            );
        }
    }

    fn enumerate_finite_language(raw: &RawPlan, max_depth: usize) -> Vec<Vec<u8>> {
        let mut stack = vec![(raw.start, Vec::new())];
        let mut seen = HashSet::new();
        let mut accepted = Vec::new();
        while let Some((state, bytes)) = stack.pop() {
            if !seen.insert((state, bytes.clone())) {
                continue;
            }
            let state_index = usize::try_from(state).expect("test state");
            match raw.roles[state_index] {
                StateRole::Accept => accepted.push(bytes),
                StateRole::Split => {
                    for edge in state_edges(raw, state_index).expect("test row") {
                        assert_ne!(raw.edge_kinds[edge], EdgeKind::ByteRange);
                        stack.push((raw.edge_targets[edge], bytes.clone()));
                    }
                }
                StateRole::Consume => {
                    if bytes.len() == max_depth {
                        continue;
                    }
                    for edge in state_edges(raw, state_index).expect("test row") {
                        assert_eq!(raw.edge_kinds[edge], EdgeKind::ByteRange);
                        for byte in raw.byte_starts[edge]..=raw.byte_ends[edge] {
                            let mut next = bytes.clone();
                            next.push(byte);
                            stack.push((raw.edge_targets[edge], next));
                        }
                    }
                }
                _ => panic!("unknown test role"),
            }
        }
        accepted.sort_unstable();
        accepted.dedup();
        accepted
    }

    fn assert_language_covered(
        set: &RequiredLiteralSet,
        language: &[Vec<u8>],
        direction: Direction,
    ) {
        assert!(!set.literals().is_empty(), "expected a literal proof");
        for word in language {
            let covered = set.literals().iter().any(|literal| match direction {
                Direction::Prefix => word.starts_with(literal.as_bytes()),
                Direction::Suffix => word.ends_with(literal.as_bytes()),
            });
            assert!(
                covered,
                "uncovered {direction:?} word {word:02x?} by {:?}",
                literal_bytes(set)
            );
        }
    }

    #[test]
    fn alternation_correlations_are_retained_in_both_directions() {
        for (pattern, expected) in [
            ("(?:ab|cd)", vec![b"ab".to_vec(), b"cd".to_vec()]),
            ("(?:ab|ac)", vec![b"ab".to_vec(), b"ac".to_vec()]),
            ("(?:aa|bb)", vec![b"aa".to_vec(), b"bb".to_vec()]),
        ] {
            let raw = lower(pattern);
            let language = enumerate_finite_language(&raw, 2);
            assert_eq!(language, expected);
            let required = derive(&raw);
            assert_eq!(required.prefix().depth(), 2);
            assert_eq!(required.suffix().depth(), 2);
            assert_eq!(literal_bytes(required.prefix()), expected);
            assert_eq!(literal_bytes(required.suffix()), expected);
            assert_language_covered(required.prefix(), &language, Direction::Prefix);
            assert_language_covered(required.suffix(), &language, Direction::Suffix);
        }
    }

    #[test]
    fn every_small_fixed_length_language_is_covered_exactly() {
        let words = ["aa", "ab", "ba", "bb"];
        for selection in 1_u8..16 {
            let selected = words
                .iter()
                .enumerate()
                .filter(|(index, _)| selection & (1_u8 << index) != 0)
                .map(|(_, word)| *word)
                .collect::<Vec<_>>();
            let pattern = format!("(?:{})", selected.join("|"));
            let raw = lower(&pattern);
            let language = enumerate_finite_language(&raw, 2);
            let required = derive(&raw);
            let expected = selected
                .iter()
                .map(|word| word.as_bytes().to_vec())
                .collect::<Vec<_>>();
            assert_eq!(language, expected);
            assert_eq!(literal_bytes(required.prefix()), expected);
            let mut expected_suffix = expected.clone();
            expected_suffix.sort_unstable();
            assert_eq!(literal_bytes(required.suffix()), expected_suffix);
            assert_language_covered(required.prefix(), &language, Direction::Prefix);
            assert_language_covered(required.suffix(), &language, Direction::Suffix);
        }
    }

    #[test]
    fn mixed_lengths_shorten_to_the_universal_safe_depth() {
        for (pattern, safe_depth) in [("(?:a|bc)", 1), ("(?:ab|cde)", 2), ("(?:a|bb|ccc)", 1)] {
            let raw = lower(pattern);
            let language = enumerate_finite_language(&raw, 3);
            let required = derive(&raw);
            assert_eq!(required.prefix().depth(), safe_depth);
            assert_eq!(required.suffix().depth(), safe_depth);
            assert!(required.prefix().shortened());
            assert!(required.suffix().shortened());
            assert_language_covered(required.prefix(), &language, Direction::Prefix);
            assert_language_covered(required.suffix(), &language, Direction::Suffix);
        }
    }

    #[test]
    fn assertions_are_zero_width_conservative_edges() {
        let raw = lower(r"(?:\Aab|cd\z|(?m:^)ef|gh(?-u:\b))");
        let language = enumerate_finite_language(&raw, 2);
        let required = derive(&raw);
        assert!(required.prefix().context_assertions());
        assert!(required.suffix().context_assertions());
        assert_eq!(required.prefix().depth(), 2);
        assert_eq!(required.suffix().depth(), 2);
        assert_language_covered(required.prefix(), &language, Direction::Prefix);
        assert_language_covered(required.suffix(), &language, Direction::Suffix);
    }

    #[test]
    fn nullable_and_cycles_shorten_without_false_literal_claims() {
        for pattern in ["(?:|ab)", "a*"] {
            let required = derive(&lower(pattern));
            assert!(required.prefix().literals().is_empty());
            assert!(required.suffix().literals().is_empty());
        }
        for (pattern, expected) in [
            ("a+", vec![b"a".to_vec()]),
            ("(?:ab|cd)+", vec![b"ab".to_vec(), b"cd".to_vec()]),
        ] {
            let required = derive(&lower(pattern));
            assert_eq!(literal_bytes(required.prefix()), expected);
            assert_eq!(literal_bytes(required.suffix()), expected);
            assert!(required.prefix().shortened());
            assert!(required.suffix().shortened());
        }
    }

    #[test]
    fn expansion_and_resource_caps_fall_back_or_decline() {
        let broad = derive(&lower(r"(?-u:[\x00-\xFF]{2})"));
        assert_eq!(broad.prefix().depth(), 1);
        assert_eq!(broad.prefix().literals().len(), 256);
        assert!(broad.prefix().resource_limited());
        assert!(broad.prefix().shortened());

        for limits in [
            RequiredLiteralLimits {
                max_work: 0,
                ..RequiredLiteralLimits::default()
            },
            RequiredLiteralLimits {
                max_allocation_items: 0,
                ..RequiredLiteralLimits::default()
            },
            RequiredLiteralLimits {
                max_frontier_items: 1,
                ..RequiredLiteralLimits::default()
            },
            RequiredLiteralLimits {
                max_total_bytes: 1,
                ..RequiredLiteralLimits::default()
            },
        ] {
            let limited = derive_with_limits(&lower("(?:ab|cd)"), limits);
            assert!(limited.prefix().literals().is_empty() || limited.prefix().depth() == 1);
            assert!(limited.prefix().resource_limited());
        }
    }

    #[test]
    fn mandatory_interior_diamond_retains_correlated_alternatives() {
        // The mandatory root consumes `a` or `c`; the graph then correlates
        // those choices with `b` or `d`. Independent columns would invent
        // `ad` and `cb`, while the path-correlated group is exactly {ab, cd}.
        let raw = hand_raw(
            0,
            vec![
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Accept,
            ],
            vec![
                vec![byte(1, b'a'), byte(2, b'c')],
                vec![byte(3, b'b')],
                vec![byte(3, b'd')],
                vec![],
            ],
        );
        assert_eq!(
            production_mandatory_consume_roots(&raw),
            brute_mandatory_consume_roots(&raw)
        );
        let required = derive(&raw);
        let candidate = required
            .interior()
            .candidates()
            .iter()
            .find(|candidate| candidate.root_state() == 0)
            .expect("mandatory diamond root");
        assert_eq!(
            interior_literal_bytes(candidate),
            vec![b"ab".to_vec(), b"cd".to_vec()]
        );
        assert_eq!(
            candidate.max_before_root(),
            MaximumConsumedDistance::Finite(0)
        );
        assert_eq!(
            candidate.max_through_accept(),
            MaximumConsumedDistance::Finite(2)
        );
        assert_interior_candidates_sound(&raw, &required);
    }

    #[test]
    fn variable_prefix_converges_on_mandatory_singleton_chain() {
        // Accepted words are `x7L7q*` and `yz7L7q*`. This is deliberately a
        // hand-built graph: the mandatory interior fact follows from the
        // converged CFG shape, not from source spelling or a pattern recipe.
        let raw = hand_raw(
            0,
            vec![
                StateRole::Split,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Split,
                StateRole::Accept,
                StateRole::Consume,
            ],
            vec![
                vec![epsilon(1), epsilon(2)],
                vec![byte(4, b'x')],
                vec![byte(3, b'y')],
                vec![byte(4, b'z')],
                vec![byte(5, b'7')],
                vec![byte(6, b'L')],
                vec![byte(7, b'7')],
                vec![epsilon(8), epsilon(9)],
                vec![],
                vec![byte(7, b'q')],
            ],
        );
        assert_eq!(
            production_mandatory_consume_roots(&raw),
            brute_mandatory_consume_roots(&raw)
        );
        assert_eq!(production_mandatory_consume_roots(&raw), vec![4, 5, 6]);
        let required = derive(&raw);
        let candidate = required
            .interior()
            .candidates()
            .iter()
            .find(|candidate| candidate.root_state() == 4)
            .expect("converged singleton chain");
        assert_eq!(interior_literal_bytes(candidate), vec![b"7L7".to_vec()]);
        assert_eq!(
            candidate.max_before_root(),
            MaximumConsumedDistance::Finite(2)
        );
        assert_eq!(
            candidate.max_through_accept(),
            MaximumConsumedDistance::Unbounded
        );
        assert_interior_candidates_sound(&raw, &required);
    }

    #[test]
    fn early_accept_and_structural_bypass_shorten_or_erase_interior_groups() {
        let early = hand_raw(
            0,
            vec![
                StateRole::Consume,
                StateRole::Split,
                StateRole::Accept,
                StateRole::Consume,
            ],
            vec![
                vec![byte(1, b'a')],
                vec![epsilon(2), epsilon(3)],
                vec![],
                vec![byte(2, b'b')],
            ],
        );
        let early_required = derive(&early);
        let candidate = early_required
            .interior()
            .candidates()
            .iter()
            .find(|candidate| candidate.root_state() == 0)
            .expect("mandatory leading root");
        assert_eq!(interior_literal_bytes(candidate), vec![b"a".to_vec()]);
        assert!(candidate.literal_set().shortened());
        assert_interior_candidates_sound(&early, &early_required);

        let nullable = hand_raw(
            0,
            vec![StateRole::Split, StateRole::Accept, StateRole::Consume],
            vec![vec![epsilon(1), epsilon(2)], vec![], vec![byte(1, b'a')]],
        );
        assert!(derive(&nullable).interior().candidates().is_empty());

        let assertion_bypass = hand_raw(
            0,
            vec![StateRole::Split, StateRole::Accept, StateRole::Consume],
            vec![vec![assertion(1), epsilon(2)], vec![], vec![byte(1, b'a')]],
        );
        let bypass = derive(&assertion_bypass);
        assert!(bypass.interior().candidates().is_empty());
        assert!(bypass.interior().context_assertions());
    }

    #[test]
    fn dead_paths_and_unreachable_accepts_do_not_weaken_dominators() {
        // States 6 and 7 are a reachable dead consuming cycle; state 8 is an
        // unreachable accept. Neither belongs to a finite start->exit path.
        let raw = hand_raw(
            0,
            vec![
                StateRole::Split,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Accept,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Accept,
            ],
            vec![
                vec![epsilon(1), epsilon(2), epsilon(6)],
                vec![byte(4, b'x')],
                vec![byte(3, b'y')],
                vec![byte(4, b'z')],
                vec![byte(5, b'a')],
                vec![],
                vec![byte(7, b'j')],
                vec![byte(6, b'k')],
                vec![],
            ],
        );
        assert_eq!(
            production_mandatory_consume_roots(&raw),
            brute_mandatory_consume_roots(&raw)
        );
        assert_eq!(production_mandatory_consume_roots(&raw), vec![4]);
        let required = derive(&raw);
        assert!(
            required
                .interior()
                .candidates()
                .iter()
                .any(|candidate| interior_literal_bytes(candidate) == vec![b"a".to_vec()])
        );
        assert_interior_candidates_sound(&raw, &required);
    }

    #[test]
    fn consumed_distance_distinguishes_consuming_and_zero_width_cycles() {
        let consuming_cycle = hand_raw(
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
        let required = derive(&consuming_cycle);
        let candidate = required
            .interior()
            .candidates()
            .iter()
            .find(|candidate| candidate.root_state() == 2)
            .expect("root after consuming cycle");
        assert_eq!(
            candidate.max_before_root(),
            MaximumConsumedDistance::Unbounded
        );
        assert_eq!(
            candidate.max_through_accept(),
            MaximumConsumedDistance::Finite(1)
        );

        let zero_width_cycle = hand_raw(
            0,
            vec![StateRole::Split, StateRole::Consume, StateRole::Accept],
            vec![vec![epsilon(0), epsilon(1)], vec![byte(2, b'a')], vec![]],
        );
        let zero_required = derive(&zero_width_cycle);
        let zero_candidate = zero_required
            .interior()
            .candidates()
            .iter()
            .find(|candidate| candidate.root_state() == 1)
            .expect("root after epsilon cycle");
        assert_eq!(
            zero_candidate.max_before_root(),
            MaximumConsumedDistance::Finite(0)
        );
        assert_eq!(
            zero_candidate.max_through_accept(),
            MaximumConsumedDistance::Finite(1)
        );
        assert_interior_candidates_sound(&consuming_cycle, &required);
        assert_interior_candidates_sound(&zero_width_cycle, &zero_required);
    }

    #[test]
    fn mandatory_line_cuts_are_graph_general_and_distance_bounded() {
        let leading = hand_raw(
            0,
            vec![StateRole::Split, StateRole::Consume, StateRole::Accept],
            vec![
                vec![line_assertion(1, EdgeKind::AssertLineStartLf)],
                vec![byte(2, b'a')],
                vec![],
            ],
        );
        assert_eq!(
            line_cut(
                derive(&leading).interior(),
                RequiredLineCutKind::ConfiguredStart,
            ),
            Some(RequiredLineCut {
                kind: RequiredLineCutKind::ConfiguredStart,
                maximum_before: MaximumConsumedDistance::Finite(0),
            })
        );

        let trailing = hand_raw(
            0,
            vec![
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Split,
                StateRole::Accept,
            ],
            vec![
                vec![byte(1, b'a')],
                vec![byte(2, b'b')],
                vec![line_assertion(3, EdgeKind::AssertLineEndCrlf)],
                vec![],
            ],
        );
        assert_eq!(
            line_cut(
                derive(&trailing).interior(),
                RequiredLineCutKind::CrlfEnd,
            ),
            Some(RequiredLineCut {
                kind: RequiredLineCutKind::CrlfEnd,
                maximum_before: MaximumConsumedDistance::Finite(2),
            })
        );

        // Neither assertion state dominates the shared accept, but removing
        // every edge of the semantic kind disconnects both alternation arms.
        let duplicated = hand_raw(
            0,
            vec![
                StateRole::Split,
                StateRole::Split,
                StateRole::Split,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Accept,
            ],
            vec![
                vec![epsilon(1), epsilon(2)],
                vec![line_assertion(3, EdgeKind::AssertLineStartCrlf)],
                vec![line_assertion(4, EdgeKind::AssertLineStartCrlf)],
                vec![byte(5, b'a')],
                vec![byte(5, b'b')],
                vec![],
            ],
        );
        assert_eq!(
            line_cut(
                derive(&duplicated).interior(),
                RequiredLineCutKind::CrlfStart,
            ),
            Some(RequiredLineCut {
                kind: RequiredLineCutKind::CrlfStart,
                maximum_before: MaximumConsumedDistance::Finite(0),
            })
        );
    }

    #[test]
    fn line_cut_declines_bypasses_and_reports_unbounded_prefixes() {
        let bypass = hand_raw(
            0,
            vec![
                StateRole::Split,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Accept,
            ],
            vec![
                vec![
                    line_assertion(1, EdgeKind::AssertLineEndLf),
                    epsilon(2),
                ],
                vec![byte(3, b'a')],
                vec![byte(3, b'b')],
                vec![],
            ],
        );
        assert!(derive(&bypass).interior().line_cuts().is_empty());

        let unbounded = hand_raw(
            0,
            vec![
                StateRole::Split,
                StateRole::Consume,
                StateRole::Split,
                StateRole::Accept,
            ],
            vec![vec![epsilon(1), epsilon(2)], vec![byte(0, b'x')], vec![
                line_assertion(3, EdgeKind::AssertLineEndLf),
            ], vec![]],
        );
        assert_eq!(
            line_cut(
                derive(&unbounded).interior(),
                RequiredLineCutKind::ConfiguredEnd,
            ),
            Some(RequiredLineCut {
                kind: RequiredLineCutKind::ConfiguredEnd,
                maximum_before: MaximumConsumedDistance::Unbounded,
            })
        );
    }

    #[test]
    fn line_cut_survives_disabled_interior_literal_expansion() {
        let raw = hand_raw(
            0,
            vec![StateRole::Split, StateRole::Consume, StateRole::Accept],
            vec![
                vec![line_assertion(1, EdgeKind::AssertLineStartLf)],
                vec![byte(2, b'a')],
                vec![],
            ],
        );
        let derived = derive_interior(
            &raw,
            RequiredLiteralLimits {
                max_depth: 0,
                max_interior_candidates: 0,
                ..RequiredLiteralLimits::default()
            },
        );
        assert!(derived.candidates().is_empty());
        assert_eq!(
            line_cut(&derived, RequiredLineCutKind::ConfiguredStart),
            Some(RequiredLineCut {
                kind: RequiredLineCutKind::ConfiguredStart,
                maximum_before: MaximumConsumedDistance::Finite(0),
            })
        );
    }

    #[test]
    fn line_cut_handles_multiple_accepts_mixed_kinds_and_later_same_kind_cycles() {
        let multiple_accepts = hand_raw(
            0,
            vec![
                StateRole::Split,
                StateRole::Split,
                StateRole::Split,
                StateRole::Accept,
                StateRole::Accept,
            ],
            vec![
                vec![epsilon(1), epsilon(2)],
                vec![line_assertion(3, EdgeKind::AssertLineEndLf)],
                vec![line_assertion(4, EdgeKind::AssertLineEndLf)],
                vec![],
                vec![],
            ],
        );
        assert_eq!(
            line_cut(
                derive(&multiple_accepts).interior(),
                RequiredLineCutKind::ConfiguredEnd,
            ),
            Some(RequiredLineCut {
                kind: RequiredLineCutKind::ConfiguredEnd,
                maximum_before: MaximumConsumedDistance::Finite(0),
            })
        );

        let mixed_kinds = hand_raw(
            0,
            vec![
                StateRole::Split,
                StateRole::Split,
                StateRole::Split,
                StateRole::Accept,
                StateRole::Accept,
            ],
            vec![
                vec![epsilon(1), epsilon(2)],
                vec![line_assertion(3, EdgeKind::AssertLineStartLf)],
                vec![line_assertion(4, EdgeKind::AssertLineEndLf)],
                vec![],
                vec![],
            ],
        );
        assert!(derive(&mixed_kinds).interior().line_cuts().is_empty());

        // The consuming cycle is reachable only after the first mandatory
        // assertion. The proof deliberately bounds possible *first* cuts,
        // so the later same-kind cut and its cycle cannot inflate the zero
        // distance of the first cut.
        let later_cycle = hand_raw(
            0,
            vec![
                StateRole::Split,
                StateRole::Split,
                StateRole::Consume,
                StateRole::Split,
                StateRole::Accept,
            ],
            vec![
                vec![line_assertion(1, EdgeKind::AssertLineStartCrlf)],
                vec![epsilon(2), epsilon(3)],
                vec![byte(1, b'x')],
                vec![line_assertion(4, EdgeKind::AssertLineStartCrlf)],
                vec![],
            ],
        );
        assert_eq!(
            line_cut(
                derive(&later_cycle).interior(),
                RequiredLineCutKind::CrlfStart,
            ),
            Some(RequiredLineCut {
                kind: RequiredLineCutKind::CrlfStart,
                maximum_before: MaximumConsumedDistance::Finite(0),
            })
        );

        let both_directions = hand_raw(
            0,
            vec![
                StateRole::Split,
                StateRole::Consume,
                StateRole::Split,
                StateRole::Accept,
            ],
            vec![
                vec![line_assertion(1, EdgeKind::AssertLineStartLf)],
                vec![byte(2, b'a')],
                vec![line_assertion(3, EdgeKind::AssertLineEndLf)],
                vec![],
            ],
        );
        let both = derive(&both_directions);
        assert_eq!(
            both.interior().line_cuts(),
            &[
                RequiredLineCut {
                    kind: RequiredLineCutKind::ConfiguredStart,
                    maximum_before: MaximumConsumedDistance::Finite(0),
                },
                RequiredLineCut {
                    kind: RequiredLineCutKind::ConfiguredEnd,
                    maximum_before: MaximumConsumedDistance::Finite(1),
                },
            ]
        );
    }

    #[test]
    fn declined_line_proof_does_not_spend_literal_budget_or_change_candidates() {
        let raw = hand_raw(
            0,
            vec![
                StateRole::Split,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Accept,
            ],
            vec![
                vec![line_assertion(1, EdgeKind::AssertLineStartLf)],
                vec![byte(2, b'x')],
                vec![byte(3, b'y')],
                vec![],
            ],
        );
        let tight = RequiredLiteralLimits {
            max_work: 2_048,
            max_allocation_items: 512,
            max_candidate_work: 512,
            max_candidate_allocation_items: 128,
            ..RequiredLiteralLimits::default()
        };
        let proved = derive_interior(&raw, tight);
        assert!(!proved.line_cuts().is_empty());
        assert!(!proved.candidates().is_empty());

        let declined = derive_interior(
            &raw,
            RequiredLiteralLimits {
                max_line_cut_work: 0,
                max_line_cut_allocation_items: 0,
                ..tight
            },
        );
        assert!(declined.line_cuts().is_empty());
        assert_eq!(declined.candidates, proved.candidates);
        assert_eq!(declined.derivation_work, proved.derivation_work);
        assert_eq!(declined.allocation_items, proved.allocation_items);
        assert_eq!(declined.resource_limited, proved.resource_limited);
        assert_eq!(declined.context_assertions, proved.context_assertions);
    }

    #[test]
    fn line_proof_is_independent_when_literal_analysis_is_disabled_or_exhausted() {
        let raw = hand_raw(
            0,
            vec![StateRole::Split, StateRole::Consume, StateRole::Accept],
            vec![
                vec![line_assertion(1, EdgeKind::AssertLineStartLf)],
                vec![byte(2, b'a')],
                vec![],
            ],
        );
        let disabled = derive_interior(
            &raw,
            RequiredLiteralLimits {
                max_depth: 0,
                max_interior_candidates: 0,
                ..RequiredLiteralLimits::default()
            },
        );
        assert_eq!(disabled.derivation_work(), 0);
        assert_eq!(disabled.allocation_items(), 0);
        assert!(!disabled.resource_limited());
        assert!(!disabled.context_assertions());
        assert!(line_cut(&disabled, RequiredLineCutKind::ConfiguredStart).is_some());

        let exhausted = derive_interior(
            &raw,
            RequiredLiteralLimits {
                max_work: 0,
                max_allocation_items: 0,
                ..RequiredLiteralLimits::default()
            },
        );
        assert!(exhausted.candidates().is_empty());
        assert!(exhausted.resource_limited());
        assert!(line_cut(&exhausted, RequiredLineCutKind::ConfiguredStart).is_some());
    }

    #[test]
    fn interior_caps_are_transactional_and_seed_order_preserves_exact_groups() {
        let raw = hand_raw(
            0,
            vec![
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Accept,
            ],
            vec![
                vec![byte_range(1, 0, u8::MAX)],
                vec![byte_range(2, 0, u8::MAX)],
                vec![byte(3, b'x')],
                vec![byte(4, b'y')],
                vec![],
            ],
        );
        let retained = derive_interior(
            &raw,
            RequiredLiteralLimits {
                max_work: 50_000,
                max_candidate_work: 256,
                ..RequiredLiteralLimits::default()
            },
        );
        assert!(retained.candidates().iter().any(|candidate| {
            candidate.root_state() == 2 && interior_literal_bytes(candidate) == vec![b"xy".to_vec()]
        }));

        let declined = derive_interior(
            &raw,
            RequiredLiteralLimits {
                max_work: 1,
                ..RequiredLiteralLimits::default()
            },
        );
        assert!(declined.candidates().is_empty());
        assert!(declined.resource_limited());
    }

    #[test]
    fn depth_and_combined_accounting_never_exceed_hard_caps() {
        let required = derive(&lower("abcdefghijklmnop"));
        assert_eq!(required.prefix().depth(), MAX_REQUIRED_LITERAL_DEPTH);
        assert_eq!(required.suffix().depth(), MAX_REQUIRED_LITERAL_DEPTH);
        assert_eq!(literal_bytes(required.prefix()), vec![b"abcdefgh".to_vec()]);
        assert_eq!(literal_bytes(required.suffix()), vec![b"ijklmnop".to_vec()]);
        assert!(
            required
                .prefix()
                .derivation_work()
                .checked_add(required.suffix().derivation_work())
                .and_then(|work| work.checked_add(required.interior().derivation_work()))
                .is_some_and(|work| work <= MAX_REQUIRED_LITERAL_WORK)
        );
        assert!(
            required
                .prefix()
                .allocation_items()
                .checked_add(required.suffix().allocation_items())
                .and_then(|items| items.checked_add(required.interior().allocation_items()))
                .is_some_and(|items| items <= MAX_REQUIRED_LITERAL_ALLOCATION_ITEMS)
        );
        assert!(
            required
                .prefix()
                .literal_bytes()
                .checked_add(required.suffix().literal_bytes())
                .and_then(|bytes| bytes.checked_add(required.interior().literal_bytes()))
                .is_some_and(|bytes| bytes <= MAX_REQUIRED_LITERAL_TOTAL_BYTES)
        );
        assert!(required.prefix().literals().len() <= MAX_REQUIRED_LITERAL_SEQUENCES);
        assert!(required.suffix().literals().len() <= MAX_REQUIRED_LITERAL_SEQUENCES);
        assert!(required.interior().candidates().len() <= MAX_REQUIRED_INTERIOR_CANDIDATES);
    }

    #[test]
    fn native_view_exposes_rederived_wire_neutral_literals() {
        let compiled = compile("a(?:b|c)");
        let expected = compiled
            .native_dfa_view()
            .expect("native DFA")
            .required_literals
            .clone();
        let bytes = compiled.serialize().expect("serialize");
        let restored = CompiledProgram::deserialize(&bytes).expect("deserialize");
        let actual = restored
            .native_dfa_view()
            .expect("restored native DFA")
            .required_literals;
        assert_eq!(actual, &expected);
        assert_eq!(
            literal_bytes(actual.prefix()),
            vec![b"ab".to_vec(), b"ac".to_vec()]
        );
        assert_eq!(
            literal_bytes(actual.suffix()),
            vec![b"ab".to_vec(), b"ac".to_vec()]
        );
        assert!(!actual.interior().candidates().is_empty());
    }
}
