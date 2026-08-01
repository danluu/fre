//! Bounded graph-derived relation between the first two consumed bytes.
//!
//! Independent anchored-byte columns lose correlations at Thompson joins. For
//! example, the columns for `(?:ab|cd)` admit the impossible pairs `ad` and
//! `cb`. This pass instead retains the exact two-byte prefix relation of the
//! assertion-erased productive graph. Supported context assertions are
//! traversed as epsilon edges, so the result can add pairs that no concrete
//! boundary context admits but can never remove a pair from a real match.
//!
//! Publication is all-or-nothing. A graph with an accepting path shorter than
//! two bytes, an unsupported or malformed edge, allocation failure, too many
//! distinct relation rows, or any explicit resource ceiling declines the
//! optional optimization.

#![allow(
    dead_code,
    reason = "the graph relation is a narrow handoff to native lowering"
)]

use core::mem::size_of;

use fre_automata::{EdgeKind, RawPlan, StateRole};

use crate::program::AnchoredByteSet;

/// Maximum validated states inspected by the optional relation analysis.
pub(crate) const MAX_PREFIX_RELATION_STATES: usize = 65_536;
/// Maximum validated edges inspected by the optional relation analysis.
pub(crate) const MAX_PREFIX_RELATION_EDGES: usize = 262_144;
/// Maximum distinct states immediately following the first consumed byte.
pub(crate) const MAX_PREFIX_RELATION_FIRST_TARGETS: usize = 4_096;
/// Maximum equivalence classes of first-byte rows published to native code.
pub(crate) const MAX_PREFIX_RELATION_GROUPS: usize = 32;
/// Maximum deterministic abstract work charged by one derivation.
pub(crate) const MAX_PREFIX_RELATION_WORK: u64 = 4_000_000;
/// Maximum auxiliary storage reserved by one derivation.
pub(crate) const MAX_PREFIX_RELATION_MEMORY_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_field_names,
    reason = "uniform max_ names make every independently tunable ceiling explicit"
)]
struct PrefixRelationLimits {
    max_states: usize,
    max_edges: usize,
    max_first_targets: usize,
    max_groups: usize,
    max_work: u64,
    max_memory_bytes: usize,
}

impl Default for PrefixRelationLimits {
    fn default() -> Self {
        Self {
            max_states: MAX_PREFIX_RELATION_STATES,
            max_edges: MAX_PREFIX_RELATION_EDGES,
            max_first_targets: MAX_PREFIX_RELATION_FIRST_TARGETS,
            max_groups: MAX_PREFIX_RELATION_GROUPS,
            max_work: MAX_PREFIX_RELATION_WORK,
            max_memory_bytes: MAX_PREFIX_RELATION_MEMORY_BYTES,
        }
    }
}

/// One disjoint equivalence class of first-byte rows.
///
/// The relation represented by this group is the Cartesian product
/// `first x second`. First-byte sets are pairwise disjoint across groups.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PrefixRelationGroup {
    first: AnchoredByteSet,
    second: AnchoredByteSet,
}

impl PrefixRelationGroup {
    #[must_use]
    pub(crate) const fn first(self) -> AnchoredByteSet {
        self.first
    }

    #[must_use]
    pub(crate) const fn second(self) -> AnchoredByteSet {
        self.second
    }
}

/// Compact exact relation for the first two bytes of the assertion-erased
/// productive Thompson graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PrefixRelation {
    groups: Vec<PrefixRelationGroup>,
    viable_first: AnchoredByteSet,
    pair_count: u32,
    derivation_work: u64,
    context_assertions: bool,
}

impl PrefixRelation {
    #[must_use]
    pub(crate) fn groups(&self) -> &[PrefixRelationGroup] {
        &self.groups
    }

    #[must_use]
    pub(crate) const fn viable_first(&self) -> AnchoredByteSet {
        self.viable_first
    }

    #[must_use]
    pub(crate) const fn pair_count(&self) -> u32 {
        self.pair_count
    }

    #[must_use]
    pub(crate) const fn derivation_work(&self) -> u64 {
        self.derivation_work
    }

    #[must_use]
    pub(crate) const fn context_assertions(&self) -> bool {
        self.context_assertions
    }

    #[cfg(test)]
    fn contains(&self, first: u8, second: u8) -> bool {
        self.groups.iter().any(|group| {
            Bitmap::from_set(group.first).contains(first)
                && Bitmap::from_set(group.second).contains(second)
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Bitmap {
    words: [u64; 4],
}

impl Bitmap {
    const EMPTY: Self = Self { words: [0; 4] };

    const fn from_set(set: AnchoredByteSet) -> Self {
        Self { words: set.words() }
    }

    const fn into_set(self) -> AnchoredByteSet {
        AnchoredByteSet::from_words(self.words)
    }

    const fn is_empty(self) -> bool {
        self.words[0] == 0 && self.words[1] == 0 && self.words[2] == 0 && self.words[3] == 0
    }

    fn contains(self, byte: u8) -> bool {
        let index = usize::from(byte);
        self.words[index / 64] & (1_u64 << (index % 64)) != 0
    }

    fn insert(&mut self, byte: u8) {
        let index = usize::from(byte);
        self.words[index / 64] |= 1_u64 << (index % 64);
    }

    fn insert_range(&mut self, start: u8, end: u8, budget: &mut Budget) -> Option<()> {
        let first_word = usize::from(start) / 64;
        let last_word = usize::from(end) / 64;
        for word in first_word..=last_word {
            budget.charge(1)?;
            let low = if word == first_word {
                usize::from(start) % 64
            } else {
                0
            };
            let high = if word == last_word {
                usize::from(end) % 64
            } else {
                63
            };
            let below_low = u64::MAX << low;
            let above_high = u64::MAX >> 63_usize.checked_sub(high)?;
            self.words[word] |= below_low & above_high;
        }
        Some(())
    }

    fn union(&mut self, other: Self, budget: &mut Budget) -> Option<()> {
        budget.charge(4)?;
        for (word, other) in self.words.iter_mut().zip(other.words) {
            *word |= other;
        }
        Some(())
    }

    fn cardinality(self) -> u32 {
        self.words.iter().map(|word| word.count_ones()).sum()
    }

    fn members(self) -> BitmapMembers {
        BitmapMembers {
            words: self.words,
            word: 0,
        }
    }
}

struct BitmapMembers {
    words: [u64; 4],
    word: usize,
}

impl Iterator for BitmapMembers {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        while self.word < self.words.len() {
            let bits = self.words[self.word];
            if bits == 0 {
                self.word = self.word.checked_add(1)?;
                continue;
            }
            let bit = bits.trailing_zeros();
            self.words[self.word] &= bits.checked_sub(1)?;
            let byte = self
                .word
                .checked_mul(64)?
                .checked_add(usize::try_from(bit).ok()?)?;
            return u8::try_from(byte).ok();
        }
        None
    }
}

#[derive(Clone, Copy, Debug)]
struct Budget {
    limit: u64,
    used: u64,
}

impl Budget {
    const fn new(limit: u64) -> Self {
        Self { limit, used: 0 }
    }

    fn charge(&mut self, amount: u64) -> Option<()> {
        let next = self.used.checked_add(amount)?;
        if next > self.limit {
            return None;
        }
        self.used = next;
        Some(())
    }

    fn charge_usize(&mut self, amount: usize) -> Option<()> {
        self.charge(u64::try_from(amount).ok()?)
    }
}

#[derive(Clone, Copy, Debug)]
struct GraphShape {
    states: usize,
    edges: usize,
    context_assertions: bool,
}

#[derive(Clone, Copy, Debug)]
struct FirstTarget {
    state: u32,
    first: Bitmap,
}

fn supported_zero_width(kind: EdgeKind) -> bool {
    matches!(
        kind,
        EdgeKind::Epsilon
            | EdgeKind::AssertHaystackStart
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
    )
}

fn state_edges(raw: &RawPlan, state: usize) -> Option<core::ops::Range<usize>> {
    let begin = usize::try_from(*raw.edge_offsets.get(state)?).ok()?;
    let end = usize::try_from(*raw.edge_offsets.get(state.checked_add(1)?)?).ok()?;
    (begin <= end && end <= raw.edge_targets.len()).then_some(begin..end)
}

fn auxiliary_storage_bytes(
    states: usize,
    edges: usize,
    first_targets: usize,
    groups: usize,
) -> Option<usize> {
    // Two incoming-index vectors; productivity; reverse and closure queues;
    // closure generations; the first-target index; and one consuming frontier.
    // The closure stack separately reserves one slot per graph edge because
    // duplicate targets can be pending before they are deduplicated on pop.
    let per_state = size_of::<usize>()
        .checked_mul(2)?
        .checked_add(size_of::<bool>())?
        .checked_add(size_of::<u32>().checked_mul(4)?)?;
    states
        .checked_add(1)?
        .checked_mul(per_state)?
        .checked_add(edges.checked_add(1)?.checked_mul(size_of::<u32>())?)?
        .checked_add(edges.checked_mul(size_of::<u32>())?)?
        .checked_add(first_targets.checked_mul(size_of::<FirstTarget>())?)?
        .checked_add(256_usize.checked_mul(size_of::<Bitmap>())?)?
        .checked_add(groups.checked_mul(size_of::<PrefixRelationGroup>())?)
}

fn validate_graph(
    raw: &RawPlan,
    limits: PrefixRelationLimits,
    budget: &mut Budget,
) -> Option<GraphShape> {
    let states = raw.roles.len();
    let edges = raw.edge_targets.len();
    if states == 0
        || states > limits.max_states
        || edges > limits.max_edges
        || usize::try_from(raw.start).ok()? >= states
        || raw.edge_offsets.len() != states.checked_add(1)?
        || raw.edge_kinds.len() != edges
        || raw.byte_starts.len() != edges
        || raw.byte_ends.len() != edges
        || raw.edge_offsets.first().copied() != Some(0)
        || usize::try_from(*raw.edge_offsets.last()?).ok()? != edges
        || auxiliary_storage_bytes(states, edges, limits.max_first_targets, limits.max_groups)?
            > limits.max_memory_bytes
    {
        return None;
    }
    budget.charge_usize(states.checked_add(edges)?)?;

    let mut context_assertions = false;
    for (state, role) in raw.roles.iter().copied().enumerate() {
        let row = state_edges(raw, state)?;
        match role {
            StateRole::Accept if !row.is_empty() => return None,
            StateRole::Accept => {}
            StateRole::Split => {
                for edge in row {
                    let kind = *raw.edge_kinds.get(edge)?;
                    if !supported_zero_width(kind)
                        || raw.byte_starts.get(edge).copied() != Some(0)
                        || raw.byte_ends.get(edge).copied() != Some(0)
                    {
                        return None;
                    }
                    context_assertions |= kind != EdgeKind::Epsilon;
                }
            }
            StateRole::Consume => {
                for edge in row {
                    if raw.edge_kinds.get(edge) != Some(&EdgeKind::ByteRange)
                        || raw.byte_starts.get(edge)? > raw.byte_ends.get(edge)?
                    {
                        return None;
                    }
                }
            }
            _ => return None,
        }
    }
    if raw
        .edge_targets
        .iter()
        .any(|target| usize::try_from(*target).map_or(true, |target| target >= states))
    {
        return None;
    }
    Some(GraphShape {
        states,
        edges,
        context_assertions,
    })
}

fn reserved_vec<T>(capacity: usize) -> Option<Vec<T>> {
    let mut values = Vec::new();
    values.try_reserve_exact(capacity).ok()?;
    Some(values)
}

fn filled_vec<T: Clone>(len: usize, value: T) -> Option<Vec<T>> {
    let mut values = reserved_vec(len)?;
    values.resize(len, value);
    Some(values)
}

fn build_productive(raw: &RawPlan, shape: GraphShape, budget: &mut Budget) -> Option<Vec<bool>> {
    let mut incoming_offsets = filled_vec(shape.states.checked_add(1)?, 0_usize)?;
    for &target in &raw.edge_targets {
        budget.charge(1)?;
        let slot = usize::try_from(target).ok()?.checked_add(1)?;
        *incoming_offsets.get_mut(slot)? = incoming_offsets.get(slot)?.checked_add(1)?;
    }
    for state in 1..incoming_offsets.len() {
        budget.charge(1)?;
        let previous = incoming_offsets[state.checked_sub(1)?];
        incoming_offsets[state] = incoming_offsets[state].checked_add(previous)?;
    }

    let mut cursors = reserved_vec(incoming_offsets.len())?;
    cursors.extend_from_slice(&incoming_offsets);
    let mut incoming_sources = filled_vec(shape.edges, u32::MAX)?;
    for source in 0..shape.states {
        let source_u32 = u32::try_from(source).ok()?;
        for edge in state_edges(raw, source)? {
            budget.charge(1)?;
            let target = usize::try_from(*raw.edge_targets.get(edge)?).ok()?;
            let slot = *cursors.get(target)?;
            *incoming_sources.get_mut(slot)? = source_u32;
            *cursors.get_mut(target)? = slot.checked_add(1)?;
        }
    }

    let mut productive = filled_vec(shape.states, false)?;
    let mut queue = reserved_vec(shape.states)?;
    for (state, role) in raw.roles.iter().copied().enumerate() {
        budget.charge(1)?;
        if role == StateRole::Accept {
            productive[state] = true;
            queue.push(u32::try_from(state).ok()?);
        }
    }
    let mut head = 0_usize;
    while let Some(&target) = queue.get(head) {
        head = head.checked_add(1)?;
        let target = usize::try_from(target).ok()?;
        let begin = *incoming_offsets.get(target)?;
        let end = *incoming_offsets.get(target.checked_add(1)?)?;
        for &source in incoming_sources.get(begin..end)? {
            budget.charge(1)?;
            let source = usize::try_from(source).ok()?;
            if !*productive.get(source)? {
                productive[source] = true;
                queue.push(u32::try_from(source).ok()?);
            }
        }
    }
    Some(productive)
}

struct ClosureWorkspace {
    seen: Vec<u32>,
    generation: u32,
    stack: Vec<u32>,
    consuming: Vec<u32>,
}

impl ClosureWorkspace {
    fn new(states: usize, edges: usize) -> Option<Self> {
        Some(Self {
            seen: filled_vec(states, 0_u32)?,
            generation: 0,
            stack: reserved_vec(edges.checked_add(1)?)?,
            consuming: reserved_vec(states)?,
        })
    }

    /// Return whether the zero-width closure reaches accept. Consuming states
    /// are retained in `self.consuming` when it does not.
    fn derive(
        &mut self,
        raw: &RawPlan,
        roots: &[u32],
        productive: &[bool],
        budget: &mut Budget,
    ) -> Option<bool> {
        self.generation = self.generation.checked_add(1)?;
        self.stack.clear();
        self.consuming.clear();
        for &root in roots {
            let root_index = usize::try_from(root).ok()?;
            if *productive.get(root_index)? {
                self.stack.push(root);
            }
        }
        while let Some(state) = self.stack.pop() {
            budget.charge(1)?;
            let state_index = usize::try_from(state).ok()?;
            let mark = self.seen.get_mut(state_index)?;
            if *mark == self.generation {
                continue;
            }
            *mark = self.generation;
            match raw.roles.get(state_index)? {
                StateRole::Accept => return Some(true),
                StateRole::Consume => self.consuming.push(state),
                StateRole::Split => {
                    for edge in state_edges(raw, state_index)? {
                        budget.charge(1)?;
                        let target = *raw.edge_targets.get(edge)?;
                        let target_index = usize::try_from(target).ok()?;
                        if *productive.get(target_index)? {
                            self.stack.push(target);
                        }
                    }
                }
                _ => return None,
            }
        }
        Some(false)
    }
}

/// Derive the bounded two-byte relation from a validated Thompson graph.
///
/// Returning `None` only declines this optional accelerator. It never changes
/// the set of programs accepted by the general compiler.
#[must_use]
pub(crate) fn derive(raw: &RawPlan) -> Option<PrefixRelation> {
    derive_with_limits(raw, PrefixRelationLimits::default())
}

#[allow(
    clippy::too_many_lines,
    reason = "the bounded proof, short-path check, and row grouping are one auditable derivation"
)]
fn derive_with_limits(raw: &RawPlan, limits: PrefixRelationLimits) -> Option<PrefixRelation> {
    let mut budget = Budget::new(limits.max_work);
    let shape = validate_graph(raw, limits, &mut budget)?;
    let productive = build_productive(raw, shape, &mut budget)?;
    let mut closure = ClosureWorkspace::new(shape.states, shape.edges)?;

    // Acceptance in the initial zero-width closure makes a two-byte candidate
    // check unsound: the match need not consume either inspected byte.
    if closure.derive(raw, &[raw.start], &productive, &mut budget)? {
        return None;
    }

    let mut target_indices = filled_vec(shape.states, u32::MAX)?;
    let mut first_targets = reserved_vec(limits.max_first_targets)?;
    for &state in &closure.consuming {
        let state = usize::try_from(state).ok()?;
        for edge in state_edges(raw, state)? {
            budget.charge(1)?;
            let target = usize::try_from(*raw.edge_targets.get(edge)?).ok()?;
            if !*productive.get(target)? {
                continue;
            }
            let existing = *target_indices.get(target)?;
            let index = if existing == u32::MAX {
                if first_targets.len() >= limits.max_first_targets {
                    return None;
                }
                let index = first_targets.len();
                first_targets.push(FirstTarget {
                    state: u32::try_from(target).ok()?,
                    first: Bitmap::EMPTY,
                });
                *target_indices.get_mut(target)? = u32::try_from(index).ok()?;
                index
            } else {
                usize::try_from(existing).ok()?
            };
            first_targets.get_mut(index)?.first.insert_range(
                *raw.byte_starts.get(edge)?,
                *raw.byte_ends.get(edge)?,
                &mut budget,
            )?;
        }
    }

    let mut rows = [Bitmap::EMPTY; 256];
    for first_target in first_targets {
        if closure.derive(raw, &[first_target.state], &productive, &mut budget)? {
            // At least one graph path accepts after a single consumed byte.
            return None;
        }
        let mut second = Bitmap::EMPTY;
        for &state in &closure.consuming {
            let state = usize::try_from(state).ok()?;
            for edge in state_edges(raw, state)? {
                budget.charge(1)?;
                let target = usize::try_from(*raw.edge_targets.get(edge)?).ok()?;
                if *productive.get(target)? {
                    second.insert_range(
                        *raw.byte_starts.get(edge)?,
                        *raw.byte_ends.get(edge)?,
                        &mut budget,
                    )?;
                }
            }
        }
        if second.is_empty() {
            continue;
        }
        for first in first_target.first.members() {
            budget.charge(1)?;
            rows[usize::from(first)].union(second, &mut budget)?;
        }
    }

    let mut groups: Vec<PrefixRelationGroup> = reserved_vec(limits.max_groups)?;
    let mut viable_first = Bitmap::EMPTY;
    let mut pair_count = 0_u32;
    for (first, row) in rows.iter().copied().enumerate() {
        budget.charge(1)?;
        if row.is_empty() {
            continue;
        }
        let first = u8::try_from(first).ok()?;
        viable_first.insert(first);
        pair_count = pair_count.checked_add(row.cardinality())?;
        let mut found = None;
        for (index, group) in groups.iter().enumerate() {
            budget.charge(1)?;
            if Bitmap::from_set(group.second) == row {
                found = Some(index);
                break;
            }
        }
        if let Some(index) = found {
            let mut first_set = Bitmap::from_set(groups.get(index)?.first);
            first_set.insert(first);
            groups.get_mut(index)?.first = first_set.into_set();
        } else {
            if groups.len() >= limits.max_groups {
                return None;
            }
            let mut first_set = Bitmap::EMPTY;
            first_set.insert(first);
            groups.push(PrefixRelationGroup {
                first: first_set.into_set(),
                second: row.into_set(),
            });
        }
    }
    if groups.is_empty() {
        return None;
    }
    Some(PrefixRelation {
        groups,
        viable_first: viable_first.into_set(),
        pair_count,
        derivation_work: budget.used,
        context_assertions: shape.context_assertions,
    })
}

#[cfg(test)]
mod tests {
    use fre_automata::{Automaton, CompileLimits as AutomatonLimits};
    use fre_lower::{LowerLimits, OperationSemantics};
    use fre_syntax::{CanonicalPattern, CompatibilityProfile, ParseRequest, RustProfile};

    use super::*;

    type TestEdge = (u32, EdgeKind, u8, u8);

    fn epsilon(target: u32) -> TestEdge {
        (target, EdgeKind::Epsilon, 0, 0)
    }

    fn assertion(target: u32) -> TestEdge {
        (target, EdgeKind::AssertWordAscii, 0, 0)
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

    #[test]
    fn correlated_alternatives_do_not_form_a_cartesian_product() {
        let relation = derive(&lower("(?:ab|cd|ef)Q")).expect("two-byte relation");
        for first in u8::MIN..=u8::MAX {
            for second in u8::MIN..=u8::MAX {
                let expected =
                    matches!((first, second), (b'a', b'b') | (b'c', b'd') | (b'e', b'f'));
                assert_eq!(
                    relation.contains(first, second),
                    expected,
                    "{first:#04x} {second:#04x}"
                );
            }
        }
        assert_eq!(relation.pair_count(), 3);
        assert_eq!(relation.groups().len(), 3);
    }

    #[test]
    fn equivalent_first_rows_share_one_compact_group() {
        let relation = derive(&lower("(?:a[bc]|d[bc])Q")).expect("two-byte relation");
        assert_eq!(relation.groups().len(), 1);
        assert_eq!(relation.groups()[0].first().cardinality(), 2);
        assert_eq!(relation.groups()[0].second().cardinality(), 2);
        assert_eq!(relation.pair_count(), 4);
    }

    #[test]
    fn any_accepting_path_shorter_than_two_bytes_declines() {
        let one_byte = hand_raw(
            0,
            vec![
                StateRole::Split,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Accept,
            ],
            vec![
                vec![epsilon(1), epsilon(2)],
                vec![byte(4, b'a')],
                vec![byte(3, b'b')],
                vec![byte(4, b'c')],
                vec![],
            ],
        );
        assert!(derive(&one_byte).is_none());

        let zero_byte = hand_raw(
            0,
            vec![StateRole::Split, StateRole::Accept],
            vec![vec![epsilon(1)], vec![]],
        );
        assert!(derive(&zero_byte).is_none());
    }

    #[test]
    fn supported_assertions_are_conservative_zero_width_edges() {
        let raw = hand_raw(
            0,
            vec![
                StateRole::Split,
                StateRole::Consume,
                StateRole::Split,
                StateRole::Consume,
                StateRole::Accept,
            ],
            vec![
                vec![assertion(1)],
                vec![byte(2, b'a')],
                vec![assertion(3)],
                vec![byte(4, b'b')],
                vec![],
            ],
        );
        let relation = derive(&raw).expect("assertion-erased relation");
        assert!(relation.context_assertions());
        assert!(relation.contains(b'a', b'b'));
        assert_eq!(relation.pair_count(), 1);
    }

    #[test]
    fn every_resource_ceiling_declines_safely() {
        let raw = lower("(?:ab|cd)Q");
        let defaults = PrefixRelationLimits::default();
        for limits in [
            PrefixRelationLimits {
                max_states: raw.roles.len().saturating_sub(1),
                ..defaults
            },
            PrefixRelationLimits {
                max_edges: raw.edge_targets.len().saturating_sub(1),
                ..defaults
            },
            PrefixRelationLimits {
                max_first_targets: 0,
                ..defaults
            },
            PrefixRelationLimits {
                max_groups: 1,
                ..defaults
            },
            PrefixRelationLimits {
                max_work: 1,
                ..defaults
            },
            PrefixRelationLimits {
                max_memory_bytes: 1,
                ..defaults
            },
        ] {
            assert!(derive_with_limits(&raw, limits).is_none(), "{limits:?}");
        }
    }

    /// Independent anchored NFA oracle. The consumed depth saturates at two:
    /// after checking the requested pair, all later byte ranges are possible.
    struct Oracle {
        marks: Vec<[u32; 3]>,
        generation: u32,
        stack: Vec<(u32, u8)>,
    }

    impl Oracle {
        fn new(states: usize) -> Self {
            Self {
                marks: vec![[0; 3]; states],
                generation: 0,
                stack: Vec::with_capacity(states.saturating_mul(3)),
            }
        }

        fn run(&mut self, raw: &RawPlan, pair: [u8; 2]) -> (bool, bool) {
            self.generation = self.generation.checked_add(1).expect("oracle generation");
            self.stack.clear();
            self.stack.push((raw.start, 0_u8));
            let mut short = false;
            let mut viable = false;
            while let Some((state, depth)) = self.stack.pop() {
                let state_index = usize::try_from(state).expect("oracle state");
                let mark = &mut self.marks[state_index][usize::from(depth)];
                if *mark == self.generation {
                    continue;
                }
                *mark = self.generation;
                match raw.roles[state_index] {
                    StateRole::Accept => {
                        if depth < 2 {
                            short = true;
                        } else {
                            viable = true;
                        }
                    }
                    StateRole::Split => {
                        for edge in state_edges(raw, state_index).expect("oracle split row") {
                            assert!(supported_zero_width(raw.edge_kinds[edge]));
                            self.stack.push((raw.edge_targets[edge], depth));
                        }
                    }
                    StateRole::Consume => {
                        for edge in state_edges(raw, state_index).expect("oracle consume row") {
                            let matches = depth >= 2
                                || (raw.byte_starts[edge]..=raw.byte_ends[edge])
                                    .contains(&pair[usize::from(depth)]);
                            if matches {
                                self.stack
                                    .push((raw.edge_targets[edge], depth.saturating_add(1).min(2)));
                            }
                        }
                    }
                    _ => panic!("oracle received an unknown state role"),
                }
            }
            (short, viable)
        }
    }

    fn generated_range(choice: u8) -> (u8, u8) {
        match choice {
            0 => (0, 0),
            1 => (1, 1),
            2 => (0, 1),
            3 => (128, 255),
            _ => unreachable!("generated range choice"),
        }
    }

    fn generated_graph(
        first_left: u8,
        first_right: u8,
        second_left: u8,
        second_right: u8,
    ) -> RawPlan {
        let (fls, fle) = generated_range(first_left);
        let (frs, fre) = generated_range(first_right);
        let (sls, sle) = generated_range(second_left);
        let (srs, sre) = generated_range(second_right);
        hand_raw(
            0,
            vec![
                StateRole::Split,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Split,
                StateRole::Split,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Accept,
            ],
            vec![
                vec![epsilon(1), epsilon(2)],
                vec![byte_range(3, fls, fle)],
                vec![byte_range(4, frs, fre)],
                vec![epsilon(3), assertion(5)],
                vec![epsilon(4), epsilon(6)],
                vec![byte_range(7, sls, sle)],
                vec![byte_range(7, srs, sre)],
                vec![byte_range(8, 0, 255)],
                vec![],
            ],
        )
    }

    #[test]
    fn generated_graph_relation_matches_independent_oracle_for_every_byte_pair() {
        for first_left in 0..4 {
            for first_right in 0..4 {
                for second_left in 0..4 {
                    for second_right in 0..4 {
                        let raw =
                            generated_graph(first_left, first_right, second_left, second_right);
                        let relation = derive(&raw).expect("generated relation");
                        let mut oracle = Oracle::new(raw.roles.len());
                        for first in u8::MIN..=u8::MAX {
                            for second in u8::MIN..=u8::MAX {
                                let (short, viable) = oracle.run(&raw, [first, second]);
                                assert!(!short);
                                assert_eq!(
                                    relation.contains(first, second),
                                    viable,
                                    "choices {first_left} {first_right} {second_left} {second_right}; pair {first:#04x} {second:#04x}"
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}
