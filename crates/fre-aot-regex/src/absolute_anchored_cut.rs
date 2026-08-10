//! Bounded graph proof for removable absolute-boundary assertion cuts.
//!
//! The proof is deliberately edge-specific. A haystack-start edge is
//! removable only when it is a first such edge on a productive path and every
//! pre-cut path reaches it before consuming a byte. A haystack-end edge is
//! removable only when it is a last such edge and every productive suffix
//! consumes zero bytes. Repeated assertions on the other side of either cut
//! remain visible and force the assertion-free candidate to decline.

#![allow(
    dead_code,
    clippy::arithmetic_side_effects,
    reason = "the staged proof is consumed by the following exact-width lowering commit; checked resource arithmetic and validated CSR indices guard graph traversal"
)]

use core::mem::size_of;

use fre_automata::{EdgeKind, RawPlan, StateRole};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AbsoluteAnchoredBounds {
    pub(crate) requires_start: bool,
    pub(crate) requires_end: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AbsoluteAnchoredCutLimits {
    pub(crate) max_work: u64,
    pub(crate) max_allocation_bytes: usize,
}

#[derive(Debug)]
pub(crate) struct RelaxedAbsoluteAnchoredPlan {
    pub(crate) raw: RawPlan,
    pub(crate) bounds: AbsoluteAnchoredBounds,
    pub(crate) proof_work: u64,
    pub(crate) allocation_bytes: usize,
    #[cfg(test)]
    pub(crate) relaxed_productive_edges: usize,
}

#[derive(Clone, Copy, Debug)]
struct Budget {
    limits: AbsoluteAnchoredCutLimits,
    work: u64,
    allocation_bytes: usize,
}

impl Budget {
    const fn new(limits: AbsoluteAnchoredCutLimits) -> Self {
        Self {
            limits,
            work: 0,
            allocation_bytes: 0,
        }
    }

    fn charge(&mut self, amount: usize) -> Option<()> {
        let amount = u64::try_from(amount).ok()?;
        let next = self.work.checked_add(amount)?;
        if next > self.limits.max_work {
            return None;
        }
        self.work = next;
        Some(())
    }

    fn reserve<T>(&mut self, values: &mut Vec<T>, additional: usize) -> Option<()> {
        let bytes = additional.checked_mul(size_of::<T>())?;
        let next = self.allocation_bytes.checked_add(bytes)?;
        if next > self.limits.max_allocation_bytes {
            return None;
        }
        values.try_reserve_exact(additional).ok()?;
        self.allocation_bytes = next;
        Some(())
    }

    fn filled<T: Clone>(&mut self, length: usize, value: T) -> Option<Vec<T>> {
        let mut values = Vec::new();
        self.reserve(&mut values, length)?;
        self.charge(length)?;
        values.resize(length, value);
        Some(values)
    }

    fn copy<T: Copy>(&mut self, source: &[T]) -> Option<Vec<T>> {
        let mut values = Vec::new();
        self.reserve(&mut values, source.len())?;
        self.charge(source.len())?;
        values.extend_from_slice(source);
        Some(values)
    }
}

#[derive(Debug)]
struct ProductiveGraph<'a> {
    raw: &'a RawPlan,
    sources: Vec<usize>,
    incoming_offsets: Vec<usize>,
    incoming_edges: Vec<usize>,
    reachable: Vec<bool>,
    coreachable: Vec<bool>,
}

impl<'a> ProductiveGraph<'a> {
    fn build(raw: &'a RawPlan, budget: &mut Budget) -> Option<Self> {
        validate_shape(raw, budget)?;
        let states = raw.roles.len();
        let edges = raw.edge_targets.len();
        let mut sources = budget.filled(edges, 0_usize)?;
        let mut incoming_degrees = budget.filled(states, 0_usize)?;
        for source in 0..states {
            for edge in state_edges(raw, source)? {
                budget.charge(1)?;
                sources[edge] = source;
                let target = usize::try_from(raw.edge_targets[edge]).ok()?;
                incoming_degrees[target] = incoming_degrees[target].checked_add(1)?;
            }
        }

        let offset_slots = states.checked_add(1)?;
        let mut incoming_offsets = budget.filled(offset_slots, 0_usize)?;
        for state in 0..states {
            budget.charge(1)?;
            incoming_offsets[state + 1] =
                incoming_offsets[state].checked_add(incoming_degrees[state])?;
        }
        if incoming_offsets[states] != edges {
            return None;
        }
        let mut incoming_edges = budget.filled(edges, 0_usize)?;
        let mut cursors = budget.copy(&incoming_offsets[..states])?;
        for (edge, &target) in raw.edge_targets.iter().enumerate() {
            budget.charge(1)?;
            let target = usize::try_from(target).ok()?;
            let slot = *cursors.get(target)?;
            *incoming_edges.get_mut(slot)? = edge;
            cursors[target] = slot.checked_add(1)?;
        }
        drop(cursors);
        drop(incoming_degrees);

        let mut reachable = budget.filled(states, false)?;
        let mut stack = Vec::new();
        budget.reserve(&mut stack, states)?;
        let start = usize::try_from(raw.start).ok()?;
        reachable[start] = true;
        stack.push(start);
        while let Some(source) = stack.pop() {
            budget.charge(1)?;
            for edge in state_edges(raw, source)? {
                budget.charge(1)?;
                let target = usize::try_from(raw.edge_targets[edge]).ok()?;
                if !reachable[target] {
                    reachable[target] = true;
                    stack.push(target);
                }
            }
        }

        let mut coreachable = budget.filled(states, false)?;
        stack.clear();
        for (state, &role) in raw.roles.iter().enumerate() {
            budget.charge(1)?;
            if role == StateRole::Accept && reachable[state] {
                coreachable[state] = true;
                stack.push(state);
            }
        }
        if stack.is_empty() {
            return None;
        }
        while let Some(target) = stack.pop() {
            budget.charge(1)?;
            let begin = *incoming_offsets.get(target)?;
            let end = *incoming_offsets.get(target.checked_add(1)?)?;
            for &edge in incoming_edges.get(begin..end)? {
                budget.charge(1)?;
                let source = sources[edge];
                if !coreachable[source] {
                    coreachable[source] = true;
                    stack.push(source);
                }
            }
        }

        Some(Self {
            raw,
            sources,
            incoming_offsets,
            incoming_edges,
            reachable,
            coreachable,
        })
    }

    fn productive_edge(&self, edge: usize) -> bool {
        self.sources
            .get(edge)
            .and_then(|&source| self.reachable.get(source))
            .copied()
            == Some(true)
            && self
                .raw
                .edge_targets
                .get(edge)
                .and_then(|&target| usize::try_from(target).ok())
                .and_then(|target| self.coreachable.get(target))
                .copied()
                == Some(true)
    }

    fn forward_without(
        &self,
        blocked: EdgeKind,
        budget: &mut Budget,
    ) -> Option<Vec<u8>> {
        let states = self.raw.roles.len();
        let mut flags = budget.filled(states, 0_u8)?;
        let queue_slots = states.checked_mul(2)?;
        let mut stack = Vec::new();
        budget.reserve(&mut stack, queue_slots)?;
        let start = usize::try_from(self.raw.start).ok()?;
        flags[start] = 1;
        stack.push(start.checked_mul(2)?);
        while let Some(item) = stack.pop() {
            budget.charge(1)?;
            let source = item / 2;
            let consumed = item & 1 != 0;
            for edge in state_edges(self.raw, source)? {
                budget.charge(1)?;
                if !self.productive_edge(edge) || self.raw.edge_kinds[edge] == blocked {
                    continue;
                }
                let target = usize::try_from(self.raw.edge_targets[edge]).ok()?;
                let next_consumed = consumed || self.raw.edge_kinds[edge] == EdgeKind::ByteRange;
                let bit = if next_consumed { 2_u8 } else { 1_u8 };
                if flags[target] & bit == 0 {
                    flags[target] |= bit;
                    stack.push(
                        target
                            .checked_mul(2)?
                            .checked_add(if next_consumed { 1 } else { 0 })?,
                    );
                }
            }
        }
        Some(flags)
    }

    fn reverse_without(
        &self,
        blocked: EdgeKind,
        budget: &mut Budget,
    ) -> Option<Vec<u8>> {
        let states = self.raw.roles.len();
        let mut flags = budget.filled(states, 0_u8)?;
        let queue_slots = states.checked_mul(2)?;
        let mut stack = Vec::new();
        budget.reserve(&mut stack, queue_slots)?;
        for (state, &role) in self.raw.roles.iter().enumerate() {
            budget.charge(1)?;
            if role == StateRole::Accept && self.reachable[state] {
                flags[state] = 1;
                stack.push(state.checked_mul(2)?);
            }
        }
        while let Some(item) = stack.pop() {
            budget.charge(1)?;
            let target = item / 2;
            let consumed = item & 1 != 0;
            let begin = *self.incoming_offsets.get(target)?;
            let end = *self.incoming_offsets.get(target.checked_add(1)?)?;
            for &edge in self.incoming_edges.get(begin..end)? {
                budget.charge(1)?;
                if !self.productive_edge(edge) || self.raw.edge_kinds[edge] == blocked {
                    continue;
                }
                let source = self.sources[edge];
                let next_consumed = consumed || self.raw.edge_kinds[edge] == EdgeKind::ByteRange;
                let bit = if next_consumed { 2_u8 } else { 1_u8 };
                if flags[source] & bit == 0 {
                    flags[source] |= bit;
                    stack.push(
                        source
                            .checked_mul(2)?
                            .checked_add(if next_consumed { 1 } else { 0 })?,
                    );
                }
            }
        }
        Some(flags)
    }

    fn first_zero_cut(
        &self,
        kind: EdgeKind,
        budget: &mut Budget,
        relaxed: &mut [bool],
    ) -> Option<bool> {
        let flags = self.forward_without(kind, budget)?;
        if self
            .raw
            .roles
            .iter()
            .enumerate()
            .any(|(state, &role)| role == StateRole::Accept && flags[state] != 0)
        {
            return Some(false);
        }
        let mut selected = 0_usize;
        for (edge, &edge_kind) in self.raw.edge_kinds.iter().enumerate() {
            budget.charge(1)?;
            if edge_kind != kind || !self.productive_edge(edge) {
                continue;
            }
            let source = self.sources[edge];
            if flags[source] == 0 {
                continue;
            }
            if flags[source] & 2 != 0 {
                return Some(false);
            }
            *relaxed.get_mut(edge)? = true;
            selected = selected.checked_add(1)?;
        }
        Some(selected != 0)
    }

    fn last_zero_cut(
        &self,
        kind: EdgeKind,
        budget: &mut Budget,
        relaxed: &mut [bool],
    ) -> Option<bool> {
        let flags = self.reverse_without(kind, budget)?;
        let start = usize::try_from(self.raw.start).ok()?;
        if flags[start] != 0 {
            return Some(false);
        }
        let mut selected = 0_usize;
        for (edge, &edge_kind) in self.raw.edge_kinds.iter().enumerate() {
            budget.charge(1)?;
            if edge_kind != kind || !self.productive_edge(edge) {
                continue;
            }
            let target = usize::try_from(self.raw.edge_targets[edge]).ok()?;
            if flags[target] == 0 {
                continue;
            }
            if flags[target] & 2 != 0 {
                return Some(false);
            }
            *relaxed.get_mut(edge)? = true;
            selected = selected.checked_add(1)?;
        }
        Some(selected != 0)
    }
}

fn validate_shape(raw: &RawPlan, budget: &mut Budget) -> Option<()> {
    let states = raw.roles.len();
    let edges = raw.edge_targets.len();
    let start = usize::try_from(raw.start).ok()?;
    budget.charge(states.checked_add(edges)?)?;
    if states == 0
        || start >= states
        || raw.edge_offsets.len() != states.checked_add(1)?
        || raw.edge_kinds.len() != edges
        || raw.byte_starts.len() != edges
        || raw.byte_ends.len() != edges
        || raw.edge_offsets.first().copied() != Some(0)
        || usize::try_from(*raw.edge_offsets.last()?).ok()? != edges
    {
        return None;
    }
    let mut has_accept = false;
    for state in 0..states {
        let row = state_edges(raw, state)?;
        match raw.roles[state] {
            StateRole::Accept => {
                if !row.is_empty() {
                    return None;
                }
                has_accept = true;
            }
            StateRole::Consume => {
                for edge in row {
                    let target = usize::try_from(raw.edge_targets[edge]).ok()?;
                    if target >= states
                        || raw.edge_kinds[edge] != EdgeKind::ByteRange
                        || raw.byte_starts[edge] > raw.byte_ends[edge]
                    {
                        return None;
                    }
                }
            }
            StateRole::Split => {
                for edge in row {
                    let target = usize::try_from(raw.edge_targets[edge]).ok()?;
                    if target >= states
                        || raw.edge_kinds[edge] == EdgeKind::ByteRange
                        || raw.byte_starts[edge] != 0
                        || raw.byte_ends[edge] != 0
                    {
                        return None;
                    }
                }
            }
            _ => return None,
        }
    }
    has_accept.then_some(())
}

fn state_edges(raw: &RawPlan, state: usize) -> Option<core::ops::Range<usize>> {
    let begin = usize::try_from(*raw.edge_offsets.get(state)?).ok()?;
    let end = usize::try_from(*raw.edge_offsets.get(state.checked_add(1)?)?).ok()?;
    (begin <= end && end <= raw.edge_targets.len()).then_some(begin..end)
}

fn is_assertion(kind: EdgeKind) -> bool {
    !matches!(kind, EdgeKind::Epsilon | EdgeKind::ByteRange)
}

fn clone_with_relaxed_edges(
    raw: &RawPlan,
    relaxed: &[bool],
    budget: &mut Budget,
) -> Option<RawPlan> {
    if relaxed.len() != raw.edge_kinds.len() {
        return None;
    }
    let mut edge_kinds = budget.copy(&raw.edge_kinds)?;
    for (kind, &relax) in edge_kinds.iter_mut().zip(relaxed) {
        budget.charge(1)?;
        if relax {
            *kind = EdgeKind::Epsilon;
        }
    }
    Some(RawPlan {
        start: raw.start,
        roles: budget.copy(&raw.roles)?,
        edge_offsets: budget.copy(&raw.edge_offsets)?,
        edge_targets: budget.copy(&raw.edge_targets)?,
        edge_kinds,
        byte_starts: budget.copy(&raw.byte_starts)?,
        byte_ends: budget.copy(&raw.byte_ends)?,
    })
}

/// Produce an assertion-free clone after proving edge-specific absolute cuts.
///
/// Assertion edges outside the productive graph are also relaxed: changing
/// their truth cannot create a topological path to Accept, and retaining them
/// would needlessly prevent the assertion-free determinizer from consuming
/// the otherwise unchanged graph. Any productive assertion not covered by a
/// proved first-start or last-end cut declines the whole optional candidate.
pub(crate) fn relax_absolute_anchored_cuts(
    raw: &RawPlan,
    limits: AbsoluteAnchoredCutLimits,
) -> Option<RelaxedAbsoluteAnchoredPlan> {
    let mut budget = Budget::new(limits);
    let graph = ProductiveGraph::build(raw, &mut budget)?;
    let mut relaxed = budget.filled(raw.edge_kinds.len(), false)?;

    let requires_start = graph.first_zero_cut(
        EdgeKind::AssertHaystackStart,
        &mut budget,
        &mut relaxed,
    )?;
    let requires_end = graph.last_zero_cut(
        EdgeKind::AssertHaystackEnd,
        &mut budget,
        &mut relaxed,
    )?;
    if !requires_start && !requires_end {
        return None;
    }

    let mut relaxed_productive_edges = 0_usize;
    for (edge, &kind) in raw.edge_kinds.iter().enumerate() {
        budget.charge(1)?;
        if !is_assertion(kind) {
            continue;
        }
        if graph.productive_edge(edge) {
            if !relaxed[edge] {
                return None;
            }
            relaxed_productive_edges = relaxed_productive_edges.checked_add(1)?;
        } else {
            relaxed[edge] = true;
        }
    }
    let raw = clone_with_relaxed_edges(raw, &relaxed, &mut budget)?;
    if raw.edge_kinds.iter().copied().any(is_assertion) {
        return None;
    }
    Some(RelaxedAbsoluteAnchoredPlan {
        raw,
        bounds: AbsoluteAnchoredBounds {
            requires_start,
            requires_end,
        },
        proof_work: budget.work,
        allocation_bytes: budget.allocation_bytes,
        #[cfg(test)]
        relaxed_productive_edges,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(roles: Vec<StateRole>, rows: Vec<Vec<(u32, EdgeKind, u8, u8)>>) -> RawPlan {
        assert_eq!(roles.len(), rows.len());
        let mut edge_offsets = Vec::with_capacity(rows.len() + 1);
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
            edge_offsets.push(u32::try_from(edge_targets.len()).unwrap());
        }
        RawPlan {
            start: 0,
            roles,
            edge_offsets,
            edge_targets,
            edge_kinds,
            byte_starts,
            byte_ends,
        }
    }

    fn limits() -> AbsoluteAnchoredCutLimits {
        AbsoluteAnchoredCutLimits {
            max_work: 100_000,
            max_allocation_bytes: 1 << 20,
        }
    }

    #[test]
    fn first_start_and_last_end_are_relaxed_by_edge() {
        let graph = raw(
            vec![
                StateRole::Split,
                StateRole::Consume,
                StateRole::Split,
                StateRole::Accept,
            ],
            vec![
                vec![(1, EdgeKind::AssertHaystackStart, 0, 0)],
                vec![(2, EdgeKind::ByteRange, b'a', b'a')],
                vec![(3, EdgeKind::AssertHaystackEnd, 0, 0)],
                vec![],
            ],
        );
        let relaxed = relax_absolute_anchored_cuts(&graph, limits()).unwrap();
        assert_eq!(
            relaxed.bounds,
            AbsoluteAnchoredBounds {
                requires_start: true,
                requires_end: true,
            }
        );
        assert_eq!(relaxed.relaxed_productive_edges, 2);
        assert!(
            relaxed
                .raw
                .edge_kinds
                .iter()
                .all(|kind| matches!(kind, EdgeKind::Epsilon | EdgeKind::ByteRange))
        );
    }

    #[test]
    fn repeated_start_after_consumption_is_not_discharged() {
        let graph = raw(
            vec![
                StateRole::Split,
                StateRole::Consume,
                StateRole::Split,
                StateRole::Accept,
            ],
            vec![
                vec![(1, EdgeKind::AssertHaystackStart, 0, 0)],
                vec![(2, EdgeKind::ByteRange, b'a', b'a')],
                vec![(3, EdgeKind::AssertHaystackStart, 0, 0)],
                vec![],
            ],
        );
        assert!(relax_absolute_anchored_cuts(&graph, limits()).is_none());
    }

    #[test]
    fn repeated_end_before_the_last_cut_is_not_discharged() {
        let graph = raw(
            vec![
                StateRole::Split,
                StateRole::Consume,
                StateRole::Split,
                StateRole::Accept,
            ],
            vec![
                vec![(1, EdgeKind::AssertHaystackEnd, 0, 0)],
                vec![(2, EdgeKind::ByteRange, b'a', b'a')],
                vec![(3, EdgeKind::AssertHaystackEnd, 0, 0)],
                vec![],
            ],
        );
        assert!(relax_absolute_anchored_cuts(&graph, limits()).is_none());
    }

    #[test]
    fn alternative_first_start_edges_are_all_discharged() {
        let graph = raw(
            vec![
                StateRole::Split,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Accept,
            ],
            vec![
                vec![
                    (1, EdgeKind::AssertHaystackStart, 0, 0),
                    (2, EdgeKind::AssertHaystackStart, 0, 0),
                ],
                vec![(3, EdgeKind::ByteRange, b'a', b'a')],
                vec![(3, EdgeKind::ByteRange, b'b', b'b')],
                vec![],
            ],
        );
        let relaxed = relax_absolute_anchored_cuts(&graph, limits()).unwrap();
        assert!(relaxed.bounds.requires_start);
        assert!(!relaxed.bounds.requires_end);
        assert_eq!(relaxed.relaxed_productive_edges, 2);
    }

    #[test]
    fn positive_prefix_or_suffix_declines() {
        let late_start = raw(
            vec![StateRole::Consume, StateRole::Split, StateRole::Accept],
            vec![
                vec![(1, EdgeKind::ByteRange, b'a', b'a')],
                vec![(2, EdgeKind::AssertHaystackStart, 0, 0)],
                vec![],
            ],
        );
        assert!(relax_absolute_anchored_cuts(&late_start, limits()).is_none());

        let early_end = raw(
            vec![StateRole::Split, StateRole::Consume, StateRole::Accept],
            vec![
                vec![(1, EdgeKind::AssertHaystackEnd, 0, 0)],
                vec![(2, EdgeKind::ByteRange, b'a', b'a')],
                vec![],
            ],
        );
        assert!(relax_absolute_anchored_cuts(&early_end, limits()).is_none());
    }

    #[test]
    fn productive_internal_assertion_declines_but_dead_assertion_does_not() {
        let productive = raw(
            vec![
                StateRole::Split,
                StateRole::Split,
                StateRole::Consume,
                StateRole::Accept,
            ],
            vec![
                vec![(1, EdgeKind::AssertHaystackStart, 0, 0)],
                vec![(2, EdgeKind::AssertWordAscii, 0, 0)],
                vec![(3, EdgeKind::ByteRange, b'a', b'a')],
                vec![],
            ],
        );
        assert!(relax_absolute_anchored_cuts(&productive, limits()).is_none());

        let dead = raw(
            vec![
                StateRole::Split,
                StateRole::Consume,
                StateRole::Split,
                StateRole::Accept,
                StateRole::Split,
                StateRole::Consume,
            ],
            vec![
                vec![
                    (1, EdgeKind::AssertHaystackStart, 0, 0),
                    (4, EdgeKind::Epsilon, 0, 0),
                ],
                vec![(2, EdgeKind::ByteRange, b'a', b'a')],
                vec![(3, EdgeKind::Epsilon, 0, 0)],
                vec![],
                vec![(5, EdgeKind::AssertWordAscii, 0, 0)],
                vec![(5, EdgeKind::ByteRange, b'x', b'x')],
            ],
        );
        let relaxed = relax_absolute_anchored_cuts(&dead, limits()).unwrap();
        assert!(relaxed.bounds.requires_start);
        assert!(
            relaxed
                .raw
                .edge_kinds
                .iter()
                .all(|kind| matches!(kind, EdgeKind::Epsilon | EdgeKind::ByteRange))
        );
    }

    #[test]
    fn work_and_allocation_limits_decline_transactionally() {
        let graph = raw(
            vec![StateRole::Split, StateRole::Accept],
            vec![
                vec![(1, EdgeKind::AssertHaystackStart, 0, 0)],
                vec![],
            ],
        );
        assert!(
            relax_absolute_anchored_cuts(
                &graph,
                AbsoluteAnchoredCutLimits {
                    max_work: 0,
                    max_allocation_bytes: usize::MAX,
                },
            )
            .is_none()
        );
        assert!(
            relax_absolute_anchored_cuts(
                &graph,
                AbsoluteAnchoredCutLimits {
                    max_work: u64::MAX,
                    max_allocation_bytes: 0,
                },
            )
            .is_none()
        );
    }
}
