//! Deterministic reverse subset construction from an explicit graph boundary.
//!
//! This is deliberately separate from the stable serialized DFA. It is a
//! transactional compiler boundary for native optimizations that need to
//! recover a match start either from every Accept state or from the boundary
//! immediately before one consuming state. The portable trace is the oracle
//! against which future target lowering is compared.

#![allow(
    dead_code,
    reason = "the standalone builder is landed before its native lowering consumer"
)]

use core::mem::size_of;

use fre_automata::{EdgeKind, RawPlan, StateRole};

/// Sentinel used by complete rows for an empty reverse frontier.
pub(crate) const SEEDED_REVERSE_NO_STATE: u32 = u32::MAX;

/// Conservative standalone construction limits.
pub(crate) const MAX_SEEDED_REVERSE_STATES: usize = 262_144;
pub(crate) const MAX_SEEDED_REVERSE_CELLS: usize = 16_777_216;
pub(crate) const MAX_SEEDED_REVERSE_WORK: u64 = 64_000_000;
pub(crate) const MAX_SEEDED_REVERSE_MEMORY_BYTES: usize = 256 * 1024 * 1024;
pub(crate) const MAX_SEEDED_REVERSE_ADDRESS_BYTES: usize = 4_294_967_295_usize;
const MAX_U32_INDEXED_ITEMS: usize = 4_294_967_295_usize;

/// Graph boundary from which reverse recognition starts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SeededReverseSeed {
    /// Seed the zero-width reverse closure from every Accept state.
    AcceptStates,
    /// Seed the boundary immediately before this consuming state.
    RootState(u32),
}

/// Independent ceilings for one seeded reverse construction.
#[allow(
    clippy::struct_field_names,
    reason = "the max prefix makes every independently copied ceiling unambiguous"
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SeededReverseLimits {
    pub(crate) max_states: usize,
    pub(crate) max_cells: usize,
    pub(crate) max_work: u64,
    pub(crate) max_memory_bytes: usize,
    pub(crate) max_addressable_bytes: usize,
}

impl Default for SeededReverseLimits {
    fn default() -> Self {
        Self {
            max_states: MAX_SEEDED_REVERSE_STATES,
            max_cells: MAX_SEEDED_REVERSE_CELLS,
            max_work: MAX_SEEDED_REVERSE_WORK,
            max_memory_bytes: MAX_SEEDED_REVERSE_MEMORY_BYTES,
            max_addressable_bytes: MAX_SEEDED_REVERSE_ADDRESS_BYTES,
        }
    }
}

/// Exact deterministic charges retained on success and decline.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct SeededReverseStats {
    pub(crate) states: usize,
    pub(crate) cells: usize,
    pub(crate) work: u64,
    pub(crate) memory_bytes: usize,
}

/// Independently selectable resource ceilings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SeededReverseResource {
    States,
    Cells,
    Work,
    MemoryBytes,
    AddressableBytes,
}

/// Static graph-shape failures. No partially built machine is returned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SeededReverseGraphIssue {
    Empty,
    StartOutOfRange,
    OffsetShape,
    EdgeTableShape,
    EdgeOffset,
    EdgeTargetOutOfRange,
    StateRoleEdges,
    EdgePayload,
    UnsupportedStateRole,
    UnsupportedEdgeKind,
}

/// Invalid boundary requests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SeededReverseSeedIssue {
    NoAcceptStates,
    RootOutOfRange,
    RootIsNotConsume,
}

/// Invalid or inexact caller-provided alphabet partitions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SeededReverseClassIssue {
    Empty,
    TooMany,
    ClassOutOfRange,
    MissingClass,
    InconsistentRangeMembership,
}

/// Allocation sites are named so allocation failures are diagnosable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SeededReverseAllocation {
    Representatives,
    ClassSeen,
    IncomingSources,
    IncomingOffsets,
    IncomingEdges,
    IncomingDegrees,
    IncomingCursors,
    ClosureSeen,
    ClosureStack,
    ClosureFrontier,
    StateKey,
    States,
    Cells,
}

/// Typed reason for conservative, transactional decline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SeededReverseDeclineReason {
    MalformedGraph(SeededReverseGraphIssue),
    InvalidSeed(SeededReverseSeedIssue),
    InvalidByteClasses(SeededReverseClassIssue),
    /// Context-sensitive assertions require the contextual reverse compiler.
    UnsupportedAssertions,
    Resource {
        resource: SeededReverseResource,
        limit: u64,
        required: u64,
    },
    Allocation(SeededReverseAllocation),
    AddressOverflow,
}

/// Decline report with the deterministic work completed before the failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SeededReverseDecline {
    pub(crate) reason: SeededReverseDeclineReason,
    pub(crate) stats: SeededReverseStats,
}

/// One complete class-mapped reverse transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SeededReverseCell {
    pub(crate) next: u32,
    pub(crate) reaches_start: bool,
}

/// Complete portable machine. State zero is always the seeded initial row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SeededReverseDfa {
    byte_classes: [u8; 256],
    class_count: usize,
    cells: Vec<SeededReverseCell>,
    initial_reaches_start: bool,
    stats: SeededReverseStats,
}

impl SeededReverseDfa {
    pub(crate) const fn byte_classes(&self) -> &[u8; 256] {
        &self.byte_classes
    }

    pub(crate) const fn class_count(&self) -> usize {
        self.class_count
    }

    pub(crate) const fn state_count(&self) -> usize {
        self.stats.states
    }

    pub(crate) fn cells(&self) -> &[SeededReverseCell] {
        &self.cells
    }

    pub(crate) fn row(&self, state: u32) -> Option<&[SeededReverseCell]> {
        let state = usize::try_from(state).ok()?;
        let begin = state.checked_mul(self.class_count)?;
        let end = begin.checked_add(self.class_count)?;
        self.cells.get(begin..end)
    }

    pub(crate) const fn initial_reaches_start(&self) -> bool {
        self.initial_reaches_start
    }

    pub(crate) const fn stats(&self) -> SeededReverseStats {
        self.stats
    }

    /// Produce every recognized start, from `boundary` back to `window_start`.
    ///
    /// The first event can equal `boundary`: it records the explicit
    /// zero-consumed-byte closure fact rather than hiding nullable/root facts
    /// in the first table transition.
    pub(crate) fn trace<'a>(
        &'a self,
        haystack: &'a [u8],
        window_start: usize,
        boundary: usize,
    ) -> Result<SeededReverseTrace<'a>, SeededReverseTraceError> {
        if boundary > haystack.len() {
            return Err(SeededReverseTraceError::BoundaryOutOfRange);
        }
        if window_start > boundary {
            return Err(SeededReverseTraceError::WindowOutOfRange);
        }
        Ok(SeededReverseTrace {
            machine: self,
            haystack,
            window_start,
            cursor: boundary,
            state: 0,
            emit_initial: self.initial_reaches_start,
        })
    }

    /// Portable reference implementation of reverse start recovery.
    pub(crate) fn recover_start(
        &self,
        haystack: &[u8],
        window_start: usize,
        boundary: usize,
    ) -> Result<Option<usize>, SeededReverseTraceError> {
        Ok(self.trace(haystack, window_start, boundary)?.last())
    }
}

/// Exact raw-range alphabet suitable for independently seeded sidecars.
///
/// Classes are dense and representatives are the first byte in each raw
/// boundary interval. This intentionally has no dependency on a completed or
/// coalesced forward DFA.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SeededReverseAlphabet {
    byte_classes: [u8; 256],
    representatives: Vec<u8>,
    stats: SeededReverseStats,
}

impl SeededReverseAlphabet {
    pub(crate) const fn byte_classes(&self) -> &[u8; 256] {
        &self.byte_classes
    }

    pub(crate) fn class_count(&self) -> usize {
        self.representatives.len()
    }

    pub(crate) fn representatives(&self) -> &[u8] {
        &self.representatives
    }

    pub(crate) const fn stats(&self) -> SeededReverseStats {
        self.stats
    }
}

/// Invalid verifier window. A compiled machine itself cannot produce a bad
/// row lookup because its table is complete and its fields are private.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SeededReverseTraceError {
    BoundaryOutOfRange,
    WindowOutOfRange,
}

/// Allocation-free portable verifier trace.
#[derive(Debug)]
pub(crate) struct SeededReverseTrace<'a> {
    machine: &'a SeededReverseDfa,
    haystack: &'a [u8],
    window_start: usize,
    cursor: usize,
    state: u32,
    emit_initial: bool,
}

impl Iterator for SeededReverseTrace<'_> {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        if self.emit_initial {
            self.emit_initial = false;
            return Some(self.cursor);
        }
        while self.cursor > self.window_start && self.state != SEEDED_REVERSE_NO_STATE {
            self.cursor = self.cursor.checked_sub(1)?;
            let byte = *self.haystack.get(self.cursor)?;
            let class = usize::from(self.machine.byte_classes[usize::from(byte)]);
            let state = usize::try_from(self.state).ok()?;
            let row = state.checked_mul(self.machine.class_count)?;
            let index = row.checked_add(class)?;
            let cell = *self.machine.cells.get(index)?;
            self.state = cell.next;
            if cell.reaches_start {
                return Some(self.cursor);
            }
        }
        None
    }
}

/// Transactional construction result. Decline never exposes partial rows.
#[allow(
    clippy::large_enum_variant,
    reason = "boxing would add an unbudgeted allocation to the transactional result boundary"
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SeededReverseBuild {
    Complete(SeededReverseDfa),
    Declined(SeededReverseDecline),
}

impl SeededReverseBuild {
    fn declined(reason: SeededReverseDeclineReason, budget: &Budget) -> Self {
        Self::Declined(SeededReverseDecline {
            reason,
            stats: budget.stats,
        })
    }
}

/// Build a deterministic reverse machine over an exact dense byte partition.
///
/// `byte_classes` must use every class in `0..class_count`, and every byte in
/// one class must have identical membership in every consuming range. This
/// makes choosing the minimum byte as a deterministic representative exact.
pub(crate) fn build_seeded_reverse(
    raw: &RawPlan,
    byte_classes: &[u8; 256],
    class_count: usize,
    seed: SeededReverseSeed,
    limits: SeededReverseLimits,
) -> SeededReverseBuild {
    let mut budget = Budget::new(limits);
    match build(raw, byte_classes, class_count, seed, &mut budget) {
        Ok(machine) => SeededReverseBuild::Complete(machine),
        Err(reason) => SeededReverseBuild::declined(reason, &budget),
    }
}

/// Build a seeded reverse machine from the raw graph's exact byte boundaries.
///
/// This is the native-sidecar entry point. It deliberately does not consume a
/// completed forward DFA's byte classes: whole-DFA column coalescing may merge
/// bytes whose full-search behavior is equivalent even though their incoming
/// membership at one interior root differs. Splitting at every raw range
/// start and one-past-end boundary preserves membership in every consuming
/// edge and is therefore exact for every seed, including [`SeededReverseSeed::RootState`].
pub(crate) fn build_seeded_reverse_exact(
    raw: &RawPlan,
    seed: SeededReverseSeed,
    limits: SeededReverseLimits,
) -> SeededReverseBuild {
    let mut budget = Budget::new(limits);
    match build_exact(raw, seed, &mut budget) {
        Ok(machine) => SeededReverseBuild::Complete(machine),
        Err(reason) => SeededReverseBuild::declined(reason, &budget),
    }
}

/// Derive only the exact raw byte-boundary alphabet.
///
/// This is useful when a native lowering needs to size or rank a prospective
/// sidecar before constructing it. The same validation and explicit resource
/// accounting used by [`build_seeded_reverse_exact`] applies here.
pub(crate) fn exact_byte_classes(
    raw: &RawPlan,
    limits: SeededReverseLimits,
) -> Result<SeededReverseAlphabet, SeededReverseDecline> {
    let mut budget = Budget::new(limits);
    let result =
        validate_raw(raw, &mut budget).and_then(|()| build_exact_alphabet(raw, &mut budget));
    match result {
        Ok((byte_classes, representatives)) => Ok(SeededReverseAlphabet {
            byte_classes,
            representatives,
            stats: budget.stats,
        }),
        Err(reason) => Err(SeededReverseDecline {
            reason,
            stats: budget.stats,
        }),
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the transactional worklist is kept contiguous for an auditable budget boundary"
)]
fn build(
    raw: &RawPlan,
    byte_classes: &[u8; 256],
    class_count: usize,
    seed: SeededReverseSeed,
    budget: &mut Budget,
) -> Result<SeededReverseDfa, SeededReverseDeclineReason> {
    validate_raw(raw, budget)?;
    let roots = validate_seed(raw, seed, budget)?;
    let representatives = validate_classes(raw, byte_classes, class_count, budget)?;
    build_validated(raw, *byte_classes, representatives, roots, budget)
}

fn build_exact(
    raw: &RawPlan,
    seed: SeededReverseSeed,
    budget: &mut Budget,
) -> Result<SeededReverseDfa, SeededReverseDeclineReason> {
    validate_raw(raw, budget)?;
    let roots = validate_seed(raw, seed, budget)?;
    let (byte_classes, representatives) = build_exact_alphabet(raw, budget)?;
    build_validated(raw, byte_classes, representatives, roots, budget)
}

fn build_validated(
    raw: &RawPlan,
    byte_classes: [u8; 256],
    representatives: Vec<u8>,
    roots: SeedRoots,
    budget: &mut Budget,
) -> Result<SeededReverseDfa, SeededReverseDeclineReason> {
    let class_count = representatives.len();
    let incoming = Incoming::build(raw, budget)?;
    let mut closure = ReverseClosure::new(raw, budget)?;

    closure.begin();
    let mut initial_reaches_start = false;
    match roots {
        SeedRoots::AcceptStates => {
            for (state, role) in raw.roles.iter().copied().enumerate() {
                budget.work(1)?;
                if role == StateRole::Accept {
                    let state = u32::try_from(state)
                        .map_err(|_| SeededReverseDeclineReason::AddressOverflow)?;
                    initial_reaches_start |= closure.expand(raw, &incoming, state, budget)?;
                }
            }
        }
        SeedRoots::RootState(root) => {
            initial_reaches_start |= closure.expand(raw, &incoming, root, budget)?;
        }
    }

    let mut states = Vec::<Vec<u32>>::new();
    let mut cells = Vec::<SeededReverseCell>::new();
    push_state(
        &mut states,
        &mut cells,
        class_count,
        closure.frontier(),
        budget,
    )?;

    let mut cursor = 0usize;
    while cursor < states.len() {
        for &byte in &representatives {
            budget.work(1)?;
            closure.begin();
            let key = states
                .get(cursor)
                .ok_or(SeededReverseDeclineReason::AddressOverflow)?;
            let mut reaches_start = false;
            for &incoming_edge in key {
                budget.work(1)?;
                let edge = usize::try_from(incoming_edge)
                    .map_err(|_| SeededReverseDeclineReason::AddressOverflow)?;
                if raw.byte_starts[edge] <= byte && byte <= raw.byte_ends[edge] {
                    reaches_start |=
                        closure.expand(raw, &incoming, incoming.sources[edge], budget)?;
                }
            }
            let next = if closure.frontier().is_empty() {
                SEEDED_REVERSE_NO_STATE
            } else if let Some(known) = find_state(&states, closure.frontier(), budget)? {
                known
            } else {
                push_state(
                    &mut states,
                    &mut cells,
                    class_count,
                    closure.frontier(),
                    budget,
                )?
            };
            push_cell(
                &mut cells,
                SeededReverseCell {
                    next,
                    reaches_start,
                },
                budget,
            )?;
        }
        cursor = cursor
            .checked_add(1)
            .ok_or(SeededReverseDeclineReason::AddressOverflow)?;
    }

    let expected = states
        .len()
        .checked_mul(class_count)
        .ok_or(SeededReverseDeclineReason::AddressOverflow)?;
    if cells.len() != expected {
        return Err(SeededReverseDeclineReason::AddressOverflow);
    }
    budget.stats.states = states.len();
    budget.stats.cells = cells.len();
    Ok(SeededReverseDfa {
        byte_classes,
        class_count,
        cells,
        initial_reaches_start,
        stats: budget.stats,
    })
}

/// Construct the coarsest interval alphabet induced by every raw byte range.
///
/// `validate_raw` has already established that every byte range is ordered.
/// A membership bit can change only at its inclusive start or immediately
/// after its inclusive end, so bytes inside one resulting interval have an
/// identical membership vector across all consuming edges. The fixed boundary
/// workspace avoids an allocation before the exact class count is known.
fn build_exact_alphabet(
    raw: &RawPlan,
    budget: &mut Budget,
) -> Result<([u8; 256], Vec<u8>), SeededReverseDeclineReason> {
    let mut boundaries = [false; 257];
    boundaries[0] = true;
    boundaries[256] = true;
    for (edge, kind) in raw.edge_kinds.iter().copied().enumerate() {
        budget.work(1)?;
        if kind != EdgeKind::ByteRange {
            continue;
        }
        let start = usize::from(raw.byte_starts[edge]);
        let end = usize::from(raw.byte_ends[edge])
            .checked_add(1)
            .ok_or(SeededReverseDeclineReason::AddressOverflow)?;
        boundaries[start] = true;
        boundaries[end] = true;
    }

    let mut byte_classes = [0_u8; 256];
    let mut representative_storage = [0_u8; 256];
    let mut class_count = 0_usize;
    for byte in 0_u16..=u16::from(u8::MAX) {
        budget.work(1)?;
        let byte = u8::try_from(byte).map_err(|_| SeededReverseDeclineReason::AddressOverflow)?;
        let byte_index = usize::from(byte);
        if boundaries[byte_index] {
            let slot = representative_storage
                .get_mut(class_count)
                .ok_or(SeededReverseDeclineReason::AddressOverflow)?;
            *slot = byte;
            class_count = class_count
                .checked_add(1)
                .ok_or(SeededReverseDeclineReason::AddressOverflow)?;
        }
        let class = class_count
            .checked_sub(1)
            .ok_or(SeededReverseDeclineReason::AddressOverflow)?;
        byte_classes[byte_index] =
            u8::try_from(class).map_err(|_| SeededReverseDeclineReason::AddressOverflow)?;
    }
    if class_count == 0 || class_count > 256 {
        return Err(SeededReverseDeclineReason::AddressOverflow);
    }
    let representatives = clone_slice(
        &representative_storage[..class_count],
        budget,
        SeededReverseAllocation::Representatives,
    )?;
    Ok((byte_classes, representatives))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SeedRoots {
    AcceptStates,
    RootState(u32),
}

fn validate_seed(
    raw: &RawPlan,
    seed: SeededReverseSeed,
    budget: &mut Budget,
) -> Result<SeedRoots, SeededReverseDeclineReason> {
    match seed {
        SeededReverseSeed::AcceptStates => {
            for role in &raw.roles {
                budget.work(1)?;
                if *role == StateRole::Accept {
                    return Ok(SeedRoots::AcceptStates);
                }
            }
            Err(SeededReverseDeclineReason::InvalidSeed(
                SeededReverseSeedIssue::NoAcceptStates,
            ))
        }
        SeededReverseSeed::RootState(root) => {
            budget.work(1)?;
            let root =
                usize::try_from(root).map_err(|_| SeededReverseDeclineReason::AddressOverflow)?;
            let Some(role) = raw.roles.get(root).copied() else {
                return Err(SeededReverseDeclineReason::InvalidSeed(
                    SeededReverseSeedIssue::RootOutOfRange,
                ));
            };
            if role != StateRole::Consume {
                return Err(SeededReverseDeclineReason::InvalidSeed(
                    SeededReverseSeedIssue::RootIsNotConsume,
                ));
            }
            Ok(SeedRoots::RootState(u32::try_from(root).map_err(|_| {
                SeededReverseDeclineReason::AddressOverflow
            })?))
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "all RawPlan invariants are checked before the first graph allocation"
)]
fn validate_raw(raw: &RawPlan, budget: &mut Budget) -> Result<(), SeededReverseDeclineReason> {
    budget.work(1)?;
    let states = raw.roles.len();
    if states == 0 {
        return Err(SeededReverseDeclineReason::MalformedGraph(
            SeededReverseGraphIssue::Empty,
        ));
    }
    if states > MAX_U32_INDEXED_ITEMS {
        return Err(SeededReverseDeclineReason::AddressOverflow);
    }
    let start =
        usize::try_from(raw.start).map_err(|_| SeededReverseDeclineReason::AddressOverflow)?;
    if start >= states {
        return Err(SeededReverseDeclineReason::MalformedGraph(
            SeededReverseGraphIssue::StartOutOfRange,
        ));
    }
    let expected_offsets = states
        .checked_add(1)
        .ok_or(SeededReverseDeclineReason::AddressOverflow)?;
    if raw.edge_offsets.len() != expected_offsets {
        return Err(SeededReverseDeclineReason::MalformedGraph(
            SeededReverseGraphIssue::OffsetShape,
        ));
    }
    let edges = raw.edge_targets.len();
    if raw.edge_kinds.len() != edges
        || raw.byte_starts.len() != edges
        || raw.byte_ends.len() != edges
    {
        return Err(SeededReverseDeclineReason::MalformedGraph(
            SeededReverseGraphIssue::EdgeTableShape,
        ));
    }
    if edges > MAX_U32_INDEXED_ITEMS {
        return Err(SeededReverseDeclineReason::AddressOverflow);
    }
    if raw.edge_offsets.first().copied() != Some(0)
        || usize::try_from(raw.edge_offsets[states]).ok() != Some(edges)
    {
        return Err(SeededReverseDeclineReason::MalformedGraph(
            SeededReverseGraphIssue::EdgeOffset,
        ));
    }

    for (state, role) in raw.roles.iter().copied().enumerate() {
        budget.work(1)?;
        match role {
            StateRole::Split | StateRole::Consume | StateRole::Accept => {}
            _ => {
                return Err(SeededReverseDeclineReason::MalformedGraph(
                    SeededReverseGraphIssue::UnsupportedStateRole,
                ));
            }
        }
        let begin = usize::try_from(raw.edge_offsets[state])
            .map_err(|_| SeededReverseDeclineReason::AddressOverflow)?;
        let next_state = state
            .checked_add(1)
            .ok_or(SeededReverseDeclineReason::AddressOverflow)?;
        let end = usize::try_from(raw.edge_offsets[next_state])
            .map_err(|_| SeededReverseDeclineReason::AddressOverflow)?;
        if begin > end || end > edges {
            return Err(SeededReverseDeclineReason::MalformedGraph(
                SeededReverseGraphIssue::EdgeOffset,
            ));
        }
        if role == StateRole::Accept && begin != end {
            return Err(SeededReverseDeclineReason::MalformedGraph(
                SeededReverseGraphIssue::StateRoleEdges,
            ));
        }
        for edge in begin..end {
            budget.work(1)?;
            let target = usize::try_from(raw.edge_targets[edge])
                .map_err(|_| SeededReverseDeclineReason::AddressOverflow)?;
            if target >= states {
                return Err(SeededReverseDeclineReason::MalformedGraph(
                    SeededReverseGraphIssue::EdgeTargetOutOfRange,
                ));
            }
            let kind = raw.edge_kinds[edge];
            if is_assertion(kind) {
                return Err(SeededReverseDeclineReason::UnsupportedAssertions);
            }
            match kind {
                EdgeKind::Epsilon => {
                    if role != StateRole::Split {
                        return Err(SeededReverseDeclineReason::MalformedGraph(
                            SeededReverseGraphIssue::StateRoleEdges,
                        ));
                    }
                    if raw.byte_starts[edge] != 0 || raw.byte_ends[edge] != 0 {
                        return Err(SeededReverseDeclineReason::MalformedGraph(
                            SeededReverseGraphIssue::EdgePayload,
                        ));
                    }
                }
                EdgeKind::ByteRange => {
                    if role != StateRole::Consume {
                        return Err(SeededReverseDeclineReason::MalformedGraph(
                            SeededReverseGraphIssue::StateRoleEdges,
                        ));
                    }
                    if raw.byte_starts[edge] > raw.byte_ends[edge] {
                        return Err(SeededReverseDeclineReason::MalformedGraph(
                            SeededReverseGraphIssue::EdgePayload,
                        ));
                    }
                }
                _ => {
                    return Err(SeededReverseDeclineReason::MalformedGraph(
                        SeededReverseGraphIssue::UnsupportedEdgeKind,
                    ));
                }
            }
        }
    }
    Ok(())
}

fn is_assertion(kind: EdgeKind) -> bool {
    matches!(
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
    )
}

fn validate_classes(
    raw: &RawPlan,
    byte_classes: &[u8; 256],
    class_count: usize,
    budget: &mut Budget,
) -> Result<Vec<u8>, SeededReverseDeclineReason> {
    budget.work(1)?;
    if class_count == 0 {
        return Err(SeededReverseDeclineReason::InvalidByteClasses(
            SeededReverseClassIssue::Empty,
        ));
    }
    if class_count > 256 {
        return Err(SeededReverseDeclineReason::InvalidByteClasses(
            SeededReverseClassIssue::TooMany,
        ));
    }
    let mut representatives = filled_vec(
        class_count,
        0_u8,
        budget,
        SeededReverseAllocation::Representatives,
    )?;
    let mut seen = filled_vec(
        class_count,
        0_u8,
        budget,
        SeededReverseAllocation::ClassSeen,
    )?;
    for byte in 0_u16..=u16::from(u8::MAX) {
        budget.work(1)?;
        let byte = u8::try_from(byte).map_err(|_| SeededReverseDeclineReason::AddressOverflow)?;
        let class = usize::from(byte_classes[usize::from(byte)]);
        if class >= class_count {
            return Err(SeededReverseDeclineReason::InvalidByteClasses(
                SeededReverseClassIssue::ClassOutOfRange,
            ));
        }
        if seen[class] == 0 {
            seen[class] = 1;
            representatives[class] = byte;
        }
    }
    if seen.contains(&0) {
        return Err(SeededReverseDeclineReason::InvalidByteClasses(
            SeededReverseClassIssue::MissingClass,
        ));
    }

    for (edge, kind) in raw.edge_kinds.iter().copied().enumerate() {
        budget.work(1)?;
        if kind != EdgeKind::ByteRange {
            continue;
        }
        let start = raw.byte_starts[edge];
        let end = raw.byte_ends[edge];
        for byte in 0_u16..=u16::from(u8::MAX) {
            budget.work(1)?;
            let byte =
                u8::try_from(byte).map_err(|_| SeededReverseDeclineReason::AddressOverflow)?;
            let class = usize::from(byte_classes[usize::from(byte)]);
            let representative = representatives[class];
            let member = start <= byte && byte <= end;
            let representative_member = start <= representative && representative <= end;
            if member != representative_member {
                return Err(SeededReverseDeclineReason::InvalidByteClasses(
                    SeededReverseClassIssue::InconsistentRangeMembership,
                ));
            }
        }
    }
    Ok(representatives)
}

#[derive(Debug)]
struct Incoming {
    sources: Vec<u32>,
    offsets: Vec<usize>,
    edges: Vec<u32>,
}

impl Incoming {
    fn build(raw: &RawPlan, budget: &mut Budget) -> Result<Self, SeededReverseDeclineReason> {
        let states = raw.roles.len();
        let edge_count = raw.edge_targets.len();
        let mut sources = filled_vec(
            edge_count,
            0_u32,
            budget,
            SeededReverseAllocation::IncomingSources,
        )?;
        let mut degrees = filled_vec(
            states,
            0_usize,
            budget,
            SeededReverseAllocation::IncomingDegrees,
        )?;
        for source in 0..states {
            budget.work(1)?;
            let source_u32 =
                u32::try_from(source).map_err(|_| SeededReverseDeclineReason::AddressOverflow)?;
            let begin = usize::try_from(raw.edge_offsets[source])
                .map_err(|_| SeededReverseDeclineReason::AddressOverflow)?;
            let next_source = source
                .checked_add(1)
                .ok_or(SeededReverseDeclineReason::AddressOverflow)?;
            let end = usize::try_from(raw.edge_offsets[next_source])
                .map_err(|_| SeededReverseDeclineReason::AddressOverflow)?;
            for (edge, source_slot) in sources.iter_mut().enumerate().take(end).skip(begin) {
                budget.work(1)?;
                *source_slot = source_u32;
                let target = usize::try_from(raw.edge_targets[edge])
                    .map_err(|_| SeededReverseDeclineReason::AddressOverflow)?;
                degrees[target] = degrees[target]
                    .checked_add(1)
                    .ok_or(SeededReverseDeclineReason::AddressOverflow)?;
            }
        }

        let offsets_len = states
            .checked_add(1)
            .ok_or(SeededReverseDeclineReason::AddressOverflow)?;
        let mut offsets = filled_vec(
            offsets_len,
            0_usize,
            budget,
            SeededReverseAllocation::IncomingOffsets,
        )?;
        for state in 0..states {
            budget.work(1)?;
            let next_state = state
                .checked_add(1)
                .ok_or(SeededReverseDeclineReason::AddressOverflow)?;
            offsets[next_state] = offsets[state]
                .checked_add(degrees[state])
                .ok_or(SeededReverseDeclineReason::AddressOverflow)?;
        }
        if offsets[states] != edge_count {
            return Err(SeededReverseDeclineReason::AddressOverflow);
        }
        let mut cursors = clone_slice(
            &offsets[..states],
            budget,
            SeededReverseAllocation::IncomingCursors,
        )?;
        let mut edges = filled_vec(
            edge_count,
            0_u32,
            budget,
            SeededReverseAllocation::IncomingEdges,
        )?;
        for (edge, &target) in raw.edge_targets.iter().enumerate() {
            budget.work(1)?;
            let target =
                usize::try_from(target).map_err(|_| SeededReverseDeclineReason::AddressOverflow)?;
            let destination = cursors[target];
            edges[destination] =
                u32::try_from(edge).map_err(|_| SeededReverseDeclineReason::AddressOverflow)?;
            cursors[target] = destination
                .checked_add(1)
                .ok_or(SeededReverseDeclineReason::AddressOverflow)?;
        }
        Ok(Self {
            sources,
            offsets,
            edges,
        })
    }

    fn row(&self, target: usize) -> Result<&[u32], SeededReverseDeclineReason> {
        let next = target
            .checked_add(1)
            .ok_or(SeededReverseDeclineReason::AddressOverflow)?;
        let begin = *self
            .offsets
            .get(target)
            .ok_or(SeededReverseDeclineReason::AddressOverflow)?;
        let end = *self
            .offsets
            .get(next)
            .ok_or(SeededReverseDeclineReason::AddressOverflow)?;
        self.edges
            .get(begin..end)
            .ok_or(SeededReverseDeclineReason::AddressOverflow)
    }
}

#[derive(Debug)]
struct ReverseClosure {
    seen: Vec<u8>,
    stack: Vec<u32>,
    stack_len: usize,
    frontier: Vec<u32>,
}

impl ReverseClosure {
    fn new(raw: &RawPlan, budget: &mut Budget) -> Result<Self, SeededReverseDeclineReason> {
        Ok(Self {
            seen: filled_vec(
                raw.roles.len(),
                0_u8,
                budget,
                SeededReverseAllocation::ClosureSeen,
            )?,
            stack: filled_vec(
                raw.roles.len(),
                0_u32,
                budget,
                SeededReverseAllocation::ClosureStack,
            )?,
            stack_len: 0,
            frontier: capacity_vec(
                raw.edge_targets.len(),
                budget,
                SeededReverseAllocation::ClosureFrontier,
            )?,
        })
    }

    fn begin(&mut self) {
        self.seen.fill(0);
        self.stack_len = 0;
        self.frontier.clear();
    }

    fn frontier(&self) -> &[u32] {
        &self.frontier
    }

    fn schedule(&mut self, state: u32) -> Result<(), SeededReverseDeclineReason> {
        let state_index =
            usize::try_from(state).map_err(|_| SeededReverseDeclineReason::AddressOverflow)?;
        let seen = self
            .seen
            .get_mut(state_index)
            .ok_or(SeededReverseDeclineReason::AddressOverflow)?;
        if *seen != 0 {
            return Ok(());
        }
        *seen = 1;
        let slot = self
            .stack
            .get_mut(self.stack_len)
            .ok_or(SeededReverseDeclineReason::AddressOverflow)?;
        *slot = state;
        self.stack_len = self
            .stack_len
            .checked_add(1)
            .ok_or(SeededReverseDeclineReason::AddressOverflow)?;
        Ok(())
    }

    fn expand(
        &mut self,
        raw: &RawPlan,
        incoming: &Incoming,
        root: u32,
        budget: &mut Budget,
    ) -> Result<bool, SeededReverseDeclineReason> {
        self.schedule(root)?;
        let mut reaches_start = false;
        while self.stack_len != 0 {
            budget.work(1)?;
            self.stack_len = self
                .stack_len
                .checked_sub(1)
                .ok_or(SeededReverseDeclineReason::AddressOverflow)?;
            let state = self.stack[self.stack_len];
            reaches_start |= state == raw.start;
            let state =
                usize::try_from(state).map_err(|_| SeededReverseDeclineReason::AddressOverflow)?;
            for &edge in incoming.row(state)? {
                budget.work(1)?;
                let edge = usize::try_from(edge)
                    .map_err(|_| SeededReverseDeclineReason::AddressOverflow)?;
                let source = incoming.sources[edge];
                let source_index = usize::try_from(source)
                    .map_err(|_| SeededReverseDeclineReason::AddressOverflow)?;
                match raw.roles[source_index] {
                    StateRole::Split => self.schedule(source)?,
                    StateRole::Consume => {
                        let edge = u32::try_from(edge)
                            .map_err(|_| SeededReverseDeclineReason::AddressOverflow)?;
                        self.frontier.push(edge);
                    }
                    StateRole::Accept => {
                        return Err(SeededReverseDeclineReason::MalformedGraph(
                            SeededReverseGraphIssue::StateRoleEdges,
                        ));
                    }
                    _ => {
                        return Err(SeededReverseDeclineReason::MalformedGraph(
                            SeededReverseGraphIssue::UnsupportedStateRole,
                        ));
                    }
                }
            }
        }
        self.frontier.sort_unstable();
        self.frontier.dedup();
        Ok(reaches_start)
    }
}

fn find_state(
    states: &[Vec<u32>],
    key: &[u32],
    budget: &mut Budget,
) -> Result<Option<u32>, SeededReverseDeclineReason> {
    for (state, known) in states.iter().enumerate() {
        budget.work(1)?;
        if known.len() != key.len() {
            continue;
        }
        let mut equal = true;
        for (&left, &right) in known.iter().zip(key) {
            budget.work(1)?;
            if left != right {
                equal = false;
                break;
            }
        }
        if equal {
            return Ok(Some(
                u32::try_from(state).map_err(|_| SeededReverseDeclineReason::AddressOverflow)?,
            ));
        }
    }
    Ok(None)
}

fn push_state(
    states: &mut Vec<Vec<u32>>,
    cells: &mut Vec<SeededReverseCell>,
    class_count: usize,
    key: &[u32],
    budget: &mut Budget,
) -> Result<u32, SeededReverseDeclineReason> {
    let required = states
        .len()
        .checked_add(1)
        .ok_or(SeededReverseDeclineReason::AddressOverflow)?;
    Budget::resource(
        SeededReverseResource::States,
        required,
        budget.limits.max_states,
    )?;
    if required > MAX_U32_INDEXED_ITEMS {
        return Err(SeededReverseDeclineReason::AddressOverflow);
    }
    let required_cells = required
        .checked_mul(class_count)
        .ok_or(SeededReverseDeclineReason::AddressOverflow)?;
    Budget::resource(
        SeededReverseResource::Cells,
        required_cells,
        budget.limits.max_cells,
    )?;
    let address_bytes = required_cells
        .checked_mul(size_of::<SeededReverseCell>())
        .ok_or(SeededReverseDeclineReason::AddressOverflow)?;
    if address_bytes > MAX_SEEDED_REVERSE_ADDRESS_BYTES {
        return Err(SeededReverseDeclineReason::AddressOverflow);
    }
    Budget::resource(
        SeededReverseResource::AddressableBytes,
        address_bytes,
        budget.limits.max_addressable_bytes,
    )?;
    let stored = clone_slice(key, budget, SeededReverseAllocation::StateKey)?;
    budget.memory(size_of::<Vec<u32>>())?;
    budget.memory(allocation_bytes::<SeededReverseCell>(class_count)?)?;
    states
        .try_reserve(1)
        .map_err(|_| SeededReverseDeclineReason::Allocation(SeededReverseAllocation::States))?;
    let additional_cells = required_cells
        .checked_sub(cells.len())
        .ok_or(SeededReverseDeclineReason::AddressOverflow)?;
    cells
        .try_reserve_exact(additional_cells)
        .map_err(|_| SeededReverseDeclineReason::Allocation(SeededReverseAllocation::Cells))?;
    let id =
        u32::try_from(states.len()).map_err(|_| SeededReverseDeclineReason::AddressOverflow)?;
    states.push(stored);
    budget.stats.states = states.len();
    Ok(id)
}

fn push_cell(
    cells: &mut Vec<SeededReverseCell>,
    cell: SeededReverseCell,
    budget: &mut Budget,
) -> Result<(), SeededReverseDeclineReason> {
    if cells.len() == cells.capacity() {
        return Err(SeededReverseDeclineReason::AddressOverflow);
    }
    cells.push(cell);
    budget.stats.cells = cells.len();
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct Budget {
    limits: SeededReverseLimits,
    stats: SeededReverseStats,
}

impl Budget {
    const fn new(limits: SeededReverseLimits) -> Self {
        Self {
            limits,
            stats: SeededReverseStats {
                states: 0,
                cells: 0,
                work: 0,
                memory_bytes: 0,
            },
        }
    }

    fn work(&mut self, amount: u64) -> Result<(), SeededReverseDeclineReason> {
        let required = self
            .stats
            .work
            .checked_add(amount)
            .ok_or(SeededReverseDeclineReason::AddressOverflow)?;
        if required > self.limits.max_work {
            return Err(SeededReverseDeclineReason::Resource {
                resource: SeededReverseResource::Work,
                limit: self.limits.max_work,
                required,
            });
        }
        self.stats.work = required;
        Ok(())
    }

    fn memory(&mut self, amount: usize) -> Result<(), SeededReverseDeclineReason> {
        let required = self
            .stats
            .memory_bytes
            .checked_add(amount)
            .ok_or(SeededReverseDeclineReason::AddressOverflow)?;
        Self::resource(
            SeededReverseResource::MemoryBytes,
            required,
            self.limits.max_memory_bytes,
        )?;
        self.stats.memory_bytes = required;
        Ok(())
    }

    fn resource(
        resource: SeededReverseResource,
        required: usize,
        limit: usize,
    ) -> Result<(), SeededReverseDeclineReason> {
        if required <= limit {
            return Ok(());
        }
        Err(SeededReverseDeclineReason::Resource {
            resource,
            limit: saturating_u64(limit),
            required: saturating_u64(required),
        })
    }
}

fn saturating_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn allocation_bytes<T>(len: usize) -> Result<usize, SeededReverseDeclineReason> {
    len.checked_mul(size_of::<T>())
        .ok_or(SeededReverseDeclineReason::AddressOverflow)
}

fn capacity_vec<T>(
    capacity: usize,
    budget: &mut Budget,
    site: SeededReverseAllocation,
) -> Result<Vec<T>, SeededReverseDeclineReason> {
    budget.memory(allocation_bytes::<T>(capacity)?)?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(capacity)
        .map_err(|_| SeededReverseDeclineReason::Allocation(site))?;
    Ok(values)
}

fn filled_vec<T: Clone>(
    len: usize,
    value: T,
    budget: &mut Budget,
    site: SeededReverseAllocation,
) -> Result<Vec<T>, SeededReverseDeclineReason> {
    let mut values = capacity_vec(len, budget, site)?;
    values.resize(len, value);
    Ok(values)
}

fn clone_slice<T: Copy>(
    values: &[T],
    budget: &mut Budget,
    site: SeededReverseAllocation,
) -> Result<Vec<T>, SeededReverseDeclineReason> {
    let mut result = capacity_vec(values.len(), budget, site)?;
    result.extend_from_slice(values);
    Ok(result)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::too_many_lines,
        reason = "bounded exhaustive test generators use asserted small dimensions"
    )]

    use fre_automata::{Automaton, CompileLimits as AutomatonLimits};
    use fre_lower::{LowerLimits, OperationSemantics};
    use fre_syntax::{CanonicalPattern, CompatibilityProfile, ParseRequest, RustProfile};

    use super::*;

    type TestEdge = (u32, EdgeKind, u8, u8);

    fn epsilon(target: u32) -> TestEdge {
        (target, EdgeKind::Epsilon, 0, 0)
    }

    fn byte(target: u32, value: u8) -> TestEdge {
        (target, EdgeKind::ByteRange, value, value)
    }

    fn raw_unchecked(start: u32, roles: Vec<StateRole>, rows: Vec<Vec<TestEdge>>) -> RawPlan {
        assert_eq!(roles.len(), rows.len());
        let mut edge_offsets = Vec::with_capacity(rows.len().saturating_add(1));
        let mut edge_targets = Vec::new();
        let mut edge_kinds = Vec::new();
        let mut byte_starts = Vec::new();
        let mut byte_ends = Vec::new();
        edge_offsets.push(0);
        for row in rows {
            for (target, kind, start_byte, end_byte) in row {
                edge_targets.push(target);
                edge_kinds.push(kind);
                byte_starts.push(start_byte);
                byte_ends.push(end_byte);
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

    fn hand_raw(start: u32, roles: Vec<StateRole>, rows: Vec<Vec<TestEdge>>) -> RawPlan {
        let raw = raw_unchecked(start, roles, rows);
        Automaton::from_raw(raw.clone(), AutomatonLimits::default())
            .expect("hand-built seeded-reverse graph validates");
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

    fn exact_classes(raw: &RawPlan) -> ([u8; 256], usize) {
        let range_edges = raw
            .edge_kinds
            .iter()
            .enumerate()
            .filter_map(|(edge, kind)| (*kind == EdgeKind::ByteRange).then_some(edge))
            .collect::<Vec<_>>();
        let mut signatures = Vec::<Vec<bool>>::new();
        let mut classes = [0_u8; 256];
        for byte in 0_u16..=u16::from(u8::MAX) {
            let byte = u8::try_from(byte).expect("test byte");
            let signature = range_edges
                .iter()
                .map(|&edge| raw.byte_starts[edge] <= byte && byte <= raw.byte_ends[edge])
                .collect::<Vec<_>>();
            let class = signatures
                .iter()
                .position(|known| *known == signature)
                .unwrap_or_else(|| {
                    signatures.push(signature);
                    signatures.len() - 1
                });
            classes[usize::from(byte)] = u8::try_from(class).expect("test class");
        }
        (classes, signatures.len())
    }

    fn exact_complete_from_raw(raw: &RawPlan, seed: SeededReverseSeed) -> SeededReverseDfa {
        match build_seeded_reverse_exact(raw, seed, SeededReverseLimits::default()) {
            SeededReverseBuild::Complete(machine) => machine,
            SeededReverseBuild::Declined(decline) => {
                panic!("exact seeded reverse unexpectedly declined: {decline:?}")
            }
        }
    }

    fn range_membership(raw: &RawPlan, edge: usize, byte: u8) -> bool {
        raw.edge_kinds[edge] == EdgeKind::ByteRange
            && raw.byte_starts[edge] <= byte
            && byte <= raw.byte_ends[edge]
    }

    fn assert_exact_raw_boundary_alphabet(raw: &RawPlan) -> SeededReverseAlphabet {
        let alphabet = exact_byte_classes(raw, SeededReverseLimits::default())
            .unwrap_or_else(|decline| panic!("exact alphabet unexpectedly declined: {decline:?}"));
        let classes = alphabet.byte_classes();
        let representatives = alphabet.representatives();
        assert!((1..=256).contains(&alphabet.class_count()));
        assert_eq!(representatives.len(), alphabet.class_count());
        assert!(alphabet.stats().work > 0);

        for (class, &representative) in representatives.iter().enumerate() {
            assert_eq!(usize::from(classes[usize::from(representative)]), class);
        }
        for byte in u8::MIN..=u8::MAX {
            let class = usize::from(classes[usize::from(byte)]);
            let representative = representatives[class];
            for edge in 0..raw.edge_kinds.len() {
                assert_eq!(
                    range_membership(raw, edge, byte),
                    range_membership(raw, edge, representative),
                    "byte={byte} representative={representative} edge={edge}"
                );
            }
        }

        // Independently reconstruct every raw interval boundary and require
        // the published dense class numbering to change exactly there.
        let mut expected_class = 0_usize;
        for byte in u8::MIN..=u8::MAX {
            let byte_index = usize::from(byte);
            if byte != 0
                && raw
                    .edge_kinds
                    .iter()
                    .copied()
                    .enumerate()
                    .any(|(edge, kind)| {
                        kind == EdgeKind::ByteRange
                            && (usize::from(raw.byte_starts[edge]) == byte_index
                                || usize::from(raw.byte_ends[edge]).saturating_add(1) == byte_index)
                    })
            {
                expected_class += 1;
            }
            assert_eq!(
                usize::from(classes[byte_index]),
                expected_class,
                "byte={byte}"
            );
        }
        assert_eq!(expected_class + 1, alphabet.class_count());

        // Exhaust all 65,536 byte pairs. Sharing one class must imply an
        // identical raw membership vector; unlike a semantic coalescer, the
        // boundary alphabet may intentionally leave disjoint equal vectors in
        // distinct interval classes.
        for left in u8::MIN..=u8::MAX {
            for right in u8::MIN..=u8::MAX {
                if classes[usize::from(left)] != classes[usize::from(right)] {
                    continue;
                }
                for edge in 0..raw.edge_kinds.len() {
                    assert_eq!(
                        range_membership(raw, edge, left),
                        range_membership(raw, edge, right),
                        "left={left} right={right} edge={edge}"
                    );
                }
            }
        }
        alphabet
    }

    fn complete(
        raw: &RawPlan,
        classes: &[u8; 256],
        class_count: usize,
        seed: SeededReverseSeed,
        limits: SeededReverseLimits,
    ) -> SeededReverseDfa {
        match build_seeded_reverse(raw, classes, class_count, seed, limits) {
            SeededReverseBuild::Complete(machine) => machine,
            SeededReverseBuild::Declined(decline) => {
                panic!("seeded reverse unexpectedly declined: {decline:?}")
            }
        }
    }

    fn decline_reason(
        raw: &RawPlan,
        classes: &[u8; 256],
        class_count: usize,
        seed: SeededReverseSeed,
        limits: SeededReverseLimits,
    ) -> SeededReverseDeclineReason {
        match build_seeded_reverse(raw, classes, class_count, seed, limits) {
            SeededReverseBuild::Complete(machine) => {
                panic!("seeded reverse unexpectedly completed: {machine:?}")
            }
            SeededReverseBuild::Declined(decline) => decline.reason,
        }
    }

    /// Independent forward NFA closure used only by the verifier tests. It
    /// deliberately shares no reverse-closure or state-key implementation.
    fn oracle_epsilon_closure(raw: &RawPlan, roots: &[u32]) -> Vec<bool> {
        let mut reached = vec![false; raw.roles.len()];
        let mut stack = roots.to_vec();
        while let Some(state) = stack.pop() {
            let state = usize::try_from(state).expect("oracle state");
            if reached[state] {
                continue;
            }
            reached[state] = true;
            if raw.roles[state] != StateRole::Split {
                continue;
            }
            let begin = usize::try_from(raw.edge_offsets[state]).expect("oracle begin");
            let end = usize::try_from(raw.edge_offsets[state + 1]).expect("oracle end");
            for edge in begin..end {
                assert_eq!(raw.edge_kinds[edge], EdgeKind::Epsilon);
                stack.push(raw.edge_targets[edge]);
            }
        }
        reached
    }

    fn oracle_recognizes(raw: &RawPlan, seed: SeededReverseSeed, bytes: &[u8]) -> bool {
        let mut reached = oracle_epsilon_closure(raw, &[raw.start]);
        for &byte in bytes {
            let mut roots = Vec::new();
            for (state, role) in raw.roles.iter().copied().enumerate() {
                if !reached[state] || role != StateRole::Consume {
                    continue;
                }
                let begin = usize::try_from(raw.edge_offsets[state]).expect("oracle begin");
                let end = usize::try_from(raw.edge_offsets[state + 1]).expect("oracle end");
                for edge in begin..end {
                    if raw.byte_starts[edge] <= byte && byte <= raw.byte_ends[edge] {
                        roots.push(raw.edge_targets[edge]);
                    }
                }
            }
            reached = oracle_epsilon_closure(raw, &roots);
        }
        match seed {
            SeededReverseSeed::AcceptStates => reached
                .iter()
                .zip(&raw.roles)
                .any(|(&is_reached, role)| is_reached && *role == StateRole::Accept),
            SeededReverseSeed::RootState(root) => reached
                .get(usize::try_from(root).expect("oracle root"))
                .copied()
                .unwrap_or(false),
        }
    }

    fn oracle_trace(
        raw: &RawPlan,
        seed: SeededReverseSeed,
        haystack: &[u8],
        window_start: usize,
        boundary: usize,
    ) -> Vec<usize> {
        (window_start..=boundary)
            .rev()
            .filter(|&candidate| oracle_recognizes(raw, seed, &haystack[candidate..boundary]))
            .collect()
    }

    fn exhaustive_haystacks(max_len: usize) -> Vec<Vec<u8>> {
        fn extend(all: &mut Vec<Vec<u8>>, prefix: &mut Vec<u8>, remaining: usize) {
            all.push(prefix.clone());
            if remaining == 0 {
                return;
            }
            for byte in [b'a', b'b', b'x'] {
                prefix.push(byte);
                extend(all, prefix, remaining - 1);
                prefix.pop();
            }
        }
        let mut all = Vec::new();
        extend(&mut all, &mut Vec::new(), max_len);
        all
    }

    #[test]
    fn exhaustive_small_graph_windows_match_independent_nfa_oracle() {
        let graphs = [
            "a",
            "ab",
            "a|b",
            "a*b",
            "(?:ab|ba)+",
            "(?:a|)b",
            "[a-c]+x?",
            "(?:a|b)*abb",
        ]
        .map(lower);
        let haystacks = exhaustive_haystacks(4);
        for raw in &graphs {
            let (classes, class_count) = exact_classes(raw);
            let mut seeds = vec![SeededReverseSeed::AcceptStates];
            seeds.extend(raw.roles.iter().enumerate().filter_map(|(state, role)| {
                (*role == StateRole::Consume).then_some(SeededReverseSeed::RootState(
                    u32::try_from(state).expect("test root"),
                ))
            }));
            for seed in seeds {
                let machine = complete(
                    raw,
                    &classes,
                    class_count,
                    seed,
                    SeededReverseLimits::default(),
                );
                assert_eq!(machine.cells().len(), machine.stats().cells);
                assert_eq!(
                    machine.cells().len(),
                    machine.stats().states * machine.class_count()
                );
                for haystack in &haystacks {
                    for boundary in 0..=haystack.len() {
                        for window_start in 0..=boundary {
                            let expected =
                                oracle_trace(raw, seed, haystack, window_start, boundary);
                            let actual = machine
                                .trace(haystack, window_start, boundary)
                                .expect("valid verifier window")
                                .collect::<Vec<_>>();
                            assert_eq!(
                                actual, expected,
                                "seed={seed:?} haystack={haystack:?} window={window_start}..{boundary} raw={raw:?}"
                            );
                            assert_eq!(
                                machine
                                    .recover_start(haystack, window_start, boundary)
                                    .expect("valid recovery window"),
                                expected.last().copied()
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn exact_raw_boundary_alphabet_preserves_tricky_range_membership() {
        let ranges = [
            (0, 0),
            (u8::MAX, u8::MAX),
            (1, 9),
            (10, 20),
            (15, 25),
            (26, 26),
            (30, 40),
            (41, 50),
            (49, 70),
            (99, 101),
            (100, 100),
            (127, 200),
            (201, 254),
        ];
        let edges = ranges
            .into_iter()
            .map(|(start, end)| (1, EdgeKind::ByteRange, start, end))
            .collect::<Vec<_>>();
        let raw = hand_raw(
            0,
            vec![StateRole::Consume, StateRole::Accept],
            vec![edges, vec![]],
        );
        let alphabet = assert_exact_raw_boundary_alphabet(&raw);
        assert!(alphabet.class_count() > ranges.len());

        let machine = exact_complete_from_raw(&raw, SeededReverseSeed::AcceptStates);
        assert_eq!(machine.byte_classes(), alphabet.byte_classes());
        assert_eq!(machine.class_count(), alphabet.class_count());
        for byte in u8::MIN..=u8::MAX {
            let haystack = [byte];
            let expected = oracle_trace(&raw, SeededReverseSeed::AcceptStates, &haystack, 0, 1);
            let actual = machine
                .trace(&haystack, 0, 1)
                .expect("valid one-byte window")
                .collect::<Vec<_>>();
            assert_eq!(actual, expected, "byte={byte}");
        }
    }

    #[test]
    fn exact_raw_boundary_alphabet_supports_all_256_classes() {
        let edges = (u8::MIN..=u8::MAX)
            .map(|byte| (1, EdgeKind::ByteRange, byte, byte))
            .collect::<Vec<_>>();
        let raw = hand_raw(
            0,
            vec![StateRole::Consume, StateRole::Accept],
            vec![edges, vec![]],
        );
        let alphabet = assert_exact_raw_boundary_alphabet(&raw);
        assert_eq!(alphabet.class_count(), 256);
        for byte in u8::MIN..=u8::MAX {
            assert_eq!(alphabet.byte_classes()[usize::from(byte)], byte);
            assert_eq!(alphabet.representatives()[usize::from(byte)], byte);
        }

        let machine = exact_complete_from_raw(&raw, SeededReverseSeed::AcceptStates);
        assert_eq!(machine.state_count(), 1);
        assert_eq!(machine.cells().len(), 256);
        for byte in u8::MIN..=u8::MAX {
            let haystack = [byte];
            assert_eq!(
                machine
                    .trace(&haystack, 0, 1)
                    .expect("valid one-byte window")
                    .collect::<Vec<_>>(),
                vec![0],
                "byte={byte}"
            );
        }
    }

    #[test]
    fn exact_raw_boundary_entry_ignores_inexact_coalesced_classes() {
        let raw = hand_raw(
            0,
            vec![StateRole::Consume, StateRole::Accept],
            vec![vec![byte(1, b'a'), byte(1, b'z')], vec![]],
        );
        let collapsed = [0_u8; 256];
        assert_eq!(
            decline_reason(
                &raw,
                &collapsed,
                1,
                SeededReverseSeed::AcceptStates,
                SeededReverseLimits::default(),
            ),
            SeededReverseDeclineReason::InvalidByteClasses(
                SeededReverseClassIssue::InconsistentRangeMembership
            )
        );

        let alphabet = assert_exact_raw_boundary_alphabet(&raw);
        let machine = exact_complete_from_raw(&raw, SeededReverseSeed::AcceptStates);
        assert_eq!(machine.byte_classes(), alphabet.byte_classes());
        for byte in u8::MIN..=u8::MAX {
            let haystack = [byte];
            assert_eq!(
                machine
                    .trace(&haystack, 0, 1)
                    .expect("valid one-byte window")
                    .collect::<Vec<_>>(),
                oracle_trace(&raw, SeededReverseSeed::AcceptStates, &haystack, 0, 1,),
                "byte={byte}"
            );
        }
    }

    #[test]
    fn exact_raw_boundary_root_seed_keeps_forward_equivalent_branches_distinct() {
        // Both alternatives have the same continuation and can become one
        // semantic column in a minimized full-search DFA. A reverse machine
        // rooted immediately before the first `x` must nevertheless retain
        // that only `a`, not `b`, reaches this particular root.
        let raw = hand_raw(
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
                vec![epsilon(1), epsilon(3)],
                vec![byte(2, b'a')],
                vec![byte(5, b'x')],
                vec![byte(4, b'b')],
                vec![byte(5, b'x')],
                vec![],
            ],
        );
        let alphabet = assert_exact_raw_boundary_alphabet(&raw);
        assert_ne!(
            alphabet.byte_classes()[usize::from(b'a')],
            alphabet.byte_classes()[usize::from(b'b')]
        );

        let seed = SeededReverseSeed::RootState(2);
        let machine = exact_complete_from_raw(&raw, seed);
        for byte in u8::MIN..=u8::MAX {
            let haystack = [byte];
            assert_eq!(
                machine
                    .trace(&haystack, 0, 1)
                    .expect("valid one-byte window")
                    .collect::<Vec<_>>(),
                oracle_trace(&raw, seed, &haystack, 0, 1),
                "byte={byte}"
            );
        }
        assert_eq!(
            machine
                .trace(b"a", 0, 1)
                .expect("a reaches the selected interior root")
                .collect::<Vec<_>>(),
            vec![0]
        );
        assert!(
            machine
                .trace(b"b", 0, 1)
                .expect("b reaches only the other branch")
                .next()
                .is_none()
        );
    }

    #[test]
    fn initial_zero_byte_events_are_explicit_for_both_seed_kinds() {
        let raw = hand_raw(
            0,
            vec![StateRole::Split, StateRole::Consume, StateRole::Accept],
            vec![vec![epsilon(1), epsilon(2)], vec![byte(2, b'a')], vec![]],
        );
        let (classes, class_count) = exact_classes(&raw);
        for seed in [
            SeededReverseSeed::AcceptStates,
            SeededReverseSeed::RootState(1),
        ] {
            let machine = complete(
                &raw,
                &classes,
                class_count,
                seed,
                SeededReverseLimits::default(),
            );
            assert!(machine.initial_reaches_start());
            assert_eq!(
                machine
                    .trace(b"", 0, 0)
                    .expect("empty window")
                    .collect::<Vec<_>>(),
                vec![0]
            );
        }

        let direct_root = hand_raw(
            0,
            vec![StateRole::Consume, StateRole::Accept],
            vec![vec![byte(1, b'a')], vec![]],
        );
        let (classes, class_count) = exact_classes(&direct_root);
        let machine = complete(
            &direct_root,
            &classes,
            class_count,
            SeededReverseSeed::RootState(0),
            SeededReverseLimits::default(),
        );
        assert!(machine.initial_reaches_start());
    }

    #[test]
    fn assertion_graphs_decline_with_a_specific_conservative_reason() {
        let assertion_kinds = [
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
        for kind in assertion_kinds {
            let raw = raw_unchecked(
                0,
                vec![StateRole::Split, StateRole::Accept],
                vec![vec![(1, kind, 0, 0)], vec![]],
            );
            let (classes, class_count) = exact_classes(&raw);
            assert_eq!(
                decline_reason(
                    &raw,
                    &classes,
                    class_count,
                    SeededReverseSeed::AcceptStates,
                    SeededReverseLimits::default(),
                ),
                SeededReverseDeclineReason::UnsupportedAssertions,
                "kind={kind:?}"
            );
        }
    }

    #[test]
    fn malformed_seeds_decline_without_partial_machine() {
        let raw = hand_raw(
            0,
            vec![StateRole::Split, StateRole::Consume, StateRole::Accept],
            vec![vec![epsilon(1)], vec![byte(2, b'a')], vec![]],
        );
        let (classes, class_count) = exact_classes(&raw);
        for (seed, issue) in [
            (
                SeededReverseSeed::RootState(7),
                SeededReverseSeedIssue::RootOutOfRange,
            ),
            (
                SeededReverseSeed::RootState(0),
                SeededReverseSeedIssue::RootIsNotConsume,
            ),
            (
                SeededReverseSeed::RootState(2),
                SeededReverseSeedIssue::RootIsNotConsume,
            ),
        ] {
            assert_eq!(
                decline_reason(
                    &raw,
                    &classes,
                    class_count,
                    seed,
                    SeededReverseLimits::default(),
                ),
                SeededReverseDeclineReason::InvalidSeed(issue)
            );
        }

        let no_accept = raw_unchecked(0, vec![StateRole::Consume], vec![vec![byte(0, b'a')]]);
        let (classes, class_count) = exact_classes(&no_accept);
        assert_eq!(
            decline_reason(
                &no_accept,
                &classes,
                class_count,
                SeededReverseSeed::AcceptStates,
                SeededReverseLimits::default(),
            ),
            SeededReverseDeclineReason::InvalidSeed(SeededReverseSeedIssue::NoAcceptStates)
        );
    }

    #[test]
    fn malformed_graph_shapes_decline_transactionally() {
        let valid = raw_unchecked(
            0,
            vec![StateRole::Consume, StateRole::Accept],
            vec![vec![byte(1, b'a')], vec![]],
        );
        let classes = [0_u8; 256];
        let cases = [
            (
                RawPlan {
                    roles: Vec::new(),
                    edge_offsets: vec![0],
                    ..valid.clone()
                },
                SeededReverseGraphIssue::Empty,
            ),
            (
                RawPlan {
                    start: 9,
                    ..valid.clone()
                },
                SeededReverseGraphIssue::StartOutOfRange,
            ),
            (
                RawPlan {
                    edge_offsets: vec![0],
                    ..valid.clone()
                },
                SeededReverseGraphIssue::OffsetShape,
            ),
            (
                RawPlan {
                    edge_kinds: Vec::new(),
                    ..valid.clone()
                },
                SeededReverseGraphIssue::EdgeTableShape,
            ),
            (
                RawPlan {
                    edge_offsets: vec![1, 1, 1],
                    ..valid.clone()
                },
                SeededReverseGraphIssue::EdgeOffset,
            ),
            (
                RawPlan {
                    edge_targets: vec![9],
                    ..valid.clone()
                },
                SeededReverseGraphIssue::EdgeTargetOutOfRange,
            ),
            (
                RawPlan {
                    edge_kinds: vec![EdgeKind::Epsilon],
                    byte_starts: vec![0],
                    byte_ends: vec![0],
                    ..valid.clone()
                },
                SeededReverseGraphIssue::StateRoleEdges,
            ),
            (
                RawPlan {
                    byte_starts: vec![b'z'],
                    byte_ends: vec![b'a'],
                    ..valid.clone()
                },
                SeededReverseGraphIssue::EdgePayload,
            ),
        ];
        for (raw, issue) in cases {
            assert_eq!(
                decline_reason(
                    &raw,
                    &classes,
                    1,
                    SeededReverseSeed::AcceptStates,
                    SeededReverseLimits::default(),
                ),
                SeededReverseDeclineReason::MalformedGraph(issue),
                "raw={raw:?}"
            );
        }

        let accept_outgoing = raw_unchecked(0, vec![StateRole::Accept], vec![vec![epsilon(0)]]);
        assert_eq!(
            decline_reason(
                &accept_outgoing,
                &classes,
                1,
                SeededReverseSeed::AcceptStates,
                SeededReverseLimits::default(),
            ),
            SeededReverseDeclineReason::MalformedGraph(SeededReverseGraphIssue::StateRoleEdges)
        );
    }

    #[test]
    fn invalid_and_inexact_byte_partitions_decline() {
        let raw = hand_raw(
            0,
            vec![StateRole::Consume, StateRole::Accept],
            vec![vec![byte(1, b'a')], vec![]],
        );
        let all_zero = [0_u8; 256];
        for (classes, count, issue) in [
            (all_zero, 0, SeededReverseClassIssue::Empty),
            (all_zero, 257, SeededReverseClassIssue::TooMany),
            (all_zero, 2, SeededReverseClassIssue::MissingClass),
            (
                {
                    let mut classes = all_zero;
                    classes[0] = 2;
                    classes
                },
                2,
                SeededReverseClassIssue::ClassOutOfRange,
            ),
            (
                all_zero,
                1,
                SeededReverseClassIssue::InconsistentRangeMembership,
            ),
        ] {
            assert_eq!(
                decline_reason(
                    &raw,
                    &classes,
                    count,
                    SeededReverseSeed::AcceptStates,
                    SeededReverseLimits::default(),
                ),
                SeededReverseDeclineReason::InvalidByteClasses(issue)
            );
        }
    }

    fn assert_resource(
        raw: &RawPlan,
        classes: &[u8; 256],
        class_count: usize,
        limits: SeededReverseLimits,
        expected: SeededReverseResource,
    ) {
        let reason = decline_reason(
            raw,
            classes,
            class_count,
            SeededReverseSeed::AcceptStates,
            limits,
        );
        assert!(
            matches!(
                reason,
                SeededReverseDeclineReason::Resource { resource, .. } if resource == expected
            ),
            "expected {expected:?}, got {reason:?}"
        );
    }

    #[test]
    fn every_resource_ceiling_accepts_exact_and_declines_one_below() {
        let raw = lower("(?:ab|ac)*d");
        let (classes, class_count) = exact_classes(&raw);
        let baseline = complete(
            &raw,
            &classes,
            class_count,
            SeededReverseSeed::AcceptStates,
            SeededReverseLimits::default(),
        );
        let stats = baseline.stats();
        assert!(stats.states > 0);
        assert!(stats.cells > 0);
        assert!(stats.work > 0);
        assert!(stats.memory_bytes > 0);

        let state_low = SeededReverseLimits {
            max_states: stats.states - 1,
            ..SeededReverseLimits::default()
        };
        assert_resource(
            &raw,
            &classes,
            class_count,
            state_low,
            SeededReverseResource::States,
        );
        complete(
            &raw,
            &classes,
            class_count,
            SeededReverseSeed::AcceptStates,
            SeededReverseLimits {
                max_states: stats.states,
                ..SeededReverseLimits::default()
            },
        );

        let cell_low = SeededReverseLimits {
            max_cells: stats.cells - 1,
            ..SeededReverseLimits::default()
        };
        assert_resource(
            &raw,
            &classes,
            class_count,
            cell_low,
            SeededReverseResource::Cells,
        );
        complete(
            &raw,
            &classes,
            class_count,
            SeededReverseSeed::AcceptStates,
            SeededReverseLimits {
                max_cells: stats.cells,
                ..SeededReverseLimits::default()
            },
        );

        let work_low = SeededReverseLimits {
            max_work: stats.work - 1,
            ..SeededReverseLimits::default()
        };
        assert_resource(
            &raw,
            &classes,
            class_count,
            work_low,
            SeededReverseResource::Work,
        );
        complete(
            &raw,
            &classes,
            class_count,
            SeededReverseSeed::AcceptStates,
            SeededReverseLimits {
                max_work: stats.work,
                ..SeededReverseLimits::default()
            },
        );

        let memory_low = SeededReverseLimits {
            max_memory_bytes: stats.memory_bytes - 1,
            ..SeededReverseLimits::default()
        };
        assert_resource(
            &raw,
            &classes,
            class_count,
            memory_low,
            SeededReverseResource::MemoryBytes,
        );
        complete(
            &raw,
            &classes,
            class_count,
            SeededReverseSeed::AcceptStates,
            SeededReverseLimits {
                max_memory_bytes: stats.memory_bytes,
                ..SeededReverseLimits::default()
            },
        );

        let address_bytes = stats
            .cells
            .checked_mul(size_of::<SeededReverseCell>())
            .expect("test address bytes");
        let address_low = SeededReverseLimits {
            max_addressable_bytes: address_bytes - 1,
            ..SeededReverseLimits::default()
        };
        assert_resource(
            &raw,
            &classes,
            class_count,
            address_low,
            SeededReverseResource::AddressableBytes,
        );
        complete(
            &raw,
            &classes,
            class_count,
            SeededReverseSeed::AcceptStates,
            SeededReverseLimits {
                max_addressable_bytes: address_bytes,
                ..SeededReverseLimits::default()
            },
        );
    }

    #[test]
    fn zero_limits_decline_before_unbounded_allocation() {
        let raw = lower("ab");
        let (classes, class_count) = exact_classes(&raw);
        for (limits, expected) in [
            (
                SeededReverseLimits {
                    max_work: 0,
                    ..SeededReverseLimits::default()
                },
                SeededReverseResource::Work,
            ),
            (
                SeededReverseLimits {
                    max_memory_bytes: 0,
                    ..SeededReverseLimits::default()
                },
                SeededReverseResource::MemoryBytes,
            ),
            (
                SeededReverseLimits {
                    max_states: 0,
                    ..SeededReverseLimits::default()
                },
                SeededReverseResource::States,
            ),
            (
                SeededReverseLimits {
                    max_cells: 0,
                    ..SeededReverseLimits::default()
                },
                SeededReverseResource::Cells,
            ),
            (
                SeededReverseLimits {
                    max_addressable_bytes: 0,
                    ..SeededReverseLimits::default()
                },
                SeededReverseResource::AddressableBytes,
            ),
        ] {
            assert_resource(&raw, &classes, class_count, limits, expected);
        }
    }

    #[test]
    fn verifier_rejects_invalid_windows() {
        let raw = lower("a");
        let (classes, class_count) = exact_classes(&raw);
        let machine = complete(
            &raw,
            &classes,
            class_count,
            SeededReverseSeed::AcceptStates,
            SeededReverseLimits::default(),
        );
        assert_eq!(
            machine.trace(b"a", 0, 2).unwrap_err(),
            SeededReverseTraceError::BoundaryOutOfRange
        );
        assert_eq!(
            machine.trace(b"a", 1, 0).unwrap_err(),
            SeededReverseTraceError::WindowOutOfRange
        );
    }

    #[test]
    fn repeated_builds_publish_identical_complete_rows_and_stats() {
        let raw = lower("(?:ab|ac|ba)+x?");
        let (classes, class_count) = exact_classes(&raw);
        let first = complete(
            &raw,
            &classes,
            class_count,
            SeededReverseSeed::AcceptStates,
            SeededReverseLimits::default(),
        );
        let second = complete(
            &raw,
            &classes,
            class_count,
            SeededReverseSeed::AcceptStates,
            SeededReverseLimits::default(),
        );
        assert_eq!(first, second);
        assert_eq!(first.byte_classes(), &classes);
        assert_eq!(first.state_count(), first.stats().states);
        for state in 0..first.state_count() {
            assert_eq!(
                first
                    .row(u32::try_from(state).expect("test row"))
                    .expect("complete row")
                    .len(),
                class_count
            );
        }
        assert!(
            first
                .row(u32::try_from(first.state_count()).expect("past-last row"))
                .is_none()
        );
    }
}
