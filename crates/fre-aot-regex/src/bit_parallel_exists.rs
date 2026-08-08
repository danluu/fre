use core::fmt;

use fre_automata::{EdgeKind, RawPlan, StateRole};

use crate::error::CompileError;

/// Largest validated Thompson graph represented by the bounded executor.
pub const MAX_BIT_PARALLEL_EXISTS_STATES: usize = 256;
/// Largest fixed machine-word count admitted by the bounded executor.
pub const MAX_BIT_PARALLEL_EXISTS_WORDS: usize = 4;
/// Exact optional-analysis work ceiling. Reaching it declines only this route.
pub const MAX_BIT_PARALLEL_EXISTS_WORK: u64 = 64_000_000;
/// Peak logical construction-memory ceiling, including temporary transition rows.
pub const MAX_BIT_PARALLEL_EXISTS_MEMORY_BYTES: usize = 4 * 1024 * 1024;

const BYTE_VALUES: usize = 256;
const NIBBLE_BITS: usize = 4;
const NIBBLE_SUBSETS: usize = 1 << NIBBLE_BITS;
const NIBBLE_SUBSET_MASK: u64 = 15;
const ACCEPT_BIT: u64 = 1_u64 << 63;
const CONSUMING_BITS: u64 = ACCEPT_BIT - 1;
const ABSENT_CONSUMING: u8 = u8::MAX;
const MAX_CONSUMING_STATES: usize = MAX_BIT_PARALLEL_EXISTS_WORDS * 64 - 1;
const FIXED_BUILD_SCRATCH_BYTES: usize = core::mem::size_of::<[usize; 256]>()
    + core::mem::size_of::<[u64; MAX_BIT_PARALLEL_EXISTS_WORDS]>()
    + core::mem::size_of::<[bool; 256]>()
    + core::mem::size_of::<[u8; 256]>();

/// Canonical dimensions and exact resource receipt for a bit-parallel executor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BitParallelExistsStats {
    pub thompson_states: usize,
    pub thompson_edges: usize,
    pub consuming_states: usize,
    pub byte_classes: usize,
    /// One for the legacy nibble-union table, otherwise two through four.
    pub words: usize,
    /// Non-zero only for the legacy one-word nibble-union representation.
    pub source_nibbles: usize,
    /// Number of retained transition `u64` values.
    pub transition_entries: usize,
    /// Exact-byte cached root-transition `u64` values (multiword only).
    pub root_transition_entries: usize,
    pub retained_bytes: usize,
    pub peak_build_bytes: usize,
    pub derivation_work: u64,
}

/// Borrowed, constructor-authenticated table view for self-contained native
/// lowering. The byte classifier and nibble-union rows are the exact
/// canonical storage used by the portable executor; native publication does
/// not reconstruct the language from source spelling or benchmark identity.
#[derive(Clone, Copy, Debug)]
pub(crate) struct NativeBitParallelExistsView<'a> {
    pub(crate) byte_to_class: &'a [u8; BYTE_VALUES],
    pub(crate) transition_masks: &'a [u64],
    pub(crate) root_transition_masks: &'a [u64],
    pub(crate) initial: [u64; MAX_BIT_PARALLEL_EXISTS_WORDS],
    pub(crate) stats: BitParallelExistsStats,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BitParallelExistsLimits {
    pub states: usize,
    pub work: u64,
    pub memory_bytes: usize,
}

impl Default for BitParallelExistsLimits {
    fn default() -> Self {
        Self {
            states: MAX_BIT_PARALLEL_EXISTS_STATES,
            work: MAX_BIT_PARALLEL_EXISTS_WORK,
            memory_bytes: MAX_BIT_PARALLEL_EXISTS_MEMORY_BYTES,
        }
    }
}

#[derive(Clone, Copy)]
struct BuildResources {
    limit: u64,
    used: u64,
}

impl BuildResources {
    const fn new(limit: u64) -> Self {
        Self { limit, used: 0 }
    }

    fn charge(&mut self, amount: usize) -> Option<()> {
        let amount = u64::try_from(amount).ok()?;
        let next = self.used.checked_add(amount)?;
        if next > self.limit {
            return None;
        }
        self.used = next;
        Some(())
    }
}

/// A complete assertion-free `Exists` executor derived from one raw graph.
///
/// The one-word representation retains the original four-source subset rows.
/// Wider representations store one dense epsilon-closed destination vector
/// per byte class and consuming-state ordinal. Bit 63 of the final live word
/// is reserved as an ephemeral acceptance marker.
#[derive(Clone)]
pub(crate) struct BitParallelExists {
    byte_to_class: [u8; BYTE_VALUES],
    raw_to_consuming: [u8; MAX_BIT_PARALLEL_EXISTS_STATES],
    transition_masks: Box<[u64]>,
    root_transition_masks: Box<[u64]>,
    initial: [u64; MAX_BIT_PARALLEL_EXISTS_WORDS],
    words: usize,
    source_nibbles: usize,
    stats: BitParallelExistsStats,
}

impl fmt::Debug for BitParallelExists {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BitParallelExists")
            .field("initial", &self.initial)
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

impl BitParallelExists {
    pub(crate) fn derive(raw: &RawPlan) -> Option<Self> {
        Self::derive_with_limits(raw, BitParallelExistsLimits::default())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "shape validation, exact resources, closure masks, and table publication are one proof"
    )]
    pub(crate) fn derive_with_limits(
        raw: &RawPlan,
        limits: BitParallelExistsLimits,
    ) -> Option<Self> {
        let states = raw.roles.len();
        let edges = raw.edge_targets.len();
        let start = usize::try_from(raw.start).ok()?;
        if states == 0
            || states > limits.states.min(MAX_BIT_PARALLEL_EXISTS_STATES)
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

        let mut resources = BuildResources::new(limits.work.min(MAX_BIT_PARALLEL_EXISTS_WORK));
        resources.charge(states.checked_add(edges)?)?;
        let mut raw_to_consuming = [ABSENT_CONSUMING; MAX_BIT_PARALLEL_EXISTS_STATES];
        let mut consuming_states = 0_usize;
        for (state, consuming_ordinal) in raw_to_consuming.iter_mut().enumerate().take(states) {
            let state_edges = state_edges(raw, state)?;
            match *raw.roles.get(state)? {
                StateRole::Split => {
                    for edge in state_edges {
                        if raw.edge_kinds.get(edge) != Some(&EdgeKind::Epsilon) {
                            return None;
                        }
                    }
                }
                StateRole::Consume => {
                    if consuming_states >= MAX_CONSUMING_STATES {
                        return None;
                    }
                    *consuming_ordinal = u8::try_from(consuming_states).ok()?;
                    consuming_states = consuming_states.checked_add(1)?;
                    for edge in state_edges {
                        if raw.edge_kinds.get(edge) != Some(&EdgeKind::ByteRange)
                            || raw.byte_starts.get(edge)? > raw.byte_ends.get(edge)?
                        {
                            return None;
                        }
                    }
                }
                StateRole::Accept => {
                    if !state_edges.is_empty() {
                        return None;
                    }
                }
                _ => return None,
            }
        }
        for &target in &raw.edge_targets {
            if usize::try_from(target).map_or(true, |target| target >= states) {
                return None;
            }
        }

        let mut boundary_starts = [false; BYTE_VALUES];
        boundary_starts[0] = true;
        for edge in 0..edges {
            resources.charge(1)?;
            if raw.edge_kinds[edge] == EdgeKind::ByteRange {
                boundary_starts[usize::from(raw.byte_starts[edge])] = true;
                if let Some(after) = raw.byte_ends[edge].checked_add(1) {
                    boundary_starts[usize::from(after)] = true;
                }
            }
        }
        let mut byte_to_class = [0_u8; BYTE_VALUES];
        let mut representatives = [0_u8; BYTE_VALUES];
        let mut byte_classes = 0_usize;
        for byte in 0_u16..=u16::from(u8::MAX) {
            resources.charge(1)?;
            let byte = usize::from(byte);
            if boundary_starts[byte] {
                representatives[byte_classes] = u8::try_from(byte).ok()?;
                byte_classes = byte_classes.checked_add(1)?;
            }
            byte_to_class[byte] = u8::try_from(byte_classes.checked_sub(1)?).ok()?;
        }
        if byte_classes == 0 || byte_classes > BYTE_VALUES {
            return None;
        }

        let words = consuming_states.checked_add(1)?.div_ceil(64).max(1);
        if words > MAX_BIT_PARALLEL_EXISTS_WORDS {
            return None;
        }
        let source_nibbles = if words == 1 {
            consuming_states.checked_add(NIBBLE_BITS - 1)? / NIBBLE_BITS
        } else {
            0
        };
        let direct_entries = byte_classes
            .checked_mul(consuming_states)?
            .checked_mul(words)?;
        let direct_bytes = direct_entries.checked_mul(core::mem::size_of::<u64>())?;
        let transition_entries = if words == 1 {
            byte_classes
                .checked_mul(source_nibbles)?
                .checked_mul(NIBBLE_SUBSETS)?
        } else {
            direct_entries
        };
        let root_transition_entries = if words == 1 {
            0
        } else {
            BYTE_VALUES.checked_mul(words)?
        };
        let retained_entries = transition_entries.checked_add(root_transition_entries)?;
        let retained_table_bytes = retained_entries.checked_mul(core::mem::size_of::<u64>())?;
        let retained_bytes = core::mem::size_of::<Self>().checked_add(retained_table_bytes)?;
        let closure_entries = states.checked_mul(words)?;
        let closure_bytes = closure_entries.checked_mul(core::mem::size_of::<u64>())?;
        let temporary_direct_bytes = (words == 1).then_some(direct_bytes).unwrap_or(0);
        let peak_build_bytes = retained_bytes
            .checked_add(temporary_direct_bytes)?
            .checked_add(closure_bytes)?
            .checked_add(2 * core::mem::size_of::<Vec<u64>>())?
            .checked_add(FIXED_BUILD_SCRATCH_BYTES)?;
        if peak_build_bytes > limits.memory_bytes
            || peak_build_bytes > MAX_BIT_PARALLEL_EXISTS_MEMORY_BYTES
        {
            return None;
        }

        let mut closures = Vec::new();
        closures.try_reserve_exact(closure_entries).ok()?;
        closures.resize(closure_entries, 0_u64);
        let mut stack = [0_usize; MAX_BIT_PARALLEL_EXISTS_STATES];
        for root in 0..states {
            let mut seen = [0_u64; MAX_BIT_PARALLEL_EXISTS_WORDS];
            let raw_word = root / 64;
            seen[raw_word] |= 1_u64.checked_shl(u32::try_from(root % 64).ok()?)?;
            let mut stack_len = 1_usize;
            stack[0] = root;
            while stack_len != 0 {
                resources.charge(1)?;
                stack_len = stack_len.checked_sub(1)?;
                let state = stack[stack_len];
                match *raw.roles.get(state)? {
                    StateRole::Split => {
                        for edge in state_edges(raw, state)? {
                            resources.charge(1)?;
                            let target = usize::try_from(*raw.edge_targets.get(edge)?).ok()?;
                            let target_word = target / 64;
                            let bit = 1_u64.checked_shl(u32::try_from(target % 64).ok()?)?;
                            if seen[target_word] & bit == 0 {
                                seen[target_word] |= bit;
                                *stack.get_mut(stack_len)? = target;
                                stack_len = stack_len.checked_add(1)?;
                            }
                        }
                    }
                    StateRole::Consume => {
                        let ordinal = *raw_to_consuming.get(state)?;
                        if ordinal == ABSENT_CONSUMING {
                            return None;
                        }
                        let ordinal = usize::from(ordinal);
                        let closure_index = root.checked_mul(words)?.checked_add(ordinal / 64)?;
                        *closures.get_mut(closure_index)? |=
                            1_u64.checked_shl(u32::try_from(ordinal % 64).ok()?)?;
                    }
                    StateRole::Accept => {
                        let closure_index = root
                            .checked_mul(words)?
                            .checked_add(words.checked_sub(1)?)?;
                        *closures.get_mut(closure_index)? |= ACCEPT_BIT;
                    }
                    _ => return None,
                }
            }
        }

        let mut direct = Vec::new();
        direct.try_reserve_exact(direct_entries).ok()?;
        direct.resize(direct_entries, 0_u64);
        for (state, &ordinal) in raw_to_consuming.iter().enumerate().take(states) {
            if ordinal == ABSENT_CONSUMING {
                continue;
            }
            for (class, &representative) in representatives.iter().enumerate().take(byte_classes) {
                for edge in state_edges(raw, state)? {
                    resources.charge(1)?;
                    if raw.byte_starts[edge] <= representative
                        && representative <= raw.byte_ends[edge]
                    {
                        let target = usize::try_from(raw.edge_targets[edge]).ok()?;
                        let target_base = target.checked_mul(words)?;
                        let direct_base = class
                            .checked_mul(consuming_states)?
                            .checked_add(usize::from(ordinal))?
                            .checked_mul(words)?;
                        for word in 0..words {
                            resources.charge(1)?;
                            let reached = *closures.get(target_base.checked_add(word)?)?;
                            *direct.get_mut(direct_base.checked_add(word)?)? |= reached;
                        }
                    }
                }
            }
        }

        let initial_base = start.checked_mul(words)?;
        let mut initial = [0_u64; MAX_BIT_PARALLEL_EXISTS_WORDS];
        initial[..words]
            .copy_from_slice(closures.get(initial_base..initial_base.checked_add(words)?)?);

        let (transition_masks, root_transition_masks) = if words == 1 {
            resources.charge(transition_entries)?;
            let mut transition_masks = Vec::new();
            transition_masks
                .try_reserve_exact(transition_entries)
                .ok()?;
            transition_masks.resize(transition_entries, 0_u64);
            for class in 0..byte_classes {
                for nibble in 0..source_nibbles {
                    let base = class
                        .checked_mul(source_nibbles)?
                        .checked_add(nibble)?
                        .checked_mul(NIBBLE_SUBSETS)?;
                    for subset in 1..NIBBLE_SUBSETS {
                        let prior = subset & subset.checked_sub(1)?;
                        let bit = usize::try_from(subset.trailing_zeros()).ok()?;
                        let ordinal = nibble.checked_mul(NIBBLE_BITS)?.checked_add(bit)?;
                        let mut reached = *transition_masks.get(base.checked_add(prior)?)?;
                        if ordinal < consuming_states {
                            let direct_index =
                                class.checked_mul(consuming_states)?.checked_add(ordinal)?;
                            reached |= *direct.get(direct_index)?;
                        }
                        *transition_masks.get_mut(base.checked_add(subset)?)? = reached;
                    }
                }
            }
            (transition_masks.into_boxed_slice(), Box::from([]))
        } else {
            let mut root_transition_masks = Vec::new();
            root_transition_masks
                .try_reserve_exact(root_transition_entries)
                .ok()?;
            root_transition_masks.resize(root_transition_entries, 0_u64);
            for byte in 0..BYTE_VALUES {
                let class = usize::from(byte_to_class[byte]);
                for source_word in 0..words {
                    let mut roots = initial[source_word];
                    if source_word.checked_add(1)? == words {
                        roots &= CONSUMING_BITS;
                    }
                    while roots != 0 {
                        resources.charge(words)?;
                        let bit = usize::try_from(roots.trailing_zeros()).ok()?;
                        roots &= roots.checked_sub(1)?;
                        let ordinal = source_word.checked_mul(64)?.checked_add(bit)?;
                        if ordinal >= consuming_states {
                            return None;
                        }
                        let direct_base = class
                            .checked_mul(consuming_states)?
                            .checked_add(ordinal)?
                            .checked_mul(words)?;
                        let root_base = byte.checked_mul(words)?;
                        for destination_word in 0..words {
                            *root_transition_masks
                                .get_mut(root_base.checked_add(destination_word)?)? |=
                                *direct.get(direct_base.checked_add(destination_word)?)?;
                        }
                    }
                }
            }
            (
                direct.into_boxed_slice(),
                root_transition_masks.into_boxed_slice(),
            )
        };

        let receipt = BitParallelExistsStats {
            thompson_states: states,
            thompson_edges: edges,
            consuming_states,
            byte_classes,
            words,
            source_nibbles,
            transition_entries,
            root_transition_entries,
            retained_bytes,
            peak_build_bytes,
            derivation_work: resources.used,
        };
        Some(Self {
            byte_to_class,
            raw_to_consuming,
            transition_masks,
            root_transition_masks,
            initial,
            words,
            source_nibbles,
            stats: receipt,
        })
    }

    pub(crate) const fn stats(&self) -> BitParallelExistsStats {
        self.stats
    }

    pub(crate) fn native_view(&self) -> NativeBitParallelExistsView<'_> {
        NativeBitParallelExistsView {
            byte_to_class: &self.byte_to_class,
            transition_masks: &self.transition_masks,
            root_transition_masks: &self.root_transition_masks,
            initial: self.initial,
            stats: self.stats,
        }
    }

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "constructor-proved class/nibble bounds make the hot table index exact"
    )]
    pub(crate) fn search(
        &self,
        haystack: &[u8],
        window_start: usize,
        window_end: usize,
    ) -> Result<bool, CompileError> {
        let source =
            haystack
                .get(window_start..window_end)
                .ok_or(CompileError::InternalInvariant(
                    "bit-parallel Exists received an unvalidated source window",
                ))?;
        let final_word = self
            .words
            .checked_sub(1)
            .ok_or(CompileError::InternalInvariant(
                "bit-parallel Exists has no machine words",
            ))?;
        if self.initial[final_word] & ACCEPT_BIT != 0 {
            return Ok(true);
        }
        let mut root = self.initial;
        root[final_word] &= CONSUMING_BITS;
        if root[..self.words].iter().all(|&word| word == 0) {
            return Ok(false);
        }
        self.search_active(source, root)
    }

    /// Continue from one canonically authenticated partial-DFA frontier.
    ///
    /// `raw_frontier` contains epsilon-closed consuming raw-state indices at
    /// `resume_position`, the first byte not consumed by the retained table.
    /// The unanchored root is present in canonical Exists keys, but injecting
    /// it again is idempotent and makes the boundary invariant explicit.
    pub(crate) fn search_from_raw_frontier(
        &self,
        haystack: &[u8],
        resume_position: usize,
        window_end: usize,
        raw_frontier: &[u32],
    ) -> Result<bool, CompileError> {
        let source =
            haystack
                .get(resume_position..window_end)
                .ok_or(CompileError::InternalInvariant(
                    "bit-parallel Exists resume exceeded the validated source window",
                ))?;
        let final_word = self
            .words
            .checked_sub(1)
            .ok_or(CompileError::InternalInvariant(
                "bit-parallel Exists has no machine words",
            ))?;
        if self.initial[final_word] & ACCEPT_BIT != 0 {
            return Ok(true);
        }
        let mut root = self.initial;
        root[final_word] &= CONSUMING_BITS;
        let mut active = root;
        for &raw_state in raw_frontier {
            let raw_state = usize::try_from(raw_state).map_err(|_| {
                CompileError::InternalInvariant(
                    "bit-parallel Exists resume state exceeded the host index",
                )
            })?;
            let ordinal =
                *self
                    .raw_to_consuming
                    .get(raw_state)
                    .ok_or(CompileError::InternalInvariant(
                        "bit-parallel Exists resume state exceeded the Thompson graph",
                    ))?;
            if ordinal == ABSENT_CONSUMING {
                return Err(CompileError::InternalInvariant(
                    "bit-parallel Exists resume frontier contains a non-consuming state",
                ));
            }
            let ordinal = usize::from(ordinal);
            let word = ordinal / 64;
            let bit = ordinal % 64;
            *active.get_mut(word).ok_or(CompileError::InternalInvariant(
                "bit-parallel Exists resume state exceeded the bounded machine",
            ))? |= 1_u64
                .checked_shl(u32::try_from(bit).map_err(|_| {
                    CompileError::InternalInvariant(
                        "bit-parallel Exists resume bit exceeded the machine word",
                    )
                })?)
                .ok_or(CompileError::InternalInvariant(
                    "bit-parallel Exists resume bit exceeded the machine word",
                ))?;
        }
        if active[..self.words].iter().all(|&word| word == 0) {
            return Ok(false);
        }
        self.search_active(source, active)
    }

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "constructor-proved class/nibble bounds make the hot table index exact"
    )]
    fn search_active(
        &self,
        source: &[u8],
        mut active: [u64; MAX_BIT_PARALLEL_EXISTS_WORDS],
    ) -> Result<bool, CompileError> {
        if self.words != 1 {
            return self.search_active_multiword(source, active);
        }
        let root = self.initial[0] & CONSUMING_BITS;
        for &byte in source {
            let class = usize::from(self.byte_to_class[usize::from(byte)]);
            let class_base = class * self.source_nibbles * NIBBLE_SUBSETS;
            let mut reached = 0_u64;
            for nibble in 0..self.source_nibbles {
                let subset =
                    usize::try_from((active[0] >> (nibble * NIBBLE_BITS)) & NIBBLE_SUBSET_MASK)
                        .map_err(|_| {
                            CompileError::InternalInvariant(
                                "bit-parallel Exists subset exceeded the host index",
                            )
                        })?;
                if subset != 0 {
                    let index = class_base + nibble * NIBBLE_SUBSETS + subset;
                    reached |= *self.transition_masks.get(index).ok_or(
                        CompileError::InternalInvariant(
                            "bit-parallel Exists transition table is incomplete",
                        ),
                    )?;
                }
            }
            if reached & ACCEPT_BIT != 0 {
                return Ok(true);
            }
            active[0] = (reached & CONSUMING_BITS) | root;
        }
        Ok(false)
    }

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "constructor-proved word, class, ordinal, and row bounds make the hot table indices exact"
    )]
    fn search_active_multiword(
        &self,
        source: &[u8],
        mut active: [u64; MAX_BIT_PARALLEL_EXISTS_WORDS],
    ) -> Result<bool, CompileError> {
        let final_word = self
            .words
            .checked_sub(1)
            .ok_or(CompileError::InternalInvariant(
                "bit-parallel Exists has no machine words",
            ))?;
        let mut root = self.initial;
        root[final_word] &= CONSUMING_BITS;
        for &byte in source {
            let byte = usize::from(byte);
            let class = usize::from(self.byte_to_class[byte]);
            let root_base = byte * self.words;
            let mut reached = [0_u64; MAX_BIT_PARALLEL_EXISTS_WORDS];
            reached[..self.words].copy_from_slice(
                self.root_transition_masks
                    .get(root_base..root_base + self.words)
                    .ok_or(CompileError::InternalInvariant(
                        "bit-parallel Exists root-transition cache is incomplete",
                    ))?,
            );
            for source_word in 0..self.words {
                let mut sources = active[source_word] & !root[source_word];
                if source_word == final_word {
                    sources &= CONSUMING_BITS;
                }
                while sources != 0 {
                    let source_bit = usize::try_from(sources.trailing_zeros()).map_err(|_| {
                        CompileError::InternalInvariant(
                            "bit-parallel Exists source bit exceeded the host index",
                        )
                    })?;
                    sources &= sources
                        .checked_sub(1)
                        .ok_or(CompileError::InternalInvariant(
                            "bit-parallel Exists source set underflowed",
                        ))?;
                    let ordinal = source_word * 64 + source_bit;
                    if ordinal >= self.stats.consuming_states {
                        return Err(CompileError::InternalInvariant(
                            "bit-parallel Exists active set contains a reserved bit",
                        ));
                    }
                    let direct_base = (class * self.stats.consuming_states + ordinal) * self.words;
                    let direct = self
                        .transition_masks
                        .get(direct_base..direct_base + self.words)
                        .ok_or(CompileError::InternalInvariant(
                            "bit-parallel Exists direct transition table is incomplete",
                        ))?;
                    for destination_word in 0..self.words {
                        reached[destination_word] |= direct[destination_word];
                    }
                }
            }
            if reached[final_word] & ACCEPT_BIT != 0 {
                return Ok(true);
            }
            reached[final_word] &= CONSUMING_BITS;
            for word in 0..self.words {
                active[word] = reached[word] | root[word];
            }
        }
        Ok(false)
    }
}

fn state_edges(raw: &RawPlan, state: usize) -> Option<core::ops::Range<usize>> {
    let begin = usize::try_from(*raw.edge_offsets.get(state)?).ok()?;
    let end = usize::try_from(*raw.edge_offsets.get(state.checked_add(1)?)?).ok()?;
    (begin <= end
        && end <= raw.edge_targets.len()
        && end <= raw.edge_kinds.len()
        && end <= raw.byte_starts.len()
        && end <= raw.byte_ends.len())
    .then_some(begin..end)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alternation_plan() -> RawPlan {
        RawPlan {
            start: 0,
            roles: vec![
                StateRole::Split,
                StateRole::Consume,
                StateRole::Accept,
                StateRole::Consume,
                StateRole::Consume,
            ],
            edge_offsets: vec![0, 2, 3, 3, 4, 5],
            edge_targets: vec![1, 3, 2, 4, 2],
            edge_kinds: vec![
                EdgeKind::Epsilon,
                EdgeKind::Epsilon,
                EdgeKind::ByteRange,
                EdgeKind::ByteRange,
                EdgeKind::ByteRange,
            ],
            byte_starts: vec![0, 0, b'a', b'b', b'c'],
            byte_ends: vec![0, 0, b'a', b'b', b'c'],
        }
    }

    #[test]
    fn canonical_word_machine_has_exact_resources_and_root_restarts() {
        let raw = alternation_plan();
        let machine = BitParallelExists::derive(&raw).expect("bounded assertion-free graph");
        let stats = machine.stats();
        assert_eq!(stats.thompson_states, 5);
        assert_eq!(stats.thompson_edges, 5);
        assert_eq!(stats.consuming_states, 3);
        assert_eq!(stats.words, 1);
        assert_eq!(stats.source_nibbles, 1);
        assert_eq!(stats.root_transition_entries, 0);
        assert_eq!(
            stats.transition_entries,
            stats.byte_classes * stats.source_nibbles * NIBBLE_SUBSETS
        );
        assert_eq!(
            stats.retained_bytes,
            core::mem::size_of::<BitParallelExists>()
                + stats.transition_entries * core::mem::size_of::<u64>()
        );
        assert!(stats.peak_build_bytes >= stats.retained_bytes);
        assert!(stats.derivation_work > 0);

        assert!(machine.search(b"a", 0, 1).unwrap());
        assert!(machine.search(b"bc", 0, 2).unwrap());
        assert!(machine.search(b"xxbcxx", 0, 6).unwrap());
        assert!(machine.search(b"xxbcxx", 2, 4).unwrap());
        assert!(!machine.search(b"xxbcxx", 0, 3).unwrap());
        assert!(!machine.search(b"xxbcxx", 4, 6).unwrap());
        assert!(!machine.search(b"", 0, 0).unwrap());
        assert!(machine.search_from_raw_frontier(b"c", 0, 1, &[4]).unwrap());
        assert!(
            machine.search_from_raw_frontier(b"a", 0, 1, &[]).unwrap(),
            "the unanchored root must be injected at the resume boundary"
        );
        assert!(
            machine.search_from_raw_frontier(b"a", 0, 1, &[0]).is_err(),
            "a split state is not an authenticated consuming frontier item"
        );

        let exact_limits = BitParallelExistsLimits {
            states: stats.thompson_states,
            work: stats.derivation_work,
            memory_bytes: stats.peak_build_bytes,
        };
        assert_eq!(
            BitParallelExists::derive_with_limits(&raw, exact_limits)
                .expect("exact limits")
                .stats(),
            stats
        );
        assert!(
            BitParallelExists::derive_with_limits(
                &raw,
                BitParallelExistsLimits {
                    states: stats.thompson_states - 1,
                    ..exact_limits
                },
            )
            .is_none()
        );
        assert!(
            BitParallelExists::derive_with_limits(
                &raw,
                BitParallelExistsLimits {
                    work: stats.derivation_work - 1,
                    ..exact_limits
                },
            )
            .is_none()
        );
        assert!(
            BitParallelExists::derive_with_limits(
                &raw,
                BitParallelExistsLimits {
                    memory_bytes: stats.peak_build_bytes - 1,
                    ..exact_limits
                },
            )
            .is_none()
        );

        let mut asserted = raw.clone();
        asserted.edge_kinds[0] = EdgeKind::AssertHaystackStart;
        assert!(BitParallelExists::derive(&asserted).is_none());
        let mut malformed = raw;
        malformed.edge_offsets.pop();
        assert!(BitParallelExists::derive(&malformed).is_none());
    }

    #[test]
    fn nullable_and_dead_roots_preserve_empty_and_restart_semantics() {
        let nullable = RawPlan {
            start: 0,
            roles: vec![StateRole::Accept],
            edge_offsets: vec![0, 0],
            edge_targets: Vec::new(),
            edge_kinds: Vec::new(),
            byte_starts: Vec::new(),
            byte_ends: Vec::new(),
        };
        let nullable = BitParallelExists::derive(&nullable).expect("nullable root");
        assert_eq!(nullable.stats().consuming_states, 0);
        assert_eq!(nullable.stats().words, 1);
        assert_eq!(nullable.stats().source_nibbles, 0);
        assert_eq!(nullable.stats().transition_entries, 0);
        assert!(nullable.search(b"", 0, 0).unwrap());
        assert!(nullable.search(b"xyz", 1, 2).unwrap());

        // The unreachable accept keeps this a valid graph shape while the
        // consuming root has no outgoing byte edge. Restarting that dead root
        // at every boundary must remain rejecting rather than manufacturing a
        // transition or accepting at the final boundary.
        let dead = RawPlan {
            start: 0,
            roles: vec![StateRole::Consume, StateRole::Accept],
            edge_offsets: vec![0, 0, 0],
            edge_targets: Vec::new(),
            edge_kinds: Vec::new(),
            byte_starts: Vec::new(),
            byte_ends: Vec::new(),
        };
        let dead = BitParallelExists::derive(&dead).expect("dead consuming root");
        assert_eq!(dead.stats().consuming_states, 1);
        assert!(!dead.search(b"", 0, 0).unwrap());
        assert!(!dead.search(b"xyz", 0, 3).unwrap());
        assert!(!dead.search(b"xyz", 1, 2).unwrap());
    }

    fn literal_chain_plan(consuming_states: usize) -> RawPlan {
        assert!((1..=MAX_CONSUMING_STATES).contains(&consuming_states));
        let mut roles = vec![StateRole::Consume; consuming_states];
        roles.push(StateRole::Accept);
        let mut edge_offsets = Vec::with_capacity(roles.len() + 1);
        for offset in 0..=consuming_states {
            edge_offsets.push(u32::try_from(offset).unwrap());
        }
        edge_offsets.push(u32::try_from(consuming_states).unwrap());
        RawPlan {
            start: 0,
            roles,
            edge_offsets,
            edge_targets: (1..=consuming_states)
                .map(|target| u32::try_from(target).unwrap())
                .collect(),
            edge_kinds: vec![EdgeKind::ByteRange; consuming_states],
            byte_starts: vec![b'a'; consuming_states],
            byte_ends: vec![b'a'; consuming_states],
        }
    }

    #[test]
    fn every_word_boundary_is_exact_bounded_and_uses_the_root_cache() {
        for (consuming_states, words) in [
            (63, 1),
            (64, 2),
            (127, 2),
            (128, 3),
            (191, 3),
            (192, 4),
            (255, 4),
        ] {
            let raw = literal_chain_plan(consuming_states);
            let machine = BitParallelExists::derive(&raw).expect("bounded literal chain");
            let stats = machine.stats();
            assert_eq!(stats.thompson_states, consuming_states + 1);
            assert_eq!(stats.consuming_states, consuming_states);
            assert_eq!(stats.words, words);
            assert_eq!(stats.source_nibbles, (words == 1).then(|| consuming_states.div_ceil(4)).unwrap_or(0));
            assert_eq!(
                stats.root_transition_entries,
                if words == 1 { 0 } else { BYTE_VALUES * words }
            );
            assert_eq!(machine.root_transition_masks.len(), stats.root_transition_entries);
            assert!(stats.derivation_work <= MAX_BIT_PARALLEL_EXISTS_WORK);
            assert!(stats.peak_build_bytes <= MAX_BIT_PARALLEL_EXISTS_MEMORY_BYTES);

            let accepted = vec![b'a'; consuming_states];
            let rejected = vec![b'a'; consuming_states - 1];
            let mut restarted = vec![b'x'; 9];
            restarted.extend_from_slice(&accepted);
            assert!(machine.search(&accepted, 0, accepted.len()).unwrap());
            assert!(!machine.search(&rejected, 0, rejected.len()).unwrap());
            assert!(machine.search(&restarted, 0, restarted.len()).unwrap());
            assert!(!machine.search(&restarted, 0, restarted.len() - 1).unwrap());

            let exact_limits = BitParallelExistsLimits {
                states: stats.thompson_states,
                work: stats.derivation_work,
                memory_bytes: stats.peak_build_bytes,
            };
            assert_eq!(
                BitParallelExists::derive_with_limits(&raw, exact_limits)
                    .expect("exact multiword limits")
                    .stats(),
                stats
            );
        }
    }
}
