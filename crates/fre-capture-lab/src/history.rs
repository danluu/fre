//! Persistent capture-history candidate executor.

use core::mem::size_of;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use crate::ast::Ast;
use crate::backtrack::BoundedBacktracker;
use crate::compile::{Program, State};
use crate::error::{BuildError, ResourceKind, SearchError};
use crate::limits::{AggregateLimits, BuildLimits, SearchLimits};
use crate::model::{
    AggregateOutcome, BoundedBacktrackProspective, CandidateKind, CaptureCountOutcome,
    CaptureGroupSlot, ExactCaptureSlotsOutcome, HistoryProgramShape, HistorySearchProspective,
    MatchKind, PARTICIPATION_QUOTIENT_CAPTURE_BITS, PARTICIPATION_QUOTIENT_MASK_BITS,
    ParticipationSearchOutcome, ParticipationSearchProspective, RestartedHistoryProspective,
    RunReport, SearchConfig, SearchKind, SearchOutcome, Span, Window,
};
use crate::runtime::HISTORY_CHUNK_CAPACITY;
use crate::runtime::{
    admit_history, admit_history_exact, admit_participation_exact, assertion_matches, canonicalize,
    canonicalize_unset, check, checked_add, commit_capture_group_slots,
    participation_exact_prospective, validate_window,
};

const UNSET_SLOT: usize = usize::MAX;
static NEXT_HISTORY_IDENTITY: AtomicU64 = AtomicU64::new(1);

fn next_history_identity() -> u64 {
    NEXT_HISTORY_IDENTITY
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |identity| {
            identity.checked_add(1)
        })
        .unwrap_or_else(|_| panic!("history exact-workspace identity space exhausted"))
}

/// Version of the exact-span capture-participation history quotient.
pub const PARTICIPATION_QUOTIENT_ALGORITHM_VERSION: u32 = 1;

/// Version of the quotient state-visit, scratch, and zero-history ledger.
pub const PARTICIPATION_QUOTIENT_ACCOUNTING_VERSION: u32 = 1;

/// Version of the fixed exact-history transition algorithm.
pub const HISTORY_EXACT_WORKSPACE_ALGORITHM_VERSION: u32 = 2;

/// Version of the fixed exact-history admission and runtime-closure ledger.
pub const HISTORY_EXACT_WORKSPACE_ACCOUNTING_VERSION: u32 = 2;

#[derive(Clone, Copy, Debug)]
struct Thread {
    pc: usize,
    history: Option<usize>,
}

#[derive(Clone, Copy, Debug)]
struct ParticipationThread {
    pc: usize,
    open: u64,
    participated: u64,
}

#[derive(Clone, Copy, Debug)]
struct HistoryNode {
    slot: usize,
    offset: usize,
    previous: Option<usize>,
}

#[derive(Debug)]
struct HistoryArena {
    chunks: Vec<Vec<HistoryNode>>,
    len: usize,
    limit: usize,
}

impl HistoryArena {
    fn new(limit: usize) -> Result<Self, SearchError> {
        let chunk_count = limit
            .checked_add(HISTORY_CHUNK_CAPACITY.saturating_sub(1))
            .ok_or(SearchError::BoundOverflow(ResourceKind::HistoryNodes))?
            .checked_div(HISTORY_CHUNK_CAPACITY)
            .ok_or(SearchError::BoundOverflow(ResourceKind::HistoryNodes))?;
        let chunks = exact_capacity_vec(chunk_count, ResourceKind::HistoryNodes)?;
        Ok(Self {
            chunks,
            len: 0,
            limit,
        })
    }

    fn preallocated(limit: usize) -> Result<Self, SearchError> {
        let mut arena = Self::new(limit)?;
        let chunk_count = limit
            .checked_add(HISTORY_CHUNK_CAPACITY.saturating_sub(1))
            .ok_or(SearchError::BoundOverflow(ResourceKind::HistoryNodes))?
            .checked_div(HISTORY_CHUNK_CAPACITY)
            .ok_or(SearchError::BoundOverflow(ResourceKind::HistoryNodes))?;
        for chunk_index in 0..chunk_count {
            let consumed = chunk_index
                .checked_mul(HISTORY_CHUNK_CAPACITY)
                .ok_or(SearchError::BoundOverflow(ResourceKind::HistoryNodes))?;
            let capacity = limit
                .checked_sub(consumed)
                .ok_or(SearchError::BoundOverflow(ResourceKind::HistoryNodes))?
                .min(HISTORY_CHUNK_CAPACITY);
            let chunk = exact_capacity_vec(capacity, ResourceKind::HistoryNodes)?;
            arena.chunks.push(chunk);
        }
        if !arena.is_exactly_preallocated(limit) {
            return Err(SearchError::Allocation(ResourceKind::HistoryNodes));
        }
        Ok(arena)
    }

    fn reset(&mut self) {
        for chunk in &mut self.chunks {
            chunk.clear();
        }
        self.len = 0;
    }

    fn push(&mut self, node: HistoryNode) -> Result<usize, SearchError> {
        let required = checked_add(self.len, 1, ResourceKind::HistoryNodes)?;
        check(ResourceKind::HistoryNodes, required, self.limit)?;
        let chunk_index = self.len / HISTORY_CHUNK_CAPACITY;
        if chunk_index == self.chunks.len() {
            let remaining = self
                .limit
                .checked_sub(self.len)
                .ok_or(SearchError::BoundOverflow(ResourceKind::HistoryNodes))?;
            let capacity = remaining.min(HISTORY_CHUNK_CAPACITY);
            let chunk = exact_capacity_vec(capacity, ResourceKind::HistoryNodes)?;
            self.chunks.push(chunk);
        }
        let id = self.len;
        let chunk = self
            .chunks
            .get_mut(chunk_index)
            .ok_or(SearchError::InvalidProgram)?;
        chunk.push(node);
        self.len = required;
        Ok(id)
    }

    fn get(&self, id: usize) -> Option<&HistoryNode> {
        if id >= self.len {
            return None;
        }
        let chunk = id / HISTORY_CHUNK_CAPACITY;
        let offset = id % HISTORY_CHUNK_CAPACITY;
        self.chunks.get(chunk)?.get(offset)
    }

    const fn len(&self) -> usize {
        self.len
    }

    fn is_exactly_preallocated(&self, limit: usize) -> bool {
        let Some(chunk_count) = limit
            .checked_add(HISTORY_CHUNK_CAPACITY.saturating_sub(1))
            .and_then(|rounded| rounded.checked_div(HISTORY_CHUNK_CAPACITY))
        else {
            return false;
        };
        if self.limit != limit
            || self.chunks.len() != chunk_count
            || self.chunks.capacity() != chunk_count
        {
            return false;
        }
        self.chunks.iter().enumerate().all(|(index, chunk)| {
            index
                .checked_mul(HISTORY_CHUNK_CAPACITY)
                .and_then(|consumed| limit.checked_sub(consumed))
                .is_some_and(|remaining| chunk.capacity() == remaining.min(HISTORY_CHUNK_CAPACITY))
        })
    }
}

fn exact_capacity_vec<T>(capacity: usize, resource: ResourceKind) -> Result<Vec<T>, SearchError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(capacity)
        .map_err(|_| SearchError::Allocation(resource))?;
    if values.capacity() != capacity {
        return Err(SearchError::Allocation(resource));
    }
    Ok(values)
}

/// Complete fixed-capacity dimensions for one reusable exact-history owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistoryExactWorkspaceUsage {
    /// Exact fixed-workspace transition algorithm.
    pub algorithm_version: u32,
    /// Exact admission and runtime-closure ledger.
    pub accounting_version: u32,
    /// Maximum admitted exact-span byte width.
    pub max_span_bytes: usize,
    /// Capacity of each current/next/closure thread vector.
    pub thread_capacity: usize,
    /// Fixed persistent-history node capacity.
    pub history_node_capacity: usize,
    /// Raw start/end tag words retained for materialization.
    pub slot_capacity: usize,
    /// Conservative algorithm scratch bound admitted under `SearchLimits`.
    pub admitted_scratch_bytes: usize,
    /// Exact retained element bytes including the workspace header and every
    /// fixed vector/chunk capacity (allocator metadata overhead excluded).
    pub persistent_bytes: usize,
}

/// Caller-owned allocation-free exact-span persistent-history storage.
///
/// The workspace contains no program-derived pointers or transition tables.
/// A source-independent binding plus complete shape authenticates it either
/// to one [`HistoryRegex`] clone lineage or to a byte-identical stable capture
/// program.
#[derive(Debug)]
pub struct HistoryExactWorkspace {
    binding: HistoryExactWorkspaceBinding,
    shape: HistoryProgramShape,
    current: Vec<Thread>,
    next: Vec<Thread>,
    stack: Vec<Thread>,
    seen: Vec<usize>,
    histories: HistoryArena,
    pub(crate) slots: Vec<usize>,
    limits: SearchLimits,
    usage: HistoryExactWorkspaceUsage,
}

/// Caller-owned reusable exact-span capture-participation storage.
///
/// The fixed-capacity frontier is bound to one [`HistoryRegex`] clone lineage.
/// Replays may use distinct source windows and search limits; each call still
/// performs its complete prospective admission before reading source bytes.
#[derive(Debug)]
pub struct ParticipationExactWorkspace {
    identity: u64,
    current: Vec<ParticipationThread>,
    next: Vec<ParticipationThread>,
    stack: Vec<ParticipationThread>,
    seen: Vec<usize>,
    generation: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HistoryExactWorkspaceBinding {
    HistoryLineage(u64),
    CaptureProgramV1([u8; 32]),
}

#[derive(Debug)]
struct Counters {
    state_visits: usize,
    history_walk: usize,
    starts_injected: usize,
    bytes_examined: usize,
    peak_threads: usize,
}

/// Exact Pike-style executor with persistent tagged histories.
#[derive(Clone, Debug)]
pub struct HistoryRegex {
    program: Arc<Program>,
    identity: u64,
}

impl HistoryRegex {
    /// Compile and wrap a laboratory AST.
    pub fn compile(ast: &Ast, limits: BuildLimits) -> Result<Self, BuildError> {
        Ok(Self {
            program: Arc::new(Program::compile(ast, limits)?),
            identity: next_history_identity(),
        })
    }

    /// Wrap an already compiled immutable program.
    #[must_use]
    pub fn from_program(program: Arc<Program>) -> Self {
        Self {
            program,
            identity: next_history_identity(),
        }
    }

    /// Access the shared immutable program.
    #[must_use]
    pub fn program(&self) -> &Arc<Program> {
        &self.program
    }

    /// Immutable shape used by an outer construction owner to authenticate
    /// persistent-history prospective receipts.
    #[must_use]
    pub fn program_shape(&self) -> HistoryProgramShape {
        self.program.history_program_shape()
    }

    /// Derive one search envelope without inspecting source bytes.
    pub fn search_prospective(
        &self,
        window: Window,
        from: usize,
    ) -> Result<HistorySearchProspective, SearchError> {
        self.program_shape().search_prospective(window, from)
    }

    /// Derive the optional resource-bounded backtracking envelope without
    /// inspecting source bytes. Unsupported search policies return `None`;
    /// the returned prospective remains authoritative for every window size.
    pub fn bounded_backtrack_prospective(
        &self,
        window: Window,
        from: usize,
        config: SearchConfig,
    ) -> Result<Option<BoundedBacktrackProspective>, SearchError> {
        if window.start > window.end || from < window.start || from > window.end {
            return Err(SearchError::InvalidWindow);
        }
        if config.kind != SearchKind::Leftmost || config.match_kind != MatchKind::LeftmostFirst {
            return Ok(None);
        }
        let backtracker = BoundedBacktracker::new(&self.program);
        if !backtracker.is_supported() {
            return Ok(None);
        }
        backtracker
            .prospective(window, from, config.anchored)
            .map(Some)
    }

    /// Derive the complete restarted-session envelope without inspecting
    /// source bytes.
    pub fn restarted_prospective(
        &self,
        window: Window,
    ) -> Result<RestartedHistoryProspective, SearchError> {
        self.program_shape().restarted_prospective(window)
    }

    /// Find the first leftmost-first match and its captures in `window`.
    pub fn captures(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
    ) -> Result<SearchOutcome, SearchError> {
        self.captures_with_config(haystack, window, SearchConfig::LEFTMOST, limits)
    }

    /// Find the first capture record under an explicit selection and
    /// anchoring policy.
    pub fn captures_with_config(
        &self,
        haystack: &[u8],
        window: Window,
        config: SearchConfig,
        limits: SearchLimits,
    ) -> Result<SearchOutcome, SearchError> {
        if config.kind == SearchKind::Leftmost
            && config.match_kind == MatchKind::LeftmostFirst
            && window.start <= window.end
            && window.end <= haystack.len()
        {
            let backtracker = BoundedBacktracker::new(&self.program);
            if let Ok(prospective) =
                backtracker.admit(window, window.start, config.anchored, limits)
            {
                if let Some(prefilter) =
                    backtracker.candidate_prefilter(window, window.start, config.anchored)
                {
                    return backtracker.captures_prefiltered(
                        haystack,
                        window,
                        window.start,
                        prefilter,
                        prospective,
                    );
                }
                return backtracker.captures(
                    haystack,
                    window,
                    window.start,
                    config.anchored,
                    prospective,
                );
            }
        }
        self.search_from(haystack, window, window.start, config, limits)
    }

    /// Run one persistent-history search from `from` while preserving the
    /// original logical window for assertions. This is the bounded primitive
    /// used by the facade-owned restarted capture-array session.
    pub fn captures_from_with_config(
        &self,
        haystack: &[u8],
        window: Window,
        from: usize,
        config: SearchConfig,
        limits: SearchLimits,
    ) -> Result<SearchOutcome, SearchError> {
        self.search_from(haystack, window, from, config, limits)
    }

    /// Search while restricting the domain of newly injected starts.
    ///
    /// `maximum_start` is an inclusive absolute ceiling. `Some(ceiling)`
    /// searches new starts in `from..=min(ceiling, window.end)`, subject to the
    /// ordinary anchoring policy. `None`, or a ceiling below `from`, selects an
    /// empty new-start domain. Consequently, this operation may omit a real
    /// match that begins after the ceiling. Threads injected at or before the
    /// ceiling remain live and may finish after it.
    ///
    /// Complete window validation and history admission precede an empty-domain
    /// result, preserving the ordinary typed refusal boundary.
    #[doc(hidden)]
    pub fn captures_from_with_config_start_ceiling(
        &self,
        haystack: &[u8],
        window: Window,
        from: usize,
        config: SearchConfig,
        maximum_start: Option<usize>,
        limits: SearchLimits,
    ) -> Result<SearchOutcome, SearchError> {
        self.search_from_start_ceiling(
            haystack,
            window,
            from,
            config,
            maximum_start,
            limits,
        )
    }

    /// Derive the complete fixed exact-history workspace before allocation or
    /// source access.
    pub fn exact_workspace_usage(
        &self,
        max_span_bytes: usize,
        limits: SearchLimits,
    ) -> Result<HistoryExactWorkspaceUsage, SearchError> {
        derive_history_exact_workspace_usage(&self.program, max_span_bytes, limits)
    }

    /// Allocate every buffer and history chunk needed for exact replay up to
    /// `max_span_bytes`.
    ///
    /// After successful preparation, accepted calls to
    /// [`Self::captures_exact_slots_with_workspace`] perform no allocation.
    pub fn prepare_exact_workspace(
        &self,
        max_span_bytes: usize,
        limits: SearchLimits,
    ) -> Result<HistoryExactWorkspace, SearchError> {
        prepare_history_exact_workspace(
            &self.program,
            HistoryExactWorkspaceBinding::HistoryLineage(self.identity),
            max_span_bytes,
            limits,
        )
    }

    /// Replay one exact span into a fixed caller-owned group array.
    ///
    /// Workspace identity, output capacity, domain bounds, and the prepared
    /// maximum span are checked before source access. On any error `output` is
    /// unchanged. Successful non-match publishes all groups as unmatched.
    pub fn captures_exact_slots_with_workspace(
        &self,
        workspace: &mut HistoryExactWorkspace,
        haystack: &[u8],
        window: Window,
        span: Span,
        output: &mut [CaptureGroupSlot],
    ) -> Result<ExactCaptureSlotsOutcome, SearchError> {
        if output.len() != self.program.groups.len()
            || workspace.slots.len() != self.program.slot_count
        {
            return Err(SearchError::InvalidProgram);
        }
        let outcome = execute_exact_with_workspace(
            &self.program,
            HistoryExactWorkspaceBinding::HistoryLineage(self.identity),
            workspace,
            haystack,
            window,
            span,
        )?;
        if outcome.matched {
            commit_capture_group_slots(&self.program, &workspace.slots, UNSET_SLOT, span, output)?;
        } else {
            output.fill(CaptureGroupSlot::UNMATCHED);
        }
        Ok(outcome)
    }

    /// Search from `from` with fixed persistent-history storage and publish
    /// the first complete capture record into a caller-owned group array.
    ///
    /// The workspace may be reused across successive searches and independent
    /// windows up to its prepared byte width. All call-specific admission and
    /// capacity checks complete before source access; on error `output` is
    /// unchanged.
    pub fn captures_from_slots_with_workspace(
        &self,
        workspace: &mut HistoryExactWorkspace,
        haystack: &[u8],
        window: Window,
        from: usize,
        config: SearchConfig,
        output: &mut [CaptureGroupSlot],
        limits: SearchLimits,
    ) -> Result<ExactCaptureSlotsOutcome, SearchError> {
        if output.len() != self.program.groups.len()
            || workspace.slots.len() != self.program.slot_count
        {
            return Err(SearchError::InvalidProgram);
        }
        let outcome = execute_search_with_workspace(
            &self.program,
            HistoryExactWorkspaceBinding::HistoryLineage(self.identity),
            workspace,
            haystack,
            window,
            from,
            config,
            limits,
        )?;
        if outcome.matched {
            let start = workspace.slots.first().copied().ok_or(SearchError::InvalidProgram)?;
            let end = workspace.slots.get(1).copied().ok_or(SearchError::InvalidProgram)?;
            if start == UNSET_SLOT || end == UNSET_SLOT || start > end {
                return Err(SearchError::InvalidProgram);
            }
            commit_capture_group_slots(
                &self.program,
                &workspace.slots,
                UNSET_SLOT,
                Span { start, end },
                output,
            )?;
        } else {
            output.fill(CaptureGroupSlot::UNMATCHED);
        }
        Ok(outcome)
    }

    /// Query one exact span while preserving assertion context from the
    /// original logical window.
    ///
    /// The start thread is injected exactly once. Match states before
    /// `span.end` are ignored, and the first prioritized match at `span.end`
    /// supplies captures. A span outside the pattern's language returns a
    /// successful outcome with no captures. Callers that already certified a
    /// span can therefore use the same operation for tagged replay, while
    /// correctness-oriented callers may enumerate exact spans without
    /// confusing an ordinary non-match with an invalid program.
    #[allow(
        clippy::too_many_lines,
        reason = "the exact-span tagged replay keeps its one-pass state transition auditable"
    )]
    pub fn captures_exact(
        &self,
        haystack: &[u8],
        window: Window,
        span: Span,
        limits: SearchLimits,
    ) -> Result<SearchOutcome, SearchError> {
        validate_window(haystack, window, span.start)?;
        if span.start > span.end || span.start < window.start || span.end > window.end {
            return Err(SearchError::InvalidWindow);
        }
        let max_span_bytes = span
            .end
            .checked_sub(span.start)
            .ok_or(SearchError::InvalidWindow)?;
        let mut workspace = self.prepare_exact_workspace(max_span_bytes, limits)?;
        let raw = execute_exact_with_workspace(
            &self.program,
            HistoryExactWorkspaceBinding::HistoryLineage(self.identity),
            &mut workspace,
            haystack,
            window,
            span,
        )?;
        let captures = raw
            .matched
            .then(|| canonicalize_unset(&self.program, &workspace.slots, UNSET_SLOT))
            .transpose()?;
        Ok(SearchOutcome {
            captures,
            report: raw.report,
        })
    }

    /// Derive the source-independent envelope for one aggregate-only exact
    /// span replay.
    ///
    /// This is available only when every user capture fits the fixed
    /// participation quotient. Larger schemas must select the full
    /// persistent-history route before source access.
    pub fn participation_exact_prospective(
        &self,
        span: Span,
    ) -> Result<ParticipationSearchProspective, SearchError> {
        self.validate_participation_quotient()?;
        participation_exact_prospective(
            &self.program,
            span,
            core::mem::size_of::<ParticipationThread>(),
        )
    }

    /// Allocate the fixed capture-participation frontier for repeated exact
    /// replay. The supplied span and limits are admitted before allocation so
    /// a caller can preserve the ordinary replay's failure ordering when it
    /// prepares this workspace lazily for its first selected span.
    pub fn prepare_participation_exact_workspace(
        &self,
        span: Span,
        limits: SearchLimits,
    ) -> Result<ParticipationExactWorkspace, SearchError> {
        self.validate_participation_quotient()?;
        let _ = admit_participation_exact(
            &self.program,
            span,
            core::mem::size_of::<ParticipationThread>(),
            limits,
        )?;
        let state_count = self.program.states.len();
        let current = reserve_participation_threads(state_count)?;
        let next = reserve_participation_threads(state_count)?;
        let stack = reserve_participation_threads(state_count)?;
        let mut seen = exact_capacity_vec(state_count, ResourceKind::ScratchBytes)?;
        seen.resize(state_count, 0_usize);
        Ok(ParticipationExactWorkspace {
            identity: self.identity,
            current,
            next,
            stack,
            seen,
            generation: 0,
        })
    }

    /// Replay one exact span while retaining only capture participation.
    ///
    /// The ordered frontier and first-arrival state quotient are identical to
    /// [`Self::captures_exact`]. Capture tags never affect control. Each
    /// well-nested start/end pair therefore projects homomorphically to one
    /// transient `open` bit and one persistent `participated` bit. Group zero
    /// is retained in the masks to authenticate exact-span acceptance, then
    /// excluded from the returned scalar.
    #[allow(
        clippy::too_many_lines,
        reason = "the aggregate-only exact-span transition mirrors captures_exact so priority and accounting remain locally auditable"
    )]
    pub fn captures_participation_exact(
        &self,
        haystack: &[u8],
        window: Window,
        span: Span,
        limits: SearchLimits,
    ) -> Result<ParticipationSearchOutcome, SearchError> {
        validate_window(haystack, window, span.start)?;
        if span.start > span.end || span.start < window.start || span.end > window.end {
            return Err(SearchError::InvalidWindow);
        }
        let mut workspace = self.prepare_participation_exact_workspace(span, limits)?;
        self.captures_participation_exact_with_workspace(
            &mut workspace,
            haystack,
            window,
            span,
            limits,
        )
    }

    /// Replay one exact span with a caller-owned fixed capture-participation
    /// frontier. Successful calls perform no allocation.
    #[allow(
        clippy::too_many_lines,
        reason = "the aggregate-only exact-span transition mirrors captures_exact so priority and accounting remain locally auditable"
    )]
    pub fn captures_participation_exact_with_workspace(
        &self,
        workspace: &mut ParticipationExactWorkspace,
        haystack: &[u8],
        window: Window,
        span: Span,
        limits: SearchLimits,
    ) -> Result<ParticipationSearchOutcome, SearchError> {
        validate_window(haystack, window, span.start)?;
        if span.start > span.end || span.start < window.start || span.end > window.end {
            return Err(SearchError::InvalidWindow);
        }
        self.validate_participation_quotient()?;
        let prospective = admit_participation_exact(
            &self.program,
            span,
            core::mem::size_of::<ParticipationThread>(),
            limits,
        )?;
        let state_count = self.program.states.len();
        if workspace.identity != self.identity
            || workspace.current.capacity() != state_count
            || workspace.next.capacity() != state_count
            || workspace.stack.capacity() != state_count
            || workspace.seen.len() != state_count
            || workspace.seen.capacity() != state_count
        {
            return Err(SearchError::InvalidProgram);
        }
        workspace.current.clear();
        workspace.next.clear();
        workspace.stack.clear();
        let replay_generations = span
            .end
            .checked_sub(span.start)
            .and_then(|length| length.checked_add(1))
            .ok_or(SearchError::BoundOverflow(ResourceKind::StateVisits))?;
        let generation =
            if let Some(end_generation) = workspace.generation.checked_add(replay_generations) {
                let start_generation = workspace
                    .generation
                    .checked_add(1)
                    .ok_or(SearchError::BoundOverflow(ResourceKind::StateVisits))?;
                workspace.generation = end_generation;
                start_generation
            } else {
                workspace.seen.fill(0);
                workspace.generation = replay_generations;
                1
            };
        let mut generation = generation;
        let mut counters = Counters {
            state_visits: 0,
            history_walk: 0,
            starts_injected: 1,
            bytes_examined: 0,
            peak_threads: 0,
        };
        let mut pos = span.start;
        add_participation_thread(
            &self.program,
            &mut workspace.current,
            &mut workspace.stack,
            &mut workspace.seen,
            generation,
            ParticipationThread {
                pc: self.program.start,
                open: 0,
                participated: 0,
            },
            pos,
            haystack,
            window,
            &mut counters,
            limits,
        )?;

        while pos < span.end {
            workspace
                .current
                .retain(|thread| !matches!(self.program.states.get(thread.pc), Some(State::Match)));
            workspace.next.clear();
            generation = generation
                .checked_add(1)
                .ok_or(SearchError::BoundOverflow(ResourceKind::StateVisits))?;
            let next_pos = pos
                .checked_add(1)
                .ok_or(SearchError::BoundOverflow(ResourceKind::StateVisits))?;
            let byte = *haystack.get(pos).ok_or(SearchError::InvalidWindow)?;
            for thread in workspace.current.drain(..) {
                let State::Byte {
                    ranges,
                    next: target,
                } = self
                    .program
                    .states
                    .get(thread.pc)
                    .ok_or(SearchError::InvalidProgram)?
                else {
                    return Err(SearchError::InvalidProgram);
                };
                if ranges
                    .iter()
                    .any(|&(start, end)| start <= byte && byte <= end)
                {
                    add_participation_thread(
                        &self.program,
                        &mut workspace.next,
                        &mut workspace.stack,
                        &mut workspace.seen,
                        generation,
                        ParticipationThread {
                            pc: *target,
                            open: thread.open,
                            participated: thread.participated,
                        },
                        next_pos,
                        haystack,
                        window,
                        &mut counters,
                        limits,
                    )?;
                }
            }
            counters.bytes_examined =
                checked_add(counters.bytes_examined, 1, ResourceKind::StateVisits)?;
            std::mem::swap(&mut workspace.current, &mut workspace.next);
            pos = next_pos;
        }

        counters.peak_threads = counters.peak_threads.max(workspace.current.len());
        let (participating_captures, participation_mask) = if let Some(thread) = workspace
            .current
            .iter()
            .find(|thread| matches!(self.program.states.get(thread.pc), Some(State::Match)))
        {
            if thread.open != 0 || thread.participated & 1 == 0 {
                return Err(SearchError::InvalidProgram);
            }
            let participating = usize::try_from((thread.participated & !1_u64).count_ones())
                .map_err(|_| SearchError::InvalidProgram)?;
            (Some(participating), Some(thread.participated))
        } else {
            (None, None)
        };
        let report = RunReport {
            candidate: CandidateKind::ParticipationQuotient,
            state_visits: counters.state_visits,
            slot_copies: 0,
            history_nodes: 0,
            history_walk: 0,
            starts_injected: counters.starts_injected,
            bytes_examined: counters.bytes_examined,
            peak_threads: counters.peak_threads,
            admitted_scratch_bytes: prospective.scratch_bytes,
        };
        if !prospective.closes_report(&report) {
            return Err(SearchError::InvalidProgram);
        }
        Ok(ParticipationSearchOutcome {
            participating_captures,
            participation_mask,
            prospective,
            report,
        })
    }

    fn validate_participation_quotient(&self) -> Result<(), SearchError> {
        let group_count = self.program.groups.len();
        let user_captures = group_count
            .checked_sub(1)
            .ok_or(SearchError::InvalidProgram)?;
        let expected_slots = self
            .program
            .groups
            .len()
            .checked_mul(2)
            .ok_or(SearchError::BoundOverflow(ResourceKind::Captures))?;
        if group_count > usize::from(PARTICIPATION_QUOTIENT_MASK_BITS)
            || user_captures > PARTICIPATION_QUOTIENT_CAPTURE_BITS
            || self.program.slot_count != expected_slots
        {
            return Err(SearchError::InvalidProgram);
        }
        Ok(())
    }

    /// Bounded repeated-search iterator with Rust byte-regex empty suppression.
    ///
    /// This is deliberately a quadratic-capable correctness formulation. Its
    /// limits and accounting are separate from one-search limits.
    pub fn captures_iter(
        &self,
        haystack: &[u8],
        window: Window,
        limits: AggregateLimits,
    ) -> Result<AggregateOutcome, SearchError> {
        self.captures_iter_with_config(haystack, window, SearchConfig::LEFTMOST, limits)
    }

    /// Bounded repeated search under an explicit selection and anchoring
    /// policy, with Rust byte-regex empty-match progression.
    pub fn captures_iter_with_config(
        &self,
        haystack: &[u8],
        window: Window,
        config: SearchConfig,
        limits: AggregateLimits,
    ) -> Result<AggregateOutcome, SearchError> {
        validate_window(haystack, window, window.start)?;
        let mut records = Vec::new();
        let mut searches = 0_usize;
        let mut total_state_visits = 0_usize;
        let mut total_history_nodes = 0_usize;
        let mut cursor = window.start;
        let mut last_match_end = None;
        loop {
            let next_searches = checked_add(searches, 1, ResourceKind::Searches)?;
            check(ResourceKind::Searches, next_searches, limits.max_searches)?;
            searches = next_searches;

            let mut per_search = limits.per_search;
            let state_remaining = limits
                .max_total_state_visits
                .checked_sub(total_state_visits)
                .ok_or(SearchError::BoundOverflow(
                    ResourceKind::AggregateStateVisits,
                ))?;
            per_search.max_state_visits = per_search.max_state_visits.min(state_remaining);
            let history_remaining = limits
                .max_total_history_nodes
                .checked_sub(total_history_nodes)
                .ok_or(SearchError::BoundOverflow(
                    ResourceKind::AggregateHistoryNodes,
                ))?;
            per_search.max_history_nodes = per_search.max_history_nodes.min(history_remaining);

            let outcome = self.search_from(haystack, window, cursor, config, per_search)?;
            total_state_visits = checked_add(
                total_state_visits,
                outcome.report.state_visits,
                ResourceKind::AggregateStateVisits,
            )?;
            total_history_nodes = checked_add(
                total_history_nodes,
                outcome.report.history_nodes,
                ResourceKind::AggregateHistoryNodes,
            )?;
            let Some(record) = outcome.captures else {
                break;
            };
            let overall = record.overall().ok_or(SearchError::InvalidProgram)?;
            if overall.start == overall.end && last_match_end == Some(overall.start) {
                if overall.end == window.end {
                    break;
                }
                cursor = overall
                    .end
                    .checked_add(1)
                    .ok_or(SearchError::BoundOverflow(ResourceKind::Searches))?;
                continue;
            }
            let next_results = checked_add(records.len(), 1, ResourceKind::Results)?;
            check(ResourceKind::Results, next_results, limits.max_results)?;
            records
                .try_reserve(1)
                .map_err(|_| SearchError::Allocation(ResourceKind::Results))?;
            records.push(record);
            last_match_end = Some(overall.end);
            if overall.start == overall.end {
                if overall.end == window.end {
                    break;
                }
                cursor = overall
                    .end
                    .checked_add(1)
                    .ok_or(SearchError::BoundOverflow(ResourceKind::Searches))?;
            } else {
                cursor = overall.end;
            }
        }
        Ok(AggregateOutcome {
            captures: records,
            searches,
            total_state_visits,
            total_slot_copies: 0,
            total_history_nodes,
        })
    }

    /// Sum participating groups over non-overlapping, non-empty matches.
    ///
    /// This is the capture-preserving reducer used by models whose public
    /// result is participation count rather than capture records. It never
    /// retains prior winners and never clones a slot vector for speculative
    /// threads. Empty selection is rejected because silently applying an
    /// iterator progress policy would change this operation's contract.
    pub fn count_captures_nonempty(
        &self,
        haystack: &[u8],
        window: Window,
        limits: AggregateLimits,
    ) -> Result<CaptureCountOutcome, SearchError> {
        validate_window(haystack, window, window.start)?;
        let mut count = 0_usize;
        let mut matches = 0_usize;
        let mut searches = 0_usize;
        let mut capture_events = 0_usize;
        let mut total_state_visits = 0_usize;
        let mut total_history_nodes = 0_usize;
        let mut total_history_walk = 0_usize;
        let mut peak_threads = 0_usize;
        let mut cursor = window.start;
        loop {
            searches = checked_add(searches, 1, ResourceKind::Searches)?;
            check(ResourceKind::Searches, searches, limits.max_searches)?;

            let mut per_search = limits.per_search;
            per_search.max_state_visits = per_search.max_state_visits.min(
                limits
                    .max_total_state_visits
                    .checked_sub(total_state_visits)
                    .ok_or(SearchError::BoundOverflow(
                        ResourceKind::AggregateStateVisits,
                    ))?,
            );
            per_search.max_history_nodes = per_search.max_history_nodes.min(
                limits
                    .max_total_history_nodes
                    .checked_sub(total_history_nodes)
                    .ok_or(SearchError::BoundOverflow(
                        ResourceKind::AggregateHistoryNodes,
                    ))?,
            );
            per_search.max_history_walk = per_search.max_history_walk.min(
                limits
                    .max_total_history_walk
                    .checked_sub(total_history_walk)
                    .ok_or(SearchError::BoundOverflow(
                        ResourceKind::AggregateHistoryWalk,
                    ))?,
            );

            let outcome =
                self.search_from(haystack, window, cursor, SearchConfig::LEFTMOST, per_search)?;
            total_state_visits = checked_add(
                total_state_visits,
                outcome.report.state_visits,
                ResourceKind::AggregateStateVisits,
            )?;
            total_history_nodes = checked_add(
                total_history_nodes,
                outcome.report.history_nodes,
                ResourceKind::AggregateHistoryNodes,
            )?;
            total_history_walk = checked_add(
                total_history_walk,
                outcome.report.history_walk,
                ResourceKind::AggregateHistoryWalk,
            )?;
            peak_threads = peak_threads.max(outcome.report.peak_threads);

            let Some(record) = outcome.captures else {
                break;
            };
            let overall = record.overall().ok_or(SearchError::InvalidProgram)?;
            if overall.start == overall.end {
                return Err(SearchError::EmptyMatch);
            }
            matches = checked_add(matches, 1, ResourceKind::Results)?;
            check(ResourceKind::Results, matches, limits.max_results)?;
            for group in record.groups {
                capture_events = checked_add(capture_events, 1, ResourceKind::CaptureEvents)?;
                check(
                    ResourceKind::CaptureEvents,
                    capture_events,
                    limits.max_capture_events,
                )?;
                if group.span.is_some() {
                    count = checked_add(count, 1, ResourceKind::CaptureCount)?;
                    check(ResourceKind::CaptureCount, count, limits.max_capture_count)?;
                }
            }
            cursor = overall.end;
        }
        Ok(CaptureCountOutcome {
            count,
            matches,
            searches,
            total_state_visits,
            total_history_nodes,
            total_history_walk,
            peak_threads,
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the complete generation transition is kept locally auditable"
    )]
    fn search_from(
        &self,
        haystack: &[u8],
        window: Window,
        from: usize,
        config: SearchConfig,
        limits: SearchLimits,
    ) -> Result<SearchOutcome, SearchError> {
        self.search_from_impl::<false>(haystack, window, from, config, None, limits)
    }

    fn search_from_start_ceiling(
        &self,
        haystack: &[u8],
        window: Window,
        from: usize,
        config: SearchConfig,
        maximum_start: Option<usize>,
        limits: SearchLimits,
    ) -> Result<SearchOutcome, SearchError> {
        self.search_from_impl::<true>(
            haystack,
            window,
            from,
            config,
            maximum_start,
            limits,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the complete generation transition and explicit new-start domain are kept locally auditable"
    )]
    fn search_from_impl<const RESTRICT_STARTS: bool>(
        &self,
        haystack: &[u8],
        window: Window,
        from: usize,
        config: SearchConfig,
        maximum_start: Option<usize>,
        limits: SearchLimits,
    ) -> Result<SearchOutcome, SearchError> {
        validate_window(haystack, window, from)?;
        let admission = admit_history(&self.program, window, from, limits)?;
        let maximum_start = if RESTRICT_STARTS {
            let Some(maximum_start) = maximum_start else {
                return Ok(empty_start_domain_outcome(admission.scratch_bytes));
            };
            let maximum_start = maximum_start.min(window.end);
            if maximum_start < from {
                return Ok(empty_start_domain_outcome(admission.scratch_bytes));
            }
            maximum_start
        } else {
            window.end
        };
        let state_count = self.program.states.len();
        let mut current = reserve_threads(state_count)?;
        let mut next = reserve_threads(state_count)?;
        let mut stack = reserve_threads(state_count)?;
        let mut seen = exact_capacity_vec(state_count, ResourceKind::ScratchBytes)?;
        seen.resize(state_count, 0_usize);
        let mut histories = HistoryArena::new(admission.history_node_bound)?;
        let mut generation = 1_usize;
        let mut counters = Counters {
            state_visits: 0,
            history_walk: 0,
            starts_injected: 0,
            bytes_examined: 0,
            peak_threads: 0,
        };
        let mut winner = None;
        let mut pos = from;

        let all_matches = config.match_kind == MatchKind::All;
        let continue_after_match = all_matches && config.kind == SearchKind::Leftmost;
        loop {
            let start_is_admissible = !RESTRICT_STARTS || pos <= maximum_start;
            if start_is_admissible
                && (winner.is_none() || continue_after_match)
                && (!config.anchored || pos == from)
            {
                counters.starts_injected =
                    checked_add(counters.starts_injected, 1, ResourceKind::StateVisits)?;
                add_thread::<true>(
                    &self.program,
                    &mut current,
                    &mut stack,
                    &mut seen,
                    &mut histories,
                    generation,
                    Thread {
                        pc: self.program.start,
                        history: None,
                    },
                    pos,
                    haystack,
                    window,
                    &mut counters,
                    limits,
                )?;
            }

            let accepting = if all_matches {
                current
                    .iter()
                    .rposition(|thread| matches!(self.program.states[thread.pc], State::Match))
            } else {
                current
                    .iter()
                    .position(|thread| matches!(self.program.states[thread.pc], State::Match))
            };
            if let Some(index) = accepting {
                winner = Some(current[index].history.ok_or(SearchError::InvalidProgram)?);
                if config.kind == SearchKind::Earliest {
                    current.clear();
                } else if !all_matches {
                    current.truncate(index);
                }
            }
            counters.peak_threads = counters.peak_threads.max(current.len());
            if current.is_empty()
                && ((winner.is_some() && !continue_after_match)
                    || (RESTRICT_STARTS && !start_is_admissible))
            {
                break;
            }
            if pos == window.end {
                break;
            }

            next.clear();
            generation = generation
                .checked_add(1)
                .ok_or(SearchError::BoundOverflow(ResourceKind::StateVisits))?;
            let next_pos = pos
                .checked_add(1)
                .ok_or(SearchError::BoundOverflow(ResourceKind::StateVisits))?;
            let byte = *haystack.get(pos).ok_or(SearchError::InvalidWindow)?;
            for thread in current.drain(..) {
                let state = self
                    .program
                    .states
                    .get(thread.pc)
                    .ok_or(SearchError::InvalidProgram)?;
                let State::Byte {
                    ranges,
                    next: target,
                } = state
                else {
                    if all_matches && matches!(state, State::Match) {
                        continue;
                    }
                    return Err(SearchError::InvalidProgram);
                };
                if ranges
                    .iter()
                    .any(|&(start, end)| start <= byte && byte <= end)
                {
                    add_thread::<true>(
                        &self.program,
                        &mut next,
                        &mut stack,
                        &mut seen,
                        &mut histories,
                        generation,
                        Thread {
                            pc: *target,
                            history: thread.history,
                        },
                        next_pos,
                        haystack,
                        window,
                        &mut counters,
                        limits,
                    )?;
                }
            }
            counters.bytes_examined =
                checked_add(counters.bytes_examined, 1, ResourceKind::StateVisits)?;
            std::mem::swap(&mut current, &mut next);
            pos = next_pos;
        }

        let captures = if let Some(history) = winner {
            let slots = materialize(&self.program, &histories, history, &mut counters, limits)?;
            Some(canonicalize(&self.program, &slots)?)
        } else {
            None
        };
        Ok(SearchOutcome {
            captures,
            report: RunReport {
                candidate: CandidateKind::PersistentHistory,
                state_visits: counters.state_visits,
                slot_copies: 0,
                history_nodes: histories.len(),
                history_walk: counters.history_walk,
                starts_injected: counters.starts_injected,
                bytes_examined: counters.bytes_examined,
                peak_threads: counters.peak_threads,
                admitted_scratch_bytes: admission.scratch_bytes,
            },
        })
    }
}

fn empty_start_domain_outcome(admitted_scratch_bytes: usize) -> SearchOutcome {
    SearchOutcome {
        captures: None,
        report: RunReport {
            candidate: CandidateKind::PersistentHistory,
            state_visits: 0,
            slot_copies: 0,
            history_nodes: 0,
            history_walk: 0,
            starts_injected: 0,
            bytes_examined: 0,
            peak_threads: 0,
            admitted_scratch_bytes,
        },
    }
}

pub(crate) fn prepare_history_exact_workspace(
    program: &Program,
    binding: HistoryExactWorkspaceBinding,
    max_span_bytes: usize,
    limits: SearchLimits,
) -> Result<HistoryExactWorkspace, SearchError> {
    let usage = derive_history_exact_workspace_usage(program, max_span_bytes, limits)?;
    let state_count = program.states.len();
    let mut seen = exact_capacity_vec(state_count, ResourceKind::ScratchBytes)?;
    seen.resize(state_count, 0);
    let mut slots = exact_capacity_vec(program.slot_count, ResourceKind::ScratchBytes)?;
    slots.resize(program.slot_count, UNSET_SLOT);
    Ok(HistoryExactWorkspace {
        binding,
        shape: program.history_program_shape(),
        current: reserve_threads(state_count)?,
        next: reserve_threads(state_count)?,
        stack: reserve_threads(state_count)?,
        seen,
        histories: HistoryArena::preallocated(usage.history_node_capacity)?,
        slots,
        limits,
        usage,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "the reusable search transition mirrors the allocating semantic authority in one auditable loop"
)]
fn execute_search_with_workspace(
    program: &Program,
    binding: HistoryExactWorkspaceBinding,
    workspace: &mut HistoryExactWorkspace,
    haystack: &[u8],
    window: Window,
    from: usize,
    config: SearchConfig,
    limits: SearchLimits,
) -> Result<ExactCaptureSlotsOutcome, SearchError> {
    if workspace.binding != binding
        || workspace.shape != program.history_program_shape()
        || workspace.usage.algorithm_version != HISTORY_EXACT_WORKSPACE_ALGORITHM_VERSION
        || workspace.usage.accounting_version != HISTORY_EXACT_WORKSPACE_ACCOUNTING_VERSION
    {
        return Err(SearchError::InvalidProgram);
    }
    validate_window(haystack, window, from)?;
    let search_bytes = window
        .end
        .checked_sub(from)
        .ok_or(SearchError::InvalidWindow)?;
    if search_bytes > workspace.usage.max_span_bytes {
        return Err(SearchError::InvalidWindow);
    }
    let admission = admit_history(program, window, from, limits)?;
    if admission.history_node_bound > workspace.usage.history_node_capacity
        || workspace.current.capacity() != workspace.usage.thread_capacity
        || workspace.next.capacity() != workspace.usage.thread_capacity
        || workspace.stack.capacity() != workspace.usage.thread_capacity
        || workspace.seen.len() != program.states.len()
        || workspace.seen.capacity() != workspace.usage.thread_capacity
        || workspace.slots.len() != program.slot_count
        || workspace.slots.capacity() != workspace.usage.slot_capacity
        || !workspace
            .histories
            .is_exactly_preallocated(workspace.usage.history_node_capacity)
    {
        return Err(SearchError::InvalidProgram);
    }
    workspace.current.clear();
    workspace.next.clear();
    workspace.stack.clear();
    workspace.seen.fill(0);
    workspace.histories.reset();
    workspace.slots.fill(UNSET_SLOT);
    let mut generation = 1_usize;
    let mut counters = Counters {
        state_visits: 0,
        history_walk: 0,
        starts_injected: 0,
        bytes_examined: 0,
        peak_threads: 0,
    };
    let mut winner = None;
    let mut pos = from;
    let all_matches = config.match_kind == MatchKind::All;
    let continue_after_match = all_matches && config.kind == SearchKind::Leftmost;
    loop {
        if (winner.is_none() || continue_after_match) && (!config.anchored || pos == from) {
            counters.starts_injected =
                checked_add(counters.starts_injected, 1, ResourceKind::StateVisits)?;
            // The fixed workspace and this call's complete state/history
            // envelope were authenticated above. The const-false instance
            // therefore omits only the redundant per-visit limit comparison;
            // checked accumulation remains live and the complete ledger is
            // closed before this search result can be published.
            add_thread::<false>(
                program,
                &mut workspace.current,
                &mut workspace.stack,
                &mut workspace.seen,
                &mut workspace.histories,
                generation,
                Thread {
                    pc: program.start,
                    history: None,
                },
                pos,
                haystack,
                window,
                &mut counters,
                limits,
            )?;
        }
        let accepting = if all_matches {
            workspace
                .current
                .iter()
                .rposition(|thread| matches!(program.states[thread.pc], State::Match))
        } else {
            workspace
                .current
                .iter()
                .position(|thread| matches!(program.states[thread.pc], State::Match))
        };
        if let Some(index) = accepting {
            winner = Some(
                workspace.current[index]
                    .history
                    .ok_or(SearchError::InvalidProgram)?,
            );
            if config.kind == SearchKind::Earliest {
                workspace.current.clear();
            } else if !all_matches {
                workspace.current.truncate(index);
            }
        }
        counters.peak_threads = counters.peak_threads.max(workspace.current.len());
        if winner.is_some() && workspace.current.is_empty() && !continue_after_match {
            break;
        }
        if pos == window.end {
            break;
        }
        workspace.next.clear();
        generation = generation
            .checked_add(1)
            .ok_or(SearchError::BoundOverflow(ResourceKind::StateVisits))?;
        let next_pos = pos
            .checked_add(1)
            .ok_or(SearchError::BoundOverflow(ResourceKind::StateVisits))?;
        let byte = *haystack.get(pos).ok_or(SearchError::InvalidWindow)?;
        for thread in workspace.current.drain(..) {
            let state = program
                .states
                .get(thread.pc)
                .ok_or(SearchError::InvalidProgram)?;
            let State::Byte {
                ranges,
                next: target,
            } = state
            else {
                if all_matches && matches!(state, State::Match) {
                    continue;
                }
                return Err(SearchError::InvalidProgram);
            };
            if ranges
                .iter()
                .any(|&(start, end)| start <= byte && byte <= end)
            {
                add_thread::<false>(
                    program,
                    &mut workspace.next,
                    &mut workspace.stack,
                    &mut workspace.seen,
                    &mut workspace.histories,
                    generation,
                    Thread {
                        pc: *target,
                        history: thread.history,
                    },
                    next_pos,
                    haystack,
                    window,
                    &mut counters,
                    limits,
                )?;
            }
        }
        counters.bytes_examined =
            checked_add(counters.bytes_examined, 1, ResourceKind::StateVisits)?;
        std::mem::swap(&mut workspace.current, &mut workspace.next);
        pos = next_pos;
    }
    let matched = if let Some(history) = winner {
        materialize_into(
            program,
            &workspace.histories,
            history,
            &mut workspace.slots,
            UNSET_SLOT,
            &mut counters,
            limits,
        )?;
        true
    } else {
        false
    };
    verify_admitted_history(&counters, &workspace.histories, admission)?;
    Ok(ExactCaptureSlotsOutcome {
        matched,
        report: RunReport {
            candidate: CandidateKind::PersistentHistory,
            state_visits: counters.state_visits,
            slot_copies: 0,
            history_nodes: workspace.histories.len(),
            history_walk: counters.history_walk,
            starts_injected: counters.starts_injected,
            bytes_examined: counters.bytes_examined,
            peak_threads: counters.peak_threads,
            admitted_scratch_bytes: admission.scratch_bytes,
        },
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "the single exact-history transition core serves allocating and fixed-workspace APIs"
)]
pub(crate) fn execute_exact_with_workspace(
    program: &Program,
    binding: HistoryExactWorkspaceBinding,
    workspace: &mut HistoryExactWorkspace,
    haystack: &[u8],
    window: Window,
    span: Span,
) -> Result<ExactCaptureSlotsOutcome, SearchError> {
    if workspace.binding != binding
        || workspace.shape != program.history_program_shape()
        || workspace.usage.algorithm_version != HISTORY_EXACT_WORKSPACE_ALGORITHM_VERSION
        || workspace.usage.accounting_version != HISTORY_EXACT_WORKSPACE_ACCOUNTING_VERSION
    {
        return Err(SearchError::InvalidProgram);
    }
    validate_window(haystack, window, span.start)?;
    let span_bytes = span
        .end
        .checked_sub(span.start)
        .ok_or(SearchError::InvalidWindow)?;
    if span.start < window.start
        || span.end > window.end
        || span_bytes > workspace.usage.max_span_bytes
    {
        return Err(SearchError::InvalidWindow);
    }
    let limits = workspace.limits;
    let admission = admit_history_exact(program, span, limits)?;
    if admission.history_node_bound > workspace.usage.history_node_capacity
        || workspace.current.capacity() != workspace.usage.thread_capacity
        || workspace.next.capacity() != workspace.usage.thread_capacity
        || workspace.stack.capacity() != workspace.usage.thread_capacity
        || workspace.seen.len() != program.states.len()
        || workspace.seen.capacity() != workspace.usage.thread_capacity
        || workspace.slots.len() != program.slot_count
        || workspace.slots.capacity() != workspace.usage.slot_capacity
        || !workspace
            .histories
            .is_exactly_preallocated(workspace.usage.history_node_capacity)
    {
        return Err(SearchError::InvalidProgram);
    }
    workspace.current.clear();
    workspace.next.clear();
    workspace.stack.clear();
    workspace.seen.fill(0);
    workspace.histories.reset();
    workspace.slots.fill(UNSET_SLOT);
    let mut generation = 1_usize;
    let mut counters = Counters {
        state_visits: 0,
        history_walk: 0,
        starts_injected: 1,
        bytes_examined: 0,
        peak_threads: 0,
    };
    let mut pos = span.start;
    // Exact replay has the same fixed-workspace authentication and complete
    // boundary-derived admission as search replay. Keep checked accumulation
    // in the loop and close the ledger before publishing the result.
    add_thread::<false>(
        program,
        &mut workspace.current,
        &mut workspace.stack,
        &mut workspace.seen,
        &mut workspace.histories,
        generation,
        Thread {
            pc: program.start,
            history: None,
        },
        pos,
        haystack,
        window,
        &mut counters,
        limits,
    )?;

    while pos < span.end {
        workspace
            .current
            .retain(|thread| !matches!(program.states.get(thread.pc), Some(State::Match)));
        workspace.next.clear();
        generation = generation
            .checked_add(1)
            .ok_or(SearchError::BoundOverflow(ResourceKind::StateVisits))?;
        let next_pos = pos
            .checked_add(1)
            .ok_or(SearchError::BoundOverflow(ResourceKind::StateVisits))?;
        let byte = *haystack.get(pos).ok_or(SearchError::InvalidWindow)?;
        for thread in workspace.current.drain(..) {
            let State::Byte {
                ranges,
                next: target,
            } = program
                .states
                .get(thread.pc)
                .ok_or(SearchError::InvalidProgram)?
            else {
                return Err(SearchError::InvalidProgram);
            };
            if ranges
                .iter()
                .any(|&(start, end)| start <= byte && byte <= end)
            {
                add_thread::<false>(
                    program,
                    &mut workspace.next,
                    &mut workspace.stack,
                    &mut workspace.seen,
                    &mut workspace.histories,
                    generation,
                    Thread {
                        pc: *target,
                        history: thread.history,
                    },
                    next_pos,
                    haystack,
                    window,
                    &mut counters,
                    limits,
                )?;
            }
        }
        counters.bytes_examined =
            checked_add(counters.bytes_examined, 1, ResourceKind::StateVisits)?;
        std::mem::swap(&mut workspace.current, &mut workspace.next);
        pos = next_pos;
    }

    counters.peak_threads = counters.peak_threads.max(workspace.current.len());
    let winner = workspace
        .current
        .iter()
        .find(|thread| matches!(program.states.get(thread.pc), Some(State::Match)))
        .map(|thread| thread.history.ok_or(SearchError::InvalidProgram))
        .transpose()?;
    let matched = if let Some(winner) = winner {
        materialize_into(
            program,
            &workspace.histories,
            winner,
            &mut workspace.slots,
            UNSET_SLOT,
            &mut counters,
            limits,
        )?;
        if workspace.slots.first().copied() != Some(span.start)
            || workspace.slots.get(1).copied() != Some(span.end)
        {
            return Err(SearchError::InvalidProgram);
        }
        true
    } else {
        false
    };
    verify_admitted_history(&counters, &workspace.histories, admission)?;
    Ok(ExactCaptureSlotsOutcome {
        matched,
        report: RunReport {
            candidate: CandidateKind::PersistentHistory,
            state_visits: counters.state_visits,
            slot_copies: 0,
            history_nodes: workspace.histories.len(),
            history_walk: counters.history_walk,
            starts_injected: counters.starts_injected,
            bytes_examined: counters.bytes_examined,
            peak_threads: counters.peak_threads,
            admitted_scratch_bytes: admission.scratch_bytes,
        },
    })
}

fn reserve_threads(capacity: usize) -> Result<Vec<Thread>, SearchError> {
    exact_capacity_vec(capacity, ResourceKind::ScratchBytes)
}

pub(crate) fn derive_history_exact_workspace_usage(
    program: &Program,
    max_span_bytes: usize,
    limits: SearchLimits,
) -> Result<HistoryExactWorkspaceUsage, SearchError> {
    let admission = admit_history_exact(
        program,
        Span {
            start: 0,
            end: max_span_bytes,
        },
        limits,
    )?;
    history_exact_workspace_usage(program, max_span_bytes, admission)
}

fn history_exact_workspace_usage(
    program: &Program,
    max_span_bytes: usize,
    admission: crate::runtime::Admission,
) -> Result<HistoryExactWorkspaceUsage, SearchError> {
    let thread_capacity = program.states.len();
    let history_node_capacity = admission.history_node_bound;
    let slot_capacity = program.slot_count;
    let thread_bytes = thread_capacity
        .checked_mul(3)
        .and_then(|count| count.checked_mul(size_of::<Thread>()))
        .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;
    let seen_bytes = thread_capacity
        .checked_mul(size_of::<usize>())
        .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;
    let history_bytes = history_node_capacity
        .checked_mul(size_of::<HistoryNode>())
        .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;
    let history_chunks = history_node_capacity
        .checked_add(HISTORY_CHUNK_CAPACITY.saturating_sub(1))
        .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?
        .checked_div(HISTORY_CHUNK_CAPACITY)
        .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;
    let history_headers = history_chunks
        .checked_mul(size_of::<Vec<HistoryNode>>())
        .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;
    let slot_bytes = slot_capacity
        .checked_mul(size_of::<usize>())
        .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;
    let persistent_bytes = size_of::<HistoryExactWorkspace>()
        .checked_add(thread_bytes)
        .and_then(|bytes| bytes.checked_add(seen_bytes))
        .and_then(|bytes| bytes.checked_add(history_bytes))
        .and_then(|bytes| bytes.checked_add(history_headers))
        .and_then(|bytes| bytes.checked_add(slot_bytes))
        .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;
    Ok(HistoryExactWorkspaceUsage {
        algorithm_version: HISTORY_EXACT_WORKSPACE_ALGORITHM_VERSION,
        accounting_version: HISTORY_EXACT_WORKSPACE_ACCOUNTING_VERSION,
        max_span_bytes,
        thread_capacity,
        history_node_capacity,
        slot_capacity,
        admitted_scratch_bytes: admission.scratch_bytes,
        persistent_bytes,
    })
}

impl HistoryExactWorkspace {
    /// Fixed source-independent workspace dimensions.
    #[must_use]
    pub const fn usage(&self) -> HistoryExactWorkspaceUsage {
        self.usage
    }

    /// Search limits permanently bound during preparation.
    #[must_use]
    pub const fn limits(&self) -> SearchLimits {
        self.limits
    }
}

fn reserve_participation_threads(capacity: usize) -> Result<Vec<ParticipationThread>, SearchError> {
    exact_capacity_vec(capacity, ResourceKind::ScratchBytes)
}

#[allow(
    clippy::too_many_arguments,
    reason = "closure resources are explicit laboratory inputs"
)]
fn add_thread<const CHECK_EACH_VISIT: bool>(
    program: &Program,
    output: &mut Vec<Thread>,
    stack: &mut Vec<Thread>,
    seen: &mut [usize],
    histories: &mut HistoryArena,
    generation: usize,
    initial: Thread,
    pos: usize,
    haystack: &[u8],
    window: Window,
    counters: &mut Counters,
    limits: SearchLimits,
) -> Result<(), SearchError> {
    stack.clear();
    stack.push(initial);
    while let Some(mut thread) = stack.pop() {
        counters.state_visits = checked_add(counters.state_visits, 1, ResourceKind::StateVisits)?;
        if CHECK_EACH_VISIT {
            check(
                ResourceKind::StateVisits,
                counters.state_visits,
                limits.max_state_visits,
            )?;
        }
        let mark = seen.get_mut(thread.pc).ok_or(SearchError::InvalidProgram)?;
        if *mark == generation {
            continue;
        }
        *mark = generation;
        match program
            .states
            .get(thread.pc)
            .ok_or(SearchError::InvalidProgram)?
        {
            State::Byte { .. } | State::Match => output.push(thread),
            State::Fail => {}
            State::Epsilon { next } => {
                thread.pc = *next;
                stack.push(thread);
            }
            State::Assert { assertion, next } => {
                if assertion_matches(*assertion, haystack, window, pos)? {
                    thread.pc = *next;
                    stack.push(thread);
                }
            }
            State::Save { slot, next, .. } => {
                let id = histories.push(HistoryNode {
                    slot: *slot,
                    offset: pos,
                    previous: thread.history,
                })?;
                thread.history = Some(id);
                thread.pc = *next;
                stack.push(thread);
            }
            State::Split { first, second } => {
                stack.push(Thread {
                    pc: *second,
                    history: thread.history,
                });
                thread.pc = *first;
                stack.push(thread);
            }
        }
    }
    counters.peak_threads = counters.peak_threads.max(output.len());
    Ok(())
}

fn verify_admitted_history(
    counters: &Counters,
    histories: &HistoryArena,
    admission: crate::runtime::Admission,
) -> Result<(), SearchError> {
    if counters.state_visits > admission.state_visit_bound
        || histories.len() > admission.history_node_bound
        || counters.history_walk > admission.history_walk_bound
        || counters.bytes_examined > admission.bytes_examined_bound
        || counters.starts_injected > admission.starts_injected_bound
        || counters.peak_threads > admission.peak_threads_bound
    {
        return Err(SearchError::InvalidProgram);
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "closure resources are explicit laboratory inputs"
)]
fn add_participation_thread(
    program: &Program,
    output: &mut Vec<ParticipationThread>,
    stack: &mut Vec<ParticipationThread>,
    seen: &mut [usize],
    generation: usize,
    initial: ParticipationThread,
    pos: usize,
    haystack: &[u8],
    window: Window,
    counters: &mut Counters,
    limits: SearchLimits,
) -> Result<(), SearchError> {
    stack.clear();
    stack.push(initial);
    while let Some(mut thread) = stack.pop() {
        counters.state_visits = checked_add(counters.state_visits, 1, ResourceKind::StateVisits)?;
        check(
            ResourceKind::StateVisits,
            counters.state_visits,
            limits.max_state_visits,
        )?;
        let mark = seen.get_mut(thread.pc).ok_or(SearchError::InvalidProgram)?;
        if *mark == generation {
            continue;
        }
        *mark = generation;
        match program
            .states
            .get(thread.pc)
            .ok_or(SearchError::InvalidProgram)?
        {
            State::Byte { .. } | State::Match => output.push(thread),
            State::Fail => {}
            State::Epsilon { next } => {
                thread.pc = *next;
                stack.push(thread);
            }
            State::Assert { assertion, next } => {
                if assertion_matches(*assertion, haystack, window, pos)? {
                    thread.pc = *next;
                    stack.push(thread);
                }
            }
            State::Save { slot, next, .. } => {
                if *slot >= program.slot_count {
                    return Err(SearchError::InvalidProgram);
                }
                let group = slot / 2;
                if group >= program.groups.len()
                    || group >= usize::from(PARTICIPATION_QUOTIENT_MASK_BITS)
                {
                    return Err(SearchError::InvalidProgram);
                }
                let shift = u32::try_from(group).map_err(|_| SearchError::InvalidProgram)?;
                let bit = 1_u64
                    .checked_shl(shift)
                    .ok_or(SearchError::InvalidProgram)?;
                if slot.is_multiple_of(2) {
                    if thread.open & bit != 0 {
                        return Err(SearchError::InvalidProgram);
                    }
                    thread.open |= bit;
                } else {
                    if thread.open & bit == 0 {
                        return Err(SearchError::InvalidProgram);
                    }
                    thread.open &= !bit;
                    thread.participated |= bit;
                }
                thread.pc = *next;
                stack.push(thread);
            }
            State::Split { first, second } => {
                stack.push(ParticipationThread {
                    pc: *second,
                    open: thread.open,
                    participated: thread.participated,
                });
                thread.pc = *first;
                stack.push(thread);
            }
        }
    }
    counters.peak_threads = counters.peak_threads.max(output.len());
    Ok(())
}

fn materialize(
    program: &Program,
    histories: &HistoryArena,
    winner: usize,
    counters: &mut Counters,
    limits: SearchLimits,
) -> Result<Vec<Option<usize>>, SearchError> {
    let mut slots = exact_capacity_vec(program.slot_count, ResourceKind::ScratchBytes)?;
    slots.resize(program.slot_count, None);
    walk_history(histories, winner, counters, limits, |node| {
        let slot = slots
            .get_mut(node.slot)
            .ok_or(SearchError::InvalidProgram)?;
        if slot.is_none() {
            *slot = Some(node.offset);
        }
        Ok(())
    })?;
    Ok(slots)
}

fn materialize_into(
    program: &Program,
    histories: &HistoryArena,
    winner: usize,
    slots: &mut [usize],
    unset: usize,
    counters: &mut Counters,
    limits: SearchLimits,
) -> Result<(), SearchError> {
    if slots.len() != program.slot_count {
        return Err(SearchError::InvalidProgram);
    }
    slots.fill(unset);
    walk_history(histories, winner, counters, limits, |node| {
        let slot = slots
            .get_mut(node.slot)
            .ok_or(SearchError::InvalidProgram)?;
        if *slot == unset {
            *slot = node.offset;
        }
        Ok(())
    })
}

fn walk_history(
    histories: &HistoryArena,
    winner: usize,
    counters: &mut Counters,
    limits: SearchLimits,
    mut visit: impl FnMut(&HistoryNode) -> Result<(), SearchError>,
) -> Result<(), SearchError> {
    let mut cursor = Some(winner);
    while let Some(id) = cursor {
        counters.history_walk = checked_add(counters.history_walk, 1, ResourceKind::HistoryWalk)?;
        check(
            ResourceKind::HistoryWalk,
            counters.history_walk,
            limits.max_history_walk,
        )?;
        let node = histories.get(id).ok_or(SearchError::InvalidProgram)?;
        visit(node)?;
        cursor = node.previous;
    }
    Ok(())
}
