//! Reusable capture-tag storage primitives.
//!
//! These types deliberately do not select a regex route. They provide the
//! bounded state carried by a future deterministic, one-pass or prioritized
//! automaton: a branch copies one small handle, and a tag action either
//! appends one immutable capture event or updates one participation quotient.

use core::{fmt, mem::size_of};
use std::sync::atomic::{AtomicU64, Ordering};

use fre_exact_alloc::{CopyError, ExactVec};

use crate::compile::{Program, State};
use crate::model::Span;

/// Semantic algorithm version of reusable tag storage.
pub const TAG_WORKSPACE_ALGORITHM_VERSION: u32 = 1;

/// Resource-accounting version of reusable tag storage.
pub const TAG_WORKSPACE_ACCOUNTING_VERSION: u32 = 4;

const NO_ID: u32 = u32::MAX;
const WORD_BITS: usize = 64;
static NEXT_WORKSPACE_ID: AtomicU64 = AtomicU64::new(1);

/// One independently limited workspace resource.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TagWorkspaceResource {
    /// Canonical capture groups, including group zero.
    Groups,
    /// Persistent history event cells.
    HistoryNodes,
    /// Copy-on-write participation states.
    MaskStates,
    /// Words in one participation mask.
    MaskWords,
    /// Allocation attempts, initialized cells and final object publication.
    BuildWork,
    /// Retained heap payload bytes initialized during construction.
    InitializedBytes,
    /// Retained payload bytes copied from caller-owned storage.
    CopiedBytes,
    /// Temporary construction payload bytes.
    ScratchBytes,
    /// Complete workspace object plus exact heap storage.
    PersistentBytes,
    /// Simultaneously live workspace plus construction scratch.
    PeakBytes,
    /// Exact bytes requested from the allocator.
    AllocatorBytes,
    /// Exact heap allocation count.
    Allocations,
    /// Tag actions applied during one reuse epoch.
    TagActions,
    /// History nodes walked to materialize one winner.
    HistoryWalk,
    /// History cells read for predecessor, head and traversal access.
    HistoryReads,
    /// Presence and slot cells inspected while materializing a winning history.
    MaterializationReads,
    /// Presence/slot cells written while materializing a winning history.
    MaterializationWrites,
    /// Reserved legacy dimension for a materialization preview. Direct
    /// materialization has no preview phase and always reports zero here.
    MaterializationPreviewWrites,
    /// Participation words initialized or copied into new states.
    MaskWordCopies,
    /// Logical participation words inspected for validation or result queries.
    MaskWordReads,
    /// Cells cleared at the beginning of one reuse epoch.
    ResetCells,
    /// Exact sum of all published reuse-epoch work dimensions.
    Work,
    /// Monotonic reuse-epoch identity.
    ReuseEpoch,
    /// Process-unique workspace identity.
    WorkspaceIdentity,
}

/// Typed workspace construction or operation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TagWorkspaceError {
    /// A checked resource ceiling would be exceeded.
    Resource {
        /// Limited resource.
        resource: TagWorkspaceResource,
        /// Required amount.
        required: usize,
        /// Configured maximum.
        limit: usize,
    },
    /// Arithmetic needed to prove a bound overflowed.
    Overflow(TagWorkspaceResource),
    /// One exact-layout allocation failed after complete preflight.
    Allocation(TagWorkspaceResource),
    /// The requested schema or action cannot be represented.
    InvalidShape(&'static str),
    /// A tag action violates per-group open/close semantics.
    InvalidAction,
    /// A history or participation handle does not belong to this reuse epoch.
    InvalidState,
}

impl fmt::Display for TagWorkspaceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "capture tag workspace error: {self:?}")
    }
}

impl std::error::Error for TagWorkspaceError {}

/// Whether a tag records the beginning or end of a capture.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TagKind {
    /// Open a capture at the current absolute byte offset.
    Start,
    /// Close a capture at the current absolute byte offset.
    End,
}

/// One capture action attached to a prioritized transition.
///
/// The compact representation is the canonical tagged slot:
/// `2 * group + kind`, where group zero is the whole match.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TagAction {
    slot: u32,
}

impl TagAction {
    /// Construct a capture-start action.
    pub fn start(group: u32) -> Result<Self, TagWorkspaceError> {
        let slot = group
            .checked_mul(2)
            .ok_or(TagWorkspaceError::Overflow(TagWorkspaceResource::Groups))?;
        Ok(Self { slot })
    }

    /// Construct a capture-end action.
    pub fn end(group: u32) -> Result<Self, TagWorkspaceError> {
        let slot = group
            .checked_mul(2)
            .and_then(|slot| slot.checked_add(1))
            .ok_or(TagWorkspaceError::Overflow(TagWorkspaceResource::Groups))?;
        Ok(Self { slot })
    }

    fn from_slot(slot: usize) -> Result<Self, TagWorkspaceError> {
        Ok(Self {
            slot: u32::try_from(slot)
                .map_err(|_| TagWorkspaceError::Overflow(TagWorkspaceResource::Groups))?,
        })
    }

    /// Numeric capture group.
    #[must_use]
    pub const fn group(self) -> u32 {
        self.slot / 2
    }

    /// Start or end action.
    #[must_use]
    pub const fn kind(self) -> TagKind {
        if self.slot.is_multiple_of(2) {
            TagKind::Start
        } else {
            TagKind::End
        }
    }

    /// Canonical tagged slot.
    #[must_use]
    pub const fn slot(self) -> u32 {
        self.slot
    }
}

/// One tag action and its immutable Thompson state ordinal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProgramTagAction {
    /// Thompson state ordinal.
    pub state: usize,
    /// Capture action performed by that state.
    pub action: TagAction,
}

/// Allocation-free ordered view of every tag action in one program.
#[derive(Debug)]
pub struct ProgramTagActions<'a> {
    states: core::iter::Enumerate<core::slice::Iter<'a, State>>,
}

impl Iterator for ProgramTagActions<'_> {
    type Item = Result<ProgramTagAction, TagWorkspaceError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.states.find_map(|(state, instruction)| {
            let State::Save { slot, .. } = instruction else {
                return None;
            };
            Some(TagAction::from_slot(*slot).map(|action| ProgramTagAction { state, action }))
        })
    }
}

impl Program {
    /// Visit capture actions in immutable state order without allocating.
    #[must_use]
    pub fn tag_actions(&self) -> ProgramTagActions<'_> {
        ProgramTagActions {
            states: self.states.iter().enumerate(),
        }
    }

    /// Number of tag-action states in the immutable program.
    #[must_use]
    pub fn tag_action_len(&self) -> usize {
        self.states
            .iter()
            .filter(|state| matches!(state, State::Save { .. }))
            .count()
    }
}

/// Limits for one fixed-envelope reusable tag workspace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TagWorkspaceLimits {
    /// Maximum canonical groups, including group zero.
    pub max_groups: usize,
    /// Maximum persistent history cells.
    pub max_history_nodes: usize,
    /// Maximum copy-on-write participation states.
    pub max_mask_states: usize,
    /// Maximum words in one participation mask.
    pub max_mask_words: usize,
    /// Maximum allocation attempts, initialized cells and object publication.
    pub max_build_work: usize,
    /// Maximum retained heap payload bytes initialized during construction.
    pub max_initialized_bytes: usize,
    /// Maximum retained payload bytes copied from caller-owned storage.
    pub max_copied_bytes: usize,
    /// Maximum temporary construction payload bytes.
    pub max_scratch_bytes: usize,
    /// Maximum complete retained workspace bytes.
    pub max_persistent_bytes: usize,
    /// Maximum simultaneously live workspace plus construction scratch.
    pub max_peak_bytes: usize,
    /// Maximum exact bytes requested from the allocator.
    pub max_allocator_bytes: usize,
    /// Maximum exact-layout allocations.
    pub max_allocations: usize,
}

impl Default for TagWorkspaceLimits {
    fn default() -> Self {
        Self {
            max_groups: 1 << 16,
            max_history_nodes: 1 << 20,
            max_mask_states: 1 << 20,
            max_mask_words: 1 << 10,
            max_build_work: 1 << 20,
            max_initialized_bytes: 256 << 20,
            max_copied_bytes: 256 << 20,
            max_scratch_bytes: 256 << 20,
            max_persistent_bytes: 256 << 20,
            max_peak_bytes: 512 << 20,
            max_allocator_bytes: 256 << 20,
            max_allocations: 5,
        }
    }
}

/// Limits for one reuse epoch after construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TagRunLimits {
    /// Maximum history cells appended.
    pub max_history_nodes: usize,
    /// Maximum history cells walked.
    pub max_history_walk: usize,
    /// Maximum history cells read for predecessor, head and traversal access.
    pub max_history_reads: usize,
    /// Maximum presence and slot cells inspected while materializing one winner.
    pub max_materialization_reads: usize,
    /// Maximum presence/slot cells written while materializing one winner.
    pub max_materialization_writes: usize,
    /// Maximum legacy preview writes. Direct materialization does not use a
    /// preview and therefore always reports zero for this dimension.
    pub max_materialization_preview_writes: usize,
    /// Maximum copy-on-write participation states.
    pub max_mask_states: usize,
    /// Maximum participation words initialized or copied.
    pub max_mask_word_copies: usize,
    /// Maximum logical words inspected for validation or result queries.
    pub max_mask_word_reads: usize,
    /// Maximum tag actions applied across both projections.
    pub max_tag_actions: usize,
    /// Maximum cells cleared before the epoch begins.
    pub max_reset_cells: usize,
    /// Maximum exact sum of all reuse-epoch work dimensions.
    pub max_work: usize,
}

impl Default for TagRunLimits {
    fn default() -> Self {
        Self {
            max_history_nodes: 1 << 20,
            max_history_walk: 1 << 20,
            max_history_reads: 1 << 24,
            max_materialization_reads: 1 << 20,
            max_materialization_writes: 1 << 21,
            max_materialization_preview_writes: 1 << 20,
            max_mask_states: 1 << 20,
            max_mask_word_copies: 1 << 24,
            max_mask_word_reads: 1 << 24,
            max_tag_actions: 1 << 24,
            max_reset_cells: 1 << 20,
            max_work: usize::MAX,
        }
    }
}

/// Whether participation is carried directly or in admitted spill rows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParticipationStorage {
    /// Up to 64 groups use two inline words in each state handle.
    Inline,
    /// Larger schemas use copy-on-write rows in exact retained storage.
    Spill,
}

/// Complete construction prospective for one workspace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TagWorkspaceProspective {
    /// Canonical groups, including group zero.
    pub groups: usize,
    /// Tagged slots.
    pub slots: usize,
    /// Words in one open or participated mask.
    pub mask_words: usize,
    /// Maximum persistent history cells.
    pub history_nodes: usize,
    /// Maximum spill-mask states.
    pub mask_states: usize,
    /// Selected participation representation.
    pub participation_storage: ParticipationStorage,
    /// Exact allocation attempts, initialized cells and object publication.
    pub build_work: usize,
    /// Exact retained heap payload bytes initialized during construction.
    pub initialized_bytes: usize,
    /// Exact retained payload bytes copied from caller-owned storage.
    pub copied_bytes: usize,
    /// Exact temporary construction payload bytes.
    pub scratch_bytes: usize,
    /// Complete object plus exact heap storage.
    pub persistent_bytes: usize,
    /// Exact simultaneously live workspace plus construction scratch.
    pub peak_bytes: usize,
    /// Exact bytes requested from the allocator.
    pub allocator_bytes: usize,
    /// Exact heap allocation count.
    pub allocations: usize,
}

impl TagWorkspaceProspective {
    /// Whether every construction dimension closes mechanically from the
    /// published schema and capacities.
    #[must_use]
    pub fn closes(self) -> bool {
        let Some(slots) = self.groups.checked_mul(2) else {
            return false;
        };
        let Some(mask_words) = self
            .groups
            .checked_add(WORD_BITS - 1)
            .and_then(|value| value.checked_div(WORD_BITS))
        else {
            return false;
        };
        let participation_storage = if mask_words == 1 {
            ParticipationStorage::Inline
        } else {
            ParticipationStorage::Spill
        };
        let expected_mask_states = if participation_storage == ParticipationStorage::Spill {
            self.mask_states
        } else {
            0
        };
        let Some(spill_cells) = expected_mask_states
            .checked_mul(2)
            .and_then(|states| states.checked_mul(mask_words))
        else {
            return false;
        };
        let Some(presence_words) = slots
            .checked_add(WORD_BITS - 1)
            .and_then(|value| value.checked_div(WORD_BITS))
        else {
            return false;
        };
        let Some(allocations) = usize::from(self.history_nodes > 0)
            .checked_add(usize::from(slots > 0))
            .and_then(|value| value.checked_add(usize::from(presence_words > 0)))
            .and_then(|value| value.checked_add(usize::from(spill_cells > 0)))
        else {
            return false;
        };
        let Some(build_work) = allocations
            .checked_add(1)
            .and_then(|value| value.checked_add(slots))
            .and_then(|value| value.checked_add(presence_words))
        else {
            return false;
        };
        let Some(history_bytes) = self.history_nodes.checked_mul(size_of::<HistoryNode>()) else {
            return false;
        };
        let Some(slot_bytes) = slots.checked_mul(size_of::<usize>()) else {
            return false;
        };
        let Some(presence_bytes) = presence_words.checked_mul(size_of::<u64>()) else {
            return false;
        };
        let Some(spill_bytes) = spill_cells.checked_mul(size_of::<u64>()) else {
            return false;
        };
        let Some(allocator_bytes) = history_bytes
            .checked_add(slot_bytes)
            .and_then(|value| value.checked_add(presence_bytes))
            .and_then(|value| value.checked_add(spill_bytes))
        else {
            return false;
        };
        let Some(initialized_bytes) = slot_bytes.checked_add(presence_bytes) else {
            return false;
        };
        let Some(persistent_bytes) = allocator_bytes.checked_add(size_of::<TagWorkspace>()) else {
            return false;
        };
        let Some(peak_bytes) = persistent_bytes.checked_add(self.scratch_bytes) else {
            return false;
        };
        self.groups > 0
            && self.slots == slots
            && self.mask_words == mask_words
            && self.participation_storage == participation_storage
            && self.mask_states == expected_mask_states
            && self.allocations == allocations
            && self.build_work == build_work
            && self.initialized_bytes == initialized_bytes
            && self.copied_bytes == 0
            && self.scratch_bytes == 0
            && self.allocator_bytes == allocator_bytes
            && self.persistent_bytes == persistent_bytes
            && self.peak_bytes == peak_bytes
    }
}

/// Exact counters for the current reuse epoch.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TagRunAccounting {
    /// History cells appended.
    pub history_nodes: usize,
    /// History cells walked.
    pub history_walk: usize,
    /// History cells read for predecessor, head and traversal access.
    pub history_reads: usize,
    /// Presence and slot cells read while materializing one winner.
    ///
    /// This is mechanically bounded by `history_walk`.
    pub materialization_reads: usize,
    /// Presence and slot cells written while materializing one winner.
    ///
    /// This is mechanically bounded by `2 * history_walk`.
    pub materialization_writes: usize,
    /// Reserved legacy preview-write counter. Direct materialization does not
    /// mutate preview scratch and therefore always reports zero.
    pub materialization_preview_writes: usize,
    /// Spill-mask states materialized.
    pub mask_states: usize,
    /// Mask words initialized or copied into spill states.
    pub mask_word_copies: usize,
    /// Logical mask words inspected for spill validation or result queries.
    pub mask_word_reads: usize,
    /// Tag actions applied.
    pub tag_actions: usize,
    /// Cells cleared before the epoch.
    pub reset_cells: usize,
    /// Exact sum of all published reuse-epoch work dimensions.
    pub work: usize,
    /// Execution allocations. A prepared workspace always reports zero.
    pub allocations: usize,
}

impl TagRunAccounting {
    /// Whether actual counters fit one admitted epoch and all derived
    /// materialization dimensions close.
    #[must_use]
    pub fn closes(self, limits: TagRunLimits) -> bool {
        self.history_nodes <= limits.max_history_nodes
            && self.history_walk <= limits.max_history_walk
            && self.history_reads <= limits.max_history_reads
            && self.materialization_reads <= self.history_walk
            && self.materialization_reads <= limits.max_materialization_reads
            && self.materialization_reads <= self.history_reads
            && self.materialization_writes <= self.materialization_reads.saturating_mul(2)
            && self.materialization_writes <= limits.max_materialization_writes
            && self.materialization_preview_writes <= limits.max_materialization_preview_writes
            && self.materialization_preview_writes <= self.materialization_reads
            && self.mask_states <= limits.max_mask_states
            && self.mask_word_copies <= limits.max_mask_word_copies
            && self.mask_word_reads <= limits.max_mask_word_reads
            && self.tag_actions <= limits.max_tag_actions
            && self.reset_cells <= limits.max_reset_cells
            && self.work <= limits.max_work
            && tag_work_sum(self).is_ok_and(|work| work == self.work)
            && self.allocations == 0
    }
}

/// Opaque immutable handle to one persistent capture history.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct HistoryId {
    workspace: u64,
    index: u32,
    depth: u32,
    end_tags: u32,
    epoch: u64,
}

/// Opaque copy-on-write participation state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParticipationState {
    workspace: u64,
    epoch: u64,
    representation: ParticipationStateRepr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ParticipationStateRepr {
    Inline { open: u64, participated: u64 },
    Spill(u32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HistoryNode {
    offset: usize,
    action: TagAction,
    previous: u32,
    depth: u32,
    end_tags: u32,
}

#[derive(Clone, Copy)]
enum MaterializationProjection {
    Slots,
    Participation,
}

/// Immutable, source-free receipt for one winner reconstruction.
///
/// The handle carries the exact depth and end-tag count, so this plan can be
/// derived and admitted before result storage changes. Full reconstruction
/// performs one deterministic presence/slot action per history node; the
/// participation projection performs one deterministic membership action per
/// end tag.
#[derive(Clone, Copy)]
struct MaterializationPlan {
    history_depth: usize,
    history_walk: usize,
    history_reads: usize,
    materialization_reads: usize,
    materialization_writes: usize,
}

impl MaterializationPlan {
    fn work_delta(self) -> Result<usize, TagWorkspaceError> {
        self.history_walk
            .checked_add(self.history_reads)
            .and_then(|value| value.checked_add(self.materialization_reads))
            .and_then(|value| value.checked_add(self.materialization_writes))
            .ok_or(TagWorkspaceError::Overflow(TagWorkspaceResource::Work))
    }
}

/// Cumulative counters proven before winner result storage changes.
#[derive(Clone, Copy)]
struct MaterializationAdmission {
    history_walk: usize,
    history_reads: usize,
    materialization_reads: usize,
    materialization_writes: usize,
    work: usize,
}

/// Cached winner facts that make persistent-history reduction independent of
/// the number of spill-mask words.
#[derive(Clone, Copy, Debug)]
struct HistoryParticipationSummary {
    complete: bool,
    user_capture_count: usize,
}

#[derive(Debug)]
enum ParticipationStore {
    Inline,
    Spill { words: usize, cells: ExactVec<u64> },
}

#[derive(Clone, Copy)]
struct SpillApplyLedger {
    current_states: usize,
    current_word_copies: usize,
    capacity_states: usize,
    max_states: usize,
    max_word_copies: usize,
}

#[derive(Clone, Copy)]
struct SpillTransition {
    parent_base: Option<usize>,
    word: usize,
    bit: u64,
    kind: TagKind,
}

#[derive(Clone, Copy)]
enum ValidatedParticipation {
    Inline { open: u64, participated: u64 },
    Spill(SpillTransition),
}

/// Fixed-envelope reusable storage for full histories and participation masks.
///
/// Branches copy [`HistoryId`] or [`ParticipationState`] in O(1). Applying a
/// full-capture action appends one compact immutable node. Applying a spill
/// participation action copies exactly two mask rows into already allocated
/// storage. [`Self::begin_run`] invalidates every prior handle without
/// releasing any allocation.
#[derive(Debug)]
pub struct TagWorkspace {
    prospective: TagWorkspaceProspective,
    histories: ExactVec<HistoryNode>,
    slots: ExactVec<usize>,
    slot_presence: ExactVec<u64>,
    participation: ParticipationStore,
    accounting: TagRunAccounting,
    run_limits: TagRunLimits,
    identity: u64,
    epoch: u64,
    active: bool,
    materialized: bool,
}

impl TagWorkspace {
    /// Derive the complete construction envelope without allocating.
    #[allow(
        clippy::too_many_lines,
        reason = "the prospective derives and closes every exact allocation and work dimension in one proof"
    )]
    pub fn prospective(
        groups: usize,
        history_nodes: usize,
        mask_states: usize,
    ) -> Result<TagWorkspaceProspective, TagWorkspaceError> {
        if groups == 0 {
            return Err(TagWorkspaceError::InvalidShape(
                "group zero must be present",
            ));
        }
        let largest_group = groups
            .checked_sub(1)
            .ok_or(TagWorkspaceError::Overflow(TagWorkspaceResource::Groups))?;
        let largest_group = u32::try_from(largest_group)
            .map_err(|_| TagWorkspaceError::Overflow(TagWorkspaceResource::Groups))?;
        TagAction::end(largest_group)?;
        representable_id_capacity(history_nodes, TagWorkspaceResource::HistoryNodes)?;
        let slots = groups
            .checked_mul(2)
            .ok_or(TagWorkspaceError::Overflow(TagWorkspaceResource::Groups))?;
        let mask_words = groups
            .checked_add(WORD_BITS - 1)
            .and_then(|value| value.checked_div(WORD_BITS))
            .ok_or(TagWorkspaceError::Overflow(TagWorkspaceResource::MaskWords))?;
        let participation_storage = if mask_words == 1 {
            ParticipationStorage::Inline
        } else {
            ParticipationStorage::Spill
        };
        let mask_states = if participation_storage == ParticipationStorage::Spill {
            representable_id_capacity(mask_states, TagWorkspaceResource::MaskStates)?;
            mask_states
        } else {
            0
        };
        let spill_cells = if participation_storage == ParticipationStorage::Spill {
            mask_states
                .checked_mul(2)
                .and_then(|states| states.checked_mul(mask_words))
                .ok_or(TagWorkspaceError::Overflow(
                    TagWorkspaceResource::PersistentBytes,
                ))?
        } else {
            0
        };
        let presence_words = slots
            .checked_add(WORD_BITS - 1)
            .and_then(|value| value.checked_div(WORD_BITS))
            .ok_or(TagWorkspaceError::Overflow(
                TagWorkspaceResource::PersistentBytes,
            ))?;
        let allocations = usize::from(history_nodes > 0)
            .checked_add(usize::from(slots > 0))
            .and_then(|value| value.checked_add(usize::from(presence_words > 0)))
            .and_then(|value| value.checked_add(usize::from(spill_cells > 0)))
            .ok_or(TagWorkspaceError::Overflow(
                TagWorkspaceResource::Allocations,
            ))?;
        let build_work = allocations
            .checked_add(1)
            .and_then(|value| value.checked_add(slots))
            .and_then(|value| value.checked_add(presence_words))
            .ok_or(TagWorkspaceError::Overflow(TagWorkspaceResource::BuildWork))?;
        let history_bytes = history_nodes.checked_mul(size_of::<HistoryNode>()).ok_or(
            TagWorkspaceError::Overflow(TagWorkspaceResource::AllocatorBytes),
        )?;
        let slot_bytes =
            slots
                .checked_mul(size_of::<usize>())
                .ok_or(TagWorkspaceError::Overflow(
                    TagWorkspaceResource::AllocatorBytes,
                ))?;
        let presence_bytes =
            presence_words
                .checked_mul(size_of::<u64>())
                .ok_or(TagWorkspaceError::Overflow(
                    TagWorkspaceResource::AllocatorBytes,
                ))?;
        let spill_bytes =
            spill_cells
                .checked_mul(size_of::<u64>())
                .ok_or(TagWorkspaceError::Overflow(
                    TagWorkspaceResource::AllocatorBytes,
                ))?;
        let allocator_bytes = history_bytes
            .checked_add(slot_bytes)
            .and_then(|value| value.checked_add(presence_bytes))
            .and_then(|value| value.checked_add(spill_bytes))
            .ok_or(TagWorkspaceError::Overflow(
                TagWorkspaceResource::AllocatorBytes,
            ))?;
        let initialized_bytes =
            slot_bytes
                .checked_add(presence_bytes)
                .ok_or(TagWorkspaceError::Overflow(
                    TagWorkspaceResource::InitializedBytes,
                ))?;
        let copied_bytes = 0;
        let scratch_bytes = 0;
        let persistent_bytes =
            size_of::<Self>()
                .checked_add(allocator_bytes)
                .ok_or(TagWorkspaceError::Overflow(
                    TagWorkspaceResource::PersistentBytes,
                ))?;
        let peak_bytes = persistent_bytes
            .checked_add(scratch_bytes)
            .ok_or(TagWorkspaceError::Overflow(TagWorkspaceResource::PeakBytes))?;
        let prospective = TagWorkspaceProspective {
            groups,
            slots,
            mask_words,
            history_nodes,
            mask_states,
            participation_storage,
            build_work,
            initialized_bytes,
            copied_bytes,
            scratch_bytes,
            persistent_bytes,
            peak_bytes,
            allocator_bytes,
            allocations,
        };
        if !prospective.closes() {
            return Err(TagWorkspaceError::InvalidShape(
                "construction accounting did not close",
            ));
        }
        Ok(prospective)
    }

    /// Allocate one exact fixed envelope after checking every limit.
    #[allow(
        clippy::too_many_lines,
        reason = "all exact allocations and post-allocation census checks remain one fail-closed construction"
    )]
    pub fn new(
        groups: usize,
        history_nodes: usize,
        mask_states: usize,
        limits: TagWorkspaceLimits,
    ) -> Result<Self, TagWorkspaceError> {
        let prospective = Self::prospective(groups, history_nodes, mask_states)?;
        check_limit(
            TagWorkspaceResource::Groups,
            prospective.groups,
            limits.max_groups,
        )?;
        check_limit(
            TagWorkspaceResource::HistoryNodes,
            prospective.history_nodes,
            limits.max_history_nodes,
        )?;
        check_limit(
            TagWorkspaceResource::MaskStates,
            prospective.mask_states,
            limits.max_mask_states,
        )?;
        check_limit(
            TagWorkspaceResource::MaskWords,
            prospective.mask_words,
            limits.max_mask_words,
        )?;
        check_limit(
            TagWorkspaceResource::BuildWork,
            prospective.build_work,
            limits.max_build_work,
        )?;
        check_limit(
            TagWorkspaceResource::InitializedBytes,
            prospective.initialized_bytes,
            limits.max_initialized_bytes,
        )?;
        check_limit(
            TagWorkspaceResource::CopiedBytes,
            prospective.copied_bytes,
            limits.max_copied_bytes,
        )?;
        check_limit(
            TagWorkspaceResource::ScratchBytes,
            prospective.scratch_bytes,
            limits.max_scratch_bytes,
        )?;
        check_limit(
            TagWorkspaceResource::PersistentBytes,
            prospective.persistent_bytes,
            limits.max_persistent_bytes,
        )?;
        check_limit(
            TagWorkspaceResource::PeakBytes,
            prospective.peak_bytes,
            limits.max_peak_bytes,
        )?;
        check_limit(
            TagWorkspaceResource::AllocatorBytes,
            prospective.allocator_bytes,
            limits.max_allocator_bytes,
        )?;
        check_limit(
            TagWorkspaceResource::Allocations,
            prospective.allocations,
            limits.max_allocations,
        )?;
        let histories = exact_storage(
            prospective.history_nodes,
            TagWorkspaceResource::HistoryNodes,
        )?;
        let mut slots = exact_storage(prospective.slots, TagWorkspaceResource::PersistentBytes)?;
        for _ in 0..prospective.slots {
            exact_push(&mut slots, 0, TagWorkspaceResource::PersistentBytes)?;
        }
        let presence_words = prospective
            .slots
            .checked_add(WORD_BITS - 1)
            .and_then(|value| value.checked_div(WORD_BITS))
            .ok_or(TagWorkspaceError::Overflow(
                TagWorkspaceResource::PersistentBytes,
            ))?;
        let mut slot_presence =
            exact_storage(presence_words, TagWorkspaceResource::PersistentBytes)?;
        for _ in 0..presence_words {
            exact_push(&mut slot_presence, 0, TagWorkspaceResource::PersistentBytes)?;
        }
        let participation = match prospective.participation_storage {
            ParticipationStorage::Inline => ParticipationStore::Inline,
            ParticipationStorage::Spill => {
                let cells = prospective
                    .mask_states
                    .checked_mul(2)
                    .and_then(|states| states.checked_mul(prospective.mask_words))
                    .ok_or(TagWorkspaceError::Overflow(
                        TagWorkspaceResource::PersistentBytes,
                    ))?;
                ParticipationStore::Spill {
                    words: prospective.mask_words,
                    cells: exact_storage(cells, TagWorkspaceResource::PersistentBytes)?,
                }
            }
        };
        let identity = NEXT_WORKSPACE_ID
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| TagWorkspaceError::Overflow(TagWorkspaceResource::WorkspaceIdentity))?;
        Ok(Self {
            prospective,
            histories,
            slots,
            slot_presence,
            participation,
            accounting: TagRunAccounting::default(),
            run_limits: TagRunLimits::default(),
            identity,
            epoch: 0,
            active: false,
            materialized: false,
        })
    }

    /// Exact successful construction report.
    ///
    /// Construction uses no data-dependent path after preflight, so this is
    /// byte-for-byte the source-independent prospective admitted by `new`.
    #[must_use]
    pub const fn build_report(&self) -> TagWorkspaceProspective {
        self.prospective
    }

    /// Begin a reuse epoch after preflighting every cell that will be cleared.
    ///
    /// Failure is transactional: prior handles and materialization remain
    /// untouched. Success invalidates all prior handles and performs no
    /// allocation.
    pub fn begin_run(&mut self, limits: TagRunLimits) -> Result<(), TagWorkspaceError> {
        let reset_cells = self
            .slots
            .len()
            .checked_add(self.slot_presence.len())
            .and_then(|value| value.checked_add(self.histories.len()))
            .and_then(|value| {
                value.checked_add(match &self.participation {
                    ParticipationStore::Inline => 0,
                    ParticipationStore::Spill { cells, .. } => cells.len(),
                })
            })
            .ok_or(TagWorkspaceError::Overflow(
                TagWorkspaceResource::ResetCells,
            ))?;
        check_limit(
            TagWorkspaceResource::ResetCells,
            reset_cells,
            limits.max_reset_cells,
        )?;
        check_limit(TagWorkspaceResource::Work, reset_cells, limits.max_work)?;
        let epoch = self
            .epoch
            .checked_add(1)
            .ok_or(TagWorkspaceError::Overflow(
                TagWorkspaceResource::ReuseEpoch,
            ))?;
        self.histories.clear();
        if let ParticipationStore::Spill { cells, .. } = &mut self.participation {
            cells.clear();
        }
        for slot in &mut self.slots {
            *slot = 0;
        }
        for word in &mut self.slot_presence {
            *word = 0;
        }
        self.accounting = TagRunAccounting {
            reset_cells,
            work: reset_cells,
            ..TagRunAccounting::default()
        };
        self.run_limits = limits;
        self.epoch = epoch;
        self.active = true;
        self.materialized = false;
        Ok(())
    }

    /// Exact counters for the active reuse epoch.
    #[must_use]
    pub const fn accounting(&self) -> TagRunAccounting {
        self.accounting
    }

    /// Tighten the active epoch's total-work cap before a caller performs
    /// additional non-tag work. The cap is monotonic and does not mutate tag
    /// state when the exact current accounting would already exceed it.
    pub fn tighten_max_work(&mut self, max_work: usize) -> Result<(), TagWorkspaceError> {
        self.require_active()?;
        check_limit(TagWorkspaceResource::Work, self.accounting.work, max_work)?;
        self.run_limits.max_work = self.run_limits.max_work.min(max_work);
        Ok(())
    }

    fn preflight_work_delta(&self, delta: usize) -> Result<usize, TagWorkspaceError> {
        let required = checked_add(self.accounting.work, delta, TagWorkspaceResource::Work)?;
        check_limit(
            TagWorkspaceResource::Work,
            required,
            self.run_limits.max_work,
        )?;
        Ok(required)
    }

    /// Append one immutable capture event and return its new history head.
    pub fn record_history(
        &mut self,
        previous: Option<HistoryId>,
        action: TagAction,
        absolute_offset: usize,
    ) -> Result<HistoryId, TagWorkspaceError> {
        self.require_active()?;
        self.validate_action(action)?;
        if let Some(previous) = previous {
            self.validate_history_handle(previous)?;
        }
        let required_actions = checked_add(
            self.accounting.tag_actions,
            1,
            TagWorkspaceResource::TagActions,
        )?;
        check_limit(
            TagWorkspaceResource::TagActions,
            required_actions,
            self.run_limits.max_tag_actions,
        )?;
        let required_nodes =
            checked_add(self.histories.len(), 1, TagWorkspaceResource::HistoryNodes)?;
        check_limit(
            TagWorkspaceResource::HistoryNodes,
            required_nodes,
            self.run_limits.max_history_nodes,
        )?;
        check_limit(
            TagWorkspaceResource::HistoryNodes,
            required_nodes,
            self.prospective.history_nodes,
        )?;
        let required_reads = checked_add(
            self.accounting.history_reads,
            usize::from(previous.is_some()),
            TagWorkspaceResource::HistoryReads,
        )?;
        check_limit(
            TagWorkspaceResource::HistoryReads,
            required_reads,
            self.run_limits.max_history_reads,
        )?;
        let work_delta = 2_usize
            .checked_add(usize::from(previous.is_some()))
            .ok_or(TagWorkspaceError::Overflow(TagWorkspaceResource::Work))?;
        let required_work = self.preflight_work_delta(work_delta)?;
        let (previous_raw, depth, previous_end_tags) = if let Some(previous) = previous {
            let node = self.history(previous)?;
            let depth = node
                .depth
                .checked_add(1)
                .ok_or(TagWorkspaceError::Overflow(
                    TagWorkspaceResource::HistoryNodes,
                ))?;
            (previous.index, depth, node.end_tags)
        } else {
            (NO_ID, 1, 0)
        };
        let end_tags = previous_end_tags
            .checked_add(u32::from(action.kind() == TagKind::End))
            .ok_or(TagWorkspaceError::Overflow(
                TagWorkspaceResource::MaterializationReads,
            ))?;
        let id = HistoryId {
            workspace: self.identity,
            index: representable_id(self.histories.len(), TagWorkspaceResource::HistoryNodes)?,
            depth,
            end_tags,
            epoch: self.epoch,
        };
        exact_push(
            &mut self.histories,
            HistoryNode {
                offset: absolute_offset,
                action,
                previous: previous_raw,
                depth,
                end_tags,
            },
            TagWorkspaceResource::HistoryNodes,
        )?;
        self.accounting.history_nodes = required_nodes;
        self.accounting.history_reads = required_reads;
        self.accounting.tag_actions = required_actions;
        self.accounting.work = required_work;
        Ok(id)
    }

    /// Derive the complete winner receipt from immutable handle metadata.
    ///
    /// No history is walked and no result cell is touched here. This is what
    /// lets every resource refusal occur before validation or reconstruction
    /// starts.
    fn materialization_plan(
        &self,
        history: HistoryId,
        projection: MaterializationProjection,
    ) -> Result<MaterializationPlan, TagWorkspaceError> {
        self.require_active()?;
        if self.materialized {
            return Err(TagWorkspaceError::InvalidState);
        }
        self.validate_history_handle(history)?;
        let history_depth = usize::try_from(history.depth)
            .map_err(|_| TagWorkspaceError::Overflow(TagWorkspaceResource::HistoryWalk))?;
        let history_walk = history_depth
            .checked_mul(2)
            .ok_or(TagWorkspaceError::Overflow(
                TagWorkspaceResource::HistoryWalk,
            ))?;
        let history_reads = history_walk
            .checked_add(1)
            .ok_or(TagWorkspaceError::Overflow(
                TagWorkspaceResource::HistoryReads,
            ))?;
        let end_tags = usize::try_from(history.end_tags)
            .map_err(|_| TagWorkspaceError::Overflow(TagWorkspaceResource::MaterializationReads))?;
        let (materialization_reads, materialization_writes) = match projection {
            MaterializationProjection::Slots => {
                let reads = history_depth
                    .checked_mul(2)
                    .ok_or(TagWorkspaceError::Overflow(
                        TagWorkspaceResource::MaterializationReads,
                    ))?;
                let writes = history_depth
                    .checked_mul(2)
                    .ok_or(TagWorkspaceError::Overflow(
                        TagWorkspaceResource::MaterializationWrites,
                    ))?;
                (reads, writes)
            }
            MaterializationProjection::Participation => (end_tags, end_tags),
        };
        Ok(MaterializationPlan {
            history_depth,
            history_walk,
            history_reads,
            materialization_reads,
            materialization_writes,
        })
    }

    /// Prove every materialization cap before a result cell changes.
    fn admit_materialization(
        &self,
        plan: MaterializationPlan,
    ) -> Result<MaterializationAdmission, TagWorkspaceError> {
        let history_walk = checked_add(
            self.accounting.history_walk,
            plan.history_walk,
            TagWorkspaceResource::HistoryWalk,
        )?;
        check_limit(
            TagWorkspaceResource::HistoryWalk,
            history_walk,
            self.run_limits.max_history_walk,
        )?;
        let history_reads = checked_add(
            self.accounting.history_reads,
            plan.history_reads,
            TagWorkspaceResource::HistoryReads,
        )?;
        check_limit(
            TagWorkspaceResource::HistoryReads,
            history_reads,
            self.run_limits.max_history_reads,
        )?;
        let materialization_reads = checked_add(
            self.accounting.materialization_reads,
            plan.materialization_reads,
            TagWorkspaceResource::MaterializationReads,
        )?;
        check_limit(
            TagWorkspaceResource::MaterializationReads,
            materialization_reads,
            self.run_limits.max_materialization_reads,
        )?;
        let materialization_writes = checked_add(
            self.accounting.materialization_writes,
            plan.materialization_writes,
            TagWorkspaceResource::MaterializationWrites,
        )?;
        check_limit(
            TagWorkspaceResource::MaterializationWrites,
            materialization_writes,
            self.run_limits.max_materialization_writes,
        )?;
        check_limit(
            TagWorkspaceResource::MaterializationPreviewWrites,
            self.accounting.materialization_preview_writes,
            self.run_limits.max_materialization_preview_writes,
        )?;
        Ok(MaterializationAdmission {
            history_walk,
            history_reads,
            materialization_reads,
            materialization_writes,
            work: self.preflight_work_delta(plan.work_delta()?)?,
        })
    }

    /// Publish counters only after the admitted reconstruction completes.
    fn publish_materialization(&mut self, admission: MaterializationAdmission) {
        self.accounting.history_walk = admission.history_walk;
        self.accounting.history_reads = admission.history_reads;
        self.accounting.materialization_reads = admission.materialization_reads;
        self.accounting.materialization_writes = admission.materialization_writes;
        self.accounting.work = admission.work;
        self.materialized = true;
    }

    /// Materialize the latest value for every tagged slot in one history.
    ///
    /// Only one winner may be materialized per reuse epoch. This keeps the
    /// reset and reconstruction ledger exact and makes a forgotten clear a
    /// typed error rather than stale output.
    pub fn materialize_history(
        &mut self,
        history: HistoryId,
    ) -> Result<TagSnapshot<'_>, TagWorkspaceError> {
        let plan = self.materialization_plan(history, MaterializationProjection::Slots)?;
        let admission = self.admit_materialization(plan)?;
        self.validate_materialization_history(history, plan)?;
        self.materialize_history_slots(history, plan.history_depth);
        self.publish_materialization(admission);
        Ok(TagSnapshot {
            groups: self.prospective.groups,
            slots: self.slots.as_slice(),
            presence: self.slot_presence.as_slice(),
        })
    }

    /// Validate the complete immutable chain after admission but before output.
    ///
    /// A valid opaque handle was created by `record_history`, whose immutable
    /// predecessor/depth ledger makes the second, mutation-only pass infallible.
    fn validate_materialization_history(
        &self,
        history: HistoryId,
        plan: MaterializationPlan,
    ) -> Result<(), TagWorkspaceError> {
        let _ = self.history(history)?;
        let mut cursor = history.index;
        let mut remaining = plan.history_depth;
        let mut expected_end_tags = history.end_tags;
        while remaining != 0 {
            if cursor == NO_ID {
                return Err(TagWorkspaceError::InvalidState);
            }
            let node = *self
                .histories
                .get(trusted_u32_index(cursor))
                .ok_or(TagWorkspaceError::InvalidState)?;
            if trusted_u32_index(node.depth) != remaining || node.end_tags != expected_end_tags {
                return Err(TagWorkspaceError::InvalidState);
            }
            self.validate_action(node.action)?;
            if node.action.kind() == TagKind::End {
                expected_end_tags = expected_end_tags
                    .checked_sub(1)
                    .ok_or(TagWorkspaceError::InvalidState)?;
            }
            cursor = node.previous;
            remaining = remaining
                .checked_sub(1)
                .ok_or(TagWorkspaceError::InvalidState)?;
        }
        if cursor == NO_ID && expected_end_tags == 0 {
            Ok(())
        } else {
            Err(TagWorkspaceError::InvalidState)
        }
    }

    /// Reconstruct slots in reverse history order after all resource gates and
    /// immutable-chain validation.
    fn materialize_history_slots(&mut self, history: HistoryId, history_depth: usize) {
        let mut cursor = history.index;
        for _ in 0..history_depth {
            debug_assert_ne!(cursor, NO_ID);
            let node = self.histories.as_slice()[trusted_u32_index(cursor)];
            let slot = trusted_u32_index(node.action.slot());
            let word = slot / WORD_BITS;
            let mask = 1_u64 << (slot % WORD_BITS);
            let already_present = self.slot_presence.as_slice()[word] & mask != 0;
            let retained_offset = self.slots.as_slice()[slot];
            self.slot_presence.as_mut_slice()[word] |= mask;
            self.slots.as_mut_slice()[slot] = if already_present {
                retained_offset
            } else {
                node.offset
            };
            cursor = node.previous;
        }
        debug_assert_eq!(cursor, NO_ID);
    }

    /// Project one winning history to aggregate-required participation only.
    ///
    /// The persistent fallback deliberately avoids reconstructing capture
    /// offsets. A completed end tag is sufficient to prove that its group
    /// participated at least once in the winning history, including captures
    /// retained from an earlier repetition. Group-zero offsets used for
    /// iterator progress remain the executor's independent scalar state.
    pub fn materialize_history_participation(
        &mut self,
        history: HistoryId,
    ) -> Result<ParticipationMask<'_>, TagWorkspaceError> {
        let plan = self.materialization_plan(history, MaterializationProjection::Participation)?;
        let admission = self.admit_materialization(plan)?;
        self.validate_materialization_history(history, plan)?;
        let summary = self.materialize_history_participation_inner(history, plan.history_depth);
        self.publish_materialization(admission);
        let words = self.prospective.mask_words;
        debug_assert!(words <= self.slot_presence.len());
        let participated = &self.slot_presence.as_slice()[..words];
        Ok(ParticipationMask {
            groups: self.prospective.groups,
            representation: ParticipationMaskRepr::Spill {
                open: &[],
                participated,
                history_summary: Some(summary),
            },
            accounting: &mut self.accounting,
            max_word_reads: self.run_limits.max_mask_word_reads,
            max_work: self.run_limits.max_work,
        })
    }

    fn materialize_history_participation_inner(
        &mut self,
        history: HistoryId,
        history_depth: usize,
    ) -> HistoryParticipationSummary {
        let mut cursor = history.index;
        let mut complete = false;
        let mut user_capture_count = 0_usize;
        for _ in 0..history_depth {
            debug_assert_ne!(cursor, NO_ID);
            let node = self.histories.as_slice()[trusted_u32_index(cursor)];
            if node.action.kind() == TagKind::End {
                let group = trusted_u32_index(node.action.group());
                let word = group / WORD_BITS;
                let mask = 1_u64 << (group % WORD_BITS);
                let already_present = self.slot_presence.as_slice()[word] & mask != 0;
                self.slot_presence.as_mut_slice()[word] |= mask;
                if group == 0 {
                    complete = true;
                } else if !already_present {
                    let Some(next) = user_capture_count.checked_add(1) else {
                        unreachable!("a validated group set fits its usize index space");
                    };
                    user_capture_count = next;
                }
            }
            cursor = node.previous;
        }
        debug_assert_eq!(cursor, NO_ID);
        HistoryParticipationSummary {
            complete,
            user_capture_count,
        }
    }

    /// The all-zero participation root for the active epoch.
    pub fn participation_root(&self) -> Result<ParticipationState, TagWorkspaceError> {
        self.require_active()?;
        Ok(ParticipationState {
            workspace: self.identity,
            epoch: self.epoch,
            representation: match self.participation {
                ParticipationStore::Inline => ParticipationStateRepr::Inline {
                    open: 0,
                    participated: 0,
                },
                ParticipationStore::Spill { .. } => ParticipationStateRepr::Spill(NO_ID),
            },
        })
    }

    /// Apply one per-group balanced tag to a copy-on-write participation state.
    pub fn apply_participation(
        &mut self,
        state: ParticipationState,
        action: TagAction,
    ) -> Result<ParticipationState, TagWorkspaceError> {
        self.require_active()?;
        let validation_reads = self.participation_validation_reads(state, action)?;
        let required_actions = checked_add(
            self.accounting.tag_actions,
            1,
            TagWorkspaceResource::TagActions,
        )?;
        check_limit(
            TagWorkspaceResource::TagActions,
            required_actions,
            self.run_limits.max_tag_actions,
        )?;
        let (state_delta, word_copy_delta) =
            if matches!(state.representation, ParticipationStateRepr::Spill(_)) {
                let ParticipationStore::Spill { words, .. } = &self.participation else {
                    return Err(TagWorkspaceError::InvalidState);
                };
                preflight_spill_participation(
                    *words,
                    SpillApplyLedger {
                        current_states: self.accounting.mask_states,
                        current_word_copies: self.accounting.mask_word_copies,
                        capacity_states: self.prospective.mask_states,
                        max_states: self.run_limits.max_mask_states,
                        max_word_copies: self.run_limits.max_mask_word_copies,
                    },
                )?;
                (
                    1,
                    words.checked_mul(2).ok_or(TagWorkspaceError::Overflow(
                        TagWorkspaceResource::MaskWordCopies,
                    ))?,
                )
            } else {
                (0, 0)
            };
        let required_reads = checked_add(
            self.accounting.mask_word_reads,
            validation_reads,
            TagWorkspaceResource::MaskWordReads,
        )?;
        check_limit(
            TagWorkspaceResource::MaskWordReads,
            required_reads,
            self.run_limits.max_mask_word_reads,
        )?;
        let work_delta = 1_usize
            .checked_add(validation_reads)
            .and_then(|value| value.checked_add(state_delta))
            .and_then(|value| value.checked_add(word_copy_delta))
            .ok_or(TagWorkspaceError::Overflow(TagWorkspaceResource::Work))?;
        let required_work = self.preflight_work_delta(work_delta)?;
        let validated = self.validate_participation_transition(state, action)?;

        let representation = match (&mut self.participation, validated) {
            (ParticipationStore::Inline, ValidatedParticipation::Inline { open, participated }) => {
                ParticipationStateRepr::Inline { open, participated }
            }
            (
                ParticipationStore::Spill { words, cells },
                ValidatedParticipation::Spill(transition),
            ) => {
                let (id, states, word_copies) = apply_spill_participation(
                    cells,
                    *words,
                    transition,
                    SpillApplyLedger {
                        current_states: self.accounting.mask_states,
                        current_word_copies: self.accounting.mask_word_copies,
                        capacity_states: self.prospective.mask_states,
                        max_states: self.run_limits.max_mask_states,
                        max_word_copies: self.run_limits.max_mask_word_copies,
                    },
                )?;
                self.accounting.mask_states = states;
                self.accounting.mask_word_copies = word_copies;
                ParticipationStateRepr::Spill(id)
            }
            (ParticipationStore::Inline, ValidatedParticipation::Spill(_))
            | (ParticipationStore::Spill { .. }, ValidatedParticipation::Inline { .. }) => {
                return Err(TagWorkspaceError::InvalidState);
            }
        };
        self.accounting.tag_actions = required_actions;
        self.accounting.mask_word_reads = required_reads;
        self.accounting.work = required_work;
        Ok(ParticipationState {
            workspace: self.identity,
            epoch: self.epoch,
            representation,
        })
    }

    /// Borrow the participated mask in numeric group order.
    pub fn participation_mask(
        &mut self,
        state: ParticipationState,
    ) -> Result<ParticipationMask<'_>, TagWorkspaceError> {
        self.require_active()?;
        if state.workspace != self.identity || state.epoch != self.epoch {
            return Err(TagWorkspaceError::InvalidState);
        }
        let representation = match (&self.participation, state.representation) {
            (ParticipationStore::Inline, ParticipationStateRepr::Inline { open, participated }) => {
                validate_inline_masks(self.prospective.groups, open, participated)?;
                ParticipationMaskRepr::Inline { open, participated }
            }
            (ParticipationStore::Spill { words, cells }, ParticipationStateRepr::Spill(id)) => {
                let Some(base) = spill_parent_base(id, self.accounting.mask_states, *words)? else {
                    return Ok(ParticipationMask {
                        groups: self.prospective.groups,
                        representation: ParticipationMaskRepr::Zero,
                        accounting: &mut self.accounting,
                        max_word_reads: self.run_limits.max_mask_word_reads,
                        max_work: self.run_limits.max_work,
                    });
                };
                let split = base
                    .checked_add(*words)
                    .ok_or(TagWorkspaceError::Overflow(TagWorkspaceResource::MaskWords))?;
                let end = split
                    .checked_add(*words)
                    .ok_or(TagWorkspaceError::Overflow(TagWorkspaceResource::MaskWords))?;
                let row = cells
                    .as_slice()
                    .get(base..end)
                    .ok_or(TagWorkspaceError::InvalidState)?;
                let (open, participated) = row.split_at(*words);
                ParticipationMaskRepr::Spill {
                    open,
                    participated,
                    history_summary: None,
                }
            }
            (ParticipationStore::Inline, ParticipationStateRepr::Spill(_))
            | (ParticipationStore::Spill { .. }, ParticipationStateRepr::Inline { .. }) => {
                return Err(TagWorkspaceError::InvalidState);
            }
        };
        Ok(ParticipationMask {
            groups: self.prospective.groups,
            representation,
            accounting: &mut self.accounting,
            max_word_reads: self.run_limits.max_mask_word_reads,
            max_work: self.run_limits.max_work,
        })
    }

    fn require_active(&self) -> Result<(), TagWorkspaceError> {
        if self.active {
            Ok(())
        } else {
            Err(TagWorkspaceError::InvalidState)
        }
    }

    fn validate_action(&self, action: TagAction) -> Result<(), TagWorkspaceError> {
        let group =
            usize::try_from(action.group()).map_err(|_| TagWorkspaceError::InvalidAction)?;
        if group < self.prospective.groups {
            Ok(())
        } else {
            Err(TagWorkspaceError::InvalidAction)
        }
    }

    fn validate_participation_transition(
        &self,
        state: ParticipationState,
        action: TagAction,
    ) -> Result<ValidatedParticipation, TagWorkspaceError> {
        if state.workspace != self.identity || state.epoch != self.epoch {
            return Err(TagWorkspaceError::InvalidState);
        }
        self.validate_action(action)?;
        match (&self.participation, state.representation) {
            (
                ParticipationStore::Inline,
                ParticipationStateRepr::Inline {
                    mut open,
                    mut participated,
                },
            ) => {
                validate_inline_masks(self.prospective.groups, open, participated)?;
                apply_inline_mask(&mut open, &mut participated, action)?;
                Ok(ValidatedParticipation::Inline { open, participated })
            }
            (ParticipationStore::Spill { words, cells }, ParticipationStateRepr::Spill(parent)) => {
                validate_spill_transition(
                    cells,
                    *words,
                    parent,
                    self.accounting.mask_states,
                    action,
                )
                .map(ValidatedParticipation::Spill)
            }
            (ParticipationStore::Inline, ParticipationStateRepr::Spill(_))
            | (ParticipationStore::Spill { .. }, ParticipationStateRepr::Inline { .. }) => {
                Err(TagWorkspaceError::InvalidState)
            }
        }
    }

    fn participation_validation_reads(
        &self,
        state: ParticipationState,
        action: TagAction,
    ) -> Result<usize, TagWorkspaceError> {
        if state.workspace != self.identity || state.epoch != self.epoch {
            return Err(TagWorkspaceError::InvalidState);
        }
        self.validate_action(action)?;
        match (&self.participation, state.representation) {
            (ParticipationStore::Inline, ParticipationStateRepr::Inline { .. }) => Ok(0),
            (ParticipationStore::Spill { words, .. }, ParticipationStateRepr::Spill(parent)) => {
                spill_parent_base(parent, self.accounting.mask_states, *words)?;
                Ok(usize::from(parent != NO_ID))
            }
            (ParticipationStore::Inline, ParticipationStateRepr::Spill(_))
            | (ParticipationStore::Spill { .. }, ParticipationStateRepr::Inline { .. }) => {
                Err(TagWorkspaceError::InvalidState)
            }
        }
    }

    fn history(&self, id: HistoryId) -> Result<&HistoryNode, TagWorkspaceError> {
        self.validate_history_handle(id)?;
        let node = self
            .histories
            .get(usize::try_from(id.index).map_err(|_| TagWorkspaceError::InvalidState)?)
            .ok_or(TagWorkspaceError::InvalidState)?;
        if node.depth == id.depth && node.end_tags == id.end_tags {
            Ok(node)
        } else {
            Err(TagWorkspaceError::InvalidState)
        }
    }

    fn validate_history_handle(&self, id: HistoryId) -> Result<(), TagWorkspaceError> {
        if id.workspace != self.identity
            || id.epoch != self.epoch
            || id.depth == 0
            || id.end_tags > id.depth
        {
            return Err(TagWorkspaceError::InvalidState);
        }
        let index = usize::try_from(id.index).map_err(|_| TagWorkspaceError::InvalidState)?;
        if index < self.histories.len() {
            Ok(())
        } else {
            Err(TagWorkspaceError::InvalidState)
        }
    }
}

/// Borrowed canonical slot materialization from one history winner.
#[derive(Debug)]
pub struct TagSnapshot<'a> {
    groups: usize,
    slots: &'a [usize],
    presence: &'a [u64],
}

impl TagSnapshot<'_> {
    /// Canonical group count, including group zero.
    #[must_use]
    pub const fn group_len(&self) -> usize {
        self.groups
    }

    /// Latest participating span for one numeric group.
    pub fn span(&self, group: usize) -> Result<Option<Span>, TagWorkspaceError> {
        if group >= self.groups {
            return Err(TagWorkspaceError::InvalidState);
        }
        let start_slot = group
            .checked_mul(2)
            .ok_or(TagWorkspaceError::Overflow(TagWorkspaceResource::Groups))?;
        let end_slot = start_slot
            .checked_add(1)
            .ok_or(TagWorkspaceError::Overflow(TagWorkspaceResource::Groups))?;
        let start_present = bit_is_set(self.presence, start_slot)?;
        let end_present = bit_is_set(self.presence, end_slot)?;
        match (start_present, end_present) {
            (false, false) => Ok(None),
            (true, true) => {
                let start = *self
                    .slots
                    .get(start_slot)
                    .ok_or(TagWorkspaceError::InvalidState)?;
                let end = *self
                    .slots
                    .get(end_slot)
                    .ok_or(TagWorkspaceError::InvalidState)?;
                if start <= end {
                    Ok(Some(Span { start, end }))
                } else {
                    Err(TagWorkspaceError::InvalidState)
                }
            }
            (false, true) | (true, false) => Err(TagWorkspaceError::InvalidState),
        }
    }
}

/// Borrowed participation mask from one winner.
#[derive(Debug)]
pub struct ParticipationMask<'a> {
    groups: usize,
    representation: ParticipationMaskRepr<'a>,
    accounting: &'a mut TagRunAccounting,
    max_word_reads: usize,
    max_work: usize,
}

#[derive(Clone, Copy, Debug)]
enum ParticipationMaskRepr<'a> {
    Zero,
    Inline {
        open: u64,
        participated: u64,
    },
    Spill {
        open: &'a [u64],
        participated: &'a [u64],
        history_summary: Option<HistoryParticipationSummary>,
    },
}

impl ParticipationMask<'_> {
    /// Canonical group count, including group zero.
    #[must_use]
    pub const fn group_len(&self) -> usize {
        self.groups
    }

    /// Whether every capture start has a matching end.
    pub fn is_closed(&mut self) -> Result<bool, TagWorkspaceError> {
        let required_reads = match self.representation {
            ParticipationMaskRepr::Zero | ParticipationMaskRepr::Inline { .. } => 1,
            ParticipationMaskRepr::Spill { open, .. } => open.len(),
        };
        self.charge_word_reads(required_reads)?;
        Ok(match self.representation {
            ParticipationMaskRepr::Zero => true,
            ParticipationMaskRepr::Inline { open, .. } => open == 0,
            ParticipationMaskRepr::Spill { open, .. } => {
                open.iter().fold(true, |closed, word| closed & (*word == 0))
            }
        })
    }

    /// Whether a numeric group participated.
    pub fn contains(&mut self, group: usize) -> Result<bool, TagWorkspaceError> {
        if group >= self.groups {
            return Err(TagWorkspaceError::InvalidState);
        }
        self.charge_word_reads(1)?;
        let word = group / WORD_BITS;
        let bit = 1_u64 << (group % WORD_BITS);
        Ok(match self.representation {
            ParticipationMaskRepr::Zero => false,
            ParticipationMaskRepr::Inline { participated, .. } => participated & bit != 0,
            ParticipationMaskRepr::Spill { participated, .. } => {
                participated
                    .get(word)
                    .ok_or(TagWorkspaceError::InvalidState)?
                    & bit
                    != 0
            }
        })
    }

    /// Participating user captures, excluding group zero.
    pub fn user_capture_count(&mut self) -> Result<usize, TagWorkspaceError> {
        if let ParticipationMaskRepr::Spill {
            history_summary: Some(summary),
            ..
        } = self.representation
        {
            return Ok(summary.user_capture_count);
        }
        let required_reads = match self.representation {
            ParticipationMaskRepr::Zero | ParticipationMaskRepr::Inline { .. } => 1,
            ParticipationMaskRepr::Spill { participated, .. } => participated.len(),
        };
        self.charge_word_reads(required_reads)?;
        let total = match self.representation {
            ParticipationMaskRepr::Zero => 0,
            ParticipationMaskRepr::Inline { participated, .. } => {
                usize::try_from(participated.count_ones()).expect("u64 bit count fits usize")
            }
            ParticipationMaskRepr::Spill { participated, .. } => participated
                .iter()
                .map(|word| usize::try_from(word.count_ones()).expect("u64 bit count fits usize"))
                .sum(),
        };
        let group_zero = match self.representation {
            ParticipationMaskRepr::Zero => false,
            ParticipationMaskRepr::Inline { participated, .. } => participated & 1 != 0,
            ParticipationMaskRepr::Spill { participated, .. } => {
                participated.first().is_some_and(|word| word & 1 != 0)
            }
        };
        Ok(total.saturating_sub(usize::from(group_zero)))
    }

    /// Whether group zero participated and every open tag was closed.
    pub fn accepts_complete_match(&mut self) -> Result<bool, TagWorkspaceError> {
        if let ParticipationMaskRepr::Spill {
            history_summary: Some(summary),
            ..
        } = self.representation
        {
            return Ok(summary.complete);
        }
        let required_reads = match self.representation {
            ParticipationMaskRepr::Zero => 1,
            ParticipationMaskRepr::Inline { .. } => 2,
            ParticipationMaskRepr::Spill { open, .. } => {
                open.len()
                    .checked_add(1)
                    .ok_or(TagWorkspaceError::Overflow(
                        TagWorkspaceResource::MaskWordReads,
                    ))?
            }
        };
        self.charge_word_reads(required_reads)?;
        Ok(match self.representation {
            ParticipationMaskRepr::Zero => false,
            ParticipationMaskRepr::Inline { open, participated } => {
                open == 0 && participated & 1 != 0
            }
            ParticipationMaskRepr::Spill {
                open, participated, ..
            } => {
                let closed = open.iter().fold(true, |closed, word| closed & (*word == 0));
                let group_zero = participated.first().is_some_and(|word| word & 1 != 0);
                closed && group_zero
            }
        })
    }

    fn charge_word_reads(&mut self, delta: usize) -> Result<(), TagWorkspaceError> {
        let required = checked_add(
            self.accounting.mask_word_reads,
            delta,
            TagWorkspaceResource::MaskWordReads,
        )?;
        check_limit(
            TagWorkspaceResource::MaskWordReads,
            required,
            self.max_word_reads,
        )?;
        let work = checked_add(self.accounting.work, delta, TagWorkspaceResource::Work)?;
        check_limit(TagWorkspaceResource::Work, work, self.max_work)?;
        self.accounting.mask_word_reads = required;
        self.accounting.work = work;
        Ok(())
    }
}

fn apply_inline_mask(
    open: &mut u64,
    participated: &mut u64,
    action: TagAction,
) -> Result<(), TagWorkspaceError> {
    let group = usize::try_from(action.group()).map_err(|_| TagWorkspaceError::InvalidAction)?;
    let shift = u32::try_from(group).map_err(|_| TagWorkspaceError::InvalidAction)?;
    let bit = 1_u64
        .checked_shl(shift)
        .ok_or(TagWorkspaceError::InvalidAction)?;
    match action.kind() {
        TagKind::Start if *open & bit == 0 => *open |= bit,
        TagKind::End if *open & bit != 0 => {
            *open &= !bit;
            *participated |= bit;
        }
        TagKind::Start | TagKind::End => return Err(TagWorkspaceError::InvalidAction),
    }
    Ok(())
}

fn validate_inline_masks(
    groups: usize,
    open: u64,
    participated: u64,
) -> Result<(), TagWorkspaceError> {
    let shift = u32::try_from(groups).map_err(|_| TagWorkspaceError::InvalidState)?;
    let valid = 1_u64
        .checked_shl(shift)
        .and_then(|value| value.checked_sub(1))
        .unwrap_or(u64::MAX);
    if (open | participated) & !valid == 0 {
        Ok(())
    } else {
        Err(TagWorkspaceError::InvalidState)
    }
}

fn apply_spill_participation(
    cells: &mut ExactVec<u64>,
    words: usize,
    transition: SpillTransition,
    ledger: SpillApplyLedger,
) -> Result<(u32, usize, usize), TagWorkspaceError> {
    let (row_words, required_states, required_copies) =
        preflight_spill_participation(words, ledger)?;

    let base = cells.len();
    for index in 0..row_words {
        let value = if let Some(parent_base) = transition.parent_base {
            let source = parent_base
                .checked_add(index)
                .ok_or(TagWorkspaceError::Overflow(TagWorkspaceResource::MaskWords))?;
            *cells.get(source).ok_or(TagWorkspaceError::InvalidState)?
        } else {
            0
        };
        exact_push(cells, value, TagWorkspaceResource::MaskStates)?;
    }
    let open_index = base
        .checked_add(transition.word)
        .ok_or(TagWorkspaceError::Overflow(TagWorkspaceResource::MaskWords))?;
    let participated_index = base
        .checked_add(words)
        .and_then(|index| index.checked_add(transition.word))
        .ok_or(TagWorkspaceError::Overflow(TagWorkspaceResource::MaskWords))?;
    match transition.kind {
        TagKind::Start => {
            *cells
                .get_mut(open_index)
                .ok_or(TagWorkspaceError::InvalidState)? |= transition.bit;
        }
        TagKind::End => {
            *cells
                .get_mut(open_index)
                .ok_or(TagWorkspaceError::InvalidState)? &= !transition.bit;
            *cells
                .get_mut(participated_index)
                .ok_or(TagWorkspaceError::InvalidState)? |= transition.bit;
        }
    }
    Ok((
        representable_id(ledger.current_states, TagWorkspaceResource::MaskStates)?,
        required_states,
        required_copies,
    ))
}

fn preflight_spill_participation(
    words: usize,
    ledger: SpillApplyLedger,
) -> Result<(usize, usize, usize), TagWorkspaceError> {
    let row_words = words.checked_mul(2).ok_or(TagWorkspaceError::Overflow(
        TagWorkspaceResource::MaskWordCopies,
    ))?;
    let required_states = checked_add(ledger.current_states, 1, TagWorkspaceResource::MaskStates)?;
    check_limit(
        TagWorkspaceResource::MaskStates,
        required_states,
        ledger.max_states,
    )?;
    check_limit(
        TagWorkspaceResource::MaskStates,
        required_states,
        ledger.capacity_states,
    )?;
    let required_copies = checked_add(
        ledger.current_word_copies,
        row_words,
        TagWorkspaceResource::MaskWordCopies,
    )?;
    check_limit(
        TagWorkspaceResource::MaskWordCopies,
        required_copies,
        ledger.max_word_copies,
    )?;
    representable_id(ledger.current_states, TagWorkspaceResource::MaskStates)?;
    Ok((row_words, required_states, required_copies))
}

fn validate_spill_transition(
    cells: &ExactVec<u64>,
    words: usize,
    parent: u32,
    state_count: usize,
    action: TagAction,
) -> Result<SpillTransition, TagWorkspaceError> {
    let parent_base = spill_parent_base(parent, state_count, words)?;
    let group = usize::try_from(action.group()).map_err(|_| TagWorkspaceError::InvalidAction)?;
    let word = group / WORD_BITS;
    let bit = 1_u64 << (group % WORD_BITS);
    let parent_open = parent_base
        .map(|base| {
            base.checked_add(word)
                .and_then(|index| cells.get(index))
                .copied()
                .ok_or(TagWorkspaceError::InvalidState)
        })
        .transpose()?
        .unwrap_or(0);
    match action.kind() {
        TagKind::Start if parent_open & bit == 0 => {}
        TagKind::End if parent_open & bit != 0 => {}
        TagKind::Start | TagKind::End => return Err(TagWorkspaceError::InvalidAction),
    }
    Ok(SpillTransition {
        parent_base,
        word,
        bit,
        kind: action.kind(),
    })
}

fn spill_parent_base(
    id: u32,
    state_count: usize,
    words: usize,
) -> Result<Option<usize>, TagWorkspaceError> {
    if id == NO_ID {
        return Ok(None);
    }
    let id = usize::try_from(id).map_err(|_| TagWorkspaceError::InvalidState)?;
    if id >= state_count {
        return Err(TagWorkspaceError::InvalidState);
    }
    id.checked_mul(2)
        .and_then(|value| value.checked_mul(words))
        .map(Some)
        .ok_or(TagWorkspaceError::Overflow(TagWorkspaceResource::MaskWords))
}

/// Convert an opaque capture identifier after the workspace has validated its
/// representable capacity and immutable predecessor chain.
fn trusted_u32_index(value: u32) -> usize {
    match usize::try_from(value) {
        Ok(value) => value,
        Err(_) => unreachable!("capture identifiers require a usize-wide target"),
    }
}

fn bit_is_set(words: &[u64], bit: usize) -> Result<bool, TagWorkspaceError> {
    let word = bit / WORD_BITS;
    let mask = 1_u64 << (bit % WORD_BITS);
    Ok(words.get(word).ok_or(TagWorkspaceError::InvalidState)? & mask != 0)
}

fn representable_id_capacity(
    capacity: usize,
    resource: TagWorkspaceResource,
) -> Result<(), TagWorkspaceError> {
    let limit = usize::try_from(NO_ID).map_err(|_| TagWorkspaceError::Overflow(resource))?;
    if capacity > limit {
        Err(TagWorkspaceError::Resource {
            resource,
            required: capacity,
            limit,
        })
    } else {
        Ok(())
    }
}

fn representable_id(
    index: usize,
    resource: TagWorkspaceResource,
) -> Result<u32, TagWorkspaceError> {
    let id = u32::try_from(index).map_err(|_| TagWorkspaceError::Overflow(resource))?;
    if id == NO_ID {
        Err(TagWorkspaceError::Overflow(resource))
    } else {
        Ok(id)
    }
}

fn exact_storage<T>(
    capacity: usize,
    resource: TagWorkspaceResource,
) -> Result<ExactVec<T>, TagWorkspaceError> {
    ExactVec::try_with_capacity(capacity).map_err(|error| match error {
        CopyError::LayoutOverflow => TagWorkspaceError::Overflow(resource),
        CopyError::AllocationFailed => TagWorkspaceError::Allocation(resource),
    })
}

fn exact_push<T>(
    storage: &mut ExactVec<T>,
    value: T,
    resource: TagWorkspaceResource,
) -> Result<(), TagWorkspaceError> {
    storage
        .try_push(value)
        .map_err(|_| TagWorkspaceError::Resource {
            resource,
            required: storage.len().saturating_add(1),
            limit: storage.capacity(),
        })
}

fn tag_work_sum(accounting: TagRunAccounting) -> Result<usize, TagWorkspaceError> {
    accounting
        .history_nodes
        .checked_add(accounting.history_walk)
        .and_then(|value| value.checked_add(accounting.history_reads))
        .and_then(|value| value.checked_add(accounting.materialization_reads))
        .and_then(|value| value.checked_add(accounting.materialization_writes))
        .and_then(|value| value.checked_add(accounting.materialization_preview_writes))
        .and_then(|value| value.checked_add(accounting.mask_states))
        .and_then(|value| value.checked_add(accounting.mask_word_copies))
        .and_then(|value| value.checked_add(accounting.mask_word_reads))
        .and_then(|value| value.checked_add(accounting.tag_actions))
        .and_then(|value| value.checked_add(accounting.reset_cells))
        .ok_or(TagWorkspaceError::Overflow(TagWorkspaceResource::Work))
}

fn checked_add(
    left: usize,
    right: usize,
    resource: TagWorkspaceResource,
) -> Result<usize, TagWorkspaceError> {
    left.checked_add(right)
        .ok_or(TagWorkspaceError::Overflow(resource))
}

fn check_limit(
    resource: TagWorkspaceResource,
    required: usize,
    limit: usize,
) -> Result<(), TagWorkspaceError> {
    if required > limit {
        Err(TagWorkspaceError::Resource {
            resource,
            required,
            limit,
        })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Ast, BuildLimits};

    fn exact_build_limits(prospective: TagWorkspaceProspective) -> TagWorkspaceLimits {
        TagWorkspaceLimits {
            max_groups: prospective.groups,
            max_history_nodes: prospective.history_nodes,
            max_mask_states: prospective.mask_states,
            max_mask_words: prospective.mask_words,
            max_build_work: prospective.build_work,
            max_initialized_bytes: prospective.initialized_bytes,
            max_copied_bytes: prospective.copied_bytes,
            max_scratch_bytes: prospective.scratch_bytes,
            max_persistent_bytes: prospective.persistent_bytes,
            max_peak_bytes: prospective.peak_bytes,
            max_allocator_bytes: prospective.allocator_bytes,
            max_allocations: prospective.allocations,
        }
    }

    fn generous_run_limits() -> TagRunLimits {
        TagRunLimits {
            max_history_nodes: usize::MAX,
            max_history_walk: usize::MAX,
            max_history_reads: usize::MAX,
            max_materialization_reads: usize::MAX,
            max_materialization_writes: usize::MAX,
            max_materialization_preview_writes: usize::MAX,
            max_mask_states: usize::MAX,
            max_mask_word_copies: usize::MAX,
            max_mask_word_reads: usize::MAX,
            max_tag_actions: usize::MAX,
            max_reset_cells: usize::MAX,
            max_work: usize::MAX,
        }
    }

    fn complete_spill_workspace(max_mask_word_reads: usize) -> (TagWorkspace, ParticipationState) {
        let prospective = TagWorkspace::prospective(65, 0, 2).expect("prospective");
        let mut workspace =
            TagWorkspace::new(65, 0, 2, exact_build_limits(prospective)).expect("workspace");
        let mut limits = generous_run_limits();
        limits.max_mask_states = 2;
        limits.max_mask_word_copies = prospective
            .mask_words
            .checked_mul(4)
            .expect("two spill rows");
        limits.max_mask_word_reads = max_mask_word_reads;
        limits.max_tag_actions = 2;
        workspace.begin_run(limits).expect("begin run");
        let root = workspace.participation_root().expect("root");
        let open = workspace
            .apply_participation(root, TagAction::start(0).expect("tag"))
            .expect("open");
        let complete = workspace
            .apply_participation(open, TagAction::end(0).expect("tag"))
            .expect("close");
        (workspace, complete)
    }

    fn complete_two_group_history(workspace: &mut TagWorkspace) -> HistoryId {
        let start_zero = workspace
            .record_history(None, TagAction::start(0).expect("group-zero start"), 0)
            .expect("group-zero start");
        let start_one = workspace
            .record_history(
                Some(start_zero),
                TagAction::start(1).expect("group-one start"),
                1,
            )
            .expect("group-one start");
        let end_one = workspace
            .record_history(
                Some(start_one),
                TagAction::end(1).expect("group-one end"),
                2,
            )
            .expect("group-one end");
        workspace
            .record_history(Some(end_one), TagAction::end(0).expect("group-zero end"), 3)
            .expect("group-zero end")
    }

    fn repeated_group_history(workspace: &mut TagWorkspace, group: u32) -> HistoryId {
        let start_zero = workspace
            .record_history(None, TagAction::start(0).expect("group-zero start"), 0)
            .expect("group-zero start");
        let first_start = workspace
            .record_history(
                Some(start_zero),
                TagAction::start(group).expect("first group start"),
                1,
            )
            .expect("first group start");
        let first_end = workspace
            .record_history(
                Some(first_start),
                TagAction::end(group).expect("first group end"),
                2,
            )
            .expect("first group end");
        let second_start = workspace
            .record_history(
                Some(first_end),
                TagAction::start(group).expect("second group start"),
                3,
            )
            .expect("second group start");
        let second_end = workspace
            .record_history(
                Some(second_start),
                TagAction::end(group).expect("second group end"),
                4,
            )
            .expect("second group end");
        workspace
            .record_history(
                Some(second_end),
                TagAction::end(0).expect("group-zero end"),
                5,
            )
            .expect("group-zero end")
    }

    fn materialization_state(
        workspace: &TagWorkspace,
    ) -> (
        Vec<usize>,
        Vec<u64>,
        Vec<HistoryNode>,
        TagRunAccounting,
        u64,
        bool,
        bool,
    ) {
        (
            workspace.slots.as_slice().to_vec(),
            workspace.slot_presence.as_slice().to_vec(),
            workspace.histories.as_slice().to_vec(),
            workspace.accounting(),
            workspace.epoch,
            workspace.active,
            workspace.materialized,
        )
    }

    fn materialization_counter(
        accounting: TagRunAccounting,
        resource: TagWorkspaceResource,
    ) -> usize {
        match resource {
            TagWorkspaceResource::HistoryWalk => accounting.history_walk,
            TagWorkspaceResource::HistoryReads => accounting.history_reads,
            TagWorkspaceResource::MaterializationReads => accounting.materialization_reads,
            TagWorkspaceResource::MaterializationWrites => accounting.materialization_writes,
            TagWorkspaceResource::Work => accounting.work,
            _ => unreachable!("test only selects materialization resources"),
        }
    }

    fn set_materialization_limit(
        limits: &mut TagRunLimits,
        resource: TagWorkspaceResource,
        value: usize,
    ) {
        match resource {
            TagWorkspaceResource::HistoryWalk => limits.max_history_walk = value,
            TagWorkspaceResource::HistoryReads => limits.max_history_reads = value,
            TagWorkspaceResource::MaterializationReads => limits.max_materialization_reads = value,
            TagWorkspaceResource::MaterializationWrites => {
                limits.max_materialization_writes = value;
            }
            TagWorkspaceResource::Work => limits.max_work = value,
            _ => unreachable!("test only selects materialization resources"),
        }
    }

    fn materialize_for_test(
        workspace: &mut TagWorkspace,
        history: HistoryId,
        participation_only: bool,
    ) -> Result<(), TagWorkspaceError> {
        if participation_only {
            let _ = workspace.materialize_history_participation(history)?;
        } else {
            let _ = workspace.materialize_history(history)?;
        }
        Ok(())
    }

    fn assert_one_below_materialization_gate(
        prospective: TagWorkspaceProspective,
        exact: TagRunAccounting,
        resource: TagWorkspaceResource,
        participation_only: bool,
    ) {
        let required = materialization_counter(exact, resource);
        let limit = required.checked_sub(1).expect("positive exact receipt");
        let mut limits = generous_run_limits();
        set_materialization_limit(&mut limits, resource, limit);
        let mut workspace =
            TagWorkspace::new(2, 6, 0, exact_build_limits(prospective)).expect("workspace");
        workspace.begin_run(limits).expect("limited run");
        let history = repeated_group_history(&mut workspace, 1);
        let before = materialization_state(&workspace);
        assert_eq!(
            materialize_for_test(&mut workspace, history, participation_only),
            Err(TagWorkspaceError::Resource {
                resource,
                required,
                limit,
            })
        );
        assert_eq!(materialization_state(&workspace), before);

        set_materialization_limit(&mut workspace.run_limits, resource, required);
        materialize_for_test(&mut workspace, history, participation_only)
            .expect("exact retry after refused admission");
        assert_eq!(workspace.accounting(), exact);
    }

    fn query_closed(mask: &mut ParticipationMask<'_>) -> Result<(), TagWorkspaceError> {
        mask.is_closed().map(|_| ())
    }

    fn query_contains(mask: &mut ParticipationMask<'_>) -> Result<(), TagWorkspaceError> {
        mask.contains(0).map(|_| ())
    }

    fn query_user_count(mask: &mut ParticipationMask<'_>) -> Result<(), TagWorkspaceError> {
        mask.user_capture_count().map(|_| ())
    }

    fn query_complete(mask: &mut ParticipationMask<'_>) -> Result<(), TagWorkspaceError> {
        mask.accepts_complete_match().map(|_| ())
    }

    fn resource_error(
        result: Result<TagWorkspace, TagWorkspaceError>,
        resource: TagWorkspaceResource,
        required: usize,
        limit: usize,
    ) {
        assert_eq!(
            result.expect_err("one-below construction must refuse"),
            TagWorkspaceError::Resource {
                resource,
                required,
                limit,
            }
        );
    }

    #[test]
    fn program_tag_actions_are_compact_and_state_ordered() {
        let ast = Ast::Byte(b'a').capture(1);
        let program = Program::compile(&ast, BuildLimits::default()).expect("compile");
        let actions = program
            .tag_actions()
            .collect::<Result<Vec<_>, _>>()
            .expect("tag actions");
        assert_eq!(actions.len(), program.tag_action_len());
        assert_eq!(actions.len(), 4);
        assert!(actions.windows(2).all(|pair| pair[0].state < pair[1].state));
        let mut slots = actions
            .iter()
            .map(|tag| tag.action.slot())
            .collect::<Vec<_>>();
        slots.sort_unstable();
        assert_eq!(slots, [0, 1, 2, 3]);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one adversarial matrix covers every independently bounded construction resource"
    )]
    fn construction_preflights_every_independent_resource() {
        let prospective = TagWorkspace::prospective(65, 8, 4).expect("prospective");
        assert_eq!(
            prospective.participation_storage,
            ParticipationStorage::Spill
        );
        assert_eq!(prospective.mask_words, 2);
        assert_eq!(prospective.allocations, 4);
        assert!(prospective.initialized_bytes > 0);
        assert_eq!(prospective.copied_bytes, 0);
        assert_eq!(prospective.scratch_bytes, 0);
        assert!(prospective.allocator_bytes > prospective.initialized_bytes);
        assert_eq!(prospective.peak_bytes, prospective.persistent_bytes);
        assert!(prospective.closes());

        let exact = exact_build_limits(prospective);
        let workspace = TagWorkspace::new(65, 8, 4, exact).expect("exact limits");
        assert_eq!(workspace.build_report(), prospective);

        let mut one_below = exact;
        one_below.max_groups = prospective.groups.checked_sub(1).expect("positive groups");
        resource_error(
            TagWorkspace::new(65, 8, 4, one_below),
            TagWorkspaceResource::Groups,
            prospective.groups,
            one_below.max_groups,
        );

        one_below = exact;
        one_below.max_history_nodes = prospective
            .history_nodes
            .checked_sub(1)
            .expect("positive history");
        resource_error(
            TagWorkspace::new(65, 8, 4, one_below),
            TagWorkspaceResource::HistoryNodes,
            prospective.history_nodes,
            one_below.max_history_nodes,
        );

        one_below = exact;
        one_below.max_mask_states = prospective
            .mask_states
            .checked_sub(1)
            .expect("positive states");
        resource_error(
            TagWorkspace::new(65, 8, 4, one_below),
            TagWorkspaceResource::MaskStates,
            prospective.mask_states,
            one_below.max_mask_states,
        );

        one_below = exact;
        one_below.max_mask_words = prospective
            .mask_words
            .checked_sub(1)
            .expect("positive words");
        resource_error(
            TagWorkspace::new(65, 8, 4, one_below),
            TagWorkspaceResource::MaskWords,
            prospective.mask_words,
            one_below.max_mask_words,
        );

        one_below = exact;
        one_below.max_build_work = prospective
            .build_work
            .checked_sub(1)
            .expect("positive work");
        resource_error(
            TagWorkspace::new(65, 8, 4, one_below),
            TagWorkspaceResource::BuildWork,
            prospective.build_work,
            one_below.max_build_work,
        );

        one_below = exact;
        one_below.max_initialized_bytes = prospective
            .initialized_bytes
            .checked_sub(1)
            .expect("positive initialized bytes");
        resource_error(
            TagWorkspace::new(65, 8, 4, one_below),
            TagWorkspaceResource::InitializedBytes,
            prospective.initialized_bytes,
            one_below.max_initialized_bytes,
        );

        one_below = exact;
        one_below.max_persistent_bytes = prospective
            .persistent_bytes
            .checked_sub(1)
            .expect("positive bytes");
        resource_error(
            TagWorkspace::new(65, 8, 4, one_below),
            TagWorkspaceResource::PersistentBytes,
            prospective.persistent_bytes,
            one_below.max_persistent_bytes,
        );

        one_below = exact;
        one_below.max_peak_bytes = prospective
            .peak_bytes
            .checked_sub(1)
            .expect("positive peak bytes");
        resource_error(
            TagWorkspace::new(65, 8, 4, one_below),
            TagWorkspaceResource::PeakBytes,
            prospective.peak_bytes,
            one_below.max_peak_bytes,
        );

        one_below = exact;
        one_below.max_allocator_bytes = prospective
            .allocator_bytes
            .checked_sub(1)
            .expect("positive allocator bytes");
        resource_error(
            TagWorkspace::new(65, 8, 4, one_below),
            TagWorkspaceResource::AllocatorBytes,
            prospective.allocator_bytes,
            one_below.max_allocator_bytes,
        );

        one_below = exact;
        one_below.max_allocations = prospective
            .allocations
            .checked_sub(1)
            .expect("positive allocations");
        resource_error(
            TagWorkspace::new(65, 8, 4, one_below),
            TagWorkspaceResource::Allocations,
            prospective.allocations,
            one_below.max_allocations,
        );
    }

    #[test]
    fn construction_rejects_unrepresentable_schemas_without_allocating() {
        assert_eq!(
            TagWorkspace::prospective(64, 0, 1)
                .expect("64 groups")
                .participation_storage,
            ParticipationStorage::Inline
        );
        assert_eq!(
            TagWorkspace::prospective(65, 0, 1)
                .expect("65 groups")
                .participation_storage,
            ParticipationStorage::Spill
        );
        assert_eq!(
            TagWorkspace::prospective(0, 0, 0),
            Err(TagWorkspaceError::InvalidShape(
                "group zero must be present"
            ))
        );
        assert_eq!(
            TagAction::end(u32::MAX),
            Err(TagWorkspaceError::Overflow(TagWorkspaceResource::Groups))
        );
        if usize::BITS > u32::BITS {
            let too_many_groups = usize::try_from(u32::MAX)
                .expect("wide usize")
                .checked_div(2)
                .and_then(|value| value.checked_add(2))
                .expect("representable test value");
            assert_eq!(
                TagWorkspace::prospective(too_many_groups, 0, 0),
                Err(TagWorkspaceError::Overflow(TagWorkspaceResource::Groups))
            );
        }
    }

    #[test]
    fn persistent_history_preserves_latest_optional_nested_and_zero_width_spans() {
        let prospective = TagWorkspace::prospective(4, 16, 0).expect("prospective");
        let mut workspace =
            TagWorkspace::new(4, 16, 0, exact_build_limits(prospective)).expect("workspace");
        workspace
            .begin_run(generous_run_limits())
            .expect("begin run");

        let group_zero_start = workspace
            .record_history(None, TagAction::start(0).expect("tag"), 0)
            .expect("group zero start");
        let first_group_start = workspace
            .record_history(Some(group_zero_start), TagAction::start(1).expect("tag"), 0)
            .expect("first group start");
        let first_group_end = workspace
            .record_history(Some(first_group_start), TagAction::end(1).expect("tag"), 1)
            .expect("first group end");
        let zero_width_start = workspace
            .record_history(Some(first_group_end), TagAction::start(2).expect("tag"), 1)
            .expect("zero-width start");
        let zero_width_end = workspace
            .record_history(Some(zero_width_start), TagAction::end(2).expect("tag"), 1)
            .expect("zero-width end");

        let losing_start = workspace
            .record_history(Some(zero_width_end), TagAction::start(3).expect("tag"), 1)
            .expect("losing branch");
        let _losing_end = workspace
            .record_history(Some(losing_start), TagAction::end(3).expect("tag"), 2)
            .expect("losing branch");

        let repeated_start = workspace
            .record_history(Some(zero_width_end), TagAction::start(1).expect("tag"), 2)
            .expect("repeated start");
        let repeated_end = workspace
            .record_history(Some(repeated_start), TagAction::end(1).expect("tag"), 3)
            .expect("repeated end");
        let winner = workspace
            .record_history(Some(repeated_end), TagAction::end(0).expect("tag"), 3)
            .expect("group zero end");

        let snapshot = workspace.materialize_history(winner).expect("snapshot");
        assert_eq!(snapshot.group_len(), 4);
        assert_eq!(
            snapshot.span(0).expect("group"),
            Some(Span { start: 0, end: 3 })
        );
        assert_eq!(
            snapshot.span(1).expect("group"),
            Some(Span { start: 2, end: 3 })
        );
        assert_eq!(
            snapshot.span(2).expect("group"),
            Some(Span { start: 1, end: 1 })
        );
        assert_eq!(snapshot.span(3).expect("group"), None);
        assert_eq!(
            workspace.accounting().history_walk,
            16,
            "only the selected branch is reconstructed"
        );
        assert_eq!(workspace.accounting().allocations, 0);
    }

    #[test]
    fn inline_participation_is_copy_on_write_and_matches_capture_presence() {
        let prospective = TagWorkspace::prospective(4, 0, 100).expect("prospective");
        assert_eq!(
            prospective.participation_storage,
            ParticipationStorage::Inline
        );
        assert_eq!(prospective.mask_states, 0);
        let mut workspace =
            TagWorkspace::new(4, 0, 100, exact_build_limits(prospective)).expect("workspace");
        workspace
            .begin_run(generous_run_limits())
            .expect("begin run");
        let root = workspace.participation_root().expect("root");
        let with_zero = workspace
            .apply_participation(root, TagAction::start(0).expect("tag"))
            .expect("start zero");
        let losing = workspace
            .apply_participation(with_zero, TagAction::start(3).expect("tag"))
            .expect("losing start");
        let losing = workspace
            .apply_participation(losing, TagAction::end(3).expect("tag"))
            .expect("losing end");
        assert!(
            workspace
                .participation_mask(losing)
                .expect("losing mask")
                .contains(3)
                .expect("group")
        );

        let with_one = workspace
            .apply_participation(with_zero, TagAction::start(1).expect("tag"))
            .expect("start one");
        let with_one = workspace
            .apply_participation(with_one, TagAction::end(1).expect("tag"))
            .expect("end one");
        let with_empty = workspace
            .apply_participation(with_one, TagAction::start(2).expect("tag"))
            .expect("start empty");
        let with_empty = workspace
            .apply_participation(with_empty, TagAction::end(2).expect("tag"))
            .expect("end empty");
        let winner = workspace
            .apply_participation(with_empty, TagAction::end(0).expect("tag"))
            .expect("end zero");
        let mut mask = workspace.participation_mask(winner).expect("winner mask");
        assert!(mask.is_closed().expect("closed query"));
        assert!(mask.accepts_complete_match().expect("complete-match query"));
        assert_eq!(mask.user_capture_count().expect("capture-count query"), 2);
        assert!(mask.contains(0).expect("group"));
        assert!(mask.contains(1).expect("group"));
        assert!(mask.contains(2).expect("group"));
        assert!(!mask.contains(3).expect("group"));
        assert_eq!(workspace.accounting().mask_states, 0);
        assert_eq!(workspace.accounting().mask_word_copies, 0);
        assert_eq!(workspace.accounting().allocations, 0);
    }

    fn assert_full_and_participation_trace_agree(
        groups: usize,
        active_group: u32,
        empty_group: u32,
        losing_group: u32,
    ) {
        let prospective = TagWorkspace::prospective(groups, 12, 12).expect("prospective");
        let mut workspace =
            TagWorkspace::new(groups, 12, 12, exact_build_limits(prospective)).expect("workspace");
        workspace
            .begin_run(generous_run_limits())
            .expect("begin run");

        let base_history = workspace
            .record_history(None, TagAction::start(0).expect("tag"), 0)
            .expect("base history");
        let base_mask = workspace
            .apply_participation(
                workspace.participation_root().expect("root"),
                TagAction::start(0).expect("tag"),
            )
            .expect("base mask");

        let losing_history = workspace
            .record_history(
                Some(base_history),
                TagAction::start(losing_group).expect("tag"),
                1,
            )
            .expect("losing history start");
        let _losing_history = workspace
            .record_history(
                Some(losing_history),
                TagAction::end(losing_group).expect("tag"),
                4,
            )
            .expect("losing history end");
        let losing_mask = workspace
            .apply_participation(base_mask, TagAction::start(losing_group).expect("tag"))
            .expect("losing mask start");
        let _losing_mask = workspace
            .apply_participation(losing_mask, TagAction::end(losing_group).expect("tag"))
            .expect("losing mask end");

        let winner_trace = [
            (TagAction::start(active_group).expect("tag"), 1),
            (TagAction::end(active_group).expect("tag"), 2),
            (TagAction::start(empty_group).expect("tag"), 2),
            (TagAction::end(empty_group).expect("tag"), 2),
            (TagAction::start(active_group).expect("tag"), 3),
            (TagAction::end(active_group).expect("tag"), 5),
            (TagAction::end(0).expect("tag"), 5),
        ];
        let mut winner_history = base_history;
        let mut winner_mask = base_mask;
        for (action, offset) in winner_trace {
            winner_history = workspace
                .record_history(Some(winner_history), action, offset)
                .expect("winner history");
            winner_mask = workspace
                .apply_participation(winner_mask, action)
                .expect("winner mask");
        }

        let spans = {
            let snapshot = workspace
                .materialize_history(winner_history)
                .expect("winner snapshot");
            (0..groups)
                .map(|group| snapshot.span(group).expect("group span"))
                .collect::<Vec<_>>()
        };
        let mut mask = workspace
            .participation_mask(winner_mask)
            .expect("winner mask");
        for (group, span) in spans.iter().enumerate() {
            assert_eq!(
                span.is_some(),
                mask.contains(group).expect("mask group"),
                "group={group}"
            );
        }
        assert_eq!(spans[0], Some(Span { start: 0, end: 5 }));
        assert_eq!(
            spans[usize::try_from(active_group).expect("group")],
            Some(Span { start: 3, end: 5 })
        );
        assert_eq!(
            spans[usize::try_from(empty_group).expect("group")],
            Some(Span { start: 2, end: 2 })
        );
        assert_eq!(spans[usize::try_from(losing_group).expect("group")], None);
        assert!(mask.accepts_complete_match().expect("complete-match query"));
        assert_eq!(mask.user_capture_count().expect("capture-count query"), 2);
        assert_eq!(workspace.accounting().history_nodes, 10);
        assert_eq!(workspace.accounting().history_walk, 16);
        assert_eq!(workspace.accounting().tag_actions, 20);
        assert_eq!(workspace.accounting().allocations, 0);
    }

    #[test]
    fn identical_ambiguous_action_traces_project_to_full_and_participation_results() {
        assert_full_and_participation_trace_agree(6, 1, 3, 4);
        assert_full_and_participation_trace_agree(65, 1, 64, 2);
        assert_full_and_participation_trace_agree(130, 64, 129, 1);
    }

    #[test]
    fn spill_participation_covers_multiple_words_without_branch_leakage() {
        let prospective = TagWorkspace::prospective(130, 0, 6).expect("prospective");
        assert_eq!(
            prospective.participation_storage,
            ParticipationStorage::Spill
        );
        assert_eq!(prospective.mask_words, 3);
        let mut workspace =
            TagWorkspace::new(130, 0, 6, exact_build_limits(prospective)).expect("workspace");
        let mut limits = generous_run_limits();
        limits.max_mask_states = 6;
        limits.max_mask_word_copies = 36;
        limits.max_tag_actions = 6;
        workspace.begin_run(limits).expect("begin run");

        let root = workspace.participation_root().expect("root");
        let with_zero = workspace
            .apply_participation(root, TagAction::start(0).expect("tag"))
            .expect("start zero");
        let losing = workspace
            .apply_participation(with_zero, TagAction::start(64).expect("tag"))
            .expect("losing start");
        let losing = workspace
            .apply_participation(losing, TagAction::end(64).expect("tag"))
            .expect("losing end");
        assert!(
            workspace
                .participation_mask(losing)
                .expect("losing mask")
                .contains(64)
                .expect("group")
        );

        let winner = workspace
            .apply_participation(with_zero, TagAction::start(129).expect("tag"))
            .expect("winner start");
        let winner = workspace
            .apply_participation(winner, TagAction::end(129).expect("tag"))
            .expect("winner end");
        let winner = workspace
            .apply_participation(winner, TagAction::end(0).expect("tag"))
            .expect("end zero");
        let mut mask = workspace.participation_mask(winner).expect("winner mask");
        assert!(mask.accepts_complete_match().expect("complete-match query"));
        assert_eq!(mask.user_capture_count().expect("capture-count query"), 1);
        assert!(mask.contains(129).expect("group"));
        assert!(!mask.contains(64).expect("group"));
        assert_eq!(workspace.accounting().mask_states, 6);
        assert_eq!(workspace.accounting().mask_word_copies, 36);
        assert_eq!(workspace.accounting().tag_actions, 6);
        assert_eq!(workspace.accounting().allocations, 0);
    }

    #[test]
    fn operation_limits_refuse_one_below_before_state_mutation() {
        let prospective = TagWorkspace::prospective(65, 2, 2).expect("prospective");
        let mut workspace =
            TagWorkspace::new(65, 2, 2, exact_build_limits(prospective)).expect("workspace");
        let first_reset = prospective
            .slots
            .checked_add(
                prospective
                    .slots
                    .checked_add(WORD_BITS - 1)
                    .and_then(|value| value.checked_div(WORD_BITS))
                    .expect("presence row"),
            )
            .expect("reset bound");
        let mut limits = generous_run_limits();
        limits.max_reset_cells = first_reset;
        limits.max_history_nodes = 1;
        limits.max_history_walk = 0;
        limits.max_mask_states = 0;
        limits.max_mask_word_copies = prospective
            .mask_words
            .checked_mul(2)
            .and_then(|value| value.checked_sub(1))
            .expect("one below copies");
        limits.max_tag_actions = 1;
        workspace.begin_run(limits).expect("exact reset");

        let history = workspace
            .record_history(None, TagAction::start(0).expect("tag"), 0)
            .expect("first history");
        assert_eq!(
            workspace.record_history(Some(history), TagAction::end(0).expect("tag"), 0),
            Err(TagWorkspaceError::Resource {
                resource: TagWorkspaceResource::TagActions,
                required: 2,
                limit: 1,
            })
        );
        assert_eq!(
            workspace.materialize_history(history).map(|_| ()),
            Err(TagWorkspaceError::Resource {
                resource: TagWorkspaceResource::HistoryWalk,
                required: 2,
                limit: 0,
            })
        );
        assert_eq!(workspace.accounting().history_nodes, 1);
        assert_eq!(workspace.accounting().history_walk, 0);
        assert_eq!(workspace.accounting().tag_actions, 1);

        let root = workspace.participation_root().expect("root");
        assert_eq!(
            workspace.apply_participation(root, TagAction::start(0).expect("tag")),
            Err(TagWorkspaceError::Resource {
                resource: TagWorkspaceResource::TagActions,
                required: 2,
                limit: 1,
            })
        );
        assert_eq!(workspace.accounting().mask_states, 0);
        assert_eq!(workspace.accounting().mask_word_copies, 0);
    }

    #[test]
    fn history_reads_charge_predecessor_head_and_traversal_before_mutation() {
        let prospective = TagWorkspace::prospective(2, 2, 0).expect("prospective");
        let mut predecessor_limited =
            TagWorkspace::new(2, 2, 0, exact_build_limits(prospective)).expect("workspace");
        let mut limits = generous_run_limits();
        limits.max_history_reads = 0;
        predecessor_limited.begin_run(limits).expect("begin run");
        let start = predecessor_limited
            .record_history(None, TagAction::start(0).expect("tag"), 0)
            .expect("first node");
        let before = predecessor_limited.accounting();
        assert_eq!(
            predecessor_limited.record_history(Some(start), TagAction::end(0).expect("tag"), 1,),
            Err(TagWorkspaceError::Resource {
                resource: TagWorkspaceResource::HistoryReads,
                required: 1,
                limit: 0,
            })
        );
        assert_eq!(predecessor_limited.accounting(), before);
        assert_eq!(predecessor_limited.histories.len(), 1);

        let mut one_below =
            TagWorkspace::new(2, 2, 0, exact_build_limits(prospective)).expect("workspace");
        limits = generous_run_limits();
        limits.max_history_reads = 3;
        one_below.begin_run(limits).expect("begin run");
        let start = one_below
            .record_history(None, TagAction::start(0).expect("tag"), 0)
            .expect("start");
        let end = one_below
            .record_history(Some(start), TagAction::end(0).expect("tag"), 1)
            .expect("end");
        let slots_before = one_below.slots.as_slice().to_vec();
        let presence_before = one_below.slot_presence.as_slice().to_vec();
        assert_eq!(
            one_below.materialize_history(end).map(|_| ()),
            Err(TagWorkspaceError::Resource {
                resource: TagWorkspaceResource::HistoryReads,
                required: 6,
                limit: 3,
            })
        );
        assert_eq!(one_below.accounting().history_reads, 1);
        assert_eq!(one_below.accounting().history_walk, 0);
        assert_eq!(one_below.slots.as_slice(), slots_before.as_slice());
        assert_eq!(
            one_below.slot_presence.as_slice(),
            presence_before.as_slice()
        );

        let mut exact =
            TagWorkspace::new(2, 2, 0, exact_build_limits(prospective)).expect("workspace");
        limits = generous_run_limits();
        limits.max_history_reads = 6;
        exact.begin_run(limits).expect("begin run");
        let start = exact
            .record_history(None, TagAction::start(0).expect("tag"), 0)
            .expect("start");
        let end = exact
            .record_history(Some(start), TagAction::end(0).expect("tag"), 1)
            .expect("end");
        exact.materialize_history(end).expect("materialize");
        let accounting = exact.accounting();
        assert_eq!(accounting.history_reads, 6);
        assert_eq!(accounting.history_walk, 4);
        assert_eq!(accounting.materialization_reads, 4);
        assert_eq!(accounting.materialization_writes, 4);
        assert_eq!(accounting.materialization_preview_writes, 0);
        assert!(accounting.closes(limits));
    }

    #[test]
    fn exact_materialization_receipts_reserve_writes_and_work_before_result_storage() {
        let prospective = TagWorkspace::prospective(2, 4, 0).expect("prospective");

        let mut baseline =
            TagWorkspace::new(2, 4, 0, exact_build_limits(prospective)).expect("workspace");
        baseline
            .begin_run(generous_run_limits())
            .expect("baseline run");
        let baseline_history = complete_two_group_history(&mut baseline);
        let before_materialization_work = baseline.accounting().work;
        baseline
            .materialize_history(baseline_history)
            .expect("baseline materialization");
        let exact = baseline.accounting();
        assert_eq!(exact.materialization_writes, 8);
        assert_eq!(exact.materialization_preview_writes, 0);

        let mut write_limited =
            TagWorkspace::new(2, 4, 0, exact_build_limits(prospective)).expect("workspace");
        let mut write_limits = generous_run_limits();
        write_limits.max_materialization_writes = exact
            .materialization_writes
            .checked_sub(1)
            .expect("positive write receipt");
        write_limited
            .begin_run(write_limits)
            .expect("write-limited run");
        let history = complete_two_group_history(&mut write_limited);
        let slots_before = write_limited.slots.as_slice().to_vec();
        let presence_before = write_limited.slot_presence.as_slice().to_vec();
        let accounting_before = write_limited.accounting();
        assert_eq!(
            write_limited.materialize_history(history).map(|_| ()),
            Err(TagWorkspaceError::Resource {
                resource: TagWorkspaceResource::MaterializationWrites,
                required: exact.materialization_writes,
                limit: exact.materialization_writes - 1,
            })
        );
        assert_eq!(write_limited.slots.as_slice(), slots_before.as_slice());
        assert_eq!(
            write_limited.slot_presence.as_slice(),
            presence_before.as_slice()
        );
        assert_eq!(write_limited.accounting(), accounting_before);

        let mut work_limited =
            TagWorkspace::new(2, 4, 0, exact_build_limits(prospective)).expect("workspace");
        let mut work_limits = generous_run_limits();
        work_limits.max_work = exact
            .work
            .checked_sub(1)
            .expect("positive materialization work");
        work_limited
            .begin_run(work_limits)
            .expect("work-limited run");
        let history = complete_two_group_history(&mut work_limited);
        assert!(work_limited.accounting().work <= before_materialization_work);
        let slots_before = work_limited.slots.as_slice().to_vec();
        let presence_before = work_limited.slot_presence.as_slice().to_vec();
        let accounting_before = work_limited.accounting();
        assert_eq!(
            work_limited.materialize_history(history).map(|_| ()),
            Err(TagWorkspaceError::Resource {
                resource: TagWorkspaceResource::Work,
                required: exact.work,
                limit: exact.work - 1,
            })
        );
        assert_eq!(work_limited.slots.as_slice(), slots_before.as_slice());
        assert_eq!(
            work_limited.slot_presence.as_slice(),
            presence_before.as_slice()
        );
        assert_eq!(work_limited.accounting(), accounting_before);
    }

    #[test]
    fn preview_limit_is_legacy_and_does_not_mutate_before_result_storage() {
        let prospective = TagWorkspace::prospective(2, 4, 0).expect("prospective");
        let mut full =
            TagWorkspace::new(2, 4, 0, exact_build_limits(prospective)).expect("workspace");
        let mut limits = generous_run_limits();
        limits.max_materialization_preview_writes = 0;
        full.begin_run(limits).expect("limited run");
        let history = complete_two_group_history(&mut full);
        full.materialize_history(history)
            .expect("full materialization with zero legacy limit");
        assert_eq!(full.accounting().materialization_preview_writes, 0);

        let mut participation =
            TagWorkspace::new(2, 4, 0, exact_build_limits(prospective)).expect("workspace");
        limits = generous_run_limits();
        limits.max_materialization_preview_writes = 0;
        participation.begin_run(limits).expect("limited run");
        let history = complete_two_group_history(&mut participation);
        let _ = participation
            .materialize_history_participation(history)
            .expect("participation materialization with zero legacy limit");
        assert_eq!(participation.accounting().materialization_preview_writes, 0);
    }

    #[test]
    fn materialization_admission_refuses_each_gate_before_any_workspace_mutation() {
        let prospective = TagWorkspace::prospective(2, 6, 0).expect("prospective");
        let resources = [
            TagWorkspaceResource::HistoryWalk,
            TagWorkspaceResource::HistoryReads,
            TagWorkspaceResource::MaterializationReads,
            TagWorkspaceResource::MaterializationWrites,
            TagWorkspaceResource::Work,
        ];
        for participation_only in [false, true] {
            let mut baseline =
                TagWorkspace::new(2, 6, 0, exact_build_limits(prospective)).expect("workspace");
            baseline
                .begin_run(generous_run_limits())
                .expect("baseline run");
            let history = repeated_group_history(&mut baseline, 1);
            materialize_for_test(&mut baseline, history, participation_only)
                .expect("baseline materialization");
            let exact = baseline.accounting();
            assert_eq!(exact.materialization_preview_writes, 0);
            for resource in resources {
                assert_one_below_materialization_gate(
                    prospective,
                    exact,
                    resource,
                    participation_only,
                );
            }
        }
    }

    #[test]
    fn wide_history_participation_summary_is_distinct_and_constant_time() {
        let prospective = TagWorkspace::prospective(130, 6, 0).expect("prospective");
        let mut workspace =
            TagWorkspace::new(130, 6, 0, exact_build_limits(prospective)).expect("workspace");
        workspace
            .begin_run(generous_run_limits())
            .expect("begin run");
        let history = repeated_group_history(&mut workspace, 129);
        let before_queries = workspace.accounting();
        {
            let mut mask = workspace
                .materialize_history_participation(history)
                .expect("wide materialization");
            assert!(mask.accepts_complete_match().expect("complete winner"));
            assert_eq!(mask.user_capture_count().expect("cached user count"), 1);
            assert!(mask.contains(129).expect("high group"));
        }
        let accounting = workspace.accounting();
        assert_eq!(accounting.history_walk, 12);
        assert_eq!(accounting.history_reads, 18);
        assert_eq!(accounting.materialization_reads, 3);
        assert_eq!(accounting.materialization_writes, 3);
        assert_eq!(accounting.materialization_preview_writes, 0);
        assert_eq!(
            accounting.mask_word_reads,
            before_queries.mask_word_reads + 1,
            "only the explicit contains query reads one spill word"
        );
    }

    #[test]
    fn tag_work_limit_refuses_before_history_mutation() {
        let prospective = TagWorkspace::prospective(2, 1, 0).expect("prospective");
        let mut workspace =
            TagWorkspace::new(2, 1, 0, exact_build_limits(prospective)).expect("workspace");
        let mut limits = generous_run_limits();
        let reset_work = workspace
            .slots
            .len()
            .checked_add(workspace.slot_presence.len())
            .expect("reset work");
        limits.max_work = reset_work.checked_add(1).expect("one-below record work");
        workspace.begin_run(limits).expect("begin run");
        let accounting_before = workspace.accounting();
        assert_eq!(
            workspace.record_history(None, TagAction::start(0).expect("tag"), 0),
            Err(TagWorkspaceError::Resource {
                resource: TagWorkspaceResource::Work,
                required: reset_work.checked_add(2).expect("record work"),
                limit: reset_work + 1,
            })
        );
        assert_eq!(workspace.accounting(), accounting_before);
        assert!(workspace.histories.is_empty());
    }

    #[test]
    fn spill_validation_and_every_mask_query_preflight_exact_word_reads() {
        type ParticipationQuery =
            for<'a> fn(&mut ParticipationMask<'a>) -> Result<(), TagWorkspaceError>;

        let prospective = TagWorkspace::prospective(65, 0, 2).expect("prospective");
        let mut validation_limited =
            TagWorkspace::new(65, 0, 2, exact_build_limits(prospective)).expect("workspace");
        let mut limits = generous_run_limits();
        limits.max_mask_states = 2;
        limits.max_mask_word_copies = 8;
        limits.max_mask_word_reads = 0;
        limits.max_tag_actions = 2;
        validation_limited.begin_run(limits).expect("begin run");
        let root = validation_limited.participation_root().expect("root");
        let open = validation_limited
            .apply_participation(root, TagAction::start(0).expect("tag"))
            .expect("root transition needs no parent read");
        let before = validation_limited.accounting();
        assert_eq!(
            validation_limited.apply_participation(open, TagAction::end(0).expect("tag")),
            Err(TagWorkspaceError::Resource {
                resource: TagWorkspaceResource::MaskWordReads,
                required: 1,
                limit: 0,
            })
        );
        assert_eq!(validation_limited.accounting(), before);

        let words = prospective.mask_words;
        let queries: [(usize, ParticipationQuery); 4] = [
            (words, query_closed),
            (1, query_contains),
            (words, query_user_count),
            (
                words.checked_add(1).expect("complete query reads"),
                query_complete,
            ),
        ];
        for (query_reads, query) in queries {
            let baseline_reads = 1_usize;
            let exact_reads = baseline_reads
                .checked_add(query_reads)
                .expect("query read bound");
            let limit = exact_reads.checked_sub(1).expect("positive query reads");
            let (mut workspace, state) = complete_spill_workspace(limit);
            let before = workspace.accounting();
            {
                let mut mask = workspace.participation_mask(state).expect("mask");
                assert_eq!(
                    query(&mut mask),
                    Err(TagWorkspaceError::Resource {
                        resource: TagWorkspaceResource::MaskWordReads,
                        required: exact_reads,
                        limit,
                    })
                );
            }
            assert_eq!(workspace.accounting(), before);
        }

        let query_reads = words
            .checked_mul(3)
            .and_then(|value| value.checked_add(2))
            .expect("all query reads");
        let exact_reads = query_reads.checked_add(1).expect("validation read");
        let (mut workspace, state) = complete_spill_workspace(exact_reads);
        {
            let mut mask = workspace.participation_mask(state).expect("mask");
            assert!(mask.is_closed().expect("closed"));
            assert!(mask.contains(0).expect("contains"));
            assert_eq!(mask.user_capture_count().expect("count"), 0);
            assert!(mask.accepts_complete_match().expect("complete"));
        }
        let accounting = workspace.accounting();
        assert_eq!(accounting.mask_word_reads, exact_reads);
        assert!(accounting.closes(TagRunLimits {
            max_mask_word_reads: exact_reads,
            ..generous_run_limits()
        }));
    }

    #[test]
    fn spill_copy_limit_refuses_before_initializing_a_state() {
        let prospective = TagWorkspace::prospective(65, 0, 1).expect("prospective");
        let mut workspace =
            TagWorkspace::new(65, 0, 1, exact_build_limits(prospective)).expect("workspace");
        let row_words = prospective.mask_words.checked_mul(2).expect("row words");
        let mut limits = generous_run_limits();
        limits.max_mask_states = 1;
        limits.max_mask_word_copies = row_words.checked_sub(1).expect("one below");
        workspace.begin_run(limits).expect("begin run");
        let root = workspace.participation_root().expect("root");
        assert_eq!(
            workspace.apply_participation(root, TagAction::start(0).expect("tag")),
            Err(TagWorkspaceError::Resource {
                resource: TagWorkspaceResource::MaskWordCopies,
                required: row_words,
                limit: row_words.checked_sub(1).expect("one below"),
            })
        );
        assert_eq!(
            workspace.accounting(),
            TagRunAccounting {
                reset_cells: workspace.accounting().reset_cells,
                work: workspace.accounting().reset_cells,
                ..TagRunAccounting::default()
            }
        );
    }

    #[test]
    fn node_and_spill_state_limits_refuse_before_mutation() {
        let inline_prospective = TagWorkspace::prospective(2, 1, 0).expect("prospective");
        let mut inline =
            TagWorkspace::new(2, 1, 0, exact_build_limits(inline_prospective)).expect("workspace");
        let mut limits = generous_run_limits();
        limits.max_history_nodes = 0;
        inline.begin_run(limits).expect("begin run");
        assert_eq!(
            inline.record_history(None, TagAction::start(0).expect("tag"), 0),
            Err(TagWorkspaceError::Resource {
                resource: TagWorkspaceResource::HistoryNodes,
                required: 1,
                limit: 0,
            })
        );
        assert_eq!(
            inline.accounting(),
            TagRunAccounting {
                reset_cells: inline.accounting().reset_cells,
                work: inline.accounting().reset_cells,
                ..TagRunAccounting::default()
            }
        );

        let spill_prospective = TagWorkspace::prospective(65, 0, 1).expect("prospective");
        let mut spill =
            TagWorkspace::new(65, 0, 1, exact_build_limits(spill_prospective)).expect("workspace");
        limits = generous_run_limits();
        limits.max_mask_states = 0;
        spill.begin_run(limits).expect("begin run");
        let root = spill.participation_root().expect("root");
        assert_eq!(
            spill.apply_participation(root, TagAction::start(0).expect("tag")),
            Err(TagWorkspaceError::Resource {
                resource: TagWorkspaceResource::MaskStates,
                required: 1,
                limit: 0,
            })
        );
        assert_eq!(
            spill.accounting(),
            TagRunAccounting {
                reset_cells: spill.accounting().reset_cells,
                work: spill.accounting().reset_cells,
                ..TagRunAccounting::default()
            }
        );
    }

    #[test]
    fn failed_reset_is_transactional_and_success_invalidates_old_handles() {
        let prospective = TagWorkspace::prospective(65, 2, 2).expect("prospective");
        let mut workspace =
            TagWorkspace::new(65, 2, 2, exact_build_limits(prospective)).expect("workspace");
        workspace
            .begin_run(generous_run_limits())
            .expect("first run");
        let history = workspace
            .record_history(None, TagAction::start(0).expect("tag"), 0)
            .expect("history");
        let state = workspace
            .apply_participation(
                workspace.participation_root().expect("root"),
                TagAction::start(0).expect("tag"),
            )
            .expect("state");
        let retained_cells = workspace
            .slots
            .len()
            .checked_add(workspace.slot_presence.len())
            .and_then(|value| value.checked_add(workspace.histories.len()))
            .and_then(|value| match &workspace.participation {
                ParticipationStore::Inline => Some(value),
                ParticipationStore::Spill { cells, .. } => value.checked_add(cells.len()),
            })
            .expect("retained cells");
        let mut one_below = generous_run_limits();
        one_below.max_reset_cells = retained_cells.checked_sub(1).expect("one below");
        assert_eq!(
            workspace.begin_run(one_below),
            Err(TagWorkspaceError::Resource {
                resource: TagWorkspaceResource::ResetCells,
                required: retained_cells,
                limit: retained_cells.checked_sub(1).expect("one below"),
            })
        );
        assert!(workspace.participation_mask(state).is_ok());
        assert_eq!(workspace.history(history).expect("old history").offset, 0);

        let mut exact = generous_run_limits();
        exact.max_reset_cells = retained_cells;
        workspace.begin_run(exact).expect("exact reset");
        assert_eq!(
            workspace.participation_mask(state).map(|_| ()),
            Err(TagWorkspaceError::InvalidState)
        );
        assert_eq!(
            workspace.history(history),
            Err(TagWorkspaceError::InvalidState)
        );
        assert_eq!(workspace.accounting().reset_cells, retained_cells);
        assert_eq!(workspace.accounting().allocations, 0);
    }

    #[test]
    fn handles_are_isolated_by_workspace_for_history_inline_and_spill() {
        let inline_prospective = TagWorkspace::prospective(2, 2, 0).expect("prospective");
        let mut inline_a = TagWorkspace::new(2, 2, 0, exact_build_limits(inline_prospective))
            .expect("workspace a");
        let mut inline_b = TagWorkspace::new(2, 2, 0, exact_build_limits(inline_prospective))
            .expect("workspace b");
        inline_a.begin_run(generous_run_limits()).expect("run a");
        let mut no_actions = generous_run_limits();
        no_actions.max_tag_actions = 0;
        inline_b.begin_run(no_actions).expect("run b");

        let foreign_history = inline_a
            .record_history(None, TagAction::start(0).expect("tag"), 0)
            .expect("history a");
        let foreign_inline = inline_a
            .apply_participation(
                inline_a.participation_root().expect("root a"),
                TagAction::start(0).expect("tag"),
            )
            .expect("inline a");
        assert_eq!(
            inline_b.record_history(Some(foreign_history), TagAction::end(0).expect("tag"), 0),
            Err(TagWorkspaceError::InvalidState)
        );
        assert_eq!(
            inline_b.materialize_history(foreign_history).map(|_| ()),
            Err(TagWorkspaceError::InvalidState)
        );
        assert_eq!(
            inline_b.apply_participation(foreign_inline, TagAction::end(0).expect("tag")),
            Err(TagWorkspaceError::InvalidState)
        );
        assert_eq!(
            inline_b.participation_mask(foreign_inline).map(|_| ()),
            Err(TagWorkspaceError::InvalidState)
        );
        assert_eq!(
            inline_b.accounting(),
            TagRunAccounting {
                reset_cells: inline_b.accounting().reset_cells,
                work: inline_b.accounting().reset_cells,
                ..TagRunAccounting::default()
            }
        );

        let spill_prospective = TagWorkspace::prospective(65, 0, 1).expect("prospective");
        let mut spill_a = TagWorkspace::new(65, 0, 1, exact_build_limits(spill_prospective))
            .expect("workspace a");
        let mut spill_b = TagWorkspace::new(65, 0, 1, exact_build_limits(spill_prospective))
            .expect("workspace b");
        spill_a.begin_run(generous_run_limits()).expect("run a");
        spill_b.begin_run(no_actions).expect("run b");
        let foreign_spill = spill_a
            .apply_participation(
                spill_a.participation_root().expect("root a"),
                TagAction::start(64).expect("tag"),
            )
            .expect("spill a");
        assert_eq!(
            spill_b.participation_mask(foreign_spill).map(|_| ()),
            Err(TagWorkspaceError::InvalidState)
        );
        assert_eq!(
            spill_b.apply_participation(foreign_spill, TagAction::end(64).expect("tag")),
            Err(TagWorkspaceError::InvalidState)
        );
        assert_eq!(spill_b.accounting().mask_states, 0);
        assert_eq!(spill_b.accounting().mask_word_copies, 0);
        assert_eq!(spill_b.accounting().tag_actions, 0);
    }

    #[test]
    fn spill_root_has_the_same_zero_mask_contract_as_inline_root() {
        let prospective = TagWorkspace::prospective(65, 0, 0).expect("prospective");
        let mut workspace =
            TagWorkspace::new(65, 0, 0, exact_build_limits(prospective)).expect("workspace");
        workspace
            .begin_run(generous_run_limits())
            .expect("begin run");
        let root = workspace.participation_root().expect("root");
        let mut mask = workspace.participation_mask(root).expect("root mask");
        assert_eq!(mask.group_len(), 65);
        assert!(mask.is_closed().expect("closed query"));
        assert!(!mask.accepts_complete_match().expect("complete-match query"));
        assert_eq!(mask.user_capture_count().expect("capture-count query"), 0);
        assert!(!mask.contains(0).expect("group zero"));
        assert!(!mask.contains(64).expect("last group"));
    }

    #[test]
    fn spill_accounting_scales_linearly_for_fixed_schema_and_reuses_storage() {
        let prospective = TagWorkspace::prospective(129, 0, 16).expect("prospective");
        let mut workspace =
            TagWorkspace::new(129, 0, 16, exact_build_limits(prospective)).expect("workspace");
        let row_words = prospective.mask_words.checked_mul(2).expect("row words");
        let actions = [
            TagAction::start(128).expect("tag"),
            TagAction::start(127).expect("tag"),
            TagAction::end(128).expect("tag"),
            TagAction::end(127).expect("tag"),
        ];
        for action_count in [4_usize, 8] {
            workspace
                .begin_run(generous_run_limits())
                .expect("reuse run");
            let mut state = workspace.participation_root().expect("root");
            for action in actions.iter().copied().cycle().take(action_count) {
                state = workspace
                    .apply_participation(state, action)
                    .expect("tag action");
            }
            assert_eq!(workspace.accounting().mask_states, action_count);
            assert_eq!(
                workspace.accounting().mask_word_copies,
                row_words.checked_mul(action_count).expect("copy bound")
            );
            assert_eq!(workspace.accounting().tag_actions, action_count);
            assert_eq!(workspace.accounting().allocations, 0);
        }
        assert_eq!(workspace.build_report(), prospective);
    }

    #[test]
    fn history_accounting_scales_linearly_for_fixed_schema() {
        let prospective = TagWorkspace::prospective(2, 8, 0).expect("prospective");
        let mut workspace =
            TagWorkspace::new(2, 8, 0, exact_build_limits(prospective)).expect("workspace");
        let actions = [
            TagAction::start(0).expect("tag"),
            TagAction::start(1).expect("tag"),
            TagAction::end(1).expect("tag"),
            TagAction::end(0).expect("tag"),
        ];
        for action_count in [4_usize, 8] {
            workspace
                .begin_run(generous_run_limits())
                .expect("reuse run");
            let mut history = None;
            for (offset, action) in actions
                .iter()
                .copied()
                .cycle()
                .take(action_count)
                .enumerate()
            {
                history = Some(
                    workspace
                        .record_history(history, action, offset)
                        .expect("history event"),
                );
            }
            workspace
                .materialize_history(history.expect("history"))
                .expect("snapshot");
            assert_eq!(workspace.accounting().history_nodes, action_count);
            assert_eq!(
                workspace.accounting().history_walk,
                action_count.checked_mul(2).expect("two-pass history walk")
            );
            assert_eq!(workspace.accounting().tag_actions, action_count);
            assert_eq!(workspace.accounting().allocations, 0);
        }
    }

    #[test]
    fn malformed_tag_sequences_and_groups_are_isolated() {
        let prospective = TagWorkspace::prospective(2, 2, 0).expect("prospective");
        let mut workspace =
            TagWorkspace::new(2, 2, 0, exact_build_limits(prospective)).expect("workspace");
        workspace
            .begin_run(generous_run_limits())
            .expect("begin run");
        let root = workspace.participation_root().expect("root");
        assert_eq!(
            workspace.apply_participation(root, TagAction::end(1).expect("tag")),
            Err(TagWorkspaceError::InvalidAction)
        );
        assert_eq!(
            workspace.apply_participation(root, TagAction::start(2).expect("tag")),
            Err(TagWorkspaceError::InvalidAction)
        );
        let open = workspace
            .apply_participation(root, TagAction::start(1).expect("tag"))
            .expect("open");
        assert_eq!(
            workspace.apply_participation(open, TagAction::start(1).expect("tag")),
            Err(TagWorkspaceError::InvalidAction)
        );
        assert_eq!(workspace.accounting().tag_actions, 1);
        assert_eq!(workspace.accounting().allocations, 0);
    }
}
