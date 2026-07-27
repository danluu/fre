//! Reusable fused capture-participation execution.
//!
//! This module executes the ordered Thompson frontier and its capture tags in
//! one operation. Capture participation is a quotient of tagged histories:
//! when two threads reach the same program counter in one generation, the
//! first thread is the leftmost-first winner and later histories cannot affect
//! control. Schemas that fit one machine word therefore retain only open and
//! participated masks. Wider schemas select persistent histories before
//! source access and materialize only the current winner.

use core::{fmt, mem::size_of};
use std::sync::Arc;

use fre_exact_alloc::{CopyError, ExactVec};

use crate::compile::{Program, State};
use crate::line::SemanticBoundary;
use crate::model::{CaptureCountOutcome, Span, Window};
use crate::tagged::{
    HistoryId, ParticipationState, ParticipationStorage, TagAction, TagRunAccounting, TagRunLimits,
    TagWorkspace, TagWorkspaceError, TagWorkspaceLimits, TagWorkspaceProspective,
    TagWorkspaceResource,
};

/// Semantic algorithm version of the fused capture stream.
pub const CAPTURE_STREAM_ALGORITHM_VERSION: u32 = 1;

/// Resource-accounting version of the fused capture stream.
pub const CAPTURE_STREAM_ACCOUNTING_VERSION: u32 = 3;

const INLINE_GROUP_BITS: usize = 64;

/// Logical domains supplied to one fused operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureStreamDomains {
    /// One ordinary complete-haystack capture operation.
    Whole,
    /// Rebar grep domains: LF terminates a line, an immediately preceding CR
    /// is stripped, lone CR is content, and no synthetic trailing line is
    /// emitted.
    RebarLines,
}

/// Construction-selected representation of capture tags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureStreamProjection {
    /// Group zero plus at most 63 user groups use reusable inline masks.
    ParticipationMask,
    /// Wider schemas retain bounded immutable histories for the current
    /// search and materialize only its winner.
    PersistentHistory,
}

/// One independently bounded capture-stream resource.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureStreamResource {
    /// Complete source bytes.
    SourceBytes,
    /// Immutable program states.
    States,
    /// Exact construction work.
    BuildWork,
    /// Complete prepared object plus exact heap storage.
    PersistentBytes,
    /// Co-live prepared bytes.
    CombinedPeakBytes,
    /// Exact-layout construction allocations.
    Allocations,
    /// Logical line domains.
    LineDomains,
    /// Independently selected searches.
    Searches,
    /// Selected non-empty matches.
    Matches,
    /// Input bytes tested by consuming transitions.
    BytesExamined,
    /// Lower-priority candidate starts injected.
    StartsInjected,
    /// Ordered-frontier state visits.
    StateVisits,
    /// Capture tag actions.
    TagActions,
    /// Persistent history cells.
    HistoryNodes,
    /// Winning-history reads.
    HistoryWalk,
    /// All history reads, including predecessor and winner access.
    HistoryReads,
    /// Winner materialization presence reads.
    MaterializationReads,
    /// Winner materialization presence/slot writes.
    MaterializationWrites,
    /// Exact-materialization preview scratch presence writes.
    MaterializationPreviewWrites,
    /// Spill participation states.
    MaskStates,
    /// Spill participation word copies.
    MaskWordCopies,
    /// Participation word reads.
    MaskWordReads,
    /// Tag-workspace reset cells.
    ResetCells,
    /// Capture-schema observations.
    CaptureEvents,
    /// Participating-group result.
    CaptureCount,
    /// LF partition source reads.
    LineSourceReads,
    /// Total logical execution work.
    Work,
    /// Monotonic frontier generation.
    Generation,
}

/// A capture-stream construction or execution failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CaptureStreamError {
    /// A checked ceiling would be exceeded.
    Resource {
        /// Limited resource.
        resource: CaptureStreamResource,
        /// Required amount.
        required: usize,
        /// Configured maximum.
        limit: usize,
    },
    /// Checked arithmetic overflowed.
    Overflow(CaptureStreamResource),
    /// One exact-layout construction allocation failed.
    Allocation(CaptureStreamResource),
    /// Reusable tag storage refused or faulted.
    Tags(TagWorkspaceError),
    /// Source length differs from the construction-bound identity.
    SourceLength {
        /// Construction-bound byte length.
        expected: usize,
        /// Supplied byte length.
        actual: usize,
    },
    /// The immutable program violated a compiled invariant.
    InvalidProgram,
    /// Count-participation does not admit empty selected matches.
    EmptyMatch,
}

impl fmt::Display for CaptureStreamError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "capture stream error: {self:?}")
    }
}

impl std::error::Error for CaptureStreamError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Tags(error) => Some(error),
            _ => None,
        }
    }
}

impl From<TagWorkspaceError> for CaptureStreamError {
    fn from(error: TagWorkspaceError) -> Self {
        match error {
            TagWorkspaceError::Resource {
                resource,
                required,
                limit,
            } => map_tag_resource(resource).map_or_else(
                || {
                    Self::Tags(TagWorkspaceError::Resource {
                        resource,
                        required,
                        limit,
                    })
                },
                |resource| Self::Resource {
                    resource,
                    required,
                    limit,
                },
            ),
            TagWorkspaceError::Overflow(resource) => map_tag_resource(resource).map_or_else(
                || Self::Tags(TagWorkspaceError::Overflow(resource)),
                Self::Overflow,
            ),
            TagWorkspaceError::Allocation(resource) => map_tag_resource(resource).map_or_else(
                || Self::Tags(TagWorkspaceError::Allocation(resource)),
                Self::Allocation,
            ),
            other => Self::Tags(other),
        }
    }
}

const fn map_tag_resource(resource: TagWorkspaceResource) -> Option<CaptureStreamResource> {
    match resource {
        TagWorkspaceResource::HistoryNodes => Some(CaptureStreamResource::HistoryNodes),
        TagWorkspaceResource::TagActions => Some(CaptureStreamResource::TagActions),
        TagWorkspaceResource::HistoryWalk => Some(CaptureStreamResource::HistoryWalk),
        TagWorkspaceResource::HistoryReads => Some(CaptureStreamResource::HistoryReads),
        TagWorkspaceResource::MaterializationReads => {
            Some(CaptureStreamResource::MaterializationReads)
        }
        TagWorkspaceResource::MaterializationWrites => {
            Some(CaptureStreamResource::MaterializationWrites)
        }
        TagWorkspaceResource::MaterializationPreviewWrites => {
            Some(CaptureStreamResource::MaterializationPreviewWrites)
        }
        TagWorkspaceResource::MaskStates => Some(CaptureStreamResource::MaskStates),
        TagWorkspaceResource::MaskWordCopies => Some(CaptureStreamResource::MaskWordCopies),
        TagWorkspaceResource::MaskWordReads => Some(CaptureStreamResource::MaskWordReads),
        TagWorkspaceResource::ResetCells => Some(CaptureStreamResource::ResetCells),
        TagWorkspaceResource::Work => Some(CaptureStreamResource::Work),
        TagWorkspaceResource::BuildWork => Some(CaptureStreamResource::BuildWork),
        TagWorkspaceResource::PersistentBytes
        | TagWorkspaceResource::InitializedBytes
        | TagWorkspaceResource::CopiedBytes
        | TagWorkspaceResource::ScratchBytes
        | TagWorkspaceResource::AllocatorBytes => Some(CaptureStreamResource::PersistentBytes),
        TagWorkspaceResource::PeakBytes => Some(CaptureStreamResource::CombinedPeakBytes),
        TagWorkspaceResource::Allocations => Some(CaptureStreamResource::Allocations),
        TagWorkspaceResource::Groups
        | TagWorkspaceResource::MaskWords
        | TagWorkspaceResource::ReuseEpoch
        | TagWorkspaceResource::WorkspaceIdentity => None,
    }
}

/// Complete construction and execution ceilings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureStreamLimits {
    /// Maximum source bytes bound into one prepared stream.
    pub max_source_bytes: usize,
    /// Maximum immutable program states.
    pub max_states: usize,
    /// Maximum construction work.
    pub max_build_work: usize,
    /// Maximum retained prepared bytes.
    pub max_persistent_bytes: usize,
    /// Maximum co-live prepared bytes.
    pub max_combined_peak_bytes: usize,
    /// Maximum exact-layout construction allocations.
    pub max_allocations: usize,
    /// Maximum line domains.
    pub max_line_domains: usize,
    /// Maximum searches, including terminal misses.
    pub max_searches: usize,
    /// Maximum selected non-empty matches.
    pub max_matches: usize,
    /// Maximum input bytes tested by consuming transitions.
    pub max_bytes_examined: usize,
    /// Maximum lower-priority candidate starts injected.
    pub max_starts_injected: usize,
    /// Maximum ordered-frontier state visits.
    pub max_state_visits: usize,
    /// Maximum capture tag actions.
    pub max_tag_actions: usize,
    /// Maximum persistent history cells.
    pub max_history_nodes: usize,
    /// Maximum winning-history reads.
    pub max_history_walk: usize,
    /// Maximum history reads, including predecessor and materialization reads.
    pub max_history_reads: usize,
    /// Maximum materialization presence-word reads.
    pub max_materialization_reads: usize,
    /// Maximum materialization presence/slot writes.
    pub max_materialization_writes: usize,
    /// Maximum exact-materialization preview scratch writes.
    pub max_materialization_preview_writes: usize,
    /// Maximum spill participation states.
    pub max_mask_states: usize,
    /// Maximum spill participation word copies.
    pub max_mask_word_copies: usize,
    /// Maximum participation word reads.
    pub max_mask_word_reads: usize,
    /// Maximum tag-workspace reset cells.
    pub max_reset_cells: usize,
    /// Maximum capture-schema observations.
    pub max_capture_events: usize,
    /// Maximum returned participation count.
    pub max_capture_count: usize,
    /// Maximum LF partition source reads.
    pub max_line_source_reads: usize,
    /// Maximum total logical execution work.
    pub max_work: usize,
}

impl Default for CaptureStreamLimits {
    fn default() -> Self {
        Self {
            max_source_bytes: 1 << 30,
            max_states: 1 << 20,
            max_build_work: 1 << 30,
            max_persistent_bytes: 512 << 20,
            max_combined_peak_bytes: 512 << 20,
            max_allocations: 16,
            max_line_domains: 1 << 30,
            max_searches: 1 << 30,
            max_matches: 1 << 30,
            max_bytes_examined: 1 << 40,
            max_starts_injected: 1 << 40,
            max_state_visits: 1 << 40,
            max_tag_actions: 1 << 40,
            max_history_nodes: 1 << 40,
            max_history_walk: 1 << 40,
            max_history_reads: 1 << 40,
            max_materialization_reads: 1 << 40,
            max_materialization_writes: 1 << 40,
            max_materialization_preview_writes: 1 << 40,
            max_mask_states: 1 << 40,
            max_mask_word_copies: 1 << 40,
            max_mask_word_reads: 1 << 40,
            max_reset_cells: 1 << 40,
            max_capture_events: 1 << 40,
            max_capture_count: 1 << 40,
            max_line_source_reads: 1 << 30,
            max_work: usize::MAX,
        }
    }
}

/// Source-independent construction envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureStreamProspective {
    /// Semantic algorithm version.
    pub algorithm_version: u32,
    /// Resource-accounting version.
    pub accounting_version: u32,
    /// Bound source length.
    pub source_bytes: usize,
    /// Canonical groups, including group zero.
    pub groups: usize,
    /// Immutable state count.
    pub states: usize,
    /// Save-state count.
    pub tag_states: usize,
    /// Construction-selected tag projection.
    pub projection: CaptureStreamProjection,
    /// Exact frontier cells retained across all searches.
    pub frontier_cells: usize,
    /// Exact outer heap payload for the three frontiers and generation marks.
    pub frontier_bytes: usize,
    /// Immutable program bytes retained by the stream owner.
    pub program_bytes: usize,
    /// Reusable tag-workspace envelope.
    pub tags: TagWorkspaceProspective,
    /// Exact construction initialization/copy work.
    pub build_work: usize,
    /// Complete object plus exact heap storage.
    pub persistent_bytes: usize,
    /// Co-live prepared bytes.
    pub combined_peak_bytes: usize,
    /// Exact-layout allocation count.
    pub allocations: usize,
    /// Exact bytes requested from the allocator by stream construction.
    pub allocator_bytes: usize,
}

/// Source-free execution envelope for one complete prepared-stream operation.
///
/// The fused executor deliberately retains its priority-preserving restarted
/// search semantics. This receipt publishes the finite, fixed-program upper
/// bound for that restart schedule before any source byte is observed. It is
/// separate from [`CaptureStreamProspective`], whose purpose is only exact
/// construction admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureStreamOperationProspective {
    /// Semantic algorithm version.
    pub algorithm_version: u32,
    /// Resource-accounting version.
    pub accounting_version: u32,
    /// Exact prepared-object envelope used by this operation.
    pub construction: CaptureStreamProspective,
    /// Logical source partition contract.
    pub domains: CaptureStreamDomains,
    /// Maximum logical line domains.
    pub line_domains: usize,
    /// Maximum independently selected searches.
    pub searches: usize,
    /// Maximum selected non-empty matches.
    pub matches: usize,
    /// Maximum consuming-transition byte tests.
    pub bytes_examined: usize,
    /// Maximum candidate starts injected into the ordered frontier.
    pub starts_injected: usize,
    /// Maximum ordered-frontier state visits.
    pub state_visits: usize,
    /// Maximum tag actions.
    pub tag_actions: usize,
    /// Maximum persistent history cells.
    pub history_nodes: usize,
    /// Maximum history cells walked while validating and materializing winners.
    pub history_walk: usize,
    /// Maximum predecessor, validation, and materialization history reads.
    pub history_reads: usize,
    /// Maximum materialization presence and slot reads.
    pub materialization_reads: usize,
    /// Maximum published materialization presence/slot writes.
    pub materialization_writes: usize,
    /// Reserved legacy preview writes; direct materialization reports zero.
    pub materialization_preview_writes: usize,
    /// Maximum spill participation states.
    pub mask_states: usize,
    /// Maximum spill participation word copies.
    pub mask_word_copies: usize,
    /// Maximum result/validation participation-word reads.
    pub mask_word_reads: usize,
    /// Maximum tag-workspace cells reset between searches.
    pub reset_cells: usize,
    /// Maximum capture-schema events.
    pub capture_events: usize,
    /// Maximum returned capture participation count.
    pub capture_count: usize,
    /// Maximum LF partition source reads.
    pub line_source_reads: usize,
    /// Maximum exact logical execution work.
    pub work: usize,
}

impl CaptureStreamOperationProspective {
    /// Whether the receipt is internally coherent without inspecting source.
    #[must_use]
    pub fn closes(self) -> bool {
        self.algorithm_version == CAPTURE_STREAM_ALGORITHM_VERSION
            && self.accounting_version == CAPTURE_STREAM_ACCOUNTING_VERSION
            && self.construction.closes()
            && self.line_domains
                == match self.domains {
                    CaptureStreamDomains::Whole => 1,
                    CaptureStreamDomains::RebarLines => self.construction.source_bytes,
                }
            && self.line_source_reads
                == match self.domains {
                    CaptureStreamDomains::Whole => 0,
                    CaptureStreamDomains::RebarLines => self.construction.source_bytes,
                }
            && self.construction.groups.checked_mul(self.matches) == Some(self.capture_events)
            && self.capture_count == self.capture_events
            && Some(self.work)
                == operation_work_sum(
                    self.line_domains,
                    self.searches,
                    self.state_visits,
                    self.tag_actions,
                    self.history_nodes,
                    self.history_walk,
                    self.history_reads,
                    self.materialization_reads,
                    self.materialization_writes,
                    self.materialization_preview_writes,
                    self.mask_states,
                    self.mask_word_copies,
                    self.mask_word_reads,
                    self.reset_cells,
                    self.capture_events,
                    self.line_source_reads,
                    self.bytes_examined,
                    self.starts_injected,
                )
                .ok()
    }

    /// Recompute and authenticate this exact fixed-program envelope.
    #[must_use]
    pub fn authenticates_program(self, program: &Program) -> bool {
        CaptureStream::operation_prospective(program, self.construction.source_bytes, self.domains)
            .is_ok_and(|expected| expected == self)
    }

    /// Check every construction and operation resource before source access.
    pub fn admits(self, limits: CaptureStreamLimits) -> Result<(), CaptureStreamError> {
        self.admits_construction(limits)?;
        self.admits_search_and_history(limits)?;
        self.admits_result(limits)
    }

    fn admits_construction(self, limits: CaptureStreamLimits) -> Result<(), CaptureStreamError> {
        check(
            CaptureStreamResource::SourceBytes,
            self.construction.source_bytes,
            limits.max_source_bytes,
        )?;
        check(
            CaptureStreamResource::States,
            self.construction.states,
            limits.max_states,
        )?;
        check(
            CaptureStreamResource::BuildWork,
            self.construction.build_work,
            limits.max_build_work,
        )?;
        check(
            CaptureStreamResource::PersistentBytes,
            self.construction.persistent_bytes,
            limits.max_persistent_bytes,
        )?;
        check(
            CaptureStreamResource::CombinedPeakBytes,
            self.construction.combined_peak_bytes,
            limits.max_combined_peak_bytes,
        )?;
        check(
            CaptureStreamResource::Allocations,
            self.construction.allocations,
            limits.max_allocations,
        )
    }

    fn admits_search_and_history(
        self,
        limits: CaptureStreamLimits,
    ) -> Result<(), CaptureStreamError> {
        check(
            CaptureStreamResource::LineDomains,
            self.line_domains,
            limits.max_line_domains,
        )?;
        check(
            CaptureStreamResource::Searches,
            self.searches,
            limits.max_searches,
        )?;
        check(
            CaptureStreamResource::Matches,
            self.matches,
            limits.max_matches,
        )?;
        check(
            CaptureStreamResource::BytesExamined,
            self.bytes_examined,
            limits.max_bytes_examined,
        )?;
        check(
            CaptureStreamResource::StartsInjected,
            self.starts_injected,
            limits.max_starts_injected,
        )?;
        check(
            CaptureStreamResource::StateVisits,
            self.state_visits,
            limits.max_state_visits,
        )?;
        check(
            CaptureStreamResource::TagActions,
            self.tag_actions,
            limits.max_tag_actions,
        )?;
        check(
            CaptureStreamResource::HistoryNodes,
            self.history_nodes,
            limits.max_history_nodes,
        )?;
        check(
            CaptureStreamResource::HistoryWalk,
            self.history_walk,
            limits.max_history_walk,
        )?;
        check(
            CaptureStreamResource::HistoryReads,
            self.history_reads,
            limits.max_history_reads,
        )
    }

    fn admits_result(self, limits: CaptureStreamLimits) -> Result<(), CaptureStreamError> {
        check(
            CaptureStreamResource::MaterializationReads,
            self.materialization_reads,
            limits.max_materialization_reads,
        )?;
        check(
            CaptureStreamResource::MaterializationWrites,
            self.materialization_writes,
            limits.max_materialization_writes,
        )?;
        check(
            CaptureStreamResource::MaterializationPreviewWrites,
            self.materialization_preview_writes,
            limits.max_materialization_preview_writes,
        )?;
        check(
            CaptureStreamResource::MaskStates,
            self.mask_states,
            limits.max_mask_states,
        )?;
        check(
            CaptureStreamResource::MaskWordCopies,
            self.mask_word_copies,
            limits.max_mask_word_copies,
        )?;
        check(
            CaptureStreamResource::MaskWordReads,
            self.mask_word_reads,
            limits.max_mask_word_reads,
        )?;
        check(
            CaptureStreamResource::ResetCells,
            self.reset_cells,
            limits.max_reset_cells,
        )?;
        check(
            CaptureStreamResource::CaptureEvents,
            self.capture_events,
            limits.max_capture_events,
        )?;
        check(
            CaptureStreamResource::CaptureCount,
            self.capture_count,
            limits.max_capture_count,
        )?;
        check(
            CaptureStreamResource::LineSourceReads,
            self.line_source_reads,
            limits.max_line_source_reads,
        )?;
        check(CaptureStreamResource::Work, self.work, limits.max_work)
    }
}

impl CaptureStreamProspective {
    /// Whether every construction dimension closes mechanically.
    #[must_use]
    pub fn closes(self) -> bool {
        let expected_projection = if self.groups <= INLINE_GROUP_BITS {
            CaptureStreamProjection::ParticipationMask
        } else {
            CaptureStreamProjection::PersistentHistory
        };
        let expected_history_nodes = match self.projection {
            CaptureStreamProjection::ParticipationMask => Some(0),
            CaptureStreamProjection::PersistentHistory => self
                .source_bytes
                .checked_add(1)
                .and_then(|boundaries| self.tag_states.checked_mul(boundaries)),
        };
        let expected_frontier_cells = self.states.checked_mul(3);
        let expected_frontier_bytes = expected_frontier_cells
            .and_then(|cells| {
                let thread_bytes = match self.projection {
                    CaptureStreamProjection::ParticipationMask => size_of::<ParticipationThread>(),
                    CaptureStreamProjection::PersistentHistory => size_of::<HistoryThread>(),
                };
                cells.checked_mul(thread_bytes)
            })
            .and_then(|bytes| {
                self.states
                    .checked_mul(size_of::<usize>())
                    .and_then(|seen| bytes.checked_add(seen))
            });
        let outer_allocations = usize::from(self.states > 0).checked_mul(4);
        let expected_allocations =
            outer_allocations.and_then(|outer| outer.checked_add(self.tags.allocations));
        let expected_build_work = self
            .states
            .checked_mul(2)
            .and_then(|work| work.checked_add(outer_allocations?))
            .and_then(|work| work.checked_add(1))
            .and_then(|work| work.checked_add(self.tags.build_work));
        let expected_allocator_bytes =
            expected_frontier_bytes.and_then(|bytes| bytes.checked_add(self.tags.allocator_bytes));
        let expected_persistent_bytes = expected_allocator_bytes
            .and_then(|bytes| bytes.checked_add(size_of::<CaptureStream>()))
            .and_then(|bytes| bytes.checked_add(self.program_bytes));
        self.algorithm_version == CAPTURE_STREAM_ALGORITHM_VERSION
            && self.accounting_version == CAPTURE_STREAM_ACCOUNTING_VERSION
            && self.states > 0
            && self.groups > 0
            && self.projection == expected_projection
            && self.tags.closes()
            && self.tags.groups == self.groups
            && expected_history_nodes == Some(self.tags.history_nodes)
            && self.tags.mask_states == 0
            && self.tags.participation_storage
                == if self.groups <= INLINE_GROUP_BITS {
                    ParticipationStorage::Inline
                } else {
                    ParticipationStorage::Spill
                }
            && expected_frontier_cells == Some(self.frontier_cells)
            && expected_frontier_bytes == Some(self.frontier_bytes)
            && expected_allocations == Some(self.allocations)
            && expected_build_work == Some(self.build_work)
            && expected_allocator_bytes == Some(self.allocator_bytes)
            && expected_persistent_bytes == Some(self.persistent_bytes)
            && self.combined_peak_bytes == self.persistent_bytes
    }

    /// Whether this prospective is the unique mechanically derived envelope
    /// for `program` and its already-bound source length.
    #[must_use]
    pub fn authenticates_program(self, program: &Program) -> bool {
        CaptureStream::prospective(program, self.source_bytes)
            .is_ok_and(|expected| expected == self)
    }
}

/// Exact logical counters for one fused operation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CaptureStreamAccounting {
    /// Logical line domains.
    pub line_domains: usize,
    /// Independently selected searches, including terminal misses.
    pub searches: usize,
    /// Ordered-frontier state visits.
    pub state_visits: usize,
    /// Capture tags applied.
    pub tag_actions: usize,
    /// Persistent history cells appended.
    pub history_nodes: usize,
    /// Winning-history cells read.
    pub history_walk: usize,
    /// History reads, including predecessor and materialization reads.
    pub history_reads: usize,
    /// Presence and slot reads while materializing winners.
    pub materialization_reads: usize,
    /// Presence/slot writes while materializing winners.
    pub materialization_writes: usize,
    /// Reserved legacy preview writes; direct materialization reports zero.
    pub materialization_preview_writes: usize,
    /// Spill participation states.
    pub mask_states: usize,
    /// Spill participation word copies.
    pub mask_word_copies: usize,
    /// Participation word reads.
    pub mask_word_reads: usize,
    /// Cells cleared across tag reuse epochs.
    pub reset_cells: usize,
    /// Capture-schema observations.
    pub capture_events: usize,
    /// LF partition source reads.
    pub line_source_reads: usize,
    /// Input bytes tested by consuming transitions.
    pub bytes_examined: usize,
    /// Candidate starts injected.
    pub starts_injected: usize,
    /// Maximum live consuming/match frontier.
    pub peak_threads: usize,
    /// Charged logical work, exactly the sum of the published work
    /// dimensions above. It is a resource ledger, not a machine-instruction
    /// count.
    pub work: usize,
    /// Dynamic execution allocations after preparation.
    pub allocations: usize,
}

/// Successful fused participation reduction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureStreamReport {
    /// Semantic algorithm version.
    pub algorithm_version: u32,
    /// Resource-accounting version.
    pub accounting_version: u32,
    /// Logical domain contract executed by this report.
    pub domains: CaptureStreamDomains,
    /// Complete construction/execution limits bound before source access.
    pub limits: CaptureStreamLimits,
    /// Construction envelope authenticated by this operation.
    pub prospective: CaptureStreamProspective,
    /// Source-free execution envelope admitted before this operation started.
    pub operation: CaptureStreamOperationProspective,
    /// Exact execution accounting.
    pub accounting: CaptureStreamAccounting,
    /// Existing aggregate-compatible projection.
    pub captures: CaptureCountOutcome,
    /// First selected whole-match span, retained without per-match storage.
    pub first_match: Option<Span>,
    /// Last selected whole-match span, retained for progress/offset closure.
    pub last_match: Option<Span>,
    /// Exact capture-schema events.
    pub capture_events: usize,
    /// Prepared co-live bytes.
    pub combined_peak_bytes: usize,
}

impl CaptureStreamReport {
    /// Whether the report is internally closed and remains within `limits`.
    #[must_use]
    #[allow(
        clippy::too_many_lines,
        reason = "the public receipt closes every prospective, observed, and derived counter in one audit boundary"
    )]
    pub fn closes(&self, limits: CaptureStreamLimits) -> bool {
        let expected_work = self
            .accounting
            .line_domains
            .checked_add(self.accounting.searches)
            .and_then(|value| value.checked_add(self.accounting.state_visits))
            .and_then(|value| value.checked_add(self.accounting.tag_actions))
            .and_then(|value| value.checked_add(self.accounting.history_nodes))
            .and_then(|value| value.checked_add(self.accounting.history_walk))
            .and_then(|value| value.checked_add(self.accounting.history_reads))
            .and_then(|value| value.checked_add(self.accounting.materialization_reads))
            .and_then(|value| value.checked_add(self.accounting.materialization_writes))
            .and_then(|value| value.checked_add(self.accounting.materialization_preview_writes))
            .and_then(|value| value.checked_add(self.accounting.mask_states))
            .and_then(|value| value.checked_add(self.accounting.mask_word_copies))
            .and_then(|value| value.checked_add(self.accounting.mask_word_reads))
            .and_then(|value| value.checked_add(self.accounting.reset_cells))
            .and_then(|value| value.checked_add(self.accounting.capture_events))
            .and_then(|value| value.checked_add(self.accounting.line_source_reads))
            .and_then(|value| value.checked_add(self.accounting.bytes_examined))
            .and_then(|value| value.checked_add(self.accounting.starts_injected));
        let expected_searches = self
            .accounting
            .line_domains
            .checked_add(self.captures.matches);
        let expected_capture_events = self.prospective.groups.checked_mul(self.captures.matches);
        let derived_history = self.accounting.materialization_reads <= self.accounting.history_walk
            && self.accounting.materialization_reads <= self.accounting.history_reads
            && self.accounting.materialization_writes <= self.accounting.materialization_reads
            && self.accounting.materialization_preview_writes
                <= self.accounting.materialization_reads;
        let expected_mask_word_reads = match self.prospective.projection {
            CaptureStreamProjection::ParticipationMask => self.captures.matches.checked_mul(3),
            CaptureStreamProjection::PersistentHistory => Some(0),
        };
        let projection_closes = match self.prospective.projection {
            CaptureStreamProjection::ParticipationMask => {
                self.accounting.history_nodes == 0
                    && self.accounting.history_walk == 0
                    && self.accounting.history_reads == 0
                    && self.accounting.materialization_reads == 0
                    && self.accounting.materialization_writes == 0
                    && self.accounting.materialization_preview_writes == 0
                    && self.accounting.mask_states == 0
                    && self.accounting.mask_word_copies == 0
            }
            CaptureStreamProjection::PersistentHistory => {
                self.accounting.history_nodes == self.accounting.tag_actions
                    && self.accounting.mask_states == 0
                    && self.accounting.mask_word_copies == 0
            }
        };
        let domains_close = match self.domains {
            CaptureStreamDomains::Whole => {
                self.accounting.line_domains == 1 && self.accounting.line_source_reads == 0
            }
            CaptureStreamDomains::RebarLines => {
                self.accounting.line_source_reads == self.prospective.source_bytes
            }
        };
        let spans_close = match (self.captures.matches, self.first_match, self.last_match) {
            (0, None, None) => true,
            (0, _, _) => false,
            (_, Some(first), Some(last)) => {
                first.start < first.end
                    && last.start < last.end
                    && first.end <= self.prospective.source_bytes
                    && last.end <= self.prospective.source_bytes
                    && first.start <= last.start
            }
            _ => false,
        };
        self.algorithm_version == CAPTURE_STREAM_ALGORITHM_VERSION
            && self.accounting_version == CAPTURE_STREAM_ACCOUNTING_VERSION
            && self.limits == limits
            && self.prospective.closes()
            && self.operation.closes()
            && self.operation.construction == self.prospective
            && self.operation.domains == self.domains
            && self.operation.admits(limits).is_ok()
            && self.prospective.tags.closes()
            && self.accounting.capture_events == self.capture_events
            && self.accounting.allocations == 0
            && expected_work == Some(self.accounting.work)
            && expected_searches == Some(self.accounting.searches)
            && expected_capture_events == Some(self.capture_events)
            && expected_mask_word_reads == Some(self.accounting.mask_word_reads)
            && self.captures.count >= self.captures.matches
            && self.captures.count <= self.capture_events
            && self.accounting.peak_threads <= self.prospective.states
            && derived_history
            && projection_closes
            && domains_close
            && spans_close
            && self.captures.searches == self.accounting.searches
            && self.captures.total_state_visits == self.accounting.state_visits
            && self.captures.total_history_nodes == self.accounting.history_nodes
            && self.captures.total_history_walk == self.accounting.history_walk
            && self.captures.peak_threads == self.accounting.peak_threads
            && self.prospective.source_bytes <= limits.max_source_bytes
            && self.prospective.states <= limits.max_states
            && self.prospective.build_work <= limits.max_build_work
            && self.prospective.persistent_bytes <= limits.max_persistent_bytes
            && self.prospective.combined_peak_bytes <= limits.max_combined_peak_bytes
            && self.prospective.allocations <= limits.max_allocations
            && self.combined_peak_bytes == self.prospective.combined_peak_bytes
            && self.accounting.line_domains <= limits.max_line_domains
            && self.accounting.searches <= limits.max_searches
            && self.captures.matches <= limits.max_matches
            && self.accounting.bytes_examined <= limits.max_bytes_examined
            && self.accounting.starts_injected <= limits.max_starts_injected
            && self.accounting.state_visits <= limits.max_state_visits
            && self.accounting.tag_actions <= limits.max_tag_actions
            && self.accounting.history_nodes <= limits.max_history_nodes
            && self.accounting.history_walk <= limits.max_history_walk
            && self.accounting.history_reads <= limits.max_history_reads
            && self.accounting.materialization_reads <= limits.max_materialization_reads
            && self.accounting.materialization_writes <= limits.max_materialization_writes
            && self.accounting.materialization_preview_writes
                <= limits.max_materialization_preview_writes
            && self.accounting.mask_states <= limits.max_mask_states
            && self.accounting.mask_word_copies <= limits.max_mask_word_copies
            && self.accounting.mask_word_reads <= limits.max_mask_word_reads
            && self.accounting.reset_cells <= limits.max_reset_cells
            && self.accounting.capture_events <= limits.max_capture_events
            && self.captures.count <= limits.max_capture_count
            && self.accounting.line_source_reads <= limits.max_line_source_reads
            && self.accounting.work <= limits.max_work
            && self.accounting.line_domains <= self.operation.line_domains
            && self.accounting.searches <= self.operation.searches
            && self.captures.matches <= self.operation.matches
            && self.accounting.bytes_examined <= self.operation.bytes_examined
            && self.accounting.starts_injected <= self.operation.starts_injected
            && self.accounting.state_visits <= self.operation.state_visits
            && self.accounting.tag_actions <= self.operation.tag_actions
            && self.accounting.history_nodes <= self.operation.history_nodes
            && self.accounting.history_walk <= self.operation.history_walk
            && self.accounting.history_reads <= self.operation.history_reads
            && self.accounting.materialization_reads <= self.operation.materialization_reads
            && self.accounting.materialization_writes <= self.operation.materialization_writes
            && self.accounting.materialization_preview_writes
                <= self.operation.materialization_preview_writes
            && self.accounting.mask_states <= self.operation.mask_states
            && self.accounting.mask_word_copies <= self.operation.mask_word_copies
            && self.accounting.mask_word_reads <= self.operation.mask_word_reads
            && self.accounting.reset_cells <= self.operation.reset_cells
            && self.capture_events <= self.operation.capture_events
            && self.captures.count <= self.operation.capture_count
            && self.accounting.line_source_reads <= self.operation.line_source_reads
            && self.accounting.work <= self.operation.work
    }

    /// Whether this successful receipt closes and binds the exact immutable
    /// program from which its construction prospective was derived.
    #[must_use]
    pub fn authenticates_program(&self, program: &Program) -> bool {
        self.closes(self.limits)
            && self.prospective.authenticates_program(program)
            && self.operation.authenticates_program(program)
    }
}

#[derive(Clone, Copy, Debug)]
struct ParticipationThread {
    pc: usize,
    tags: ParticipationState,
    overall_start: Option<usize>,
    overall_end: Option<usize>,
}

#[derive(Clone, Copy, Debug)]
struct HistoryThread {
    pc: usize,
    history: Option<HistoryId>,
    overall_start: Option<usize>,
    overall_end: Option<usize>,
}

#[derive(Debug)]
struct ParticipationFrontier {
    current: ExactVec<ParticipationThread>,
    next: ExactVec<ParticipationThread>,
    stack: ExactVec<ParticipationThread>,
}

#[derive(Debug)]
struct HistoryFrontier {
    current: ExactVec<HistoryThread>,
    next: ExactVec<HistoryThread>,
    stack: ExactVec<HistoryThread>,
}

#[derive(Debug)]
enum Frontier {
    Participation(ParticipationFrontier),
    History(HistoryFrontier),
}

/// Prepared reusable capture stream.
///
/// Construction allocates the complete fixed envelope before source access.
/// [`Self::execute`] clears and reuses it for every selected match and line.
#[derive(Debug)]
pub struct CaptureStream {
    program: Arc<Program>,
    domains: CaptureStreamDomains,
    limits: CaptureStreamLimits,
    prospective: CaptureStreamProspective,
    operation: CaptureStreamOperationProspective,
    frontier: Frontier,
    seen: ExactVec<usize>,
    tags: TagWorkspace,
    generation: usize,
}

impl CaptureStream {
    /// Derive a complete source-independent envelope without allocating.
    pub fn prospective(
        program: &Program,
        source_bytes: usize,
    ) -> Result<CaptureStreamProspective, CaptureStreamError> {
        let states = program.states.len();
        let groups = program.groups.len();
        if states == 0 || groups == 0 || program.slot_count != groups.saturating_mul(2) {
            return Err(CaptureStreamError::InvalidProgram);
        }
        let tag_states = program
            .states
            .iter()
            .filter(|state| matches!(state, State::Save { .. }))
            .count();
        let projection = if groups <= INLINE_GROUP_BITS {
            CaptureStreamProjection::ParticipationMask
        } else {
            CaptureStreamProjection::PersistentHistory
        };
        let boundaries = source_bytes
            .checked_add(1)
            .ok_or(CaptureStreamError::Overflow(
                CaptureStreamResource::HistoryNodes,
            ))?;
        let history_capacity = if projection == CaptureStreamProjection::PersistentHistory {
            tag_states
                .checked_mul(boundaries)
                .ok_or(CaptureStreamError::Overflow(
                    CaptureStreamResource::HistoryNodes,
                ))?
        } else {
            0
        };
        let tags = TagWorkspace::prospective(groups, history_capacity, 0)?;
        let frontier_cells = states.checked_mul(3).ok_or(CaptureStreamError::Overflow(
            CaptureStreamResource::PersistentBytes,
        ))?;
        let thread_bytes = match projection {
            CaptureStreamProjection::ParticipationMask => size_of::<ParticipationThread>(),
            CaptureStreamProjection::PersistentHistory => size_of::<HistoryThread>(),
        };
        let frontier_bytes = frontier_cells
            .checked_mul(thread_bytes)
            .and_then(|bytes| bytes.checked_add(states.checked_mul(size_of::<usize>())?))
            .ok_or(CaptureStreamError::Overflow(
                CaptureStreamResource::PersistentBytes,
            ))?;
        let outer_allocations =
            usize::from(states > 0)
                .checked_mul(4)
                .ok_or(CaptureStreamError::Overflow(
                    CaptureStreamResource::Allocations,
                ))?;
        let allocations =
            outer_allocations
                .checked_add(tags.allocations)
                .ok_or(CaptureStreamError::Overflow(
                    CaptureStreamResource::Allocations,
                ))?;
        let build_work = states
            .checked_mul(2)
            .and_then(|value| value.checked_add(outer_allocations))
            .and_then(|value| value.checked_add(1))
            .and_then(|value| value.checked_add(tags.build_work))
            .ok_or(CaptureStreamError::Overflow(
                CaptureStreamResource::BuildWork,
            ))?;
        let allocator_bytes = frontier_bytes.checked_add(tags.allocator_bytes).ok_or(
            CaptureStreamError::Overflow(CaptureStreamResource::PersistentBytes),
        )?;
        let program_bytes = program.build_report().program_bytes;
        let persistent_bytes = size_of::<Self>()
            .checked_add(allocator_bytes)
            .and_then(|bytes| bytes.checked_add(program.build_report().program_bytes))
            .ok_or(CaptureStreamError::Overflow(
                CaptureStreamResource::PersistentBytes,
            ))?;
        let prospective = CaptureStreamProspective {
            algorithm_version: CAPTURE_STREAM_ALGORITHM_VERSION,
            accounting_version: CAPTURE_STREAM_ACCOUNTING_VERSION,
            source_bytes,
            groups,
            states,
            tag_states,
            projection,
            frontier_cells,
            frontier_bytes,
            program_bytes,
            tags,
            build_work,
            persistent_bytes,
            combined_peak_bytes: persistent_bytes,
            allocations,
            allocator_bytes,
        };
        if prospective.closes() {
            Ok(prospective)
        } else {
            Err(CaptureStreamError::InvalidProgram)
        }
    }

    /// Derive the complete restart-aware operation envelope without reading
    /// source bytes or allocating. The executor rejects empty winners, so the
    /// positive-width restarted proof applies to both stream projections.
    #[allow(
        clippy::too_many_lines,
        reason = "every published restart, tag, result, and work dimension is derived together before source access"
    )]
    pub fn operation_prospective(
        program: &Program,
        source_bytes: usize,
        domains: CaptureStreamDomains,
    ) -> Result<CaptureStreamOperationProspective, CaptureStreamError> {
        let construction = Self::prospective(program, source_bytes)?;
        let restarted = program
            .history_program_shape()
            .restarted_prospective_with_minimum(
                Window {
                    start: 0,
                    end: source_bytes,
                },
                1,
            )
            .map_err(|_| CaptureStreamError::Overflow(CaptureStreamResource::Work))?;
        let matches = restarted.results;
        let tag_actions = restarted.total_history_nodes;
        let (
            history_nodes,
            history_walk,
            history_reads,
            materialization_reads,
            materialization_writes,
            materialization_preview_writes,
        ) = match construction.projection {
            CaptureStreamProjection::ParticipationMask => (0, 0, 0, 0, 0, 0),
            CaptureStreamProjection::PersistentHistory => {
                let history_nodes = restarted.total_history_nodes;
                let history_walk =
                    history_nodes
                        .checked_mul(2)
                        .ok_or(CaptureStreamError::Overflow(
                            CaptureStreamResource::HistoryWalk,
                        ))?;
                let history_reads = history_nodes
                    .checked_add(history_walk)
                    .and_then(|value| value.checked_add(matches))
                    .ok_or(CaptureStreamError::Overflow(
                        CaptureStreamResource::HistoryReads,
                    ))?;
                (
                    history_nodes,
                    history_walk,
                    history_reads,
                    history_nodes,
                    history_nodes,
                    0,
                )
            }
        };
        let mask_word_reads_per_match = match construction.projection {
            CaptureStreamProjection::ParticipationMask => 3,
            CaptureStreamProjection::PersistentHistory => 0,
        };
        let mask_word_reads =
            matches
                .checked_mul(mask_word_reads_per_match)
                .ok_or(CaptureStreamError::Overflow(
                    CaptureStreamResource::MaskWordReads,
                ))?;
        let presence_words = construction
            .tags
            .slots
            .checked_add(63)
            .and_then(|value| value.checked_div(64))
            .ok_or(CaptureStreamError::Overflow(
                CaptureStreamResource::ResetCells,
            ))?;
        let reset_per_search = construction.tags.slots.checked_add(presence_words).ok_or(
            CaptureStreamError::Overflow(CaptureStreamResource::ResetCells),
        )?;
        let reset_cells = restarted
            .searches
            .checked_mul(reset_per_search)
            .and_then(|value| value.checked_add(history_nodes))
            .ok_or(CaptureStreamError::Overflow(
                CaptureStreamResource::ResetCells,
            ))?;
        let capture_events =
            construction
                .groups
                .checked_mul(matches)
                .ok_or(CaptureStreamError::Overflow(
                    CaptureStreamResource::CaptureEvents,
                ))?;
        let line_domains = match domains {
            CaptureStreamDomains::Whole => 1,
            CaptureStreamDomains::RebarLines => source_bytes,
        };
        let line_source_reads = match domains {
            CaptureStreamDomains::Whole => 0,
            CaptureStreamDomains::RebarLines => source_bytes,
        };
        let work = operation_work_sum(
            line_domains,
            restarted.searches,
            restarted.total_state_visits,
            tag_actions,
            history_nodes,
            history_walk,
            history_reads,
            materialization_reads,
            materialization_writes,
            materialization_preview_writes,
            0,
            0,
            mask_word_reads,
            reset_cells,
            capture_events,
            line_source_reads,
            restarted.bytes_examined,
            restarted.starts_injected,
        )
        .map_err(CaptureStreamError::Overflow)?;
        let operation = CaptureStreamOperationProspective {
            algorithm_version: CAPTURE_STREAM_ALGORITHM_VERSION,
            accounting_version: CAPTURE_STREAM_ACCOUNTING_VERSION,
            construction,
            domains,
            line_domains,
            searches: restarted.searches,
            matches,
            bytes_examined: restarted.bytes_examined,
            starts_injected: restarted.starts_injected,
            state_visits: restarted.total_state_visits,
            tag_actions,
            history_nodes,
            history_walk,
            history_reads,
            materialization_reads,
            materialization_writes,
            materialization_preview_writes,
            mask_states: 0,
            mask_word_copies: 0,
            mask_word_reads,
            reset_cells,
            capture_events,
            capture_count: capture_events,
            line_source_reads,
            work,
        };
        if operation.closes() {
            Ok(operation)
        } else {
            Err(CaptureStreamError::InvalidProgram)
        }
    }

    /// Allocate one exact reusable envelope after checking every limit.
    pub fn new(
        program: Arc<Program>,
        source_bytes: usize,
        domains: CaptureStreamDomains,
        limits: CaptureStreamLimits,
    ) -> Result<Self, CaptureStreamError> {
        let operation = Self::operation_prospective(&program, source_bytes, domains)?;
        let prospective = operation.construction;
        operation.admits(limits)?;
        let tags = TagWorkspace::new(
            prospective.groups,
            prospective.tags.history_nodes,
            0,
            TagWorkspaceLimits {
                max_groups: prospective.tags.groups,
                max_history_nodes: prospective.tags.history_nodes,
                max_mask_states: prospective.tags.mask_states,
                max_mask_words: prospective.tags.mask_words,
                max_build_work: prospective.tags.build_work,
                max_initialized_bytes: prospective.tags.initialized_bytes,
                max_copied_bytes: prospective.tags.copied_bytes,
                max_scratch_bytes: prospective.tags.scratch_bytes,
                max_persistent_bytes: prospective.tags.persistent_bytes,
                max_peak_bytes: prospective.tags.peak_bytes,
                max_allocator_bytes: prospective.tags.allocator_bytes,
                max_allocations: prospective.tags.allocations,
            },
        )?;
        let frontier = match prospective.projection {
            CaptureStreamProjection::ParticipationMask => {
                Frontier::Participation(ParticipationFrontier {
                    current: exact_vec(prospective.states)?,
                    next: exact_vec(prospective.states)?,
                    stack: exact_vec(prospective.states)?,
                })
            }
            CaptureStreamProjection::PersistentHistory => Frontier::History(HistoryFrontier {
                current: exact_vec(prospective.states)?,
                next: exact_vec(prospective.states)?,
                stack: exact_vec(prospective.states)?,
            }),
        };
        let mut seen = exact_vec(prospective.states)?;
        for _ in 0..prospective.states {
            exact_push(&mut seen, 0)?;
        }
        Ok(Self {
            program,
            domains,
            limits,
            prospective,
            operation,
            frontier,
            seen,
            tags,
            generation: 0,
        })
    }

    /// Construction envelope bound into this prepared stream.
    #[must_use]
    pub const fn build_report(&self) -> CaptureStreamProspective {
        self.prospective
    }

    /// Complete source-free envelope bound to this prepared stream.
    #[must_use]
    pub const fn operation_report(&self) -> CaptureStreamOperationProspective {
        self.operation
    }

    /// Execute one complete fused operation without allocating.
    #[allow(
        clippy::too_many_lines,
        reason = "domain iteration and the terminal receipt are one allocation-free operation transaction"
    )]
    pub fn execute(&mut self, haystack: &[u8]) -> Result<CaptureStreamReport, CaptureStreamError> {
        if haystack.len() != self.prospective.source_bytes {
            return Err(CaptureStreamError::SourceLength {
                expected: self.prospective.source_bytes,
                actual: haystack.len(),
            });
        }
        let mut accounting = CaptureStreamAccounting::default();
        let mut count = 0_usize;
        let mut matches = 0_usize;
        let mut first_match = None;
        let mut last_match = None;
        match self.domains {
            CaptureStreamDomains::Whole => {
                self.execute_domain(
                    haystack,
                    Window::all(haystack),
                    false,
                    &mut accounting,
                    &mut count,
                    &mut matches,
                    &mut first_match,
                    &mut last_match,
                )?;
            }
            CaptureStreamDomains::RebarLines => {
                let mut start = 0_usize;
                let mut index = 0_usize;
                let mut previous_was_cr = false;
                while index < haystack.len() {
                    charge_accounted(
                        &mut accounting.line_source_reads,
                        &mut accounting.work,
                        1,
                        CaptureStreamResource::LineSourceReads,
                        self.limits.max_line_source_reads,
                        self.limits.max_work,
                    )?;
                    let byte = haystack[index];
                    if byte == b'\n' {
                        let content_end = if index > start && previous_was_cr {
                            index
                                .checked_sub(1)
                                .ok_or(CaptureStreamError::InvalidProgram)?
                        } else {
                            index
                        };
                        self.execute_domain(
                            haystack,
                            Window {
                                start,
                                end: content_end,
                            },
                            true,
                            &mut accounting,
                            &mut count,
                            &mut matches,
                            &mut first_match,
                            &mut last_match,
                        )?;
                        start = index.checked_add(1).ok_or(CaptureStreamError::Overflow(
                            CaptureStreamResource::LineDomains,
                        ))?;
                        previous_was_cr = false;
                    } else {
                        previous_was_cr = byte == b'\r';
                    }
                    index = index.checked_add(1).ok_or(CaptureStreamError::Overflow(
                        CaptureStreamResource::LineSourceReads,
                    ))?;
                }
                if start < haystack.len() {
                    self.execute_domain(
                        haystack,
                        Window {
                            start,
                            end: haystack.len(),
                        },
                        true,
                        &mut accounting,
                        &mut count,
                        &mut matches,
                        &mut first_match,
                        &mut last_match,
                    )?;
                }
            }
        }
        let expected_work = accounting
            .line_domains
            .checked_add(accounting.searches)
            .and_then(|value| value.checked_add(accounting.state_visits))
            .and_then(|value| value.checked_add(accounting.tag_actions))
            .and_then(|value| value.checked_add(accounting.history_nodes))
            .and_then(|value| value.checked_add(accounting.history_walk))
            .and_then(|value| value.checked_add(accounting.history_reads))
            .and_then(|value| value.checked_add(accounting.materialization_reads))
            .and_then(|value| value.checked_add(accounting.materialization_writes))
            .and_then(|value| value.checked_add(accounting.materialization_preview_writes))
            .and_then(|value| value.checked_add(accounting.mask_states))
            .and_then(|value| value.checked_add(accounting.mask_word_copies))
            .and_then(|value| value.checked_add(accounting.mask_word_reads))
            .and_then(|value| value.checked_add(accounting.reset_cells))
            .and_then(|value| value.checked_add(accounting.capture_events))
            .and_then(|value| value.checked_add(accounting.line_source_reads))
            .and_then(|value| value.checked_add(accounting.bytes_examined))
            .and_then(|value| value.checked_add(accounting.starts_injected))
            .ok_or(CaptureStreamError::Overflow(CaptureStreamResource::Work))?;
        if expected_work != accounting.work {
            return Err(CaptureStreamError::InvalidProgram);
        }
        let captures = CaptureCountOutcome {
            count,
            matches,
            searches: accounting.searches,
            total_state_visits: accounting.state_visits,
            total_history_nodes: accounting.history_nodes,
            total_history_walk: accounting.history_walk,
            peak_threads: accounting.peak_threads,
        };
        let report = CaptureStreamReport {
            algorithm_version: CAPTURE_STREAM_ALGORITHM_VERSION,
            accounting_version: CAPTURE_STREAM_ACCOUNTING_VERSION,
            domains: self.domains,
            limits: self.limits,
            prospective: self.prospective,
            operation: self.operation,
            accounting,
            captures,
            first_match,
            last_match,
            capture_events: accounting.capture_events,
            combined_peak_bytes: self.prospective.combined_peak_bytes,
        };
        if report.closes(self.limits) {
            Ok(report)
        } else {
            Err(CaptureStreamError::InvalidProgram)
        }
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "one domain carries explicit counters and boundaries into a single receipt-bearing transaction"
    )]
    fn execute_domain(
        &mut self,
        haystack: &[u8],
        window: Window,
        clipped_assertions: bool,
        accounting: &mut CaptureStreamAccounting,
        count: &mut usize,
        matches: &mut usize,
        first_match: &mut Option<Span>,
        last_match: &mut Option<Span>,
    ) -> Result<(), CaptureStreamError> {
        charge_accounted(
            &mut accounting.line_domains,
            &mut accounting.work,
            1,
            CaptureStreamResource::LineDomains,
            self.limits.max_line_domains,
            self.limits.max_work,
        )?;
        let mut cursor = window.start;
        loop {
            charge_accounted(
                &mut accounting.searches,
                &mut accounting.work,
                1,
                CaptureStreamResource::Searches,
                self.limits.max_searches,
                self.limits.max_work,
            )?;
            let winner = match &mut self.frontier {
                Frontier::Participation(frontier) => search_participation(
                    &self.program,
                    frontier,
                    &mut self.seen,
                    &mut self.generation,
                    &mut self.tags,
                    haystack,
                    window,
                    cursor,
                    clipped_assertions,
                    self.limits,
                    accounting,
                )?
                .map(StreamWinner::Participation),
                Frontier::History(frontier) => search_history(
                    &self.program,
                    frontier,
                    &mut self.seen,
                    &mut self.generation,
                    &mut self.tags,
                    haystack,
                    window,
                    cursor,
                    clipped_assertions,
                    self.limits,
                    accounting,
                )?
                .map(StreamWinner::History),
            };
            let Some(winner) = winner else {
                accumulate_tag_accounting(&self.tags.accounting(), accounting, self.limits)?;
                break;
            };
            let overall = match winner {
                StreamWinner::Participation(winner) => winner.overall,
                StreamWinner::History(winner) => winner.overall,
            };
            if overall.start < cursor || overall.end > window.end || overall.start == overall.end {
                return Err(CaptureStreamError::EmptyMatch);
            }
            charge(
                matches,
                1,
                CaptureStreamResource::Matches,
                self.limits.max_matches,
            )?;
            let participating = match winner {
                StreamWinner::Participation(winner) => {
                    tighten_tag_work_limit(&mut self.tags, self.limits, accounting)?;
                    let mut mask = self.tags.participation_mask(winner.tags)?;
                    if !mask.accepts_complete_match()? {
                        return Err(CaptureStreamError::InvalidProgram);
                    }
                    mask.user_capture_count()?.checked_add(1).ok_or(
                        CaptureStreamError::Overflow(CaptureStreamResource::CaptureCount),
                    )?
                }
                StreamWinner::History(winner) => {
                    tighten_tag_work_limit(&mut self.tags, self.limits, accounting)?;
                    let mut mask = self
                        .tags
                        .materialize_history_participation(winner.history)?;
                    if !mask.accepts_complete_match()? {
                        return Err(CaptureStreamError::InvalidProgram);
                    }
                    mask.user_capture_count()?.checked_add(1).ok_or(
                        CaptureStreamError::Overflow(CaptureStreamResource::CaptureCount),
                    )?
                }
            };
            charge(
                count,
                participating,
                CaptureStreamResource::CaptureCount,
                self.limits.max_capture_count,
            )?;
            charge_accounted(
                &mut accounting.capture_events,
                &mut accounting.work,
                self.prospective.groups,
                CaptureStreamResource::CaptureEvents,
                self.limits.max_capture_events,
                self.limits.max_work,
            )?;
            accumulate_tag_accounting(&self.tags.accounting(), accounting, self.limits)?;
            if first_match.is_none() {
                *first_match = Some(overall);
            }
            *last_match = Some(overall);
            cursor = overall.end;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
enum StreamWinner {
    Participation(ParticipationWinner),
    History(HistoryWinner),
}

#[derive(Clone, Copy, Debug)]
struct ParticipationWinner {
    tags: ParticipationState,
    overall: Span,
}

#[derive(Clone, Copy, Debug)]
struct HistoryWinner {
    history: HistoryId,
    overall: Span,
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the reusable frontier keeps source, assertion context, limits, and accounting explicit"
)]
fn search_participation(
    program: &Program,
    frontier: &mut ParticipationFrontier,
    seen: &mut ExactVec<usize>,
    generation: &mut usize,
    tags: &mut TagWorkspace,
    haystack: &[u8],
    window: Window,
    from: usize,
    clipped_assertions: bool,
    limits: CaptureStreamLimits,
    accounting: &mut CaptureStreamAccounting,
) -> Result<Option<ParticipationWinner>, CaptureStreamError> {
    if from < window.start || from > window.end || window.end > haystack.len() {
        return Err(CaptureStreamError::InvalidProgram);
    }
    frontier.current.clear();
    frontier.next.clear();
    frontier.stack.clear();
    let tag_limits = tag_run_limits(tags.build_report(), limits, accounting)?;
    tags.begin_run(tag_limits)?;
    let root = tags.participation_root()?;
    let mut winner = None;
    let mut pos = from;
    next_generation(generation)?;
    loop {
        if winner.is_none() {
            charge_accounted(
                &mut accounting.starts_injected,
                &mut accounting.work,
                1,
                CaptureStreamResource::StartsInjected,
                limits.max_starts_injected,
                limits.max_work,
            )?;
            add_participation_thread(
                program,
                &mut frontier.current,
                &mut frontier.stack,
                seen,
                *generation,
                ParticipationThread {
                    pc: program.start,
                    tags: root,
                    overall_start: None,
                    overall_end: None,
                },
                pos,
                haystack,
                window,
                clipped_assertions,
                tags,
                limits,
                accounting,
            )?;
        }
        let accepting = frontier
            .current
            .as_slice()
            .iter()
            .position(|thread| matches!(program.states.get(thread.pc), Some(State::Match)));
        let active = if let Some(index) = accepting {
            let thread = frontier.current[index];
            winner = Some(ParticipationWinner {
                tags: thread.tags,
                overall: Span {
                    start: thread
                        .overall_start
                        .ok_or(CaptureStreamError::InvalidProgram)?,
                    end: thread
                        .overall_end
                        .ok_or(CaptureStreamError::InvalidProgram)?,
                },
            });
            index
        } else {
            frontier.current.len()
        };
        accounting.peak_threads = accounting.peak_threads.max(active);
        if winner.is_some() && active == 0 {
            break;
        }
        if pos == window.end {
            break;
        }
        frontier.next.clear();
        next_generation(generation)?;
        let next_pos = pos.checked_add(1).ok_or(CaptureStreamError::Overflow(
            CaptureStreamResource::StateVisits,
        ))?;
        let byte = *haystack
            .get(pos)
            .ok_or(CaptureStreamError::InvalidProgram)?;
        for thread in frontier.current.as_slice().iter().take(active).copied() {
            let State::Byte {
                ranges,
                next: target,
            } = program
                .states
                .get(thread.pc)
                .ok_or(CaptureStreamError::InvalidProgram)?
            else {
                return Err(CaptureStreamError::InvalidProgram);
            };
            if ranges
                .iter()
                .any(|&(start, end)| start <= byte && byte <= end)
            {
                add_participation_thread(
                    program,
                    &mut frontier.next,
                    &mut frontier.stack,
                    seen,
                    *generation,
                    ParticipationThread {
                        pc: *target,
                        tags: thread.tags,
                        overall_start: thread.overall_start,
                        overall_end: thread.overall_end,
                    },
                    next_pos,
                    haystack,
                    window,
                    clipped_assertions,
                    tags,
                    limits,
                    accounting,
                )?;
            }
        }
        charge_accounted(
            &mut accounting.bytes_examined,
            &mut accounting.work,
            1,
            CaptureStreamResource::BytesExamined,
            limits.max_bytes_examined,
            limits.max_work,
        )?;
        core::mem::swap(&mut frontier.current, &mut frontier.next);
        pos = next_pos;
    }
    Ok(winner)
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the reusable frontier keeps source, assertion context, limits, and accounting explicit"
)]
fn search_history(
    program: &Program,
    frontier: &mut HistoryFrontier,
    seen: &mut ExactVec<usize>,
    generation: &mut usize,
    tags: &mut TagWorkspace,
    haystack: &[u8],
    window: Window,
    from: usize,
    clipped_assertions: bool,
    limits: CaptureStreamLimits,
    accounting: &mut CaptureStreamAccounting,
) -> Result<Option<HistoryWinner>, CaptureStreamError> {
    if from < window.start || from > window.end || window.end > haystack.len() {
        return Err(CaptureStreamError::InvalidProgram);
    }
    frontier.current.clear();
    frontier.next.clear();
    frontier.stack.clear();
    let tag_limits = tag_run_limits(tags.build_report(), limits, accounting)?;
    tags.begin_run(tag_limits)?;
    let mut winner = None;
    let mut pos = from;
    next_generation(generation)?;
    loop {
        if winner.is_none() {
            charge_accounted(
                &mut accounting.starts_injected,
                &mut accounting.work,
                1,
                CaptureStreamResource::StartsInjected,
                limits.max_starts_injected,
                limits.max_work,
            )?;
            add_history_thread(
                program,
                &mut frontier.current,
                &mut frontier.stack,
                seen,
                *generation,
                HistoryThread {
                    pc: program.start,
                    history: None,
                    overall_start: None,
                    overall_end: None,
                },
                pos,
                haystack,
                window,
                clipped_assertions,
                tags,
                limits,
                accounting,
            )?;
        }
        let accepting = frontier
            .current
            .as_slice()
            .iter()
            .position(|thread| matches!(program.states.get(thread.pc), Some(State::Match)));
        let active = if let Some(index) = accepting {
            let thread = frontier.current[index];
            winner = Some(HistoryWinner {
                history: thread.history.ok_or(CaptureStreamError::InvalidProgram)?,
                overall: Span {
                    start: thread
                        .overall_start
                        .ok_or(CaptureStreamError::InvalidProgram)?,
                    end: thread
                        .overall_end
                        .ok_or(CaptureStreamError::InvalidProgram)?,
                },
            });
            index
        } else {
            frontier.current.len()
        };
        accounting.peak_threads = accounting.peak_threads.max(active);
        if winner.is_some() && active == 0 {
            break;
        }
        if pos == window.end {
            break;
        }
        frontier.next.clear();
        next_generation(generation)?;
        let next_pos = pos.checked_add(1).ok_or(CaptureStreamError::Overflow(
            CaptureStreamResource::StateVisits,
        ))?;
        let byte = *haystack
            .get(pos)
            .ok_or(CaptureStreamError::InvalidProgram)?;
        for thread in frontier.current.as_slice().iter().take(active).copied() {
            let State::Byte {
                ranges,
                next: target,
            } = program
                .states
                .get(thread.pc)
                .ok_or(CaptureStreamError::InvalidProgram)?
            else {
                return Err(CaptureStreamError::InvalidProgram);
            };
            if ranges
                .iter()
                .any(|&(start, end)| start <= byte && byte <= end)
            {
                add_history_thread(
                    program,
                    &mut frontier.next,
                    &mut frontier.stack,
                    seen,
                    *generation,
                    HistoryThread {
                        pc: *target,
                        history: thread.history,
                        overall_start: thread.overall_start,
                        overall_end: thread.overall_end,
                    },
                    next_pos,
                    haystack,
                    window,
                    clipped_assertions,
                    tags,
                    limits,
                    accounting,
                )?;
            }
        }
        charge_accounted(
            &mut accounting.bytes_examined,
            &mut accounting.work,
            1,
            CaptureStreamResource::BytesExamined,
            limits.max_bytes_examined,
            limits.max_work,
        )?;
        core::mem::swap(&mut frontier.current, &mut frontier.next);
        pos = next_pos;
    }
    Ok(winner)
}

#[allow(
    clippy::too_many_arguments,
    reason = "ordered closure resources and semantic context are explicit"
)]
fn add_participation_thread(
    program: &Program,
    output: &mut ExactVec<ParticipationThread>,
    stack: &mut ExactVec<ParticipationThread>,
    seen: &mut ExactVec<usize>,
    generation: usize,
    initial: ParticipationThread,
    pos: usize,
    haystack: &[u8],
    window: Window,
    clipped_assertions: bool,
    tags: &mut TagWorkspace,
    limits: CaptureStreamLimits,
    accounting: &mut CaptureStreamAccounting,
) -> Result<(), CaptureStreamError> {
    stack.clear();
    exact_push(stack, initial)?;
    while let Some(mut thread) = stack.pop() {
        charge_accounted(
            &mut accounting.state_visits,
            &mut accounting.work,
            1,
            CaptureStreamResource::StateVisits,
            limits.max_state_visits,
            limits.max_work,
        )?;
        let mark = seen
            .as_mut_slice()
            .get_mut(thread.pc)
            .ok_or(CaptureStreamError::InvalidProgram)?;
        if *mark == generation {
            continue;
        }
        *mark = generation;
        match program
            .states
            .get(thread.pc)
            .ok_or(CaptureStreamError::InvalidProgram)?
        {
            State::Byte { .. } | State::Match => exact_push(output, thread)?,
            State::Fail => {}
            State::Epsilon { next } => {
                thread.pc = *next;
                exact_push(stack, thread)?;
            }
            State::Assert { assertion, next } => {
                if boundary_matches(haystack, window, pos, clipped_assertions, *assertion)? {
                    thread.pc = *next;
                    exact_push(stack, thread)?;
                }
            }
            State::Save { slot, next } => {
                let action = action_from_slot(*slot)?;
                if *slot == 0 {
                    thread.overall_start = Some(pos);
                } else if *slot == 1 {
                    thread.overall_end = Some(pos);
                }
                tighten_tag_work_limit(tags, limits, accounting)?;
                thread.tags = tags.apply_participation(thread.tags, action)?;
                thread.pc = *next;
                exact_push(stack, thread)?;
            }
            State::Split { first, second } => {
                exact_push(
                    stack,
                    ParticipationThread {
                        pc: *second,
                        tags: thread.tags,
                        overall_start: thread.overall_start,
                        overall_end: thread.overall_end,
                    },
                )?;
                thread.pc = *first;
                exact_push(stack, thread)?;
            }
        }
    }
    accounting.peak_threads = accounting.peak_threads.max(output.len());
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "ordered closure resources and semantic context are explicit"
)]
fn add_history_thread(
    program: &Program,
    output: &mut ExactVec<HistoryThread>,
    stack: &mut ExactVec<HistoryThread>,
    seen: &mut ExactVec<usize>,
    generation: usize,
    initial: HistoryThread,
    pos: usize,
    haystack: &[u8],
    window: Window,
    clipped_assertions: bool,
    tags: &mut TagWorkspace,
    limits: CaptureStreamLimits,
    accounting: &mut CaptureStreamAccounting,
) -> Result<(), CaptureStreamError> {
    stack.clear();
    exact_push(stack, initial)?;
    while let Some(mut thread) = stack.pop() {
        charge_accounted(
            &mut accounting.state_visits,
            &mut accounting.work,
            1,
            CaptureStreamResource::StateVisits,
            limits.max_state_visits,
            limits.max_work,
        )?;
        let mark = seen
            .as_mut_slice()
            .get_mut(thread.pc)
            .ok_or(CaptureStreamError::InvalidProgram)?;
        if *mark == generation {
            continue;
        }
        *mark = generation;
        match program
            .states
            .get(thread.pc)
            .ok_or(CaptureStreamError::InvalidProgram)?
        {
            State::Byte { .. } | State::Match => exact_push(output, thread)?,
            State::Fail => {}
            State::Epsilon { next } => {
                thread.pc = *next;
                exact_push(stack, thread)?;
            }
            State::Assert { assertion, next } => {
                if boundary_matches(haystack, window, pos, clipped_assertions, *assertion)? {
                    thread.pc = *next;
                    exact_push(stack, thread)?;
                }
            }
            State::Save { slot, next } => {
                if *slot == 0 {
                    thread.overall_start = Some(pos);
                } else if *slot == 1 {
                    thread.overall_end = Some(pos);
                }
                tighten_tag_work_limit(tags, limits, accounting)?;
                thread.history =
                    Some(tags.record_history(thread.history, action_from_slot(*slot)?, pos)?);
                thread.pc = *next;
                exact_push(stack, thread)?;
            }
            State::Split { first, second } => {
                exact_push(
                    stack,
                    HistoryThread {
                        pc: *second,
                        history: thread.history,
                        overall_start: thread.overall_start,
                        overall_end: thread.overall_end,
                    },
                )?;
                thread.pc = *first;
                exact_push(stack, thread)?;
            }
        }
    }
    accounting.peak_threads = accounting.peak_threads.max(output.len());
    Ok(())
}

fn boundary_matches(
    haystack: &[u8],
    window: Window,
    position: usize,
    clipped: bool,
    assertion: crate::Assertion,
) -> Result<bool, CaptureStreamError> {
    let boundary = if clipped {
        SemanticBoundary::new_clipped(haystack, window, position)
    } else {
        SemanticBoundary::new(haystack, window, position)
    }
    .map_err(|_| CaptureStreamError::InvalidProgram)?;
    boundary
        .matches(assertion)
        .map_err(|_| CaptureStreamError::InvalidProgram)
}

fn action_from_slot(slot: usize) -> Result<TagAction, CaptureStreamError> {
    let group = u32::try_from(slot / 2).map_err(|_| CaptureStreamError::InvalidProgram)?;
    if slot.is_multiple_of(2) {
        TagAction::start(group).map_err(Into::into)
    } else {
        TagAction::end(group).map_err(Into::into)
    }
}

fn tag_run_limits(
    prospective: TagWorkspaceProspective,
    limits: CaptureStreamLimits,
    accounting: &CaptureStreamAccounting,
) -> Result<TagRunLimits, CaptureStreamError> {
    let history_nodes = limits
        .max_history_nodes
        .checked_sub(accounting.history_nodes)
        .ok_or(CaptureStreamError::InvalidProgram)?;
    let history_walk = limits
        .max_history_walk
        .checked_sub(accounting.history_walk)
        .ok_or(CaptureStreamError::InvalidProgram)?;
    let history_reads = limits
        .max_history_reads
        .checked_sub(accounting.history_reads)
        .ok_or(CaptureStreamError::InvalidProgram)?;
    let mask_word_reads = limits
        .max_mask_word_reads
        .checked_sub(accounting.mask_word_reads)
        .ok_or(CaptureStreamError::InvalidProgram)?;
    let tag_actions = limits
        .max_tag_actions
        .checked_sub(accounting.tag_actions)
        .ok_or(CaptureStreamError::InvalidProgram)?;
    Ok(TagRunLimits {
        max_history_nodes: history_nodes.min(prospective.history_nodes),
        max_history_walk: history_walk,
        max_history_reads: history_reads,
        max_materialization_reads: limits
            .max_materialization_reads
            .checked_sub(accounting.materialization_reads)
            .ok_or(CaptureStreamError::InvalidProgram)?,
        max_materialization_writes: limits
            .max_materialization_writes
            .checked_sub(accounting.materialization_writes)
            .ok_or(CaptureStreamError::InvalidProgram)?,
        max_materialization_preview_writes: limits
            .max_materialization_preview_writes
            .checked_sub(accounting.materialization_preview_writes)
            .ok_or(CaptureStreamError::InvalidProgram)?,
        max_mask_states: 0,
        max_mask_word_copies: 0,
        max_mask_word_reads: mask_word_reads,
        max_tag_actions: tag_actions,
        max_reset_cells: prospective
            .slots
            .checked_add(
                prospective
                    .slots
                    .checked_add(63)
                    .and_then(|value| value.checked_div(64))
                    .ok_or(CaptureStreamError::Overflow(CaptureStreamResource::Work))?,
            )
            .and_then(|value| value.checked_add(prospective.history_nodes))
            .ok_or(CaptureStreamError::Overflow(CaptureStreamResource::Work))?
            .min(
                limits
                    .max_reset_cells
                    .checked_sub(accounting.reset_cells)
                    .ok_or(CaptureStreamError::InvalidProgram)?,
            ),
        max_work: limits
            .max_work
            .checked_sub(accounting.work)
            .ok_or(CaptureStreamError::InvalidProgram)?,
    })
}

fn tighten_tag_work_limit(
    tags: &mut TagWorkspace,
    limits: CaptureStreamLimits,
    accounting: &CaptureStreamAccounting,
) -> Result<(), CaptureStreamError> {
    let remaining = limits
        .max_work
        .checked_sub(accounting.work)
        .ok_or(CaptureStreamError::InvalidProgram)?;
    tags.tighten_max_work(remaining)?;
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "every tagged-workspace counter is copied and limit-checked explicitly at one audit boundary"
)]
fn accumulate_tag_accounting(
    run: &TagRunAccounting,
    accounting: &mut CaptureStreamAccounting,
    limits: CaptureStreamLimits,
) -> Result<(), CaptureStreamError> {
    // A run's tag counters are copied exactly once. `search_participation`
    // accounts its terminal run before returning; persistent history is
    // accounted after winner materialization so the walk is included.
    if run.allocations != 0 {
        return Err(CaptureStreamError::InvalidProgram);
    }
    let tag_actions =
        accounting
            .tag_actions
            .checked_add(run.tag_actions)
            .ok_or(CaptureStreamError::Overflow(
                CaptureStreamResource::TagActions,
            ))?;
    let history_nodes = accounting
        .history_nodes
        .checked_add(run.history_nodes)
        .ok_or(CaptureStreamError::Overflow(
            CaptureStreamResource::HistoryNodes,
        ))?;
    let history_walk = accounting
        .history_walk
        .checked_add(run.history_walk)
        .ok_or(CaptureStreamError::Overflow(
            CaptureStreamResource::HistoryWalk,
        ))?;
    let history_reads = accounting
        .history_reads
        .checked_add(run.history_reads)
        .ok_or(CaptureStreamError::Overflow(
            CaptureStreamResource::HistoryReads,
        ))?;
    let materialization_reads = accounting
        .materialization_reads
        .checked_add(run.materialization_reads)
        .ok_or(CaptureStreamError::Overflow(
            CaptureStreamResource::MaterializationReads,
        ))?;
    let materialization_writes = accounting
        .materialization_writes
        .checked_add(run.materialization_writes)
        .ok_or(CaptureStreamError::Overflow(
            CaptureStreamResource::MaterializationWrites,
        ))?;
    let materialization_preview_writes = accounting
        .materialization_preview_writes
        .checked_add(run.materialization_preview_writes)
        .ok_or(CaptureStreamError::Overflow(
            CaptureStreamResource::MaterializationPreviewWrites,
        ))?;
    let mask_states =
        accounting
            .mask_states
            .checked_add(run.mask_states)
            .ok_or(CaptureStreamError::Overflow(
                CaptureStreamResource::MaskStates,
            ))?;
    let mask_word_copies = accounting
        .mask_word_copies
        .checked_add(run.mask_word_copies)
        .ok_or(CaptureStreamError::Overflow(
            CaptureStreamResource::MaskWordCopies,
        ))?;
    let mask_word_reads = accounting
        .mask_word_reads
        .checked_add(run.mask_word_reads)
        .ok_or(CaptureStreamError::Overflow(
            CaptureStreamResource::MaskWordReads,
        ))?;
    let reset_cells =
        accounting
            .reset_cells
            .checked_add(run.reset_cells)
            .ok_or(CaptureStreamError::Overflow(
                CaptureStreamResource::ResetCells,
            ))?;
    check(
        CaptureStreamResource::TagActions,
        tag_actions,
        limits.max_tag_actions,
    )?;
    check(
        CaptureStreamResource::HistoryNodes,
        history_nodes,
        limits.max_history_nodes,
    )?;
    check(
        CaptureStreamResource::HistoryWalk,
        history_walk,
        limits.max_history_walk,
    )?;
    check(
        CaptureStreamResource::HistoryReads,
        history_reads,
        limits.max_history_reads,
    )?;
    check(
        CaptureStreamResource::MaterializationReads,
        materialization_reads,
        limits.max_materialization_reads,
    )?;
    check(
        CaptureStreamResource::MaterializationWrites,
        materialization_writes,
        limits.max_materialization_writes,
    )?;
    check(
        CaptureStreamResource::MaterializationPreviewWrites,
        materialization_preview_writes,
        limits.max_materialization_preview_writes,
    )?;
    check(
        CaptureStreamResource::MaskStates,
        mask_states,
        limits.max_mask_states,
    )?;
    check(
        CaptureStreamResource::MaskWordCopies,
        mask_word_copies,
        limits.max_mask_word_copies,
    )?;
    check(
        CaptureStreamResource::MaskWordReads,
        mask_word_reads,
        limits.max_mask_word_reads,
    )?;
    check(
        CaptureStreamResource::ResetCells,
        reset_cells,
        limits.max_reset_cells,
    )?;
    let delta_work = run
        .tag_actions
        .checked_add(run.history_nodes)
        .and_then(|value| value.checked_add(run.history_walk))
        .and_then(|value| value.checked_add(run.history_reads))
        .and_then(|value| value.checked_add(run.materialization_reads))
        .and_then(|value| value.checked_add(run.materialization_writes))
        .and_then(|value| value.checked_add(run.materialization_preview_writes))
        .and_then(|value| value.checked_add(run.mask_states))
        .and_then(|value| value.checked_add(run.mask_word_copies))
        .and_then(|value| value.checked_add(run.mask_word_reads))
        .and_then(|value| value.checked_add(run.reset_cells))
        .ok_or(CaptureStreamError::Overflow(CaptureStreamResource::Work))?;
    if delta_work != run.work {
        return Err(CaptureStreamError::InvalidProgram);
    }
    let work = accounting
        .work
        .checked_add(delta_work)
        .ok_or(CaptureStreamError::Overflow(CaptureStreamResource::Work))?;
    check(CaptureStreamResource::Work, work, limits.max_work)?;
    accounting.tag_actions = tag_actions;
    accounting.history_nodes = history_nodes;
    accounting.history_walk = history_walk;
    accounting.history_reads = history_reads;
    accounting.materialization_reads = materialization_reads;
    accounting.materialization_writes = materialization_writes;
    accounting.materialization_preview_writes = materialization_preview_writes;
    accounting.mask_states = mask_states;
    accounting.mask_word_copies = mask_word_copies;
    accounting.mask_word_reads = mask_word_reads;
    accounting.reset_cells = reset_cells;
    accounting.work = work;
    Ok(())
}

fn next_generation(generation: &mut usize) -> Result<(), CaptureStreamError> {
    if *generation == usize::MAX {
        return Err(CaptureStreamError::Overflow(
            CaptureStreamResource::Generation,
        ));
    }
    *generation = generation
        .checked_add(1)
        .ok_or(CaptureStreamError::Overflow(
            CaptureStreamResource::Generation,
        ))?;
    Ok(())
}

fn exact_vec<T>(capacity: usize) -> Result<ExactVec<T>, CaptureStreamError> {
    ExactVec::try_with_capacity(capacity).map_err(|error| match error {
        CopyError::LayoutOverflow => {
            CaptureStreamError::Overflow(CaptureStreamResource::PersistentBytes)
        }
        CopyError::AllocationFailed => {
            CaptureStreamError::Allocation(CaptureStreamResource::PersistentBytes)
        }
    })
}

fn exact_push<T>(storage: &mut ExactVec<T>, value: T) -> Result<(), CaptureStreamError> {
    storage
        .try_push(value)
        .map_err(|_| CaptureStreamError::Resource {
            resource: CaptureStreamResource::States,
            required: storage.len().saturating_add(1),
            limit: storage.capacity(),
        })
}

fn check(
    resource: CaptureStreamResource,
    required: usize,
    limit: usize,
) -> Result<(), CaptureStreamError> {
    if required > limit {
        Err(CaptureStreamError::Resource {
            resource,
            required,
            limit,
        })
    } else {
        Ok(())
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the public work receipt intentionally lists every independently metered dimension"
)]
fn operation_work_sum(
    line_domains: usize,
    searches: usize,
    state_visits: usize,
    tag_actions: usize,
    history_nodes: usize,
    history_walk: usize,
    history_reads: usize,
    materialization_reads: usize,
    materialization_writes: usize,
    materialization_preview_writes: usize,
    mask_states: usize,
    mask_word_copies: usize,
    mask_word_reads: usize,
    reset_cells: usize,
    capture_events: usize,
    line_source_reads: usize,
    bytes_examined: usize,
    starts_injected: usize,
) -> Result<usize, CaptureStreamResource> {
    line_domains
        .checked_add(searches)
        .and_then(|value| value.checked_add(state_visits))
        .and_then(|value| value.checked_add(tag_actions))
        .and_then(|value| value.checked_add(history_nodes))
        .and_then(|value| value.checked_add(history_walk))
        .and_then(|value| value.checked_add(history_reads))
        .and_then(|value| value.checked_add(materialization_reads))
        .and_then(|value| value.checked_add(materialization_writes))
        .and_then(|value| value.checked_add(materialization_preview_writes))
        .and_then(|value| value.checked_add(mask_states))
        .and_then(|value| value.checked_add(mask_word_copies))
        .and_then(|value| value.checked_add(mask_word_reads))
        .and_then(|value| value.checked_add(reset_cells))
        .and_then(|value| value.checked_add(capture_events))
        .and_then(|value| value.checked_add(line_source_reads))
        .and_then(|value| value.checked_add(bytes_examined))
        .and_then(|value| value.checked_add(starts_injected))
        .ok_or(CaptureStreamResource::Work)
}

fn charge(
    current: &mut usize,
    amount: usize,
    resource: CaptureStreamResource,
    limit: usize,
) -> Result<(), CaptureStreamError> {
    let required = current
        .checked_add(amount)
        .ok_or(CaptureStreamError::Overflow(resource))?;
    check(resource, required, limit)?;
    *current = required;
    Ok(())
}

fn charge_accounted(
    current: &mut usize,
    work: &mut usize,
    amount: usize,
    resource: CaptureStreamResource,
    limit: usize,
    work_limit: usize,
) -> Result<(), CaptureStreamError> {
    let required = current
        .checked_add(amount)
        .ok_or(CaptureStreamError::Overflow(resource))?;
    let required_work = work
        .checked_add(amount)
        .ok_or(CaptureStreamError::Overflow(CaptureStreamResource::Work))?;
    check(resource, required, limit)?;
    check(CaptureStreamResource::Work, required_work, work_limit)?;
    *current = required;
    *work = required_work;
    Ok(())
}
