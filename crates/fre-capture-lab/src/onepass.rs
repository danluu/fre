//! Construction-complete one-pass DFA for exact-span capture replay.
//!
//! The plan is derived only from an immutable tagged Thompson program. It is
//! either published complete or refused: execution never grows a transition
//! cache and never inspects source bytes to choose this route. A successful
//! plan has at most one consuming continuation for every DFA state and byte
//! class. Capture tags on loops are ordinary direct slot overwrites, not
//! persistent history events.

use core::{fmt, mem::size_of};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use fre_exact_alloc::{CopyError, ExactVec};

use crate::ast::Assertion;
use crate::compile::{Program, State};
use crate::error::{ResourceKind, SearchError};
use crate::limits::SearchLimits;
use crate::model::{
    CandidateKind, CaptureGroupSlot, ExactCaptureSlotsOutcome, HistoryProgramShape, RunReport,
    SearchOutcome, Span, Window,
};
use crate::runtime::{
    assertion_matches, canonicalize_unset, check, checked_add, commit_capture_group_slots,
    validate_window,
};

const DEAD: u32 = u32::MAX;
const MATCH_WINS: u32 = 1 << 31;
const TARGET_ROW_MASK: u32 = !MATCH_WINS;
const UNSET_SLOT: usize = usize::MAX;
const BYTE_DOMAIN: usize = 256;
const DIRECT_TAG_SLOT_LIMIT: usize = 32;
const INLINE_CAPTURE_SLOTS: usize = 32;
/// Semantic version of the construction-complete one-pass exact replay.
pub const ONEPASS_CAPTURE_ALGORITHM_VERSION: u32 = 3;
/// Version of one-pass construction and execution resource accounting.
pub const ONEPASS_CAPTURE_ACCOUNTING_VERSION: u32 = 4;
static NEXT_PLAN_IDENTITY: AtomicU64 = AtomicU64::new(1);

fn next_plan_identity() -> u64 {
    NEXT_PLAN_IDENTITY
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |identity| {
            identity.checked_add(1)
        })
        .unwrap_or_else(|_| panic!("one-pass capture plan identity space exhausted"))
}

/// Independently limited one-pass construction resource.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OnePassCaptureBuildResource {
    /// Reachable deterministic states.
    States,
    /// Source-independent construction work.
    CompileWork,
    /// Logical immutable bytes owned by the completed sidecar.
    ImmutableBytes,
}

/// A semantic reason why a valid Thompson program is not one-pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OnePassCaptureRefusal {
    /// More than one epsilon path reaches the same program state. The paths
    /// can differ at run time when one contains a conditional assertion, so
    /// silently retaining only the first path would not be sound.
    MultipleEpsilonPaths,
    /// Two consuming paths for one byte require different continuations or
    /// capture/assertion actions.
    ConflictingTransition,
    /// More than one epsilon path reaches a match terminal in one state.
    MultipleMatchPaths,
}

/// Typed construction failure for an optional one-pass capture sidecar.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OnePassCaptureBuildError {
    /// A configured construction ceiling would be exceeded.
    Resource {
        /// Limited dimension.
        resource: OnePassCaptureBuildResource,
        /// Required amount.
        required: usize,
        /// Configured maximum.
        limit: usize,
    },
    /// Checked arithmetic overflowed while deriving a bound.
    Overflow(OnePassCaptureBuildResource),
    /// A fallible construction allocation failed.
    Allocation(OnePassCaptureBuildResource),
    /// The valid program does not have the one-pass graph property.
    NotOnePass(OnePassCaptureRefusal),
    /// The supplied immutable program violates an internal invariant.
    InvalidProgram(&'static str),
}

/// A failed one-pass construction together with all compile work completed by
/// that unpublished attempt.
///
/// Optional facade builders use this receipt to charge a declined sidecar
/// without retaining any of its temporary allocations. The legacy
/// [`OnePassCapturePlan::try_from_program`] entry point continues to return
/// only [`OnePassCaptureBuildError`] for callers that do not aggregate build
/// accounting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnePassCaptureBuildFailure {
    /// Typed terminal reason for the unpublished construction.
    pub source: OnePassCaptureBuildError,
    /// Exact metered compile work completed through the terminal attempt.
    pub compile_work: usize,
}

impl fmt::Display for OnePassCaptureBuildFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "one-pass capture build failed after {} work: {}",
            self.compile_work, self.source
        )
    }
}

impl std::error::Error for OnePassCaptureBuildFailure {}

impl fmt::Display for OnePassCaptureBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "one-pass capture build error: {self:?}")
    }
}

impl std::error::Error for OnePassCaptureBuildError {}

/// Source-independent one-pass construction limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OnePassCaptureBuildLimits {
    /// Maximum reachable deterministic states.
    pub max_states: usize,
    /// Maximum metered graph, byte-partition and table construction work.
    pub max_compile_work: usize,
    /// Maximum logical immutable bytes in the completed sidecar.
    pub max_program_bytes: usize,
}

impl Default for OnePassCaptureBuildLimits {
    fn default() -> Self {
        Self {
            max_states: 65_536,
            max_compile_work: 16_000_000,
            max_program_bytes: 16 * 1_024 * 1_024,
        }
    }
}

/// Complete construction facts for one immutable one-pass capture plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OnePassCaptureBuildReport {
    /// Process-unique identity shared by clones of this exact plan.
    pub plan_identity: u64,
    /// Reachable deterministic states.
    pub states: usize,
    /// Maximal byte-behavior equivalence classes.
    pub byte_classes: usize,
    /// Complete dense state/class transitions.
    pub transitions: usize,
    /// Interned transition and match actions, including the empty action.
    pub actions: usize,
    /// Capture-slot indices retained by all interned actions.
    pub tag_actions: usize,
    /// Assertion predicates retained by all interned actions.
    pub assertions: usize,
    /// Maximum direct slot writes performed by one action.
    pub max_action_tag_actions: usize,
    /// Maximum assertion predicates evaluated by one action.
    pub max_action_assertions: usize,
    /// Whether assertion-free actions are packed into transition-local
    /// 32-bit slot masks instead of requiring an action-table lookup.
    pub direct_tag_masks: bool,
    /// Exact metered source-independent construction work.
    pub compile_work: usize,
    /// Logical immutable sidecar bytes.
    pub program_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Transition {
    target: u32,
    action: u32,
}

/// One assertion-free state exposed to a bounded native exact-span
/// materializer. This is a construction view, not a stable wire format.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OnePassCaptureNativeStateV1 {
    pub match_action: u32,
    pub is_match: bool,
}

/// One assertion-free transition exposed to a bounded native exact-span
/// materializer. `target_state == u32::MAX` is the canonical dead edge.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OnePassCaptureNativeTransitionV1 {
    pub target_state: u32,
    pub action: u32,
}

const _: () = assert!(size_of::<Transition>() == 8);

impl Transition {
    const DEAD: Self = Self {
        target: DEAD,
        action: 0,
    };

    fn live(
        target_row: u32,
        action: u32,
        match_wins: bool,
    ) -> Result<Self, OnePassCaptureBuildError> {
        let max_target_row = if match_wins {
            TARGET_ROW_MASK - 1
        } else {
            TARGET_ROW_MASK
        };
        if target_row > max_target_row {
            return Err(OnePassCaptureBuildError::Resource {
                resource: OnePassCaptureBuildResource::States,
                required: usize::try_from(target_row).unwrap_or(usize::MAX),
                limit: usize::try_from(max_target_row).unwrap_or(usize::MAX),
            });
        }
        Ok(Self {
            target: target_row | if match_wins { MATCH_WINS } else { 0 },
            action,
        })
    }

    const fn is_dead(self) -> bool {
        self.target == DEAD
    }

    const fn target_row(self) -> u32 {
        self.target & TARGET_ROW_MASK
    }

    const fn match_wins(self) -> bool {
        !self.is_dead() && self.target & MATCH_WINS != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DfaState {
    match_action: u32,
    is_match: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Action {
    tags: Box<[u32]>,
    assertions: Box<[Assertion]>,
    inline_tags: [u32; 2],
    direct_tag_mask: u32,
}

impl Action {
    fn empty() -> Self {
        Self {
            tags: Box::new([]),
            assertions: Box::new([]),
            inline_tags: [0; 2],
            direct_tag_mask: 0,
        }
    }
}

#[derive(Debug)]
struct OnePassCaptureInner {
    program: OnePassProgramBinding,
    slot_count: usize,
    group_count: usize,
    identity: u64,
    byte_class: [u8; BYTE_DOMAIN],
    alphabet_len: usize,
    start: u32,
    states: Box<[DfaState]>,
    transitions: Box<[Transition]>,
    actions: Box<[Action]>,
    direct_tag_masks: bool,
    post_accept_live_tags_stable: bool,
    report: OnePassCaptureBuildReport,
}

#[derive(Debug)]
enum OnePassProgramBinding {
    Shared(Arc<Program>),
    CaptureProgramV1 {
        semantic_digest: [u8; 32],
        shape: HistoryProgramShape,
    },
}

impl OnePassProgramBinding {
    fn shared(&self) -> Option<&Program> {
        match self {
            Self::Shared(program) => Some(program),
            Self::CaptureProgramV1 { .. } => None,
        }
    }

    fn authenticates_capture_program(&self, program: &Program, semantic_digest: [u8; 32]) -> bool {
        matches!(
            self,
            Self::CaptureProgramV1 {
                semantic_digest: expected,
                shape,
            } if *expected == semantic_digest && *shape == program.history_program_shape()
        )
    }
}

/// Immutable, construction-complete one-pass capture sidecar.
///
/// Clones share one plan identity and can use workspaces created by any clone.
/// Independently constructed plans always have distinct workspace identities.
#[derive(Clone, Debug)]
pub struct OnePassCapturePlan {
    inner: Arc<OnePassCaptureInner>,
}

/// Borrowed, allocation-free view of the construction-complete direct-tag
/// subset that a native exact-span materializer can lower without calling a
/// semantic helper.
///
/// Admission requires an assertion-free one-pass plan, at most 32 raw tag
/// words, canonical two-tag group geometry, and state-index transitions that
/// close exactly. Unsupported plans return no view; execution must not fall
/// back after selecting this representation.
#[doc(hidden)]
#[derive(Clone, Copy, Debug)]
pub struct OnePassCaptureNativeV1View<'a> {
    inner: &'a OnePassCaptureInner,
    alphabet_len_u32: u32,
    start_state: u32,
}

impl<'a> OnePassCaptureNativeV1View<'a> {
    #[must_use]
    pub const fn byte_classes(self) -> &'a [u8; BYTE_DOMAIN] {
        &self.inner.byte_class
    }

    #[must_use]
    pub const fn alphabet_len(self) -> usize {
        self.inner.alphabet_len
    }

    #[must_use]
    pub const fn start_state(self) -> u32 {
        self.start_state
    }

    #[must_use]
    pub const fn state_count(self) -> usize {
        self.inner.states.len()
    }

    #[must_use]
    pub const fn transition_count(self) -> usize {
        self.inner.transitions.len()
    }

    #[must_use]
    pub const fn group_count(self) -> usize {
        self.inner.group_count
    }

    #[must_use]
    pub const fn tag_slot_count(self) -> usize {
        self.inner.slot_count
    }

    #[must_use]
    pub fn states(self) -> impl ExactSizeIterator<Item = OnePassCaptureNativeStateV1> + 'a {
        self.inner
            .states
            .iter()
            .map(|state| OnePassCaptureNativeStateV1 {
                match_action: state.match_action,
                is_match: state.is_match,
            })
    }

    #[must_use]
    pub fn transitions(
        self,
    ) -> impl ExactSizeIterator<Item = OnePassCaptureNativeTransitionV1> + 'a {
        let alphabet_len = self.alphabet_len_u32;
        self.inner
            .transitions
            .iter()
            .map(move |transition| OnePassCaptureNativeTransitionV1 {
                target_state: if transition.is_dead() {
                    u32::MAX
                } else {
                    transition.target_row() / alphabet_len
                },
                action: transition.action,
            })
    }
}

/// Opaque construction owner shared with one exact one-pass plan.
///
/// Cloning this seal only clones the plan's existing `Arc`; equality is
/// pointer identity, so an independently constructed equivalent plan cannot
/// authenticate as the same owner.
#[doc(hidden)]
#[derive(Clone)]
pub struct OnePassCaptureOwnerSeal {
    inner: Arc<OnePassCaptureInner>,
}

const _: () = assert!(size_of::<Option<OnePassCaptureOwnerSeal>>() == size_of::<usize>());

impl PartialEq for OnePassCaptureOwnerSeal {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
}

impl Eq for OnePassCaptureOwnerSeal {}

impl fmt::Debug for OnePassCaptureOwnerSeal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OnePassCaptureOwnerSeal")
            .field("plan_identity", &self.inner.identity)
            .field("states", &self.inner.report.states)
            .field("groups", &self.inner.group_count)
            .finish_non_exhaustive()
    }
}

impl OnePassCaptureOwnerSeal {
    /// Fixed construction-provenance word retained by an optional enclosing
    /// owner. This is not dynamic search scratch, returned output, or part of
    /// the immutable DFA program byte count.
    #[must_use]
    pub const fn retained_provenance_bytes() -> usize {
        size_of::<Option<Self>>()
    }

    /// Whether `plan` is backed by this exact immutable owner.
    #[must_use]
    pub fn authenticates(&self, plan: &OnePassCapturePlan) -> bool {
        Arc::ptr_eq(&self.inner, &plan.inner)
    }

    /// Immutable construction report owned by this exact seal.
    #[must_use]
    pub fn build_report(&self) -> &OnePassCaptureBuildReport {
        &self.inner.report
    }

    /// Borrow the complete assertion-free direct-tag tables admitted by the
    /// native materializer ABI V1.
    ///
    /// This is an allocation-free construction query. `None` is a stable
    /// decline, never permission for an execution-time fallback.
    #[doc(hidden)]
    #[must_use]
    pub fn native_v1_view(&self) -> Option<OnePassCaptureNativeV1View<'_>> {
        native_v1_view(self.inner.as_ref())
    }

    /// Complete capture schema including group zero.
    #[must_use]
    pub fn capture_group_count(&self) -> usize {
        self.inner.group_count
    }

    /// Raw start/end tag-word schema.
    #[must_use]
    pub fn capture_slot_count(&self) -> usize {
        self.inner.slot_count
    }

    /// Reproduce the complete anchored-search work envelope from immutable
    /// owner shape and a source length.
    pub fn anchored_search_prospective(
        &self,
        length: usize,
    ) -> Result<OnePassCaptureSearchProspective, SearchError> {
        anchored_search_prospective(&self.inner, length)
    }

    /// Admit one full-domain anchored search in the fixed two-array stack
    /// owner, including an enclosing caller's additional co-live stack bytes.
    ///
    /// `Ok(None)` is a source-free schema refusal. Resource and arithmetic
    /// refusals are returned before a token can be published.
    #[doc(hidden)]
    pub fn anchored_inline_admission(
        &self,
        length: usize,
        additional_stack_bytes: usize,
        limits: SearchLimits,
    ) -> Result<Option<OnePassCaptureAnchoredInlineAdmission>, SearchError> {
        let Some(issuer) = self.anchored_inline_issuer() else {
            return Ok(None);
        };
        issuer.admit(length, additional_stack_bytes, limits).map(Some)
    }

    /// Prepare the schema-bound fixed-stack admission issuer once for a
    /// sequence of independent source domains.
    #[doc(hidden)]
    #[must_use]
    pub fn anchored_inline_issuer(&self) -> Option<OnePassCaptureAnchoredInlineIssuer<'_>> {
        (self.inner.slot_count <= INLINE_CAPTURE_SLOTS).then_some(
            OnePassCaptureAnchoredInlineIssuer {
                inner: self.inner.as_ref(),
            },
        )
    }

    /// Fixed two-array raw-slot charge, or `None` for a wider schema.
    #[must_use]
    pub fn anchored_inline_scratch_bytes(&self) -> Option<usize> {
        (self.inner.slot_count <= INLINE_CAPTURE_SLOTS)
            .then_some(size_of::<[[usize; INLINE_CAPTURE_SLOTS]; 2]>())
    }
}

fn native_v1_view(inner: &OnePassCaptureInner) -> Option<OnePassCaptureNativeV1View<'_>> {
    let alphabet_len_u32 = u32::try_from(inner.alphabet_len).ok()?;
    let state_count_u32 = u32::try_from(inner.states.len()).ok()?;
    let expected_transitions = inner.states.len().checked_mul(inner.alphabet_len)?;
    if !inner.direct_tag_masks
        || inner.report.assertions != 0
        || inner.alphabet_len == 0
        || inner.states.is_empty()
        || inner.group_count == 0
        || inner.slot_count == 0
        || inner.slot_count > DIRECT_TAG_SLOT_LIMIT
        || inner.group_count.checked_mul(2) != Some(inner.slot_count)
        || inner.transitions.len() != expected_transitions
        || inner.start % alphabet_len_u32 != 0
        || inner
            .byte_class
            .iter()
            .any(|&class| usize::from(class) >= inner.alphabet_len)
    {
        return None;
    }
    let start_state = inner.start.checked_div(alphabet_len_u32)?;
    if start_state >= state_count_u32 {
        return None;
    }
    let tag_mask_limit = if inner.slot_count == DIRECT_TAG_SLOT_LIMIT {
        None
    } else {
        Some(1_u32.checked_shl(u32::try_from(inner.slot_count).ok()?)?)
    };
    let mask_is_valid = |mask: u32| tag_mask_limit.is_none_or(|limit| mask < limit);
    if inner
        .states
        .iter()
        .any(|state| !mask_is_valid(state.match_action))
    {
        return None;
    }
    for transition in &inner.transitions {
        if !mask_is_valid(transition.action) {
            return None;
        }
        if transition.is_dead() {
            continue;
        }
        let row = transition.target_row();
        if row % alphabet_len_u32 != 0 || row.checked_div(alphabet_len_u32)? >= state_count_u32 {
            return None;
        }
    }
    Some(OnePassCaptureNativeV1View {
        inner,
        alphabet_len_u32,
        start_state,
    })
}

/// Borrowed schema-authenticated issuer for repeated fixed-stack admissions.
#[doc(hidden)]
#[derive(Clone, Copy)]
pub struct OnePassCaptureAnchoredInlineIssuer<'a> {
    inner: &'a OnePassCaptureInner,
}

impl fmt::Debug for OnePassCaptureAnchoredInlineIssuer<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OnePassCaptureAnchoredInlineIssuer")
            .field("plan_identity", &self.inner.identity)
            .field("groups", &self.inner.group_count)
            .finish()
    }
}

impl OnePassCaptureAnchoredInlineIssuer<'_> {
    /// Derive and admit one exact-length token without repeating the schema
    /// selection already performed when this issuer was prepared.
    #[doc(hidden)]
    pub fn admit(
        self,
        length: usize,
        additional_stack_bytes: usize,
        limits: SearchLimits,
    ) -> Result<OnePassCaptureAnchoredInlineAdmission, SearchError> {
        let raw_scratch_bytes = size_of::<[[usize; INLINE_CAPTURE_SLOTS]; 2]>();
        let combined_scratch_bytes = raw_scratch_bytes
            .checked_add(additional_stack_bytes)
            .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;
        let prospective = anchored_search_prospective(self.inner, length)?;
        check(
            ResourceKind::StateVisits,
            prospective.state_visits,
            limits.max_state_visits,
        )?;
        check(
            ResourceKind::SlotCopies,
            prospective.slot_copies,
            limits.max_slot_copies,
        )?;
        check(
            ResourceKind::ScratchBytes,
            combined_scratch_bytes,
            limits.max_scratch_bytes,
        )?;
        Ok(OnePassCaptureAnchoredInlineAdmission {
            plan_identity: self.inner.identity,
            length,
            prospective,
        })
    }
}

/// Caller-owned direct-slot scratch bound to exactly one immutable plan.
#[derive(Debug)]
pub struct OnePassCaptureWorkspace {
    plan_identity: u64,
    slots: ExactVec<usize>,
    usage: OnePassCaptureWorkspaceUsage,
}

/// Caller-owned live and last-accepting slot scratch for one anchored search.
///
/// Keeping the candidate slots separate is required for leftmost-first
/// rollback: a higher-priority continuation may overwrite live tags and then
/// fail after an earlier accepting boundary has already been observed.
#[derive(Debug)]
pub struct OnePassCaptureSearchWorkspace {
    plan_identity: u64,
    live_slots: ExactVec<usize>,
    candidate_slots: ExactVec<usize>,
    usage: OnePassCaptureSearchWorkspaceUsage,
}

/// Exact retained dimensions for one reusable one-pass capture workspace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OnePassCaptureWorkspaceUsage {
    /// Exact number of retained raw tag words.
    pub slot_capacity: usize,
    /// Workspace header plus the exact tag-word allocation.
    pub persistent_bytes: usize,
}

/// Exact retained dimensions for one reusable anchored one-pass search.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OnePassCaptureSearchWorkspaceUsage {
    /// Exact number of retained words in each of the live and candidate slot
    /// arrays.
    pub slot_capacity: usize,
    /// Workspace header plus both exact tag-word allocations.
    pub persistent_bytes: usize,
}

/// Source-independent complete work envelope for one anchored one-pass
/// capture search.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OnePassCaptureSearchProspective {
    /// Maximum state and assertion visits.
    pub state_visits: usize,
    /// Maximum tag writes plus complete accepting-candidate snapshots.
    pub slot_copies: usize,
    /// Maximum input bytes examined.
    pub bytes_examined: usize,
    /// Exact number of deterministic starts injected.
    pub starts_injected: usize,
    /// Exact maximum number of live deterministic threads.
    pub peak_threads: usize,
}

/// Opaque owner-bound admission for one fixed-stack full-domain anchored
/// search.
///
/// Construction derives the work prospective once and admits state visits,
/// slot copies and the caller-declared co-live stack footprint. Execution can
/// then bind this token to the same owner and exact source length without
/// repeating those checked bounds.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OnePassCaptureAnchoredInlineAdmission {
    plan_identity: u64,
    length: usize,
    prospective: OnePassCaptureSearchProspective,
}

impl OnePassCaptureAnchoredInlineAdmission {
    /// Complete source-independent state/slot/source envelope admitted by
    /// this exact token.
    #[must_use]
    pub const fn prospective(self) -> OnePassCaptureSearchProspective {
        self.prospective
    }
}

fn anchored_search_prospective(
    inner: &OnePassCaptureInner,
    length: usize,
) -> Result<OnePassCaptureSearchProspective, SearchError> {
    let boundaries = length
        .checked_add(1)
        .ok_or(SearchError::BoundOverflow(ResourceKind::StateVisits))?;
    let action_boundaries = length
        .checked_add(boundaries)
        .ok_or(SearchError::BoundOverflow(ResourceKind::StateVisits))?;
    let state_visits = action_boundaries
        .checked_mul(inner.report.max_action_assertions)
        .and_then(|assertions| assertions.checked_add(boundaries))
        .ok_or(SearchError::BoundOverflow(ResourceKind::StateVisits))?;
    let slot_copies = boundaries
        .checked_mul(inner.slot_count)
        .and_then(|snapshots| {
            action_boundaries
                .checked_mul(inner.report.max_action_tag_actions)
                .and_then(|actions| snapshots.checked_add(actions))
        })
        .ok_or(SearchError::BoundOverflow(ResourceKind::SlotCopies))?;
    Ok(OnePassCaptureSearchProspective {
        state_visits,
        slot_copies,
        bytes_examined: length,
        starts_injected: 1,
        peak_threads: 1,
    })
}

impl OnePassCapturePlan {
    /// Opaque pointer-authenticated owner for construction compositions.
    #[doc(hidden)]
    #[must_use]
    pub fn owner_seal(&self) -> OnePassCaptureOwnerSeal {
        OnePassCaptureOwnerSeal {
            inner: Arc::clone(&self.inner),
        }
    }

    /// Borrow the assertion-free direct-tag construction tables admitted by
    /// the native exact-span materializer. A declined view is terminal for
    /// that native artifact and never authorizes execution-time replay.
    #[doc(hidden)]
    #[must_use]
    pub fn native_v1_view(&self) -> Option<OnePassCaptureNativeV1View<'_>> {
        native_v1_view(self.inner.as_ref())
    }

    fn exact_work_bounds(&self, span: Span) -> Result<(usize, usize, usize, usize), SearchError> {
        let length = span
            .end
            .checked_sub(span.start)
            .ok_or(SearchError::InvalidWindow)?;
        let base_state_visits = length
            .checked_add(1)
            .ok_or(SearchError::BoundOverflow(ResourceKind::StateVisits))?;
        let visits_per_boundary = self
            .inner
            .report
            .max_action_assertions
            .checked_add(1)
            .ok_or(SearchError::BoundOverflow(ResourceKind::StateVisits))?;
        let state_visits = base_state_visits
            .checked_mul(visits_per_boundary)
            .ok_or(SearchError::BoundOverflow(ResourceKind::StateVisits))?;
        let slot_copies = base_state_visits
            .checked_mul(self.inner.report.max_action_tag_actions)
            .ok_or(SearchError::BoundOverflow(ResourceKind::SlotCopies))?;
        Ok((length, base_state_visits, state_visits, slot_copies))
    }

    /// Derive the complete execution envelope for one anchored search without
    /// allocating or inspecting source bytes.
    #[doc(hidden)]
    pub fn anchored_search_prospective(
        &self,
        length: usize,
    ) -> Result<OnePassCaptureSearchProspective, SearchError> {
        anchored_search_prospective(&self.inner, length)
    }

    /// Whether exact replay's complete state-visit and slot-copy envelope fits
    /// the supplied limits. This source-free query intentionally excludes the
    /// caller's choice of inline or heap scratch owner.
    #[doc(hidden)]
    #[must_use]
    pub fn exact_replay_work_is_admitted(&self, span: Span, limits: SearchLimits) -> bool {
        self.exact_work_bounds(span)
            .is_ok_and(|(_, _, state_visits, slot_copies)| {
                state_visits <= limits.max_state_visits && slot_copies <= limits.max_slot_copies
            })
    }

    /// Whether a complete anchored leftmost-first search over at most
    /// `max_span_bytes` fits the supplied state-visit and slot-copy limits.
    /// This query is source independent and excludes retained scratch.
    #[doc(hidden)]
    #[must_use]
    pub fn anchored_search_work_is_admitted(
        &self,
        max_span_bytes: usize,
        limits: SearchLimits,
    ) -> bool {
        self.anchored_search_prospective(max_span_bytes)
            .is_ok_and(|prospective| {
                prospective.state_visits <= limits.max_state_visits
                    && prospective.slot_copies <= limits.max_slot_copies
            })
    }

    /// Derive the complete exact-span execution and retained-workspace
    /// envelope without allocating or inspecting source bytes.
    pub fn exact_workspace_usage(
        &self,
        span: Span,
        limits: SearchLimits,
    ) -> Result<OnePassCaptureWorkspaceUsage, SearchError> {
        let (_, _, state_visits, slot_copies) = self.exact_work_bounds(span)?;
        check(
            ResourceKind::StateVisits,
            state_visits,
            limits.max_state_visits,
        )?;
        check(
            ResourceKind::SlotCopies,
            slot_copies,
            limits.max_slot_copies,
        )?;
        self.workspace_usage(limits)
    }

    /// Derive the exact retained direct-slot owner without allocating.
    pub fn workspace_usage(
        &self,
        limits: SearchLimits,
    ) -> Result<OnePassCaptureWorkspaceUsage, SearchError> {
        let persistent_bytes = size_of::<OnePassCaptureWorkspace>()
            .checked_add(
                self.inner
                    .slot_count
                    .checked_mul(size_of::<usize>())
                    .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?,
            )
            .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;
        check(
            ResourceKind::ScratchBytes,
            persistent_bytes,
            limits.max_scratch_bytes,
        )?;
        Ok(OnePassCaptureWorkspaceUsage {
            slot_capacity: self.inner.slot_count,
            persistent_bytes,
        })
    }

    /// Derive the exact retained live/candidate owner for anchored search
    /// without allocating or inspecting source bytes.
    pub fn search_workspace_usage(
        &self,
        limits: SearchLimits,
    ) -> Result<OnePassCaptureSearchWorkspaceUsage, SearchError> {
        let slot_bytes = self
            .inner
            .slot_count
            .checked_mul(size_of::<usize>())
            .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;
        let persistent_bytes = slot_bytes
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(size_of::<OnePassCaptureSearchWorkspace>()))
            .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;
        check(
            ResourceKind::ScratchBytes,
            persistent_bytes,
            limits.max_scratch_bytes,
        )?;
        Ok(OnePassCaptureSearchWorkspaceUsage {
            slot_capacity: self.inner.slot_count,
            persistent_bytes,
        })
    }

    /// Attempt a complete, source-independent one-pass construction.
    ///
    /// Any error leaves no published plan or mutable partial cache. In
    /// particular, [`OnePassCaptureBuildError::NotOnePass`] is a normal
    /// prepublication fallback edge for a general capture engine.
    pub fn try_from_program(
        program: Arc<Program>,
        limits: OnePassCaptureBuildLimits,
    ) -> Result<Self, OnePassCaptureBuildError> {
        Self::try_from_program_accounted(program, limits).map_err(|failure| failure.source)
    }

    /// Attempt complete construction while preserving exact compile work on
    /// every declined or failed terminal.
    pub fn try_from_program_accounted(
        program: Arc<Program>,
        limits: OnePassCaptureBuildLimits,
    ) -> Result<Self, OnePassCaptureBuildFailure> {
        let borrowed = Arc::clone(&program);
        let binding = OnePassProgramBinding::Shared(program);
        Self::try_from_borrowed_program_accounted(&borrowed, binding, limits)
    }

    pub(crate) fn try_from_capture_program_v1_accounted(
        program: &Program,
        semantic_digest: [u8; 32],
        limits: OnePassCaptureBuildLimits,
    ) -> Result<Self, OnePassCaptureBuildFailure> {
        Self::try_from_borrowed_program_accounted(
            program,
            OnePassProgramBinding::CaptureProgramV1 {
                semantic_digest,
                shape: program.history_program_shape(),
            },
            limits,
        )
    }

    fn try_from_borrowed_program_accounted(
        program: &Program,
        binding: OnePassProgramBinding,
        limits: OnePassCaptureBuildLimits,
    ) -> Result<Self, OnePassCaptureBuildFailure> {
        let completed = Compiler::new(program, limits)?.build()?;
        let compile_work = completed.work;
        let direct_tag_masks = completed.direct_tag_masks;
        let post_accept_live_tags_stable = completed.post_accept_live_tags_stable;
        let program_bytes = immutable_bytes(
            completed.states.len(),
            completed.transitions.len(),
            &completed.actions,
        )
        .map_err(|source| OnePassCaptureBuildFailure {
            source,
            compile_work,
        })?;
        enforce(
            OnePassCaptureBuildResource::ImmutableBytes,
            program_bytes,
            limits.max_program_bytes,
        )
        .map_err(|source| OnePassCaptureBuildFailure {
            source,
            compile_work,
        })?;
        let identity = next_plan_identity();
        let tag_actions = completed
            .actions
            .iter()
            .try_fold(0_usize, |sum, action| {
                sum.checked_add(action.tags.len())
                    .ok_or(OnePassCaptureBuildError::Overflow(
                        OnePassCaptureBuildResource::ImmutableBytes,
                    ))
            })
            .map_err(|source| OnePassCaptureBuildFailure {
                source,
                compile_work,
            })?;
        let assertions = completed
            .actions
            .iter()
            .try_fold(0_usize, |sum, action| {
                sum.checked_add(action.assertions.len())
                    .ok_or(OnePassCaptureBuildError::Overflow(
                        OnePassCaptureBuildResource::ImmutableBytes,
                    ))
            })
            .map_err(|source| OnePassCaptureBuildFailure {
                source,
                compile_work,
            })?;
        let max_action_tag_actions = completed
            .actions
            .iter()
            .map(|action| action.tags.len())
            .max()
            .unwrap_or(0);
        let max_action_assertions = completed
            .actions
            .iter()
            .map(|action| action.assertions.len())
            .max()
            .unwrap_or(0);
        let report = OnePassCaptureBuildReport {
            plan_identity: identity,
            states: completed.states.len(),
            byte_classes: completed.alphabet_len,
            transitions: completed.transitions.len(),
            actions: completed.actions.len(),
            tag_actions,
            assertions,
            max_action_tag_actions,
            max_action_assertions,
            direct_tag_masks,
            compile_work: completed.work,
            program_bytes,
        };
        Ok(Self {
            inner: Arc::new(OnePassCaptureInner {
                program: binding,
                slot_count: program.slot_count,
                group_count: program.groups.len(),
                identity,
                byte_class: completed.byte_class,
                alphabet_len: completed.alphabet_len,
                start: completed.start,
                states: completed.states.into_boxed_slice(),
                transitions: completed.transitions.into_boxed_slice(),
                actions: completed.actions.into_boxed_slice(),
                direct_tag_masks,
                post_accept_live_tags_stable,
                report,
            }),
        })
    }

    /// Construction report and immutable plan identity.
    #[must_use]
    pub fn build_report(&self) -> &OnePassCaptureBuildReport {
        &self.inner.report
    }

    /// Canonical capture schema width, including group zero.
    #[doc(hidden)]
    #[must_use]
    pub fn capture_group_count(&self) -> usize {
        self.inner.group_count
    }

    /// Raw start/end tag-word schema width.
    #[doc(hidden)]
    #[must_use]
    pub fn capture_slot_count(&self) -> usize {
        self.inner.slot_count
    }

    /// Whether construction admitted the deferred accepting-snapshot proof.
    #[doc(hidden)]
    #[must_use]
    pub fn post_accept_live_tags_stable(&self) -> bool {
        self.inner.post_accept_live_tags_stable
    }

    /// Full fixed stack charge for the allocation-free anchored-search owner,
    /// or `None` when the raw capture schema is too wide for that owner.
    #[doc(hidden)]
    #[must_use]
    pub fn anchored_inline_scratch_bytes(&self) -> Option<usize> {
        (self.inner.slot_count <= INLINE_CAPTURE_SLOTS)
            .then_some(size_of::<[[usize; INLINE_CAPTURE_SLOTS]; 2]>())
    }

    /// Process-unique identity shared by clones of this exact plan.
    #[must_use]
    pub fn identity(&self) -> u64 {
        self.inner.identity
    }

    /// Allocate one reusable direct-slot workspace after checking its actual
    /// retained capacity against the supplied scratch ceiling.
    pub fn create_workspace(
        &self,
        limits: SearchLimits,
    ) -> Result<OnePassCaptureWorkspace, SearchError> {
        let usage = self.workspace_usage(limits)?;
        let mut slots =
            ExactVec::try_with_capacity(usage.slot_capacity).map_err(|error| match error {
                CopyError::LayoutOverflow => SearchError::BoundOverflow(ResourceKind::ScratchBytes),
                CopyError::AllocationFailed => SearchError::Allocation(ResourceKind::ScratchBytes),
            })?;
        if slots.capacity() != usage.slot_capacity {
            return Err(SearchError::Allocation(ResourceKind::ScratchBytes));
        }
        for _ in 0..usage.slot_capacity {
            slots
                .try_push(UNSET_SLOT)
                .map_err(|_| SearchError::InvalidProgram)?;
        }
        Ok(OnePassCaptureWorkspace {
            plan_identity: self.inner.identity,
            slots,
            usage,
        })
    }

    /// Allocate one reusable anchored-search workspace after checking both
    /// exact slot arrays against the supplied scratch ceiling.
    pub fn create_search_workspace(
        &self,
        limits: SearchLimits,
    ) -> Result<OnePassCaptureSearchWorkspace, SearchError> {
        let usage = self.search_workspace_usage(limits)?;
        let allocate_slots = || -> Result<ExactVec<usize>, SearchError> {
            let mut slots =
                ExactVec::try_with_capacity(usage.slot_capacity).map_err(|error| match error {
                    CopyError::LayoutOverflow => {
                        SearchError::BoundOverflow(ResourceKind::ScratchBytes)
                    }
                    CopyError::AllocationFailed => {
                        SearchError::Allocation(ResourceKind::ScratchBytes)
                    }
                })?;
            if slots.capacity() != usage.slot_capacity {
                return Err(SearchError::Allocation(ResourceKind::ScratchBytes));
            }
            for _ in 0..usage.slot_capacity {
                slots
                    .try_push(UNSET_SLOT)
                    .map_err(|_| SearchError::InvalidProgram)?;
            }
            Ok(slots)
        };
        let live_slots = allocate_slots()?;
        let candidate_slots = allocate_slots()?;
        Ok(OnePassCaptureSearchWorkspace {
            plan_identity: self.inner.identity,
            live_slots,
            candidate_slots,
            usage,
        })
    }

    /// Replay one exact, already-selected span with full original-haystack
    /// assertion context.
    ///
    /// Workspace identity and every source-independent execution bound are
    /// checked before source bytes are inspected or slots are reset. A valid
    /// span outside the pattern language returns a successful non-match.
    #[allow(
        clippy::too_many_lines,
        reason = "pre-source admission and the complete deterministic replay stay auditable together"
    )]
    pub fn captures_exact(
        &self,
        workspace: &mut OnePassCaptureWorkspace,
        haystack: &[u8],
        window: Window,
        span: Span,
        limits: SearchLimits,
    ) -> Result<SearchOutcome, SearchError> {
        let program = self
            .inner
            .program
            .shared()
            .ok_or(SearchError::InvalidProgram)?;
        if workspace.plan_identity != self.inner.identity
            || workspace.slots.len() != self.inner.slot_count
            || workspace.slots.capacity() != self.inner.slot_count
        {
            return Err(SearchError::InvalidProgram);
        }
        let raw = self.captures_exact_with_slots(
            workspace.slots.as_mut_slice(),
            workspace.usage.persistent_bytes,
            haystack,
            window,
            span,
            limits,
        )?;
        let captures = raw
            .matched
            .then(|| canonicalize_unset(program, workspace.slots.as_slice(), UNSET_SLOT))
            .transpose()?;
        Ok(SearchOutcome {
            captures,
            report: raw.report,
        })
    }

    /// Replay one exact span into a fixed caller-owned group array.
    ///
    /// The output length, workspace identity, window, and complete resource
    /// envelope are checked before source access. Every raw tag pair and
    /// group zero are validated before the first output write. On any error,
    /// `output` is unchanged; a successful non-match publishes all groups as
    /// [`CaptureGroupSlot::UNMATCHED`].
    pub fn captures_exact_slots(
        &self,
        workspace: &mut OnePassCaptureWorkspace,
        haystack: &[u8],
        window: Window,
        span: Span,
        output: &mut [CaptureGroupSlot],
        limits: SearchLimits,
    ) -> Result<ExactCaptureSlotsOutcome, SearchError> {
        let program = self
            .inner
            .program
            .shared()
            .ok_or(SearchError::InvalidProgram)?;
        if output.len() != self.inner.group_count
            || workspace.plan_identity != self.inner.identity
            || workspace.slots.len() != self.inner.slot_count
            || workspace.slots.capacity() != self.inner.slot_count
        {
            return Err(SearchError::InvalidProgram);
        }
        let outcome = self.captures_exact_with_slots(
            workspace.slots.as_mut_slice(),
            workspace.usage.persistent_bytes,
            haystack,
            window,
            span,
            limits,
        )?;
        if outcome.matched {
            commit_capture_group_slots(
                program,
                workspace.slots.as_slice(),
                UNSET_SLOT,
                span,
                output,
            )?;
        } else {
            output.fill(CaptureGroupSlot::UNMATCHED);
        }
        Ok(outcome)
    }

    /// Execute one anchored leftmost-first capture search from `from` through
    /// the end of `window` into a fixed caller-owned group array.
    ///
    /// The output length, workspace identity, complete execution envelope and
    /// retained scratch are checked before source access. Live capture tags
    /// and the last accepting candidate use separate exact arrays so a failed
    /// higher-priority continuation cannot corrupt rollback. On any error,
    /// `output` is unchanged.
    #[doc(hidden)]
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "pre-source admission and the complete prioritized search stay auditable together"
    )]
    pub fn captures_anchored_slots(
        &self,
        workspace: &mut OnePassCaptureSearchWorkspace,
        haystack: &[u8],
        window: Window,
        from: usize,
        output: &mut [CaptureGroupSlot],
        limits: SearchLimits,
    ) -> Result<ExactCaptureSlotsOutcome, SearchError> {
        if workspace.plan_identity != self.inner.identity
            || workspace.live_slots.len() != self.inner.slot_count
            || workspace.live_slots.capacity() != self.inner.slot_count
            || workspace.candidate_slots.len() != self.inner.slot_count
            || workspace.candidate_slots.capacity() != self.inner.slot_count
        {
            return Err(SearchError::InvalidProgram);
        }
        let scratch_bytes = workspace.usage.persistent_bytes;
        self.captures_anchored_with_slots(
            workspace.live_slots.as_mut_slice(),
            workspace.candidate_slots.as_mut_slice(),
            scratch_bytes,
            haystack,
            window,
            from,
            output,
            limits,
        )
    }

    /// Try one anchored search in two fixed 32-word stack arrays.
    ///
    /// `Ok(None)` is selected before source access when either the capture
    /// schema is wider than 32 raw slots or the complete 64-word stack owner
    /// is not admitted. A returned result charges the full fixed owner.
    #[doc(hidden)]
    #[allow(
        clippy::too_many_arguments,
        reason = "the bounded inline owner and full anchored input remain explicit"
    )]
    pub fn try_captures_anchored_inline(
        &self,
        haystack: &[u8],
        window: Window,
        from: usize,
        output: &mut [CaptureGroupSlot],
        limits: SearchLimits,
    ) -> Result<Option<ExactCaptureSlotsOutcome>, SearchError> {
        let scratch_bytes = size_of::<[[usize; INLINE_CAPTURE_SLOTS]; 2]>();
        if self.inner.slot_count > INLINE_CAPTURE_SLOTS || scratch_bytes > limits.max_scratch_bytes
        {
            return Ok(None);
        }
        let mut live_slots = [UNSET_SLOT; INLINE_CAPTURE_SLOTS];
        let mut candidate_slots = [UNSET_SLOT; INLINE_CAPTURE_SLOTS];
        self.captures_anchored_with_slots(
            &mut live_slots[..self.inner.slot_count],
            &mut candidate_slots[..self.inner.slot_count],
            scratch_bytes,
            haystack,
            window,
            from,
            output,
            limits,
        )
        .map(Some)
    }

    /// Execute one already-admitted full-domain anchored search in the fixed
    /// two-array stack owner.
    ///
    /// The opaque token binds the exact plan and source length and has already
    /// admitted state visits, slot copies and the complete caller-declared
    /// co-live stack footprint. This method performs only those bindings and
    /// the output-schema check before source access; it does not derive or
    /// admit the prospective again.
    #[doc(hidden)]
    pub fn captures_anchored_full_inline_admitted(
        &self,
        admission: OnePassCaptureAnchoredInlineAdmission,
        haystack: &[u8],
        output: &mut [CaptureGroupSlot],
    ) -> Result<ExactCaptureSlotsOutcome, SearchError> {
        if admission.plan_identity != self.inner.identity
            || admission.length != haystack.len()
            || output.len() != self.inner.group_count
        {
            return Err(SearchError::InvalidProgram);
        }
        let program = self
            .inner
            .program
            .shared()
            .ok_or(SearchError::InvalidProgram)?;
        let scratch_bytes = size_of::<[[usize; INLINE_CAPTURE_SLOTS]; 2]>();
        let mut live_slots = [UNSET_SLOT; INLINE_CAPTURE_SLOTS];
        let mut candidate_slots = [UNSET_SLOT; INLINE_CAPTURE_SLOTS];
        self.captures_anchored_with_slots_admitted(
            program,
            &mut live_slots[..self.inner.slot_count],
            &mut candidate_slots[..self.inner.slot_count],
            scratch_bytes,
            haystack,
            Window {
                start: 0,
                end: haystack.len(),
            },
            0,
            output,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "heap and inline owners share one admitted prioritized transition core"
    )]
    fn captures_anchored_with_slots(
        &self,
        live_slots: &mut [usize],
        candidate_slots: &mut [usize],
        scratch_bytes: usize,
        haystack: &[u8],
        window: Window,
        from: usize,
        output: &mut [CaptureGroupSlot],
        limits: SearchLimits,
    ) -> Result<ExactCaptureSlotsOutcome, SearchError> {
        let program = self
            .inner
            .program
            .shared()
            .ok_or(SearchError::InvalidProgram)?;
        if output.len() != self.inner.group_count
            || live_slots.len() != self.inner.slot_count
            || candidate_slots.len() != self.inner.slot_count
        {
            return Err(SearchError::InvalidProgram);
        }
        validate_window(haystack, window, from)?;
        check(
            ResourceKind::ScratchBytes,
            scratch_bytes,
            limits.max_scratch_bytes,
        )?;
        let length = window
            .end
            .checked_sub(from)
            .ok_or(SearchError::InvalidWindow)?;
        let prospective = self.anchored_search_prospective(length)?;
        check(
            ResourceKind::StateVisits,
            prospective.state_visits,
            limits.max_state_visits,
        )?;
        check(
            ResourceKind::SlotCopies,
            prospective.slot_copies,
            limits.max_slot_copies,
        )?;

        self.captures_anchored_with_slots_admitted(
            program,
            live_slots,
            candidate_slots,
            scratch_bytes,
            haystack,
            window,
            from,
            output,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "preadmitted heap and inline owners share one prioritized transition core"
    )]
    fn captures_anchored_with_slots_admitted(
        &self,
        program: &Program,
        live_slots: &mut [usize],
        candidate_slots: &mut [usize],
        scratch_bytes: usize,
        haystack: &[u8],
        window: Window,
        from: usize,
        output: &mut [CaptureGroupSlot],
    ) -> Result<ExactCaptureSlotsOutcome, SearchError> {
        live_slots.fill(UNSET_SLOT);
        candidate_slots.fill(UNSET_SLOT);
        if self.inner.post_accept_live_tags_stable {
            return self.captures_anchored_with_slots_admitted_stable(
                program,
                live_slots,
                candidate_slots,
                scratch_bytes,
                haystack,
                window,
                from,
                output,
            );
        }
        let mut state = self.inner.start;
        let mut position = from;
        let mut candidate_end = None;
        let mut base_state_visits = 0_usize;
        let mut assertion_checks = 0_usize;
        let mut slot_copies = 0_usize;
        let mut bytes_examined = 0_usize;
        loop {
            base_state_visits = checked_add(base_state_visits, 1, ResourceKind::StateVisits)?;
            let state_index = usize::try_from(state)
                .ok()
                .and_then(|row| row.checked_div(self.inner.alphabet_len))
                .ok_or(SearchError::InvalidProgram)?;
            let dfa_state = *self
                .inner
                .states
                .get(state_index)
                .ok_or(SearchError::InvalidProgram)?;

            let transition = if position < window.end {
                let byte = *haystack.get(position).ok_or(SearchError::InvalidWindow)?;
                let class = usize::from(self.inner.byte_class[usize::from(byte)]);
                let offset = usize::try_from(state)
                    .ok()
                    .and_then(|row| row.checked_add(class))
                    .ok_or(SearchError::InvalidProgram)?;
                bytes_examined = checked_add(bytes_examined, 1, ResourceKind::StateVisits)?;
                Some(
                    *self
                        .inner
                        .transitions
                        .get(offset)
                        .ok_or(SearchError::InvalidProgram)?,
                )
            } else {
                None
            };

            let mut accepted = false;
            if dfa_state.is_match {
                accepted = if self.inner.direct_tag_masks {
                    true
                } else {
                    let action = self.action(dfa_state.match_action)?;
                    action_matches(action, haystack, window, position, &mut assertion_checks)?
                };
                if accepted {
                    candidate_slots.copy_from_slice(live_slots);
                    slot_copies =
                        checked_add(slot_copies, self.inner.slot_count, ResourceKind::SlotCopies)?;
                    if self.inner.direct_tag_masks {
                        apply_tag_mask(
                            dfa_state.match_action,
                            candidate_slots,
                            position,
                            &mut slot_copies,
                        )?;
                    } else {
                        let action = self.action(dfa_state.match_action)?;
                        apply_tags(action, candidate_slots, position, &mut slot_copies)?;
                    }
                    candidate_end = Some(position);
                }
            }

            let Some(transition) = transition else {
                break;
            };
            if accepted && transition.match_wins() {
                break;
            }
            if transition.is_dead() {
                break;
            }
            if self.inner.direct_tag_masks {
                if transition.action != 0 {
                    apply_tag_mask(transition.action, live_slots, position, &mut slot_copies)?;
                }
            } else if transition.action != 0 {
                let action = self.action(transition.action)?;
                if !action_matches(action, haystack, window, position, &mut assertion_checks)? {
                    break;
                }
                apply_tags(action, live_slots, position, &mut slot_copies)?;
            }
            state = transition.target_row();
            position = position
                .checked_add(1)
                .ok_or(SearchError::BoundOverflow(ResourceKind::StateVisits))?;
        }

        let state_visits = base_state_visits
            .checked_add(assertion_checks)
            .ok_or(SearchError::BoundOverflow(ResourceKind::StateVisits))?;
        let matched = if let Some(end) = candidate_end {
            commit_capture_group_slots(
                program,
                candidate_slots,
                UNSET_SLOT,
                Span { start: from, end },
                output,
            )?;
            true
        } else {
            output.fill(CaptureGroupSlot::UNMATCHED);
            false
        };
        Ok(ExactCaptureSlotsOutcome {
            matched,
            report: Self::run_report(scratch_bytes, state_visits, slot_copies, bytes_examined),
        })
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the certified executor mirrors the general transition semantics while deferring exactly one accepting snapshot"
    )]
    fn captures_anchored_with_slots_admitted_stable(
        &self,
        program: &Program,
        live_slots: &mut [usize],
        candidate_slots: &mut [usize],
        scratch_bytes: usize,
        haystack: &[u8],
        window: Window,
        from: usize,
        output: &mut [CaptureGroupSlot],
    ) -> Result<ExactCaptureSlotsOutcome, SearchError> {
        debug_assert!(self.inner.post_accept_live_tags_stable);
        let mut state = self.inner.start;
        let mut position = from;
        let mut candidate = None;
        let mut base_state_visits = 0_usize;
        let mut assertion_checks = 0_usize;
        let mut slot_copies = 0_usize;
        let mut bytes_examined = 0_usize;
        loop {
            base_state_visits = checked_add(base_state_visits, 1, ResourceKind::StateVisits)?;
            let state_index = usize::try_from(state)
                .ok()
                .and_then(|row| row.checked_div(self.inner.alphabet_len))
                .ok_or(SearchError::InvalidProgram)?;
            let dfa_state = *self
                .inner
                .states
                .get(state_index)
                .ok_or(SearchError::InvalidProgram)?;

            let transition = if position < window.end {
                let byte = *haystack.get(position).ok_or(SearchError::InvalidWindow)?;
                let class = usize::from(self.inner.byte_class[usize::from(byte)]);
                let offset = usize::try_from(state)
                    .ok()
                    .and_then(|row| row.checked_add(class))
                    .ok_or(SearchError::InvalidProgram)?;
                bytes_examined = checked_add(bytes_examined, 1, ResourceKind::StateVisits)?;
                Some(
                    *self
                        .inner
                        .transitions
                        .get(offset)
                        .ok_or(SearchError::InvalidProgram)?,
                )
            } else {
                None
            };

            let mut accepted = false;
            if dfa_state.is_match {
                accepted = if self.inner.direct_tag_masks {
                    true
                } else {
                    let action = self.action(dfa_state.match_action)?;
                    action_matches(action, haystack, window, position, &mut assertion_checks)?
                };
                if accepted {
                    candidate = Some((position, dfa_state.match_action));
                }
            }

            let Some(transition) = transition else {
                break;
            };
            if accepted && transition.match_wins() {
                break;
            }
            if transition.is_dead() {
                break;
            }
            if self.inner.direct_tag_masks {
                if transition.action != 0 {
                    apply_tag_mask(transition.action, live_slots, position, &mut slot_copies)?;
                }
            } else if transition.action != 0 {
                let action = self.action(transition.action)?;
                if !action_matches(action, haystack, window, position, &mut assertion_checks)? {
                    break;
                }
                apply_tags(action, live_slots, position, &mut slot_copies)?;
            }
            state = transition.target_row();
            position = position
                .checked_add(1)
                .ok_or(SearchError::BoundOverflow(ResourceKind::StateVisits))?;
        }

        let state_visits = base_state_visits
            .checked_add(assertion_checks)
            .ok_or(SearchError::BoundOverflow(ResourceKind::StateVisits))?;
        let matched = if let Some((end, match_action)) = candidate {
            candidate_slots.copy_from_slice(live_slots);
            slot_copies = checked_add(
                slot_copies,
                self.inner.slot_count,
                ResourceKind::SlotCopies,
            )?;
            if self.inner.direct_tag_masks {
                apply_tag_mask(match_action, candidate_slots, end, &mut slot_copies)?;
            } else {
                let action = self.action(match_action)?;
                apply_tags(action, candidate_slots, end, &mut slot_copies)?;
            }
            commit_capture_group_slots(
                program,
                candidate_slots,
                UNSET_SLOT,
                Span { start: from, end },
                output,
            )?;
            true
        } else {
            output.fill(CaptureGroupSlot::UNMATCHED);
            false
        };
        Ok(ExactCaptureSlotsOutcome {
            matched,
            report: Self::run_report(scratch_bytes, state_visits, slot_copies, bytes_examined),
        })
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the stable-program binding and complete caller-owned execution domain stay explicit"
    )]
    pub(crate) fn captures_exact_slots_capture_program_v1(
        &self,
        program: &Program,
        semantic_digest: [u8; 32],
        workspace: &mut OnePassCaptureWorkspace,
        haystack: &[u8],
        window: Window,
        span: Span,
        output: &mut [CaptureGroupSlot],
        limits: SearchLimits,
    ) -> Result<ExactCaptureSlotsOutcome, SearchError> {
        if !self
            .inner
            .program
            .authenticates_capture_program(program, semantic_digest)
            || output.len() != self.inner.group_count
            || workspace.plan_identity != self.inner.identity
            || workspace.slots.len() != self.inner.slot_count
            || workspace.slots.capacity() != self.inner.slot_count
        {
            return Err(SearchError::InvalidProgram);
        }
        let outcome = self.captures_exact_with_slots(
            workspace.slots.as_mut_slice(),
            workspace.usage.persistent_bytes,
            haystack,
            window,
            span,
            limits,
        )?;
        if outcome.matched {
            commit_capture_group_slots(
                program,
                workspace.slots.as_slice(),
                UNSET_SLOT,
                span,
                output,
            )?;
        } else {
            output.fill(CaptureGroupSlot::UNMATCHED);
        }
        Ok(outcome)
    }

    /// Try exact replay in a fixed stack workspace for schemas containing at
    /// most 32 tagged capture slots.
    ///
    /// `Ok(None)` is decided before source access when either the schema is
    /// wider or the caller cannot admit the complete 32-word stack buffer. A
    /// returned execution result charges that full buffer rather than only
    /// the used prefix.
    pub fn try_captures_exact_inline(
        &self,
        haystack: &[u8],
        window: Window,
        span: Span,
        limits: SearchLimits,
    ) -> Result<Option<SearchOutcome>, SearchError> {
        let inline_scratch_bytes = size_of::<[usize; INLINE_CAPTURE_SLOTS]>();
        let program = self
            .inner
            .program
            .shared()
            .ok_or(SearchError::InvalidProgram)?;
        if self.inner.slot_count > INLINE_CAPTURE_SLOTS
            || inline_scratch_bytes > limits.max_scratch_bytes
        {
            return Ok(None);
        }
        let mut slots = [UNSET_SLOT; INLINE_CAPTURE_SLOTS];
        let raw = self.captures_exact_with_slots(
            &mut slots[..self.inner.slot_count],
            inline_scratch_bytes,
            haystack,
            window,
            span,
            limits,
        )?;
        let captures = raw
            .matched
            .then(|| canonicalize_unset(program, &slots[..self.inner.slot_count], UNSET_SLOT))
            .transpose()?;
        Ok(Some(SearchOutcome {
            captures,
            report: raw.report,
        }))
    }

    #[allow(
        clippy::too_many_lines,
        reason = "pre-source admission and the complete deterministic replay stay auditable together"
    )]
    fn captures_exact_with_slots(
        &self,
        slots: &mut [usize],
        scratch_bytes: usize,
        haystack: &[u8],
        window: Window,
        span: Span,
        limits: SearchLimits,
    ) -> Result<ExactCaptureSlotsOutcome, SearchError> {
        if slots.len() != self.inner.slot_count {
            return Err(SearchError::InvalidProgram);
        }
        validate_window(haystack, window, span.start)?;
        if span.start > span.end || span.start < window.start || span.end > window.end {
            return Err(SearchError::InvalidWindow);
        }
        check(
            ResourceKind::ScratchBytes,
            scratch_bytes,
            limits.max_scratch_bytes,
        )?;
        let (length, base_state_visits, admitted_state_visits, admitted_slot_writes) =
            self.exact_work_bounds(span)?;
        check(
            ResourceKind::StateVisits,
            admitted_state_visits,
            limits.max_state_visits,
        )?;
        check(
            ResourceKind::SlotCopies,
            admitted_slot_writes,
            limits.max_slot_copies,
        )?;

        slots.fill(UNSET_SLOT);
        let mut state = self.inner.start;
        let mut slot_writes = 0_usize;
        let mut assertion_checks = 0_usize;
        let bytes = haystack
            .get(span.start..span.end)
            .ok_or(SearchError::InvalidWindow)?;
        for (&byte, position) in bytes.iter().zip(span.start..span.end) {
            let class = usize::from(self.inner.byte_class[usize::from(byte)]);
            let offset = usize::try_from(state)
                .ok()
                .and_then(|row| row.checked_add(class))
                .ok_or(SearchError::InvalidProgram)?;
            let transition = *self
                .inner
                .transitions
                .get(offset)
                .ok_or(SearchError::InvalidProgram)?;
            if transition.is_dead() {
                return Self::slots_none_at(
                    scratch_bytes,
                    span.start,
                    position,
                    slot_writes,
                    assertion_checks,
                );
            }
            if self.inner.direct_tag_masks {
                if transition.action != 0 {
                    apply_tag_mask(transition.action, slots, position, &mut slot_writes)?;
                }
            } else if transition.action != 0 {
                let action = self.action(transition.action)?;
                if !action_matches(action, haystack, window, position, &mut assertion_checks)? {
                    return Self::slots_none_at(
                        scratch_bytes,
                        span.start,
                        position,
                        slot_writes,
                        assertion_checks,
                    );
                }
                apply_tags(action, slots, position, &mut slot_writes)?;
            }
            state = transition.target_row();
        }

        let state_visits = base_state_visits
            .checked_add(assertion_checks)
            .ok_or(SearchError::BoundOverflow(ResourceKind::StateVisits))?;
        let bytes_examined = length;
        let position = span.end;
        let state = usize::try_from(state).map_err(|_| SearchError::InvalidProgram)?;
        let state = state
            .checked_div(self.inner.alphabet_len)
            .ok_or(SearchError::InvalidProgram)?;
        let dfa_state = self
            .inner
            .states
            .get(state)
            .ok_or(SearchError::InvalidProgram)?;
        if !dfa_state.is_match {
            return Ok(Self::slots_none(
                scratch_bytes,
                state_visits,
                slot_writes,
                bytes_examined,
            ));
        }
        if self.inner.direct_tag_masks {
            apply_tag_mask(dfa_state.match_action, slots, position, &mut slot_writes)?;
        } else {
            let action = self.action(dfa_state.match_action)?;
            if !action_matches(action, haystack, window, position, &mut assertion_checks)? {
                let state_visits = base_state_visits
                    .checked_add(assertion_checks)
                    .ok_or(SearchError::BoundOverflow(ResourceKind::StateVisits))?;
                return Ok(Self::slots_none(
                    scratch_bytes,
                    state_visits,
                    slot_writes,
                    bytes_examined,
                ));
            }
            apply_tags(action, slots, position, &mut slot_writes)?;
        }
        if slots.first().copied() != Some(span.start) || slots.get(1).copied() != Some(span.end) {
            return Err(SearchError::InvalidProgram);
        }
        let state_visits = base_state_visits
            .checked_add(assertion_checks)
            .ok_or(SearchError::BoundOverflow(ResourceKind::StateVisits))?;
        Ok(ExactCaptureSlotsOutcome {
            matched: true,
            report: Self::run_report(scratch_bytes, state_visits, slot_writes, bytes_examined),
        })
    }

    fn action(&self, id: u32) -> Result<&Action, SearchError> {
        self.inner
            .actions
            .get(usize::try_from(id).map_err(|_| SearchError::InvalidProgram)?)
            .ok_or(SearchError::InvalidProgram)
    }

    fn slots_none(
        scratch_bytes: usize,
        state_visits: usize,
        slot_writes: usize,
        bytes_examined: usize,
    ) -> ExactCaptureSlotsOutcome {
        ExactCaptureSlotsOutcome {
            matched: false,
            report: Self::run_report(scratch_bytes, state_visits, slot_writes, bytes_examined),
        }
    }

    fn slots_none_at(
        scratch_bytes: usize,
        start: usize,
        position: usize,
        slot_writes: usize,
        assertion_checks: usize,
    ) -> Result<ExactCaptureSlotsOutcome, SearchError> {
        let bytes_examined = position
            .checked_sub(start)
            .and_then(|length| length.checked_add(1))
            .ok_or(SearchError::BoundOverflow(ResourceKind::StateVisits))?;
        let state_visits = bytes_examined
            .checked_add(assertion_checks)
            .ok_or(SearchError::BoundOverflow(ResourceKind::StateVisits))?;
        Ok(Self::slots_none(
            scratch_bytes,
            state_visits,
            slot_writes,
            bytes_examined,
        ))
    }

    fn run_report(
        scratch_bytes: usize,
        state_visits: usize,
        slot_writes: usize,
        bytes_examined: usize,
    ) -> RunReport {
        RunReport {
            candidate: CandidateKind::OnePassCapture,
            state_visits,
            slot_copies: slot_writes,
            history_nodes: 0,
            history_walk: 0,
            starts_injected: 1,
            bytes_examined,
            peak_threads: 1,
            admitted_scratch_bytes: scratch_bytes,
        }
    }
}

impl OnePassCaptureWorkspace {
    /// Immutable plan identity to which this workspace is bound.
    #[must_use]
    pub const fn plan_identity(&self) -> u64 {
        self.plan_identity
    }

    /// Actual retained workspace bytes admitted during construction.
    #[must_use]
    pub const fn scratch_bytes(&self) -> usize {
        self.usage.persistent_bytes
    }

    /// Exact retained workspace dimensions admitted during construction.
    #[must_use]
    pub const fn usage(&self) -> OnePassCaptureWorkspaceUsage {
        self.usage
    }
}

impl OnePassCaptureSearchWorkspace {
    /// Immutable plan identity to which this workspace is bound.
    #[must_use]
    pub const fn plan_identity(&self) -> u64 {
        self.plan_identity
    }

    /// Actual retained workspace bytes admitted during construction.
    #[must_use]
    pub const fn scratch_bytes(&self) -> usize {
        self.usage.persistent_bytes
    }

    /// Exact retained workspace dimensions admitted during construction.
    #[must_use]
    pub const fn usage(&self) -> OnePassCaptureSearchWorkspaceUsage {
        self.usage
    }
}

#[inline]
fn action_matches(
    action: &Action,
    haystack: &[u8],
    window: Window,
    position: usize,
    assertion_checks: &mut usize,
) -> Result<bool, SearchError> {
    for &assertion in &action.assertions {
        *assertion_checks = checked_add(*assertion_checks, 1, ResourceKind::StateVisits)?;
        if !assertion_matches(assertion, haystack, window, position)? {
            return Ok(false);
        }
    }
    Ok(true)
}

#[inline]
fn apply_tags(
    action: &Action,
    slots: &mut [usize],
    position: usize,
    writes: &mut usize,
) -> Result<(), SearchError> {
    let next_writes = checked_add(*writes, action.tags.len(), ResourceKind::SlotCopies)?;
    match action.tags.len() {
        0 => {}
        1 => write_tag(slots, action.inline_tags[0], position)?,
        2 => {
            write_tag(slots, action.inline_tags[0], position)?;
            write_tag(slots, action.inline_tags[1], position)?;
        }
        _ => {
            for &slot in &action.tags {
                write_tag(slots, slot, position)?;
            }
        }
    }
    *writes = next_writes;
    Ok(())
}

#[inline]
fn write_tag(slots: &mut [usize], slot: u32, position: usize) -> Result<(), SearchError> {
    let slot = usize::try_from(slot).map_err(|_| SearchError::InvalidProgram)?;
    *slots.get_mut(slot).ok_or(SearchError::InvalidProgram)? = position;
    Ok(())
}

#[inline]
fn apply_tag_mask(
    mut mask: u32,
    slots: &mut [usize],
    position: usize,
    writes: &mut usize,
) -> Result<(), SearchError> {
    let tag_count = usize::try_from(mask.count_ones()).map_err(|_| SearchError::InvalidProgram)?;
    let next_writes = checked_add(*writes, tag_count, ResourceKind::SlotCopies)?;
    while mask != 0 {
        let slot = mask.trailing_zeros();
        write_tag(slots, slot, position)?;
        mask &= mask.wrapping_sub(1);
    }
    *writes = next_writes;
    Ok(())
}

#[derive(Debug)]
struct Completed {
    byte_class: [u8; BYTE_DOMAIN],
    alphabet_len: usize,
    start: u32,
    states: Vec<DfaState>,
    transitions: Vec<Transition>,
    actions: Vec<Action>,
    direct_tag_masks: bool,
    post_accept_live_tags_stable: bool,
    work: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Path {
    tags: Vec<u32>,
    assertions: Vec<Assertion>,
}

impl Path {
    const fn empty() -> Self {
        Self {
            tags: Vec::new(),
            assertions: Vec::new(),
        }
    }
}

#[derive(Debug)]
enum TerminalKind {
    Byte { pc: usize, next: usize },
    Match,
}

#[derive(Debug)]
struct Terminal {
    kind: TerminalKind,
    path: Path,
}

#[derive(Clone, Copy, Debug)]
enum CompiledTerminalKind {
    Byte { pc: usize, next: usize },
    Match,
}

#[derive(Clone, Copy, Debug)]
struct CompiledTerminal {
    kind: CompiledTerminalKind,
    action: u32,
}

#[derive(Debug)]
struct ByteClasses {
    map: [u8; BYTE_DOMAIN],
    representatives: Vec<u8>,
}

#[derive(Debug)]
struct Compiler<'a> {
    program: &'a Program,
    limits: OnePassCaptureBuildLimits,
    work: usize,
    byte_classes: ByteClasses,
    roots: Vec<usize>,
    state_by_pc: Vec<usize>,
    states: Vec<DfaState>,
    transitions: Vec<Transition>,
    actions: Vec<Action>,
    direct_tag_masks: bool,
}

impl<'a> Compiler<'a> {
    fn new(
        program: &'a Program,
        limits: OnePassCaptureBuildLimits,
    ) -> Result<Self, OnePassCaptureBuildFailure> {
        if program.states.is_empty()
            || program.start >= program.states.len()
            || program.slot_count == 0
            || !program.slot_count.is_multiple_of(2)
        {
            return Err(OnePassCaptureBuildFailure {
                source: OnePassCaptureBuildError::InvalidProgram("invalid tagged Thompson shape"),
                compile_work: 0,
            });
        }
        let empty_action = Path::empty();
        let base_immutable_bytes = immutable_bytes_with_extra(0, 0, &[], Some(&empty_action))
            .map_err(|source| OnePassCaptureBuildFailure {
                source,
                compile_work: 0,
            })?;
        enforce(
            OnePassCaptureBuildResource::ImmutableBytes,
            base_immutable_bytes,
            limits.max_program_bytes,
        )
        .map_err(|source| OnePassCaptureBuildFailure {
            source,
            compile_work: 0,
        })?;
        let mut state_by_pc = Vec::new();
        state_by_pc
            .try_reserve_exact(program.states.len())
            .map_err(|_| OnePassCaptureBuildFailure {
                source: allocation(OnePassCaptureBuildResource::CompileWork),
                compile_work: 0,
            })?;
        state_by_pc.resize(program.states.len(), usize::MAX);
        let mut compiler = Self {
            program,
            limits,
            work: 0,
            byte_classes: ByteClasses {
                map: [0; BYTE_DOMAIN],
                representatives: Vec::new(),
            },
            roots: Vec::new(),
            state_by_pc,
            states: Vec::new(),
            transitions: Vec::new(),
            actions: Vec::new(),
            direct_tag_masks: program.slot_count <= DIRECT_TAG_SLOT_LIMIT,
        };
        compiler.byte_classes =
            compiler
                .build_byte_classes()
                .map_err(|source| OnePassCaptureBuildFailure {
                    source,
                    compile_work: compiler.work,
                })?;
        compiler
            .actions
            .try_reserve(1)
            .map_err(|_| OnePassCaptureBuildFailure {
                source: allocation(OnePassCaptureBuildResource::ImmutableBytes),
                compile_work: compiler.work,
            })?;
        compiler.actions.push(Action::empty());
        debug_assert!(compiler.enforce_immutable_for(0, None).is_ok());
        Ok(compiler)
    }

    fn build(mut self) -> Result<Completed, OnePassCaptureBuildFailure> {
        let start = self
            .build_complete()
            .map_err(|source| OnePassCaptureBuildFailure {
                source,
                compile_work: self.work,
            })?;
        let post_accept_live_tags_stable = self.certify_post_accept_live_tags_stable();
        Ok(Completed {
            byte_class: self.byte_classes.map,
            alphabet_len: self.byte_classes.representatives.len(),
            start,
            states: self.states,
            transitions: self.transitions,
            actions: self.actions,
            direct_tag_masks: self.direct_tag_masks,
            post_accept_live_tags_stable,
            work: self.work,
        })
    }

    /// Optionally certify that no live capture tag can change after any DFA
    /// match state has been reached. The complete proof work is admitted
    /// before either temporary allocation. A missed work ceiling or
    /// allocation declines only this optimization and never a plan that the
    /// incumbent compiler already completed.
    fn certify_post_accept_live_tags_stable(&mut self) -> bool {
        let proof_work = match self
            .states
            .len()
            .checked_add(self.transitions.len())
            .and_then(|work| work.checked_add(1))
        {
            Some(work) => work,
            None => return false,
        };
        let Some(work_after) = self.work.checked_add(proof_work) else {
            return false;
        };
        if work_after > self.limits.max_compile_work {
            return false;
        }
        self.work = work_after;

        let mut reached = Vec::new();
        if reached.try_reserve_exact(self.states.len()).is_err() {
            return false;
        }
        reached.resize(self.states.len(), false);
        let mut pending = Vec::new();
        if pending.try_reserve_exact(self.states.len()).is_err() {
            return false;
        }
        for (state, dfa) in self.states.iter().enumerate() {
            if dfa.is_match {
                reached[state] = true;
                pending.push(state);
            }
        }
        while let Some(state) = pending.pop() {
            let Some(row) = state.checked_mul(self.byte_classes.representatives.len()) else {
                return false;
            };
            for class in 0..self.byte_classes.representatives.len() {
                let Some(transition) = row
                    .checked_add(class)
                    .and_then(|offset| self.transitions.get(offset))
                    .copied()
                else {
                    return false;
                };
                if transition.is_dead() {
                    continue;
                }
                let writes_tags = if self.direct_tag_masks {
                    transition.action != 0
                } else {
                    usize::try_from(transition.action)
                        .ok()
                        .and_then(|action| self.actions.get(action))
                        .is_none_or(|action| !action.tags.is_empty())
                };
                if writes_tags {
                    return false;
                }
                let Some(target) = usize::try_from(transition.target_row())
                    .ok()
                    .and_then(|target| target.checked_div(self.byte_classes.representatives.len()))
                    .filter(|&target| target < self.states.len())
                else {
                    return false;
                };
                if !reached[target] {
                    reached[target] = true;
                    pending.push(target);
                }
            }
        }
        true
    }

    fn build_complete(&mut self) -> Result<u32, OnePassCaptureBuildError> {
        let start = self.intern_state(self.program.start)?;
        let start = self.transition_row(start)?;
        let mut cursor = 0_usize;
        while cursor < self.roots.len() {
            let root = self.roots[cursor];
            let terminals = self.closure(root)?;
            let compiled = self.compile_terminals(terminals)?;
            let mut match_action = 0_u32;
            let mut is_match = false;
            for terminal in &compiled {
                self.charge(1)?;
                if matches!(terminal.kind, CompiledTerminalKind::Match) {
                    if is_match {
                        return Err(OnePassCaptureBuildError::NotOnePass(
                            OnePassCaptureRefusal::MultipleMatchPaths,
                        ));
                    }
                    is_match = true;
                    match_action = terminal.action;
                }
            }
            self.states
                .try_reserve(1)
                .map_err(|_| allocation(OnePassCaptureBuildResource::States))?;
            self.states.push(DfaState {
                match_action,
                is_match,
            });
            let class_count = self.byte_classes.representatives.len();
            self.transitions
                .try_reserve(class_count)
                .map_err(|_| allocation(OnePassCaptureBuildResource::ImmutableBytes))?;
            for class in 0..class_count {
                self.charge(1)?;
                let representative = self.byte_classes.representatives[class];
                let mut passed_match = false;
                let mut selected: Option<(usize, u32, bool)> = None;
                for terminal in &compiled {
                    self.charge(1)?;
                    let CompiledTerminalKind::Byte { pc, next } = terminal.kind else {
                        passed_match = true;
                        continue;
                    };
                    if !self.byte_state_matches(pc, representative)? {
                        continue;
                    }
                    match selected {
                        None => selected = Some((next, terminal.action, passed_match)),
                        // Exact replay already admitted duplicate byte paths
                        // with an identical continuation/action. Preserve the
                        // first (highest-priority) occurrence's match flag so
                        // adding search metadata does not narrow that API.
                        Some((old_next, old_action, _))
                            if (old_next, old_action) == (next, terminal.action) => {}
                        Some(_) => {
                            return Err(OnePassCaptureBuildError::NotOnePass(
                                OnePassCaptureRefusal::ConflictingTransition,
                            ));
                        }
                    }
                }
                let transition = if let Some((next, action, match_wins)) = selected {
                    let target = self.intern_state(next)?;
                    Transition::live(self.transition_row(target)?, action, match_wins)?
                } else {
                    Transition::DEAD
                };
                self.transitions.push(transition);
            }
            cursor = cursor
                .checked_add(1)
                .ok_or(OnePassCaptureBuildError::Overflow(
                    OnePassCaptureBuildResource::States,
                ))?;
        }
        if self.states.len() != self.roots.len() {
            return Err(OnePassCaptureBuildError::InvalidProgram(
                "one-pass state publication is incomplete",
            ));
        }
        let expected_transitions = self
            .states
            .len()
            .checked_mul(self.byte_classes.representatives.len())
            .ok_or(OnePassCaptureBuildError::Overflow(
                OnePassCaptureBuildResource::ImmutableBytes,
            ))?;
        if self.transitions.len() != expected_transitions {
            return Err(OnePassCaptureBuildError::InvalidProgram(
                "one-pass transition table is incomplete",
            ));
        }
        Ok(start)
    }

    fn build_byte_classes(&mut self) -> Result<ByteClasses, OnePassCaptureBuildError> {
        let mut boundaries = [false; BYTE_DOMAIN + 1];
        boundaries[0] = true;
        boundaries[BYTE_DOMAIN] = true;
        for state in &self.program.states {
            self.charge(1)?;
            if matches!(state, State::Assert { .. }) {
                self.direct_tag_masks = false;
            }
            if let State::Byte { ranges, .. } = state {
                for &(start, end) in ranges {
                    self.charge(1)?;
                    if start > end {
                        return Err(OnePassCaptureBuildError::InvalidProgram(
                            "byte range is reversed",
                        ));
                    }
                    boundaries[usize::from(start)] = true;
                    let after = usize::from(end).checked_add(1).ok_or(
                        OnePassCaptureBuildError::Overflow(
                            OnePassCaptureBuildResource::CompileWork,
                        ),
                    )?;
                    boundaries[after] = true;
                }
            }
        }
        let mut intervals = Vec::new();
        intervals
            .try_reserve(BYTE_DOMAIN)
            .map_err(|_| allocation(OnePassCaptureBuildResource::CompileWork))?;
        for (byte, &is_boundary) in boundaries.iter().take(BYTE_DOMAIN).enumerate() {
            self.charge(1)?;
            if is_boundary {
                intervals.push(u8::try_from(byte).map_err(|_| {
                    OnePassCaptureBuildError::InvalidProgram("byte boundary exceeds u8")
                })?);
            }
        }
        let mut representatives = Vec::new();
        representatives
            .try_reserve(intervals.len())
            .map_err(|_| allocation(OnePassCaptureBuildResource::CompileWork))?;
        let mut map = [0_u8; BYTE_DOMAIN];
        for (interval_index, &representative) in intervals.iter().enumerate() {
            let mut class = None;
            for (candidate, &old) in representatives.iter().enumerate() {
                if self.bytes_are_equivalent(representative, old)? {
                    class = Some(candidate);
                    break;
                }
            }
            let class = if let Some(class) = class {
                class
            } else {
                let class = representatives.len();
                if class >= BYTE_DOMAIN {
                    return Err(OnePassCaptureBuildError::InvalidProgram(
                        "byte-class count exceeds byte domain",
                    ));
                }
                representatives.push(representative);
                class
            };
            let next_interval =
                interval_index
                    .checked_add(1)
                    .ok_or(OnePassCaptureBuildError::Overflow(
                        OnePassCaptureBuildResource::CompileWork,
                    ))?;
            let end = intervals
                .get(next_interval)
                .map_or(BYTE_DOMAIN, |&next| usize::from(next));
            let class = u8::try_from(class).map_err(|_| {
                OnePassCaptureBuildError::InvalidProgram("byte-class ID exceeds u8")
            })?;
            for entry in map.iter_mut().take(end).skip(usize::from(representative)) {
                self.charge(1)?;
                *entry = class;
            }
        }
        if representatives.is_empty() {
            return Err(OnePassCaptureBuildError::InvalidProgram(
                "byte partition is empty",
            ));
        }
        Ok(ByteClasses {
            map,
            representatives,
        })
    }

    fn bytes_are_equivalent(
        &mut self,
        left: u8,
        right: u8,
    ) -> Result<bool, OnePassCaptureBuildError> {
        for state in &self.program.states {
            self.charge(1)?;
            let State::Byte { ranges, .. } = state else {
                continue;
            };
            if self.ranges_match(ranges, left)? != self.ranges_match(ranges, right)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn ranges_match(
        &mut self,
        ranges: &[(u8, u8)],
        byte: u8,
    ) -> Result<bool, OnePassCaptureBuildError> {
        for &(start, end) in ranges {
            self.charge(1)?;
            if start <= byte && byte <= end {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn byte_state_matches(
        &mut self,
        pc: usize,
        byte: u8,
    ) -> Result<bool, OnePassCaptureBuildError> {
        let State::Byte { ranges, .. } =
            self.program
                .states
                .get(pc)
                .ok_or(OnePassCaptureBuildError::InvalidProgram(
                    "byte terminal is outside program",
                ))?
        else {
            return Err(OnePassCaptureBuildError::InvalidProgram(
                "one-pass terminal is not a byte state",
            ));
        };
        self.ranges_match(ranges, byte)
    }

    fn intern_state(&mut self, pc: usize) -> Result<u32, OnePassCaptureBuildError> {
        let state = *self
            .state_by_pc
            .get(pc)
            .ok_or(OnePassCaptureBuildError::InvalidProgram(
                "one-pass root is outside program",
            ))?;
        if state != usize::MAX {
            return u32::try_from(state).map_err(|_| {
                OnePassCaptureBuildError::InvalidProgram("one-pass state ID exceeds u32")
            });
        }
        let required =
            self.roots
                .len()
                .checked_add(1)
                .ok_or(OnePassCaptureBuildError::Overflow(
                    OnePassCaptureBuildResource::States,
                ))?;
        enforce(
            OnePassCaptureBuildResource::States,
            required,
            self.limits.max_states,
        )?;
        if required > usize::try_from(u32::MAX).unwrap_or(usize::MAX) {
            return Err(OnePassCaptureBuildError::Resource {
                resource: OnePassCaptureBuildResource::States,
                required,
                limit: usize::try_from(u32::MAX).unwrap_or(usize::MAX),
            });
        }
        self.enforce_immutable_for(required, None)?;
        let transitions = required
            .checked_mul(self.byte_classes.representatives.len())
            .ok_or(OnePassCaptureBuildError::Overflow(
                OnePassCaptureBuildResource::ImmutableBytes,
            ))?;
        if transitions > usize::try_from(u32::MAX).unwrap_or(usize::MAX) {
            return Err(OnePassCaptureBuildError::Resource {
                resource: OnePassCaptureBuildResource::ImmutableBytes,
                required: transitions,
                limit: usize::try_from(u32::MAX).unwrap_or(usize::MAX),
            });
        }
        self.roots
            .try_reserve(1)
            .map_err(|_| allocation(OnePassCaptureBuildResource::States))?;
        let id = self.roots.len();
        self.roots.push(pc);
        *self
            .state_by_pc
            .get_mut(pc)
            .ok_or(OnePassCaptureBuildError::InvalidProgram(
                "one-pass root is outside program",
            ))? = id;
        u32::try_from(id)
            .map_err(|_| OnePassCaptureBuildError::InvalidProgram("one-pass state ID exceeds u32"))
    }

    fn transition_row(&self, state: u32) -> Result<u32, OnePassCaptureBuildError> {
        usize::try_from(state)
            .ok()
            .and_then(|state| state.checked_mul(self.byte_classes.representatives.len()))
            .and_then(|row| u32::try_from(row).ok())
            .ok_or(OnePassCaptureBuildError::InvalidProgram(
                "one-pass transition row exceeds u32",
            ))
    }

    fn closure(&mut self, start: usize) -> Result<Vec<Terminal>, OnePassCaptureBuildError> {
        let mut stack = Vec::new();
        stack
            .try_reserve(1)
            .map_err(|_| allocation(OnePassCaptureBuildResource::CompileWork))?;
        stack.push((start, Path::empty()));
        let mut seen = Vec::new();
        seen.try_reserve_exact(self.program.states.len())
            .map_err(|_| allocation(OnePassCaptureBuildResource::CompileWork))?;
        seen.resize(self.program.states.len(), false);
        let mut terminals = Vec::new();
        while let Some((pc, mut path)) = stack.pop() {
            self.charge(1)?;
            let marked = seen
                .get_mut(pc)
                .ok_or(OnePassCaptureBuildError::InvalidProgram(
                    "epsilon path is outside program",
                ))?;
            if *marked {
                return Err(OnePassCaptureBuildError::NotOnePass(
                    OnePassCaptureRefusal::MultipleEpsilonPaths,
                ));
            }
            *marked = true;
            match self
                .program
                .states
                .get(pc)
                .ok_or(OnePassCaptureBuildError::InvalidProgram(
                    "state is outside program",
                ))? {
                State::Byte { next, .. } => {
                    if *next >= self.program.states.len() {
                        return Err(OnePassCaptureBuildError::InvalidProgram(
                            "byte target is outside program",
                        ));
                    }
                    terminals
                        .try_reserve(1)
                        .map_err(|_| allocation(OnePassCaptureBuildResource::CompileWork))?;
                    terminals.push(Terminal {
                        kind: TerminalKind::Byte { pc, next: *next },
                        path,
                    });
                }
                State::Match => {
                    terminals
                        .try_reserve(1)
                        .map_err(|_| allocation(OnePassCaptureBuildResource::CompileWork))?;
                    terminals.push(Terminal {
                        kind: TerminalKind::Match,
                        path,
                    });
                }
                State::Fail => {}
                State::Epsilon { next } => stack.push((*next, path)),
                State::Assert { assertion, next } => {
                    path.assertions
                        .try_reserve(1)
                        .map_err(|_| allocation(OnePassCaptureBuildResource::ImmutableBytes))?;
                    path.assertions.push(*assertion);
                    stack.push((*next, path));
                }
                State::Save { slot, next, .. } => {
                    if *slot >= self.program.slot_count {
                        return Err(OnePassCaptureBuildError::InvalidProgram(
                            "capture slot is outside schema",
                        ));
                    }
                    let slot = u32::try_from(*slot).map_err(|_| {
                        OnePassCaptureBuildError::InvalidProgram("capture slot exceeds u32")
                    })?;
                    path.tags
                        .try_reserve(1)
                        .map_err(|_| allocation(OnePassCaptureBuildResource::ImmutableBytes))?;
                    path.tags.push(slot);
                    stack.push((*next, path));
                }
                State::Split { first, second } => {
                    let second_path = self.clone_path(&path)?;
                    stack
                        .try_reserve(2)
                        .map_err(|_| allocation(OnePassCaptureBuildResource::CompileWork))?;
                    stack.push((*second, second_path));
                    stack.push((*first, path));
                }
            }
        }
        Ok(terminals)
    }

    fn clone_path(&mut self, path: &Path) -> Result<Path, OnePassCaptureBuildError> {
        let copied = path
            .tags
            .len()
            .checked_add(path.assertions.len())
            .and_then(|items| items.checked_add(1))
            .ok_or(OnePassCaptureBuildError::Overflow(
                OnePassCaptureBuildResource::CompileWork,
            ))?;
        self.charge(copied)?;
        let mut tags = Vec::new();
        tags.try_reserve_exact(path.tags.len())
            .map_err(|_| allocation(OnePassCaptureBuildResource::CompileWork))?;
        tags.extend_from_slice(&path.tags);
        let mut assertions = Vec::new();
        assertions
            .try_reserve_exact(path.assertions.len())
            .map_err(|_| allocation(OnePassCaptureBuildResource::CompileWork))?;
        assertions.extend_from_slice(&path.assertions);
        Ok(Path { tags, assertions })
    }

    fn compile_terminals(
        &mut self,
        terminals: Vec<Terminal>,
    ) -> Result<Vec<CompiledTerminal>, OnePassCaptureBuildError> {
        let mut compiled = Vec::new();
        compiled
            .try_reserve_exact(terminals.len())
            .map_err(|_| allocation(OnePassCaptureBuildResource::CompileWork))?;
        for terminal in terminals {
            let action = self.intern_action(terminal.path)?;
            let action = self.execution_action(action)?;
            let kind = match terminal.kind {
                TerminalKind::Byte { pc, next } => CompiledTerminalKind::Byte { pc, next },
                TerminalKind::Match => CompiledTerminalKind::Match,
            };
            compiled.push(CompiledTerminal { kind, action });
        }
        Ok(compiled)
    }

    fn intern_action(&mut self, path: Path) -> Result<u32, OnePassCaptureBuildError> {
        for index in 0..self.actions.len() {
            let comparison_work = self.actions[index]
                .tags
                .len()
                .checked_add(self.actions[index].assertions.len())
                .and_then(|items| items.checked_add(path.tags.len()))
                .and_then(|items| items.checked_add(path.assertions.len()))
                .and_then(|items| items.checked_add(1))
                .ok_or(OnePassCaptureBuildError::Overflow(
                    OnePassCaptureBuildResource::CompileWork,
                ))?;
            self.charge(comparison_work)?;
            if self.actions[index].tags.as_ref() == path.tags.as_slice()
                && self.actions[index].assertions.as_ref() == path.assertions.as_slice()
            {
                return u32::try_from(index).map_err(|_| {
                    OnePassCaptureBuildError::InvalidProgram("action ID exceeds u32")
                });
            }
        }
        let required =
            self.actions
                .len()
                .checked_add(1)
                .ok_or(OnePassCaptureBuildError::Overflow(
                    OnePassCaptureBuildResource::ImmutableBytes,
                ))?;
        if required > usize::try_from(u32::MAX).unwrap_or(usize::MAX) {
            return Err(OnePassCaptureBuildError::Resource {
                resource: OnePassCaptureBuildResource::ImmutableBytes,
                required,
                limit: usize::try_from(u32::MAX).unwrap_or(usize::MAX),
            });
        }
        self.enforce_immutable_for(self.roots.len(), Some(&path))?;
        let direct_tag_mask = if self.direct_tag_masks {
            self.charge(path.tags.len())?;
            let mut mask = 0_u32;
            for &slot in &path.tags {
                let bit =
                    1_u32
                        .checked_shl(slot)
                        .ok_or(OnePassCaptureBuildError::InvalidProgram(
                            "direct one-pass capture slot exceeds mask width",
                        ))?;
                mask |= bit;
            }
            mask
        } else {
            0
        };
        self.actions
            .try_reserve(1)
            .map_err(|_| allocation(OnePassCaptureBuildResource::ImmutableBytes))?;
        let id = self.actions.len();
        self.actions.push(Action {
            inline_tags: [
                path.tags.first().copied().unwrap_or(0),
                path.tags.get(1).copied().unwrap_or(0),
            ],
            tags: path.tags.into_boxed_slice(),
            assertions: path.assertions.into_boxed_slice(),
            direct_tag_mask,
        });
        u32::try_from(id)
            .map_err(|_| OnePassCaptureBuildError::InvalidProgram("action ID exceeds u32"))
    }

    fn execution_action(&mut self, action: u32) -> Result<u32, OnePassCaptureBuildError> {
        if !self.direct_tag_masks {
            return Ok(action);
        }
        self.charge(1)?;
        self.actions
            .get(usize::try_from(action).map_err(|_| {
                OnePassCaptureBuildError::InvalidProgram("one-pass action ID exceeds usize")
            })?)
            .map(|action| action.direct_tag_mask)
            .ok_or(OnePassCaptureBuildError::InvalidProgram(
                "one-pass action is outside its table",
            ))
    }

    fn charge(&mut self, amount: usize) -> Result<(), OnePassCaptureBuildError> {
        let required = self
            .work
            .checked_add(amount)
            .ok_or(OnePassCaptureBuildError::Overflow(
                OnePassCaptureBuildResource::CompileWork,
            ))?;
        enforce(
            OnePassCaptureBuildResource::CompileWork,
            required,
            self.limits.max_compile_work,
        )?;
        self.work = required;
        Ok(())
    }

    fn enforce_immutable_for(
        &self,
        states: usize,
        extra_action: Option<&Path>,
    ) -> Result<(), OnePassCaptureBuildError> {
        let transitions = states
            .checked_mul(self.byte_classes.representatives.len())
            .ok_or(OnePassCaptureBuildError::Overflow(
                OnePassCaptureBuildResource::ImmutableBytes,
            ))?;
        let required =
            immutable_bytes_with_extra(states, transitions, &self.actions, extra_action)?;
        enforce(
            OnePassCaptureBuildResource::ImmutableBytes,
            required,
            self.limits.max_program_bytes,
        )
    }
}

fn immutable_bytes(
    states: usize,
    transitions: usize,
    actions: &[Action],
) -> Result<usize, OnePassCaptureBuildError> {
    immutable_bytes_with_extra(states, transitions, actions, None)
}

fn immutable_bytes_with_extra(
    states: usize,
    transitions: usize,
    actions: &[Action],
    extra_action: Option<&Path>,
) -> Result<usize, OnePassCaptureBuildError> {
    let state_bytes =
        states
            .checked_mul(size_of::<DfaState>())
            .ok_or(OnePassCaptureBuildError::Overflow(
                OnePassCaptureBuildResource::ImmutableBytes,
            ))?;
    let transition_bytes = transitions.checked_mul(size_of::<Transition>()).ok_or(
        OnePassCaptureBuildError::Overflow(OnePassCaptureBuildResource::ImmutableBytes),
    )?;
    let action_count = actions
        .len()
        .checked_add(usize::from(extra_action.is_some()))
        .ok_or(OnePassCaptureBuildError::Overflow(
            OnePassCaptureBuildResource::ImmutableBytes,
        ))?;
    let action_headers =
        action_count
            .checked_mul(size_of::<Action>())
            .ok_or(OnePassCaptureBuildError::Overflow(
                OnePassCaptureBuildResource::ImmutableBytes,
            ))?;
    let action_payload = actions.iter().try_fold(0_usize, |bytes, action| {
        let tags = action.tags.len().checked_mul(size_of::<u32>()).ok_or(
            OnePassCaptureBuildError::Overflow(OnePassCaptureBuildResource::ImmutableBytes),
        )?;
        let assertions = action
            .assertions
            .len()
            .checked_mul(size_of::<Assertion>())
            .ok_or(OnePassCaptureBuildError::Overflow(
                OnePassCaptureBuildResource::ImmutableBytes,
            ))?;
        bytes
            .checked_add(tags)
            .and_then(|bytes| bytes.checked_add(assertions))
            .ok_or(OnePassCaptureBuildError::Overflow(
                OnePassCaptureBuildResource::ImmutableBytes,
            ))
    })?;
    let action_payload = if let Some(path) = extra_action {
        let tags = path.tags.len().checked_mul(size_of::<u32>()).ok_or(
            OnePassCaptureBuildError::Overflow(OnePassCaptureBuildResource::ImmutableBytes),
        )?;
        let assertions = path
            .assertions
            .len()
            .checked_mul(size_of::<Assertion>())
            .ok_or(OnePassCaptureBuildError::Overflow(
                OnePassCaptureBuildResource::ImmutableBytes,
            ))?;
        action_payload
            .checked_add(tags)
            .and_then(|bytes| bytes.checked_add(assertions))
            .ok_or(OnePassCaptureBuildError::Overflow(
                OnePassCaptureBuildResource::ImmutableBytes,
            ))?
    } else {
        action_payload
    };
    size_of::<OnePassCaptureInner>()
        .checked_add(state_bytes)
        .and_then(|bytes| bytes.checked_add(transition_bytes))
        .and_then(|bytes| bytes.checked_add(action_headers))
        .and_then(|bytes| bytes.checked_add(action_payload))
        .ok_or(OnePassCaptureBuildError::Overflow(
            OnePassCaptureBuildResource::ImmutableBytes,
        ))
}

fn enforce(
    resource: OnePassCaptureBuildResource,
    required: usize,
    limit: usize,
) -> Result<(), OnePassCaptureBuildError> {
    if required > limit {
        return Err(OnePassCaptureBuildError::Resource {
            resource,
            required,
            limit,
        });
    }
    Ok(())
}

const fn allocation(resource: OnePassCaptureBuildResource) -> OnePassCaptureBuildError {
    OnePassCaptureBuildError::Allocation(resource)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{
        MATCH_WINS, OnePassCaptureBuildError, OnePassCaptureBuildLimits,
        OnePassCaptureBuildResource, OnePassCapturePlan, TARGET_ROW_MASK, Transition,
    };
    use crate::{Assertion, Ast, BuildLimits, Greed, Program};

    fn plan(ast: &Ast) -> OnePassCapturePlan {
        let program = Program::compile(ast, BuildLimits::default()).expect("compile fixture");
        OnePassCapturePlan::try_from_program(
            Arc::new(program),
            OnePassCaptureBuildLimits::default(),
        )
        .expect("build one-pass fixture")
    }

    #[test]
    fn packed_transition_rejects_the_dead_alias() {
        assert_eq!(
            Transition::live(TARGET_ROW_MASK, 0, true),
            Err(OnePassCaptureBuildError::Resource {
                resource: OnePassCaptureBuildResource::States,
                required: usize::try_from(TARGET_ROW_MASK).expect("target row fits usize"),
                limit: usize::try_from(TARGET_ROW_MASK - 1).expect("target row fits usize"),
            })
        );
        let largest_unflagged =
            Transition::live(TARGET_ROW_MASK, 0, false).expect("unflagged row is representable");
        assert!(!largest_unflagged.is_dead());
        assert_eq!(largest_unflagged.target_row(), TARGET_ROW_MASK);
        let largest_flagged = Transition::live(TARGET_ROW_MASK - 1, 0, true)
            .expect("largest flagged row is representable");
        assert!(!largest_flagged.is_dead());
        assert_eq!(largest_flagged.target, (TARGET_ROW_MASK - 1) | MATCH_WINS);
    }

    #[test]
    fn native_v1_view_is_closed_and_uses_state_indices() {
        let plan = plan(&Ast::concat([
            Ast::Byte(b'a').capture(1),
            Ast::Byte(b'b').repeat(0, None, Greed::Greedy).capture(2),
        ]));
        let view = plan
            .native_v1_view()
            .expect("assertion-free direct-tag view");
        assert_eq!(view.group_count(), 3);
        assert_eq!(view.tag_slot_count(), 6);
        assert_eq!(
            view.transition_count(),
            view.state_count() * view.alphabet_len()
        );
        assert!(usize::try_from(view.start_state()).unwrap() < view.state_count());
        assert!(
            view.byte_classes()
                .iter()
                .all(|&class| usize::from(class) < view.alphabet_len())
        );
        let action_limit = 1_u32 << u32::try_from(view.tag_slot_count()).unwrap();
        assert!(view.states().all(|state| state.match_action < action_limit));
        assert!(view.transitions().all(|transition| {
            transition.action < action_limit
                && (transition.target_state == u32::MAX
                    || usize::try_from(transition.target_state).unwrap() < view.state_count())
        }));
    }

    #[test]
    fn native_v1_view_declines_assertions_and_wide_tag_geometry() {
        let asserted = plan(&Ast::concat([
            Ast::Assert(Assertion::Start),
            Ast::Byte(b'a').capture(1),
        ]));
        assert!(asserted.native_v1_view().is_none());

        let wide = plan(&Ast::concat(
            (1..=16).map(|index| Ast::Byte(b'a').capture(index)),
        ));
        assert_eq!(wide.capture_group_count(), 17);
        assert!(wide.native_v1_view().is_none());
    }
}
