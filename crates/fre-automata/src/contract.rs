use core::marker::PhantomData;

use crate::{
    Automaton, K0ResumeSet, K0SearchSession, K0SpanSourceCursor, K0Workspace, SearchError,
    SearchLimits, SearchWindow,
};

/// The capture-free output promised by a prepared entry point.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum OutputContract {
    /// Whether a selected match exists.
    Exists,
    /// The ending byte offset at the first accepting search boundary.
    EarliestEnd,
    /// The ending byte offset of the selected match.
    SelectedEnd,
    /// The starting and ending byte offsets of the selected match.
    Span,
}

/// A half-open match in byte offsets relative to the original haystack.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MatchSpan {
    start: usize,
    end: usize,
}

impl MatchSpan {
    #[must_use]
    pub const fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    #[must_use]
    pub const fn start(self) -> usize {
        self.start
    }

    #[must_use]
    pub const fn end(self) -> usize {
        self.end
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.start == self.end
    }
}

/// Exact counters returned with every successful search invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchAccounting {
    work: u64,
    setup: SetupAccounting,
    transition_work: u64,
    scratch_bytes: usize,
    boundaries: usize,
}

impl SearchAccounting {
    pub(crate) const fn new(
        work: u64,
        setup: SetupAccounting,
        transition_work: u64,
        scratch_bytes: usize,
        boundaries: usize,
    ) -> Self {
        Self {
            work,
            setup,
            transition_work,
            scratch_bytes,
            boundaries,
        }
    }

    /// Total charged work: setup plus automaton transition work.
    #[must_use]
    pub const fn work(self) -> u64 {
        self.work
    }

    /// Workspace setup plus transactional retained-owner publication work.
    ///
    /// Retained owners are committed only after the search loop succeeds, but
    /// remain setup rather than transition work in this accounting split.
    #[must_use]
    pub const fn setup_work(self) -> u64 {
        self.setup.work()
    }

    /// Work charged while examining boundaries, states, and edges.
    #[must_use]
    pub const fn transition_work(self) -> u64 {
        self.transition_work
    }

    /// Allocation, initialization, and reuse charges for this call.
    #[must_use]
    pub const fn setup(self) -> SetupAccounting {
        self.setup
    }

    /// Heap payload bytes preflighted for this invocation.
    #[must_use]
    pub const fn scratch_bytes(self) -> usize {
        self.scratch_bytes
    }

    /// Candidate input boundaries expanded by the automaton loop.
    ///
    /// A start scanner can prove that no candidate exists without expanding a
    /// boundary, so a successful miss may report zero.
    #[must_use]
    pub const fn boundaries(self) -> usize {
        self.boundaries
    }
}

/// Auditable workspace setup and retained-owner preparation for one invocation.
///
/// `allocated_bytes` counts retained heap payload obtained during this call. It
/// is zero for a warm reusable-workspace call, while a cold reusable call may
/// retain one immutable plan-side proof. `initialized_bytes` counts payload
/// bytes logically written during construction, a generation-table reset, or
/// transactional proof publication. Such a proof is published only after the
/// execution loop succeeds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetupAccounting {
    pub(crate) work: u64,
    pub(crate) allocated_bytes: usize,
    pub(crate) initialized_bytes: usize,
    pub(crate) retained_bytes: usize,
    pub(crate) reused: bool,
}

impl SetupAccounting {
    pub(crate) const fn empty(retained_bytes: usize, reused: bool) -> Self {
        Self {
            work: 0,
            allocated_bytes: 0,
            initialized_bytes: 0,
            retained_bytes,
            reused,
        }
    }

    /// Logical setup operations charged to the hard work limit.
    #[must_use]
    pub const fn work(self) -> u64 {
        self.work
    }

    /// Heap payload bytes allocated and retained by this call.
    #[must_use]
    pub const fn allocated_bytes(self) -> usize {
        self.allocated_bytes
    }

    /// Payload bytes initialized or cleared by this call.
    #[must_use]
    pub const fn initialized_bytes(self) -> usize {
        self.initialized_bytes
    }

    /// Total heap payload bytes retained by the workspace used for this call.
    ///
    /// This excludes an immutable plan-side proof even when this invocation
    /// allocated it; that delta is visible through [`Self::allocated_bytes`].
    #[must_use]
    pub const fn retained_bytes(self) -> usize {
        self.retained_bytes
    }

    /// Whether the workspace existed before this search invocation.
    #[must_use]
    pub const fn reused(self) -> bool {
        self.reused
    }
}

/// A typed output paired with the work actually charged to produce it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchReport<T> {
    output: T,
    accounting: SearchAccounting,
}

impl<T> SearchReport<T> {
    pub(crate) const fn new(output: T, accounting: SearchAccounting) -> Self {
        Self { output, accounting }
    }

    #[must_use]
    pub fn output(&self) -> &T {
        &self.output
    }

    #[must_use]
    pub const fn accounting(&self) -> SearchAccounting {
        self.accounting
    }

    #[must_use]
    pub fn into_output(self) -> T {
        self.output
    }
}

mod sealed {
    pub trait Sealed {}
}

/// A sealed marker selecting one exact K0 output contract.
pub trait Operation: sealed::Sealed {
    type Output;

    const CONTRACT: OutputContract;

    #[doc(hidden)]
    fn project(found: Option<MatchSpan>) -> Self::Output;
}

/// Boolean existence operation.
///
/// Unlike the selected-end and span contracts, existence does not depend on
/// leftmost-first endpoint selection. The executor may therefore return at
/// the first accepting boundary even while a higher-priority thread remains
/// live.
#[derive(Clone, Copy, Debug, Default)]
pub struct Exists;

impl sealed::Sealed for Exists {}

impl Operation for Exists {
    type Output = bool;

    const CONTRACT: OutputContract = OutputContract::Exists;
    fn project(found: Option<MatchSpan>) -> Self::Output {
        found.is_some()
    }
}

/// End offset at the first boundary where the executor detects a match.
#[derive(Clone, Copy, Debug, Default)]
pub struct EarliestEnd;

impl sealed::Sealed for EarliestEnd {}

impl Operation for EarliestEnd {
    type Output = Option<usize>;

    const CONTRACT: OutputContract = OutputContract::EarliestEnd;
    fn project(found: Option<MatchSpan>) -> Self::Output {
        found.map(MatchSpan::end)
    }
}

/// End offset of the profile-selected leftmost-first match.
#[derive(Clone, Copy, Debug, Default)]
pub struct SelectedEnd;

impl sealed::Sealed for SelectedEnd {}

impl Operation for SelectedEnd {
    type Output = Option<usize>;

    const CONTRACT: OutputContract = OutputContract::SelectedEnd;
    fn project(found: Option<MatchSpan>) -> Self::Output {
        found.map(MatchSpan::end)
    }
}

/// Full span of the profile-selected leftmost-first match.
#[derive(Clone, Copy, Debug, Default)]
pub struct Span;

impl sealed::Sealed for Span {}

impl Operation for Span {
    type Output = Option<MatchSpan>;

    const CONTRACT: OutputContract = OutputContract::Span;
    fn project(found: Option<MatchSpan>) -> Self::Output {
        found
    }
}

/// An immutable automaton entry point whose output type cannot be confused
/// with another operation's output.
#[derive(Clone, Copy, Debug)]
pub struct TypedPlan<'a, O: Operation> {
    pub(crate) automaton: &'a Automaton,
    pub(crate) operation: PhantomData<O>,
}

impl<O: Operation> TypedPlan<'_, O> {
    #[must_use]
    pub const fn contract(&self) -> OutputContract {
        O::CONTRACT
    }

    /// Search the full haystack with the supplied hard limits.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] when scratch preflight, work accounting, or
    /// allocation fails. The executor never returns a partial match.
    pub fn search(
        &self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<SearchReport<O::Output>, SearchError> {
        self.search_window(haystack, SearchWindow::full(haystack), limits)
    }

    /// Search a byte range while evaluating assertions against the original
    /// haystack. Empty matches are permitted at `window.end()`.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] for an invalid window or when scratch preflight,
    /// work accounting, or allocation fails. The executor never returns a
    /// partial match.
    pub fn search_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<SearchReport<O::Output>, SearchError> {
        let report = crate::k0::search(self.automaton, haystack, window, limits, O::CONTRACT)?;
        Ok(SearchReport::new(
            O::project(report.found),
            report.accounting,
        ))
    }

    /// Search the full haystack using caller-owned, reusable fixed-capacity
    /// workspace. This method never allocates or grows the workspace.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] when the workspace was prepared for a different
    /// automaton shape, a hard limit is too low, or execution fails. A failed
    /// call may leave logical lengths non-zero; the next call resets them before
    /// reading any slot.
    pub fn search_with_workspace(
        &self,
        haystack: &[u8],
        workspace: &mut K0Workspace,
        limits: SearchLimits,
    ) -> Result<SearchReport<O::Output>, SearchError> {
        self.search_window_with_workspace(haystack, SearchWindow::full(haystack), workspace, limits)
    }

    /// Search a byte range using caller-owned, reusable fixed-capacity
    /// workspace. Assertions still inspect the original haystack.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] for an invalid range, incompatible workspace,
    /// insufficient hard limit, or execution failure. No allocation occurs.
    pub fn search_window_with_workspace(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        workspace: &mut K0Workspace,
        limits: SearchLimits,
    ) -> Result<SearchReport<O::Output>, SearchError> {
        let report = crate::k0::search_with_workspace(
            self.automaton,
            haystack,
            window,
            workspace,
            limits,
            O::CONTRACT,
        )?;
        Ok(SearchReport::new(
            O::project(report.found),
            report.accounting,
        ))
    }

    /// Search through a workspace that the caller has already bound to this
    /// exact immutable automaton.
    ///
    /// This entry is reserved for facades that retain their own stronger
    /// semantic identity check. It preserves window, resource, reset, and
    /// accounting validation while reusing the authenticated workspace shape
    /// and lazy capabilities. A workspace allocated for another immutable
    /// automaton takes the ordinary fully validated path, preserving support
    /// for independently constructed but semantically identical programs.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] for an invalid range, an incompatible workspace
    /// shape, insufficient hard limits, or an execution failure.
    #[doc(hidden)]
    pub fn search_window_with_authenticated_workspace(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        workspace: &mut K0Workspace,
        limits: SearchLimits,
    ) -> Result<SearchReport<O::Output>, SearchError> {
        let report = crate::k0::search_with_authenticated_workspace(
            self.automaton,
            haystack,
            window,
            workspace,
            limits,
            O::CONTRACT,
        )?;
        Ok(SearchReport::new(
            O::project(report.found),
            report.accounting,
        ))
    }

    /// Search through an authenticated workspace after the facade has already
    /// validated the supplied window against `haystack`.
    ///
    /// This is the same identity-preserving bridge as
    /// [`Self::search_window_with_authenticated_workspace`], except that an
    /// exact automaton/workspace pair reuses the caller's range proof. A
    /// workspace from an independently constructed semantic clone still takes
    /// the ordinary fully validated workspace path.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] for an incompatible workspace shape,
    /// insufficient hard limits, or an execution failure. Supplying an invalid
    /// window violates this facade-only entry's precondition.
    #[doc(hidden)]
    pub fn search_prevalidated_window_with_authenticated_workspace(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        workspace: &mut K0Workspace,
        limits: SearchLimits,
    ) -> Result<SearchReport<O::Output>, SearchError> {
        let report = crate::k0::search_prevalidated_window_with_authenticated_workspace(
            self.automaton,
            haystack,
            window,
            workspace,
            limits,
            O::CONTRACT,
        )?;
        Ok(SearchReport::new(
            O::project(report.found),
            report.accounting,
        ))
    }

    /// Replay the ordered automaton from exactly the first boundary of a
    /// caller-validated window.
    ///
    /// Unlike an ordinary search, this entry never injects a new start after
    /// `window.start()`. It is reserved for facades that carry an independent
    /// graph proof that the globally selected match begins at that boundary.
    /// Assertions still inspect the original `haystack`, and ordered
    /// alternation plus greedy/lazy priority remain authoritative for the
    /// selected endpoint.
    ///
    /// This bridge does not trust the proof for memory safety: a false proof
    /// simply produces no match. The exact automaton/workspace identity and
    /// the caller's prevalidated window retain the same contract as
    /// [`Self::search_prevalidated_window_with_authenticated_workspace`].
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] for an incompatible workspace shape,
    /// insufficient hard limits, or an execution failure. Supplying an invalid
    /// window violates this facade-only entry's precondition.
    #[doc(hidden)]
    pub fn search_prevalidated_exact_start_with_authenticated_workspace(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        workspace: &mut K0Workspace,
        limits: SearchLimits,
    ) -> Result<SearchReport<O::Output>, SearchError> {
        let report = crate::k0::search_prevalidated_exact_start_with_authenticated_workspace(
            self.automaton,
            haystack,
            window,
            workspace,
            limits,
            O::CONTRACT,
        )?;
        Ok(SearchReport::new(
            O::project(report.found),
            report.accounting,
        ))
    }

    /// Replay a caller-proved matching start through ordered lazy rows when
    /// their assertion-free route is available.
    ///
    /// This is the stronger counterpart to
    /// [`Self::search_prevalidated_exact_start_with_authenticated_workspace`]:
    /// the facade must prove both that `window.start()` is globally earliest
    /// and that a match beginning there exists. That proof makes every later
    /// root carried by an ordinary ordered lazy row permanently lower
    /// priority, so K0 may omit source-start bookkeeping while it selects the
    /// exact start's greedy/lazy endpoint. Unsupported contracts and
    /// assertion-bearing graphs retain the exact-start Pike route.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] for an incompatible workspace shape,
    /// insufficient hard limits, or an execution failure. Supplying an invalid
    /// window or a false matching-start proof violates this facade-only
    /// entry's precondition.
    #[doc(hidden)]
    pub fn search_prevalidated_proved_exact_start_with_authenticated_workspace(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        workspace: &mut K0Workspace,
        limits: SearchLimits,
    ) -> Result<SearchReport<O::Output>, SearchError> {
        let report =
            crate::k0::search_prevalidated_proved_exact_start_with_authenticated_workspace(
                self.automaton,
                haystack,
                window,
                workspace,
                limits,
                O::CONTRACT,
            )?;
        Ok(SearchReport::new(
            O::project(report.found),
            report.accounting,
        ))
    }

    /// Continue from one authenticated ordered consuming frontier at an
    /// already-consumed byte boundary.
    ///
    /// The original `window` remains authoritative for assertion-independent
    /// unanchored semantics and span start recovery. `resume_position` is the
    /// first unconsumed byte. `pending_end` must be present exactly when the
    /// selected frontier's pending mode is set, and must identify the most
    /// recent accepted boundary in the consumed prefix.
    ///
    /// This entry is reserved for a producer that canonically authenticates
    /// frontier reachability, such as the AOT partial ordered-DFA executor.
    /// K0 validates graph binding and state shape again before continuation.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] for an invalid window, mismatched resume state,
    /// incompatible workspace, hard-limit refusal, or execution failure.
    #[doc(hidden)]
    #[allow(
        clippy::too_many_arguments,
        reason = "the resume boundary keeps its original window and committed prefix explicit"
    )]
    pub fn search_window_from_ordered_resume(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        workspace: &mut K0Workspace,
        resume_set: &mut K0ResumeSet,
        resume_state: usize,
        resume_position: usize,
        pending_end: Option<usize>,
        limits: SearchLimits,
    ) -> Result<SearchReport<O::Output>, SearchError> {
        let report = crate::k0::search_from_resume_with_workspace(
            self.automaton,
            haystack,
            window,
            workspace,
            resume_set,
            resume_state,
            resume_position,
            pending_end,
            limits,
            O::CONTRACT,
        )?;
        Ok(SearchReport::new(
            O::project(report.found),
            report.accounting,
        ))
    }
}

impl TypedPlan<'_, Exists> {
    /// Return only existence through a caller-validated, authenticated
    /// workspace. Unlimited warm calls may read completed lazy rows without
    /// constructing accounting that this value-only facade discards. A direct
    /// row's first unavailable transition hands off mutably at that exact byte
    /// without replaying its already-filled prefix. The continuation may use a
    /// retained loop proof or attempt publication when needed and capacity
    /// permits it.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same contract as
    /// [`TypedPlan::search_prevalidated_window_with_authenticated_workspace`].
    /// Supplying an invalid window violates this facade-only entry's
    /// precondition.
    #[doc(hidden)]
    pub fn search_prevalidated_exists_value_with_authenticated_workspace(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        workspace: &mut K0Workspace,
        limits: SearchLimits,
    ) -> Result<bool, SearchError> {
        crate::k0::search_prevalidated_exists_value_with_authenticated_workspace(
            self.automaton,
            haystack,
            window,
            workspace,
            limits,
        )
    }

    /// Return only existence after one authenticated ordered frontier has
    /// already consumed the prefix ending at `resume_position`.
    ///
    /// Unlimited warm calls may read a content-checked cached resume row and
    /// its filled successors without constructing diagnostic accounting. An
    /// unavailable hint re-enters the ordinary exact resume executor; an
    /// unfilled successor hands its exact row, source position, and pending
    /// endpoint to mutable execution without replaying the filled prefix.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same resume, window, workspace, and
    /// limit contract as [`TypedPlan::search_window_from_ordered_resume`].
    #[doc(hidden)]
    #[allow(
        clippy::too_many_arguments,
        reason = "the value-only resume boundary keeps its committed prefix explicit"
    )]
    pub fn search_prevalidated_exists_value_from_ordered_resume_with_authenticated_workspace(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        workspace: &mut K0Workspace,
        resume_set: &mut K0ResumeSet,
        resume_state: usize,
        resume_position: usize,
        pending_end: Option<usize>,
        limits: SearchLimits,
    ) -> Result<bool, SearchError> {
        crate::k0::search_prevalidated_exists_value_from_ordered_resume_with_authenticated_workspace(
            self.automaton,
            haystack,
            window,
            workspace,
            resume_set,
            resume_state,
            resume_position,
            pending_end,
            limits,
        )
    }
}

impl TypedPlan<'_, SelectedEnd> {
    /// Return only the selected endpoint through an authenticated,
    /// caller-validated workspace.
    ///
    /// An unlimited exact-identity call may read already-filled forward rows
    /// without constructing diagnostic accounting. Its first unavailable
    /// direct transition can continue mutably at that exact byte without
    /// replaying the filled prefix. Every finite, cold, contextual,
    /// unauthenticated, or otherwise ineligible case uses the ordinary
    /// report-producing executor with unchanged error behavior.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] for an incompatible workspace, hard-limit
    /// refusal, or execution failure. Supplying an invalid window violates
    /// this facade-only entry's precondition.
    #[doc(hidden)]
    pub fn search_prevalidated_selected_end_value_with_authenticated_workspace(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        workspace: &mut K0Workspace,
        limits: SearchLimits,
    ) -> Result<Option<usize>, SearchError> {
        crate::k0::search_prevalidated_selected_end_value_with_authenticated_workspace(
            self.automaton,
            haystack,
            window,
            workspace,
            limits,
        )
    }

    /// Return only the selected endpoint after one authenticated ordered
    /// frontier has already consumed the prefix ending at `resume_position`.
    ///
    /// An unlimited warm call may complete through immutable filled lazy rows
    /// after content-checking the cached frontier hint. Its first unfilled row
    /// continues mutably at that exact byte without replay. Cold, finite-limit,
    /// and incompatible cases use the ordinary resume executor.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same resume, window, workspace, and
    /// limit contract as [`TypedPlan::search_window_from_ordered_resume`].
    #[doc(hidden)]
    #[allow(
        clippy::too_many_arguments,
        reason = "the value-only resume boundary keeps its committed prefix explicit"
    )]
    pub fn search_prevalidated_selected_end_value_from_ordered_resume_with_authenticated_workspace(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        workspace: &mut K0Workspace,
        resume_set: &mut K0ResumeSet,
        resume_state: usize,
        resume_position: usize,
        pending_end: Option<usize>,
        limits: SearchLimits,
    ) -> Result<Option<usize>, SearchError> {
        crate::k0::search_prevalidated_selected_end_value_from_ordered_resume_with_authenticated_workspace(
            self.automaton,
            haystack,
            window,
            workspace,
            resume_set,
            resume_state,
            resume_position,
            pending_end,
            limits,
        )
    }

    /// Return the selected endpoint for an authenticated matching start.
    ///
    /// An unlimited exact-identity call may read already-filled forward rows
    /// without constructing diagnostic accounting. The facade must prove that
    /// `window.start()` is both globally earliest and the start of a match.
    /// Every cold, finite, contextual, incomplete-cache, or unauthenticated
    /// case uses the ordinary proved-start executor.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] for an incompatible workspace, hard-limit
    /// refusal, or execution failure. An invalid window or false matching-start
    /// proof violates this facade-only entry's precondition.
    #[doc(hidden)]
    pub fn search_prevalidated_proved_exact_start_selected_end_value_with_authenticated_workspace(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        workspace: &mut K0Workspace,
        limits: SearchLimits,
    ) -> Result<Option<usize>, SearchError> {
        crate::k0::search_prevalidated_proved_exact_start_selected_end_value_with_authenticated_workspace(
            self.automaton,
            haystack,
            window,
            workspace,
            limits,
        )
    }
}

impl TypedPlan<'_, Span> {
    /// Return only a selected span through an authenticated, caller-validated
    /// workspace.
    ///
    /// An unlimited exact-identity call may use already-filled forward and
    /// reverse rows without constructing diagnostic accounting. Every finite,
    /// cold, contextual, unfilled, or unauthenticated case uses the ordinary
    /// report-producing executor with unchanged error behavior.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] for an incompatible workspace, hard-limit
    /// refusal, or execution failure. Supplying an invalid window violates
    /// this facade-only entry's precondition.
    #[doc(hidden)]
    pub fn search_prevalidated_span_value_with_authenticated_workspace(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        workspace: &mut K0Workspace,
        limits: SearchLimits,
    ) -> Result<Option<MatchSpan>, SearchError> {
        crate::k0::search_prevalidated_span_value_with_authenticated_workspace(
            self.automaton,
            haystack,
            window,
            workspace,
            limits,
        )
    }

    /// Return only the selected span after one authenticated ordered frontier
    /// has already consumed the prefix ending at `resume_position`.
    ///
    /// Unlimited warm calls may pair a content-checked filled forward resume
    /// row with filled reverse rows without constructing diagnostic
    /// accounting. The first unfilled forward or reverse row continues at its
    /// exact cached frontier without replaying either completed prefix. Cold,
    /// finite-limit, and incompatible cases use the ordinary bidirectional
    /// resume executor.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same resume, window, workspace, and
    /// limit contract as [`TypedPlan::search_window_from_ordered_resume`].
    #[doc(hidden)]
    #[allow(
        clippy::too_many_arguments,
        reason = "the value-only Span resume boundary keeps its committed prefix explicit"
    )]
    pub fn search_prevalidated_span_value_from_ordered_resume_with_authenticated_workspace(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        workspace: &mut K0Workspace,
        resume_set: &mut K0ResumeSet,
        resume_state: usize,
        resume_position: usize,
        pending_end: Option<usize>,
        limits: SearchLimits,
    ) -> Result<Option<MatchSpan>, SearchError> {
        crate::k0::search_prevalidated_span_value_from_ordered_resume_with_authenticated_workspace(
            self.automaton,
            haystack,
            window,
            workspace,
            resume_set,
            resume_state,
            resume_position,
            pending_end,
            limits,
        )
    }

    /// Recover a span from one already authenticated selected endpoint.
    ///
    /// This entry runs only K0's reverse machine. `selected_end` must be the
    /// exact leftmost-first endpoint previously produced for `window` by an
    /// ordered forward executor over this same immutable automaton. The
    /// caller-owned workspace must be bound to it and must retain reverse
    /// storage whenever the endpoint follows the window start.
    ///
    /// This facade-only bridge exists for exact partial-DFA producers. It
    /// retains the ordinary hard work, scratch, reset, and accounting
    /// contracts and performs no allocation during the prepared call.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] for an invalid range or endpoint, incompatible
    /// workspace, hard-limit refusal, or reverse execution failure.
    #[doc(hidden)]
    pub fn recover_span_from_selected_end_with_workspace(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        workspace: &mut K0Workspace,
        selected_end: usize,
        limits: SearchLimits,
    ) -> Result<SearchReport<MatchSpan>, SearchError> {
        let report = crate::k0::recover_span_from_selected_end_with_workspace(
            self.automaton,
            haystack,
            window,
            workspace,
            selected_end,
            limits,
        )?;
        let span = report.found.ok_or(SearchError::InternalInvariant {
            detail: "selected-end reverse recovery returned no span",
        })?;
        Ok(SearchReport::new(span, report.accounting))
    }

    /// Search a complete-haystack suffix in one non-overlapping traversal.
    ///
    /// The workspace retains source-independent span invocation facts after
    /// the first call. The original haystack remains intact so assertions
    /// inspect the same context as [`Self::search_window_with_workspace`].
    /// Logical reset, generation-rollover preflight, work limits, and result
    /// accounting still apply independently to every suffix search.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same range, workspace, and resource
    /// contract as [`Self::search_window_with_workspace`].
    #[doc(hidden)]
    pub fn search_at_with_workspace_cursor(
        &self,
        haystack: &[u8],
        start: usize,
        workspace: &mut K0Workspace,
        limits: SearchLimits,
    ) -> Result<SearchReport<Option<MatchSpan>>, SearchError> {
        let report = crate::k0::search_span_with_workspace_cursor(
            self.automaton,
            haystack,
            start,
            workspace,
            limits,
        )?;
        Ok(SearchReport::new(report.found, report.accounting))
    }
}

impl K0SearchSession<'_> {
    /// Search the full haystack under one typed output contract.
    ///
    /// The session is permanently bound to the immutable automaton that
    /// constructed its workspace. Per-call range, work, scratch, reset, and
    /// accounting checks remain identical to the caller-owned workspace API.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] for a hard-limit refusal or execution failure.
    pub fn search<O: Operation>(
        &mut self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<SearchReport<O::Output>, SearchError> {
        self.search_window::<O>(haystack, SearchWindow::full(haystack), limits)
    }

    /// Search a byte range under one typed output contract.
    ///
    /// Assertions inspect the complete original haystack. The range is
    /// validated on every call even though graph and workspace compatibility
    /// were authenticated during construction.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] for an invalid range, a hard-limit refusal, or
    /// execution failure.
    pub fn search_window<O: Operation>(
        &mut self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<SearchReport<O::Output>, SearchError> {
        let report = self.search_window_untyped(haystack, window, limits, O::CONTRACT)?;
        Ok(SearchReport::new(
            O::project(report.found),
            report.accounting,
        ))
    }

    /// Return only existence, allowing an authenticated warm session to omit
    /// diagnostic report construction for unlimited value-only calls.
    ///
    /// Finite limits and every cold or structurally ineligible invocation use
    /// the ordinary report-producing executor with unchanged accounting and
    /// error precedence.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] for an invalid range, a hard-limit refusal, or
    /// execution failure.
    #[doc(hidden)]
    pub fn search_exists_value(
        &mut self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<bool, SearchError> {
        self.search_exists_value_untyped(haystack, window, limits)
    }

    /// Return only the selected endpoint, allowing an authenticated warm
    /// session to omit diagnostic report construction for unlimited calls.
    ///
    /// Finite limits and every cold, contextual, or otherwise ineligible call
    /// use the ordinary report-producing executor with unchanged accounting
    /// and error precedence.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] for an invalid range, a hard-limit refusal, or
    /// execution failure.
    #[doc(hidden)]
    pub fn search_selected_end_value(
        &mut self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<Option<usize>, SearchError> {
        self.search_selected_end_value_untyped(haystack, window, limits)
    }

    /// Return only a Span, allowing an authenticated warm bidirectional
    /// session to omit diagnostic construction and recover an unknown start
    /// through already-filled reverse DFA rows.
    ///
    /// Finite limits and every cold, contextual, or incomplete-cache call use
    /// the ordinary report-producing executor with unchanged resource and
    /// error behavior.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] for an invalid range, a hard-limit refusal, or
    /// execution failure.
    #[doc(hidden)]
    pub fn search_span_value(
        &mut self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<Option<MatchSpan>, SearchError> {
        self.search_span_value_untyped(haystack, window, limits)
    }

    /// Search a complete-haystack suffix with retained source-independent
    /// span cursor facts.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same range and resource contract as
    /// [`Self::search_window`].
    #[doc(hidden)]
    #[inline]
    pub fn search_span_at_cursor(
        &mut self,
        haystack: &[u8],
        start: usize,
        limits: SearchLimits,
    ) -> Result<SearchReport<Option<MatchSpan>>, SearchError> {
        let mut source = K0SpanSourceCursor::new(haystack);
        self.search_span_at_source_cursor(&mut source, start, limits)
    }

    /// Search one suffix while retaining masks tied to this exact source
    /// borrow. This entry is reserved for a lifetime-bound match iterator.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same range and resource contract as
    /// [`Self::search_window`].
    #[doc(hidden)]
    #[inline]
    pub fn search_span_at_source_cursor(
        &mut self,
        source: &mut K0SpanSourceCursor<'_>,
        start: usize,
        limits: SearchLimits,
    ) -> Result<SearchReport<Option<MatchSpan>>, SearchError> {
        let report = self.search_span_at_untyped(source, start, limits)?;
        Ok(SearchReport::new(report.found, report.accounting))
    }
}
