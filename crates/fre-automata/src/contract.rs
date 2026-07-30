use core::marker::PhantomData;

use crate::{Automaton, K0SearchSession, K0Workspace, SearchError, SearchLimits, SearchWindow};

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
}

impl TypedPlan<'_, Span> {
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

    /// Search a complete-haystack suffix with retained span cursor facts.
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
        let report = self.search_span_at_untyped(haystack, start, limits)?;
        Ok(SearchReport::new(report.found, report.accounting))
    }
}
