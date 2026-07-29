use core::marker::PhantomData;

use crate::{Automaton, K0Workspace, SearchError, SearchLimits, SearchWindow};

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

    /// Work charged before the first automaton transition.
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

/// Auditable workspace setup performed before an execution loop starts.
///
/// `allocated_bytes` counts retained heap payload obtained during this call;
/// it is zero for a reusable-workspace call. `initialized_bytes` counts payload
/// bytes logically written during construction or a generation-table reset.
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
    const EARLIEST: bool;

    #[doc(hidden)]
    fn project(found: Option<MatchSpan>) -> Self::Output;
}

/// Boolean existence operation.
#[derive(Clone, Copy, Debug, Default)]
pub struct Exists;

impl sealed::Sealed for Exists {}

impl Operation for Exists {
    type Output = bool;

    const CONTRACT: OutputContract = OutputContract::Exists;
    const EARLIEST: bool = false;

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
    const EARLIEST: bool = true;

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
    const EARLIEST: bool = false;

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
    const EARLIEST: bool = false;

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
        let report = crate::k0::search(self.automaton, haystack, window, limits, O::EARLIEST)?;
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
            O::EARLIEST,
        )?;
        Ok(SearchReport::new(
            O::project(report.found),
            report.accounting,
        ))
    }
}
