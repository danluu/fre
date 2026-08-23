use core::marker::PhantomData;

use crate::{
    Automaton, DynamicDirectHoleResolution, K0FullyPrefilledResumeCacheReceipt, K0ResumeSet,
    K0SearchSession, K0SpanSourceCursor, K0Workspace, SearchError, SearchLimits, SearchWindow,
    WorkspaceLimits,
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

/// Whether a compiler-private value was decided entirely by immutable warm
/// rows already retained in the authenticated workspace.
///
/// Ordered-resume and contextual ordinary-value callers use this receipt to
/// distinguish a true warm completion from a call that had to publish or
/// recover any row. It is deliberately independent of the selected output
/// value: a warm no-match is still a complete warm execution.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum K0OrderedResumeCompletion {
    FullyWarmRows,
    NotFullyWarm,
}

/// A compiler-private value-only result paired with its warm-row completion
/// status. The historical type name is retained for API stability.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct K0OrderedResumeValue<T> {
    output: T,
    completion: K0OrderedResumeCompletion,
}

impl<T> K0OrderedResumeValue<T> {
    pub(crate) const fn new(output: T, completion: K0OrderedResumeCompletion) -> Self {
        Self { output, completion }
    }

    #[doc(hidden)]
    #[must_use]
    pub const fn completion(&self) -> K0OrderedResumeCompletion {
        self.completion
    }

    #[doc(hidden)]
    #[must_use]
    pub fn into_output(self) -> T {
        self.output
    }

    #[doc(hidden)]
    #[must_use]
    pub fn into_parts(self) -> (T, K0OrderedResumeCompletion) {
        (self.output, self.completion)
    }
}

/// Demand-grown cache resources observed during one successful invocation.
///
/// This ledger is separate from [`SetupAccounting`]: it covers cache storage
/// obtained or initialized after source-free setup, while the automaton is
/// executing. Its event boundary is logical rather than allocator-specific.
/// One event is one executor-reported demand-growth transaction that
/// successfully allocates or initializes payload. A transaction may allocate
/// several buffers, and a request rejected before obtaining or initializing
/// payload is not an event. Staged payload that is subsequently discarded is
/// still counted by `allocated_bytes` and `initialized_bytes`.
///
/// `peak_scratch_bytes` is an observed high-water mark: it counts all scratch
/// payload simultaneously live during an accounted growth event, including
/// payload retained before the call and staged replacement storage. This can
/// exceed [`SearchAccounting::scratch_bytes`], which reports only payload
/// retained when the successful call completes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CacheGrowthAccounting {
    events: usize,
    allocated_bytes: usize,
    initialized_bytes: usize,
    retained_delta: usize,
    peak_scratch_bytes: usize,
}

#[allow(
    dead_code,
    reason = "cache construction and accumulation precede demand-grown executor integration"
)]
impl CacheGrowthAccounting {
    pub(crate) const fn empty() -> Self {
        Self {
            events: 0,
            allocated_bytes: 0,
            initialized_bytes: 0,
            retained_delta: 0,
            peak_scratch_bytes: 0,
        }
    }

    pub(crate) const fn new(
        events: usize,
        allocated_bytes: usize,
        initialized_bytes: usize,
        retained_delta: usize,
        peak_scratch_bytes: usize,
    ) -> Self {
        Self {
            events,
            allocated_bytes,
            initialized_bytes,
            retained_delta,
            peak_scratch_bytes,
        }
    }

    pub(crate) const fn event(
        allocated_bytes: usize,
        initialized_bytes: usize,
        retained_delta: usize,
        peak_scratch_bytes: usize,
    ) -> Self {
        Self::new(
            1,
            allocated_bytes,
            initialized_bytes,
            retained_delta,
            peak_scratch_bytes,
        )
    }

    /// Add another aggregate without partially updating on overflow.
    pub(crate) fn checked_accumulate(&mut self, additional: Self) -> bool {
        let Some(events) = self.events.checked_add(additional.events) else {
            return false;
        };
        let Some(allocated_bytes) = self.allocated_bytes.checked_add(additional.allocated_bytes)
        else {
            return false;
        };
        let Some(initialized_bytes) = self
            .initialized_bytes
            .checked_add(additional.initialized_bytes)
        else {
            return false;
        };
        let Some(retained_delta) = self.retained_delta.checked_add(additional.retained_delta)
        else {
            return false;
        };
        *self = Self {
            events,
            allocated_bytes,
            initialized_bytes,
            retained_delta,
            peak_scratch_bytes: self.peak_scratch_bytes.max(additional.peak_scratch_bytes),
        };
        true
    }

    /// Logical demand-growth transactions observed during this call.
    ///
    /// This is not an allocator-call or allocation count. One event may own
    /// multiple allocations, and all byte fields remain authoritative.
    #[must_use]
    pub const fn events(self) -> usize {
        self.events
    }

    /// Heap payload bytes successfully allocated by cache growth.
    ///
    /// This is cumulative traffic, so it includes staged or replaced payload
    /// released before the successful call returns. Failed allocation
    /// requests that obtain no payload are excluded, as are setup allocations.
    #[must_use]
    pub const fn allocated_bytes(self) -> usize {
        self.allocated_bytes
    }

    /// Payload bytes logically written while growing cache storage.
    ///
    /// Repeated initialization is counted repeatedly. This excludes setup
    /// writes and ordinary updates to cache cells whose storage was already
    /// admitted.
    #[must_use]
    pub const fn initialized_bytes(self) -> usize {
        self.initialized_bytes
    }

    /// Newly retained cache payload attributable to this call.
    ///
    /// This is a non-negative addition relative to call entry. It can be less
    /// than `allocated_bytes` when growth used transient replacement storage
    /// or discarded a staged candidate.
    #[must_use]
    pub const fn retained_delta(self) -> usize {
        self.retained_delta
    }

    /// Largest total scratch payload live during a cache-growth event.
    ///
    /// This observed peak includes pre-existing retained scratch and staged
    /// storage. It is zero when no growth event was observed and is not the
    /// invocation's admitted ceiling; see [`SearchAccounting::scratch_bytes`].
    #[must_use]
    pub const fn peak_scratch_bytes(self) -> usize {
        self.peak_scratch_bytes
    }
}

/// Exact counters returned with every successful search invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchAccounting {
    work: u64,
    setup: SetupAccounting,
    cache_growth: CacheGrowthAccounting,
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
            cache_growth: CacheGrowthAccounting::empty(),
            transition_work,
            scratch_bytes,
            boundaries,
        }
    }

    #[allow(
        dead_code,
        reason = "demand-grown executors will attach their ledger after legacy construction"
    )]
    pub(crate) const fn with_cache_growth(mut self, cache_growth: CacheGrowthAccounting) -> Self {
        self.cache_growth = cache_growth;
        self
    }

    /// Add scratch retained outside this executor to its successful receipt.
    ///
    /// Facades use this after running a primary K0 workspace while a fixed
    /// sidecar remains live. A nonzero growth peak describes the same active
    /// invocation and therefore includes the external payload; an empty growth
    /// ledger keeps its sentinel zero peak.
    #[doc(hidden)]
    pub fn with_external_scratch_bytes(mut self, bytes: usize) -> Result<Self, SearchError> {
        let retained_bytes = self.setup.retained_bytes.checked_add(bytes).ok_or(
            SearchError::ArithmeticOverflow {
                computation: "external K0 scratch accounting",
            },
        )?;
        let scratch_bytes = self.scratch_bytes.checked_add(bytes).ok_or(
            SearchError::ArithmeticOverflow {
                computation: "external K0 scratch accounting",
            },
        )?;
        let cache_growth = if self.cache_growth.events == 0 {
            self.cache_growth
        } else {
            CacheGrowthAccounting {
                peak_scratch_bytes: self
                    .cache_growth
                    .peak_scratch_bytes
                    .checked_add(bytes)
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "external K0 scratch accounting",
                    })?,
                ..self.cache_growth
            }
        };
        self.setup.retained_bytes = retained_bytes;
        self.scratch_bytes = scratch_bytes;
        self.cache_growth = cache_growth;
        Ok(self)
    }

    /// Total charged work: setup plus automaton execution work.
    ///
    /// Execution work includes any cache-growth initialization reported by
    /// [`Self::cache_growth`].
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

    /// Work charged while examining boundaries, states, and edges or growing
    /// cache payload during execution.
    #[must_use]
    pub const fn transition_work(self) -> u64 {
        self.transition_work
    }

    /// Allocation, initialization, and reuse charges for this call.
    #[must_use]
    pub const fn setup(self) -> SetupAccounting {
        self.setup
    }

    /// Demand-grown cache resources observed during this call.
    #[must_use]
    pub const fn cache_growth(self) -> CacheGrowthAccounting {
        self.cache_growth
    }

    /// Heap scratch payload retained when this invocation completes.
    ///
    /// Fixed workspaces report the payload preflighted before execution.
    /// Aggregate routes also include any concurrently retained owner payload
    /// that their invocation keeps live, such as an automaton-owned pool box.
    /// Demand-grown workspaces include payload published during this call,
    /// but exclude replaced staging allocations that have already been
    /// released. The corresponding active-call high-water mark is reported by
    /// [`CacheGrowthAccounting::peak_scratch_bytes`].
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
/// bytes logically written by setup: construction, a generation-table reset,
/// or transactional proof publication. It deliberately excludes transition
/// cache rows and cells initialized while executing the automaton; those
/// writes are charged as execution work. A plan-side proof is published only
/// after the execution loop succeeds.
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

    /// Payload bytes initialized or cleared by this call's setup phase.
    ///
    /// This excludes lazy transition-cache publication performed by the
    /// execution loop, whose writes are represented by the work charge.
    #[must_use]
    pub const fn initialized_bytes(self) -> usize {
        self.initialized_bytes
    }

    /// Total heap payload bytes retained by the workspace and any aggregate
    /// owner needed to keep it available for this call.
    ///
    /// A cold pooled call includes its newly retained pool owner. This excludes
    /// an immutable plan-side proof even when this invocation allocated it;
    /// that delta is visible through [`Self::allocated_bytes`].
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

#[cfg(test)]
mod accounting_tests {
    use super::{CacheGrowthAccounting, SearchAccounting, SetupAccounting};

    #[test]
    fn cache_growth_accumulates_traffic_delta_and_peak_transactionally() {
        let mut growth = CacheGrowthAccounting::event(32, 24, 16, 80);
        assert!(growth.checked_accumulate(CacheGrowthAccounting::new(2, 40, 48, 20, 72,)));
        assert_eq!(growth.events(), 3);
        assert_eq!(growth.allocated_bytes(), 72);
        assert_eq!(growth.initialized_bytes(), 72);
        assert_eq!(growth.retained_delta(), 36);
        assert_eq!(growth.peak_scratch_bytes(), 80);

        let before = growth;
        assert!(!growth.checked_accumulate(CacheGrowthAccounting::new(
            usize::MAX,
            0,
            0,
            0,
            usize::MAX,
        )));
        assert_eq!(growth, before);
    }

    #[test]
    fn search_accounting_defaults_empty_and_attaches_growth_without_changing_admission() {
        let setup = SetupAccounting::empty(96, true);
        let base = SearchAccounting::new(11, setup, 9, 128, 4);
        assert_eq!(base.cache_growth(), CacheGrowthAccounting::empty());

        let growth = CacheGrowthAccounting::event(24, 16, 24, 120);
        let accounting = base.with_cache_growth(growth);
        assert_eq!(accounting.cache_growth(), growth);
        assert_eq!(accounting.scratch_bytes(), 128);
        assert_eq!(accounting.work(), 11);
        assert_eq!(accounting.transition_work(), 9);
        assert_eq!(accounting.boundaries(), 4);

        let aggregate = accounting
            .with_external_scratch_bytes(32)
            .expect("external sidecar scratch fits");
        assert_eq!(aggregate.setup().retained_bytes(), 128);
        assert_eq!(aggregate.scratch_bytes(), 160);
        assert_eq!(aggregate.cache_growth().peak_scratch_bytes(), 152);
        let no_growth = base
            .with_external_scratch_bytes(32)
            .expect("external scratch preserves an empty growth sentinel");
        assert_eq!(no_growth.setup().retained_bytes(), 128);
        assert_eq!(no_growth.scratch_bytes(), 160);
        assert_eq!(no_growth.cache_growth().peak_scratch_bytes(), 0);
        assert!(
            SearchAccounting::new(0, SetupAccounting::empty(0, true), 0, usize::MAX, 0)
                .with_external_scratch_bytes(1)
                .is_err(),
        );
        assert!(
            SearchAccounting::new(
                0,
                SetupAccounting::empty(usize::MAX, true),
                0,
                0,
                0,
            )
            .with_external_scratch_bytes(1)
            .is_err(),
        );
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

    /// Search the full haystack using caller-owned, reusable workspace.
    ///
    /// Workspace vectors built by the public fixed-capacity constructors never
    /// allocate or grow here. A cold automaton may independently allocate and
    /// publish its immutable start-filter proof on the first search. The
    /// doc-hidden adaptive constructor used by the portable facade may also
    /// grow its direct caches transactionally; that traffic is reported by
    /// [`SearchAccounting::cache_growth`].
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

    /// Search a byte range using caller-owned, reusable workspace. Assertions
    /// still inspect the original haystack. Public fixed-capacity workspace
    /// vectors never grow during this call, though a cold automaton may publish
    /// its separate immutable start-filter proof. A doc-hidden adaptive
    /// workspace may additionally report transactional direct-cache growth.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] for an invalid range, incompatible workspace,
    /// insufficient hard limit, or execution failure.
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

impl Automaton {
    /// Check out an optional automaton-owned session for the facade's
    /// outer-unlimited reverse-suffix operation. Finite workspace envelopes
    /// decline before inspecting or mutating the pool. The returned owner is
    /// bound to this exact immutable automaton and contains no source position
    /// or result.
    #[doc(hidden)]
    pub fn try_checkout_pooled_search_session(
        &self,
        workspace_limits: WorkspaceLimits,
        endpoint_eligible: bool,
        bidirectional: bool,
    ) -> Result<Option<K0SearchSession<'_>>, SearchError> {
        if workspace_limits != WorkspaceLimits::unlimited() {
            return Ok(None);
        }
        let Some(workspace) =
            self.try_checkout_pooled_workspace(workspace_limits, endpoint_eligible, bidirectional)
        else {
            return Ok(None);
        };
        K0SearchSession::from_pooled_workspace(self, workspace).map(Some)
    }

    /// Return a successfully used facade-composed session to this exact
    /// automaton. Cross-plan returns fail closed and never populate the pool.
    #[doc(hidden)]
    pub fn return_pooled_search_session(
        &self,
        session: K0SearchSession<'_>,
    ) -> Result<(), SearchError> {
        if !session.is_bound_to(self) {
            return Err(SearchError::InvalidResumeState {
                detail: "pooled K0 session belongs to another automaton",
            });
        }
        session.commit_pooled_workspace();
        Ok(())
    }

    /// Replace a successfully checked-out outer-unlimited facade session with
    /// genuinely fresh selected scratch. A finite workspace envelope restores
    /// the old session without constructing a candidate. Unlimited optional
    /// refusal or construction failure likewise restores the old session as a
    /// deliberate performance decline.
    #[doc(hidden)]
    pub fn refresh_pooled_search_session(
        &self,
        session: K0SearchSession<'_>,
        workspace_limits: WorkspaceLimits,
        endpoint_eligible: bool,
        bidirectional: bool,
    ) -> Result<(), SearchError> {
        if !session.is_bound_to(self) {
            return Err(SearchError::InvalidResumeState {
                detail: "pooled K0 session belongs to another automaton",
            });
        }
        if workspace_limits != WorkspaceLimits::unlimited() {
            session.commit_pooled_workspace();
            return Ok(());
        }
        match self.try_new_pooled_workspace(workspace_limits, endpoint_eligible, bidirectional) {
            Ok(Some(fresh)) => {
                session.commit_fresh_pooled_workspace(fresh);
                Ok(())
            }
            Ok(None) | Err(_) => {
                session.commit_pooled_workspace();
                Ok(())
            }
        }
    }

    /// Return whether the immutable start proof admits the bounded
    /// assertion-contextual ordinary Exists projection.
    #[doc(hidden)]
    #[must_use]
    #[inline]
    pub fn can_use_pooled_contextual_ordinary_exists_projection(&self) -> bool {
        crate::k0::can_prepare_contextual_ordinary_exists_projection(self)
    }

    /// Return whether the immutable start proof admits the bounded
    /// assertion-contextual ordinary Span projection.
    #[doc(hidden)]
    #[must_use]
    #[inline]
    pub fn can_use_pooled_contextual_ordinary_span_projection(&self) -> bool {
        crate::k0::can_prepare_contextual_ordinary_span_projection(self)
    }

    /// Attempt the bounded contextual ordinary-Exists projection through the
    /// populated owner lane only. A decline before checkout leaves the
    /// incumbent pooled path untouched; after checkout, every projection
    /// decline replays canonical unlimited K0 under the same owner guard.
    ///
    /// # Errors
    ///
    /// Returns the existing contextual authentication or canonical execution
    /// error. Errors discard the checked-out owner exactly like the incumbent
    /// pooled transaction.
    #[doc(hidden)]
    #[inline(never)]
    pub fn search_window_with_warm_owner_contextual_ordinary_exists_value(
        &self,
        haystack: &[u8],
        window: SearchWindow,
    ) -> Result<Option<K0OrderedResumeValue<bool>>, SearchError> {
        if window.start() > window.end() || window.end() > haystack.len() {
            return Ok(None);
        }
        let window_bytes = window.end().saturating_sub(window.start());
        let Some(witness) =
            crate::k0::prepared_contextual_ordinary_exists_witness(self, window_bytes)
        else {
            return Ok(None);
        };
        let warm = self.try_with_warm_owner_workspace(
            WorkspaceLimits::unlimited(),
            true,
            false,
            |workspace| {
                crate::k0::search_prevalidated_contextual_ordinary_exists_value_with_authenticated_warm_owner(
                    self,
                    haystack,
                    window,
                    workspace,
                    witness,
                    Self::pooled_workspace_owner_bytes(),
                )
            },
        );
        match warm {
            Some(result) => result.map(Some),
            None => Ok(None),
        }
    }

    /// Attempt the bounded contextual ordinary-Span projection through the
    /// populated owner lane only. A selected endpoint whose scalar start is
    /// unknown replays canonical unlimited Span under the same owner guard.
    ///
    /// # Errors
    ///
    /// Returns the existing contextual authentication or canonical execution
    /// error. Errors discard the checked-out owner exactly like the incumbent
    /// pooled transaction.
    #[doc(hidden)]
    #[inline(never)]
    pub fn search_window_with_warm_owner_contextual_ordinary_span_value(
        &self,
        haystack: &[u8],
        window: SearchWindow,
    ) -> Result<Option<K0OrderedResumeValue<Option<MatchSpan>>>, SearchError> {
        if window.start() > window.end() || window.end() > haystack.len() {
            return Ok(None);
        }
        let window_bytes = window.end().saturating_sub(window.start());
        let Some(witness) =
            crate::k0::prepared_contextual_ordinary_span_witness(self, window_bytes)
        else {
            return Ok(None);
        };
        let warm = self.try_with_warm_owner_workspace(
            WorkspaceLimits::unlimited(),
            true,
            true,
            |workspace| {
                crate::k0::search_prevalidated_contextual_ordinary_span_value_with_authenticated_warm_owner(
                    self,
                    haystack,
                    window,
                    workspace,
                    witness,
                    Self::pooled_workspace_owner_bytes(),
                )
            },
        );
        match warm {
            Some(result) => result.map(Some),
            None => Ok(None),
        }
    }

    /// Return whether this thread owns a populated workspace compatible with
    /// the ordinary positive-Exists capability envelope.
    ///
    /// This is a storage-free observation: a missing pool, foreign owner, or
    /// incompatible workspace returns `false` without constructing or moving
    /// scratch. A compatible owner is checked out only for a no-op transaction
    /// and is committed unchanged before this method returns.
    #[doc(hidden)]
    #[must_use]
    #[inline]
    pub fn has_compatible_warm_pooled_ordinary_exists_owner(&self) -> bool {
        self.try_with_warm_owner_workspace(
            WorkspaceLimits::unlimited(),
            true,
            false,
            |_| Ok::<(), SearchError>(()),
        )
        .is_some_and(|result| result.is_ok())
    }

    /// Search for existence through the automaton-owned optional value-only
    /// workspace. The workspace is checked out only from this exact immutable
    /// automaton and is returned only after a successful execution.
    ///
    /// `Ok(None)` means the optional route declined before finite execution,
    /// or that an unlimited optional construction was unavailable; the facade
    /// must use its canonical one-shot entry. An actual search result is
    /// wrapped in `Some`.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] if pooled execution fails, or if cold workspace
    /// construction fails under the exact default finite envelope. Invalid
    /// windows and custom finite limits decline before pooled execution;
    /// unlimited optional construction failures remain `Ok(None)`.
    #[doc(hidden)]
    pub fn search_window_with_optional_pooled_exists_value(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
        workspace_limits: WorkspaceLimits,
        endpoint_eligible: bool,
        bidirectional: bool,
    ) -> Result<Option<bool>, SearchError> {
        if (limits != SearchLimits::unlimited() && limits != SearchLimits::default())
            || window.start() > window.end()
            || window.end() > haystack.len()
        {
            return Ok(None);
        }
        let workspace_limits =
            Self::pooled_workspace_limits_for_search(workspace_limits, limits);
        let warm = self.try_with_warm_owner_workspace(
            workspace_limits,
            endpoint_eligible,
            bidirectional,
            |workspace| {
                crate::k0::search_prevalidated_exists_value_with_authenticated_workspace_and_external_scratch(
                    self,
                    haystack,
                    window,
                    workspace,
                    limits,
                    Self::pooled_workspace_owner_bytes(),
                )
            },
        );
        if let Some(result) = warm {
            return result.map(Some);
        }
        self.search_window_with_optional_pooled_exists_value_slow(
            haystack,
            window,
            limits,
            workspace_limits,
            endpoint_eligible,
            bidirectional,
        )
    }

    #[inline(never)]
    fn search_window_with_optional_pooled_exists_value_slow(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
        workspace_limits: WorkspaceLimits,
        endpoint_eligible: bool,
        bidirectional: bool,
    ) -> Result<Option<bool>, SearchError> {
        let checkout = self.try_checkout_pooled_workspace_with_setup(
            workspace_limits,
            limits.max_work,
            endpoint_eligible,
            bidirectional,
        );
        let Some(mut checkout) = (match checkout {
            Ok(checkout) => checkout,
            Err(_) if limits == SearchLimits::unlimited() => return Ok(None),
            Err(error) => return Err(error),
        })
        else {
            return Ok(None);
        };
        let external_scratch_bytes = checkout.external_retained_scratch_bytes();
        let result = match (limits == SearchLimits::default(), checkout.cold_setup) {
            (true, Some(setup)) => {
                crate::k0::search_prevalidated_exists_value_with_authenticated_workspace_and_setup(
                    self,
                    haystack,
                    window,
                    &mut checkout,
                    limits,
                    setup,
                    external_scratch_bytes,
                )
            }
            _ => crate::k0::search_prevalidated_exists_value_with_authenticated_workspace_and_external_scratch(
                self,
                haystack,
                window,
                &mut checkout,
                limits,
                external_scratch_bytes,
            ),
        };
        if result.is_ok() {
            checkout.commit();
        }
        result.map(Some)
    }

    /// Search for the first accepting endpoint through the automaton-owned
    /// optional value-only workspace.
    ///
    /// The outer option distinguishes an unavailable optional workspace from
    /// the inner option's no-match result. See
    /// [`Self::search_window_with_optional_pooled_exists_value`] for the
    /// ownership, fallback, and error contract.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] if pooled execution fails, or if cold workspace
    /// construction fails under the exact default finite envelope. Invalid
    /// windows and custom finite limits decline before pooled execution;
    /// unlimited optional construction failures remain `Ok(None)`.
    #[doc(hidden)]
    pub fn search_window_with_optional_pooled_earliest_end_value(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
        workspace_limits: WorkspaceLimits,
        endpoint_eligible: bool,
    ) -> Result<Option<Option<usize>>, SearchError> {
        if (limits != SearchLimits::unlimited() && limits != SearchLimits::default())
            || window.start() > window.end()
            || window.end() > haystack.len()
        {
            return Ok(None);
        }
        let workspace_limits =
            Self::pooled_workspace_limits_for_search(workspace_limits, limits);
        let warm = self.try_with_warm_owner_workspace(
            workspace_limits,
            endpoint_eligible,
            false,
            |workspace| {
                crate::k0::search_prevalidated_earliest_end_value_with_authenticated_workspace_and_external_scratch(
                    self,
                    haystack,
                    window,
                    workspace,
                    limits,
                    Self::pooled_workspace_owner_bytes(),
                )
            },
        );
        if let Some(result) = warm {
            return result.map(Some);
        }
        self.search_window_with_optional_pooled_earliest_end_value_slow(
            haystack,
            window,
            limits,
            workspace_limits,
            endpoint_eligible,
        )
    }

    #[inline(never)]
    fn search_window_with_optional_pooled_earliest_end_value_slow(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
        workspace_limits: WorkspaceLimits,
        endpoint_eligible: bool,
    ) -> Result<Option<Option<usize>>, SearchError> {
        let checkout = self.try_checkout_pooled_workspace_with_setup(
            workspace_limits,
            limits.max_work,
            endpoint_eligible,
            false,
        );
        let Some(mut checkout) = (match checkout {
            Ok(checkout) => checkout,
            Err(_) if limits == SearchLimits::unlimited() => return Ok(None),
            Err(error) => return Err(error),
        })
        else {
            return Ok(None);
        };
        let external_scratch_bytes = checkout.external_retained_scratch_bytes();
        let result = match (limits == SearchLimits::default(), checkout.cold_setup) {
            (true, Some(setup)) => {
                crate::k0::search_prevalidated_earliest_end_value_with_authenticated_workspace_and_setup(
                    self,
                    haystack,
                    window,
                    &mut checkout,
                    limits,
                    setup,
                    external_scratch_bytes,
                )
            }
            _ => crate::k0::search_prevalidated_earliest_end_value_with_authenticated_workspace_and_external_scratch(
                self,
                haystack,
                window,
                &mut checkout,
                limits,
                external_scratch_bytes,
            ),
        };
        if result.is_ok() {
            checkout.commit();
        }
        result.map(Some)
    }

    /// Search for a selected span through the automaton-owned optional
    /// value-only workspace.
    ///
    /// The outer option distinguishes an unavailable optional workspace from
    /// the inner option's no-match result. See
    /// [`Self::search_window_with_optional_pooled_exists_value`] for the
    /// ownership, fallback, and error contract.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] if pooled execution fails, or if cold workspace
    /// construction fails under the exact default finite envelope. Invalid
    /// windows and custom finite limits decline before pooled execution;
    /// unlimited optional construction failures remain `Ok(None)`.
    #[doc(hidden)]
    pub fn search_window_with_optional_pooled_span_value(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
        workspace_limits: WorkspaceLimits,
        endpoint_eligible: bool,
        bidirectional: bool,
    ) -> Result<Option<Option<MatchSpan>>, SearchError> {
        if (limits != SearchLimits::unlimited() && limits != SearchLimits::default())
            || window.start() > window.end()
            || window.end() > haystack.len()
        {
            return Ok(None);
        }
        let workspace_limits =
            Self::pooled_workspace_limits_for_search(workspace_limits, limits);
        let warm = self.try_with_warm_owner_workspace(
            workspace_limits,
            endpoint_eligible,
            bidirectional,
            |workspace| {
                crate::k0::search_prevalidated_span_value_with_authenticated_workspace_and_external_scratch(
                    self,
                    haystack,
                    window,
                    workspace,
                    limits,
                    Self::pooled_workspace_owner_bytes(),
                )
            },
        );
        if let Some(result) = warm {
            return result.map(Some);
        }
        self.search_window_with_optional_pooled_span_value_slow(
            haystack,
            window,
            limits,
            workspace_limits,
            endpoint_eligible,
            bidirectional,
        )
    }

    #[inline(never)]
    fn search_window_with_optional_pooled_span_value_slow(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
        workspace_limits: WorkspaceLimits,
        endpoint_eligible: bool,
        bidirectional: bool,
    ) -> Result<Option<Option<MatchSpan>>, SearchError> {
        let checkout = self.try_checkout_pooled_workspace_with_setup(
            workspace_limits,
            limits.max_work,
            endpoint_eligible,
            bidirectional,
        );
        let Some(mut checkout) = (match checkout {
            Ok(checkout) => checkout,
            Err(_) if limits == SearchLimits::unlimited() => return Ok(None),
            Err(error) => return Err(error),
        })
        else {
            return Ok(None);
        };
        let external_scratch_bytes = checkout.external_retained_scratch_bytes();
        let result = match (limits == SearchLimits::default(), checkout.cold_setup) {
            (true, Some(setup)) => {
                crate::k0::search_prevalidated_span_value_with_authenticated_workspace_and_setup(
                    self,
                    haystack,
                    window,
                    &mut checkout,
                    limits,
                    setup,
                    external_scratch_bytes,
                )
            }
            _ => crate::k0::search_prevalidated_span_value_with_authenticated_workspace_and_external_scratch(
                self,
                haystack,
                window,
                &mut checkout,
                limits,
                external_scratch_bytes,
            ),
        };
        if result.is_ok() {
            checkout.commit();
        }
        result.map(Some)
    }

    /// Verify an exact positive endpoint through the automaton-owned
    /// bidirectional workspace. `maximum_match_bytes` narrows the reverse
    /// source window only when the caller has an immutable language proof for
    /// the same automaton. `Ok(None)` declines to the caller's canonical path.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] after authenticated pooled execution begins.
    #[doc(hidden)]
    pub fn search_window_with_optional_pooled_positive_end_exists_value(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
        workspace_limits: WorkspaceLimits,
        maximum_match_bytes: Option<usize>,
    ) -> Result<Option<bool>, SearchError> {
        if limits != SearchLimits::unlimited()
            || window.start() >= window.end()
            || window.end() > haystack.len()
        {
            return Ok(None);
        }
        let verifier_start = maximum_match_bytes.map_or(window.start(), |maximum| {
            window.end().saturating_sub(maximum).max(window.start())
        });
        if verifier_start >= window.end() {
            return Ok(Some(false));
        }
        let verifier_window = SearchWindow::new(verifier_start, window.end());
        let Some(workspace) = self.try_checkout_pooled_workspace(workspace_limits, true, true)
        else {
            return Ok(None);
        };
        let mut session = K0SearchSession::from_pooled_workspace(self, workspace)?;
        let verifier_bytes = verifier_window
            .end()
            .saturating_sub(verifier_window.start());
        let Some(max_work) = session.positive_end_verifier_work_certificate(verifier_bytes) else {
            session.commit_pooled_workspace();
            return Ok(None);
        };
        let verification = session.try_positive_match_ending_at(
            haystack,
            verifier_window,
            window.end(),
            crate::K0PositiveEndLimits::new(max_work, verifier_bytes),
        );
        match verification {
            Ok(verification) => {
                session.commit_pooled_workspace();
                match verification.outcome() {
                    crate::K0PositiveEndOutcome::Matched => Ok(Some(true)),
                    crate::K0PositiveEndOutcome::Rejected => Ok(Some(false)),
                    crate::K0PositiveEndOutcome::Declined => Ok(None),
                }
            }
            Err(error) => Err(error),
        }
    }

    /// Recover the earliest start for an exact positive endpoint through the
    /// same bounded pooled reverse proof.
    ///
    /// The outer option is route availability; the inner option is the exact
    /// no-match/match result.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] after authenticated pooled execution begins.
    #[doc(hidden)]
    pub fn search_window_with_optional_pooled_positive_end_span_value(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
        workspace_limits: WorkspaceLimits,
        maximum_match_bytes: Option<usize>,
    ) -> Result<Option<Option<MatchSpan>>, SearchError> {
        if limits != SearchLimits::unlimited()
            || window.start() >= window.end()
            || window.end() > haystack.len()
        {
            return Ok(None);
        }
        let verifier_start = maximum_match_bytes.map_or(window.start(), |maximum| {
            window.end().saturating_sub(maximum).max(window.start())
        });
        if verifier_start >= window.end() {
            return Ok(Some(None));
        }
        let verifier_window = SearchWindow::new(verifier_start, window.end());
        let Some(workspace) = self.try_checkout_pooled_workspace(workspace_limits, true, true)
        else {
            return Ok(None);
        };
        let mut session = K0SearchSession::from_pooled_workspace(self, workspace)?;
        let verifier_bytes = verifier_window
            .end()
            .saturating_sub(verifier_window.start());
        let Some(max_work) = session.positive_end_verifier_work_certificate(verifier_bytes) else {
            session.commit_pooled_workspace();
            return Ok(None);
        };
        let verification = session.try_earliest_start_ending_at(
            haystack,
            verifier_window,
            window.end(),
            crate::K0PositiveEndLimits::new(max_work, verifier_bytes),
        );
        match verification {
            Ok(verification) => {
                session.commit_pooled_workspace();
                match verification.outcome() {
                    crate::K0PositiveEndStartOutcome::Matched { start } => {
                        Ok(Some(Some(MatchSpan::new(start, window.end()))))
                    }
                    crate::K0PositiveEndStartOutcome::Rejected => Ok(Some(None)),
                    crate::K0PositiveEndStartOutcome::Declined => Ok(None),
                }
            }
            Err(error) => Err(error),
        }
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

    /// Continue a compiler-authenticated warmed native row at its exact first
    /// unpublished cell without replaying the generated scalar prefix.
    #[doc(hidden)]
    #[allow(
        clippy::too_many_arguments,
        reason = "the private continuation keeps its cache identity and unread boundary explicit"
    )]
    pub fn search_prevalidated_exists_value_from_dynamic_direct_hole_with_authenticated_workspace(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        workspace: &mut K0Workspace,
        current_row: u32,
        position: usize,
        scanner_hits: usize,
        cache_identity: u64,
    ) -> Result<bool, SearchError> {
        crate::k0::search_prevalidated_exists_value_from_dynamic_direct_hole_with_authenticated_workspace(
            self.automaton,
            haystack,
            window,
            workspace,
            current_row,
            position,
            scanner_hits,
            cache_identity,
        )
    }

    /// Resolve one compiler-authenticated direct hole without consuming its
    /// unread byte when the transition can be retained.
    #[doc(hidden)]
    #[allow(
        clippy::too_many_arguments,
        reason = "the private resolver keeps its cache identity and unread boundary explicit"
    )]
    pub fn resolve_prevalidated_exists_dynamic_direct_hole_with_authenticated_workspace(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        workspace: &mut K0Workspace,
        current_row: u32,
        position: usize,
        scanner_hits: usize,
        cache_identity: u64,
    ) -> Result<DynamicDirectHoleResolution<bool>, SearchError> {
        crate::k0::resolve_prevalidated_exists_dynamic_direct_hole_with_authenticated_workspace(
            self.automaton,
            haystack,
            window,
            workspace,
            current_row,
            position,
            scanner_hits,
            cache_identity,
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
        self.search_prevalidated_exists_value_from_ordered_resume_with_authenticated_workspace_with_completion(
            haystack,
            window,
            workspace,
            resume_set,
            resume_state,
            resume_position,
            pending_end,
            limits,
        )
        .map(K0OrderedResumeValue::into_output)
    }

    /// Return existence together with whether immutable warm rows alone
    /// decided the ordered-resume result.
    #[doc(hidden)]
    #[allow(
        clippy::too_many_arguments,
        reason = "the value-only resume boundary keeps its committed prefix explicit"
    )]
    pub fn search_prevalidated_exists_value_from_ordered_resume_with_authenticated_workspace_with_completion(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        workspace: &mut K0Workspace,
        resume_set: &mut K0ResumeSet,
        resume_state: usize,
        resume_position: usize,
        pending_end: Option<usize>,
        limits: SearchLimits,
    ) -> Result<K0OrderedResumeValue<bool>, SearchError> {
        crate::k0::search_prevalidated_exists_value_from_ordered_resume_with_authenticated_workspace_with_completion(
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

    /// Return existence through a setup-authenticated complete ordered-resume
    /// cache. A stale receipt fails closed to the ordinary exact warm path.
    #[doc(hidden)]
    #[allow(
        clippy::too_many_arguments,
        reason = "the fully-prefilled resume boundary keeps its setup receipt explicit"
    )]
    pub fn search_prevalidated_exists_value_from_fully_prefilled_ordered_resume_with_authenticated_workspace_with_completion(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        workspace: &mut K0Workspace,
        resume_set: &mut K0ResumeSet,
        resume_state: usize,
        resume_position: usize,
        pending_end: Option<usize>,
        limits: SearchLimits,
        receipt: K0FullyPrefilledResumeCacheReceipt,
    ) -> Result<K0OrderedResumeValue<bool>, SearchError> {
        crate::k0::search_prevalidated_exists_value_from_fully_prefilled_ordered_resume_with_authenticated_workspace_with_completion(
            self.automaton,
            haystack,
            window,
            workspace,
            resume_set,
            resume_state,
            resume_position,
            pending_end,
            limits,
            receipt,
        )
    }
}

impl TypedPlan<'_, SelectedEnd> {
    /// Return only the selected endpoint through an authenticated,
    /// caller-validated workspace.
    ///
    /// An unlimited exact-identity call may read already-filled forward rows
    /// without constructing diagnostic accounting. Assertion-free execution
    /// can continue mutably at its first unavailable direct transition;
    /// contextual execution reads only a complete already-published path and
    /// declines transactionally on a missing record. Every finite, cold,
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

    /// Continue a compiler-authenticated warmed native row at its exact first
    /// unpublished cell while retaining the selected endpoint committed by
    /// its generated prefix.
    #[doc(hidden)]
    #[allow(
        clippy::too_many_arguments,
        reason = "the private continuation keeps its cache identity and pending endpoint explicit"
    )]
    pub fn search_prevalidated_selected_end_value_from_dynamic_direct_hole_with_authenticated_workspace(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        workspace: &mut K0Workspace,
        current_row: u32,
        position: usize,
        pending_end: Option<usize>,
        scanner_hits: usize,
        cache_identity: u64,
    ) -> Result<Option<usize>, SearchError> {
        crate::k0::search_prevalidated_selected_end_value_from_dynamic_direct_hole_with_authenticated_workspace(
            self.automaton,
            haystack,
            window,
            workspace,
            current_row,
            position,
            pending_end,
            scanner_hits,
            cache_identity,
        )
    }

    /// Resolve one compiler-authenticated selected-end direct hole without
    /// consuming its unread byte when the transition can be retained.
    #[doc(hidden)]
    #[allow(
        clippy::too_many_arguments,
        reason = "the private resolver keeps its cache identity and pending endpoint explicit"
    )]
    pub fn resolve_prevalidated_selected_end_dynamic_direct_hole_with_authenticated_workspace(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        workspace: &mut K0Workspace,
        current_row: u32,
        position: usize,
        pending_end: Option<usize>,
        scanner_hits: usize,
        cache_identity: u64,
    ) -> Result<DynamicDirectHoleResolution<Option<usize>>, SearchError> {
        crate::k0::resolve_prevalidated_selected_end_dynamic_direct_hole_with_authenticated_workspace(
            self.automaton,
            haystack,
            window,
            workspace,
            current_row,
            position,
            pending_end,
            scanner_hits,
            cache_identity,
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
        self.search_prevalidated_selected_end_value_from_ordered_resume_with_authenticated_workspace_with_completion(
            haystack,
            window,
            workspace,
            resume_set,
            resume_state,
            resume_position,
            pending_end,
            limits,
        )
        .map(K0OrderedResumeValue::into_output)
    }

    /// Return the selected endpoint together with whether immutable warm rows
    /// alone decided the ordered-resume result.
    #[doc(hidden)]
    #[allow(
        clippy::too_many_arguments,
        reason = "the value-only resume boundary keeps its committed prefix explicit"
    )]
    pub fn search_prevalidated_selected_end_value_from_ordered_resume_with_authenticated_workspace_with_completion(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        workspace: &mut K0Workspace,
        resume_set: &mut K0ResumeSet,
        resume_state: usize,
        resume_position: usize,
        pending_end: Option<usize>,
        limits: SearchLimits,
    ) -> Result<K0OrderedResumeValue<Option<usize>>, SearchError> {
        crate::k0::search_prevalidated_selected_end_value_from_ordered_resume_with_authenticated_workspace_with_completion(
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

    /// Return the selected endpoint through a setup-authenticated complete
    /// ordered-resume cache. A stale receipt uses the ordinary exact path.
    #[doc(hidden)]
    #[allow(
        clippy::too_many_arguments,
        reason = "the fully-prefilled resume boundary keeps its setup receipt explicit"
    )]
    pub fn search_prevalidated_selected_end_value_from_fully_prefilled_ordered_resume_with_authenticated_workspace_with_completion(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        workspace: &mut K0Workspace,
        resume_set: &mut K0ResumeSet,
        resume_state: usize,
        resume_position: usize,
        pending_end: Option<usize>,
        limits: SearchLimits,
        receipt: K0FullyPrefilledResumeCacheReceipt,
    ) -> Result<K0OrderedResumeValue<Option<usize>>, SearchError> {
        crate::k0::search_prevalidated_selected_end_value_from_fully_prefilled_ordered_resume_with_authenticated_workspace_with_completion(
            self.automaton,
            haystack,
            window,
            workspace,
            resume_set,
            resume_state,
            resume_position,
            pending_end,
            limits,
            receipt,
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
    /// reverse rows or exact assertion-contextual records without constructing
    /// diagnostic accounting. A contextual cache miss declines the entire
    /// read-only attempt transactionally. Every finite, cold, incomplete, or
    /// unauthenticated case uses the ordinary report-producing executor with
    /// unchanged error behavior.
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
        self.search_prevalidated_span_value_from_ordered_resume_with_authenticated_workspace_with_completion(
            haystack,
            window,
            workspace,
            resume_set,
            resume_state,
            resume_position,
            pending_end,
            limits,
        )
        .map(K0OrderedResumeValue::into_output)
    }

    /// Return the selected span together with whether immutable warm forward
    /// and, when required, reverse rows alone decided the result.
    #[doc(hidden)]
    #[allow(
        clippy::too_many_arguments,
        reason = "the value-only Span resume boundary keeps its committed prefix explicit"
    )]
    pub fn search_prevalidated_span_value_from_ordered_resume_with_authenticated_workspace_with_completion(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        workspace: &mut K0Workspace,
        resume_set: &mut K0ResumeSet,
        resume_state: usize,
        resume_position: usize,
        pending_end: Option<usize>,
        limits: SearchLimits,
    ) -> Result<K0OrderedResumeValue<Option<MatchSpan>>, SearchError> {
        crate::k0::search_prevalidated_span_value_from_ordered_resume_with_authenticated_workspace_with_completion(
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

    /// Return the selected span through setup-authenticated complete forward
    /// and reverse ordered-resume caches. A stale receipt uses the ordinary
    /// exact path.
    #[doc(hidden)]
    #[allow(
        clippy::too_many_arguments,
        reason = "the fully-prefilled Span resume boundary keeps its setup receipt explicit"
    )]
    pub fn search_prevalidated_span_value_from_fully_prefilled_ordered_resume_with_authenticated_workspace_with_completion(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        workspace: &mut K0Workspace,
        resume_set: &mut K0ResumeSet,
        resume_state: usize,
        resume_position: usize,
        pending_end: Option<usize>,
        limits: SearchLimits,
        receipt: K0FullyPrefilledResumeCacheReceipt,
    ) -> Result<K0OrderedResumeValue<Option<MatchSpan>>, SearchError> {
        crate::k0::search_prevalidated_span_value_from_fully_prefilled_ordered_resume_with_authenticated_workspace_with_completion(
            self.automaton,
            haystack,
            window,
            workspace,
            resume_set,
            resume_state,
            resume_position,
            pending_end,
            limits,
            receipt,
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
    /// contracts. A fixed workspace performs no allocation during the call;
    /// an adaptive workspace may demand-grow its reverse cache within those
    /// limits and reports that traffic through search accounting.
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

    /// Recover an authenticated selected endpoint through setup-completed
    /// reverse rows. A stale receipt or finite resource limit fails closed to
    /// [`Self::recover_span_from_selected_end_with_workspace`].
    #[doc(hidden)]
    #[allow(
        clippy::too_many_arguments,
        reason = "the fully-prefilled reverse bridge keeps its cache owner and selected endpoint explicit"
    )]
    pub fn recover_span_from_selected_end_with_fully_prefilled_workspace(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        workspace: &mut K0Workspace,
        resume_set: &K0ResumeSet,
        selected_end: usize,
        limits: SearchLimits,
        receipt: K0FullyPrefilledResumeCacheReceipt,
    ) -> Result<SearchReport<MatchSpan>, SearchError> {
        let report =
            crate::k0::recover_span_from_selected_end_with_fully_prefilled_workspace(
                self.automaton,
                haystack,
                window,
                workspace,
                resume_set,
                selected_end,
                limits,
                receipt,
            )?;
        let span = report.found.ok_or(SearchError::InternalInvariant {
            detail: "fully-prefilled selected-end reverse recovery returned no span",
        })?;
        Ok(SearchReport::new(span, report.accounting))
    }

    /// Recover an authenticated root-selected endpoint through
    /// setup-completed reverse rows without continuation-set authority. A
    /// stale receipt or finite resource limit fails closed to
    /// [`Self::recover_span_from_selected_end_with_workspace`].
    #[doc(hidden)]
    #[allow(
        clippy::too_many_arguments,
        reason = "the root-prefilled reverse bridge keeps its cache owner and selected endpoint explicit"
    )]
    pub fn recover_span_from_selected_end_with_fully_prefilled_root_workspace(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        workspace: &mut K0Workspace,
        selected_end: usize,
        limits: SearchLimits,
        receipt: K0FullyPrefilledResumeCacheReceipt,
    ) -> Result<SearchReport<MatchSpan>, SearchError> {
        let report =
            crate::k0::recover_span_from_selected_end_with_fully_prefilled_root_workspace(
                self.automaton,
                haystack,
                window,
                workspace,
                selected_end,
                limits,
                receipt,
            )?;
        let span = report.found.ok_or(SearchError::InternalInvariant {
            detail: "fully-prefilled root selected-end reverse recovery returned no span",
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
    /// accounting checks remain identical to the caller-owned workspace API
    /// for explicitly constructed sessions. Sessions returned by
    /// [`Automaton::try_checkout_pooled_search_session`] are reserved for an
    /// outer-unlimited facade route: their generic search methods reject
    /// finite [`SearchLimits`] before ordinary range or resource validation.
    /// Their private positive-end verifier methods retain their separate
    /// [`K0PositiveEndLimits`] contract.
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
    /// Assertions inspect the complete original haystack. Caller-owned
    /// sessions, and pooled sessions admitted with unlimited limits, validate
    /// the range on every call even though graph and workspace compatibility
    /// were authenticated during construction. A finite pooled call rejects
    /// at its provenance boundary before range validation.
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

    /// Return only the first accepting endpoint, allowing an authenticated
    /// warm session to omit diagnostic report construction for unlimited
    /// assertion-free calls.
    ///
    /// Finite limits and every cold, contextual, or structurally ineligible
    /// invocation use the ordinary report-producing executor with unchanged
    /// accounting and error precedence.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] for an invalid range, a hard-limit refusal, or
    /// execution failure.
    #[doc(hidden)]
    pub fn search_earliest_end_value(
        &mut self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<Option<usize>, SearchError> {
        self.search_earliest_end_value_untyped(haystack, window, limits)
    }

    /// Try only the authenticated report-free warm existence route.
    ///
    /// `Ok(None)` is a transactional decline: no semantic search completed,
    /// so a facade may replay its ordinary bounded route. This entry never
    /// constructs a cold cache or falls through to the report-producing K0
    /// executor. It is intended for a facade that has already certified the
    /// retained workspace and the caller's finite work envelope.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] for an invalid range or a warm-cache invariant
    /// failure.
    #[doc(hidden)]
    pub fn try_search_warm_exists_value(
        &mut self,
        haystack: &[u8],
        window: SearchWindow,
    ) -> Result<Option<bool>, SearchError> {
        self.try_search_warm_exists_value_untyped(haystack, window)
    }

    /// Try only the authenticated report-free warm existence route under
    /// finite invocation limits.
    ///
    /// Current retained scratch and the logical reset are checked before warm
    /// admission. A finite call is authoritative: if the report-free cache is
    /// structurally cold, ordinary K0 completes under these same limits and
    /// returns `Some`. Immutable-prefix work and any exact mutable continuation
    /// likewise remain under `limits`; resource exhaustion is returned as an
    /// error and never converted into wider facade replay.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] for an invalid range, a hard-limit refusal, or
    /// a warm-cache invariant failure.
    #[doc(hidden)]
    pub fn try_search_warm_exists_value_with_limits(
        &mut self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<Option<bool>, SearchError> {
        self.try_search_warm_exists_value_with_limits_untyped(haystack, window, limits)
    }

    /// Return only the selected endpoint, allowing an authenticated warm
    /// session to omit diagnostic report construction for unlimited calls.
    ///
    /// Finite limits and every cold or otherwise ineligible call use the
    /// ordinary report-producing executor with unchanged accounting and error
    /// precedence. A contextual warm projection is read-only and falls back
    /// transactionally if any required published record is unavailable.
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
    /// through already-filled direct or exact assertion-contextual reverse
    /// rows.
    ///
    /// A contextual warm projection reads retained records only and declines
    /// transactionally on any missing forward or reverse cell. Finite limits
    /// and every cold or incomplete-cache call use the ordinary
    /// report-producing executor with unchanged resource and error behavior.
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

    /// Return only a Span for one iterator-owned suffix while retaining
    /// primary-scanner masks tied to the cursor's exact immutable source.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same range and resource contract as
    /// [`Self::search_span_value`].
    #[doc(hidden)]
    #[inline]
    pub fn search_span_value_at_source_cursor(
        &mut self,
        source: &mut K0SpanSourceCursor<'_>,
        start: usize,
        limits: SearchLimits,
    ) -> Result<Option<MatchSpan>, SearchError> {
        self.search_span_value_at_source_untyped(source, start, limits)
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
