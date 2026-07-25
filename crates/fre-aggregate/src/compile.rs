use std::collections::VecDeque;

use fre_exact_alloc::{CopyError, ExactVec};
use regex_syntax::hir::{Class, Hir, HirKind, Look, Repetition};
use regex_syntax::utf8::Utf8Sequences;

use crate::accounting::CompileAccounting;
use crate::candidate::{self, Draft as CandidateDraft, Entry as CandidateEntry};
use crate::error::{add, enforce, mul};
use crate::program::{Assertion, ByteSet, Inst, NO_SPLIT_RANK, Program, ScalarSet, StartDomain};
use crate::required_internal_anchor;
use crate::{CompileLimits, Error, Resource, Unsupported};

pub(crate) mod ordered_bounded_span_sum;

pub(crate) use ordered_bounded_span_sum::OrderedBoundedSpanSumPlan;

#[cfg(test)]
pub(crate) mod url_pack_allocation_probe {
    use std::cell::Cell;

    std::thread_local! {
        static CALLS: Cell<usize> = const { Cell::new(0) };
        static PREALLOCATION_WORK: Cell<usize> = const { Cell::new(usize::MAX) };
        static COUNT_CALLS: Cell<usize> = const { Cell::new(0) };
        static PRECOUNT_WORK: Cell<usize> = const { Cell::new(usize::MAX) };
        static COPY_CALLS: Cell<usize> = const { Cell::new(0) };
        static PRECOPY_WORK: Cell<usize> = const { Cell::new(usize::MAX) };
    }

    pub(crate) fn reset() {
        CALLS.set(0);
        PREALLOCATION_WORK.set(usize::MAX);
        COUNT_CALLS.set(0);
        PRECOUNT_WORK.set(usize::MAX);
        COPY_CALLS.set(0);
        PRECOPY_WORK.set(usize::MAX);
    }

    pub(crate) fn record_preallocation_work(work: usize) {
        PREALLOCATION_WORK.set(work);
    }

    pub(crate) fn record_call() {
        CALLS.set(CALLS.get().saturating_add(1));
    }

    pub(crate) fn calls() -> usize {
        CALLS.get()
    }

    pub(crate) fn preallocation_work() -> Option<usize> {
        let work = PREALLOCATION_WORK.get();
        (work != usize::MAX).then_some(work)
    }

    pub(crate) fn record_precount_work(work: usize) {
        PRECOUNT_WORK.set(work);
    }

    pub(crate) fn record_count_call() {
        COUNT_CALLS.set(COUNT_CALLS.get().saturating_add(1));
    }

    pub(crate) fn count_calls() -> usize {
        COUNT_CALLS.get()
    }

    pub(crate) fn precount_work() -> Option<usize> {
        let work = PRECOUNT_WORK.get();
        (work != usize::MAX).then_some(work)
    }

    pub(crate) fn record_precopy_work(work: usize) {
        if PRECOPY_WORK.get() == usize::MAX {
            PRECOPY_WORK.set(work);
        }
    }

    pub(crate) fn record_copy_call() {
        COPY_CALLS.set(COPY_CALLS.get().saturating_add(1));
    }

    pub(crate) fn copy_calls() -> usize {
        COPY_CALLS.get()
    }

    pub(crate) fn precopy_work() -> Option<usize> {
        let work = PRECOPY_WORK.get();
        (work != usize::MAX).then_some(work)
    }
}

/// Deterministic failure injection at compiler-owned allocation calls.
///
/// The probe is test-only and thread-local. Its branch is never active in an
/// ordinary production compile. Receipt accounting itself remains scoped by
/// [`CompileBudget::allocation_scope`] or the construction-effect scope.
#[cfg(test)]
pub(crate) mod compiler_allocation_probe {
    use std::cell::Cell;

    use crate::{Error, Resource};

    std::thread_local! {
        static FAIL_AT: Cell<usize> = const { Cell::new(usize::MAX) };
        static CALLS: Cell<usize> = const { Cell::new(0) };
    }

    pub(crate) struct FaultGuard;

    impl Drop for FaultGuard {
        fn drop(&mut self) {
            FAIL_AT.set(usize::MAX);
            CALLS.set(0);
        }
    }

    pub(crate) fn fail_at(ordinal: usize) -> FaultGuard {
        FAIL_AT.set(ordinal);
        CALLS.set(0);
        FaultGuard
    }

    pub(crate) fn before(resource: Resource, items: usize) -> Result<(), Error> {
        let ordinal = CALLS.get();
        CALLS.set(ordinal.saturating_add(1));
        if ordinal == FAIL_AT.get() {
            return Err(Error::AllocationFailed { resource, items });
        }
        Ok(())
    }

    pub(crate) fn calls() -> usize {
        CALLS.get()
    }
}

/// Explicit semantic profile asserted by direct HIR callers.
///
/// HIR intentionally does not retain every parser option. In particular, an
/// empty HIR cannot reveal whether Unicode mode was enabled. Passing this
/// token asserts both the pinned parser configuration and the empty-match
/// boundary policy. Unicode-on callers receive literals, byte classes, Unicode
/// scalar classes retained as bounded scalar-consuming transitions, every pinned look
/// assertion, and their regular composition.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RustByteProfile {
    unicode: bool,
}

impl RustByteProfile {
    /// Pinned Unicode-off production profile for regex 1.12.4 /
    /// regex-syntax 0.8.11 with byte-boundary empty matches.
    pub const PINNED_1_12_4: Self = Self { unicode: false };

    /// Pinned Unicode-on Rust-bytes profile with `utf8(false)` and
    /// `utf8_empty(false)`, with scalar classes matched at canonical UTF-8 boundaries.
    /// Positive Unicode word boundaries additionally require valid UTF-8 at
    /// operation admission.
    pub const PINNED_1_12_4_UNICODE_ON_BYTE_STABLE: Self = Self { unicode: true };

    const fn identity_domain(self) -> &'static [u8] {
        if self.unicode {
            b"fre.aggregate.rust.bytes.unicode-on-utf8-scalar.v2"
        } else {
            // Preserve the pre-existing Unicode-off identities exactly.
            b"fre.aggregate.rust.bytes.unicode-off.v2"
        }
    }
}

/// Public semantic tag for a receipt-bearing compiler attempt.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CompileAttemptKind {
    /// Capture annotations are transparent because the caller observes only
    /// whole-match values.
    EraseCapturesForWholeMatch,
}

/// Immutable semantic identity of a receipt-bearing compiler attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompileAttemptIdentity {
    pub profile: RustByteProfile,
    pub kind: CompileAttemptKind,
}

/// Complete compiler envelope and exact cumulative ledger at a terminal
/// construction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompileAttemptReceipt {
    pub identity: CompileAttemptIdentity,
    /// The exact caller-supplied envelope bound before HIR traversal begins.
    pub prospective: CompileLimits,
    /// U1-scoped allocation ceiling supplied by the eager scalar residual;
    /// absent on the ordinary receipt-bearing compiler entry point.
    pub allocation_limit: Option<usize>,
    /// Complete input-only allocation count when the caller supplied the
    /// fixed-scalar residual census; absent on ordinary compiler attempts.
    pub prospective_allocations: Option<usize>,
    /// Exact counters committed through the last admitted compiler step.
    pub actual: CompileAccounting,
    /// Successful compiler-owned allocations committed through this attempt.
    pub actual_allocations: Option<usize>,
    /// Logical construction bytes live immediately before the failure
    /// unwinds and drops unpublished compiler-owned values.
    pub live_construction_bytes: usize,
    /// A terminal error never publishes a partial continuation program.
    pub published: bool,
}

impl CompileAttemptReceipt {
    #[must_use]
    pub const fn contains_actual(self) -> bool {
        self.actual.hir_nodes <= self.prospective.max_hir_nodes
            && self.actual.hir_depth <= self.prospective.max_hir_depth
            && self.actual.peak_hir_stack_items <= self.prospective.max_hir_stack_items
            && self.actual.literal_bytes <= self.prospective.max_literal_bytes
            && self.actual.class_ranges <= self.prospective.max_class_ranges
            && self.actual.utf8_sequences <= self.prospective.max_utf8_sequences
            && self.actual.utf8_byte_ranges <= self.prospective.max_utf8_byte_ranges
            && self.actual.look_assertions <= self.prospective.max_look_assertions
            && self.actual.program_states <= self.prospective.max_program_states
            && self.actual.temporary_states_peak <= self.prospective.max_temporary_states
            && self.actual.program_bytes <= self.prospective.max_program_bytes
            && self.actual.construction_peak_bytes <= self.prospective.max_program_bytes
            && self.actual.work <= self.prospective.max_work
            && self.actual.captures_erased <= self.actual.hir_nodes
            && self.actual.capture_erasure_work <= self.actual.work
            && match (
                self.allocation_limit,
                self.prospective_allocations,
                self.actual_allocations,
            ) {
                (Some(limit), Some(upper), Some(actual)) => actual <= limit && actual <= upper,
                (None, None, None) => true,
                _ => false,
            }
            && self.live_construction_bytes <= self.actual.construction_peak_bytes
            && !self.published
    }
}

/// Terminal refusal from the U1-scoped receipt-bearing compiler entry point.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompileAttemptError {
    pub source: Error,
    pub receipt: CompileAttemptReceipt,
}

impl core::fmt::Display for CompileAttemptError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(&self.source, formatter)
    }
}

impl std::error::Error for CompileAttemptError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Exact effects committed by one receipt-bearing continuation compilation.
///
/// Allocation counters describe successful physical capacity changes.
/// Initialization and copy counters are cumulative successful writes, while
/// `live_program_bytes` and `live_construction_bytes` are terminal liveness
/// snapshots. A refusal has no live program but retains the exact unpublished
/// construction bytes that will be abandoned while the error unwinds.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CompileConstructionActual {
    pub work: usize,
    pub allocations: usize,
    pub allocated_bytes: usize,
    pub copied_bytes: usize,
    pub initialized_bytes: usize,
    pub live_program_bytes: usize,
    pub live_construction_bytes: usize,
    pub construction_peak_bytes: usize,
    pub abandonable_bytes: usize,
    pub published: bool,
}

impl CompileConstructionActual {
    #[must_use]
    pub const fn is_closed(self) -> bool {
        self.copied_bytes <= self.initialized_bytes
            && self.live_program_bytes <= self.live_construction_bytes
            && self.live_construction_bytes <= self.construction_peak_bytes
            && self.abandonable_bytes <= self.live_construction_bytes
            && ((!self.published && self.live_program_bytes == 0)
                || (self.published
                    && self.live_program_bytes == self.live_construction_bytes
                    && self.abandonable_bytes == 0))
    }
}

/// Closed terminal receipt for construction-effect-aware continuation
/// compilation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompileConstructionAttemptReceipt {
    pub identity: CompileAttemptIdentity,
    pub prospective: CompileLimits,
    /// Optional caller allocation ceiling for the fixed-scalar residual.
    pub allocation_limit: Option<usize>,
    /// Optional input-only allocation census paired with the ceiling.
    pub prospective_allocations: Option<usize>,
    pub accounting: CompileAccounting,
    pub actual: CompileConstructionActual,
    authentication: CompileConstructionAttemptReceiptAuthentication,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CompileConstructionAttemptReceiptAuthentication {
    identity: CompileAttemptIdentity,
    prospective: CompileLimits,
    allocation_limit: Option<usize>,
    prospective_allocations: Option<usize>,
    accounting: CompileAccounting,
    actual: CompileConstructionActual,
}

impl CompileConstructionAttemptReceiptAuthentication {
    fn matches(self, receipt: &CompileConstructionAttemptReceipt) -> bool {
        self.identity == receipt.identity
            && self.prospective == receipt.prospective
            && self.allocation_limit == receipt.allocation_limit
            && self.prospective_allocations == receipt.prospective_allocations
            && self.accounting == receipt.accounting
            && self.actual == receipt.actual
    }
}

impl CompileConstructionAttemptReceipt {
    fn new(
        identity: CompileAttemptIdentity,
        prospective: CompileLimits,
        allocation_limit: Option<usize>,
        prospective_allocations: Option<usize>,
        accounting: &CompileAccounting,
        actual: CompileConstructionActual,
    ) -> Self {
        Self {
            identity,
            prospective,
            allocation_limit,
            prospective_allocations,
            accounting: *accounting,
            actual,
            authentication: CompileConstructionAttemptReceiptAuthentication {
                identity,
                prospective,
                allocation_limit,
                prospective_allocations,
                accounting: *accounting,
                actual,
            },
        }
    }

    #[must_use]
    pub const fn contains_actual(self) -> bool {
        self.accounting.hir_nodes <= self.prospective.max_hir_nodes
            && self.accounting.hir_depth <= self.prospective.max_hir_depth
            && self.accounting.peak_hir_stack_items <= self.prospective.max_hir_stack_items
            && self.accounting.literal_bytes <= self.prospective.max_literal_bytes
            && self.accounting.class_ranges <= self.prospective.max_class_ranges
            && self.accounting.utf8_sequences <= self.prospective.max_utf8_sequences
            && self.accounting.utf8_byte_ranges <= self.prospective.max_utf8_byte_ranges
            && self.accounting.look_assertions <= self.prospective.max_look_assertions
            && self.accounting.program_states <= self.prospective.max_program_states
            && self.accounting.temporary_states_peak <= self.prospective.max_temporary_states
            && self.accounting.program_bytes <= self.prospective.max_program_bytes
            && self.accounting.construction_peak_bytes <= self.prospective.max_program_bytes
            && self.accounting.work <= self.prospective.max_work
            && self.actual.work == self.accounting.work
            && self.actual.construction_peak_bytes == self.accounting.construction_peak_bytes
            && match (self.allocation_limit, self.prospective_allocations) {
                (Some(limit), Some(prospective)) => {
                    self.actual.allocations <= limit && self.actual.allocations <= prospective
                }
                (None, None) => true,
                _ => false,
            }
            && self.actual.is_closed()
            && !self.actual.published
    }

    /// Authenticate the exact immutable P/accounting/A terminal published by
    /// the compiler, in addition to checking its structural envelope.
    ///
    /// [`Self::contains_actual`] deliberately remains the legacy structural
    /// containment predicate. This stronger check rejects coordinated public
    /// field mutations that still fit within P.
    #[must_use]
    pub fn authenticates_canonical(&self) -> bool {
        self.authentication.matches(self) && (*self).contains_actual()
    }
}

/// Successful continuation construction paired with its exact effects.
#[derive(Debug)]
pub struct CompileConstructionAttempt {
    compiled: CompiledRegex,
    actual: CompileConstructionActual,
}

impl CompileConstructionAttempt {
    #[must_use]
    pub const fn actual(&self) -> CompileConstructionActual {
        self.actual
    }

    #[must_use]
    pub fn compiled(&self) -> &CompiledRegex {
        &self.compiled
    }

    #[must_use]
    pub fn into_parts(self) -> (CompiledRegex, CompileConstructionActual) {
        (self.compiled, self.actual)
    }

    #[must_use]
    pub fn into_compiled(self) -> CompiledRegex {
        self.compiled
    }
}

/// Terminal continuation construction error with exact partial effects.
#[derive(Debug, Eq, PartialEq)]
pub struct CompileConstructionAttemptError {
    source: Error,
    receipt: CompileConstructionAttemptReceipt,
}

impl core::fmt::Display for CompileConstructionAttemptError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(&self.source, formatter)
    }
}

impl std::error::Error for CompileConstructionAttemptError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl CompileConstructionAttemptError {
    #[allow(
        clippy::large_types_passed_by_value,
        reason = "the terminal receipt must move exactly once without a post-failure allocation"
    )]
    fn new(source: Error, receipt: CompileConstructionAttemptReceipt) -> Self {
        Self { source, receipt }
    }

    /// Exact typed compiler terminal.
    #[must_use]
    pub const fn source(&self) -> &Error {
        &self.source
    }

    /// Exact authenticated construction receipt paired with the terminal.
    #[must_use]
    pub const fn receipt(&self) -> &CompileConstructionAttemptReceipt {
        &self.receipt
    }

    /// Authenticate the private source/receipt pairing and canonical receipt.
    #[must_use]
    pub fn closes(&self) -> bool {
        self.receipt.authenticates_canonical()
            && construction_error_matches_receipt(&self.source, &self.receipt)
    }

    /// Consume the exact paired terminal without exposing mutable access while
    /// it remains a closable error.
    #[must_use]
    pub fn into_parts(self) -> (Error, CompileConstructionAttemptReceipt) {
        (self.source, self.receipt)
    }

    /// Project the exact construction refusal back to the legacy
    /// allocation-receipt surface without changing its typed source.
    ///
    /// The returned legacy receipt retains its established structural
    /// containment contract; it does not acquire this construction receipt's
    /// private exact-field authentication. Consume and authenticate this error
    /// before crossing that compatibility boundary.
    #[must_use]
    pub fn into_legacy_attempt_error(self) -> CompileAttemptError {
        CompileAttemptError {
            source: self.source,
            receipt: CompileAttemptReceipt {
                identity: self.receipt.identity,
                prospective: self.receipt.prospective,
                allocation_limit: self.receipt.allocation_limit,
                prospective_allocations: self.receipt.prospective_allocations,
                actual: self.receipt.accounting,
                actual_allocations: self
                    .receipt
                    .allocation_limit
                    .map(|_| self.receipt.actual.allocations),
                live_construction_bytes: self.receipt.actual.live_construction_bytes,
                published: false,
            },
        }
    }
}

fn construction_error_matches_receipt(
    source: &Error,
    receipt: &CompileConstructionAttemptReceipt,
) -> bool {
    match *source {
        Error::ResourceLimit {
            resource,
            required,
            limit,
        } => {
            required > limit
                && compile_resource_ceiling(receipt, resource)
                    .is_some_and(|ceiling| limit == ceiling)
        }
        Error::ArithmeticOverflow { resource } | Error::AllocationFailed { resource, .. } => {
            is_compile_resource(resource)
        }
        Error::Unsupported(_)
        | Error::InvalidRepetition
        | Error::EmptyAlternation
        | Error::SameBoundaryCycle
        | Error::InternalInvariant(_) => true,
        Error::InvalidRange { .. } | Error::InvalidUtf8ForUnicodeWordBoundary => false,
    }
}

fn compile_resource_ceiling(
    receipt: &CompileConstructionAttemptReceipt,
    resource: Resource,
) -> Option<usize> {
    match resource {
        Resource::HirNodes => Some(receipt.prospective.max_hir_nodes),
        Resource::HirDepth => Some(receipt.prospective.max_hir_depth),
        Resource::HirStackItems => Some(receipt.prospective.max_hir_stack_items),
        Resource::LiteralBytes => Some(receipt.prospective.max_literal_bytes),
        Resource::ClassRanges => Some(receipt.prospective.max_class_ranges),
        Resource::Utf8Sequences => Some(receipt.prospective.max_utf8_sequences),
        Resource::Utf8ByteRanges => Some(receipt.prospective.max_utf8_byte_ranges),
        Resource::LookAssertions => Some(receipt.prospective.max_look_assertions),
        Resource::RepeatBound => usize::try_from(receipt.prospective.max_repeat_bound).ok(),
        Resource::ProgramStates => Some(receipt.prospective.max_program_states),
        Resource::TemporaryStates => Some(receipt.prospective.max_temporary_states),
        Resource::ProgramBytes => Some(receipt.prospective.max_program_bytes),
        Resource::CompileWork => Some(receipt.prospective.max_work),
        Resource::Allocations => receipt.allocation_limit,
        Resource::Boundaries
        | Resource::TableCells
        | Resource::RandomAccessBytes
        | Resource::ScratchBytes
        | Resource::LogBytes
        | Resource::SequentialBytes
        | Resource::MatchEvents
        | Resource::OutputMatches
        | Resource::OutputBytes
        | Resource::SpanSum
        | Resource::PeakBytes
        | Resource::ExecutionWork => None,
    }
}

const fn is_compile_resource(resource: Resource) -> bool {
    matches!(
        resource,
        Resource::HirNodes
            | Resource::HirDepth
            | Resource::HirStackItems
            | Resource::LiteralBytes
            | Resource::ClassRanges
            | Resource::Utf8Sequences
            | Resource::Utf8ByteRanges
            | Resource::LookAssertions
            | Resource::RepeatBound
            | Resource::ProgramStates
            | Resource::TemporaryStates
            | Resource::ProgramBytes
            | Resource::CompileWork
            | Resource::Allocations
            | Resource::ExecutionWork
    )
}

/// Stable identity of the semantic continuation program.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PlanId(pub(crate) [u8; 16]);

impl PlanId {
    #[must_use]
    pub const fn bytes(self) -> [u8; 16] {
        self.0
    }
}

impl core::fmt::Display for PlanId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Validated capture-free continuation program.
#[derive(Debug)]
pub struct CompiledRegex {
    pub(crate) program: Program,
    pub(crate) candidate: Option<candidate::Plan>,
    pub(crate) url_aggregate: Option<fre_kernels::UrlAggregatePlan>,
    pub(crate) state_byte_span_sum: Option<StateByteSpanSumPlan>,
    pub(crate) ordered_bounded_span_sum: Option<OrderedBoundedSpanSumPlan>,
    pub(crate) required_suffixes: RequiredSuffixes,
    pub(crate) required_literals: RequiredLiteralSets,
    pub(crate) required_internal_anchor: Option<fre_kernels::RequiredInternalAnchorPlan>,
    pub(crate) terminal_frontier: TerminalFrontierSeed,
    /// Authenticated whole-match byte minimum from the same canonical HIR.
    ///
    /// A positive value bounds the number of selected non-overlapping
    /// matches without inspecting the source. Nullable and empty-language
    /// programs retain their exact `Some(0)` / `None` distinction.
    pub(crate) minimum_match_bytes: Option<usize>,
    plan_id: PlanId,
    accounting: CompileAccounting,
}

const MAX_STATE_BYTE_SPAN_SUM_LITERAL_BYTES: usize = 64;

/// Source-independent proof for a compact byte-topology `SpanSum` executor.
///
/// Each variant is an exact canonical-HIR theorem, not a candidate filter:
/// the executor may therefore publish it as the terminal physical route
/// without a continuation-program fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StateByteSpanSumPlan {
    topology: StateByteSpanSumTopology,
    first: ByteSet,
    second: ByteSet,
    literal: [u8; MAX_STATE_BYTE_SPAN_SUM_LITERAL_BYTES],
    literal_failure: [u8; MAX_STATE_BYTE_SPAN_SUM_LITERAL_BYTES],
    literal_len: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StateByteSpanSumTopology {
    /// Exact greedy `C* L D*`, with nonempty `L`, `L ⊆ C`, and `C ⊆ D`.
    GreedyPrefixLiteralSuffix,
    /// Exact greedy `W+ S+ L`, with disjoint `W`/`S`, `L[0] ∈ W`.
    DisjointRunsLiteral,
}

impl StateByteSpanSumPlan {
    pub(crate) const fn topology(&self) -> StateByteSpanSumTopology {
        self.topology
    }

    pub(crate) const fn first(&self) -> ByteSet {
        self.first
    }

    pub(crate) const fn second(&self) -> ByteSet {
        self.second
    }

    pub(crate) fn literal(&self) -> &[u8] {
        &self.literal[..self.literal_len]
    }

    pub(crate) fn literal_failure(&self) -> &[u8] {
        &self.literal_failure[..self.literal_len]
    }

    const fn materialized_bytes() -> usize {
        core::mem::size_of::<Self>()
    }

    const fn retained_slot_bytes() -> usize {
        // `CompiledRegex` always retains this inline slot. An absent theorem
        // therefore owns the same fixed program storage as a materialized
        // theorem; only the logical plan count differs.
        core::mem::size_of::<Option<Self>>()
    }

    const fn topology_tag(&self) -> u8 {
        match self.topology {
            StateByteSpanSumTopology::GreedyPrefixLiteralSuffix => 1,
            StateByteSpanSumTopology::DisjointRunsLiteral => 2,
        }
    }
}

const MAX_REQUIRED_LITERAL_SETS: usize = 4;

/// Bounded canonical-HIR proof used only to reject a source that cannot match.
///
/// Each nonzero set is an independent theorem: every match consumes at least
/// one ASCII byte in that set. Concatenation retains independent theorems in
/// source order; alternation conservatively unions one theorem from every
/// arm. Unsupported or non-ASCII forms simply retain no theorem.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RequiredLiteralSets {
    sets: [u128; MAX_REQUIRED_LITERAL_SETS],
    len: u8,
}

impl RequiredLiteralSets {
    const fn empty() -> Self {
        Self {
            sets: [0; MAX_REQUIRED_LITERAL_SETS],
            len: 0,
        }
    }

    const fn retained_bytes() -> usize {
        core::mem::size_of::<Self>()
    }

    pub(crate) fn len(self) -> usize {
        usize::from(self.len)
    }

    pub(crate) const fn is_empty(self) -> bool {
        self.len == 0
    }

    pub(crate) fn iter(self) -> impl Iterator<Item = u128> {
        self.sets.into_iter().take(self.len())
    }

    fn push(&mut self, set: u128) {
        if set == 0 || self.iter().any(|existing| existing == set) {
            return;
        }
        let index = self.len();
        if index == MAX_REQUIRED_LITERAL_SETS {
            return;
        }
        self.sets[index] = set;
        self.len = self.len.saturating_add(1);
    }

    fn append(&mut self, other: Self) {
        for set in other.iter() {
            self.push(set);
        }
    }
}

/// A small construction-proved set: every match ends with one of these
/// nonempty byte strings. It is only an execution hint; an ineligible HIR
/// retains the dense continuation route.
#[derive(Debug)]
pub(crate) struct RequiredSuffixes {
    bytes: ExactVec<u8>,
    ends: ExactVec<usize>,
}

const UNICODE_SUFFIX_DOMAIN_TAG: usize = 1_usize << (usize::BITS - 1);

impl Default for RequiredSuffixes {
    fn default() -> Self {
        Self {
            bytes: ExactVec::try_with_capacity(0).expect("u8 has a valid empty exact allocation"),
            ends: ExactVec::try_with_capacity(0).expect("usize has a valid empty exact allocation"),
        }
    }
}

impl RequiredSuffixes {
    pub(crate) fn iter(&self) -> impl Iterator<Item = &[u8]> {
        let mut start = 0_usize;
        self.ends.iter().map(move |&end| {
            let end = end & !UNICODE_SUFFIX_DOMAIN_TAG;
            let suffix = &self.bytes[start..end];
            start = end;
            suffix
        })
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.ends.is_empty()
    }

    pub(crate) fn prefers_sparse_verification(&self) -> bool {
        self.ends
            .first()
            .is_some_and(|end| end & UNICODE_SUFFIX_DOMAIN_TAG != 0)
    }

    fn retained_bytes(&self) -> Result<usize, Error> {
        add(
            self.bytes.len(),
            mul(
                self.ends.len(),
                core::mem::size_of::<usize>(),
                Resource::ProgramBytes,
            )?,
            Resource::ProgramBytes,
        )
    }
}

const MAX_TERMINAL_FRONTIER_PREFIX_BYTES: usize = 32;
const MIN_TERMINAL_FRONTIER_PREFIX_BYTES: usize = 2;

/// Construction-proved hints for the unbounded terminal-frontier route.
///
/// Every admitted match starts with `prefix` and ends immediately after one
/// byte in `terminals`. Both facts come from the same canonical HIR used to
/// build the continuation program. Fixed inline storage makes the proof
/// immutable without introducing a second allocation or allocator-dependent
/// capacity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TerminalFrontierSeed {
    prefix: [u8; MAX_TERMINAL_FRONTIER_PREFIX_BYTES],
    prefix_len: usize,
    terminals: TerminalByteSet,
}

impl TerminalFrontierSeed {
    const fn empty() -> Self {
        Self {
            prefix: [0; MAX_TERMINAL_FRONTIER_PREFIX_BYTES],
            prefix_len: 0,
            terminals: TerminalByteSet::empty(),
        }
    }

    pub(crate) const fn is_empty(self) -> bool {
        self.prefix_len == 0 || self.terminals.len == 0
    }

    pub(crate) fn prefix_bytes(&self) -> &[u8] {
        &self.prefix[..self.prefix_len]
    }

    pub(crate) const fn prefix_len(self) -> usize {
        self.prefix_len
    }

    pub(crate) fn terminal_bytes(self) -> impl Iterator<Item = u8> {
        self.terminals.iter()
    }

    #[cfg(test)]
    pub(crate) fn terminal_matches(self, byte: u8) -> bool {
        self.terminal_bytes().any(|terminal| terminal == byte)
    }

    #[cfg(test)]
    pub(crate) const fn terminal_count(self) -> usize {
        self.terminals.len
    }

    const fn retained_bytes() -> usize {
        // The certificate is retained inline in every compiled artifact. Its
        // complete fixed representation, including an empty/ineligible seed,
        // is therefore persistent program storage. Logical prefix/terminal
        // lengths must not under-report the zero-filled arrays or metadata.
        core::mem::size_of::<Self>()
    }
}

impl CompiledRegex {
    /// Compile canonical HIR for the explicit pinned byte profile.
    ///
    /// Validation first proves a depth bound. Lowering recursion is therefore
    /// bounded by `limits.max_hir_depth`; repetition expansion itself is
    /// iterative and separately limited.
    pub fn from_hir(
        hir: &Hir,
        profile: RustByteProfile,
        limits: CompileLimits,
    ) -> Result<Self, Error> {
        Self::compile(hir, profile, limits, CapturePolicy::Reject, false)
    }

    /// Compile canonical HIR for an API that exposes whole-match values only.
    ///
    /// Capture annotations are semantically transparent for whole-match spans,
    /// counts and matched-byte sums. This entry point handles them directly in
    /// the already bounded validation and lowering traversals: it neither
    /// clones the HIR nor allocates a capture-free copy. The exact number of
    /// annotations and transparent traversal steps is reported in
    /// [`CompileAccounting`]. Callers must not use this plan to implement a
    /// capture group API.
    pub fn from_hir_erasing_captures_for_whole_match(
        hir: &Hir,
        profile: RustByteProfile,
        limits: CompileLimits,
    ) -> Result<Self, Error> {
        Self::compile(
            hir,
            profile,
            limits,
            CapturePolicy::EraseForWholeMatch,
            false,
        )
    }

    /// Compile a capture-erased selector whose proved top-level ordered
    /// alternation is retained as one batched root-choice program.
    ///
    /// This constructor exposes whole-match Count only through the dedicated
    /// ordered-root operation. Its caller must independently prove fixed
    /// capture participation from this same canonical HIR.
    #[doc(hidden)]
    pub fn from_hir_erasing_captures_for_ordered_root_count(
        hir: &Hir,
        profile: RustByteProfile,
        limits: CompileLimits,
    ) -> Result<Self, Error> {
        Self::compile(
            hir,
            profile,
            limits,
            CapturePolicy::EraseForWholeMatch,
            true,
        )
    }

    /// Compile the whole-match-only program while retaining exact cumulative
    /// P/A construction evidence on every terminal refusal.
    #[allow(
        clippy::result_large_err,
        reason = "the typed terminal receipt preserves the complete bounded compiler ledger"
    )]
    pub fn from_hir_erasing_captures_for_whole_match_with_receipt(
        hir: &Hir,
        profile: RustByteProfile,
        limits: CompileLimits,
    ) -> Result<Self, CompileAttemptError> {
        Self::compile_with_optional_allocation_receipt(hir, profile, limits, None)
            .map(|(compiled, _)| compiled)
    }

    /// U1-only whole-match compiler entry point with a prospective/allocation
    /// receipt. Ordinary compiler entry points never enable this scope.
    #[doc(hidden)]
    #[allow(
        clippy::result_large_err,
        reason = "the typed terminal receipt preserves the complete bounded compiler ledger"
    )]
    pub fn from_hir_erasing_captures_for_whole_match_with_allocation_receipt(
        hir: &Hir,
        profile: RustByteProfile,
        limits: CompileLimits,
        allocation_limit: usize,
        prospective_allocations: usize,
    ) -> Result<(Self, usize), CompileAttemptError> {
        Self::compile_with_optional_allocation_receipt(
            hir,
            profile,
            limits,
            Some((allocation_limit, prospective_allocations)),
        )
    }

    /// Compile an arbitrary whole-match continuation while retaining exact
    /// construction effects on both success and refusal.
    ///
    /// This observation scope does not add a resource limit. It therefore
    /// preserves the semantic and resource-error ordering of the ordinary
    /// receipt-bearing entry point while making every successful capacity
    /// change and committed write visible to the aggregate construction
    /// transaction.
    #[allow(
        clippy::result_large_err,
        reason = "the typed terminal receipt preserves the complete bounded compiler ledger"
    )]
    pub fn from_hir_erasing_captures_for_whole_match_with_construction_receipt(
        hir: &Hir,
        profile: RustByteProfile,
        limits: CompileLimits,
    ) -> Result<CompileConstructionAttempt, CompileConstructionAttemptError> {
        Self::compile_with_construction_receipt(hir, profile, limits, None)
    }

    /// Fixed-scalar residual compiler entry point combining the existing
    /// allocation census with exact construction effects.
    #[doc(hidden)]
    #[allow(
        clippy::result_large_err,
        reason = "the typed terminal receipt preserves the complete bounded compiler ledger"
    )]
    pub fn from_hir_erasing_captures_for_whole_match_with_construction_and_allocation_receipt(
        hir: &Hir,
        profile: RustByteProfile,
        limits: CompileLimits,
        allocation_limit: usize,
        prospective_allocations: usize,
    ) -> Result<CompileConstructionAttempt, CompileConstructionAttemptError> {
        Self::compile_with_construction_receipt(
            hir,
            profile,
            limits,
            Some(AllocationScope {
                limit: allocation_limit,
                prospective: prospective_allocations,
            }),
        )
    }

    #[allow(
        clippy::result_large_err,
        reason = "the typed terminal receipt preserves the complete bounded compiler ledger"
    )]
    fn compile_with_construction_receipt(
        hir: &Hir,
        profile: RustByteProfile,
        limits: CompileLimits,
        allocation_scope: Option<AllocationScope>,
    ) -> Result<CompileConstructionAttempt, CompileConstructionAttemptError> {
        let identity = CompileAttemptIdentity {
            profile,
            kind: CompileAttemptKind::EraseCapturesForWholeMatch,
        };
        let mut budget = CompileBudget::new_construction_receipt(limits, allocation_scope);
        let result = match allocation_scope {
            Some(scope) => enforce(scope.prospective, scope.limit, Resource::Allocations),
            None => Ok(()),
        }
        .and_then(|()| {
            Self::compile_with_budget(
                hir,
                profile,
                limits,
                CapturePolicy::EraseForWholeMatch,
                false,
                &mut budget,
            )
        });
        match result {
            Ok(compiled) => {
                let actual = budget.construction_actual(true);
                if !actual.is_closed()
                    || actual.live_program_bytes != compiled.compile_accounting().program_bytes
                    || allocation_scope.is_some_and(|scope| actual.allocations != scope.prospective)
                {
                    return Err(CompileConstructionAttemptError::new(
                        Error::InternalInvariant(
                            "successful compile construction receipt did not close",
                        ),
                        budget.construction_failure_receipt(identity),
                    ));
                }
                Ok(CompileConstructionAttempt { compiled, actual })
            }
            Err(source) => {
                let receipt = budget.construction_failure_receipt(identity);
                let source = if receipt.contains_actual() {
                    source
                } else {
                    Error::InternalInvariant(
                        "compile construction actual ledger exceeds its envelope",
                    )
                };
                Err(CompileConstructionAttemptError::new(source, receipt))
            }
        }
    }

    #[allow(
        clippy::result_large_err,
        reason = "the typed terminal receipt preserves the complete bounded compiler ledger"
    )]
    fn compile_with_optional_allocation_receipt(
        hir: &Hir,
        profile: RustByteProfile,
        limits: CompileLimits,
        allocation: Option<(usize, usize)>,
    ) -> Result<(Self, usize), CompileAttemptError> {
        let identity = CompileAttemptIdentity {
            profile,
            kind: CompileAttemptKind::EraseCapturesForWholeMatch,
        };
        let scope = allocation.map(|(limit, prospective)| AllocationScope { limit, prospective });
        let mut budget = CompileBudget::new_receipt(limits, scope);
        let result = match scope {
            Some(scope) => enforce(scope.prospective, scope.limit, Resource::Allocations),
            None => Ok(()),
        }
        .and_then(|()| {
            Self::compile_with_budget(
                hir,
                profile,
                limits,
                CapturePolicy::EraseForWholeMatch,
                false,
                &mut budget,
            )
        });
        match result {
            Ok(compiled)
                if scope.is_none_or(|scope| budget.actual_allocations == scope.prospective) =>
            {
                Ok((compiled, budget.actual_allocations))
            }
            Ok(_) => Err(CompileAttemptError {
                source: Error::InternalInvariant(
                    "fixed scalar allocation census differs from compilation",
                ),
                receipt: budget.failure_receipt(identity),
            }),
            Err(source) => {
                let receipt = budget.failure_receipt(identity);
                let source = if receipt.contains_actual() {
                    source
                } else {
                    Error::InternalInvariant(
                        "compile failure actual ledger exceeds its prospective envelope",
                    )
                };
                Err(CompileAttemptError { source, receipt })
            }
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "compile keeps resource lifetime and publication ordering in one auditable transaction"
    )]
    fn compile(
        hir: &Hir,
        profile: RustByteProfile,
        limits: CompileLimits,
        capture_policy: CapturePolicy,
        ordered_root: bool,
    ) -> Result<Self, Error> {
        let mut budget = CompileBudget::new(limits);
        Self::compile_with_budget(
            hir,
            profile,
            limits,
            capture_policy,
            ordered_root,
            &mut budget,
        )
    }

    #[allow(
        clippy::too_many_lines,
        reason = "compile keeps resource lifetime and publication ordering in one auditable transaction"
    )]
    fn compile_with_budget(
        hir: &Hir,
        profile: RustByteProfile,
        limits: CompileLimits,
        capture_policy: CapturePolicy,
        ordered_root: bool,
        budget: &mut CompileBudget,
    ) -> Result<Self, Error> {
        validate_hir(hir, profile, capture_policy, budget)?;
        let minimum_match_bytes = hir.properties().minimum_len();
        let url_aggregate = if ordered_root {
            None
        } else {
            build_url_aggregate_plan(hir, profile, capture_policy, limits, budget)?
        };
        let (
            required_suffixes,
            required_literals,
            required_internal_anchor,
            terminal_frontier,
            mut start_domain,
            retained_program_bytes,
        ) = build_retained_components(hir, profile, limits, budget)?;
        let state_byte_span_sum_slot_bytes = StateByteSpanSumPlan::retained_slot_bytes();
        budget.preflight_receipt_construction_bytes(state_byte_span_sum_slot_bytes)?;
        if budget.receipt_scope {
            budget.acquire_checked_construction_bytes(state_byte_span_sum_slot_bytes)?;
        } else {
            budget.acquire_construction_bytes(state_byte_span_sum_slot_bytes)?;
            enforce(
                budget.current_construction_bytes,
                limits.max_program_bytes,
                Resource::ProgramBytes,
            )?;
        }
        let state_byte_span_sum = if ordered_root {
            None
        } else {
            build_state_byte_span_sum_plan(hir, profile, capture_policy, budget)?
        };
        budget.record_initialization(state_byte_span_sum_slot_bytes, false)?;
        if let Some(plan) = &state_byte_span_sum {
            budget.record_copy(plan.literal().len())?;
        }
        budget.accounting.state_byte_span_sum_persistent_bytes = state_byte_span_sum_slot_bytes;
        let ordered_bounded_span_sum = if ordered_root {
            None
        } else {
            ordered_bounded_span_sum::build_plan(hir, profile, capture_policy, budget)?
        };
        let mut candidate = if ordered_root {
            None
        } else {
            build_candidate_plan(hir, profile, capture_policy, budget)?
        };
        let candidate_bytes = candidate
            .as_ref()
            .map_or(Ok(0), candidate::Plan::retained_bytes)?;
        let retained_program_bytes = add(
            add(
                add(
                    retained_program_bytes,
                    candidate_bytes,
                    Resource::ProgramBytes,
                )?,
                add(
                    state_byte_span_sum_slot_bytes,
                    ordered_bounded_span_sum
                        .as_ref()
                        .map_or(0, |_| OrderedBoundedSpanSumPlan::retained_bytes()),
                    Resource::ProgramBytes,
                )?,
                Resource::ProgramBytes,
            )?,
            url_aggregate
                .as_ref()
                .map_or(0, |plan| plan.build_accounting().persistent_bytes),
            Resource::ProgramBytes,
        )?;
        enforce(
            retained_program_bytes,
            limits.max_program_bytes,
            Resource::ProgramBytes,
        )?;
        let mut builder = Builder::new(
            limits.max_program_states,
            profile,
            capture_policy,
            retained_program_bytes,
            budget,
        );
        let accept = builder.push(Inst::Match)?;
        let (entry, root_alternation_arms) = if ordered_root {
            builder.compile_ordered_root(hir, accept, 1)?
        } else if let Some(plan) = &mut candidate {
            (
                builder.compile_candidate_root(hir, accept, &mut plan.entries)?,
                0,
            )
        } else {
            (builder.compile_node(hir, accept, 1)?, 0)
        };
        let scalar_range_bytes = builder.scalar_range_bytes;
        let insts = builder.finish()?;
        enforce(
            insts.len(),
            limits.max_program_states,
            Resource::ProgramStates,
        )?;
        let certificate =
            certify_program(&insts, scalar_range_bytes, retained_program_bytes, budget)?;
        // `program_bytes` visits every instruction to include each deeply
        // owned scalar-range box in the exact retained-byte total.
        budget.charge(insts.len())?;
        let program_bytes = add(
            program_bytes(
                &insts,
                insts.len(),
                certificate.epsilon_order.len(),
                certificate.split_rank.len(),
            )?,
            retained_program_bytes,
            Resource::ProgramBytes,
        )?;
        enforce(
            program_bytes,
            limits.max_program_bytes,
            Resource::ProgramBytes,
        )?;
        budget.accounting.program_states = insts.len();
        budget.accounting.program_bytes = program_bytes;
        budget.accounting.execution_state_work = certificate.execution_state_work;
        budget.accounting.predecessor_edges = certificate.predecessor_edges;
        budget.accounting.has_scalar_transitions = certificate.has_scalar_transition;
        budget.accounting.max_scalar_search_checks = certificate.max_scalar_search_checks;
        let mut program = Program {
            insts,
            entry,
            epsilon_order: certificate.epsilon_order,
            split_rank: certificate.split_rank,
            split_count: certificate.split_count,
            root_split_count: certificate.root_split_count,
            root_alternation_arms,
            execution_state_work: certificate.execution_state_work,
            predecessor_edges: certificate.predecessor_edges,
            has_scalar_transition: certificate.has_scalar_transition,
            has_assertion: certificate.has_assertion,
            max_scalar_search_checks: certificate.max_scalar_search_checks,
            has_unicode_word_boundary: false,
            start_domain: StartDomain::AnyBoundary,
        };
        start_domain = partitioned_start_domain(start_domain, &program, budget)?;
        program.start_domain = start_domain;
        let mut plan_id = finalize_program(&mut program, profile, terminal_frontier, budget)?;
        plan_id = bind_start_domain_identity(plan_id, start_domain, budget)?;
        plan_id = bind_required_literal_identity(plan_id, required_literals, budget)?;
        if let Some(candidate) = &candidate {
            plan_id = bind_candidate_identity(plan_id, candidate, budget)?;
        }
        if let Some(plan) = &required_internal_anchor {
            plan_id = bind_required_internal_anchor_identity(plan_id, plan, budget)?;
        }
        if let Some(plan) = &url_aggregate {
            plan_id = bind_url_aggregate_identity(plan_id, plan, budget)?;
        }
        if let Some(plan) = &state_byte_span_sum {
            plan_id = bind_state_byte_span_sum_identity(plan_id, plan, budget)?;
        }
        if let Some(plan) = &ordered_bounded_span_sum {
            plan_id = ordered_bounded_span_sum::bind_plan_identity(plan_id, plan, budget)?;
        }
        if budget.current_construction_bytes != program_bytes {
            return Err(Error::InternalInvariant(
                "compiler retained bytes differ from construction accounting",
            ));
        }
        let accounting = budget.accounting;
        Ok(Self {
            program,
            candidate,
            url_aggregate,
            state_byte_span_sum,
            ordered_bounded_span_sum,
            required_suffixes,
            required_literals,
            required_internal_anchor,
            terminal_frontier,
            minimum_match_bytes,
            plan_id,
            accounting,
        })
    }

    #[must_use]
    pub const fn plan_id(&self) -> PlanId {
        self.plan_id
    }

    #[must_use]
    pub const fn compile_accounting(&self) -> CompileAccounting {
        self.accounting
    }

    #[must_use]
    pub fn state_count(&self) -> usize {
        self.program.insts.len()
    }

    /// Capacity of the pinned Rust 1.93 base `Vec` HIR stack immediately
    /// after its initial `try_reserve_exact(1)` allocation.
    ///
    /// This is exposed for the U1 input-only allocation census. Callers must
    /// refuse that optional route when they are not using the pinned compiler
    /// profile instead of guessing a different allocator graph.
    #[doc(hidden)]
    #[must_use]
    pub const fn pinned_hir_stack_initial_capacity() -> usize {
        1
    }

    /// Model one capacity-changing `Vec<(&Hir, usize)>::try_reserve(1)` call
    /// in the pinned Rust 1.93 compiler graph.
    #[doc(hidden)]
    #[must_use]
    pub const fn pinned_hir_stack_capacity_after_push(
        current_capacity: usize,
        required_len: usize,
    ) -> Option<usize> {
        pinned_vec_capacity_after_push(
            current_capacity,
            required_len,
            core::mem::size_of::<(&Hir, usize)>(),
        )
    }

    /// Model one capacity-changing `Vec<Inst>::try_reserve(1)` call in the
    /// pinned Rust 1.93 compiler graph.
    #[doc(hidden)]
    #[must_use]
    pub const fn pinned_state_capacity_after_push(
        current_capacity: usize,
        required_len: usize,
    ) -> Option<usize> {
        pinned_vec_capacity_after_push(current_capacity, required_len, core::mem::size_of::<Inst>())
    }
}

/// Rust 1.93's `RawVec` amortized growth rule for a non-ZST `Vec` whose
/// caller requests exactly the one missing slot. The minimum non-zero
/// capacity is 8 for one-byte elements, 4 for elements up to 1 KiB, and 1 for
/// larger elements; subsequent growth doubles unless the required length is
/// larger. Returning `None` makes overflow an authenticated census refusal.
const fn pinned_vec_capacity_after_push(
    current_capacity: usize,
    required_len: usize,
    element_size: usize,
) -> Option<usize> {
    if required_len <= current_capacity {
        return Some(current_capacity);
    }
    if element_size == 0 {
        return Some(usize::MAX);
    }
    let minimum = if element_size == 1 {
        8
    } else if element_size <= 1_024 {
        4
    } else {
        1
    };
    let Some(doubled) = current_capacity.checked_mul(2) else {
        return None;
    };
    let grown = if doubled > minimum { doubled } else { minimum };
    Some(if required_len > grown {
        required_len
    } else {
        grown
    })
}

struct PackedUrlTlds {
    bytes: ExactVec<u8>,
    ends: ExactVec<usize>,
    allocated_bytes: usize,
}

impl PackedUrlTlds {
    fn release(self, budget: &mut CompileBudget) -> Result<(), Error> {
        let allocated_bytes = self.allocated_bytes;
        drop(self);
        budget.release_construction_bytes(allocated_bytes)
    }
}

struct UrlBuildAuthority<'a> {
    budget: &'a mut CompileBudget,
    error: Option<Error>,
    retained_attempt_bytes: usize,
}

impl UrlBuildAuthority<'_> {
    fn record(
        &mut self,
        result: Result<(), Error>,
    ) -> Result<(), fre_kernels::UrlAggregateBuildError> {
        match result {
            Ok(()) => Ok(()),
            Err(error) => {
                self.error = Some(error);
                Err(fre_kernels::UrlAggregateBuildError::Invariant(
                    "authoritative aggregate compile budget refused URL build",
                ))
            }
        }
    }
}

impl fre_kernels::UrlAggregateBuildAuthority for UrlBuildAuthority<'_> {
    fn charge_work(&mut self, amount: usize) -> Result<(), fre_kernels::UrlAggregateBuildError> {
        let result = self.budget.charge(amount);
        self.record(result)
    }

    fn retain_bytes(&mut self, amount: usize) -> Result<(), fre_kernels::UrlAggregateBuildError> {
        let result = self.budget.acquire_checked_construction_bytes(amount);
        if result.is_ok() {
            self.retained_attempt_bytes = amount;
        }
        self.record(result)
    }

    fn release_bytes(&mut self, amount: usize) -> Result<(), fre_kernels::UrlAggregateBuildError> {
        let result = self.budget.release_construction_bytes(amount);
        self.record(result)
    }
}

fn build_state_byte_span_sum_plan(
    hir: &Hir,
    profile: RustByteProfile,
    capture_policy: CapturePolicy,
    budget: &mut CompileBudget,
) -> Result<Option<StateByteSpanSumPlan>, Error> {
    let start_work = budget.accounting.work;
    budget.charge(1)?;
    if profile.unicode || capture_policy != CapturePolicy::EraseForWholeMatch {
        return Ok(None);
    }
    let Some(parts) = state_byte_concat_parts(hir, budget)? else {
        return Ok(None);
    };
    budget.charge(1)?;
    if parts.len() != 3 {
        return Ok(None);
    }
    let mut proof = None;
    if let Some((first_min, first)) = state_byte_unbounded_class(&parts[0], budget)?
        && let Some(literal) = state_byte_literal(&parts[1], budget)?
        && !literal.is_empty()
        && literal.len() <= MAX_STATE_BYTE_SPAN_SUM_LITERAL_BYTES
        && let Some((second_min, second)) = state_byte_unbounded_class(&parts[2], budget)?
    {
        budget.charge(add(literal.len(), 4, Resource::CompileWork)?)?;
        if first_min == 0
            && second_min == 0
            && literal.iter().copied().all(|byte| first.contains(byte))
            && first
                .0
                .iter()
                .zip(second.0)
                .all(|(&left, right)| left & !right == 0)
        {
            proof = Some((
                StateByteSpanSumTopology::GreedyPrefixLiteralSuffix,
                first,
                second,
                literal,
            ));
        }
    }
    if proof.is_none()
        && let Some((first_min, first)) = state_byte_unbounded_class(&parts[0], budget)?
        && let Some((second_min, second)) = state_byte_unbounded_class(&parts[1], budget)?
        && let Some(literal) = state_byte_literal(&parts[2], budget)?
        && !literal.is_empty()
        && literal.len() <= MAX_STATE_BYTE_SPAN_SUM_LITERAL_BYTES
    {
        budget.charge(add(literal.len(), 4, Resource::CompileWork)?)?;
        if first_min == 1
            && second_min == 1
            && first
                .0
                .iter()
                .zip(second.0)
                .all(|(&left, right)| left & right == 0)
            && first.contains(literal[0])
        {
            proof = Some((
                StateByteSpanSumTopology::DisjointRunsLiteral,
                first,
                second,
                literal,
            ));
        }
    }
    let Some((topology, first, second, literal)) = proof else {
        return Ok(None);
    };

    let retained_bytes = StateByteSpanSumPlan::materialized_bytes();
    budget.charge(add(retained_bytes, literal.len(), Resource::CompileWork)?)?;
    let literal_failure = state_byte_literal_failure(literal, budget)?;
    let mut retained_literal = [0_u8; MAX_STATE_BYTE_SPAN_SUM_LITERAL_BYTES];
    retained_literal[..literal.len()].copy_from_slice(literal);
    let plan = StateByteSpanSumPlan {
        topology,
        first,
        second,
        literal: retained_literal,
        literal_failure,
        literal_len: literal.len(),
    };
    budget.accounting.state_byte_span_sum_plans = 1;
    budget.accounting.state_byte_span_sum_literal_bytes = literal.len();
    budget.accounting.state_byte_span_sum_build_work = budget
        .accounting
        .work
        .checked_sub(start_work)
        .ok_or(Error::InternalInvariant(
            "state-byte SpanSum build work underflow",
        ))?;
    Ok(Some(plan))
}

fn state_byte_literal_failure(
    literal: &[u8],
    budget: &mut CompileBudget,
) -> Result<[u8; MAX_STATE_BYTE_SPAN_SUM_LITERAL_BYTES], Error> {
    let mut failure = [0_u8; MAX_STATE_BYTE_SPAN_SUM_LITERAL_BYTES];
    let mut matched = 0_usize;
    for index in 1..literal.len() {
        while matched > 0 {
            budget.charge(1)?;
            if literal[index] == literal[matched] {
                break;
            }
            let fallback_index = matched.checked_sub(1).ok_or(Error::InternalInvariant(
                "positive state-byte failure prefix lost its predecessor",
            ))?;
            matched = usize::from(failure[fallback_index]);
        }
        if matched == 0 {
            budget.charge(1)?;
            if literal[index] == literal[0] {
                matched = 1;
            }
        } else {
            // The equality terminating the fallback loop was already
            // charged and proved above.
            matched = add(matched, 1, Resource::CompileWork)?;
        }
        failure[index] = u8::try_from(matched).map_err(|_| {
            Error::InternalInvariant(
                "state-byte literal failure prefix exceeds its fixed byte representation",
            )
        })?;
        budget.charge(1)?;
    }
    Ok(failure)
}

fn state_byte_concat_parts<'a>(
    mut hir: &'a Hir,
    budget: &mut CompileBudget,
) -> Result<Option<&'a [Hir]>, Error> {
    loop {
        budget.charge(1)?;
        match hir.kind() {
            HirKind::Capture(capture) => hir = &capture.sub,
            HirKind::Concat(parts) => return Ok(Some(parts)),
            _ => return Ok(None),
        }
    }
}

fn state_byte_unbounded_class(
    mut hir: &Hir,
    budget: &mut CompileBudget,
) -> Result<Option<(u32, ByteSet)>, Error> {
    loop {
        budget.charge(1)?;
        match hir.kind() {
            HirKind::Capture(capture) => hir = &capture.sub,
            HirKind::Repetition(repetition)
                if repetition.greedy
                    && repetition.max.is_none()
                    && matches!(repetition.min, 0 | 1) =>
            {
                let mut sub = &*repetition.sub;
                loop {
                    budget.charge(1)?;
                    match sub.kind() {
                        HirKind::Capture(capture) => sub = &capture.sub,
                        HirKind::Class(Class::Bytes(class)) => {
                            let mut bytes = ByteSet::empty();
                            for range in class.ranges() {
                                let width = inclusive_byte_width(range.start(), range.end())?;
                                budget.charge(add(width, 1, Resource::CompileWork)?)?;
                                bytes.insert_range(range.start(), range.end());
                            }
                            return Ok(Some((repetition.min, bytes)));
                        }
                        HirKind::Literal(regex_syntax::hir::Literal(bytes)) if bytes.len() == 1 => {
                            budget.charge(1)?;
                            let mut class = ByteSet::empty();
                            class.insert(bytes[0]);
                            return Ok(Some((repetition.min, class)));
                        }
                        _ => return Ok(None),
                    }
                }
            }
            _ => return Ok(None),
        }
    }
}

fn state_byte_literal<'a>(
    mut hir: &'a Hir,
    budget: &mut CompileBudget,
) -> Result<Option<&'a [u8]>, Error> {
    loop {
        budget.charge(1)?;
        match hir.kind() {
            HirKind::Capture(capture) => hir = &capture.sub,
            HirKind::Literal(regex_syntax::hir::Literal(bytes)) => return Ok(Some(bytes)),
            _ => return Ok(None),
        }
    }
}

fn build_url_aggregate_plan(
    hir: &Hir,
    profile: RustByteProfile,
    capture_policy: CapturePolicy,
    limits: CompileLimits,
    budget: &mut CompileBudget,
) -> Result<Option<fre_kernels::UrlAggregatePlan>, Error> {
    budget.charge(2)?;
    if profile.unicode || capture_policy != CapturePolicy::EraseForWholeMatch {
        return Ok(None);
    }
    let Some(certificate) = crate::anchored_island::certify_url_authoritative(
        hir,
        crate::anchored_island::Limits {
            max_scratch_bytes: limits.max_program_bytes,
        },
        budget,
    )?
    else {
        return Ok(None);
    };
    let result = build_url_aggregate_from_certificate(&certificate, budget);
    let release = certificate.release(budget);
    match (result, release) {
        (Ok(plan), Ok(())) => Ok(plan),
        (Err(error), Ok(())) | (Ok(None), Err(error)) => Err(error),
        (Ok(Some(plan)), Err(error)) => {
            budget.release_construction_bytes(plan.build_accounting().persistent_bytes)?;
            Err(error)
        }
        (Err(_), Err(release_error)) => Err(release_error),
    }
}

fn build_url_aggregate_from_certificate(
    certificate: &crate::anchored_island::UrlCertificate<'_>,
    budget: &mut CompileBudget,
) -> Result<Option<fre_kernels::UrlAggregatePlan>, Error> {
    let packed = pack_url_tlds(certificate, budget)?;
    let build = {
        let (result, retained_attempt_bytes, authoritative_error) = {
            let mut authority = UrlBuildAuthority {
                budget,
                error: None,
                retained_attempt_bytes: 0,
            };
            let result = fre_kernels::UrlAggregatePlan::build_with_authority(
                &packed.bytes,
                &packed.ends,
                fre_kernels::UrlAggregateBuildLimits::default(),
                &mut authority,
            );
            (
                result,
                authority.retained_attempt_bytes,
                authority.error.take(),
            )
        };
        budget.record_url_build_terminal(&result, retained_attempt_bytes, packed.bytes.len())?;
        match result {
            Ok(plan) => Ok(Some(plan)),
            Err(_) if authoritative_error.is_some() => Err(authoritative_error.unwrap_or(
                Error::InternalInvariant("URL build authority lost its refusal"),
            )),
            Err(
                fre_kernels::UrlAggregateBuildError::DuplicateTld { .. }
                | fre_kernels::UrlAggregateBuildError::PriorityConflict { .. },
            ) => Ok(None),
            Err(error) => Err(map_url_build_error(&error)),
        }
    };
    let release = packed.release(budget);
    match (build, release) {
        (Ok(Some(plan)), Ok(())) => {
            let accounting = plan.build_accounting();
            budget.accounting.url_aggregate_plans = 1;
            budget.accounting.url_aggregate_tlds = accounting.tlds;
            budget.accounting.url_aggregate_tld_bytes = accounting.tld_bytes;
            budget.accounting.url_aggregate_build_work = accounting.work;
            budget.accounting.url_aggregate_persistent_bytes = accounting.persistent_bytes;
            Ok(Some(plan))
        }
        (Ok(None), Ok(())) => Ok(None),
        (Err(error), Ok(())) | (Ok(None), Err(error)) => Err(error),
        (Ok(Some(plan)), Err(error)) => {
            budget.release_construction_bytes(plan.build_accounting().persistent_bytes)?;
            Err(error)
        }
        (Err(_), Err(release_error)) => Err(release_error),
    }
}

trait UrlTldSource {
    fn tld(&self, index: usize) -> Option<&[u8]>;
    fn tld_count(&self) -> Option<usize>;
}

impl UrlTldSource for crate::anchored_island::UrlCertificate<'_> {
    fn tld(&self, index: usize) -> Option<&[u8]> {
        crate::anchored_island::UrlCertificate::tld(self, index)
    }

    fn tld_count(&self) -> Option<usize> {
        crate::anchored_island::UrlCertificate::tld_count(self)
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "URL packing keeps the two allocator commits and exact copy in one auditable transaction"
)]
fn pack_url_tlds(
    certificate: &impl UrlTldSource,
    budget: &mut CompileBudget,
) -> Result<PackedUrlTlds, Error> {
    #[cfg(test)]
    url_pack_allocation_probe::record_precount_work(budget.accounting.work);
    budget.charge(1)?;
    #[cfg(test)]
    url_pack_allocation_probe::record_count_call();
    let count = certificate.tld_count().ok_or(Error::InternalInvariant(
        "URL certificate lost its authenticated domain branch",
    ))?;
    let mut byte_count = 0_usize;
    for index in 0..count {
        budget.charge(1)?;
        let tld = certificate.tld(index).ok_or(Error::InternalInvariant(
            "URL certificate TLD census changed before packing",
        ))?;
        budget.charge(add(tld.len(), 1, Resource::CompileWork)?)?;
        byte_count = add(byte_count, tld.len(), Resource::LiteralBytes)?;
    }
    budget.charge(1)?;
    if certificate.tld(count).is_some() {
        return Err(Error::InternalInvariant(
            "URL certificate TLD count omitted a retained entry",
        ));
    }
    let ends_bytes = mul(count, core::mem::size_of::<usize>(), Resource::ProgramBytes)?;
    let allocated_bytes = add(byte_count, ends_bytes, Resource::ProgramBytes)?;
    // Two exact allocator calls and their eventual deallocations are prepaid
    // before either allocation is attempted.
    #[cfg(test)]
    url_pack_allocation_probe::record_preallocation_work(budget.accounting.work);
    budget.charge(4)?;
    let receipt_scope = budget.receipt_scope;
    if receipt_scope {
        // Bind the full two-allocation P/peak before either allocator call.
        budget.preflight_receipt_construction_bytes(allocated_bytes)?;
    } else {
        // Preserve the incumbent prepayment and error ordering exactly.
        budget.acquire_checked_construction_bytes(allocated_bytes)?;
    }
    let packed = (|| {
        #[cfg(test)]
        url_pack_allocation_probe::record_call();
        let mut bytes = compiler_allocation(
            budget,
            byte_count > 0,
            Resource::ProgramBytes,
            byte_count,
            || {
                ExactVec::try_with_capacity(byte_count).map_err(|error| {
                    exact_url_allocation_error(error, Resource::ProgramBytes, byte_count)
                })
            },
            |values| {
                mul(
                    values.capacity(),
                    core::mem::size_of::<u8>(),
                    Resource::ProgramBytes,
                )
            },
        )?;
        if receipt_scope {
            budget.acquire_construction_bytes(byte_count)?;
        }
        #[cfg(test)]
        url_pack_allocation_probe::record_call();
        let mut ends = compiler_allocation(
            budget,
            count > 0,
            Resource::ProgramBytes,
            count,
            || {
                ExactVec::try_with_capacity(count).map_err(|error| {
                    exact_url_allocation_error(error, Resource::ProgramBytes, count)
                })
            },
            |values| {
                mul(
                    values.capacity(),
                    core::mem::size_of::<usize>(),
                    Resource::ProgramBytes,
                )
            },
        )?;
        if receipt_scope {
            budget.acquire_construction_bytes(ends_bytes)?;
        }
        for index in 0..count {
            budget.charge(1)?;
            let tld = certificate.tld(index).ok_or(Error::InternalInvariant(
                "URL certificate TLD language changed during exact copy",
            ))?;
            for offset in 0..tld.len() {
                #[cfg(test)]
                url_pack_allocation_probe::record_precopy_work(budget.accounting.work);
                budget.charge(1)?;
                let byte = *tld.get(offset).ok_or(Error::InternalInvariant(
                    "URL certificate TLD byte disappeared during exact copy",
                ))?;
                #[cfg(test)]
                url_pack_allocation_probe::record_copy_call();
                bytes.try_push(byte).map_err(|_| {
                    Error::InternalInvariant("URL TLD byte census changed during exact copy")
                })?;
                budget.record_items::<u8>(1, true)?;
            }
            budget.charge(1)?;
            ends.try_push(bytes.len())
                .map_err(|_| Error::InternalInvariant("URL TLD count changed during exact copy"))?;
            budget.record_items::<usize>(1, false)?;
        }
        budget.charge(1)?;
        if certificate.tld(count).is_some() {
            return Err(Error::InternalInvariant(
                "URL certificate TLD copy omitted a retained entry",
            ));
        }
        if bytes.len() != byte_count || ends.len() != count {
            return Err(Error::InternalInvariant(
                "URL TLD language changed between census and exact copy",
            ));
        }
        Ok(PackedUrlTlds {
            bytes,
            ends,
            allocated_bytes,
        })
    })();
    if packed.is_err() && !receipt_scope {
        budget.release_construction_bytes(allocated_bytes)?;
    }
    packed
}

fn exact_url_allocation_error(error: CopyError, resource: Resource, items: usize) -> Error {
    match error {
        CopyError::LayoutOverflow => Error::ArithmeticOverflow { resource },
        CopyError::AllocationFailed => Error::AllocationFailed { resource, items },
    }
}

fn map_url_build_error(error: &fre_kernels::UrlAggregateBuildError) -> Error {
    use fre_kernels::UrlAggregateBuildError as BuildError;
    match *error {
        BuildError::Resource {
            resource: "work",
            needed,
            limit,
        } => Error::ResourceLimit {
            resource: Resource::CompileWork,
            required: needed,
            limit,
        },
        BuildError::Resource { needed, limit, .. } => Error::ResourceLimit {
            resource: Resource::ProgramBytes,
            required: needed,
            limit,
        },
        BuildError::Overflow("work") => Error::ArithmeticOverflow {
            resource: Resource::CompileWork,
        },
        BuildError::Overflow(_) => Error::ArithmeticOverflow {
            resource: Resource::ProgramBytes,
        },
        BuildError::Allocation { items, .. } => Error::AllocationFailed {
            resource: Resource::ProgramBytes,
            items,
        },
        BuildError::EmptyLanguage
        | BuildError::EmptyTld { .. }
        | BuildError::InvalidTld { .. }
        | BuildError::TldLength { .. }
        | BuildError::DuplicateTld { .. }
        | BuildError::PriorityConflict { .. }
        | BuildError::Invariant(_) => Error::InternalInvariant(
            "strict URL certificate disagrees with URL aggregate construction",
        ),
        _ => Error::InternalInvariant("unclassified URL aggregate construction refusal"),
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "candidate construction keeps every retained allocation and charged initialization explicit"
)]
fn build_candidate_plan(
    hir: &Hir,
    profile: RustByteProfile,
    capture_policy: CapturePolicy,
    budget: &mut CompileBudget,
) -> Result<Option<candidate::Plan>, Error> {
    // The executor is deliberately byte-only. Unicode-on plans retain their
    // existing scalar-aware execution route even when a particular HIR happens
    // to contain only ASCII atoms.
    budget.charge(1)?;
    if profile.unicode {
        return Ok(None);
    }
    let (branches, single_capture_selector) = match hir.kind() {
        HirKind::Alternation(branches)
            if (2..=candidate::MAX_ENTRIES).contains(&branches.len()) =>
        {
            (branches.as_slice(), false)
        }
        HirKind::Alternation(_) => return Ok(None),
        _ if capture_policy == CapturePolicy::EraseForWholeMatch => {
            (core::slice::from_ref(hir), true)
        }
        _ => return Ok(None),
    };
    let single_fixed = if single_capture_selector {
        leading_fixed_candidate(hir, budget)?
    } else {
        None
    };
    let fixed_continuation_proof = if single_capture_selector
        && single_fixed
            .as_ref()
            .is_none_or(|fixed| fixed.check_len < candidate::MAX_FILTER_CHECKS)
    {
        let Some(proof) = prove_fixed_continuation_candidate(hir, single_fixed.as_ref(), budget)?
        else {
            return Ok(None);
        };
        Some(proof)
    } else {
        None
    };

    let draft_bytes = mul(
        branches.len(),
        core::mem::size_of::<CandidateDraft>(),
        Resource::ProgramBytes,
    )?;
    enforce(
        add(
            budget.current_construction_bytes,
            draft_bytes,
            Resource::ProgramBytes,
        )?,
        budget.limits.max_program_bytes,
        Resource::ProgramBytes,
    )?;
    budget.charge(branches.len())?;
    if budget.receipt_scope {
        budget.preflight_receipt_construction_bytes(draft_bytes)?;
    } else {
        budget.acquire_construction_bytes(draft_bytes)?;
    }
    let mut drafts = compiler_allocation(
        budget,
        !branches.is_empty(),
        Resource::ProgramBytes,
        branches.len(),
        || candidate::exact_drafts(branches.len()),
        |values| {
            mul(
                values.capacity(),
                core::mem::size_of::<CandidateDraft>(),
                Resource::ProgramBytes,
            )
        },
    )?;
    if budget.receipt_scope {
        budget.acquire_construction_bytes(draft_bytes)?;
    }
    for branch in branches {
        budget.charge(1)?;
        let fixed = if single_capture_selector {
            single_fixed
        } else {
            leading_fixed_candidate(branch, budget)?
        };
        let Some(draft) = analyze_candidate_branch(branch, fixed.as_ref(), budget)? else {
            budget.release_construction_bytes(draft_bytes)?;
            return Ok(None);
        };
        drafts.try_push(draft).map_err(|_| {
            Error::InternalInvariant("candidate analysis exceeded exact branch census")
        })?;
        budget.record_items::<CandidateDraft>(1, false)?;
    }
    if drafts.len() != branches.len() {
        return Err(Error::InternalInvariant(
            "candidate analysis changed direct-root branch count",
        ));
    }

    let entry_bytes = mul(
        drafts.len(),
        core::mem::size_of::<CandidateEntry>(),
        Resource::ProgramBytes,
    )?;
    let bucket_bytes = mul(
        candidate::bucket_count(),
        core::mem::size_of::<u128>(),
        Resource::ProgramBytes,
    )?;
    let retained_bytes = add(
        entry_bytes,
        mul(2, bucket_bytes, Resource::ProgramBytes)?,
        Resource::ProgramBytes,
    )?;
    enforce(
        add(
            budget.current_construction_bytes,
            retained_bytes,
            Resource::ProgramBytes,
        )?,
        budget.limits.max_program_bytes,
        Resource::ProgramBytes,
    )?;
    let entry_initialization = mul(
        drafts.len(),
        add(
            mul(2, candidate::MAX_FILTER_CHECKS, Resource::CompileWork)?,
            6,
            Resource::CompileWork,
        )?,
        Resource::CompileWork,
    )?;
    let initialization = add(
        entry_initialization,
        mul(2, candidate::bucket_count(), Resource::CompileWork)?,
        Resource::CompileWork,
    )?;
    budget.charge(initialization)?;
    if budget.receipt_scope {
        budget.preflight_receipt_construction_bytes(retained_bytes)?;
    } else {
        budget.acquire_construction_bytes(retained_bytes)?;
    }
    let mut entries = compiler_allocation(
        budget,
        !drafts.is_empty(),
        Resource::ProgramBytes,
        drafts.len(),
        || candidate::exact_entries(drafts.len()),
        |values| {
            mul(
                values.capacity(),
                core::mem::size_of::<CandidateEntry>(),
                Resource::ProgramBytes,
            )
        },
    )?;
    if budget.receipt_scope {
        budget.acquire_construction_bytes(entry_bytes)?;
    }
    for draft in &*drafts {
        entries
            .try_push(CandidateEntry {
                pc: usize::MAX,
                min_offset: draft.min_offset,
                max_offset: draft.max_offset,
                checks: draft.checks,
                check_len: draft.check_len,
                leading_assertion: draft.leading_assertion,
                global_checks: draft.global_checks,
                global_check_len: draft.global_check_len,
            })
            .map_err(|_| Error::InternalInvariant("candidate entry allocation filled early"))?;
        budget.record_items::<CandidateEntry>(1, false)?;
    }
    let mut buckets = compiler_allocation(
        budget,
        candidate::bucket_count() > 0,
        Resource::ProgramBytes,
        candidate::bucket_count(),
        candidate::exact_buckets,
        |values| {
            mul(
                values.capacity(),
                core::mem::size_of::<u128>(),
                Resource::ProgramBytes,
            )
        },
    )?;
    if budget.receipt_scope {
        budget.acquire_construction_bytes(bucket_bytes)?;
    }
    for _ in 0..candidate::bucket_count() {
        buckets
            .try_push(0)
            .map_err(|_| Error::InternalInvariant("candidate bucket allocation filled early"))?;
        budget.record_items::<u128>(1, false)?;
    }
    let mut global_buckets = compiler_allocation(
        budget,
        candidate::bucket_count() > 0,
        Resource::ProgramBytes,
        candidate::bucket_count(),
        candidate::exact_buckets,
        |values| {
            mul(
                values.capacity(),
                core::mem::size_of::<u128>(),
                Resource::ProgramBytes,
            )
        },
    )?;
    if budget.receipt_scope {
        budget.acquire_construction_bytes(bucket_bytes)?;
    }
    for _ in 0..candidate::bucket_count() {
        global_buckets.try_push(0).map_err(|_| {
            Error::InternalInvariant("candidate global bucket allocation filled early")
        })?;
        budget.record_items::<u128>(1, false)?;
    }
    let mut max_offset = 0_usize;
    for (ordinal, draft) in drafts.iter().enumerate() {
        budget.charge(2)?; // maximum-offset comparison and owner derivation
        max_offset = max_offset.max(draft.max_offset);
        let shift = u32::try_from(ordinal).map_err(|_| {
            Error::InternalInvariant("candidate ordinal exceeds bucket shift width")
        })?;
        let owner = 1_u128.checked_shl(shift).ok_or(Error::InternalInvariant(
            "candidate ordinal outside bucket word",
        ))?;
        for byte in u8::MIN..=u8::MAX {
            budget.charge(2)?;
            if draft.bytes.contains(byte) {
                budget.charge(1)?;
                *buckets
                    .get_mut(usize::from(byte))
                    .ok_or(Error::InternalInvariant(
                        "candidate bucket publication outside table",
                    ))? |= owner;
            }
            if draft.global_bytes.contains(byte) {
                budget.charge(1)?;
                *global_buckets
                    .get_mut(usize::from(byte))
                    .ok_or(Error::InternalInvariant(
                        "candidate global bucket publication outside table",
                    ))? |= owner;
            }
        }
    }
    let shared_fixed_work = add(entries.len(), buckets.len(), Resource::CompileWork)?;
    budget.charge(shared_fixed_work)?;
    let shared_fixed = candidate::shared_fixed_anchors(&entries, &buckets)?;
    let shape = candidate::packed_shape(max_offset, shared_fixed)?;
    let shape = if let Some(proof) = fixed_continuation_proof {
        let fixed = build_fixed_continuation(hir, proof, shape, budget)?;
        retain_fixed_continuation(fixed, budget)?
    } else {
        candidate::inline_candidate_shape(shape)?
    };
    budget.release_construction_bytes(draft_bytes)?;
    let plan = candidate::Plan {
        entries,
        buckets,
        global_buckets,
        shape,
    };
    budget.accounting.candidate_entries = plan.entries.len();
    budget.accounting.candidate_bytes = plan.retained_bytes()?;
    Ok(Some(plan))
}

fn analyze_candidate_branch(
    branch: &Hir,
    fixed: Option<&CandidateDraft>,
    budget: &mut CompileBudget,
) -> Result<Option<CandidateDraft>, Error> {
    let fallback = if let Some(draft) = required_candidate(branch, budget)? {
        draft
    } else {
        let Some(draft) = leading_candidate(branch, budget)? else {
            return Ok(None);
        };
        draft
    };
    let mut draft = match fixed {
        Some(fixed) if fixed.check_len >= 2 => choose_candidate(Some(fallback), *fixed, budget)?
            .ok_or(Error::InternalInvariant(
                "candidate choice lost both proved alternatives",
            ))?,
        _ => fallback,
    };
    let Some(mut global) = required_global_candidate(branch, budget)? else {
        return Ok(None);
    };
    if let Some(trailing) = required_trailing_global_candidate(branch, budget)?
        && !global_probe_equal(&global, &trailing, budget)?
    {
        // The scheduler already retains the strongest start-relative proof.
        // Prefer a distinct mandatory trailing global proof so the source-wide
        // census is complementary instead of rechecking a dense prefix.
        global = trailing;
    }
    draft.global_bytes = global.bytes;
    draft.global_checks = global.checks;
    draft.global_check_len = global.check_len;
    draft.leading_assertion = leading_assertion(branch, budget)?;
    if draft.max_offset > candidate::MAX_OFFSET {
        return Ok(None);
    }
    Ok(Some(draft))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FixedContinuationProof {
    tokens: usize,
    leading_tokens: usize,
    body: ByteSet,
    anchor: u8,
    close: u8,
    semicolon: u8,
    comparison_work: usize,
    comparison_bytes: usize,
    retained_copy_bytes: usize,
    leading_comparison_work: usize,
    leading_comparison_bytes: usize,
    leading_retained_copy_bytes: usize,
}

fn prove_fixed_continuation_candidate(
    hir: &Hir,
    fixed: Option<&CandidateDraft>,
    budget: &mut CompileBudget,
) -> Result<Option<FixedContinuationProof>, Error> {
    let Some(parts) = transparent_concat(hir, budget)? else {
        return Ok(None);
    };
    budget.charge(1)?;
    if parts.len() != 4 {
        return Ok(None);
    }
    prove_fixed_continuation_candidate_after_root_shape(hir, fixed, budget)
}

fn prove_fixed_continuation_candidate_after_root_shape(
    hir: &Hir,
    fixed: Option<&CandidateDraft>,
    budget: &mut CompileBudget,
) -> Result<Option<FixedContinuationProof>, Error> {
    let Some(draft) = analyze_candidate_branch(hir, fixed, budget)? else {
        return Ok(None);
    };
    fixed_continuation_proof(hir, &draft, budget)
}

fn fixed_continuation_proof(
    hir: &Hir,
    draft: &CandidateDraft,
    budget: &mut CompileBudget,
) -> Result<Option<FixedContinuationProof>, Error> {
    // This is a complete whole-match theorem, not a benchmark signature.
    // Every accepted field comes from canonical HIR, and every rejected
    // near-miss keeps the ordinary continuation program. The short bounded
    // start proof limits retained candidate fan-out while the deterministic
    // token languages make greedy repetition reducible without re-running the
    // program at source-dependent candidate starts.
    budget.charge(2)?; // bounded start interval and unfiltered-global checks
    if draft.max_offset > candidate::MAX_FILTER_CHECKS || draft.global_check_len != 0 {
        return Ok(None);
    }

    let mut anchor = None;
    for byte in u8::MIN..=u8::MAX {
        budget.charge(1)?;
        if !draft.global_bytes.contains(byte) {
            continue;
        }
        budget.charge(2)?; // singleton census and disjointness comparison
        if anchor.is_some() || draft.bytes.contains(byte) {
            return Ok(None);
        }
        anchor = Some(byte);
    }
    let Some(anchor) = anchor else {
        return Ok(None);
    };

    let Some(parts) = transparent_concat(hir, budget)? else {
        return Ok(None);
    };
    budget.charge(1)?;
    let [prefix, close, semicolon, suffix] = parts else {
        return Ok(None);
    };
    let Some((prefix_sub, 1, None)) = greedy_repetition(prefix, budget)? else {
        return Ok(None);
    };
    let Some((close_sub, 0, None)) = greedy_repetition(close, budget)? else {
        return Ok(None);
    };
    let Some((semicolon_sub, 0, Some(1))) = greedy_repetition(semicolon, budget)? else {
        return Ok(None);
    };
    let Some(suffix_parts) = transparent_concat(suffix, budget)? else {
        return Ok(None);
    };
    budget.charge(1)?;
    let [leading, first_dot, second_dot, required, trailing_dot] = suffix_parts else {
        return Ok(None);
    };
    let Some(body) = greedy_star_byte_class(first_dot, budget)? else {
        return Ok(None);
    };
    if !fixed_continuation_greedy_star_equals(second_dot, body, budget)?
        || !fixed_continuation_greedy_star_equals(trailing_dot, body, budget)?
        || singleton_literal(required, budget)? != Some(anchor)
        || !fixed_continuation_byte_set_contains(body, anchor, budget)?
    {
        return Ok(None);
    }
    let Some((leading_sub, 0, None)) = greedy_repetition(leading, budget)? else {
        return Ok(None);
    };
    let Some(close) = singleton_literal(close_sub, budget)? else {
        return Ok(None);
    };
    let Some(semicolon) = singleton_literal(semicolon_sub, budget)? else {
        return Ok(None);
    };
    if !fixed_continuation_byte_set_contains(body, close, budget)?
        || !fixed_continuation_byte_set_contains(body, semicolon, budget)?
    {
        return Ok(None);
    }
    let Some((tokens, comparison_work, comparison_bytes, retained_copy_bytes)) =
        fixed_continuation_token_census(prefix_sub, Some(body), anchor, budget)?
    else {
        return Ok(None);
    };
    let Some((
        leading_tokens,
        leading_comparison_work,
        leading_comparison_bytes,
        leading_retained_copy_bytes,
    )) = fixed_continuation_token_census(leading_sub, None, anchor, budget)?
    else {
        return Ok(None);
    };
    Ok(Some(FixedContinuationProof {
        tokens,
        leading_tokens,
        body,
        anchor,
        close,
        semicolon,
        comparison_work,
        comparison_bytes,
        retained_copy_bytes,
        leading_comparison_work,
        leading_comparison_bytes,
        leading_retained_copy_bytes,
    }))
}

fn transparent_concat<'a>(
    mut hir: &'a Hir,
    budget: &mut CompileBudget,
) -> Result<Option<&'a [Hir]>, Error> {
    loop {
        budget.charge(1)?;
        match hir.kind() {
            HirKind::Capture(capture) => hir = &capture.sub,
            HirKind::Concat(parts) => return Ok(Some(parts)),
            _ => return Ok(None),
        }
    }
}

type GreedyRepetition<'a> = (&'a Hir, u32, Option<u32>);

fn greedy_repetition<'a>(
    mut hir: &'a Hir,
    budget: &mut CompileBudget,
) -> Result<Option<GreedyRepetition<'a>>, Error> {
    loop {
        budget.charge(1)?;
        match hir.kind() {
            HirKind::Capture(capture) => hir = &capture.sub,
            HirKind::Repetition(repetition) if repetition.greedy => {
                return Ok(Some((&repetition.sub, repetition.min, repetition.max)));
            }
            _ => return Ok(None),
        }
    }
}

fn byte_class_set(
    class: &regex_syntax::hir::ClassBytes,
    budget: &mut CompileBudget,
) -> Result<ByteSet, Error> {
    let mut bytes = ByteSet::empty();
    for range in class.ranges() {
        let width = inclusive_byte_width(range.start(), range.end())?;
        budget.charge(add(width, 1, Resource::CompileWork)?)?;
        bytes.insert_range(range.start(), range.end());
    }
    Ok(bytes)
}

fn greedy_star_byte_class(hir: &Hir, budget: &mut CompileBudget) -> Result<Option<ByteSet>, Error> {
    let Some((mut sub, 0, None)) = greedy_repetition(hir, budget)? else {
        return Ok(None);
    };
    loop {
        budget.charge(1)?;
        match sub.kind() {
            HirKind::Capture(capture) => sub = &capture.sub,
            HirKind::Class(Class::Bytes(class)) => {
                return byte_class_set(class, budget).map(Some);
            }
            _ => return Ok(None),
        }
    }
}

fn singleton_literal(mut hir: &Hir, budget: &mut CompileBudget) -> Result<Option<u8>, Error> {
    loop {
        budget.charge(1)?;
        match hir.kind() {
            HirKind::Capture(capture) => hir = &capture.sub,
            HirKind::Literal(regex_syntax::hir::Literal(bytes)) if bytes.len() == 1 => {
                return Ok(bytes.first().copied());
            }
            _ => return Ok(None),
        }
    }
}

fn fixed_continuation_byte_sets_equal(
    left: ByteSet,
    right: ByteSet,
    budget: &mut CompileBudget,
) -> Result<bool, Error> {
    for index in 0..left.0.len() {
        budget.charge(1)?;
        if left.0[index] != right.0[index] {
            return Ok(false);
        }
    }
    Ok(true)
}

fn fixed_continuation_greedy_star_equals(
    hir: &Hir,
    expected: ByteSet,
    budget: &mut CompileBudget,
) -> Result<bool, Error> {
    let Some(actual) = greedy_star_byte_class(hir, budget)? else {
        return Ok(false);
    };
    fixed_continuation_byte_sets_equal(expected, actual, budget)
}

fn fixed_continuation_byte_set_contains(
    bytes: ByteSet,
    byte: u8,
    budget: &mut CompileBudget,
) -> Result<bool, Error> {
    budget.charge(1)?;
    Ok(bytes.contains(byte))
}

fn fixed_continuation_byte_set_is_empty(
    bytes: ByteSet,
    budget: &mut CompileBudget,
) -> Result<bool, Error> {
    for word in bytes.0 {
        budget.charge(1)?;
        if word != 0 {
            return Ok(false);
        }
    }
    Ok(true)
}

fn fixed_continuation_byte_set_is_subset(
    candidate: ByteSet,
    allowed: ByteSet,
    budget: &mut CompileBudget,
) -> Result<bool, Error> {
    for (candidate, allowed) in candidate.0.into_iter().zip(allowed.0) {
        budget.charge(1)?;
        if candidate & !allowed != 0 {
            return Ok(false);
        }
    }
    Ok(true)
}

fn fixed_continuation_byte_sets_overlap(
    left: ByteSet,
    right: ByteSet,
    budget: &mut CompileBudget,
) -> Result<bool, Error> {
    for (left, right) in left.0.into_iter().zip(right.0) {
        budget.charge(1)?;
        if left & right != 0 {
            return Ok(true);
        }
    }
    Ok(false)
}

fn fixed_continuation_literal_is_in_body(
    literal: &[u8],
    body: ByteSet,
    budget: &mut CompileBudget,
) -> Result<bool, Error> {
    for &byte in literal {
        if !fixed_continuation_byte_set_contains(body, byte, budget)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn fixed_continuation_token_hirs(hir: &Hir) -> &[Hir] {
    match hir.kind() {
        HirKind::Alternation(branches) => branches,
        _ => core::slice::from_ref(hir),
    }
}

fn fixed_continuation_token_census(
    hir: &Hir,
    body: Option<ByteSet>,
    anchor: u8,
    budget: &mut CompileBudget,
) -> Result<Option<(usize, usize, usize, usize)>, Error> {
    let branches = fixed_continuation_token_hirs(hir);
    if branches.is_empty() || branches.len() > candidate::MAX_ENTRIES {
        return Ok(None);
    }
    let mut comparison_work = 0_usize;
    let mut comparison_bytes = 0_usize;
    let mut retained_copy_bytes = 0_usize;
    for branch in branches {
        budget.charge(1)?; // token dispatch plus bounded scalar shape/anchor checks
        let bytes = match branch.kind() {
            HirKind::Literal(regex_syntax::hir::Literal(bytes)) => {
                if bytes.is_empty() || bytes.len() > candidate::MAX_FIXED_CONTINUATION_TOKEN_BYTES {
                    return Ok(None);
                }
                if let Some(body) = body
                    && !fixed_continuation_literal_is_in_body(bytes, body, budget)?
                {
                    return Ok(None);
                }
                if bytes.first().is_some_and(|&byte| byte == anchor) {
                    return Ok(None);
                }
                retained_copy_bytes = add(retained_copy_bytes, bytes.len(), Resource::CompileWork)?;
                bytes.len()
            }
            HirKind::Class(Class::Bytes(class)) => {
                let bytes = byte_class_set(class, budget)?;
                if fixed_continuation_byte_set_contains(bytes, anchor, budget)?
                    || fixed_continuation_byte_set_is_empty(bytes, budget)?
                {
                    return Ok(None);
                }
                if let Some(body) = body
                    && !fixed_continuation_byte_set_is_subset(bytes, body, budget)?
                {
                    return Ok(None);
                }
                1
            }
            HirKind::Empty
            | HirKind::Class(_)
            | HirKind::Look(_)
            | HirKind::Repetition(_)
            | HirKind::Capture(_)
            | HirKind::Concat(_)
            | HirKind::Alternation(_) => return Ok(None),
        };
        comparison_bytes = add(comparison_bytes, bytes, Resource::CompileWork)?;
        comparison_work = add(
            comparison_work,
            add(1, bytes, Resource::CompileWork)?,
            Resource::CompileWork,
        )?;
    }
    for (left_index, left) in branches.iter().enumerate() {
        let right_start = left_index.checked_add(1).ok_or(Error::ArithmeticOverflow {
            resource: Resource::CompileWork,
        })?;
        for right in &branches[right_start..] {
            budget.charge(1)?;
            if fixed_tokens_overlap(left, right, budget)? {
                return Ok(None);
            }
        }
    }
    Ok(Some((
        branches.len(),
        comparison_work,
        comparison_bytes,
        retained_copy_bytes,
    )))
}

fn fixed_tokens_overlap(
    left: &Hir,
    right: &Hir,
    budget: &mut CompileBudget,
) -> Result<bool, Error> {
    match (left.kind(), right.kind()) {
        (
            HirKind::Literal(regex_syntax::hir::Literal(left)),
            HirKind::Literal(regex_syntax::hir::Literal(right)),
        ) => {
            let common = left.len().min(right.len());
            budget.charge(common)?;
            Ok(left[..common] == right[..common])
        }
        (HirKind::Class(Class::Bytes(left)), HirKind::Class(Class::Bytes(right))) => {
            let left = byte_class_set(left, budget)?;
            let right = byte_class_set(right, budget)?;
            fixed_continuation_byte_sets_overlap(left, right, budget)
        }
        (
            HirKind::Class(Class::Bytes(class)),
            HirKind::Literal(regex_syntax::hir::Literal(literal)),
        )
        | (
            HirKind::Literal(regex_syntax::hir::Literal(literal)),
            HirKind::Class(Class::Bytes(class)),
        ) => {
            let class = byte_class_set(class, budget)?;
            let Some(&first) = literal.first() else {
                return Ok(false);
            };
            fixed_continuation_byte_set_contains(class, first, budget)
        }
        _ => Err(Error::InternalInvariant(
            "fixed-continuation token census admitted an unknown token",
        )),
    }
}

fn build_fixed_continuation(
    hir: &Hir,
    proof: FixedContinuationProof,
    shape: usize,
    budget: &mut CompileBudget,
) -> Result<candidate::FixedContinuation, Error> {
    let parts = transparent_concat(hir, budget)?.ok_or(Error::InternalInvariant(
        "fixed-continuation proof lost its root concatenation",
    ))?;
    let prefix = parts.first().ok_or(Error::InternalInvariant(
        "fixed-continuation proof lost its prefix",
    ))?;
    let (prefix_sub, 1, None) = greedy_repetition(prefix, budget)?.ok_or(
        Error::InternalInvariant("fixed-continuation proof lost its greedy prefix"),
    )?
    else {
        return Err(Error::InternalInvariant(
            "fixed-continuation prefix repetition changed after proof",
        ));
    };
    let suffix = parts.get(3).ok_or(Error::InternalInvariant(
        "fixed-continuation proof lost its suffix",
    ))?;
    let suffix_parts = transparent_concat(suffix, budget)?.ok_or(Error::InternalInvariant(
        "fixed-continuation proof lost its suffix concatenation",
    ))?;
    let leading = suffix_parts.first().ok_or(Error::InternalInvariant(
        "fixed-continuation proof lost its leading repetition",
    ))?;
    let (leading_sub, 0, None) = greedy_repetition(leading, budget)?.ok_or(
        Error::InternalInvariant("fixed-continuation proof lost its leading token repetition"),
    )?
    else {
        return Err(Error::InternalInvariant(
            "fixed-continuation leading repetition changed after proof",
        ));
    };
    let tokens = retain_fixed_continuation_tokens(
        prefix_sub,
        proof.tokens,
        proof.comparison_work,
        proof.comparison_bytes,
        proof.retained_copy_bytes,
        budget,
    )?;
    let leading_tokens = retain_fixed_continuation_tokens(
        leading_sub,
        proof.leading_tokens,
        proof.leading_comparison_work,
        proof.leading_comparison_bytes,
        proof.leading_retained_copy_bytes,
        budget,
    )?;
    Ok(candidate::FixedContinuation {
        tokens,
        leading_tokens,
        body: proof.body,
        anchor: proof.anchor,
        close: proof.close,
        semicolon: proof.semicolon,
        comparison_work: proof.comparison_work,
        comparison_bytes: proof.comparison_bytes,
        leading_comparison_work: proof.leading_comparison_work,
        leading_comparison_bytes: proof.leading_comparison_bytes,
        shape,
    })
}

fn retain_fixed_continuation(
    fixed: candidate::FixedContinuation,
    budget: &mut CompileBudget,
) -> Result<fre_exact_alloc::ExactBoxOrUsize<candidate::FixedContinuation>, Error> {
    let retained_bytes = core::mem::size_of::<candidate::FixedContinuation>();
    enforce(
        add(
            budget.current_construction_bytes,
            retained_bytes,
            Resource::ProgramBytes,
        )?,
        budget.limits.max_program_bytes,
        Resource::ProgramBytes,
    )?;
    budget.charge(1)?;
    if budget.receipt_scope {
        budget.preflight_receipt_construction_bytes(retained_bytes)?;
    } else {
        budget.acquire_construction_bytes(retained_bytes)?;
    }
    let fixed = compiler_allocation(
        budget,
        retained_bytes != 0,
        Resource::ProgramBytes,
        1,
        || candidate::exact_fixed_continuation(fixed),
        |_| Ok(retained_bytes),
    )?;
    if budget.receipt_scope {
        budget.acquire_construction_bytes(retained_bytes)?;
    }
    budget.record_items::<candidate::FixedContinuation>(1, false)?;
    Ok(fixed)
}

fn retain_fixed_continuation_tokens(
    hir: &Hir,
    expected_tokens: usize,
    expected_comparison_work: usize,
    expected_comparison_bytes: usize,
    expected_copy_bytes: usize,
    budget: &mut CompileBudget,
) -> Result<fre_exact_alloc::ExactVec<candidate::FixedContinuationToken>, Error> {
    let branches = fixed_continuation_token_hirs(hir);
    if branches.len() != expected_tokens {
        return Err(Error::InternalInvariant(
            "fixed-continuation token census changed during retention",
        ));
    }
    let retained_bytes = mul(
        expected_tokens,
        core::mem::size_of::<candidate::FixedContinuationToken>(),
        Resource::ProgramBytes,
    )?;
    enforce(
        add(
            budget.current_construction_bytes,
            retained_bytes,
            Resource::ProgramBytes,
        )?,
        budget.limits.max_program_bytes,
        Resource::ProgramBytes,
    )?;
    // Admit the distinct retained-token visit and literal payload copy before
    // allocation. These units are neither the earlier theorem proof nor the
    // executor comparison census (a class compares one source byte but copies
    // no HIR literal bytes). One atomic charge publishes the complete required
    // work while retaining only completed proof work in a refusal receipt.
    let retention_work = add(expected_tokens, expected_copy_bytes, Resource::CompileWork)?;
    budget.charge(retention_work)?;
    if budget.receipt_scope {
        budget.preflight_receipt_construction_bytes(retained_bytes)?;
    } else {
        budget.acquire_construction_bytes(retained_bytes)?;
    }
    let mut tokens = compiler_allocation(
        budget,
        expected_tokens != 0,
        Resource::ProgramBytes,
        expected_tokens,
        || candidate::exact_fixed_continuation_tokens(expected_tokens),
        |values| {
            mul(
                values.capacity(),
                core::mem::size_of::<candidate::FixedContinuationToken>(),
                Resource::ProgramBytes,
            )
        },
    )?;
    if budget.receipt_scope {
        budget.acquire_construction_bytes(retained_bytes)?;
    }
    let mut comparison_work = 0_usize;
    let mut comparison_bytes = 0_usize;
    let mut copy_bytes = 0_usize;
    for branch in branches {
        let token = match branch.kind() {
            HirKind::Literal(regex_syntax::hir::Literal(bytes)) => {
                let token = candidate::FixedContinuationToken::literal(bytes)?;
                budget.record_copy(bytes.len())?;
                copy_bytes = add(copy_bytes, bytes.len(), Resource::CompileWork)?;
                token
            }
            HirKind::Class(Class::Bytes(class)) => {
                candidate::FixedContinuationToken::class(byte_class_set(class, budget)?)
            }
            _ => {
                return Err(Error::InternalInvariant(
                    "fixed-continuation token changed after proof",
                ));
            }
        };
        let bytes = token.comparison_bytes();
        comparison_bytes = add(comparison_bytes, bytes, Resource::CompileWork)?;
        comparison_work = add(
            comparison_work,
            add(1, bytes, Resource::CompileWork)?,
            Resource::CompileWork,
        )?;
        tokens.try_push(token).map_err(|_| {
            Error::InternalInvariant("fixed-continuation token allocation filled early")
        })?;
        budget.record_items::<candidate::FixedContinuationToken>(1, false)?;
    }
    if comparison_work != expected_comparison_work
        || comparison_bytes != expected_comparison_bytes
        || copy_bytes != expected_copy_bytes
    {
        return Err(Error::InternalInvariant(
            "fixed-continuation census changed during retention",
        ));
    }
    Ok(tokens)
}

const FILTER_WIDTH: usize = candidate::MAX_FILTER_CHECKS + 1;

#[derive(Clone, Copy)]
struct FixedPrefix {
    sets: [ByteSet; FILTER_WIDTH],
    len: usize,
    exact: bool,
}

impl FixedPrefix {
    const fn empty(exact: bool) -> Self {
        Self {
            sets: [ByteSet::empty(); FILTER_WIDTH],
            len: 0,
            exact,
        }
    }

    fn append(&mut self, other: Self, budget: &mut CompileBudget) -> Result<(), Error> {
        let available = FILTER_WIDTH.saturating_sub(self.len);
        let copied = available.min(other.len);
        budget.charge(add(copied, 2, Resource::CompileWork)?)?;
        for index in 0..copied {
            let output = self
                .len
                .checked_add(index)
                .ok_or(Error::ArithmeticOverflow {
                    resource: Resource::CompileWork,
                })?;
            self.sets[output] = other.sets[index];
        }
        let complete = copied == other.len;
        self.len = add(self.len, copied, Resource::CompileWork)?;
        self.exact &= other.exact && complete;
        Ok(())
    }
}

fn initialized_fixed_prefix(exact: bool, budget: &mut CompileBudget) -> Result<FixedPrefix, Error> {
    budget.charge(FILTER_WIDTH)?;
    Ok(FixedPrefix::empty(exact))
}

fn initialized_filter_checks(
    budget: &mut CompileBudget,
) -> Result<[candidate::FilterCheck; candidate::MAX_FILTER_CHECKS], Error> {
    budget.charge(candidate::MAX_FILTER_CHECKS)?;
    Ok([candidate::EMPTY_FILTER_CHECK; candidate::MAX_FILTER_CHECKS])
}

#[allow(
    clippy::large_types_passed_by_value,
    reason = "the fixed-width proof array is deliberately copied into one retained descriptor"
)]
const fn candidate_draft(
    bytes: ByteSet,
    min_offset: usize,
    max_offset: usize,
    checks: [candidate::FilterCheck; candidate::MAX_FILTER_CHECKS],
    check_len: usize,
) -> CandidateDraft {
    CandidateDraft {
        bytes,
        min_offset,
        max_offset,
        checks,
        check_len,
        leading_assertion: None,
        global_bytes: bytes,
        global_checks: checks,
        global_check_len: check_len,
    }
}

fn leading_fixed_candidate(
    hir: &Hir,
    budget: &mut CompileBudget,
) -> Result<Option<CandidateDraft>, Error> {
    let fixed = fixed_prefix(hir, budget)?;
    if fixed.len < 2 {
        return Ok(None);
    }
    let mut selected = 0_usize;
    let mut selected_weight = byte_set_weight(fixed.sets[0], budget)?;
    for index in 1..fixed.len {
        let weight = byte_set_weight(fixed.sets[index], budget)?;
        budget.charge(1)?;
        if weight < selected_weight {
            selected = index;
            selected_weight = weight;
        }
    }
    let mut checks = initialized_filter_checks(budget)?;
    let mut check_len = 0_usize;
    for index in 0..fixed.len {
        budget.charge(1)?;
        if index == selected {
            continue;
        }
        let relative = isize::try_from(index)
            .ok()
            .and_then(|index| {
                isize::try_from(selected)
                    .ok()
                    .and_then(|selected| index.checked_sub(selected))
            })
            .and_then(|relative| i8::try_from(relative).ok())
            .ok_or(Error::InternalInvariant(
                "candidate fixed-prefix relative offset overflow",
            ))?;
        checks[check_len] = candidate::FilterCheck {
            relative,
            bytes: fixed.sets[index],
        };
        check_len = add(check_len, 1, Resource::CompileWork)?;
    }
    Ok(Some(candidate_draft(
        fixed.sets[selected],
        selected,
        selected,
        checks,
        check_len,
    )))
}

// Keep recursive dispatch separate from the per-shape analyzers. `FixedPrefix`
// retains several complete byte sets; combining all HIR-arm temporaries in one
// debug frame makes otherwise bounded large-pattern compilation exhaust the
// standard Rust test-thread stack on x86.
fn fixed_prefix(hir: &Hir, budget: &mut CompileBudget) -> Result<FixedPrefix, Error> {
    budget.charge(1)?;
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) => initialized_fixed_prefix(true, budget),
        HirKind::Literal(regex_syntax::hir::Literal(bytes)) => fixed_literal_prefix(bytes, budget),
        HirKind::Class(Class::Bytes(class)) => fixed_byte_class_prefix(class, budget),
        HirKind::Class(Class::Unicode(_)) => initialized_fixed_prefix(false, budget),
        HirKind::Capture(capture) => fixed_prefix(&capture.sub, budget),
        HirKind::Concat(parts) => fixed_concat_prefix(parts, budget),
        HirKind::Alternation(branches) => fixed_alternation_prefix(branches, budget),
        HirKind::Repetition(repetition) => fixed_repetition_prefix(repetition, budget),
    }
}

fn fixed_literal_prefix(bytes: &[u8], budget: &mut CompileBudget) -> Result<FixedPrefix, Error> {
    let mut output = initialized_fixed_prefix(bytes.len() <= FILTER_WIDTH, budget)?;
    let retained = bytes.len().min(FILTER_WIDTH);
    budget.charge(add(bytes.len(), retained, Resource::CompileWork)?)?;
    for (index, &byte) in bytes.iter().take(retained).enumerate() {
        let mut set = ByteSet::empty();
        set.insert(byte);
        output.sets[index] = set;
    }
    output.len = retained;
    Ok(output)
}

fn fixed_byte_class_prefix(
    class: &regex_syntax::hir::ClassBytes,
    budget: &mut CompileBudget,
) -> Result<FixedPrefix, Error> {
    let mut set = ByteSet::empty();
    for range in class.ranges() {
        let width = inclusive_byte_width(range.start(), range.end())?;
        budget.charge(add(width, 1, Resource::CompileWork)?)?;
        set.insert_range(range.start(), range.end());
    }
    let mut output = initialized_fixed_prefix(true, budget)?;
    output.sets[0] = set;
    output.len = 1;
    Ok(output)
}

fn fixed_concat_prefix(parts: &[Hir], budget: &mut CompileBudget) -> Result<FixedPrefix, Error> {
    let mut output = initialized_fixed_prefix(true, budget)?;
    for part in parts {
        budget.charge(1)?;
        let child = fixed_prefix(part, budget)?;
        output.append(child, budget)?;
        if !child.exact || output.len == FILTER_WIDTH {
            output.exact = false;
            break;
        }
    }
    Ok(output)
}

fn fixed_alternation_prefix(
    branches: &[Hir],
    budget: &mut CompileBudget,
) -> Result<FixedPrefix, Error> {
    let Some((first, rest)) = branches.split_first() else {
        return initialized_fixed_prefix(false, budget);
    };
    let mut output = fixed_prefix(first, budget)?;
    for branch in rest {
        budget.charge(1)?;
        let branch = fixed_prefix(branch, budget)?;
        let shared = output.len.min(branch.len);
        for index in 0..shared {
            for word in 0..output.sets[index].0.len() {
                budget.charge(2)?;
                output.sets[index].0[word] |= branch.sets[index].0[word];
            }
        }
        output.exact &= branch.exact && output.len == branch.len;
        output.len = shared;
        if output.len == 0 {
            break;
        }
    }
    Ok(output)
}

fn fixed_repetition_prefix(
    repetition: &Repetition,
    budget: &mut CompileBudget,
) -> Result<FixedPrefix, Error> {
    budget.charge(1)?;
    if repetition.min == 0 {
        return initialized_fixed_prefix(false, budget);
    }
    let child = fixed_prefix(&repetition.sub, budget)?;
    if child.len == 0 {
        return initialized_fixed_prefix(false, budget);
    }
    let mut output = initialized_fixed_prefix(true, budget)?;
    for _ in 0..repetition.min {
        budget.charge(1)?;
        output.append(child, budget)?;
        if !child.exact || output.len == FILTER_WIDTH {
            output.exact = false;
            break;
        }
    }
    output.exact &= child.exact && repetition.max == Some(repetition.min);
    Ok(output)
}

fn leading_assertion(hir: &Hir, budget: &mut CompileBudget) -> Result<Option<Assertion>, Error> {
    budget.charge(1)?;
    match hir.kind() {
        HirKind::Look(look) => Ok(Some(Assertion::from_look(*look))),
        HirKind::Capture(capture) => leading_assertion(&capture.sub, budget),
        HirKind::Concat(parts) => {
            for part in parts {
                budget.charge(2)?; // child visit and minimum-length property
                if let Some(assertion) = leading_assertion(part, budget)? {
                    return Ok(Some(assertion));
                }
                if part.properties().maximum_len() != Some(0) {
                    break;
                }
            }
            Ok(None)
        }
        HirKind::Repetition(repetition) if repetition.min > 0 => {
            leading_assertion(&repetition.sub, budget)
        }
        HirKind::Alternation(branches) => {
            let mut common = None;
            for branch in branches {
                budget.charge(1)?;
                let assertion = leading_assertion(branch, budget)?;
                match (common, assertion) {
                    (None, Some(assertion)) => common = Some(assertion),
                    (Some(expected), Some(actual)) if expected == actual => {}
                    _ => return Ok(None),
                }
            }
            Ok(common)
        }
        HirKind::Empty | HirKind::Literal(_) | HirKind::Class(_) | HirKind::Repetition(_) => {
            Ok(None)
        }
    }
}

fn byte_set_weight(set: ByteSet, budget: &mut CompileBudget) -> Result<usize, Error> {
    let mut weight = 0_usize;
    for byte in u8::MIN..=u8::MAX {
        budget.charge(1)?;
        if set.contains(byte) {
            budget.charge(1)?;
            weight = add(
                weight,
                usize::from(candidate_byte_weight(byte)),
                Resource::CompileWork,
            )?;
        }
    }
    Ok(weight)
}

#[allow(
    clippy::too_many_lines,
    reason = "the bounded HIR proof keeps every syntax case and offset update explicit"
)]
fn required_candidate(
    hir: &Hir,
    budget: &mut CompileBudget,
) -> Result<Option<CandidateDraft>, Error> {
    budget.charge(1)?;
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) | HirKind::Class(Class::Unicode(_)) => Ok(None),
        HirKind::Literal(regex_syntax::hir::Literal(bytes)) => {
            let Some((&first, tail)) = bytes.split_first() else {
                return Ok(None);
            };
            let mut selected = first;
            let mut selected_offset = 0_usize;
            for (index, &byte) in tail.iter().enumerate() {
                // Visit, rank comparison and potential publication are all
                // charged before consulting the next literal byte.
                budget.charge(3)?;
                if candidate_byte_weight(byte) < candidate_byte_weight(selected) {
                    selected = byte;
                    selected_offset = add(index, 1, Resource::CompileWork)?;
                }
            }
            let mut set = ByteSet::empty();
            budget.charge(1)?;
            set.insert(selected);
            Ok(Some(candidate_draft(
                set,
                selected_offset,
                selected_offset,
                initialized_filter_checks(budget)?,
                0,
            )))
        }
        HirKind::Class(Class::Bytes(class)) => {
            let mut set = ByteSet::empty();
            for range in class.ranges() {
                let width = inclusive_byte_width(range.start(), range.end())?;
                budget.charge(add(width, 1, Resource::CompileWork)?)?;
                set.insert_range(range.start(), range.end());
            }
            Ok(Some(candidate_draft(
                set,
                0,
                0,
                initialized_filter_checks(budget)?,
                0,
            )))
        }
        HirKind::Capture(capture) => required_candidate(&capture.sub, budget),
        HirKind::Repetition(repetition) => {
            budget.charge(1)?;
            if repetition.min == 0 {
                Ok(None)
            } else {
                required_candidate(&repetition.sub, budget)
            }
        }
        HirKind::Concat(parts) => {
            let mut prefix_min = 0_usize;
            let mut prefix_max = Some(0_usize);
            let mut selected = None;
            for part in parts {
                budget.charge(3)?; // child, min property and max property
                if let Some(maximum) = prefix_max
                    && let Some(mut candidate) = required_candidate(part, budget)?
                {
                    candidate.min_offset =
                        add(candidate.min_offset, prefix_min, Resource::CompileWork)?;
                    candidate.max_offset =
                        add(candidate.max_offset, maximum, Resource::CompileWork)?;
                    selected = choose_candidate(selected, candidate, budget)?;
                }
                let Some(minimum) = part.properties().minimum_len() else {
                    return Ok(None);
                };
                prefix_min = add(prefix_min, minimum, Resource::CompileWork)?;
                prefix_max = match (prefix_max, part.properties().maximum_len()) {
                    (Some(prefix), Some(maximum)) => {
                        Some(add(prefix, maximum, Resource::CompileWork)?)
                    }
                    _ => None,
                };
            }
            Ok(selected)
        }
        HirKind::Alternation(branches) => {
            let mut combined: Option<CandidateDraft> = None;
            for branch in branches {
                budget.charge(1)?;
                let Some(branch) = required_candidate(branch, budget)? else {
                    return Ok(None);
                };
                combined = Some(match combined {
                    None => branch,
                    Some(mut combined) => {
                        for word in 0..combined.bytes.0.len() {
                            budget.charge(2)?; // word visit and union write
                            combined.bytes.0[word] |= branch.bytes.0[word];
                        }
                        budget.charge(4)?; // two min/max comparisons and writes
                        combined.min_offset = combined.min_offset.min(branch.min_offset);
                        combined.max_offset = combined.max_offset.max(branch.max_offset);
                        combined
                    }
                });
            }
            Ok(combined)
        }
    }
}

// As with `fixed_prefix`, per-shape helpers prevent every recursive call from
// retaining the union of all `CandidateDraft` temporaries in its debug frame.
fn required_global_candidate(
    hir: &Hir,
    budget: &mut CompileBudget,
) -> Result<Option<CandidateDraft>, Error> {
    budget.charge(1)?;
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) | HirKind::Class(Class::Unicode(_)) => Ok(None),
        HirKind::Literal(_) | HirKind::Class(Class::Bytes(_)) => {
            required_global_leaf_candidate(hir, budget)
        }
        HirKind::Capture(capture) => required_global_candidate(&capture.sub, budget),
        HirKind::Repetition(repetition) => required_global_repetition_candidate(repetition, budget),
        HirKind::Concat(parts) => required_global_concat_candidate(hir, parts, budget),
        HirKind::Alternation(branches) => required_global_alternation_candidate(branches, budget),
    }
}

fn required_global_leaf_candidate(
    hir: &Hir,
    budget: &mut CompileBudget,
) -> Result<Option<CandidateDraft>, Error> {
    if let Some(fixed) = leading_fixed_candidate(hir, budget)? {
        Ok(Some(fixed))
    } else {
        required_candidate(hir, budget)
    }
}

fn required_global_repetition_candidate(
    repetition: &Repetition,
    budget: &mut CompileBudget,
) -> Result<Option<CandidateDraft>, Error> {
    budget.charge(1)?;
    if repetition.min == 0 {
        Ok(None)
    } else {
        required_global_candidate(&repetition.sub, budget)
    }
}

fn required_global_concat_candidate(
    hir: &Hir,
    parts: &[Hir],
    budget: &mut CompileBudget,
) -> Result<Option<CandidateDraft>, Error> {
    let mut selected = if hir
        .properties()
        .minimum_len()
        .is_some_and(|minimum| minimum > 0)
    {
        leading_fixed_candidate(hir, budget)?
    } else {
        None
    };
    for part in parts {
        budget.charge(2)?; // child visit and nonempty property
        if part
            .properties()
            .minimum_len()
            .is_some_and(|minimum| minimum > 0)
            && let Some(candidate) = required_global_candidate(part, budget)?
        {
            selected = choose_candidate(selected, candidate, budget)?;
        }
    }
    Ok(selected)
}

fn required_global_alternation_candidate(
    branches: &[Hir],
    budget: &mut CompileBudget,
) -> Result<Option<CandidateDraft>, Error> {
    let mut combined: Option<CandidateDraft> = None;
    for branch in branches {
        budget.charge(1)?;
        let Some(branch) = required_global_candidate(branch, budget)? else {
            return Ok(None);
        };
        combined = Some(match combined {
            None => branch,
            Some(mut combined) => {
                if global_probe_equal(&combined, &branch, budget)? {
                    combined
                } else {
                    for word in 0..combined.bytes.0.len() {
                        budget.charge(2)?;
                        combined.bytes.0[word] |= branch.bytes.0[word];
                    }
                    combined.checks = initialized_filter_checks(budget)?;
                    combined.check_len = 0;
                    combined.min_offset = 0;
                    combined.max_offset = 0;
                    combined.global_bytes = combined.bytes;
                    combined.global_checks = combined.checks;
                    combined.global_check_len = 0;
                    combined
                }
            }
        });
    }
    Ok(combined)
}

fn required_trailing_global_candidate(
    hir: &Hir,
    budget: &mut CompileBudget,
) -> Result<Option<CandidateDraft>, Error> {
    budget.charge(1)?;
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) | HirKind::Class(Class::Unicode(_)) => Ok(None),
        HirKind::Literal(_) | HirKind::Class(Class::Bytes(_)) => {
            required_global_candidate(hir, budget)
        }
        HirKind::Capture(capture) => required_trailing_global_candidate(&capture.sub, budget),
        HirKind::Repetition(repetition) => {
            required_trailing_repetition_candidate(repetition, budget)
        }
        HirKind::Concat(parts) => required_trailing_concat_candidate(parts, budget),
        HirKind::Alternation(branches) => required_trailing_alternation_candidate(branches, budget),
    }
}

fn required_trailing_repetition_candidate(
    repetition: &Repetition,
    budget: &mut CompileBudget,
) -> Result<Option<CandidateDraft>, Error> {
    budget.charge(1)?;
    if repetition.min == 0 {
        Ok(None)
    } else {
        required_trailing_global_candidate(&repetition.sub, budget)
    }
}

fn required_trailing_concat_candidate(
    parts: &[Hir],
    budget: &mut CompileBudget,
) -> Result<Option<CandidateDraft>, Error> {
    for part in parts.iter().rev() {
        budget.charge(2)?; // child visit and mandatory-width property
        if part
            .properties()
            .minimum_len()
            .is_some_and(|minimum| minimum > 0)
            && let Some(candidate) = required_trailing_global_candidate(part, budget)?
        {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

fn required_trailing_alternation_candidate(
    branches: &[Hir],
    budget: &mut CompileBudget,
) -> Result<Option<CandidateDraft>, Error> {
    let mut combined: Option<CandidateDraft> = None;
    for branch in branches {
        budget.charge(1)?;
        let Some(branch) = required_trailing_global_candidate(branch, budget)? else {
            return Ok(None);
        };
        combined = Some(match combined {
            None => branch,
            Some(mut combined) => {
                if global_probe_equal(&combined, &branch, budget)? {
                    combined
                } else {
                    for word in 0..combined.bytes.0.len() {
                        budget.charge(2)?;
                        combined.bytes.0[word] |= branch.bytes.0[word];
                    }
                    combined.checks = initialized_filter_checks(budget)?;
                    combined.check_len = 0;
                    combined.min_offset = 0;
                    combined.max_offset = 0;
                    combined.global_bytes = combined.bytes;
                    combined.global_checks = combined.checks;
                    combined.global_check_len = 0;
                    combined
                }
            }
        });
    }
    Ok(combined)
}

fn global_probe_equal(
    left: &CandidateDraft,
    right: &CandidateDraft,
    budget: &mut CompileBudget,
) -> Result<bool, Error> {
    budget.charge(1)?;
    if left.check_len != right.check_len {
        return Ok(false);
    }
    for word in 0..left.bytes.0.len() {
        budget.charge(1)?;
        if left.bytes.0[word] != right.bytes.0[word] {
            return Ok(false);
        }
    }
    for index in 0..left.check_len {
        let left = left.checks[index];
        let right = right.checks[index];
        budget.charge(1)?;
        if left.relative != right.relative {
            return Ok(false);
        }
        for word in 0..left.bytes.0.len() {
            budget.charge(1)?;
            if left.bytes.0[word] != right.bytes.0[word] {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn leading_candidate(
    hir: &Hir,
    budget: &mut CompileBudget,
) -> Result<Option<CandidateDraft>, Error> {
    budget.charge(1)?;
    if hir
        .properties()
        .minimum_len()
        .is_none_or(|minimum| minimum == 0)
    {
        return Ok(None);
    }
    let bytes = possible_first_bytes(hir, budget)?;
    budget.charge(bytes.0.len())?;
    if bytes.0.iter().all(|&word| word == 0) {
        return Ok(None);
    }
    Ok(Some(candidate_draft(
        bytes,
        0,
        0,
        initialized_filter_checks(budget)?,
        0,
    )))
}

fn possible_first_bytes(hir: &Hir, budget: &mut CompileBudget) -> Result<ByteSet, Error> {
    budget.charge(1)?;
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) | HirKind::Class(Class::Unicode(_)) => {
            Ok(ByteSet::empty())
        }
        HirKind::Literal(regex_syntax::hir::Literal(bytes)) => {
            let mut output = ByteSet::empty();
            if let Some(&byte) = bytes.first() {
                budget.charge(1)?;
                output.insert(byte);
            }
            Ok(output)
        }
        HirKind::Class(Class::Bytes(class)) => {
            let mut output = ByteSet::empty();
            for range in class.ranges() {
                let width = inclusive_byte_width(range.start(), range.end())?;
                budget.charge(add(width, 1, Resource::CompileWork)?)?;
                output.insert_range(range.start(), range.end());
            }
            Ok(output)
        }
        HirKind::Capture(capture) => possible_first_bytes(&capture.sub, budget),
        HirKind::Repetition(repetition) => {
            budget.charge(1)?;
            possible_first_bytes(&repetition.sub, budget)
        }
        HirKind::Concat(parts) => {
            let mut output = ByteSet::empty();
            for part in parts {
                budget.charge(2)?; // child visit and nullability property
                let child = possible_first_bytes(part, budget)?;
                for word in 0..output.0.len() {
                    budget.charge(2)?;
                    output.0[word] |= child.0[word];
                }
                if part
                    .properties()
                    .minimum_len()
                    .is_some_and(|minimum| minimum > 0)
                {
                    break;
                }
            }
            Ok(output)
        }
        HirKind::Alternation(branches) => {
            let mut output = ByteSet::empty();
            for branch in branches {
                budget.charge(1)?;
                let child = possible_first_bytes(branch, budget)?;
                for word in 0..output.0.len() {
                    budget.charge(2)?;
                    output.0[word] |= child.0[word];
                }
            }
            Ok(output)
        }
    }
}

#[allow(
    clippy::large_types_passed_by_value,
    reason = "selection transfers ownership of one fixed bounded descriptor without allocation"
)]
fn choose_candidate(
    selected: Option<CandidateDraft>,
    candidate: CandidateDraft,
    budget: &mut CompileBudget,
) -> Result<Option<CandidateDraft>, Error> {
    let Some(selected) = selected else {
        return Ok(Some(candidate));
    };
    let selected_score = candidate_score(&selected, budget)?;
    let candidate_score = candidate_score(&candidate, budget)?;
    budget.charge(2)?; // score comparison and tie dispatch
    let tied_stronger_filter = if candidate_score == selected_score {
        budget.charge(3)?; // offset pair and filter-length comparisons
        let same_minimum = candidate.min_offset == selected.min_offset;
        let same_maximum = candidate.max_offset == selected.max_offset;
        let stronger_filter = candidate.check_len > selected.check_len;
        let mut same_bytes = same_minimum && same_maximum;
        for word in 0..candidate.bytes.0.len() {
            budget.charge(1)?;
            if candidate.bytes.0[word] != selected.bytes.0[word] {
                same_bytes = false;
            }
        }
        same_bytes && stronger_filter
    } else {
        false
    };
    Ok(Some(
        if candidate_score < selected_score || tied_stronger_filter {
            candidate
        } else {
            selected
        },
    ))
}

fn candidate_score(candidate: &CandidateDraft, budget: &mut CompileBudget) -> Result<usize, Error> {
    let mut byte_weight = 0_usize;
    for byte in u8::MIN..=u8::MAX {
        budget.charge(1)?;
        if candidate.bytes.contains(byte) {
            budget.charge(1)?;
            byte_weight = add(
                byte_weight,
                usize::from(candidate_byte_weight(byte)),
                Resource::CompileWork,
            )?;
        }
    }
    let width = add(
        candidate
            .max_offset
            .checked_sub(candidate.min_offset)
            .ok_or(Error::InternalInvariant(
                "candidate offset interval reversed",
            ))?,
        1,
        Resource::CompileWork,
    )?;
    mul(byte_weight, width, Resource::CompileWork)
}

const fn candidate_byte_weight(byte: u8) -> u8 {
    let lower = byte.to_ascii_lowercase();
    if lower.is_ascii_alphabetic() {
        match lower {
            b't' => 58,
            b'a' => 54,
            b'o' => 52,
            b'i' => 50,
            b'n' => 48,
            b's' => 46,
            b'r' => 44,
            b'h' => 40,
            b'l' => 38,
            b'd' => 36,
            b'c' => 34,
            b'u' => 32,
            b'm' => 30,
            b'f' => 28,
            b'p' => 26,
            b'g' => 24,
            b'w' => 22,
            b'y' => 20,
            b'b' => 18,
            b'v' => 14,
            b'k' => 12,
            b'x' => 8,
            b'j' => 6,
            b'q' => 4,
            b'z' => 2,
            _ => 64,
        }
    } else if byte.is_ascii_digit() {
        12
    } else if byte.is_ascii_whitespace() {
        4
    } else if byte == b'_' || byte == b'-' || byte == b'/' || byte == b'.' {
        2
    } else {
        1
    }
}

type RetainedComponents = (
    RequiredSuffixes,
    RequiredLiteralSets,
    Option<fre_kernels::RequiredInternalAnchorPlan>,
    TerminalFrontierSeed,
    StartDomain,
    usize,
);

#[allow(
    clippy::too_many_lines,
    reason = "retained execution seeds are constructed and charged in one auditable accounting scope"
)]
fn build_retained_components(
    hir: &Hir,
    profile: RustByteProfile,
    limits: CompileLimits,
    budget: &mut CompileBudget,
) -> Result<RetainedComponents, Error> {
    let seed_start_bytes = budget.current_construction_bytes;
    let (required_suffixes, terminal_frontier) = execution_seeds(hir, profile, budget)?;
    let required_literals = analyze_required_literal_sets(hir, budget)?;
    budget.accounting.required_suffixes = required_suffixes.ends.len();
    budget.accounting.required_suffix_bytes = required_suffixes.bytes.len();
    budget.accounting.required_literal_sets = required_literals.len();
    budget.accounting.required_literal_proof_bytes = RequiredLiteralSets::retained_bytes();
    budget.accounting.terminal_frontier_prefix_bytes = terminal_frontier.prefix_len;
    budget.accounting.terminal_frontier_bytes = terminal_frontier.terminals.len;
    let minimum_match_bytes_proof_bytes = core::mem::size_of::<Option<usize>>();
    budget.accounting.minimum_match_bytes_proof_bytes = minimum_match_bytes_proof_bytes;
    if budget.receipt_scope {
        budget.preflight_receipt_construction_bytes(minimum_match_bytes_proof_bytes)?;
        budget.acquire_checked_construction_bytes(minimum_match_bytes_proof_bytes)?;
    }
    budget.record_initialization(minimum_match_bytes_proof_bytes, false)?;
    budget.charge(1)?;
    if budget.receipt_scope {
        budget.preflight_receipt_construction_bytes(RequiredLiteralSets::retained_bytes())?;
        budget.acquire_checked_construction_bytes(RequiredLiteralSets::retained_bytes())?;
    }
    budget.record_initialization(RequiredLiteralSets::retained_bytes(), false)?;
    budget.record_copy(mul(
        required_literals.len(),
        core::mem::size_of::<u128>(),
        Resource::ProgramBytes,
    )?)?;
    let start_domain = mandatory_start_domain(hir);
    let start_domain_proof_bytes = core::mem::size_of::<StartDomain>();
    budget.accounting.start_domain_proof_bytes =
        u8::try_from(start_domain_proof_bytes).map_err(|_| Error::ArithmeticOverflow {
            resource: Resource::ProgramBytes,
        })?;
    if budget.receipt_scope {
        budget.preflight_receipt_construction_bytes(start_domain_proof_bytes)?;
        budget.acquire_checked_construction_bytes(start_domain_proof_bytes)?;
    }
    budget.record_initialization(start_domain_proof_bytes, false)?;
    let seed_program_bytes = add(
        add(
            required_suffixes.retained_bytes()?,
            TerminalFrontierSeed::retained_bytes(),
            Resource::ProgramBytes,
        )?,
        add(
            minimum_match_bytes_proof_bytes,
            add(
                start_domain_proof_bytes,
                RequiredLiteralSets::retained_bytes(),
                Resource::ProgramBytes,
            )?,
            Resource::ProgramBytes,
        )?,
        Resource::ProgramBytes,
    )?;
    if budget.receipt_scope {
        let expected_seed_bytes =
            add(seed_start_bytes, seed_program_bytes, Resource::ProgramBytes)?;
        if budget.current_construction_bytes != expected_seed_bytes {
            return Err(Error::InternalInvariant(
                "receipt seed allocations differ from retained seed bytes",
            ));
        }
    } else {
        budget.acquire_construction_bytes(seed_program_bytes)?;
        enforce(
            budget.current_construction_bytes,
            limits.max_program_bytes,
            Resource::ProgramBytes,
        )?;
    }
    let required_internal_anchor = if profile.unicode {
        None
    } else {
        let remaining_work = limits.max_work.checked_sub(budget.accounting.work).ok_or(
            Error::ArithmeticOverflow {
                resource: Resource::CompileWork,
            },
        )?;
        let remaining_program_bytes = limits
            .max_program_bytes
            .checked_sub(budget.current_construction_bytes)
            .ok_or(Error::ArithmeticOverflow {
                resource: Resource::ProgramBytes,
            })?;
        let inspection = if budget.receipt_scope {
            let outer_work = budget.accounting.work;
            let attempt = required_internal_anchor::inspect_attempt(
                hir,
                remaining_work,
                limits.max_literal_bytes,
                remaining_program_bytes,
            );
            match attempt.result {
                Ok(inspection) => inspection,
                Err(source) => {
                    budget.charge(attempt.inspection_work)?;
                    let source = match source {
                        Error::ResourceLimit {
                            resource: Resource::CompileWork,
                            required,
                            limit,
                        } if limit == remaining_work => Error::ResourceLimit {
                            resource: Resource::CompileWork,
                            required: add(outer_work, required, Resource::CompileWork)?,
                            limit: limits.max_work,
                        },
                        source => source,
                    };
                    return Err(source);
                }
            }
        } else {
            required_internal_anchor::inspect(
                hir,
                remaining_work,
                limits.max_literal_bytes,
                remaining_program_bytes,
            )?
        };
        retain_required_internal_anchor(inspection, budget)?
    };
    let required_internal_anchor_program_bytes = required_internal_anchor
        .as_ref()
        .map_or(0, |plan| plan.build_accounting().persistent_bytes);
    let retained_program_bytes = add(
        seed_program_bytes,
        required_internal_anchor_program_bytes,
        Resource::ProgramBytes,
    )?;
    enforce(
        retained_program_bytes,
        limits.max_program_bytes,
        Resource::ProgramBytes,
    )?;
    Ok((
        required_suffixes,
        required_literals,
        required_internal_anchor,
        terminal_frontier,
        start_domain,
        retained_program_bytes,
    ))
}

fn analyze_required_literal_sets(
    hir: &Hir,
    budget: &mut CompileBudget,
) -> Result<RequiredLiteralSets, Error> {
    budget.charge(1)?;
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) => Ok(RequiredLiteralSets::empty()),
        HirKind::Literal(regex_syntax::hir::Literal(bytes)) => {
            let mut proof = RequiredLiteralSets::empty();
            budget.charge(bytes.len())?;
            if let Some(&byte) = bytes.iter().find(|&&byte| byte.is_ascii()) {
                proof.push(1_u128 << byte);
            }
            Ok(proof)
        }
        HirKind::Class(Class::Bytes(class)) => {
            let mut set = 0_u128;
            for range in class.ranges() {
                budget.charge(1)?;
                if !range.end().is_ascii() {
                    return Ok(RequiredLiteralSets::empty());
                }
                for byte in range.start()..=range.end() {
                    budget.charge(1)?;
                    set |= 1_u128 << byte;
                }
            }
            let mut proof = RequiredLiteralSets::empty();
            proof.push(set);
            Ok(proof)
        }
        HirKind::Class(Class::Unicode(class)) => {
            let mut set = 0_u128;
            for range in class.ranges() {
                budget.charge(1)?;
                if !range.end().is_ascii() {
                    return Ok(RequiredLiteralSets::empty());
                }
                for scalar in u32::from(range.start())..=u32::from(range.end()) {
                    budget.charge(1)?;
                    let byte = u8::try_from(scalar).map_err(|_| {
                        Error::InternalInvariant(
                            "ASCII required-literal scalar did not fit one byte",
                        )
                    })?;
                    set |= 1_u128 << byte;
                }
            }
            let mut proof = RequiredLiteralSets::empty();
            proof.push(set);
            Ok(proof)
        }
        HirKind::Capture(capture) => analyze_required_literal_sets(&capture.sub, budget),
        HirKind::Repetition(repetition) => {
            if repetition.min == 0 {
                Ok(RequiredLiteralSets::empty())
            } else {
                analyze_required_literal_sets(&repetition.sub, budget)
            }
        }
        HirKind::Concat(parts) => {
            let mut proof = RequiredLiteralSets::empty();
            for part in parts {
                proof.append(analyze_required_literal_sets(part, budget)?);
            }
            Ok(proof)
        }
        HirKind::Alternation(branches) => {
            let mut union = 0_u128;
            for branch in branches {
                budget.charge(1)?;
                let branch = analyze_required_literal_sets(branch, budget)?;
                let Some(set) = branch.iter().min_by_key(|set| set.count_ones()) else {
                    return Ok(RequiredLiteralSets::empty());
                };
                union |= set;
            }
            let mut proof = RequiredLiteralSets::empty();
            proof.push(union);
            Ok(proof)
        }
    }
}

fn mandatory_start_domain(hir: &Hir) -> StartDomain {
    let prefix = hir.properties().look_set_prefix();
    if prefix.contains(Look::Start) {
        StartDomain::AbsoluteStart
    } else if prefix.contains(Look::StartLF) {
        StartDomain::LineStartLf
    } else if prefix.contains(Look::StartCRLF) {
        StartDomain::LineStartCrlf
    } else {
        StartDomain::AnyBoundary
    }
}

fn partitioned_start_domain(
    start_domain: StartDomain,
    program: &Program,
    budget: &mut CompileBudget,
) -> Result<StartDomain, Error> {
    let separators: &[u8] = match start_domain {
        StartDomain::AnyBoundary | StartDomain::AbsoluteStart => return Ok(start_domain),
        StartDomain::LineStartLf => b"\n",
        StartDomain::LineStartCrlf => b"\r\n",
    };
    for inst in &*program.insts {
        budget.charge(separators.len())?;
        match inst {
            Inst::Consume { bytes, .. }
                if separators
                    .iter()
                    .copied()
                    .any(|separator| bytes.contains(separator)) =>
            {
                return Ok(StartDomain::AnyBoundary);
            }
            // Scalar continuations are not eligible for the compact executor,
            // but treating them as unpartitioned keeps this retained proof
            // independently conservative.
            Inst::ConsumeScalar { .. } => return Ok(StartDomain::AnyBoundary),
            _ => {}
        }
    }
    Ok(start_domain)
}

fn retain_required_internal_anchor(
    inspection: required_internal_anchor::Inspection,
    budget: &mut CompileBudget,
) -> Result<Option<fre_kernels::RequiredInternalAnchorPlan>, Error> {
    budget.charge(inspection.inspection_work)?;
    let Some(plan) = inspection.plan else {
        return Ok(None);
    };
    let build = plan.build_accounting();
    budget.acquire_construction_bytes(build.persistent_bytes)?;
    budget.record_initialization(build.persistent_bytes, false)?;
    budget.record_copy(build.anchor_copy_bytes)?;
    budget.accounting.required_internal_anchors = 1;
    budget.accounting.required_internal_anchor_bytes = build.anchor_bytes;
    budget.accounting.required_internal_anchor_optional_stages = build.optional_stages;
    budget.accounting.required_internal_anchor_build_work = build.observed_structural_work;
    budget
        .accounting
        .required_internal_anchor_build_work_upper_bound = build.work_upper_bound;
    budget.accounting.required_internal_anchor_persistent_bytes = build.persistent_bytes;
    Ok(Some(plan))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CapturePolicy {
    Reject,
    EraseForWholeMatch,
}

pub(crate) struct CompileBudget {
    limits: CompileLimits,
    accounting: CompileAccounting,
    receipt_scope: bool,
    construction_effect_scope: bool,
    allocation_scope: Option<AllocationScope>,
    actual_allocations: usize,
    actual_allocated_bytes: usize,
    actual_copied_bytes: usize,
    actual_initialized_bytes: usize,
    current_temporary_states: usize,
    current_construction_bytes: usize,
}

#[derive(Clone, Copy)]
struct AllocationScope {
    limit: usize,
    prospective: usize,
}

impl CompileBudget {
    pub(crate) const fn new(limits: CompileLimits) -> Self {
        Self::new_inner(limits, false, false, None)
    }

    const fn new_receipt(limits: CompileLimits, allocation_scope: Option<AllocationScope>) -> Self {
        Self::new_inner(limits, true, false, allocation_scope)
    }

    const fn new_construction_receipt(
        limits: CompileLimits,
        allocation_scope: Option<AllocationScope>,
    ) -> Self {
        Self::new_inner(limits, true, true, allocation_scope)
    }

    const fn new_inner(
        limits: CompileLimits,
        receipt_scope: bool,
        construction_effect_scope: bool,
        allocation_scope: Option<AllocationScope>,
    ) -> Self {
        Self {
            limits,
            accounting: CompileAccounting {
                hir_nodes: 0,
                hir_depth: 0,
                peak_hir_stack_items: 0,
                captures_erased: 0,
                capture_erasure_work: 0,
                literal_bytes: 0,
                class_ranges: 0,
                utf8_sequences: 0,
                utf8_byte_ranges: 0,
                look_assertions: 0,
                required_suffixes: 0,
                required_suffix_bytes: 0,
                required_literal_sets: 0,
                required_literal_proof_bytes: 0,
                required_internal_anchors: 0,
                required_internal_anchor_bytes: 0,
                required_internal_anchor_optional_stages: 0,
                required_internal_anchor_build_work: 0,
                required_internal_anchor_build_work_upper_bound: 0,
                required_internal_anchor_persistent_bytes: 0,
                url_aggregate_plans: 0,
                url_aggregate_tlds: 0,
                url_aggregate_tld_bytes: 0,
                url_aggregate_build_work: 0,
                url_aggregate_persistent_bytes: 0,
                state_byte_span_sum_plans: 0,
                state_byte_span_sum_literal_bytes: 0,
                state_byte_span_sum_build_work: 0,
                state_byte_span_sum_persistent_bytes: 0,
                ordered_bounded_span_sum_plans: 0,
                ordered_bounded_span_sum_anchor_bytes: 0,
                ordered_bounded_span_sum_max_chunks: 0,
                ordered_bounded_span_sum_build_work: 0,
                ordered_bounded_span_sum_persistent_bytes: 0,
                terminal_frontier_prefix_bytes: 0,
                terminal_frontier_bytes: 0,
                candidate_entries: 0,
                candidate_bytes: 0,
                minimum_match_bytes_proof_bytes: 0,
                start_domain_proof_bytes: 0,
                program_states: 0,
                temporary_states_peak: 0,
                program_bytes: 0,
                construction_peak_bytes: 0,
                execution_state_work: 0,
                predecessor_edges: 0,
                has_scalar_transitions: false,
                max_scalar_search_checks: 0,
                unicode_word_boundary_checks: 0,
                requires_utf8_validation: false,
                work: 0,
            },
            receipt_scope,
            construction_effect_scope,
            allocation_scope,
            actual_allocations: 0,
            actual_allocated_bytes: 0,
            actual_copied_bytes: 0,
            actual_initialized_bytes: 0,
            current_temporary_states: 0,
            current_construction_bytes: 0,
        }
    }

    pub(crate) fn charge(&mut self, amount: usize) -> Result<(), Error> {
        let required = add(self.accounting.work, amount, Resource::CompileWork)?;
        enforce(required, self.limits.max_work, Resource::CompileWork)?;
        self.accounting.work = required;
        Ok(())
    }

    /// Preflight one physical allocation only when the U1 receipt scope is
    /// active. The ordinary path returns before arithmetic or enforcement, so
    /// this hook cannot alter its error ordering.
    fn preflight_allocation(&self, needed: bool) -> Result<Option<usize>, Error> {
        if self.allocation_scope.is_none() && !self.construction_effect_scope {
            return Ok(None);
        }
        if !needed {
            return Ok(None);
        }
        let required = add(self.actual_allocations, 1, Resource::Allocations)?;
        if let Some(scope) = self.allocation_scope {
            enforce(required, scope.limit, Resource::Allocations)?;
            enforce(required, scope.prospective, Resource::Allocations)?;
        }
        Ok(Some(required))
    }

    /// Commit only after the allocator has succeeded and a capacity-bearing
    /// object exists. An ordinary compile always supplies `None` and returns
    /// immediately without inspecting allocator behavior.
    fn commit_allocation(
        &mut self,
        preflight: Option<usize>,
        allocated: bool,
        allocated_bytes: usize,
    ) -> Result<(), Error> {
        let Some(required) = preflight else {
            return Ok(());
        };
        if !allocated {
            return Err(Error::InternalInvariant(
                "preflighted compiler allocation did not change capacity",
            ));
        }
        let expected = add(self.actual_allocations, 1, Resource::Allocations)?;
        if required != expected {
            return Err(Error::InternalInvariant(
                "compiler allocation ledger changed between preflight and commit",
            ));
        }
        self.actual_allocations = required;
        if self.construction_effect_scope {
            self.actual_allocated_bytes = add(
                self.actual_allocated_bytes,
                allocated_bytes,
                Resource::ProgramBytes,
            )?;
        }
        Ok(())
    }

    fn record_initialization(&mut self, amount: usize, copied: bool) -> Result<(), Error> {
        if !self.construction_effect_scope || amount == 0 {
            return Ok(());
        }
        self.actual_initialized_bytes = add(
            self.actual_initialized_bytes,
            amount,
            Resource::ProgramBytes,
        )?;
        if copied {
            self.actual_copied_bytes =
                add(self.actual_copied_bytes, amount, Resource::ProgramBytes)?;
        }
        Ok(())
    }

    fn record_copy(&mut self, amount: usize) -> Result<(), Error> {
        if !self.construction_effect_scope || amount == 0 {
            return Ok(());
        }
        self.actual_copied_bytes = add(self.actual_copied_bytes, amount, Resource::ProgramBytes)?;
        Ok(())
    }

    fn record_items<T>(&mut self, count: usize, copied: bool) -> Result<(), Error> {
        if !self.construction_effect_scope || count == 0 || core::mem::size_of::<T>() == 0 {
            return Ok(());
        }
        self.record_initialization(
            mul(count, core::mem::size_of::<T>(), Resource::ProgramBytes)?,
            copied,
        )
    }

    fn record_external_allocation(&mut self, allocated_bytes: usize) -> Result<(), Error> {
        if !self.construction_effect_scope || allocated_bytes == 0 {
            return Ok(());
        }
        self.actual_allocations = add(self.actual_allocations, 1, Resource::Allocations)?;
        self.actual_allocated_bytes = add(
            self.actual_allocated_bytes,
            allocated_bytes,
            Resource::ProgramBytes,
        )?;
        Ok(())
    }

    fn record_url_build_terminal(
        &mut self,
        result: &Result<fre_kernels::UrlAggregatePlan, fre_kernels::UrlAggregateBuildError>,
        retained_attempt_bytes: usize,
        tld_bytes: usize,
    ) -> Result<(), Error> {
        if !self.construction_effect_scope || retained_attempt_bytes == 0 {
            return Ok(());
        }
        let states_upper_bound = add(tld_bytes, 1, Resource::ProgramBytes)?;
        let terminal_bytes = mul(
            states_upper_bound,
            core::mem::size_of::<bool>(),
            Resource::ProgramBytes,
        )?;
        let transition_bytes = retained_attempt_bytes
            .checked_sub(core::mem::size_of::<fre_kernels::UrlAggregatePlan>())
            .and_then(|bytes| bytes.checked_sub(terminal_bytes))
            .ok_or(Error::InternalInvariant(
                "URL build retained envelope is smaller than its exact storage",
            ))?;
        match result {
            Ok(plan) => {
                let accounting = plan.build_accounting();
                if accounting.states_upper_bound != states_upper_bound
                    || accounting.persistent_bytes != retained_attempt_bytes
                {
                    return Err(Error::InternalInvariant(
                        "URL build accounting differs from compiler authority envelope",
                    ));
                }
                self.record_external_allocation(transition_bytes)?;
                self.record_external_allocation(terminal_bytes)?;
                self.record_initialization(retained_attempt_bytes, false)
            }
            Err(fre_kernels::UrlAggregateBuildError::Allocation { resource, .. })
                if *resource == "transition table" =>
            {
                Ok(())
            }
            Err(fre_kernels::UrlAggregateBuildError::Allocation { resource, .. })
                if *resource == "terminal states" =>
            {
                self.record_external_allocation(transition_bytes)?;
                self.record_initialization(transition_bytes, false)
            }
            Err(_) => {
                // All semantic/resource validation precedes `retain_bytes`.
                // Once retained, a non-allocation refusal can only occur after
                // both exact arrays were allocated and initialized.
                self.record_external_allocation(transition_bytes)?;
                self.record_external_allocation(terminal_bytes)?;
                self.record_initialization(
                    add(transition_bytes, terminal_bytes, Resource::ProgramBytes)?,
                    false,
                )
            }
        }
    }

    fn failure_receipt(&self, identity: CompileAttemptIdentity) -> CompileAttemptReceipt {
        debug_assert!(self.receipt_scope);
        CompileAttemptReceipt {
            identity,
            prospective: self.limits,
            allocation_limit: self.allocation_scope.map(|scope| scope.limit),
            prospective_allocations: self.allocation_scope.map(|scope| scope.prospective),
            actual: self.accounting,
            actual_allocations: self.allocation_scope.map(|_| self.actual_allocations),
            live_construction_bytes: self.current_construction_bytes,
            published: false,
        }
    }

    fn construction_actual(&self, published: bool) -> CompileConstructionActual {
        debug_assert!(self.construction_effect_scope);
        CompileConstructionActual {
            work: self.accounting.work,
            allocations: self.actual_allocations,
            allocated_bytes: self.actual_allocated_bytes,
            copied_bytes: self.actual_copied_bytes,
            initialized_bytes: self.actual_initialized_bytes,
            live_program_bytes: if published {
                self.current_construction_bytes
            } else {
                0
            },
            live_construction_bytes: self.current_construction_bytes,
            construction_peak_bytes: self.accounting.construction_peak_bytes,
            abandonable_bytes: if published {
                0
            } else {
                self.current_construction_bytes
            },
            published,
        }
    }

    fn construction_failure_receipt(
        &self,
        identity: CompileAttemptIdentity,
    ) -> CompileConstructionAttemptReceipt {
        CompileConstructionAttemptReceipt::new(
            identity,
            self.limits,
            self.allocation_scope.map(|scope| scope.limit),
            self.allocation_scope.map(|scope| scope.prospective),
            &self.accounting,
            self.construction_actual(false),
        )
    }

    pub(crate) fn acquire_construction_bytes(&mut self, amount: usize) -> Result<(), Error> {
        self.current_construction_bytes = add(
            self.current_construction_bytes,
            amount,
            Resource::ProgramBytes,
        )?;
        self.accounting.construction_peak_bytes = self
            .accounting
            .construction_peak_bytes
            .max(self.current_construction_bytes);
        Ok(())
    }

    pub(crate) fn acquire_checked_construction_bytes(
        &mut self,
        amount: usize,
    ) -> Result<(), Error> {
        let required = add(
            self.current_construction_bytes,
            amount,
            Resource::ProgramBytes,
        )?;
        enforce(
            required,
            self.limits.max_program_bytes,
            Resource::ProgramBytes,
        )?;
        self.acquire_construction_bytes(amount)
    }

    /// Receipt-only P check. Ordinary compilation returns before arithmetic
    /// or enforcement so its incumbent error and counter ordering is exact.
    fn preflight_receipt_construction_bytes(&self, amount: usize) -> Result<(), Error> {
        if !self.receipt_scope {
            return Ok(());
        }
        let required = add(
            self.current_construction_bytes,
            amount,
            Resource::ProgramBytes,
        )?;
        enforce(
            required,
            self.limits.max_program_bytes,
            Resource::ProgramBytes,
        )
    }
    pub(crate) fn release_construction_bytes(&mut self, amount: usize) -> Result<(), Error> {
        self.current_construction_bytes = self
            .current_construction_bytes
            .checked_sub(amount)
            .ok_or(Error::InternalInvariant(
                "compiler construction-byte accounting underflow",
            ))?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) const fn current_construction_bytes(&self) -> usize {
        self.current_construction_bytes
    }

    fn acquire_state(&mut self) -> Result<(), Error> {
        let current = add(self.current_temporary_states, 1, Resource::TemporaryStates)?;
        enforce(
            current,
            self.limits.max_temporary_states,
            Resource::TemporaryStates,
        )?;
        self.charge(1)?;
        self.current_temporary_states = current;
        self.accounting.temporary_states_peak = self.accounting.temporary_states_peak.max(current);
        Ok(())
    }

    fn release_states(&mut self, count: usize) -> Result<(), Error> {
        self.current_temporary_states =
            self.current_temporary_states
                .checked_sub(count)
                .ok_or(Error::InternalInvariant(
                    "temporary state accounting underflow",
                ))?;
        Ok(())
    }

    fn record_capture_erasure(&mut self, unique_annotation: bool) -> Result<(), Error> {
        self.accounting.capture_erasure_work = add(
            self.accounting.capture_erasure_work,
            1,
            Resource::CompileWork,
        )?;
        if unique_annotation {
            self.accounting.captures_erased =
                add(self.accounting.captures_erased, 1, Resource::HirNodes)?;
        }
        Ok(())
    }

    fn record_look_assertion(&mut self) -> Result<(), Error> {
        let required = add(self.accounting.look_assertions, 1, Resource::LookAssertions)?;
        if self.receipt_scope {
            enforce(
                required,
                self.limits.max_look_assertions,
                Resource::LookAssertions,
            )?;
            self.accounting.look_assertions = required;
            Ok(())
        } else {
            self.accounting.look_assertions = required;
            enforce(
                self.accounting.look_assertions,
                self.limits.max_look_assertions,
                Resource::LookAssertions,
            )
        }
    }
}

const MAX_REQUIRED_SUFFIXES: usize = 8;
const MAX_REQUIRED_SUFFIX_BYTES: usize = 4_096;

#[derive(Clone, Copy)]
struct SuffixSet<'a> {
    literals: [Option<&'a [u8]>; MAX_REQUIRED_SUFFIXES],
    len: usize,
    bytes: usize,
}

impl<'a> SuffixSet<'a> {
    const fn empty() -> Self {
        Self {
            literals: [None; MAX_REQUIRED_SUFFIXES],
            len: 0,
            bytes: 0,
        }
    }

    fn insert(&mut self, literal: &'a [u8], budget: &mut CompileBudget) -> Result<bool, Error> {
        if literal.is_empty() || literal.len() > MAX_REQUIRED_SUFFIX_BYTES {
            return Ok(false);
        }
        for existing in self.literals[..self.len].iter().flatten().copied() {
            // Preflight the length check and worst-case shared byte prefix
            // before slice equality can perform either.
            let comparison_work = add(existing.len().min(literal.len()), 1, Resource::CompileWork)?;
            budget.charge(comparison_work)?;
            if existing == literal {
                return Ok(true);
            }
        }
        if self.len == MAX_REQUIRED_SUFFIXES {
            return Ok(false);
        }
        let Some(bytes) = self.bytes.checked_add(literal.len()) else {
            return Ok(false);
        };
        if bytes > MAX_REQUIRED_SUFFIX_BYTES {
            return Ok(false);
        }
        self.literals[self.len] = Some(literal);
        self.len = self.len.saturating_add(1);
        self.bytes = bytes;
        Ok(true)
    }

    fn iter(&self) -> impl Iterator<Item = &'a [u8]> + '_ {
        self.literals[..self.len].iter().flatten().copied()
    }
}

#[derive(Clone, Copy)]
enum SuffixAnalysis<'a> {
    /// This HIR consumes no bytes, so a containing concatenation must continue
    /// looking to its left.
    ZeroWidth,
    /// No bounded nonempty suffix theorem was proved.
    None,
    Literals(SuffixSet<'a>),
    /// Every match ends in one member of this small canonical byte class.
    TerminalBytes(TerminalByteSet),
    /// Every match ends in one member of this small canonical Unicode-scalar
    /// domain. The original continuation program remains the semantic
    /// authority; these encodings only decide which reverse rows can become
    /// live.
    UnicodeDomains(UnicodeSuffixDomains),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TerminalByteSet {
    bytes: [u8; MAX_REQUIRED_SUFFIXES],
    len: usize,
}

impl TerminalByteSet {
    const fn empty() -> Self {
        Self {
            bytes: [0; MAX_REQUIRED_SUFFIXES],
            len: 0,
        }
    }

    fn iter(self) -> impl Iterator<Item = u8> {
        self.bytes.into_iter().take(self.len)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EncodedUnicodeSuffix {
    bytes: [u8; 4],
    len: u8,
}

impl EncodedUnicodeSuffix {
    const EMPTY: Self = Self {
        bytes: [0; 4],
        len: 0,
    };

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UnicodeSuffixDomains {
    suffixes: [EncodedUnicodeSuffix; MAX_REQUIRED_SUFFIXES],
    len: usize,
    bytes: usize,
}

impl UnicodeSuffixDomains {
    fn iter(&self) -> impl Iterator<Item = &[u8]> {
        self.suffixes[..self.len]
            .iter()
            .map(EncodedUnicodeSuffix::as_bytes)
    }
}

fn unicode_scalar_range_width(start: char, end: char) -> Result<usize, Error> {
    let start = u32::from(start);
    let end = u32::from(end);
    let raw = end
        .checked_sub(start)
        .and_then(|width| width.checked_add(1))
        .ok_or(Error::ArithmeticOverflow {
            resource: Resource::CompileWork,
        })?;
    let surrogate_start = start.max(0xD800);
    let surrogate_end = end.min(0xDFFF);
    let surrogates = if surrogate_start <= surrogate_end {
        surrogate_end
            .checked_sub(surrogate_start)
            .and_then(|width| width.checked_add(1))
            .ok_or(Error::ArithmeticOverflow {
                resource: Resource::CompileWork,
            })?
    } else {
        0
    };
    usize::try_from(raw.checked_sub(surrogates).ok_or(Error::InternalInvariant(
        "canonical Unicode range contains more surrogates than scalars",
    ))?)
    .map_err(|_| Error::ArithmeticOverflow {
        resource: Resource::CompileWork,
    })
}

fn unicode_suffix_domains(
    class: &regex_syntax::hir::ClassUnicode,
    budget: &mut CompileBudget,
) -> Result<Option<UnicodeSuffixDomains>, Error> {
    let mut members = 0_usize;
    for range in class.ranges() {
        // Range visit, endpoint reads, checked scalar-width arithmetic and
        // admission comparison are charged before the range is inspected.
        budget.charge(4)?;
        members = add(
            members,
            unicode_scalar_range_width(range.start(), range.end())?,
            Resource::CompileWork,
        )?;
        if members > MAX_REQUIRED_SUFFIXES {
            return Ok(None);
        }
    }
    budget.charge(1)?; // empty-domain branch
    if members == 0 {
        return Ok(None);
    }

    // Canonical regex-syntax classes contain sorted, disjoint ranges, so the
    // scalar encodings are unique and require no data-dependent dedup pass.
    // Charge every fixed slot before initializing the inline temporary.
    budget.charge(MAX_REQUIRED_SUFFIXES)?;
    let mut domains = UnicodeSuffixDomains {
        suffixes: [EncodedUnicodeSuffix::EMPTY; MAX_REQUIRED_SUFFIXES],
        len: 0,
        bytes: 0,
    };
    for range in class.ranges() {
        budget.charge(1)?; // materialization range visit
        for scalar in range.start()..=range.end() {
            // Precharge loop service, four-byte temporary initialization,
            // UTF-8 encoding, length conversion, checked counters and the
            // fixed-width inline copy before any of those operations.
            budget.charge(12)?;
            let mut encoded = [0_u8; 4];
            let encoded = scalar.encode_utf8(&mut encoded).as_bytes();
            let len = u8::try_from(encoded.len()).map_err(|_| {
                Error::InternalInvariant("Unicode scalar encoding exceeds four bytes")
            })?;
            let slot = domains
                .suffixes
                .get_mut(domains.len)
                .ok_or(Error::InternalInvariant(
                    "Unicode suffix domain exceeded its admitted census",
                ))?;
            slot.bytes[..encoded.len()].copy_from_slice(encoded);
            slot.len = len;
            domains.len = add(domains.len, 1, Resource::CompileWork)?;
            domains.bytes = add(domains.bytes, encoded.len(), Resource::CompileWork)?;
        }
    }
    if domains.len != members {
        return Err(Error::InternalInvariant(
            "canonical Unicode suffix census changed during materialization",
        ));
    }
    Ok(Some(domains))
}

fn execution_seeds(
    hir: &Hir,
    profile: RustByteProfile,
    budget: &mut CompileBudget,
) -> Result<(RequiredSuffixes, TerminalFrontierSeed), Error> {
    let analysis = analyze_required_suffixes(hir, budget)?;
    let terminal_frontier = terminal_frontier_seed(hir, profile, &analysis, budget)?;
    if budget.receipt_scope {
        budget.acquire_checked_construction_bytes(TerminalFrontierSeed::retained_bytes())?;
    }
    budget.record_initialization(TerminalFrontierSeed::retained_bytes(), false)?;
    budget.record_copy(
        terminal_frontier
            .prefix_len
            .checked_add(terminal_frontier.terminals.len)
            .ok_or(Error::ArithmeticOverflow {
                resource: Resource::ProgramBytes,
            })?,
    )?;
    let required_suffixes = materialize_required_suffixes(hir, analysis, budget)?;
    Ok((required_suffixes, terminal_frontier))
}

#[cfg(test)]
fn required_suffixes(hir: &Hir, budget: &mut CompileBudget) -> Result<RequiredSuffixes, Error> {
    let analysis = analyze_required_suffixes(hir, budget)?;
    materialize_required_suffixes(hir, analysis, budget)
}

fn retain_unicode_suffix_domains(
    domains: &UnicodeSuffixDomains,
    bytes: &mut ExactVec<u8>,
    ends: &mut ExactVec<usize>,
    budget: &mut CompileBudget,
) -> Result<(), Error> {
    for (index, suffix) in domains.iter().enumerate() {
        for &byte in suffix {
            bytes.try_push(byte).map_err(|_| {
                Error::InternalInvariant("Unicode required suffix exceeded exact byte allocation")
            })?;
            budget.record_items::<u8>(1, true)?;
        }
        let end = if index == 0 {
            if bytes.len() >= UNICODE_SUFFIX_DOMAIN_TAG {
                return Err(Error::InternalInvariant(
                    "Unicode suffix endpoint overlaps its domain tag",
                ));
            }
            bytes.len() | UNICODE_SUFFIX_DOMAIN_TAG
        } else {
            bytes.len()
        };
        ends.try_push(end).map_err(|_| {
            Error::InternalInvariant("Unicode required suffix exceeded exact endpoint allocation")
        })?;
        budget.record_items::<usize>(1, false)?;
    }
    Ok(())
}

fn materialize_required_suffixes(
    hir: &Hir,
    analysis: SuffixAnalysis<'_>,
    budget: &mut CompileBudget,
) -> Result<RequiredSuffixes, Error> {
    if matches!(&analysis, SuffixAnalysis::TerminalBytes(_)) {
        // A byte-class endpoint can occur far more often than a multi-byte
        // literal. Retain it only when the authenticated HIR proves a finite
        // predecessor window; sparse execution then naturally clears live
        // rows outside that window.
        budget.charge(1)?;
        if hir.properties().maximum_len().is_none() {
            return Ok(RequiredSuffixes::default());
        }
    }
    let (suffix_count, suffix_bytes) = match &analysis {
        SuffixAnalysis::Literals(literals) => (literals.len, literals.bytes),
        SuffixAnalysis::TerminalBytes(terminals) => (terminals.len, terminals.len),
        SuffixAnalysis::UnicodeDomains(domains) => (domains.len, domains.bytes),
        SuffixAnalysis::ZeroWidth | SuffixAnalysis::None => {
            return Ok(RequiredSuffixes::default());
        }
    };
    if suffix_count == 0 {
        return Ok(RequiredSuffixes::default());
    }
    let requested_program_bytes = add(
        suffix_bytes,
        mul(
            suffix_count,
            core::mem::size_of::<usize>(),
            Resource::ProgramBytes,
        )?,
        Resource::ProgramBytes,
    )?;
    enforce(
        requested_program_bytes,
        budget.limits.max_program_bytes,
        Resource::ProgramBytes,
    )?;
    budget.preflight_receipt_construction_bytes(requested_program_bytes)?;
    // Preflight every retained endpoint and byte before allocation or copy.
    budget.charge(add(suffix_count, suffix_bytes, Resource::CompileWork)?)?;
    let mut bytes = exact_program_vec_metered(suffix_bytes, budget)?;
    if budget.receipt_scope {
        budget.acquire_construction_bytes(suffix_bytes)?;
    }
    let mut ends = exact_program_vec_metered(suffix_count, budget)?;
    if budget.receipt_scope {
        budget.acquire_construction_bytes(mul(
            suffix_count,
            core::mem::size_of::<usize>(),
            Resource::ProgramBytes,
        )?)?;
    }
    match analysis {
        SuffixAnalysis::Literals(literals) => {
            for literal in literals.iter() {
                for &byte in literal {
                    bytes.try_push(byte).map_err(|_| {
                        Error::InternalInvariant("required suffix exceeded exact byte allocation")
                    })?;
                    budget.record_items::<u8>(1, true)?;
                }
                ends.try_push(bytes.len()).map_err(|_| {
                    Error::InternalInvariant("required suffix exceeded exact endpoint allocation")
                })?;
                budget.record_items::<usize>(1, false)?;
            }
        }
        SuffixAnalysis::TerminalBytes(terminals) => {
            for byte in terminals.iter() {
                bytes.try_push(byte).map_err(|_| {
                    Error::InternalInvariant("required suffix exceeded exact byte allocation")
                })?;
                budget.record_items::<u8>(1, true)?;
                ends.try_push(bytes.len()).map_err(|_| {
                    Error::InternalInvariant("required suffix exceeded exact endpoint allocation")
                })?;
                budget.record_items::<usize>(1, false)?;
            }
        }
        SuffixAnalysis::UnicodeDomains(domains) => {
            retain_unicode_suffix_domains(&domains, &mut bytes, &mut ends, budget)?;
        }
        SuffixAnalysis::ZeroWidth | SuffixAnalysis::None => {
            return Err(Error::InternalInvariant(
                "ineligible required suffix reached materialization",
            ));
        }
    }
    Ok(RequiredSuffixes { bytes, ends })
}

#[derive(Clone, Copy)]
enum LeadingLiteral<'a> {
    ZeroWidth,
    Literal(&'a [u8]),
    None,
}

fn terminal_frontier_seed(
    hir: &Hir,
    profile: RustByteProfile,
    suffix: &SuffixAnalysis<'_>,
    budget: &mut CompileBudget,
) -> Result<TerminalFrontierSeed, Error> {
    budget.charge(1)?;
    let properties = hir.properties();
    if profile.unicode
        || properties.maximum_len().is_some()
        || properties.minimum_len().is_none_or(|minimum| minimum == 0)
    {
        return Ok(TerminalFrontierSeed::empty());
    }
    let SuffixAnalysis::TerminalBytes(terminals) = suffix else {
        return Ok(TerminalFrontierSeed::empty());
    };
    if terminals.len < 2 || !ends_in_byte_class(hir, budget)? {
        return Ok(TerminalFrontierSeed::empty());
    }
    let LeadingLiteral::Literal(prefix) = analyze_leading_literal(hir, budget)? else {
        return Ok(TerminalFrontierSeed::empty());
    };
    if !(MIN_TERMINAL_FRONTIER_PREFIX_BYTES..=MAX_TERMINAL_FRONTIER_PREFIX_BYTES)
        .contains(&prefix.len())
    {
        return Ok(TerminalFrontierSeed::empty());
    }
    // Charge the complete inline initialization and both logical copies before
    // publishing the certificate. The fixed arrays add no heap allocation;
    // `program_bytes` below reports the complete fixed inline proof object.
    let initialization = add(
        MAX_TERMINAL_FRONTIER_PREFIX_BYTES,
        MAX_REQUIRED_SUFFIXES,
        Resource::CompileWork,
    )?;
    budget.charge(add(
        initialization,
        add(prefix.len(), terminals.len, Resource::CompileWork)?,
        Resource::CompileWork,
    )?)?;
    let mut retained = [0_u8; MAX_TERMINAL_FRONTIER_PREFIX_BYTES];
    retained[..prefix.len()].copy_from_slice(prefix);
    Ok(TerminalFrontierSeed {
        prefix: retained,
        prefix_len: prefix.len(),
        terminals: *terminals,
    })
}

fn ends_in_byte_class(mut hir: &Hir, budget: &mut CompileBudget) -> Result<bool, Error> {
    loop {
        budget.charge(1)?;
        match hir.kind() {
            HirKind::Capture(capture) => hir = &capture.sub,
            HirKind::Concat(parts) => {
                let mut last_consuming = None;
                for part in parts.iter().rev() {
                    budget.charge(1)?;
                    if part
                        .properties()
                        .minimum_len()
                        .is_some_and(|length| length > 0)
                    {
                        last_consuming = Some(part);
                        break;
                    }
                }
                let Some(last_consuming) = last_consuming else {
                    return Ok(false);
                };
                hir = last_consuming;
            }
            HirKind::Class(Class::Bytes(_)) => return Ok(true),
            _ => return Ok(false),
        }
    }
}

fn analyze_leading_literal<'a>(
    hir: &'a Hir,
    budget: &mut CompileBudget,
) -> Result<LeadingLiteral<'a>, Error> {
    budget.charge(1)?;
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) => Ok(LeadingLiteral::ZeroWidth),
        HirKind::Literal(regex_syntax::hir::Literal(bytes)) => {
            if bytes.is_empty() {
                Ok(LeadingLiteral::ZeroWidth)
            } else {
                Ok(LeadingLiteral::Literal(bytes))
            }
        }
        HirKind::Capture(capture) => analyze_leading_literal(&capture.sub, budget),
        HirKind::Repetition(repetition) => {
            if repetition.min == 0 {
                Ok(LeadingLiteral::None)
            } else {
                analyze_leading_literal(&repetition.sub, budget)
            }
        }
        HirKind::Concat(parts) => {
            for part in parts {
                match analyze_leading_literal(part, budget)? {
                    LeadingLiteral::ZeroWidth => {}
                    leading => return Ok(leading),
                }
            }
            Ok(LeadingLiteral::ZeroWidth)
        }
        HirKind::Alternation(branches) => common_leading_literal(branches, budget),
        HirKind::Class(_) => Ok(LeadingLiteral::None),
    }
}

fn common_leading_literal<'a>(
    branches: &'a [Hir],
    budget: &mut CompileBudget,
) -> Result<LeadingLiteral<'a>, Error> {
    let mut common = None;
    for branch in branches {
        budget.charge(1)?;
        let LeadingLiteral::Literal(candidate) = analyze_leading_literal(branch, budget)? else {
            return Ok(LeadingLiteral::None);
        };
        let Some(expected) = common else {
            common = Some(candidate);
            continue;
        };
        budget.charge(add(
            expected.len().min(candidate.len()),
            1,
            Resource::CompileWork,
        )?)?;
        let shared_limit = expected.len().min(candidate.len());
        let mut shared = 0_usize;
        while shared < shared_limit && expected[shared] == candidate[shared] {
            shared = shared.saturating_add(1);
        }
        if shared == 0 {
            return Ok(LeadingLiteral::None);
        }
        common = Some(&expected[..shared]);
    }
    Ok(common.map_or(LeadingLiteral::None, LeadingLiteral::Literal))
}

fn analyze_required_suffixes<'a>(
    hir: &'a Hir,
    budget: &mut CompileBudget,
) -> Result<SuffixAnalysis<'a>, Error> {
    budget.charge(1)?;
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) => Ok(SuffixAnalysis::ZeroWidth),
        HirKind::Literal(regex_syntax::hir::Literal(bytes)) => {
            if bytes.is_empty() {
                Ok(SuffixAnalysis::ZeroWidth)
            } else {
                let mut suffixes = SuffixSet::empty();
                if suffixes.insert(bytes, budget)? {
                    Ok(SuffixAnalysis::Literals(suffixes))
                } else {
                    Ok(SuffixAnalysis::None)
                }
            }
        }
        HirKind::Class(Class::Bytes(class)) => {
            let mut terminals = TerminalByteSet::empty();
            for range in class.ranges() {
                let width = inclusive_byte_width(range.start(), range.end())?;
                budget.charge(add(width, 1, Resource::CompileWork)?)?;
                let Some(next_len) = terminals.len.checked_add(width) else {
                    return Ok(SuffixAnalysis::None);
                };
                if next_len > MAX_REQUIRED_SUFFIXES {
                    return Ok(SuffixAnalysis::None);
                }
                for byte in range.start()..=range.end() {
                    terminals.bytes[terminals.len] = byte;
                    terminals.len = terminals.len.saturating_add(1);
                }
            }
            if terminals.len == 0 {
                Ok(SuffixAnalysis::None)
            } else {
                Ok(SuffixAnalysis::TerminalBytes(terminals))
            }
        }
        HirKind::Class(Class::Unicode(class)) => Ok(unicode_suffix_domains(class, budget)?
            .map_or(SuffixAnalysis::None, SuffixAnalysis::UnicodeDomains)),
        HirKind::Capture(capture) => analyze_required_suffixes(&capture.sub, budget),
        HirKind::Repetition(repetition) => {
            if repetition.min == 0 {
                Ok(SuffixAnalysis::None)
            } else {
                analyze_required_suffixes(&repetition.sub, budget)
            }
        }
        HirKind::Concat(parts) => {
            for part in parts.iter().rev() {
                match analyze_required_suffixes(part, budget)? {
                    SuffixAnalysis::ZeroWidth => {}
                    other => return Ok(other),
                }
            }
            Ok(SuffixAnalysis::ZeroWidth)
        }
        HirKind::Alternation(branches) => {
            let mut combined = SuffixSet::empty();
            for branch in branches {
                // Branch selection is separate from the recursive node visit.
                budget.charge(1)?;
                let SuffixAnalysis::Literals(suffixes) = analyze_required_suffixes(branch, budget)?
                else {
                    return Ok(SuffixAnalysis::None);
                };
                for suffix in suffixes.iter() {
                    if !combined.insert(suffix, budget)? {
                        return Ok(SuffixAnalysis::None);
                    }
                }
            }
            if combined.len == 0 {
                Ok(SuffixAnalysis::None)
            } else {
                Ok(SuffixAnalysis::Literals(combined))
            }
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "validation keeps incumbent traversal and receipt-only counter commits adjacent"
)]
fn validate_hir(
    hir: &Hir,
    profile: RustByteProfile,
    capture_policy: CapturePolicy,
    budget: &mut CompileBudget,
) -> Result<(), Error> {
    let mut stack = Vec::new();
    if budget.receipt_scope {
        budget.preflight_receipt_construction_bytes(mul(
            CompiledRegex::pinned_hir_stack_initial_capacity(),
            core::mem::size_of::<(&Hir, usize)>(),
            Resource::ProgramBytes,
        )?)?;
    }
    let initial_capacity = compiler_allocation(
        budget,
        true,
        Resource::HirStackItems,
        1,
        || {
            stack
                .try_reserve_exact(1)
                .map_err(|_| Error::AllocationFailed {
                    resource: Resource::HirStackItems,
                    items: 1,
                })?;
            Ok(stack.capacity())
        },
        |capacity| {
            mul(
                *capacity,
                core::mem::size_of::<(&Hir, usize)>(),
                Resource::ProgramBytes,
            )
        },
    )?;
    if initial_capacity != stack.capacity() {
        return Err(Error::InternalInvariant(
            "HIR stack capacity changed after allocation accounting",
        ));
    }
    if budget.receipt_scope
        && stack.capacity() != CompiledRegex::pinned_hir_stack_initial_capacity()
    {
        return Err(Error::InternalInvariant(
            "pinned initial HIR stack capacity profile differs from Rust Vec",
        ));
    }
    budget.acquire_construction_bytes(mul(
        stack.capacity(),
        core::mem::size_of::<(&Hir, usize)>(),
        Resource::ProgramBytes,
    )?)?;
    enforce(
        1,
        budget.limits.max_hir_stack_items,
        Resource::HirStackItems,
    )?;
    stack.push((hir, 1_usize));
    budget.record_items::<(&Hir, usize)>(1, false)?;
    budget.accounting.peak_hir_stack_items = 1;
    while let Some((node, depth)) = stack.pop() {
        budget.charge(1)?;
        let hir_nodes = add(budget.accounting.hir_nodes, 1, Resource::HirNodes)?;
        if budget.receipt_scope {
            enforce(hir_nodes, budget.limits.max_hir_nodes, Resource::HirNodes)?;
            budget.accounting.hir_nodes = hir_nodes;
        } else {
            budget.accounting.hir_nodes = hir_nodes;
            enforce(
                budget.accounting.hir_nodes,
                budget.limits.max_hir_nodes,
                Resource::HirNodes,
            )?;
        }
        enforce(depth, budget.limits.max_hir_depth, Resource::HirDepth)?;
        budget.accounting.hir_depth = budget.accounting.hir_depth.max(depth);
        match node.kind() {
            HirKind::Empty => {}
            HirKind::Literal(literal) => {
                budget.charge(literal.0.len())?;
                let literal_bytes = add(
                    budget.accounting.literal_bytes,
                    literal.0.len(),
                    Resource::LiteralBytes,
                )?;
                if budget.receipt_scope {
                    enforce(
                        literal_bytes,
                        budget.limits.max_literal_bytes,
                        Resource::LiteralBytes,
                    )?;
                    budget.accounting.literal_bytes = literal_bytes;
                } else {
                    budget.accounting.literal_bytes = literal_bytes;
                    enforce(
                        budget.accounting.literal_bytes,
                        budget.limits.max_literal_bytes,
                        Resource::LiteralBytes,
                    )?;
                }
            }
            HirKind::Class(Class::Unicode(class)) => {
                validate_unicode_class(class, profile, budget)?;
            }
            HirKind::Class(Class::Bytes(class)) => {
                let ranges = class.ranges().len();
                budget.charge(ranges)?;
                let class_ranges = add(
                    budget.accounting.class_ranges,
                    ranges,
                    Resource::ClassRanges,
                )?;
                if budget.receipt_scope {
                    enforce(
                        class_ranges,
                        budget.limits.max_class_ranges,
                        Resource::ClassRanges,
                    )?;
                    budget.accounting.class_ranges = class_ranges;
                } else {
                    budget.accounting.class_ranges = class_ranges;
                    enforce(
                        budget.accounting.class_ranges,
                        budget.limits.max_class_ranges,
                        Resource::ClassRanges,
                    )?;
                }
            }
            HirKind::Look(_) => {
                budget.record_look_assertion()?;
            }
            HirKind::Capture(capture) => match capture_policy {
                CapturePolicy::Reject => return Err(Error::Unsupported(Unsupported::Capture)),
                CapturePolicy::EraseForWholeMatch => {
                    budget.record_capture_erasure(true)?;
                    push_children(&mut stack, [capture.sub.as_ref()], depth, budget)?;
                }
            },
            HirKind::Repetition(repetition) => {
                validate_repetition(repetition, budget)?;
                push_children(&mut stack, [repetition.sub.as_ref()], depth, budget)?;
            }
            HirKind::Concat(children) | HirKind::Alternation(children) => {
                if matches!(node.kind(), HirKind::Alternation(_)) && children.is_empty() {
                    return Err(Error::EmptyAlternation);
                }
                push_children(&mut stack, children.iter(), depth, budget)?;
            }
        }
    }
    budget.release_construction_bytes(mul(
        stack.capacity(),
        core::mem::size_of::<(&Hir, usize)>(),
        Resource::ProgramBytes,
    )?)?;
    Ok(())
}

fn validate_unicode_class(
    class: &regex_syntax::hir::ClassUnicode,
    profile: RustByteProfile,
    budget: &mut CompileBudget,
) -> Result<(), Error> {
    let receipt_metered_unicode_off_scan = !profile.unicode && budget.receipt_scope;
    if !profile.unicode {
        if budget.receipt_scope {
            for range in class.ranges() {
                budget.charge(1)?;
                if !range.end().is_ascii() {
                    return Err(Error::Unsupported(Unsupported::UnicodeClass));
                }
            }
        } else if class.ranges().iter().any(|range| !range.end().is_ascii()) {
            return Err(Error::Unsupported(Unsupported::UnicodeClass));
        }
    }
    let ranges = class.ranges().len();
    if !receipt_metered_unicode_off_scan {
        budget.charge(ranges)?;
    }
    let class_ranges = add(
        budget.accounting.class_ranges,
        ranges,
        Resource::ClassRanges,
    )?;
    if budget.receipt_scope {
        enforce(
            class_ranges,
            budget.limits.max_class_ranges,
            Resource::ClassRanges,
        )?;
        budget.accounting.class_ranges = class_ranges;
    } else {
        budget.accounting.class_ranges = class_ranges;
        enforce(
            budget.accounting.class_ranges,
            budget.limits.max_class_ranges,
            Resource::ClassRanges,
        )?;
    }
    if profile.unicode {
        for range in class.ranges() {
            for sequence in Utf8Sequences::new(range.start(), range.end()) {
                budget.charge(1)?;
                let utf8_sequences =
                    add(budget.accounting.utf8_sequences, 1, Resource::Utf8Sequences)?;
                if budget.receipt_scope {
                    enforce(
                        utf8_sequences,
                        budget.limits.max_utf8_sequences,
                        Resource::Utf8Sequences,
                    )?;
                    budget.accounting.utf8_sequences = utf8_sequences;
                } else {
                    budget.accounting.utf8_sequences = utf8_sequences;
                    enforce(
                        budget.accounting.utf8_sequences,
                        budget.limits.max_utf8_sequences,
                        Resource::Utf8Sequences,
                    )?;
                }
                let byte_ranges = sequence.as_slice().len();
                budget.charge(byte_ranges)?;
                let utf8_byte_ranges = add(
                    budget.accounting.utf8_byte_ranges,
                    byte_ranges,
                    Resource::Utf8ByteRanges,
                )?;
                if budget.receipt_scope {
                    enforce(
                        utf8_byte_ranges,
                        budget.limits.max_utf8_byte_ranges,
                        Resource::Utf8ByteRanges,
                    )?;
                    budget.accounting.utf8_byte_ranges = utf8_byte_ranges;
                } else {
                    budget.accounting.utf8_byte_ranges = utf8_byte_ranges;
                    enforce(
                        budget.accounting.utf8_byte_ranges,
                        budget.limits.max_utf8_byte_ranges,
                        Resource::Utf8ByteRanges,
                    )?;
                }
            }
        }
    }
    Ok(())
}

fn push_children<'a>(
    stack: &mut Vec<(&'a Hir, usize)>,
    children: impl IntoIterator<Item = &'a Hir>,
    depth: usize,
    budget: &mut CompileBudget,
) -> Result<(), Error> {
    let next_depth = add(depth, 1, Resource::HirDepth)?;
    for child in children {
        let required = add(stack.len(), 1, Resource::HirStackItems)?;
        enforce(
            required,
            budget.limits.max_hir_stack_items,
            Resource::HirStackItems,
        )?;
        if budget.receipt_scope {
            budget.charge(1)?;
        }
        let old_capacity = stack.capacity();
        let needs_allocation = stack.len() == stack.capacity();
        let receipt_capacity = if budget.receipt_scope && needs_allocation {
            let capacity =
                CompiledRegex::pinned_hir_stack_capacity_after_push(old_capacity, required).ok_or(
                    Error::ArithmeticOverflow {
                        resource: Resource::ProgramBytes,
                    },
                )?;
            budget.preflight_receipt_construction_bytes(mul(
                capacity
                    .checked_sub(old_capacity)
                    .ok_or(Error::InternalInvariant(
                        "pinned HIR stack capacity decreased",
                    ))?,
                core::mem::size_of::<(&Hir, usize)>(),
                Resource::ProgramBytes,
            )?)?;
            Some(capacity)
        } else {
            None
        };
        let observed_capacity = compiler_allocation(
            budget,
            needs_allocation,
            Resource::HirStackItems,
            1,
            || {
                stack.try_reserve(1).map_err(|_| Error::AllocationFailed {
                    resource: Resource::HirStackItems,
                    items: 1,
                })?;
                Ok(stack.capacity())
            },
            |capacity| {
                mul(
                    capacity
                        .checked_sub(old_capacity)
                        .ok_or(Error::InternalInvariant(
                            "HIR stack capacity decreased during allocation accounting",
                        ))?,
                    core::mem::size_of::<(&Hir, usize)>(),
                    Resource::ProgramBytes,
                )
            },
        )?;
        if observed_capacity != stack.capacity() {
            return Err(Error::InternalInvariant(
                "HIR stack capacity changed after allocation accounting",
            ));
        }
        if receipt_capacity.is_some_and(|capacity| capacity != stack.capacity()) {
            return Err(Error::InternalInvariant(
                "pinned HIR stack capacity profile differs from Rust Vec",
            ));
        }
        let added_capacity =
            stack
                .capacity()
                .checked_sub(old_capacity)
                .ok_or(Error::InternalInvariant(
                    "HIR stack capacity decreased during reserve",
                ))?;
        budget.acquire_construction_bytes(mul(
            added_capacity,
            core::mem::size_of::<(&Hir, usize)>(),
            Resource::ProgramBytes,
        )?)?;
        stack.push((child, next_depth));
        budget.record_items::<(&Hir, usize)>(1, false)?;
        budget.accounting.peak_hir_stack_items =
            budget.accounting.peak_hir_stack_items.max(stack.len());
        if !budget.receipt_scope {
            budget.charge(1)?;
        }
    }
    Ok(())
}

fn validate_repetition(repetition: &Repetition, budget: &mut CompileBudget) -> Result<(), Error> {
    if repetition
        .max
        .is_some_and(|maximum| maximum < repetition.min)
    {
        return Err(Error::InvalidRepetition);
    }
    let largest = repetition.max.unwrap_or(repetition.min);
    let required = usize::try_from(largest).map_err(|_| Error::ArithmeticOverflow {
        resource: Resource::RepeatBound,
    })?;
    let limit =
        usize::try_from(budget.limits.max_repeat_bound).map_err(|_| Error::ArithmeticOverflow {
            resource: Resource::RepeatBound,
        })?;
    enforce(required, limit, Resource::RepeatBound)
}

struct Builder<'a> {
    slots: Vec<Inst>,
    scalar_range_bytes: usize,
    retained_program_bytes: usize,
    state_limit: usize,
    profile: RustByteProfile,
    capture_policy: CapturePolicy,
    budget: &'a mut CompileBudget,
}

impl<'a> Builder<'a> {
    fn new(
        state_limit: usize,
        profile: RustByteProfile,
        capture_policy: CapturePolicy,
        retained_program_bytes: usize,
        budget: &'a mut CompileBudget,
    ) -> Self {
        Self {
            slots: Vec::new(),
            scalar_range_bytes: 0,
            retained_program_bytes,
            state_limit,
            profile,
            capture_policy,
            budget,
        }
    }

    fn enforce_program_shape(&self, states: usize, scalar_range_bytes: usize) -> Result<(), Error> {
        enforce(states, self.state_limit, Resource::ProgramStates)?;
        let state_metadata_bytes = mul(2, core::mem::size_of::<usize>(), Resource::ProgramBytes)?;
        let state_bytes = mul(
            states,
            add(
                core::mem::size_of::<Inst>(),
                state_metadata_bytes,
                Resource::ProgramBytes,
            )?,
            Resource::ProgramBytes,
        )?;
        enforce(
            add(
                add(state_bytes, scalar_range_bytes, Resource::ProgramBytes)?,
                self.retained_program_bytes,
                Resource::ProgramBytes,
            )?,
            self.budget.limits.max_program_bytes,
            Resource::ProgramBytes,
        )
    }

    fn push(&mut self, inst: Inst) -> Result<usize, Error> {
        self.push_with_scalar_accounting(inst, false)
    }

    fn push_preaccounted_scalar(&mut self, inst: Inst) -> Result<usize, Error> {
        self.push_with_scalar_accounting(inst, true)
    }

    fn push_with_scalar_accounting(
        &mut self,
        inst: Inst,
        scalar_preaccounted: bool,
    ) -> Result<usize, Error> {
        let required = add(self.slots.len(), 1, Resource::ProgramStates)?;
        let added_scalar_bytes = match &inst {
            Inst::ConsumeScalar { scalars, .. } => scalars.allocated_bytes()?,
            _ => 0,
        };
        if scalar_preaccounted != (self.budget.receipt_scope && added_scalar_bytes != 0) {
            return Err(Error::InternalInvariant(
                "compiler scalar state accounting scope differs from owned storage",
            ));
        }
        let scalar_range_bytes = add(
            self.scalar_range_bytes,
            added_scalar_bytes,
            Resource::ProgramBytes,
        )?;
        self.enforce_program_shape(required, scalar_range_bytes)?;
        self.budget.acquire_state()?;
        let old_capacity = self.slots.capacity();
        let needs_allocation = self.slots.len() == self.slots.capacity();
        let receipt_capacity = if self.budget.receipt_scope && needs_allocation {
            let capacity = CompiledRegex::pinned_state_capacity_after_push(old_capacity, required)
                .ok_or(Error::ArithmeticOverflow {
                    resource: Resource::ProgramBytes,
                })?;
            self.budget.preflight_receipt_construction_bytes(mul(
                capacity
                    .checked_sub(old_capacity)
                    .ok_or(Error::InternalInvariant(
                        "pinned compiler state capacity decreased",
                    ))?,
                core::mem::size_of::<Inst>(),
                Resource::ProgramBytes,
            )?)?;
            Some(capacity)
        } else {
            None
        };
        let observed_capacity = compiler_allocation(
            self.budget,
            needs_allocation,
            Resource::TemporaryStates,
            1,
            || {
                self.slots
                    .try_reserve(1)
                    .map_err(|_| Error::AllocationFailed {
                        resource: Resource::TemporaryStates,
                        items: 1,
                    })?;
                Ok(self.slots.capacity())
            },
            |capacity| {
                mul(
                    capacity
                        .checked_sub(old_capacity)
                        .ok_or(Error::InternalInvariant(
                            "compiler state capacity decreased during allocation accounting",
                        ))?,
                    core::mem::size_of::<Inst>(),
                    Resource::ProgramBytes,
                )
            },
        )?;
        if observed_capacity != self.slots.capacity() {
            return Err(Error::InternalInvariant(
                "compiler state capacity changed after allocation accounting",
            ));
        }
        if receipt_capacity.is_some_and(|capacity| capacity != self.slots.capacity()) {
            return Err(Error::InternalInvariant(
                "pinned compiler state capacity profile differs from Rust Vec",
            ));
        }
        let added_capacity =
            self.slots
                .capacity()
                .checked_sub(old_capacity)
                .ok_or(Error::InternalInvariant(
                    "compiler state capacity decreased during reserve",
                ))?;
        let state_capacity_bytes = mul(
            added_capacity,
            core::mem::size_of::<Inst>(),
            Resource::ProgramBytes,
        )?;
        self.budget
            .acquire_construction_bytes(if scalar_preaccounted {
                state_capacity_bytes
            } else {
                add(
                    state_capacity_bytes,
                    added_scalar_bytes,
                    Resource::ProgramBytes,
                )?
            })?;
        let index = self.slots.len();
        self.slots.push(inst);
        self.budget.record_items::<Inst>(1, false)?;
        self.scalar_range_bytes = scalar_range_bytes;
        Ok(index)
    }

    fn fill_unfilled(&mut self, index: usize, inst: Inst) -> Result<(), Error> {
        self.fill_unfilled_with_scalar_accounting(index, inst, false)
    }

    fn fill_unfilled_preaccounted_scalar(&mut self, index: usize, inst: Inst) -> Result<(), Error> {
        self.fill_unfilled_with_scalar_accounting(index, inst, true)
    }

    fn fill_unfilled_with_scalar_accounting(
        &mut self,
        index: usize,
        inst: Inst,
        scalar_preaccounted: bool,
    ) -> Result<(), Error> {
        if !matches!(self.slots.get(index), Some(Inst::Unfilled)) {
            return Err(Error::InternalInvariant(
                "compiler attempted to replace a filled state",
            ));
        }
        let added_scalar_bytes = match &inst {
            Inst::ConsumeScalar { scalars, .. } => scalars.allocated_bytes()?,
            _ => 0,
        };
        if scalar_preaccounted != (self.budget.receipt_scope && added_scalar_bytes != 0) {
            return Err(Error::InternalInvariant(
                "compiler scalar fill accounting scope differs from owned storage",
            ));
        }
        let scalar_range_bytes = add(
            self.scalar_range_bytes,
            added_scalar_bytes,
            Resource::ProgramBytes,
        )?;
        self.enforce_program_shape(self.slots.len(), scalar_range_bytes)?;
        if !scalar_preaccounted {
            self.budget.acquire_construction_bytes(added_scalar_bytes)?;
        }
        self.slots[index] = inst;
        self.scalar_range_bytes = scalar_range_bytes;
        Ok(())
    }

    /// Check both persistent space and construction work before cloning a
    /// scalar range allocation into a progress-product state.
    fn preflight_progress_fill(&mut self, index: usize, source: &Inst) -> Result<(), Error> {
        if !matches!(self.slots.get(index), Some(Inst::Unfilled)) {
            return Err(Error::InternalInvariant(
                "compiler attempted to replace a filled state",
            ));
        }
        let added_scalar_bytes = match source {
            Inst::ConsumeScalar { scalars, .. } => scalars.allocated_bytes()?,
            _ => 0,
        };
        let scalar_range_bytes = add(
            self.scalar_range_bytes,
            added_scalar_bytes,
            Resource::ProgramBytes,
        )?;
        self.enforce_program_shape(self.slots.len(), scalar_range_bytes)?;
        if let Inst::ConsumeScalar { scalars, .. } = source {
            self.budget.charge(scalars.len())?;
            self.budget
                .preflight_receipt_construction_bytes(added_scalar_bytes)?;
        }
        Ok(())
    }

    fn preflight_scalar_set(&self, range_count: usize) -> Result<(), Error> {
        let allocation_bytes = ScalarSet::required_bytes(range_count)?;
        let states = add(self.slots.len(), 1, Resource::ProgramStates)?;
        let scalar_range_bytes = add(
            self.scalar_range_bytes,
            allocation_bytes,
            Resource::ProgramBytes,
        )?;
        self.enforce_program_shape(states, scalar_range_bytes)?;
        self.budget
            .preflight_receipt_construction_bytes(allocation_bytes)
    }

    fn finish(self) -> Result<ExactVec<Inst>, Error> {
        if self.budget.receipt_scope {
            self.budget.charge(self.slots.len())?;
        }
        if self.slots.iter().any(|inst| matches!(inst, Inst::Unfilled)) {
            return Err(Error::InternalInvariant("unfilled compiler state"));
        }
        let retained_state_bytes = mul(
            self.slots.len(),
            core::mem::size_of::<Inst>(),
            Resource::ProgramBytes,
        )?;
        let construction_state_bytes = mul(
            self.slots.capacity(),
            core::mem::size_of::<Inst>(),
            Resource::ProgramBytes,
        )?;
        if !self.budget.receipt_scope {
            self.budget.charge(self.slots.len())?;
        }
        if self.budget.receipt_scope {
            self.budget
                .preflight_receipt_construction_bytes(retained_state_bytes)?;
        } else {
            self.budget
                .acquire_construction_bytes(retained_state_bytes)?;
        }
        let retained = retain_exact_program_vec_metered(self.slots, self.budget)?;
        if self.budget.receipt_scope {
            self.budget
                .acquire_construction_bytes(retained_state_bytes)?;
        }
        self.budget
            .release_construction_bytes(construction_state_bytes)?;
        Ok(retained)
    }

    fn compile_node(
        &mut self,
        hir: &Hir,
        continuation: usize,
        depth: usize,
    ) -> Result<usize, Error> {
        enforce(depth, self.budget.limits.max_hir_depth, Resource::HirDepth)?;
        self.budget.charge(1)?;
        let child_depth = add(depth, 1, Resource::HirDepth)?;
        match hir.kind() {
            HirKind::Empty => Ok(continuation),
            HirKind::Literal(literal) => {
                let mut next = continuation;
                for &byte in literal.0.iter().rev() {
                    let mut bytes = ByteSet::empty();
                    bytes.insert(byte);
                    next = self.push(Inst::Consume { bytes, next })?;
                }
                Ok(next)
            }
            HirKind::Class(Class::Bytes(class)) => {
                let mut bytes = ByteSet::empty();
                for range in class.ranges() {
                    self.budget
                        .charge(inclusive_byte_width(range.start(), range.end())?)?;
                    bytes.insert_range(range.start(), range.end());
                }
                self.push(Inst::Consume {
                    bytes,
                    next: continuation,
                })
            }
            HirKind::Class(Class::Unicode(class)) => {
                self.compile_unicode_class(class, continuation)
            }
            HirKind::Look(look) => {
                let assertion = Assertion::from_look(*look);
                self.push(Inst::Assert {
                    assertion,
                    next: continuation,
                })
            }
            HirKind::Capture(capture) => match self.capture_policy {
                CapturePolicy::Reject => Err(Error::Unsupported(Unsupported::Capture)),
                CapturePolicy::EraseForWholeMatch => {
                    self.budget.record_capture_erasure(false)?;
                    self.compile_node(capture.sub.as_ref(), continuation, child_depth)
                }
            },
            HirKind::Concat(children) => {
                let mut next = continuation;
                for child in children.iter().rev() {
                    next = self.compile_node(child, next, child_depth)?;
                }
                Ok(next)
            }
            HirKind::Alternation(children) => {
                let Some((last, preceding)) = children.split_last() else {
                    return Err(Error::EmptyAlternation);
                };
                let mut fallback = self.compile_node(last, continuation, child_depth)?;
                for child in preceding.iter().rev() {
                    let preferred = self.compile_node(child, continuation, child_depth)?;
                    fallback = self.push(Inst::Split {
                        preferred,
                        fallback,
                    })?;
                }
                Ok(fallback)
            }
            HirKind::Repetition(repetition) => {
                self.compile_repetition(repetition, continuation, child_depth)
            }
        }
    }

    fn compile_ordered_root(
        &mut self,
        hir: &Hir,
        continuation: usize,
        depth: usize,
    ) -> Result<(usize, usize), Error> {
        enforce(depth, self.budget.limits.max_hir_depth, Resource::HirDepth)?;
        self.budget.charge(1)?;
        let child_depth = add(depth, 1, Resource::HirDepth)?;
        let HirKind::Alternation(children) = hir.kind() else {
            return Err(Error::Unsupported(Unsupported::OrderedRootCaptureManyShape));
        };
        let Some((last, preceding)) = children.split_last() else {
            return Err(Error::EmptyAlternation);
        };
        if preceding.is_empty() {
            return Err(Error::Unsupported(Unsupported::OrderedRootCaptureManyShape));
        }
        let mut fallback = self.compile_node(last, continuation, child_depth)?;
        for child in preceding.iter().rev() {
            let preferred = self.compile_node(child, continuation, child_depth)?;
            fallback = self.push(Inst::RootSplit {
                preferred,
                fallback,
            })?;
        }
        Ok((fallback, children.len()))
    }

    fn compile_candidate_root(
        &mut self,
        hir: &Hir,
        continuation: usize,
        entries: &mut [CandidateEntry],
    ) -> Result<usize, Error> {
        self.budget.charge(1)?;
        if entries.len() == 1 && !matches!(hir.kind(), HirKind::Alternation(_)) {
            let entry = self.compile_node(hir, continuation, 1)?;
            entries[0].pc = entry;
            return Ok(entry);
        }
        let HirKind::Alternation(branches) = hir.kind() else {
            return Err(Error::InternalInvariant(
                "candidate plan lost its direct-root shape",
            ));
        };
        if branches.len() != entries.len() || branches.is_empty() {
            return Err(Error::InternalInvariant(
                "candidate entry count differs from root alternatives",
            ));
        }
        let mut fallback = None;
        for index in (0..branches.len()).rev() {
            self.budget.charge(2)?; // branch visit and entry-PC publication
            let preferred = self.compile_node(&branches[index], continuation, 2)?;
            entries[index].pc = preferred;
            fallback = Some(match fallback {
                None => preferred,
                Some(fallback) => self.push(Inst::Split {
                    preferred,
                    fallback,
                })?,
            });
        }
        fallback.ok_or(Error::EmptyAlternation)
    }

    fn compile_unicode_class(
        &mut self,
        class: &regex_syntax::hir::ClassUnicode,
        continuation: usize,
    ) -> Result<usize, Error> {
        if self.profile.unicode {
            self.budget.charge(class.ranges().len())?;
            let mut next_by_width = [continuation; 4];
            let mut tail = continuation;
            let maximum_width = class
                .ranges()
                .last()
                .map_or(0, |range| range.end().len_utf8());
            let mut continuation_bytes = ByteSet::empty();
            if maximum_width > 1 {
                self.budget.charge(inclusive_byte_width(0x80, 0xBF)?)?;
                continuation_bytes.insert_range(0x80, 0xBF);
            }
            for slot in next_by_width.iter_mut().take(maximum_width).skip(1) {
                tail = self.push(Inst::Consume {
                    bytes: continuation_bytes,
                    next: tail,
                })?;
                *slot = tail;
            }
            self.preflight_scalar_set(class.ranges().len())?;
            let scalars = compiler_allocation(
                self.budget,
                !class.ranges().is_empty(),
                Resource::ProgramBytes,
                class.ranges().len(),
                || ScalarSet::from_unicode_class(class),
                ScalarSet::allocated_bytes,
            )?;
            let scalar_bytes = scalars.allocated_bytes()?;
            if self.budget.receipt_scope {
                self.budget.acquire_construction_bytes(scalar_bytes)?;
            }
            self.budget.record_initialization(scalar_bytes, false)?;
            let inst = Inst::ConsumeScalar {
                scalars,
                next_by_width,
            };
            return if self.budget.receipt_scope {
                self.push_preaccounted_scalar(inst)
            } else {
                self.push(inst)
            };
        }

        let mut entry = None;
        for range in class.ranges() {
            let start = u8::try_from(u32::from(range.start()))
                .map_err(|_| Error::Unsupported(Unsupported::UnicodeClass))?;
            let end = u8::try_from(u32::from(range.end()))
                .map_err(|_| Error::Unsupported(Unsupported::UnicodeClass))?;
            self.budget.charge(inclusive_byte_width(start, end)?)?;
            let mut bytes = ByteSet::empty();
            bytes.insert_range(start, end);
            let next = self.push(Inst::Consume {
                bytes,
                next: continuation,
            })?;
            entry = Some(match entry {
                None => next,
                Some(preferred) => self.push(Inst::Split {
                    preferred,
                    fallback: next,
                })?,
            });
        }
        entry.ok_or(Error::InternalInvariant("empty Unicode scalar class"))
    }

    fn compile_repetition(
        &mut self,
        repetition: &Repetition,
        continuation: usize,
        depth: usize,
    ) -> Result<usize, Error> {
        let Some(maximum) = repetition.max else {
            return self.compile_unbounded(
                repetition.sub.as_ref(),
                repetition.min,
                repetition.greedy,
                continuation,
                depth,
            );
        };
        let optional = maximum
            .checked_sub(repetition.min)
            .ok_or(Error::InvalidRepetition)?;
        let mut next = continuation;
        for _ in 0..optional {
            let child_entry = self.compile_node(repetition.sub.as_ref(), next, depth)?;
            let (preferred, fallback) = if repetition.greedy {
                (child_entry, next)
            } else {
                (next, child_entry)
            };
            next = self.push(Inst::Split {
                preferred,
                fallback,
            })?;
        }
        for _ in 0..repetition.min {
            next = self.compile_node(repetition.sub.as_ref(), next, depth)?;
        }
        Ok(next)
    }

    fn compile_unbounded(
        &mut self,
        child: &Hir,
        minimum: u32,
        greedy: bool,
        continuation: usize,
        depth: usize,
    ) -> Result<usize, Error> {
        // Rust's empty-loop guard distinguishes a repetition before and after
        // it has consumed. In the initial mode, a zero-width body exits. In
        // the progressed mode, a zero-width body path fails so lower-priority
        // consuming paths are tried before the loop exit. A single loop entry
        // gets `(?:b|(?:|a))*` on `ba` wrong.
        let fail = self.push(Inst::Fail)?;
        let initial_loop = self.push(Inst::Unfilled)?;
        let progressed_loop = self.push(Inst::Unfilled)?;
        let (fragment, fragment_entry) = {
            let mut fragment_builder = Builder::new(
                self.state_limit,
                self.profile,
                self.capture_policy,
                self.retained_program_bytes,
                self.budget,
            );
            let accept = fragment_builder.push(Inst::Match)?;
            let fragment_entry = fragment_builder.compile_node(child, accept, depth)?;
            (fragment_builder.finish()?, fragment_entry)
        };
        let fragment_len = fragment.len();
        let fragment_bytes = inst_vec_owned_bytes(&fragment)?;
        let initial_body =
            self.import_progress_product(&fragment, fragment_entry, continuation, progressed_loop)?;
        let progressed_body =
            self.import_progress_product(&fragment, fragment_entry, fail, progressed_loop)?;
        drop(fragment);
        self.budget.release_construction_bytes(fragment_bytes)?;
        self.budget.release_states(fragment_len)?;
        let (preferred, fallback) = if greedy {
            (initial_body, continuation)
        } else {
            (continuation, initial_body)
        };
        self.slots[initial_loop] = Inst::Split {
            preferred,
            fallback,
        };
        let (preferred, fallback) = if greedy {
            (progressed_body, continuation)
        } else {
            (continuation, progressed_body)
        };
        self.slots[progressed_loop] = Inst::Split {
            preferred,
            fallback,
        };
        if minimum == 0 {
            return Ok(initial_loop);
        }

        // Required iterations are finite, but their aggregate progress must
        // select the right mode for the open tail.
        let (required, required_entry) = {
            let mut fragment_builder = Builder::new(
                self.state_limit,
                self.profile,
                self.capture_policy,
                self.retained_program_bytes,
                self.budget,
            );
            let accept = fragment_builder.push(Inst::Match)?;
            let mut entry = accept;
            for _ in 0..minimum {
                entry = fragment_builder.compile_node(child, entry, depth)?;
            }
            (fragment_builder.finish()?, entry)
        };
        let required_len = required.len();
        let required_bytes = inst_vec_owned_bytes(&required)?;
        let entry =
            self.import_progress_product(&required, required_entry, initial_loop, progressed_loop)?;
        drop(required);
        self.budget.release_construction_bytes(required_bytes)?;
        self.budget.release_states(required_len)?;
        Ok(entry)
    }

    fn import_progress_product(
        &mut self,
        fragment: &[Inst],
        fragment_entry: usize,
        zero_continuation: usize,
        consumed_continuation: usize,
    ) -> Result<usize, Error> {
        let prospective_map_bytes = if self.budget.receipt_scope {
            let map_items = mul(2, fragment.len(), Resource::TemporaryStates)?;
            let bytes = mul(
                map_items,
                core::mem::size_of::<usize>(),
                Resource::ProgramBytes,
            )?;
            self.budget.preflight_receipt_construction_bytes(bytes)?;
            Some(bytes)
        } else {
            None
        };
        let mut zero_map =
            reserved_vec_metered(fragment.len(), Resource::TemporaryStates, self.budget)?;
        if self.budget.receipt_scope {
            self.budget
                .acquire_construction_bytes(vector_capacity_bytes(&zero_map)?)?;
        }
        let mut consumed_map =
            reserved_vec_metered(fragment.len(), Resource::TemporaryStates, self.budget)?;
        if self.budget.receipt_scope {
            self.budget
                .acquire_construction_bytes(vector_capacity_bytes(&consumed_map)?)?;
        }
        let map_bytes = add(
            mul(
                zero_map.capacity(),
                core::mem::size_of::<usize>(),
                Resource::ProgramBytes,
            )?,
            mul(
                consumed_map.capacity(),
                core::mem::size_of::<usize>(),
                Resource::ProgramBytes,
            )?,
            Resource::ProgramBytes,
        )?;
        if !self.budget.receipt_scope {
            self.budget.acquire_construction_bytes(map_bytes)?;
        } else if prospective_map_bytes != Some(map_bytes) {
            return Err(Error::InternalInvariant(
                "pinned progress-map capacity profile differs from exact reserve",
            ));
        }
        for inst in fragment {
            if matches!(inst, Inst::Match) {
                zero_map.push(zero_continuation);
                consumed_map.push(consumed_continuation);
            } else {
                zero_map.push(self.push(Inst::Unfilled)?);
                consumed_map.push(self.push(Inst::Unfilled)?);
            }
            self.budget.record_items::<usize>(2, false)?;
        }
        for (pc, inst) in fragment.iter().enumerate() {
            self.budget.charge(1)?;
            if matches!(inst, Inst::Match) {
                continue;
            }
            self.preflight_progress_fill(zero_map[pc], inst)?;
            let zero = translate_progress(inst, &zero_map, &consumed_map, false, self.budget)?;
            if self.budget.receipt_scope && matches!(&zero, Inst::ConsumeScalar { .. }) {
                self.fill_unfilled_preaccounted_scalar(zero_map[pc], zero)?;
            } else {
                self.fill_unfilled(zero_map[pc], zero)?;
            }
            self.preflight_progress_fill(consumed_map[pc], inst)?;
            let consumed = translate_progress(inst, &zero_map, &consumed_map, true, self.budget)?;
            if self.budget.receipt_scope && matches!(&consumed, Inst::ConsumeScalar { .. }) {
                self.fill_unfilled_preaccounted_scalar(consumed_map[pc], consumed)?;
            } else {
                self.fill_unfilled(consumed_map[pc], consumed)?;
            }
        }
        let entry = zero_map
            .get(fragment_entry)
            .copied()
            .ok_or(Error::InternalInvariant("fragment entry outside fragment"))?;
        drop(zero_map);
        drop(consumed_map);
        self.budget.release_construction_bytes(map_bytes)?;
        Ok(entry)
    }
}

fn translate_progress(
    inst: &Inst,
    zero: &[usize],
    consumed: &[usize],
    has_consumed: bool,
    budget: &mut CompileBudget,
) -> Result<Inst, Error> {
    let same = if has_consumed { consumed } else { zero };
    let mapped = |map: &[usize], pc: usize| {
        map.get(pc)
            .copied()
            .ok_or(Error::InternalInvariant("fragment target outside fragment"))
    };
    match inst {
        Inst::Unfilled => Err(Error::InternalInvariant("unfilled fragment state")),
        Inst::Fail => Ok(Inst::Fail),
        Inst::Match => Err(Error::InternalInvariant("translated fragment match")),
        Inst::Consume { bytes, next } => Ok(Inst::Consume {
            bytes: *bytes,
            next: mapped(consumed, *next)?,
        }),
        Inst::ConsumeScalar {
            scalars,
            next_by_width,
        } => {
            let mut translated = [0_usize; 4];
            for (destination, source) in translated.iter_mut().zip(next_by_width) {
                *destination = mapped(consumed, *source)?;
            }
            let scalars = compiler_allocation(
                budget,
                scalars.len() > 0,
                Resource::ProgramBytes,
                scalars.len(),
                || scalars.try_clone(),
                ScalarSet::allocated_bytes,
            )?;
            if budget.receipt_scope {
                budget.acquire_construction_bytes(scalars.allocated_bytes()?)?;
            }
            budget.record_initialization(scalars.allocated_bytes()?, true)?;
            Ok(Inst::ConsumeScalar {
                scalars,
                next_by_width: translated,
            })
        }
        Inst::Assert { assertion, next } => Ok(Inst::Assert {
            assertion: *assertion,
            next: mapped(same, *next)?,
        }),
        Inst::Split {
            preferred,
            fallback,
        } => Ok(Inst::Split {
            preferred: mapped(same, *preferred)?,
            fallback: mapped(same, *fallback)?,
        }),
        Inst::RootSplit {
            preferred,
            fallback,
        } => Ok(Inst::RootSplit {
            preferred: mapped(same, *preferred)?,
            fallback: mapped(same, *fallback)?,
        }),
    }
}

struct ProgramCertificate {
    epsilon_order: ExactVec<usize>,
    split_rank: ExactVec<usize>,
    split_count: usize,
    root_split_count: usize,
    execution_state_work: usize,
    predecessor_edges: usize,
    has_scalar_transition: bool,
    has_assertion: bool,
    max_scalar_search_checks: usize,
}

struct EpsilonParentIndex {
    outgoing: ExactVec<usize>,
    offsets: Vec<usize>,
    parents: Vec<usize>,
    scratch_bytes: usize,
}

fn certify_program(
    insts: &[Inst],
    scalar_range_bytes: usize,
    retained_program_bytes: usize,
    budget: &mut CompileBudget,
) -> Result<ProgramCertificate, Error> {
    let states = insts.len();
    preflight_certification_program_bytes(
        states,
        states,
        scalar_range_bytes,
        retained_program_bytes,
        budget.limits.max_program_bytes,
    )?;
    certify_program_admitted(insts, budget)
}

#[allow(
    clippy::too_many_lines,
    reason = "one transaction keeps exact parent-index allocation, initialization and release adjacent"
)]
fn build_epsilon_parent_index(
    insts: &[Inst],
    budget: &mut CompileBudget,
) -> Result<EpsilonParentIndex, Error> {
    let states = insts.len();
    let receipt_state_vector_bytes = if budget.receipt_scope {
        let bytes = mul(
            states,
            core::mem::size_of::<usize>(),
            Resource::ProgramBytes,
        )?;
        budget.preflight_receipt_construction_bytes(mul(2, bytes, Resource::ProgramBytes)?)?;
        Some(bytes)
    } else {
        None
    };
    let mut outgoing = zeroed_exact_program_vec_metered(states, budget)?;
    if budget.receipt_scope {
        budget.acquire_construction_bytes(exact_vector_bytes(&outgoing)?)?;
    }
    let mut parent_counts = zeroed_vec_metered(states, Resource::TemporaryStates, budget)?;
    if budget.receipt_scope {
        budget.acquire_construction_bytes(vector_capacity_bytes(&parent_counts)?)?;
    }
    let outgoing_bytes = exact_vector_bytes(&outgoing)?;
    let parent_counts_bytes = vector_capacity_bytes(&parent_counts)?;
    if !budget.receipt_scope {
        budget.acquire_construction_bytes(add(
            outgoing_bytes,
            parent_counts_bytes,
            Resource::ProgramBytes,
        )?)?;
    } else if receipt_state_vector_bytes != Some(outgoing_bytes)
        || receipt_state_vector_bytes != Some(parent_counts_bytes)
    {
        return Err(Error::InternalInvariant(
            "pinned certification state-vector capacity differs from exact reserve",
        ));
    }
    let mut edge_count = 0_usize;
    for (parent, inst) in insts.iter().enumerate() {
        for child in epsilon_targets(inst) {
            budget.charge(1)?;
            if child >= states {
                return Err(Error::InternalInvariant("epsilon target outside program"));
            }
            outgoing[parent] = add(outgoing[parent], 1, Resource::TemporaryStates)?;
            parent_counts[child] = add(parent_counts[child], 1, Resource::TemporaryStates)?;
            edge_count = add(edge_count, 1, Resource::TemporaryStates)?;
        }
    }
    let offset_items = add(states, 1, Resource::TemporaryStates)?;
    if budget.receipt_scope {
        budget.preflight_receipt_construction_bytes(mul(
            offset_items,
            core::mem::size_of::<usize>(),
            Resource::ProgramBytes,
        )?)?;
    }
    let mut offsets = zeroed_vec_metered(offset_items, Resource::TemporaryStates, budget)?;
    let offsets_bytes = vector_capacity_bytes(&offsets)?;
    budget.acquire_construction_bytes(offsets_bytes)?;
    for index in 0..states {
        let next_index = add(index, 1, Resource::TemporaryStates)?;
        offsets[next_index] = add(
            offsets[index],
            parent_counts[index],
            Resource::TemporaryStates,
        )?;
    }
    // Parent cardinalities are dead once their prefix offsets are frozen.
    // Reuse that exact allocation for the per-child insertion cursors.
    let mut cursor = parent_counts;
    cursor.copy_from_slice(&offsets[..states]);
    budget.record_copy(mul(
        states,
        core::mem::size_of::<usize>(),
        Resource::ProgramBytes,
    )?)?;
    if budget.receipt_scope {
        budget.preflight_receipt_construction_bytes(mul(
            edge_count,
            core::mem::size_of::<usize>(),
            Resource::ProgramBytes,
        )?)?;
    }
    let mut parents = zeroed_vec_metered(edge_count, Resource::TemporaryStates, budget)?;
    let parents_bytes = vector_capacity_bytes(&parents)?;
    budget.acquire_construction_bytes(parents_bytes)?;
    for (parent, inst) in insts.iter().enumerate() {
        for child in epsilon_targets(inst) {
            if budget.receipt_scope {
                budget.charge(1)?;
            }
            let slot = cursor[child];
            parents[slot] = parent;
            cursor[child] = add(cursor[child], 1, Resource::TemporaryStates)?;
            if !budget.receipt_scope {
                budget.charge(1)?;
            }
        }
    }
    drop(cursor);
    budget.release_construction_bytes(parent_counts_bytes)?;
    Ok(EpsilonParentIndex {
        outgoing,
        offsets,
        parents,
        scratch_bytes: add(offsets_bytes, parents_bytes, Resource::ProgramBytes)?,
    })
}

fn certify_program_admitted(
    insts: &[Inst],
    budget: &mut CompileBudget,
) -> Result<ProgramCertificate, Error> {
    let states = insts.len();
    let EpsilonParentIndex {
        mut outgoing,
        offsets,
        parents,
        scratch_bytes,
    } = build_epsilon_parent_index(insts, budget)?;
    let receipt_queue_capacity = if budget.receipt_scope {
        let capacity = pinned_vec_capacity_after_push(0, states, core::mem::size_of::<usize>())
            .ok_or(Error::ArithmeticOverflow {
                resource: Resource::ProgramBytes,
            })?;
        budget.preflight_receipt_construction_bytes(mul(
            capacity,
            core::mem::size_of::<usize>(),
            Resource::ProgramBytes,
        )?)?;
        Some(capacity)
    } else {
        None
    };
    let mut queue = reserved_queue_metered(states, budget)?;
    let queue_bytes = mul(
        queue.capacity(),
        core::mem::size_of::<usize>(),
        Resource::ProgramBytes,
    )?;
    if receipt_queue_capacity.is_some_and(|capacity| queue.capacity() != capacity) {
        return Err(Error::InternalInvariant(
            "pinned certification queue capacity profile differs from VecDeque",
        ));
    }
    budget.acquire_construction_bytes(queue_bytes)?;
    for (state, count) in outgoing.iter().enumerate() {
        if *count == 0 {
            queue.push_back(state);
            budget.record_items::<usize>(1, false)?;
        }
    }
    if budget.receipt_scope {
        budget.preflight_receipt_construction_bytes(mul(
            states,
            core::mem::size_of::<usize>(),
            Resource::ProgramBytes,
        )?)?;
    }
    let mut order = exact_program_vec_metered(states, budget)?;
    let order_bytes = exact_vector_bytes(&order)?;
    budget.acquire_construction_bytes(order_bytes)?;
    while let Some(child) = queue.pop_front() {
        order.try_push(child).map_err(|_| {
            Error::InternalInvariant("certificate order exceeded exact state allocation")
        })?;
        budget.record_items::<usize>(1, false)?;
        let next_child = add(child, 1, Resource::TemporaryStates)?;
        for &parent in &parents[offsets[child]..offsets[next_child]] {
            budget.charge(1)?;
            outgoing[parent] = outgoing[parent]
                .checked_sub(1)
                .ok_or(Error::SameBoundaryCycle)?;
            if outgoing[parent] == 0 {
                queue.push_back(parent);
                budget.record_items::<usize>(1, false)?;
            }
        }
    }
    if order.len() != states {
        return Err(Error::SameBoundaryCycle);
    }
    // A successful topological drain leaves every outgoing count dead. Reuse
    // the exact state-width allocation as the persistent split-rank table.
    let mut split_rank = outgoing;
    let metadata = certify_execution_metadata(&mut split_rank, insts, budget)?;
    drop(offsets);
    drop(parents);
    drop(queue);
    budget.release_construction_bytes(add(scratch_bytes, queue_bytes, Resource::ProgramBytes)?)?;
    Ok(ProgramCertificate {
        epsilon_order: order,
        split_rank,
        split_count: metadata.split_count,
        root_split_count: metadata.root_split_count,
        execution_state_work: metadata.state_work,
        predecessor_edges: metadata.predecessor_edges,
        has_scalar_transition: metadata.has_scalar_transition,
        has_assertion: metadata.has_assertion,
        max_scalar_search_checks: metadata.max_scalar_search_checks,
    })
}

fn preflight_certification_program_bytes(
    retained_state_count: usize,
    states: usize,
    scalar_range_bytes: usize,
    retained_program_bytes: usize,
    limit: usize,
) -> Result<usize, Error> {
    let state_bytes = mul(
        retained_state_count,
        core::mem::size_of::<Inst>(),
        Resource::ProgramBytes,
    )?;
    let certificate_items = mul(2, states, Resource::ProgramBytes)?;
    let certificate_bytes = mul(
        certificate_items,
        core::mem::size_of::<usize>(),
        Resource::ProgramBytes,
    )?;
    let required = add(
        add(state_bytes, scalar_range_bytes, Resource::ProgramBytes)?,
        add(
            certificate_bytes,
            retained_program_bytes,
            Resource::ProgramBytes,
        )?,
        Resource::ProgramBytes,
    )?;
    enforce(required, limit, Resource::ProgramBytes)?;
    Ok(required)
}

struct ExecutionMetadata {
    split_count: usize,
    root_split_count: usize,
    state_work: usize,
    predecessor_edges: usize,
    has_scalar_transition: bool,
    has_assertion: bool,
    max_scalar_search_checks: usize,
}

fn certify_execution_metadata(
    split_rank: &mut [usize],
    insts: &[Inst],
    budget: &mut CompileBudget,
) -> Result<ExecutionMetadata, Error> {
    let mut metadata = ExecutionMetadata {
        split_count: 0,
        root_split_count: 0,
        state_work: 0,
        predecessor_edges: 0,
        has_scalar_transition: false,
        has_assertion: false,
        max_scalar_search_checks: 0,
    };
    for (rank, inst) in split_rank.iter_mut().zip(insts) {
        budget.charge(1)?;
        if matches!(inst, Inst::Split { .. } | Inst::RootSplit { .. }) {
            *rank = metadata.split_count;
            metadata.split_count = add(metadata.split_count, 1, Resource::ProgramStates)?;
        } else {
            *rank = NO_SPLIT_RANK;
        }
        if matches!(inst, Inst::RootSplit { .. }) {
            metadata.root_split_count = add(metadata.root_split_count, 1, Resource::ProgramStates)?;
        }
        metadata.has_assertion |= matches!(inst, Inst::Assert { .. });
        let transitions = execution_transitions(
            inst,
            &mut metadata.has_scalar_transition,
            &mut metadata.max_scalar_search_checks,
        )?;
        metadata.state_work = add(
            add(metadata.state_work, 1, Resource::ExecutionWork)?,
            transitions,
            Resource::ExecutionWork,
        )?;
        metadata.predecessor_edges = add(
            metadata.predecessor_edges,
            predecessor_edge_count(inst),
            Resource::ProgramStates,
        )?;
    }
    Ok(metadata)
}

const fn predecessor_edge_count(inst: &Inst) -> usize {
    match inst {
        Inst::Unfilled | Inst::Fail | Inst::Match => 0,
        Inst::Consume { .. } | Inst::Assert { .. } => 1,
        Inst::Split { .. } | Inst::RootSplit { .. } => 2,
        Inst::ConsumeScalar { .. } => 4,
    }
}

fn execution_transitions(
    inst: &Inst,
    has_scalar_transition: &mut bool,
    max_scalar_search_checks: &mut usize,
) -> Result<usize, Error> {
    match inst {
        Inst::Unfilled => Err(Error::InternalInvariant("unfilled execution state")),
        Inst::Fail | Inst::Match => Ok(0),
        Inst::Consume { .. } | Inst::Assert { .. } => Ok(1),
        Inst::ConsumeScalar { scalars, .. } => {
            *has_scalar_transition = true;
            let checks = scalars.max_search_checks();
            *max_scalar_search_checks = (*max_scalar_search_checks).max(checks);
            add(1, checks, Resource::ExecutionWork)
        }
        Inst::Split { .. } | Inst::RootSplit { .. } => Ok(2),
    }
}

fn epsilon_targets(inst: &Inst) -> impl Iterator<Item = usize> {
    let targets = match inst {
        Inst::Assert { next, .. } => [Some(*next), None],
        Inst::Split {
            preferred,
            fallback,
        }
        | Inst::RootSplit {
            preferred,
            fallback,
        } => [Some(*preferred), Some(*fallback)],
        Inst::Unfilled
        | Inst::Fail
        | Inst::Match
        | Inst::Consume { .. }
        | Inst::ConsumeScalar { .. } => [None, None],
    };
    targets.into_iter().flatten()
}

fn program_bytes(
    insts: &[Inst],
    retained_inst_count: usize,
    retained_order_count: usize,
    retained_rank_count: usize,
) -> Result<usize, Error> {
    let state_bytes = mul(
        retained_inst_count,
        core::mem::size_of::<Inst>(),
        Resource::ProgramBytes,
    )?;
    let scalar_bytes = insts.iter().try_fold(0_usize, |total, inst| {
        let bytes = match inst {
            Inst::ConsumeScalar { scalars, .. } => scalars.allocated_bytes()?,
            _ => 0,
        };
        add(total, bytes, Resource::ProgramBytes)
    })?;
    let insts = add(state_bytes, scalar_bytes, Resource::ProgramBytes)?;
    let order = mul(
        retained_order_count,
        core::mem::size_of::<usize>(),
        Resource::ProgramBytes,
    )?;
    let ranks = mul(
        retained_rank_count,
        core::mem::size_of::<usize>(),
        Resource::ProgramBytes,
    )?;
    add(
        add(insts, order, Resource::ProgramBytes)?,
        ranks,
        Resource::ProgramBytes,
    )
}

fn inst_vec_owned_bytes(insts: &[Inst]) -> Result<usize, Error> {
    let state_bytes = mul(
        insts.len(),
        core::mem::size_of::<Inst>(),
        Resource::ProgramBytes,
    )?;
    insts.iter().try_fold(state_bytes, |total, inst| {
        let scalar_bytes = match inst {
            Inst::ConsumeScalar { scalars, .. } => scalars.allocated_bytes()?,
            _ => 0,
        };
        add(total, scalar_bytes, Resource::ProgramBytes)
    })
}

fn finalize_program(
    program: &mut Program,
    profile: RustByteProfile,
    terminal_frontier: TerminalFrontierSeed,
    budget: &mut CompileBudget,
) -> Result<PlanId, Error> {
    let mut first = StableHash::new(0xcbf2_9ce4_8422_2325);
    let mut second = StableHash::new(0x8422_2325_cbf2_9ce4);
    first.bytes(profile.identity_domain());
    second.bytes(profile.identity_domain());
    if !terminal_frontier.is_empty() {
        let identity_payload = add(
            add(
                b"terminal-class-frontier-v1".len(),
                mul(2, core::mem::size_of::<u64>(), Resource::CompileWork)?,
                Resource::CompileWork,
            )?,
            add(
                terminal_frontier.prefix_len,
                terminal_frontier.terminals.len,
                Resource::CompileWork,
            )?,
            Resource::CompileWork,
        )?;
        let identity_work = add(
            mul(2, identity_payload, Resource::CompileWork)?,
            1,
            Resource::CompileWork,
        )?;
        budget.charge(identity_work)?;
        first.bytes(b"terminal-class-frontier-v1");
        second.bytes(b"terminal-class-frontier-v1");
        hash_usize(&mut first, terminal_frontier.prefix_len);
        hash_usize(&mut second, terminal_frontier.prefix_len);
        first.bytes(terminal_frontier.prefix_bytes());
        second.bytes(terminal_frontier.prefix_bytes());
        hash_usize(&mut first, terminal_frontier.terminals.len);
        hash_usize(&mut second, terminal_frontier.terminals.len);
        for terminal in terminal_frontier.terminals.iter() {
            first.byte(terminal);
            second.byte(terminal);
        }
    }
    hash_usize(&mut first, program.entry);
    hash_usize(&mut second, program.entry);
    let mut has_unicode_word_boundary = false;
    for inst in &program.insts {
        // This one per-instruction identity unit includes both stable hashing
        // and the immutable assertion-property classification. Classification
        // is not a second traversal or a separate uncharged unit.
        budget.charge(1)?;
        budget.accounting.unicode_word_boundary_checks = add(
            budget.accounting.unicode_word_boundary_checks,
            1,
            Resource::CompileWork,
        )?;
        has_unicode_word_boundary |= matches!(
            inst,
            Inst::Assert { assertion, .. } if assertion.is_unicode_word()
        );
        if let Inst::ConsumeScalar { scalars, .. } = inst {
            budget.charge(scalars.len())?;
        }
        hash_inst(&mut first, inst);
        hash_inst(&mut second, inst);
    }
    program.has_unicode_word_boundary = has_unicode_word_boundary;
    budget.accounting.requires_utf8_validation = has_unicode_word_boundary;
    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(&first.finish().to_le_bytes());
    bytes[8..].copy_from_slice(&second.finish().to_le_bytes());
    Ok(PlanId(bytes))
}

fn bind_start_domain_identity(
    program: PlanId,
    start_domain: StartDomain,
    budget: &mut CompileBudget,
) -> Result<PlanId, Error> {
    let domain = b"fre.aggregate.start-domain.v1";
    let payload = add(
        add(program.0.len(), domain.len(), Resource::CompileWork)?,
        1,
        Resource::CompileWork,
    )?;
    budget.charge(mul(2, payload, Resource::CompileWork)?)?;
    let mut first = StableHash::new(0x2f93_70dc_5b18_64a1);
    let mut second = StableHash::new(0xb248_6d3a_f165_09ce);
    first.bytes(domain);
    second.bytes(domain);
    first.bytes(&program.0);
    second.bytes(&program.0);
    first.byte(start_domain.identity_tag());
    second.byte(start_domain.identity_tag());
    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(&first.finish().to_le_bytes());
    bytes[8..].copy_from_slice(&second.finish().to_le_bytes());
    Ok(PlanId(bytes))
}

fn bind_required_literal_identity(
    program: PlanId,
    proof: RequiredLiteralSets,
    budget: &mut CompileBudget,
) -> Result<PlanId, Error> {
    if proof.is_empty() {
        return Ok(program);
    }
    let domain = b"fre.aggregate.required-literal-sets.v1";
    let payload = add(
        add(program.0.len(), domain.len(), Resource::CompileWork)?,
        add(
            1,
            mul(
                proof.len(),
                core::mem::size_of::<u128>(),
                Resource::CompileWork,
            )?,
            Resource::CompileWork,
        )?,
        Resource::CompileWork,
    )?;
    budget.charge(mul(2, payload, Resource::CompileWork)?)?;
    let mut first = StableHash::new(0xf194_6c72_a083_5deb);
    let mut second = StableHash::new(0x3ad8_b501_7e6c_942f);
    for hash in [&mut first, &mut second] {
        hash.bytes(domain);
        hash.bytes(&program.0);
        hash.byte(proof.len);
        for set in proof.iter() {
            hash.bytes(&set.to_le_bytes());
        }
    }
    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(&first.finish().to_le_bytes());
    bytes[8..].copy_from_slice(&second.finish().to_le_bytes());
    Ok(PlanId(bytes))
}

#[allow(
    clippy::too_many_lines,
    reason = "identity binding enumerates every resource-bearing candidate field explicitly"
)]
fn bind_candidate_identity(
    program: PlanId,
    plan: &candidate::Plan,
    budget: &mut CompileBudget,
) -> Result<PlanId, Error> {
    let domain = if plan.fixed_continuation().is_some() {
        b"fre.aggregate.candidate-intervals.v2".as_slice()
    } else {
        b"fre.aggregate.candidate-intervals.v1".as_slice()
    };
    let check_payload = mul(
        candidate::MAX_FILTER_CHECKS,
        add(
            1,
            mul(4, core::mem::size_of::<u64>(), Resource::CompileWork)?,
            Resource::CompileWork,
        )?,
        Resource::CompileWork,
    )?;
    let scheduled_entry_payload = add(
        add(
            mul(4, core::mem::size_of::<u64>(), Resource::CompileWork)?,
            check_payload,
            Resource::CompileWork,
        )?,
        2,
        Resource::CompileWork,
    )?;
    let one_entry_payload = add(
        scheduled_entry_payload,
        add(
            core::mem::size_of::<u64>(),
            check_payload,
            Resource::CompileWork,
        )?,
        Resource::CompileWork,
    )?;
    let entry_payload = mul(plan.entries.len(), one_entry_payload, Resource::CompileWork)?;
    let bucket_payload = mul(
        add(
            plan.buckets.len(),
            plan.global_buckets.len(),
            Resource::CompileWork,
        )?,
        core::mem::size_of::<u128>(),
        Resource::CompileWork,
    )?;
    let fixed_payload = if let Some(fixed) = plan.fixed_continuation() {
        let token_payload = add(
            2,
            add(
                candidate::MAX_FIXED_CONTINUATION_TOKEN_BYTES,
                mul(4, core::mem::size_of::<u64>(), Resource::CompileWork)?,
                Resource::CompileWork,
            )?,
            Resource::CompileWork,
        )?;
        let tokens = add(
            fixed.tokens.len(),
            fixed.leading_tokens.len(),
            Resource::CompileWork,
        )?;
        add(
            add(
                mul(tokens, token_payload, Resource::CompileWork)?,
                mul(4, core::mem::size_of::<u64>(), Resource::CompileWork)?,
                Resource::CompileWork,
            )?,
            add(
                4,
                mul(6, core::mem::size_of::<u64>(), Resource::CompileWork)?,
                Resource::CompileWork,
            )?,
            Resource::CompileWork,
        )?
    } else {
        0
    };
    let payload = add(
        add(program.0.len(), domain.len(), Resource::CompileWork)?,
        add(
            add(
                add(entry_payload, bucket_payload, Resource::CompileWork)?,
                core::mem::size_of::<u64>(),
                Resource::CompileWork,
            )?,
            fixed_payload,
            Resource::CompileWork,
        )?,
        Resource::CompileWork,
    )?;
    budget.charge(mul(2, payload, Resource::CompileWork)?)?;
    let mut first = StableHash::new(0x4d0a_7309_d0f3_4521);
    let mut second = StableHash::new(0x9b76_18c2_2a41_e70d);
    first.bytes(domain);
    second.bytes(domain);
    first.bytes(&program.0);
    second.bytes(&program.0);
    hash_usize(&mut first, plan.max_offset());
    hash_usize(&mut second, plan.max_offset());
    for entry in &*plan.entries {
        hash_usize(&mut first, entry.pc);
        hash_usize(&mut second, entry.pc);
        hash_usize(&mut first, entry.min_offset);
        hash_usize(&mut second, entry.min_offset);
        hash_usize(&mut first, entry.max_offset);
        hash_usize(&mut second, entry.max_offset);
        hash_usize(&mut first, entry.check_len);
        hash_usize(&mut second, entry.check_len);
        for check in entry.checks {
            first.byte(check.relative.cast_unsigned());
            second.byte(check.relative.cast_unsigned());
            for word in check.bytes.0 {
                first.bytes(&word.to_le_bytes());
                second.bytes(&word.to_le_bytes());
            }
        }
        let (present, assertion) = entry
            .leading_assertion
            .map_or((0_u8, 0_u8), |assertion| (1, assertion.identity_tag()));
        first.byte(present);
        second.byte(present);
        first.byte(assertion);
        second.byte(assertion);
        hash_usize(&mut first, entry.global_check_len);
        hash_usize(&mut second, entry.global_check_len);
        for check in entry.global_checks {
            first.byte(check.relative.cast_unsigned());
            second.byte(check.relative.cast_unsigned());
            for word in check.bytes.0 {
                first.bytes(&word.to_le_bytes());
                second.bytes(&word.to_le_bytes());
            }
        }
    }
    for &bucket in &*plan.buckets {
        first.bytes(&bucket.to_le_bytes());
        second.bytes(&bucket.to_le_bytes());
    }
    for &bucket in &*plan.global_buckets {
        first.bytes(&bucket.to_le_bytes());
        second.bytes(&bucket.to_le_bytes());
    }
    if let Some(fixed) = plan.fixed_continuation() {
        for hash in [&mut first, &mut second] {
            hash.byte(1);
            for word in fixed.body.0 {
                hash.bytes(&word.to_le_bytes());
            }
            hash.byte(fixed.anchor);
            hash.byte(fixed.close);
            hash.byte(fixed.semicolon);
            hash_usize(hash, fixed.tokens.len());
            hash_usize(hash, fixed.leading_tokens.len());
            hash_usize(hash, fixed.comparison_work);
            hash_usize(hash, fixed.comparison_bytes);
            hash_usize(hash, fixed.leading_comparison_work);
            hash_usize(hash, fixed.leading_comparison_bytes);
            for &token in fixed.tokens.iter().chain(fixed.leading_tokens.iter()) {
                hash_fixed_continuation_token(hash, token);
            }
        }
    }
    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(&first.finish().to_le_bytes());
    bytes[8..].copy_from_slice(&second.finish().to_le_bytes());
    Ok(PlanId(bytes))
}

fn hash_fixed_continuation_token(hash: &mut StableHash, token: candidate::FixedContinuationToken) {
    match token {
        candidate::FixedContinuationToken::Literal { bytes, len } => {
            hash.byte(1);
            hash.byte(len);
            hash.bytes(&bytes);
            for _ in 0..4 {
                hash.bytes(&0_u64.to_le_bytes());
            }
        }
        candidate::FixedContinuationToken::Class(bytes) => {
            hash.byte(2);
            hash.byte(0);
            hash.bytes(&[0; candidate::MAX_FIXED_CONTINUATION_TOKEN_BYTES]);
            for word in bytes.0 {
                hash.bytes(&word.to_le_bytes());
            }
        }
    }
}

fn bind_required_internal_anchor_identity(
    program: PlanId,
    plan: &fre_kernels::RequiredInternalAnchorPlan,
    budget: &mut CompileBudget,
) -> Result<PlanId, Error> {
    let domain = fre_kernels::REQUIRED_INTERNAL_ANCHOR_PLAN_ID.as_bytes();
    let operation = fre_kernels::REQUIRED_INTERNAL_ANCHOR_COUNT_OPERATION_ID.as_bytes();
    let class_bytes = mul(4, core::mem::size_of::<u64>(), Resource::CompileWork)?;
    let class_identity_bytes = mul(7, class_bytes, Resource::CompileWork)?;
    let optional_identity_bytes = mul(
        fre_kernels::REQUIRED_INTERNAL_ANCHOR_MAX_OPTIONAL_STAGES,
        2,
        Resource::CompileWork,
    )?;
    let configuration_identity_bytes = add(
        add(
            class_identity_bytes,
            optional_identity_bytes,
            Resource::CompileWork,
        )?,
        add(1, core::mem::size_of::<u64>(), Resource::CompileWork)?,
        Resource::CompileWork,
    )?;
    budget.charge(add(
        add(
            add(program.0.len(), domain.len(), Resource::CompileWork)?,
            add(operation.len(), plan.anchor().len(), Resource::CompileWork)?,
            Resource::CompileWork,
        )?,
        configuration_identity_bytes,
        Resource::CompileWork,
    )?)?;
    let continuation = plan.continuation();
    let mut first = StableHash::new(0xa87c_19e2_d4b5_6301);
    let mut second = StableHash::new(0x6301_d4b5_19e2_a87c);
    for hash in [&mut first, &mut second] {
        hash.bytes(&program.0);
        hash.bytes(domain);
        hash.bytes(operation);
        hash_usize(hash, plan.anchor().len());
        hash.bytes(plan.anchor());
        for word in plan.prefix().words() {
            hash.bytes(&word.to_le_bytes());
        }
        for word in continuation.head.words() {
            hash.bytes(&word.to_le_bytes());
        }
        for word in continuation.tail.words() {
            hash.bytes(&word.to_le_bytes());
        }
        hash.byte(continuation.optional_count);
        for stage in continuation.optional {
            if let Some(stage) = stage {
                hash.byte(1);
                hash.byte(stage.introducer);
                for word in stage.class.words() {
                    hash.bytes(&word.to_le_bytes());
                }
            } else {
                hash.byte(0);
            }
        }
    }
    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(&first.finish().to_le_bytes());
    bytes[8..].copy_from_slice(&second.finish().to_le_bytes());
    Ok(PlanId(bytes))
}

fn bind_url_aggregate_identity(
    program: PlanId,
    plan: &fre_kernels::UrlAggregatePlan,
    budget: &mut CompileBudget,
) -> Result<PlanId, Error> {
    let domain = fre_kernels::URL_AGGREGATE_PLAN_ID.as_bytes();
    let operation = fre_kernels::URL_AGGREGATE_SPAN_SUM_OPERATION_ID.as_bytes();
    let accounting = plan.build_accounting();
    let fields = [
        accounting.tlds,
        accounting.tld_bytes,
        accounting.states_upper_bound,
        accounting.states,
        accounting.table_cells,
        accounting.initialized_cells,
        accounting.priority_comparisons,
        accounting.trie_transitions,
        accounting.work,
        accounting.persistent_bytes,
        accounting.scratch_bytes,
        accounting.peak_bytes,
    ];
    let payload = add(
        add(program.0.len(), domain.len(), Resource::CompileWork)?,
        add(
            operation.len(),
            mul(
                fields.len(),
                core::mem::size_of::<u64>(),
                Resource::CompileWork,
            )?,
            Resource::CompileWork,
        )?,
        Resource::CompileWork,
    )?;
    budget.charge(mul(2, payload, Resource::CompileWork)?)?;
    let mut first = StableHash::new(0xd7b9_0f23_6a15_4ce1);
    let mut second = StableHash::new(0x4ce1_6a15_0f23_d7b9);
    for hash in [&mut first, &mut second] {
        hash.bytes(&program.0);
        hash.bytes(domain);
        hash.bytes(operation);
        for field in fields {
            hash_usize(hash, field);
        }
    }
    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(&first.finish().to_le_bytes());
    bytes[8..].copy_from_slice(&second.finish().to_le_bytes());
    Ok(PlanId(bytes))
}

fn bind_state_byte_span_sum_identity(
    program: PlanId,
    plan: &StateByteSpanSumPlan,
    budget: &mut CompileBudget,
) -> Result<PlanId, Error> {
    let domain = b"fre.aggregate.state-byte-span-sum-plan.v2";
    let operation = b"fre.aggregate.state-byte-span-sum-operation.v2";
    let class_bytes = mul(8, core::mem::size_of::<u64>(), Resource::CompileWork)?;
    let payload = add(
        add(
            add(program.0.len(), domain.len(), Resource::CompileWork)?,
            operation.len(),
            Resource::CompileWork,
        )?,
        add(
            add(
                class_bytes,
                add(
                    plan.literal().len(),
                    plan.literal_failure().len(),
                    Resource::CompileWork,
                )?,
                Resource::CompileWork,
            )?,
            add(1, core::mem::size_of::<usize>(), Resource::CompileWork)?,
            Resource::CompileWork,
        )?,
        Resource::CompileWork,
    )?;
    budget.charge(mul(2, payload, Resource::CompileWork)?)?;
    let mut first = StableHash::new(0x91f7_2a64_c38d_05be);
    let mut second = StableHash::new(0x05be_c38d_2a64_91f7);
    for hash in [&mut first, &mut second] {
        hash.bytes(&program.0);
        hash.bytes(domain);
        hash.bytes(operation);
        hash.byte(plan.topology_tag());
        for word in plan.first.0 {
            hash.bytes(&word.to_le_bytes());
        }
        for word in plan.second.0 {
            hash.bytes(&word.to_le_bytes());
        }
        hash_usize(hash, plan.literal().len());
        hash.bytes(plan.literal());
        hash.bytes(plan.literal_failure());
    }
    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(&first.finish().to_le_bytes());
    bytes[8..].copy_from_slice(&second.finish().to_le_bytes());
    Ok(PlanId(bytes))
}

fn hash_inst(hash: &mut StableHash, inst: &Inst) {
    match inst {
        Inst::Unfilled => hash.byte(0),
        Inst::Fail => hash.byte(1),
        Inst::Match => hash.byte(2),
        Inst::Consume { bytes, next } => {
            hash.byte(3);
            for word in bytes.0 {
                hash.bytes(&word.to_le_bytes());
            }
            hash_usize(hash, *next);
        }
        Inst::ConsumeScalar {
            scalars,
            next_by_width,
        } => {
            hash.byte(6);
            hash_usize(hash, scalars.len());
            for (start, end) in scalars.ranges() {
                hash.bytes(&start.to_le_bytes());
                hash.bytes(&end.to_le_bytes());
            }
            for next in next_by_width {
                hash_usize(hash, *next);
            }
        }
        Inst::Assert { assertion, next } => {
            hash.byte(4);
            hash.byte(assertion.identity_tag());
            hash_usize(hash, *next);
        }
        Inst::Split {
            preferred,
            fallback,
        } => {
            hash.byte(5);
            hash_usize(hash, *preferred);
            hash_usize(hash, *fallback);
        }
        Inst::RootSplit {
            preferred,
            fallback,
        } => {
            hash.byte(7);
            hash_usize(hash, *preferred);
            hash_usize(hash, *fallback);
        }
    }
}

fn hash_usize(hash: &mut StableHash, value: usize) {
    let canonical = u64::try_from(value).unwrap_or(u64::MAX);
    hash.bytes(&canonical.to_le_bytes());
}

fn inclusive_byte_width(start: u8, end: u8) -> Result<usize, Error> {
    let difference = end
        .checked_sub(start)
        .ok_or(Error::InternalInvariant("non-canonical byte class range"))?;
    add(usize::from(difference), 1, Resource::CompileWork)
}

struct StableHash(u64);

impl StableHash {
    const fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn byte(&mut self, byte: u8) {
        self.0 ^= u64::from(byte);
        self.0 = self.0.wrapping_mul(0x0000_0100_0000_01b3);
    }

    fn bytes(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.byte(byte);
        }
    }

    const fn finish(self) -> u64 {
        self.0
    }
}

/// Wrap one compiler-owned allocation without changing the incumbent
/// allocation algorithm. When no U1 allocation scope is installed,
/// `preflight_allocation` returns immediately and the original constructor is
/// invoked unchanged. The receipt ledger commits only after success.
fn compiler_allocation<T>(
    budget: &mut CompileBudget,
    needed: bool,
    resource: Resource,
    items: usize,
    construct: impl FnOnce() -> Result<T, Error>,
    allocated_bytes: impl FnOnce(&T) -> Result<usize, Error>,
) -> Result<T, Error> {
    let preflight = budget.preflight_allocation(needed)?;
    #[cfg(test)]
    if preflight.is_some() {
        compiler_allocation_probe::before(resource, items)?;
    }
    #[cfg(not(test))]
    let _ = (resource, items);
    let value = construct()?;
    let bytes = if budget.construction_effect_scope && preflight.is_some() {
        allocated_bytes(&value)?
    } else {
        0
    };
    budget.commit_allocation(preflight, needed, bytes)?;
    Ok(value)
}

fn exact_program_vec_metered<T>(
    capacity: usize,
    budget: &mut CompileBudget,
) -> Result<ExactVec<T>, Error> {
    compiler_allocation(
        budget,
        capacity > 0 && core::mem::size_of::<T>() > 0,
        Resource::ProgramBytes,
        capacity,
        || exact_program_vec(capacity),
        |values| {
            mul(
                values.capacity(),
                core::mem::size_of::<T>(),
                Resource::ProgramBytes,
            )
        },
    )
}

fn reserved_vec_metered<T>(
    length: usize,
    resource: Resource,
    budget: &mut CompileBudget,
) -> Result<Vec<T>, Error> {
    compiler_allocation(
        budget,
        length > 0 && core::mem::size_of::<T>() > 0,
        resource,
        length,
        || reserved_vec(length, resource),
        vector_capacity_bytes,
    )
}

fn reserved_queue_metered(
    length: usize,
    budget: &mut CompileBudget,
) -> Result<VecDeque<usize>, Error> {
    compiler_allocation(
        budget,
        length > 0,
        Resource::TemporaryStates,
        length,
        || reserved_queue(length),
        |queue| {
            mul(
                queue.capacity(),
                core::mem::size_of::<usize>(),
                Resource::ProgramBytes,
            )
        },
    )
}

fn reserved_vec<T>(length: usize, resource: Resource) -> Result<Vec<T>, Error> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(length)
        .map_err(|_| Error::AllocationFailed {
            resource,
            items: length,
        })?;
    Ok(values)
}

fn vector_capacity_bytes<T>(values: &Vec<T>) -> Result<usize, Error> {
    mul(
        values.capacity(),
        core::mem::size_of::<T>(),
        Resource::ProgramBytes,
    )
}

fn exact_vector_bytes<T>(values: &ExactVec<T>) -> Result<usize, Error> {
    mul(
        values.capacity(),
        core::mem::size_of::<T>(),
        Resource::ProgramBytes,
    )
}

fn reserved_queue(length: usize) -> Result<VecDeque<usize>, Error> {
    let mut queue = VecDeque::new();
    queue
        .try_reserve(length)
        .map_err(|_| Error::AllocationFailed {
            resource: Resource::TemporaryStates,
            items: length,
        })?;
    Ok(queue)
}

fn exact_program_vec<T>(capacity: usize) -> Result<ExactVec<T>, Error> {
    ExactVec::try_with_capacity(capacity).map_err(|error| match error {
        CopyError::LayoutOverflow => Error::ArithmeticOverflow {
            resource: Resource::ProgramBytes,
        },
        CopyError::AllocationFailed => Error::AllocationFailed {
            resource: Resource::ProgramBytes,
            items: capacity,
        },
    })
}

fn retain_exact_program_vec_metered<T>(
    values: Vec<T>,
    budget: &mut CompileBudget,
) -> Result<ExactVec<T>, Error> {
    let length = values.len();
    let mut retained = exact_program_vec_metered(length, budget)?;
    for value in values {
        retained.try_push(value).map_err(|_| {
            Error::InternalInvariant("exact retained program allocation changed capacity")
        })?;
        budget.record_items::<T>(1, false)?;
    }
    Ok(retained)
}

fn zeroed_exact_program_vec_metered(
    length: usize,
    budget: &mut CompileBudget,
) -> Result<ExactVec<usize>, Error> {
    let mut values = exact_program_vec_metered(length, budget)?;
    for _ in 0..length {
        values.try_push(0).map_err(|_| {
            Error::InternalInvariant("exact zeroed program allocation changed capacity")
        })?;
        budget.record_items::<usize>(1, false)?;
    }
    Ok(values)
}

fn zeroed_vec_metered(
    length: usize,
    resource: Resource,
    budget: &mut CompileBudget,
) -> Result<Vec<usize>, Error> {
    let mut values = reserved_vec_metered(length, resource, budget)?;
    values.resize(length, 0);
    budget.record_items::<usize>(length, false)?;
    Ok(values)
}

#[cfg(test)]
mod tests {
    use regex_syntax::{ParserBuilder, hir::Look};

    use super::*;

    const ADVERSARIAL_ANALYSIS_WORK: usize = 2_368;
    const ADVERSARIAL_ANALYSIS_ONE_BELOW: usize = 2_367;
    const ADVERSARIAL_RETAINED_WORK: usize = 2_888;
    const ADVERSARIAL_RETAINED_ONE_BELOW: usize = 2_887;

    fn suffix_adversary(ninth_is_duplicate: bool) -> Hir {
        let looks = [
            Look::Start,
            Look::End,
            Look::StartLF,
            Look::EndLF,
            Look::StartCRLF,
            Look::EndCRLF,
            Look::WordAscii,
            Look::WordAsciiNegate,
            Look::WordStartAscii,
        ];
        let branches = looks
            .into_iter()
            .enumerate()
            .map(|(index, look)| {
                let mut suffix = vec![b'x'; 64];
                suffix[63] = if ninth_is_duplicate && index == 8 {
                    7
                } else {
                    u8::try_from(index).expect("nine branches fit in u8")
                };
                Hir::concat(vec![Hir::look(look), Hir::literal(suffix)])
            })
            .collect();
        let hir = Hir::alternation(branches);
        assert!(matches!(
            hir.kind(),
            HirKind::Alternation(branches) if branches.len() == 9
        ));
        hir
    }

    fn suffix_budget(max_work: usize) -> CompileBudget {
        CompileBudget::new(CompileLimits {
            max_work,
            ..CompileLimits::default()
        })
    }

    fn four_range_unicode_class() -> Hir {
        ParserBuilder::new()
            .utf8(false)
            .unicode(true)
            .build()
            .parse(r"[\u{100}\u{102}\u{104}\u{106}-\u{107}]")
            .unwrap()
    }

    fn ascii_unicode_class() -> Hir {
        ParserBuilder::new()
            .utf8(false)
            .unicode(true)
            .build()
            .parse("[a-z]")
            .unwrap()
    }

    type FixedTokenCensus = (usize, usize, usize, usize);
    type FixedTokenConstruction = Result<
        (
            fre_exact_alloc::ExactVec<candidate::FixedContinuationToken>,
            FixedTokenCensus,
        ),
        Error,
    >;

    fn fixed_token_construction_attempt(
        hir: &Hir,
        body: ByteSet,
        anchor: u8,
        max_work: usize,
    ) -> (FixedTokenConstruction, CompileBudget) {
        let mut budget = CompileBudget::new_construction_receipt(
            CompileLimits {
                max_work,
                ..CompileLimits::default()
            },
            None,
        );
        let result = (|| {
            let census = fixed_continuation_token_census(hir, Some(body), anchor, &mut budget)?
                .ok_or(Error::InternalInvariant(
                    "fixed-token adversary must retain its language proof",
                ))?;
            let retained = retain_fixed_continuation_tokens(
                hir,
                census.0,
                census.1,
                census.2,
                census.3,
                &mut budget,
            )?;
            Ok((retained, census))
        })();
        (result, budget)
    }

    const fn fixed_test_identity() -> CompileAttemptIdentity {
        CompileAttemptIdentity {
            profile: RustByteProfile::PINNED_1_12_4,
            kind: CompileAttemptKind::EraseCapturesForWholeMatch,
        }
    }

    fn exercise_fixed_byte_set_traversals(budget: &mut CompileBudget) -> Result<(), Error> {
        let full = ByteSet([u64::MAX; 4]);
        let last_word_mismatch = ByteSet([u64::MAX, u64::MAX, u64::MAX, u64::MAX - 1]);
        let high = ByteSet([0, 0, 0, 1]);
        let low = ByteSet([1, 0, 0, 0]);

        assert!(fixed_continuation_byte_sets_equal(full, full, budget)?);
        assert!(!fixed_continuation_byte_sets_equal(
            full,
            last_word_mismatch,
            budget
        )?);
        assert!(fixed_continuation_byte_set_contains(full, u8::MAX, budget)?);
        assert!(!fixed_continuation_byte_set_is_empty(high, budget)?);
        assert!(fixed_continuation_byte_set_is_empty(
            ByteSet::empty(),
            budget
        )?);
        assert!(fixed_continuation_byte_set_is_subset(high, full, budget)?);
        assert!(!fixed_continuation_byte_sets_overlap(high, low, budget)?);
        Ok(())
    }

    fn parse_bytes(pattern: &str) -> Hir {
        ParserBuilder::new()
            .utf8(false)
            .unicode(false)
            .build()
            .parse(pattern)
            .unwrap()
    }

    #[test]
    fn required_literal_sets_are_canonical_bounded_and_work_exact() {
        let hir = parse_bytes(r".(?P<head>[A-Z])[a-z]+(?:efgh|efij)");
        let mut census = suffix_budget(CompileLimits::default().max_work);
        let proof = analyze_required_literal_sets(&hir, &mut census).unwrap();
        assert_eq!(proof.len(), 3);
        let sets = proof.iter().collect::<Vec<_>>();
        assert!(sets[0] & (1_u128 << b'A') != 0);
        assert!(sets[0] & (1_u128 << b'Z') != 0);
        assert!(sets[0] & (1_u128 << b'a') == 0);
        assert!(sets[1] & (1_u128 << b'a') != 0);
        assert!(sets[1] & (1_u128 << b'z') != 0);
        assert_eq!(sets[2], 1_u128 << b'e');

        let exact_work = census.accounting.work;
        let mut exact = suffix_budget(exact_work);
        assert_eq!(
            analyze_required_literal_sets(&hir, &mut exact).unwrap(),
            proof
        );
        let mut one_below = suffix_budget(exact_work - 1);
        assert_eq!(
            analyze_required_literal_sets(&hir, &mut one_below).unwrap_err(),
            Error::ResourceLimit {
                resource: Resource::CompileWork,
                required: exact_work,
                limit: exact_work - 1,
            }
        );

        let nullable_arm = parse_bytes(r"(?:[A-Z]x|)");
        let mut budget = suffix_budget(CompileLimits::default().max_work);
        assert!(
            analyze_required_literal_sets(&nullable_arm, &mut budget)
                .unwrap()
                .is_empty()
        );
    }

    struct TestUrlTlds<'a>(&'a [&'a [u8]]);

    impl UrlTldSource for TestUrlTlds<'_> {
        fn tld(&self, index: usize) -> Option<&[u8]> {
            self.0.get(index).copied()
        }

        fn tld_count(&self) -> Option<usize> {
            Some(self.0.len())
        }
    }

    #[test]
    fn url_allocations_preflight_full_p_and_commit_each_successful_a() {
        let words: &[&[u8]] = &[b"com", b"org"];
        let source = TestUrlTlds(words);
        let byte_count = words.iter().map(|word| word.len()).sum::<usize>();
        let ends_bytes = words.len() * core::mem::size_of::<usize>();
        let allocated_bytes = byte_count + ends_bytes;

        let fault = compiler_allocation_probe::fail_at(0);
        let mut one_below = CompileBudget::new_receipt(
            CompileLimits {
                max_program_bytes: allocated_bytes - 1,
                ..CompileLimits::default()
            },
            Some(AllocationScope {
                limit: 2,
                prospective: 2,
            }),
        );
        let Err(one_below_error) = pack_url_tlds(&source, &mut one_below) else {
            panic!("one-below URL packing must refuse before allocation")
        };
        assert_eq!(
            one_below_error,
            Error::ResourceLimit {
                resource: Resource::ProgramBytes,
                required: allocated_bytes,
                limit: allocated_bytes - 1,
            }
        );
        assert_eq!(compiler_allocation_probe::calls(), 0);
        drop(fault);
        assert_eq!(one_below.actual_allocations, 0);
        assert_eq!(one_below.current_construction_bytes, 0);
        assert_eq!(one_below.accounting.construction_peak_bytes, 0);

        for (ordinal, expected_live) in [(0, 0), (1, byte_count)] {
            let mut budget = CompileBudget::new_receipt(
                CompileLimits {
                    max_program_bytes: allocated_bytes,
                    ..CompileLimits::default()
                },
                Some(AllocationScope {
                    limit: 2,
                    prospective: 2,
                }),
            );
            let fault = compiler_allocation_probe::fail_at(ordinal);
            let Err(error) = pack_url_tlds(&source, &mut budget) else {
                panic!("injected URL allocation must refuse")
            };
            drop(fault);
            assert!(matches!(error, Error::AllocationFailed { .. }));
            assert_eq!(budget.actual_allocations, ordinal);
            assert_eq!(budget.current_construction_bytes, expected_live);
            assert_eq!(budget.accounting.construction_peak_bytes, expected_live);
        }

        let mut exact = CompileBudget::new_receipt(
            CompileLimits {
                max_program_bytes: allocated_bytes,
                ..CompileLimits::default()
            },
            Some(AllocationScope {
                limit: 2,
                prospective: 2,
            }),
        );
        let packed = pack_url_tlds(&source, &mut exact).unwrap();
        assert_eq!(exact.actual_allocations, 2);
        assert_eq!(exact.current_construction_bytes, allocated_bytes);
        assert_eq!(exact.accounting.construction_peak_bytes, allocated_bytes);
        packed.release(&mut exact).unwrap();
        assert_eq!(exact.current_construction_bytes, 0);
    }

    #[test]
    fn terminal_frontier_seed_is_hir_derived_capture_transparent_and_exactly_charged() {
        let hir = parse_bytes(r"(?P<root>cargo)[\\/][^/]+[\\/]");
        let mut census = suffix_budget(CompileLimits::default().max_work);
        let (suffixes, seed) =
            execution_seeds(&hir, RustByteProfile::PINNED_1_12_4, &mut census).unwrap();
        assert!(suffixes.is_empty());
        assert_eq!(seed.prefix_bytes(), b"cargo");
        assert_eq!(seed.terminal_count(), 2);
        assert!(seed.terminal_matches(b'/'));
        assert!(seed.terminal_matches(b'\\'));
        let exact_work = census.accounting.work;

        let mut exact = suffix_budget(exact_work);
        execution_seeds(&hir, RustByteProfile::PINNED_1_12_4, &mut exact).unwrap();
        assert_eq!(exact.accounting.work, exact_work);
        let mut one_below = suffix_budget(exact_work - 1);
        assert_eq!(
            execution_seeds(&hir, RustByteProfile::PINNED_1_12_4, &mut one_below,).unwrap_err(),
            Error::ResourceLimit {
                resource: Resource::CompileWork,
                required: exact_work,
                limit: exact_work - 1,
            }
        );
    }

    #[test]
    fn terminal_frontier_leading_literal_uses_common_prefix_and_refuses_nullable_or_scalar() {
        let cases = [
            (r"(?:cargo.*|cargoes.*)[\\/]", b"cargo".as_slice()),
            (r"(?:cargo.*|carpet.*)[\\/]", b"car".as_slice()),
        ];
        for (pattern, expected) in cases {
            let hir = parse_bytes(pattern);
            let mut budget = suffix_budget(CompileLimits::default().max_work);
            let (_, seed) =
                execution_seeds(&hir, RustByteProfile::PINNED_1_12_4, &mut budget).unwrap();
            assert_eq!(seed.prefix_bytes(), expected, "{pattern}");
        }

        for pattern in [
            r"(?:cargo|dog).*[\\/]",
            r"(?:cargo|).*[\\/]",
            r".*cargo[\\/]",
            r"cargo/.*/",
            r"cargo/.*/|cargo\\.*\\",
        ] {
            let hir = parse_bytes(pattern);
            let mut budget = suffix_budget(CompileLimits::default().max_work);
            let (_, seed) =
                execution_seeds(&hir, RustByteProfile::PINNED_1_12_4, &mut budget).unwrap();
            assert!(seed.is_empty(), "{pattern}");
        }

        let hir = ParserBuilder::new()
            .utf8(false)
            .unicode(true)
            .build()
            .parse(r"cargo.*[\\/]")
            .unwrap();
        let mut budget = suffix_budget(CompileLimits::default().max_work);
        let (_, seed) = execution_seeds(
            &hir,
            RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE,
            &mut budget,
        )
        .unwrap();
        assert!(seed.is_empty());
    }

    #[test]
    fn terminal_frontier_persistent_bytes_and_full_compile_work_are_exact() {
        let hir = parse_bytes(r"cargo[\\/]registry[\\/]src[\\/].*[\\/]");
        let compiled = CompiledRegex::from_hir(
            &hir,
            RustByteProfile::PINNED_1_12_4,
            CompileLimits::default(),
        )
        .unwrap();
        let accounting = compiled.compile_accounting();
        assert!(accounting.program_bytes >= core::mem::size_of::<TerminalFrontierSeed>());
        let exact = CompileLimits {
            max_program_bytes: accounting.program_bytes,
            max_work: accounting.work,
            ..CompileLimits::default()
        };
        let replay = CompiledRegex::from_hir(&hir, RustByteProfile::PINNED_1_12_4, exact).unwrap();
        assert_eq!(replay.compile_accounting(), accounting);

        assert!(matches!(
            CompiledRegex::from_hir(
                &hir,
                RustByteProfile::PINNED_1_12_4,
                CompileLimits {
                    max_program_bytes: accounting.program_bytes - 1,
                    ..exact
                },
            ),
            Err(Error::ResourceLimit {
                resource: Resource::ProgramBytes,
                ..
            })
        ));
        assert!(matches!(
            CompiledRegex::from_hir(
                &hir,
                RustByteProfile::PINNED_1_12_4,
                CompileLimits {
                    max_work: accounting.work - 1,
                    ..exact
                },
            ),
            Err(Error::ResourceLimit {
                resource: Resource::CompileWork,
                ..
            })
        ));
    }

    #[test]
    fn minimum_match_width_proof_is_retained_and_program_bounded() {
        let hir = parse_bytes(r"a{4}");
        let baseline = CompiledRegex::from_hir_erasing_captures_for_whole_match(
            &hir,
            RustByteProfile::PINNED_1_12_4,
            CompileLimits::default(),
        )
        .unwrap();
        let accounting = baseline.compile_accounting();
        assert_eq!(baseline.minimum_match_bytes, Some(4));
        assert_eq!(
            accounting.minimum_match_bytes_proof_bytes,
            core::mem::size_of::<Option<usize>>()
        );
        let exact = CompileLimits {
            max_program_bytes: accounting.program_bytes,
            ..CompileLimits::default()
        };
        let replay = CompiledRegex::from_hir_erasing_captures_for_whole_match(
            &hir,
            RustByteProfile::PINNED_1_12_4,
            exact,
        )
        .unwrap();
        assert_eq!(replay.compile_accounting(), accounting);
        let one_below = CompileLimits {
            max_program_bytes: accounting.program_bytes - 1,
            ..exact
        };
        assert_eq!(
            CompiledRegex::from_hir_erasing_captures_for_whole_match(
                &hir,
                RustByteProfile::PINNED_1_12_4,
                one_below,
            )
            .unwrap_err(),
            Error::ResourceLimit {
                resource: Resource::ProgramBytes,
                required: accounting.program_bytes,
                limit: accounting.program_bytes - 1,
            }
        );
        let receipt_exact = CompileLimits {
            max_program_bytes: accounting.construction_peak_bytes,
            ..CompileLimits::default()
        };
        let receipt_replay = CompiledRegex::from_hir_erasing_captures_for_whole_match_with_receipt(
            &hir,
            RustByteProfile::PINNED_1_12_4,
            receipt_exact,
        )
        .unwrap();
        assert_eq!(receipt_replay.compile_accounting(), accounting);
        let receipt_one_below = CompileLimits {
            max_program_bytes: accounting.construction_peak_bytes - 1,
            ..receipt_exact
        };
        let receipt_failure =
            CompiledRegex::from_hir_erasing_captures_for_whole_match_with_receipt(
                &hir,
                RustByteProfile::PINNED_1_12_4,
                receipt_one_below,
            )
            .unwrap_err();
        assert_eq!(
            receipt_failure.source,
            Error::ResourceLimit {
                resource: Resource::ProgramBytes,
                required: accounting.construction_peak_bytes,
                limit: accounting.construction_peak_bytes - 1,
            }
        );
        assert_eq!(
            receipt_failure
                .receipt
                .actual
                .minimum_match_bytes_proof_bytes,
            core::mem::size_of::<Option<usize>>()
        );
        assert!(receipt_failure.receipt.contains_actual());
    }

    #[test]
    fn candidate_analysis_and_retained_bytes_are_exact_and_one_below() {
        let hir = parse_bytes(r"(?:ab|ac)d|cd|x[0-9]z");
        let compiled = CompiledRegex::from_hir(
            &hir,
            RustByteProfile::PINNED_1_12_4,
            CompileLimits::default(),
        )
        .unwrap();
        let accounting = compiled.compile_accounting();
        assert_eq!(accounting.candidate_entries, 3);
        assert!(accounting.candidate_bytes > 0);
        let exact_program_limit = accounting
            .program_bytes
            .max(accounting.construction_peak_bytes);
        let exact = CompileLimits {
            max_program_bytes: exact_program_limit,
            max_work: accounting.work,
            ..CompileLimits::default()
        };
        assert_eq!(
            CompiledRegex::from_hir(&hir, RustByteProfile::PINNED_1_12_4, exact)
                .unwrap()
                .compile_accounting(),
            accounting
        );
        assert!(matches!(
            CompiledRegex::from_hir(
                &hir,
                RustByteProfile::PINNED_1_12_4,
                CompileLimits {
                    max_work: accounting.work - 1,
                    ..exact
                },
            ),
            Err(Error::ResourceLimit {
                resource: Resource::CompileWork,
                ..
            })
        ));
        let one_below_bytes = CompiledRegex::from_hir(
            &hir,
            RustByteProfile::PINNED_1_12_4,
            CompileLimits {
                max_program_bytes: accounting.program_bytes - 1,
                ..exact
            },
        )
        .unwrap_err();
        assert!(
            matches!(
                one_below_bytes,
                Error::ResourceLimit {
                    resource: Resource::ProgramBytes,
                    ..
                }
            ),
            "unexpected one-below candidate byte error: {one_below_bytes:?}"
        );
    }

    #[test]
    fn fixed_continuation_byte_set_traversals_have_exact_partial_receipts() {
        // Two four-word equalities, one membership, two four-word emptiness
        // scans, one four-word subset scan and one four-word overlap scan.
        const EXACT_WORK: usize = 4 + 4 + 1 + 4 + 4 + 4 + 4;
        assert_eq!(EXACT_WORK, 25);

        let mut exact = CompileBudget::new_construction_receipt(
            CompileLimits {
                max_work: EXACT_WORK,
                ..CompileLimits::default()
            },
            None,
        );
        exercise_fixed_byte_set_traversals(&mut exact).unwrap();
        assert_eq!(exact.accounting.work, EXACT_WORK);
        assert_eq!(
            exact.construction_actual(false),
            CompileConstructionActual {
                work: EXACT_WORK,
                ..CompileConstructionActual::default()
            }
        );

        let one_below_limit = EXACT_WORK - 1;
        let mut one_below = CompileBudget::new_construction_receipt(
            CompileLimits {
                max_work: one_below_limit,
                ..CompileLimits::default()
            },
            None,
        );
        assert_eq!(
            exercise_fixed_byte_set_traversals(&mut one_below).unwrap_err(),
            Error::ResourceLimit {
                resource: Resource::CompileWork,
                required: EXACT_WORK,
                limit: one_below_limit,
            }
        );
        let receipt = one_below.construction_failure_receipt(fixed_test_identity());
        assert_eq!(receipt.actual.work, one_below_limit);
        assert_eq!(receipt.actual.allocations, 0);
        assert!(receipt.authenticates_canonical());
    }

    #[test]
    fn fixed_continuation_class_census_charges_all_admission_traversals() {
        // One token visit, one two-byte range construction (range + two
        // bytes), one anchor membership, a four-word high-byte emptiness scan
        // and a complete four-word subset proof.
        const EXACT_WORK: usize = 1 + 3 + 1 + 4 + 4;
        assert_eq!(EXACT_WORK, 13);
        let hir = Hir::class(Class::Bytes(regex_syntax::hir::ClassBytes::new([
            regex_syntax::hir::ClassBytesRange::new(192, 193),
        ])));
        let body = ByteSet([u64::MAX; 4]);

        let mut exact = CompileBudget::new_construction_receipt(
            CompileLimits {
                max_work: EXACT_WORK,
                ..CompileLimits::default()
            },
            None,
        );
        assert_eq!(
            fixed_continuation_token_census(&hir, Some(body), u8::MAX, &mut exact).unwrap(),
            Some((1, 2, 1, 0))
        );
        assert_eq!(exact.accounting.work, EXACT_WORK);

        let one_below_limit = EXACT_WORK - 1;
        let mut one_below = CompileBudget::new_construction_receipt(
            CompileLimits {
                max_work: one_below_limit,
                ..CompileLimits::default()
            },
            None,
        );
        assert_eq!(
            fixed_continuation_token_census(&hir, Some(body), u8::MAX, &mut one_below).unwrap_err(),
            Error::ResourceLimit {
                resource: Resource::CompileWork,
                required: EXACT_WORK,
                limit: one_below_limit,
            }
        );
        let receipt = one_below.construction_failure_receipt(fixed_test_identity());
        assert_eq!(receipt.actual.work, one_below_limit);
        assert!(receipt.authenticates_canonical());
    }

    #[test]
    fn fixed_continuation_max_width_literal_proof_and_copy_are_independent() {
        const TOKENS: usize = 2;
        const WIDTH: usize = 16;
        const PAIRS: usize = 1;
        // Proof: two token visits, 32 body-membership comparisons, one pair
        // visit and one complete 16-byte prefix comparison.
        const PROOF_WORK: usize = 2 + 32 + 1 + 16;
        // Retention: two token visits plus a distinct copy of all 32 literal
        // bytes. No proof comparison is credited to this later traversal.
        const RETENTION_WORK: usize = 2 + 32;
        const EXACT_WORK: usize = PROOF_WORK + RETENTION_WORK;
        assert_eq!(candidate::MAX_FIXED_CONTINUATION_TOKEN_BYTES, WIDTH);
        assert_eq!(PAIRS, TOKENS * (TOKENS - 1) / 2);
        assert_eq!(PROOF_WORK, 51);
        assert_eq!(RETENTION_WORK, 34);
        assert_eq!(EXACT_WORK, 85);

        let mut left = [b'a'; WIDTH];
        left[0] = 1;
        let mut right = [b'a'; WIDTH];
        right[0] = 2;
        let hir = Hir::alternation(vec![
            Hir::literal(left.to_vec()),
            Hir::literal(right.to_vec()),
        ]);
        assert!(matches!(
            hir.kind(),
            HirKind::Alternation(branches) if branches.len() == TOKENS
        ));
        let body = ByteSet([u64::MAX; 4]);

        let (exact_result, exact_budget) =
            fixed_token_construction_attempt(&hir, body, u8::MAX, EXACT_WORK);
        let (tokens, census) = exact_result.unwrap();
        assert_eq!(tokens.len(), TOKENS);
        assert_eq!(census, (TOKENS, 34, 32, 32));
        assert_eq!(exact_budget.accounting.work, EXACT_WORK);
        let exact_actual = exact_budget.construction_actual(true);
        assert_eq!(exact_actual.work, EXACT_WORK);
        assert_eq!(exact_actual.allocations, 1);
        assert_eq!(exact_actual.copied_bytes, TOKENS * WIDTH);
        assert_eq!(
            exact_actual.initialized_bytes,
            TOKENS * core::mem::size_of::<candidate::FixedContinuationToken>()
        );
        assert!(exact_actual.is_closed());

        let one_below_limit = EXACT_WORK - 1;
        let (one_below_result, one_below_budget) =
            fixed_token_construction_attempt(&hir, body, u8::MAX, one_below_limit);
        assert_eq!(
            one_below_result.unwrap_err(),
            Error::ResourceLimit {
                resource: Resource::CompileWork,
                required: EXACT_WORK,
                limit: one_below_limit,
            }
        );
        let receipt = one_below_budget.construction_failure_receipt(fixed_test_identity());
        assert_eq!(receipt.actual.work, PROOF_WORK);
        assert_eq!(receipt.actual.allocations, 0);
        assert_eq!(receipt.actual.copied_bytes, 0);
        assert_eq!(receipt.actual.live_construction_bytes, 0);
        assert!(receipt.authenticates_canonical());
    }

    #[test]
    fn fixed_continuation_max_alternatives_have_exact_proof_and_copy_receipts() {
        const ALTERNATIVES: usize = 128;
        const WIDTH: usize = 2;
        const PAIRS: usize = 8_128;
        // Proof: N token visits + N*2 body memberships + one pair visit and
        // two compared bytes for every N*(N-1)/2 ordered-language pair.
        const PROOF_WORK: usize = 128 + 256 + 8_128 + 16_256;
        // Retention is a separate N-token + N*2-byte copy traversal.
        const RETENTION_WORK: usize = 128 + 256;
        const EXACT_WORK: usize = PROOF_WORK + RETENTION_WORK;
        assert_eq!(candidate::MAX_ENTRIES, ALTERNATIVES);
        assert_eq!(PAIRS, ALTERNATIVES * (ALTERNATIVES - 1) / 2);
        assert_eq!(PROOF_WORK, 24_768);
        assert_eq!(RETENTION_WORK, 384);
        assert_eq!(EXACT_WORK, 25_152);

        let branches = (0..ALTERNATIVES)
            .map(|ordinal| {
                Hir::literal(vec![
                    u8::try_from(ordinal).expect("128 alternatives fit in one byte"),
                    0xfe,
                ])
            })
            .collect();
        let hir = Hir::alternation(branches);
        assert!(matches!(
            hir.kind(),
            HirKind::Alternation(branches) if branches.len() == ALTERNATIVES
        ));
        let body = ByteSet([u64::MAX; 4]);

        let (exact_result, exact_budget) =
            fixed_token_construction_attempt(&hir, body, u8::MAX, EXACT_WORK);
        let (tokens, census) = exact_result.unwrap();
        assert_eq!(tokens.len(), ALTERNATIVES);
        assert_eq!(census, (ALTERNATIVES, 384, 256, 256));
        assert_eq!(exact_budget.accounting.work, EXACT_WORK);
        let exact_actual = exact_budget.construction_actual(true);
        assert_eq!(exact_actual.work, EXACT_WORK);
        assert_eq!(exact_actual.allocations, 1);
        assert_eq!(exact_actual.copied_bytes, ALTERNATIVES * WIDTH);
        assert_eq!(
            exact_actual.initialized_bytes,
            ALTERNATIVES * core::mem::size_of::<candidate::FixedContinuationToken>()
        );
        assert!(exact_actual.is_closed());

        let one_below_limit = EXACT_WORK - 1;
        let (one_below_result, one_below_budget) =
            fixed_token_construction_attempt(&hir, body, u8::MAX, one_below_limit);
        assert_eq!(
            one_below_result.unwrap_err(),
            Error::ResourceLimit {
                resource: Resource::CompileWork,
                required: EXACT_WORK,
                limit: one_below_limit,
            }
        );
        let receipt = one_below_budget.construction_failure_receipt(fixed_test_identity());
        assert_eq!(receipt.actual.work, PROOF_WORK);
        assert_eq!(receipt.actual.allocations, 0);
        assert_eq!(receipt.actual.copied_bytes, 0);
        assert_eq!(receipt.actual.live_construction_bytes, 0);
        assert!(receipt.authenticates_canonical());
    }

    #[test]
    fn single_capture_selector_requires_a_strong_or_short_complementary_proof() {
        let hir = parse_bytes(r"cargo/registry/src/[^/]+/([a-z]+)-([0-9.]+)/");
        let selector = CompiledRegex::from_hir_erasing_captures_for_whole_match(
            &hir,
            RustByteProfile::PINNED_1_12_4,
            CompileLimits::default(),
        )
        .unwrap();
        assert_eq!(selector.compile_accounting().candidate_entries, 1);
        assert_eq!(
            selector.uniform_capture_count_route(),
            crate::OperationPhysicalRoute::Candidate
        );

        let ordinary = CompiledRegex::from_hir(
            &parse_bytes(r"cargo/registry/src/[^/]+/[a-z]+-[0-9.]+/"),
            RustByteProfile::PINNED_1_12_4,
            CompileLimits::default(),
        )
        .unwrap();
        assert_eq!(ordinary.compile_accounting().candidate_entries, 0);

        let complementary_pattern = r#"(?:(?:alpha|beta|nil|true|\d|["'\\+])+\)*;?((?:\s|-|~|!|\{\}|\|\||\+)*.*(?:.*=.*)))"#;
        let complementary_hir = parse_bytes(complementary_pattern);
        let complementary = CompiledRegex::from_hir_erasing_captures_for_whole_match(
            &complementary_hir,
            RustByteProfile::PINNED_1_12_4,
            CompileLimits::default(),
        )
        .unwrap();
        let complementary_accounting = complementary.compile_accounting();
        assert_eq!(complementary_accounting.candidate_entries, 1);
        assert!(complementary_accounting.candidate_bytes > 0);
        let plan = complementary.candidate.as_ref().unwrap();
        assert!(!candidate::has_complete_shared_fixed_filter(plan));
        assert!(plan.fixed_continuation().is_some());
        assert!(plan.max_offset() <= candidate::MAX_FILTER_CHECKS);
        assert_eq!(plan.global_buckets[usize::from(b'=')], 1);
        assert_eq!(plan.buckets[usize::from(b'=')], 0);
        let exact = CompileLimits {
            max_program_bytes: complementary_accounting
                .program_bytes
                .max(complementary_accounting.construction_peak_bytes),
            max_work: complementary_accounting.work,
            ..CompileLimits::default()
        };
        let replay = CompiledRegex::from_hir_erasing_captures_for_whole_match(
            &complementary_hir,
            RustByteProfile::PINNED_1_12_4,
            exact,
        )
        .unwrap();
        assert_eq!(replay.compile_accounting(), complementary_accounting);
        assert_eq!(replay.plan_id(), complementary.plan_id());
        assert!(matches!(
            CompiledRegex::from_hir_erasing_captures_for_whole_match(
                &complementary_hir,
                RustByteProfile::PINNED_1_12_4,
                CompileLimits {
                    max_work: complementary_accounting.work - 1,
                    ..exact
                },
            ),
            Err(Error::ResourceLimit {
                resource: Resource::CompileWork,
                ..
            })
        ));

        for pattern in [
            r"short([a-z]+)",
            r"[a-z]+suffix",
            r"(?:alpha|beta)+(?:x|y)",
            r"(?:alpha|beta)+.*(?:=.*)?",
            r"(?:(?:q|eeeeeeeeez))+.*=.*",
            r"(?:(?:a|ab)+\)*;?((?:\s|-)*.*(?:.*=.*)))",
            r"(?:(?:alpha|beta)+?\)*;?((?:\s|-)*.*(?:.*=.*)))",
            r"(?:(?:alpha|beta)+\)*;?((?:\s|  )*.*(?:.*=.*)))",
            r"(?:(?:alpha|beta)+\)*((?:\s|-)*.*(?:.*=.*)))",
        ] {
            let weak = CompiledRegex::from_hir_erasing_captures_for_whole_match(
                &parse_bytes(pattern),
                RustByteProfile::PINNED_1_12_4,
                CompileLimits::default(),
            )
            .unwrap();
            assert_eq!(weak.compile_accounting().candidate_entries, 0, "{pattern}");
        }

        let unicode_hir = ParserBuilder::new()
            .utf8(false)
            .unicode(true)
            .build()
            .parse(complementary_pattern)
            .unwrap();
        let unicode = CompiledRegex::from_hir_erasing_captures_for_whole_match(
            &unicode_hir,
            RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE,
            CompileLimits::default(),
        )
        .unwrap();
        assert_eq!(unicode.compile_accounting().candidate_entries, 0);
    }

    #[test]
    fn mandatory_start_domain_is_hir_derived_capture_transparent_and_bounded() {
        let cases = [
            (r"a", StartDomain::AnyBoundary),
            (r"\Aa", StartDomain::AbsoluteStart),
            (r"(?m:^a)", StartDomain::LineStartLf),
            (r"(?Rm:^a)", StartDomain::LineStartCrlf),
            (r"(?m:^(a))", StartDomain::LineStartLf),
            (r"(?m:^a)|(?m:^b)", StartDomain::LineStartLf),
        ];
        for (pattern, expected) in cases {
            let hir = parse_bytes(pattern);
            assert_eq!(mandatory_start_domain(&hir), expected, "{pattern:?}");
            let compiled = CompiledRegex::from_hir_erasing_captures_for_whole_match(
                &hir,
                RustByteProfile::PINNED_1_12_4,
                CompileLimits::default(),
            )
            .unwrap();
            assert_eq!(compiled.program.start_domain, expected, "{pattern:?}");
            assert_eq!(
                compiled.compile_accounting().start_domain_proof_bytes(),
                core::mem::size_of::<StartDomain>()
            );
            let accounting = compiled.compile_accounting();
            let exact = CompileLimits {
                max_program_bytes: accounting.program_bytes,
                max_work: accounting.work,
                ..CompileLimits::default()
            };
            let replay = CompiledRegex::from_hir_erasing_captures_for_whole_match(
                &hir,
                RustByteProfile::PINNED_1_12_4,
                exact,
            )
            .unwrap();
            assert_eq!(replay.compile_accounting(), accounting);
            assert_eq!(replay.plan_id(), compiled.plan_id());
            assert!(matches!(
                CompiledRegex::from_hir_erasing_captures_for_whole_match(
                    &hir,
                    RustByteProfile::PINNED_1_12_4,
                    CompileLimits {
                        max_program_bytes: accounting.program_bytes - 1,
                        ..exact
                    },
                ),
                Err(Error::ResourceLimit {
                    resource: Resource::ProgramBytes,
                    ..
                })
            ));
        }
    }

    #[test]
    fn line_start_domain_requires_a_line_partitioned_byte_program() {
        let cases = [
            (r"(?m:^[^\n]*Z)", StartDomain::LineStartLf),
            (r"(?ms:^.*Z)", StartDomain::AnyBoundary),
            (r"(?Rm:^[^\r\n]*Z)", StartDomain::LineStartCrlf),
            (r"(?Rm:^[^\n]*Z)", StartDomain::AnyBoundary),
            (r"(?Rms:^.*Z)", StartDomain::AnyBoundary),
        ];
        for (pattern, expected) in cases {
            let hir = parse_bytes(pattern);
            let compiled = CompiledRegex::from_hir_erasing_captures_for_whole_match(
                &hir,
                RustByteProfile::PINNED_1_12_4,
                CompileLimits::default(),
            )
            .unwrap();
            assert_eq!(compiled.program.start_domain, expected, "{pattern:?}");
        }
    }

    #[test]
    fn candidate_allocation_failures_commit_only_successful_storage() {
        let hir = parse_bytes(r"(?:ab|ac)d|cd|x[0-9]z");
        let HirKind::Alternation(branches) = hir.kind() else {
            panic!("candidate fixture must remain a root alternation")
        };
        let draft_bytes = branches.len() * core::mem::size_of::<CandidateDraft>();
        let entry_bytes = branches.len() * core::mem::size_of::<CandidateEntry>();
        let bucket_bytes = candidate::bucket_count() * core::mem::size_of::<u128>();
        let expected_live = [
            0,
            draft_bytes,
            draft_bytes + entry_bytes,
            draft_bytes + entry_bytes + bucket_bytes,
        ];
        for (ordinal, expected_live) in expected_live.into_iter().enumerate() {
            let mut budget = CompileBudget::new_receipt(
                CompileLimits::default(),
                Some(AllocationScope {
                    limit: 4,
                    prospective: 4,
                }),
            );
            let fault = compiler_allocation_probe::fail_at(ordinal);
            let error = build_candidate_plan(
                &hir,
                RustByteProfile::PINNED_1_12_4,
                CapturePolicy::Reject,
                &mut budget,
            )
            .unwrap_err();
            drop(fault);
            assert!(matches!(error, Error::AllocationFailed { .. }));
            assert_eq!(budget.actual_allocations, ordinal);
            assert_eq!(budget.current_construction_bytes, expected_live);
            assert_eq!(budget.accounting.construction_peak_bytes, expected_live);
        }

        let mut budget = CompileBudget::new_receipt(
            CompileLimits::default(),
            Some(AllocationScope {
                limit: 4,
                prospective: 4,
            }),
        );
        let plan = build_candidate_plan(
            &hir,
            RustByteProfile::PINNED_1_12_4,
            CapturePolicy::Reject,
            &mut budget,
        )
        .unwrap()
        .unwrap();
        assert_eq!(budget.actual_allocations, 4);
        assert_eq!(
            budget.current_construction_bytes,
            plan.retained_bytes().unwrap()
        );
    }

    #[test]
    fn fixed_continuation_allocation_receipts_cover_tokens_and_tagged_proof() {
        let pattern = r#"(?:(?:alpha|beta|nil|true|\d|["'\\+])+\)*;?((?:\s|-|~|!|\{\}|\|\||\+)*.*(?:.*=.*)))"#;
        let hir = parse_bytes(pattern);
        let mut census_budget = CompileBudget::new(CompileLimits::default());
        let census = build_candidate_plan(
            &hir,
            RustByteProfile::PINNED_1_12_4,
            CapturePolicy::EraseForWholeMatch,
            &mut census_budget,
        )
        .unwrap()
        .unwrap();
        let fixed = census.fixed_continuation().unwrap();
        let token_bytes =
            fixed.tokens.len() * core::mem::size_of::<candidate::FixedContinuationToken>();
        let leading_token_bytes =
            fixed.leading_tokens.len() * core::mem::size_of::<candidate::FixedContinuationToken>();
        let retained_bytes = census.retained_bytes().unwrap();
        drop(census);

        let draft_bytes = core::mem::size_of::<CandidateDraft>();
        let entry_bytes = core::mem::size_of::<CandidateEntry>();
        let bucket_bytes = candidate::bucket_count() * core::mem::size_of::<u128>();
        let base = draft_bytes + entry_bytes + 2 * bucket_bytes;
        let expected_live = [
            0,
            draft_bytes,
            draft_bytes + entry_bytes,
            draft_bytes + entry_bytes + bucket_bytes,
            base,
            base + token_bytes,
            base + token_bytes + leading_token_bytes,
        ];
        for (ordinal, expected_live) in expected_live.into_iter().enumerate() {
            let mut budget = CompileBudget::new_construction_receipt(
                CompileLimits::default(),
                Some(AllocationScope {
                    limit: 7,
                    prospective: 7,
                }),
            );
            let fault = compiler_allocation_probe::fail_at(ordinal);
            let error = build_candidate_plan(
                &hir,
                RustByteProfile::PINNED_1_12_4,
                CapturePolicy::EraseForWholeMatch,
                &mut budget,
            )
            .unwrap_err();
            drop(fault);
            assert!(matches!(error, Error::AllocationFailed { .. }));
            assert_eq!(budget.actual_allocations, ordinal);
            assert_eq!(budget.actual_allocated_bytes, expected_live);
            assert_eq!(budget.actual_initialized_bytes, expected_live);
            assert_eq!(budget.current_construction_bytes, expected_live);
            assert_eq!(budget.accounting.construction_peak_bytes, expected_live);
        }

        let mut budget = CompileBudget::new_construction_receipt(
            CompileLimits::default(),
            Some(AllocationScope {
                limit: 7,
                prospective: 7,
            }),
        );
        let plan = build_candidate_plan(
            &hir,
            RustByteProfile::PINNED_1_12_4,
            CapturePolicy::EraseForWholeMatch,
            &mut budget,
        )
        .unwrap()
        .unwrap();
        assert_eq!(budget.actual_allocations, 7);
        assert_eq!(budget.actual_allocated_bytes, retained_bytes + draft_bytes);
        assert_eq!(
            budget.actual_initialized_bytes,
            retained_bytes + draft_bytes
        );
        assert_eq!(plan.retained_bytes().unwrap(), retained_bytes);
        assert_eq!(budget.current_construction_bytes, retained_bytes);
        assert_eq!(
            budget.accounting.construction_peak_bytes,
            retained_bytes + draft_bytes
        );
    }

    #[test]
    fn scalar_construction_charges_ranges_and_one_continuation_set_exactly() {
        // Four canonical-range copies, 64 continuation-byte insertions, one
        // two-byte continuation state and one scalar state: 4 + 64 + 1 + 1.
        const EXACT_WORK: usize = 70;
        let hir = four_range_unicode_class();
        let HirKind::Class(Class::Unicode(class)) = hir.kind() else {
            panic!("fixture must remain one Unicode class")
        };

        let mut exact = CompileBudget::new(CompileLimits {
            max_work: EXACT_WORK,
            ..CompileLimits::default()
        });
        {
            let mut builder = Builder::new(
                CompileLimits::default().max_program_states,
                RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE,
                CapturePolicy::Reject,
                0,
                &mut exact,
            );
            builder.compile_unicode_class(class, 0).unwrap();
            assert_eq!(builder.slots.len(), 2);
        }
        assert_eq!(exact.accounting.work, EXACT_WORK);

        let mut one_below = CompileBudget::new(CompileLimits {
            max_work: EXACT_WORK - 1,
            ..CompileLimits::default()
        });
        let error = Builder::new(
            CompileLimits::default().max_program_states,
            RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE,
            CapturePolicy::Reject,
            0,
            &mut one_below,
        )
        .compile_unicode_class(class, 0)
        .unwrap_err();
        assert_eq!(
            error,
            Error::ResourceLimit {
                resource: Resource::CompileWork,
                required: EXACT_WORK,
                limit: EXACT_WORK - 1,
            }
        );
        assert_eq!(one_below.accounting.work, EXACT_WORK - 1);
        assert_eq!(one_below.current_temporary_states, 1);

        // A one-byte class never constructs the unused continuation set.
        let ascii = ascii_unicode_class();
        let HirKind::Class(Class::Unicode(ascii)) = ascii.kind() else {
            panic!("fixture must remain one Unicode class")
        };
        let mut ascii_budget = CompileBudget::new(CompileLimits {
            max_work: 2,
            ..CompileLimits::default()
        });
        Builder::new(
            CompileLimits::default().max_program_states,
            RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE,
            CapturePolicy::Reject,
            0,
            &mut ascii_budget,
        )
        .compile_unicode_class(ascii, 0)
        .unwrap();
        assert_eq!(ascii_budget.accounting.work, 2);
    }

    #[test]
    fn receipt_scalar_storage_remains_live_at_post_allocation_refusals() {
        let ascii = ascii_unicode_class();
        let HirKind::Class(Class::Unicode(class)) = ascii.kind() else {
            panic!("fixture must remain one Unicode class")
        };
        let scalar_bytes = ScalarSet::required_bytes(class.ranges().len()).unwrap();
        for (limits, expected) in [
            (
                CompileLimits {
                    max_work: 1,
                    ..CompileLimits::default()
                },
                Error::ResourceLimit {
                    resource: Resource::CompileWork,
                    required: 2,
                    limit: 1,
                },
            ),
            (
                CompileLimits {
                    max_temporary_states: 0,
                    ..CompileLimits::default()
                },
                Error::ResourceLimit {
                    resource: Resource::TemporaryStates,
                    required: 1,
                    limit: 0,
                },
            ),
        ] {
            let mut budget = CompileBudget::new_receipt(
                limits,
                Some(AllocationScope {
                    limit: 2,
                    prospective: 2,
                }),
            );
            let error = Builder::new(
                limits.max_program_states,
                RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE,
                CapturePolicy::Reject,
                0,
                &mut budget,
            )
            .compile_unicode_class(class, 0)
            .unwrap_err();
            assert_eq!(error, expected);
            assert_eq!(budget.actual_allocations, 1);
            assert_eq!(budget.current_construction_bytes, scalar_bytes);
            assert_eq!(budget.accounting.construction_peak_bytes, scalar_bytes);
        }

        for (ordinal, expected_live, expected_allocations) in [(0, 0, 0), (1, scalar_bytes, 1)] {
            let limits = CompileLimits::default();
            let mut budget = CompileBudget::new_receipt(
                limits,
                Some(AllocationScope {
                    limit: 2,
                    prospective: 2,
                }),
            );
            let fault = compiler_allocation_probe::fail_at(ordinal);
            let error = Builder::new(
                limits.max_program_states,
                RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE,
                CapturePolicy::Reject,
                0,
                &mut budget,
            )
            .compile_unicode_class(class, 0)
            .unwrap_err();
            drop(fault);
            assert!(matches!(error, Error::AllocationFailed { .. }));
            assert_eq!(budget.actual_allocations, expected_allocations);
            assert_eq!(budget.current_construction_bytes, expected_live);
            assert_eq!(budget.accounting.construction_peak_bytes, expected_live);
        }
    }

    #[test]
    fn receipt_retained_and_parent_failures_have_no_phantom_bytes() {
        let limits = CompileLimits::default();
        let mut budget = CompileBudget::new_receipt(
            limits,
            Some(AllocationScope {
                limit: 2,
                prospective: 2,
            }),
        );
        let mut builder = Builder::new(
            limits.max_program_states,
            RustByteProfile::PINNED_1_12_4,
            CapturePolicy::Reject,
            0,
            &mut budget,
        );
        builder.push(Inst::Match).unwrap();
        let live_before = builder.budget.current_construction_bytes;
        let peak_before = builder.budget.accounting.construction_peak_bytes;
        let fault = compiler_allocation_probe::fail_at(0);
        let error = builder.finish().unwrap_err();
        drop(fault);
        assert!(matches!(error, Error::AllocationFailed { .. }));
        assert_eq!(budget.actual_allocations, 1);
        assert_eq!(budget.current_construction_bytes, live_before);
        assert_eq!(budget.accounting.construction_peak_bytes, peak_before);

        let mut insts = exact_program_vec(1).unwrap();
        insts.try_push(Inst::Match).unwrap();
        let mut parent_budget = CompileBudget::new_receipt(
            limits,
            Some(AllocationScope {
                limit: 4,
                prospective: 4,
            }),
        );
        let fault = compiler_allocation_probe::fail_at(1);
        let Err(error) = build_epsilon_parent_index(&insts, &mut parent_budget) else {
            panic!("injected parent-count allocation must fail")
        };
        drop(fault);
        assert!(matches!(error, Error::AllocationFailed { .. }));
        let outgoing_bytes = core::mem::size_of::<usize>();
        assert_eq!(parent_budget.actual_allocations, 1);
        assert_eq!(parent_budget.current_construction_bytes, outgoing_bytes);
        assert_eq!(
            parent_budget.accounting.construction_peak_bytes,
            outgoing_bytes
        );
    }

    #[test]
    fn receipt_finish_slot_scan_is_exactly_charged_before_observation() {
        let exact_limits = CompileLimits {
            max_work: 2,
            ..CompileLimits::default()
        };
        let mut exact_budget = CompileBudget::new_receipt(exact_limits, None);
        let mut exact_builder = Builder::new(
            exact_limits.max_program_states,
            RustByteProfile::PINNED_1_12_4,
            CapturePolicy::Reject,
            0,
            &mut exact_budget,
        );
        exact_builder.push(Inst::Match).unwrap();
        let retained = exact_builder.finish().unwrap();
        assert_eq!(retained.len(), 1);
        assert_eq!(exact_budget.accounting.work, 2);

        let one_below_limits = CompileLimits {
            max_work: 1,
            ..CompileLimits::default()
        };
        let mut one_below_budget = CompileBudget::new_receipt(one_below_limits, None);
        let mut one_below_builder = Builder::new(
            one_below_limits.max_program_states,
            RustByteProfile::PINNED_1_12_4,
            CapturePolicy::Reject,
            0,
            &mut one_below_budget,
        );
        one_below_builder.push(Inst::Match).unwrap();
        assert_eq!(
            one_below_builder.finish().unwrap_err(),
            Error::ResourceLimit {
                resource: Resource::CompileWork,
                required: 2,
                limit: 1,
            }
        );
        assert_eq!(one_below_budget.accounting.work, 1);

        let mut invalid_budget = CompileBudget::new_receipt(exact_limits, None);
        let mut invalid_builder = Builder::new(
            exact_limits.max_program_states,
            RustByteProfile::PINNED_1_12_4,
            CapturePolicy::Reject,
            0,
            &mut invalid_budget,
        );
        invalid_builder.push(Inst::Unfilled).unwrap();
        assert_eq!(
            invalid_builder.finish().unwrap_err(),
            Error::InternalInvariant("unfilled compiler state")
        );
        assert_eq!(invalid_budget.accounting.work, 2);
    }

    #[test]
    fn receipt_child_push_refuses_one_below_before_allocation_or_publication() {
        let child = Hir::empty();
        let exact_limits = CompileLimits {
            max_work: 1,
            ..CompileLimits::default()
        };
        let mut exact_budget = CompileBudget::new_receipt(
            exact_limits,
            Some(AllocationScope {
                limit: 1,
                prospective: 1,
            }),
        );
        let mut exact_stack = Vec::new();
        push_children(&mut exact_stack, [&child], 0, &mut exact_budget).unwrap();
        assert_eq!(exact_stack, [(&child, 1)]);
        assert_eq!(exact_budget.accounting.work, 1);
        assert_eq!(exact_budget.actual_allocations, 1);

        let one_below_limits = CompileLimits {
            max_work: 0,
            ..CompileLimits::default()
        };
        let mut one_below_budget = CompileBudget::new_receipt(
            one_below_limits,
            Some(AllocationScope {
                limit: 1,
                prospective: 1,
            }),
        );
        let mut one_below_stack = Vec::new();
        assert_eq!(
            push_children(&mut one_below_stack, [&child], 0, &mut one_below_budget,).unwrap_err(),
            Error::ResourceLimit {
                resource: Resource::CompileWork,
                required: 1,
                limit: 0,
            }
        );
        assert!(one_below_stack.is_empty());
        assert_eq!(one_below_stack.capacity(), 0);
        assert_eq!(one_below_budget.accounting.work, 0);
        assert_eq!(one_below_budget.actual_allocations, 0);
        assert_eq!(one_below_budget.current_construction_bytes, 0);
        assert_eq!(one_below_budget.accounting.peak_hir_stack_items, 0);
    }

    #[test]
    fn receipt_epsilon_parent_write_refuses_one_below_at_prewrite_charge() {
        let mut insts = exact_program_vec(2).unwrap();
        insts
            .try_push(Inst::Assert {
                assertion: crate::program::Assertion::StartText,
                next: 1,
            })
            .unwrap();
        insts.try_push(Inst::Match).unwrap();
        let exact_limits = CompileLimits {
            max_work: 2,
            ..CompileLimits::default()
        };
        let mut exact_budget = CompileBudget::new_receipt(
            exact_limits,
            Some(AllocationScope {
                limit: 4,
                prospective: 4,
            }),
        );
        let index = build_epsilon_parent_index(&insts, &mut exact_budget).unwrap();
        assert_eq!(index.outgoing.as_slice(), [1, 0]);
        assert_eq!(index.offsets, [0, 0, 1]);
        assert_eq!(index.parents, [0]);
        assert_eq!(exact_budget.accounting.work, 2);
        assert_eq!(exact_budget.actual_allocations, 4);

        let one_below_limits = CompileLimits {
            max_work: 1,
            ..CompileLimits::default()
        };
        let mut one_below_budget = CompileBudget::new_receipt(
            one_below_limits,
            Some(AllocationScope {
                limit: 4,
                prospective: 4,
            }),
        );
        let Err(error) = build_epsilon_parent_index(&insts, &mut one_below_budget) else {
            panic!("one-below parent publication must refuse")
        };
        assert_eq!(
            error,
            Error::ResourceLimit {
                resource: Resource::CompileWork,
                required: 2,
                limit: 1,
            }
        );
        assert_eq!(one_below_budget.accounting.work, 1);
        assert_eq!(one_below_budget.actual_allocations, 4);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the exact-limit and one-below receipt assertions share one authenticated setup"
    )]
    fn receipt_required_anchor_failure_commits_inspection_work_and_rebases_limit() {
        let hir = parse_bytes(r"a+Xb+[ab]+");
        let profile = RustByteProfile::PINNED_1_12_4;
        let default_limits = CompileLimits::default();

        let mut prefix_budget = CompileBudget::new_receipt(default_limits, None);
        validate_hir(
            &hir,
            profile,
            CapturePolicy::EraseForWholeMatch,
            &mut prefix_budget,
        )
        .unwrap();
        assert!(
            build_url_aggregate_plan(
                &hir,
                profile,
                CapturePolicy::EraseForWholeMatch,
                default_limits,
                &mut prefix_budget,
            )
            .unwrap()
            .is_none()
        );
        let prefix_work = prefix_budget.accounting.work;

        let mut seed_budget = CompileBudget::new_receipt(default_limits, None);
        let _seeds = execution_seeds(&hir, profile, &mut seed_budget).unwrap();
        let seed_work = seed_budget.accounting.work;
        let mut literal_budget = CompileBudget::new_receipt(default_limits, None);
        let _literal_proof = analyze_required_literal_sets(&hir, &mut literal_budget).unwrap();
        let literal_work = literal_budget.accounting.work;
        let inspection = required_internal_anchor::inspect(
            &hir,
            default_limits.max_work,
            default_limits.max_literal_bytes,
            default_limits.max_program_bytes,
        )
        .unwrap();
        assert!(inspection.plan.is_some());
        let exact_work = add(
            add(
                add(
                    add(prefix_work, seed_work, Resource::CompileWork).unwrap(),
                    literal_work,
                    Resource::CompileWork,
                )
                .unwrap(),
                1,
                Resource::CompileWork,
            )
            .unwrap(),
            inspection.inspection_work,
            Resource::CompileWork,
        )
        .unwrap();

        let exact_limits = CompileLimits {
            max_work: exact_work,
            ..default_limits
        };
        let mut exact_budget = CompileBudget::new_receipt(exact_limits, None);
        validate_hir(
            &hir,
            profile,
            CapturePolicy::EraseForWholeMatch,
            &mut exact_budget,
        )
        .unwrap();
        assert!(
            build_url_aggregate_plan(
                &hir,
                profile,
                CapturePolicy::EraseForWholeMatch,
                exact_limits,
                &mut exact_budget,
            )
            .unwrap()
            .is_none()
        );
        build_retained_components(&hir, profile, exact_limits, &mut exact_budget).unwrap();
        assert_eq!(exact_budget.accounting.work, exact_work);

        let one_below_limit = exact_work - 1;
        let local_limit = inspection.inspection_work - 1;
        let local_attempt = required_internal_anchor::inspect_attempt(
            &hir,
            local_limit,
            default_limits.max_literal_bytes,
            default_limits.max_program_bytes,
        );
        assert!(matches!(
            local_attempt.result,
            Err(Error::ResourceLimit {
                resource: Resource::CompileWork,
                required,
                limit,
            }) if required == inspection.inspection_work && limit == local_limit
        ));

        let refusal = CompiledRegex::from_hir_erasing_captures_for_whole_match_with_receipt(
            &hir,
            profile,
            CompileLimits {
                max_work: one_below_limit,
                ..default_limits
            },
        )
        .unwrap_err();
        assert_eq!(
            refusal.source,
            Error::ResourceLimit {
                resource: Resource::CompileWork,
                required: exact_work,
                limit: one_below_limit,
            }
        );
        assert_eq!(
            refusal.receipt.actual.work,
            prefix_work + seed_work + literal_work + 1 + local_attempt.inspection_work
        );
        assert!(refusal.receipt.contains_actual());
    }

    #[test]
    fn u1_receipt_scope_preserves_incumbent_compile_and_refuses_allocation_one_below_pre_source() {
        let hir = ParserBuilder::new().build().parse(r"^.{3}$").unwrap();
        let profile = RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE;
        let limits = CompileLimits::default();
        let ordinary =
            CompiledRegex::from_hir_erasing_captures_for_whole_match(&hir, profile, limits)
                .unwrap();

        // A deliberately oversized prospective census yields its terminal
        // actual ledger without changing the compiler algorithm. The exact
        // replay must then produce the same plan and incumbent accounting.
        let census =
            CompiledRegex::from_hir_erasing_captures_for_whole_match_with_allocation_receipt(
                &hir,
                profile,
                limits,
                usize::MAX,
                usize::MAX,
            )
            .unwrap_err();
        assert_eq!(
            census.source,
            Error::InternalInvariant("fixed scalar allocation census differs from compilation")
        );
        let allocations = census
            .receipt
            .actual_allocations
            .expect("allocation-scoped receipt must retain its exact actual count");
        assert_eq!(allocations, 15);
        assert!(allocations > 0);
        assert!(census.receipt.contains_actual());

        let (scoped, actual) =
            CompiledRegex::from_hir_erasing_captures_for_whole_match_with_allocation_receipt(
                &hir,
                profile,
                limits,
                allocations,
                allocations,
            )
            .unwrap();
        assert_eq!(actual, allocations);
        assert_eq!(scoped.plan_id(), ordinary.plan_id());
        assert_eq!(scoped.compile_accounting(), ordinary.compile_accounting());
        assert_eq!(scoped.state_count(), ordinary.state_count());

        let fault = compiler_allocation_probe::fail_at(0);
        let one_below =
            CompiledRegex::from_hir_erasing_captures_for_whole_match_with_allocation_receipt(
                &hir,
                profile,
                limits,
                allocations - 1,
                allocations,
            )
            .unwrap_err();
        assert_eq!(compiler_allocation_probe::calls(), 0);
        drop(fault);
        assert_eq!(
            one_below.source,
            Error::ResourceLimit {
                resource: Resource::Allocations,
                required: allocations,
                limit: allocations - 1,
            }
        );
        assert_eq!(one_below.receipt.actual_allocations, Some(0));
        assert_eq!(one_below.receipt.actual.hir_nodes, 0);
        assert_eq!(one_below.receipt.actual.work, 0);
        assert_eq!(one_below.receipt.live_construction_bytes, 0);
        assert!(one_below.receipt.contains_actual());

        for ordinal in 0..allocations {
            let fault = compiler_allocation_probe::fail_at(ordinal);
            let refusal =
                CompiledRegex::from_hir_erasing_captures_for_whole_match_with_allocation_receipt(
                    &hir,
                    profile,
                    limits,
                    allocations,
                    allocations,
                )
                .unwrap_err();
            drop(fault);
            assert!(matches!(refusal.source, Error::AllocationFailed { .. }));
            assert_eq!(refusal.receipt.actual_allocations, Some(ordinal));
            assert!(refusal.receipt.contains_actual());
            assert!(!refusal.receipt.published);
        }
    }

    #[test]
    fn pinned_base_vec_census_matches_small_and_large_scalar_compiles() {
        let profile = RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE;
        let limits = CompileLimits::default();
        for (pattern, expected_allocations) in [(r"^.{3}$", 15), (r"^.{249}$", 267)] {
            let hir = ParserBuilder::new().build().parse(pattern).unwrap();
            let ordinary =
                CompiledRegex::from_hir_erasing_captures_for_whole_match(&hir, profile, limits)
                    .unwrap();
            let census =
                CompiledRegex::from_hir_erasing_captures_for_whole_match_with_allocation_receipt(
                    &hir,
                    profile,
                    limits,
                    usize::MAX,
                    usize::MAX,
                )
                .unwrap_err();
            assert_eq!(
                census.source,
                Error::InternalInvariant("fixed scalar allocation census differs from compilation")
            );
            assert_eq!(
                census.receipt.actual_allocations,
                Some(expected_allocations)
            );
            assert!(census.receipt.contains_actual());

            let (scoped, actual) =
                CompiledRegex::from_hir_erasing_captures_for_whole_match_with_allocation_receipt(
                    &hir,
                    profile,
                    limits,
                    expected_allocations,
                    expected_allocations,
                )
                .unwrap();
            assert_eq!(actual, expected_allocations);
            assert_eq!(scoped.plan_id(), ordinary.plan_id());
            assert_eq!(scoped.compile_accounting(), ordinary.compile_accounting());
            assert_eq!(scoped.state_count(), ordinary.state_count());

            let fault = compiler_allocation_probe::fail_at(0);
            let one_below =
                CompiledRegex::from_hir_erasing_captures_for_whole_match_with_allocation_receipt(
                    &hir,
                    profile,
                    limits,
                    expected_allocations - 1,
                    expected_allocations,
                )
                .unwrap_err();
            assert_eq!(compiler_allocation_probe::calls(), 0);
            drop(fault);
            assert_eq!(
                one_below.source,
                Error::ResourceLimit {
                    resource: Resource::Allocations,
                    required: expected_allocations,
                    limit: expected_allocations - 1,
                }
            );
            assert_eq!(one_below.receipt.actual_allocations, Some(0));
            assert_eq!(one_below.receipt.actual.hir_nodes, 0);
            assert_eq!(one_below.receipt.actual.work, 0);
            assert_eq!(one_below.receipt.live_construction_bytes, 0);
            assert!(one_below.receipt.contains_actual());
        }
    }

    #[test]
    fn generic_receipt_preserves_parity_and_omits_allocation_scope() {
        let hir = ParserBuilder::new().build().parse(r"^.{3}$").unwrap();
        let profile = RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE;
        let ordinary = CompiledRegex::from_hir_erasing_captures_for_whole_match(
            &hir,
            profile,
            CompileLimits::default(),
        )
        .unwrap();
        let receipt_compile =
            CompiledRegex::from_hir_erasing_captures_for_whole_match_with_receipt(
                &hir,
                profile,
                CompileLimits::default(),
            )
            .unwrap();
        assert_eq!(receipt_compile.plan_id(), ordinary.plan_id());
        assert_eq!(
            receipt_compile.compile_accounting(),
            ordinary.compile_accounting()
        );
        assert_eq!(receipt_compile.state_count(), ordinary.state_count());

        let refusal = CompiledRegex::from_hir_erasing_captures_for_whole_match_with_receipt(
            &hir,
            profile,
            CompileLimits {
                max_hir_nodes: 0,
                ..CompileLimits::default()
            },
        )
        .unwrap_err();
        assert_eq!(
            refusal.source,
            Error::ResourceLimit {
                resource: Resource::HirNodes,
                required: 1,
                limit: 0,
            }
        );
        assert_eq!(refusal.receipt.allocation_limit, None);
        assert_eq!(refusal.receipt.prospective_allocations, None);
        assert_eq!(refusal.receipt.actual_allocations, None);
        assert_eq!(refusal.receipt.actual.hir_nodes, 0);
        assert!(refusal.receipt.live_construction_bytes > 0);
        assert!(refusal.receipt.contains_actual());
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one end-to-end test keeps success and both refusal closure invariants adjacent"
    )]
    fn construction_receipt_closes_success_and_partial_refusal_without_changing_plan() {
        let hir = ParserBuilder::new().build().parse(r"^(?:ab|cd)+$").unwrap();
        let profile = RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE;
        let ordinary = CompiledRegex::from_hir_erasing_captures_for_whole_match(
            &hir,
            profile,
            CompileLimits::default(),
        )
        .unwrap();
        let attempt =
            CompiledRegex::from_hir_erasing_captures_for_whole_match_with_construction_receipt(
                &hir,
                profile,
                CompileLimits::default(),
            )
            .unwrap();
        assert_eq!(attempt.compiled().plan_id(), ordinary.plan_id());
        assert_eq!(
            attempt.compiled().compile_accounting(),
            ordinary.compile_accounting()
        );
        let actual = attempt.actual();
        assert!(actual.is_closed());
        assert!(actual.published);
        assert!(actual.allocations > 0);
        assert!(actual.allocated_bytes >= actual.live_program_bytes);
        assert!(actual.initialized_bytes >= actual.live_program_bytes);
        assert_eq!(
            actual.live_program_bytes,
            attempt.compiled().compile_accounting().program_bytes
        );

        let scoped =
            CompiledRegex::from_hir_erasing_captures_for_whole_match_with_construction_and_allocation_receipt(
                &hir,
                profile,
                CompileLimits::default(),
                actual.allocations,
                actual.allocations,
            )
            .unwrap();
        assert_eq!(scoped.actual(), actual);
        assert_eq!(scoped.compiled().plan_id(), ordinary.plan_id());
        let one_below =
            CompiledRegex::from_hir_erasing_captures_for_whole_match_with_construction_and_allocation_receipt(
                &hir,
                profile,
                CompileLimits::default(),
                actual.allocations - 1,
                actual.allocations,
            )
            .unwrap_err();
        assert_eq!(
            one_below.source,
            Error::ResourceLimit {
                resource: Resource::Allocations,
                required: actual.allocations,
                limit: actual.allocations - 1,
            }
        );
        assert_eq!(
            one_below.receipt.actual,
            CompileConstructionActual::default()
        );
        assert!(one_below.receipt.contains_actual());

        let refusal =
            CompiledRegex::from_hir_erasing_captures_for_whole_match_with_construction_receipt(
                &hir,
                profile,
                CompileLimits {
                    max_hir_nodes: 0,
                    ..CompileLimits::default()
                },
            )
            .unwrap_err();
        assert_eq!(
            refusal.source,
            Error::ResourceLimit {
                resource: Resource::HirNodes,
                required: 1,
                limit: 0,
            }
        );
        assert!(refusal.receipt.contains_actual());
        assert_eq!(refusal.receipt.actual.allocations, 1);
        assert!(refusal.receipt.actual.allocated_bytes > 0);
        assert!(refusal.receipt.actual.initialized_bytes > 0);
        assert_eq!(refusal.receipt.actual.live_program_bytes, 0);
        assert_eq!(
            refusal.receipt.actual.abandonable_bytes,
            refusal.receipt.actual.live_construction_bytes
        );

        let fault = compiler_allocation_probe::fail_at(1);
        let allocation_refusal =
            CompiledRegex::from_hir_erasing_captures_for_whole_match_with_construction_receipt(
                &hir,
                profile,
                CompileLimits::default(),
            )
            .unwrap_err();
        drop(fault);
        assert!(matches!(
            allocation_refusal.source,
            Error::AllocationFailed { .. }
        ));
        assert!(allocation_refusal.receipt.contains_actual());
        assert_eq!(allocation_refusal.receipt.actual.allocations, 1);
        assert!(allocation_refusal.receipt.actual.allocated_bytes > 0);
        assert!(allocation_refusal.receipt.actual.initialized_bytes > 0);
    }

    #[test]
    fn construction_error_rejects_coherent_receipt_mutations_and_terminal_splices() {
        let hir = ParserBuilder::new().build().parse(r"^(?:ab|cd)+$").unwrap();
        let profile = RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE;
        let refusal =
            CompiledRegex::from_hir_erasing_captures_for_whole_match_with_construction_receipt(
                &hir,
                profile,
                CompileLimits {
                    max_hir_nodes: 0,
                    ..CompileLimits::default()
                },
            )
            .unwrap_err();
        assert!(refusal.closes());
        assert!(refusal.receipt().authenticates_canonical());
        assert!(refusal.receipt().actual.work > 0);

        let mut prospective_mutation = *refusal.receipt();
        prospective_mutation.prospective.max_hir_nodes = 1;
        assert!(prospective_mutation.contains_actual());
        assert!(!prospective_mutation.authenticates_canonical());

        let mut accounting_actual_mutation = *refusal.receipt();
        accounting_actual_mutation.accounting.work = accounting_actual_mutation
            .accounting
            .work
            .checked_sub(1)
            .unwrap();
        accounting_actual_mutation.actual.work = accounting_actual_mutation
            .actual
            .work
            .checked_sub(1)
            .unwrap();
        assert!(accounting_actual_mutation.contains_actual());
        assert!(!accounting_actual_mutation.authenticates_canonical());

        let allocation_refusal =
            CompiledRegex::from_hir_erasing_captures_for_whole_match_with_construction_and_allocation_receipt(
                &hir,
                profile,
                CompileLimits::default(),
                0,
                1,
            )
            .unwrap_err();
        assert!(allocation_refusal.closes());

        let source_splice = CompileConstructionAttemptError::new(
            allocation_refusal.source().clone(),
            *refusal.receipt(),
        );
        assert!(!source_splice.closes());

        let receipt_splice = CompileConstructionAttemptError::new(
            refusal.source().clone(),
            *allocation_refusal.receipt(),
        );
        assert!(!receipt_splice.closes());

        let (source, receipt) = refusal.into_parts();
        assert!(matches!(
            source,
            Error::ResourceLimit {
                resource: Resource::HirNodes,
                ..
            }
        ));
        assert!(receipt.authenticates_canonical());
    }

    #[test]
    fn receipt_unicode_off_nonascii_class_scan_is_fully_metered() {
        let hir = Hir::class(Class::Unicode(regex_syntax::hir::ClassUnicode::new([
            regex_syntax::hir::ClassUnicodeRange::new('a', 'a'),
            regex_syntax::hir::ClassUnicodeRange::new('c', 'c'),
            regex_syntax::hir::ClassUnicodeRange::new('\u{100}', '\u{100}'),
        ])));
        let ranges = match hir.kind() {
            HirKind::Class(Class::Unicode(class)) => class.ranges().len(),
            _ => unreachable!("fixture must remain one Unicode class"),
        };
        assert_eq!(ranges, 3);

        let refusal = CompiledRegex::from_hir_erasing_captures_for_whole_match_with_receipt(
            &hir,
            RustByteProfile::PINNED_1_12_4,
            CompileLimits::default(),
        )
        .unwrap_err();
        assert_eq!(
            refusal.source,
            Error::Unsupported(Unsupported::UnicodeClass)
        );
        assert_eq!(refusal.receipt.actual.work, 1 + ranges);
        assert_eq!(refusal.receipt.actual.class_ranges, 0);
        assert!(refusal.receipt.contains_actual());

        let limit = refusal.receipt.actual.work - 1;
        let one_below = CompiledRegex::from_hir_erasing_captures_for_whole_match_with_receipt(
            &hir,
            RustByteProfile::PINNED_1_12_4,
            CompileLimits {
                max_work: limit,
                ..CompileLimits::default()
            },
        )
        .unwrap_err();
        assert_eq!(
            one_below.source,
            Error::ResourceLimit {
                resource: Resource::CompileWork,
                required: limit + 1,
                limit,
            }
        );
        assert_eq!(one_below.receipt.actual.work, limit);
        assert_eq!(one_below.receipt.actual.class_ranges, 0);
        assert!(one_below.receipt.contains_actual());
    }

    #[test]
    fn scoped_receipt_preserves_literal_candidate_suffix_and_progress_parity() {
        let cases = [
            (parse_bytes("abc"), RustByteProfile::PINNED_1_12_4),
            (
                parse_bytes(r"(?:ab|ac)d|cd|x[0-9]z"),
                RustByteProfile::PINNED_1_12_4,
            ),
            (parse_bytes("a*"), RustByteProfile::PINNED_1_12_4),
            (
                ParserBuilder::new().build().parse(r"^.+$").unwrap(),
                RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE,
            ),
        ];
        for (hir, profile) in cases {
            let ordinary = CompiledRegex::from_hir_erasing_captures_for_whole_match(
                &hir,
                profile,
                CompileLimits::default(),
            )
            .unwrap();
            let census =
                CompiledRegex::from_hir_erasing_captures_for_whole_match_with_allocation_receipt(
                    &hir,
                    profile,
                    CompileLimits::default(),
                    usize::MAX,
                    usize::MAX,
                )
                .unwrap_err();
            let allocations = census
                .receipt
                .actual_allocations
                .expect("allocation-scoped census must retain A");
            assert!(allocations > 0);
            assert!(census.receipt.contains_actual());
            let (scoped, actual) =
                CompiledRegex::from_hir_erasing_captures_for_whole_match_with_allocation_receipt(
                    &hir,
                    profile,
                    CompileLimits::default(),
                    allocations,
                    allocations,
                )
                .unwrap();
            assert_eq!(actual, allocations);
            assert_eq!(scoped.plan_id(), ordinary.plan_id());
            assert_eq!(scoped.compile_accounting(), ordinary.compile_accounting());
            assert_eq!(scoped.state_count(), ordinary.state_count());
        }
    }

    #[test]
    fn required_suffix_ineligible_analysis_exact_limit_and_one_below() {
        // 19 visited nodes + 9 alternation branches + 36 worst-case
        // 64-byte dedup comparisons, each charged as min(lengths) + 1.
        let hir = suffix_adversary(false);
        let mut exact = suffix_budget(ADVERSARIAL_ANALYSIS_WORK);
        let suffixes = required_suffixes(&hir, &mut exact).unwrap();
        assert!(suffixes.is_empty());
        assert_eq!(ADVERSARIAL_ANALYSIS_WORK, exact.accounting.work);

        let mut one_below = suffix_budget(ADVERSARIAL_ANALYSIS_ONE_BELOW);
        assert_eq!(
            Error::ResourceLimit {
                resource: Resource::CompileWork,
                required: ADVERSARIAL_ANALYSIS_WORK,
                limit: ADVERSARIAL_ANALYSIS_ONE_BELOW,
            },
            required_suffixes(&hir, &mut one_below).unwrap_err()
        );
    }

    #[test]
    fn required_suffix_retained_copy_exact_limit_and_one_below() {
        // The same adversarial analysis retains eight 64-byte suffixes when
        // the ninth branch duplicates the eighth, adding 8 endpoint writes
        // and 512 byte copies to the preflighted work.
        let hir = suffix_adversary(true);
        let mut exact = suffix_budget(ADVERSARIAL_RETAINED_WORK);
        let suffixes = required_suffixes(&hir, &mut exact).unwrap();
        assert_eq!(8, suffixes.ends.len());
        assert_eq!(512, suffixes.bytes.len());
        assert_eq!(ADVERSARIAL_RETAINED_WORK, exact.accounting.work);

        let retained_bytes = suffixes.retained_bytes().unwrap();
        assert_eq!(retained_bytes, 512 + 8 * core::mem::size_of::<usize>());
        let mut exact_bytes = CompileBudget::new(CompileLimits {
            max_work: ADVERSARIAL_RETAINED_WORK,
            max_program_bytes: retained_bytes,
            ..CompileLimits::default()
        });
        assert_eq!(
            required_suffixes(&hir, &mut exact_bytes)
                .unwrap()
                .retained_bytes()
                .unwrap(),
            retained_bytes
        );
        let mut one_below_bytes = CompileBudget::new(CompileLimits {
            max_work: ADVERSARIAL_RETAINED_WORK,
            max_program_bytes: retained_bytes - 1,
            ..CompileLimits::default()
        });
        assert_eq!(
            required_suffixes(&hir, &mut one_below_bytes).unwrap_err(),
            Error::ResourceLimit {
                resource: Resource::ProgramBytes,
                required: retained_bytes,
                limit: retained_bytes - 1,
            }
        );
        assert_eq!(one_below_bytes.accounting.work, ADVERSARIAL_ANALYSIS_WORK);

        let mut one_below = suffix_budget(ADVERSARIAL_RETAINED_ONE_BELOW);
        assert_eq!(
            Error::ResourceLimit {
                resource: Resource::CompileWork,
                required: ADVERSARIAL_RETAINED_WORK,
                limit: ADVERSARIAL_RETAINED_ONE_BELOW,
            },
            required_suffixes(&hir, &mut one_below).unwrap_err()
        );
    }

    #[test]
    fn required_suffix_allocations_commit_bytes_then_endpoints() {
        let hir = parse_bytes("abc");
        let suffix_bytes = 3;
        let endpoint_bytes = core::mem::size_of::<usize>();
        for (ordinal, expected_live) in [(0, 0), (1, suffix_bytes)] {
            let mut budget = CompileBudget::new_receipt(
                CompileLimits::default(),
                Some(AllocationScope {
                    limit: 2,
                    prospective: 2,
                }),
            );
            let fault = compiler_allocation_probe::fail_at(ordinal);
            let error = required_suffixes(&hir, &mut budget).unwrap_err();
            drop(fault);
            assert!(matches!(error, Error::AllocationFailed { .. }));
            assert_eq!(budget.actual_allocations, ordinal);
            assert_eq!(budget.current_construction_bytes, expected_live);
            assert_eq!(budget.accounting.construction_peak_bytes, expected_live);
        }

        let mut exact = CompileBudget::new_receipt(
            CompileLimits::default(),
            Some(AllocationScope {
                limit: 2,
                prospective: 2,
            }),
        );
        let suffixes = required_suffixes(&hir, &mut exact).unwrap();
        assert_eq!(suffixes.iter().collect::<Vec<_>>(), [b"abc".as_slice()]);
        assert_eq!(exact.actual_allocations, 2);
        assert_eq!(
            exact.current_construction_bytes,
            suffix_bytes + endpoint_bytes
        );
        assert_eq!(
            exact.accounting.construction_peak_bytes,
            suffix_bytes + endpoint_bytes
        );
    }

    #[test]
    fn retained_components_preflight_general_and_certificate_bytes_before_work() {
        const SUFFIX_BYTES: usize = 17;
        const ANCHOR_BYTES: usize = 23;
        let retained_bytes = SUFFIX_BYTES + ANCHOR_BYTES;
        let state_bytes = core::mem::size_of::<Inst>() + 2 * core::mem::size_of::<usize>();
        let exact_limit = retained_bytes + state_bytes;

        let mut exact = CompileBudget::new(CompileLimits {
            max_program_bytes: exact_limit,
            ..CompileLimits::default()
        });
        let exact_insts = {
            let mut builder = Builder::new(
                CompileLimits::default().max_program_states,
                RustByteProfile::PINNED_1_12_4,
                CapturePolicy::Reject,
                retained_bytes,
                &mut exact,
            );
            assert_eq!(builder.slots.capacity(), 0);
            builder.push(Inst::Match).unwrap();
            builder.finish().unwrap()
        };
        assert_eq!(exact_insts.len(), 1);
        assert_eq!(
            core::mem::size_of_val(&*exact_insts),
            core::mem::size_of::<Inst>()
        );
        assert_eq!(exact.accounting.work, 2);
        assert_eq!(exact.current_temporary_states, 1);

        let mut one_below = CompileBudget::new(CompileLimits {
            max_program_bytes: exact_limit - 1,
            ..CompileLimits::default()
        });
        {
            let mut builder = Builder::new(
                CompileLimits::default().max_program_states,
                RustByteProfile::PINNED_1_12_4,
                CapturePolicy::Reject,
                retained_bytes,
                &mut one_below,
            );
            assert_eq!(
                builder.push(Inst::Match).unwrap_err(),
                Error::ResourceLimit {
                    resource: Resource::ProgramBytes,
                    required: exact_limit,
                    limit: exact_limit - 1,
                }
            );
            assert!(builder.slots.is_empty());
            assert_eq!(builder.slots.capacity(), 0);
        }
        assert_eq!(one_below.accounting.work, 0);
        assert_eq!(one_below.current_temporary_states, 0);

        let mut insts = exact_program_vec(1).unwrap();
        insts.try_push(Inst::Match).unwrap();
        let certificate_limit = preflight_certification_program_bytes(
            insts.len(),
            insts.len(),
            0,
            retained_bytes,
            usize::MAX,
        )
        .unwrap();
        let mut certificate_exact = CompileBudget::new(CompileLimits {
            max_program_bytes: certificate_limit,
            ..CompileLimits::default()
        });
        let certificate =
            certify_program(&insts, 0, retained_bytes, &mut certificate_exact).unwrap();
        assert_eq!(certificate.epsilon_order.len(), insts.len());
        assert_eq!(certificate.split_rank.len(), insts.len());
        assert_eq!(
            core::mem::size_of_val(&*certificate.epsilon_order),
            core::mem::size_of::<usize>()
        );
        assert_eq!(
            core::mem::size_of_val(&*certificate.split_rank),
            core::mem::size_of::<usize>()
        );
        let mut certificate_one_below = CompileBudget::new(CompileLimits {
            max_program_bytes: certificate_limit - 1,
            ..CompileLimits::default()
        });
        let Err(certificate_error) =
            certify_program(&insts, 0, retained_bytes, &mut certificate_one_below)
        else {
            panic!("one-below certificate admission must refuse");
        };
        assert_eq!(
            certificate_error,
            Error::ResourceLimit {
                resource: Resource::ProgramBytes,
                required: certificate_limit,
                limit: certificate_limit - 1,
            }
        );
        assert_eq!(certificate_one_below.accounting.work, 0);
        assert_eq!(certificate_one_below.current_temporary_states, 0);
    }

    #[test]
    fn required_anchor_combined_program_bytes_are_exact_and_one_below() {
        let hir = ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse(r"[\w]+://[^/\s?#]+[^\s?#]+(?:\?[^\s#]*)?(?:#[^\s]*)?")
            .unwrap();
        let baseline = CompiledRegex::from_hir(
            &hir,
            RustByteProfile::PINNED_1_12_4,
            CompileLimits::default(),
        )
        .unwrap();
        let accounting = baseline.compile_accounting();
        assert_eq!(accounting.required_internal_anchors, 1);
        assert!(accounting.required_internal_anchor_persistent_bytes > 0);
        let exact = CompileLimits {
            max_program_bytes: accounting.program_bytes,
            ..CompileLimits::default()
        };
        CompiledRegex::from_hir(&hir, RustByteProfile::PINNED_1_12_4, exact).unwrap();
        let one_below = CompileLimits {
            max_program_bytes: accounting.program_bytes - 1,
            ..CompileLimits::default()
        };
        assert_eq!(
            CompiledRegex::from_hir(&hir, RustByteProfile::PINNED_1_12_4, one_below).unwrap_err(),
            Error::ResourceLimit {
                resource: Resource::ProgramBytes,
                required: accounting.program_bytes,
                limit: accounting.program_bytes - 1,
            }
        );
    }

    #[test]
    fn terminal_byte_class_suffix_copy_is_exact_and_bounded() {
        const EXACT_WORK: usize = 10;
        let hir = ParserBuilder::new()
            .utf8(false)
            .unicode(false)
            .build()
            .parse(r#"["']"#)
            .unwrap();
        let mut exact = suffix_budget(EXACT_WORK);
        let suffixes = required_suffixes(&hir, &mut exact).unwrap();
        assert_eq!(
            suffixes.iter().collect::<Vec<_>>(),
            [b"\"".as_slice(), b"'".as_slice()]
        );
        assert_eq!(EXACT_WORK, exact.accounting.work);

        let mut one_below = suffix_budget(EXACT_WORK - 1);
        assert_eq!(
            Error::ResourceLimit {
                resource: Resource::CompileWork,
                required: EXACT_WORK,
                limit: EXACT_WORK - 1,
            },
            required_suffixes(&hir, &mut one_below).unwrap_err()
        );

        let too_wide = ParserBuilder::new()
            .utf8(false)
            .unicode(false)
            .build()
            .parse("[a-i]")
            .unwrap();
        let mut bounded = suffix_budget(CompileLimits::default().max_work);
        assert!(
            required_suffixes(&too_wide, &mut bounded)
                .unwrap()
                .is_empty()
        );

        let unbounded = ParserBuilder::new()
            .utf8(false)
            .unicode(false)
            .build()
            .parse(r#"[a-z]+["']"#)
            .unwrap();
        let mut bounded = suffix_budget(CompileLimits::default().max_work);
        assert!(
            required_suffixes(&unbounded, &mut bounded)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn unicode_casefold_literal_suffix_domains_are_canonical_and_exactly_bounded() {
        let hir = ParserBuilder::new()
            .utf8(false)
            .unicode(true)
            .case_insensitive(true)
            .build()
            .parse("Шерлок Холмс")
            .unwrap();
        let mut census = suffix_budget(CompileLimits::default().max_work);
        let suffixes = required_suffixes(&hir, &mut census).unwrap();
        assert!(suffixes.prefers_sparse_verification());
        assert_eq!(
            suffixes.iter().collect::<Vec<_>>(),
            ["С".as_bytes(), "с".as_bytes(), "ᲃ".as_bytes()]
        );
        assert_eq!(
            suffixes.retained_bytes().unwrap(),
            7 + 3 * size_of::<usize>()
        );
        let exact_work = census.accounting.work;

        let mut exact = suffix_budget(exact_work);
        assert_eq!(
            required_suffixes(&hir, &mut exact)
                .unwrap()
                .iter()
                .collect::<Vec<_>>(),
            ["С".as_bytes(), "с".as_bytes(), "ᲃ".as_bytes()]
        );
        assert_eq!(exact.accounting.work, exact_work);

        let mut one_below = suffix_budget(exact_work - 1);
        assert_eq!(
            required_suffixes(&hir, &mut one_below).unwrap_err(),
            Error::ResourceLimit {
                resource: Resource::CompileWork,
                required: exact_work,
                limit: exact_work - 1,
            }
        );

        let retained = suffixes.retained_bytes().unwrap();
        let mut exact_bytes = CompileBudget::new(CompileLimits {
            max_program_bytes: retained,
            ..CompileLimits::default()
        });
        assert_eq!(
            required_suffixes(&hir, &mut exact_bytes)
                .unwrap()
                .retained_bytes()
                .unwrap(),
            retained
        );
        let mut one_below_bytes = CompileBudget::new(CompileLimits {
            max_program_bytes: retained - 1,
            ..CompileLimits::default()
        });
        assert_eq!(
            required_suffixes(&hir, &mut one_below_bytes).unwrap_err(),
            Error::ResourceLimit {
                resource: Resource::ProgramBytes,
                required: retained,
                limit: retained - 1,
            }
        );
    }

    #[test]
    fn unicode_suffix_domains_cover_variable_width_and_keep_wide_fallbacks() {
        let kelvin = ParserBuilder::new()
            .utf8(false)
            .unicode(true)
            .case_insensitive(true)
            .build()
            .parse("k")
            .unwrap();
        let mut budget = suffix_budget(CompileLimits::default().max_work);
        assert_eq!(
            required_suffixes(&kelvin, &mut budget)
                .unwrap()
                .iter()
                .collect::<Vec<_>>(),
            [b"K".as_slice(), b"k".as_slice(), "\u{212A}".as_bytes()]
        );

        let sigma = ParserBuilder::new()
            .utf8(false)
            .unicode(true)
            .case_insensitive(true)
            .build()
            .parse("σ")
            .unwrap();
        let mut budget = suffix_budget(CompileLimits::default().max_work);
        assert_eq!(
            required_suffixes(&sigma, &mut budget)
                .unwrap()
                .iter()
                .collect::<Vec<_>>(),
            ["Σ".as_bytes(), "ς".as_bytes(), "σ".as_bytes()]
        );

        let mut budget = suffix_budget(CompileLimits::default().max_work);
        assert!(
            required_suffixes(&ascii_unicode_class(), &mut budget)
                .unwrap()
                .is_empty()
        );
        let literal = parse_bytes("ing");
        let mut budget = suffix_budget(CompileLimits::default().max_work);
        let literal_suffixes = required_suffixes(&literal, &mut budget).unwrap();
        assert_eq!(
            literal_suffixes.iter().collect::<Vec<_>>(),
            [b"ing".as_slice()]
        );
        assert!(!literal_suffixes.prefers_sparse_verification());
    }

    fn required_anchor_plan_id(
        prefix: &[u8],
        anchor: &[u8],
        head: &[u8],
        tail: &[u8],
        optional: Option<(u8, &[u8])>,
    ) -> PlanId {
        let mut continuation = fre_kernels::RequiredInternalAnchorContinuationSource::new(
            fre_kernels::RequiredInternalAnchorByteClass::from_bytes(head),
            fre_kernels::RequiredInternalAnchorByteClass::from_bytes(tail),
        );
        if let Some((introducer, class)) = optional {
            continuation.optional[0] =
                Some(fre_kernels::RequiredInternalAnchorOptionalStageSource {
                    introducer,
                    class: fre_kernels::RequiredInternalAnchorByteClass::from_bytes(class),
                });
            continuation.optional_count = 1;
        }
        let plan = fre_kernels::RequiredInternalAnchorPlan::build(
            fre_kernels::RequiredInternalAnchorByteClass::from_bytes(prefix),
            anchor,
            continuation,
            fre_kernels::RequiredInternalAnchorBuildLimits::default(),
        )
        .expect("valid identity fixture");
        let mut budget = CompileBudget::new(CompileLimits::default());
        bind_required_internal_anchor_identity(PlanId([0x5a; 16]), &plan, &mut budget)
            .expect("bind required-anchor identity")
    }

    #[derive(Clone, Copy)]
    enum StateByteSlotCompileKind {
        Erase,
        Reject,
        OrderedRoot,
    }

    fn compile_state_byte_slot_case(
        hir: &Hir,
        profile: RustByteProfile,
        kind: StateByteSlotCompileKind,
        limits: CompileLimits,
    ) -> Result<CompiledRegex, Error> {
        match kind {
            StateByteSlotCompileKind::Erase => {
                CompiledRegex::from_hir_erasing_captures_for_whole_match(hir, profile, limits)
            }
            StateByteSlotCompileKind::Reject => CompiledRegex::from_hir(hir, profile, limits),
            StateByteSlotCompileKind::OrderedRoot => {
                CompiledRegex::from_hir_erasing_captures_for_ordered_root_count(
                    hir, profile, limits,
                )
            }
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one matrix keeps every eligible and ineligible inline-slot representation under the same exact-byte assertions"
    )]
    fn state_byte_span_sum_inline_slot_is_complete_for_every_shape() {
        let eligible = parse_bytes(r"[a-c]*ab[a-z]*");
        let structurally_ineligible = parse_bytes(r"[a-c]*az[a-z]*");
        let unicode = ParserBuilder::new()
            .unicode(true)
            .utf8(false)
            .build()
            .parse(r"\w+\s+Holmes")
            .unwrap();
        let ordered_root = parse_bytes(r"ab|cd");
        let cases = [
            (
                &eligible,
                RustByteProfile::PINNED_1_12_4,
                StateByteSlotCompileKind::Erase,
                true,
            ),
            (
                &eligible,
                RustByteProfile::PINNED_1_12_4,
                StateByteSlotCompileKind::Reject,
                false,
            ),
            (
                &structurally_ineligible,
                RustByteProfile::PINNED_1_12_4,
                StateByteSlotCompileKind::Erase,
                false,
            ),
            (
                &unicode,
                RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE,
                StateByteSlotCompileKind::Erase,
                false,
            ),
            (
                &ordered_root,
                RustByteProfile::PINNED_1_12_4,
                StateByteSlotCompileKind::OrderedRoot,
                false,
            ),
        ];
        let retained_slot_bytes = core::mem::size_of::<Option<StateByteSpanSumPlan>>();
        assert_eq!(retained_slot_bytes, 208);
        for (hir, profile, kind, eligible) in cases {
            let compiled =
                compile_state_byte_slot_case(hir, profile, kind, CompileLimits::default()).unwrap();
            let accounting = compiled.compile_accounting();
            assert_eq!(
                accounting.state_byte_span_sum_persistent_bytes,
                retained_slot_bytes
            );
            assert_eq!(accounting.state_byte_span_sum_plans, usize::from(eligible));
            assert_eq!(compiled.state_byte_span_sum.is_some(), eligible);

            let exact = CompileLimits {
                max_program_bytes: accounting.program_bytes,
                ..CompileLimits::default()
            };
            let replay = compile_state_byte_slot_case(hir, profile, kind, exact).unwrap();
            assert_eq!(replay.compile_accounting(), accounting);
            assert_eq!(
                compile_state_byte_slot_case(
                    hir,
                    profile,
                    kind,
                    CompileLimits {
                        max_program_bytes: accounting.program_bytes - 1,
                        ..exact
                    },
                )
                .unwrap_err(),
                Error::ResourceLimit {
                    resource: Resource::ProgramBytes,
                    required: accounting.program_bytes,
                    limit: accounting.program_bytes - 1,
                }
            );
        }

        let eligible_receipt =
            CompiledRegex::from_hir_erasing_captures_for_whole_match_with_construction_receipt(
                &eligible,
                RustByteProfile::PINNED_1_12_4,
                CompileLimits::default(),
            )
            .unwrap();
        let ineligible_receipt =
            CompiledRegex::from_hir_erasing_captures_for_whole_match_with_construction_receipt(
                &structurally_ineligible,
                RustByteProfile::PINNED_1_12_4,
                CompileLimits::default(),
            )
            .unwrap();
        for receipt in [&eligible_receipt, &ineligible_receipt] {
            let actual = receipt.actual();
            assert!(actual.is_closed());
            assert!(actual.published);
            assert_eq!(
                actual.live_program_bytes,
                receipt.compiled().compile_accounting().program_bytes
            );
            assert_eq!(
                receipt
                    .compiled()
                    .compile_accounting()
                    .state_byte_span_sum_persistent_bytes,
                retained_slot_bytes
            );
        }
        assert_eq!(
            eligible_receipt.actual().allocations,
            ineligible_receipt.actual().allocations
        );
    }

    #[test]
    fn state_byte_failure_table_one_below_closes_construction_receipt() {
        let hir = parse_bytes(r"[ab]*abab[a-z]*");
        let profile = RustByteProfile::PINNED_1_12_4;
        let limits = CompileLimits::default();
        let mut budget = CompileBudget::new_construction_receipt(limits, None);
        validate_hir(
            &hir,
            profile,
            CapturePolicy::EraseForWholeMatch,
            &mut budget,
        )
        .unwrap();
        let _url = build_url_aggregate_plan(
            &hir,
            profile,
            CapturePolicy::EraseForWholeMatch,
            limits,
            &mut budget,
        )
        .unwrap();
        let _retained = build_retained_components(&hir, profile, limits, &mut budget).unwrap();
        let slot_bytes = StateByteSpanSumPlan::retained_slot_bytes();
        budget
            .preflight_receipt_construction_bytes(slot_bytes)
            .unwrap();
        budget
            .acquire_checked_construction_bytes(slot_bytes)
            .unwrap();
        assert!(
            build_state_byte_span_sum_plan(
                &hir,
                profile,
                CapturePolicy::EraseForWholeMatch,
                &mut budget,
            )
            .unwrap()
            .is_some()
        );
        let table_end_work = budget.accounting.work;
        let one_below = table_end_work - 1;

        let refusal =
            CompiledRegex::from_hir_erasing_captures_for_whole_match_with_construction_receipt(
                &hir,
                profile,
                CompileLimits {
                    max_work: one_below,
                    ..limits
                },
            )
            .unwrap_err();
        assert_eq!(
            refusal.source(),
            &Error::ResourceLimit {
                resource: Resource::CompileWork,
                required: table_end_work,
                limit: one_below,
            }
        );
        assert!(refusal.closes());
        assert!(refusal.receipt().contains_actual());
        assert!(
            refusal.receipt().actual.copied_bytes <= refusal.receipt().actual.initialized_bytes
        );
        assert_eq!(refusal.receipt().accounting.state_byte_span_sum_plans, 0);
    }

    #[test]
    fn required_anchor_identity_binds_every_resource_bearing_configuration_field() {
        let base = required_anchor_plan_id(b"a", b"X", b"b", b"bc", None);
        for changed in [
            required_anchor_plan_id(b"d", b"X", b"b", b"bc", None),
            required_anchor_plan_id(b"a", b"Y", b"b", b"bc", None),
            required_anchor_plan_id(b"a", b"X", b"c", b"bc", None),
            required_anchor_plan_id(b"a", b"X", b"b", b"bd", None),
            required_anchor_plan_id(b"a", b"X", b"b", b"bc", Some((b'?', b"d"))),
            required_anchor_plan_id(b"a", b"X", b"b", b"bc", Some((b'!', b"d"))),
            required_anchor_plan_id(b"a", b"X", b"b", b"bc", Some((b'?', b"e"))),
        ] {
            assert_ne!(base, changed);
        }
    }
}
