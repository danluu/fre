//! Two ordered `LITERAL BYTE_CLASS+` alternatives reduced in one linear stream.
//!
//! Each literal is proved non-self-overlapping by the sufficient condition
//! that its first byte does not occur in its remainder. Consequently one
//! persistent `memmem::Finder::find_iter` per alternative enumerates every
//! literal occurrence without restarting searches. Merging the two monotone
//! occurrence streams, then greedily extending the selected byte class,
//! implements Rust's leftmost-first, non-overlapping whole-match semantics in
//! `O(N + Q)` time and constant operation space. `N` is the haystack length;
//! `Q` is retained literal bytes plus canonical class ranges.
//!
//! Prospective resource ledger: compiler analysis charges each HIR inspection
//! (1), fixed branch comparison (2 total), literal-byte/self-overlap comparison
//! (2 per byte), and canonical range inspection (1 per range) before it occurs,
//! bounded by `H + 2L + R + 2`. Construction never trusts an iterator length:
//! it charges before every `next`, validates each yielded range, and writes its
//! at-most-four bitmap words in that same single traversal. The fixed 64 units
//! and eight units per retained prefix byte are admitted before construction;
//! self-overlap comparisons, iterator traversals, six base units per yielded
//! range, range comparisons/state writes, and four units per touched bitmap
//! word are then charged before they occur. This also covers two exact
//! allocations and copies, both linear Finder
//! preprocessors, eight bitmap zero-writes, branches, and plan publication.
//! Thus construction is `O(L + R)`, never `O(L * R)` or `O(R^2)`. Persistent,
//! retained-capacity, and peak admission is `size_of(plan) + L`; construction
//! scratch, reserve slack, temporary copies, deduplication storage, UTF-8 or
//! boundary preprocessing, and data-dependent stack/queue storage are zero;
//! the fixed local frame is `O(1)` and covered by the 64-unit fixed term.
//! Execution admits `16N + 8Q + 64`, `N` match events, and `N` count before
//! iterator creation or haystack inspection; this covers both monotone
//! searches, every candidate read/branch/start comparison, membership
//! comparison, counter/cursor write, and count conversion. Execution
//! allocation, initialization, reserve, copy, deduplication, UTF-8/boundary
//! preprocessing, and growing stack/queue storage are zero; its two iterators,
//! two next-candidate slots, and scalar counters form an `O(1)` fixed frame.
//! Allocation failure is typed and never changes the selected route.
//!
//! The capture-aware uniform-participation operation has a distinct identity
//! and receipt. Before source access it reserves each complete Finder service
//! separately, all candidates and start arbitration, first-class probes,
//! greedy extension reads, results, checked participating output, complete
//! capture-schema events, zero operation allocations/bytes/scratch, and the
//! retained plan peak. Its actual receipt repeats every dimension and is
//! fieldwise checked against the prospective at runtime.
//!
//! rebar-row:imported/leipzig/huck-saw@rust/regex

#![allow(
    clippy::arithmetic_side_effects,
    reason = "all reducer arithmetic is preflight-bounded or checked; bitmap shifts use proved 0..=63 operands"
)]

use core::{fmt, mem::size_of, ops::Range};

use fre_exact_alloc::CopyError;
use memchr::memmem::{Finder, FinderBuilder};

use crate::{DirectBuildAttempt, DirectBuildAttemptActual, DirectBuildAttemptError};

pub const PLAN_ID: &str = "prefix-class-alternation.two-monotone-literal-streams.v1";
pub const COUNT_OPERATION_ID: &str = "prefix-class-alternation.count.unicode-off.v1";
pub const UNIFORM_PARTICIPATION_PLAN_ID: &str =
    "prefix-class-alternation.uniform-participation.two-finder.v1";
pub const UNIFORM_PARTICIPATION_OPERATION_ID: &str =
    "prefix-class-alternation.capture-participation.unicode-off.v1";
pub const UNIFORM_PARTICIPATION_ALGORITHM_VERSION: u32 = 1;
pub const UNIFORM_PARTICIPATION_ACCOUNTING_VERSION: u32 = 2;

const FIXED_BUILD_WORK: usize = 64;
const PREFIX_BUILD_WORK_PER_BYTE: usize = 8;
const RANGE_ITEM_BASE_WORK: usize = 6;
const BITMAP_WORK_PER_WORD: usize = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationIdentity {
    pub plan_id: &'static str,
    pub operation_id: &'static str,
    pub alternatives: usize,
    pub unicode: bool,
    pub non_overlapping: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildLimits {
    pub max_shape_units: usize,
    pub max_build_work: usize,
    pub max_scratch_bytes: usize,
    pub max_persistent_bytes: usize,
    pub max_peak_bytes: usize,
}

impl BuildLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_shape_units: usize::MAX,
            max_build_work: usize::MAX,
            max_scratch_bytes: usize::MAX,
            max_persistent_bytes: usize::MAX,
            max_peak_bytes: usize::MAX,
        }
    }
}

impl Default for BuildLimits {
    fn default() -> Self {
        Self {
            max_shape_units: 4 * 1024 * 1024,
            max_build_work: 32 * 1024 * 1024,
            max_scratch_bytes: 0,
            max_persistent_bytes: 32 * 1024 * 1024,
            max_peak_bytes: 32 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildAccounting {
    pub prefix_bytes: usize,
    pub class_ranges: usize,
    pub shape_units: usize,
    pub work_upper_bound: usize,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

/// Construction receipt exposed only by the distinct capture-aware operation.
/// The incumbent aggregate build accounting remains unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UniformParticipationBuildAccounting {
    pub prefix_bytes: usize,
    pub class_ranges: usize,
    pub shape_units: usize,
    pub work_upper_bound: usize,
    pub allocations: usize,
    pub copied_prefix_bytes: usize,
    pub finder_preprocess_input_bytes: usize,
    pub initialized_bitmap_bytes: usize,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub retained_capacity_bytes: usize,
    pub peak_bytes: usize,
}

/// Construction limits owned only by the direct capture-aware route. The
/// first five dimensions preserve the incumbent kernel's admission, while
/// the remaining dimensions close every direct construction side effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UniformParticipationBuildLimits {
    pub max_shape_units: usize,
    pub max_build_work: usize,
    pub max_scratch_bytes: usize,
    pub max_persistent_bytes: usize,
    pub max_peak_bytes: usize,
    pub max_allocations: usize,
    pub max_copied_prefix_bytes: usize,
    pub max_finder_preprocess_input_bytes: usize,
    pub max_initialized_bitmap_bytes: usize,
    pub max_retained_capacity_bytes: usize,
}

impl UniformParticipationBuildLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_shape_units: usize::MAX,
            max_build_work: usize::MAX,
            max_scratch_bytes: usize::MAX,
            max_persistent_bytes: usize::MAX,
            max_peak_bytes: usize::MAX,
            max_allocations: usize::MAX,
            max_copied_prefix_bytes: usize::MAX,
            max_finder_preprocess_input_bytes: usize::MAX,
            max_initialized_bitmap_bytes: usize::MAX,
            max_retained_capacity_bytes: usize::MAX,
        }
    }

    const fn kernel(self) -> BuildLimits {
        BuildLimits {
            max_shape_units: self.max_shape_units,
            max_build_work: self.max_build_work,
            max_scratch_bytes: self.max_scratch_bytes,
            max_persistent_bytes: self.max_persistent_bytes,
            max_peak_bytes: self.max_peak_bytes,
        }
    }
}

impl Default for UniformParticipationBuildLimits {
    fn default() -> Self {
        let kernel = BuildLimits::default();
        Self {
            max_shape_units: kernel.max_shape_units,
            max_build_work: kernel.max_build_work,
            max_scratch_bytes: kernel.max_scratch_bytes,
            max_persistent_bytes: kernel.max_persistent_bytes,
            max_peak_bytes: kernel.max_peak_bytes,
            max_allocations: 2,
            max_copied_prefix_bytes: 4 * 1024 * 1024,
            max_finder_preprocess_input_bytes: 4 * 1024 * 1024,
            max_initialized_bitmap_bytes: size_of::<[u64; 8]>(),
            max_retained_capacity_bytes: 32 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum UniformParticipationBuildError {
    Kernel(BuildError),
    AllocationsLimit { needed: usize, limit: usize },
    CopiedPrefixBytesLimit { needed: usize, limit: usize },
    FinderPreprocessInputBytesLimit { needed: usize, limit: usize },
    InitializedBitmapBytesLimit { needed: usize, limit: usize },
    RetainedCapacityBytesLimit { needed: usize, limit: usize },
    ArithmeticOverflow { computation: &'static str },
}

impl fmt::Display for UniformParticipationBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "prefix/class uniform-participation build failed: {self:?}"
        )
    }
}

impl std::error::Error for UniformParticipationBuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Kernel(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceLimits {
    pub max_work: usize,
    pub max_match_events: usize,
    pub max_count: u64,
    pub max_scratch_bytes: usize,
    pub max_peak_bytes: usize,
}

impl ReduceLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_work: usize::MAX,
            max_match_events: usize::MAX,
            max_count: u64::MAX,
            max_scratch_bytes: usize::MAX,
            max_peak_bytes: usize::MAX,
        }
    }
}

impl Default for ReduceLimits {
    fn default() -> Self {
        Self {
            max_work: 512 * 1024 * 1024,
            max_match_events: 64 * 1024 * 1024,
            max_count: 64 * 1024 * 1024,
            max_scratch_bytes: 0,
            max_peak_bytes: 32 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceUpperBounds {
    pub haystack_bytes: usize,
    pub shape_units: usize,
    pub work: usize,
    pub match_events: usize,
    pub count: u64,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceActualCounters {
    pub prefix_candidates: usize,
    pub class_bytes: usize,
    pub matches: usize,
    pub count: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceAccounting {
    pub identity: OperationIdentity,
    pub upper_bounds: ReduceUpperBounds,
    pub actual: ReduceActualCounters,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountResult {
    pub count: u64,
    pub accounting: ReduceAccounting,
}

/// Capture-aware identity for the direct uniform-participation operation.
///
/// This is deliberately distinct from [`OperationIdentity`]: whole-match
/// aggregate Count and capture participation have different outputs, ledgers,
/// and fallback contracts even when they share the immutable prefix/class
/// plan.
#[allow(
    clippy::struct_excessive_bools,
    reason = "orthogonal semantic flags are authenticated fields of the fixed-layout operation identity"
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UniformParticipationIdentity {
    pub plan_id: &'static str,
    pub operation_id: &'static str,
    pub algorithm_version: u32,
    pub accounting_version: u32,
    pub alternatives: usize,
    pub unicode: bool,
    pub case_insensitive: bool,
    pub ordered_branch_priority: bool,
    pub greedy_class: bool,
    pub non_overlapping: bool,
    pub participating_with_overall: usize,
    pub capture_schema_slots: usize,
}

/// Capture schema proved from the same canonical HIR as the prefix/class plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UniformParticipationSchema {
    /// Group zero plus the fixed number of participating user groups.
    pub participating_with_overall: usize,
    /// Group zero plus every user slot, including unmatched branch siblings.
    pub capture_schema_slots: usize,
}

/// Independent direct-operation limits. Every positive dimension is checked
/// before iterator creation or haystack inspection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UniformParticipationLimits {
    pub max_work: usize,
    pub max_first_finder_bytes: usize,
    pub max_second_finder_bytes: usize,
    pub max_prefix_candidates: usize,
    pub max_start_arbitrations: usize,
    pub max_first_class_probes: usize,
    pub max_greedy_extension_reads: usize,
    pub max_results: usize,
    pub max_capture_count: usize,
    pub max_capture_events: usize,
    pub max_operation_allocations: usize,
    pub max_operation_bytes: usize,
    pub max_scratch_bytes: usize,
    pub max_peak_bytes: usize,
}

impl UniformParticipationLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_work: usize::MAX,
            max_first_finder_bytes: usize::MAX,
            max_second_finder_bytes: usize::MAX,
            max_prefix_candidates: usize::MAX,
            max_start_arbitrations: usize::MAX,
            max_first_class_probes: usize::MAX,
            max_greedy_extension_reads: usize::MAX,
            max_results: usize::MAX,
            max_capture_count: usize::MAX,
            max_capture_events: usize::MAX,
            max_operation_allocations: usize::MAX,
            max_operation_bytes: usize::MAX,
            max_scratch_bytes: usize::MAX,
            max_peak_bytes: usize::MAX,
        }
    }
}

impl Default for UniformParticipationLimits {
    fn default() -> Self {
        Self {
            max_work: 512 * 1024 * 1024,
            max_first_finder_bytes: 64 * 1024 * 1024,
            max_second_finder_bytes: 64 * 1024 * 1024,
            max_prefix_candidates: 128 * 1024 * 1024,
            max_start_arbitrations: 256 * 1024 * 1024,
            max_first_class_probes: 128 * 1024 * 1024,
            max_greedy_extension_reads: 128 * 1024 * 1024,
            max_results: 64 * 1024 * 1024,
            max_capture_count: 128 * 1024 * 1024,
            max_capture_events: 192 * 1024 * 1024,
            max_operation_allocations: 0,
            max_operation_bytes: 0,
            max_scratch_bytes: 0,
            max_peak_bytes: 32 * 1024 * 1024,
        }
    }
}

/// Complete prospective ledger published before direct source access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UniformParticipationProspective {
    pub haystack_bytes: usize,
    pub shape_units: usize,
    pub minimum_match_bytes: usize,
    pub first_finder_bytes: usize,
    pub second_finder_bytes: usize,
    pub first_finder_candidates: usize,
    pub second_finder_candidates: usize,
    pub prefix_candidates: usize,
    pub start_arbitrations: usize,
    pub first_class_probes: usize,
    pub greedy_extension_reads: usize,
    pub results: usize,
    pub capture_count: usize,
    pub capture_events: usize,
    pub work: usize,
    pub operation_allocations: usize,
    pub operation_bytes: usize,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

impl UniformParticipationProspective {
    /// Verify every v2 direct accounting dimension against cumulative A.
    #[must_use]
    pub fn contains(&self, actual: &UniformParticipationActual) -> bool {
        uniform_actual_is_bounded(actual, self)
    }
}

/// Complete actual direct-operation ledger.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UniformParticipationActual {
    pub first_finder_bytes: usize,
    pub second_finder_bytes: usize,
    pub first_finder_candidates: usize,
    pub second_finder_candidates: usize,
    pub prefix_candidates: usize,
    pub start_arbitrations: usize,
    pub first_class_probes: usize,
    pub greedy_extension_reads: usize,
    pub results: usize,
    pub capture_count: usize,
    pub capture_events: usize,
    pub work: usize,
    pub operation_allocations: usize,
    pub operation_bytes: usize,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UniformParticipationAccounting {
    pub identity: UniformParticipationIdentity,
    pub prospective: UniformParticipationProspective,
    pub actual: UniformParticipationActual,
}

impl UniformParticipationAccounting {
    /// Verify that this successful P/A accounting closes the same attempt
    /// receipt without allocation.
    #[must_use]
    pub fn closes_receipt(&self, receipt: &UniformParticipationAttemptReceipt) -> bool {
        receipt.identity == self.identity
            && receipt.prospective == Some(self.prospective)
            && receipt.actual == self.actual
            && receipt.retains_bounded_actual()
    }
}

/// Exact invocation bound to one direct capture-participation attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UniformParticipationInvocation {
    pub haystack_bytes: usize,
    pub schema: UniformParticipationSchema,
    pub limits: UniformParticipationLimits,
}

/// Identity, invocation, published P and cumulative A for one direct attempt.
///
/// `prospective` is absent only before source-free prospective computation
/// completes. Once present, every terminal path retains it together with every
/// execution effect committed before the refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UniformParticipationAttemptReceipt {
    pub identity: UniformParticipationIdentity,
    pub invocation: UniformParticipationInvocation,
    pub prospective: Option<UniformParticipationProspective>,
    pub actual: UniformParticipationActual,
    pub actual_allocations: usize,
}

impl UniformParticipationAttemptReceipt {
    #[must_use]
    pub fn authenticates(
        &self,
        identity: UniformParticipationIdentity,
        invocation: UniformParticipationInvocation,
    ) -> bool {
        self.identity == identity && self.invocation == invocation
    }

    /// Verify the duplicated allocation count and every cumulative A<=P
    /// dimension without allocation.
    #[must_use]
    pub fn retains_bounded_actual(&self) -> bool {
        self.actual_allocations == self.actual.operation_allocations
            && self.prospective.map_or_else(
                || self.actual == UniformParticipationActual::default(),
                |prospective| prospective.contains(&self.actual),
            )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UniformParticipationResult {
    pub matches: usize,
    pub capture_count: usize,
    pub accounting: UniformParticipationAccounting,
}

/// Successful direct attempt and its complete authenticated receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UniformParticipationAttempt {
    pub result: UniformParticipationResult,
    pub receipt: UniformParticipationAttemptReceipt,
}

impl UniformParticipationAttempt {
    /// Verify exact identity/limits and the duplicated success accounting.
    #[must_use]
    pub fn authenticates(
        &self,
        identity: UniformParticipationIdentity,
        invocation: UniformParticipationInvocation,
    ) -> bool {
        self.receipt.authenticates(identity, invocation)
            && self.result.accounting.closes_receipt(&self.receipt)
            && self.result.matches == self.receipt.actual.results
            && self.result.capture_count == self.receipt.actual.capture_count
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum UniformParticipationError {
    InvalidSchema,
    WorkLimit {
        needed: usize,
        limit: usize,
    },
    FirstFinderBytesLimit {
        needed: usize,
        limit: usize,
    },
    SecondFinderBytesLimit {
        needed: usize,
        limit: usize,
    },
    PrefixCandidatesLimit {
        needed: usize,
        limit: usize,
    },
    StartArbitrationsLimit {
        needed: usize,
        limit: usize,
    },
    FirstClassProbesLimit {
        needed: usize,
        limit: usize,
    },
    GreedyExtensionReadsLimit {
        needed: usize,
        limit: usize,
    },
    ResultsLimit {
        needed: usize,
        limit: usize,
    },
    CaptureCountLimit {
        needed: usize,
        limit: usize,
    },
    CaptureEventsLimit {
        needed: usize,
        limit: usize,
    },
    OperationAllocationsLimit {
        needed: usize,
        limit: usize,
    },
    OperationBytesLimit {
        needed: usize,
        limit: usize,
    },
    ScratchLimit {
        needed: usize,
        limit: usize,
    },
    PeakLimit {
        needed: usize,
        limit: usize,
    },
    ActualEscapedProspective {
        dimension: &'static str,
        actual: usize,
        prospective: usize,
    },
    ReceiptInvariant {
        detail: &'static str,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
}

impl fmt::Display for UniformParticipationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "prefix/class uniform participation failed: {self:?}")
    }
}

impl std::error::Error for UniformParticipationError {}

/// Terminal direct refusal retaining P and every exact committed effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UniformParticipationAttemptError {
    pub source: UniformParticipationError,
    pub receipt: UniformParticipationAttemptReceipt,
}

impl fmt::Display for UniformParticipationAttemptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.source, formatter)
    }
}

impl std::error::Error for UniformParticipationAttemptError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BuildError {
    EmptyPrefix { alternative: usize },
    SelfOverlappingPrefix { alternative: usize },
    EmptyClass { alternative: usize },
    NonCanonicalClass { alternative: usize },
    ShapeLimit { needed: usize, limit: usize },
    WorkLimit { needed: usize, limit: usize },
    ScratchLimit { needed: usize, limit: usize },
    PersistentLimit { needed: usize, limit: usize },
    PeakLimit { needed: usize, limit: usize },
    AllocationFailed { alternative: usize, bytes: usize },
    ArithmeticOverflow { computation: &'static str },
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "prefix/class alternation build failed: {self:?}")
    }
}

impl std::error::Error for BuildError {}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ReduceError {
    WorkLimit { needed: usize, limit: usize },
    MatchEventsLimit { needed: usize, limit: usize },
    CountLimit { needed: u64, limit: u64 },
    ScratchLimit { needed: usize, limit: usize },
    PeakLimit { needed: usize, limit: usize },
    ArithmeticOverflow { computation: &'static str },
}

impl fmt::Display for ReduceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "prefix/class alternation reduction failed: {self:?}")
    }
}

impl std::error::Error for ReduceError {}

#[derive(Clone, Copy, Debug)]
struct ByteClass {
    words: [u64; 4],
}

impl ByteClass {
    const fn empty() -> Self {
        Self { words: [0; 4] }
    }

    fn insert_range(
        &mut self,
        start: u8,
        end: u8,
        work: &mut BuildWork<'_>,
    ) -> Result<(), BuildError> {
        let first_word = usize::from(start) >> 6;
        let last_word = usize::from(end) >> 6;
        for word in first_word..=last_word {
            // Covers the loop traversal, the two boundary comparisons and the
            // bitmap word write before any of them occurs. A byte range can
            // touch at most four words, so this remains O(1) per yielded range.
            work.charge(BITMAP_WORK_PER_WORD)?;
            let low = if word == first_word {
                u32::from(start) & 63
            } else {
                0
            };
            let high = if word == last_word {
                u32::from(end) & 63
            } else {
                63
            };
            self.words[word] |= u64::MAX << low & u64::MAX >> (63 - high);
        }
        Ok(())
    }

    fn contains(self, byte: u8) -> bool {
        let word = usize::from(byte) >> 6;
        let bit = u32::from(byte) & 63;
        self.words[word] & (1_u64 << bit) != 0
    }
}

#[derive(Debug)]
struct Alternative {
    finder: Finder<'static>,
    class: ByteClass,
}

#[derive(Debug)]
pub struct PrefixClassAlternationPlan {
    alternatives: [Alternative; 2],
    build: BuildAccounting,
}

impl PrefixClassAlternationPlan {
    /// Build the shared kernel under the capture-aware construction envelope.
    /// Every direct-only construction limit is checked before range traversal,
    /// allocation, copying, bitmap initialization, or Finder preprocessing.
    pub fn build_uniform_participation<I>(
        prefixes: [&[u8]; 2],
        ranges: [I; 2],
        limits: UniformParticipationBuildLimits,
    ) -> Result<Self, UniformParticipationBuildError>
    where
        I: Iterator<Item = (u8, u8)>,
    {
        Self::build_uniform_participation_attempt(prefixes, ranges, limits)
            .map(DirectBuildAttempt::into_plan)
            .map_err(DirectBuildAttemptError::into_source)
    }

    /// Build the uniform-participation route with exact observed effects.
    pub fn build_uniform_participation_attempt<I>(
        prefixes: [&[u8]; 2],
        ranges: [I; 2],
        limits: UniformParticipationBuildLimits,
    ) -> Result<DirectBuildAttempt<Self>, DirectBuildAttemptError<UniformParticipationBuildError>>
    where
        I: Iterator<Item = (u8, u8)>,
    {
        let prefix_bytes = prefixes[0].len().checked_add(prefixes[1].len()).ok_or(
            DirectBuildAttemptError::new(
                UniformParticipationBuildError::ArithmeticOverflow {
                    computation: "direct prefix byte total",
                },
                DirectBuildAttemptActual::default(),
            ),
        )?;
        let allocations = 2;
        let initialized_bitmap_bytes = size_of::<[u64; 8]>();
        if allocations > limits.max_allocations {
            return Err(DirectBuildAttemptError::new(
                UniformParticipationBuildError::AllocationsLimit {
                    needed: allocations,
                    limit: limits.max_allocations,
                },
                DirectBuildAttemptActual::default(),
            ));
        }
        if prefix_bytes > limits.max_copied_prefix_bytes {
            return Err(DirectBuildAttemptError::new(
                UniformParticipationBuildError::CopiedPrefixBytesLimit {
                    needed: prefix_bytes,
                    limit: limits.max_copied_prefix_bytes,
                },
                DirectBuildAttemptActual::default(),
            ));
        }
        if prefix_bytes > limits.max_finder_preprocess_input_bytes {
            return Err(DirectBuildAttemptError::new(
                UniformParticipationBuildError::FinderPreprocessInputBytesLimit {
                    needed: prefix_bytes,
                    limit: limits.max_finder_preprocess_input_bytes,
                },
                DirectBuildAttemptActual::default(),
            ));
        }
        if initialized_bitmap_bytes > limits.max_initialized_bitmap_bytes {
            return Err(DirectBuildAttemptError::new(
                UniformParticipationBuildError::InitializedBitmapBytesLimit {
                    needed: initialized_bitmap_bytes,
                    limit: limits.max_initialized_bitmap_bytes,
                },
                DirectBuildAttemptActual::default(),
            ));
        }
        if prefix_bytes > limits.max_retained_capacity_bytes {
            return Err(DirectBuildAttemptError::new(
                UniformParticipationBuildError::RetainedCapacityBytesLimit {
                    needed: prefix_bytes,
                    limit: limits.max_retained_capacity_bytes,
                },
                DirectBuildAttemptActual::default(),
            ));
        }
        match Self::build_attempt(prefixes, ranges, limits.kernel()) {
            Ok(attempt) => Ok(attempt),
            Err(error) => {
                let actual = error.actual();
                Err(DirectBuildAttemptError::new(
                    UniformParticipationBuildError::Kernel(error.into_source()),
                    actual,
                ))
            }
        }
    }

    #[allow(
        clippy::needless_range_loop,
        clippy::too_many_lines,
        reason = "the fixed two-alternative proof keeps admission, validation, exact allocation, and publication adjacent"
    )]
    pub fn build<I>(
        prefixes: [&[u8]; 2],
        ranges: [I; 2],
        limits: BuildLimits,
    ) -> Result<Self, BuildError>
    where
        I: Iterator<Item = (u8, u8)>,
    {
        Self::build_attempt(prefixes, ranges, limits)
            .map(DirectBuildAttempt::into_plan)
            .map_err(DirectBuildAttemptError::into_source)
    }

    /// Build two prefix/class alternatives with exact observed effects.
    #[allow(
        clippy::needless_range_loop,
        clippy::too_many_lines,
        reason = "the exact two-alternative attempt keeps validation, observed allocation, and publication adjacent"
    )]
    pub fn build_attempt<I>(
        prefixes: [&[u8]; 2],
        ranges: [I; 2],
        limits: BuildLimits,
    ) -> Result<DirectBuildAttempt<Self>, DirectBuildAttemptError<BuildError>>
    where
        I: Iterator<Item = (u8, u8)>,
    {
        let mut tracker = DirectBuildTracker::new();
        let result = (|| {
            let prefix_bytes = prefixes[0].len().checked_add(prefixes[1].len()).ok_or(
                BuildError::ArithmeticOverflow {
                    computation: "prefix byte total",
                },
            )?;
            let mut shape_units = prefix_bytes;
            let prefix_build_work = prefix_bytes
                .checked_mul(PREFIX_BUILD_WORK_PER_BYTE)
                .and_then(|work| work.checked_add(FIXED_BUILD_WORK))
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "fixed and prefix build work",
                })?;
            let persistent_bytes = size_of::<Self>().checked_add(prefix_bytes).ok_or(
                BuildError::ArithmeticOverflow {
                    computation: "persistent bytes",
                },
            )?;
            let scratch_bytes = 0;
            let peak_bytes = persistent_bytes;

            enforce_build(shape_units, limits.max_shape_units, BuildResource::Shape)?;
            enforce_build(
                scratch_bytes,
                limits.max_scratch_bytes,
                BuildResource::Scratch,
            )?;
            enforce_build(
                persistent_bytes,
                limits.max_persistent_bytes,
                BuildResource::Persistent,
            )?;
            enforce_build(peak_bytes, limits.max_peak_bytes, BuildResource::Peak)?;

            // This reservation precedes prefix validation, allocation, copying,
            // bitmap initialization and Finder preprocessing. Range-dependent work
            // is deliberately not guessed from `size_hint`/`ExactSizeIterator`.
            let mut work = BuildWork::new(limits.max_build_work, &mut tracker);
            work.charge(prefix_build_work)?;

            for alternative in 0..2 {
                let prefix = prefixes[alternative];
                if prefix.is_empty() {
                    return Err(BuildError::EmptyPrefix { alternative });
                }
                for &byte in &prefix[1..] {
                    work.charge(1)?;
                    if byte == prefix[0] {
                        return Err(BuildError::SelfOverlappingPrefix { alternative });
                    }
                }
            }

            let mut classes = [ByteClass::empty(); 2];
            let mut class_ranges = 0_usize;
            for (alternative, mut ranges) in ranges.into_iter().enumerate() {
                let mut previous_end = None;
                loop {
                    // Charge the traversal before calling user-supplied iterator
                    // code. This includes each yielded item and the terminal None.
                    work.charge(1)?;
                    let Some((start, end)) = ranges.next() else {
                        break;
                    };
                    // Covers accepting the yielded item, both range/shape counter
                    // writes, their checked arithmetic, the shape-limit comparison
                    // and the previous-range presence branch before processing it.
                    work.charge(RANGE_ITEM_BASE_WORK)?;
                    class_ranges =
                        class_ranges
                            .checked_add(1)
                            .ok_or(BuildError::ArithmeticOverflow {
                                computation: "class range total",
                            })?;
                    shape_units = prefix_bytes.checked_add(class_ranges).ok_or(
                        BuildError::ArithmeticOverflow {
                            computation: "shape units",
                        },
                    )?;
                    enforce_build(shape_units, limits.max_shape_units, BuildResource::Shape)?;

                    work.charge(1)?;
                    if start > end {
                        return Err(BuildError::NonCanonicalClass { alternative });
                    }
                    if let Some(previous) = previous_end {
                        work.charge(1)?;
                        if previous >= start {
                            return Err(BuildError::NonCanonicalClass { alternative });
                        }
                    }
                    work.charge(1)?;
                    previous_end = Some(end);
                    classes[alternative].insert_range(start, end, &mut work)?;
                }
                if previous_end.is_none() {
                    return Err(BuildError::EmptyClass { alternative });
                }
            }

            // Admission above covers both exact allocations, every copied byte,
            // both Finder preprocessors, and all eight zero-initialized bitmap
            // words before any of that work occurs.
            let first = copy_prefix(prefixes[0], 0)?;
            work.tracker.observe_prefix_copy(prefixes[0].len())?;
            let second = copy_prefix(prefixes[1], 1)?;
            work.tracker.observe_prefix_copy(prefixes[1].len())?;
            let work_used = work.used();
            let alternatives = [
                Alternative {
                    finder: FinderBuilder::new().build_forward_owned(first.into_boxed_slice()),
                    class: classes[0],
                },
                Alternative {
                    finder: FinderBuilder::new().build_forward_owned(second.into_boxed_slice()),
                    class: classes[1],
                },
            ];
            let plan = Self {
                alternatives,
                build: BuildAccounting {
                    prefix_bytes,
                    class_ranges,
                    shape_units,
                    work_upper_bound: work_used,
                    scratch_bytes,
                    persistent_bytes,
                    peak_bytes,
                },
            };
            tracker.publish(persistent_bytes)?;
            Ok(plan)
        })();
        match result {
            Ok(plan) => Ok(DirectBuildAttempt::new(plan, tracker.actual)),
            Err(source) => {
                tracker.actual.live_persistent_bytes = 0;
                Err(DirectBuildAttemptError::new(source, tracker.actual))
            }
        }
    }

    #[must_use]
    pub const fn build_accounting(&self) -> BuildAccounting {
        self.build
    }

    #[must_use]
    pub const fn uniform_participation_build_accounting(
        &self,
    ) -> UniformParticipationBuildAccounting {
        UniformParticipationBuildAccounting {
            prefix_bytes: self.build.prefix_bytes,
            class_ranges: self.build.class_ranges,
            shape_units: self.build.shape_units,
            work_upper_bound: self.build.work_upper_bound,
            allocations: 2,
            copied_prefix_bytes: self.build.prefix_bytes,
            finder_preprocess_input_bytes: self.build.prefix_bytes,
            initialized_bitmap_bytes: size_of::<[u64; 8]>(),
            scratch_bytes: self.build.scratch_bytes,
            persistent_bytes: self.build.persistent_bytes,
            retained_capacity_bytes: self.build.prefix_bytes,
            peak_bytes: self.build.peak_bytes,
        }
    }

    #[must_use]
    pub const fn count_identity(&self) -> OperationIdentity {
        OperationIdentity {
            plan_id: PLAN_ID,
            operation_id: COUNT_OPERATION_ID,
            alternatives: 2,
            unicode: false,
            non_overlapping: true,
        }
    }

    pub fn count(&self, haystack: &[u8], limits: ReduceLimits) -> Result<CountResult, ReduceError> {
        let upper_bounds = self.preflight(haystack.len(), limits)?;
        let actual = self.scan(haystack, upper_bounds, |_| {})?;
        Ok(CountResult {
            count: actual.count,
            accounting: ReduceAccounting {
                identity: self.count_identity(),
                upper_bounds,
                actual,
            },
        })
    }

    #[must_use]
    pub const fn uniform_participation_identity(
        &self,
        schema: UniformParticipationSchema,
    ) -> UniformParticipationIdentity {
        UniformParticipationIdentity {
            plan_id: UNIFORM_PARTICIPATION_PLAN_ID,
            operation_id: UNIFORM_PARTICIPATION_OPERATION_ID,
            algorithm_version: UNIFORM_PARTICIPATION_ALGORITHM_VERSION,
            accounting_version: UNIFORM_PARTICIPATION_ACCOUNTING_VERSION,
            alternatives: 2,
            unicode: false,
            case_insensitive: false,
            ordered_branch_priority: true,
            greedy_class: true,
            non_overlapping: true,
            participating_with_overall: schema.participating_with_overall,
            capture_schema_slots: schema.capture_schema_slots,
        }
    }

    /// Publish the complete direct capture-operation envelope without source
    /// access. Callers can use this for transactional owner-local admission.
    #[allow(
        clippy::too_many_lines,
        reason = "the source-free prospective keeps every checked v2 accounting formula adjacent before publication"
    )]
    pub fn uniform_participation_prospective(
        &self,
        haystack_len: usize,
        schema: UniformParticipationSchema,
    ) -> Result<UniformParticipationProspective, UniformParticipationError> {
        if schema.participating_with_overall == 0
            || schema.capture_schema_slots < schema.participating_with_overall
        {
            return Err(UniformParticipationError::InvalidSchema);
        }
        let first_finder_bytes = haystack_len;
        let second_finder_bytes = haystack_len;
        let first_finder_candidates = haystack_len;
        let second_finder_candidates = haystack_len;
        let prefix_candidates = first_finder_candidates
            .checked_add(second_finder_candidates)
            .ok_or(UniformParticipationError::ArithmeticOverflow {
                computation: "two complete prefix candidate streams",
            })?;
        let start_arbitrations =
            haystack_len
                .checked_mul(4)
                .ok_or(UniformParticipationError::ArithmeticOverflow {
                    computation: "candidate and selected-start arbitration",
                })?;
        let first_class_probes =
            haystack_len
                .checked_mul(2)
                .ok_or(UniformParticipationError::ArithmeticOverflow {
                    computation: "first-class probes",
                })?;
        let greedy_extension_reads =
            haystack_len
                .checked_mul(2)
                .ok_or(UniformParticipationError::ArithmeticOverflow {
                    computation: "greedy extension reads",
                })?;
        let minimum_match_bytes = self.alternatives[0]
            .finder
            .needle()
            .len()
            .min(self.alternatives[1].finder.needle().len())
            .checked_add(1)
            .ok_or(UniformParticipationError::ArithmeticOverflow {
                computation: "minimum positive match bytes",
            })?;
        let results = haystack_len
            .checked_div(minimum_match_bytes)
            .ok_or(UniformParticipationError::InvalidSchema)?;
        let capture_count = results
            .checked_mul(schema.participating_with_overall)
            .ok_or(UniformParticipationError::ArithmeticOverflow {
                computation: "prospective participating capture count",
            })?;
        let capture_events = results.checked_mul(schema.capture_schema_slots).ok_or(
            UniformParticipationError::ArithmeticOverflow {
                computation: "prospective capture schema events",
            },
        )?;
        let shape_work = self
            .build
            .shape_units
            .checked_mul(8)
            .and_then(|value| value.checked_add(64))
            .ok_or(UniformParticipationError::ArithmeticOverflow {
                computation: "uniform participation shape work",
            })?;
        let work = [
            first_finder_bytes,
            second_finder_bytes,
            prefix_candidates,
            start_arbitrations,
            first_class_probes,
            greedy_extension_reads,
            results,
            capture_count,
            capture_events,
            shape_work,
        ]
        .into_iter()
        .try_fold(0_usize, |sum, value| {
            sum.checked_add(value)
                .ok_or(UniformParticipationError::ArithmeticOverflow {
                    computation: "uniform participation total work",
                })
        })?;
        let operation_allocations = 0;
        let operation_bytes = 0;
        let scratch_bytes = 0;
        let persistent_bytes = self.build.persistent_bytes;
        let peak_bytes = persistent_bytes;

        Ok(UniformParticipationProspective {
            haystack_bytes: haystack_len,
            shape_units: self.build.shape_units,
            minimum_match_bytes,
            first_finder_bytes,
            second_finder_bytes,
            first_finder_candidates,
            second_finder_candidates,
            prefix_candidates,
            start_arbitrations,
            first_class_probes,
            greedy_extension_reads,
            results,
            capture_count,
            capture_events,
            work,
            operation_allocations,
            operation_bytes,
            scratch_bytes,
            persistent_bytes,
            peak_bytes,
        })
    }

    /// Enforce caller-owned limits against an already-published prospective.
    ///
    /// This is deliberately separate from prospective computation so a caller
    /// can retain P before any one-below refusal is returned.
    pub fn enforce_uniform_participation(
        &self,
        prospective: UniformParticipationProspective,
        limits: UniformParticipationLimits,
    ) -> Result<(), UniformParticipationError> {
        // Preserve reducer precedence independently of source-service limits.
        enforce_uniform(
            prospective.results,
            limits.max_results,
            UniformParticipationResource::Results,
        )?;
        enforce_uniform(
            prospective.capture_count,
            limits.max_capture_count,
            UniformParticipationResource::CaptureCount,
        )?;
        enforce_uniform(
            prospective.capture_events,
            limits.max_capture_events,
            UniformParticipationResource::CaptureEvents,
        )?;
        enforce_uniform(
            prospective.first_finder_bytes,
            limits.max_first_finder_bytes,
            UniformParticipationResource::FirstFinderBytes,
        )?;
        enforce_uniform(
            prospective.second_finder_bytes,
            limits.max_second_finder_bytes,
            UniformParticipationResource::SecondFinderBytes,
        )?;
        enforce_uniform(
            prospective.prefix_candidates,
            limits.max_prefix_candidates,
            UniformParticipationResource::PrefixCandidates,
        )?;
        enforce_uniform(
            prospective.start_arbitrations,
            limits.max_start_arbitrations,
            UniformParticipationResource::StartArbitrations,
        )?;
        enforce_uniform(
            prospective.first_class_probes,
            limits.max_first_class_probes,
            UniformParticipationResource::FirstClassProbes,
        )?;
        enforce_uniform(
            prospective.greedy_extension_reads,
            limits.max_greedy_extension_reads,
            UniformParticipationResource::GreedyExtensionReads,
        )?;
        enforce_uniform(
            prospective.work,
            limits.max_work,
            UniformParticipationResource::Work,
        )?;
        enforce_uniform(
            prospective.operation_allocations,
            limits.max_operation_allocations,
            UniformParticipationResource::OperationAllocations,
        )?;
        enforce_uniform(
            prospective.operation_bytes,
            limits.max_operation_bytes,
            UniformParticipationResource::OperationBytes,
        )?;
        enforce_uniform(
            prospective.scratch_bytes,
            limits.max_scratch_bytes,
            UniformParticipationResource::Scratch,
        )?;
        enforce_uniform(
            prospective.peak_bytes,
            limits.max_peak_bytes,
            UniformParticipationResource::Peak,
        )?;
        Ok(())
    }

    /// Construct the source-free attempt receipt before prospective
    /// publication. The returned A and allocation count are both exactly zero.
    #[must_use]
    pub const fn uniform_participation_attempt_receipt(
        &self,
        haystack_bytes: usize,
        schema: UniformParticipationSchema,
        limits: UniformParticipationLimits,
    ) -> UniformParticipationAttemptReceipt {
        UniformParticipationAttemptReceipt {
            identity: self.uniform_participation_identity(schema),
            invocation: UniformParticipationInvocation {
                haystack_bytes,
                schema,
                limits,
            },
            prospective: None,
            actual: UniformParticipationActual {
                first_finder_bytes: 0,
                second_finder_bytes: 0,
                first_finder_candidates: 0,
                second_finder_candidates: 0,
                prefix_candidates: 0,
                start_arbitrations: 0,
                first_class_probes: 0,
                greedy_extension_reads: 0,
                results: 0,
                capture_count: 0,
                capture_events: 0,
                work: 0,
                operation_allocations: 0,
                operation_bytes: 0,
                scratch_bytes: 0,
                persistent_bytes: 0,
                peak_bytes: 0,
            },
            actual_allocations: 0,
        }
    }

    /// Count fixed capture participation using the direct prefix/class route.
    ///
    /// Preflight completes before either Finder iterator is created. Any
    /// failure after that publication is terminal and never invokes another
    /// route.
    pub fn count_uniform_participation(
        &self,
        haystack: &[u8],
        schema: UniformParticipationSchema,
        limits: UniformParticipationLimits,
    ) -> Result<UniformParticipationResult, UniformParticipationError> {
        self.count_uniform_participation_attempt(haystack, schema, limits)
            .map(|attempt| attempt.result)
            .map_err(|error| error.source)
    }

    /// Count while retaining exact P/A and successful allocation count on
    /// every terminal path.
    #[allow(
        clippy::result_large_err,
        reason = "the fixed-layout terminal receipt deliberately preserves complete direct P/A without allocating"
    )]
    pub fn count_uniform_participation_attempt(
        &self,
        haystack: &[u8],
        schema: UniformParticipationSchema,
        limits: UniformParticipationLimits,
    ) -> Result<UniformParticipationAttempt, UniformParticipationAttemptError> {
        let mut receipt =
            self.uniform_participation_attempt_receipt(haystack.len(), schema, limits);
        let identity = receipt.identity;
        let invocation = receipt.invocation;
        let prospective = self
            .uniform_participation_prospective(haystack.len(), schema)
            .map_err(|source| uniform_attempt_error(source, receipt, identity, invocation))?;
        receipt.prospective = Some(prospective);
        self.enforce_uniform_participation(prospective, limits)
            .map_err(|source| uniform_attempt_error(source, receipt, identity, invocation))?;
        let matches = match self.scan_uniform_participation(
            haystack,
            schema,
            prospective,
            &mut receipt,
            |_| Ok(()),
        ) {
            Ok(matches) => matches,
            Err(source) => {
                return Err(uniform_attempt_error(source, receipt, identity, invocation));
            }
        };
        let result = UniformParticipationResult {
            matches,
            capture_count: receipt.actual.capture_count,
            accounting: UniformParticipationAccounting {
                identity: receipt.identity,
                prospective,
                actual: receipt.actual,
            },
        };
        let attempt = UniformParticipationAttempt { result, receipt };
        if !attempt.authenticates(identity, invocation) {
            return Err(UniformParticipationAttemptError {
                source: UniformParticipationError::ReceiptInvariant {
                    detail: "successful direct attempt did not close identity/invocation/P/A",
                },
                receipt,
            });
        }
        Ok(attempt)
    }

    #[allow(
        clippy::needless_range_loop,
        clippy::too_many_lines,
        reason = "the fixed two-stream scan keeps each source read and its checked direct-operation counter adjacent"
    )]
    fn scan_uniform_participation(
        &self,
        haystack: &[u8],
        schema: UniformParticipationSchema,
        prospective: UniformParticipationProspective,
        receipt: &mut UniformParticipationAttemptReceipt,
        mut emit: impl FnMut(Range<usize>) -> Result<(), UniformParticipationError>,
    ) -> Result<usize, UniformParticipationError> {
        let actual = &mut receipt.actual;
        let shape_work = prospective
            .shape_units
            .checked_mul(8)
            .and_then(|value| value.checked_add(64))
            .ok_or(UniformParticipationError::ArithmeticOverflow {
                computation: "actual direct shape work",
            })?;
        actual.work = shape_work;
        actual.persistent_bytes = self.build.persistent_bytes;
        actual.peak_bytes = self.build.persistent_bytes;

        let mut streams = [
            self.alternatives[0].finder.find_iter(haystack),
            self.alternatives[1].finder.find_iter(haystack),
        ];
        actual.first_finder_bytes = haystack.len();
        uniform_actual_add(
            &mut actual.work,
            haystack.len(),
            "actual first Finder service work",
        )?;
        let first = streams[0].next();
        uniform_account_candidate(actual, 0, first.is_some())?;
        actual.second_finder_bytes = haystack.len();
        uniform_actual_add(
            &mut actual.work,
            haystack.len(),
            "actual second Finder service work",
        )?;
        let second = streams[1].next();
        uniform_account_candidate(actual, 1, second.is_some())?;
        let mut next = [first, second];
        let mut cursor = 0_usize;
        loop {
            for alternative in 0..2 {
                while next[alternative].is_some_and(|start| start < cursor) {
                    next[alternative] = streams[alternative].next();
                    uniform_account_candidate(actual, alternative, next[alternative].is_some())?;
                }
            }
            let alternative = match (next[0], next[1]) {
                (None, None) => break,
                (Some(_), None) => 0,
                (None, Some(_)) => 1,
                // Alternative zero wins an equal-start tie.
                (Some(left), Some(right)) => usize::from(right < left),
            };
            let start = next[alternative].ok_or(UniformParticipationError::ArithmeticOverflow {
                computation: "selected direct prefix candidate",
            })?;
            uniform_actual_add(
                &mut actual.start_arbitrations,
                1,
                "selected direct prefix candidates",
            )?;
            uniform_actual_add(&mut actual.work, 1, "selected direct prefix candidate work")?;
            next[alternative] = streams[alternative].next();
            uniform_account_candidate(actual, alternative, next[alternative].is_some())?;
            let prefix_end = start
                .checked_add(self.alternatives[alternative].finder.needle().len())
                .ok_or(UniformParticipationError::ArithmeticOverflow {
                    computation: "direct prefix end",
                })?;
            let Some(&first_class_byte) = haystack.get(prefix_end) else {
                continue;
            };
            uniform_actual_add(
                &mut actual.first_class_probes,
                1,
                "actual first-class probes",
            )?;
            uniform_actual_add(&mut actual.work, 1, "actual first-class probe work")?;
            if !self.alternatives[alternative]
                .class
                .contains(first_class_byte)
            {
                continue;
            }
            let mut end =
                prefix_end
                    .checked_add(1)
                    .ok_or(UniformParticipationError::ArithmeticOverflow {
                        computation: "direct first class byte end",
                    })?;
            while let Some(&byte) = haystack.get(end) {
                uniform_actual_add(
                    &mut actual.greedy_extension_reads,
                    1,
                    "actual greedy extension reads",
                )?;
                uniform_actual_add(&mut actual.work, 1, "actual greedy extension read work")?;
                if !self.alternatives[alternative].class.contains(byte) {
                    break;
                }
                end = end
                    .checked_add(1)
                    .ok_or(UniformParticipationError::ArithmeticOverflow {
                        computation: "direct greedy class end",
                    })?;
            }
            uniform_actual_add(&mut actual.results, 1, "direct match count")?;
            uniform_actual_add(&mut actual.work, 1, "direct result work")?;
            uniform_actual_add(
                &mut actual.capture_count,
                schema.participating_with_overall,
                "actual participating capture count",
            )?;
            uniform_actual_add(
                &mut actual.work,
                schema.participating_with_overall,
                "actual participating capture work",
            )?;
            uniform_actual_add(
                &mut actual.capture_events,
                schema.capture_schema_slots,
                "actual capture schema events",
            )?;
            uniform_actual_add(
                &mut actual.work,
                schema.capture_schema_slots,
                "actual capture schema work",
            )?;
            emit(start..end)?;
            #[cfg(test)]
            if uniform_scan_fault::take_after_result(actual.results) {
                return Err(UniformParticipationError::ArithmeticOverflow {
                    computation: "injected post-source terminal",
                });
            }
            cursor = end;
        }
        receipt.actual_allocations = actual.operation_allocations;
        ensure_uniform_actual(actual, &prospective)?;
        Ok(actual.results)
    }

    fn preflight(
        &self,
        haystack_len: usize,
        limits: ReduceLimits,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        let work = haystack_len
            .checked_mul(16)
            .and_then(|work| {
                self.build
                    .shape_units
                    .checked_mul(8)
                    .and_then(|shape| work.checked_add(shape))
            })
            .and_then(|work| work.checked_add(64))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "16N + 8Q + 64 work bound",
            })?;
        let match_events = haystack_len;
        let count = u64::try_from(match_events).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "match event bound as u64",
        })?;
        let scratch_bytes = 0;
        let peak_bytes = self.build.persistent_bytes;
        enforce_reduce(work, limits.max_work, ReduceResource::Work)?;
        enforce_reduce(
            match_events,
            limits.max_match_events,
            ReduceResource::MatchEvents,
        )?;
        if count > limits.max_count {
            return Err(ReduceError::CountLimit {
                needed: count,
                limit: limits.max_count,
            });
        }
        enforce_reduce(
            scratch_bytes,
            limits.max_scratch_bytes,
            ReduceResource::Scratch,
        )?;
        enforce_reduce(peak_bytes, limits.max_peak_bytes, ReduceResource::Peak)?;
        Ok(ReduceUpperBounds {
            haystack_bytes: haystack_len,
            shape_units: self.build.shape_units,
            work,
            match_events,
            count,
            scratch_bytes,
            persistent_bytes: self.build.persistent_bytes,
            peak_bytes,
        })
    }

    #[allow(
        clippy::needless_range_loop,
        reason = "numeric indices preserve stable alternative priority across paired iterator and candidate arrays"
    )]
    fn scan(
        &self,
        haystack: &[u8],
        upper: ReduceUpperBounds,
        mut emit: impl FnMut(Range<usize>),
    ) -> Result<ReduceActualCounters, ReduceError> {
        let mut streams = [
            self.alternatives[0].finder.find_iter(haystack),
            self.alternatives[1].finder.find_iter(haystack),
        ];
        let mut next = [streams[0].next(), streams[1].next()];
        let mut cursor = 0_usize;
        let mut prefix_candidates = 0_usize;
        let mut class_bytes = 0_usize;
        let mut matches = 0_usize;
        loop {
            for alternative in 0..2 {
                while next[alternative].is_some_and(|start| start < cursor) {
                    next[alternative] = streams[alternative].next();
                }
            }
            let alternative = match (next[0], next[1]) {
                (None, None) => break,
                (Some(_), None) => 0,
                (None, Some(_)) => 1,
                (Some(left), Some(right)) => usize::from(right < left),
            };
            let start = next[alternative].ok_or(ReduceError::ArithmeticOverflow {
                computation: "selected prefix candidate",
            })?;
            next[alternative] = streams[alternative].next();
            prefix_candidates =
                prefix_candidates
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "prefix candidate count",
                    })?;
            let prefix_end = start
                .checked_add(self.alternatives[alternative].finder.needle().len())
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "prefix end",
                })?;
            let Some(&first_class_byte) = haystack.get(prefix_end) else {
                continue;
            };
            class_bytes = class_bytes
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "class byte count",
                })?;
            if !self.alternatives[alternative]
                .class
                .contains(first_class_byte)
            {
                continue;
            }
            let mut end = prefix_end
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "first class byte end",
                })?;
            while let Some(&byte) = haystack.get(end) {
                class_bytes =
                    class_bytes
                        .checked_add(1)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "class byte count",
                        })?;
                if !self.alternatives[alternative].class.contains(byte) {
                    break;
                }
                end = end.checked_add(1).ok_or(ReduceError::ArithmeticOverflow {
                    computation: "greedy class end",
                })?;
            }
            emit(start..end);
            matches = matches
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "match count",
                })?;
            cursor = end;
        }
        let count = u64::try_from(matches).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "actual count as u64",
        })?;
        debug_assert!(matches <= upper.match_events);
        Ok(ReduceActualCounters {
            prefix_candidates,
            class_bytes,
            matches,
            count,
        })
    }
}

fn copy_prefix(prefix: &[u8], alternative: usize) -> Result<Vec<u8>, BuildError> {
    fre_exact_alloc::copy_exact(prefix).map_err(|error| match error {
        CopyError::LayoutOverflow => BuildError::ArithmeticOverflow {
            computation: "exact prefix allocation layout",
        },
        CopyError::AllocationFailed => BuildError::AllocationFailed {
            alternative,
            bytes: prefix.len(),
        },
    })
}

#[derive(Clone, Copy, Debug)]
struct DirectBuildTracker {
    actual: DirectBuildAttemptActual,
    live_unpublished_bytes: usize,
}

impl DirectBuildTracker {
    const fn new() -> Self {
        Self {
            actual: DirectBuildAttemptActual {
                work: 0,
                allocations: 0,
                allocated_bytes: 0,
                copied_bytes: 0,
                initialized_bytes: 0,
                live_persistent_bytes: 0,
                peak_bytes: 0,
            },
            live_unpublished_bytes: 0,
        }
    }

    fn observe_prefix_copy(&mut self, bytes: usize) -> Result<(), BuildError> {
        self.actual.allocations =
            self.actual
                .allocations
                .checked_add(1)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "actual prefix allocation count",
                })?;
        self.actual.allocated_bytes = self.actual.allocated_bytes.checked_add(bytes).ok_or(
            BuildError::ArithmeticOverflow {
                computation: "cumulative prefix allocated bytes",
            },
        )?;
        self.actual.copied_bytes =
            self.actual
                .copied_bytes
                .checked_add(bytes)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "actual copied prefix bytes",
                })?;
        self.actual.initialized_bytes = self.actual.initialized_bytes.checked_add(bytes).ok_or(
            BuildError::ArithmeticOverflow {
                computation: "actual initialized prefix bytes",
            },
        )?;
        self.live_unpublished_bytes = self.live_unpublished_bytes.checked_add(bytes).ok_or(
            BuildError::ArithmeticOverflow {
                computation: "live unpublished prefix bytes",
            },
        )?;
        self.actual.peak_bytes = self.actual.peak_bytes.max(self.live_unpublished_bytes);
        Ok(())
    }

    fn publish(&mut self, persistent_bytes: usize) -> Result<(), BuildError> {
        self.actual.initialized_bytes = self
            .actual
            .initialized_bytes
            .checked_add(size_of::<PrefixClassAlternationPlan>())
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "published prefix plan inline initialized bytes",
            })?;
        self.actual.live_persistent_bytes = persistent_bytes;
        self.actual.peak_bytes = self.actual.peak_bytes.max(persistent_bytes);
        Ok(())
    }
}

#[derive(Debug)]
struct BuildWork<'a> {
    used: usize,
    limit: usize,
    tracker: &'a mut DirectBuildTracker,
}

impl<'a> BuildWork<'a> {
    const fn new(limit: usize, tracker: &'a mut DirectBuildTracker) -> Self {
        Self {
            used: 0,
            limit,
            tracker,
        }
    }

    fn charge(&mut self, units: usize) -> Result<(), BuildError> {
        let needed = self
            .used
            .checked_add(units)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "charged build work",
            })?;
        if needed > self.limit {
            return Err(BuildError::WorkLimit {
                needed,
                limit: self.limit,
            });
        }
        self.used = needed;
        self.tracker.actual.work =
            u64::try_from(needed).map_err(|_| BuildError::ArithmeticOverflow {
                computation: "actual prefix build work as u64",
            })?;
        Ok(())
    }

    const fn used(self) -> usize {
        self.used
    }
}

#[derive(Clone, Copy)]
enum BuildResource {
    Shape,
    Scratch,
    Persistent,
    Peak,
}

fn enforce_build(needed: usize, limit: usize, resource: BuildResource) -> Result<(), BuildError> {
    if needed <= limit {
        return Ok(());
    }
    Err(match resource {
        BuildResource::Shape => BuildError::ShapeLimit { needed, limit },
        BuildResource::Scratch => BuildError::ScratchLimit { needed, limit },
        BuildResource::Persistent => BuildError::PersistentLimit { needed, limit },
        BuildResource::Peak => BuildError::PeakLimit { needed, limit },
    })
}

#[derive(Clone, Copy)]
enum ReduceResource {
    Work,
    MatchEvents,
    Scratch,
    Peak,
}

fn enforce_reduce(
    needed: usize,
    limit: usize,
    resource: ReduceResource,
) -> Result<(), ReduceError> {
    if needed <= limit {
        return Ok(());
    }
    Err(match resource {
        ReduceResource::Work => ReduceError::WorkLimit { needed, limit },
        ReduceResource::MatchEvents => ReduceError::MatchEventsLimit { needed, limit },
        ReduceResource::Scratch => ReduceError::ScratchLimit { needed, limit },
        ReduceResource::Peak => ReduceError::PeakLimit { needed, limit },
    })
}

#[derive(Clone, Copy)]
enum UniformParticipationResource {
    Work,
    FirstFinderBytes,
    SecondFinderBytes,
    PrefixCandidates,
    StartArbitrations,
    FirstClassProbes,
    GreedyExtensionReads,
    Results,
    CaptureCount,
    CaptureEvents,
    OperationAllocations,
    OperationBytes,
    Scratch,
    Peak,
}

fn enforce_uniform(
    needed: usize,
    limit: usize,
    resource: UniformParticipationResource,
) -> Result<(), UniformParticipationError> {
    if needed <= limit {
        return Ok(());
    }
    Err(match resource {
        UniformParticipationResource::Work => {
            UniformParticipationError::WorkLimit { needed, limit }
        }
        UniformParticipationResource::FirstFinderBytes => {
            UniformParticipationError::FirstFinderBytesLimit { needed, limit }
        }
        UniformParticipationResource::SecondFinderBytes => {
            UniformParticipationError::SecondFinderBytesLimit { needed, limit }
        }
        UniformParticipationResource::PrefixCandidates => {
            UniformParticipationError::PrefixCandidatesLimit { needed, limit }
        }
        UniformParticipationResource::StartArbitrations => {
            UniformParticipationError::StartArbitrationsLimit { needed, limit }
        }
        UniformParticipationResource::FirstClassProbes => {
            UniformParticipationError::FirstClassProbesLimit { needed, limit }
        }
        UniformParticipationResource::GreedyExtensionReads => {
            UniformParticipationError::GreedyExtensionReadsLimit { needed, limit }
        }
        UniformParticipationResource::Results => {
            UniformParticipationError::ResultsLimit { needed, limit }
        }
        UniformParticipationResource::CaptureCount => {
            UniformParticipationError::CaptureCountLimit { needed, limit }
        }
        UniformParticipationResource::CaptureEvents => {
            UniformParticipationError::CaptureEventsLimit { needed, limit }
        }
        UniformParticipationResource::OperationAllocations => {
            UniformParticipationError::OperationAllocationsLimit { needed, limit }
        }
        UniformParticipationResource::OperationBytes => {
            UniformParticipationError::OperationBytesLimit { needed, limit }
        }
        UniformParticipationResource::Scratch => {
            UniformParticipationError::ScratchLimit { needed, limit }
        }
        UniformParticipationResource::Peak => {
            UniformParticipationError::PeakLimit { needed, limit }
        }
    })
}

fn uniform_actual_add(
    counter: &mut usize,
    amount: usize,
    computation: &'static str,
) -> Result<(), UniformParticipationError> {
    *counter = counter
        .checked_add(amount)
        .ok_or(UniformParticipationError::ArithmeticOverflow { computation })?;
    Ok(())
}

fn uniform_account_candidate(
    actual: &mut UniformParticipationActual,
    alternative: usize,
    present: bool,
) -> Result<(), UniformParticipationError> {
    if !present {
        return Ok(());
    }
    let candidate_counter = if alternative == 0 {
        &mut actual.first_finder_candidates
    } else {
        &mut actual.second_finder_candidates
    };
    uniform_actual_add(candidate_counter, 1, "actual Finder candidates")?;
    uniform_actual_add(
        &mut actual.prefix_candidates,
        1,
        "actual prefix candidate total",
    )?;
    uniform_actual_add(
        &mut actual.start_arbitrations,
        1,
        "actual candidate arbitration total",
    )?;
    uniform_actual_add(&mut actual.work, 2, "actual candidate service work")
}

fn uniform_actual_is_bounded(
    actual: &UniformParticipationActual,
    prospective: &UniformParticipationProspective,
) -> bool {
    ensure_uniform_actual(actual, prospective).is_ok()
}

#[allow(
    clippy::large_types_passed_by_value,
    reason = "the Copy receipt is moved into the terminal error as one immutable fixed-layout snapshot"
)]
fn uniform_attempt_error(
    source: UniformParticipationError,
    receipt: UniformParticipationAttemptReceipt,
    identity: UniformParticipationIdentity,
    invocation: UniformParticipationInvocation,
) -> UniformParticipationAttemptError {
    let source = if receipt.authenticates(identity, invocation) && receipt.retains_bounded_actual()
    {
        source
    } else {
        UniformParticipationError::ReceiptInvariant {
            detail: "terminal direct attempt did not retain exact identity/invocation/P/A",
        }
    };
    UniformParticipationAttemptError { source, receipt }
}

fn ensure_uniform_actual(
    actual: &UniformParticipationActual,
    prospective: &UniformParticipationProspective,
) -> Result<(), UniformParticipationError> {
    for (dimension, actual, prospective) in [
        (
            "first finder bytes",
            actual.first_finder_bytes,
            prospective.first_finder_bytes,
        ),
        (
            "second finder bytes",
            actual.second_finder_bytes,
            prospective.second_finder_bytes,
        ),
        (
            "first finder candidates",
            actual.first_finder_candidates,
            prospective.first_finder_candidates,
        ),
        (
            "second finder candidates",
            actual.second_finder_candidates,
            prospective.second_finder_candidates,
        ),
        (
            "prefix candidates",
            actual.prefix_candidates,
            prospective.prefix_candidates,
        ),
        (
            "start arbitrations",
            actual.start_arbitrations,
            prospective.start_arbitrations,
        ),
        (
            "first class probes",
            actual.first_class_probes,
            prospective.first_class_probes,
        ),
        (
            "greedy extension reads",
            actual.greedy_extension_reads,
            prospective.greedy_extension_reads,
        ),
        ("results", actual.results, prospective.results),
        (
            "capture count",
            actual.capture_count,
            prospective.capture_count,
        ),
        (
            "capture events",
            actual.capture_events,
            prospective.capture_events,
        ),
        ("work", actual.work, prospective.work),
        (
            "operation allocations",
            actual.operation_allocations,
            prospective.operation_allocations,
        ),
        (
            "operation bytes",
            actual.operation_bytes,
            prospective.operation_bytes,
        ),
        (
            "scratch bytes",
            actual.scratch_bytes,
            prospective.scratch_bytes,
        ),
        (
            "persistent bytes",
            actual.persistent_bytes,
            prospective.persistent_bytes,
        ),
        ("peak bytes", actual.peak_bytes, prospective.peak_bytes),
    ] {
        if actual > prospective {
            return Err(UniformParticipationError::ActualEscapedProspective {
                dimension,
                actual,
                prospective,
            });
        }
    }
    if actual
        .first_finder_candidates
        .checked_add(actual.second_finder_candidates)
        != Some(actual.prefix_candidates)
    {
        return Err(UniformParticipationError::ReceiptInvariant {
            detail: "per-stream candidate A does not sum to aggregate candidate A",
        });
    }
    Ok(())
}

#[cfg(test)]
mod uniform_scan_fault {
    use std::cell::Cell;

    std::thread_local! {
        static AFTER_RESULT: Cell<Option<usize>> = const { Cell::new(None) };
    }

    pub(super) fn arm(after_result: usize) {
        AFTER_RESULT.with(|armed| armed.set(Some(after_result)));
    }

    pub(super) fn take_after_result(results: usize) -> bool {
        AFTER_RESULT.with(|armed| {
            if armed.get() == Some(results) {
                armed.set(None);
                true
            } else {
                false
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, rc::Rc};

    use regex::bytes::RegexBuilder;

    use super::*;

    fn plan() -> PrefixClassAlternationPlan {
        PrefixClassAlternationPlan::build(
            [b"ab", b"xy"],
            [[(b'a', b'z')].into_iter(), [(b'0', b'9')].into_iter()],
            BuildLimits::unlimited(),
        )
        .unwrap()
    }

    #[test]
    fn build_attempt_reports_exact_success_and_partial_validation_failure() {
        let attempt = PrefixClassAlternationPlan::build_attempt(
            [b"ab", b"xy"],
            [[(b'a', b'z')].into_iter(), [(b'0', b'9')].into_iter()],
            BuildLimits::unlimited(),
        )
        .unwrap();
        let actual = attempt.actual();
        let plan = attempt.into_plan();
        let build = plan.build_accounting();
        assert_eq!(actual.work, u64::try_from(build.work_upper_bound).unwrap());
        assert_eq!(actual.allocations, 2);
        assert_eq!(actual.allocated_bytes, build.prefix_bytes);
        assert_eq!(actual.copied_bytes, build.prefix_bytes);
        assert_eq!(actual.initialized_bytes, build.persistent_bytes);
        assert_eq!(actual.live_persistent_bytes, build.persistent_bytes);
        assert_eq!(actual.peak_bytes, build.persistent_bytes);

        let failure = PrefixClassAlternationPlan::build_attempt(
            [b"ab", b"xy"],
            [[(b'z', b'a')].into_iter(), [(b'0', b'9')].into_iter()],
            BuildLimits::unlimited(),
        )
        .unwrap_err();
        assert!(matches!(
            failure.source(),
            BuildError::NonCanonicalClass { alternative: 0 }
        ));
        let partial = failure.actual();
        let expected_work =
            4 * PREFIX_BUILD_WORK_PER_BYTE + FIXED_BUILD_WORK + 2 + 1 + RANGE_ITEM_BASE_WORK + 1;
        assert_eq!(partial.work, u64::try_from(expected_work).unwrap());
        assert_eq!(partial.allocations, 0);
        assert_eq!(partial.allocated_bytes, 0);
        assert_eq!(partial.copied_bytes, 0);
        assert_eq!(partial.initialized_bytes, 0);
        assert_eq!(partial.live_persistent_bytes, 0);
        assert_eq!(partial.peak_bytes, 0);
    }

    fn sut_spans(plan: &PrefixClassAlternationPlan, haystack: &[u8]) -> Vec<Range<usize>> {
        let upper = plan
            .preflight(haystack.len(), ReduceLimits::unlimited())
            .unwrap();
        let mut spans = Vec::new();
        plan.scan(haystack, upper, |span| spans.push(span)).unwrap();
        spans
    }

    fn reference_spans(pattern: &str, haystack: &[u8]) -> Vec<Range<usize>> {
        RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap()
            .find_iter(haystack)
            .map(|matched| matched.start()..matched.end())
            .collect()
    }

    fn rust_functions_plan() -> PrefixClassAlternationPlan {
        let word = [(b'0', b'9'), (b'A', b'Z'), (b'_', b'_'), (b'a', b'z')];
        PrefixClassAlternationPlan::build_uniform_participation(
            [b"fn is_", b"fn as_"],
            [word.into_iter(), word.into_iter()],
            UniformParticipationBuildLimits::unlimited(),
        )
        .unwrap()
    }

    const fn rust_functions_schema() -> UniformParticipationSchema {
        UniformParticipationSchema {
            participating_with_overall: 2,
            capture_schema_slots: 3,
        }
    }

    fn exact_uniform_limits(
        prospective: UniformParticipationProspective,
    ) -> UniformParticipationLimits {
        UniformParticipationLimits {
            max_work: prospective.work,
            max_first_finder_bytes: prospective.first_finder_bytes,
            max_second_finder_bytes: prospective.second_finder_bytes,
            max_prefix_candidates: prospective.prefix_candidates,
            max_start_arbitrations: prospective.start_arbitrations,
            max_first_class_probes: prospective.first_class_probes,
            max_greedy_extension_reads: prospective.greedy_extension_reads,
            max_results: prospective.results,
            max_capture_count: prospective.capture_count,
            max_capture_events: prospective.capture_events,
            max_operation_allocations: prospective.operation_allocations,
            max_operation_bytes: prospective.operation_bytes,
            max_scratch_bytes: prospective.scratch_bytes,
            max_peak_bytes: prospective.peak_bytes,
        }
    }

    #[test]
    fn rust_functions_uniform_participation_matches_complete_reference_spans() {
        let plan = rust_functions_plan();
        let pattern = r"fn is_(\w+)|fn as_(\w+)";
        for haystack in [
            b"".as_slice(),
            b"fn is_alpha fn as_beta",
            b"fn is_ fn as_",
            b"fn as_9fn is_Z",
            b"fn is_a\x00fn as_b\xfffn is_c",
            b"fn is_azAZ09_fn as_0__ fn is_\x80",
        ] {
            let spans = reference_spans(pattern, haystack);
            let prospective = plan
                .uniform_participation_prospective(haystack.len(), rust_functions_schema())
                .unwrap();
            let mut receipt = plan.uniform_participation_attempt_receipt(
                haystack.len(),
                rust_functions_schema(),
                UniformParticipationLimits::unlimited(),
            );
            receipt.prospective = Some(prospective);
            let mut direct_spans = Vec::new();
            plan.scan_uniform_participation(
                haystack,
                rust_functions_schema(),
                prospective,
                &mut receipt,
                |span| {
                    direct_spans.push(span);
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(spans, direct_spans, "haystack={haystack:?}");
            let result = plan
                .count_uniform_participation(
                    haystack,
                    rust_functions_schema(),
                    UniformParticipationLimits::unlimited(),
                )
                .unwrap();
            assert_eq!(spans.len(), result.matches, "haystack={haystack:?}");
            assert_eq!(spans.len() * 2, result.capture_count);
            assert_eq!(spans.len() * 3, result.accounting.actual.capture_events);
            assert_eq!(0, result.accounting.actual.operation_allocations);
            assert_eq!(0, result.accounting.actual.operation_bytes);
            assert_eq!(0, result.accounting.actual.scratch_bytes);
            ensure_uniform_actual(&result.accounting.actual, &result.accounting.prospective)
                .unwrap();
        }
    }

    #[test]
    fn uniform_participation_preserves_branch_zero_on_equal_start() {
        let plan = PrefixClassAlternationPlan::build_uniform_participation(
            [b"ab", b"abc"],
            [[(b'c', b'c')].into_iter(), [(b'd', b'd')].into_iter()],
            UniformParticipationBuildLimits::unlimited(),
        )
        .unwrap();
        let schema = UniformParticipationSchema {
            participating_with_overall: 2,
            capture_schema_slots: 3,
        };
        let haystack = b"abcd abcdd abcc";
        let expected = reference_spans(r"ab[c]+|abc[d]+", haystack);
        let prospective = plan
            .uniform_participation_prospective(haystack.len(), schema)
            .unwrap();
        let mut receipt = plan.uniform_participation_attempt_receipt(
            haystack.len(),
            schema,
            UniformParticipationLimits::unlimited(),
        );
        receipt.prospective = Some(prospective);
        let mut actual = Vec::new();
        let matches = plan
            .scan_uniform_participation(haystack, schema, prospective, &mut receipt, |span| {
                actual.push(span);
                Ok(())
            })
            .unwrap();
        assert_eq!(expected, actual);
        assert_eq!(expected.len(), matches);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one table-like boundary test keeps every positive direct-operation fence under the same authenticated receipt assertions"
    )]
    fn rust_functions_uniform_participation_exact_and_every_positive_one_below() {
        let plan = rust_functions_plan();
        let haystack = b"fn is_alpha fn as_beta";
        let schema = rust_functions_schema();
        let prospective = plan
            .uniform_participation_prospective(haystack.len(), schema)
            .unwrap();
        let exact = exact_uniform_limits(prospective);
        let success = plan
            .count_uniform_participation_attempt(haystack, schema, exact)
            .unwrap();
        assert_eq!(4, success.result.capture_count);
        assert_eq!(UNIFORM_PARTICIPATION_ALGORITHM_VERSION, 1);
        assert_eq!(UNIFORM_PARTICIPATION_ACCOUNTING_VERSION, 2);
        assert_eq!(success.receipt.prospective, Some(prospective));
        assert_eq!(success.receipt.actual, success.result.accounting.actual);
        assert_eq!(success.receipt.actual_allocations, 0);
        assert!(success.receipt.retains_bounded_actual());
        assert!(success.receipt.authenticates(
            plan.uniform_participation_identity(schema),
            UniformParticipationInvocation {
                haystack_bytes: haystack.len(),
                schema,
                limits: exact,
            }
        ));
        let mut forged_stream = success.receipt;
        forged_stream.actual.first_finder_candidates =
            prospective.first_finder_candidates.saturating_add(1);
        assert!(!forged_stream.retains_bounded_actual());
        let mut forged_total = success.receipt;
        forged_total.actual.prefix_candidates =
            forged_total.actual.prefix_candidates.saturating_add(1);
        assert!(!forged_total.retains_bounded_actual());
        let mut forged_allocations = success.receipt;
        forged_allocations.actual_allocations = 1;
        assert!(!forged_allocations.retains_bounded_actual());

        macro_rules! one_below {
            ($limit_field:ident, $prospective_field:ident, $pattern:pat) => {{
                assert!(prospective.$prospective_field > 0);
                let mut limits = exact;
                limits.$limit_field = prospective.$prospective_field - 1;
                let error = plan
                    .count_uniform_participation_attempt(haystack, schema, limits)
                    .expect_err("one-below direct attempt must refuse");
                assert!(matches!(error.source, $pattern));
                assert_eq!(error.receipt.prospective, Some(prospective));
                assert_eq!(error.receipt.actual, UniformParticipationActual::default());
                assert_eq!(error.receipt.actual_allocations, 0);
                assert!(error.receipt.retains_bounded_actual());
                assert!(error.receipt.authenticates(
                    plan.uniform_participation_identity(schema),
                    UniformParticipationInvocation {
                        haystack_bytes: haystack.len(),
                        schema,
                        limits,
                    }
                ));
            }};
        }
        one_below!(
            max_results,
            results,
            UniformParticipationError::ResultsLimit { .. }
        );
        one_below!(
            max_capture_count,
            capture_count,
            UniformParticipationError::CaptureCountLimit { .. }
        );
        one_below!(
            max_capture_events,
            capture_events,
            UniformParticipationError::CaptureEventsLimit { .. }
        );
        one_below!(
            max_first_finder_bytes,
            first_finder_bytes,
            UniformParticipationError::FirstFinderBytesLimit { .. }
        );
        one_below!(
            max_second_finder_bytes,
            second_finder_bytes,
            UniformParticipationError::SecondFinderBytesLimit { .. }
        );
        one_below!(
            max_prefix_candidates,
            prefix_candidates,
            UniformParticipationError::PrefixCandidatesLimit { .. }
        );
        one_below!(
            max_start_arbitrations,
            start_arbitrations,
            UniformParticipationError::StartArbitrationsLimit { .. }
        );
        one_below!(
            max_first_class_probes,
            first_class_probes,
            UniformParticipationError::FirstClassProbesLimit { .. }
        );
        one_below!(
            max_greedy_extension_reads,
            greedy_extension_reads,
            UniformParticipationError::GreedyExtensionReadsLimit { .. }
        );
        one_below!(max_work, work, UniformParticipationError::WorkLimit { .. });
        one_below!(
            max_peak_bytes,
            peak_bytes,
            UniformParticipationError::PeakLimit { .. }
        );
    }

    #[test]
    fn uniform_participation_post_source_refusal_retains_p_and_cumulative_a() {
        let plan = rust_functions_plan();
        let haystack = b"fn is_alpha fn as_beta";
        let schema = rust_functions_schema();
        let prospective = plan
            .uniform_participation_prospective(haystack.len(), schema)
            .unwrap();
        let limits = exact_uniform_limits(prospective);
        uniform_scan_fault::arm(1);
        let terminal = plan
            .count_uniform_participation_attempt(haystack, schema, limits)
            .expect_err("injected terminal must refuse after the first result");
        assert_eq!(terminal.receipt.prospective, Some(prospective));
        assert_eq!(terminal.receipt.actual.results, 1);
        assert_eq!(terminal.receipt.actual.capture_count, 2);
        assert_eq!(terminal.receipt.actual.capture_events, 3);
        assert!(terminal.receipt.actual.first_finder_bytes > 0);
        assert!(terminal.receipt.actual.work > 0);
        assert_eq!(terminal.receipt.actual_allocations, 0);
        assert!(terminal.receipt.retains_bounded_actual());
        assert!(terminal.receipt.authenticates(
            plan.uniform_participation_identity(schema),
            UniformParticipationInvocation {
                haystack_bytes: haystack.len(),
                schema,
                limits,
            }
        ));
        assert!(matches!(
            terminal.source,
            UniformParticipationError::ArithmeticOverflow {
                computation: "injected post-source terminal",
            }
        ));
    }

    #[test]
    fn uniform_participation_overflow_is_typed_before_source_access() {
        let plan = rust_functions_plan();
        let invalid_schema = UniformParticipationSchema {
            participating_with_overall: 0,
            capture_schema_slots: 0,
        };
        let invalid = plan
            .count_uniform_participation_attempt(
                b"",
                invalid_schema,
                UniformParticipationLimits::unlimited(),
            )
            .expect_err("invalid schema must refuse before P");
        assert_eq!(invalid.source, UniformParticipationError::InvalidSchema);
        assert_eq!(invalid.receipt.prospective, None);
        assert_eq!(
            invalid.receipt.actual,
            UniformParticipationActual::default()
        );
        assert_eq!(invalid.receipt.actual_allocations, 0);
        assert!(invalid.receipt.retains_bounded_actual());
        assert!(matches!(
            plan.uniform_participation_prospective(usize::MAX, rust_functions_schema(),),
            Err(UniformParticipationError::ArithmeticOverflow {
                computation: "two complete prefix candidate streams",
            })
        ));
        assert!(matches!(
            plan.uniform_participation_prospective(
                14,
                UniformParticipationSchema {
                    participating_with_overall: usize::MAX,
                    capture_schema_slots: usize::MAX,
                },
            ),
            Err(UniformParticipationError::ArithmeticOverflow {
                computation: "prospective participating capture count",
            })
        ));
        assert!(matches!(
            plan.uniform_participation_prospective(
                14,
                UniformParticipationSchema {
                    participating_with_overall: 1,
                    capture_schema_slots: usize::MAX,
                },
            ),
            Err(UniformParticipationError::ArithmeticOverflow {
                computation: "prospective capture schema events",
            })
        ));
    }

    #[test]
    fn rust_functions_uniform_participation_n_2n_4n_is_deterministic() {
        let plan = rust_functions_plan();
        let schema = rust_functions_schema();
        let mut previous = None;
        for n in [140, 280, 560] {
            let prospective = plan.uniform_participation_prospective(n, schema).unwrap();
            assert_eq!(n, prospective.first_finder_bytes);
            assert_eq!(n, prospective.second_finder_bytes);
            assert_eq!(n, prospective.first_finder_candidates);
            assert_eq!(n, prospective.second_finder_candidates);
            assert_eq!(2 * n, prospective.prefix_candidates);
            assert_eq!(4 * n, prospective.start_arbitrations);
            assert_eq!(2 * n, prospective.first_class_probes);
            assert_eq!(2 * n, prospective.greedy_extension_reads);
            assert_eq!(7, prospective.minimum_match_bytes);
            assert_eq!(n / 7, prospective.results);
            assert_eq!(2 * (n / 7), prospective.capture_count);
            assert_eq!(3 * (n / 7), prospective.capture_events);
            if let Some((previous_n, previous_work)) = previous {
                let fixed = plan.build_accounting().shape_units * 8 + 64;
                assert_eq!(
                    12 * (n - previous_n) + 6 * ((n - previous_n) / 7),
                    prospective.work - previous_work
                );
                assert_eq!(fixed + 12 * n + 6 * (n / 7), prospective.work);
            }
            previous = Some((n, prospective.work));
        }
    }

    #[test]
    fn rust_functions_uniform_participation_actual_counters_are_linear_at_all_densities() {
        let plan = rust_functions_plan();
        let schema = rust_functions_schema();
        let fixed = plan.build_accounting().shape_units * 8 + 64;
        for n in [128_usize, 256, 512] {
            let sparse = vec![b'x'; n];
            let sparse = plan
                .count_uniform_participation(
                    &sparse,
                    schema,
                    UniformParticipationLimits::unlimited(),
                )
                .unwrap()
                .accounting
                .actual;
            assert_eq!(n, sparse.first_finder_bytes);
            assert_eq!(n, sparse.second_finder_bytes);
            assert_eq!(0, sparse.prefix_candidates);
            assert_eq!(0, sparse.results);
            assert_eq!(2 * n + fixed, sparse.work);

            let dense = b"fn is_a!".repeat(n / 8);
            assert_eq!(n, dense.len());
            let dense = plan
                .count_uniform_participation(
                    &dense,
                    schema,
                    UniformParticipationLimits::unlimited(),
                )
                .unwrap()
                .accounting
                .actual;
            let matches = n / 8;
            assert_eq!(n, dense.first_finder_bytes);
            assert_eq!(n, dense.second_finder_bytes);
            assert_eq!(matches, dense.first_finder_candidates);
            assert_eq!(0, dense.second_finder_candidates);
            assert_eq!(matches, dense.prefix_candidates);
            assert_eq!(matches * 2, dense.start_arbitrations);
            assert_eq!(matches, dense.first_class_probes);
            assert_eq!(matches, dense.greedy_extension_reads);
            assert_eq!(matches, dense.results);
            assert_eq!(matches * 2, dense.capture_count);
            assert_eq!(matches * 3, dense.capture_events);
            assert_eq!(2 * n + 11 * matches + fixed, dense.work);
        }
    }

    struct DeceptiveExactRanges {
        items: &'static [(u8, u8)],
        position: usize,
        next_calls: Rc<Cell<usize>>,
        len_calls: Rc<Cell<usize>>,
    }

    impl Iterator for DeceptiveExactRanges {
        type Item = (u8, u8);

        fn next(&mut self) -> Option<Self::Item> {
            self.next_calls.set(self.next_calls.get() + 1);
            let item = self.items.get(self.position).copied();
            self.position += usize::from(item.is_some());
            item
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            // Deliberately violates ExactSizeIterator's semantic contract.
            // Resource safety must depend on actual traversal, not this claim.
            (0, Some(0))
        }
    }

    impl ExactSizeIterator for DeceptiveExactRanges {
        fn len(&self) -> usize {
            self.len_calls.set(self.len_calls.get() + 1);
            0
        }
    }

    fn deceptive_ranges(
        items: &'static [(u8, u8)],
    ) -> (DeceptiveExactRanges, Rc<Cell<usize>>, Rc<Cell<usize>>) {
        let next_calls = Rc::new(Cell::new(0));
        let len_calls = Rc::new(Cell::new(0));
        (
            DeceptiveExactRanges {
                items,
                position: 0,
                next_calls: Rc::clone(&next_calls),
                len_calls: Rc::clone(&len_calls),
            },
            next_calls,
            len_calls,
        )
    }

    #[test]
    fn direct_construction_refuses_before_observing_range_sources() {
        let (first, first_next, first_len) = deceptive_ranges(&[(b'a', b'z')]);
        let (second, second_next, second_len) = deceptive_ranges(&[(b'0', b'9')]);
        let error = PrefixClassAlternationPlan::build_uniform_participation(
            [b"ab", b"xy"],
            [first, second],
            UniformParticipationBuildLimits {
                max_allocations: 1,
                ..UniformParticipationBuildLimits::unlimited()
            },
        )
        .expect_err("direct allocation one-below must preflight");
        assert_eq!(
            error,
            UniformParticipationBuildError::AllocationsLimit {
                needed: 2,
                limit: 1,
            }
        );
        assert_eq!(first_next.get(), 0);
        assert_eq!(second_next.get(), 0);
        assert_eq!(first_len.get(), 0);
        assert_eq!(second_len.get(), 0);
    }

    #[test]
    fn rebar_row_imported_leipzig_huck_saw_exact_256_and_one_below_255() {
        // rebar-row:imported/leipzig/huck-saw@rust/regex
        // Independent witness: N=9, Q=(2+2)+(1+1)=6, hence
        // W=16*9+8*6+64=256. Expected complete spans are 0..4 and 6..9.
        let plan = plan();
        let haystack = b"abcz--xy7";
        let expected = vec![0..4, 6..9];
        assert_eq!(expected, sut_spans(&plan, haystack));
        let exact = ReduceLimits {
            max_work: 256,
            ..ReduceLimits::unlimited()
        };
        assert_eq!(2, plan.count(haystack, exact).unwrap().count);
        let one_below = ReduceLimits {
            max_work: 255,
            ..ReduceLimits::unlimited()
        };
        assert_eq!(
            Err(ReduceError::WorkLimit {
                needed: 256,
                limit: 255,
            }),
            plan.count(haystack, one_below)
        );
    }

    #[test]
    fn rebar_row_imported_leipzig_huck_saw_complete_span_differential_boundaries() {
        // rebar-row:imported/leipzig/huck-saw@rust/regex
        let plan = plan();
        for haystack in [
            b"".as_slice(),
            b"abz",
            b"_abzz_xy7_",
            b"abxy7",
            b"ababzxy77",
            b"\xFFabq\x80xy0",
        ] {
            assert_eq!(
                reference_spans(r"ab[a-z]+|xy[0-9]+", haystack),
                sut_spans(&plan, haystack),
                "haystack={haystack:?}"
            );
        }
    }

    #[test]
    fn rebar_row_imported_leipzig_huck_saw_additive_n_and_q_witnesses() {
        // rebar-row:imported/leipzig/huck-saw@rust/regex
        // With Q=6, N/2N/4N at 32/64/128 bytes gives exactly
        // 16N+8Q+64 = 624/1136/2160 admitted runtime work.
        let plan = plan();
        for (n, expected) in [(32, 624), (64, 1_136), (128, 2_160)] {
            let upper = plan.preflight(n, ReduceLimits::unlimited()).unwrap();
            assert_eq!(expected, upper.work);
        }

        // Independent Q/2Q/4Q build adversaries use two canonical ranges and
        // prefix payloads of Q-2. The single-pass charged ledger gives
        // 9Q+72 = 216/360/648 at Q=16/32/64.
        for (q, expected) in [(16, 216), (32, 360), (64, 648)] {
            let per_prefix = (q - 2) / 2;
            let mut first = vec![b'b'; per_prefix];
            let mut second = vec![b'd'; per_prefix];
            first[0] = b'A';
            second[0] = b'C';
            let scaled = PrefixClassAlternationPlan::build(
                [&first, &second],
                [[(b'a', b'z')].into_iter(), [(b'0', b'9')].into_iter()],
                BuildLimits::unlimited(),
            )
            .unwrap();
            assert_eq!(q, scaled.build_accounting().shape_units);
            assert_eq!(expected, scaled.build_accounting().work_upper_bound);
        }
    }

    #[test]
    fn deceptive_exact_size_ranges_are_single_pass_and_exactly_charged() {
        static FIRST: [(u8, u8); 2] = [(b'a', b'm'), (b'n', b'z')];
        static SECOND: [(u8, u8); 2] = [(b'0', b'4'), (b'5', b'9')];

        let (first, first_next, first_len) = deceptive_ranges(&FIRST);
        let (second, second_next, second_len) = deceptive_ranges(&SECOND);
        let baseline = PrefixClassAlternationPlan::build(
            [b"ab", b"xy"],
            [first, second],
            BuildLimits::unlimited(),
        )
        .unwrap();
        let accounting = baseline.build_accounting();
        assert_eq!(4, accounting.class_ranges);
        assert_eq!(8, accounting.shape_units);
        assert_eq!(0, first_len.get());
        assert_eq!(0, second_len.get());
        assert_eq!(FIRST.len() + 1, first_next.get());
        assert_eq!(SECOND.len() + 1, second_next.get());

        let (first, _, first_len) = deceptive_ranges(&FIRST);
        let (second, _, second_len) = deceptive_ranges(&SECOND);
        let exact = PrefixClassAlternationPlan::build(
            [b"ab", b"xy"],
            [first, second],
            BuildLimits {
                max_shape_units: accounting.shape_units,
                max_build_work: accounting.work_upper_bound,
                ..BuildLimits::unlimited()
            },
        )
        .unwrap();
        assert_eq!(accounting, exact.build_accounting());
        assert_eq!(0, first_len.get());
        assert_eq!(0, second_len.get());

        let (first, _, _) = deceptive_ranges(&FIRST);
        let (second, _, _) = deceptive_ranges(&SECOND);
        assert!(matches!(
            PrefixClassAlternationPlan::build(
                [b"ab", b"xy"],
                [first, second],
                BuildLimits {
                    max_build_work: accounting.work_upper_bound - 1,
                    ..BuildLimits::unlimited()
                },
            ),
            Err(BuildError::WorkLimit { needed, limit })
                if needed == accounting.work_upper_bound
                    && limit == accounting.work_upper_bound - 1
        ));

        let (first, _, _) = deceptive_ranges(&FIRST);
        let (second, _, _) = deceptive_ranges(&SECOND);
        assert!(matches!(
            PrefixClassAlternationPlan::build(
                [b"ab", b"xy"],
                [first, second],
                BuildLimits {
                    max_shape_units: accounting.shape_units - 1,
                    ..BuildLimits::unlimited()
                },
            ),
            Err(BuildError::ShapeLimit {
                needed: 8,
                limit: 7
            })
        ));
    }
}
