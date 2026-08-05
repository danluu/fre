//! Two ordered `LITERAL BYTE_CLASS+` alternatives reduced in one linear stream.
//!
//! Each literal is proved non-self-overlapping by the sufficient condition
//! that its first byte does not occur in its remainder. Consequently one
//! persistent `memmem::Finder::find_iter` per alternative enumerates every
//! literal occurrence without restarting selected-span searches. Merging the
//! two monotone occurrence streams, then greedily extending the selected byte
//! class, implements Rust's leftmost-first, non-overlapping whole-match
//! semantics. Exists and earliest-end instead begin with both literal
//! first-byte streams, authenticate the exact literals, and inspect exactly
//! one following class member without constructing or extending a greedy
//! match. A fixed noisy-anchor budget falls back to the retained literal
//! streams, preserving low constants for dense first-byte rejection. Both
//! routes are `O(N + Q)` with constant operation space. `N` is the haystack
//! length; `Q` is retained literal bytes plus canonical class ranges.
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
//! candidate services, every candidate read/branch/start comparison, membership
//! comparison, counter/cursor write, count conversion, and checked logical
//! match-width accumulation. Span sum additionally reserves `N` matched bytes:
//! positive non-overlapping spans cannot exceed the haystack length. Execution
//! allocation, initialization, reserve, copy, deduplication, UTF-8/boundary
//! preprocessing, and growing stack/queue storage are zero; its two iterators,
//! two next-candidate slots, and scalar counters form an `O(1)` fixed frame.
//! Allocation failure is typed and never changes the selected route.
//!
//! A distinct dispatched owner is available only from one caller-captured
//! context with OS-usable SVE and two proved ASCII classes. It retains one
//! fixed-16 SVE/SVE2 run scanner per alternative. Construction adds exactly
//! two 130-unit scanner compilations and one fallible exact dispatched-owner
//! allocation; execution
//! adds at most 15 physical classifications per selected run to both aggregate
//! and uniform-participation prospective work. Non-SVE and non-ASCII
//! production routes keep the incumbent scalar owner, identity, layout, and
//! receipt values.
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

use core::{fmt, mem::size_of, num::NonZeroUsize, ops::Range};

use fre_exact_alloc::{CopyError, try_box_preserve};
#[cfg(not(feature = "static-dispatch"))]
use fre_simd_kernels::FeatureSet;
use fre_simd_kernels::{
    ASCII_RUN_MAX_CLASSIFICATION_OVERHEAD, AsciiByteSet, AsciiByteSetRunScanner, DispatchPolicy,
    Feature, SelectionReceipt, SimdDispatchContext,
};
use memchr::{memchr, memchr2};
use memchr::memmem::{Finder, FinderBuilder};

use crate::{DirectBuildAttempt, DirectBuildAttemptActual, DirectBuildAttemptError, Window};

pub const PLAN_ID: &str = "prefix-class-alternation.two-monotone-literal-streams.v1";
pub const DISPATCHED_PLAN_ID: &str =
    "prefix-class-alternation.two-monotone-literal-streams.sve-run16.v1";
pub const COUNT_OPERATION_ID: &str = "prefix-class-alternation.count.unicode-off.v1";
pub const SPAN_SUM_OPERATION_ID: &str = "prefix-class-alternation.span-sum.unicode-off.v1";
pub const EXISTS_OPERATION_ID: &str = "prefix-class-alternation.exists.unicode-off.v1";
pub const SEARCH_OPERATION_ID: &str = "prefix-class-alternation.search.unicode-off.v1";
pub const SHORTEST_SEARCH_OPERATION_ID: &str =
    "prefix-class-alternation.shortest.unicode-off.v1";
pub const UNIFORM_PARTICIPATION_PLAN_ID: &str =
    "prefix-class-alternation.uniform-participation.two-finder.v1";
pub const DISPATCHED_UNIFORM_PARTICIPATION_PLAN_ID: &str =
    "prefix-class-alternation.uniform-participation.two-finder.sve-run16.v1";
pub const UNIFORM_PARTICIPATION_OPERATION_ID: &str =
    "prefix-class-alternation.capture-participation.unicode-off.v1";
pub const UNIFORM_PARTICIPATION_ALGORITHM_VERSION: u32 = 1;
pub const UNIFORM_PARTICIPATION_ACCOUNTING_VERSION: u32 = 2;

const FIXED_BUILD_WORK: usize = 64;
const PREFIX_BUILD_WORK_PER_BYTE: usize = 8;
const RANGE_ITEM_BASE_WORK: usize = 6;
const BITMAP_WORK_PER_WORD: usize = 4;
const SIMD_RUN_SCANNER_BUILD_WORK: usize = 128 + 1 + 1;
const RUN_SCANNERS: usize = 2;
// One narrow block bounds per-hit scalar overhead before exact Finders regain
// the advantage on a dense, mostly false first-byte stream.
const DIRECT_ENDPOINT_ANCHOR_BUDGET: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationIdentity {
    pub plan_id: &'static str,
    pub operation_id: &'static str,
    pub alternatives: usize,
    pub unicode: bool,
    pub non_overlapping: bool,
}

/// Physical class-extension implementation retained by a count plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReduceImplementation {
    /// Scalar class extension.
    Scalar,
    /// One retained directional SIMD run scanner per alternative.
    DispatchedRunScanners,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Operation {
    Count,
    SpanSum,
    Exists,
    Search,
    Shortest,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunScannerBuildAccounting {
    pub build_work: usize,
    pub scanners: usize,
    pub allocations: usize,
    pub initialized_bytes: usize,
    pub retained_allocation_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StoredBuildAccounting {
    prefix_bytes: usize,
    class_ranges: usize,
    shape_units: usize,
    work_upper_bound: usize,
    scratch_bytes: usize,
    persistent_bytes: usize,
    peak_bytes: usize,
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
    pub initialized_run_scanner_bytes: usize,
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
    pub max_initialized_run_scanner_bytes: usize,
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
            max_initialized_run_scanner_bytes: usize::MAX,
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
            max_allocations: 3,
            max_copied_prefix_bytes: 4 * 1024 * 1024,
            max_finder_preprocess_input_bytes: 4 * 1024 * 1024,
            max_initialized_bitmap_bytes: size_of::<[u64; 8]>(),
            max_initialized_run_scanner_bytes: size_of::<[AsciiByteSetRunScanner; RUN_SCANNERS]>(),
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
    InitializedRunScannerBytesLimit { needed: usize, limit: usize },
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
    pub max_span_sum: u64,
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
            max_span_sum: u64::MAX,
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
            max_span_sum: u64::MAX,
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
    pub prefix_candidates: usize,
    pub class_bytes: usize,
    pub match_events: usize,
    pub count: u64,
    pub span_sum: u64,
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
    pub span_sum: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceAccounting {
    pub identity: OperationIdentity,
    pub upper_bounds: ReduceUpperBounds,
    pub actual: ReduceActualCounters,
}

/// Limits checked from a complete source-independent ordinary-search envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchLimits {
    pub max_work_upper_bound: u64,
    pub max_scratch_bytes: usize,
}

impl SearchLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_work_upper_bound: u64::MAX,
            max_scratch_bytes: usize::MAX,
        }
    }
}

impl Default for SearchLimits {
    fn default() -> Self {
        Self {
            max_work_upper_bound: 32_u64 << 30,
            max_scratch_bytes: 0,
        }
    }
}

/// Source-independent search envelope and exact structural counters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchAccounting {
    pub identity: OperationIdentity,
    pub window: Window,
    pub upper_bounds: ReduceUpperBounds,
    pub actual: ReduceActualCounters,
}

/// Ordinary search shares the reducer's checked arithmetic and limit errors.
pub type SearchError = ReduceError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountResult {
    pub count: u64,
    pub accounting: ReduceAccounting,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpanSumResult {
    pub span_sum: u64,
    pub accounting: ReduceAccounting,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SearchProjection {
    Exists,
    Selected,
    EarliestEnd,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EndpointProjection {
    Exists,
    EarliestEnd,
}

/// Derive the complete source-free reduction envelope for a retained implementation.
fn derive_reduce_upper_bounds(
    build: BuildAccounting,
    haystack_len: usize,
    implementation: ReduceImplementation,
    operation: Operation,
) -> Result<ReduceUpperBounds, ReduceError> {
    let match_events = haystack_len;
    let prefix_candidates = haystack_len
        .checked_mul(2)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "two prefix candidate streams",
        })?;
    let scanner_overhead = match implementation {
        ReduceImplementation::Scalar => 0,
        ReduceImplementation::DispatchedRunScanners => match_events
            .checked_mul(ASCII_RUN_MAX_CLASSIFICATION_OVERHEAD)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "run scanner classification overhead",
            })?,
    };
    let class_bytes = haystack_len
        .checked_mul(4)
        .and_then(|bytes| bytes.checked_add(scanner_overhead))
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "prefix probes, greedy class extension, and scanner overhead",
        })?;
    let work = haystack_len
        .checked_mul(16)
        .and_then(|work| {
            build
                .shape_units
                .checked_mul(8)
                .and_then(|shape| work.checked_add(shape))
        })
        .and_then(|work| work.checked_add(64))
        .and_then(|work| work.checked_add(scanner_overhead))
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "16N + 8Q + 64 + scanner overhead work bound",
        })?;
    let count = u64::try_from(match_events).map_err(|_| ReduceError::ArithmeticOverflow {
        computation: "match event bound as u64",
    })?;
    let span_sum = match operation {
        Operation::Count | Operation::Exists | Operation::Search | Operation::Shortest => 0,
        Operation::SpanSum => {
            u64::try_from(haystack_len).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "haystack length as span-sum bound",
            })?
        }
    };
    Ok(ReduceUpperBounds {
        haystack_bytes: haystack_len,
        shape_units: build.shape_units,
        work,
        prefix_candidates,
        class_bytes,
        match_events,
        count,
        span_sum,
        scratch_bytes: 0,
        persistent_bytes: build.persistent_bytes,
        peak_bytes: build.persistent_bytes,
    })
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
    RunScannerDispatchUnavailable,
    NonAsciiRunScannerClass { alternative: usize },
    RunScannerAllocationFailed { bytes: usize },
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
    InvalidWindow {
        start: usize,
        end: usize,
        haystack_len: usize,
    },
    WorkLimit { needed: usize, limit: usize },
    MatchEventsLimit { needed: usize, limit: usize },
    CountLimit { needed: u64, limit: u64 },
    SpanSumLimit { needed: u64, limit: u64 },
    ScratchLimit { needed: usize, limit: usize },
    PeakLimit { needed: usize, limit: usize },
    AccountingInvariant {
        resource: &'static str,
        actual: usize,
        upper: usize,
    },
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

    const fn is_ascii(self) -> bool {
        self.words[2] == 0 && self.words[3] == 0
    }

    const fn ascii_set(self) -> AsciiByteSet {
        AsciiByteSet::from_words([self.words[0], self.words[1]])
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
    // Keep the incumbent scalar owner layout stable. Dispatched-only scanner
    // dimensions are projected by its distinct owner instead of widening this
    // embedded receipt.
    build: StoredBuildAccounting,
}

/// SVE-only owner for the same two-alternative proof.
///
/// The embedded legacy plan retains both Finders and classes. Exactly one
/// fixed-16 directional scanner is compiled for each proved ASCII class and
/// both are retained with the embedded scalar proof in one exact allocation
/// so the public handle and aggregate owner stay stack-neutral.
#[derive(Debug)]
pub struct DispatchedPrefixClassAlternationPlan {
    owner: RetainedDispatchedPrefixClassAlternationOwner,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PrefixCandidateStreamState {
    Need { from: usize },
    Ready { start: usize, next_from: usize },
    Exhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StoredPrefixCandidateStreamState {
    ready_start: Option<NonZeroUsize>,
    next_from: usize,
}

impl StoredPrefixCandidateStreamState {
    const EXHAUSTED_FROM: usize = usize::MAX;

    const fn need(from: usize) -> Self {
        Self {
            ready_start: None,
            next_from: from,
        }
    }

    const fn exhausted() -> Self {
        Self {
            ready_start: None,
            next_from: Self::EXHAUSTED_FROM,
        }
    }

    fn state(self) -> PrefixCandidateStreamState {
        if let Some(start) = self.ready_start {
            return PrefixCandidateStreamState::Ready {
                start: start.get() - 1,
                next_from: self.next_from,
            };
        }
        if self.next_from == Self::EXHAUSTED_FROM {
            PrefixCandidateStreamState::Exhausted
        } else {
            PrefixCandidateStreamState::Need {
                from: self.next_from,
            }
        }
    }

    const fn set_need(&mut self, from: usize) {
        *self = Self::need(from);
    }

    fn set_ready(&mut self, start: usize, next_from: usize) -> Result<(), SearchError> {
        let encoded = start
            .checked_add(1)
            .and_then(NonZeroUsize::new)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "encoded retained prefix candidate start",
            })?;
        self.ready_start = Some(encoded);
        self.next_from = next_from;
        Ok(())
    }

    const fn set_exhausted(&mut self) {
        *self = Self::exhausted();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PrefixClassAlternationCursorState {
    streams: [StoredPrefixCandidateStreamState; 2],
    window_end: usize,
    next_start: usize,
}

impl PrefixClassAlternationCursorState {
    const fn new() -> Self {
        Self {
            streams: [StoredPrefixCandidateStreamState::exhausted(); 2],
            window_end: 0,
            next_start: usize::MAX,
        }
    }

    fn reset(&mut self, window: Window) {
        self.streams = [
            StoredPrefixCandidateStreamState::need(window.start()),
            StoredPrefixCandidateStreamState::need(window.start()),
        ];
        self.window_end = window.end();
        self.next_start = window.start();
    }

    fn prepare(&mut self, window: Window) -> bool {
        if self.next_start != window.start() || self.window_end != window.end() {
            self.reset(window);
            true
        } else {
            false
        }
    }

    fn retain_match(&mut self, end: usize) {
        self.next_start = end;
    }

    fn exhaust(&mut self) {
        self.streams = [StoredPrefixCandidateStreamState::exhausted(); 2];
        self.next_start = self.window_end;
    }
}

/// Plan-and-source-bound continuation for monotone prefix/class iteration.
///
/// The capability retains both literal streams across successive
/// non-overlapping searches. Its immutable borrows bind every retained
/// candidate to exactly one plan and haystack. Independent searches should
/// use [`PrefixClassAlternationPlan::find_in`].
#[doc(hidden)]
#[derive(Clone, Copy, Debug)]
pub struct PrefixClassAlternationSearchCursor<'p, 'h> {
    plan: &'p PrefixClassAlternationPlan,
    haystack: &'h [u8],
    state: PrefixClassAlternationCursorState,
}

/// Dispatched counterpart of [`PrefixClassAlternationSearchCursor`].
#[doc(hidden)]
#[derive(Clone, Copy, Debug)]
pub struct DispatchedPrefixClassAlternationSearchCursor<'p, 'h> {
    plan: &'p DispatchedPrefixClassAlternationPlan,
    haystack: &'h [u8],
    state: PrefixClassAlternationCursorState,
}

type RunScanners = [AsciiByteSetRunScanner; RUN_SCANNERS];

#[derive(Debug)]
struct DispatchedPrefixClassAlternationOwner {
    plan: PrefixClassAlternationPlan,
    run_scanners: RunScanners,
}

type RetainedDispatchedPrefixClassAlternationOwner = Box<DispatchedPrefixClassAlternationOwner>;

impl<'p, 'h> PrefixClassAlternationSearchCursor<'p, 'h> {
    const fn new(plan: &'p PrefixClassAlternationPlan, haystack: &'h [u8]) -> Self {
        Self {
            plan,
            haystack,
            state: PrefixClassAlternationCursorState::new(),
        }
    }

    /// Find one selected span while retaining both monotone literal streams.
    ///
    /// The third tuple element is the work charged to a containing iterator:
    /// one complete suffix envelope on the first call after construction or a
    /// reset and zero on contiguous continuations covered by that prepayment.
    pub fn find_window(
        &mut self,
        window: Window,
        limits: SearchLimits,
    ) -> Result<(Option<(usize, usize)>, SearchAccounting, usize), SearchError> {
        self.find_window_transaction(window, limits, false)
    }

    /// Search at or after `start` in the complete bound haystack.
    pub fn find_at(
        &mut self,
        start: usize,
        limits: SearchLimits,
    ) -> Result<(Option<(usize, usize)>, SearchAccounting, usize), SearchError> {
        self.find_window(Window::new(start, self.haystack.len()), limits)
    }

    /// The immutable source bound to this continuation.
    #[must_use]
    pub const fn haystack(&self) -> &'h [u8] {
        self.haystack
    }

    fn find_window_transaction(
        &mut self,
        window: Window,
        limits: SearchLimits,
        inject_late_failure: bool,
    ) -> Result<(Option<(usize, usize)>, SearchAccounting, usize), SearchError> {
        self.plan.search_in_with_cursor_state(
            self.haystack,
            window,
            limits,
            self.plan.search_identity(),
            [None, None],
            &mut self.state,
            inject_late_failure,
        )
    }

    #[cfg(test)]
    fn find_window_with_late_failure(
        &mut self,
        window: Window,
        limits: SearchLimits,
    ) -> Result<(Option<(usize, usize)>, SearchAccounting, usize), SearchError> {
        self.find_window_transaction(window, limits, true)
    }
}

impl<'p, 'h> DispatchedPrefixClassAlternationSearchCursor<'p, 'h> {
    const fn new(
        plan: &'p DispatchedPrefixClassAlternationPlan,
        haystack: &'h [u8],
    ) -> Self {
        Self {
            plan,
            haystack,
            state: PrefixClassAlternationCursorState::new(),
        }
    }

    /// Find one selected span while retaining both monotone literal streams.
    pub fn find_window(
        &mut self,
        window: Window,
        limits: SearchLimits,
    ) -> Result<(Option<(usize, usize)>, SearchAccounting, usize), SearchError> {
        self.plan.plan().search_in_with_cursor_state(
            self.haystack,
            window,
            limits,
            self.plan.search_identity(),
            self.plan.scanner_refs(),
            &mut self.state,
            false,
        )
    }

    /// Search at or after `start` in the complete bound haystack.
    pub fn find_at(
        &mut self,
        start: usize,
        limits: SearchLimits,
    ) -> Result<(Option<(usize, usize)>, SearchAccounting, usize), SearchError> {
        self.find_window(Window::new(start, self.haystack.len()), limits)
    }

    /// The immutable source bound to this continuation.
    #[must_use]
    pub const fn haystack(&self) -> &'h [u8] {
        self.haystack
    }
}

impl PrefixClassAlternationPlan {
    /// Whether this captured host can retain the fixed-16 SVE scanner pair.
    #[must_use]
    pub fn run_scanners_usable(dispatch: SimdDispatchContext) -> bool {
        run_scanner_policy(dispatch).is_some()
    }

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
        preflight_uniform_participation_build(prefixes, 0, 0, 0, limits)?;
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
    pub fn build_attempt<I>(
        prefixes: [&[u8]; 2],
        ranges: [I; 2],
        limits: BuildLimits,
    ) -> Result<DirectBuildAttempt<Self>, DirectBuildAttemptError<BuildError>>
    where
        I: Iterator<Item = (u8, u8)>,
    {
        Self::build_attempt_inner(prefixes, ranges, limits)
    }

    #[allow(
        clippy::needless_range_loop,
        clippy::too_many_lines,
        reason = "the exact two-alternative attempt keeps validation, observed allocation, and publication adjacent"
    )]
    fn build_attempt_inner<I>(
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
            let owner_bytes = size_of::<Self>();
            let persistent_bytes =
                owner_bytes
                    .checked_add(prefix_bytes)
                    .ok_or(BuildError::ArithmeticOverflow {
                        computation: "persistent bytes",
                    })?;
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

            // Admission above covers both exact prefix allocations, every
            // copied byte, both Finder preprocessors, and all eight
            // zero-initialized bitmap words before any of that work occurs.
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
                build: StoredBuildAccounting {
                    prefix_bytes,
                    class_ranges,
                    shape_units,
                    work_upper_bound: work_used,
                    scratch_bytes,
                    persistent_bytes,
                    peak_bytes,
                },
            };
            tracker.publish(persistent_bytes, owner_bytes)?;
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
        BuildAccounting {
            prefix_bytes: self.build.prefix_bytes,
            class_ranges: self.build.class_ranges,
            shape_units: self.build.shape_units,
            work_upper_bound: self.build.work_upper_bound,
            scratch_bytes: self.build.scratch_bytes,
            persistent_bytes: self.build.persistent_bytes,
            peak_bytes: self.build.peak_bytes,
        }
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
            initialized_run_scanner_bytes: 0,
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

    #[must_use]
    pub const fn span_sum_identity(&self) -> OperationIdentity {
        OperationIdentity {
            plan_id: PLAN_ID,
            operation_id: SPAN_SUM_OPERATION_ID,
            alternatives: 2,
            unicode: false,
            non_overlapping: true,
        }
    }

    #[must_use]
    pub const fn exists_identity(&self) -> OperationIdentity {
        self.search_operation_identity(EXISTS_OPERATION_ID)
    }

    #[must_use]
    pub const fn search_identity(&self) -> OperationIdentity {
        self.search_operation_identity(SEARCH_OPERATION_ID)
    }

    #[must_use]
    pub const fn shortest_identity(&self) -> OperationIdentity {
        self.search_operation_identity(SHORTEST_SEARCH_OPERATION_ID)
    }

    const fn search_operation_identity(&self, operation_id: &'static str) -> OperationIdentity {
        OperationIdentity {
            plan_id: PLAN_ID,
            operation_id,
            alternatives: 2,
            unicode: false,
            non_overlapping: true,
        }
    }

    /// Publish the scalar plan's exact source-free full-window count envelope.
    pub fn count_upper_bounds(
        &self,
        haystack_len: usize,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        derive_reduce_upper_bounds(
            self.build_accounting(),
            haystack_len,
            ReduceImplementation::Scalar,
            Operation::Count,
        )
    }

    /// Publish the scalar plan's exact source-free full-window span-sum envelope.
    pub fn span_sum_upper_bounds(
        &self,
        haystack_len: usize,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        derive_reduce_upper_bounds(
            self.build_accounting(),
            haystack_len,
            ReduceImplementation::Scalar,
            Operation::SpanSum,
        )
    }

    pub fn count(&self, haystack: &[u8], limits: ReduceLimits) -> Result<CountResult, ReduceError> {
        self.count_with_run_scanners(haystack, limits, self.count_identity(), [None, None])
    }

    fn count_with_run_scanners(
        &self,
        haystack: &[u8],
        limits: ReduceLimits,
        identity: OperationIdentity,
        run_scanners: [Option<&AsciiByteSetRunScanner>; RUN_SCANNERS],
    ) -> Result<CountResult, ReduceError> {
        let upper_bounds = self.preflight_with_run_scanners(
            haystack.len(),
            Operation::Count,
            limits,
            run_scanners[0].is_some(),
        )?;
        let actual = self.scan_with_run_scanners(
            haystack,
            Operation::Count,
            upper_bounds,
            run_scanners,
            |_| {},
        )?;
        Ok(CountResult {
            count: actual.count,
            accounting: ReduceAccounting {
                identity,
                upper_bounds,
                actual,
            },
        })
    }

    pub fn span_sum(
        &self,
        haystack: &[u8],
        limits: ReduceLimits,
    ) -> Result<SpanSumResult, ReduceError> {
        self.span_sum_with_run_scanners(haystack, limits, self.span_sum_identity(), [None, None])
    }

    fn span_sum_with_run_scanners(
        &self,
        haystack: &[u8],
        limits: ReduceLimits,
        identity: OperationIdentity,
        run_scanners: [Option<&AsciiByteSetRunScanner>; RUN_SCANNERS],
    ) -> Result<SpanSumResult, ReduceError> {
        let upper_bounds = self.preflight_with_run_scanners(
            haystack.len(),
            Operation::SpanSum,
            limits,
            run_scanners[0].is_some(),
        )?;
        let actual = self.scan_with_run_scanners(
            haystack,
            Operation::SpanSum,
            upper_bounds,
            run_scanners,
            |_| {},
        )?;
        Ok(SpanSumResult {
            span_sum: actual.span_sum,
            accounting: ReduceAccounting {
                identity,
                upper_bounds,
                actual,
            },
        })
    }

    /// Bind a monotone selected-span continuation to this plan and source.
    #[doc(hidden)]
    #[must_use]
    pub const fn search_cursor<'p, 'h>(
        &'p self,
        haystack: &'h [u8],
    ) -> PrefixClassAlternationSearchCursor<'p, 'h> {
        PrefixClassAlternationSearchCursor::new(self, haystack)
    }

    /// Find the selected leftmost-first span in the complete haystack.
    pub fn find(
        &self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<(Option<(usize, usize)>, SearchAccounting), SearchError> {
        self.find_in(haystack, Window::full(haystack), limits)
    }

    /// Find the selected leftmost-first span wholly inside `window`.
    pub fn find_in(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
    ) -> Result<(Option<(usize, usize)>, SearchAccounting), SearchError> {
        self.search_in_with_run_scanners(
            haystack,
            window,
            limits,
            SearchProjection::Selected,
            Operation::Search,
            self.search_identity(),
            [None, None],
        )
    }

    /// Report whether a match exists in the complete haystack.
    pub fn is_match(
        &self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<(bool, SearchAccounting), SearchError> {
        self.is_match_in(haystack, Window::full(haystack), limits)
    }

    /// Report whether a match exists wholly inside `window`.
    pub fn is_match_in(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
    ) -> Result<(bool, SearchAccounting), SearchError> {
        let (matched, accounting) = self.search_in_with_run_scanners(
            haystack,
            window,
            limits,
            SearchProjection::Exists,
            Operation::Exists,
            self.exists_identity(),
            [None, None],
        )?;
        Ok((matched.is_some(), accounting))
    }

    /// Return the first accepting end offset in the complete haystack.
    pub fn shortest(
        &self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<(Option<usize>, SearchAccounting), SearchError> {
        self.shortest_in(haystack, Window::full(haystack), limits)
    }

    /// Return the first accepting end offset wholly inside `window`.
    pub fn shortest_in(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
    ) -> Result<(Option<usize>, SearchAccounting), SearchError> {
        let (matched, accounting) = self.search_in_with_run_scanners(
            haystack,
            window,
            limits,
            SearchProjection::EarliestEnd,
            Operation::Shortest,
            self.shortest_identity(),
            [None, None],
        )?;
        Ok((matched.map(|(_, end)| end), accounting))
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "projection, identity, and retained scanner choice remain authenticated at one search boundary"
    )]
    fn search_in_with_run_scanners(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
        projection: SearchProjection,
        operation: Operation,
        identity: OperationIdentity,
        run_scanners: [Option<&AsciiByteSetRunScanner>; RUN_SCANNERS],
    ) -> Result<(Option<(usize, usize)>, SearchAccounting), SearchError> {
        let endpoint = match projection {
            SearchProjection::Exists => Some(EndpointProjection::Exists),
            SearchProjection::Selected => None,
            SearchProjection::EarliestEnd => Some(EndpointProjection::EarliestEnd),
        };
        if let Some(endpoint) = endpoint {
            let upper_bounds = self.search_preflight(
                haystack,
                window,
                limits,
                operation,
                false,
            )?;
            let (matched, actual) = self.execute_endpoint_search(
                haystack,
                window,
                endpoint,
                upper_bounds,
            )?;
            return Ok((
                matched,
                SearchAccounting {
                    identity,
                    window,
                    upper_bounds,
                    actual,
                },
            ));
        }
        let upper_bounds = self.search_preflight(
            haystack,
            window,
            limits,
            operation,
            run_scanners[0].is_some(),
        )?;
        let (matched, actual) = self.execute_search(
            haystack,
            window,
            projection,
            upper_bounds,
            run_scanners,
        )?;
        Ok((
            matched,
            SearchAccounting {
                identity,
                window,
                upper_bounds,
                actual,
            },
        ))
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the retained transaction keeps its identity, scanner proof, exact preflight, and test-only precommit fault at one publication boundary"
    )]
    fn search_in_with_cursor_state(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
        identity: OperationIdentity,
        run_scanners: [Option<&AsciiByteSetRunScanner>; RUN_SCANNERS],
        state: &mut PrefixClassAlternationCursorState,
        inject_late_failure: bool,
    ) -> Result<(Option<(usize, usize)>, SearchAccounting, usize), SearchError> {
        // Refuse before even resetting a stale continuation. A retry with the
        // admitted envelope must observe exactly the prior candidate state.
        let upper_bounds = self.search_preflight(
            haystack,
            window,
            limits,
            Operation::Search,
            run_scanners[0].is_some(),
        )?;
        let mut next = *state;
        let reset = next.prepare(window);
        let prepaid_work = if reset { upper_bounds.work } else { 0 };
        let (matched, actual) = self.execute_search_with_cursor(
            haystack,
            window,
            upper_bounds,
            run_scanners,
            &mut next,
        )?;
        if inject_late_failure {
            return Err(ReduceError::AccountingInvariant {
                resource: "injected prefix cursor precommit failure",
                actual: 1,
                upper: 0,
            });
        }
        *state = next;
        Ok((
            matched,
            SearchAccounting {
                identity,
                window,
                upper_bounds,
                actual,
            },
            prepaid_work,
        ))
    }

    fn fill_cursor_stream(
        &self,
        haystack: &[u8],
        window: Window,
        alternative: usize,
        state: &mut StoredPrefixCandidateStreamState,
    ) -> Result<(), SearchError> {
        loop {
            match state.state() {
                PrefixCandidateStreamState::Exhausted => return Ok(()),
                PrefixCandidateStreamState::Ready { start, .. }
                    if start >= window.start() =>
                {
                    return Ok(());
                }
                PrefixCandidateStreamState::Ready { next_from, .. } => {
                    state.set_need(next_from.max(window.start()));
                }
                PrefixCandidateStreamState::Need { from } => {
                    let from = from.max(window.start());
                    let search = haystack.get(from..window.end()).ok_or(
                        ReduceError::InvalidWindow {
                            start: window.start(),
                            end: window.end(),
                            haystack_len: haystack.len(),
                        },
                    )?;
                    let Some(relative) = self.alternatives[alternative].finder.find(search) else {
                        state.set_exhausted();
                        return Ok(());
                    };
                    let start = from.checked_add(relative).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "retained prefix candidate start",
                        },
                    )?;
                    // Admission proves the literal nonempty and that its first
                    // byte does not recur in the remainder. Therefore no
                    // occurrence can begin inside this consumed literal.
                    let next_from = start
                        .checked_add(self.alternatives[alternative].finder.needle().len())
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "retained prefix stream restart",
                        })?;
                    state.set_ready(start, next_from)?;
                    return Ok(());
                }
            }
        }
    }

    #[allow(
        clippy::needless_range_loop,
        clippy::too_many_lines,
        reason = "the two retained streams keep merge priority, candidate consumption, class reads, and continuation publication adjacent"
    )]
    fn execute_search_with_cursor(
        &self,
        haystack: &[u8],
        window: Window,
        upper: ReduceUpperBounds,
        run_scanners: [Option<&AsciiByteSetRunScanner>; RUN_SCANNERS],
        continuation: &mut PrefixClassAlternationCursorState,
    ) -> Result<(Option<(usize, usize)>, ReduceActualCounters), SearchError> {
        let bounded_haystack = haystack.get(..window.end()).ok_or(
            ReduceError::InvalidWindow {
                start: window.start(),
                end: window.end(),
                haystack_len: haystack.len(),
            },
        )?;
        let mut prefix_candidates = 0_usize;
        let mut class_bytes = 0_usize;
        loop {
            for alternative in 0..2 {
                self.fill_cursor_stream(
                    haystack,
                    window,
                    alternative,
                    &mut continuation.streams[alternative],
                )?;
            }
            let alternative = match (
                continuation.streams[0].state(),
                continuation.streams[1].state(),
            ) {
                (
                    PrefixCandidateStreamState::Exhausted,
                    PrefixCandidateStreamState::Exhausted,
                ) => {
                    continuation.exhaust();
                    return finish_search_execution(
                        None,
                        prefix_candidates,
                        class_bytes,
                        upper,
                    );
                }
                (PrefixCandidateStreamState::Ready { .. }, PrefixCandidateStreamState::Exhausted) => 0,
                (PrefixCandidateStreamState::Exhausted, PrefixCandidateStreamState::Ready { .. }) => 1,
                (
                    PrefixCandidateStreamState::Ready { start: left, .. },
                    PrefixCandidateStreamState::Ready { start: right, .. },
                ) => usize::from(right < left),
                _ => {
                    return Err(ReduceError::AccountingInvariant {
                        resource: "retained prefix stream readiness",
                        actual: 1,
                        upper: 0,
                    });
                }
            };
            let PrefixCandidateStreamState::Ready { start, next_from } =
                continuation.streams[alternative].state()
            else {
                return Err(ReduceError::AccountingInvariant {
                    resource: "selected retained prefix stream",
                    actual: 1,
                    upper: 0,
                });
            };
            continuation.streams[alternative].set_need(next_from);
            prefix_candidates = prefix_candidates.checked_add(1).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "retained prefix candidate count",
                },
            )?;
            let prefix_end = start
                .checked_add(self.alternatives[alternative].finder.needle().len())
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "retained prefix literal end",
                })?;
            if prefix_end >= window.end() {
                continue;
            }
            let first_class_byte = *haystack.get(prefix_end).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "retained prefix first class byte",
                },
            )?;
            class_bytes = class_bytes.checked_add(1).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "retained prefix classification count",
                },
            )?;
            if !self.alternatives[alternative]
                .class
                .contains(first_class_byte)
            {
                continue;
            }
            let accepting_end = prefix_end.checked_add(1).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "retained prefix first accepting end",
                },
            )?;
            let extension = extend_greedy_class(
                bounded_haystack,
                accepting_end,
                self.alternatives[alternative].class,
                run_scanners[alternative],
            );
            class_bytes = class_bytes
                .checked_add(extension.physical_classifications)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "retained prefix greedy classifications",
                })?;
            continuation.retain_match(extension.end);
            return finish_search_execution(
                Some((start, extension.end)),
                prefix_candidates,
                class_bytes,
                upper,
            );
        }
    }

    fn search_preflight(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
        operation: Operation,
        run_scanners: bool,
    ) -> Result<ReduceUpperBounds, SearchError> {
        if window.start() > window.end() || window.end() > haystack.len() {
            return Err(ReduceError::InvalidWindow {
                start: window.start(),
                end: window.end(),
                haystack_len: haystack.len(),
            });
        }
        let window_bytes = window.end().checked_sub(window.start()).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "prefix/class search window byte length",
            },
        )?;
        let implementation = if run_scanners {
            ReduceImplementation::DispatchedRunScanners
        } else {
            ReduceImplementation::Scalar
        };
        let upper_bounds =
            derive_reduce_upper_bounds(self.build_accounting(), window_bytes, implementation, operation)?;
        let work = u64::try_from(upper_bounds.work).unwrap_or(u64::MAX);
        if work > limits.max_work_upper_bound {
            return Err(ReduceError::WorkLimit {
                needed: upper_bounds.work,
                limit: usize::try_from(limits.max_work_upper_bound).unwrap_or(usize::MAX),
            });
        }
        enforce_reduce(
            upper_bounds.scratch_bytes,
            limits.max_scratch_bytes,
            ReduceResource::Scratch,
        )?;
        Ok(upper_bounds)
    }

    /// Search the union of both first-byte streams once, then authenticate
    /// only the alternatives whose literal can begin at each monotone hit.
    ///
    /// Admission proves that a literal's first byte does not recur in its
    /// remainder. Consequently the exact comparisons between successive
    /// first-byte hits cover disjoint source intervals except for their
    /// boundary byte. Across both alternatives this remains linear in the
    /// window and needs no operation storage. Existence returns after one
    /// exact literal and its first class member. Earliest-end retains only the
    /// best `literal_end + 1` and never invokes greedy class extension. Dense
    /// false anchors hand off once to the established exact-literal merge at
    /// the first unprocessed start.
    #[allow(
        clippy::needless_range_loop,
        reason = "the fixed two alternatives preserve source priority at equal candidate starts"
    )]
    fn execute_endpoint_search(
        &self,
        haystack: &[u8],
        window: Window,
        projection: EndpointProjection,
        upper: ReduceUpperBounds,
    ) -> Result<(Option<(usize, usize)>, ReduceActualCounters), SearchError> {
        let first_bytes = [
            *self.alternatives[0]
                .finder
                .needle()
                .first()
                .ok_or(ReduceError::AccountingInvariant {
                    resource: "empty first endpoint prefix",
                    actual: 1,
                    upper: 0,
                })?,
            *self.alternatives[1]
                .finder
                .needle()
                .first()
                .ok_or(ReduceError::AccountingInvariant {
                    resource: "empty second endpoint prefix",
                    actual: 1,
                    upper: 0,
                })?,
        ];
        let mut cursor = window.start();
        let mut anchor_candidates = 0_usize;
        let mut prefix_candidates = 0_usize;
        let mut class_bytes = 0_usize;
        let mut earliest = None::<(usize, usize)>;
        loop {
            let scan_end = earliest.map_or(window.end(), |(_, end)| end);
            if cursor >= scan_end {
                return finish_search_execution(
                    earliest,
                    prefix_candidates,
                    class_bytes,
                    upper,
                );
            }
            let searched = haystack.get(cursor..scan_end).ok_or(
                ReduceError::InvalidWindow {
                    start: window.start(),
                    end: window.end(),
                    haystack_len: haystack.len(),
                },
            )?;
            let relative = if first_bytes[0] == first_bytes[1] {
                memchr(first_bytes[0], searched)
            } else {
                memchr2(first_bytes[0], first_bytes[1], searched)
            };
            let Some(relative) = relative else {
                return finish_search_execution(
                    earliest,
                    prefix_candidates,
                    class_bytes,
                    upper,
                );
            };
            let start = cursor.checked_add(relative).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "direct endpoint candidate start",
                },
            )?;
            cursor = start.checked_add(1).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "direct endpoint candidate advance",
                },
            )?;
            anchor_candidates = anchor_candidates.checked_add(1).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "direct endpoint anchor candidate count",
                },
            )?;
            let first_byte = *haystack.get(start).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "direct endpoint first-byte hit",
                },
            )?;
            for alternative in 0..2 {
                if first_bytes[alternative] != first_byte {
                    continue;
                }
                let prefix = self.alternatives[alternative].finder.needle();
                let prefix_end = start.checked_add(prefix.len()).ok_or(
                    ReduceError::ArithmeticOverflow {
                        computation: "direct endpoint literal end",
                    },
                )?;
                if prefix_end > window.end() {
                    continue;
                }
                let candidate = haystack.get(start..prefix_end).ok_or(
                    ReduceError::InvalidWindow {
                        start: window.start(),
                        end: window.end(),
                        haystack_len: haystack.len(),
                    },
                )?;
                if candidate != prefix {
                    continue;
                }
                prefix_candidates = prefix_candidates.checked_add(1).ok_or(
                    ReduceError::ArithmeticOverflow {
                        computation: "direct endpoint prefix candidate count",
                    },
                )?;
                if prefix_end == window.end() {
                    continue;
                }
                let first_class_byte = *haystack.get(prefix_end).ok_or(
                    ReduceError::ArithmeticOverflow {
                        computation: "direct endpoint first class byte",
                    },
                )?;
                class_bytes = class_bytes.checked_add(1).ok_or(
                    ReduceError::ArithmeticOverflow {
                        computation: "direct endpoint classification count",
                    },
                )?;
                if !self.alternatives[alternative]
                    .class
                    .contains(first_class_byte)
                {
                    continue;
                }
                let accepting_end = prefix_end.checked_add(1).ok_or(
                    ReduceError::ArithmeticOverflow {
                        computation: "direct endpoint first accepting end",
                    },
                )?;
                match projection {
                    EndpointProjection::Exists => {
                        return finish_search_execution(
                            Some((start, accepting_end)),
                            prefix_candidates,
                            class_bytes,
                            upper,
                        );
                    }
                    EndpointProjection::EarliestEnd => {
                        if earliest.is_none_or(|(_, old_end)| accepting_end < old_end) {
                            earliest = Some((start, accepting_end));
                        }
                    }
                }
            }
            if earliest.is_none() && anchor_candidates >= DIRECT_ENDPOINT_ANCHOR_BUDGET {
                // A first byte can be much denser than either complete
                // literal. Bound scalar restart overhead, then resume from
                // the first unprocessed start with the established Finder
                // merge. The direct prefix is failure-only here, so combining
                // both exact counter fragments preserves one atomic receipt.
                let fallback_window = Window::new(cursor, window.end());
                let fallback_projection = match projection {
                    EndpointProjection::Exists => SearchProjection::Exists,
                    EndpointProjection::EarliestEnd => SearchProjection::EarliestEnd,
                };
                let (matched, fallback) = self.execute_search(
                    haystack,
                    fallback_window,
                    fallback_projection,
                    upper,
                    [None, None],
                )?;
                prefix_candidates = prefix_candidates
                    .checked_add(fallback.prefix_candidates)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "combined direct endpoint prefix candidates",
                    })?;
                class_bytes = class_bytes.checked_add(fallback.class_bytes).ok_or(
                    ReduceError::ArithmeticOverflow {
                        computation: "combined direct endpoint classifications",
                    },
                )?;
                return finish_search_execution(
                    matched,
                    prefix_candidates,
                    class_bytes,
                    upper,
                );
            }
        }
    }

    #[allow(
        clippy::needless_range_loop,
        clippy::too_many_lines,
        reason = "the two monotone streams keep source reads, exact counters, and early-stop proofs adjacent"
    )]
    fn execute_search(
        &self,
        haystack: &[u8],
        window: Window,
        projection: SearchProjection,
        upper: ReduceUpperBounds,
        run_scanners: [Option<&AsciiByteSetRunScanner>; RUN_SCANNERS],
    ) -> Result<(Option<(usize, usize)>, ReduceActualCounters), SearchError> {
        let input = haystack.get(window.start()..window.end()).ok_or(
            ReduceError::InvalidWindow {
                start: window.start(),
                end: window.end(),
                haystack_len: haystack.len(),
            },
        )?;
        let bounded_haystack = haystack.get(..window.end()).ok_or(
            ReduceError::InvalidWindow {
                start: window.start(),
                end: window.end(),
                haystack_len: haystack.len(),
            },
        )?;
        let mut streams = [
            self.alternatives[0].finder.find_iter(input),
            self.alternatives[1].finder.find_iter(input),
        ];
        let mut next = [None; 2];
        for alternative in 0..2 {
            next[alternative] = streams[alternative]
                .next()
                .map(|relative| {
                    window.start().checked_add(relative).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "absolute prefix/class candidate start",
                        },
                    )
                })
                .transpose()?;
        }

        let mut prefix_candidates = 0_usize;
        let mut class_bytes = 0_usize;
        let mut earliest = None::<(usize, usize)>;
        loop {
            let alternative = match (next[0], next[1]) {
                (None, None) => {
                    return finish_search_execution(
                        earliest,
                        prefix_candidates,
                        class_bytes,
                        upper,
                    );
                }
                (Some(_), None) => 0,
                (None, Some(_)) => 1,
                // Branch zero retains source priority on an equal start.
                (Some(left), Some(right)) => usize::from(right < left),
            };
            let start = next[alternative].ok_or(ReduceError::ArithmeticOverflow {
                computation: "selected prefix/class search candidate",
            })?;
            if projection == SearchProjection::EarliestEnd
                && earliest.is_some_and(|(_, end)| start >= end)
            {
                return finish_search_execution(
                    earliest,
                    prefix_candidates,
                    class_bytes,
                    upper,
                );
            }
            next[alternative] = streams[alternative]
                .next()
                .map(|relative| {
                    window.start().checked_add(relative).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "next absolute prefix/class candidate start",
                        },
                    )
                })
                .transpose()?;
            prefix_candidates = prefix_candidates.checked_add(1).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "ordinary prefix/class candidate count",
                },
            )?;
            let prefix_end = start
                .checked_add(self.alternatives[alternative].finder.needle().len())
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "ordinary prefix/class literal end",
                })?;
            if prefix_end >= window.end() {
                continue;
            }
            let first_class_byte = *haystack.get(prefix_end).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "ordinary prefix/class first class byte",
                },
            )?;
            class_bytes = class_bytes.checked_add(1).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "ordinary prefix/class classification count",
                },
            )?;
            if !self.alternatives[alternative]
                .class
                .contains(first_class_byte)
            {
                continue;
            }
            let accepting_end = prefix_end.checked_add(1).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "ordinary prefix/class first accepting end",
                },
            )?;
            match projection {
                SearchProjection::Exists => {
                    return finish_search_execution(
                        Some((start, accepting_end)),
                        prefix_candidates,
                        class_bytes,
                        upper,
                    );
                }
                SearchProjection::Selected => {
                    let extension = extend_greedy_class(
                        bounded_haystack,
                        accepting_end,
                        self.alternatives[alternative].class,
                        run_scanners[alternative],
                    );
                    class_bytes = class_bytes
                        .checked_add(extension.physical_classifications)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "ordinary prefix/class greedy classifications",
                        })?;
                    return finish_search_execution(
                        Some((start, extension.end)),
                        prefix_candidates,
                        class_bytes,
                        upper,
                    );
                }
                SearchProjection::EarliestEnd => {
                    if earliest.is_none_or(|(_, old_end)| accepting_end < old_end) {
                        earliest = Some((start, accepting_end));
                    }
                }
            }
        }
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
        self.uniform_participation_prospective_with_run_scanners(haystack_len, schema, false)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the scalar and dispatched paths share one source-free prospective ledger"
    )]
    fn uniform_participation_prospective_with_run_scanners(
        &self,
        haystack_len: usize,
        schema: UniformParticipationSchema,
        run_scanners: bool,
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
        let scanner_overhead = if run_scanners {
            haystack_len
                .checked_mul(ASCII_RUN_MAX_CLASSIFICATION_OVERHEAD)
                .ok_or(UniformParticipationError::ArithmeticOverflow {
                    computation: "greedy extension scanner overhead",
                })?
        } else {
            0
        };
        let greedy_extension_reads = haystack_len
            .checked_mul(2)
            .and_then(|reads| reads.checked_add(scanner_overhead))
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
        self.count_uniform_participation_attempt_with_run_scanners(
            haystack,
            schema,
            limits,
            self.uniform_participation_identity(schema),
            [None, None],
        )
    }

    #[allow(
        clippy::result_large_err,
        reason = "the fixed-layout terminal receipt deliberately preserves complete direct P/A without allocating"
    )]
    fn count_uniform_participation_attempt_with_run_scanners(
        &self,
        haystack: &[u8],
        schema: UniformParticipationSchema,
        limits: UniformParticipationLimits,
        identity: UniformParticipationIdentity,
        run_scanners: [Option<&AsciiByteSetRunScanner>; RUN_SCANNERS],
    ) -> Result<UniformParticipationAttempt, UniformParticipationAttemptError> {
        let mut receipt =
            self.uniform_participation_attempt_receipt(haystack.len(), schema, limits);
        receipt.identity = identity;
        let invocation = receipt.invocation;
        let prospective = self
            .uniform_participation_prospective_with_run_scanners(
                haystack.len(),
                schema,
                run_scanners[0].is_some(),
            )
            .map_err(|source| uniform_attempt_error(source, receipt, identity, invocation))?;
        receipt.prospective = Some(prospective);
        self.enforce_uniform_participation(prospective, limits)
            .map_err(|source| uniform_attempt_error(source, receipt, identity, invocation))?;
        let matches = match self.scan_uniform_participation_with_run_scanners(
            haystack,
            schema,
            prospective,
            &mut receipt,
            run_scanners,
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
    #[cfg(test)]
    fn scan_uniform_participation(
        &self,
        haystack: &[u8],
        schema: UniformParticipationSchema,
        prospective: UniformParticipationProspective,
        receipt: &mut UniformParticipationAttemptReceipt,
        emit: impl FnMut(Range<usize>) -> Result<(), UniformParticipationError>,
    ) -> Result<usize, UniformParticipationError> {
        self.scan_uniform_participation_with_run_scanners(
            haystack,
            schema,
            prospective,
            receipt,
            [None, None],
            emit,
        )
    }

    #[allow(
        clippy::needless_range_loop,
        clippy::too_many_lines,
        reason = "the fixed two-stream scan keeps each source read and its checked direct-operation counter adjacent"
    )]
    fn scan_uniform_participation_with_run_scanners(
        &self,
        haystack: &[u8],
        schema: UniformParticipationSchema,
        prospective: UniformParticipationProspective,
        receipt: &mut UniformParticipationAttemptReceipt,
        run_scanners: [Option<&AsciiByteSetRunScanner>; RUN_SCANNERS],
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
            let extension_start =
                prefix_end
                    .checked_add(1)
                    .ok_or(UniformParticipationError::ArithmeticOverflow {
                        computation: "direct first class byte end",
                    })?;
            let extension = extend_greedy_class(
                haystack,
                extension_start,
                self.alternatives[alternative].class,
                run_scanners[alternative],
            );
            uniform_actual_add(
                &mut actual.greedy_extension_reads,
                extension.physical_classifications,
                "actual greedy extension reads",
            )?;
            uniform_actual_add(
                &mut actual.work,
                extension.physical_classifications,
                "actual greedy extension read work",
            )?;
            let end = extension.end;
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

    #[cfg(test)]
    fn preflight(
        &self,
        haystack_len: usize,
        limits: ReduceLimits,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        self.preflight_with_run_scanners(haystack_len, Operation::Count, limits, false)
    }

    fn preflight_with_run_scanners(
        &self,
        haystack_len: usize,
        operation: Operation,
        limits: ReduceLimits,
        run_scanners: bool,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        let implementation = if run_scanners {
            ReduceImplementation::DispatchedRunScanners
        } else {
            ReduceImplementation::Scalar
        };
        let upper = derive_reduce_upper_bounds(
            self.build_accounting(),
            haystack_len,
            implementation,
            operation,
        )?;
        enforce_reduce(upper.work, limits.max_work, ReduceResource::Work)?;
        enforce_reduce(
            upper.match_events,
            limits.max_match_events,
            ReduceResource::MatchEvents,
        )?;
        if upper.count > limits.max_count {
            return Err(ReduceError::CountLimit {
                needed: upper.count,
                limit: limits.max_count,
            });
        }
        if upper.span_sum > limits.max_span_sum {
            return Err(ReduceError::SpanSumLimit {
                needed: upper.span_sum,
                limit: limits.max_span_sum,
            });
        }
        enforce_reduce(
            upper.scratch_bytes,
            limits.max_scratch_bytes,
            ReduceResource::Scratch,
        )?;
        enforce_reduce(
            upper.peak_bytes,
            limits.max_peak_bytes,
            ReduceResource::Peak,
        )?;
        Ok(upper)
    }

    #[allow(
        clippy::needless_range_loop,
        reason = "numeric indices preserve stable alternative priority across paired iterator and candidate arrays"
    )]
    #[cfg(test)]
    fn scan(
        &self,
        haystack: &[u8],
        upper: ReduceUpperBounds,
        emit: impl FnMut(Range<usize>),
    ) -> Result<ReduceActualCounters, ReduceError> {
        self.scan_with_run_scanners(haystack, Operation::Count, upper, [None, None], emit)
    }

    #[allow(
        clippy::needless_range_loop,
        reason = "numeric indices preserve stable alternative priority across paired iterator, candidate, and scanner arrays"
    )]
    fn scan_with_run_scanners(
        &self,
        haystack: &[u8],
        operation: Operation,
        upper: ReduceUpperBounds,
        run_scanners: [Option<&AsciiByteSetRunScanner>; RUN_SCANNERS],
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
        let mut span_sum = 0_u64;
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
            let extension_start =
                prefix_end
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "first class byte end",
                    })?;
            let extension = extend_greedy_class(
                haystack,
                extension_start,
                self.alternatives[alternative].class,
                run_scanners[alternative],
            );
            class_bytes = class_bytes
                .checked_add(extension.physical_classifications)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "class byte count",
                })?;
            let end = extension.end;
            emit(start..end);
            if operation == Operation::SpanSum {
                let width = end
                    .checked_sub(start)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "actual match width",
                    })?;
                span_sum = span_sum
                    .checked_add(u64::try_from(width).map_err(|_| {
                        ReduceError::ArithmeticOverflow {
                            computation: "actual match width as u64",
                        }
                    })?)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "actual span sum",
                    })?;
            }
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
            span_sum,
        })
    }
}

fn finish_search_execution(
    matched: Option<(usize, usize)>,
    prefix_candidates: usize,
    class_bytes: usize,
    upper: ReduceUpperBounds,
) -> Result<(Option<(usize, usize)>, ReduceActualCounters), SearchError> {
    let matches = usize::from(matched.is_some());
    verify_search_counter(
        "prefix candidates",
        prefix_candidates,
        upper.prefix_candidates,
    )?;
    verify_search_counter("class bytes", class_bytes, upper.class_bytes)?;
    verify_search_counter("match events", matches, upper.match_events)?;
    Ok((
        matched,
        ReduceActualCounters {
            prefix_candidates,
            class_bytes,
            matches,
            count: u64::try_from(matches).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "ordinary prefix/class match count as u64",
            })?,
            span_sum: 0,
        },
    ))
}

fn verify_search_counter(
    resource: &'static str,
    actual: usize,
    upper: usize,
) -> Result<(), SearchError> {
    if actual <= upper {
        return Ok(());
    }
    Err(ReduceError::AccountingInvariant {
        resource,
        actual,
        upper,
    })
}

impl DispatchedPrefixClassAlternationPlan {
    /// Build the distinct fixed-16 SVE owner from one caller-captured host
    /// snapshot. Hosts without OS-usable SVE are rejected before input access.
    pub fn build_with_dispatch<I>(
        dispatch: SimdDispatchContext,
        prefixes: [&[u8]; 2],
        ranges: [I; 2],
        limits: BuildLimits,
    ) -> Result<Self, BuildError>
    where
        I: Iterator<Item = (u8, u8)>,
    {
        Self::build_attempt_with_dispatch(dispatch, prefixes, ranges, limits)
            .map(DirectBuildAttempt::into_plan)
            .map_err(DirectBuildAttemptError::into_source)
    }

    /// Build the fixed-16 SVE owner with exact observed construction effects.
    #[allow(
        clippy::too_many_lines,
        reason = "the source-free dispatched envelope, scalar attempt mapping, ASCII proof, and exact owner publication remain adjacent"
    )]
    pub fn build_attempt_with_dispatch<I>(
        dispatch: SimdDispatchContext,
        prefixes: [&[u8]; 2],
        ranges: [I; 2],
        limits: BuildLimits,
    ) -> Result<DirectBuildAttempt<Self>, DirectBuildAttemptError<BuildError>>
    where
        I: Iterator<Item = (u8, u8)>,
    {
        let Some(policy) = run_scanner_policy(dispatch) else {
            return Err(DirectBuildAttemptError::new(
                BuildError::RunScannerDispatchUnavailable,
                DirectBuildAttemptActual::default(),
            ));
        };
        let empty_actual = DirectBuildAttemptActual::default();
        let scanner_work = SIMD_RUN_SCANNER_BUILD_WORK
            .checked_mul(RUN_SCANNERS)
            .ok_or(DirectBuildAttemptError::new(
                BuildError::ArithmeticOverflow {
                    computation: "run scanner construction work",
                },
                empty_actual,
            ))?;
        let scalar_work_limit =
            limits
                .max_build_work
                .checked_sub(scanner_work)
                .ok_or(DirectBuildAttemptError::new(
                    BuildError::WorkLimit {
                        needed: scanner_work,
                        limit: limits.max_build_work,
                    },
                    empty_actual,
                ))?;
        let prefix_bytes = prefixes[0].len().checked_add(prefixes[1].len()).ok_or(
            DirectBuildAttemptError::new(
                BuildError::ArithmeticOverflow {
                    computation: "dispatched prefix byte total",
                },
                empty_actual,
            ),
        )?;
        let persistent_bytes = size_of::<Self>()
            .checked_add(size_of::<DispatchedPrefixClassAlternationOwner>())
            .and_then(|bytes| bytes.checked_add(prefix_bytes))
            .ok_or(DirectBuildAttemptError::new(
                BuildError::ArithmeticOverflow {
                    computation: "dispatched persistent bytes",
                },
                empty_actual,
            ))?;
        for result in [
            enforce_build(
                persistent_bytes,
                limits.max_persistent_bytes,
                BuildResource::Persistent,
            ),
            enforce_build(persistent_bytes, limits.max_peak_bytes, BuildResource::Peak),
        ] {
            if let Err(source) = result {
                return Err(DirectBuildAttemptError::new(source, empty_actual));
            }
        }
        let scalar_limits = BuildLimits {
            max_build_work: scalar_work_limit,
            ..limits
        };
        let attempt =
            match PrefixClassAlternationPlan::build_attempt(prefixes, ranges, scalar_limits) {
                Ok(attempt) => attempt,
                Err(error) => {
                    let actual = error.actual();
                    let source = match error.into_source() {
                        BuildError::WorkLimit { needed, .. } => {
                            let needed = needed.checked_add(scanner_work).ok_or(
                                DirectBuildAttemptError::new(
                                    BuildError::ArithmeticOverflow {
                                        computation: "dispatched build work refusal",
                                    },
                                    actual,
                                ),
                            )?;
                            BuildError::WorkLimit {
                                needed,
                                limit: limits.max_build_work,
                            }
                        }
                        source => source,
                    };
                    return Err(DirectBuildAttemptError::new(source, actual));
                }
            };
        let (plan, mut actual) = attempt.into_parts();
        for (alternative, candidate) in plan.alternatives.iter().enumerate() {
            if !candidate.class.is_ascii() {
                actual.live_persistent_bytes = 0;
                return Err(DirectBuildAttemptError::new(
                    BuildError::NonAsciiRunScannerClass { alternative },
                    actual,
                ));
            }
        }
        build_dispatched_prefix_class_owner(
            dispatch,
            policy,
            plan,
            actual,
            persistent_bytes,
            scanner_work,
        )
    }

    /// Build the dispatched owner under the complete capture-aware envelope.
    pub fn build_uniform_participation_with_dispatch<I>(
        dispatch: SimdDispatchContext,
        prefixes: [&[u8]; 2],
        ranges: [I; 2],
        limits: UniformParticipationBuildLimits,
    ) -> Result<Self, UniformParticipationBuildError>
    where
        I: Iterator<Item = (u8, u8)>,
    {
        Self::build_uniform_participation_attempt_with_dispatch(dispatch, prefixes, ranges, limits)
            .map(DirectBuildAttempt::into_plan)
            .map_err(DirectBuildAttemptError::into_source)
    }

    /// Build the dispatched capture-aware owner with exact observed effects.
    pub fn build_uniform_participation_attempt_with_dispatch<I>(
        dispatch: SimdDispatchContext,
        prefixes: [&[u8]; 2],
        ranges: [I; 2],
        limits: UniformParticipationBuildLimits,
    ) -> Result<DirectBuildAttempt<Self>, DirectBuildAttemptError<UniformParticipationBuildError>>
    where
        I: Iterator<Item = (u8, u8)>,
    {
        preflight_uniform_participation_build(
            prefixes,
            1,
            size_of::<RunScanners>(),
            size_of::<DispatchedPrefixClassAlternationOwner>(),
            limits,
        )?;
        match Self::build_attempt_with_dispatch(dispatch, prefixes, ranges, limits.kernel()) {
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

    #[must_use]
    pub fn build_accounting(&self) -> BuildAccounting {
        let established = self.plan().build_accounting();
        BuildAccounting {
            prefix_bytes: established.prefix_bytes,
            class_ranges: established.class_ranges,
            shape_units: established.shape_units,
            work_upper_bound: established.work_upper_bound,
            scratch_bytes: established.scratch_bytes,
            persistent_bytes: established.persistent_bytes,
            peak_bytes: established.peak_bytes,
        }
    }

    #[must_use]
    pub const fn run_scanner_build_accounting(&self) -> RunScannerBuildAccounting {
        RunScannerBuildAccounting {
            build_work: SIMD_RUN_SCANNER_BUILD_WORK * RUN_SCANNERS,
            scanners: RUN_SCANNERS,
            allocations: 1,
            initialized_bytes: size_of::<RunScanners>(),
            retained_allocation_bytes: size_of::<DispatchedPrefixClassAlternationOwner>(),
        }
    }

    #[must_use]
    pub fn uniform_participation_build_accounting(&self) -> UniformParticipationBuildAccounting {
        let established = self.plan().uniform_participation_build_accounting();
        UniformParticipationBuildAccounting {
            prefix_bytes: established.prefix_bytes,
            class_ranges: established.class_ranges,
            shape_units: established.shape_units,
            work_upper_bound: established.work_upper_bound,
            allocations: established.allocations + 1,
            copied_prefix_bytes: established.copied_prefix_bytes,
            finder_preprocess_input_bytes: established.finder_preprocess_input_bytes,
            initialized_bitmap_bytes: established.initialized_bitmap_bytes,
            initialized_run_scanner_bytes: size_of::<RunScanners>(),
            scratch_bytes: established.scratch_bytes,
            persistent_bytes: established.persistent_bytes,
            retained_capacity_bytes: established.retained_capacity_bytes
                + size_of::<DispatchedPrefixClassAlternationOwner>(),
            peak_bytes: established.peak_bytes,
        }
    }

    #[must_use]
    pub const fn count_identity(&self) -> OperationIdentity {
        OperationIdentity {
            plan_id: DISPATCHED_PLAN_ID,
            operation_id: COUNT_OPERATION_ID,
            alternatives: 2,
            unicode: false,
            non_overlapping: true,
        }
    }

    #[must_use]
    pub const fn span_sum_identity(&self) -> OperationIdentity {
        OperationIdentity {
            plan_id: DISPATCHED_PLAN_ID,
            operation_id: SPAN_SUM_OPERATION_ID,
            alternatives: 2,
            unicode: false,
            non_overlapping: true,
        }
    }

    #[must_use]
    pub const fn exists_identity(&self) -> OperationIdentity {
        self.search_operation_identity(EXISTS_OPERATION_ID)
    }

    #[must_use]
    pub const fn search_identity(&self) -> OperationIdentity {
        self.search_operation_identity(SEARCH_OPERATION_ID)
    }

    #[must_use]
    pub const fn shortest_identity(&self) -> OperationIdentity {
        self.search_operation_identity(SHORTEST_SEARCH_OPERATION_ID)
    }

    const fn search_operation_identity(&self, operation_id: &'static str) -> OperationIdentity {
        OperationIdentity {
            plan_id: DISPATCHED_PLAN_ID,
            operation_id,
            alternatives: 2,
            unicode: false,
            non_overlapping: true,
        }
    }

    /// Publish the dispatched plan's exact source-free full-window count
    /// envelope, including retained run-scanner classifications.
    pub fn count_upper_bounds(
        &self,
        haystack_len: usize,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        derive_reduce_upper_bounds(
            self.build_accounting(),
            haystack_len,
            ReduceImplementation::DispatchedRunScanners,
            Operation::Count,
        )
    }

    /// Publish the dispatched plan's exact source-free full-window span-sum
    /// envelope, including retained run-scanner classifications.
    pub fn span_sum_upper_bounds(
        &self,
        haystack_len: usize,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        derive_reduce_upper_bounds(
            self.build_accounting(),
            haystack_len,
            ReduceImplementation::DispatchedRunScanners,
            Operation::SpanSum,
        )
    }

    pub fn count(&self, haystack: &[u8], limits: ReduceLimits) -> Result<CountResult, ReduceError> {
        self.plan().count_with_run_scanners(
            haystack,
            limits,
            self.count_identity(),
            self.scanner_refs(),
        )
    }

    pub fn span_sum(
        &self,
        haystack: &[u8],
        limits: ReduceLimits,
    ) -> Result<SpanSumResult, ReduceError> {
        self.plan().span_sum_with_run_scanners(
            haystack,
            limits,
            self.span_sum_identity(),
            self.scanner_refs(),
        )
    }

    /// Bind a monotone selected-span continuation to this plan and source.
    #[doc(hidden)]
    #[must_use]
    pub const fn search_cursor<'p, 'h>(
        &'p self,
        haystack: &'h [u8],
    ) -> DispatchedPrefixClassAlternationSearchCursor<'p, 'h> {
        DispatchedPrefixClassAlternationSearchCursor::new(self, haystack)
    }

    pub fn find(
        &self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<(Option<(usize, usize)>, SearchAccounting), SearchError> {
        self.find_in(haystack, Window::full(haystack), limits)
    }

    pub fn find_in(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
    ) -> Result<(Option<(usize, usize)>, SearchAccounting), SearchError> {
        self.plan().search_in_with_run_scanners(
            haystack,
            window,
            limits,
            SearchProjection::Selected,
            Operation::Search,
            self.search_identity(),
            self.scanner_refs(),
        )
    }

    pub fn is_match(
        &self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<(bool, SearchAccounting), SearchError> {
        self.is_match_in(haystack, Window::full(haystack), limits)
    }

    pub fn is_match_in(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
    ) -> Result<(bool, SearchAccounting), SearchError> {
        let (matched, accounting) = self.plan().search_in_with_run_scanners(
            haystack,
            window,
            limits,
            SearchProjection::Exists,
            Operation::Exists,
            self.exists_identity(),
            self.scanner_refs(),
        )?;
        Ok((matched.is_some(), accounting))
    }

    pub fn shortest(
        &self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<(Option<usize>, SearchAccounting), SearchError> {
        self.shortest_in(haystack, Window::full(haystack), limits)
    }

    pub fn shortest_in(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
    ) -> Result<(Option<usize>, SearchAccounting), SearchError> {
        let (matched, accounting) = self.plan().search_in_with_run_scanners(
            haystack,
            window,
            limits,
            SearchProjection::EarliestEnd,
            Operation::Shortest,
            self.shortest_identity(),
            self.scanner_refs(),
        )?;
        Ok((matched.map(|(_, end)| end), accounting))
    }

    #[must_use]
    pub const fn uniform_participation_identity(
        &self,
        schema: UniformParticipationSchema,
    ) -> UniformParticipationIdentity {
        UniformParticipationIdentity {
            plan_id: DISPATCHED_UNIFORM_PARTICIPATION_PLAN_ID,
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

    pub fn uniform_participation_prospective(
        &self,
        haystack_len: usize,
        schema: UniformParticipationSchema,
    ) -> Result<UniformParticipationProspective, UniformParticipationError> {
        self.plan()
            .uniform_participation_prospective_with_run_scanners(haystack_len, schema, true)
    }

    pub fn enforce_uniform_participation(
        &self,
        prospective: UniformParticipationProspective,
        limits: UniformParticipationLimits,
    ) -> Result<(), UniformParticipationError> {
        self.plan()
            .enforce_uniform_participation(prospective, limits)
    }

    #[must_use]
    pub fn uniform_participation_attempt_receipt(
        &self,
        haystack_bytes: usize,
        schema: UniformParticipationSchema,
        limits: UniformParticipationLimits,
    ) -> UniformParticipationAttemptReceipt {
        let mut receipt =
            self.plan()
                .uniform_participation_attempt_receipt(haystack_bytes, schema, limits);
        receipt.identity = self.uniform_participation_identity(schema);
        receipt
    }

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
        self.plan()
            .count_uniform_participation_attempt_with_run_scanners(
                haystack,
                schema,
                limits,
                self.uniform_participation_identity(schema),
                self.scanner_refs(),
            )
    }

    /// Stable proof of the two retained SVE/SVE2 scanner selections.
    #[must_use]
    pub fn run_scanner_selections(&self) -> [SelectionReceipt; RUN_SCANNERS] {
        let scanners = self.scanners();
        [scanners[0].selection(), scanners[1].selection()]
    }

    fn scanner_refs(&self) -> [Option<&AsciiByteSetRunScanner>; RUN_SCANNERS] {
        let scanners = self.scanners();
        [Some(&scanners[0]), Some(&scanners[1])]
    }

    fn plan(&self) -> &PrefixClassAlternationPlan {
        &self.owner().plan
    }

    fn scanners(&self) -> &RunScanners {
        &self.owner().run_scanners
    }

    fn owner(&self) -> &DispatchedPrefixClassAlternationOwner {
        self.owner.as_ref()
    }
}

#[inline(never)]
fn build_dispatched_prefix_class_owner(
    dispatch: SimdDispatchContext,
    policy: DispatchPolicy,
    mut plan: PrefixClassAlternationPlan,
    mut actual: DirectBuildAttemptActual,
    persistent_bytes: usize,
    scanner_work: usize,
) -> Result<
    DirectBuildAttempt<DispatchedPrefixClassAlternationPlan>,
    DirectBuildAttemptError<BuildError>,
> {
    let result = (|| {
        let work_upper_bound = plan
            .build
            .work_upper_bound
            .checked_add(scanner_work)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "dispatched build work",
            })?;
        actual.work = actual
            .work
            .checked_add(u64::try_from(scanner_work).map_err(|_| {
                BuildError::ArithmeticOverflow {
                    computation: "run scanner work as u64",
                }
            })?)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "actual dispatched build work",
            })?;
        let run_scanners = [
            dispatch
                .ascii_byte_set_run_scanner(plan.alternatives[0].class.ascii_set(), policy)
                .expect("the caller supplied an authentic compatible dispatch policy"),
            dispatch
                .ascii_byte_set_run_scanner(plan.alternatives[1].class.ascii_set(), policy)
                .expect("the caller supplied an authentic compatible dispatch policy"),
        ];
        plan.build.work_upper_bound = work_upper_bound;
        plan.build.persistent_bytes = persistent_bytes;
        plan.build.peak_bytes = persistent_bytes;
        let owner = DispatchedPrefixClassAlternationOwner { plan, run_scanners };
        let owner_bytes = size_of::<DispatchedPrefixClassAlternationOwner>();
        let owner = try_box_preserve(owner).map_err(|(error, _owner)| match error {
            CopyError::LayoutOverflow => BuildError::ArithmeticOverflow {
                computation: "exact dispatched owner allocation layout",
            },
            CopyError::AllocationFailed => {
                BuildError::RunScannerAllocationFailed { bytes: owner_bytes }
            }
        })?;
        actual.allocations =
            actual
                .allocations
                .checked_add(1)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "actual dispatched owner allocation count",
                })?;
        actual.allocated_bytes = actual.allocated_bytes.checked_add(owner_bytes).ok_or(
            BuildError::ArithmeticOverflow {
                computation: "cumulative dispatched owner allocated bytes",
            },
        )?;
        actual.initialized_bytes = persistent_bytes;
        actual.live_persistent_bytes = persistent_bytes;
        actual.peak_bytes = actual.peak_bytes.max(persistent_bytes);
        Ok(DispatchedPrefixClassAlternationPlan { owner })
    })();
    match result {
        Ok(owner) => Ok(DirectBuildAttempt::new(owner, actual)),
        Err(source) => {
            actual.live_persistent_bytes = 0;
            Err(DirectBuildAttemptError::new(source, actual))
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ClassExtension {
    end: usize,
    physical_classifications: usize,
}

fn run_scanner_policy(dispatch: SimdDispatchContext) -> Option<DispatchPolicy> {
    let usable = dispatch.capabilities().usable();
    if !usable.contains(Feature::ArmSve) {
        return None;
    }
    #[cfg(feature = "static-dispatch")]
    {
        Some(DispatchPolicy::Auto)
    }
    #[cfg(not(feature = "static-dispatch"))]
    {
        let mut allowed = FeatureSet::of(Feature::ArmSve);
        if usable.contains(Feature::ArmSve2) {
            allowed = allowed.with(Feature::ArmSve2);
        }
        Some(DispatchPolicy::AllowOnly(allowed))
    }
}

fn extend_greedy_class(
    haystack: &[u8],
    start: usize,
    class: ByteClass,
    scanner: Option<&AsciiByteSetRunScanner>,
) -> ClassExtension {
    let remaining = haystack
        .get(start..)
        .expect("the validated first class byte precedes the extension");
    if let Some(scanner) = scanner {
        let result = scanner.scan_forward(remaining);
        return ClassExtension {
            end: start
                .checked_add(result.member_run_len())
                .expect("a run within one slice fits its end offset"),
            physical_classifications: result.examined_bytes(),
        };
    }
    let mut end = start;
    let mut physical_classifications = 0_usize;
    while let Some(&byte) = haystack.get(end) {
        physical_classifications = physical_classifications
            .checked_add(1)
            .expect("classifications cannot exceed the source length");
        if !class.contains(byte) {
            break;
        }
        end = end
            .checked_add(1)
            .expect("a cursor within one slice fits usize");
    }
    ClassExtension {
        end,
        physical_classifications,
    }
}

fn preflight_uniform_participation_build(
    prefixes: [&[u8]; 2],
    additional_allocations: usize,
    initialized_run_scanner_bytes: usize,
    retained_run_scanner_bytes: usize,
    limits: UniformParticipationBuildLimits,
) -> Result<(), DirectBuildAttemptError<UniformParticipationBuildError>> {
    let empty_actual = DirectBuildAttemptActual::default();
    let prefix_bytes =
        prefixes[0]
            .len()
            .checked_add(prefixes[1].len())
            .ok_or(DirectBuildAttemptError::new(
                UniformParticipationBuildError::ArithmeticOverflow {
                    computation: "direct prefix byte total",
                },
                empty_actual,
            ))?;
    let allocations =
        2_usize
            .checked_add(additional_allocations)
            .ok_or(DirectBuildAttemptError::new(
                UniformParticipationBuildError::ArithmeticOverflow {
                    computation: "direct allocation total",
                },
                empty_actual,
            ))?;
    let retained_capacity_bytes = prefix_bytes.checked_add(retained_run_scanner_bytes).ok_or(
        DirectBuildAttemptError::new(
            UniformParticipationBuildError::ArithmeticOverflow {
                computation: "direct retained capacity bytes",
            },
            empty_actual,
        ),
    )?;
    let initialized_bitmap_bytes = size_of::<[u64; 8]>();
    for (needed, limit, error) in [
        (
            allocations,
            limits.max_allocations,
            UniformParticipationBuildError::AllocationsLimit {
                needed: allocations,
                limit: limits.max_allocations,
            },
        ),
        (
            prefix_bytes,
            limits.max_copied_prefix_bytes,
            UniformParticipationBuildError::CopiedPrefixBytesLimit {
                needed: prefix_bytes,
                limit: limits.max_copied_prefix_bytes,
            },
        ),
        (
            prefix_bytes,
            limits.max_finder_preprocess_input_bytes,
            UniformParticipationBuildError::FinderPreprocessInputBytesLimit {
                needed: prefix_bytes,
                limit: limits.max_finder_preprocess_input_bytes,
            },
        ),
        (
            initialized_bitmap_bytes,
            limits.max_initialized_bitmap_bytes,
            UniformParticipationBuildError::InitializedBitmapBytesLimit {
                needed: initialized_bitmap_bytes,
                limit: limits.max_initialized_bitmap_bytes,
            },
        ),
        (
            initialized_run_scanner_bytes,
            limits.max_initialized_run_scanner_bytes,
            UniformParticipationBuildError::InitializedRunScannerBytesLimit {
                needed: initialized_run_scanner_bytes,
                limit: limits.max_initialized_run_scanner_bytes,
            },
        ),
        (
            retained_capacity_bytes,
            limits.max_retained_capacity_bytes,
            UniformParticipationBuildError::RetainedCapacityBytesLimit {
                needed: retained_capacity_bytes,
                limit: limits.max_retained_capacity_bytes,
            },
        ),
    ] {
        if needed > limit {
            return Err(DirectBuildAttemptError::new(error, empty_actual));
        }
    }
    Ok(())
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

    fn publish(&mut self, persistent_bytes: usize, owner_bytes: usize) -> Result<(), BuildError> {
        self.actual.initialized_bytes = self
            .actual
            .initialized_bytes
            .checked_add(owner_bytes)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "published prefix owner inline initialized bytes",
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
    use std::{cell::Cell, hint::black_box, rc::Rc, time::Instant};

    use regex::bytes::RegexBuilder;

    use super::*;
    use fre_simd_kernels::ASCII_NARROW_BYTES;

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

    fn execute_ordinary_search(
        plan: &PrefixClassAlternationPlan,
        haystack: &[u8],
        window: Window,
        projection: SearchProjection,
    ) -> (Option<(usize, usize)>, ReduceActualCounters) {
        let (operation, identity) = match projection {
            SearchProjection::Exists => (Operation::Exists, plan.exists_identity()),
            SearchProjection::Selected => (Operation::Search, plan.search_identity()),
            SearchProjection::EarliestEnd => (Operation::Shortest, plan.shortest_identity()),
        };
        let (matched, accounting) = plan
            .search_in_with_run_scanners(
                haystack,
                window,
                SearchLimits::unlimited(),
                projection,
                operation,
                identity,
                [None, None],
            )
            .unwrap();
        (matched, accounting.actual)
    }

    #[test]
    fn ordinary_execute_search_preserves_branch_zero_at_an_equal_start() {
        let plan = PrefixClassAlternationPlan::build(
            [b"abcd", b"ab"],
            [[(b'x', b'x')].into_iter(), [(b'c', b'c')].into_iter()],
            BuildLimits::unlimited(),
        )
        .unwrap();
        let haystack = b"abcdxxx!";
        let window = Window::full(haystack);

        let (selected, selected_actual) = execute_ordinary_search(
            &plan,
            haystack,
            window,
            SearchProjection::Selected,
        );
        assert_eq!(Some((0, 7)), selected);
        assert_eq!(1, selected_actual.prefix_candidates);

        let (exists, exists_actual) =
            execute_ordinary_search(&plan, haystack, window, SearchProjection::Exists);
        assert_eq!(Some((0, 5)), exists);
        assert_eq!(1, exists_actual.prefix_candidates);

        let (earliest, earliest_actual) = execute_ordinary_search(
            &plan,
            haystack,
            window,
            SearchProjection::EarliestEnd,
        );
        assert_eq!(Some((0, 3)), earliest);
        assert_eq!(2, earliest_actual.prefix_candidates);
    }

    #[test]
    fn ordinary_execute_search_retries_branch_one_after_equal_start_rejection() {
        let plan = PrefixClassAlternationPlan::build(
            [b"abcd", b"ab"],
            [[(b'x', b'x')].into_iter(), [(b'c', b'c')].into_iter()],
            BuildLimits::unlimited(),
        )
        .unwrap();
        let haystack = b"abcd!";
        let window = Window::full(haystack);

        for projection in [
            SearchProjection::Selected,
            SearchProjection::Exists,
            SearchProjection::EarliestEnd,
        ] {
            let (matched, actual) =
                execute_ordinary_search(&plan, haystack, window, projection);
            assert_eq!(Some((0, 3)), matched, "projection={projection:?}");
            assert_eq!(2, actual.prefix_candidates, "projection={projection:?}");
            let expected_class_bytes = if projection == SearchProjection::Selected {
                3
            } else {
                2
            };
            assert_eq!(
                expected_class_bytes,
                actual.class_bytes,
                "projection={projection:?}",
            );
        }
    }

    #[test]
    fn ordinary_execute_search_handles_duplicate_spans_inside_bounded_windows() {
        let first_class = [(b'x', b'x')];
        let second_class = [(b'c', b'd'), (b'x', b'x')];
        let plan = PrefixClassAlternationPlan::build(
            [b"abcd", b"ab"],
            [
                first_class.as_slice().iter().copied(),
                second_class.as_slice().iter().copied(),
            ],
            BuildLimits::unlimited(),
        )
        .unwrap();
        let haystack = b"##abcdxxx!!abcdxxx$$";
        let bounded = Window::new(11, 17);

        assert_eq!(
            vec![0..6],
            reference_spans(r"abcd[x]+", &haystack[bounded.start()..bounded.end()])
        );
        assert_eq!(
            vec![0..6],
            reference_spans(r"ab[cdx]+", &haystack[bounded.start()..bounded.end()])
        );
        assert_eq!(
            Some((11, 17)),
            execute_ordinary_search(&plan, haystack, bounded, SearchProjection::Selected).0
        );
        assert_eq!(
            Some((11, 16)),
            execute_ordinary_search(&plan, haystack, bounded, SearchProjection::Exists).0
        );
        assert_eq!(
            Some((11, 14)),
            execute_ordinary_search(&plan, haystack, bounded, SearchProjection::EarliestEnd).0
        );

        let first_start_excluded = Window::new(3, 18);
        assert_eq!(
            Some((11, 18)),
            execute_ordinary_search(
                &plan,
                haystack,
                first_start_excluded,
                SearchProjection::Selected,
            )
            .0
        );
        let every_start_excluded = Window::new(12, 18);
        for projection in [
            SearchProjection::Selected,
            SearchProjection::Exists,
            SearchProjection::EarliestEnd,
        ] {
            assert_eq!(
                None,
                execute_ordinary_search(&plan, haystack, every_start_excluded, projection).0,
                "projection={projection:?}",
            );
        }
    }

    fn reference_endpoint_search(
        plan: &PrefixClassAlternationPlan,
        haystack: &[u8],
        window: Window,
        projection: EndpointProjection,
    ) -> Option<(usize, usize)> {
        let mut earliest = None;
        for start in window.start()..window.end() {
            for alternative in 0..2 {
                let prefix = plan.alternatives[alternative].finder.needle();
                let Some(prefix_end) = start.checked_add(prefix.len()) else {
                    continue;
                };
                if prefix_end >= window.end()
                    || haystack.get(start..prefix_end) != Some(prefix)
                {
                    continue;
                }
                let Some(&first_class_byte) = haystack.get(prefix_end) else {
                    continue;
                };
                if !plan.alternatives[alternative]
                    .class
                    .contains(first_class_byte)
                {
                    continue;
                }
                let candidate = (start, prefix_end + 1);
                match projection {
                    EndpointProjection::Exists => return Some(candidate),
                    EndpointProjection::EarliestEnd => {
                        if earliest.is_none_or(|(_, old_end)| candidate.1 < old_end) {
                            earliest = Some(candidate);
                        }
                    }
                }
            }
        }
        earliest
    }

    #[test]
    fn direct_endpoints_match_exhaustive_proper_prefix_high_byte_windows() {
        fn visit(plan: &PrefixClassAlternationPlan, haystack: &mut Vec<u8>, depth: usize) {
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let window = Window::new(start, end);
                    for (projection, endpoint) in [
                        (SearchProjection::Exists, EndpointProjection::Exists),
                        (
                            SearchProjection::EarliestEnd,
                            EndpointProjection::EarliestEnd,
                        ),
                    ] {
                        assert_eq!(
                            reference_endpoint_search(plan, haystack, window, endpoint),
                            execute_ordinary_search(plan, haystack, window, projection).0,
                            "haystack={haystack:?} window={start}..{end} projection={projection:?}",
                        );
                    }
                }
            }
            if depth == 4 {
                return;
            }
            for byte in [0, b'a', b'b', 0x80, 0xfe, 0xff] {
                haystack.push(byte);
                visit(plan, haystack, depth + 1);
                haystack.pop();
            }
        }

        let first_class = [(0xff, 0xff)];
        let second_class = [(0, 0), (b'b', b'b'), (0x80, 0xfe)];
        let plan = PrefixClassAlternationPlan::build(
            [b"a\x80", b"a\x80\xff"],
            [
                first_class.as_slice().iter().copied(),
                second_class.as_slice().iter().copied(),
            ],
            BuildLimits::unlimited(),
        )
        .unwrap();
        visit(&plan, &mut Vec::new(), 0);
    }

    #[test]
    fn direct_earliest_end_compares_a_later_shorter_literal() {
        let plan = PrefixClassAlternationPlan::build(
            [b"abcdef", b"bc"],
            [
                [(b'x', b'x')].into_iter(),
                [(b'd', b'd')].into_iter(),
            ],
            BuildLimits::unlimited(),
        )
        .unwrap();
        let haystack = b"abcdefx";
        let window = Window::full(haystack);
        assert_eq!(
            Some((0, 7)),
            execute_ordinary_search(&plan, haystack, window, SearchProjection::Exists).0,
        );
        assert_eq!(
            Some((1, 4)),
            execute_ordinary_search(
                &plan,
                haystack,
                window,
                SearchProjection::EarliestEnd,
            )
            .0,
        );
    }

    #[test]
    fn direct_endpoint_dense_rejections_are_linear_n_2n_4n() {
        let plan = PrefixClassAlternationPlan::build(
            [b"ab", b"xy"],
            [
                [(b'0', b'9')].into_iter(),
                [(b'A', b'Z')].into_iter(),
            ],
            BuildLimits::unlimited(),
        )
        .unwrap();
        let fixed = plan.build_accounting().shape_units * 8 + 64;
        for repetitions in [64_usize, 128, 256] {
            let haystack = b"abxxyq".repeat(repetitions);
            let (exists, exists_accounting) = plan
                .is_match(&haystack, SearchLimits::unlimited())
                .unwrap();
            let (shortest, shortest_accounting) = plan
                .shortest(&haystack, SearchLimits::unlimited())
                .unwrap();
            assert!(!exists);
            assert_eq!(None, shortest);
            for accounting in [exists_accounting, shortest_accounting] {
                assert_eq!(2 * repetitions, accounting.actual.prefix_candidates);
                assert_eq!(2 * repetitions, accounting.actual.class_bytes);
                assert_eq!(16 * haystack.len() + fixed, accounting.upper_bounds.work);
                assert_eq!(2 * haystack.len(), accounting.upper_bounds.prefix_candidates);
                assert_eq!(4 * haystack.len(), accounting.upper_bounds.class_bytes);
            }
        }
    }

    #[test]
    fn direct_endpoint_limit_failures_are_atomic_at_one_below() {
        let plan = PrefixClassAlternationPlan::build(
            [b"abcdef", b"bc"],
            [
                [(b'x', b'x')].into_iter(),
                [(b'd', b'd')].into_iter(),
            ],
            BuildLimits::unlimited(),
        )
        .unwrap();
        let haystack = b"!abcdefx";
        let window = Window::full(haystack);

        let exists = plan
            .is_match_in(haystack, window, SearchLimits::unlimited())
            .unwrap();
        let exists_exact = SearchLimits {
            max_work_upper_bound: u64::try_from(exists.1.upper_bounds.work).unwrap(),
            max_scratch_bytes: exists.1.upper_bounds.scratch_bytes,
        };
        assert!(matches!(
            plan.is_match_in(
                haystack,
                window,
                SearchLimits {
                    max_work_upper_bound: exists_exact.max_work_upper_bound - 1,
                    ..exists_exact
                },
            ),
            Err(ReduceError::WorkLimit { .. })
        ));
        let exists_retry = plan.is_match_in(haystack, window, exists_exact).unwrap();
        assert_eq!(exists.0, exists_retry.0);
        assert_eq!(exists.1.actual, exists_retry.1.actual);

        let shortest = plan
            .shortest_in(haystack, window, SearchLimits::unlimited())
            .unwrap();
        let shortest_exact = SearchLimits {
            max_work_upper_bound: u64::try_from(shortest.1.upper_bounds.work).unwrap(),
            max_scratch_bytes: shortest.1.upper_bounds.scratch_bytes,
        };
        assert!(matches!(
            plan.shortest_in(
                haystack,
                window,
                SearchLimits {
                    max_work_upper_bound: shortest_exact.max_work_upper_bound - 1,
                    ..shortest_exact
                },
            ),
            Err(ReduceError::WorkLimit { .. })
        ));
        let invalid = Window::new(window.start(), window.end() + 1);
        assert!(matches!(
            plan.shortest_in(haystack, invalid, shortest_exact),
            Err(ReduceError::InvalidWindow { .. })
        ));
        let shortest_retry = plan.shortest_in(haystack, window, shortest_exact).unwrap();
        assert_eq!(shortest.0, shortest_retry.0);
        assert_eq!(shortest.1.actual, shortest_retry.1.actual);
    }

    fn retained_cursor_spans(
        plan: &PrefixClassAlternationPlan,
        haystack: &[u8],
    ) -> (Vec<(usize, usize)>, usize, usize, usize) {
        let mut cursor = plan.search_cursor(haystack);
        let mut start = 0_usize;
        let mut spans = Vec::new();
        let mut charged_work = 0_usize;
        let mut prefix_candidates = 0_usize;
        let mut calls = 0_usize;
        loop {
            let (matched, accounting, charged) = cursor
                .find_at(start, SearchLimits::unlimited())
                .expect("retained prefix cursor search");
            charged_work = charged_work.checked_add(charged).unwrap();
            prefix_candidates = prefix_candidates
                .checked_add(accounting.actual.prefix_candidates)
                .unwrap();
            calls = calls.checked_add(1).unwrap();
            let Some(span) = matched else {
                break;
            };
            start = span.1;
            spans.push(span);
        }
        (spans, charged_work, prefix_candidates, calls)
    }

    #[test]
    fn retained_cursor_joint_stream_work_is_linear_for_dense_matches() {
        let class = [(b'0', b'9')];
        for preferred_alternative in 0..2 {
            let plan = if preferred_alternative == 0 {
                PrefixClassAlternationPlan::build(
                    [b"ab", b"xy"],
                    [class.into_iter(), class.into_iter()],
                    BuildLimits::unlimited(),
                )
                .unwrap()
            } else {
                PrefixClassAlternationPlan::build(
                    [b"xy", b"ab"],
                    [class.into_iter(), class.into_iter()],
                    BuildLimits::unlimited(),
                )
                .unwrap()
            };
            let mut observations = Vec::new();
            for repetitions in [64_usize, 128, 256] {
                let haystack = b"ab0!".repeat(repetitions);
                let baseline = plan
                    .find_in(
                        &haystack,
                        Window::full(&haystack),
                        SearchLimits::unlimited(),
                    )
                    .unwrap()
                    .1;
                let (spans, charged_work, candidates, calls) =
                    retained_cursor_spans(&plan, &haystack);
                assert_eq!(repetitions, spans.len());
                assert_eq!(repetitions, candidates);
                assert_eq!(repetitions + 1, calls);
                assert_eq!(baseline.upper_bounds.work, charged_work);
                assert!(spans
                    .iter()
                    .enumerate()
                    .all(|(index, span)| *span == (4 * index, 4 * index + 3)));
                let fixed = baseline
                    .upper_bounds
                    .work
                    .checked_sub(16 * haystack.len())
                    .unwrap();
                observations.push((haystack.len(), charged_work, fixed));
            }
            let fixed = observations[0].2;
            assert!(observations.iter().all(|observation| observation.2 == fixed));
            assert_eq!(
                2 * (observations[0].1 - fixed),
                observations[1].1 - fixed,
            );
            assert_eq!(
                4 * (observations[0].1 - fixed),
                observations[2].1 - fixed,
            );
        }
    }

    #[test]
    fn retained_cursor_inverse_stream_and_dense_rejections_are_linear() {
        let digits = [(b'0', b'9')];
        let letters = [(b'A', b'Z')];
        let plan = PrefixClassAlternationPlan::build(
            [b"ab", b"xy"],
            [digits.into_iter(), letters.into_iter()],
            BuildLimits::unlimited(),
        )
        .unwrap();

        let inverse = b"xyA!".repeat(96);
        let (spans, charged_work, candidates, calls) = retained_cursor_spans(&plan, &inverse);
        assert_eq!(96, spans.len());
        assert_eq!(96, candidates);
        assert_eq!(97, calls);
        let inverse_upper = plan
            .find_in(
                &inverse,
                Window::full(&inverse),
                SearchLimits::unlimited(),
            )
            .unwrap()
            .1
            .upper_bounds;
        assert_eq!(inverse_upper.work, charged_work);

        let mut rejected = b"abx!".repeat(512);
        rejected.extend_from_slice(b"ab7!");
        let mut cursor = plan.search_cursor(&rejected);
        let (late, accounting, first_charge) = cursor
            .find_at(0, SearchLimits::unlimited())
            .expect("dense rejection search");
        assert_eq!(Some((2048, 2051)), late);
        assert_eq!(513, accounting.actual.prefix_candidates);
        assert_eq!(514, accounting.actual.class_bytes);
        assert_eq!(accounting.upper_bounds.work, first_charge);
        let (terminal, _, continuation_charge) = cursor
            .find_at(2051, SearchLimits::unlimited())
            .expect("dense rejection terminal search");
        assert_eq!(None, terminal);
        assert_eq!(0, continuation_charge);
    }

    #[test]
    fn retained_cursor_preserves_equal_start_priority_and_retry() {
        let plan = PrefixClassAlternationPlan::build(
            [b"abcd", b"ab"],
            [
                [(b'x', b'x')].into_iter(),
                [(b'c', b'c')].into_iter(),
            ],
            BuildLimits::unlimited(),
        )
        .unwrap();

        let accepted = b"abcdxxx!abcd!";
        let mut accepted_cursor = plan.search_cursor(accepted);
        let (first, first_accounting, first_charge) = accepted_cursor
            .find_at(0, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(Some((0, 7)), first);
        assert_eq!(1, first_accounting.actual.prefix_candidates);
        assert!(first_charge > 0);
        let (second, second_accounting, second_charge) = accepted_cursor
            .find_at(7, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(Some((8, 11)), second);
        assert_eq!(2, second_accounting.actual.prefix_candidates);
        assert_eq!(0, second_charge);

        let rejected = b"abcd!";
        let mut rejected_cursor = plan.search_cursor(rejected);
        let (retried, accounting, _) = rejected_cursor
            .find_at(0, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(Some((0, 3)), retried);
        assert_eq!(2, accounting.actual.prefix_candidates);
    }

    #[test]
    fn retained_cursor_window_resets_and_failures_are_atomic() {
        let plan = plan();
        let haystack = b"!!aba!abzz!xy7!aba!";
        let full = Window::full(haystack);
        let baseline = plan
            .find_in(haystack, full, SearchLimits::unlimited())
            .unwrap();
        let exact = SearchLimits {
            max_work_upper_bound: u64::try_from(baseline.1.upper_bounds.work).unwrap(),
            max_scratch_bytes: baseline.1.upper_bounds.scratch_bytes,
        };
        let mut cursor = plan.search_cursor(haystack);
        let initial = cursor.state;
        let one_below = SearchLimits {
            max_work_upper_bound: exact.max_work_upper_bound - 1,
            ..exact
        };
        assert!(cursor.find_window(full, one_below).is_err());
        assert_eq!(initial, cursor.state);
        assert!(cursor
            .find_window_with_late_failure(full, exact)
            .is_err());
        assert_eq!(initial, cursor.state);

        let (first, _, first_charge) = cursor.find_window(full, exact).unwrap();
        assert_eq!(baseline.0, first);
        assert_eq!(baseline.1.upper_bounds.work, first_charge);
        let first = first.unwrap();
        let continuation = Window::new(first.1, haystack.len());
        let continuation_baseline = plan
            .find_in(haystack, continuation, SearchLimits::unlimited())
            .unwrap();
        let continuation_exact = SearchLimits {
            max_work_upper_bound: u64::try_from(continuation_baseline.1.upper_bounds.work).unwrap(),
            max_scratch_bytes: continuation_baseline.1.upper_bounds.scratch_bytes,
        };
        let before_retry = cursor.state;
        assert!(cursor
            .find_window(
                continuation,
                SearchLimits {
                    max_work_upper_bound: continuation_exact.max_work_upper_bound - 1,
                    ..continuation_exact
                },
            )
            .is_err());
        assert_eq!(before_retry, cursor.state);
        assert!(cursor
            .find_window_with_late_failure(continuation, continuation_exact)
            .is_err());
        assert_eq!(before_retry, cursor.state);
        let (second, _, second_charge) = cursor
            .find_window(continuation, continuation_exact)
            .unwrap();
        assert_eq!(continuation_baseline.0, second);
        assert_eq!(0, second_charge);

        let skipped = Window::new(second.unwrap().1 + 1, haystack.len());
        let expected_skipped = plan
            .find_in(haystack, skipped, SearchLimits::unlimited())
            .unwrap()
            .0;
        let (actual_skipped, _, reset_charge) = cursor
            .find_window(skipped, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(expected_skipped, actual_skipped);
        assert!(reset_charge > 0);

        let shortened = Window::new(skipped.start(), haystack.len() - 1);
        let expected_shortened = plan
            .find_in(haystack, shortened, SearchLimits::unlimited())
            .unwrap()
            .0;
        let (actual_shortened, _, end_reset_charge) = cursor
            .find_window(shortened, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(expected_shortened, actual_shortened);
        assert!(end_reset_charge > 0);
    }

    #[test]
    fn retained_cursor_binding_is_plan_local_and_source_local() {
        let digits = PrefixClassAlternationPlan::build(
            [b"ab", b"xy"],
            [
                [(b'0', b'9')].into_iter(),
                [(b'0', b'9')].into_iter(),
            ],
            BuildLimits::unlimited(),
        )
        .unwrap();
        let letters = PrefixClassAlternationPlan::build(
            [b"ab", b"xy"],
            [
                [(b'A', b'Z')].into_iter(),
                [(b'A', b'Z')].into_iter(),
            ],
            BuildLimits::unlimited(),
        )
        .unwrap();
        let mut haystack = b"!ab12!xyQ!".to_vec();
        let address = haystack.as_ptr();
        {
            let mut digit_cursor = digits.search_cursor(&haystack);
            let mut letter_cursor = letters.search_cursor(&haystack);
            assert_eq!(digit_cursor.haystack().as_ptr(), letter_cursor.haystack().as_ptr());
            assert_eq!(Some((1, 5)), digit_cursor.find_at(0, SearchLimits::unlimited()).unwrap().0);
            assert_eq!(Some((6, 9)), letter_cursor.find_at(0, SearchLimits::unlimited()).unwrap().0);
        }

        haystack[3..5].copy_from_slice(b"AZ");
        haystack[8] = b'7';
        assert_eq!(address, haystack.as_ptr());
        let mut digit_cursor = digits.search_cursor(&haystack);
        let mut letter_cursor = letters.search_cursor(&haystack);
        assert_eq!(Some((6, 9)), digit_cursor.find_at(0, SearchLimits::unlimited()).unwrap().0);
        assert_eq!(Some((1, 5)), letter_cursor.find_at(0, SearchLimits::unlimited()).unwrap().0);
    }

    #[test]
    fn dispatched_retained_cursor_matches_scalar_when_available() {
        let dispatch = SimdDispatchContext::capture();
        if !PrefixClassAlternationPlan::run_scanners_usable(dispatch) {
            return;
        }
        let digits = [(b'0', b'9')];
        let letters = [(b'A', b'Z')];
        let scalar = PrefixClassAlternationPlan::build(
            [b"ab", b"xy"],
            [digits.into_iter(), letters.into_iter()],
            BuildLimits::unlimited(),
        )
        .unwrap();
        let dispatched = DispatchedPrefixClassAlternationPlan::build_with_dispatch(
            dispatch,
            [b"ab", b"xy"],
            [digits.into_iter(), letters.into_iter()],
            BuildLimits::unlimited(),
        )
        .unwrap();
        let haystack = b"!ab123!xyAZ!ab9!xyQ!";
        let expected = retained_cursor_spans(&scalar, haystack).0;
        let upper = dispatched
            .find_in(
                haystack,
                Window::full(haystack),
                SearchLimits::unlimited(),
            )
            .unwrap()
            .1
            .upper_bounds;
        let mut cursor = dispatched.search_cursor(haystack);
        let mut actual = Vec::new();
        let mut start = 0_usize;
        let mut total_charge = 0_usize;
        loop {
            let (matched, accounting, charge) = cursor
                .find_at(start, SearchLimits::unlimited())
                .unwrap();
            assert!(accounting.actual.prefix_candidates <= accounting.upper_bounds.prefix_candidates);
            total_charge = total_charge.checked_add(charge).unwrap();
            let Some(span) = matched else {
                break;
            };
            start = span.1;
            actual.push(span);
        }
        assert_eq!(expected, actual);
        assert_eq!(upper.work, total_charge);
    }

    #[test]
    #[cfg(not(feature = "static-dispatch"))]
    fn shared_class_extension_preserves_every_alignment_and_exact_boundary() {
        let established = plan();
        let class = established.alternatives[0].class;
        let scanner =
            AsciiByteSetRunScanner::with_policy(class.ascii_set(), DispatchPolicy::Portable)
                .expect("the portable scanner is always available");
        for leading in 0..32 {
            for run_len in 0..65 {
                let mut haystack = vec![b'!'; leading];
                haystack.extend(std::iter::repeat_n(b'a', run_len));
                haystack.extend(std::iter::repeat_n(b'!', 32));
                let scalar = extend_greedy_class(&haystack, leading, class, None);
                let vector_result = extend_greedy_class(&haystack, leading, class, Some(&scanner));
                assert_eq!(leading + run_len, scalar.end);
                assert_eq!(scalar.end, vector_result.end);
                assert!(
                    vector_result.physical_classifications
                        <= scalar.physical_classifications + ASCII_RUN_MAX_CLASSIFICATION_OVERHEAD
                );
            }
        }

        for run_len in 0..65 {
            let haystack = vec![b'z'; run_len];
            let scalar = extend_greedy_class(&haystack, 0, class, None);
            let vector_result = extend_greedy_class(&haystack, 0, class, Some(&scanner));
            assert_eq!(run_len, scalar.end);
            assert_eq!(scalar.end, vector_result.end);
            assert!(
                vector_result.physical_classifications
                    <= scalar.physical_classifications + ASCII_RUN_MAX_CLASSIFICATION_OVERHEAD
            );
        }
    }

    #[test]
    fn dispatched_owner_refuses_before_range_access_without_usable_sve() {
        let dispatch = SimdDispatchContext::capture();
        if PrefixClassAlternationPlan::run_scanners_usable(dispatch) {
            return;
        }
        let (first, first_next, first_len) = deceptive_ranges(&[(b'a', b'z')]);
        let (second, second_next, second_len) = deceptive_ranges(&[(b'0', b'9')]);
        let failure = DispatchedPrefixClassAlternationPlan::build_attempt_with_dispatch(
            dispatch,
            [b"ab", b"xy"],
            [first, second],
            BuildLimits::unlimited(),
        )
        .expect_err("a non-SVE host must retain the established scalar owner");
        assert_eq!(failure.source(), &BuildError::RunScannerDispatchUnavailable);
        assert_eq!(failure.actual(), DirectBuildAttemptActual::default());
        assert_eq!(first_next.get(), 0);
        assert_eq!(second_next.get(), 0);
        assert_eq!(first_len.get(), 0);
        assert_eq!(second_len.get(), 0);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the SVE gate keeps construction, boundary, aggregate, uniform, and accounting equivalence under one captured host receipt"
    )]
    fn sve_owner_matches_scalar_and_shares_physical_classification_accounting() {
        let dispatch = SimdDispatchContext::capture();
        if !PrefixClassAlternationPlan::run_scanners_usable(dispatch) {
            return;
        }
        let word = [(b'0', b'9'), (b'A', b'Z'), (b'_', b'_'), (b'a', b'z')];
        let established_attempt = PrefixClassAlternationPlan::build_attempt(
            [b"fn is_", b"fn as_"],
            [word.into_iter(), word.into_iter()],
            BuildLimits::unlimited(),
        )
        .unwrap();
        let established_actual = established_attempt.actual();
        let established = established_attempt.into_plan();
        let dispatched_attempt = DispatchedPrefixClassAlternationPlan::build_attempt_with_dispatch(
            dispatch,
            [b"fn is_", b"fn as_"],
            [word.into_iter(), word.into_iter()],
            BuildLimits::unlimited(),
        )
        .unwrap();
        let dispatched_actual = dispatched_attempt.actual();
        let dispatched = dispatched_attempt.into_plan();

        let established_build = established.build_accounting();
        let dispatched_build = dispatched.build_accounting();
        let scanner_build = dispatched.run_scanner_build_accounting();
        assert_eq!(RUN_SCANNERS, scanner_build.scanners);
        assert_eq!(1, scanner_build.allocations);
        assert_eq!(
            SIMD_RUN_SCANNER_BUILD_WORK * RUN_SCANNERS,
            scanner_build.build_work
        );
        assert_eq!(size_of::<RunScanners>(), scanner_build.initialized_bytes);
        assert_eq!(
            size_of::<DispatchedPrefixClassAlternationOwner>(),
            scanner_build.retained_allocation_bytes
        );
        assert_eq!(
            established_build.work_upper_bound + SIMD_RUN_SCANNER_BUILD_WORK * RUN_SCANNERS,
            dispatched_build.work_upper_bound
        );
        assert_eq!(
            size_of::<DispatchedPrefixClassAlternationPlan>()
                + dispatched_build.prefix_bytes
                + size_of::<DispatchedPrefixClassAlternationOwner>(),
            dispatched_build.persistent_bytes
        );
        assert_eq!(
            established_build.persistent_bytes,
            established_actual.live_persistent_bytes
        );
        assert_eq!(
            dispatched_build.persistent_bytes,
            dispatched_actual.live_persistent_bytes
        );
        assert_eq!(
            dispatched_build.persistent_bytes,
            dispatched_actual.initialized_bytes
        );
        assert_eq!(3, dispatched_actual.allocations);
        assert_eq!(
            dispatched_build.prefix_bytes + size_of::<DispatchedPrefixClassAlternationOwner>(),
            dispatched_actual.allocated_bytes
        );
        assert_eq!(PLAN_ID, established.count_identity().plan_id);
        assert_eq!(DISPATCHED_PLAN_ID, dispatched.count_identity().plan_id);
        for selection in dispatched.run_scanner_selections() {
            #[cfg(not(feature = "static-dispatch"))]
            {
                assert!(selection.required.contains(Feature::ArmSve));
                assert!(selection.variant_id.contains("sve"));
            }
            #[cfg(feature = "static-dispatch")]
            {
                assert_eq!(selection.policy, DispatchPolicy::Auto);
                assert!(
                    selection.required.contains(Feature::ArmNeon)
                        || selection.required.contains(Feature::ArmSve)
                );
                assert!(
                    selection.variant_id.contains("neon") || selection.variant_id.contains("sve")
                );
            }
            assert_eq!(ASCII_NARROW_BYTES, selection.minimum_input_bytes);
        }

        let schema = rust_functions_schema();
        let pattern = r"fn is_(\w+)|fn as_(\w+)";
        let mut cases = vec![
            Vec::new(),
            b"fn is_alpha fn as_beta".to_vec(),
            b"fn is_ fn as_".to_vec(),
            b"fn as_9fn is_Z".to_vec(),
            b"fn is_a\x00fn as_b\xfffn is_c".to_vec(),
        ];
        for leading in 0..32 {
            let mut haystack = vec![b'!'; leading];
            haystack.extend_from_slice(b"fn is_");
            haystack.extend(std::iter::repeat_n(b'a', 97));
            haystack.extend_from_slice(b"!fn as_");
            haystack.extend(std::iter::repeat_n(b'7', 33));
            haystack.extend_from_slice(b"\x80fn is_z!");
            cases.push(haystack);
        }
        for haystack in cases {
            let reference = reference_spans(pattern, &haystack);
            let established_count = established
                .count(&haystack, ReduceLimits::unlimited())
                .unwrap();
            let dispatched_count = dispatched
                .count(&haystack, ReduceLimits::unlimited())
                .unwrap();
            assert_eq!(
                u64::try_from(reference.len()).unwrap(),
                established_count.count
            );
            assert_eq!(established_count.count, dispatched_count.count);
            assert_eq!(
                established_count.accounting.upper_bounds.work
                    + haystack.len() * ASCII_RUN_MAX_CLASSIFICATION_OVERHEAD,
                dispatched_count.accounting.upper_bounds.work
            );

            let established_uniform = established
                .count_uniform_participation(
                    &haystack,
                    schema,
                    UniformParticipationLimits::unlimited(),
                )
                .unwrap();
            let dispatched_uniform = dispatched
                .count_uniform_participation(
                    &haystack,
                    schema,
                    UniformParticipationLimits::unlimited(),
                )
                .unwrap();
            assert_eq!(reference.len(), established_uniform.matches);
            assert_eq!(established_uniform.matches, dispatched_uniform.matches);
            assert_eq!(
                established_uniform.capture_count,
                dispatched_uniform.capture_count
            );
            assert_eq!(
                dispatched_count.accounting.actual.class_bytes,
                dispatched_uniform.accounting.actual.first_class_probes
                    + dispatched_uniform.accounting.actual.greedy_extension_reads
            );
            assert_eq!(
                established_uniform
                    .accounting
                    .prospective
                    .greedy_extension_reads
                    + haystack.len() * ASCII_RUN_MAX_CLASSIFICATION_OVERHEAD,
                dispatched_uniform
                    .accounting
                    .prospective
                    .greedy_extension_reads
            );
            assert!(
                dispatched_uniform.accounting.closes_receipt(
                    &dispatched
                        .count_uniform_participation_attempt(
                            &haystack,
                            schema,
                            UniformParticipationLimits::unlimited(),
                        )
                        .unwrap()
                        .receipt
                )
            );
        }
    }

    #[test]
    #[ignore = "manual release benchmark; requires an OS-usable fixed-16 SVE run scanner"]
    fn benchmark_scalar_and_sve_prefix_class_extension() {
        let dispatch = SimdDispatchContext::capture();
        assert!(
            PrefixClassAlternationPlan::run_scanners_usable(dispatch),
            "benchmark requires OS-usable SVE"
        );
        let word = [(b'0', b'9'), (b'A', b'Z'), (b'_', b'_'), (b'a', b'z')];
        let established = PrefixClassAlternationPlan::build(
            [b"fn is_", b"fn as_"],
            [word.into_iter(), word.into_iter()],
            BuildLimits::unlimited(),
        )
        .unwrap();
        let dispatched = DispatchedPrefixClassAlternationPlan::build_with_dispatch(
            dispatch,
            [b"fn is_", b"fn as_"],
            [word.into_iter(), word.into_iter()],
            BuildLimits::unlimited(),
        )
        .unwrap();
        let mut haystack = Vec::new();
        for _ in 0..4_096 {
            haystack.extend_from_slice(b"fn is_");
            haystack.extend(std::iter::repeat_n(b'a', 128));
            haystack.extend_from_slice(b"!fn as_");
            haystack.extend(std::iter::repeat_n(b'7', 128));
            haystack.push(b'!');
        }
        let iterations = 200;
        let started = Instant::now();
        let mut established_count = 0_u64;
        for _ in 0..iterations {
            established_count = established_count.wrapping_add(black_box(
                established
                    .count(black_box(&haystack), ReduceLimits::unlimited())
                    .unwrap()
                    .count,
            ));
        }
        let established_elapsed = started.elapsed();
        let started = Instant::now();
        let mut dispatched_count = 0_u64;
        for _ in 0..iterations {
            dispatched_count = dispatched_count.wrapping_add(black_box(
                dispatched
                    .count(black_box(&haystack), ReduceLimits::unlimited())
                    .unwrap()
                    .count,
            ));
        }
        let dispatched_elapsed = started.elapsed();
        assert_eq!(established_count, dispatched_count);
        eprintln!(
            "PREFIX_CLASS_ALTERNATION_BENCH scalar_ns={} sve_ns={} sve_over_scalar={:.9} bytes={} iterations={} selections={:?}",
            established_elapsed.as_nanos(),
            dispatched_elapsed.as_nanos(),
            dispatched_elapsed.as_secs_f64() / established_elapsed.as_secs_f64(),
            haystack.len(),
            iterations,
            dispatched.run_scanner_selections()
        );
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

        let scanner_bytes = size_of::<RunScanners>();
        let (first, first_next, first_len) = deceptive_ranges(&[(b'a', b'z')]);
        let (second, second_next, second_len) = deceptive_ranges(&[(b'0', b'9')]);
        let error =
            DispatchedPrefixClassAlternationPlan::build_uniform_participation_with_dispatch(
                SimdDispatchContext::capture(),
                [b"ab", b"xy"],
                [first, second],
                UniformParticipationBuildLimits {
                    max_initialized_run_scanner_bytes: scanner_bytes - 1,
                    ..UniformParticipationBuildLimits::unlimited()
                },
            )
            .expect_err("scanner initialization one-below must preflight");
        assert_eq!(
            error,
            UniformParticipationBuildError::InitializedRunScannerBytesLimit {
                needed: scanner_bytes,
                limit: scanner_bytes - 1,
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
    fn rebar_row_imported_leipzig_huck_saw_span_sum_and_one_below() {
        // rebar-row:imported/leipzig/huck-saw@rust/regex
        let plan = plan();
        let haystack = b"abcz--xy7";
        let result = plan.span_sum(haystack, ReduceLimits::unlimited()).unwrap();
        assert_eq!(7, result.span_sum);
        assert_eq!(7, result.accounting.actual.span_sum);
        assert_eq!(9, result.accounting.upper_bounds.span_sum);
        assert_eq!(
            SPAN_SUM_OPERATION_ID,
            result.accounting.identity.operation_id
        );

        let one_below = ReduceLimits {
            max_span_sum: 8,
            ..ReduceLimits::unlimited()
        };
        assert_eq!(
            Err(ReduceError::SpanSumLimit {
                needed: 9,
                limit: 8,
            }),
            plan.span_sum(haystack, one_below)
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
            let expected = reference_spans(r"ab[a-z]+|xy[0-9]+", haystack);
            assert_eq!(
                expected,
                sut_spans(&plan, haystack),
                "haystack={haystack:?}"
            );
            let expected_span_sum = expected.iter().try_fold(0_u64, |sum, span| {
                sum.checked_add(u64::try_from(span.len()).ok()?)
            });
            assert_eq!(
                expected_span_sum,
                Some(
                    plan.span_sum(haystack, ReduceLimits::unlimited())
                        .unwrap()
                        .span_sum
                ),
                "span sum for haystack={haystack:?}"
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
