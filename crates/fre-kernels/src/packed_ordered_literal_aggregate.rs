//! Receipt-correct packed reducers for small ordered literal sets.
//!
//! The retained owner is entirely FRE controlled. It contains one
//! length-prefixed copy of the ordered patterns, fixed metadata, a fixed
//! fixed-anchor-byte-to-pattern map, one full-byte screening classifier and
//! one correlated full-byte bucket classifier. In runtime-dispatch builds,
//! equal-width ordinary reducers may additionally retain one separately
//! allocated 256-entry Word64 Shift-And table. Static-dispatch builds retain
//! the incumbent byte-bucket owner and transaction exactly. Construction
//! ranks common in-pattern offsets using a
//! frozen byte-frequency policy and complete bucket cost. It publishes the
//! fixed owner through one exact fallible allocation after any optional table.
//! The operation either walks candidate starts monotonically and verifies
//! pattern IDs in source order, or performs one scalar Shift-And transition per
//! input byte. Neither runtime leaf allocates.
//!
//! This kernel intentionally knows nothing about Unicode boundaries. It
//! implements ordered, nonempty byte strings. A facade may bind either
//! Unicode-off byte semantics or a separately proved set of complete UTF-8
//! words to that byte-string contract.

use core::{fmt, mem::size_of};

#[cfg(not(feature = "static-dispatch"))]
use fre_exact_alloc::ExactBoxOrUsize;
use fre_exact_alloc::{CopyError, try_box_preserve};
use fre_simd_kernels::{
    BYTE_BUCKET_BLOCK_BYTES, BYTE_BUCKET_COUNT, BYTE_BUCKET_MAX_COLUMNS, ByteBucketClassifier,
    ByteBucketTables, DispatchPolicy, FeatureSet, SelectionReceipt, SimdDispatchContext,
};

use crate::ordered_literal_aggregate::{IterationSemantics, MatchSemantics, Operation};

const CACHE_FORMAT_VERSION: u32 = 7;
const LENGTH_PREFIX_BYTES: usize = size_of::<u64>();
const IDENTITY_CAPACITY_BYTES: usize = LENGTH_PREFIX_BYTES
    + CERTIFIED_MAX_PATTERNS * LENGTH_PREFIX_BYTES
    + CERTIFIED_MAX_TOTAL_PATTERN_BYTES;
const CLASSIFIER_BUILD_WORK: usize = 256;
const SIMD_BLOCK_BYTES: usize = BYTE_BUCKET_BLOCK_BYTES;
#[cfg(not(feature = "static-dispatch"))]
const UNIFORM_TRANSITION_WORK: usize = 3;
#[cfg(not(feature = "static-dispatch"))]
const UNIFORM_MATCH_WORK: usize = 2;
#[cfg(not(feature = "static-dispatch"))]
const UNIFORM_FINAL_WORK: usize = 1;
const UNIFORM_WORD_BITS: usize = 64;
const UNIFORM_ALPHABET_ZERO_WORK: usize = 256;
const UNIFORM_MASK_ZERO_WORK: usize = 256;
const UNIFORM_MASK_BYTES: usize = 256 * size_of::<u64>();
const UNIFORM_VARIANT_ID: &str = "uniform-word64.scalar.v1";
/// Lowest frozen general-text frequency rank admitted by every selected
/// anchor byte of the serial Word64 leaf. Lower ranks keep the skip-friendly
/// byte-bucket reducer.
pub const UNIFORM_WORD64_MIN_ANCHOR_FREQUENCY_RANK: u8 = 128;
/// Smallest common literal width admitted by the serial Word64 leaf.
///
/// The incumbent byte-bucket classifier correlates up to four literal bytes
/// across sixteen starts at once. Requiring twice that width keeps short
/// literal sets on the SIMD leaf and reserves the scalar transition stream for
/// languages where it can eliminate at least four additional verification
/// bytes per candidate.
pub const UNIFORM_WORD64_MIN_PATTERN_BYTES: usize = 2 * BYTE_BUCKET_MAX_COLUMNS;
/// Largest distinct pattern alphabet admitted by the scalar Word64 leaf.
pub const UNIFORM_WORD64_MAX_DISTINCT_PATTERN_BYTES: usize = 8;
/// Smallest total-pattern-byte reuse per distinct byte.
pub const UNIFORM_WORD64_MIN_ALPHABET_REUSE: usize = 3;

// Frozen memchr 2.8.3 packed-pair frequency order, shared conceptually with
// the authenticated AArch64 literal backend. Lower ranks are rarer and
// therefore better fixed anchors. Keeping this local avoids coupling the
// portable kernel crate to one JIT backend.
const BYTE_FREQUENCY_RANK: [u8; 256] = [
    55, 52, 51, 50, 49, 48, 47, 46, 45, 103, 242, 66, 67, 229, 44, 43, 42, 41, 40, 39, 38, 37, 36,
    35, 34, 33, 56, 32, 31, 30, 29, 28, 255, 148, 164, 149, 136, 160, 155, 173, 221, 222, 134, 122,
    232, 202, 215, 224, 208, 220, 204, 187, 183, 179, 177, 168, 178, 200, 226, 195, 154, 184, 174,
    126, 120, 191, 157, 194, 170, 189, 162, 161, 150, 193, 142, 137, 171, 176, 185, 167, 186, 112,
    175, 192, 188, 156, 140, 143, 123, 133, 128, 147, 138, 146, 114, 223, 151, 249, 216, 238, 236,
    253, 227, 218, 230, 247, 135, 180, 241, 233, 246, 244, 231, 139, 245, 243, 251, 235, 201, 196,
    240, 214, 152, 182, 205, 181, 127, 27, 212, 211, 210, 213, 228, 197, 169, 159, 131, 172, 105,
    80, 98, 96, 97, 81, 207, 145, 116, 115, 144, 130, 153, 121, 107, 132, 109, 110, 124, 111, 82,
    108, 118, 141, 113, 129, 119, 125, 165, 117, 92, 106, 83, 72, 99, 93, 65, 79, 166, 237, 163,
    199, 190, 225, 209, 203, 198, 217, 219, 206, 234, 248, 158, 239, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255,
];

/// Frozen general-purpose byte-frequency rank shared by construction-time
/// anchor selectors. Lower ranks are expected to be rarer.
///
/// This deliberately exposes only the immutable policy, not the packed
/// reducer's bucket scoring or tie-breaking rules.
pub(crate) fn byte_frequency_rank(byte: u8) -> u8 {
    BYTE_FREQUENCY_RANK[usize::from(byte)]
}

/// Smallest admitted ordered set. Singletons already have a stronger direct
/// literal implementation.
pub const CERTIFIED_MIN_PATTERNS: usize = 2;
/// Absolute theorem bound, independent of caller limits.
pub const CERTIFIED_MAX_PATTERNS: usize = 16;
/// Smallest admitted literal. One-byte sets are deliberately left to the
/// existing byte-class reducers until separately qualified.
pub const CERTIFIED_MIN_PATTERN_BYTES: usize = 2;
/// Absolute theorem bound, independent of caller limits.
pub const CERTIFIED_MAX_PATTERN_BYTES: usize = 64;
/// Absolute theorem bound, independent of caller limits.
pub const CERTIFIED_MAX_TOTAL_PATTERN_BYTES: usize = 512;
/// Largest greedy byte prefix admitted by the bounded-prefix wrapper.
pub const CERTIFIED_MAX_BOUNDED_PREFIX_BYTES: u8 = 4;
/// Stable FRE-owned strategy identity.
pub const ALGORITHM_ID: &str = "ordered-literal-aggregate.packed-byte-bucket-or-uniform-word64.v6";
/// Stable count-plan identity.
pub const COUNT_PLAN_ID: &str =
    "ordered-literal-aggregate.count.packed-byte-bucket-or-uniform-word64.v6";
/// Stable span-sum-plan identity.
pub const SPAN_SUM_PLAN_ID: &str =
    "ordered-literal-aggregate.span-sum.packed-byte-bucket-or-uniform-word64.v6";
/// Stable count identity for a finite greedy dot-byte prefix followed by the
/// ordered literal set.
pub const BOUNDED_PREFIX_COUNT_PLAN_ID: &str =
    "bounded-prefix-ordered-literal-aggregate.count.packed-byte-bucket-stream.v4";
/// Version of the success-or-failure construction protocol.
pub const BUILD_ATTEMPT_ALGORITHM_VERSION: u32 = 6;
/// Version of the partial-actual construction ledger.
pub const BUILD_ATTEMPT_ACCOUNTING_VERSION: u32 = 6;

/// Runtime leaf retained by one packed finite-literal plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeReducer {
    /// Fixed-anchor SIMD filtering followed by source-ordered verification.
    ByteBucket,
    /// One allocation-free Shift-And state with one lane per equal-width word.
    UniformWord64,
}

/// Boundary contract owned by this byte-string kernel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundarySemantics {
    /// Every alternative is nonempty. Character-boundary validity, when
    /// required, is proved and bound by the caller.
    NonemptyByteStrings,
}

/// Exact matching semantics represented by the cache identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Semantics {
    pub match_semantics: MatchSemantics,
    pub iteration_semantics: IterationSemantics,
    pub boundary_semantics: BoundarySemantics,
}

const SEMANTICS: Semantics = Semantics {
    match_semantics: MatchSemantics::LeftmostFirst,
    iteration_semantics: IterationSemantics::NonOverlapping,
    boundary_semantics: BoundarySemantics::NonemptyByteStrings,
};

/// Collision-free process-local semantic identity for one packed plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheIdentity<'a> {
    pub algorithm_id: &'static str,
    pub plan_id: &'static str,
    pub operation: Operation,
    pub cache_format_version: u32,
    pub implementation_kind: &'static str,
    pub identity_scope: &'static str,
    pub target_arch: &'static str,
    pub runtime_minimum_haystack_bytes: usize,
    pub semantics: Semantics,
    pub runtime_reducer: RuntimeReducer,
    pub anchor_offset: usize,
    pub anchor_has_non_ascii: bool,
    pub mask_columns: u8,
    /// Active byte-bucket dispatch receipt, or `None` for scalar Word64.
    pub classifier_selection: Option<SelectionReceipt>,
    pub certified_min_patterns: usize,
    pub certified_max_patterns: usize,
    pub certified_min_pattern_bytes: usize,
    pub certified_max_pattern_bytes: usize,
    pub certified_max_total_pattern_bytes: usize,
    pub bounded_prefix: Option<BoundedPrefixBounds>,
    pub encoded_patterns: &'a [u8],
}

/// Exact greedy byte-prefix bounds bound into construction and cache identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundedPrefixBounds {
    pub minimum: u8,
    pub maximum: u8,
}

/// Copyable operation and exact native-reducer identity. Pattern bytes remain in
/// [`CacheIdentity`] and may be authenticated separately by an owning facade.
/// The `wide_*` field names are retained for facade compatibility; they now
/// describe either the direct byte-bucket receipt or the frozen scalar leaf.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationIdentity {
    pub algorithm_id: &'static str,
    pub plan_id: &'static str,
    pub operation: Operation,
    pub runtime_reducer: RuntimeReducer,
    pub cache_format_version: u32,
    pub wide_policy_version: u16,
    pub wide_variant_id: &'static str,
    pub wide_delegate_variant_id: Option<&'static str>,
    pub wide_policy_usable: FeatureSet,
    pub wide_required: FeatureSet,
    pub wide_minimum_input_bytes: usize,
    pub anchor_offset: usize,
    pub anchor_has_non_ascii: bool,
    pub mask_columns: u8,
    pub bounded_prefix: Option<BoundedPrefixBounds>,
}

impl CacheIdentity<'_> {
    /// Drop only the borrowed pattern encoding while preserving the complete
    /// operation and native-classifier identity.
    #[must_use]
    pub const fn operation_identity(self) -> OperationIdentity {
        let (
            wide_policy_version,
            wide_variant_id,
            wide_delegate_variant_id,
            wide_policy_usable,
            wide_required,
            wide_minimum_input_bytes,
        ) = match self.classifier_selection {
            Some(wide) => (
                wide.policy_version,
                wide.variant_id,
                wide.delegate_variant_id,
                wide.policy_usable,
                wide.required,
                wide.minimum_input_bytes,
            ),
            None => (
                0,
                UNIFORM_VARIANT_ID,
                None,
                FeatureSet::EMPTY,
                FeatureSet::EMPTY,
                0,
            ),
        };
        OperationIdentity {
            algorithm_id: self.algorithm_id,
            plan_id: self.plan_id,
            operation: self.operation,
            runtime_reducer: self.runtime_reducer,
            cache_format_version: self.cache_format_version,
            wide_policy_version,
            wide_variant_id,
            wide_delegate_variant_id,
            wide_policy_usable,
            wide_required,
            wide_minimum_input_bytes,
            anchor_offset: self.anchor_offset,
            anchor_has_non_ascii: self.anchor_has_non_ascii,
            mask_columns: self.mask_columns,
            bounded_prefix: self.bounded_prefix,
        }
    }
}

/// Caller limits for one packed construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildLimits {
    pub max_patterns: usize,
    pub max_pattern_bytes: usize,
    pub max_total_pattern_bytes: usize,
    pub max_identity_bytes: usize,
    pub max_build_work: usize,
    pub max_build_peak_bytes: usize,
    pub max_persistent_bytes: usize,
}

impl BuildLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_patterns: usize::MAX,
            max_pattern_bytes: usize::MAX,
            max_total_pattern_bytes: usize::MAX,
            max_identity_bytes: usize::MAX,
            max_build_work: usize::MAX,
            max_build_peak_bytes: usize::MAX,
            max_persistent_bytes: usize::MAX,
        }
    }
}

impl Default for BuildLimits {
    fn default() -> Self {
        Self {
            max_patterns: CERTIFIED_MAX_PATTERNS,
            max_pattern_bytes: CERTIFIED_MAX_PATTERN_BYTES,
            max_total_pattern_bytes: CERTIFIED_MAX_TOTAL_PATTERN_BYTES,
            max_identity_bytes: 4 * 1024,
            max_build_work: 4 * 1024 * 1024,
            max_build_peak_bytes: 16 * 1024 * 1024,
            max_persistent_bytes: 1024 * 1024,
        }
    }
}

/// Prospective and published accounting for one packed plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildAccounting {
    pub patterns: usize,
    pub pattern_bytes: usize,
    pub max_pattern_bytes: usize,
    pub min_pattern_bytes: usize,
    /// Construction-selected runtime leaf.
    pub runtime_reducer: RuntimeReducer,
    /// Rarest selected anchor byte under the frozen general-text rank.
    /// Zero when the set shape is not a candidate for the uniform reducer.
    pub selected_anchor_minimum_frequency_rank: u8,
    /// Distinct byte values across the admitted equal-width literal family.
    pub uniform_distinct_pattern_bytes: u8,
    /// Whether construction read every selected-anchor frequency rank.
    pub uniform_route_inspected: bool,
    pub anchor_offset: usize,
    pub anchor_has_non_ascii: bool,
    pub anchor_selection_work: u64,
    pub mask_columns: usize,
    pub bucket_assignment_work: u64,
    pub max_anchor_byte_bucket_patterns: usize,
    pub max_anchor_byte_bucket_pattern_bytes: usize,
    pub identity_bytes: usize,
    pub identity_capacity_bytes: usize,
    pub build_work_upper_bound: u64,
    pub build_peak_upper_bound: usize,
    pub persistent_bytes: usize,
    pub simd_minimum_haystack_bytes: usize,
    pub bounded_prefix: Option<BoundedPrefixBounds>,
}

impl BuildAccounting {
    /// Total Shift-And state positions, or zero for the byte-bucket leaf.
    #[must_use]
    pub const fn uniform_state_positions(self) -> usize {
        match self.runtime_reducer {
            RuntimeReducer::ByteBucket => 0,
            RuntimeReducer::UniformWord64 => self.pattern_bytes,
        }
    }

    /// Exact mask-table construction work, or zero for the byte-bucket leaf.
    #[must_use]
    pub fn uniform_mask_build_work(self) -> u64 {
        match self.runtime_reducer {
            RuntimeReducer::ByteBucket => 0,
            RuntimeReducer::UniformWord64 => u64::try_from(
                UNIFORM_MASK_ZERO_WORK
                    .checked_add(self.pattern_bytes)
                    .and_then(|work| work.checked_add(self.patterns.checked_mul(2)?))
                    .expect("certified uniform mask work fits usize"),
            )
            .expect("certified uniform mask work fits u64"),
        }
    }

    /// Separately allocated transition-table bytes, or zero for byte-bucket.
    #[must_use]
    pub const fn uniform_mask_bytes(self) -> usize {
        match self.runtime_reducer {
            RuntimeReducer::ByteBucket => 0,
            RuntimeReducer::UniformWord64 => UNIFORM_MASK_BYTES,
        }
    }

    /// Exact selected-anchor rank reads, alphabet-table initialization and
    /// pattern-byte census work for uniform-route admission.
    #[must_use]
    pub fn uniform_route_selection_work(self) -> u64 {
        if self.uniform_route_inspected {
            u64::try_from(
                self.patterns
                    .checked_add(UNIFORM_ALPHABET_ZERO_WORK)
                    .and_then(|work| work.checked_add(self.pattern_bytes))
                    .expect("certified uniform route work fits usize"),
            )
            .expect("certified uniform route work fits u64")
        } else {
            0
        }
    }

    /// Whether the source-visible shape reaches the optional route census.
    #[must_use]
    pub const fn uniform_shape_candidate(self) -> bool {
        !cfg!(feature = "static-dispatch")
            && self.bounded_prefix.is_none()
            && self.min_pattern_bytes == self.max_pattern_bytes
            && self.min_pattern_bytes >= UNIFORM_WORD64_MIN_PATTERN_BYTES
            && self.pattern_bytes <= UNIFORM_WORD_BITS
    }

    /// Whether the frozen alphabet reuse predicate admits the inspected set.
    #[must_use]
    pub fn uniform_alphabet_admitted(self) -> bool {
        let distinct = usize::from(self.uniform_distinct_pattern_bytes);
        self.uniform_route_inspected
            && distinct != 0
            && distinct <= UNIFORM_WORD64_MAX_DISTINCT_PATTERN_BYTES
            && distinct
                .checked_mul(UNIFORM_WORD64_MIN_ALPHABET_REUSE)
                .is_some_and(|needed| self.pattern_bytes >= needed)
    }

    /// The static route was proved, but its table delta did not fit the
    /// caller's existing work/persistent/peak envelope.
    #[must_use]
    pub fn uniform_resource_declined(self) -> bool {
        self.runtime_reducer == RuntimeReducer::ByteBucket
            && self.uniform_shape_candidate()
            && self.uniform_route_inspected
            && self.selected_anchor_minimum_frequency_rank
                >= UNIFORM_WORD64_MIN_ANCHOR_FREQUENCY_RANK
            && self.uniform_alphabet_admitted()
    }
}

/// Immutable identity and caller envelope for one construction attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildAttemptIdentity {
    pub algorithm_id: &'static str,
    pub plan_id: &'static str,
    pub operation: Operation,
    pub limits: BuildLimits,
    pub algorithm_version: u32,
    pub accounting_version: u32,
    pub bounded_prefix: Option<BoundedPrefixBounds>,
}

/// Exact effects committed through the last completed construction step.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BuildAttemptActual {
    pub work: u64,
    pub allocations: usize,
    pub allocated_bytes: usize,
    pub released_allocations: usize,
    pub released_bytes: usize,
    pub copied_bytes: usize,
    pub initialized_bytes: usize,
    pub live_persistent_bytes: usize,
    pub live_scratch_bytes: usize,
    pub peak_bytes: usize,
}

/// One closed successful or failed construction receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildAttemptReceipt {
    identity: BuildAttemptIdentity,
    actual: BuildAttemptActual,
    accounting: Option<BuildAccounting>,
    published: bool,
}

impl BuildAttemptReceipt {
    #[must_use]
    pub const fn identity(&self) -> BuildAttemptIdentity {
        self.identity
    }

    #[must_use]
    pub const fn actual(&self) -> BuildAttemptActual {
        self.actual
    }

    #[must_use]
    pub const fn accounting(&self) -> Option<BuildAccounting> {
        self.accounting
    }

    #[must_use]
    pub const fn published(&self) -> bool {
        self.published
    }

    #[must_use]
    pub fn contains_actual(&self) -> bool {
        let work_fits = u64::try_from(self.identity.limits.max_build_work)
            .map_or(true, |limit| self.actual.work <= limit);
        self.identity.algorithm_id == ALGORITHM_ID
            && self.identity.algorithm_version == BUILD_ATTEMPT_ALGORITHM_VERSION
            && self.identity.accounting_version == BUILD_ATTEMPT_ACCOUNTING_VERSION
            && work_fits
            && self.actual.live_persistent_bytes <= self.identity.limits.max_persistent_bytes
            && self.actual.peak_bytes <= self.identity.limits.max_build_peak_bytes
            && self.actual.live_scratch_bytes == 0
            && self.actual.released_allocations <= self.actual.allocations
            && self.actual.released_bytes <= self.actual.allocated_bytes
            && self.actual.copied_bytes <= self.actual.initialized_bytes
            && self.actual.peak_bytes
                >= self
                    .actual
                    .live_persistent_bytes
                    .saturating_add(self.actual.live_scratch_bytes)
    }

    fn closes_success(
        &self,
        plan_id: &'static str,
        operation: Operation,
        accounting: BuildAccounting,
    ) -> bool {
        self.published
            && self.identity.operation == operation
            && self.identity.plan_id == plan_id
            && self.identity.bounded_prefix == accounting.bounded_prefix
            && self.accounting == Some(accounting)
            && self.contains_actual()
            && self.actual.work == accounting.build_work_upper_bound
            && self.actual.allocations
                == if accounting.uniform_mask_bytes() == 0 {
                    1
                } else {
                    2
                }
            && size_of::<PackedOwner>()
                .checked_add(accounting.uniform_mask_bytes())
                .is_some_and(|bytes| self.actual.allocated_bytes == bytes)
            && self.actual.released_allocations == 0
            && self.actual.released_bytes == 0
            && self.actual.copied_bytes == accounting.identity_bytes
            && self.actual.initialized_bytes == accounting.persistent_bytes
            && self.actual.live_persistent_bytes == accounting.persistent_bytes
            && self.actual.peak_bytes == accounting.build_peak_upper_bound
    }

    fn closes_failure(&self) -> bool {
        !self.published
            && self.accounting.is_none()
            && self.contains_actual()
            && self.actual.live_persistent_bytes == 0
            && self.actual.live_scratch_bytes == 0
            && self.actual.released_allocations == self.actual.allocations
            && self.actual.released_bytes == self.actual.allocated_bytes
    }
}

/// Limits checked before touching one operation's source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceLimits {
    pub max_work: u64,
    pub max_match_events: usize,
    pub max_count: u64,
    pub max_span_sum: u64,
    pub max_reducer_steps: usize,
    pub max_scratch_bytes: usize,
    pub max_peak_bytes: usize,
}

impl ReduceLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_work: u64::MAX,
            max_match_events: usize::MAX,
            max_count: u64::MAX,
            max_span_sum: u64::MAX,
            max_reducer_steps: usize::MAX,
            max_scratch_bytes: usize::MAX,
            max_peak_bytes: usize::MAX,
        }
    }
}

impl Default for ReduceLimits {
    fn default() -> Self {
        Self {
            max_work: 16 * 1024 * 1024 * 1024,
            max_match_events: 128 * 1024 * 1024,
            max_count: 128 * 1024 * 1024,
            max_span_sum: 128 * 1024 * 1024,
            max_reducer_steps: 128 * 1024 * 1024 + 1,
            max_scratch_bytes: 0,
            max_peak_bytes: 2 * 1024 * 1024,
        }
    }
}

/// Complete source-independent envelope for one reduction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceUpperBounds {
    pub haystack_bytes: usize,
    pub candidate_positions: usize,
    /// Retained for compatibility with the former restarted iterator theorem.
    /// The monotone FRE-owned stream never revisits a suffix.
    pub restart_tail_positions: usize,
    pub examined_positions: usize,
    pub work_per_position: usize,
    /// Retained for compatibility. The monotone stream has no iterator setup.
    pub iterator_setup_work: usize,
    pub source_byte_reads: usize,
    /// Maximum Shift-And transitions for the uniform-word leaf.
    pub shift_and_transitions: usize,
    pub pattern_checks: usize,
    pub work: u64,
    pub match_events: usize,
    pub count: u64,
    pub span_sum: u64,
    pub reducer_steps: usize,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

/// Successful operation counters.
///
/// Prefix equality is intentionally left optimized. As with the existing
/// dependency-owned Two-Way primitive, its opaque early exits are charged at
/// the prospective source-read envelope in the successful actual receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceActualCounters {
    pub match_events: u64,
    /// Native reducer observations including one final exhausted observation.
    /// This is candidate events plus one for byte-bucket and transitions plus
    /// one for uniform Word64.
    pub iterator_next_calls: usize,
    pub count: Option<u64>,
    pub span_sum: Option<u64>,
    pub classified_positions: usize,
    pub candidate_events: usize,
    pub pattern_checks: usize,
    pub source_byte_reads: usize,
    /// Exact Shift-And transitions for the uniform-word leaf.
    pub shift_and_transitions: usize,
    pub work: u64,
    pub scratch_bytes: usize,
    pub peak_bytes: usize,
}

/// Successful reduction certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceAccounting<'a> {
    pub identity: CacheIdentity<'a>,
    pub upper_bounds: ReduceUpperBounds,
    pub actual: ReduceActualCounters,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountResult<'a> {
    pub count: u64,
    pub accounting: ReduceAccounting<'a>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpanSumResult<'a> {
    pub span_sum: u64,
    pub accounting: ReduceAccounting<'a>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BuildError {
    EmptyPatternSet,
    EmptyPattern {
        index: usize,
    },
    ProofRefused {
        fact: &'static str,
        needed: usize,
        certified_limit: usize,
    },
    PatternLimit {
        needed: usize,
        limit: usize,
    },
    PatternBytesLimit {
        needed: usize,
        limit: usize,
    },
    TotalPatternBytesLimit {
        needed: usize,
        limit: usize,
    },
    IdentityLimit {
        needed: usize,
        limit: usize,
    },
    WorkLimit {
        needed: usize,
        limit: usize,
    },
    BuildPeakLimit {
        needed: usize,
        limit: usize,
    },
    PersistentLimit {
        needed: usize,
        limit: usize,
    },
    UnsupportedTargetOrShape,
    AllocationFailed {
        additional: usize,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "packed ordered-literal build refusal: {self:?}")
    }
}

impl std::error::Error for BuildError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BuildFailureKind {
    EmptyPatternSet,
    EmptyPattern,
    ProofRefused,
    PatternLimit,
    PatternBytesLimit,
    TotalPatternBytesLimit,
    IdentityLimit,
    WorkLimit,
    BuildPeakLimit,
    PersistentLimit,
    UnsupportedTargetOrShape,
    AllocationFailed,
    ArithmeticOverflow,
}

impl BuildFailureKind {
    const fn from_error(error: &BuildError) -> Self {
        match error {
            BuildError::EmptyPatternSet => Self::EmptyPatternSet,
            BuildError::EmptyPattern { .. } => Self::EmptyPattern,
            BuildError::ProofRefused { .. } => Self::ProofRefused,
            BuildError::PatternLimit { .. } => Self::PatternLimit,
            BuildError::PatternBytesLimit { .. } => Self::PatternBytesLimit,
            BuildError::TotalPatternBytesLimit { .. } => Self::TotalPatternBytesLimit,
            BuildError::IdentityLimit { .. } => Self::IdentityLimit,
            BuildError::WorkLimit { .. } => Self::WorkLimit,
            BuildError::BuildPeakLimit { .. } => Self::BuildPeakLimit,
            BuildError::PersistentLimit { .. } => Self::PersistentLimit,
            BuildError::UnsupportedTargetOrShape => Self::UnsupportedTargetOrShape,
            BuildError::AllocationFailed { .. } => Self::AllocationFailed,
            BuildError::ArithmeticOverflow { .. } => Self::ArithmeticOverflow,
        }
    }
}

/// Terminal construction failure with its immutable partial actuals.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildAttemptError {
    source: BuildError,
    receipt: BuildAttemptReceipt,
    seal: BuildFailureKind,
}

impl BuildAttemptError {
    fn new(source: BuildError, identity: BuildAttemptIdentity, actual: BuildAttemptActual) -> Self {
        let seal = BuildFailureKind::from_error(&source);
        Self {
            source,
            receipt: BuildAttemptReceipt {
                identity,
                actual,
                accounting: None,
                published: false,
            },
            seal,
        }
    }

    #[must_use]
    pub const fn source(&self) -> &BuildError {
        &self.source
    }

    #[must_use]
    pub const fn receipt(&self) -> &BuildAttemptReceipt {
        &self.receipt
    }

    #[must_use]
    pub fn closes(&self) -> bool {
        self.seal == BuildFailureKind::from_error(&self.source) && self.receipt.closes_failure()
    }

    #[must_use]
    pub fn into_source(self) -> BuildError {
        self.source
    }
}

impl fmt::Display for BuildAttemptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.source.fmt(formatter)
    }
}

impl std::error::Error for BuildAttemptError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ReduceError {
    WorkLimit { needed: u64, limit: u64 },
    MatchEventsLimit { needed: usize, limit: usize },
    CountLimit { needed: u64, limit: u64 },
    SpanSumLimit { needed: u64, limit: u64 },
    ReducerStepsLimit { needed: usize, limit: usize },
    ScratchLimit { needed: usize, limit: usize },
    PeakLimit { needed: usize, limit: usize },
    ArithmeticOverflow { computation: &'static str },
    InternalInvariant { detail: &'static str },
}

impl fmt::Display for ReduceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "packed ordered-literal reduce refusal: {self:?}")
    }
}

impl std::error::Error for ReduceError {}

#[derive(Clone, Copy, Debug)]
struct PatternMeta {
    offset: u16,
    length: u8,
}

impl PatternMeta {
    const EMPTY: Self = Self {
        offset: 0,
        length: 0,
    };
}

#[derive(Debug)]
struct PackedOwner {
    screening_classifier: ByteBucketClassifier,
    classifier: ByteBucketClassifier,
    bucket_patterns: [u16; BYTE_BUCKET_COUNT],
    #[cfg(feature = "static-dispatch")]
    anchor_offset: u8,
    #[cfg(feature = "static-dispatch")]
    has_non_ascii_anchor_byte: bool,
    anchor_byte_patterns: [u16; 256],
    patterns: [PatternMeta; CERTIFIED_MAX_PATTERNS],
    encoded_patterns: [u8; IDENTITY_CAPACITY_BYTES],
    // ByteBucket stores encoded-length/anchor metadata inline. UniformWord64
    // stores one exact 256-word table allocation; its metadata and the two
    // scalar masks reuse byte-bucket-only fixed arrays below. This keeps the
    // incumbent owner exactly its prior size and allocation shape.
    #[cfg(not(feature = "static-dispatch"))]
    runtime: ExactBoxOrUsize<[u64; 256]>,
    #[cfg(feature = "static-dispatch")]
    encoded_len: u16,
}

impl PackedOwner {
    fn encoded_patterns(&self) -> &[u8] {
        let (len, _, _) = self.runtime_metadata();
        &self.encoded_patterns[..len]
    }

    fn pattern(&self, id: usize) -> &[u8] {
        let meta = self.patterns[id];
        let start = usize::from(meta.offset);
        let end = start
            .checked_add(usize::from(meta.length))
            .expect("certified pattern extent fits the fixed identity");
        &self.encoded_patterns[start..end]
    }

    fn runtime_reducer(&self) -> RuntimeReducer {
        #[cfg(feature = "static-dispatch")]
        {
            RuntimeReducer::ByteBucket
        }
        #[cfg(not(feature = "static-dispatch"))]
        {
            if self.runtime.as_usize().is_some() {
                RuntimeReducer::ByteBucket
            } else {
                RuntimeReducer::UniformWord64
            }
        }
    }

    fn runtime_metadata(&self) -> (usize, usize, bool) {
        #[cfg(feature = "static-dispatch")]
        {
            return (
                usize::from(self.encoded_len),
                usize::from(self.anchor_offset),
                self.has_non_ascii_anchor_byte,
            );
        }
        #[cfg(not(feature = "static-dispatch"))]
        {
            if let Some(encoded) = self.runtime.as_usize() {
                return (
                    encoded & 0xffff,
                    (encoded >> 16) & 0xff,
                    (encoded >> 24) & 1 != 0,
                );
            }
            (
                usize::from(self.bucket_patterns[0]),
                usize::from(self.bucket_patterns[1]),
                self.bucket_patterns[2] != 0,
            )
        }
    }

    #[cfg(not(feature = "static-dispatch"))]
    fn uniform_masks(&self) -> Option<&[u64; 256]> {
        self.runtime.boxed()
    }

    #[cfg(not(feature = "static-dispatch"))]
    fn uniform_start_mask(&self) -> u64 {
        packed_u16_word(&self.anchor_byte_patterns[..4])
    }

    #[cfg(not(feature = "static-dispatch"))]
    fn uniform_accept_mask(&self) -> u64 {
        packed_u16_word(&self.anchor_byte_patterns[4..8])
    }
}

#[cfg(not(feature = "static-dispatch"))]
fn packed_runtime_metadata(encoded_len: u16, anchor_offset: u8, non_ascii: bool) -> usize {
    usize::from(encoded_len) | (usize::from(anchor_offset) << 16) | (usize::from(non_ascii) << 24)
}

#[cfg(not(feature = "static-dispatch"))]
fn packed_u16_word(parts: &[u16]) -> u64 {
    debug_assert_eq!(parts.len(), 4);
    u64::from(parts[0])
        | (u64::from(parts[1]) << 16)
        | (u64::from(parts[2]) << 32)
        | (u64::from(parts[3]) << 48)
}

#[cfg(not(feature = "static-dispatch"))]
fn store_packed_u16_word(parts: &mut [u16], value: u64) {
    debug_assert_eq!(parts.len(), 4);
    parts[0] = u16::try_from(value & 0xffff).expect("low Word64 lane fits u16");
    parts[1] = u16::try_from((value >> 16) & 0xffff).expect("second Word64 lane fits u16");
    parts[2] = u16::try_from((value >> 32) & 0xffff).expect("third Word64 lane fits u16");
    parts[3] = u16::try_from((value >> 48) & 0xffff).expect("high Word64 lane fits u16");
}

#[derive(Debug)]
struct PlanCore {
    owner: Box<PackedOwner>,
    build: BuildAccounting,
}

/// Non-`Clone`, count-specialized packed plan.
#[derive(Debug)]
pub struct PackedOrderedLiteralCountPlan {
    core: PlanCore,
}

/// Non-`Clone`, span-specialized packed plan.
#[derive(Debug)]
pub struct PackedOrderedLiteralSpanSumPlan {
    core: PlanCore,
}

/// Non-`Clone`, count-specialized plan for a greedy finite dot-byte prefix
/// followed by a small ordered literal set.
#[derive(Debug)]
pub struct PackedBoundedPrefixLiteralCountPlan {
    core: PlanCore,
    bounds: BoundedPrefixBounds,
}

/// Successful count-plan construction and its closed receipt.
#[derive(Debug)]
pub struct CountBuildAttempt {
    plan: PackedOrderedLiteralCountPlan,
    receipt: BuildAttemptReceipt,
}

impl CountBuildAttempt {
    #[must_use]
    pub const fn plan(&self) -> &PackedOrderedLiteralCountPlan {
        &self.plan
    }

    #[must_use]
    pub const fn receipt(&self) -> &BuildAttemptReceipt {
        &self.receipt
    }

    #[must_use]
    pub fn closes(&self) -> bool {
        self.receipt.closes_success(
            COUNT_PLAN_ID,
            Operation::Count,
            self.plan.build_accounting(),
        )
    }

    #[must_use]
    pub fn into_parts(self) -> (PackedOrderedLiteralCountPlan, BuildAttemptReceipt) {
        (self.plan, self.receipt)
    }

    #[must_use]
    pub fn into_plan(self) -> PackedOrderedLiteralCountPlan {
        self.plan
    }
}

/// Successful span-sum-plan construction and its closed receipt.
#[derive(Debug)]
pub struct SpanSumBuildAttempt {
    plan: PackedOrderedLiteralSpanSumPlan,
    receipt: BuildAttemptReceipt,
}

impl SpanSumBuildAttempt {
    #[must_use]
    pub const fn plan(&self) -> &PackedOrderedLiteralSpanSumPlan {
        &self.plan
    }

    #[must_use]
    pub const fn receipt(&self) -> &BuildAttemptReceipt {
        &self.receipt
    }

    #[must_use]
    pub fn closes(&self) -> bool {
        self.receipt.closes_success(
            SPAN_SUM_PLAN_ID,
            Operation::SpanSum,
            self.plan.build_accounting(),
        )
    }

    #[must_use]
    pub fn into_parts(self) -> (PackedOrderedLiteralSpanSumPlan, BuildAttemptReceipt) {
        (self.plan, self.receipt)
    }

    #[must_use]
    pub fn into_plan(self) -> PackedOrderedLiteralSpanSumPlan {
        self.plan
    }
}

/// Successful bounded-prefix count-plan construction and its closed receipt.
#[derive(Debug)]
pub struct BoundedPrefixCountBuildAttempt {
    plan: PackedBoundedPrefixLiteralCountPlan,
    receipt: BuildAttemptReceipt,
}

impl BoundedPrefixCountBuildAttempt {
    #[must_use]
    pub const fn plan(&self) -> &PackedBoundedPrefixLiteralCountPlan {
        &self.plan
    }

    #[must_use]
    pub const fn receipt(&self) -> &BuildAttemptReceipt {
        &self.receipt
    }

    #[must_use]
    pub fn closes(&self) -> bool {
        self.receipt.closes_success(
            BOUNDED_PREFIX_COUNT_PLAN_ID,
            Operation::Count,
            self.plan.build_accounting(),
        )
    }

    #[must_use]
    pub fn into_parts(self) -> (PackedBoundedPrefixLiteralCountPlan, BuildAttemptReceipt) {
        (self.plan, self.receipt)
    }

    #[must_use]
    pub fn into_plan(self) -> PackedBoundedPrefixLiteralCountPlan {
        self.plan
    }
}

impl PackedOrderedLiteralCountPlan {
    pub fn build<P: AsRef<[u8]>>(patterns: &[P], limits: BuildLimits) -> Result<Self, BuildError> {
        Self::build_with_dispatch(SimdDispatchContext::capture(), patterns, limits)
    }

    /// Build from one caller-captured capability snapshot.
    pub fn build_with_dispatch<P: AsRef<[u8]>>(
        dispatch: SimdDispatchContext,
        patterns: &[P],
        limits: BuildLimits,
    ) -> Result<Self, BuildError> {
        Self::build_attempt_with_dispatch(dispatch, patterns, limits)
            .map(CountBuildAttempt::into_plan)
            .map_err(BuildAttemptError::into_source)
    }

    #[allow(
        clippy::result_large_err,
        reason = "the terminal receipt remains inline so failed allocation reporting cannot allocate"
    )]
    pub fn build_attempt<P: AsRef<[u8]>>(
        patterns: &[P],
        limits: BuildLimits,
    ) -> Result<CountBuildAttempt, BuildAttemptError> {
        Self::build_attempt_with_dispatch(SimdDispatchContext::capture(), patterns, limits)
    }

    /// Build with one caller-captured capability snapshot and retain the
    /// complete success-or-failure receipt.
    #[allow(
        clippy::result_large_err,
        reason = "the terminal receipt remains inline so failed allocation reporting cannot allocate"
    )]
    pub fn build_attempt_with_dispatch<P: AsRef<[u8]>>(
        dispatch: SimdDispatchContext,
        patterns: &[P],
        limits: BuildLimits,
    ) -> Result<CountBuildAttempt, BuildAttemptError> {
        let identity = build_attempt_identity(COUNT_PLAN_ID, Operation::Count, None, limits);
        PlanCore::build_attempt(patterns, limits, size_of::<Self>(), identity, dispatch).map(
            |(core, receipt)| CountBuildAttempt {
                plan: Self { core },
                receipt,
            },
        )
    }

    #[must_use]
    pub const fn build_accounting(&self) -> BuildAccounting {
        self.core.build
    }

    #[must_use]
    pub fn cache_identity(&self) -> CacheIdentity<'_> {
        self.core.identity(
            COUNT_PLAN_ID,
            Operation::Count,
            "FRE-owned monotone fixed-anchor SIMD candidate stream with ordered verification",
        )
    }

    #[inline]
    pub fn count<'a>(
        &'a self,
        haystack: &[u8],
        limits: ReduceLimits,
    ) -> Result<CountResult<'a>, ReduceError> {
        let outcome = self.core.reduce::<false>(haystack, limits)?;
        Ok(CountResult {
            count: outcome.count,
            accounting: ReduceAccounting {
                identity: self.cache_identity(),
                upper_bounds: outcome.upper,
                actual: outcome.actual,
            },
        })
    }
}

impl PackedOrderedLiteralSpanSumPlan {
    pub fn build<P: AsRef<[u8]>>(patterns: &[P], limits: BuildLimits) -> Result<Self, BuildError> {
        Self::build_with_dispatch(SimdDispatchContext::capture(), patterns, limits)
    }

    /// Build from one caller-captured capability snapshot.
    pub fn build_with_dispatch<P: AsRef<[u8]>>(
        dispatch: SimdDispatchContext,
        patterns: &[P],
        limits: BuildLimits,
    ) -> Result<Self, BuildError> {
        Self::build_attempt_with_dispatch(dispatch, patterns, limits)
            .map(SpanSumBuildAttempt::into_plan)
            .map_err(BuildAttemptError::into_source)
    }

    #[allow(
        clippy::result_large_err,
        reason = "the terminal receipt remains inline so failed allocation reporting cannot allocate"
    )]
    pub fn build_attempt<P: AsRef<[u8]>>(
        patterns: &[P],
        limits: BuildLimits,
    ) -> Result<SpanSumBuildAttempt, BuildAttemptError> {
        Self::build_attempt_with_dispatch(SimdDispatchContext::capture(), patterns, limits)
    }

    /// Build with one caller-captured capability snapshot and retain the
    /// complete success-or-failure receipt.
    #[allow(
        clippy::result_large_err,
        reason = "the terminal receipt remains inline so failed allocation reporting cannot allocate"
    )]
    pub fn build_attempt_with_dispatch<P: AsRef<[u8]>>(
        dispatch: SimdDispatchContext,
        patterns: &[P],
        limits: BuildLimits,
    ) -> Result<SpanSumBuildAttempt, BuildAttemptError> {
        let identity = build_attempt_identity(SPAN_SUM_PLAN_ID, Operation::SpanSum, None, limits);
        PlanCore::build_attempt(patterns, limits, size_of::<Self>(), identity, dispatch).map(
            |(core, receipt)| SpanSumBuildAttempt {
                plan: Self { core },
                receipt,
            },
        )
    }

    #[must_use]
    pub const fn build_accounting(&self) -> BuildAccounting {
        self.core.build
    }

    #[must_use]
    pub fn cache_identity(&self) -> CacheIdentity<'_> {
        self.core.identity(
            SPAN_SUM_PLAN_ID,
            Operation::SpanSum,
            "FRE-owned monotone fixed-anchor SIMD candidate stream with ordered verification",
        )
    }

    #[inline]
    pub fn span_sum<'a>(
        &'a self,
        haystack: &[u8],
        limits: ReduceLimits,
    ) -> Result<SpanSumResult<'a>, ReduceError> {
        let outcome = self.core.reduce::<true>(haystack, limits)?;
        Ok(SpanSumResult {
            span_sum: outcome.span_sum,
            accounting: ReduceAccounting {
                identity: self.cache_identity(),
                upper_bounds: outcome.upper,
                actual: outcome.actual,
            },
        })
    }
}

impl PackedBoundedPrefixLiteralCountPlan {
    pub fn build<P: AsRef<[u8]>>(
        patterns: &[P],
        bounds: BoundedPrefixBounds,
        limits: BuildLimits,
    ) -> Result<Self, BuildError> {
        Self::build_with_dispatch(SimdDispatchContext::capture(), patterns, bounds, limits)
    }

    /// Build from one caller-captured capability snapshot.
    pub fn build_with_dispatch<P: AsRef<[u8]>>(
        dispatch: SimdDispatchContext,
        patterns: &[P],
        bounds: BoundedPrefixBounds,
        limits: BuildLimits,
    ) -> Result<Self, BuildError> {
        Self::build_attempt_with_dispatch(dispatch, patterns, bounds, limits)
            .map(BoundedPrefixCountBuildAttempt::into_plan)
            .map_err(BuildAttemptError::into_source)
    }

    #[allow(
        clippy::result_large_err,
        reason = "the terminal receipt remains inline so failed allocation reporting cannot allocate"
    )]
    pub fn build_attempt<P: AsRef<[u8]>>(
        patterns: &[P],
        bounds: BoundedPrefixBounds,
        limits: BuildLimits,
    ) -> Result<BoundedPrefixCountBuildAttempt, BuildAttemptError> {
        Self::build_attempt_with_dispatch(SimdDispatchContext::capture(), patterns, bounds, limits)
    }

    /// Build with one caller-captured capability snapshot and retain the
    /// complete success-or-failure receipt.
    #[allow(
        clippy::result_large_err,
        reason = "the terminal receipt remains inline so failed allocation reporting cannot allocate"
    )]
    pub fn build_attempt_with_dispatch<P: AsRef<[u8]>>(
        dispatch: SimdDispatchContext,
        patterns: &[P],
        bounds: BoundedPrefixBounds,
        limits: BuildLimits,
    ) -> Result<BoundedPrefixCountBuildAttempt, BuildAttemptError> {
        let identity = build_attempt_identity(
            BOUNDED_PREFIX_COUNT_PLAN_ID,
            Operation::Count,
            Some(bounds),
            limits,
        );
        if limits.max_build_work == 0 {
            return Err(attempt_error(
                BuildError::WorkLimit {
                    needed: 1,
                    limit: 0,
                },
                identity,
                BuildAttemptActual::default(),
            ));
        }
        let bounds_actual = BuildAttemptActual {
            work: 1,
            ..BuildAttemptActual::default()
        };
        if bounds.minimum > bounds.maximum {
            return Err(attempt_error(
                BuildError::ProofRefused {
                    fact: "bounded prefix minimum does not exceed maximum",
                    needed: usize::from(bounds.minimum),
                    certified_limit: usize::from(bounds.maximum),
                },
                identity,
                bounds_actual,
            ));
        }
        if bounds.maximum > CERTIFIED_MAX_BOUNDED_PREFIX_BYTES {
            return Err(attempt_error(
                BuildError::ProofRefused {
                    fact: "bounded prefix maximum",
                    needed: usize::from(bounds.maximum),
                    certified_limit: usize::from(CERTIFIED_MAX_BOUNDED_PREFIX_BYTES),
                },
                identity,
                bounds_actual,
            ));
        }
        PlanCore::build_attempt(patterns, limits, size_of::<Self>(), identity, dispatch).map(
            |(core, receipt)| BoundedPrefixCountBuildAttempt {
                plan: Self { core, bounds },
                receipt,
            },
        )
    }

    #[must_use]
    pub const fn build_accounting(&self) -> BuildAccounting {
        self.core.build
    }

    #[must_use]
    pub fn cache_identity(&self) -> CacheIdentity<'_> {
        self.core.identity(
            BOUNDED_PREFIX_COUNT_PLAN_ID,
            Operation::Count,
            "FRE-owned monotone fixed-anchor SIMD literal-start stream with greedy bounded-prefix arbitration",
        )
    }

    #[inline]
    pub fn count<'a>(
        &'a self,
        haystack: &[u8],
        limits: ReduceLimits,
    ) -> Result<CountResult<'a>, ReduceError> {
        let outcome = self
            .core
            .reduce_bounded_prefix(haystack, self.bounds, limits)?;
        Ok(CountResult {
            count: outcome.count,
            accounting: ReduceAccounting {
                identity: self.cache_identity(),
                upper_bounds: outcome.upper,
                actual: outcome.actual,
            },
        })
    }
}

const fn build_attempt_identity(
    plan_id: &'static str,
    operation: Operation,
    bounded_prefix: Option<BoundedPrefixBounds>,
    limits: BuildLimits,
) -> BuildAttemptIdentity {
    BuildAttemptIdentity {
        algorithm_id: ALGORITHM_ID,
        plan_id,
        operation,
        limits,
        algorithm_version: BUILD_ATTEMPT_ALGORITHM_VERSION,
        accounting_version: BUILD_ATTEMPT_ACCOUNTING_VERSION,
        bounded_prefix,
    }
}

impl PlanCore {
    fn identity(
        &self,
        plan_id: &'static str,
        operation: Operation,
        implementation_kind: &'static str,
    ) -> CacheIdentity<'_> {
        let runtime_reducer = self.owner.runtime_reducer();
        CacheIdentity {
            algorithm_id: ALGORITHM_ID,
            plan_id,
            operation,
            cache_format_version: CACHE_FORMAT_VERSION,
            implementation_kind: match runtime_reducer {
                RuntimeReducer::ByteBucket => implementation_kind,
                RuntimeReducer::UniformWord64 => "FRE-owned uniform-word Word64 Shift-And stream",
            },
            identity_scope: match runtime_reducer {
                RuntimeReducer::ByteBucket => {
                    "process-local semantic identity with authenticated classifier receipt"
                }
                RuntimeReducer::UniformWord64 => {
                    "process-local semantic identity with retained inactive byte-bucket construction and authenticated scalar reducer receipt"
                }
            },
            target_arch: std::env::consts::ARCH,
            runtime_minimum_haystack_bytes: match runtime_reducer {
                RuntimeReducer::ByteBucket => SIMD_BLOCK_BYTES,
                RuntimeReducer::UniformWord64 => 0,
            },
            semantics: SEMANTICS,
            runtime_reducer,
            anchor_offset: self.build.anchor_offset,
            anchor_has_non_ascii: self.build.anchor_has_non_ascii,
            mask_columns: u8::try_from(self.owner.classifier.tables().columns())
                .expect("the fixed mask-column cap fits in u8"),
            classifier_selection: match runtime_reducer {
                RuntimeReducer::ByteBucket => Some(self.owner.classifier.selection()),
                RuntimeReducer::UniformWord64 => None,
            },
            certified_min_patterns: CERTIFIED_MIN_PATTERNS,
            certified_max_patterns: CERTIFIED_MAX_PATTERNS,
            certified_min_pattern_bytes: CERTIFIED_MIN_PATTERN_BYTES,
            certified_max_pattern_bytes: CERTIFIED_MAX_PATTERN_BYTES,
            certified_max_total_pattern_bytes: CERTIFIED_MAX_TOTAL_PATTERN_BYTES,
            bounded_prefix: self.build.bounded_prefix,
            encoded_patterns: self.owner.encoded_patterns(),
        }
    }

    #[allow(
        clippy::result_large_err,
        clippy::too_many_lines,
        reason = "the failed attempt carries the exact inline receipt, and the source-to-fixed-owner transaction remains adjacent for accounting audit"
    )]
    fn build_attempt<P: AsRef<[u8]>>(
        patterns: &[P],
        limits: BuildLimits,
        inline_bytes: usize,
        identity: BuildAttemptIdentity,
        dispatch: SimdDispatchContext,
    ) -> Result<(Self, BuildAttemptReceipt), BuildAttemptError> {
        let (preflight, mut actual) = preflight(
            patterns,
            limits,
            inline_bytes,
            usize::from(identity.bounded_prefix.is_some()),
            identity.bounded_prefix.is_none() && !cfg!(feature = "static-dispatch"),
        )
        .map_err(|failure| BuildAttemptError::new(failure.source, identity, failure.actual))?;

        let anchor_offset = preflight.anchor_offset;
        let (screening_tables, bucket_tables, bucket_patterns) =
            build_byte_bucket_tables(patterns, preflight.mask_columns, anchor_offset)
                .map_err(|error| attempt_error(error, identity, actual))?;
        #[cfg(not(feature = "static-dispatch"))]
        let mut bucket_patterns = bucket_patterns;
        charge_attempt_work(
            &mut actual,
            usize::try_from(preflight.bucket_assignment_work)
                .expect("preflight bucket work originated as usize"),
            identity,
            "completed byte-bucket assignment work",
        )?;
        let mut encoded_patterns = [0_u8; IDENTITY_CAPACITY_BYTES];
        let mut pattern_meta = [PatternMeta::EMPTY; CERTIFIED_MAX_PATTERNS];
        let mut anchor_byte_patterns = [0_u16; 256];
        let mut anchor_byte_pattern_bytes = [0_usize; 256];
        let mut max_anchor_byte_bucket_patterns = 0_usize;
        let mut max_anchor_byte_bucket_pattern_bytes = 0_usize;
        let mut has_non_ascii_anchor_byte = false;
        let count = u64::try_from(patterns.len()).map_err(|_| {
            attempt_error(
                BuildError::ArithmeticOverflow {
                    computation: "identity pattern count",
                },
                identity,
                actual,
            )
        })?;
        encoded_patterns[..LENGTH_PREFIX_BYTES].copy_from_slice(&count.to_le_bytes());
        let mut cursor = LENGTH_PREFIX_BYTES;
        for (index, pattern) in patterns.iter().enumerate() {
            let bytes = pattern.as_ref();
            let length = u64::try_from(bytes.len()).map_err(|_| {
                attempt_error(
                    BuildError::ArithmeticOverflow {
                        computation: "identity pattern length",
                    },
                    identity,
                    actual,
                )
            })?;
            let prefix_end = cursor.checked_add(LENGTH_PREFIX_BYTES).ok_or_else(|| {
                attempt_error(
                    BuildError::ArithmeticOverflow {
                        computation: "identity length-prefix end",
                    },
                    identity,
                    actual,
                )
            })?;
            encoded_patterns[cursor..prefix_end].copy_from_slice(&length.to_le_bytes());
            let bytes_end = prefix_end.checked_add(bytes.len()).ok_or_else(|| {
                attempt_error(
                    BuildError::ArithmeticOverflow {
                        computation: "identity pattern end",
                    },
                    identity,
                    actual,
                )
            })?;
            encoded_patterns[prefix_end..bytes_end].copy_from_slice(bytes);
            pattern_meta[index] = PatternMeta {
                offset: u16::try_from(prefix_end).map_err(|_| {
                    attempt_error(
                        BuildError::ArithmeticOverflow {
                            computation: "pattern identity offset",
                        },
                        identity,
                        actual,
                    )
                })?,
                length: u8::try_from(bytes.len()).map_err(|_| {
                    attempt_error(
                        BuildError::ArithmeticOverflow {
                            computation: "pattern length metadata",
                        },
                        identity,
                        actual,
                    )
                })?,
            };
            let anchor = bytes[anchor_offset];
            let bit = 1_u16
                .checked_shl(u32::try_from(index).map_err(|_| {
                    attempt_error(
                        BuildError::ArithmeticOverflow {
                            computation: "pattern map bit",
                        },
                        identity,
                        actual,
                    )
                })?)
                .ok_or_else(|| {
                    attempt_error(
                        BuildError::ArithmeticOverflow {
                            computation: "pattern map bit",
                        },
                        identity,
                        actual,
                    )
                })?;
            anchor_byte_patterns[usize::from(anchor)] |= bit;
            max_anchor_byte_bucket_patterns = max_anchor_byte_bucket_patterns.max(
                usize::try_from(anchor_byte_patterns[usize::from(anchor)].count_ones())
                    .expect("u16 population count always fits a supported usize"),
            );
            anchor_byte_pattern_bytes[usize::from(anchor)] = anchor_byte_pattern_bytes
                [usize::from(anchor)]
            .checked_add(bytes.len())
            .ok_or_else(|| {
                attempt_error(
                    BuildError::ArithmeticOverflow {
                        computation: "anchor-byte bucket pattern bytes",
                    },
                    identity,
                    actual,
                )
            })?;
            max_anchor_byte_bucket_pattern_bytes = max_anchor_byte_bucket_pattern_bytes
                .max(anchor_byte_pattern_bytes[usize::from(anchor)]);
            if anchor >= 128 {
                has_non_ascii_anchor_byte = true;
            }
            cursor = bytes_end;
        }
        if cursor != preflight.identity_bytes {
            return Err(attempt_error(
                BuildError::ArithmeticOverflow {
                    computation: "identity encoded length invariant",
                },
                identity,
                actual,
            ));
        }
        charge_attempt_work(
            &mut actual,
            preflight.identity_bytes,
            identity,
            "completed identity-copy work",
        )?;
        charge_attempt_work(
            &mut actual,
            size_of::<PackedOwner>(),
            identity,
            "completed inline owner initialization work",
        )?;
        actual.copied_bytes = preflight.identity_bytes;
        actual.initialized_bytes = size_of::<PackedOwner>();
        let anchor_offset_u8 = u8::try_from(anchor_offset).map_err(|_| {
            attempt_error(
                BuildError::ArithmeticOverflow {
                    computation: "anchor offset metadata",
                },
                identity,
                actual,
            )
        })?;
        let encoded_len = u16::try_from(cursor).map_err(|_| {
            attempt_error(
                BuildError::ArithmeticOverflow {
                    computation: "identity encoded length metadata",
                },
                identity,
                actual,
            )
        })?;
        let screening_classifier = dispatch
            .byte_bucket_classifier(screening_tables, DispatchPolicy::Auto)
            .map_err(|_| attempt_error(BuildError::UnsupportedTargetOrShape, identity, actual))?;
        let classifier = dispatch
            .byte_bucket_classifier(bucket_tables, DispatchPolicy::Auto)
            .map_err(|_| attempt_error(BuildError::UnsupportedTargetOrShape, identity, actual))?;
        charge_attempt_work(
            &mut actual,
            CLASSIFIER_BUILD_WORK,
            identity,
            "completed byte-bucket classifier work",
        )?;
        debug_assert_eq!(screening_classifier.selection(), classifier.selection());
        #[cfg(not(feature = "static-dispatch"))]
        if preflight.runtime_reducer == RuntimeReducer::UniformWord64 {
            charge_attempt_work(
                &mut actual,
                UNIFORM_MASK_ZERO_WORK,
                identity,
                "completed uniform mask zero-initialization work",
            )?;
            charge_attempt_work(
                &mut actual,
                preflight.uniform_mask_bytes,
                identity,
                "completed uniform mask initialization work",
            )?;
            actual.initialized_bytes = actual
                .initialized_bytes
                .checked_add(preflight.uniform_mask_bytes)
                .ok_or_else(|| {
                    attempt_error(
                        BuildError::ArithmeticOverflow {
                            computation: "uniform mask initialized bytes",
                        },
                        identity,
                        actual,
                    )
                })?;
        }
        #[cfg(not(feature = "static-dispatch"))]
        let uniform = if preflight.runtime_reducer == RuntimeReducer::UniformWord64 {
            let masks = allocate_uniform_masks().map_err(|_| {
                attempt_error(
                    BuildError::AllocationFailed {
                        additional: UNIFORM_MASK_BYTES,
                    },
                    identity,
                    actual,
                )
            })?;
            actual.allocations = 1;
            actual.allocated_bytes = preflight.uniform_mask_bytes;
            actual.live_persistent_bytes = preflight.uniform_mask_bytes;
            actual.peak_bytes = preflight.uniform_mask_bytes;
            let tables = populate_uniform_word64(patterns, masks);
            charge_attempt_work(
                &mut actual,
                usize::try_from(preflight.uniform_mask_build_work)
                    .expect("preflight uniform mask work originated as usize")
                    .checked_sub(UNIFORM_MASK_ZERO_WORK)
                    .expect("uniform mask work includes its zero initialization"),
                identity,
                "completed uniform mask literal construction work",
            )
            .map_err(|mut error| {
                error.receipt.actual.released_allocations = actual.allocations;
                error.receipt.actual.released_bytes = actual.allocated_bytes;
                error.receipt.actual.live_persistent_bytes = 0;
                error
            })?;
            tables
        } else {
            UniformWord64Tables::empty()
        };
        #[cfg(not(feature = "static-dispatch"))]
        let runtime = match uniform.masks {
            Some(masks) => {
                bucket_patterns[0] = encoded_len;
                bucket_patterns[1] = u16::from(anchor_offset_u8);
                bucket_patterns[2] = u16::from(has_non_ascii_anchor_byte);
                store_packed_u16_word(&mut anchor_byte_patterns[..4], uniform.start_mask);
                store_packed_u16_word(&mut anchor_byte_patterns[4..8], uniform.accept_mask);
                masks
            }
            None => ExactBoxOrUsize::try_from_usize(packed_runtime_metadata(
                encoded_len,
                anchor_offset_u8,
                has_non_ascii_anchor_byte,
            ))
            .map_err(|_| {
                attempt_error(
                    BuildError::ArithmeticOverflow {
                        computation: "inline byte-bucket runtime metadata",
                    },
                    identity,
                    actual,
                )
            })?,
        };
        #[cfg(feature = "static-dispatch")]
        {
            debug_assert_eq!(preflight.runtime_reducer, RuntimeReducer::ByteBucket);
        }
        let owner = PackedOwner {
            screening_classifier,
            classifier,
            bucket_patterns,
            #[cfg(feature = "static-dispatch")]
            anchor_offset: anchor_offset_u8,
            #[cfg(feature = "static-dispatch")]
            has_non_ascii_anchor_byte,
            anchor_byte_patterns,
            patterns: pattern_meta,
            encoded_patterns,
            #[cfg(not(feature = "static-dispatch"))]
            runtime,
            #[cfg(feature = "static-dispatch")]
            encoded_len,
        };
        let owner = allocate_owner(owner).map_err(|(_, _owner)| {
            let mut failed = actual;
            failed.released_allocations = failed.allocations;
            failed.released_bytes = failed.allocated_bytes;
            failed.live_persistent_bytes = 0;
            attempt_error(
                BuildError::AllocationFailed {
                    additional: size_of::<PackedOwner>(),
                },
                identity,
                failed,
            )
        })?;
        debug_assert_eq!(actual.work, preflight.build_work);
        actual.allocations = if preflight.uniform_mask_bytes == 0 {
            1
        } else {
            2
        };
        actual.allocated_bytes = preflight
            .persistent_bytes
            .checked_sub(inline_bytes)
            .expect("preflight persistent bytes contain the inline owner");
        actual.initialized_bytes = preflight.persistent_bytes;
        actual.live_persistent_bytes = preflight.persistent_bytes;
        actual.peak_bytes = preflight.peak_bytes;
        let build = BuildAccounting {
            patterns: patterns.len(),
            pattern_bytes: preflight.pattern_bytes,
            max_pattern_bytes: preflight.max_pattern_bytes,
            min_pattern_bytes: preflight.min_pattern_bytes,
            runtime_reducer: preflight.runtime_reducer,
            selected_anchor_minimum_frequency_rank: preflight
                .selected_anchor_minimum_frequency_rank,
            uniform_distinct_pattern_bytes: preflight.uniform_distinct_pattern_bytes,
            uniform_route_inspected: preflight.uniform_route_selection_work != 0,
            anchor_offset,
            anchor_has_non_ascii: has_non_ascii_anchor_byte,
            anchor_selection_work: preflight.anchor_selection_work,
            mask_columns: preflight.mask_columns,
            bucket_assignment_work: preflight.bucket_assignment_work,
            max_anchor_byte_bucket_patterns,
            max_anchor_byte_bucket_pattern_bytes,
            identity_bytes: preflight.identity_bytes,
            identity_capacity_bytes: IDENTITY_CAPACITY_BYTES,
            build_work_upper_bound: preflight.build_work,
            build_peak_upper_bound: preflight.peak_bytes,
            persistent_bytes: preflight.persistent_bytes,
            simd_minimum_haystack_bytes: match preflight.runtime_reducer {
                RuntimeReducer::ByteBucket => SIMD_BLOCK_BYTES,
                RuntimeReducer::UniformWord64 => 0,
            },
            bounded_prefix: identity.bounded_prefix,
        };
        let receipt = BuildAttemptReceipt {
            identity,
            actual,
            accounting: Some(build),
            published: true,
        };
        let core = Self { owner, build };
        if !receipt.closes_success(identity.plan_id, identity.operation, core.build) {
            let mut failed = actual;
            failed.released_allocations = failed.allocations;
            failed.released_bytes = failed.allocated_bytes;
            failed.live_persistent_bytes = 0;
            return Err(attempt_error(
                BuildError::ArithmeticOverflow {
                    computation: "successful construction receipt closure",
                },
                identity,
                failed,
            ));
        }
        Ok((core, receipt))
    }

    fn preflight_reduce<const SPAN_SUM: bool>(
        &self,
        haystack_len: usize,
        limits: ReduceLimits,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        let candidate_positions = if haystack_len < self.build.min_pattern_bytes {
            0
        } else {
            haystack_len
                .checked_sub(self.build.min_pattern_bytes)
                .and_then(|remaining| remaining.checked_add(1))
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "candidate positions",
                })?
        };
        let pattern_checks = candidate_positions
            .checked_mul(self.build.max_anchor_byte_bucket_patterns)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "anchor-byte bucket pattern checks",
            })?;
        let verification_reads = candidate_positions
            .checked_mul(self.build.max_anchor_byte_bucket_pattern_bytes)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "anchor-byte bucket verification source reads",
            })?;
        let fixed_source_reads_per_position =
            self.build
                .mask_columns
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "fixed source reads per position",
                })?;
        let source_byte_reads = candidate_positions
            .checked_mul(fixed_source_reads_per_position)
            .and_then(|reads| reads.checked_add(verification_reads))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "source byte reads",
            })?;
        let work_per_position = self
            .build
            .max_anchor_byte_bucket_pattern_bytes
            .checked_add(self.build.max_anchor_byte_bucket_patterns)
            .and_then(|work| work.checked_add(4))
            .and_then(|work| work.checked_add(fixed_source_reads_per_position))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "work per position",
            })?;
        let work_usize = candidate_positions
            .checked_mul(work_per_position)
            .and_then(|work| work.checked_add(1))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "packed operation work",
            })?;
        let work = u64::try_from(work_usize).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "packed operation work as u64",
        })?;
        let match_events = haystack_len
            .checked_div(self.build.min_pattern_bytes)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "event quotient",
            })?;
        let count = u64::try_from(match_events).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "count upper bound",
        })?;
        let span_sum =
            u64::try_from(haystack_len).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "span-sum upper bound",
            })?;
        let reducer_steps =
            candidate_positions
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "reducer steps",
                })?;
        let upper = ReduceUpperBounds {
            haystack_bytes: haystack_len,
            candidate_positions,
            restart_tail_positions: 0,
            examined_positions: candidate_positions,
            work_per_position,
            iterator_setup_work: 0,
            source_byte_reads,
            shift_and_transitions: 0,
            pattern_checks,
            work,
            match_events,
            count,
            span_sum,
            reducer_steps,
            scratch_bytes: 0,
            persistent_bytes: self.build.persistent_bytes,
            peak_bytes: self.build.persistent_bytes,
        };
        check_reduce(upper, SPAN_SUM, limits)?;
        Ok(upper)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the monotone block/tail traversal and its exact counters remain in one auditable operation"
    )]
    fn reduce<const SPAN_SUM: bool>(
        &self,
        haystack: &[u8],
        limits: ReduceLimits,
    ) -> Result<ReduceOutcome, ReduceError> {
        #[cfg(not(feature = "static-dispatch"))]
        if self.owner.runtime_reducer() == RuntimeReducer::UniformWord64 {
            return self.reduce_uniform::<SPAN_SUM>(haystack, limits);
        }
        let upper = self.preflight_reduce::<SPAN_SUM>(haystack.len(), limits)?;
        let candidate_positions = upper.candidate_positions;
        #[cfg(feature = "static-dispatch")]
        let anchor_offset = usize::from(self.owner.anchor_offset);
        #[cfg(not(feature = "static-dispatch"))]
        let anchor_offset = self.build.anchor_offset;
        let mut block_start = 0_usize;
        let mut consumed_through = 0_usize;
        let mut candidate_events = 0_usize;
        let mut pattern_checks = 0_usize;
        let mut match_events = 0_u64;
        let mut span_sum = 0_u64;

        while block_start
            .checked_add(SIMD_BLOCK_BYTES)
            .is_some_and(|end| end <= candidate_positions)
        {
            let block_end = block_start.checked_add(SIMD_BLOCK_BYTES).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "SIMD block end",
                },
            )?;
            let screening_start =
                block_start
                    .checked_add(anchor_offset)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "byte-bucket screening start",
                    })?;
            let screening_end = screening_start.checked_add(SIMD_BLOCK_BYTES).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "byte-bucket screening end",
                },
            )?;
            let screening = self
                .owner
                .screening_classifier
                .classify_16(&haystack[screening_start..screening_end])
                .ok_or(ReduceError::InternalInvariant {
                    detail: "complete candidate block lost its screening extent",
                })?
                .chunks();
            if screening == [0, 0] {
                block_start = block_end;
                continue;
            }
            let classifier_end = block_end
                .checked_add(self.build.mask_columns.saturating_sub(1))
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "byte-bucket classifier end",
                })?;
            let classified = self
                .owner
                .classifier
                .classify_16(&haystack[block_start..classifier_end])
                .ok_or(ReduceError::InternalInvariant {
                    detail: "complete candidate block lost its correlated-byte extent",
                })?
                .chunks();
            let candidates = [screening[0] & classified[0], screening[1] & classified[1]];
            self.consume_bucket_candidate_chunks::<SPAN_SUM>(
                haystack,
                block_start,
                candidates,
                &mut consumed_through,
                &mut candidate_events,
                &mut pattern_checks,
                &mut match_events,
                &mut span_sum,
            )?;
            block_start = block_end;
        }
        while block_start < candidate_positions {
            let anchor_position =
                block_start
                    .checked_add(anchor_offset)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "scalar anchor position",
                    })?;
            let byte = haystack[anchor_position];
            let pattern_bits = self.owner.anchor_byte_patterns[usize::from(byte)];
            if pattern_bits != 0 {
                candidate_events =
                    candidate_events
                        .checked_add(1)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "actual candidate events",
                        })?;
                self.consume_candidate::<SPAN_SUM>(
                    haystack,
                    block_start,
                    pattern_bits,
                    &mut consumed_through,
                    &mut pattern_checks,
                    &mut match_events,
                    &mut span_sum,
                )?;
            }
            block_start = block_start
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "scalar candidate cursor",
                })?;
        }

        let iterator_next_calls =
            candidate_events
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "candidate stream calls",
                })?;
        let count = match_events;
        let candidate_control_work =
            candidate_events
                .checked_mul(2)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "actual candidate control work",
                })?;
        let actual_work_usize = candidate_positions
            .checked_add(upper.source_byte_reads)
            .and_then(|work| work.checked_add(pattern_checks))
            .and_then(|work| work.checked_add(candidate_control_work))
            .and_then(|work| work.checked_add(iterator_next_calls))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "actual packed operation work",
            })?;
        let actual_work =
            u64::try_from(actual_work_usize).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "actual packed operation work as u64",
            })?;
        let actual = ReduceActualCounters {
            match_events,
            iterator_next_calls,
            count: Some(count),
            span_sum: SPAN_SUM.then_some(span_sum),
            classified_positions: candidate_positions,
            candidate_events,
            pattern_checks,
            source_byte_reads: upper.source_byte_reads,
            shift_and_transitions: 0,
            work: actual_work,
            scratch_bytes: 0,
            peak_bytes: self.build.persistent_bytes,
        };
        debug_assert!(match_events <= upper.count);
        debug_assert!(span_sum <= upper.span_sum);
        debug_assert!(candidate_events <= upper.candidate_positions);
        debug_assert!(pattern_checks <= upper.pattern_checks);
        Ok(ReduceOutcome {
            count,
            span_sum,
            upper,
            actual,
        })
    }

    #[cfg(not(feature = "static-dispatch"))]
    fn preflight_uniform_reduce<const SPAN_SUM: bool>(
        &self,
        haystack_len: usize,
        limits: ReduceLimits,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        let width = self.build.min_pattern_bytes;
        let start_mask = self.owner.uniform_start_mask();
        let accept_mask = self.owner.uniform_accept_mask();
        if width == 0 || start_mask == 0 || accept_mask == 0 {
            return Err(ReduceError::InternalInvariant {
                detail: "uniform Shift-And plan lost its retained masks",
            });
        }
        let candidate_positions = if haystack_len < width {
            0
        } else {
            haystack_len
                .checked_sub(width)
                .and_then(|remaining| remaining.checked_add(1))
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "uniform Shift-And candidate positions",
                })?
        };
        let transitions = if candidate_positions == 0 {
            0
        } else {
            haystack_len
        };
        let match_events =
            haystack_len
                .checked_div(width)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "uniform Shift-And event quotient",
                })?;
        let count = u64::try_from(match_events).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "uniform Shift-And count upper bound",
        })?;
        let span_sum = count
            .checked_mul(
                u64::try_from(width).map_err(|_| ReduceError::ArithmeticOverflow {
                    computation: "uniform Shift-And span width",
                })?,
            )
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "uniform Shift-And span upper bound",
            })?;
        let work_usize = transitions
            .checked_mul(UNIFORM_TRANSITION_WORK)
            .and_then(|work| work.checked_add(match_events.checked_mul(UNIFORM_MATCH_WORK)?))
            .and_then(|work| work.checked_add(UNIFORM_FINAL_WORK))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "uniform Shift-And operation work",
            })?;
        let work = u64::try_from(work_usize).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "uniform Shift-And operation work as u64",
        })?;
        let reducer_steps = transitions
            .checked_add(1)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "uniform Shift-And reducer steps",
            })?;
        let upper = ReduceUpperBounds {
            haystack_bytes: haystack_len,
            candidate_positions,
            restart_tail_positions: 0,
            examined_positions: transitions,
            work_per_position: UNIFORM_TRANSITION_WORK,
            iterator_setup_work: 0,
            source_byte_reads: transitions,
            shift_and_transitions: transitions,
            pattern_checks: 0,
            work,
            match_events,
            count,
            span_sum,
            reducer_steps,
            scratch_bytes: 0,
            persistent_bytes: self.build.persistent_bytes,
            peak_bytes: self.build.persistent_bytes,
        };
        check_reduce(upper, SPAN_SUM, limits)?;
        Ok(upper)
    }

    #[cfg(not(feature = "static-dispatch"))]
    fn reduce_uniform<const SPAN_SUM: bool>(
        &self,
        haystack: &[u8],
        limits: ReduceLimits,
    ) -> Result<ReduceOutcome, ReduceError> {
        let upper = self.preflight_uniform_reduce::<SPAN_SUM>(haystack.len(), limits)?;
        let width = self.build.min_pattern_bytes;
        let masks = self
            .owner
            .uniform_masks()
            .ok_or(ReduceError::InternalInvariant {
                detail: "uniform Shift-And plan lost its mask table",
            })?;
        let start_mask = self.owner.uniform_start_mask();
        let accept_mask = self.owner.uniform_accept_mask();
        let mut state = 0_u64;
        let mut match_events = 0_u64;
        if upper.shift_and_transitions != 0 {
            for &byte in haystack {
                // Every accepting transition resets below, so no terminal bit
                // can enter the next iteration and shift across a word lane.
                debug_assert_eq!(state & accept_mask, 0);
                state = (state.wrapping_shl(1) | start_mask) & masks[usize::from(byte)];
                if state & accept_mask != 0 {
                    match_events =
                        match_events
                            .checked_add(1)
                            .ok_or(ReduceError::ArithmeticOverflow {
                                computation: "uniform Shift-And actual match events",
                            })?;
                    state = 0;
                }
            }
        }
        let span_sum = if SPAN_SUM {
            match_events
                .checked_mul(
                    u64::try_from(width).map_err(|_| ReduceError::ArithmeticOverflow {
                        computation: "uniform Shift-And actual span width",
                    })?,
                )
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "uniform Shift-And actual span sum",
                })?
        } else {
            0
        };
        let iterator_next_calls = upper.reducer_steps;
        let actual_work_usize = upper
            .shift_and_transitions
            .checked_mul(UNIFORM_TRANSITION_WORK)
            .and_then(|work| {
                work.checked_add(
                    usize::try_from(match_events)
                        .ok()?
                        .checked_mul(UNIFORM_MATCH_WORK)?,
                )
            })
            .and_then(|work| work.checked_add(UNIFORM_FINAL_WORK))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "uniform Shift-And actual work",
            })?;
        let actual = ReduceActualCounters {
            match_events,
            iterator_next_calls,
            count: Some(match_events),
            span_sum: SPAN_SUM.then_some(span_sum),
            classified_positions: 0,
            candidate_events: 0,
            pattern_checks: 0,
            source_byte_reads: upper.shift_and_transitions,
            shift_and_transitions: upper.shift_and_transitions,
            work: u64::try_from(actual_work_usize).map_err(|_| {
                ReduceError::ArithmeticOverflow {
                    computation: "uniform Shift-And actual work as u64",
                }
            })?,
            scratch_bytes: 0,
            peak_bytes: self.build.persistent_bytes,
        };
        debug_assert!(match_events <= upper.count);
        debug_assert!(span_sum <= upper.span_sum);
        debug_assert!(actual.work <= upper.work);
        Ok(ReduceOutcome {
            count: match_events,
            span_sum,
            upper,
            actual,
        })
    }

    fn preflight_bounded_prefix_reduce(
        &self,
        haystack_len: usize,
        bounds: BoundedPrefixBounds,
        limits: ReduceLimits,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        let mut upper = self.preflight_reduce::<false>(haystack_len, ReduceLimits::unlimited())?;
        let prefix_reads = upper
            .candidate_positions
            .checked_mul(usize::from(bounds.maximum))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "bounded-prefix source reads",
            })?;
        upper.source_byte_reads = upper.source_byte_reads.checked_add(prefix_reads).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "bounded-prefix total source reads",
            },
        )?;
        upper.work_per_position = upper
            .work_per_position
            .checked_add(usize::from(bounds.maximum))
            .and_then(|work| work.checked_add(8))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "bounded-prefix work per position",
            })?;
        let work_usize = upper
            .candidate_positions
            .checked_mul(upper.work_per_position)
            .and_then(|work| work.checked_add(1))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "bounded-prefix operation work",
            })?;
        upper.work = u64::try_from(work_usize).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "bounded-prefix operation work as u64",
        })?;
        check_reduce(upper, false, limits)?;
        Ok(upper)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the monotone SIMD literal-start traversal and greedy-prefix arbitration remain adjacent for audit"
    )]
    fn reduce_bounded_prefix(
        &self,
        haystack: &[u8],
        bounds: BoundedPrefixBounds,
        limits: ReduceLimits,
    ) -> Result<ReduceOutcome, ReduceError> {
        let upper = self.preflight_bounded_prefix_reduce(haystack.len(), bounds, limits)?;
        let candidate_positions = upper.candidate_positions;
        #[cfg(feature = "static-dispatch")]
        let anchor_offset = usize::from(self.owner.anchor_offset);
        #[cfg(not(feature = "static-dispatch"))]
        let anchor_offset = self.build.anchor_offset;
        let mut block_start = 0_usize;
        let mut candidate_events = 0_usize;
        let mut pattern_checks = 0_usize;
        let mut reducer = BoundedPrefixReducer::default();

        while block_start
            .checked_add(SIMD_BLOCK_BYTES)
            .is_some_and(|end| end <= candidate_positions)
        {
            let block_end = block_start.checked_add(SIMD_BLOCK_BYTES).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "bounded-prefix SIMD block end",
                },
            )?;
            let screening_start =
                block_start
                    .checked_add(anchor_offset)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "bounded-prefix byte-bucket screening start",
                    })?;
            let screening_end = screening_start.checked_add(SIMD_BLOCK_BYTES).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "bounded-prefix byte-bucket screening end",
                },
            )?;
            let screening = self
                .owner
                .screening_classifier
                .classify_16(&haystack[screening_start..screening_end])
                .ok_or(ReduceError::InternalInvariant {
                    detail: "complete bounded-prefix block lost its screening extent",
                })?
                .chunks();
            if screening == [0, 0] {
                block_start = block_end;
                continue;
            }
            let classifier_end = block_end
                .checked_add(self.build.mask_columns.saturating_sub(1))
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "bounded-prefix byte-bucket classifier end",
                })?;
            let classified = self
                .owner
                .classifier
                .classify_16(&haystack[block_start..classifier_end])
                .ok_or(ReduceError::InternalInvariant {
                    detail: "complete bounded-prefix block lost its correlated-byte extent",
                })?
                .chunks();
            let candidates = [screening[0] & classified[0], screening[1] & classified[1]];
            self.consume_bounded_prefix_bucket_chunks(
                haystack,
                block_start,
                candidates,
                bounds,
                &mut candidate_events,
                &mut pattern_checks,
                &mut reducer,
            )?;
            block_start = block_end;
        }
        while block_start < candidate_positions {
            let anchor_position =
                block_start
                    .checked_add(anchor_offset)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "bounded-prefix scalar anchor position",
                    })?;
            let byte = haystack[anchor_position];
            let pattern_bits = self.owner.anchor_byte_patterns[usize::from(byte)];
            if pattern_bits != 0 {
                candidate_events =
                    candidate_events
                        .checked_add(1)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "bounded-prefix actual candidate events",
                        })?;
                self.consume_bounded_prefix_candidate(
                    haystack,
                    block_start,
                    pattern_bits,
                    bounds,
                    &mut pattern_checks,
                    &mut reducer,
                )?;
            }
            block_start = block_start
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "bounded-prefix scalar candidate cursor",
                })?;
        }
        reducer.finish()?;

        let iterator_next_calls =
            candidate_events
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "bounded-prefix candidate stream calls",
                })?;
        let candidate_control_work =
            candidate_events
                .checked_mul(8)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "bounded-prefix actual candidate control work",
                })?;
        let actual_work_usize = candidate_positions
            .checked_add(upper.source_byte_reads)
            .and_then(|work| work.checked_add(pattern_checks))
            .and_then(|work| work.checked_add(candidate_control_work))
            .and_then(|work| work.checked_add(iterator_next_calls))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "actual bounded-prefix operation work",
            })?;
        let actual_work =
            u64::try_from(actual_work_usize).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "actual bounded-prefix operation work as u64",
            })?;
        let actual = ReduceActualCounters {
            match_events: reducer.count,
            iterator_next_calls,
            count: Some(reducer.count),
            span_sum: None,
            classified_positions: candidate_positions,
            candidate_events,
            pattern_checks,
            source_byte_reads: upper.source_byte_reads,
            shift_and_transitions: 0,
            work: actual_work,
            scratch_bytes: 0,
            peak_bytes: self.build.persistent_bytes,
        };
        debug_assert!(reducer.count <= upper.count);
        debug_assert!(candidate_events <= upper.candidate_positions);
        debug_assert!(pattern_checks <= upper.pattern_checks);
        debug_assert!(actual.work <= upper.work);
        Ok(ReduceOutcome {
            count: reducer.count,
            span_sum: 0,
            upper,
            actual,
        })
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the hot monotone reducer keeps its scalar counters borrowed and allocation-free"
    )]
    fn consume_bounded_prefix_bucket_chunks(
        &self,
        haystack: &[u8],
        block_start: usize,
        chunks: [u64; 2],
        bounds: BoundedPrefixBounds,
        candidate_events: &mut usize,
        pattern_checks: &mut usize,
        reducer: &mut BoundedPrefixReducer,
    ) -> Result<(), ReduceError> {
        for (chunk_index, mut chunk) in chunks.into_iter().enumerate() {
            while chunk != 0 {
                let byte_lane = usize::try_from(chunk.trailing_zeros() / u8::BITS)
                    .expect("a u64 byte lane fits in usize");
                let shift = u32::try_from(
                    byte_lane
                        .checked_mul(8)
                        .expect("a packed byte-lane shift fits in usize"),
                )
                .expect("a packed byte-lane shift fits in u32");
                let buckets = u8::try_from((chunk >> shift) & u64::from(u8::MAX))
                    .expect("the masked candidate bucket set fits in u8");
                chunk &= !(u64::from(u8::MAX) << shift);
                let lane = chunk_index
                    .checked_mul(8)
                    .and_then(|base| base.checked_add(byte_lane))
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "bounded-prefix candidate lane",
                    })?;
                let start =
                    block_start
                        .checked_add(lane)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "bounded-prefix candidate start",
                        })?;
                *candidate_events =
                    candidate_events
                        .checked_add(1)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "bounded-prefix actual candidate events",
                        })?;
                self.consume_bounded_prefix_candidate(
                    haystack,
                    start,
                    self.patterns_for_buckets(buckets),
                    bounds,
                    pattern_checks,
                    reducer,
                )?;
            }
        }
        Ok(())
    }

    fn consume_bounded_prefix_candidate(
        &self,
        haystack: &[u8],
        literal_start: usize,
        pattern_bits: u16,
        bounds: BoundedPrefixBounds,
        pattern_checks: &mut usize,
        reducer: &mut BoundedPrefixReducer,
    ) -> Result<(), ReduceError> {
        let Some(end) =
            self.verified_candidate_end(haystack, literal_start, pattern_bits, pattern_checks)?
        else {
            return Ok(());
        };
        reducer.observe(haystack, literal_start, end, bounds)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the hot monotone reducer keeps its scalar counters borrowed and allocation-free"
    )]
    fn consume_bucket_candidate_chunks<const SPAN_SUM: bool>(
        &self,
        haystack: &[u8],
        block_start: usize,
        chunks: [u64; 2],
        consumed_through: &mut usize,
        candidate_events: &mut usize,
        pattern_checks: &mut usize,
        match_events: &mut u64,
        span_sum: &mut u64,
    ) -> Result<(), ReduceError> {
        for (chunk_index, mut chunk) in chunks.into_iter().enumerate() {
            while chunk != 0 {
                let byte_lane = usize::try_from(chunk.trailing_zeros() / u8::BITS)
                    .expect("a u64 byte lane fits in usize");
                let shift = u32::try_from(
                    byte_lane
                        .checked_mul(8)
                        .expect("a packed byte-lane shift fits in usize"),
                )
                .expect("a packed byte-lane shift fits in u32");
                let buckets = u8::try_from((chunk >> shift) & u64::from(u8::MAX))
                    .expect("the masked candidate bucket set fits in u8");
                chunk &= !(u64::from(u8::MAX) << shift);
                let lane = chunk_index
                    .checked_mul(8)
                    .and_then(|base| base.checked_add(byte_lane))
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "candidate lane",
                    })?;
                let start =
                    block_start
                        .checked_add(lane)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "candidate start",
                        })?;
                *candidate_events =
                    candidate_events
                        .checked_add(1)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "actual candidate events",
                        })?;
                self.consume_candidate::<SPAN_SUM>(
                    haystack,
                    start,
                    self.patterns_for_buckets(buckets),
                    consumed_through,
                    pattern_checks,
                    match_events,
                    span_sum,
                )?;
            }
        }
        Ok(())
    }

    fn patterns_for_buckets(&self, mut buckets: u8) -> u16 {
        let mut patterns = 0_u16;
        while buckets != 0 {
            let bucket = buckets.trailing_zeros();
            buckets &= buckets.wrapping_sub(1);
            patterns |= self.owner.bucket_patterns
                [usize::try_from(bucket).expect("a u8 bucket index fits in usize")];
        }
        patterns
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the hot exact verifier keeps its scalar counters borrowed and allocation-free"
    )]
    fn consume_candidate<const SPAN_SUM: bool>(
        &self,
        haystack: &[u8],
        start: usize,
        pattern_bits: u16,
        consumed_through: &mut usize,
        pattern_checks: &mut usize,
        match_events: &mut u64,
        span_sum: &mut u64,
    ) -> Result<(), ReduceError> {
        if start < *consumed_through {
            return Ok(());
        }
        let Some(end) =
            self.verified_candidate_end(haystack, start, pattern_bits, pattern_checks)?
        else {
            return Ok(());
        };
        *match_events = match_events
            .checked_add(1)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "actual match events",
            })?;
        if SPAN_SUM {
            *span_sum = span_sum
                .checked_add(
                    u64::try_from(end.checked_sub(start).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "matched width",
                        },
                    )?)
                    .map_err(|_| ReduceError::ArithmeticOverflow {
                        computation: "matched width as u64",
                    })?,
                )
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "actual span sum",
                })?;
        }
        *consumed_through = end;
        Ok(())
    }

    fn verified_candidate_end(
        &self,
        haystack: &[u8],
        start: usize,
        mut pattern_bits: u16,
        pattern_checks: &mut usize,
    ) -> Result<Option<usize>, ReduceError> {
        while pattern_bits != 0 {
            let id = pattern_bits.trailing_zeros();
            pattern_bits &= pattern_bits.wrapping_sub(1);
            *pattern_checks =
                pattern_checks
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "actual pattern checks",
                    })?;
            let id = usize::try_from(id).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "pattern ID",
            })?;
            let pattern = self.owner.pattern(id);
            let end = start
                .checked_add(pattern.len())
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "matched end",
                })?;
            if end <= haystack.len() && haystack[start..end] == *pattern {
                return Ok(Some(end));
            }
        }
        Ok(None)
    }
}

#[derive(Clone, Copy, Debug)]
struct PendingBoundedPrefixMatch {
    start: usize,
    literal_start: usize,
    end: usize,
}

#[derive(Debug, Default)]
struct BoundedPrefixReducer {
    cursor: usize,
    pending: Option<PendingBoundedPrefixMatch>,
    count: u64,
}

impl BoundedPrefixReducer {
    fn observe(
        &mut self,
        haystack: &[u8],
        literal_start: usize,
        end: usize,
        bounds: BoundedPrefixBounds,
    ) -> Result<(), ReduceError> {
        loop {
            let Some(start) =
                bounded_prefix_match_start(haystack, self.cursor, literal_start, bounds)
            else {
                return Ok(());
            };
            let Some(pending) = self.pending else {
                self.pending = Some(PendingBoundedPrefixMatch {
                    start,
                    literal_start,
                    end,
                });
                return Ok(());
            };
            if start < pending.start {
                return Err(ReduceError::InternalInvariant {
                    detail: "bounded-prefix literal stream lost monotone match starts",
                });
            }
            if start == pending.start {
                if literal_start > pending.literal_start {
                    self.pending = Some(PendingBoundedPrefixMatch {
                        start,
                        literal_start,
                        end,
                    });
                }
                return Ok(());
            }
            self.commit_pending()?;
        }
    }

    fn finish(&mut self) -> Result<(), ReduceError> {
        if self.pending.is_some() {
            self.commit_pending()?;
        }
        Ok(())
    }

    fn commit_pending(&mut self) -> Result<(), ReduceError> {
        let pending = self.pending.take().ok_or(ReduceError::InternalInvariant {
            detail: "bounded-prefix reducer committed an empty group",
        })?;
        self.count = self
            .count
            .checked_add(1)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "bounded-prefix actual match events",
            })?;
        self.cursor = pending.end;
        Ok(())
    }
}

fn bounded_prefix_match_start(
    haystack: &[u8],
    cursor: usize,
    literal_start: usize,
    bounds: BoundedPrefixBounds,
) -> Option<usize> {
    if literal_start < cursor {
        return None;
    }
    let floor = literal_start.saturating_sub(usize::from(bounds.maximum));
    let mut run_start = floor;
    for (offset, &byte) in haystack[floor..literal_start].iter().enumerate() {
        if byte == b'\n' {
            run_start = floor
                .checked_add(offset)
                .and_then(|position| position.checked_add(1))
                .expect("the observed prefix offset remains within the haystack");
        }
    }
    let start = cursor.max(run_start);
    literal_start
        .checked_sub(start)
        .filter(|&width| width >= usize::from(bounds.minimum))
        .map(|_| start)
}

/// Choose the lowest-cost common byte offset using a frozen general-purpose
/// byte-frequency rank and the complete pattern fan-out behind each distinct
/// anchor. Every prior-ID and bucket comparison is performed, including after
/// a duplicate is known, so construction work is exact and source-independent.
fn select_anchor_offset<P: AsRef<[u8]>>(patterns: &[P], min_pattern_bytes: usize) -> usize {
    debug_assert!(!patterns.is_empty());
    debug_assert!(min_pattern_bytes != 0);
    let mut selected_offset = 0_usize;
    let mut selected_score = u64::MAX;
    for offset in 0..min_pattern_bytes {
        let mut score = 0_u64;
        for (index, pattern) in patterns.iter().enumerate() {
            let anchor = pattern.as_ref()[offset];
            let mut seen = false;
            for prior in &patterns[..index] {
                seen |= prior.as_ref()[offset] == anchor;
            }
            let mut bucket_patterns = 0_u64;
            let mut bucket_pattern_bytes = 0_u64;
            for candidate in patterns {
                if candidate.as_ref()[offset] == anchor {
                    bucket_patterns = bucket_patterns
                        .checked_add(1)
                        .expect("a certified pattern count fits in u64");
                    bucket_pattern_bytes = bucket_pattern_bytes
                        .checked_add(
                            u64::try_from(candidate.as_ref().len())
                                .expect("a certified pattern width fits in u64"),
                        )
                        .expect("certified total pattern bytes fit in u64");
                }
            }
            if !seen {
                let frequency_weight = u64::from(BYTE_FREQUENCY_RANK[usize::from(anchor)])
                    .checked_add(1)
                    .expect("a byte-frequency rank plus one fits in u64");
                let bucket_cost = bucket_patterns
                    .checked_add(bucket_pattern_bytes)
                    .expect("certified bucket cost fits in u64");
                let weighted_cost = frequency_weight
                    .checked_mul(bucket_cost)
                    .expect("certified weighted bucket cost fits in u64");
                score = score
                    .checked_add(weighted_cost)
                    .expect("certified anchor score fits in u64");
            }
        }
        if score < selected_score {
            selected_offset = offset;
            selected_score = score;
        }
    }
    selected_offset
}

fn build_byte_bucket_tables<P: AsRef<[u8]>>(
    patterns: &[P],
    mask_columns: usize,
    anchor_offset: usize,
) -> Result<(ByteBucketTables, ByteBucketTables, [u16; BYTE_BUCKET_COUNT]), BuildError> {
    debug_assert!((1..=BYTE_BUCKET_MAX_COLUMNS).contains(&mask_columns));
    debug_assert!(patterns.len() <= CERTIFIED_MAX_PATTERNS);
    let mut low = [[0_u8; 16]; BYTE_BUCKET_MAX_COLUMNS];
    let mut high = [[0_u8; 16]; BYTE_BUCKET_MAX_COLUMNS];
    let mut screening_low = [[0_u8; 16]; BYTE_BUCKET_MAX_COLUMNS];
    let mut screening_high = [[0_u8; 16]; BYTE_BUCKET_MAX_COLUMNS];
    let mut bucket_patterns = [0_u16; BYTE_BUCKET_COUNT];
    let mut assigned = [0_u8; CERTIFIED_MAX_PATTERNS];
    let mut distinct_prefixes = 0_usize;

    for (id, pattern) in patterns.iter().enumerate() {
        let bytes = pattern.as_ref();
        let mut inherited = None;
        for prior in 0..id {
            let mut equal = true;
            for (column, &byte) in bytes.iter().take(mask_columns).enumerate() {
                equal &= byte == patterns[prior].as_ref()[column];
            }
            if equal && inherited.is_none() {
                inherited = Some(assigned[prior]);
            }
        }
        let bucket = inherited.unwrap_or_else(|| {
            let bucket = BYTE_BUCKET_COUNT
                .checked_sub(1)
                .and_then(|last| last.checked_sub(distinct_prefixes % BYTE_BUCKET_COUNT))
                .expect("a fixed recycled bucket index fits in usize");
            distinct_prefixes = distinct_prefixes
                .checked_add(1)
                .expect("the certified pattern count fits in usize");
            u8::try_from(bucket).expect("the fixed bucket count fits in u8")
        });
        assigned[id] = bucket;
        let pattern_bit = 1_u16
            .checked_shl(
                u32::try_from(id).map_err(|_| BuildError::ArithmeticOverflow {
                    computation: "bucket pattern bit",
                })?,
            )
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "bucket pattern bit",
            })?;
        let bucket_index = usize::from(bucket);
        bucket_patterns[bucket_index] |= pattern_bit;
        let bucket_bit =
            1_u8.checked_shl(u32::from(bucket))
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "byte-bucket mask bit",
                })?;
        for column in 0..mask_columns {
            let byte = bytes[column];
            low[column][usize::from(byte & 0x0f)] |= bucket_bit;
            high[column][usize::from(byte >> 4)] |= bucket_bit;
        }
        let anchor = bytes[anchor_offset];
        screening_low[0][usize::from(anchor & 0x0f)] |= bucket_bit;
        screening_high[0][usize::from(anchor >> 4)] |= bucket_bit;
    }
    let tables = ByteBucketTables::new(mask_columns, low, high)
        .map_err(|_| BuildError::UnsupportedTargetOrShape)?;
    let screening_tables = ByteBucketTables::new(1, screening_low, screening_high)
        .map_err(|_| BuildError::UnsupportedTargetOrShape)?;
    Ok((screening_tables, tables, bucket_patterns))
}

#[cfg(not(feature = "static-dispatch"))]
struct UniformWord64Tables {
    masks: Option<ExactBoxOrUsize<[u64; 256]>>,
    start_mask: u64,
    accept_mask: u64,
}

#[cfg(not(feature = "static-dispatch"))]
impl UniformWord64Tables {
    fn empty() -> Self {
        Self {
            masks: None,
            start_mask: 0,
            accept_mask: 0,
        }
    }
}

#[cfg(not(feature = "static-dispatch"))]
fn populate_uniform_word64<P: AsRef<[u8]>>(
    patterns: &[P],
    masks: ExactBoxOrUsize<[u64; 256]>,
) -> UniformWord64Tables {
    let width = patterns
        .first()
        .map(|pattern| pattern.as_ref().len())
        .expect("the admitted uniform pattern set is nonempty");
    let state_extent = width
        .checked_mul(patterns.len())
        .expect("the preflighted uniform state extent fits usize");
    assert!(state_extent != 0 && state_extent <= UNIFORM_WORD_BITS);
    // `RuntimeReducer::UniformWord64` is private proof-carrying state: the
    // source-free preflight has already established one nonzero width and an
    // exact total state extent. Population after the recorded allocation has
    // no remaining fallible operation.
    let mut tables = UniformWord64Tables {
        masks: Some(masks),
        start_mask: 0,
        accept_mask: 0,
    };
    let mut state_offset = 0_usize;
    for pattern in patterns {
        let bytes = pattern.as_ref();
        let start_shift =
            u32::try_from(state_offset).expect("the preflighted Word64 start offset fits u32");
        tables.start_mask |= 1_u64
            .checked_shl(start_shift)
            .expect("the preflighted Word64 start offset fits u64");
        for (position, &byte) in bytes.iter().enumerate() {
            let state_position = state_offset
                .checked_add(position)
                .expect("the preflighted Word64 state position fits usize");
            let shift = u32::try_from(state_position)
                .expect("the preflighted Word64 state position fits u32");
            let bit = 1_u64
                .checked_shl(shift)
                .expect("the preflighted Word64 state position fits u64");
            tables
                .masks
                .as_mut()
                .and_then(ExactBoxOrUsize::boxed_mut)
                .expect("the uniform reducer owns its admitted mask table")[usize::from(byte)] |=
                bit;
        }
        let accept_position = state_offset
            .checked_add(width)
            .and_then(|end| end.checked_sub(1))
            .expect("the preflighted Word64 accept position fits usize");
        let accept_shift = u32::try_from(accept_position)
            .expect("the preflighted Word64 accept position fits u32");
        tables.accept_mask |= 1_u64
            .checked_shl(accept_shift)
            .expect("the preflighted Word64 accept position fits u64");
        state_offset = state_offset
            .checked_add(width)
            .expect("the preflighted Word64 state extent fits usize");
    }
    assert_eq!(state_offset, state_extent);
    assert!(tables.start_mask != 0 && tables.accept_mask != 0);
    tables
}

#[cfg(not(feature = "static-dispatch"))]
fn allocate_uniform_masks() -> Result<ExactBoxOrUsize<[u64; 256]>, CopyError> {
    let masks = [0_u64; 256];
    #[cfg(test)]
    if build_allocation_probe::take_uniform_mask_failure() {
        return Err(CopyError::AllocationFailed);
    }
    ExactBoxOrUsize::try_from_boxed(masks)
}

#[derive(Clone, Copy)]
struct BuildPreflight {
    pattern_bytes: usize,
    max_pattern_bytes: usize,
    min_pattern_bytes: usize,
    runtime_reducer: RuntimeReducer,
    #[cfg(not(feature = "static-dispatch"))]
    uniform_mask_build_work: u64,
    uniform_mask_bytes: usize,
    anchor_offset: usize,
    selected_anchor_minimum_frequency_rank: u8,
    uniform_distinct_pattern_bytes: u8,
    uniform_route_selection_work: u64,
    anchor_selection_work: u64,
    mask_columns: usize,
    bucket_assignment_work: u64,
    identity_bytes: usize,
    build_work: u64,
    persistent_bytes: usize,
    peak_bytes: usize,
}

struct PreflightFailure {
    source: BuildError,
    actual: BuildAttemptActual,
}

#[allow(
    clippy::too_many_lines,
    reason = "proof caps, caller limits and exact prospective construction accounting are deliberately ordered in one source-free preflight"
)]
fn preflight<P: AsRef<[u8]>>(
    patterns: &[P],
    limits: BuildLimits,
    inline_bytes: usize,
    initial_work: usize,
    allow_uniform_word64: bool,
) -> Result<(BuildPreflight, BuildAttemptActual), PreflightFailure> {
    let mut actual = BuildAttemptActual {
        work: u64::try_from(initial_work).map_err(|_| PreflightFailure {
            source: BuildError::ArithmeticOverflow {
                computation: "initial build proof work as u64",
            },
            actual: BuildAttemptActual::default(),
        })?,
        ..BuildAttemptActual::default()
    };
    if initial_work > limits.max_build_work {
        return Err(PreflightFailure {
            source: BuildError::WorkLimit {
                needed: initial_work,
                limit: limits.max_build_work,
            },
            actual: BuildAttemptActual::default(),
        });
    }
    let first_work = initial_work.checked_add(1).ok_or(PreflightFailure {
        source: BuildError::ArithmeticOverflow {
            computation: "initial set proof work",
        },
        actual,
    })?;
    if first_work > limits.max_build_work {
        return Err(PreflightFailure {
            source: BuildError::WorkLimit {
                needed: first_work,
                limit: limits.max_build_work,
            },
            actual,
        });
    }
    actual.work = u64::try_from(first_work).map_err(|_| PreflightFailure {
        source: BuildError::ArithmeticOverflow {
            computation: "initial set proof work as u64",
        },
        actual,
    })?;
    if patterns.is_empty() {
        return Err(PreflightFailure {
            source: BuildError::EmptyPatternSet,
            actual,
        });
    }
    if patterns.len() < CERTIFIED_MIN_PATTERNS {
        return Err(PreflightFailure {
            source: BuildError::ProofRefused {
                fact: "pattern count minimum",
                needed: patterns.len(),
                certified_limit: CERTIFIED_MIN_PATTERNS,
            },
            actual,
        });
    }
    if patterns.len() > CERTIFIED_MAX_PATTERNS {
        return Err(PreflightFailure {
            source: BuildError::ProofRefused {
                fact: "pattern count",
                needed: patterns.len(),
                certified_limit: CERTIFIED_MAX_PATTERNS,
            },
            actual,
        });
    }
    if patterns.len() > limits.max_patterns {
        return Err(PreflightFailure {
            source: BuildError::PatternLimit {
                needed: patterns.len(),
                limit: limits.max_patterns,
            },
            actual,
        });
    }
    let census_work = patterns
        .len()
        .checked_add(1)
        .and_then(|work| work.checked_add(initial_work))
        .ok_or(PreflightFailure {
            source: BuildError::ArithmeticOverflow {
                computation: "set proof and pattern length census work",
            },
            actual,
        })?;
    if census_work > limits.max_build_work {
        return Err(PreflightFailure {
            source: BuildError::WorkLimit {
                needed: census_work,
                limit: limits.max_build_work,
            },
            actual,
        });
    }

    let mut pattern_bytes = 0_usize;
    let mut max_pattern_bytes = 0_usize;
    let mut min_pattern_bytes = usize::MAX;
    for (index, pattern) in patterns.iter().enumerate() {
        actual.work = actual.work.checked_add(1).ok_or(PreflightFailure {
            source: BuildError::ArithmeticOverflow {
                computation: "pattern length census work",
            },
            actual,
        })?;
        let bytes = pattern.as_ref();
        if bytes.is_empty() {
            return Err(PreflightFailure {
                source: BuildError::EmptyPattern { index },
                actual,
            });
        }
        if bytes.len() < CERTIFIED_MIN_PATTERN_BYTES {
            return Err(PreflightFailure {
                source: BuildError::ProofRefused {
                    fact: "literal width minimum",
                    needed: bytes.len(),
                    certified_limit: CERTIFIED_MIN_PATTERN_BYTES,
                },
                actual,
            });
        }
        if bytes.len() > CERTIFIED_MAX_PATTERN_BYTES {
            return Err(PreflightFailure {
                source: BuildError::ProofRefused {
                    fact: "literal width",
                    needed: bytes.len(),
                    certified_limit: CERTIFIED_MAX_PATTERN_BYTES,
                },
                actual,
            });
        }
        if bytes.len() > limits.max_pattern_bytes {
            return Err(PreflightFailure {
                source: BuildError::PatternBytesLimit {
                    needed: bytes.len(),
                    limit: limits.max_pattern_bytes,
                },
                actual,
            });
        }
        pattern_bytes = pattern_bytes
            .checked_add(bytes.len())
            .ok_or(PreflightFailure {
                source: BuildError::ArithmeticOverflow {
                    computation: "total pattern bytes",
                },
                actual,
            })?;
        max_pattern_bytes = max_pattern_bytes.max(bytes.len());
        min_pattern_bytes = min_pattern_bytes.min(bytes.len());
    }
    if pattern_bytes > CERTIFIED_MAX_TOTAL_PATTERN_BYTES {
        return Err(PreflightFailure {
            source: BuildError::ProofRefused {
                fact: "total literal bytes",
                needed: pattern_bytes,
                certified_limit: CERTIFIED_MAX_TOTAL_PATTERN_BYTES,
            },
            actual,
        });
    }
    if pattern_bytes > limits.max_total_pattern_bytes {
        return Err(PreflightFailure {
            source: BuildError::TotalPatternBytesLimit {
                needed: pattern_bytes,
                limit: limits.max_total_pattern_bytes,
            },
            actual,
        });
    }
    let identity_bytes =
        LENGTH_PREFIX_BYTES
            .checked_add(patterns.len().checked_mul(LENGTH_PREFIX_BYTES).ok_or(
                PreflightFailure {
                    source: BuildError::ArithmeticOverflow {
                        computation: "identity prefixes",
                    },
                    actual,
                },
            )?)
            .and_then(|bytes| bytes.checked_add(pattern_bytes))
            .ok_or(PreflightFailure {
                source: BuildError::ArithmeticOverflow {
                    computation: "identity bytes",
                },
                actual,
            })?;
    if identity_bytes > limits.max_identity_bytes {
        return Err(PreflightFailure {
            source: BuildError::IdentityLimit {
                needed: identity_bytes,
                limit: limits.max_identity_bytes,
            },
            actual,
        });
    }
    let prior_anchor_comparisons = patterns
        .len()
        .checked_mul(patterns.len().saturating_sub(1))
        .map(|work| work / 2)
        .ok_or(PreflightFailure {
            source: BuildError::ArithmeticOverflow {
                computation: "fixed-anchor prior-ID comparisons",
            },
            actual,
        })?;
    let bucket_anchor_comparisons =
        patterns
            .len()
            .checked_mul(patterns.len())
            .ok_or(PreflightFailure {
                source: BuildError::ArithmeticOverflow {
                    computation: "fixed-anchor bucket comparisons",
                },
                actual,
            })?;
    let anchor_selection_work = prior_anchor_comparisons
        .checked_add(bucket_anchor_comparisons)
        .and_then(|work| work.checked_mul(min_pattern_bytes))
        .ok_or(PreflightFailure {
            source: BuildError::ArithmeticOverflow {
                computation: "fixed-anchor selection work",
            },
            actual,
        })?;
    let mask_columns = min_pattern_bytes.min(BYTE_BUCKET_MAX_COLUMNS);
    let bucket_prefix_comparisons =
        prior_anchor_comparisons
            .checked_mul(mask_columns)
            .ok_or(PreflightFailure {
                source: BuildError::ArithmeticOverflow {
                    computation: "byte-bucket prefix comparisons",
                },
                actual,
            })?;
    let bucket_table_writes = patterns
        .len()
        .checked_mul(mask_columns)
        .and_then(|work| work.checked_mul(2))
        .and_then(|work| work.checked_add(patterns.len().checked_mul(2)?))
        .ok_or(PreflightFailure {
            source: BuildError::ArithmeticOverflow {
                computation: "byte-bucket table writes",
            },
            actual,
        })?;
    let bucket_assignment_work = bucket_prefix_comparisons
        .checked_add(bucket_table_writes)
        .and_then(|work| work.checked_add(patterns.len()))
        .ok_or(PreflightFailure {
            source: BuildError::ArithmeticOverflow {
                computation: "byte-bucket assignment work",
            },
            actual,
        })?;
    let byte_bucket_build_work = census_work
        .checked_add(anchor_selection_work)
        .and_then(|work| work.checked_add(bucket_assignment_work))
        .and_then(|work| work.checked_add(size_of::<PackedOwner>()))
        .and_then(|work| work.checked_add(identity_bytes))
        .and_then(|work| work.checked_add(CLASSIFIER_BUILD_WORK))
        .ok_or(PreflightFailure {
            source: BuildError::ArithmeticOverflow {
                computation: "byte-bucket build work",
            },
            actual,
        })?;
    if byte_bucket_build_work > limits.max_build_work {
        return Err(PreflightFailure {
            source: BuildError::WorkLimit {
                needed: byte_bucket_build_work,
                limit: limits.max_build_work,
            },
            actual,
        });
    }
    let byte_bucket_persistent_bytes =
        inline_bytes
            .checked_add(size_of::<PackedOwner>())
            .ok_or(PreflightFailure {
                source: BuildError::ArithmeticOverflow {
                    computation: "byte-bucket persistent bytes",
                },
                actual,
            })?;
    if byte_bucket_persistent_bytes > limits.max_persistent_bytes {
        return Err(PreflightFailure {
            source: BuildError::PersistentLimit {
                needed: byte_bucket_persistent_bytes,
                limit: limits.max_persistent_bytes,
            },
            actual,
        });
    }
    if byte_bucket_persistent_bytes > limits.max_build_peak_bytes {
        return Err(PreflightFailure {
            source: BuildError::BuildPeakLimit {
                needed: byte_bucket_persistent_bytes,
                limit: limits.max_build_peak_bytes,
            },
            actual,
        });
    }
    let anchor_selection_completed_work =
        census_work
            .checked_add(anchor_selection_work)
            .ok_or(PreflightFailure {
                source: BuildError::ArithmeticOverflow {
                    computation: "completed fixed-anchor selection work",
                },
                actual,
            })?;
    if anchor_selection_completed_work > limits.max_build_work {
        return Err(PreflightFailure {
            source: BuildError::WorkLimit {
                needed: anchor_selection_completed_work,
                limit: limits.max_build_work,
            },
            actual,
        });
    }
    actual.work = u64::try_from(anchor_selection_completed_work).map_err(|_| PreflightFailure {
        source: BuildError::ArithmeticOverflow {
            computation: "completed fixed-anchor selection work as u64",
        },
        actual,
    })?;
    let anchor_offset = select_anchor_offset(patterns, min_pattern_bytes);
    let uniform_shape_candidate = allow_uniform_word64
        && min_pattern_bytes == max_pattern_bytes
        && min_pattern_bytes >= UNIFORM_WORD64_MIN_PATTERN_BYTES
        && pattern_bytes <= UNIFORM_WORD_BITS;
    let uniform_route_selection_work_candidate = patterns
        .len()
        .checked_add(UNIFORM_ALPHABET_ZERO_WORK)
        .and_then(|work| work.checked_add(pattern_bytes))
        .ok_or(PreflightFailure {
            source: BuildError::ArithmeticOverflow {
                computation: "uniform-route selection work",
            },
            actual,
        })?;
    let prospective_uniform_route_work = byte_bucket_build_work
        .checked_add(uniform_route_selection_work_candidate)
        .ok_or(PreflightFailure {
            source: BuildError::ArithmeticOverflow {
                computation: "uniform-route prospective build work",
            },
            actual,
        })?;
    let inspect_uniform_route =
        uniform_shape_candidate && prospective_uniform_route_work <= limits.max_build_work;
    let uniform_route_selection_work_usize = if inspect_uniform_route {
        uniform_route_selection_work_candidate
    } else {
        0
    };
    let uniform_route_completed_work = anchor_selection_completed_work
        .checked_add(uniform_route_selection_work_usize)
        .ok_or(PreflightFailure {
            source: BuildError::ArithmeticOverflow {
                computation: "completed uniform-route selection work",
            },
            actual,
        })?;
    actual.work = u64::try_from(uniform_route_completed_work).map_err(|_| PreflightFailure {
        source: BuildError::ArithmeticOverflow {
            computation: "completed uniform-route selection work as u64",
        },
        actual,
    })?;
    let selected_anchor_minimum_frequency_rank = if inspect_uniform_route {
        patterns
            .iter()
            .map(|pattern| byte_frequency_rank(pattern.as_ref()[anchor_offset]))
            .min()
            .expect("the admitted nonempty pattern set has a selected anchor")
    } else {
        0
    };
    let uniform_distinct_pattern_bytes = if inspect_uniform_route {
        let mut present = [false; 256];
        let mut distinct = 0_usize;
        for pattern in patterns {
            for &byte in pattern.as_ref() {
                let slot = &mut present[usize::from(byte)];
                if !*slot {
                    *slot = true;
                    distinct = distinct.checked_add(1).ok_or(PreflightFailure {
                        source: BuildError::ArithmeticOverflow {
                            computation: "uniform-route distinct pattern bytes",
                        },
                        actual,
                    })?;
                }
            }
        }
        u8::try_from(distinct).map_err(|_| PreflightFailure {
            source: BuildError::ArithmeticOverflow {
                computation: "uniform-route distinct pattern bytes",
            },
            actual,
        })?
    } else {
        0
    };
    let uniform_rank_admitted = inspect_uniform_route
        && selected_anchor_minimum_frequency_rank >= UNIFORM_WORD64_MIN_ANCHOR_FREQUENCY_RANK;
    let uniform_distinct_pattern_bytes_usize = usize::from(uniform_distinct_pattern_bytes);
    let uniform_alphabet_admitted = inspect_uniform_route
        && uniform_distinct_pattern_bytes_usize != 0
        && uniform_distinct_pattern_bytes_usize <= UNIFORM_WORD64_MAX_DISTINCT_PATTERN_BYTES
        && uniform_distinct_pattern_bytes_usize
            .checked_mul(UNIFORM_WORD64_MIN_ALPHABET_REUSE)
            .is_some_and(|needed| pattern_bytes >= needed);
    let uniform_static_admitted = uniform_rank_admitted && uniform_alphabet_admitted;
    let prospective_uniform_mask_build_work = if uniform_static_admitted {
        UNIFORM_MASK_ZERO_WORK
            .checked_add(pattern_bytes)
            .and_then(|work| work.checked_add(patterns.len().checked_mul(2)?))
            .ok_or(PreflightFailure {
                source: BuildError::ArithmeticOverflow {
                    computation: "uniform Shift-And mask construction work",
                },
                actual,
            })?
    } else {
        0
    };
    let prospective_uniform_build_work = prospective_uniform_route_work
        .checked_add(prospective_uniform_mask_build_work)
        .and_then(|work| work.checked_add(UNIFORM_MASK_BYTES))
        .ok_or(PreflightFailure {
            source: BuildError::ArithmeticOverflow {
                computation: "uniform Shift-And prospective build work",
            },
            actual,
        })?;
    let prospective_uniform_persistent_bytes = byte_bucket_persistent_bytes
        .checked_add(UNIFORM_MASK_BYTES)
        .ok_or(PreflightFailure {
            source: BuildError::ArithmeticOverflow {
                computation: "uniform Shift-And prospective persistent bytes",
            },
            actual,
        })?;
    let uniform_resource_admitted = uniform_static_admitted
        && prospective_uniform_build_work <= limits.max_build_work
        && prospective_uniform_persistent_bytes <= limits.max_persistent_bytes
        && prospective_uniform_persistent_bytes <= limits.max_build_peak_bytes;
    let runtime_reducer = if uniform_resource_admitted {
        RuntimeReducer::UniformWord64
    } else {
        RuntimeReducer::ByteBucket
    };
    #[cfg(not(feature = "static-dispatch"))]
    let uniform_mask_build_work_usize = if uniform_resource_admitted {
        prospective_uniform_mask_build_work
    } else {
        0
    };
    let uniform_mask_bytes = if uniform_resource_admitted {
        UNIFORM_MASK_BYTES
    } else {
        0
    };
    let build_work_usize = if uniform_resource_admitted {
        prospective_uniform_build_work
    } else if inspect_uniform_route {
        prospective_uniform_route_work
    } else {
        byte_bucket_build_work
    };
    let persistent_bytes = if uniform_resource_admitted {
        prospective_uniform_persistent_bytes
    } else {
        byte_bucket_persistent_bytes
    };
    let peak_bytes = persistent_bytes;
    let build_work = u64::try_from(build_work_usize).map_err(|_| PreflightFailure {
        source: BuildError::ArithmeticOverflow {
            computation: "build work as u64",
        },
        actual,
    })?;
    let anchor_selection_work =
        u64::try_from(anchor_selection_work).map_err(|_| PreflightFailure {
            source: BuildError::ArithmeticOverflow {
                computation: "fixed-anchor selection work as u64",
            },
            actual,
        })?;
    let bucket_assignment_work =
        u64::try_from(bucket_assignment_work).map_err(|_| PreflightFailure {
            source: BuildError::ArithmeticOverflow {
                computation: "byte-bucket assignment work as u64",
            },
            actual,
        })?;
    #[cfg(not(feature = "static-dispatch"))]
    let uniform_mask_build_work =
        u64::try_from(uniform_mask_build_work_usize).map_err(|_| PreflightFailure {
            source: BuildError::ArithmeticOverflow {
                computation: "uniform Shift-And mask construction work as u64",
            },
            actual,
        })?;
    let uniform_route_selection_work =
        u64::try_from(uniform_route_selection_work_usize).map_err(|_| PreflightFailure {
            source: BuildError::ArithmeticOverflow {
                computation: "uniform-route selection work as u64",
            },
            actual,
        })?;
    Ok((
        BuildPreflight {
            pattern_bytes,
            max_pattern_bytes,
            min_pattern_bytes,
            runtime_reducer,
            #[cfg(not(feature = "static-dispatch"))]
            uniform_mask_build_work,
            uniform_mask_bytes,
            anchor_offset,
            selected_anchor_minimum_frequency_rank,
            uniform_distinct_pattern_bytes,
            uniform_route_selection_work,
            anchor_selection_work,
            mask_columns,
            bucket_assignment_work,
            identity_bytes,
            build_work,
            persistent_bytes,
            peak_bytes,
        },
        actual,
    ))
}

fn attempt_error(
    source: BuildError,
    identity: BuildAttemptIdentity,
    actual: BuildAttemptActual,
) -> BuildAttemptError {
    BuildAttemptError::new(source, identity, actual)
}

#[allow(
    clippy::result_large_err,
    reason = "a progressive construction failure retains the exact inline receipt"
)]
fn charge_attempt_work(
    actual: &mut BuildAttemptActual,
    additional: usize,
    identity: BuildAttemptIdentity,
    computation: &'static str,
) -> Result<(), BuildAttemptError> {
    let additional = u64::try_from(additional).map_err(|_| {
        attempt_error(
            BuildError::ArithmeticOverflow { computation },
            identity,
            *actual,
        )
    })?;
    actual.work = actual.work.checked_add(additional).ok_or_else(|| {
        attempt_error(
            BuildError::ArithmeticOverflow { computation },
            identity,
            *actual,
        )
    })?;
    Ok(())
}

fn check_reduce(
    upper: ReduceUpperBounds,
    check_span: bool,
    limits: ReduceLimits,
) -> Result<(), ReduceError> {
    if upper.work > limits.max_work {
        return Err(ReduceError::WorkLimit {
            needed: upper.work,
            limit: limits.max_work,
        });
    }
    if upper.match_events > limits.max_match_events {
        return Err(ReduceError::MatchEventsLimit {
            needed: upper.match_events,
            limit: limits.max_match_events,
        });
    }
    if upper.count > limits.max_count {
        return Err(ReduceError::CountLimit {
            needed: upper.count,
            limit: limits.max_count,
        });
    }
    if check_span && upper.span_sum > limits.max_span_sum {
        return Err(ReduceError::SpanSumLimit {
            needed: upper.span_sum,
            limit: limits.max_span_sum,
        });
    }
    if upper.reducer_steps > limits.max_reducer_steps {
        return Err(ReduceError::ReducerStepsLimit {
            needed: upper.reducer_steps,
            limit: limits.max_reducer_steps,
        });
    }
    if upper.scratch_bytes > limits.max_scratch_bytes {
        return Err(ReduceError::ScratchLimit {
            needed: upper.scratch_bytes,
            limit: limits.max_scratch_bytes,
        });
    }
    if upper.peak_bytes > limits.max_peak_bytes {
        return Err(ReduceError::PeakLimit {
            needed: upper.peak_bytes,
            limit: limits.max_peak_bytes,
        });
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct ReduceOutcome {
    count: u64,
    span_sum: u64,
    upper: ReduceUpperBounds,
    actual: ReduceActualCounters,
}

#[allow(
    clippy::result_large_err,
    reason = "fallible exact publication must preserve the fixed owner without allocating an error"
)]
fn allocate_owner(owner: PackedOwner) -> Result<Box<PackedOwner>, (CopyError, PackedOwner)> {
    #[cfg(test)]
    if build_allocation_probe::take_failure() {
        return Err((CopyError::AllocationFailed, owner));
    }
    try_box_preserve(owner)
}

#[cfg(test)]
mod build_allocation_probe {
    use std::cell::Cell;

    thread_local! {
        static FAIL_NEXT_OWNER: Cell<bool> = const { Cell::new(false) };
        static FAIL_NEXT_UNIFORM_MASK: Cell<bool> = const { Cell::new(false) };
    }

    pub(super) struct Guard;

    impl Drop for Guard {
        fn drop(&mut self) {
            FAIL_NEXT_OWNER.with(|fail| fail.set(false));
            FAIL_NEXT_UNIFORM_MASK.with(|fail| fail.set(false));
        }
    }

    pub(super) fn fail_next() -> Guard {
        FAIL_NEXT_OWNER.with(|fail| fail.set(true));
        Guard
    }

    pub(super) fn take_failure() -> bool {
        FAIL_NEXT_OWNER.with(|fail| fail.replace(false))
    }

    #[cfg(not(feature = "static-dispatch"))]
    pub(super) fn fail_next_uniform_mask() -> Guard {
        FAIL_NEXT_UNIFORM_MASK.with(|fail| fail.set(true));
        Guard
    }

    #[cfg(not(feature = "static-dispatch"))]
    pub(super) fn take_uniform_mask_failure() -> bool {
        FAIL_NEXT_UNIFORM_MASK.with(|fail| fail.replace(false))
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use regex::bytes::RegexBuilder;

    use super::{
        BoundedPrefixBounds, BuildError, BuildLimits, PackedBoundedPrefixLiteralCountPlan,
        PackedOrderedLiteralCountPlan, PackedOrderedLiteralSpanSumPlan, ReduceError, ReduceLimits,
        RuntimeReducer, build_allocation_probe,
    };

    fn source(patterns: &[Vec<u8>]) -> String {
        let mut source = String::from("(?:");
        for (index, pattern) in patterns.iter().enumerate() {
            if index != 0 {
                source.push('|');
            }
            for &byte in pattern {
                write!(&mut source, "\\x{byte:02X}").unwrap();
            }
        }
        source.push(')');
        source
    }

    fn bounded_prefix_source(patterns: &[Vec<u8>], bounds: BoundedPrefixBounds) -> String {
        format!(
            ".{{{},{}}}{}",
            bounds.minimum,
            bounds.maximum,
            source(patterns)
        )
    }

    fn words(alphabet: &[u8], maximum_len: usize) -> Vec<Vec<u8>> {
        let mut all = vec![Vec::new()];
        let mut level = vec![Vec::new()];
        for _ in 0..maximum_len {
            let mut next = Vec::new();
            for prefix in &level {
                for &byte in alphabet {
                    let mut word = prefix.clone();
                    word.push(byte);
                    next.push(word);
                }
            }
            all.extend(next.iter().cloned());
            level = next;
        }
        all
    }

    fn pattern_lists(universe: &[Vec<u8>], maximum_len: usize) -> Vec<Vec<Vec<u8>>> {
        let mut all = Vec::new();
        let mut level = vec![Vec::new()];
        for _ in 0..maximum_len {
            let mut next = Vec::new();
            for prefix in &level {
                for pattern in universe {
                    let mut list = prefix.clone();
                    list.push(pattern.clone());
                    next.push(list);
                }
            }
            all.extend(next.iter().cloned());
            level = next;
        }
        all
    }

    #[test]
    fn ordered_prefix_duplicate_and_arbitrary_bytes_match_regex() {
        let languages = [
            vec![b"aa".to_vec(), b"aab".to_vec()],
            vec![b"aab".to_vec(), b"aa".to_vec()],
            vec![b"aa".to_vec(), b"aa".to_vec()],
            vec![b"\xFF\x00".to_vec(), b"\xFF\x00\x80".to_vec()],
        ];
        let haystacks: &[&[u8]] = &[b"", b"a", b"aaa", b"aaaaab", b"\xFF\x00\xFF\x00\x80"];
        for patterns in languages {
            let regex = RegexBuilder::new(&source(&patterns))
                .unicode(false)
                .build()
                .unwrap();
            let count =
                PackedOrderedLiteralCountPlan::build(&patterns, BuildLimits::unlimited()).unwrap();
            let span = PackedOrderedLiteralSpanSumPlan::build(&patterns, BuildLimits::unlimited())
                .unwrap();
            for haystack in haystacks {
                let expected_count = u64::try_from(regex.find_iter(haystack).count()).unwrap();
                let expected_span = regex
                    .find_iter(haystack)
                    .map(|matched| u64::try_from(matched.end() - matched.start()).unwrap())
                    .sum::<u64>();
                assert_eq!(
                    count
                        .count(haystack, ReduceLimits::unlimited())
                        .unwrap()
                        .count,
                    expected_count
                );
                assert_eq!(
                    span.span_sum(haystack, ReduceLimits::unlimited())
                        .unwrap()
                        .span_sum,
                    expected_span
                );
            }
        }
    }

    #[test]
    fn exhaustive_nonempty_languages_match_upstream() {
        let universe = vec![
            b"aa".to_vec(),
            b"ab".to_vec(),
            b"\xFFa".to_vec(),
            b"aaa".to_vec(),
            b"aab".to_vec(),
        ];
        let languages = pattern_lists(&universe, 3)
            .into_iter()
            .filter(|patterns| patterns.len() >= super::CERTIFIED_MIN_PATTERNS);
        let haystacks = words(b"\x00a\xFF", 4);
        for patterns in languages {
            let regex = RegexBuilder::new(&source(&patterns))
                .unicode(false)
                .build()
                .unwrap();
            let packed_count =
                PackedOrderedLiteralCountPlan::build(&patterns, BuildLimits::unlimited()).unwrap();
            let packed_span =
                PackedOrderedLiteralSpanSumPlan::build(&patterns, BuildLimits::unlimited())
                    .unwrap();
            for haystack in &haystacks {
                let expected_count = u64::try_from(regex.find_iter(haystack).count()).unwrap();
                let expected_span = regex
                    .find_iter(haystack)
                    .map(|matched| u64::try_from(matched.end() - matched.start()).unwrap())
                    .sum::<u64>();
                assert_eq!(
                    packed_count
                        .count(haystack, ReduceLimits::unlimited())
                        .unwrap()
                        .count,
                    expected_count,
                    "patterns={patterns:?}, haystack={haystack:?}"
                );
                assert_eq!(
                    packed_span
                        .span_sum(haystack, ReduceLimits::unlimited())
                        .unwrap()
                        .span_sum,
                    expected_span,
                    "patterns={patterns:?}, haystack={haystack:?}"
                );
            }
        }
    }

    #[test]
    fn nonempty_utf8_words_are_profile_neutral_bytes() {
        let patterns = ["∞".as_bytes(), "✓".as_bytes()];
        let haystack = "--∞--✓--∞--".as_bytes();
        let count =
            PackedOrderedLiteralCountPlan::build(&patterns, BuildLimits::unlimited()).unwrap();
        let span =
            PackedOrderedLiteralSpanSumPlan::build(&patterns, BuildLimits::unlimited()).unwrap();
        assert_eq!(
            count
                .count(haystack, ReduceLimits::unlimited())
                .unwrap()
                .count,
            3
        );
        assert_eq!(
            span.span_sum(haystack, ReduceLimits::unlimited())
                .unwrap()
                .span_sum,
            9
        );
        assert_eq!(
            count.cache_identity().semantics.boundary_semantics,
            super::BoundarySemantics::NonemptyByteStrings
        );
    }

    #[test]
    fn maximum_width_ordered_arbitrary_bytes_match_regex() {
        let mut first = vec![b'a'; super::CERTIFIED_MAX_PATTERN_BYTES];
        first[31] = 0xFF;
        first[super::CERTIFIED_MAX_PATTERN_BYTES - 1] = b'x';
        let mut second = first.clone();
        second[super::CERTIFIED_MAX_PATTERN_BYTES - 1] = b'y';
        let patterns = vec![first, second];
        let regex = RegexBuilder::new(&source(&patterns))
            .unicode(false)
            .build()
            .unwrap();
        let count =
            PackedOrderedLiteralCountPlan::build(&patterns, BuildLimits::unlimited()).unwrap();
        let span =
            PackedOrderedLiteralSpanSumPlan::build(&patterns, BuildLimits::unlimited()).unwrap();
        let mut haystack = patterns[1].clone();
        haystack.extend_from_slice(b"--");
        haystack.extend_from_slice(&patterns[0]);
        haystack.extend_from_slice(b"--");
        haystack.extend_from_slice(&patterns[1]);
        let expected_count = u64::try_from(regex.find_iter(&haystack).count()).unwrap();
        let expected_span = regex
            .find_iter(&haystack)
            .map(|matched| u64::try_from(matched.end() - matched.start()).unwrap())
            .sum::<u64>();
        assert_eq!(
            count
                .count(&haystack, ReduceLimits::unlimited())
                .unwrap()
                .count,
            expected_count
        );
        assert_eq!(
            span.span_sum(&haystack, ReduceLimits::unlimited())
                .unwrap()
                .span_sum,
            expected_span
        );
    }

    #[test]
    fn bounded_prefix_greediness_newline_and_restart_match_regex() {
        let patterns = [
            b"Tom".to_vec(),
            b"Sawyer".to_vec(),
            b"Huckleberry".to_vec(),
            b"Finn".to_vec(),
        ];
        let haystacks: &[&[u8]] = &[
            b"",
            b"Tom",
            b"xxTom",
            b"xxxxTom",
            b"xxxxxTom",
            b"x\nxTom",
            b"xxTomSawyer",
            b"xxTomxxSawyerxxFinn",
            b"TomTomTom",
            b"xxxSawyerxFinnxxxxHuckleberry",
        ];
        for bounds in [
            BoundedPrefixBounds {
                minimum: 0,
                maximum: 2,
            },
            BoundedPrefixBounds {
                minimum: 2,
                maximum: 4,
            },
        ] {
            let regex = RegexBuilder::new(&bounded_prefix_source(&patterns, bounds))
                .unicode(false)
                .build()
                .unwrap();
            let plan = PackedBoundedPrefixLiteralCountPlan::build(
                &patterns,
                bounds,
                BuildLimits::unlimited(),
            )
            .unwrap();
            assert_eq!(plan.cache_identity().bounded_prefix, Some(bounds));
            for haystack in haystacks {
                let expected = u64::try_from(regex.find_iter(haystack).count()).unwrap();
                let actual = plan
                    .count(haystack, ReduceLimits::unlimited())
                    .unwrap()
                    .count;
                assert_eq!(actual, expected, "bounds={bounds:?}, haystack={haystack:?}");
            }
        }
    }

    #[test]
    fn bounded_prefix_small_exhaustive_matches_regex() {
        let patterns = [b"Tom".to_vec(), b"Saw".to_vec()];
        let haystacks = words(b"\naxTomS", 5);
        for bounds in [
            BoundedPrefixBounds {
                minimum: 0,
                maximum: 2,
            },
            BoundedPrefixBounds {
                minimum: 2,
                maximum: 4,
            },
        ] {
            let regex = RegexBuilder::new(&bounded_prefix_source(&patterns, bounds))
                .unicode(false)
                .build()
                .unwrap();
            let plan = PackedBoundedPrefixLiteralCountPlan::build(
                &patterns,
                bounds,
                BuildLimits::unlimited(),
            )
            .unwrap();
            for haystack in &haystacks {
                let expected = u64::try_from(regex.find_iter(haystack).count()).unwrap();
                let actual = plan
                    .count(haystack, ReduceLimits::unlimited())
                    .unwrap()
                    .count;
                assert_eq!(actual, expected, "bounds={bounds:?}, haystack={haystack:?}");
            }
        }
    }

    #[test]
    fn bounded_prefix_deterministic_random_differential_matches_regex() {
        let patterns = [
            b"Tom".to_vec(),
            b"Sawyer".to_vec(),
            b"Huckleberry".to_vec(),
            b"Finn".to_vec(),
        ];
        let mut state = 0x9E37_79B9_7F4A_7C15_u64;
        for bounds in [
            BoundedPrefixBounds {
                minimum: 0,
                maximum: 2,
            },
            BoundedPrefixBounds {
                minimum: 2,
                maximum: 4,
            },
        ] {
            let regex = RegexBuilder::new(&bounded_prefix_source(&patterns, bounds))
                .unicode(false)
                .build()
                .unwrap();
            let plan = PackedBoundedPrefixLiteralCountPlan::build(
                &patterns,
                bounds,
                BuildLimits::unlimited(),
            )
            .unwrap();
            for _ in 0..2_000 {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                let len = usize::try_from((state >> 32) % 192).unwrap();
                let mut haystack = Vec::with_capacity(len);
                for _ in 0..len {
                    state = state
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1_442_695_040_888_963_407);
                    const ALPHABET: &[u8] = b"\n abcdefiklmnorstuwyTFHS";
                    let index =
                        usize::try_from(state % u64::try_from(ALPHABET.len()).unwrap()).unwrap();
                    haystack.push(ALPHABET[index]);
                }
                let expected = u64::try_from(regex.find_iter(&haystack).count()).unwrap();
                let actual = plan
                    .count(&haystack, ReduceLimits::unlimited())
                    .unwrap()
                    .count;
                assert_eq!(actual, expected, "bounds={bounds:?}, haystack={haystack:?}");
            }
        }
    }

    #[test]
    fn bounded_prefix_bounds_and_build_work_are_receipt_closed() {
        let patterns = [b"Tom".as_slice(), b"Finn".as_slice()];
        let bounds = BoundedPrefixBounds {
            minimum: 2,
            maximum: 4,
        };
        let attempt = PackedBoundedPrefixLiteralCountPlan::build_attempt(
            &patterns,
            bounds,
            BuildLimits::unlimited(),
        )
        .unwrap();
        assert!(attempt.closes());
        assert_eq!(attempt.receipt().identity().bounded_prefix, Some(bounds));
        let exact_work =
            usize::try_from(attempt.plan().build_accounting().build_work_upper_bound).unwrap();
        assert!(
            PackedBoundedPrefixLiteralCountPlan::build_attempt(
                &patterns,
                bounds,
                BuildLimits {
                    max_build_work: exact_work,
                    ..BuildLimits::unlimited()
                }
            )
            .unwrap()
            .closes()
        );
        let one_below = PackedBoundedPrefixLiteralCountPlan::build_attempt(
            &patterns,
            bounds,
            BuildLimits {
                max_build_work: exact_work - 1,
                ..BuildLimits::unlimited()
            },
        )
        .unwrap_err();
        assert!(one_below.closes());
        assert!(matches!(one_below.source(), BuildError::WorkLimit { .. }));

        let invalid = PackedBoundedPrefixLiteralCountPlan::build_attempt(
            &patterns,
            BoundedPrefixBounds {
                minimum: 4,
                maximum: 2,
            },
            BuildLimits::unlimited(),
        )
        .unwrap_err();
        assert!(invalid.closes());
        assert_eq!(invalid.receipt().actual().work, 1);
        let zero_work = PackedBoundedPrefixLiteralCountPlan::build_attempt(
            &patterns,
            bounds,
            BuildLimits {
                max_build_work: 0,
                ..BuildLimits::unlimited()
            },
        )
        .unwrap_err();
        assert!(zero_work.closes());
        assert!(matches!(
            zero_work.source(),
            BuildError::WorkLimit {
                needed: 1,
                limit: 0
            }
        ));
        assert_eq!(zero_work.receipt().actual().work, 0);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the exact/one-below matrix keeps every packed limit and receipt visible"
    )]
    fn every_nonzero_limit_has_exact_and_one_below_behavior() {
        let patterns = [b"ab".as_slice(), b"abc".as_slice(), b"\xFF\x00".as_slice()];
        let baseline =
            PackedOrderedLiteralCountPlan::build_attempt(&patterns, BuildLimits::unlimited())
                .unwrap();
        assert!(baseline.closes());
        let (baseline, receipt) = baseline.into_parts();
        assert!(receipt.contains_actual());
        let build = baseline.build_accounting();
        let exact = BuildLimits {
            max_patterns: build.patterns,
            max_pattern_bytes: build.max_pattern_bytes,
            max_total_pattern_bytes: build.pattern_bytes,
            max_identity_bytes: build.identity_bytes,
            max_build_work: usize::try_from(build.build_work_upper_bound).unwrap(),
            max_build_peak_bytes: build.build_peak_upper_bound,
            max_persistent_bytes: build.persistent_bytes,
        };
        assert!(
            PackedOrderedLiteralCountPlan::build_attempt(&patterns, exact)
                .unwrap()
                .closes()
        );
        let build_cases = [
            BuildLimits {
                max_patterns: exact.max_patterns - 1,
                ..exact
            },
            BuildLimits {
                max_pattern_bytes: exact.max_pattern_bytes - 1,
                ..exact
            },
            BuildLimits {
                max_total_pattern_bytes: exact.max_total_pattern_bytes - 1,
                ..exact
            },
            BuildLimits {
                max_identity_bytes: exact.max_identity_bytes - 1,
                ..exact
            },
            BuildLimits {
                max_build_work: exact.max_build_work - 1,
                ..exact
            },
            BuildLimits {
                max_build_peak_bytes: exact.max_build_peak_bytes - 1,
                ..exact
            },
            BuildLimits {
                max_persistent_bytes: exact.max_persistent_bytes - 1,
                ..exact
            },
        ];
        for limits in build_cases {
            let failure = PackedOrderedLiteralCountPlan::build_attempt(&patterns, limits)
                .expect_err("one-below build limit must refuse");
            assert!(failure.closes(), "{failure:?}");
        }

        let haystack = b"abcab\xFF\x00";
        let result = baseline.count(haystack, ReduceLimits::unlimited()).unwrap();
        let upper = result.accounting.upper_bounds;
        let reduce_exact = ReduceLimits {
            max_work: upper.work,
            max_match_events: upper.match_events,
            max_count: upper.count,
            max_span_sum: u64::MAX,
            max_reducer_steps: upper.reducer_steps,
            max_scratch_bytes: upper.scratch_bytes,
            max_peak_bytes: upper.peak_bytes,
        };
        baseline.count(haystack, reduce_exact).unwrap();
        assert!(matches!(
            baseline.count(
                haystack,
                ReduceLimits {
                    max_work: reduce_exact.max_work - 1,
                    ..reduce_exact
                }
            ),
            Err(ReduceError::WorkLimit { .. })
        ));
        assert!(matches!(
            baseline.count(
                haystack,
                ReduceLimits {
                    max_match_events: reduce_exact.max_match_events - 1,
                    ..reduce_exact
                }
            ),
            Err(ReduceError::MatchEventsLimit { .. })
        ));
        assert!(matches!(
            baseline.count(
                haystack,
                ReduceLimits {
                    max_count: reduce_exact.max_count - 1,
                    ..reduce_exact
                }
            ),
            Err(ReduceError::CountLimit { .. })
        ));
        assert!(matches!(
            baseline.count(
                haystack,
                ReduceLimits {
                    max_reducer_steps: reduce_exact.max_reducer_steps - 1,
                    ..reduce_exact
                }
            ),
            Err(ReduceError::ReducerStepsLimit { .. })
        ));
        assert!(matches!(
            baseline.count(
                haystack,
                ReduceLimits {
                    max_peak_bytes: reduce_exact.max_peak_bytes - 1,
                    ..reduce_exact
                }
            ),
            Err(ReduceError::PeakLimit { .. })
        ));

        let span_plan =
            PackedOrderedLiteralSpanSumPlan::build(&patterns, BuildLimits::unlimited()).unwrap();
        let span = span_plan
            .span_sum(haystack, ReduceLimits::unlimited())
            .unwrap();
        assert!(matches!(
            span_plan.span_sum(
                haystack,
                ReduceLimits {
                    max_span_sum: span.accounting.upper_bounds.span_sum - 1,
                    ..ReduceLimits::unlimited()
                }
            ),
            Err(ReduceError::SpanSumLimit { .. })
        ));
    }

    #[test]
    fn failed_owner_allocation_has_a_closed_partial_receipt() {
        let patterns = [b"ab".as_slice(), b"cde".as_slice()];
        let _guard = build_allocation_probe::fail_next();
        let failure =
            PackedOrderedLiteralCountPlan::build_attempt(&patterns, BuildLimits::unlimited())
                .unwrap_err();
        assert!(matches!(
            failure.source(),
            BuildError::AllocationFailed { additional }
                if *additional == size_of::<super::PackedOwner>()
        ));
        assert!(failure.closes());
        let actual = failure.receipt().actual();
        assert_eq!(actual.allocations, 0);
        assert_eq!(actual.allocated_bytes, 0);
        assert_eq!(actual.released_allocations, 0);
        assert_eq!(actual.released_bytes, 0);
        assert_eq!(actual.copied_bytes, 29);
        assert_eq!(actual.live_persistent_bytes, 0);
        assert_eq!(actual.peak_bytes, 0);
    }

    #[test]
    #[cfg(not(feature = "static-dispatch"))]
    fn failed_uniform_owner_allocation_accounts_and_releases_the_mask_table() {
        let patterns = [b"agggtaaa".as_slice(), b"tttaccct".as_slice()];
        let successful =
            PackedOrderedLiteralCountPlan::build(&patterns, BuildLimits::unlimited()).unwrap();
        let _guard = build_allocation_probe::fail_next();
        let failure =
            PackedOrderedLiteralCountPlan::build_attempt(&patterns, BuildLimits::unlimited())
                .unwrap_err();
        assert!(matches!(
            failure.source(),
            BuildError::AllocationFailed { additional }
                if *additional == size_of::<super::PackedOwner>()
        ));
        assert!(failure.closes());
        let actual = failure.receipt().actual();
        assert_eq!(
            actual.work,
            successful.build_accounting().build_work_upper_bound
        );
        assert_eq!(actual.allocations, 1);
        assert_eq!(actual.allocated_bytes, super::UNIFORM_MASK_BYTES);
        assert_eq!(actual.released_allocations, 1);
        assert_eq!(actual.released_bytes, super::UNIFORM_MASK_BYTES);
        assert_eq!(actual.copied_bytes, 40);
        assert_eq!(actual.live_persistent_bytes, 0);
        assert_eq!(actual.peak_bytes, super::UNIFORM_MASK_BYTES);
    }

    #[test]
    #[cfg(not(feature = "static-dispatch"))]
    fn failed_uniform_mask_allocation_has_a_closed_zero_allocation_receipt() {
        let patterns = [b"agggtaaa".as_slice(), b"tttaccct".as_slice()];
        let successful =
            PackedOrderedLiteralCountPlan::build(&patterns, BuildLimits::unlimited()).unwrap();
        let build = successful.build_accounting();
        let _guard = build_allocation_probe::fail_next_uniform_mask();
        let failure =
            PackedOrderedLiteralCountPlan::build_attempt(&patterns, BuildLimits::unlimited())
                .unwrap_err();
        assert!(matches!(
            failure.source(),
            BuildError::AllocationFailed { additional }
                if *additional == super::UNIFORM_MASK_BYTES
        ));
        assert!(failure.closes());
        let actual = failure.receipt().actual();
        assert_eq!(
            actual.work,
            build
                .build_work_upper_bound
                .checked_sub(
                    build
                        .uniform_mask_build_work()
                        .checked_sub(u64::try_from(super::UNIFORM_MASK_ZERO_WORK).unwrap())
                        .unwrap()
                )
                .unwrap()
        );
        assert_eq!(actual.allocations, 0);
        assert_eq!(actual.allocated_bytes, 0);
        assert_eq!(actual.released_allocations, 0);
        assert_eq!(actual.released_bytes, 0);
        assert_eq!(
            actual.initialized_bytes,
            size_of::<super::PackedOwner>() + super::UNIFORM_MASK_BYTES
        );
        assert_eq!(actual.live_persistent_bytes, 0);
        assert_eq!(actual.peak_bytes, 0);
    }

    #[test]
    fn theorem_refuses_count_width_and_total_outside_absolute_bounds() {
        assert!(matches!(
            PackedOrderedLiteralCountPlan::build::<&[u8]>(&[], BuildLimits::unlimited()),
            Err(BuildError::EmptyPatternSet)
        ));
        assert!(matches!(
            PackedOrderedLiteralCountPlan::build(&[b"ab".as_slice()], BuildLimits::unlimited()),
            Err(BuildError::ProofRefused {
                fact: "pattern count minimum",
                ..
            })
        ));
        assert!(matches!(
            PackedOrderedLiteralCountPlan::build(
                &[b"a".as_slice(), b"bc".as_slice()],
                BuildLimits::unlimited()
            ),
            Err(BuildError::ProofRefused {
                fact: "literal width minimum",
                ..
            })
        ));
        let too_many = vec![b"aa".as_slice(); super::CERTIFIED_MAX_PATTERNS + 1];
        assert!(matches!(
            PackedOrderedLiteralCountPlan::build(&too_many, BuildLimits::unlimited()),
            Err(BuildError::ProofRefused {
                fact: "pattern count",
                ..
            })
        ));
        let too_wide = vec![b'a'; super::CERTIFIED_MAX_PATTERN_BYTES + 1];
        assert!(matches!(
            PackedOrderedLiteralCountPlan::build(
                &[too_wide.as_slice(), b"bc".as_slice()],
                BuildLimits::unlimited()
            ),
            Err(BuildError::ProofRefused {
                fact: "literal width",
                ..
            })
        ));
        let maximum_width = vec![b'a'; super::CERTIFIED_MAX_PATTERN_BYTES];
        let maximum_total = vec![
            maximum_width.as_slice();
            super::CERTIFIED_MAX_TOTAL_PATTERN_BYTES
                / super::CERTIFIED_MAX_PATTERN_BYTES
        ];
        PackedOrderedLiteralCountPlan::build(&maximum_total, BuildLimits::unlimited()).unwrap();
        let mut too_large = maximum_total;
        too_large.push(b"bb".as_slice());
        assert!(matches!(
            PackedOrderedLiteralCountPlan::build(&too_large, BuildLimits::unlimited()),
            Err(BuildError::ProofRefused {
                fact: "total literal bytes",
                ..
            })
        ));
    }

    #[test]
    fn set_shape_refusals_and_zero_work_limits_have_closed_receipts() {
        let too_many = vec![b"aa".as_slice(); super::CERTIFIED_MAX_PATTERNS + 1];
        let shape_failure =
            PackedOrderedLiteralCountPlan::build_attempt(&too_many, BuildLimits::unlimited())
                .unwrap_err();
        assert!(matches!(
            shape_failure.source(),
            BuildError::ProofRefused {
                fact: "pattern count",
                ..
            }
        ));
        assert!(shape_failure.closes());
        assert_eq!(shape_failure.receipt().actual().work, 1);

        let zero_work_failure = PackedOrderedLiteralCountPlan::build_attempt(
            &[b"ab".as_slice(), b"cd".as_slice()],
            BuildLimits {
                max_build_work: 0,
                ..BuildLimits::unlimited()
            },
        )
        .unwrap_err();
        assert!(matches!(
            zero_work_failure.source(),
            BuildError::WorkLimit {
                needed: 1,
                limit: 0
            }
        ));
        assert!(zero_work_failure.closes());
        assert_eq!(zero_work_failure.receipt().actual().work, 0);
    }

    #[test]
    fn operation_receipt_is_bounded_and_allocation_free() {
        let patterns = [b"Sherlock".as_slice(), b"Holmes".as_slice()];
        let plan =
            PackedOrderedLiteralCountPlan::build(&patterns, BuildLimits::unlimited()).unwrap();
        let build = plan.build_accounting();
        assert_eq!(build.anchor_offset, 0);
        assert_eq!(build.max_anchor_byte_bucket_patterns, 1);
        assert_eq!(
            build.max_anchor_byte_bucket_pattern_bytes,
            b"Sherlock".len()
        );
        assert!(
            build.patterns > build.max_anchor_byte_bucket_patterns,
            "the proof must distinguish the whole set from one anchor-byte bucket"
        );
        assert!(
            build.pattern_bytes > build.max_anchor_byte_bucket_pattern_bytes,
            "the proof must charge only bytes reachable through one anchor-byte bucket"
        );
        let result = plan
            .count(
                b"Sherlock and Holmes and Sherlock",
                ReduceLimits::unlimited(),
            )
            .unwrap();
        let upper = result.accounting.upper_bounds;
        let actual = result.accounting.actual;
        assert_eq!(result.count, 3);
        assert_eq!(actual.scratch_bytes, 0);
        assert_eq!(actual.span_sum, None);
        assert_eq!(upper.scratch_bytes, 0);
        assert_eq!(
            upper.pattern_checks,
            upper
                .candidate_positions
                .checked_mul(build.max_anchor_byte_bucket_patterns)
                .unwrap()
        );
        assert_eq!(
            upper.source_byte_reads,
            upper
                .candidate_positions
                .checked_mul(build.max_anchor_byte_bucket_pattern_bytes + build.mask_columns + 1)
                .unwrap()
        );
        assert_eq!(
            upper.work,
            u64::try_from(
                upper
                    .candidate_positions
                    .checked_mul(
                        build.max_anchor_byte_bucket_pattern_bytes
                            + build.max_anchor_byte_bucket_patterns
                            + build.mask_columns
                            + 5
                    )
                    .and_then(|work| work.checked_add(1))
                    .unwrap()
            )
            .unwrap()
        );
        assert!(matches!(
            plan.count(
                b"Sherlock and Holmes and Sherlock",
                ReduceLimits {
                    max_work: upper.work - 1,
                    ..ReduceLimits::unlimited()
                }
            ),
            Err(ReduceError::WorkLimit {
                needed,
                limit
            }) if needed == upper.work && limit == upper.work - 1
        ));
        assert_eq!(actual.classified_positions, upper.candidate_positions);
        assert!(actual.candidate_events <= upper.candidate_positions);
        assert!(actual.pattern_checks <= upper.pattern_checks);
        assert_eq!(actual.source_byte_reads, upper.source_byte_reads);
        assert!(actual.work <= upper.work);
        assert_eq!(upper.restart_tail_positions, 0);
        assert_eq!(upper.iterator_setup_work, 0);
    }

    #[test]
    fn ranked_full_byte_screen_rejects_sparse_non_ascii_blocks() {
        let patterns = [
            b"\xFF\x00needle".as_slice(),
            b"rare-two".as_slice(),
            b"third\xFE".as_slice(),
        ];
        let plan =
            PackedOrderedLiteralCountPlan::build(&patterns, BuildLimits::unlimited()).unwrap();
        let source = [0x80_u8; 96];
        let classified = plan
            .core
            .owner
            .screening_classifier
            .classify_16(&source)
            .unwrap();
        assert_eq!(classified.chunks(), [0, 0]);
    }

    #[test]
    fn scalar_vector_boundaries_and_ordered_prefixes_match_regex() {
        let pattern_sets = [
            vec![b"ab".to_vec(), b"abc".to_vec(), b"\xFF\x00".to_vec()],
            vec![b"abc".to_vec(), b"ab".to_vec(), b"\xFF\x00".to_vec()],
        ];
        for patterns in pattern_sets {
            let regex = RegexBuilder::new(&source(&patterns))
                .unicode(false)
                .build()
                .unwrap();
            let count =
                PackedOrderedLiteralCountPlan::build(&patterns, BuildLimits::unlimited()).unwrap();
            let span = PackedOrderedLiteralSpanSumPlan::build(&patterns, BuildLimits::unlimited())
                .unwrap();
            for candidate_positions in [15_usize, 16, 17, 31, 32, 33] {
                let haystack_len = candidate_positions + 1;
                for match_start in [0_usize, 14, 15, 16, 17, 30, 31] {
                    let mut haystack = vec![0x80_u8; haystack_len];
                    if let Some(end) = match_start.checked_add(3)
                        && end <= haystack.len()
                    {
                        haystack[match_start..end].copy_from_slice(b"abc");
                    }
                    let expected_count = u64::try_from(regex.find_iter(&haystack).count()).unwrap();
                    let expected_span = regex
                        .find_iter(&haystack)
                        .map(|matched| u64::try_from(matched.len()).unwrap())
                        .sum::<u64>();
                    assert_eq!(
                        count
                            .count(&haystack, ReduceLimits::unlimited())
                            .unwrap()
                            .count,
                        expected_count,
                        "patterns={patterns:?} candidates={candidate_positions} start={match_start}"
                    );
                    assert_eq!(
                        span.span_sum(&haystack, ReduceLimits::unlimited())
                            .unwrap()
                            .span_sum,
                        expected_span,
                        "patterns={patterns:?} candidates={candidate_positions} start={match_start}"
                    );
                }
            }
        }
    }

    #[test]
    fn recycled_bucket_false_positives_are_verified_in_global_pattern_order() {
        let patterns = vec![
            vec![0x12, 0x56, b'a', b'a'],
            vec![0x20, 0x40, b'c', b'c'],
            vec![0x21, 0x41, b'd', b'd'],
            vec![0x22, 0x42, b'e', b'e'],
            vec![0x23, 0x43, b'f', b'f'],
            vec![0x24, 0x44, b'g', b'g'],
            vec![0x25, 0x45, b'h', b'h'],
            vec![0x26, 0x46, b'i', b'i'],
            vec![0x34, 0x78, b'b', b'b'],
            // Keep this byte-bucket-specific test off the equal-width leaf.
            vec![0x35, 0x79, b'j', b'j', b'x'],
        ];
        let plan =
            PackedOrderedLiteralCountPlan::build(&patterns, BuildLimits::unlimited()).unwrap();
        let mut false_positive_source = Vec::new();
        for _ in 0..12 {
            false_positive_source.extend_from_slice(&[0x14, 0x58, b'a', b'b']);
        }
        let false_positive = plan
            .count(&false_positive_source, ReduceLimits::unlimited())
            .unwrap();
        assert_eq!(false_positive.count, 0);
        assert!(
            false_positive.accounting.actual.candidate_events > 0,
            "the recycled-bucket cross product must reach exact verification"
        );
        assert!(false_positive.accounting.actual.pattern_checks > 0);

        let ordered = [
            b"same".as_slice(),
            b"same-long".as_slice(),
            b"other".as_slice(),
        ];
        let first_short =
            PackedOrderedLiteralSpanSumPlan::build(&ordered, BuildLimits::unlimited()).unwrap();
        let reversed = [
            b"same-long".as_slice(),
            b"same".as_slice(),
            b"other".as_slice(),
        ];
        let first_long =
            PackedOrderedLiteralSpanSumPlan::build(&reversed, BuildLimits::unlimited()).unwrap();
        let mut haystack = vec![b'x'; 48];
        haystack[16..25].copy_from_slice(b"same-long");
        assert_eq!(
            first_short
                .span_sum(&haystack, ReduceLimits::unlimited())
                .unwrap()
                .span_sum,
            4
        );
        assert_eq!(
            first_long
                .span_sum(&haystack, ReduceLimits::unlimited())
                .unwrap()
                .span_sum,
            9
        );
    }

    #[test]
    #[cfg(not(feature = "static-dispatch"))]
    fn uniform_word64_is_exact_for_duplicates_overlaps_and_adjacent_matches() {
        let cases = [
            (
                vec![b"abababab".to_vec(), b"babababa".to_vec()],
                b"ababababababababababa".to_vec(),
            ),
            (
                vec![b"aaaaaaaa".to_vec(), b"aaaaaaaa".to_vec()],
                b"aaaaaaaaaaaaaaaaa".to_vec(),
            ),
            (
                vec![b"acgtacgt".to_vec(), b"tgcagtca".to_vec()],
                b"acgtacgttgcagtcatgcagtcaacgtacgt".to_vec(),
            ),
            (
                vec![
                    vec![0xff, 0xfe, 0xfd, 0xfc, 0xff, 0xfe, 0xfd, 0xfc],
                    vec![0xfc, 0xfd, 0xfe, 0xff, 0xfc, 0xfd, 0xfe, 0xff],
                ],
                vec![
                    0xff, 0xfe, 0xfd, 0xfc, 0xff, 0xfe, 0xfd, 0xfc, 0xfc, 0xfd, 0xfe, 0xff, 0xfc,
                    0xfd, 0xfe, 0xff, 0xff, 0xfe, 0xfd, 0xfc, 0xff, 0xfe, 0xfd, 0xfc,
                ],
            ),
        ];
        for (patterns, haystack) in cases {
            let regex = RegexBuilder::new(&source(&patterns))
                .unicode(false)
                .build()
                .unwrap();
            let count =
                PackedOrderedLiteralCountPlan::build(&patterns, BuildLimits::unlimited()).unwrap();
            let span = PackedOrderedLiteralSpanSumPlan::build(&patterns, BuildLimits::unlimited())
                .unwrap();
            assert_eq!(
                count.build_accounting().runtime_reducer,
                RuntimeReducer::UniformWord64
            );
            assert_eq!(
                span.build_accounting().runtime_reducer,
                RuntimeReducer::UniformWord64
            );
            let expected_count = u64::try_from(regex.find_iter(&haystack).count()).unwrap();
            let expected_span = regex
                .find_iter(&haystack)
                .map(|matched| u64::try_from(matched.len()).unwrap())
                .sum::<u64>();
            let counted = count.count(&haystack, ReduceLimits::unlimited()).unwrap();
            let summed = span.span_sum(&haystack, ReduceLimits::unlimited()).unwrap();
            assert_eq!(counted.count, expected_count, "patterns={patterns:?}");
            assert_eq!(summed.span_sum, expected_span, "patterns={patterns:?}");
            assert_eq!(
                counted.accounting.identity.runtime_reducer,
                RuntimeReducer::UniformWord64
            );
            assert_eq!(
                counted.accounting.actual.shift_and_transitions,
                haystack.len()
            );
            assert_eq!(counted.accounting.actual.classified_positions, 0);
            assert_eq!(counted.accounting.actual.pattern_checks, 0);
            assert_eq!(counted.accounting.actual.source_byte_reads, haystack.len());
        }
    }

    #[test]
    #[cfg(not(feature = "static-dispatch"))]
    fn uniform_word64_bounded_exhaustive_width_eight_matches_regex() {
        let motifs = words(b"ab", 4)
            .into_iter()
            .filter(|motif| motif.len() == 4)
            .collect::<Vec<_>>();
        let universe = motifs
            .into_iter()
            .map(|motif| motif.repeat(2))
            .collect::<Vec<_>>();
        let haystacks = words(b"ab", 11);

        for first in &universe {
            for second in &universe {
                let patterns = vec![first.clone(), second.clone()];
                let regex = RegexBuilder::new(&source(&patterns))
                    .unicode(false)
                    .build()
                    .unwrap();
                let count =
                    PackedOrderedLiteralCountPlan::build(&patterns, BuildLimits::unlimited())
                        .unwrap();
                let span =
                    PackedOrderedLiteralSpanSumPlan::build(&patterns, BuildLimits::unlimited())
                        .unwrap();
                assert_eq!(
                    count.build_accounting().runtime_reducer,
                    RuntimeReducer::UniformWord64
                );
                for haystack in &haystacks {
                    let (expected_count, expected_span) =
                        regex
                            .find_iter(haystack)
                            .fold((0_u64, 0_u64), |(count, span), matched| {
                                (
                                    count.checked_add(1).unwrap(),
                                    span.checked_add(u64::try_from(matched.len()).unwrap())
                                        .unwrap(),
                                )
                            });
                    assert_eq!(
                        count
                            .count(haystack, ReduceLimits::unlimited())
                            .unwrap()
                            .count,
                        expected_count,
                        "patterns={patterns:?} haystack={haystack:?}"
                    );
                    assert_eq!(
                        span.span_sum(haystack, ReduceLimits::unlimited())
                            .unwrap()
                            .span_sum,
                        expected_span,
                        "patterns={patterns:?} haystack={haystack:?}"
                    );
                }
            }
        }
    }

    #[test]
    #[cfg(not(feature = "static-dispatch"))]
    #[allow(
        clippy::too_many_lines,
        reason = "the route, resource fallback, rank and alphabet controls share one exact-work comparison"
    )]
    fn uniform_word64_route_rank_and_preflight_work_are_closed() {
        let common = [b"agggtaaa".as_slice(), b"tttaccct".as_slice()];
        let plan = PackedOrderedLiteralCountPlan::build(&common, BuildLimits::unlimited()).unwrap();
        let build = plan.build_accounting();
        assert_eq!(build.runtime_reducer, RuntimeReducer::UniformWord64);
        assert_eq!(
            build.uniform_route_selection_work(),
            u64::try_from(
                common
                    .len()
                    .checked_add(super::UNIFORM_ALPHABET_ZERO_WORK)
                    .and_then(|work| work.checked_add(build.pattern_bytes))
                    .unwrap()
            )
            .unwrap()
        );
        assert_eq!(build.uniform_distinct_pattern_bytes, 4);
        assert!(build.uniform_alphabet_admitted());
        assert!(
            build.selected_anchor_minimum_frequency_rank
                >= super::UNIFORM_WORD64_MIN_ANCHOR_FREQUENCY_RANK
        );

        let uniform_delta = build
            .uniform_mask_build_work()
            .checked_add(u64::try_from(build.uniform_mask_bytes()).unwrap())
            .unwrap();
        let bucket_with_rank_work = build
            .build_work_upper_bound
            .checked_sub(uniform_delta)
            .unwrap();
        let bucket_without_rank_work = bucket_with_rank_work
            .checked_sub(build.uniform_route_selection_work())
            .unwrap();

        let ranked_decline = PackedOrderedLiteralCountPlan::build(
            &common,
            BuildLimits {
                max_build_work: usize::try_from(bucket_with_rank_work).unwrap(),
                ..BuildLimits::unlimited()
            },
        )
        .unwrap();
        let ranked_decline_build = ranked_decline.build_accounting();
        assert_eq!(
            ranked_decline_build.runtime_reducer,
            RuntimeReducer::ByteBucket
        );
        assert!(ranked_decline_build.uniform_resource_declined());
        assert_eq!(
            ranked_decline_build.uniform_route_selection_work(),
            build.uniform_route_selection_work()
        );

        let uninspected_decline = PackedOrderedLiteralCountPlan::build(
            &common,
            BuildLimits {
                max_build_work: usize::try_from(bucket_without_rank_work).unwrap(),
                ..BuildLimits::unlimited()
            },
        )
        .unwrap();
        let uninspected_decline_build = uninspected_decline.build_accounting();
        assert_eq!(
            uninspected_decline_build.runtime_reducer,
            RuntimeReducer::ByteBucket
        );
        assert!(!uninspected_decline_build.uniform_resource_declined());
        assert_eq!(uninspected_decline_build.uniform_route_selection_work(), 0);
        assert_eq!(
            uninspected_decline_build.selected_anchor_minimum_frequency_rank,
            0
        );

        let below_bucket_work = bucket_without_rank_work.checked_sub(1).unwrap();
        let failure = PackedOrderedLiteralCountPlan::build_attempt(
            &common,
            BuildLimits {
                max_build_work: usize::try_from(below_bucket_work).unwrap(),
                ..BuildLimits::unlimited()
            },
        )
        .unwrap_err();
        assert!(failure.closes());
        assert!(matches!(
            failure.source(),
            BuildError::WorkLimit { needed, limit }
                if u64::try_from(*needed).unwrap() == bucket_without_rank_work
                    && u64::try_from(*limit).unwrap() == below_bucket_work
        ));

        let rare = [b"\x00aaaaaaa".as_slice(), b"\x01bbbbbbb".as_slice()];
        let rare_plan =
            PackedOrderedLiteralCountPlan::build(&rare, BuildLimits::unlimited()).unwrap();
        let rare_build = rare_plan.build_accounting();
        assert_eq!(rare_build.runtime_reducer, RuntimeReducer::ByteBucket);
        assert_eq!(
            rare_build.uniform_route_selection_work(),
            u64::try_from(
                rare.len()
                    .checked_add(super::UNIFORM_ALPHABET_ZERO_WORK)
                    .and_then(|work| work.checked_add(rare_build.pattern_bytes))
                    .unwrap()
            )
            .unwrap()
        );
        assert!(
            rare_build.selected_anchor_minimum_frequency_rank
                < super::UNIFORM_WORD64_MIN_ANCHOR_FREQUENCY_RANK
        );
        assert!(!rare_build.uniform_resource_declined());

        let unequal = [b"agggtaaa".as_slice(), b"tttaccctt".as_slice()];
        let unequal_plan =
            PackedOrderedLiteralCountPlan::build(&unequal, BuildLimits::unlimited()).unwrap();
        let unequal_build = unequal_plan.build_accounting();
        assert_eq!(unequal_build.runtime_reducer, RuntimeReducer::ByteBucket);
        assert_eq!(unequal_build.uniform_route_selection_work(), 0);
        assert_eq!(unequal_build.selected_anchor_minimum_frequency_rank, 0);
        assert!(!unequal_build.uniform_resource_declined());
    }

    #[test]
    #[cfg(not(feature = "static-dispatch"))]
    fn uniform_word64_alphabet_reuse_boundaries_are_explicit() {
        assert_eq!(super::UNIFORM_WORD64_MAX_DISTINCT_PATTERN_BYTES, 8);
        assert_eq!(super::UNIFORM_WORD64_MIN_ALPHABET_REUSE, 3);

        let exact = [
            b"aaaaaaaa".as_slice(),
            b"bbbbbbbb".as_slice(),
            b"cdefghcd".as_slice(),
        ];
        let exact_plan =
            PackedOrderedLiteralCountPlan::build(&exact, BuildLimits::unlimited()).unwrap();
        let exact_build = exact_plan.build_accounting();
        assert_eq!(exact_build.uniform_distinct_pattern_bytes, 8);
        assert!(exact_build.uniform_alphabet_admitted());
        assert_eq!(exact_build.runtime_reducer, RuntimeReducer::UniformWord64);

        let too_many = [
            b"aaaaaaaa".as_slice(),
            b"bbbbbbbb".as_slice(),
            b"cccccccc".as_slice(),
            b"defghide".as_slice(),
        ];
        let too_many_plan =
            PackedOrderedLiteralCountPlan::build(&too_many, BuildLimits::unlimited()).unwrap();
        let too_many_build = too_many_plan.build_accounting();
        assert_eq!(too_many_build.uniform_distinct_pattern_bytes, 9);
        assert!(!too_many_build.uniform_alphabet_admitted());
        assert_eq!(too_many_build.runtime_reducer, RuntimeReducer::ByteBucket);
        assert!(!too_many_build.uniform_resource_declined());

        let insufficient_reuse = [b"abcdefgh".as_slice(), b"hgfedcba".as_slice()];
        let insufficient_plan =
            PackedOrderedLiteralCountPlan::build(&insufficient_reuse, BuildLimits::unlimited())
                .unwrap();
        let insufficient_build = insufficient_plan.build_accounting();
        assert_eq!(insufficient_build.uniform_distinct_pattern_bytes, 8);
        assert!(!insufficient_build.uniform_alphabet_admitted());
        assert_eq!(
            insufficient_build.runtime_reducer,
            RuntimeReducer::ByteBucket
        );
        assert!(!insufficient_build.uniform_resource_declined());
    }

    #[test]
    #[cfg(not(feature = "static-dispatch"))]
    fn uniform_word64_short_straddling_and_full_lane_shapes_match_regex() {
        let mut eight_by_eight = Vec::new();
        for index in 0_u8..8 {
            let alphabet = b"acgt";
            eight_by_eight.push(vec![
                alphabet[usize::from(index & 3)],
                alphabet[usize::from((index >> 2) & 3)],
                b'g',
                b't',
                b'a',
                b'c',
                b'g',
                b't',
            ]);
        }
        let thirty_two_by_two = vec![vec![b'a'; 32], vec![b'c'; 32]];
        for patterns in [eight_by_eight, thirty_two_by_two] {
            let regex = RegexBuilder::new(&source(&patterns))
                .unicode(false)
                .build()
                .unwrap();
            let count =
                PackedOrderedLiteralCountPlan::build(&patterns, BuildLimits::unlimited()).unwrap();
            let span = PackedOrderedLiteralSpanSumPlan::build(&patterns, BuildLimits::unlimited())
                .unwrap();
            assert_eq!(
                count.build_accounting().runtime_reducer,
                RuntimeReducer::UniformWord64
            );
            assert_eq!(count.build_accounting().uniform_state_positions(), 64);

            let width = patterns[0].len();
            for haystack in [Vec::new(), vec![b'x'; width - 1]] {
                let counted = count.count(&haystack, ReduceLimits::unlimited()).unwrap();
                assert_eq!(counted.count, 0);
                assert_eq!(counted.accounting.actual.shift_and_transitions, 0);
            }

            let mut haystack = vec![b'x'; 15];
            haystack.extend_from_slice(&patterns[0]);
            haystack.extend_from_slice(b"xxx");
            haystack.extend_from_slice(&patterns[1]);
            let expected_count = u64::try_from(regex.find_iter(&haystack).count()).unwrap();
            let expected_span = regex
                .find_iter(&haystack)
                .map(|matched| u64::try_from(matched.len()).unwrap())
                .sum::<u64>();
            assert_eq!(
                count
                    .count(&haystack, ReduceLimits::unlimited())
                    .unwrap()
                    .count,
                expected_count
            );
            assert_eq!(
                span.span_sum(&haystack, ReduceLimits::unlimited())
                    .unwrap()
                    .span_sum,
                expected_span
            );
        }
    }

    #[test]
    #[cfg(not(feature = "static-dispatch"))]
    fn uniform_word64_boundary_and_bounded_prefix_exclusion_are_explicit() {
        assert_eq!(super::UNIFORM_WORD64_MIN_PATTERN_BYTES, 8);
        let width_seven = [b"aaaaaaa".as_slice(), b"ccccccc".as_slice()];
        let below =
            PackedOrderedLiteralCountPlan::build(&width_seven, BuildLimits::unlimited()).unwrap();
        assert_eq!(
            below.build_accounting().runtime_reducer,
            RuntimeReducer::ByteBucket
        );
        assert!(!below.build_accounting().uniform_route_inspected);
        assert_eq!(below.build_accounting().uniform_state_positions(), 0);

        let width_eight = [
            b"00000000".as_slice(),
            b"11111111".as_slice(),
            b"22222222".as_slice(),
            b"33333333".as_slice(),
            b"44444444".as_slice(),
            b"55555555".as_slice(),
            b"66666666".as_slice(),
            b"77777777".as_slice(),
        ];
        let exact =
            PackedOrderedLiteralCountPlan::build(&width_eight, BuildLimits::unlimited()).unwrap();
        let build = exact.build_accounting();
        assert_eq!(build.runtime_reducer, RuntimeReducer::UniformWord64);
        assert_eq!(build.uniform_state_positions(), 64);
        assert_eq!(build.uniform_mask_build_work(), 256 + 64 + 16);
        assert_eq!(build.uniform_mask_bytes(), super::UNIFORM_MASK_BYTES);

        let width_thirteen = [
            b"0000000000000".as_slice(),
            b"1111111111111".as_slice(),
            b"2222222222222".as_slice(),
            b"3333333333333".as_slice(),
            b"4444444444444".as_slice(),
        ];
        let over = PackedOrderedLiteralCountPlan::build(&width_thirteen, BuildLimits::unlimited())
            .unwrap();
        assert_eq!(
            over.build_accounting().runtime_reducer,
            RuntimeReducer::ByteBucket
        );
        assert_eq!(over.build_accounting().uniform_state_positions(), 0);
        assert_eq!(over.build_accounting().uniform_mask_bytes(), 0);

        let bounded = PackedBoundedPrefixLiteralCountPlan::build(
            &[b"ab".as_slice(), b"cd".as_slice()],
            BoundedPrefixBounds {
                minimum: 0,
                maximum: 2,
            },
            BuildLimits::unlimited(),
        )
        .unwrap();
        assert_eq!(
            bounded.build_accounting().runtime_reducer,
            RuntimeReducer::ByteBucket
        );
    }

    #[test]
    fn byte_bucket_owner_and_plan_keep_the_incumbent_layout() {
        use core::mem::{align_of, size_of};
        use fre_simd_kernels::ByteBucketClassifier;

        #[allow(dead_code, reason = "this is an exact mirror of the incumbent layout")]
        struct IncumbentOwner {
            screening_classifier: ByteBucketClassifier,
            classifier: ByteBucketClassifier,
            bucket_patterns: [u16; super::BYTE_BUCKET_COUNT],
            anchor_offset: u8,
            has_non_ascii_anchor_byte: bool,
            anchor_byte_patterns: [u16; 256],
            patterns: [super::PatternMeta; super::CERTIFIED_MAX_PATTERNS],
            encoded_patterns: [u8; super::IDENTITY_CAPACITY_BYTES],
            encoded_len: u16,
        }

        #[allow(dead_code, reason = "this is an exact mirror of the incumbent layout")]
        struct IncumbentAccounting {
            patterns: usize,
            pattern_bytes: usize,
            max_pattern_bytes: usize,
            min_pattern_bytes: usize,
            anchor_offset: usize,
            anchor_has_non_ascii: bool,
            anchor_selection_work: u64,
            mask_columns: usize,
            bucket_assignment_work: u64,
            max_anchor_byte_bucket_patterns: usize,
            max_anchor_byte_bucket_pattern_bytes: usize,
            identity_bytes: usize,
            identity_capacity_bytes: usize,
            build_work_upper_bound: u64,
            build_peak_upper_bound: usize,
            persistent_bytes: usize,
            simd_minimum_haystack_bytes: usize,
            bounded_prefix: Option<super::BoundedPrefixBounds>,
        }

        #[allow(dead_code, reason = "this is an exact mirror of the incumbent layout")]
        struct IncumbentCore {
            owner: Box<IncumbentOwner>,
            build: IncumbentAccounting,
        }

        assert_eq!(size_of::<super::PackedOwner>(), size_of::<IncumbentOwner>());
        assert_eq!(
            align_of::<super::PackedOwner>(),
            align_of::<IncumbentOwner>()
        );
        assert_eq!(
            size_of::<super::BuildAccounting>(),
            size_of::<IncumbentAccounting>()
        );
        assert_eq!(
            align_of::<super::BuildAccounting>(),
            align_of::<IncumbentAccounting>()
        );
        assert_eq!(size_of::<super::PlanCore>(), size_of::<IncumbentCore>());
        assert_eq!(align_of::<super::PlanCore>(), align_of::<IncumbentCore>());
        assert_eq!(
            size_of::<PackedOrderedLiteralCountPlan>(),
            size_of::<IncumbentCore>()
        );

        let below = PackedOrderedLiteralCountPlan::build(
            &[b"aaaaaaa".as_slice(), b"ccccccc".as_slice()],
            BuildLimits::unlimited(),
        )
        .unwrap();
        let build = below.build_accounting();
        assert_eq!(build.runtime_reducer, RuntimeReducer::ByteBucket);
        assert_eq!(
            build.persistent_bytes,
            size_of::<PackedOrderedLiteralCountPlan>() + size_of::<super::PackedOwner>()
        );
    }

    #[test]
    #[cfg(feature = "static-dispatch")]
    fn static_dispatch_retains_the_exact_byte_bucket_transaction() {
        let patterns = [b"agggtaaa".as_slice(), b"tttaccct".as_slice()];
        let attempt =
            PackedOrderedLiteralCountPlan::build_attempt(&patterns, BuildLimits::unlimited())
                .unwrap();
        assert!(attempt.closes());
        let build = attempt.plan().build_accounting();
        let actual = attempt.receipt().actual();
        assert_eq!(build.runtime_reducer, RuntimeReducer::ByteBucket);
        assert!(!build.uniform_shape_candidate());
        assert!(!build.uniform_route_inspected);
        assert_eq!(build.uniform_route_selection_work(), 0);
        assert_eq!(build.uniform_mask_build_work(), 0);
        assert_eq!(build.uniform_mask_bytes(), 0);
        assert_eq!(actual.work, build.build_work_upper_bound);
        assert_eq!(actual.allocations, 1);
        assert_eq!(actual.allocated_bytes, size_of::<super::PackedOwner>());
        assert_eq!(actual.released_allocations, 0);
        assert_eq!(actual.released_bytes, 0);
        assert_eq!(actual.initialized_bytes, build.persistent_bytes);
        assert_eq!(actual.live_persistent_bytes, build.persistent_bytes);
    }

    #[test]
    #[cfg(not(feature = "static-dispatch"))]
    fn uniform_word64_exact_limits_close_without_bucket_counters() {
        let patterns = [b"agggtaaa".as_slice(), b"tttaccct".as_slice()];
        let plan =
            PackedOrderedLiteralCountPlan::build(&patterns, BuildLimits::unlimited()).unwrap();
        let build = plan.build_accounting();
        assert_eq!(build.runtime_reducer, RuntimeReducer::UniformWord64);
        let exact_build = BuildLimits {
            max_patterns: build.patterns,
            max_pattern_bytes: build.max_pattern_bytes,
            max_total_pattern_bytes: build.pattern_bytes,
            max_identity_bytes: build.identity_bytes,
            max_build_work: usize::try_from(build.build_work_upper_bound).unwrap(),
            max_build_peak_bytes: build.build_peak_upper_bound,
            max_persistent_bytes: build.persistent_bytes,
        };
        PackedOrderedLiteralCountPlan::build(&patterns, exact_build).unwrap();
        for constrained in [
            BuildLimits {
                max_build_work: exact_build.max_build_work.checked_sub(1).unwrap(),
                ..exact_build
            },
            BuildLimits {
                max_build_peak_bytes: exact_build.max_build_peak_bytes.checked_sub(1).unwrap(),
                ..exact_build
            },
            BuildLimits {
                max_persistent_bytes: exact_build.max_persistent_bytes.checked_sub(1).unwrap(),
                ..exact_build
            },
        ] {
            let fallback = PackedOrderedLiteralCountPlan::build(&patterns, constrained).unwrap();
            assert_eq!(
                fallback.build_accounting().runtime_reducer,
                RuntimeReducer::ByteBucket
            );
            assert!(fallback.build_accounting().uniform_resource_declined());
        }

        let haystack = b"agggtaaaNtttaccctNagggtaaa";
        let result = plan.count(haystack, ReduceLimits::unlimited()).unwrap();
        let upper = result.accounting.upper_bounds;
        assert_eq!(upper.shift_and_transitions, haystack.len());
        assert_eq!(upper.match_events, haystack.len() / 8);
        let exact_run = ReduceLimits {
            max_work: upper.work,
            max_match_events: upper.match_events,
            max_count: upper.count,
            max_span_sum: u64::MAX,
            max_reducer_steps: upper.reducer_steps,
            max_scratch_bytes: 0,
            max_peak_bytes: upper.peak_bytes,
        };
        plan.count(haystack, exact_run).unwrap();
        assert!(matches!(
            plan.count(
                haystack,
                ReduceLimits {
                    max_work: exact_run.max_work.checked_sub(1).unwrap(),
                    ..exact_run
                }
            ),
            Err(ReduceError::WorkLimit { .. })
        ));

        let span =
            PackedOrderedLiteralSpanSumPlan::build(&patterns, BuildLimits::unlimited()).unwrap();
        let span_result = span.span_sum(haystack, ReduceLimits::unlimited()).unwrap();
        let span_upper = span_result.accounting.upper_bounds;
        span.span_sum(
            haystack,
            ReduceLimits {
                max_span_sum: span_upper.span_sum,
                ..ReduceLimits::unlimited()
            },
        )
        .unwrap();
        assert!(matches!(
            span.span_sum(
                haystack,
                ReduceLimits {
                    max_span_sum: span_upper.span_sum.checked_sub(1).unwrap(),
                    ..ReduceLimits::unlimited()
                }
            ),
            Err(ReduceError::SpanSumLimit { .. })
        ));
    }

    #[test]
    fn ranked_fixed_anchor_preserves_order_and_selects_rare_columns() {
        let split = PackedOrderedLiteralCountPlan::build(&[b"ab", b"ac"], BuildLimits::unlimited())
            .unwrap();
        let split_build = split.build_accounting();
        assert_eq!(split_build.anchor_offset, 1);
        assert_eq!(split_build.max_anchor_byte_bucket_patterns, 1);
        assert_eq!(
            split
                .count(b"abac xx ac", ReduceLimits::unlimited())
                .unwrap()
                .count,
            3
        );

        let english = PackedOrderedLiteralCountPlan::build(
            &[
                b"Sherlock Holmes".as_slice(),
                b"John Watson".as_slice(),
                b"Irene Adler".as_slice(),
                b"Inspector Lestrade".as_slice(),
                b"Professor Moriarty".as_slice(),
            ],
            BuildLimits::unlimited(),
        )
        .unwrap();
        assert_eq!(english.build_accounting().anchor_offset, 0);

        let chinese = PackedOrderedLiteralCountPlan::build(
            &[
                "夏洛克·福尔摩斯".as_bytes(),
                "约翰华生".as_bytes(),
                "阿德勒".as_bytes(),
                "雷斯垂德".as_bytes(),
                "莫里亚蒂教授".as_bytes(),
            ],
            BuildLimits::unlimited(),
        )
        .unwrap();
        let chinese_build = chinese.build_accounting();
        assert_eq!(chinese_build.anchor_offset, 8);
        assert!(chinese_build.anchor_has_non_ascii);
        assert_eq!(
            chinese
                .count(
                    "莫里亚蒂教授和夏洛克·福尔摩斯以及阿德勒".as_bytes(),
                    ReduceLimits::unlimited()
                )
                .unwrap()
                .count,
            3
        );
    }
}
