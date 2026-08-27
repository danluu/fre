//! Stable runtime helper for general FRE AOT regex objects.
//!
//! Runtime-backed object entries have the C ABI
//! `entry(haystack, haystack_len, window_start, window_end, result_out)` and
//! tail-call [`fre_aot_regex_runtime_search_v1`] after inserting their
//! immutable program address as the first argument. A generated complete
//! variable-width endpoint oracle instead calls
//! [`fre_aot_regex_runtime_search_without_endpoint_oracle_v1`] on its short
//! and possible-match fallback paths, avoiding a duplicate portable probe.
//! An exact-width endpoint oracle returns the first accepting boundary and
//! writes the complete result in generated code without calling this runtime.
//!
//! For search calls, status `0` means no match, `1` means match, `2` means an
//! invalid null or misaligned pointer or invalid search window, and `3` means
//! a malformed program or runtime search failure. Prepared searches can also
//! return `4` when another search or a concurrent destroy owns the handle
//! state and `5` for an invalidated or unknown handle. On search status `0` or
//! `1`, `result_out` is initialized as follows:
//!
//! - `Exists`: both fields are zero; only status carries semantic information.
//! - `SelectedEnd`: both fields equal the selected match end.
//! - `Span`: the fields are the selected half-open match span.
//!
//! No result value is promised for status `2` through `5`. Lifecycle calls use
//! status `0` for success. All offsets are relative to the original haystack,
//! including when a sub-window is searched.
//!
//! Runtime-backed callers that search repeatedly can prepare an owned handle
//! once with [`fre_aot_regex_runtime_prepare_v1`], search it with
//! [`fre_aot_regex_runtime_search_prepared_v1`], and release it with
//! [`fre_aot_regex_runtime_destroy_prepared_v1`]. A handle owns its decoded
//! program and workspace; it never borrows the input artifact.
//!
//! Callers that can guarantee exclusive single-threaded ownership may instead
//! use [`fre_aot_regex_runtime_prepare_exclusive_v1`],
//! [`fre_aot_regex_runtime_search_exclusive_v1`], and
//! [`fre_aot_regex_runtime_destroy_exclusive_v1`]. That explicitly unsafe
//! lifecycle passes an opaque allocation pointer directly and therefore pays
//! no registry, reference-count, thread-local, or mutex cost per search.
//! Current compiler-emitted retained-row entries use
//! [`fre_aot_regex_runtime_search_exclusive_partial_preflight_v1`] before
//! native rows execute. That call settles the prior local completion, runs
//! suffix then cut, and combines adaptive admission with exact-window handoff
//! or in-helper K0 completion. A compiler that proves its emitted vectorized
//! root scanner should own an admitted search can instead use
//! [`fre_aot_regex_runtime_search_exclusive_partial_native_root_preflight_v1`];
//! that authenticated call admits first and runs the portable proofs only on
//! a decline. If a native scan then reaches a partial-DFA hole, the current
//! compiler first continues the same exclusive session through
//! [`fre_aot_regex_runtime_search_exclusive_from_partial_preflight_compact_v3`].
//! That entry projects every eligible retained hole into the sealed immutable
//! continuation owner and returns compiler-private status 8; a general
//! projection decline consumes through the unchanged
//! [`fre_aot_regex_runtime_search_exclusive_from_partial_preflight_compact_v2`]
//! path. Their single-use preflight ticket replaces repeated program and
//! window authentication and supplies pending mode from the compact canonical
//! resume-state index without replaying the retained prefix. The
//! fully authenticating
//! [`fre_aot_regex_runtime_search_exclusive_from_partial_v1`] remains available
//! for older generated objects.
//! A resource-bounded slow compiler can keep a larger transient native prefix
//! outside the stable program format. Its eager preflight first tries admitted
//! complete graph proofs, then retains a cheap synchronous object ticket when
//! native execution is still needed. Only a native hole parses and binds the
//! emitted exact frontier descriptor before compact continuation proceeds
//! without replaying completed rows. Current objects use packed wire-V2
//! descriptors through the private ABI-V3/V4 helpers; legacy wire-V1 objects
//! through ABI-V1/V2 remain supported.
//! A variable-width Span table that completes locally with only its selected
//! endpoint uses
//! [`fre_aot_regex_runtime_search_exclusive_recover_partial_span_v1`] to
//! authenticate the preflight window and recover only the selected start.
//! A variable-width dynamic-row entry uses the parallel
//! [`fre_aot_regex_runtime_search_exclusive_dynamic_rows_recover_span_v1`]
//! postflight after selecting its authoritative endpoint natively. Mutable
//! rows and legacy V1/V2 headers authenticate a single-use preflight window;
//! an active immutable V3--V14 owner instead authenticates that same
//! reverse-only postflight directly and remains reusable after success.
//! [`fre_aot_regex_runtime_prepared_partial_should_enter_v1`] remains exported
//! only for compatibility with older generated objects.

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(unsafe_code)]

use std::cell::RefCell;
use std::collections::HashMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex, OnceLock, TryLockError};

use fre_aot_regex::{
    AotOperationAxesV1, AotOperationOutputV1, AotOperationSetV1View,
    CompileError, CompiledProgram, FrozenCompactLoopScanner, FrozenDynamicRowsStorageV3,
    DynamicNativeRowsHoleResolution,
    FrozenPreparedHeaderOwnerGenerationKey, FrozenPreparedHeaderV6,
    FrozenStaticContinuationRowsStorageV1,
    FullyPrefilledFallbackReceipt, GrepCountConstructionReceipt, GrepCountError,
    GrepCountPrepareError, GrepCountReceipt, GrepCountWorkspace, GrepCountWorkspaceLimits,
    FrozenOrderedNfaLimitsV1, FrozenOrderedNfaPreparedScratchV1,
    GenericNfaProgramCensus, MatchResult, OutputContract, StaticPrefixResumeAdmission,
    StaticPrefixResumeAdmissionPlan,
    StaticPrefixResumeDescriptorKey, StaticPrefixResumeSearchOutcome,
    StaticPrefixSpanRecoveryAdmission, FrozenStaticPrefixResumeProjection,
    FROZEN_DYNAMIC_ROWS_V3_FORMAT_VERSION, FROZEN_DYNAMIC_ROWS_V4_FORMAT_VERSION,
    FROZEN_DYNAMIC_ROWS_V8_FORMAT_VERSION, FROZEN_DYNAMIC_ROWS_V9_FORMAT_VERSION,
    FROZEN_DYNAMIC_ROWS_V10_FORMAT_VERSION, FROZEN_DYNAMIC_ROWS_V11_FORMAT_VERSION,
    FROZEN_DYNAMIC_ROWS_V12_FORMAT_VERSION, FROZEN_DYNAMIC_ROWS_V13_FORMAT_VERSION,
    FROZEN_DYNAMIC_ROWS_V14_FORMAT_VERSION, FROZEN_PREPARED_HEADER_V6_BYTES,
    DEFAULT_FROZEN_ORDERED_NFA_V1_MAX_HANDLE_BYTES,
    FROZEN_ORDERED_NFA_V1_MAX_SCRATCH_BYTES, FROZEN_ORDERED_NFA_V1_MAX_SETUP_WORK,
    FROZEN_ORDERED_NFA_V15_MAX_DESCRIPTOR_BYTES,
    FROZEN_DYNAMIC_SIDECAR_MAX_K0_BYTES, FROZEN_DYNAMIC_SIDECAR_MAX_PACKED_BYTES,
    PROGRAM_HEADER_LEN, ProgramFormatError, ProgramWorkspace, RetainedPartialPreflight,
    STATIC_PREFIX_INVOCATION_EPOCH_OFFSET,
    STATIC_PREFIX_RESUME_DESCRIPTOR_V1_HEADER_BYTES,
    STATIC_PREFIX_RESUME_DESCRIPTOR_V1_MAGIC, STATIC_PREFIX_RESUME_DESCRIPTOR_V1_MAX_BYTES,
    STATIC_PREFIX_RESUME_DESCRIPTOR_V1_VERSION, STATIC_PREFIX_RESUME_DESCRIPTOR_V2_HEADER_BYTES,
    STATIC_PREFIX_RESUME_DESCRIPTOR_V2_MAGIC, STATIC_PREFIX_RESUME_DESCRIPTOR_V2_VERSION,
    SearchWindow,
};
use fre_exact_alloc::try_box_preserve;
#[cfg(test)]
use fre_aot_regex::{FrozenPreparedHeaderV2, FrozenPreparedHeaderV3};

mod literal_replacement;
mod operation_set_v2;

pub use literal_replacement::{
    AotLiteralReplacement, AotLiteralReplacementAccounting, AotLiteralReplacementError,
    AotLiteralReplacementLimits, AotMatchStats,
};
pub use operation_set_v2::{
    C_API_OPERATION_SET_V2_HEADER, DEFAULT_OPERATION_SET_V2_MAX_CAPTURE_COUNT,
    DEFAULT_OPERATION_SET_V2_MAX_CAPTURE_EVENTS, DEFAULT_OPERATION_SET_V2_MAX_CAPTURE_OWNER_BYTES,
    DEFAULT_OPERATION_SET_V2_MAX_CAPTURE_VALIDATION_SCRATCH_BYTES,
    DEFAULT_OPERATION_SET_V2_MAX_CAPTURE_WORK, DEFAULT_OPERATION_SET_V2_MAX_CAPTURE_WORKSPACE_BYTES,
    FreAotRegexOperationSetExclusiveHandleV2, FreAotRegexOperationSetOutputV2,
    FreAotRegexOperationSetPrepareConfigV2, OPERATION_SET_OUTPUT_CAPTURE_PARTICIPATION_COUNT,
    OPERATION_SET_PREPARE_CONFIG_V2_SIZE, OPERATION_SET_PREPARE_CONFIG_V2_VERSION,
    fre_aot_regex_runtime_destroy_operation_set_exclusive_v2,
    fre_aot_regex_runtime_execute_operation_set_exclusive_v2,
    fre_aot_regex_runtime_prepare_operation_set_exclusive_v2,
};

/// No match was selected.
pub const STATUS_NO_MATCH: u32 = 0;
/// A match was selected and `result_out` was initialized.
pub const STATUS_MATCH: u32 = 1;
/// A pointer or search-window precondition was invalid.
pub const STATUS_INVALID_ARGUMENT: u32 = 2;
/// Program validation or portable execution failed.
pub const STATUS_RUNTIME_FAILURE: u32 = 3;
/// Another search or a concurrent destroy owns this handle's mutable state.
pub const STATUS_HANDLE_BUSY: u32 = 4;
/// A prepared handle was zero, unknown, destroyed, or concurrently invalidated.
pub const STATUS_INVALID_HANDLE: u32 = 5;
/// Native retained rows were admitted on the returned exact search window.
pub const STATUS_PARTIAL_PREFLIGHT_ENTER: u32 = 6;
/// Compiler-private status selecting an authenticated local static-resume tail.
#[doc(hidden)]
pub const STATUS_STATIC_PREFIX_NATIVE_RESUME: u32 = 7;
/// Compiler-private status selecting the immutable continuation local tail.
#[doc(hidden)]
pub const STATUS_STATIC_PREFIX_NATIVE_CONTINUATION_RESUME: u32 = 8;
/// Compiler-private status returning one newly published dynamic-row cell.
///
/// The result record temporarily carries the fresh native-row descriptor
/// address in `start` and the packed `u32` cell in `end`. Generated code must
/// consume both synchronously and retry the same unread byte locally.
#[doc(hidden)]
pub const STATUS_DYNAMIC_ROWS_CELL_RESUME: u32 = 9;
/// A requested capture object entry was published as an explicit negative.
pub const STATUS_NATIVE_CAPTURE_UNAVAILABLE: u32 = 10;
/// A requested exact-span participation entry was published as an explicit negative.
pub const STATUS_NATIVE_PARTICIPATION_UNAVAILABLE: u32 = 10;
/// Successful status for prepare and destroy lifecycle operations.
pub const STATUS_SUCCESS: u32 = 0;
/// Miss sentinel published by an exact-singleton first-candidate endpoint.
pub const EXACT_SINGLETON_FIRST_CANDIDATE_MISS: u64 = u64::MAX;
/// Miss sentinel published by a matching-LF-line witness endpoint.
pub const MATCHING_LF_LINE_WITNESS_MISS: u64 = u64::MAX;
/// Bytes in the exact SHA-256 semantic-artifact identity accepted by resume.
pub const ARTIFACT_IDENTITY_BYTES: usize = 32;
/// The prepared native retained-row entry should use the ordinary executor.
pub const PARTIAL_ENTRY_BYPASS: u32 = 0;
/// The prepared native retained-row entry should execute its authenticated rows.
pub const PARTIAL_ENTRY_ENTER: u32 = 1;
/// A Span-fill iterator has accepted at least one match.
pub const ITER_HAS_LAST: u32 = 1 << 0;
/// A Span-fill iterator must advance one byte before its next search.
pub const ITER_PENDING_EMPTY: u32 = 1 << 1;
/// A Span-fill iterator is fused and has no further matches.
pub const ITER_FINISHED: u32 = 1 << 2;
/// Every flag accepted in [`FreAotRegexIterStateV1::flags`].
pub const ITER_KNOWN_FLAGS: u32 = ITER_HAS_LAST | ITER_PENDING_EMPTY | ITER_FINISHED;

/// Exact byte size required in [`FreAotRegexPrepareConfigV2::struct_size`].
pub const PREPARE_CONFIG_V2_SIZE: u32 = 64;
/// Exact version required in [`FreAotRegexPrepareConfigV2::config_version`].
pub const PREPARE_CONFIG_V2_VERSION: u32 = 2;
/// Exact byte size required in [`FreAotRegexPrepareConfigV3::struct_size`].
pub const PREPARE_CONFIG_V3_SIZE: u32 = 112;
/// Exact version required in [`FreAotRegexPrepareConfigV3::config_version`].
pub const PREPARE_CONFIG_V3_VERSION: u32 = 3;
/// Default source-independent work cap for complete start-filter settlement.
pub const DEFAULT_START_FILTER_SETUP_WORK: u64 = 100_000_000;
/// Default logical fixed-store byte cap for prepared GrepCount.
pub const DEFAULT_GREP_COUNT_WORKSPACE_BYTES: u64 = 67_108_864;
/// Prepare the ordinary scalar Search operation before source access.
pub const PREPARE_OPERATION_SEARCH: u64 = 1 << 0;
/// Prepare repeated non-overlapping Count before source access.
pub const PREPARE_OPERATION_COUNT: u64 = 1 << 1;
/// Prepare repeated non-overlapping SpanSum before source access.
pub const PREPARE_OPERATION_SPAN_SUM: u64 = 1 << 2;
/// Prepare whole-haystack matching-line Count before source access.
pub const PREPARE_OPERATION_GREP_COUNT: u64 = 1 << 3;
/// Every operation flag accepted by [`FreAotRegexPrepareConfigV2`].
pub const PREPARE_OPERATION_KNOWN_FLAGS: u64 = PREPARE_OPERATION_SEARCH
    | PREPARE_OPERATION_COUNT
    | PREPARE_OPERATION_SPAN_SUM
    | PREPARE_OPERATION_GREP_COUNT;
/// Require an authenticated native Ordered-TNFA V15 scratch capability.
pub const PREPARE_CAPABILITY_ORDERED_NFA_V15: u64 = 1 << 0;
/// Every capability bit accepted by [`FreAotRegexPrepareConfigV3`].
pub const PREPARE_CAPABILITY_KNOWN_FLAGS: u64 = PREPARE_CAPABILITY_ORDERED_NFA_V15;

/// Exact byte size required in [`FreAotRegexOperationSetPrepareConfigV1::struct_size`].
pub const OPERATION_SET_PREPARE_CONFIG_V1_SIZE: u32 = 64;
/// Exact version required in
/// [`FreAotRegexOperationSetPrepareConfigV1::config_version`].
pub const OPERATION_SET_PREPARE_CONFIG_V1_VERSION: u32 = 1;
/// Default whole-handle retained-payload cap for a prepared operation set.
pub const DEFAULT_OPERATION_SET_MAX_HANDLE_BYTES: u64 = 1_073_741_824;
/// Search output kind binding an `Exists` member contract.
pub const OPERATION_SET_OUTPUT_SEARCH_EXISTS: u32 = 1;
/// Search output kind binding a `SelectedEnd` member contract.
pub const OPERATION_SET_OUTPUT_SEARCH_SELECTED_END: u32 = 2;
/// Search output kind binding a `Span` member contract.
pub const OPERATION_SET_OUTPUT_SEARCH_SPAN: u32 = 3;
/// Scalar non-overlapping match-count output kind.
pub const OPERATION_SET_OUTPUT_COUNT: u32 = 4;
/// Scalar selected-span-width-sum output kind.
pub const OPERATION_SET_OUTPUT_SPAN_SUM: u32 = 5;
/// Scalar matching-line-count output kind.
pub const OPERATION_SET_OUTPUT_GREP_COUNT: u32 = 6;

/// Bounded preparation policy for one complete Stage-1 operation set.
///
/// All limits apply once to the complete handle, not independently to each
/// member. `max_handle_bytes` covers retained owner payload: the final owner,
/// vector capacities, decoded generic graphs, ordinary K0 workspaces,
/// optional start-filter proofs, and `GrepCount` stores. It excludes transient
/// construction allocations, allocator metadata, and the unretained input
/// wire. Admitted proof payload maxima and exact `GrepCount` logical stores are
/// checked before allocating those auxiliary owners; actual final capacities
/// are checked again before publication. Reserved words must be zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct FreAotRegexOperationSetPrepareConfigV1 {
    /// Must equal [`OPERATION_SET_PREPARE_CONFIG_V1_SIZE`].
    pub struct_size: u32,
    /// Must equal [`OPERATION_SET_PREPARE_CONFIG_V1_VERSION`].
    pub config_version: u32,
    /// Maximum complete retained owner payload.
    pub max_handle_bytes: u64,
    /// Maximum total source-free start-filter setup work.
    pub max_start_filter_setup_work: u64,
    /// Maximum total logical `GrepCount` fixed-store bytes.
    pub max_grep_count_workspace_bytes: u64,
    /// Must contain four zero words.
    pub reserved: [u64; 4],
}

impl FreAotRegexOperationSetPrepareConfigV1 {
    /// Construct the established bounded Stage-1 policy.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            struct_size: OPERATION_SET_PREPARE_CONFIG_V1_SIZE,
            config_version: OPERATION_SET_PREPARE_CONFIG_V1_VERSION,
            max_handle_bytes: DEFAULT_OPERATION_SET_MAX_HANDLE_BYTES,
            max_start_filter_setup_work: DEFAULT_START_FILTER_SETUP_WORK,
            max_grep_count_workspace_bytes: DEFAULT_GREP_COUNT_WORKSPACE_BYTES,
            reserved: [0; 4],
        }
    }

    const fn is_valid(self) -> bool {
        self.struct_size == OPERATION_SET_PREPARE_CONFIG_V1_SIZE
            && self.config_version == OPERATION_SET_PREPARE_CONFIG_V1_VERSION
            && self.reserved[0] == 0
            && self.reserved[1] == 0
            && self.reserved[2] == 0
            && self.reserved[3] == 0
    }
}

impl Default for FreAotRegexOperationSetPrepareConfigV1 {
    fn default() -> Self {
        Self::new()
    }
}

const _: () = assert!(
    std::mem::size_of::<FreAotRegexOperationSetPrepareConfigV1>() == 64
);
const _: () = assert!(
    std::mem::align_of::<FreAotRegexOperationSetPrepareConfigV1>()
        == std::mem::align_of::<u64>()
);
const _: () = assert!(
    std::mem::offset_of!(FreAotRegexOperationSetPrepareConfigV1, struct_size) == 0
);
const _: () = assert!(
    std::mem::offset_of!(FreAotRegexOperationSetPrepareConfigV1, config_version) == 4
);
const _: () = assert!(
    std::mem::offset_of!(FreAotRegexOperationSetPrepareConfigV1, max_handle_bytes) == 8
);
const _: () = assert!(
    std::mem::offset_of!(
        FreAotRegexOperationSetPrepareConfigV1,
        max_start_filter_setup_work
    ) == 16
);
const _: () = assert!(
    std::mem::offset_of!(
        FreAotRegexOperationSetPrepareConfigV1,
        max_grep_count_workspace_bytes
    ) == 24
);
const _: () = assert!(
    std::mem::offset_of!(FreAotRegexOperationSetPrepareConfigV1, reserved) == 32
);

/// Versioned operation declaration for exclusive prepared AOT handles.
///
/// Reserved words must be zero. Count and SpanSum declarations require a
/// program compiled for [`OutputContract::Span`]. A start-filter work cap that
/// cannot admit the complete graph-only proof permanently selects ordinary K0
/// and succeeds. A requested GrepCount workspace must fit its byte cap or the
/// complete preparation transaction fails. The declaration covers operations
/// entered through this runtime handle, not extra descriptors owned by a
/// compiler-produced native-fused object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct FreAotRegexPrepareConfigV2 {
    /// Must equal [`PREPARE_CONFIG_V2_SIZE`].
    pub struct_size: u32,
    /// Must equal [`PREPARE_CONFIG_V2_VERSION`].
    pub config_version: u32,
    /// Bitwise union of the `PREPARE_OPERATION_*` declarations.
    pub operation_flags: u64,
    /// Maximum conservative work admitted for complete graph-only proof setup.
    pub max_start_filter_setup_work: u64,
    /// Maximum bytes in GrepCount's three logical `u64` payload stores.
    ///
    /// `Vec` owners and allocator overhead are not charged to this cap.
    pub max_grep_count_workspace_bytes: u64,
    /// Must contain four zero words.
    pub reserved: [u64; 4],
}

impl FreAotRegexPrepareConfigV2 {
    /// Construct a versioned declaration with the established bounded setup
    /// defaults. `operation_flags` must contain only known operation bits.
    #[must_use]
    pub const fn new(operation_flags: u64) -> Self {
        Self {
            struct_size: PREPARE_CONFIG_V2_SIZE,
            config_version: PREPARE_CONFIG_V2_VERSION,
            operation_flags,
            max_start_filter_setup_work: DEFAULT_START_FILTER_SETUP_WORK,
            max_grep_count_workspace_bytes: DEFAULT_GREP_COUNT_WORKSPACE_BYTES,
            reserved: [0; 4],
        }
    }

    const fn is_valid(self) -> bool {
        self.struct_size == PREPARE_CONFIG_V2_SIZE
            && self.config_version == PREPARE_CONFIG_V2_VERSION
            && self.operation_flags & !PREPARE_OPERATION_KNOWN_FLAGS == 0
            && self.reserved[0] == 0
            && self.reserved[1] == 0
            && self.reserved[2] == 0
            && self.reserved[3] == 0
    }
}

const _: () = assert!(std::mem::size_of::<FreAotRegexPrepareConfigV2>() == 64);
const _: () = assert!(
    std::mem::align_of::<FreAotRegexPrepareConfigV2>() == std::mem::align_of::<u64>()
);
const _: () = assert!(std::mem::offset_of!(FreAotRegexPrepareConfigV2, struct_size) == 0);
const _: () = assert!(std::mem::offset_of!(FreAotRegexPrepareConfigV2, config_version) == 4);
const _: () = assert!(std::mem::offset_of!(FreAotRegexPrepareConfigV2, operation_flags) == 8);
const _: () = assert!(
    std::mem::offset_of!(FreAotRegexPrepareConfigV2, max_start_filter_setup_work) == 16
);
const _: () = assert!(
    std::mem::offset_of!(
        FreAotRegexPrepareConfigV2,
        max_grep_count_workspace_bytes
    ) == 24
);
const _: () = assert!(std::mem::offset_of!(FreAotRegexPrepareConfigV2, reserved) == 32);

/// Additive preparation declaration for native Ordered-TNFA scratch.
///
/// V3 repeats the complete 64-byte V2 prefix and assigns new named fields
/// after it; V2's four reserved words remain reserved and are never
/// reinterpreted.
/// When `required_capabilities` selects V15, a Count or SpanSum declaration
/// requires Ordered-TNFA admission; structural, allocation, or cap refusal
/// fails the transaction rather than publishing a helper-only handle for a
/// native-only object. Without that bit, V3 preserves the complete V2 path.
/// On admission,
/// `max_handle_bytes` charges exactly the scratch descriptor and four Pike
/// payload allocations, while the graph remains authenticated object-local
/// read-only data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct FreAotRegexPrepareConfigV3 {
    /// Must equal [`PREPARE_CONFIG_V3_SIZE`].
    pub struct_size: u32,
    /// Must equal [`PREPARE_CONFIG_V3_VERSION`].
    pub config_version: u32,
    /// Bitwise union of the `PREPARE_OPERATION_*` declarations.
    pub operation_flags: u64,
    /// Maximum conservative work admitted for complete graph-only proof setup.
    pub max_start_filter_setup_work: u64,
    /// Maximum bytes in GrepCount's three logical `u64` payload stores.
    pub max_grep_count_workspace_bytes: u64,
    /// The complete V2 reserved tail; every word must remain zero.
    pub v2_reserved: [u64; 4],
    /// Maximum retained bytes for the Ordered-TNFA scratch owner.
    pub max_handle_bytes: u64,
    /// Maximum bytes for its exact four Pike payloads plus descriptor.
    pub max_ordered_nfa_scratch_bytes: u64,
    /// Maximum source-independent Pike scratch construction work.
    pub max_ordered_nfa_setup_work: u64,
    /// Capabilities the compiled object declares mandatory for these entries.
    pub required_capabilities: u64,
    /// Must contain two zero words.
    pub reserved: [u64; 2],
}

impl FreAotRegexPrepareConfigV3 {
    /// Construct V3 with the sealed-census generic limits.
    #[must_use]
    pub const fn new(operation_flags: u64) -> Self {
        Self {
            struct_size: PREPARE_CONFIG_V3_SIZE,
            config_version: PREPARE_CONFIG_V3_VERSION,
            operation_flags,
            max_start_filter_setup_work: DEFAULT_START_FILTER_SETUP_WORK,
            max_grep_count_workspace_bytes: DEFAULT_GREP_COUNT_WORKSPACE_BYTES,
            v2_reserved: [0; 4],
            max_handle_bytes: DEFAULT_FROZEN_ORDERED_NFA_V1_MAX_HANDLE_BYTES as u64,
            max_ordered_nfa_scratch_bytes: FROZEN_ORDERED_NFA_V1_MAX_SCRATCH_BYTES as u64,
            max_ordered_nfa_setup_work: FROZEN_ORDERED_NFA_V1_MAX_SETUP_WORK,
            required_capabilities: 0,
            reserved: [0; 2],
        }
    }

    const fn is_valid(self) -> bool {
        self.struct_size == PREPARE_CONFIG_V3_SIZE
            && self.config_version == PREPARE_CONFIG_V3_VERSION
            && self.operation_flags & !PREPARE_OPERATION_KNOWN_FLAGS == 0
            && self.v2_reserved[0] == 0
            && self.v2_reserved[1] == 0
            && self.v2_reserved[2] == 0
            && self.v2_reserved[3] == 0
            && self.required_capabilities & !PREPARE_CAPABILITY_KNOWN_FLAGS == 0
            && (self.required_capabilities & PREPARE_CAPABILITY_ORDERED_NFA_V15 == 0
                || self.operation_flags
                    & (PREPARE_OPERATION_COUNT | PREPARE_OPERATION_SPAN_SUM)
                    != 0)
            && self.reserved[0] == 0
            && self.reserved[1] == 0
    }

    const fn v2_prefix(self) -> FreAotRegexPrepareConfigV2 {
        FreAotRegexPrepareConfigV2 {
            struct_size: PREPARE_CONFIG_V2_SIZE,
            config_version: PREPARE_CONFIG_V2_VERSION,
            operation_flags: self.operation_flags,
            max_start_filter_setup_work: self.max_start_filter_setup_work,
            max_grep_count_workspace_bytes: self.max_grep_count_workspace_bytes,
            reserved: [0; 4],
        }
    }
}

const _: () = assert!(std::mem::size_of::<FreAotRegexPrepareConfigV3>() == 112);
const _: () = assert!(
    std::mem::align_of::<FreAotRegexPrepareConfigV3>() == std::mem::align_of::<u64>()
);
const _: () = assert!(std::mem::offset_of!(FreAotRegexPrepareConfigV3, struct_size) == 0);
const _: () = assert!(std::mem::offset_of!(FreAotRegexPrepareConfigV3, config_version) == 4);
const _: () = assert!(std::mem::offset_of!(FreAotRegexPrepareConfigV3, operation_flags) == 8);
const _: () = assert!(
    std::mem::offset_of!(FreAotRegexPrepareConfigV3, max_start_filter_setup_work) == 16
);
const _: () = assert!(
    std::mem::offset_of!(FreAotRegexPrepareConfigV3, max_grep_count_workspace_bytes) == 24
);
const _: () = assert!(std::mem::offset_of!(FreAotRegexPrepareConfigV3, v2_reserved) == 32);
const _: () = assert!(std::mem::offset_of!(FreAotRegexPrepareConfigV3, max_handle_bytes) == 64);
const _: () = assert!(
    std::mem::offset_of!(FreAotRegexPrepareConfigV3, max_ordered_nfa_scratch_bytes) == 72
);
const _: () = assert!(
    std::mem::offset_of!(FreAotRegexPrepareConfigV3, max_ordered_nfa_setup_work) == 80
);
const _: () = assert!(
    std::mem::offset_of!(FreAotRegexPrepareConfigV3, required_capabilities) == 88
);
const _: () = assert!(std::mem::offset_of!(FreAotRegexPrepareConfigV3, reserved) == 96);

/// C declarations for the complete stable V1 runtime ABI.
///
/// The declarations use a process-local integer token rather than exposing a
/// Rust allocation address. Copying a token is allowed, but it is not a
/// security credential and becomes invalid after a successful destroy.
pub const C_API_V1_HEADER: &str = include_str!("../include/fre_aot_regex_runtime_v1.h");

/// C declarations for the additive operation-aware V2 preparation ABI.
pub const C_API_V2_HEADER: &str = include_str!("../include/fre_aot_regex_runtime_v2.h");
/// C declarations for additive native Ordered-TNFA preparation.
pub const C_API_V3_HEADER: &str = include_str!("../include/fre_aot_regex_runtime_v3.h");
/// C declarations for helper-free identity-suffixed native capture entries.
pub const C_API_NATIVE_CAPTURE_V1_HEADER: &str =
    include_str!("../include/fre_aot_regex_runtime_captures_v1.h");
/// C declarations for helper-free identity-suffixed participation entries.
pub const C_API_NATIVE_PARTICIPATION_V1_HEADER: &str =
    include_str!("../include/fre_aot_regex_runtime_participation_v1.h");

/// C declarations for the bounded Stage-1 operation-set runtime ABI.
pub const C_API_OPERATION_SET_V1_HEADER: &str =
    include_str!("../include/fre_aot_regex_runtime_operation_set_v1.h");

/// C-layout result shared by runtime-backed and directly lowered AOT entries.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct FreAotRegexResultV1 {
    pub start: usize,
    pub end: usize,
}

/// One capture group produced by a native capture object entry.
///
/// `{usize::MAX, usize::MAX}` is the only unmatched representation. Equal
/// in-range offsets represent a participating empty group.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct FreAotRegexCaptureSlotV1 {
    pub start: usize,
    pub end: usize,
}

impl FreAotRegexCaptureSlotV1 {
    pub const UNMATCHED: Self = Self {
        start: usize::MAX,
        end: usize::MAX,
    };
}

impl Default for FreAotRegexCaptureSlotV1 {
    fn default() -> Self {
        Self::UNMATCHED
    }
}

#[cfg(target_pointer_width = "64")]
const _: () = assert!(std::mem::size_of::<FreAotRegexCaptureSlotV1>() == 16);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(std::mem::align_of::<FreAotRegexCaptureSlotV1>() == 8);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(std::mem::offset_of!(FreAotRegexCaptureSlotV1, start) == 0);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(std::mem::offset_of!(FreAotRegexCaptureSlotV1, end) == 8);

/// Object-local exact-span capture materializer. Selected implementations do
/// not enter this runtime crate; this type only declares their stable ABI.
pub type FreAotRegexCaptureMaterializeV1 = unsafe extern "C" fn(
    *const u8,
    usize,
    usize,
    usize,
    *mut FreAotRegexCaptureSlotV1,
    usize,
) -> u32;

/// Object-local non-overlapping capture iterator. Selected implementations do
/// not enter this runtime crate; this type only declares their stable ABI.
pub type FreAotRegexCaptureNextV1 = unsafe extern "C" fn(
    *const u8,
    usize,
    *mut FreAotRegexIterStateV1,
    *mut FreAotRegexCaptureSlotV1,
    usize,
) -> u32;

/// Identity-suffixed whole-operation capture-participation scalar. Selected
/// entries publish `value_out` only on [`STATUS_SUCCESS`].
pub type FreAotRegexCaptureReducerV1 =
    unsafe extern "C" fn(*const u8, usize, *mut u64) -> u32;

/// Identity-suffixed whole-operation capture-participation scalar with exact
/// receipt-sized caller-owned scratch. The scratch and output extents must be
/// writable, naturally aligned, nonoverlapping, and disjoint from a nonempty
/// haystack. Entries publish `value_out` only on [`STATUS_SUCCESS`] and never
/// retain the scratch pointer after return.
pub type FreAotRegexCaptureReducerScratchV1 =
    unsafe extern "C" fn(*const u8, usize, *mut u8, usize, *mut u64) -> u32;

/// Complete request for an object-local exact-span participation replay.
///
/// `bundle` must be the paired identity-suffixed bundle symbol from the same
/// linked object as the entry. The exact span must have been returned by that
/// object's ordinary full-window Span selector. Selected entries require
/// naturally aligned caller-owned scratch of the exact extent in the paired
/// receipt. DFA entries require 16 reserved bytes and do not read or write
/// them. Ordered-NFA entries use their larger receipt-sized extent as
/// transient replay state and may overwrite it. No selected entry retains the
/// pointer after return. Selected entries publish `count_out` only on
/// [`STATUS_MATCH`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct FreAotRegexParticipationRequestV1 {
    pub bundle: *const u8,
    pub haystack: *const u8,
    pub haystack_len: usize,
    pub match_start: usize,
    pub match_end: usize,
    pub scratch: *mut u8,
    pub scratch_len: usize,
    pub count_out: *mut usize,
}

/// Object-local helper-free participation replay entry.
pub type FreAotRegexParticipationExactV1 =
    unsafe extern "C" fn(*const FreAotRegexParticipationRequestV1) -> u32;

#[cfg(target_pointer_width = "64")]
const _: () = assert!(std::mem::size_of::<FreAotRegexParticipationRequestV1>() == 64);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(std::mem::align_of::<FreAotRegexParticipationRequestV1>() == 8);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(std::mem::offset_of!(FreAotRegexParticipationRequestV1, bundle) == 0);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(std::mem::offset_of!(FreAotRegexParticipationRequestV1, haystack) == 8);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(std::mem::offset_of!(FreAotRegexParticipationRequestV1, haystack_len) == 16);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(std::mem::offset_of!(FreAotRegexParticipationRequestV1, match_start) == 24);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(std::mem::offset_of!(FreAotRegexParticipationRequestV1, match_end) == 32);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(std::mem::offset_of!(FreAotRegexParticipationRequestV1, scratch) == 40);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(std::mem::offset_of!(FreAotRegexParticipationRequestV1, scratch_len) == 48);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(std::mem::offset_of!(FreAotRegexParticipationRequestV1, count_out) == 56);

/// One root-aligned result from a successful operation-set execution.
///
/// `kind` binds the operation and, for Search, the member output contract.
/// Search records use status zero/one for no-match/match and encode offsets in
/// `first`/`second`. Scalar records use success status zero, place their value
/// in `first`, and keep `second` zero.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct FreAotRegexOperationSetOutputV1 {
    pub kind: u32,
    pub status: u32,
    pub first: u64,
    pub second: u64,
}

const _: () = assert!(std::mem::size_of::<FreAotRegexOperationSetOutputV1>() == 24);
const _: () = assert!(
    std::mem::align_of::<FreAotRegexOperationSetOutputV1>() == std::mem::align_of::<u64>()
);
const _: () = assert!(std::mem::offset_of!(FreAotRegexOperationSetOutputV1, kind) == 0);
const _: () = assert!(std::mem::offset_of!(FreAotRegexOperationSetOutputV1, status) == 4);
const _: () = assert!(std::mem::offset_of!(FreAotRegexOperationSetOutputV1, first) == 8);
const _: () = assert!(std::mem::offset_of!(FreAotRegexOperationSetOutputV1, second) == 16);

/// Caller-owned continuation state for a compiler-produced prepared Span-fill
/// entry.
///
/// The all-zero value begins an iteration at byte zero. The same state must be
/// passed to every refill for one haystack. Once [`ITER_FINISHED`] is set, the
/// iterator is fused and later refills return no matches. `reserved` must be
/// zero and `flags` may contain only [`ITER_KNOWN_FLAGS`]. `next_start` and an
/// active `last_match_end` must be in bounds. [`ITER_PENDING_EMPTY`] requires
/// [`ITER_HAS_LAST`] and equal next/last offsets; a finished state cannot be
/// pending.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct FreAotRegexIterStateV1 {
    pub next_start: usize,
    pub last_match_end: usize,
    pub flags: u32,
    pub reserved: u32,
}

/// One independent byte haystack accepted by a compiler-produced Exists-batch
/// entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct FreAotRegexHaystackV1 {
    pub ptr: *const u8,
    pub len: usize,
}

impl Default for FreAotRegexHaystackV1 {
    fn default() -> Self {
        Self {
            ptr: std::ptr::null(),
            len: 0,
        }
    }
}

/// Compiler-produced, stateful Span-fill entry for one exclusively prepared
/// program.
///
/// An all-zero [`FreAotRegexIterStateV1`] starts iteration. Status zero means
/// the state is finished; status one means the capacity filled and another
/// call may be required. `written_out` is always required and, after argument
/// validation, contains the initialized result prefix length. A zero capacity
/// is a valid progress probe: `results` may be null and the entry returns zero
/// only for an already-finished state. A later search failure preserves the
/// initialized prefix, marks the state finished, and returns the underlying
/// error status.
pub type FreAotRegexExclusiveSpanFillV1 = unsafe extern "C" fn(
    FreAotRegexExclusiveHandleV1,
    *const u8,
    usize,
    *mut FreAotRegexIterStateV1,
    *mut FreAotRegexResultV1,
    usize,
    *mut usize,
) -> u32;

/// Compiler-produced Exists-batch entry for one exclusively prepared program.
///
/// Status zero means all independent haystacks were processed. After argument
/// validation, `processed_out` contains the initialized prefix length and each
/// corresponding output byte is exactly zero or one. A later invalid input or
/// search failure preserves that prefix. A zero input count is valid, permits
/// null input/output arrays, and publishes a processed count of zero.
pub type FreAotRegexExclusiveExistsBatchV1 = unsafe extern "C" fn(
    FreAotRegexExclusiveHandleV1,
    *const FreAotRegexHaystackV1,
    usize,
    *mut u8,
    *mut usize,
) -> u32;

/// Compiler-produced handle-free Exists-batch entry for a self-contained
/// direct program.
///
/// Status zero means all independent haystacks were processed. After top-level
/// argument validation, `processed_out` is initialized to zero. When the call
/// returns, it counts the completely initialized `matched_out` prefix; every
/// initialized byte is exactly zero or one. A later invalid descriptor or
/// ordinary-entry failure returns the exact completed prefix. A zero input
/// count is valid, permits null input/output arrays, and publishes a processed
/// count of zero.
///
/// For a nonzero count, the descriptor and output arrays are live for the
/// complete call, every descriptor pointer is nonnull even for an empty
/// haystack, and its length is in the signed address domain. Input and output
/// extents do not overlap.
pub type FreAotRegexIndependentExistsBatchV1 = unsafe extern "C" fn(
    *const FreAotRegexHaystackV1,
    usize,
    *mut u8,
    *mut usize,
) -> u32;

/// Compiler-produced exact-singleton whole-haystack earliest-candidate entry.
///
/// Status [`STATUS_SUCCESS`] publishes either the inclusive final-byte offset
/// of the earliest full match or [`EXACT_SINGLETON_FIRST_CANDIDATE_MISS`].
/// Every nonzero status leaves `inclusive_final_byte_out` untouched.
pub type FreAotRegexExactSingletonFirstCandidateV1 =
    unsafe extern "C" fn(*const u8, usize, *mut u64) -> u32;

/// Compiler-produced whole-haystack matching-LF-line witness entry.
///
/// Status [`STATUS_SUCCESS`] publishes either a byte offset on an LF-delimited
/// line known to contain a match or [`MATCHING_LF_LINE_WITNESS_MISS`]. A hit is
/// a candidate line witness, not an exact match boundary or inclusive final
/// byte. Every nonzero status leaves `matching_line_byte_out` untouched. The
/// haystack pointer is nonnull and readable for its signed-address-domain
/// length, including a nonnull zero-length pointer. The output is nonnull,
/// naturally aligned, writable for one `u64`, and disjoint from the haystack.
pub type FreAotRegexMatchingLfLineWitnessV1 =
    unsafe extern "C" fn(*const u8, usize, *mut u64) -> u32;

/// Compiler-produced full-haystack Count entry for one exclusively prepared
/// Span program.
///
/// Status zero means the complete non-overlapping byte iteration succeeded,
/// including when its value is zero. On success `value_out` is initialized to
/// the number of selected matches. Every nonzero status leaves `value_out`
/// untouched.
pub type FreAotRegexExclusiveCountV1 = unsafe extern "C" fn(
    FreAotRegexExclusiveHandleV1,
    *const u8,
    usize,
    *mut u64,
) -> u32;

/// Compiler-produced full-haystack matched-byte-sum entry for one exclusively
/// prepared Span program.
///
/// Status zero means the complete non-overlapping byte iteration succeeded.
/// On success `value_out` is initialized to the sum of every selected
/// half-open match width. Every nonzero status leaves `value_out` untouched.
pub type FreAotRegexExclusiveSpanSumV1 = unsafe extern "C" fn(
    FreAotRegexExclusiveHandleV1,
    *const u8,
    usize,
    *mut u64,
) -> u32;

/// Compiler-produced whole-haystack matching-line Count entry.
///
/// Status zero initializes `value_out` with the number of matching semantic
/// LF/CRLF line domains. Every nonzero status leaves it untouched. This
/// operation is independent of the prepared program's search output contract.
pub type FreAotRegexExclusiveGrepCountV1 = unsafe extern "C" fn(
    FreAotRegexExclusiveHandleV1,
    *const u8,
    usize,
    *mut u64,
) -> u32;

/// C-layout exact search window returned to an admitted native retained table.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct FreAotRegexSearchWindowV1 {
    pub start: usize,
    pub end: usize,
}

/// Exact admitted window and identity-authenticated ordinary K0 rows.
///
/// This private record carries the immutable, process-unique workspace cache
/// identity separately. The `cache_generation` field name is retained for the
/// private V1 ABI layout, but the value is neither a mutable generation counter
/// nor a single-use ticket. V1, V2, and V3 producers initialize it for older
/// private callers. V4 and V5 leave it untouched; generated code instead
/// reloads the same identity from the trusted descriptor only on a continuation
/// side exit. The
/// descriptor and its exposed-provenance addresses are valid only for the
/// synchronous native scan admitted by this preflight and must not survive a
/// helper call or re-entry.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct FreAotRegexDynamicRowsPreflightV1 {
    pub start: usize,
    pub end: usize,
    pub native_rows_address: usize,
    pub cache_generation: u64,
}

/// Compiler-private V6 dynamic-row preflight return registers.
///
/// The two native words map to the ordinary C aggregate return registers:
/// RAX/RDX on x86-64 SysV and Darwin, and X0/X1 on AAPCS64. The descriptor is
/// nonzero only when `status` is [`STATUS_PARTIAL_PREFLIGHT_ENTER`].
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct FreAotRegexDynamicRowsPreflightResultV6 {
    pub status: usize,
    pub native_rows_address: usize,
}

/// Compiler-private payload for one exact first-unpublished-cell handoff.
///
/// The exact admitted window remains in the search helper's ordinary arguments.
/// This record carries only the dynamic cache frontier and committed endpoint;
/// generated code allocates it in its synchronous call frame.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct FreAotRegexDynamicRowsContinuationV1 {
    pub current_row: usize,
    pub resume_position: usize,
    /// Low bit: pending endpoint present. Upper bits: emitted root-scanner
    /// hits whose extra logical reads precede the unread DFA cell.
    pub pending_valid: usize,
    pub pending_end: usize,
    pub cache_identity: u64,
}

/// One selected half-open byte match borrowing its original haystack.
///
/// Offsets and [`Self::as_bytes`] always refer to the complete haystack used to
/// construct the match, whether through [`Self::from_span`],
/// [`PreparedAotRegex::find`], [`PreparedAotRegex::find_at`], or
/// [`PreparedAotRegex::find_iter`].
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct AotMatch<'h> {
    haystack: &'h [u8],
    start: usize,
    end: usize,
}

impl<'h> AotMatch<'h> {
    /// Construct a borrowed match after checking its half-open span.
    ///
    /// Returns `None` unless `start <= end <= haystack.len()`.
    #[must_use]
    pub const fn from_span(haystack: &'h [u8], start: usize, end: usize) -> Option<Self> {
        if start <= end && end <= haystack.len() {
            Some(Self {
                haystack,
                start,
                end,
            })
        } else {
            None
        }
    }

    /// Start byte offset in the original haystack.
    #[must_use]
    pub const fn start(&self) -> usize {
        self.start
    }

    /// Exclusive end byte offset in the original haystack.
    #[must_use]
    pub const fn end(&self) -> usize {
        self.end
    }

    /// Length of this match in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    /// Whether this match contains no bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.start == self.end
    }

    /// Half-open byte range in the original haystack.
    #[must_use]
    pub const fn range(&self) -> std::ops::Range<usize> {
        self.start..self.end
    }

    /// Bytes selected from the original haystack.
    #[must_use]
    pub fn as_bytes(&self) -> &'h [u8] {
        &self.haystack[self.start..self.end]
    }
}

impl std::fmt::Debug for AotMatch<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AotMatch")
            .field("start", &self.start())
            .field("end", &self.end())
            .field("bytes", &DebugMatchBytes(self.as_bytes()))
            .finish()
    }
}

struct DebugMatchBytes<'a>(&'a [u8]);

impl std::fmt::Debug for DebugMatchBytes<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("\"")?;
        let mut bytes = self.0;
        while !bytes.is_empty() {
            match std::str::from_utf8(bytes) {
                Ok(valid) => {
                    write_debug_match_str(formatter, valid)?;
                    bytes = &[];
                }
                Err(error) => {
                    let valid_up_to = error.valid_up_to();
                    let valid = std::str::from_utf8(&bytes[..valid_up_to])
                        .expect("UTF-8 error's valid prefix must decode");
                    write_debug_match_str(formatter, valid)?;
                    write!(formatter, r"\x{:02x}", bytes[valid_up_to])?;
                    bytes = &bytes[valid_up_to.saturating_add(1)..];
                }
            }
        }
        formatter.write_str("\"")
    }
}

fn write_debug_match_str(formatter: &mut std::fmt::Formatter<'_>, valid: &str) -> std::fmt::Result {
    for character in valid.chars() {
        match character {
            '\0' => formatter.write_str("\\0")?,
            '\u{1}'..='\u{8}' | '\u{b}' | '\u{c}' | '\u{e}'..='\u{19}' | '\u{7f}' => {
                write!(formatter, "\\x{:02x}", u32::from(character))?;
            }
            _ => write!(formatter, "{}", character.escape_debug())?,
        }
    }
    Ok(())
}

impl<'h> From<AotMatch<'h>> for &'h [u8] {
    fn from(matched: AotMatch<'h>) -> Self {
        matched.as_bytes()
    }
}

impl From<AotMatch<'_>> for std::ops::Range<usize> {
    fn from(matched: AotMatch<'_>) -> Self {
        matched.range()
    }
}

/// Failure while using a prepared artifact as a span finder.
#[derive(Debug)]
pub enum AotRegexFindError {
    /// The artifact was compiled for a result other than [`OutputContract::Span`].
    OutputContract { actual: OutputContract },
    /// The reusable semantic program rejected or failed a search.
    Search(CompileError),
}

/// Failure while preparing or executing whole-haystack plain-grep Count.
#[derive(Debug)]
pub enum AotRegexGrepCountError {
    /// Fixed caller/session-owned storage could not be prepared before source.
    Prepare(GrepCountPrepareError),
    /// The authenticated one-pass reducer refused or failed.
    Run(GrepCountError),
}

impl std::fmt::Display for AotRegexGrepCountError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Prepare(error) => write!(formatter, "prepared grep Count setup failed: {error}"),
            Self::Run(error) => write!(formatter, "prepared grep Count failed: {error}"),
        }
    }
}

impl std::error::Error for AotRegexGrepCountError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Prepare(error) => Some(error),
            Self::Run(error) => Some(error),
        }
    }
}

impl std::fmt::Display for AotRegexFindError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OutputContract { actual } => write!(
                formatter,
                "prepared AOT find requires Span output, artifact uses {actual:?}"
            ),
            Self::Search(error) => write!(formatter, "prepared AOT find failed: {error}"),
        }
    }
}

impl std::error::Error for AotRegexFindError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::OutputContract { .. } => None,
            Self::Search(error) => Some(error),
        }
    }
}

impl From<CompileError> for AotRegexFindError {
    fn from(value: CompileError) -> Self {
        Self::Search(value)
    }
}

/// Process-local opaque identifier for owned prepared runtime state.
///
/// The zero value is always invalid. Handles may be copied and sent between
/// threads, but a handle permits only one mutable search at a time. It is an
/// opaque lifecycle token, not an authentication secret.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct FreAotRegexPreparedHandleV1(u64);

impl FreAotRegexPreparedHandleV1 {
    /// The stable invalid/null handle representation.
    pub const INVALID: Self = Self(0);

    /// Return whether this is the invalid/null handle.
    #[must_use]
    pub const fn is_invalid(self) -> bool {
        self.0 == 0
    }
}

/// Exclusively owned prepared runtime state for the direct-pointer ABI.
///
/// The null value is invalid. Unlike [`FreAotRegexPreparedHandleV1`], this
/// handle must not be copied for concurrent use, sent to another thread while
/// a call is active, searched after destruction, or destroyed more than once.
/// Those lifecycle rules are safety preconditions rather than recoverable
/// status checks, which permits a synchronization-free hot path.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct FreAotRegexExclusiveHandleV1(*mut std::ffi::c_void);

impl FreAotRegexExclusiveHandleV1 {
    /// The stable invalid/null handle representation.
    pub const INVALID: Self = Self(std::ptr::null_mut());

    /// Return whether this is the invalid/null handle.
    #[must_use]
    pub const fn is_invalid(self) -> bool {
        self.0.is_null()
    }
}

impl Default for FreAotRegexExclusiveHandleV1 {
    fn default() -> Self {
        Self::INVALID
    }
}

/// Exclusively owned prepared Stage-1 operation-set runtime state.
///
/// This is intentionally distinct from [`FreAotRegexExclusiveHandleV1`]. The
/// null value is invalid, and the same exclusive use, one-destroy, and
/// no-use-after-destroy safety rules apply.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct FreAotRegexOperationSetExclusiveHandleV1(*mut std::ffi::c_void);

impl FreAotRegexOperationSetExclusiveHandleV1 {
    /// The stable invalid/null handle representation.
    pub const INVALID: Self = Self(std::ptr::null_mut());

    /// Return whether this is the invalid/null handle.
    #[must_use]
    pub const fn is_invalid(self) -> bool {
        self.0.is_null()
    }
}

impl Default for FreAotRegexOperationSetExclusiveHandleV1 {
    fn default() -> Self {
        Self::INVALID
    }
}

/// Owned, reusable runtime state for fair steady-state execution.
///
/// Construction validates and deserializes the artifact once and initializes
/// the program's fixed-capacity workspace once. Repeated [`Self::search`]
/// calls neither deserialize the program nor allocate executor workspace.
#[derive(Debug)]
#[repr(C)]
pub struct PreparedAotRegex {
    frozen_header: FrozenPreparedHeaderV6,
    static_continuation_header: FrozenPreparedHeaderV6,
    static_prefix_invocation_epoch: u64,
    program: CompiledProgram,
    workspace: ProgramWorkspace,
    frozen_ordered_nfa_scratch: Option<FrozenOrderedNfaPreparedScratchV1>,
    frozen_dynamic_rows: Option<FrozenDynamicRowsStorageV3>,
    frozen_static_continuation_rows: Option<FrozenStaticContinuationRowsStorageV1>,
    frozen_header_owner_generation_key: Option<FrozenPreparedHeaderOwnerGenerationKey>,
    static_continuation_owner_generation_key: Option<FrozenPreparedHeaderOwnerGenerationKey>,
    fully_prefilled_fallback: Option<FullyPrefilledFallbackReceipt>,
    static_prefix_object_ticket: Option<StaticPrefixObjectTicket>,
    static_prefix_span_postflight_ticket: Option<StaticPrefixSpanPostflightTicket>,
    grep_count_workspace: Option<GrepCountWorkspace>,
    max_grep_count_workspace_bytes: usize,
    #[cfg(test)]
    static_prefix_dense_selections: usize,
    #[cfg(test)]
    static_prefix_legacy_projection_attempts: usize,
    #[cfg(test)]
    retained_partial_frozen_owner_handoffs: usize,
    #[cfg(test)]
    fully_prefilled_fallback_searches: usize,
}

const OPERATION_SET_MEMBER_SEARCH: u8 = 1 << 0;
const OPERATION_SET_MEMBER_COUNT: u8 = 1 << 1;
const OPERATION_SET_MEMBER_SPAN_SUM: u8 = 1 << 2;
const OPERATION_SET_MEMBER_GREP_COUNT: u8 = 1 << 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stage1Operation {
    Search,
    Count,
    SpanSum,
    GrepCount,
}

impl Stage1Operation {
    fn from_axes(axes: AotOperationAxesV1) -> Result<Self, OperationSetRuntimeError> {
        if axes == AotOperationAxesV1::SEARCH {
            Ok(Self::Search)
        } else if axes == AotOperationAxesV1::COUNT {
            Ok(Self::Count)
        } else if axes == AotOperationAxesV1::SPAN_SUM {
            Ok(Self::SpanSum)
        } else if axes == AotOperationAxesV1::GREP_COUNT {
            Ok(Self::GrepCount)
        } else {
            Err(OperationSetRuntimeError::UnsupportedOperation)
        }
    }

    const fn member_flag(self) -> u8 {
        match self {
            Self::Search => OPERATION_SET_MEMBER_SEARCH,
            Self::Count => OPERATION_SET_MEMBER_COUNT,
            Self::SpanSum => OPERATION_SET_MEMBER_SPAN_SUM,
            Self::GrepCount => OPERATION_SET_MEMBER_GREP_COUNT,
        }
    }

    const fn expected_output(self) -> AotOperationOutputV1 {
        match self {
            Self::Search => AotOperationOutputV1::OneRecord,
            Self::Count | Self::SpanSum | Self::GrepCount => {
                AotOperationOutputV1::ScalarU64
            }
        }
    }

    const fn requires_span(self) -> bool {
        matches!(self, Self::Count | Self::SpanSum)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct MemberOperationUnion(u8);

impl MemberOperationUnion {
    fn insert(&mut self, operation: Stage1Operation) {
        self.0 |= operation.member_flag();
    }

    const fn is_empty(self) -> bool {
        self.0 == 0
    }

    const fn requires_start_filter(self) -> bool {
        self.0
            & (OPERATION_SET_MEMBER_SEARCH
                | OPERATION_SET_MEMBER_COUNT
                | OPERATION_SET_MEMBER_SPAN_SUM)
            != 0
    }

    const fn requires_grep_count(self) -> bool {
        self.0 & OPERATION_SET_MEMBER_GREP_COUNT != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PreparedOperationSetRoot {
    member_index: usize,
    operation: Stage1Operation,
}

#[derive(Debug)]
struct OperationSetPreparationPlan {
    member_operations: Vec<MemberOperationUnion>,
    roots: Vec<PreparedOperationSetRoot>,
}

impl OperationSetPreparationPlan {
    fn from_view(
        view: AotOperationSetV1View<'_>,
    ) -> Result<Self, OperationSetRuntimeError> {
        let mut member_operations = Vec::new();
        member_operations
            .try_reserve_exact(view.member_count())
            .map_err(|_| OperationSetRuntimeError::Allocation("member operation union"))?;
        member_operations.resize(view.member_count(), MemberOperationUnion::default());

        let mut roots = Vec::new();
        roots
            .try_reserve_exact(view.operation_count())
            .map_err(|_| OperationSetRuntimeError::Allocation("root execution plan"))?;
        for root in view.roots() {
            let member_index = usize::try_from(root.member_index()).map_err(|_| {
                OperationSetRuntimeError::Arithmetic("root member index conversion")
            })?;
            let operation = Stage1Operation::from_axes(root.axes())?;
            if root.output() != operation.expected_output() {
                return Err(OperationSetRuntimeError::UnsupportedOperation);
            }
            let member = view
                .member(member_index)
                .ok_or(OperationSetRuntimeError::Malformed(
                    "root member index is out of bounds",
                ))?;
            if operation.requires_span()
                && member.output_contract() != OutputContract::Span
            {
                return Err(OperationSetRuntimeError::IncompatibleOutput);
            }
            member_operations
                .get_mut(member_index)
                .ok_or(OperationSetRuntimeError::Malformed(
                    "root member index is out of bounds",
                ))?
                .insert(operation);
            roots.push(PreparedOperationSetRoot {
                member_index,
                operation,
            });
        }
        if member_operations
            .iter()
            .copied()
            .any(MemberOperationUnion::is_empty)
        {
            return Err(OperationSetRuntimeError::UnreachableMember);
        }
        Ok(Self {
            member_operations,
            roots,
        })
    }
}

#[derive(Debug)]
struct PreparedOperationSetMember {
    operations: MemberOperationUnion,
    program: CompiledProgram,
    workspace: ProgramWorkspace,
    grep_count_workspace: Option<GrepCountWorkspace>,
}

#[derive(Debug)]
struct PreparedAotOperationSet {
    members: Vec<PreparedOperationSetMember>,
    roots: Vec<PreparedOperationSetRoot>,
    output_scratch: Vec<FreAotRegexOperationSetOutputV1>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OperationSetPreparationReceipt {
    prospective_start_filter_work: Option<u64>,
    actual_start_filter_work: u64,
    start_filter_aggregate_admitted: bool,
    grep_count_workspace_bytes: u64,
    prospective_handle_bytes: u64,
    retained_handle_bytes: u64,
}

impl OperationSetPreparationReceipt {
    const fn authenticates(
        self,
        config: FreAotRegexOperationSetPrepareConfigV1,
    ) -> bool {
        let start_filter_authenticates = match (
            self.prospective_start_filter_work,
            self.start_filter_aggregate_admitted,
        ) {
            (Some(required), true) => {
                required <= config.max_start_filter_setup_work
                    && self.actual_start_filter_work <= required
            }
            (Some(required), false) => {
                required > config.max_start_filter_setup_work
                    && self.actual_start_filter_work == 0
            }
            (None, false) => self.actual_start_filter_work == 0,
            (None, true) => false,
        };
        start_filter_authenticates
            && self.grep_count_workspace_bytes <= config.max_grep_count_workspace_bytes
            && self.prospective_handle_bytes <= config.max_handle_bytes
            && self.retained_handle_bytes <= self.prospective_handle_bytes
            && self.retained_handle_bytes <= config.max_handle_bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OperationSetRuntimeError {
    Malformed(&'static str),
    UnsupportedOperation,
    UnreachableMember,
    IncompatibleOutput,
    Allocation(&'static str),
    Arithmetic(&'static str),
    Resource(&'static str),
    InternalInvariant(&'static str),
    Execution,
}

impl std::fmt::Display for OperationSetRuntimeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(detail) => write!(formatter, "malformed operation set: {detail}"),
            Self::UnsupportedOperation => {
                formatter.write_str("unsupported Stage-1 operation")
            }
            Self::UnreachableMember => {
                formatter.write_str("operation set contains an unreachable member")
            }
            Self::IncompatibleOutput => {
                formatter.write_str("operation requires a different member output contract")
            }
            Self::Allocation(owner) => write!(formatter, "could not allocate {owner}"),
            Self::Arithmetic(computation) => {
                write!(formatter, "operation-set arithmetic overflow at {computation}")
            }
            Self::Resource(resource) => {
                write!(formatter, "operation-set {resource} exceeds its configured cap")
            }
            Self::InternalInvariant(detail) => {
                write!(formatter, "operation-set invariant failed: {detail}")
            }
            Self::Execution => formatter.write_str("operation-set root execution failed"),
        }
    }
}

impl std::error::Error for OperationSetRuntimeError {}

fn operation_set_fixed_retained_bytes(
    member_count: usize,
    root_count: usize,
) -> Result<u64, OperationSetRuntimeError> {
    std::mem::size_of::<PreparedAotOperationSet>()
        .checked_add(
            member_count
                .checked_mul(std::mem::size_of::<PreparedOperationSetMember>())
                .ok_or(OperationSetRuntimeError::Arithmetic(
                    "prospective member owner bytes",
                ))?,
        )
        .and_then(|bytes| {
            root_count
                .checked_mul(std::mem::size_of::<PreparedOperationSetRoot>())
                .and_then(|part| bytes.checked_add(part))
        })
        .and_then(|bytes| {
            root_count
                .checked_mul(std::mem::size_of::<FreAotRegexOperationSetOutputV1>())
                .and_then(|part| bytes.checked_add(part))
        })
        .ok_or(OperationSetRuntimeError::Arithmetic(
            "prospective fixed owner bytes",
        ))
        .and_then(|bytes| {
            u64::try_from(bytes).map_err(|_| {
                OperationSetRuntimeError::Arithmetic(
                    "prospective fixed owner byte conversion",
                )
            })
        })
}

fn add_retained_usize(
    total: u64,
    bytes: usize,
    computation: &'static str,
) -> Result<u64, OperationSetRuntimeError> {
    let bytes = u64::try_from(bytes)
        .map_err(|_| OperationSetRuntimeError::Arithmetic(computation))?;
    total
        .checked_add(bytes)
        .ok_or(OperationSetRuntimeError::Arithmetic(computation))
}

impl PreparedAotOperationSet {
    #[allow(
        clippy::too_many_lines,
        reason = "the preparation transaction keeps its ordered validation, planning, allocation, and final commit boundary visible"
    )]
    fn deserialize_with_config(
        bytes: &[u8],
        config: FreAotRegexOperationSetPrepareConfigV1,
    ) -> Result<(Self, OperationSetPreparationReceipt), OperationSetRuntimeError> {
        if !config.is_valid() {
            return Err(OperationSetRuntimeError::Malformed(
                "operation-set prepare config is invalid",
            ));
        }
        let view = AotOperationSetV1View::deserialize(bytes).map_err(|_| {
            OperationSetRuntimeError::Malformed("operation-set envelope validation failed")
        })?;
        let mut minimum_handle_bytes =
            operation_set_fixed_retained_bytes(view.member_count(), view.operation_count())?;
        if minimum_handle_bytes > config.max_handle_bytes {
            return Err(OperationSetRuntimeError::Resource("retained handle bytes"));
        }
        // The borrowed envelope deliberately defers global reachability and
        // member-body validation. Resolve the O(M+R) root/member plan first,
        // so an unreachable candidate cannot trigger any full-body census,
        // decoded owner, or executor-workspace work.
        let plan = OperationSetPreparationPlan::from_view(view)?;

        let mut censuses = Vec::new();
        censuses
            .try_reserve_exact(view.member_count())
            .map_err(|_| OperationSetRuntimeError::Allocation("member census table"))?;
        for member in view.members() {
            let census = GenericNfaProgramCensus::from_wire(member.as_bytes()).map_err(|_| {
                OperationSetRuntimeError::Malformed(
                    "member is not a canonical scalar generic NFA",
                )
            })?;
            if census.artifact_identity() != member.identity()
                || census.output_contract() != member.output_contract()
            {
                return Err(OperationSetRuntimeError::InternalInvariant(
                    "member census disagrees with envelope preflight",
                ));
            }
            minimum_handle_bytes = add_retained_usize(
                minimum_handle_bytes,
                census.semantic_graph_logical_bytes(),
                "prospective semantic graph bytes",
            )?;
            minimum_handle_bytes = add_retained_usize(
                minimum_handle_bytes,
                census.workspace_layout().logical_bytes(),
                "prospective ordinary workspace bytes",
            )?;
            if minimum_handle_bytes > config.max_handle_bytes {
                return Err(OperationSetRuntimeError::Resource("retained handle bytes"));
            }
            censuses.push(census);
        }

        let OperationSetPreparationPlan {
            member_operations,
            roots,
        } = plan;
        let mut members = Vec::new();
        members
            .try_reserve_exact(view.member_count())
            .map_err(|_| OperationSetRuntimeError::Allocation("prepared member table"))?;
        for (index, member) in view.members().enumerate() {
            let census = censuses[index];
            let program = CompiledProgram::deserialize(member.as_bytes()).map_err(|_| {
                OperationSetRuntimeError::Malformed("member program reconstruction failed")
            })?;
            if program.output_contract() != census.output_contract() {
                return Err(OperationSetRuntimeError::InternalInvariant(
                    "member output changed after generic census",
                ));
            }
            let workspace = program
                .prepare_generic_nfa_workspace(census)
                .map_err(|_| OperationSetRuntimeError::Allocation("ordinary member workspace"))?;
            members.push(PreparedOperationSetMember {
                operations: member_operations[index],
                program,
                workspace,
                grep_count_workspace: None,
            });
        }

        // Allocate every non-auxiliary retained owner before admitting either
        // optional proofs or GrepCount stores. The next cap check therefore
        // binds their maxima to observable final Vec capacities, rather than
        // to smaller census-logical estimates that allocation may round up.
        let mut output_scratch = Vec::new();
        output_scratch
            .try_reserve_exact(roots.len())
            .map_err(|_| OperationSetRuntimeError::Allocation("output transaction scratch"))?;
        output_scratch.resize(roots.len(), FreAotRegexOperationSetOutputV1::default());
        let mut prepared = Self {
            members,
            roots,
            output_scratch,
        };
        let base_retained_handle_bytes = prepared.actual_retained_handle_bytes(&censuses)?;
        if base_retained_handle_bytes > config.max_handle_bytes {
            return Err(OperationSetRuntimeError::Resource("retained handle bytes"));
        }

        let mut prospective_start_filter_work = Some(0_u64);
        let mut prospective_start_filter_proof_bytes = 0_u64;
        let mut prospective_grep_count_bytes = 0_u64;
        for (member, census) in prepared.members.iter().zip(censuses.iter().copied()) {
            if member.operations.requires_start_filter() {
                let bound = member
                    .program
                    .generic_nfa_start_filter_setup_work_bound(census)
                    .map_err(|_| {
                        OperationSetRuntimeError::InternalInvariant(
                            "generic member start-filter sizing failed",
                        )
                    })?;
                prospective_start_filter_work = match (prospective_start_filter_work, bound) {
                    (Some(total), Some(member_work)) => total.checked_add(member_work),
                    _ => None,
                };
                let proof_bytes = member
                    .program
                    .generic_nfa_start_filter_proof_retained_bytes_bound(census)
                    .map_err(|_| {
                        OperationSetRuntimeError::InternalInvariant(
                            "generic member start-filter retained sizing failed",
                        )
                    })?;
                prospective_start_filter_proof_bytes = add_retained_usize(
                    prospective_start_filter_proof_bytes,
                    proof_bytes,
                    "prospective aggregate start-filter proof bytes",
                )?;
            }
            if member.operations.requires_grep_count() {
                let member_bytes = member
                    .program
                    .generic_nfa_grep_count_workspace_logical_bytes(census)
                    .map_err(|_| {
                        OperationSetRuntimeError::InternalInvariant(
                            "generic member GrepCount sizing failed",
                        )
                    })?;
                let member_bytes = u64::try_from(member_bytes).map_err(|_| {
                    OperationSetRuntimeError::Arithmetic(
                        "prospective GrepCount byte conversion",
                    )
                })?;
                prospective_grep_count_bytes = prospective_grep_count_bytes
                    .checked_add(member_bytes)
                    .ok_or(OperationSetRuntimeError::Arithmetic(
                        "prospective aggregate GrepCount bytes",
                    ))?;
            }
        }
        if prospective_grep_count_bytes > config.max_grep_count_workspace_bytes {
            return Err(OperationSetRuntimeError::Resource(
                "aggregate GrepCount workspace bytes",
            ));
        }

        // V2-compatible all-or-none cap policy: the cap admits the complete
        // set of strongest-proof attempts, or every start-using member is
        // deterministically settled to ordinary K0 in canonical member order.
        // An admitted attempt can still settle that member to ordinary after
        // an optional owner-allocation failure. No member receives a reused
        // per-member copy of the whole-handle cap.
        let start_filter_aggregate_admitted = prospective_start_filter_work
            .is_some_and(|required| required <= config.max_start_filter_setup_work);
        let admitted_start_filter_proof_bytes = if start_filter_aggregate_admitted {
            prospective_start_filter_proof_bytes
        } else {
            0
        };
        let prospective_auxiliary_bytes = admitted_start_filter_proof_bytes
            .checked_add(prospective_grep_count_bytes)
            .ok_or(OperationSetRuntimeError::Arithmetic(
                "prospective aggregate auxiliary retained bytes",
            ))?;
        let prospective_handle_bytes = base_retained_handle_bytes
            .checked_add(prospective_auxiliary_bytes)
            .ok_or(OperationSetRuntimeError::Arithmetic(
                "prospective complete retained handle bytes",
            ))?;
        if prospective_handle_bytes > config.max_handle_bytes {
            return Err(OperationSetRuntimeError::Resource("retained handle bytes"));
        }
        let mut actual_start_filter_work = 0_u64;
        for (member, census) in prepared
            .members
            .iter_mut()
            .zip(censuses.iter().copied())
        {
            if !member.operations.requires_start_filter() {
                continue;
            }
            let member_limit = if start_filter_aggregate_admitted {
                member
                    .program
                    .generic_nfa_start_filter_setup_work_bound(census)
                    .map_err(|_| {
                        OperationSetRuntimeError::InternalInvariant(
                            "generic member start-filter sizing changed",
                        )
                    })?
                    .ok_or(OperationSetRuntimeError::InternalInvariant(
                        "admitted aggregate contains an unbounded start-filter proof",
                    ))?
            } else {
                0
            };
            let receipt = member
                .program
                .prepare_start_filter_with_workspace_limit(
                    &mut member.workspace,
                    member_limit,
                )
                .map_err(|_| OperationSetRuntimeError::Execution)?;
            actual_start_filter_work = actual_start_filter_work
                .checked_add(receipt.work_completed())
                .ok_or(OperationSetRuntimeError::Arithmetic(
                    "actual aggregate start-filter work",
                ))?;
        }
        let actual_start_filter_work_within_prospective = match (
            prospective_start_filter_work,
            start_filter_aggregate_admitted,
        ) {
            (Some(required), true) => actual_start_filter_work <= required,
            _ => actual_start_filter_work == 0,
        };
        if !actual_start_filter_work_within_prospective
            || actual_start_filter_work > config.max_start_filter_setup_work
        {
            return Err(OperationSetRuntimeError::InternalInvariant(
                "actual aggregate start-filter work exceeded its admission",
            ));
        }

        let mut actual_grep_count_bytes = 0_u64;
        for (member, census) in prepared
            .members
            .iter_mut()
            .zip(censuses.iter().copied())
        {
            if !member.operations.requires_grep_count() {
                continue;
            }
            let required = member
                .program
                .generic_nfa_grep_count_workspace_logical_bytes(census)
                .map_err(|_| {
                    OperationSetRuntimeError::InternalInvariant(
                        "generic member GrepCount sizing changed",
                    )
                })?;
            let workspace = member
                .program
                .prepare_grep_count_workspace_with_limits(GrepCountWorkspaceLimits {
                    max_workspace_bytes: required,
                })
                .map_err(|_| OperationSetRuntimeError::Allocation("GrepCount workspace"))?;
            let actual = workspace
                .compiler_private_retained_heap_bytes()
                .ok_or(OperationSetRuntimeError::Arithmetic(
                    "actual GrepCount retained bytes",
                ))?;
            if actual != required {
                return Err(OperationSetRuntimeError::InternalInvariant(
                    "GrepCount retained capacity changed after sizing",
                ));
            }
            actual_grep_count_bytes = add_retained_usize(
                actual_grep_count_bytes,
                actual,
                "actual aggregate GrepCount bytes",
            )?;
            member.grep_count_workspace = Some(workspace);
        }
        if actual_grep_count_bytes != prospective_grep_count_bytes
            || actual_grep_count_bytes > config.max_grep_count_workspace_bytes
        {
            return Err(OperationSetRuntimeError::InternalInvariant(
                "actual aggregate GrepCount bytes exceeded their admission",
            ));
        }

        let retained_handle_bytes = prepared.actual_retained_handle_bytes(&censuses)?;
        if retained_handle_bytes > config.max_handle_bytes {
            return Err(OperationSetRuntimeError::Resource("retained handle bytes"));
        }
        let receipt = OperationSetPreparationReceipt {
            prospective_start_filter_work,
            actual_start_filter_work,
            start_filter_aggregate_admitted,
            grep_count_workspace_bytes: actual_grep_count_bytes,
            prospective_handle_bytes,
            retained_handle_bytes,
        };
        if !receipt.authenticates(config) {
            return Err(OperationSetRuntimeError::InternalInvariant(
                "final preparation receipt does not authenticate its config",
            ));
        }
        Ok((prepared, receipt))
    }

    fn actual_retained_handle_bytes(
        &self,
        censuses: &[GenericNfaProgramCensus],
    ) -> Result<u64, OperationSetRuntimeError> {
        if self.members.len() != censuses.len() {
            return Err(OperationSetRuntimeError::InternalInvariant(
                "retained member and census counts differ",
            ));
        }
        let mut bytes = u64::try_from(std::mem::size_of::<Self>()).map_err(|_| {
            OperationSetRuntimeError::Arithmetic("retained owner byte conversion")
        })?;
        bytes = add_retained_usize(
            bytes,
            self.members
                .capacity()
                .checked_mul(std::mem::size_of::<PreparedOperationSetMember>())
                .ok_or(OperationSetRuntimeError::Arithmetic(
                    "retained member vector bytes",
                ))?,
            "retained member vector bytes",
        )?;
        bytes = add_retained_usize(
            bytes,
            self.roots
                .capacity()
                .checked_mul(std::mem::size_of::<PreparedOperationSetRoot>())
                .ok_or(OperationSetRuntimeError::Arithmetic(
                    "retained root vector bytes",
                ))?,
            "retained root vector bytes",
        )?;
        bytes = add_retained_usize(
            bytes,
            self.output_scratch
                .capacity()
                .checked_mul(std::mem::size_of::<FreAotRegexOperationSetOutputV1>())
                .ok_or(OperationSetRuntimeError::Arithmetic(
                    "retained output scratch bytes",
                ))?,
            "retained output scratch bytes",
        )?;
        for (member, census) in self.members.iter().zip(censuses.iter().copied()) {
            bytes = add_retained_usize(
                bytes,
                member
                    .program
                    .generic_nfa_retained_heap_bytes(census)
                    .map_err(|_| {
                        OperationSetRuntimeError::InternalInvariant(
                            "generic member retained accounting failed",
                        )
                    })?,
                "retained generic member bytes",
            )?;
            bytes = add_retained_usize(
                bytes,
                member.workspace.compiler_private_k0_retained_bytes(),
                "retained ordinary workspace bytes",
            )?;
            if let Some(grep) = member.grep_count_workspace.as_ref() {
                bytes = add_retained_usize(
                    bytes,
                    grep.compiler_private_retained_heap_bytes().ok_or(
                        OperationSetRuntimeError::Arithmetic(
                            "retained GrepCount workspace bytes",
                        ),
                    )?,
                    "retained GrepCount workspace bytes",
                )?;
            }
        }
        Ok(bytes)
    }

    fn execute(&mut self, haystack: &[u8]) -> Result<(), OperationSetRuntimeError> {
        let Self {
            members,
            roots,
            output_scratch,
        } = self;
        for (index, root) in roots.iter().copied().enumerate() {
            let member = members
                .get_mut(root.member_index)
                .ok_or(OperationSetRuntimeError::InternalInvariant(
                    "prepared root member index is out of bounds",
                ))?;
            let output = match root.operation {
                Stage1Operation::Search => {
                    let found = member
                        .program
                        .search_with_workspace(
                            haystack,
                            SearchWindow::full(haystack),
                            &mut member.workspace,
                        )
                        .map_err(|_| OperationSetRuntimeError::Execution)?;
                    encode_operation_set_search(found)?
                }
                Stage1Operation::Count => FreAotRegexOperationSetOutputV1 {
                    kind: OPERATION_SET_OUTPUT_COUNT,
                    status: STATUS_SUCCESS,
                    first: reduce_operation_set_spans(
                        &member.program,
                        &mut member.workspace,
                        haystack,
                        ExclusiveSpanReducer::Count,
                    )?,
                    second: 0,
                },
                Stage1Operation::SpanSum => FreAotRegexOperationSetOutputV1 {
                    kind: OPERATION_SET_OUTPUT_SPAN_SUM,
                    status: STATUS_SUCCESS,
                    first: reduce_operation_set_spans(
                        &member.program,
                        &mut member.workspace,
                        haystack,
                        ExclusiveSpanReducer::SpanSum,
                    )?,
                    second: 0,
                },
                Stage1Operation::GrepCount => {
                    let workspace = member.grep_count_workspace.as_mut().ok_or(
                        OperationSetRuntimeError::InternalInvariant(
                            "GrepCount root has no prepared workspace",
                        ),
                    )?;
                    let count = member
                        .program
                        .grep_count_with_workspace(haystack, workspace)
                        .map_err(|_| OperationSetRuntimeError::Execution)?
                        .count();
                    FreAotRegexOperationSetOutputV1 {
                        kind: OPERATION_SET_OUTPUT_GREP_COUNT,
                        status: STATUS_SUCCESS,
                        first: count,
                        second: 0,
                    }
                }
            };
            output_scratch[index] = output;
        }
        Ok(())
    }
}

fn encode_operation_set_search(
    found: MatchResult,
) -> Result<FreAotRegexOperationSetOutputV1, OperationSetRuntimeError> {
    let (kind, status, first, second) = match found {
        MatchResult::Exists(false) => (
            OPERATION_SET_OUTPUT_SEARCH_EXISTS,
            STATUS_NO_MATCH,
            0,
            0,
        ),
        MatchResult::Exists(true) => (
            OPERATION_SET_OUTPUT_SEARCH_EXISTS,
            STATUS_MATCH,
            0,
            0,
        ),
        MatchResult::SelectedEnd(None) => (
            OPERATION_SET_OUTPUT_SEARCH_SELECTED_END,
            STATUS_NO_MATCH,
            0,
            0,
        ),
        MatchResult::SelectedEnd(Some(end)) => {
            let end = u64::try_from(end).map_err(|_| {
                OperationSetRuntimeError::Arithmetic("SelectedEnd output conversion")
            })?;
            (
                OPERATION_SET_OUTPUT_SEARCH_SELECTED_END,
                STATUS_MATCH,
                end,
                end,
            )
        }
        MatchResult::Span(None) => (
            OPERATION_SET_OUTPUT_SEARCH_SPAN,
            STATUS_NO_MATCH,
            0,
            0,
        ),
        MatchResult::Span(Some((start, end))) => (
            OPERATION_SET_OUTPUT_SEARCH_SPAN,
            STATUS_MATCH,
            u64::try_from(start).map_err(|_| {
                OperationSetRuntimeError::Arithmetic("Span start output conversion")
            })?,
            u64::try_from(end).map_err(|_| {
                OperationSetRuntimeError::Arithmetic("Span end output conversion")
            })?,
        ),
    };
    Ok(FreAotRegexOperationSetOutputV1 {
        kind,
        status,
        first,
        second,
    })
}

fn reduce_operation_set_spans(
    program: &CompiledProgram,
    workspace: &mut ProgramWorkspace,
    haystack: &[u8],
    reducer: ExclusiveSpanReducer,
) -> Result<u64, OperationSetRuntimeError> {
    if program.output_contract() != OutputContract::Span {
        return Err(OperationSetRuntimeError::IncompatibleOutput);
    }
    let mut value = 0_u64;
    let mut start = 0_usize;
    let mut last_match_end = None;
    let mut pending_empty_progress = false;
    loop {
        if pending_empty_progress {
            pending_empty_progress = false;
            if start == haystack.len() {
                return Ok(value);
            }
            start = start
                .checked_add(1)
                .ok_or(OperationSetRuntimeError::Arithmetic(
                    "empty-match progress",
                ))?;
        }
        let search_start = start;
        let result = program
            .search_with_workspace(
                haystack,
                SearchWindow::new(search_start, haystack.len()),
                workspace,
            )
            .map_err(|_| OperationSetRuntimeError::Execution)?;
        let MatchResult::Span(found) = result else {
            return Err(OperationSetRuntimeError::IncompatibleOutput);
        };
        let Some((match_start, match_end)) = found else {
            return Ok(value);
        };
        if match_start < search_start || match_start > match_end || match_end > haystack.len() {
            return Err(OperationSetRuntimeError::InternalInvariant(
                "Span reducer received a match outside its search window",
            ));
        }
        if match_start == match_end && last_match_end == Some(match_end) {
            if start == haystack.len() {
                return Ok(value);
            }
            start = start
                .checked_add(1)
                .ok_or(OperationSetRuntimeError::Arithmetic(
                    "repeated empty-match progress",
                ))?;
            continue;
        }
        let contribution = match reducer {
            ExclusiveSpanReducer::Count => 1,
            ExclusiveSpanReducer::SpanSum => u64::try_from(
                match_end
                    .checked_sub(match_start)
                    .ok_or(OperationSetRuntimeError::InternalInvariant(
                        "Span reducer received an inverted match",
                    ))?,
            )
            .map_err(|_| OperationSetRuntimeError::Arithmetic("SpanSum width conversion"))?,
        };
        value = value
            .checked_add(contribution)
            .ok_or(OperationSetRuntimeError::Arithmetic("scalar reducer result"))?;
        start = match_end;
        last_match_end = Some(match_end);
        pending_empty_progress = match_start == match_end;
    }
}

/// One generated static-prefix invocation awaiting either a native hole or a
/// Span postflight. Keeping this raw object ticket outside `ProgramWorkspace`
/// lets an all-native path avoid descriptor parsing, graph binding, and cache
/// prefill; short windows also avoid touching portable executor workspace.
#[derive(Debug)]
struct StaticPrefixObjectTicket {
    haystack_address: usize,
    haystack_len: usize,
    window: SearchWindow,
    artifact_identity: [u8; ARTIFACT_IDENTITY_BYTES],
    descriptor_key: StaticPrefixResumeDescriptorKey,
    invocation_epoch: u64,
}

/// One successful authenticated status-7/8 continuation awaiting its
/// synchronous variable-Span postflight. This is deliberately distinct from
/// [`StaticPrefixObjectTicket`]: the continuation consumes the raw generated
/// object capability while binding its descriptor, so Span recovery must not
/// recreate or consume that descriptor capability a second time.
#[derive(Debug)]
struct StaticPrefixSpanPostflightTicket {
    haystack_address: usize,
    haystack_len: usize,
    window: SearchWindow,
    artifact_identity: [u8; ARTIFACT_IDENTITY_BYTES],
    invocation_epoch: u64,
    recovery: StaticPrefixSpanRecoveryAdmission,
}

/// Fully validated publication plan retained across the final linear
/// continuation consume. The recovery authority itself is minted by that
/// consume, so installing the pair afterward performs no validation and
/// cannot return an error.
#[derive(Debug)]
enum StaticPrefixSpanPostflightPublication {
    None,
    VariableSpan {
        haystack_address: usize,
        haystack_len: usize,
        window: SearchWindow,
        artifact_identity: [u8; ARTIFACT_IDENTITY_BYTES],
        invocation_epoch: u64,
    },
}

/// One authenticated continuation outcome before its ABI result encoding.
/// Keeping this independent of caller storage lets both the established
/// ticket-consuming boundary and the fused deferred-hole boundary share one
/// descriptor/binding transaction without publishing an intermediate ticket.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StaticPrefixContinuationOutcome {
    Native {
        status: u32,
        canonical_state: usize,
        pending_end: usize,
    },
    Complete(MatchResult),
}

/// Linear result of trying to publish an authenticated immutable local tail.
/// A decline returns the still-unconsumed admission for the frozen in-process
/// scan and then K0.
#[derive(Debug)]
enum StaticPrefixFrozenProjectionOutcome {
    Native {
        status: u32,
        canonical_state: usize,
        pending_end: usize,
        span_recovery: Option<StaticPrefixSpanRecoveryAdmission>,
    },
    Declined(StaticPrefixResumeAdmission),
}

const _: () = assert!(std::mem::offset_of!(PreparedAotRegex, frozen_header) == 0);
const _: () = assert!(
    std::mem::offset_of!(PreparedAotRegex, static_continuation_header)
        == FROZEN_PREPARED_HEADER_V6_BYTES
);
const _: () = assert!(
    std::mem::offset_of!(PreparedAotRegex, static_prefix_invocation_epoch)
        == STATIC_PREFIX_INVOCATION_EPOCH_OFFSET
);

// A complete compact sidecar is optional setup-only storage. Its shared K0
// staging and final immutable-copy limits are defined beside the builder so
// every prepared-runtime and diagnostic caller follows the same policy.
// One descriptor-bound map is shared by both frozen owners. Keep its payload
// independently bounded so alternating object versions cannot accumulate
// unaccounted side storage; rebinding replaces the sole owned map.
const FROZEN_STATIC_PREFIX_RESUME_MAP_MAX_BYTES: usize = 512 * 1024;

impl PreparedAotRegex {
    /// Validate, own, and prepare one serialized AOT semantic program.
    ///
    /// # Errors
    ///
    /// Returns a strict format error for malformed artifacts or a compiler
    /// error if fixed-capacity executor workspace cannot be prepared. No
    /// reference into `bytes` is retained.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, PrepareError> {
        let program = CompiledProgram::deserialize(bytes).map_err(PrepareError::Format)?;
        Self::from_program(program)
    }

    fn from_program(program: CompiledProgram) -> Result<Self, PrepareError> {
        let workspace = program
            .prepare_workspace()
            .map_err(PrepareError::Workspace)?;
        Self::from_program_with_workspace(program, workspace)
    }

    fn deserialize_with_prepare_config_v2(
        bytes: &[u8],
        config: FreAotRegexPrepareConfigV2,
    ) -> Result<Self, ()> {
        let program = CompiledProgram::deserialize(bytes).map_err(|_| ())?;
        Self::from_program_with_prepare_config_v2(program, config)
    }

    fn from_program_with_prepare_config_v2(
        program: CompiledProgram,
        config: FreAotRegexPrepareConfigV2,
    ) -> Result<Self, ()> {
        if !config.is_valid() {
            return Err(());
        }
        let span_reducer_flags = PREPARE_OPERATION_COUNT | PREPARE_OPERATION_SPAN_SUM;
        if config.operation_flags & span_reducer_flags != 0
            && program.output_contract() != OutputContract::Span
        {
            return Err(());
        }

        let mut workspace = program.prepare_workspace().map_err(|_| ())?;
        let start_filter_flags = PREPARE_OPERATION_SEARCH | span_reducer_flags;
        if config.operation_flags & start_filter_flags != 0 {
            let _ = program
                .prepare_start_filter_with_workspace_limit(
                    &mut workspace,
                    config.max_start_filter_setup_work,
                )
                .map_err(|_| ())?;
        }

        let mut prepared = Self::from_program_with_workspace(program, workspace).map_err(|_| ())?;
        prepared.max_grep_count_workspace_bytes =
            usize::try_from(config.max_grep_count_workspace_bytes).unwrap_or(usize::MAX);
        if config.operation_flags & PREPARE_OPERATION_GREP_COUNT != 0 {
            let _ = prepared.prepare_grep_count().map_err(|_| ())?;
        }
        Ok(prepared)
    }

    fn deserialize_with_prepare_config_v3(
        bytes: &[u8],
        config: FreAotRegexPrepareConfigV3,
    ) -> Result<Self, ()> {
        if !config.is_valid() {
            return Err(());
        }
        let program = CompiledProgram::deserialize(bytes).map_err(|_| ())?;
        Self::from_program_with_prepare_config_v3(program, config)
    }

    fn from_program_with_prepare_config_v3(
        program: CompiledProgram,
        config: FreAotRegexPrepareConfigV3,
    ) -> Result<Self, ()> {
        if !config.is_valid() {
            return Err(());
        }
        let requires_ordered_nfa =
            config.required_capabilities & PREPARE_CAPABILITY_ORDERED_NFA_V15 != 0;
        let mut prepared = Self::from_program_with_prepare_config_v2(program, config.v2_prefix())?;
        let requests_span_iteration = config.operation_flags
            & (PREPARE_OPERATION_COUNT | PREPARE_OPERATION_SPAN_SUM)
            != 0;
        if !requests_span_iteration {
            return Ok(prepared);
        }

        let max_handle_bytes = usize::try_from(config.max_handle_bytes).unwrap_or(usize::MAX);
        let max_scratch_bytes =
            usize::try_from(config.max_ordered_nfa_scratch_bytes).unwrap_or(usize::MAX);
        let mut limits = FrozenOrderedNfaLimitsV1::new(max_handle_bytes);
        if requires_ordered_nfa {
            limits.max_descriptor_bytes = FROZEN_ORDERED_NFA_V15_MAX_DESCRIPTOR_BYTES;
        }
        limits.max_scratch_bytes = limits.max_scratch_bytes.min(max_scratch_bytes);
        limits.max_setup_work = limits.max_setup_work.min(config.max_ordered_nfa_setup_work);
        let owner = prepared
            .program
            .compiler_private_frozen_ordered_nfa_prepared_scratch_v1(limits);
        let Some(owner) = owner else {
            return if requires_ordered_nfa {
                Err(())
            } else {
                Ok(prepared)
            };
        };
        let header = prepared
            .program
            .compiler_private_frozen_ordered_nfa_prepared_header_v15(&owner);
        let Some(header) = header else {
            return if requires_ordered_nfa {
                Err(())
            } else {
                Ok(prepared)
            };
        };
        if !header.compiler_private_authenticates_ordered_nfa_v15_owner(
            &owner,
            prepared.program.artifact_identity(),
        )
            || owner.accounting().retained_handle_bytes() > max_handle_bytes
        {
            return if requires_ordered_nfa {
                Err(())
            } else {
                Ok(prepared)
            };
        }
        // This owner is still private and unpublished, but retire the prior
        // compact capability before replacing offset zero to preserve the
        // same seal-first transition order used after publication.
        if prepared.frozen_header.is_active() {
            prepared.frozen_header.deactivate();
        }
        prepared.frozen_header = header;
        prepared.frozen_ordered_nfa_scratch = Some(owner);
        Ok(prepared)
    }

    fn reduce_exclusive_operation(
        &mut self,
        haystack: &[u8],
        reducer: ExclusiveReducer,
    ) -> Result<u64, ()> {
        if !matches!(reducer, ExclusiveReducer::GrepCount)
            && self.program.output_contract() != OutputContract::Span
        {
            return Err(());
        }
        // A prior generated entry may have left one authenticated native-row
        // admission for its immediately following runtime continuation. The
        // iterator reducers retire it here. GrepCount's public prepared path
        // owns that same single settlement before its independent workspace
        // setup, so it must not be settled a second time at this boundary.
        if !matches!(reducer, ExclusiveReducer::GrepCount) {
            self.settle_dynamic_native_rows_local_completion();
        }
        match reducer {
            ExclusiveReducer::Count => self
                .reduce_spans_exclusive_after_deactivation(haystack, ExclusiveSpanReducer::Count)
                .map_err(|_| ()),
            ExclusiveReducer::SpanSum => self
                .reduce_spans_exclusive_after_deactivation(
                    haystack,
                    ExclusiveSpanReducer::SpanSum,
                )
                .map_err(|_| ()),
            ExclusiveReducer::GrepCount => self.grep_count(haystack).map_err(|_| ()),
        }
    }

    fn from_program_with_workspace(
        program: CompiledProgram,
        mut workspace: ProgramWorkspace,
    ) -> Result<Self, PrepareError> {
        let fully_prefilled_fallback = program
            .compiler_private_try_prefill_retained_fallback_with_workspace_receipt_bounded(
                &mut workspace,
                FROZEN_DYNAMIC_SIDECAR_MAX_K0_BYTES,
            )
            .map_err(PrepareError::Workspace)?;
        // A retained-partial receipt is still valuable to every ordinary or
        // continuation fallback, but it need not force the generated entry
        // to execute the older wide K0 projection. The header publishers keep
        // their established rule that a receipt wins when both candidates are
        // supplied; this runtime owner instead copies the compact projection
        // from that same completed live cache and presents only the compact
        // owner first. A compact construction or publication decline then
        // presents the retained receipt alone and recovers the established V1
        // capability. Every retained proof remains immutable until revocation.
        let mut frozen_dynamic_rows = program
            .compiler_private_frozen_dynamic_rows_storage_v3_with_fallback_receipt(
                &mut workspace,
                fully_prefilled_fallback,
                FROZEN_DYNAMIC_SIDECAR_MAX_K0_BYTES,
                FROZEN_DYNAMIC_SIDECAR_MAX_PACKED_BYTES,
            );
        let (frozen_header, frozen_header_owner_generation_key) =
            if let Some(owner) = frozen_dynamic_rows.as_ref() {
                match program
                    .compiler_private_frozen_prepared_header_v6_with_owner_generation_key(
                        &workspace,
                        owner,
                    )
                {
                    Some((header, key)) => (header, Some(key)),
                    None => {
                        frozen_dynamic_rows = None;
                        (
                            program.compiler_private_frozen_prepared_header_v6(
                                &workspace,
                                fully_prefilled_fallback,
                                None,
                            ),
                            None,
                        )
                    }
                }
            } else {
                (
                    program.compiler_private_frozen_prepared_header_v6(
                        &workspace,
                        fully_prefilled_fallback,
                        None,
                    ),
                    None,
                )
            };
        let static_continuation_receipt = frozen_dynamic_rows
            .as_ref()
            .map(FrozenDynamicRowsStorageV3::compiler_private_fully_prefilled_fallback_receipt)
            .or(fully_prefilled_fallback);
        let mut frozen_static_continuation_rows = program
            .compiler_private_frozen_static_continuation_rows_storage_v3_with_fallback_receipt(
                &mut workspace,
                static_continuation_receipt,
                FROZEN_DYNAMIC_SIDECAR_MAX_K0_BYTES,
                FROZEN_DYNAMIC_SIDECAR_MAX_PACKED_BYTES,
            );
        let static_continuation_publication = frozen_static_continuation_rows
            .as_ref()
            .and_then(|owner| {
                program
                    .compiler_private_frozen_static_continuation_header_with_owner_generation_key(
                        &workspace,
                        owner,
                    )
            });
        if static_continuation_publication.is_none() {
            frozen_static_continuation_rows = None;
        }
        let (static_continuation_header, static_continuation_owner_generation_key) =
            static_continuation_publication.map_or_else(
                || {
                    (
                        program.compiler_private_frozen_prepared_header_v6(
                            &workspace,
                            None,
                            None,
                        ),
                        None,
                    )
                },
                |(header, key)| (header, Some(key)),
            );
        Ok(Self {
            frozen_header,
            static_continuation_header,
            static_prefix_invocation_epoch: 1,
            program,
            workspace,
            frozen_ordered_nfa_scratch: None,
            frozen_dynamic_rows,
            frozen_static_continuation_rows,
            frozen_header_owner_generation_key,
            static_continuation_owner_generation_key,
            fully_prefilled_fallback,
            static_prefix_object_ticket: None,
            static_prefix_span_postflight_ticket: None,
            grep_count_workspace: None,
            max_grep_count_workspace_bytes:
                fre_aot_regex::DEFAULT_GREP_COUNT_MAX_WORKSPACE_BYTES,
            #[cfg(test)]
            static_prefix_dense_selections: 0,
            #[cfg(test)]
            static_prefix_legacy_projection_attempts: 0,
            #[cfg(test)]
            retained_partial_frozen_owner_handoffs: 0,
            #[cfg(test)]
            fully_prefilled_fallback_searches: 0,
        })
    }

    /// Retire every outstanding compiler-private static-prefix invocation and
    /// return the prior capabilities to the one path that may consume them.
    #[inline]
    fn retire_static_prefix_capabilities(
        &mut self,
    ) -> (
        Option<StaticPrefixObjectTicket>,
        Option<StaticPrefixSpanPostflightTicket>,
    ) {
        (
            self.static_prefix_object_ticket.take(),
            self.static_prefix_span_postflight_ticket.take(),
        )
    }

    #[inline]
    fn deactivate_frozen_header(&mut self) {
        let _ = self.retire_static_prefix_capabilities();
        debug_assert!(
            !self.frozen_header.has_ordered_nfa_v15()
                || self.frozen_ordered_nfa_scratch.is_some(),
            "an active Ordered-TNFA header must retain its scratch-only owner"
        );
        debug_assert!(
            !self.frozen_header.has_dynamic_rows() || self.frozen_dynamic_rows.is_some(),
            "an active compact header must retain its immutable payload owner"
        );
        if self.frozen_header.is_active() {
            self.frozen_header.deactivate();
        }
        if let Some(owner) = self.frozen_ordered_nfa_scratch.as_mut() {
            // The offset-zero seal was cleared first, so no generated entry
            // can acquire this mutable descriptor while its own seal retires.
            owner.revoke();
        }
        debug_assert!(
            !self.static_continuation_header.has_dynamic_rows()
                || self.frozen_static_continuation_rows.is_some(),
            "an active static-continuation header must retain its immutable payload owner"
        );
        if self.static_continuation_header.is_active() {
            self.static_continuation_header.deactivate();
        }
    }

    #[inline]
    fn admit_static_prefix_object(
        &mut self,
        haystack: &[u8],
        window: SearchWindow,
        expected_artifact_identity: [u8; ARTIFACT_IDENTITY_BYTES],
        descriptor_version: u32,
        descriptor_address: usize,
    ) -> Result<(), CompileError> {
        let _ = self.retire_static_prefix_capabilities();
        if expected_artifact_identity != *self.frozen_header.artifact_identity() {
            return Err(CompileError::InternalInvariant(
                "static-prefix object preflight rejected its artifact or descriptor",
            ));
        }
        let descriptor_key =
            StaticPrefixResumeDescriptorKey::new(descriptor_version, descriptor_address)?;
        self.static_prefix_object_ticket = Some(StaticPrefixObjectTicket {
            haystack_address: haystack.as_ptr().expose_provenance(),
            haystack_len: haystack.len(),
            window,
            artifact_identity: expected_artifact_identity,
            descriptor_key,
            invocation_epoch: self.static_prefix_invocation_epoch,
        });
        Ok(())
    }

    #[inline]
    fn consume_static_prefix_object(
        &mut self,
        haystack: &[u8],
    ) -> Result<StaticPrefixObjectTicket, CompileError> {
        // A second continuation is a replay, not the synchronous Span
        // postflight selected by the first continuation. Retire any such
        // postflight capability before rejecting the missing object ticket.
        let (object, _) = self.retire_static_prefix_capabilities();
        let ticket = object.ok_or(
            CompileError::InternalInvariant(
                "static-prefix continuation has no synchronous object ticket",
            ),
        )?;
        if ticket.haystack_address != haystack.as_ptr().expose_provenance()
            || ticket.haystack_len != haystack.len()
            || ticket.invocation_epoch != self.static_prefix_invocation_epoch
            || ticket.artifact_identity != *self.frozen_header.artifact_identity()
        {
            return Err(CompileError::InternalInvariant(
                "static-prefix continuation haystack differs from object preflight",
            ));
        }
        Ok(ticket)
    }

    #[inline]
    fn validate_static_prefix_span_postflight_publication(
        &mut self,
        haystack: &[u8],
        ticket: &StaticPrefixObjectTicket,
    ) -> Result<StaticPrefixSpanPostflightPublication, CompileError> {
        let _ = self.retire_static_prefix_capabilities();
        if ticket.haystack_address != haystack.as_ptr().expose_provenance()
            || ticket.haystack_len != haystack.len()
            || ticket.invocation_epoch != self.static_prefix_invocation_epoch
            || ticket.artifact_identity != *self.frozen_header.artifact_identity()
        {
            return Err(CompileError::InternalInvariant(
                "static-prefix continuation cannot publish a foreign postflight",
            ));
        }
        if self.program.output_contract() == OutputContract::Span
            && self.program.exact_match_width().is_none()
        {
            Ok(StaticPrefixSpanPostflightPublication::VariableSpan {
                haystack_address: ticket.haystack_address,
                haystack_len: ticket.haystack_len,
                window: ticket.window,
                artifact_identity: ticket.artifact_identity,
                invocation_epoch: ticket.invocation_epoch,
            })
        } else {
            Ok(StaticPrefixSpanPostflightPublication::None)
        }
    }

    #[inline]
    fn install_static_prefix_span_postflight(
        &mut self,
        publication: StaticPrefixSpanPostflightPublication,
        recovery: Option<StaticPrefixSpanRecoveryAdmission>,
    ) {
        match (publication, recovery) {
            (StaticPrefixSpanPostflightPublication::None, None) => {}
            (
                StaticPrefixSpanPostflightPublication::VariableSpan {
                    haystack_address,
                    haystack_len,
                    window,
                    artifact_identity,
                    invocation_epoch,
                },
                Some(recovery),
            ) => {
                self.static_prefix_span_postflight_ticket =
                    Some(StaticPrefixSpanPostflightTicket {
                        haystack_address,
                        haystack_len,
                        window,
                        artifact_identity,
                        invocation_epoch,
                        recovery,
                    });
            }
            (StaticPrefixSpanPostflightPublication::None, Some(_)) => {
                unreachable!("non-variable-Span continuation minted a recovery admission");
            }
            (StaticPrefixSpanPostflightPublication::VariableSpan { .. }, None) => {
                unreachable!("variable-Span continuation omitted its recovery admission");
            }
        }
    }

    #[inline]
    fn consume_static_prefix_span_recovery_ticket(
        &mut self,
        haystack: &[u8],
        window: SearchWindow,
        expected_artifact_identity: [u8; ARTIFACT_IDENTITY_BYTES],
    ) -> Result<Option<StaticPrefixSpanRecoveryAdmission>, CompileError> {
        let (object, postflight) = self.retire_static_prefix_capabilities();
        let (
            haystack_address,
            haystack_len,
            admitted_window,
            artifact_identity,
            invocation_epoch,
            recovery,
        ) =
            match (object, postflight) {
                (Some(ticket), None) => (
                    ticket.haystack_address,
                    ticket.haystack_len,
                    ticket.window,
                    ticket.artifact_identity,
                    ticket.invocation_epoch,
                    None,
                ),
                (None, Some(ticket)) => (
                    ticket.haystack_address,
                    ticket.haystack_len,
                    ticket.window,
                    ticket.artifact_identity,
                    ticket.invocation_epoch,
                    Some(ticket.recovery),
                ),
                (None, None) | (Some(_), Some(_)) => {
                    return Err(CompileError::InternalInvariant(
                        "static-prefix Span recovery has no unique synchronous capability",
                    ));
                }
            };
        if haystack_address != haystack.as_ptr().expose_provenance()
            || haystack_len != haystack.len()
            || admitted_window != window
            || artifact_identity != expected_artifact_identity
            || invocation_epoch != self.static_prefix_invocation_epoch
        {
            return Err(CompileError::InternalInvariant(
                "static-prefix Span recovery differs from its admitted invocation",
            ));
        }
        Ok(recovery)
    }

    /// Execute without re-deserializing or allocating executor workspace.
    ///
    /// # Errors
    ///
    /// Returns a typed invalid-window or portable executor failure.
    pub fn search(
        &mut self,
        haystack: &[u8],
        window: SearchWindow,
    ) -> Result<MatchResult, CompileError> {
        self.deactivate_frozen_header();
        self.program
            .search_optimized_with_workspace(haystack, window, &mut self.workspace)
    }

    #[inline]
    fn search_without_endpoint_oracle(
        &mut self,
        haystack: &[u8],
        window: SearchWindow,
    ) -> Result<MatchResult, CompileError> {
        self.deactivate_frozen_header();
        self.program.search_without_endpoint_oracle_with_workspace(
            haystack,
            window,
            &mut self.workspace,
        )
    }

    #[inline]
    fn search_exclusive(
        &mut self,
        haystack: &[u8],
        window: SearchWindow,
    ) -> Result<MatchResult, CompileError> {
        self.deactivate_frozen_header();
        self.search_exclusive_after_deactivation(haystack, window)
    }

    /// Execute a portable exclusive search after the caller has retired all
    /// compiler-private native capabilities for the enclosing operation.
    #[inline]
    fn search_exclusive_after_deactivation(
        &mut self,
        haystack: &[u8],
        window: SearchWindow,
    ) -> Result<MatchResult, CompileError> {
        if let Some(receipt) = self.fully_prefilled_fallback {
            #[cfg(test)]
            {
                self.fully_prefilled_fallback_searches =
                    self.fully_prefilled_fallback_searches.saturating_add(1);
            }
            self.program
                .search_exclusive_optimized_with_fully_prefilled_fallback_workspace(
                    haystack,
                    window,
                    &mut self.workspace,
                    receipt,
                )
        } else {
            self.program.search_exclusive_optimized_with_workspace(
                haystack,
                window,
                &mut self.workspace,
            )
        }
    }

    fn search_from_retained_partial_resume(
        &mut self,
        haystack: &[u8],
        window: SearchWindow,
        expected_artifact_identity: [u8; ARTIFACT_IDENTITY_BYTES],
        resume_state: usize,
        resume_position: usize,
        pending_end: Option<usize>,
    ) -> Result<MatchResult, CompileError> {
        self.deactivate_frozen_header();
        if let Some(receipt) = self.fully_prefilled_fallback {
            self.program
                .search_from_retained_partial_resume_with_fully_prefilled_fallback_workspace(
                    haystack,
                    window,
                    &mut self.workspace,
                    expected_artifact_identity,
                    resume_state,
                    resume_position,
                    pending_end,
                    receipt,
                )
        } else {
            self.program.search_from_retained_partial_resume_with_workspace(
                haystack,
                window,
                &mut self.workspace,
                expected_artifact_identity,
                resume_state,
                resume_position,
                pending_end,
            )
        }
    }

    fn search_from_preflight_retained_partial_resume(
        &mut self,
        haystack: &[u8],
        window: SearchWindow,
        resume_state: usize,
        resume_position: usize,
        pending_end: Option<usize>,
    ) -> Result<MatchResult, CompileError> {
        self.deactivate_frozen_header();
        if let Some(receipt) = self.fully_prefilled_fallback {
            self.program
                .search_from_preflight_retained_partial_resume_with_fully_prefilled_fallback_workspace(
                    haystack,
                    window,
                    &mut self.workspace,
                    resume_state,
                    resume_position,
                    pending_end,
                    receipt,
                )
        } else {
            self.program
                .search_from_preflight_retained_partial_resume_with_workspace(
                haystack,
                window,
                &mut self.workspace,
                resume_state,
                resume_position,
                pending_end,
            )
        }
    }

    fn search_from_preflight_retained_partial_resume_ticket(
        &mut self,
        haystack: &[u8],
        resume_state: usize,
        resume_position: usize,
        pending_end: Option<usize>,
    ) -> Result<MatchResult, CompileError> {
        self.deactivate_frozen_header();
        if let Some(receipt) = self.fully_prefilled_fallback {
            self.program
                .search_from_preflight_retained_partial_resume_ticket_with_fully_prefilled_fallback_workspace(
                    haystack,
                    &mut self.workspace,
                    resume_state,
                    resume_position,
                    pending_end,
                    receipt,
                )
        } else {
            self.program
                .search_from_preflight_retained_partial_resume_ticket_with_workspace(
                haystack,
                &mut self.workspace,
                resume_state,
                resume_position,
                pending_end,
            )
        }
    }

    fn search_from_preflight_retained_partial_resume_ticket_inferred(
        &mut self,
        haystack: &[u8],
        resume_state: usize,
        resume_position: usize,
        pending_end: usize,
    ) -> Result<MatchResult, CompileError> {
        self.deactivate_frozen_header();
        if let Some(owner) = self.frozen_static_continuation_rows.as_ref()
            && let Some(receipt) = self.fully_prefilled_fallback
        {
            #[cfg(test)]
            {
                self.retained_partial_frozen_owner_handoffs = self
                    .retained_partial_frozen_owner_handoffs
                    .saturating_add(1);
            }
            return self
                .program
                .search_from_preflight_retained_partial_resume_ticket_inferred_with_frozen_static_continuation_rows_workspace(
                    haystack,
                    &mut self.workspace,
                    owner,
                    resume_state,
                    resume_position,
                    pending_end,
                    receipt,
                );
        }
        if let Some(receipt) = self.fully_prefilled_fallback {
            self.program
                .search_from_preflight_retained_partial_resume_ticket_inferred_with_fully_prefilled_fallback_workspace(
                    haystack,
                    &mut self.workspace,
                    resume_state,
                    resume_position,
                    pending_end,
                    receipt,
                )
        } else {
            self.program
                .search_from_preflight_retained_partial_resume_ticket_inferred_with_workspace(
                haystack,
                &mut self.workspace,
                resume_state,
                resume_position,
                pending_end,
            )
        }
    }

    /// Try the compact-v3 retained-hole handoff without consuming the root
    /// ticket on decline. A successful result has already published the exact
    /// immutable continuation header and transferred linear ownership to it.
    fn project_preflight_retained_partial_resume_ticket_to_native_continuation(
        &mut self,
        haystack: &[u8],
        resume_state: usize,
        resume_position: usize,
        pending_end: usize,
    ) -> Result<Option<(usize, usize)>, CompileError> {
        let Some(receipt) = self.fully_prefilled_fallback else {
            return Ok(None);
        };
        let Some(owner) = self.frozen_static_continuation_rows.as_ref() else {
            return Ok(None);
        };
        let Some(generation_key) = self
            .static_continuation_owner_generation_key
            .as_ref()
        else {
            return Ok(None);
        };
        let Some(projection) = self
            .program
            .try_project_preflight_retained_partial_resume_ticket_with_frozen_static_continuation_rows_workspace(
                haystack,
                &self.workspace,
                owner,
                resume_state,
                resume_position,
                pending_end,
                receipt,
            )?
        else {
            return Ok(None);
        };
        let Some(rearm) = self
            .program
            .compiler_private_validate_frozen_static_continuation_header_rearm(
                &self.workspace,
                owner,
                &mut self.static_continuation_header,
                generation_key,
                projection.format_version(),
            )
        else {
            return Ok(None);
        };

        // This is the final fallible operation. Once ownership leaves the
        // root there is no decline or portable re-entry before the exact
        // second-header generation is synchronously published.
        self.program
            .transfer_preflight_retained_partial_projection_with_workspace(
                &mut self.workspace,
                owner,
                projection,
            )?;
        // The retained preflight revoked both stable headers. Retire any
        // unrelated static-prefix capability and keep offset zero inactive;
        // only the exact second-header generation is republished below.
        let _ = self.static_prefix_object_ticket.take();
        let _ = self.static_prefix_span_postflight_ticket.take();
        if self.frozen_header.is_active() {
            self.frozen_header.deactivate();
        }
        rearm.compiler_private_commit();
        #[cfg(test)]
        {
            self.retained_partial_frozen_owner_handoffs = self
                .retained_partial_frozen_owner_handoffs
                .saturating_add(1);
        }
        Ok(Some((
            projection.canonical_state(),
            projection.pending_end_word(),
        )))
    }

    fn prepared_partial_should_enter(
        &mut self,
        input_bytes: usize,
    ) -> Result<bool, CompileError> {
        self.deactivate_frozen_header();
        self.program
            .prepared_partial_should_enter_with_workspace(&mut self.workspace, input_bytes)
    }

    fn preflight_retained_partial(
        &mut self,
        haystack: &[u8],
        window: SearchWindow,
        expected_artifact_identity: [u8; ARTIFACT_IDENTITY_BYTES],
    ) -> Result<RetainedPartialPreflight, CompileError> {
        self.deactivate_frozen_header();
        self.program.preflight_retained_partial_with_workspace(
            haystack,
            window,
            &mut self.workspace,
            expected_artifact_identity,
        )
    }

    fn recover_retained_partial_span_from_selected_end(
        &mut self,
        haystack: &[u8],
        window: SearchWindow,
        expected_artifact_identity: [u8; ARTIFACT_IDENTITY_BYTES],
        selected_end: usize,
    ) -> Result<MatchResult, CompileError> {
        self.deactivate_frozen_header();
        if let Some(receipt) = self.fully_prefilled_fallback {
            self.program
                .recover_retained_partial_span_from_selected_end_with_fully_prefilled_fallback_workspace(
                    haystack,
                    window,
                    &mut self.workspace,
                    expected_artifact_identity,
                    selected_end,
                    receipt,
                )
        } else {
            self.program
                .recover_retained_partial_span_from_selected_end_with_workspace(
                    haystack,
                    window,
                    &mut self.workspace,
                    expected_artifact_identity,
                    selected_end,
                )
        }
    }

    fn recover_static_prefix_span_from_selected_end(
        &mut self,
        haystack: &[u8],
        window: SearchWindow,
        expected_artifact_identity: [u8; ARTIFACT_IDENTITY_BYTES],
        selected_end: usize,
        admission: Option<StaticPrefixSpanRecoveryAdmission>,
    ) -> Result<MatchResult, CompileError> {
        self.deactivate_frozen_header();
        if let Some(admission) = admission {
            return self
                .program
                .recover_static_prefix_span_from_admission_with_workspace(
                    haystack,
                    &mut self.workspace,
                    admission,
                    selected_end,
                );
        }
        if let Some(receipt) = self.fully_prefilled_fallback {
            self.program
                .recover_static_prefix_span_from_selected_end_with_fully_prefilled_fallback_workspace(
                    haystack,
                    window,
                    &mut self.workspace,
                    expected_artifact_identity,
                    selected_end,
                    receipt,
                )
        } else {
            self.program
                .recover_static_prefix_span_from_selected_end_with_workspace(
                    haystack,
                    window,
                    &mut self.workspace,
                    expected_artifact_identity,
                    selected_end,
                )
        }
    }

    fn preflight_static_prefix_complete_proofs(
        &mut self,
        haystack: &[u8],
        window: SearchWindow,
        expected_artifact_identity: [u8; ARTIFACT_IDENTITY_BYTES],
    ) -> Result<RetainedPartialPreflight, CompileError> {
        if self
            .program
            .compiler_private_static_prefix_preflight_may_search_with_workspace(
                &self.workspace,
                window.end().saturating_sub(window.start()),
            )?
        {
            self.deactivate_frozen_header();
        }
        self.program
            .preflight_static_prefix_complete_proofs_with_workspace(
                haystack,
                window,
                &mut self.workspace,
                expected_artifact_identity,
            )
    }

    fn install_static_prefix_resume_receipt(
        &mut self,
        newly_published: Option<FullyPrefilledFallbackReceipt>,
    ) {
        if let Some(receipt) = newly_published {
            // Replacing the complete K0 cache retires every receipt and
            // immutable copy derived from its prior generation. Rebuild the
            // compact owner from the newly authenticated root-plus-resume
            // superset. A packing decline keeps the new fully-prefilled K0
            // continuation but must never retain the stale owner.
            self.frozen_header_owner_generation_key = None;
            self.static_continuation_owner_generation_key = None;
            self.frozen_header.deactivate();
            self.static_continuation_header.deactivate();
            self.fully_prefilled_fallback = None;
            self.frozen_dynamic_rows = None;
            self.frozen_static_continuation_rows = None;
            self.frozen_dynamic_rows = self
                .program
                .compiler_private_frozen_dynamic_rows_storage_v3_with_fallback_receipt(
                    &mut self.workspace,
                    Some(receipt),
                    FROZEN_DYNAMIC_SIDECAR_MAX_K0_BYTES,
                    FROZEN_DYNAMIC_SIDECAR_MAX_PACKED_BYTES,
                );
            let static_continuation_receipt = self
                .frozen_dynamic_rows
                .as_ref()
                .map(
                    FrozenDynamicRowsStorageV3::compiler_private_fully_prefilled_fallback_receipt,
                )
                .unwrap_or(receipt);
            self.frozen_static_continuation_rows = self
                .program
                .compiler_private_frozen_static_continuation_rows_storage_v3_with_fallback_receipt(
                    &mut self.workspace,
                    Some(static_continuation_receipt),
                    FROZEN_DYNAMIC_SIDECAR_MAX_K0_BYTES,
                    FROZEN_DYNAMIC_SIDECAR_MAX_PACKED_BYTES,
                );

            let root_publication = self.frozen_dynamic_rows.as_ref().and_then(|owner| {
                self.program
                    .compiler_private_frozen_prepared_header_v6_with_owner_generation_key(
                        &self.workspace,
                        owner,
                    )
            });
            if let Some((header, key)) = root_publication {
                self.frozen_header = header;
                self.frozen_header_owner_generation_key = Some(key);
            } else {
                self.frozen_dynamic_rows = None;
                self.frozen_header = self.program.compiler_private_frozen_prepared_header_v6(
                    &self.workspace,
                    None,
                    None,
                );
            }

            let continuation_publication = self
                .frozen_static_continuation_rows
                .as_ref()
                .and_then(|owner| {
                    self.program
                        .compiler_private_frozen_static_continuation_header_with_owner_generation_key(
                            &self.workspace,
                            owner,
                        )
                });
            if let Some((header, key)) = continuation_publication {
                self.static_continuation_header = header;
                self.static_continuation_owner_generation_key = Some(key);
            } else {
                self.frozen_static_continuation_rows = None;
                self.static_continuation_header = self
                    .program
                    .compiler_private_frozen_prepared_header_v6(&self.workspace, None, None);
            }
        }
        if self.frozen_dynamic_rows.is_none()
            && self.frozen_static_continuation_rows.is_none()
        {
            self.program
                .compiler_private_disable_static_prefix_resume_frozen_map_with_workspace(
                    &mut self.workspace,
                );
        }
    }

    #[inline]
    fn publish_static_prefix_continuation_projection(
        &mut self,
        haystack: &[u8],
        admission: StaticPrefixResumeAdmission,
        projection: FrozenStaticPrefixResumeProjection,
    ) -> Result<StaticPrefixFrozenProjectionOutcome, CompileError> {
        let Some(owner) = self.frozen_static_continuation_rows.as_ref() else {
            return Ok(StaticPrefixFrozenProjectionOutcome::Declined(admission));
        };
        let Some(generation_key) = self
            .static_continuation_owner_generation_key
            .as_ref()
        else {
            return Ok(StaticPrefixFrozenProjectionOutcome::Declined(admission));
        };
        let projection_format = projection.format_version();
        let active_header_format = self
            .static_continuation_header
            .compiler_private_dynamic_rows_format_version();
        let publication = if active_header_format == Some(projection_format) {
            Some(None)
        } else {
            self.program
                .compiler_private_validate_frozen_static_continuation_header_rearm(
                    &self.workspace,
                    owner,
                    &mut self.static_continuation_header,
                    generation_key,
                    projection_format,
                )
                .map(Some)
        };
        let Some(rearm) = publication else {
            return Ok(StaticPrefixFrozenProjectionOutcome::Declined(admission));
        };
        let canonical_state = projection.canonical_state();
        let pending_end = match projection.pending_end() {
            None => 0,
            Some(0) => {
                return Err(CompileError::InternalInvariant(
                    "static-prefix native projection cannot encode a zero pending endpoint",
                ));
            }
            Some(pending_end) => pending_end,
        };
        let span_recovery = self
            .program
            .consume_static_prefix_resume_admission_projection_with_workspace(
                haystack,
                &mut self.workspace,
                admission,
                projection,
            )?;
        if let Some(rearm) = rearm {
            rearm.compiler_private_commit();
        }
        Ok(StaticPrefixFrozenProjectionOutcome::Native {
            status: STATUS_STATIC_PREFIX_NATIVE_CONTINUATION_RESUME,
            canonical_state,
            pending_end,
            span_recovery,
        })
    }

    #[inline]
    fn publish_static_prefix_root_projection(
        &mut self,
        haystack: &[u8],
        admission: StaticPrefixResumeAdmission,
        projection: FrozenStaticPrefixResumeProjection,
    ) -> Result<StaticPrefixFrozenProjectionOutcome, CompileError> {
        let Some(owner) = self.frozen_dynamic_rows.as_ref() else {
            return Ok(StaticPrefixFrozenProjectionOutcome::Declined(admission));
        };
        let Some(generation_key) = self.frozen_header_owner_generation_key.as_ref() else {
            return Ok(StaticPrefixFrozenProjectionOutcome::Declined(admission));
        };
        if !matches!(
            projection.format_version(),
            FROZEN_DYNAMIC_ROWS_V3_FORMAT_VERSION
                | FROZEN_DYNAMIC_ROWS_V4_FORMAT_VERSION
                | FROZEN_DYNAMIC_ROWS_V8_FORMAT_VERSION
                | FROZEN_DYNAMIC_ROWS_V9_FORMAT_VERSION
                | FROZEN_DYNAMIC_ROWS_V10_FORMAT_VERSION
                | FROZEN_DYNAMIC_ROWS_V11_FORMAT_VERSION
                | FROZEN_DYNAMIC_ROWS_V12_FORMAT_VERSION
                | FROZEN_DYNAMIC_ROWS_V13_FORMAT_VERSION
                | FROZEN_DYNAMIC_ROWS_V14_FORMAT_VERSION
        ) {
            return Ok(StaticPrefixFrozenProjectionOutcome::Declined(admission));
        }
        let projection_format = projection.format_version();
        let active_header_format = self
            .frozen_header
            .compiler_private_dynamic_rows_format_version();
        let publication = if active_header_format == Some(projection_format) {
            Some(None)
        } else {
            self.program
                .compiler_private_validate_frozen_prepared_header_rearm(
                    &self.workspace,
                    owner,
                    &mut self.frozen_header,
                    generation_key,
                    projection_format,
                )
                .map(Some)
        };
        let Some(rearm) = publication else {
            return Ok(StaticPrefixFrozenProjectionOutcome::Declined(admission));
        };
        let canonical_state = projection.canonical_state();
        let pending_end = match projection.pending_end() {
            None => 0,
            Some(0) => {
                return Err(CompileError::InternalInvariant(
                    "static-prefix native projection cannot encode a zero pending endpoint",
                ));
            }
            Some(pending_end) => pending_end,
        };
        let span_recovery = self
            .program
            .consume_static_prefix_resume_admission_projection_with_workspace(
                haystack,
                &mut self.workspace,
                admission,
                projection,
            )?;
        if let Some(rearm) = rearm {
            rearm.compiler_private_commit();
        }
        Ok(StaticPrefixFrozenProjectionOutcome::Native {
            status: STATUS_STATIC_PREFIX_NATIVE_RESUME,
            canonical_state,
            pending_end,
            span_recovery,
        })
    }

    /// Authenticate one immutable compact continuation and publish the exact
    /// stable header consumed by the selected generated local tail. The
    /// continuation owner at the fixed second-header offset has precedence;
    /// the established root-compatible offset-zero owner remains status 7.
    /// Returned state words are physical-layout independent.
    fn project_static_prefix_resume_to_frozen_owner(
        &mut self,
        haystack: &[u8],
        mut admission: StaticPrefixResumeAdmission,
        resume_state: usize,
        resume_position: usize,
        pending_end: usize,
    ) -> Result<StaticPrefixFrozenProjectionOutcome, CompileError> {
        let frozen_selection = self
            .program
            .try_select_static_prefix_resume_admission_with_frozen_map(
                haystack,
                &self.workspace,
                &admission,
                resume_state,
                resume_position,
                pending_end,
            )?;
        #[cfg(test)]
        if frozen_selection.is_some() {
            self.static_prefix_dense_selections =
                self.static_prefix_dense_selections.saturating_add(1);
        }
        if let Some(selection) = frozen_selection.as_ref() {
            let continuation_projection = if self
                .static_continuation_owner_generation_key
                .is_some()
            {
                self.frozen_static_continuation_rows.as_ref().and_then(|owner| {
                    self.program
                    .try_project_static_prefix_resume_selection_with_frozen_static_continuation_rows(
                        &self.workspace,
                        owner,
                        &admission,
                        selection,
                    )
                })
            } else {
                None
            };
            if let Some(projection) = continuation_projection {
                match self.publish_static_prefix_continuation_projection(
                    haystack,
                    admission,
                    projection,
                )? {
                    native @ StaticPrefixFrozenProjectionOutcome::Native { .. } => {
                        return Ok(native);
                    }
                    StaticPrefixFrozenProjectionOutcome::Declined(returned) => {
                        admission = returned;
                    }
                }
            }

            let root_projection = if self.frozen_header_owner_generation_key.is_some() {
                self.frozen_dynamic_rows.as_ref().and_then(|owner| {
                    self.program
                        .try_project_static_prefix_resume_selection_with_frozen_rows(
                            &self.workspace,
                            owner,
                            &admission,
                            selection,
                        )
                })
            } else {
                None
            };
            if let Some(projection) = root_projection {
                match self.publish_static_prefix_root_projection(
                    haystack,
                    admission,
                    projection,
                )? {
                    native @ StaticPrefixFrozenProjectionOutcome::Native { .. } => {
                        return Ok(native);
                    }
                    StaticPrefixFrozenProjectionOutcome::Declined(returned) => {
                        admission = returned;
                    }
                }
            }
        }

        let continuation_projection = if self
            .static_continuation_owner_generation_key
            .is_some()
        {
            if let Some(owner) = self.frozen_static_continuation_rows.as_ref() {
                #[cfg(test)]
                {
                    self.static_prefix_legacy_projection_attempts = self
                        .static_prefix_legacy_projection_attempts
                        .saturating_add(1);
                }
                self.program
                    .try_project_static_prefix_resume_admission_with_frozen_static_continuation_rows(
                        haystack,
                        &mut self.workspace,
                        owner,
                        &admission,
                        resume_state,
                        resume_position,
                        pending_end,
                    )?
            } else {
                None
            }
        } else {
            None
        };
        if let Some(projection) = continuation_projection {
            match self.publish_static_prefix_continuation_projection(
                haystack,
                admission,
                projection,
            )? {
                native @ StaticPrefixFrozenProjectionOutcome::Native { .. } => {
                    return Ok(native);
                }
                StaticPrefixFrozenProjectionOutcome::Declined(returned) => {
                    admission = returned;
                }
            }
        }

        let root_projection = if self.frozen_header_owner_generation_key.is_some() {
            if let Some(owner) = self.frozen_dynamic_rows.as_ref() {
                #[cfg(test)]
                {
                    self.static_prefix_legacy_projection_attempts = self
                        .static_prefix_legacy_projection_attempts
                        .saturating_add(1);
                }
                self.program
                .try_project_static_prefix_resume_admission_with_frozen_rows(
                    haystack,
                    &mut self.workspace,
                    owner,
                    &admission,
                    resume_state,
                    resume_position,
                    pending_end,
                )?
            } else {
                None
            }
        } else {
            None
        };
        if let Some(projection) = root_projection {
            match self.publish_static_prefix_root_projection(
                haystack,
                admission,
                projection,
            )? {
                native @ StaticPrefixFrozenProjectionOutcome::Native { .. } => {
                    return Ok(native);
                }
                StaticPrefixFrozenProjectionOutcome::Declined(returned) => {
                    admission = returned;
                }
            }
        }
        Ok(StaticPrefixFrozenProjectionOutcome::Declined(admission))
    }

    fn search_from_static_prefix_resume_admission(
        &mut self,
        haystack: &[u8],
        admission: StaticPrefixResumeAdmission,
        resume_state: usize,
        resume_position: usize,
        pending_end: usize,
    ) -> Result<MatchResult, CompileError> {
        self.deactivate_frozen_header();
        let admission = if let Some(owner) = self.frozen_dynamic_rows.as_ref() {
            match self
                .program
                .try_search_from_static_prefix_resume_admission_with_frozen_rows(
                    haystack,
                    &mut self.workspace,
                    owner,
                    admission,
                    resume_state,
                    resume_position,
                    pending_end,
                )? {
                StaticPrefixResumeSearchOutcome::Complete(found) => return Ok(found),
                StaticPrefixResumeSearchOutcome::Declined(admission) => admission,
            }
        } else {
            admission
        };
        self.program
            .search_from_static_prefix_resume_admission_with_workspace(
                haystack,
                &mut self.workspace,
                admission,
                resume_state,
                resume_position,
                pending_end,
            )
    }

    /// Bind and consume one already-authenticated generated static-prefix
    /// object. The caller owns the ticket's provenance: eager ABI-V1/V3
    /// continuation takes it from the prepared owner, while fused ABI-V2/V4
    /// continuation constructs it on the stack after authenticating all raw
    /// object arguments.
    ///
    /// # Safety
    ///
    /// `ticket.descriptor_key` must name the still-live immutable
    /// compiler-owned descriptor promised by the private object ABI.
    #[allow(
        unsafe_code,
        reason = "the shared private continuation reads one bounded compiler-owned descriptor"
    )]
    unsafe fn continue_static_prefix_object(
        &mut self,
        haystack: &[u8],
        ticket: StaticPrefixObjectTicket,
        resume_state: usize,
        resume_position: usize,
        pending_end: usize,
    ) -> Result<StaticPrefixContinuationOutcome, CompileError> {
        debug_assert_eq!(
            ticket.haystack_address,
            haystack.as_ptr().expose_provenance(),
            "the caller must pass one authenticated object"
        );
        debug_assert_eq!(ticket.haystack_len, haystack.len());
        debug_assert_eq!(ticket.invocation_epoch, self.static_prefix_invocation_epoch);
        debug_assert_eq!(
            ticket.artifact_identity,
            *self.frozen_header.artifact_identity()
        );

        let admission = match self
            .program
            .classify_static_prefix_resume_object_with_workspace(
                haystack,
                ticket.window,
                &mut self.workspace,
                ticket.artifact_identity,
                ticket.descriptor_key,
            )?
        {
            StaticPrefixResumeAdmissionPlan::Warm(admission) => admission,
            StaticPrefixResumeAdmissionPlan::Cold(object) => {
                let descriptor_key = object.descriptor_key();
                let (header_words, expected_magic, reserved_start) =
                    match descriptor_key.version() {
                        STATIC_PREFIX_RESUME_DESCRIPTOR_V1_VERSION => (
                            STATIC_PREFIX_RESUME_DESCRIPTOR_V1_HEADER_BYTES
                                / std::mem::size_of::<u32>(),
                            STATIC_PREFIX_RESUME_DESCRIPTOR_V1_MAGIC,
                            5,
                        ),
                        STATIC_PREFIX_RESUME_DESCRIPTOR_V2_VERSION => (
                            STATIC_PREFIX_RESUME_DESCRIPTOR_V2_HEADER_BYTES
                                / std::mem::size_of::<u32>(),
                            STATIC_PREFIX_RESUME_DESCRIPTOR_V2_MAGIC,
                            6,
                        ),
                        _ => unreachable!("authenticated static-prefix descriptor key"),
                    };
                let descriptor_ptr =
                    std::ptr::with_exposed_provenance::<u32>(descriptor_key.address());
                // SAFETY: the private ABI promises a readable fixed header at
                // the authenticated compiler-owned address. Only its declared
                // word extent is consulted before the bounded check below.
                let header = unsafe {
                    std::slice::from_raw_parts(descriptor_ptr, header_words)
                };
                let total_words = usize::try_from(header[2]).map_err(|_| {
                    CompileError::InternalInvariant(
                        "static-prefix descriptor word count does not fit usize",
                    )
                })?;
                let total_bytes = total_words
                    .checked_mul(std::mem::size_of::<u32>())
                    .ok_or(CompileError::InternalInvariant(
                        "static-prefix descriptor byte count overflowed",
                    ))?;
                if total_words < header_words
                    || total_bytes > STATIC_PREFIX_RESUME_DESCRIPTOR_V1_MAX_BYTES
                {
                    return Err(CompileError::InternalInvariant(
                        "static-prefix descriptor extent is invalid",
                    ));
                }
                // Zero, undersized, oversized, and overflowing declarations
                // leave immutable owners published. Once the declared extent
                // is bounded, the cold transaction may replace K0 lineage, so
                // revoke both headers before semantic header validation and
                // full descriptor decode.
                self.deactivate_frozen_header();
                let mut magic = [0_u8; 8];
                magic[..4].copy_from_slice(&header[0].to_le_bytes());
                magic[4..].copy_from_slice(&header[1].to_le_bytes());
                let fixed_header_is_valid = &magic == expected_magic
                    && header[3] != 0
                    && header[4] != 0
                    && header[reserved_start..].iter().all(|&word| word == 0)
                    && (descriptor_key.version()
                        != STATIC_PREFIX_RESUME_DESCRIPTOR_V2_VERSION
                        || (header[4] <= 0x7fff_ffff
                            && matches!(header[5], 1 | 2 | 4)));
                if !fixed_header_is_valid {
                    return Err(CompileError::InternalInvariant(
                        "static-prefix descriptor fixed header is invalid",
                    ));
                }
                // SAFETY: the compiler-owned object promises the complete extent
                // declared by its checked fixed header.
                let descriptor = unsafe {
                    std::slice::from_raw_parts(descriptor_ptr, total_words)
                };
                let frozen_map_max_bytes = if self.frozen_dynamic_rows.is_some()
                    || self.frozen_static_continuation_rows.is_some()
                {
                    FROZEN_STATIC_PREFIX_RESUME_MAP_MAX_BYTES
                } else {
                    0
                };
                let (admission, newly_published) = self
                    .program
                    .bind_cold_static_prefix_resume_object_with_workspace_limits(
                        &mut self.workspace,
                        self.frozen_dynamic_rows.as_ref(),
                        object,
                        descriptor,
                        FROZEN_DYNAMIC_SIDECAR_MAX_K0_BYTES,
                        frozen_map_max_bytes,
                    )?;
                self.install_static_prefix_resume_receipt(newly_published);
                admission
            }
        };
        let span_postflight =
            self.validate_static_prefix_span_postflight_publication(haystack, &ticket)?;
        match self.project_static_prefix_resume_to_frozen_owner(
            haystack,
            admission,
            resume_state,
            resume_position,
            pending_end,
        )? {
            StaticPrefixFrozenProjectionOutcome::Native {
                status,
                canonical_state,
                pending_end,
                span_recovery,
            } => {
                self.install_static_prefix_span_postflight(span_postflight, span_recovery);
                Ok(StaticPrefixContinuationOutcome::Native {
                    status,
                    canonical_state,
                    pending_end,
                })
            }
            StaticPrefixFrozenProjectionOutcome::Declined(admission) => self
                .search_from_static_prefix_resume_admission(
                    haystack,
                    admission,
                    resume_state,
                    resume_position,
                    pending_end,
                )
                .map(StaticPrefixContinuationOutcome::Complete),
        }
    }

    fn preflight_retained_partial_native_root(
        &mut self,
        haystack: &[u8],
        window: SearchWindow,
        expected_artifact_identity: [u8; ARTIFACT_IDENTITY_BYTES],
    ) -> Result<RetainedPartialPreflight, CompileError> {
        self.deactivate_frozen_header();
        self.program
            .preflight_retained_partial_native_root_with_workspace(
                haystack,
                window,
                &mut self.workspace,
                expected_artifact_identity,
            )
    }

    fn preflight_dynamic_native_rows(
        &mut self,
        haystack: &[u8],
        window: SearchWindow,
        expected_artifact_identity: [u8; ARTIFACT_IDENTITY_BYTES],
    ) -> Result<(RetainedPartialPreflight, usize, u64), CompileError> {
        self.deactivate_frozen_header();
        self.program.preflight_dynamic_native_rows_with_workspace(
            haystack,
            window,
            &mut self.workspace,
            expected_artifact_identity,
        )
    }

    fn compiler_private_preflight_dynamic_native_rows_v3(
        &mut self,
        haystack: &[u8],
        window: SearchWindow,
        expected_artifact_identity: [u8; ARTIFACT_IDENTITY_BYTES],
    ) -> Result<(RetainedPartialPreflight, usize, u64), CompileError> {
        self.deactivate_frozen_header();
        self.program
            .compiler_private_preflight_dynamic_native_rows_v3_with_workspace(
                haystack,
                window,
                &mut self.workspace,
                expected_artifact_identity,
            )
    }

    fn search_after_dynamic_native_rows_deopt(
        &mut self,
        haystack: &[u8],
        window: SearchWindow,
    ) -> Result<MatchResult, CompileError> {
        self.deactivate_frozen_header();
        self.program
            .search_after_dynamic_native_rows_deopt_with_workspace(
                haystack,
                window,
                &mut self.workspace,
                self.fully_prefilled_fallback,
            )
    }

    fn settle_dynamic_native_rows_local_completion(&mut self) {
        self.deactivate_frozen_header();
        self.program
            .settle_dynamic_native_rows_local_completion_with_workspace(&mut self.workspace);
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the compiler-private continuation retains its full authentication payload"
    )]
    fn search_from_dynamic_native_rows_hole(
        &mut self,
        haystack: &[u8],
        window: SearchWindow,
        expected_artifact_identity: [u8; ARTIFACT_IDENTITY_BYTES],
        continuation: FreAotRegexDynamicRowsContinuationV1,
    ) -> Result<MatchResult, CompileError> {
        self.deactivate_frozen_header();
        self.program
            .search_from_dynamic_native_rows_hole_with_workspace(
                haystack,
                window,
                &mut self.workspace,
                expected_artifact_identity,
                continuation.current_row,
                continuation.resume_position,
                continuation.pending_valid,
                continuation.pending_end,
                continuation.cache_identity,
            )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the compiler-private cell resolver retains its full authentication payload"
    )]
    fn resolve_dynamic_native_rows_hole(
        &mut self,
        haystack: &[u8],
        window: SearchWindow,
        expected_artifact_identity: [u8; ARTIFACT_IDENTITY_BYTES],
        continuation: FreAotRegexDynamicRowsContinuationV1,
    ) -> Result<DynamicNativeRowsHoleResolution, CompileError> {
        self.deactivate_frozen_header();
        self.program.resolve_dynamic_native_rows_hole_with_workspace(
            haystack,
            window,
            &mut self.workspace,
            expected_artifact_identity,
            continuation.current_row,
            continuation.resume_position,
            continuation.pending_valid,
            continuation.pending_end,
            continuation.cache_identity,
        )
    }

    fn recover_dynamic_native_rows_span_from_selected_end(
        &mut self,
        haystack: &[u8],
        window: SearchWindow,
        expected_artifact_identity: [u8; ARTIFACT_IDENTITY_BYTES],
        selected_end: usize,
    ) -> Result<MatchResult, CompileError> {
        // Mint the no-preflight mode before any legacy revocation. The token
        // proves an active V3--V14 header whose published row pointer matches
        // this exact immutable owner. Reverse K0 receives only `workspace`, a
        // disjoint field whose allocations were prepared independently from
        // every header and sidecar allocation.
        let compact_capability = self.frozen_dynamic_rows.as_ref().and_then(|owner| {
            self.frozen_header
                .compiler_private_active_span_capability(
                    owner,
                    expected_artifact_identity,
                )
        });
        let used_compact_capability = compact_capability.is_some();
        let recovered = if let Some(capability) = compact_capability {
            self.program
                .recover_frozen_dynamic_rows_span_from_selected_end_with_workspace(
                    haystack,
                    window,
                    &mut self.workspace,
                    expected_artifact_identity,
                    selected_end,
                    capability,
                )
        } else {
            // Legacy V1/V2 and mutable dynamic rows retain the original
            // revoke-then-consume single-use preflight transaction.
            self.deactivate_frozen_header();
            self.program
                .recover_dynamic_native_rows_span_from_selected_end_with_workspace(
                    haystack,
                    window,
                    &mut self.workspace,
                    expected_artifact_identity,
                    selected_end,
                )
        };
        if recovered.is_err() && used_compact_capability {
            // A rejected compact postflight cannot leave a reusable capability
            // behind for a later endpoint or fallback invocation.
            self.deactivate_frozen_header();
        }
        recovered
    }

    /// Find the first selected span in `haystack`.
    ///
    /// # Errors
    ///
    /// Returns an output-contract error unless this artifact was compiled for
    /// [`OutputContract::Span`], or a search error if execution fails.
    pub fn find<'h>(
        &mut self,
        haystack: &'h [u8],
    ) -> Result<Option<AotMatch<'h>>, AotRegexFindError> {
        self.find_at(haystack, 0)
    }

    /// Find the first selected span at or after `start` in the original
    /// `haystack`.
    ///
    /// Passing the complete haystack preserves absolute and contextual
    /// assertions while only the search window advances.
    ///
    /// # Errors
    ///
    /// Returns an output-contract error unless this artifact was compiled for
    /// [`OutputContract::Span`]. An out-of-bounds `start` and executor failures
    /// are returned as [`AotRegexFindError::Search`].
    pub fn find_at<'h>(
        &mut self,
        haystack: &'h [u8],
        start: usize,
    ) -> Result<Option<AotMatch<'h>>, AotRegexFindError> {
        self.require_span_output()?;
        self.find_span_at(haystack, start)
    }

    /// Iterate over non-overlapping byte matches in the original haystack.
    ///
    /// Empty matches use byte-wise progress and an empty match at the previous
    /// match end is suppressed, matching `regex::bytes::Regex::find_iter`.
    /// The iterator exclusively borrows this prepared matcher so its reusable
    /// workspace remains attached for the complete iteration.
    ///
    /// # Errors
    ///
    /// Returns an output-contract error unless this artifact was compiled for
    /// [`OutputContract::Span`]. Execution failures are yielded by the
    /// iterator, which becomes fused after its first failure.
    pub fn find_iter<'p, 'h>(
        &'p mut self,
        haystack: &'h [u8],
    ) -> Result<PreparedAotMatches<'p, 'h>, AotRegexFindError> {
        self.require_span_output()?;
        Ok(PreparedAotMatches {
            prepared: self,
            haystack,
            start: 0,
            last_match_end: None,
            pending_empty_progress: false,
            finished: false,
        })
    }

    /// Count every selected non-overlapping byte match in `haystack`.
    ///
    /// This consumes the same iterator state machine as [`Self::find_iter`],
    /// including byte-wise empty progress and suppression of a repeated empty
    /// match at the preceding match end, without materializing a span array.
    ///
    /// # Errors
    ///
    /// Returns an output-contract error unless this artifact was compiled for
    /// [`OutputContract::Span`], or the first search failure observed during
    /// iteration.
    pub fn count_matches(&mut self, haystack: &[u8]) -> Result<u64, AotRegexFindError> {
        let mut value = 0_u64;
        for matched in self.find_iter(haystack)? {
            let _ = matched?;
            value = value.checked_add(1).ok_or(AotRegexFindError::Search(
                CompileError::InternalInvariant("prepared Count result overflowed u64"),
            ))?;
        }
        Ok(value)
    }

    /// Sum the byte widths of every selected non-overlapping match.
    ///
    /// Empty matches contribute zero while retaining the exact progress and
    /// suppression rules of [`Self::find_iter`]. No span output collection is
    /// allocated or materialized.
    ///
    /// # Errors
    ///
    /// Returns an output-contract error unless this artifact was compiled for
    /// [`OutputContract::Span`], or the first search/arithmetic failure
    /// observed during iteration.
    pub fn span_sum(&mut self, haystack: &[u8]) -> Result<u64, AotRegexFindError> {
        let mut value = 0_u64;
        for matched in self.find_iter(haystack)? {
            let width = u64::try_from(matched?.len()).map_err(|_| {
                AotRegexFindError::Search(CompileError::InternalInvariant(
                    "prepared SpanSum width did not fit u64",
                ))
            })?;
            value = value.checked_add(width).ok_or(AotRegexFindError::Search(
                CompileError::InternalInvariant("prepared SpanSum result overflowed u64"),
            ))?;
        }
        Ok(value)
    }

    /// Reduce spans after the exclusive ABI boundary has retired every native
    /// capability exactly once. Each advancing window uses the receipt-aware
    /// exclusive search entry without repeating that retirement.
    fn reduce_spans_exclusive_after_deactivation(
        &mut self,
        haystack: &[u8],
        reducer: ExclusiveSpanReducer,
    ) -> Result<u64, AotRegexFindError> {
        self.require_span_output()?;
        let mut value = 0_u64;
        let mut start = 0;
        let mut last_match_end = None;
        let mut pending_empty_progress = false;
        loop {
            if pending_empty_progress {
                pending_empty_progress = false;
                if start == haystack.len() {
                    return Ok(value);
                }
                start += 1;
            }

            let search_start = start;
            let result = self
                .search_exclusive_after_deactivation(
                    haystack,
                    SearchWindow::new(search_start, haystack.len()),
                )
                .map_err(AotRegexFindError::Search)?;
            let MatchResult::Span(found) = result else {
                return Err(AotRegexFindError::OutputContract {
                    actual: self.program.output_contract(),
                });
            };
            let Some((match_start, match_end)) = found else {
                return Ok(value);
            };
            if match_start < search_start || match_start > match_end || match_end > haystack.len() {
                return Err(AotRegexFindError::Search(
                    CompileError::InternalInvariant(
                        "exclusive span reducer received a match outside its search window",
                    ),
                ));
            }
            if match_start == match_end && last_match_end == Some(match_end) {
                if start == haystack.len() {
                    return Ok(value);
                }
                start += 1;
                continue;
            }

            let contribution = match reducer {
                ExclusiveSpanReducer::Count => 1,
                ExclusiveSpanReducer::SpanSum => {
                    u64::try_from(match_end - match_start).map_err(|_| {
                        AotRegexFindError::Search(CompileError::InternalInvariant(
                            "prepared SpanSum width did not fit u64",
                        ))
                    })?
                }
            };
            value = value.checked_add(contribution).ok_or(AotRegexFindError::Search(
                CompileError::InternalInvariant(match reducer {
                    ExclusiveSpanReducer::Count => "prepared Count result overflowed u64",
                    ExclusiveSpanReducer::SpanSum => {
                        "prepared SpanSum result overflowed u64"
                    }
                }),
            ))?;
            start = match_end;
            last_match_end = Some(match_end);
            pending_empty_progress = match_start == match_end;
        }
    }

    /// Prepare fixed storage for repeated whole-haystack plain-grep Count.
    ///
    /// Preparation depends only on the authenticated capture-free graph. It
    /// is independent of the search output contract and never reads source.
    /// Repeated calls reuse the same storage and perform no allocation.
    pub fn prepare_grep_count(
        &mut self,
    ) -> Result<GrepCountConstructionReceipt, AotRegexGrepCountError> {
        if self.grep_count_workspace.is_none() {
            self.grep_count_workspace = Some(
                self.program
                    .prepare_grep_count_workspace_with_limits(GrepCountWorkspaceLimits {
                        max_workspace_bytes: self.max_grep_count_workspace_bytes,
                    })
                    .map_err(AotRegexGrepCountError::Prepare)?,
            );
        }
        self.grep_count_workspace
            .as_ref()
            .map(GrepCountWorkspace::construction_receipt)
            .ok_or(AotRegexGrepCountError::Run(
                GrepCountError::WorkspaceBinding,
            ))
    }

    /// Count matching LF/CRLF line domains in one ordered source pass.
    ///
    /// The first call lazily prepares fixed storage completely before source
    /// access. Later calls allocate nothing. This operation never falls back
    /// to repeated per-line searches and is valid for every search output
    /// contract.
    pub fn grep_count_report(
        &mut self,
        haystack: &[u8],
    ) -> Result<GrepCountReceipt, AotRegexGrepCountError> {
        // Retire a capability left by a compiler-generated search before this
        // distinct exclusive operation mutates any reusable runtime state.
        self.settle_dynamic_native_rows_local_completion();
        let _ = self.prepare_grep_count()?;
        let program = &self.program;
        let workspace = self
            .grep_count_workspace
            .as_mut()
            .ok_or(AotRegexGrepCountError::Run(
                GrepCountError::WorkspaceBinding,
            ))?;
        program
            .grep_count_with_workspace(haystack, workspace)
            .map_err(AotRegexGrepCountError::Run)
    }

    /// Return only the matching-line count from [`Self::grep_count_report`].
    pub fn grep_count(&mut self, haystack: &[u8]) -> Result<u64, AotRegexGrepCountError> {
        self.grep_count_report(haystack)
            .map(GrepCountReceipt::count)
    }

    fn scan_frozen_loop(&self, scanner_address: usize, source: &[u8]) -> Option<usize> {
        if !self.frozen_header.is_active() || !self.frozen_header.has_dynamic_rows() {
            return None;
        }
        let artifact_identity = *self.frozen_header.artifact_identity();
        self.frozen_dynamic_rows
            .as_ref()?
            .compiler_private_scan_frozen_loop(artifact_identity, scanner_address, source)
    }

    fn require_span_output(&self) -> Result<(), AotRegexFindError> {
        let actual = self.program.output_contract();
        if actual == OutputContract::Span {
            Ok(())
        } else {
            Err(AotRegexFindError::OutputContract { actual })
        }
    }

    fn find_span_at<'h>(
        &mut self,
        haystack: &'h [u8],
        start: usize,
    ) -> Result<Option<AotMatch<'h>>, AotRegexFindError> {
        let result = self
            .search(haystack, SearchWindow::new(start, haystack.len()))
            .map_err(AotRegexFindError::Search)?;
        let MatchResult::Span(span) = result else {
            return Err(AotRegexFindError::OutputContract {
                actual: self.program.output_contract(),
            });
        };
        span.map(|(match_start, match_end)| {
            if match_start < start {
                return Err(AotRegexFindError::Search(CompileError::InternalInvariant(
                    "span program returned a match before its search start",
                )));
            }
            AotMatch::from_span(haystack, match_start, match_end).ok_or(AotRegexFindError::Search(
                CompileError::InternalInvariant(
                    "span program returned a match outside its haystack",
                ),
            ))
        })
        .transpose()
    }
}

/// Failure result returned by the fully validating private V1 loop helper.
///
/// Current generated code calls the trusted V2 helper and still compares its
/// result with the unchanged requested length before advancing position. Older
/// V1 callers observe this sentinel after any recoverable boundary failure.
pub const FROZEN_LOOP_SCAN_FAILURE: usize = usize::MAX;

/// Scan one immutable graph-proved loop member prefix.
///
/// This is a private generated-object ABI. The opaque scanner address is never
/// dereferenced directly: it must match the exact pointer retained by the live
/// prepared handle, whose artifact identity and active header are checked by
/// the safe owner method. A mismatch, panic, invalid extent, or inactive owner
/// returns [`FROZEN_LOOP_SCAN_FAILURE`].
///
/// # Safety
///
/// `handle` must name the live exclusive prepared session that entered the
/// generated matcher. `source_ptr` must be non-null and readable for exactly
/// `source_len` bytes during this call. No mutable operation may overlap the
/// call or release either owner.
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    reason = "the generated loop helper validates its raw handle and source at the C ABI boundary"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_scan_frozen_loop_v1(
    handle: FreAotRegexExclusiveHandleV1,
    scanner_address: usize,
    source_ptr: *const u8,
    source_len: usize,
) -> usize {
    if handle.is_invalid()
        || scanner_address == 0
        || source_ptr.is_null()
        || source_len > isize::MAX.unsigned_abs()
    {
        return FROZEN_LOOP_SCAN_FAILURE;
    }
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: the function contract supplies both live extents. The
        // prepared owner validates the opaque scanner address before following
        // its own independently retained pointer.
        let prepared = unsafe { &*handle.0.cast::<PreparedAotRegex>() };
        // SAFETY: the caller guarantees this exact readable source extent.
        let source = unsafe { std::slice::from_raw_parts(source_ptr, source_len) };
        prepared
            .scan_frozen_loop(scanner_address, source)
            .filter(|&consumed| consumed <= source_len)
            .unwrap_or(FROZEN_LOOP_SCAN_FAILURE)
    }))
    .unwrap_or(FROZEN_LOOP_SCAN_FAILURE)
}

/// Scan one already-authenticated immutable loop member prefix.
///
/// This private V2 generated-object ABI deliberately takes no prepared handle.
/// Generated V6/V7 code has already authenticated the exclusive active
/// capability, selected an in-range frozen plan, checked the plan's canonical
/// state against the live table key, and loaded the non-null scanner address
/// published by that immutable owner. Omitting the handle prevents repeating
/// owner/header/identity/plan-list validation and panic framing inside every
/// profitable loop scan. The source pointer is first in this private ABI so
/// both supported ISAs can form it in place while retaining the authenticated
/// scanner in their second argument register.
///
/// The V1 helper remains the fully validating boundary for older generated
/// objects and callers that do not carry the active-capability proof.
///
/// # Safety
///
/// `scanner` must be non-null, aligned, and point to the exact
/// [`FrozenCompactLoopScanner`] retained by the live exclusive prepared owner
/// whose V6/V7 capability was authenticated by the calling generated entry.
/// That owner must remain exclusively live and immutable for the complete
/// call. `source_ptr` must be non-null and readable for exactly `source_len`
/// bytes, `source_len` must not exceed `isize::MAX`, and the extent must remain
/// live for the complete call. Violating this trusted private ABI is undefined
/// behavior.
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    reason = "authenticated generated code supplies one typed immutable scanner and exact readable source extent"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_scan_frozen_loop_v2(
    source_ptr: *const u8,
    scanner: *const FrozenCompactLoopScanner,
    source_len: usize,
) -> usize {
    // SAFETY: the private V2 contract supplies the exact live typed owner and
    // readable byte extent. `scan_prefix` is total for every byte sequence and
    // returns a value no greater than the supplied source length.
    let scanner = std::ptr::with_exposed_provenance::<FrozenCompactLoopScanner>(scanner.addr());
    let scanner = unsafe { &*scanner };
    // SAFETY: guaranteed by the same private V2 contract.
    let source = unsafe { std::slice::from_raw_parts(source_ptr, source_len) };
    scanner.scan_prefix(source)
}

/// Fallible iterator over non-overlapping matches from a prepared AOT Span
/// artifact.
#[derive(Debug)]
pub struct PreparedAotMatches<'p, 'h> {
    prepared: &'p mut PreparedAotRegex,
    haystack: &'h [u8],
    start: usize,
    last_match_end: Option<usize>,
    pending_empty_progress: bool,
    finished: bool,
}

impl PreparedAotMatches<'_, '_> {
    fn fail<'h>(&mut self, error: AotRegexFindError) -> Result<AotMatch<'h>, AotRegexFindError> {
        self.finished = true;
        Err(error)
    }

    fn advance_past_repeated_empty(&mut self) -> bool {
        if self.start == self.haystack.len() {
            self.finished = true;
            return false;
        }
        self.start = self.start.saturating_add(1);
        true
    }
}

impl<'h> Iterator for PreparedAotMatches<'_, 'h> {
    type Item = Result<AotMatch<'h>, AotRegexFindError>;

    fn next(&mut self) -> Option<Self::Item> {
        while !self.finished {
            if self.pending_empty_progress {
                self.pending_empty_progress = false;
                if !self.advance_past_repeated_empty() {
                    return None;
                }
            }

            let matched = match self.prepared.find_span_at(self.haystack, self.start) {
                Ok(Some(matched)) => matched,
                Ok(None) => {
                    self.finished = true;
                    return None;
                }
                Err(error) => return Some(self.fail(error)),
            };

            if matched.is_empty() && self.last_match_end == Some(matched.end()) {
                if !self.advance_past_repeated_empty() {
                    return None;
                }
                continue;
            }

            self.start = matched.end();
            self.last_match_end = Some(matched.end());
            self.pending_empty_progress = matched.is_empty();
            return Some(Ok(matched));
        }
        None
    }
}

impl std::iter::FusedIterator for PreparedAotMatches<'_, '_> {}

struct PreparedHandleState {
    prepared: Mutex<Option<PreparedAotRegex>>,
}

struct PreparedRegistry {
    next_token: u64,
    entries: HashMap<u64, Arc<PreparedHandleState>>,
}

impl PreparedRegistry {
    fn new() -> Self {
        Self {
            next_token: 1,
            entries: HashMap::new(),
        }
    }

    fn insert(&mut self, prepared: PreparedAotRegex) -> Result<FreAotRegexPreparedHandleV1, ()> {
        let token = self.next_token;
        let Some(next_token) = token.checked_add(1) else {
            return Err(());
        };
        if token == 0 || self.entries.contains_key(&token) {
            return Err(());
        }
        self.next_token = next_token;
        self.entries.insert(
            token,
            Arc::new(PreparedHandleState {
                prepared: Mutex::new(Some(prepared)),
            }),
        );
        Ok(FreAotRegexPreparedHandleV1(token))
    }
}

fn prepared_registry() -> &'static Mutex<PreparedRegistry> {
    static REGISTRY: OnceLock<Mutex<PreparedRegistry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(PreparedRegistry::new()))
}

fn prepared_entry(
    handle: FreAotRegexPreparedHandleV1,
) -> Result<Option<Arc<PreparedHandleState>>, ()> {
    prepared_registry()
        .lock()
        .map(|registry| registry.entries.get(&handle.0).cloned())
        .map_err(|_| ())
}

thread_local! {
    /// One bounded per-thread registry hit. Repeated searches normally use one
    /// prepared program, so retaining its state owner removes the global map
    /// mutex and `Arc` increment from the hot path. Tokens are never reused,
    /// and destroy clears the state behind every retained owner before it
    /// returns, so a cached entry cannot revive an invalidated handle.
    static PREPARED_ENTRY_CACHE: RefCell<Option<(u64, Arc<PreparedHandleState>)>> =
        const { RefCell::new(None) };
}

fn with_cached_prepared_entry<T>(
    handle: FreAotRegexPreparedHandleV1,
    use_entry: impl FnOnce(&PreparedHandleState) -> T,
) -> Result<Option<T>, ()> {
    PREPARED_ENTRY_CACHE
        .try_with(|cache| {
            let mut cache = cache.try_borrow_mut().map_err(|_| ())?;
            if cache.as_ref().is_none_or(|(token, _)| *token != handle.0) {
                let Some(entry) = prepared_entry(handle)? else {
                    return Ok(None);
                };
                *cache = Some((handle.0, entry));
            }
            Ok(cache.as_ref().map(|(_, entry)| use_entry(entry.as_ref())))
        })
        .map_err(|_| ())?
}

fn remove_prepared_entry(
    handle: FreAotRegexPreparedHandleV1,
) -> Result<Option<Arc<PreparedHandleState>>, ()> {
    prepared_registry()
        .lock()
        .map(|mut registry| registry.entries.remove(&handle.0))
        .map_err(|_| ())
}

fn register_prepared(prepared: PreparedAotRegex) -> Result<FreAotRegexPreparedHandleV1, ()> {
    prepared_registry().lock().map_err(|_| ())?.insert(prepared)
}

/// Failure while constructing owned reusable runtime state.
#[derive(Debug)]
pub enum PrepareError {
    Format(ProgramFormatError),
    Workspace(CompileError),
}

impl std::fmt::Display for PrepareError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Format(error) => write!(formatter, "program preparation failed: {error}"),
            Self::Workspace(error) => write!(formatter, "workspace preparation failed: {error}"),
        }
    }
}

impl std::error::Error for PrepareError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Format(error) => Some(error),
            Self::Workspace(error) => Some(error),
        }
    }
}

/// Validate, own, and prepare one exact serialized program for repeated C ABI
/// searches.
///
/// On status [`STATUS_SUCCESS`], `handle_out` is initialized to a new
/// process-local handle and the caller may immediately release or reuse the
/// source bytes. On every failure status, `handle_out` is left untouched.
///
/// # Thread safety
///
/// Preparation is thread-safe. The returned token may be copied to other
/// threads, subject to the exclusive-search contract documented on
/// [`fre_aot_regex_runtime_search_prepared_v1`].
///
/// # Safety
///
/// `program_ptr` must be non-null and readable for exactly `program_len`
/// bytes for this call; that extent must reside in one allocated object and be
/// no larger than `isize::MAX`. `handle_out` must be non-null, properly
/// aligned, and writable for one [`FreAotRegexPreparedHandleV1`]. The output
/// storage must not overlap the program extent.
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    reason = "this exported symbol is an audited raw C pointer boundary"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_prepare_v1(
    program_ptr: *const u8,
    program_len: usize,
    handle_out: *mut FreAotRegexPreparedHandleV1,
) -> u32 {
    if program_ptr.is_null()
        || handle_out.is_null()
        || !handle_out.is_aligned()
        || program_len > isize::MAX.unsigned_abs()
    {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: the function contract supplies the readable source extent and
    // aligned, writable, non-overlapping output. The checked helper borrows
    // the source only for deserialization and writes the output last.
    catch_unwind(AssertUnwindSafe(|| unsafe {
        prepare_checked_pointers(program_ptr, program_len, handle_out)
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

#[allow(
    unsafe_code,
    reason = "slice construction and the final disjoint handle write are confined to this audited helper"
)]
unsafe fn prepare_checked_pointers(
    program_ptr: *const u8,
    program_len: usize,
    handle_out: *mut FreAotRegexPreparedHandleV1,
) -> u32 {
    // SAFETY: guaranteed by the exported prepare contract and checked length.
    let program_bytes = unsafe { std::slice::from_raw_parts(program_ptr, program_len) };
    let Ok(prepared) = PreparedAotRegex::deserialize(program_bytes) else {
        return STATUS_RUNTIME_FAILURE;
    };
    let Ok(handle) = register_prepared(prepared) else {
        return STATUS_RUNTIME_FAILURE;
    };
    // SAFETY: guaranteed aligned, writable, and disjoint by the exported
    // prepare contract. No borrow of `program_bytes` survives preparation.
    unsafe { handle_out.write(handle) };
    STATUS_SUCCESS
}

/// Validate, own, and prepare one serialized program as an exclusively owned
/// direct-pointer session.
///
/// On success, `handle_out` receives a non-null handle and the source bytes
/// may immediately be released. Unlike the registry-backed prepared ABI, the
/// returned handle has no recoverable stale-handle or concurrent-use checks.
///
/// # Safety
///
/// The pointer requirements are identical to
/// [`fre_aot_regex_runtime_prepare_v1`]. After success, the caller must retain
/// exclusive ownership of the returned handle, pass it only to the exclusive
/// search and destroy functions, and destroy it exactly once.
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    reason = "this exported symbol is an audited raw C pointer boundary"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_prepare_exclusive_v1(
    program_ptr: *const u8,
    program_len: usize,
    handle_out: *mut FreAotRegexExclusiveHandleV1,
) -> u32 {
    if program_ptr.is_null()
        || handle_out.is_null()
        || !handle_out.is_aligned()
        || program_len > isize::MAX.unsigned_abs()
    {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: the function contract supplies the readable source extent and
    // aligned, writable, non-overlapping output.
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let program_bytes = std::slice::from_raw_parts(program_ptr, program_len);
        let Ok(prepared) = PreparedAotRegex::deserialize(program_bytes) else {
            return STATUS_RUNTIME_FAILURE;
        };
        let allocation = Box::into_raw(Box::new(prepared)).cast::<std::ffi::c_void>();
        handle_out.write(FreAotRegexExclusiveHandleV1(allocation));
        STATUS_SUCCESS
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

/// Validate, own, and prepare one serialized program for explicitly declared
/// exclusive operations.
///
/// Configuration validation happens before the program bytes are inspected or
/// any preparation allocation is attempted. On success, every declared
/// operation has completed its source-independent setup: Search, Count, and
/// SpanSum have settled the immutable K0 start-filter policy, while GrepCount
/// owns its fixed workspace. Undeclared operations retain the V1 lazy setup
/// behavior. These guarantees cover the runtime handle search and reducer
/// functions; a compiler-produced native-fused object entry may declare
/// additional object-descriptor setup in a later ABI. Every failure leaves
/// `handle_out` untouched.
///
/// Count and SpanSum require a Span-output artifact. An insufficient
/// `max_start_filter_setup_work` safely and permanently selects ordinary K0;
/// an insufficient `max_grep_count_workspace_bytes` fails the transaction.
///
/// # Safety
///
/// `program_ptr` must be non-null and readable for exactly `program_len`
/// bytes, with a length no greater than `isize::MAX`. `config_ptr` must be
/// non-null, aligned, and readable for one [`FreAotRegexPrepareConfigV2`].
/// `handle_out` must be non-null, aligned, and writable for one
/// [`FreAotRegexExclusiveHandleV1`]. The writable output must not overlap
/// either readable extent. After success, the V1 exclusive ownership and
/// destruction rules apply to the returned handle.
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    reason = "this exported symbol is an audited raw C pointer boundary"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_prepare_exclusive_v2(
    program_ptr: *const u8,
    program_len: usize,
    config_ptr: *const FreAotRegexPrepareConfigV2,
    handle_out: *mut FreAotRegexExclusiveHandleV1,
) -> u32 {
    if program_ptr.is_null()
        || config_ptr.is_null()
        || !config_ptr.is_aligned()
        || handle_out.is_null()
        || !handle_out.is_aligned()
        || program_len > isize::MAX.unsigned_abs()
    {
        return STATUS_INVALID_ARGUMENT;
    }

    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: the function contract supplies one aligned readable config.
        // Copy and validate it before constructing the program slice.
        let config = unsafe { config_ptr.read() };
        if !config.is_valid() {
            return STATUS_INVALID_ARGUMENT;
        }
        // SAFETY: the function contract supplies this readable source extent.
        let program_bytes = unsafe { std::slice::from_raw_parts(program_ptr, program_len) };
        let Ok(prepared) =
            PreparedAotRegex::deserialize_with_prepare_config_v2(program_bytes, config)
        else {
            return STATUS_RUNTIME_FAILURE;
        };
        let allocation = Box::into_raw(Box::new(prepared)).cast::<std::ffi::c_void>();
        // SAFETY: the function contract supplies aligned, writable, disjoint
        // output storage. This is the transaction's final observable write.
        unsafe { handle_out.write(FreAotRegexExclusiveHandleV1(allocation)) };
        STATUS_SUCCESS
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

/// Validate and prepare an exclusive handle that a native Ordered-TNFA
/// aggregate/fill object may require.
///
/// Configuration is copied and validated before program bytes are read. Count
/// or SpanSum declarations whose required-capability mask selects V15 require
/// successful scratch admission; a structural, allocation, or exact-cap
/// refusal fails preparation and leaves `handle_out` untouched. This prevents
/// a native-only aggregate export from silently publishing a handle that can
/// execute only through a semantic helper. Without the V15 bit, the complete
/// V2 behavior is retained.
///
/// # Safety
///
/// `program_ptr` must be non-null and readable for exactly `program_len`
/// bytes, with a length no greater than `isize::MAX`. `config_ptr` must be
/// non-null, aligned, and readable for one [`FreAotRegexPrepareConfigV3`].
/// `handle_out` must be non-null, aligned, writable for one
/// [`FreAotRegexExclusiveHandleV1`], and disjoint from both readable extents.
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    reason = "this exported symbol is an audited raw C pointer boundary"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_prepare_exclusive_v3(
    program_ptr: *const u8,
    program_len: usize,
    config_ptr: *const FreAotRegexPrepareConfigV3,
    handle_out: *mut FreAotRegexExclusiveHandleV1,
) -> u32 {
    if program_ptr.is_null()
        || config_ptr.is_null()
        || !config_ptr.is_aligned()
        || handle_out.is_null()
        || !handle_out.is_aligned()
        || program_len > isize::MAX.unsigned_abs()
    {
        return STATUS_INVALID_ARGUMENT;
    }

    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: the function contract supplies one aligned readable config.
        let config = unsafe { config_ptr.read() };
        if !config.is_valid() {
            return STATUS_INVALID_ARGUMENT;
        }
        // SAFETY: the function contract supplies this readable source extent.
        let program_bytes = unsafe { std::slice::from_raw_parts(program_ptr, program_len) };
        let Ok(prepared) =
            PreparedAotRegex::deserialize_with_prepare_config_v3(program_bytes, config)
        else {
            return STATUS_RUNTIME_FAILURE;
        };
        let allocation = Box::into_raw(Box::new(prepared)).cast::<std::ffi::c_void>();
        // SAFETY: validation completed and the caller supplies disjoint,
        // aligned writable output. This is the only observable transaction
        // write.
        unsafe { handle_out.write(FreAotRegexExclusiveHandleV1(allocation)) };
        STATUS_SUCCESS
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

/// Validate and prepare one canonical Stage-1 operation set.
///
/// The config is copied and validated before the operation-set bytes are
/// inspected. Preparation accepts only scalar members in the canonical
/// optimizer-free V4 `OrderedNfa` generic form, derives the exact per-member
/// operation union from roots, applies every cap once to the complete handle,
/// and publishes the opaque owner only after all prospective and actual
/// accounting checks succeed. Every failure leaves `handle_out` untouched,
/// and no reference into the input wire is retained.
///
/// # Safety
///
/// `operation_set_ptr` must be non-null and readable for
/// `operation_set_len` bytes, with a length no greater than `isize::MAX`.
/// `config_ptr` must be non-null, aligned, and readable for one
/// [`FreAotRegexOperationSetPrepareConfigV1`]. `handle_out` must be non-null,
/// aligned, writable for one [`FreAotRegexOperationSetExclusiveHandleV1`],
/// and disjoint from both readable extents. A successful handle must be used
/// exclusively and destroyed exactly once.
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    reason = "this exported symbol is an audited raw C pointer boundary"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_prepare_operation_set_exclusive_v1(
    operation_set_ptr: *const u8,
    operation_set_len: usize,
    config_ptr: *const FreAotRegexOperationSetPrepareConfigV1,
    handle_out: *mut FreAotRegexOperationSetExclusiveHandleV1,
) -> u32 {
    if operation_set_ptr.is_null()
        || config_ptr.is_null()
        || !config_ptr.is_aligned()
        || handle_out.is_null()
        || !handle_out.is_aligned()
        || operation_set_len > isize::MAX.unsigned_abs()
    {
        return STATUS_INVALID_ARGUMENT;
    }
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: the caller supplies one aligned readable config. Validate
        // it before constructing or inspecting the operation-set slice.
        let config = unsafe { config_ptr.read() };
        if !config.is_valid() {
            return STATUS_INVALID_ARGUMENT;
        }
        // SAFETY: the caller supplies this complete readable extent.
        let bytes = unsafe {
            std::slice::from_raw_parts(operation_set_ptr, operation_set_len)
        };
        let Ok((prepared, _receipt)) =
            PreparedAotOperationSet::deserialize_with_config(bytes, config)
        else {
            return STATUS_RUNTIME_FAILURE;
        };
        let Ok(owner) = try_box_preserve(prepared) else {
            return STATUS_RUNTIME_FAILURE;
        };
        let allocation = Box::into_raw(owner).cast::<std::ffi::c_void>();
        // SAFETY: the caller supplies aligned writable disjoint output. This
        // is the complete transaction's final observable write.
        unsafe {
            handle_out.write(FreAotRegexOperationSetExclusiveHandleV1(allocation));
        }
        STATUS_SUCCESS
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

/// Execute every prepared root in canonical wire order.
///
/// `output_count` must equal the operation count in the prepared set. All
/// roots execute into handle-owned scratch; only complete success copies the
/// entire root-aligned array to `outputs`. Any error leaves caller output
/// untouched. Search record status carries match/no-match; the function's own
/// success status is always [`STATUS_SUCCESS`]. An argument-validation failure
/// happens before source or workspace mutation and the handle remains reusable.
/// A [`STATUS_RUNTIME_FAILURE`] can leave internal scratch/workspace advanced;
/// caller output is still untouched, but the handle is then valid only for one
/// destruction and must not execute again.
///
/// # Safety
///
/// `handle` must be a live uniquely owned value returned by
/// [`fre_aot_regex_runtime_prepare_operation_set_exclusive_v1`]. No execute or
/// destroy may overlap. `haystack_ptr` must be non-null and readable for
/// `haystack_len` bytes. `outputs` must be non-null, aligned, writable for
/// `output_count` records. The haystack extent, output extent, and handle
/// allocation together with all handle-owned storage must be pairwise
/// disjoint. Every extent must remain live for the complete call.
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    reason = "this exported symbol validates raw extents and commits outputs only after complete execution"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_execute_operation_set_exclusive_v1(
    handle: FreAotRegexOperationSetExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    outputs: *mut FreAotRegexOperationSetOutputV1,
    output_count: usize,
) -> u32 {
    if handle.is_invalid() {
        return STATUS_INVALID_HANDLE;
    }
    let output_bytes = output_count
        .checked_mul(std::mem::size_of::<FreAotRegexOperationSetOutputV1>());
    if haystack_ptr.is_null()
        || outputs.is_null()
        || !outputs.is_aligned()
        || haystack_len > isize::MAX.unsigned_abs()
        || !matches!(output_bytes, Some(bytes) if bytes <= isize::MAX.unsigned_abs())
    {
        return STATUS_INVALID_ARGUMENT;
    }
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let prepared = &mut *handle.0.cast::<PreparedAotOperationSet>();
        if output_count != prepared.roots.len() {
            return STATUS_INVALID_ARGUMENT;
        }
        let haystack = std::slice::from_raw_parts(haystack_ptr, haystack_len);
        if prepared.execute(haystack).is_err() {
            return STATUS_RUNTIME_FAILURE;
        }
        std::ptr::copy_nonoverlapping(
            prepared.output_scratch.as_ptr(),
            outputs,
            output_count,
        );
        STATUS_SUCCESS
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

/// Release one exclusively owned prepared operation set.
///
/// # Safety
///
/// `handle` must be a live value returned by
/// [`fre_aot_regex_runtime_prepare_operation_set_exclusive_v1`]. No execute
/// may overlap, and no handle copy may be used or destroyed afterward.
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    reason = "this exported symbol releases an exclusively owned opaque allocation"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_destroy_operation_set_exclusive_v1(
    handle: FreAotRegexOperationSetExclusiveHandleV1,
) -> u32 {
    if handle.is_invalid() {
        return STATUS_INVALID_HANDLE;
    }
    catch_unwind(AssertUnwindSafe(|| unsafe {
        drop(Box::from_raw(handle.0.cast::<PreparedAotOperationSet>()));
        STATUS_SUCCESS
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

/// Search an owned prepared program without reconstructing it or allocating
/// executor workspace.
///
/// Status and result conventions are identical to
/// [`fre_aot_regex_runtime_search_v1`]. Additionally,
/// [`STATUS_HANDLE_BUSY`] reports overlapping mutable searches or a destroy
/// that has acquired the handle state, and
/// [`STATUS_INVALID_HANDLE`] reports a zero, unknown, destroyed, or
/// concurrently invalidated handle. Every failure leaves `result_ptr`
/// untouched.
///
/// # Thread safety
///
/// Tokens may be passed between threads, but the workspace is mutable and
/// exclusive: at most one search per handle may execute at a time. Overlap is
/// rejected without waiting. Different handles may search concurrently.
/// Destroy waits for a search that already acquired the handle. A search
/// racing with destroy can complete first, observe [`STATUS_INVALID_HANDLE`],
/// or observe [`STATUS_HANDLE_BUSY`] while destroy owns the state mutex.
///
/// # Safety
///
/// `haystack_ptr` must be non-null and readable for `haystack_len` bytes for
/// this call. `result_ptr` must be non-null, properly aligned, and writable
/// for one [`FreAotRegexResultV1`]. The two extents must not overlap, each
/// extent must reside in one allocated object, and `haystack_len` must be no
/// greater than `isize::MAX`.
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    reason = "this exported symbol is an audited raw C pointer boundary"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_search_prepared_v1(
    handle: FreAotRegexPreparedHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
) -> u32 {
    if handle.is_invalid() {
        return STATUS_INVALID_HANDLE;
    }
    if haystack_ptr.is_null()
        || result_ptr.is_null()
        || !result_ptr.is_aligned()
        || haystack_len > isize::MAX.unsigned_abs()
        || window_start > window_end
        || window_end > haystack_len
    {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: the function contract supplies the readable haystack and
    // aligned, writable, non-overlapping result extent.
    catch_unwind(AssertUnwindSafe(|| unsafe {
        search_prepared_checked_pointers(
            handle,
            haystack_ptr,
            haystack_len,
            window_start,
            window_end,
            result_ptr,
        )
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

#[allow(
    unsafe_code,
    reason = "slice construction and the final disjoint result write are confined to this audited helper"
)]
unsafe fn search_prepared_checked_pointers(
    handle: FreAotRegexPreparedHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
) -> u32 {
    let searched = with_cached_prepared_entry(handle, |entry| {
        let mut state = match entry.prepared.try_lock() {
            Ok(state) => state,
            Err(TryLockError::WouldBlock) => return Err(STATUS_HANDLE_BUSY),
            Err(TryLockError::Poisoned(_)) => return Err(STATUS_RUNTIME_FAILURE),
        };
        let Some(prepared) = state.as_mut() else {
            return Err(STATUS_INVALID_HANDLE);
        };
        // SAFETY: guaranteed by the exported prepared-search contract and
        // checked length.
        let haystack = unsafe { std::slice::from_raw_parts(haystack_ptr, haystack_len) };
        execute_search(prepared, haystack, window_start, window_end)
            .map_err(|_| STATUS_RUNTIME_FAILURE)
    });
    let (status, result) = match searched {
        Ok(Some(Ok(found))) => found,
        Ok(Some(Err(status))) => return status,
        Ok(None) => return STATUS_INVALID_HANDLE,
        Err(()) => return STATUS_RUNTIME_FAILURE,
    };
    // SAFETY: guaranteed aligned, writable, and disjoint by the exported
    // prepared-search contract.
    unsafe { result_ptr.write(result) };
    status
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DynamicNativeRowsFallbackOutcome {
    LocalCompletion,
    Deopt,
}

#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "the shared implementation validates and executes one raw exclusive-search ABI"
)]
fn search_exclusive_with_dynamic_rows_outcome(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    dynamic_rows_outcome: DynamicNativeRowsFallbackOutcome,
) -> u32 {
    if handle.is_invalid() {
        return STATUS_INVALID_HANDLE;
    }
    if haystack_ptr.is_null()
        || result_ptr.is_null()
        || !result_ptr.is_aligned()
        || haystack_len > isize::MAX.unsigned_abs()
        || window_start > window_end
        || window_end > haystack_len
    {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: each exported caller requires the live exclusively owned
    // session plus readable haystack and writable disjoint result extents.
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let prepared = &mut *handle.0.cast::<PreparedAotRegex>();
        let haystack = std::slice::from_raw_parts(haystack_ptr, haystack_len);
        let searched = match dynamic_rows_outcome {
            DynamicNativeRowsFallbackOutcome::LocalCompletion => {
                prepared.settle_dynamic_native_rows_local_completion();
                prepared.search_exclusive(
                    haystack,
                    SearchWindow::new(window_start, window_end),
                )
            }
            DynamicNativeRowsFallbackOutcome::Deopt => prepared
                .search_after_dynamic_native_rows_deopt(
                    haystack,
                    SearchWindow::new(window_start, window_end),
                ),
        };
        let Ok(found) = searched else {
            return STATUS_RUNTIME_FAILURE;
        };
        let (status, result) = encode_match_result(found);
        result_ptr.write(result);
        status
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

/// Search an exclusively owned direct-pointer prepared session.
///
/// Status and result conventions are identical to
/// [`fre_aot_regex_runtime_search_v1`]. This path performs no registry lookup,
/// reference counting, thread-local access, or synchronization.
///
/// # Safety
///
/// `handle` must be a live value returned by
/// [`fre_aot_regex_runtime_prepare_exclusive_v1`], with no overlapping search
/// or destroy call on any copy. It must not have been destroyed. Haystack and
/// result pointer requirements are identical to
/// [`fre_aot_regex_runtime_search_prepared_v1`].
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    reason = "this exported symbol is an audited raw C pointer boundary"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_search_exclusive_v1(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
) -> u32 {
    search_exclusive_with_dynamic_rows_outcome(
        handle,
        haystack_ptr,
        haystack_len,
        window_start,
        window_end,
        result_ptr,
        DynamicNativeRowsFallbackOutcome::LocalCompletion,
    )
}

fn exclusive_span_iter_state_is_valid(
    state: &FreAotRegexIterStateV1,
    haystack_len: usize,
) -> bool {
    let has_last = state.flags & ITER_HAS_LAST != 0;
    let pending = state.flags & ITER_PENDING_EMPTY != 0;
    let finished = state.flags & ITER_FINISHED != 0;
    state.reserved == 0
        && state.flags & !ITER_KNOWN_FLAGS == 0
        && state.next_start <= haystack_len
        && state.last_match_end <= haystack_len
        && (!pending
            || (has_last && !finished && state.next_start == state.last_match_end))
        && (has_last
            || (state.next_start == 0 && state.last_match_end == 0))
        && (!has_last || state.next_start >= state.last_match_end)
}

fn finish_exclusive_span_iter(state: &mut FreAotRegexIterStateV1) {
    state.flags = (state.flags & ITER_HAS_LAST) | ITER_FINISHED;
}

/// Fill non-overlapping Spans through one exclusively owned prepared runtime.
///
/// This is the target-neutral bulk fallback used by compiler-produced
/// RuntimeAdapter objects. It validates and dereferences the exclusive handle
/// once, retains its workspace for the complete refill, and implements the
/// byte-empty progress rules documented by [`FreAotRegexIterStateV1`]. Status
/// and prefix-publication conventions are those of
/// [`FreAotRegexExclusiveSpanFillV1`].
///
/// # Safety
///
/// `handle` must satisfy the exclusive ownership contract of
/// [`fre_aot_regex_runtime_search_exclusive_v1`]. `haystack_ptr` must be
/// non-null and readable for `haystack_len` bytes. `state` and `written_out`
/// must be non-null, naturally aligned, and writable. When `capacity` is
/// nonzero, `results` must be non-null, naturally aligned, and writable for
/// that many records. Every readable and writable extent must reside in one
/// allocation and the writable extents must be mutually disjoint and disjoint
/// from the haystack.
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the exported stateful bulk ABI validates and executes one raw exclusive session"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_fill_spans_exclusive_v1(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    state: *mut FreAotRegexIterStateV1,
    results: *mut FreAotRegexResultV1,
    capacity: usize,
    written_out: *mut usize,
) -> u32 {
    if handle.is_invalid() {
        return STATUS_INVALID_HANDLE;
    }
    if haystack_ptr.is_null()
        || state.is_null()
        || !state.is_aligned()
        || written_out.is_null()
        || !written_out.is_aligned()
        || haystack_len > isize::MAX.unsigned_abs()
        || capacity > isize::MAX.unsigned_abs() / std::mem::size_of::<FreAotRegexResultV1>()
        || (capacity != 0 && (results.is_null() || !results.is_aligned()))
    {
        return STATUS_INVALID_ARGUMENT;
    }

    let execution = catch_unwind(AssertUnwindSafe(|| unsafe {
        let state = &mut *state;
        if !exclusive_span_iter_state_is_valid(state, haystack_len) {
            return STATUS_INVALID_ARGUMENT;
        }
        written_out.write(0);
        if capacity == 0 {
            return if state.flags & ITER_FINISHED != 0 {
                STATUS_NO_MATCH
            } else {
                STATUS_MATCH
            };
        }

        let prepared = &mut *handle.0.cast::<PreparedAotRegex>();
        // A generated native entry may have left one unobserved admission on
        // this reusable handle. Retire it once before the portable bulk loop;
        // portable searches cannot mint another native-entry admission.
        prepared.settle_dynamic_native_rows_local_completion();
        let haystack = std::slice::from_raw_parts(haystack_ptr, haystack_len);
        let results = std::slice::from_raw_parts_mut(results, capacity);
        let mut written = 0;
        loop {
            if state.flags & ITER_FINISHED != 0 {
                return STATUS_NO_MATCH;
            }
            if state.flags & ITER_PENDING_EMPTY != 0 {
                state.flags &= !ITER_PENDING_EMPTY;
                if state.next_start == haystack_len {
                    finish_exclusive_span_iter(state);
                    return STATUS_NO_MATCH;
                }
                state.next_start += 1;
            }

            let search_start = state.next_start;
            let searched = prepared.search_exclusive_after_deactivation(
                haystack,
                SearchWindow::new(search_start, haystack_len),
            );
            let found = match searched {
                Ok(MatchResult::Span(found)) => found,
                Ok(_) | Err(_) => {
                    finish_exclusive_span_iter(state);
                    return STATUS_RUNTIME_FAILURE;
                }
            };
            let Some((start, end)) = found else {
                finish_exclusive_span_iter(state);
                return STATUS_NO_MATCH;
            };
            if start < search_start || start > end || end > haystack_len {
                finish_exclusive_span_iter(state);
                return STATUS_RUNTIME_FAILURE;
            }

            if start == end
                && state.flags & ITER_HAS_LAST != 0
                && state.last_match_end == end
            {
                if state.next_start == haystack_len {
                    finish_exclusive_span_iter(state);
                    return STATUS_NO_MATCH;
                }
                state.next_start += 1;
                continue;
            }

            state.next_start = end;
            state.last_match_end = end;
            state.flags = ITER_HAS_LAST
                | if start == end {
                    ITER_PENDING_EMPTY
                } else {
                    0
                };
            results[written] = FreAotRegexResultV1 { start, end };
            written += 1;
            written_out.write(written);
            if written == capacity {
                return STATUS_MATCH;
            }
        }
    }));
    match execution {
        Ok(status) => status,
        Err(_) => {
            // SAFETY: raw validation above established an aligned writable
            // state pointer, and the exclusive call still owns it here.
            unsafe { finish_exclusive_span_iter(&mut *state) };
            STATUS_RUNTIME_FAILURE
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum ExclusiveSpanReducer {
    Count,
    SpanSum,
}

#[derive(Clone, Copy)]
enum ExclusiveReducer {
    Count,
    SpanSum,
    GrepCount,
}

#[allow(
    unsafe_code,
    reason = "the shared reducer validates its raw C pointers before constructing slices or publishing output"
)]
unsafe fn reduce_exclusive_v1(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    value_out: *mut u64,
    reducer: ExclusiveReducer,
    expected_artifact_identity_ptr: Option<*const u8>,
) -> u32 {
    if handle.is_invalid() {
        return STATUS_INVALID_HANDLE;
    }
    if haystack_ptr.is_null()
        || value_out.is_null()
        || !value_out.is_aligned()
        || haystack_len > isize::MAX.unsigned_abs()
    {
        return STATUS_INVALID_ARGUMENT;
    }
    if expected_artifact_identity_ptr.is_some_and(<*const u8>::is_null) {
        return STATUS_INVALID_ARGUMENT;
    }

    catch_unwind(AssertUnwindSafe(|| unsafe {
        let prepared = &mut *handle.0.cast::<PreparedAotRegex>();
        if let Some(expected_artifact_identity_ptr) = expected_artifact_identity_ptr {
            let expected_artifact_identity: [u8; ARTIFACT_IDENTITY_BYTES] =
                std::slice::from_raw_parts(
                    expected_artifact_identity_ptr,
                    ARTIFACT_IDENTITY_BYTES,
                )
                .try_into()
                .expect("fixed artifact-identity extent");
            if expected_artifact_identity != *prepared.frozen_header.artifact_identity() {
                return STATUS_RUNTIME_FAILURE;
            }
        }
        if !matches!(reducer, ExclusiveReducer::GrepCount)
            && prepared.program.output_contract() != OutputContract::Span
        {
            return STATUS_RUNTIME_FAILURE;
        }
        let haystack = std::slice::from_raw_parts(haystack_ptr, haystack_len);
        match prepared.reduce_exclusive_operation(haystack, reducer) {
            Ok(value) => {
                value_out.write(value);
                STATUS_SUCCESS
            }
            Err(_) => STATUS_RUNTIME_FAILURE,
        }
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

/// Count all selected non-overlapping matches through one exclusive prepared
/// Span runtime.
///
/// The handle is dereferenced once for the complete operation. The existing
/// prepared workspace and exact byte-empty iteration rules are reused without
/// materializing an intermediate span buffer. `value_out` is written only
/// after successful completion.
///
/// # Safety
///
/// `handle` must satisfy the exclusive ownership contract of
/// [`fre_aot_regex_runtime_search_exclusive_v1`]. `haystack_ptr` must be
/// non-null and readable for `haystack_len` bytes, while `value_out` must be
/// non-null, naturally aligned, writable for one `u64`, and disjoint from the
/// haystack. Both extents must remain live for the complete call.
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    reason = "the exported Count symbol is an audited raw C pointer boundary"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_count_exclusive_v1(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    value_out: *mut u64,
) -> u32 {
    // SAFETY: the shared boundary repeats every raw-pointer validation before
    // dereference and preserves output transactionality.
    unsafe {
        reduce_exclusive_v1(
            handle,
            haystack_ptr,
            haystack_len,
            value_out,
            ExclusiveReducer::Count,
            None,
        )
    }
}

/// Sum all selected non-overlapping match widths through one exclusive
/// prepared Span runtime.
///
/// Empty matches contribute zero and retain the same progress/suppression
/// behavior as the prepared Span iterator. `value_out` is written only after
/// successful completion.
///
/// # Safety
///
/// `handle` must satisfy the exclusive ownership contract of
/// [`fre_aot_regex_runtime_search_exclusive_v1`]. `haystack_ptr` must be
/// non-null and readable for `haystack_len` bytes, while `value_out` must be
/// non-null, naturally aligned, writable for one `u64`, and disjoint from the
/// haystack. Both extents must remain live for the complete call.
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    reason = "the exported SpanSum symbol is an audited raw C pointer boundary"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_span_sum_exclusive_v1(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    value_out: *mut u64,
) -> u32 {
    // SAFETY: the shared boundary repeats every raw-pointer validation before
    // dereference and preserves output transactionality.
    unsafe {
        reduce_exclusive_v1(
            handle,
            haystack_ptr,
            haystack_len,
            value_out,
            ExclusiveReducer::SpanSum,
            None,
        )
    }
}

/// Count matching LF/CRLF line domains through one exclusive prepared
/// runtime.
///
/// The one-pass p16 reducer strips one CR immediately before LF, treats every
/// other CR as content, and creates no synthetic domain for empty input or
/// after a trailing LF. Fixed storage is prepared before source access on the
/// first call and reused thereafter. `value_out` is written only after a
/// successful complete reduction. The program's search output contract is
/// irrelevant.
///
/// # Safety
///
/// `handle` must satisfy the exclusive ownership contract of
/// [`fre_aot_regex_runtime_search_exclusive_v1`]. `haystack_ptr` must be
/// non-null and readable for `haystack_len` bytes, while `value_out` must be
/// non-null, naturally aligned, writable for one `u64`, and disjoint from the
/// haystack. Both extents must remain live for the complete call.
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    reason = "the exported GrepCount symbol is an audited raw C pointer boundary"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_grep_count_exclusive_v1(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    value_out: *mut u64,
) -> u32 {
    // SAFETY: the shared boundary repeats every raw-pointer validation before
    // dereference and preserves output transactionality.
    unsafe {
        reduce_exclusive_v1(
            handle,
            haystack_ptr,
            haystack_len,
            value_out,
            ExclusiveReducer::GrepCount,
            None,
        )
    }
}

/// Compiler-private Count continuation that binds an object entry to the
/// exact semantic artifact used to prepare its exclusive handle.
///
/// # Safety
///
/// The public reducer pointer requirements apply. In addition,
/// `expected_artifact_identity_ptr` must be non-null and readable for exactly
/// [`ARTIFACT_IDENTITY_BYTES`] bytes for the complete call.
#[unsafe(no_mangle)]
#[doc(hidden)]
#[allow(
    unsafe_code,
    reason = "the compiler-private Count continuation validates its raw identity pointer before use"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_compiler_private_count_exclusive_v1(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    value_out: *mut u64,
    expected_artifact_identity_ptr: *const u8,
) -> u32 {
    // SAFETY: the shared boundary repeats all raw-pointer validation and binds
    // the handle before any workspace mutation or output publication.
    unsafe {
        reduce_exclusive_v1(
            handle,
            haystack_ptr,
            haystack_len,
            value_out,
            ExclusiveReducer::Count,
            Some(expected_artifact_identity_ptr),
        )
    }
}

/// Compiler-private SpanSum continuation that binds an object entry to the
/// exact semantic artifact used to prepare its exclusive handle.
///
/// # Safety
///
/// The public reducer pointer requirements apply. In addition,
/// `expected_artifact_identity_ptr` must be non-null and readable for exactly
/// [`ARTIFACT_IDENTITY_BYTES`] bytes for the complete call.
#[unsafe(no_mangle)]
#[doc(hidden)]
#[allow(
    unsafe_code,
    reason = "the compiler-private SpanSum continuation validates its raw identity pointer before use"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_compiler_private_span_sum_exclusive_v1(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    value_out: *mut u64,
    expected_artifact_identity_ptr: *const u8,
) -> u32 {
    // SAFETY: the shared boundary repeats all raw-pointer validation and binds
    // the handle before any workspace mutation or output publication.
    unsafe {
        reduce_exclusive_v1(
            handle,
            haystack_ptr,
            haystack_len,
            value_out,
            ExclusiveReducer::SpanSum,
            Some(expected_artifact_identity_ptr),
        )
    }
}

/// Compiler-private GrepCount continuation binding an object entry to the
/// exact semantic artifact used to prepare its exclusive handle.
///
/// # Safety
///
/// The public GrepCount pointer requirements apply. In addition,
/// `expected_artifact_identity_ptr` must be non-null and readable for exactly
/// [`ARTIFACT_IDENTITY_BYTES`] bytes for the complete call.
#[unsafe(no_mangle)]
#[doc(hidden)]
#[allow(
    unsafe_code,
    reason = "the compiler-private GrepCount continuation validates its raw identity pointer before use"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_compiler_private_grep_count_exclusive_v1(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    value_out: *mut u64,
    expected_artifact_identity_ptr: *const u8,
) -> u32 {
    // SAFETY: the shared boundary repeats all raw-pointer validation and binds
    // the handle before fixed-workspace mutation or output publication.
    unsafe {
        reduce_exclusive_v1(
            handle,
            haystack_ptr,
            haystack_len,
            value_out,
            ExclusiveReducer::GrepCount,
            Some(expected_artifact_identity_ptr),
        )
    }
}

/// Search independent haystacks through one exclusively owned prepared
/// runtime.
///
/// This is the target-neutral batch fallback used by compiler-produced
/// RuntimeAdapter objects. The handle is validated and dereferenced once for
/// the complete batch. Status and prefix-publication conventions are those of
/// [`FreAotRegexExclusiveExistsBatchV1`].
///
/// # Safety
///
/// `handle` must satisfy the exclusive ownership contract of
/// [`fre_aot_regex_runtime_search_exclusive_v1`]. `processed_out` must be
/// non-null, naturally aligned, and writable. For a nonzero `count`,
/// `haystacks` must be non-null, naturally aligned, and readable for `count`
/// descriptors, while `matched_out` must be writable for `count` bytes. Each
/// descriptor pointer must be non-null and readable for its declared length.
/// All extents must reside in allocated objects, and writable extents must not
/// overlap any input or each other.
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    reason = "the exported batch ABI validates and executes one raw exclusive session"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_is_match_batch_exclusive_v1(
    handle: FreAotRegexExclusiveHandleV1,
    haystacks: *const FreAotRegexHaystackV1,
    count: usize,
    matched_out: *mut u8,
    processed_out: *mut usize,
) -> u32 {
    if handle.is_invalid() {
        return STATUS_INVALID_HANDLE;
    }
    if processed_out.is_null()
        || !processed_out.is_aligned()
        || count > isize::MAX.unsigned_abs() / std::mem::size_of::<FreAotRegexHaystackV1>()
        || (count != 0
            && (haystacks.is_null() || !haystacks.is_aligned() || matched_out.is_null()))
    {
        return STATUS_INVALID_ARGUMENT;
    }

    catch_unwind(AssertUnwindSafe(|| unsafe {
        processed_out.write(0);
        if count == 0 {
            return STATUS_SUCCESS;
        }
        let prepared = &mut *handle.0.cast::<PreparedAotRegex>();
        // See the Span-fill path: one settlement retires any admission left
        // by a prior generated call, and this portable batch creates none.
        prepared.settle_dynamic_native_rows_local_completion();
        let haystacks = std::slice::from_raw_parts(haystacks, count);
        let matched_out = std::slice::from_raw_parts_mut(matched_out, count);
        for (index, descriptor) in haystacks.iter().enumerate() {
            if descriptor.ptr.is_null() || descriptor.len > isize::MAX.unsigned_abs() {
                return STATUS_INVALID_ARGUMENT;
            }
            let haystack = std::slice::from_raw_parts(descriptor.ptr, descriptor.len);
            let searched = prepared
                .search_exclusive_after_deactivation(haystack, SearchWindow::full(haystack));
            let matched = match searched {
                Ok(MatchResult::Exists(matched)) => matched,
                Ok(_) | Err(_) => return STATUS_RUNTIME_FAILURE,
            };
            matched_out[index] = u8::from(matched);
            processed_out.write(index + 1);
        }
        STATUS_SUCCESS
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

/// Authenticate one compiler-owned static native prefix search.
///
/// This compiler-private entry validates the ordinary exclusive-search
/// boundary and binds generated code to the exact prepared artifact. The
/// authenticated preflight may return a complete whole-window proof, or it may
/// complete an exact ordinary variable-width Span when the prepared workspace
/// lacks reverse-only recovery. Otherwise it admits the immutable native
/// prefix over the unchanged search window. A later native hole still leaves
/// generated code and completes the same whole search through
/// [`fre_aot_regex_runtime_search_exclusive_v1`].
///
/// The helper is deliberately independent of serialized retained-DFA rows.
/// Optimizing compilation can therefore publish a transient, resource-bounded
/// native prefix without adding pattern-specific state to the stable program
/// format or rebuilding a runtime on every hole.
///
/// # Safety
///
/// `handle` must satisfy the exclusive ownership contract of
/// [`fre_aot_regex_runtime_search_exclusive_v1`]. Haystack and result extents
/// have the same requirements. `expected_artifact_identity_ptr` must address
/// exactly [`ARTIFACT_IDENTITY_BYTES`] readable bytes and be disjoint from the
/// writable result for the duration of the call.
#[doc(hidden)]
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "the compiler-private static-prefix boundary authenticates raw generated-code arguments"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_preflight_v1(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    expected_artifact_identity_ptr: *const u8,
) -> u32 {
    if handle.is_invalid() {
        return STATUS_INVALID_HANDLE;
    }
    // A non-null private owner is valid even when a later raw argument is
    // malformed. ABI-V1 and ABI-V2 share that owner, so beginning either
    // generation retires every single-use capability left by the other.
    // SAFETY: this follows the function's exclusive live-handle premise and
    // does not inspect any as-yet-unvalidated caller pointer.
    let _ = unsafe {
        &mut *handle.0.cast::<PreparedAotRegex>()
    }
    .retire_static_prefix_capabilities();
    if haystack_ptr.is_null()
        || result_ptr.is_null()
        || !result_ptr.is_aligned()
        || expected_artifact_identity_ptr.is_null()
        || haystack_len > isize::MAX.unsigned_abs()
        || window_start > window_end
        || window_end > haystack_len
    {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: the caller guarantees one live exclusively owned allocation and
    // every readable/writable extent documented above. Cross-version private
    // capabilities were retired above before every outcome. The ordinary
    // program preflight may complete a variable-width Span here when this
    // handle has no authenticated reverse-only recovery; in that case it owns
    // the same exclusive workspace and publishes the result transactionally.
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let expected_artifact_identity = expected_artifact_identity_ptr
            .cast::<[u8; ARTIFACT_IDENTITY_BYTES]>()
            .read();
        let prepared = &mut *handle.0.cast::<PreparedAotRegex>();
        if expected_artifact_identity != *prepared.frozen_header.artifact_identity() {
            return STATUS_RUNTIME_FAILURE;
        }
        let Ok(may_search) = prepared
            .program
            .compiler_private_static_prefix_preflight_may_search_with_workspace(
                &prepared.workspace,
                window_end.saturating_sub(window_start),
            )
        else {
            return STATUS_RUNTIME_FAILURE;
        };
        if !may_search {
            return STATUS_PARTIAL_PREFLIGHT_ENTER;
        }
        let haystack = std::slice::from_raw_parts(haystack_ptr, haystack_len);
        let window = SearchWindow::new(window_start, window_end);
        let Ok(preflight) = prepared.preflight_static_prefix_complete_proofs(
            haystack,
            window,
            expected_artifact_identity,
        ) else {
            return STATUS_RUNTIME_FAILURE;
        };
        if let RetainedPartialPreflight::Complete(found) = preflight {
            let (status, result) = encode_match_result(found);
            result_ptr.write(result);
            return status;
        }
        debug_assert_eq!(preflight, RetainedPartialPreflight::Enter(window));
        STATUS_PARTIAL_PREFLIGHT_ENTER
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

/// Authenticate one compiler-owned static-prefix object and admit one
/// synchronous native search window.
///
/// Like ABI-V1, this preflight can first run graph-derived complete suffix/cut
/// proofs or finish an uncertified variable-width Span through ordinary exact
/// execution. Unlike ABI-V1, an inconclusive proof retains the descriptor
/// address with the exact haystack and window, but does not read the
/// descriptor, bind its frontiers, or fill K0 caches. Those costs remain
/// deferred until native code reaches a hole. Generated code must consume the
/// ticket through either the matching continuation or Span postflight.
///
/// This private object/runtime seam is intentionally absent from the public C
/// header. The descriptor is object data, not stable serialized-program data.
///
/// # Safety
///
/// The handle, haystack, result, and identity requirements are identical to
/// [`fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_preflight_v1`].
/// `descriptor_ptr` must be aligned for `u32` and address a readable canonical
/// wire-V1 descriptor whose fixed header declares its complete readable
/// extent. ABI-V2 preflight stores but does not dereference this pointer. The
/// extent must not overlap writable result storage, its bytes must remain
/// immutable, and it must remain live through synchronous native execution
/// and any continuation. Its address remains the private binding capability
/// for the lifetime of the generated object.
#[doc(hidden)]
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "the compiler-private static-prefix boundary binds generated object data and an exact call"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_preflight_v2(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    expected_artifact_identity_ptr: *const u8,
    descriptor_ptr: *const u32,
) -> u32 {
    if handle.is_invalid() {
        return STATUS_INVALID_HANDLE;
    }
    if haystack_ptr.is_null()
        || result_ptr.is_null()
        || !result_ptr.is_aligned()
        || expected_artifact_identity_ptr.is_null()
        || descriptor_ptr.is_null()
        || !descriptor_ptr.is_aligned()
        || haystack_len > isize::MAX.unsigned_abs()
        || window_start > window_end
        || window_end > haystack_len
    {
        // SAFETY: every non-invalid handle supplied to this unsafe ABI remains
        // one live exclusively owned prepared allocation even when another
        // boundary argument is malformed.
        let _ = unsafe {
            &mut *handle.0.cast::<PreparedAotRegex>()
        }
        .retire_static_prefix_capabilities();
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: the caller supplies the live exclusive owner and every extent
    // documented above. Descriptor access is deferred to the hole continuation;
    // the optional portable stage uses only the authenticated program/window.
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let haystack = std::slice::from_raw_parts(haystack_ptr, haystack_len);
        let expected_artifact_identity = expected_artifact_identity_ptr
            .cast::<[u8; ARTIFACT_IDENTITY_BYTES]>()
            .read();
        let prepared = &mut *handle.0.cast::<PreparedAotRegex>();
        let _ = prepared.retire_static_prefix_capabilities();
        let window = SearchWindow::new(window_start, window_end);
        let Ok(preflight) = prepared.preflight_static_prefix_complete_proofs(
            haystack,
            window,
            expected_artifact_identity,
        ) else {
            return STATUS_RUNTIME_FAILURE;
        };
        if let RetainedPartialPreflight::Complete(found) = preflight {
            let (status, result) = encode_match_result(found);
            result_ptr.write(result);
            return status;
        }
        debug_assert_eq!(preflight, RetainedPartialPreflight::Enter(window));
        let Ok(()) = prepared.admit_static_prefix_object(
            haystack,
            window,
            expected_artifact_identity,
            STATIC_PREFIX_RESUME_DESCRIPTOR_V1_VERSION,
            descriptor_ptr.expose_provenance(),
        ) else {
            return STATUS_RUNTIME_FAILURE;
        };
        STATUS_PARTIAL_PREFLIGHT_ENTER
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

/// Packed-wire-V2 counterpart to the established lazy static-prefix
/// preflight. This boundary records the packed wire version without reading
/// object data; only its matching first-hole continuation may decode it.
///
/// # Safety
///
/// The pointer, extent, exclusivity, and lifetime requirements are identical
/// to [`fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_preflight_v2`],
/// except that `descriptor_ptr` names a canonical packed V2 descriptor.
#[doc(hidden)]
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "the packed compiler-private preflight binds generated object data and an exact call"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_preflight_v3(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    expected_artifact_identity_ptr: *const u8,
    descriptor_ptr: *const u32,
) -> u32 {
    if handle.is_invalid() {
        return STATUS_INVALID_HANDLE;
    }
    if haystack_ptr.is_null()
        || result_ptr.is_null()
        || !result_ptr.is_aligned()
        || expected_artifact_identity_ptr.is_null()
        || descriptor_ptr.is_null()
        || !descriptor_ptr.is_aligned()
        || haystack_len > isize::MAX.unsigned_abs()
        || window_start > window_end
        || window_end > haystack_len
    {
        // SAFETY: every non-invalid handle supplied to this unsafe ABI remains
        // one live exclusively owned prepared allocation even when another
        // boundary argument is malformed.
        let _ = unsafe {
            &mut *handle.0.cast::<PreparedAotRegex>()
        }
        .retire_static_prefix_capabilities();
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: descriptor access remains deferred; the caller supplies the
    // live exclusive owner and every other documented extent.
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let haystack = std::slice::from_raw_parts(haystack_ptr, haystack_len);
        let expected_artifact_identity = expected_artifact_identity_ptr
            .cast::<[u8; ARTIFACT_IDENTITY_BYTES]>()
            .read();
        let prepared = &mut *handle.0.cast::<PreparedAotRegex>();
        let _ = prepared.retire_static_prefix_capabilities();
        let window = SearchWindow::new(window_start, window_end);
        let Ok(preflight) = prepared.preflight_static_prefix_complete_proofs(
            haystack,
            window,
            expected_artifact_identity,
        ) else {
            return STATUS_RUNTIME_FAILURE;
        };
        if let RetainedPartialPreflight::Complete(found) = preflight {
            let (status, result) = encode_match_result(found);
            result_ptr.write(result);
            return status;
        }
        debug_assert_eq!(preflight, RetainedPartialPreflight::Enter(window));
        let Ok(()) = prepared.admit_static_prefix_object(
            haystack,
            window,
            expected_artifact_identity,
            STATIC_PREFIX_RESUME_DESCRIPTOR_V2_VERSION,
            descriptor_ptr.expose_provenance(),
        ) else {
            return STATUS_RUNTIME_FAILURE;
        };
        STATUS_PARTIAL_PREFLIGHT_ENTER
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

/// Retire every outstanding static-prefix invocation capability and advance
/// its generation before a generated guard or rare epoch-overflow exit.
///
/// Deferred entries use this boundary after an inline argument/artifact
/// rejection. Both eager and deferred entries use it only when their inline
/// epoch increment would wrap; the helper resets that generation to one and
/// fails closed or preserves the already selected public result status. It
/// never searches or writes caller result storage.
///
/// # Safety
///
/// `handle` must be a live exclusively owned value satisfying
/// [`fre_aot_regex_runtime_search_exclusive_v1`]. `return_status` must be one
/// of the stable public no-match, match, invalid-argument, runtime-failure, or
/// invalid-handle statuses. Any private or unknown status fails closed.
#[doc(hidden)]
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    reason = "the generated local-exit boundary retires private synchronous capabilities"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_retire_v1(
    handle: FreAotRegexExclusiveHandleV1,
    return_status: u32,
) -> u32 {
    if handle.is_invalid() {
        return STATUS_INVALID_HANDLE;
    }
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let prepared = &mut *handle.0.cast::<PreparedAotRegex>();
        let _ = prepared.retire_static_prefix_capabilities();
        prepared.static_prefix_invocation_epoch = prepared
            .static_prefix_invocation_epoch
            .checked_add(1)
            .unwrap_or(1);
        match return_status {
            STATUS_NO_MATCH
            | STATUS_MATCH
            | STATUS_INVALID_ARGUMENT
            | STATUS_RUNTIME_FAILURE
            | STATUS_INVALID_HANDLE => return_status,
            _ => STATUS_RUNTIME_FAILURE,
        }
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

/// Continue an admitted static native prefix from its exact K0 frontier and
/// first unconsumed byte.
///
/// This compact private ABI consumes the single-use object ticket created by
/// ABI-V2 preflight. Only this hole path parses and graph-binds the wire-V1
/// descriptor, fills its K0 resume caches, and tries complete portable proofs.
/// Pending mode is authenticated from the bound frontier set; the final word
/// carries the pending endpoint only when that mode is active.
///
/// # Safety
///
/// The handle, haystack, and result requirements are identical to
/// [`fre_aot_regex_runtime_search_exclusive_v1`]. The caller must be the
/// generated native entry that received [`STATUS_PARTIAL_PREFLIGHT_ENTER`]
/// from ABI-V2 preflight for this exact haystack and must pass a state,
/// position, and pending endpoint emitted by that native prefix.
#[doc(hidden)]
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "the compact continuation carries one exact native frontier payload"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_continue_v1(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    result_ptr: *mut FreAotRegexResultV1,
    resume_state: usize,
    resume_position: usize,
    pending_end: usize,
) -> u32 {
    if handle.is_invalid() {
        return STATUS_INVALID_HANDLE;
    }
    if haystack_ptr.is_null()
        || result_ptr.is_null()
        || !result_ptr.is_aligned()
        || haystack_len > isize::MAX.unsigned_abs()
    {
        // SAFETY: the non-invalid exclusive handle remains live even though a
        // continuation payload or output pointer is malformed.
        let _ = unsafe {
            &mut *handle.0.cast::<PreparedAotRegex>()
        }
        .retire_static_prefix_capabilities();
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: the generated caller guarantees the exclusive owner and the
    // readable/writable disjoint extents documented above. The object ticket
    // authenticates the haystack and supplies a still-live descriptor pointer.
    // Its bounded header is checked before the complete slice is formed.
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let prepared = &mut *handle.0.cast::<PreparedAotRegex>();
        let haystack = std::slice::from_raw_parts(haystack_ptr, haystack_len);
        let Ok(ticket) = prepared.consume_static_prefix_object(haystack) else {
            return STATUS_RUNTIME_FAILURE;
        };
        if ticket.descriptor_key.version() != STATIC_PREFIX_RESUME_DESCRIPTOR_V1_VERSION {
            return STATUS_RUNTIME_FAILURE;
        }
        let Ok(outcome) = prepared.continue_static_prefix_object(
            haystack,
            ticket,
            resume_state,
            resume_position,
            pending_end,
        ) else {
            return STATUS_RUNTIME_FAILURE;
        };
        match outcome {
            StaticPrefixContinuationOutcome::Native {
                status,
                canonical_state,
                pending_end,
            } => {
                result_ptr.write(FreAotRegexResultV1 {
                    start: canonical_state,
                    end: pending_end,
                });
                status
            }
            StaticPrefixContinuationOutcome::Complete(found) => {
                let (status, result) = encode_match_result(found);
                result_ptr.write(result);
                status
            }
        }
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

/// Consume a packed-V2 object ticket and continue from its exact K0 frontier.
/// This distinct private symbol prevents a packed object from linking against
/// a runtime that only understands the wire-V1 descriptor.
///
/// # Safety
///
/// The requirements are identical to
/// [`fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_continue_v1`],
/// and the consumed ticket must have been issued by ABI-V3 preflight.
#[doc(hidden)]
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "the packed compact continuation carries one exact native frontier payload"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_continue_v3(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    result_ptr: *mut FreAotRegexResultV1,
    resume_state: usize,
    resume_position: usize,
    pending_end: usize,
) -> u32 {
    if handle.is_invalid() {
        return STATUS_INVALID_HANDLE;
    }
    if haystack_ptr.is_null()
        || result_ptr.is_null()
        || !result_ptr.is_aligned()
        || haystack_len > isize::MAX.unsigned_abs()
    {
        // SAFETY: the non-invalid exclusive handle remains live even though a
        // continuation payload or output pointer is malformed.
        let _ = unsafe {
            &mut *handle.0.cast::<PreparedAotRegex>()
        }
        .retire_static_prefix_capabilities();
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: the generated caller guarantees the exclusive owner and every
    // readable/writable extent. The packed-wire-V2 ticket authenticates the descriptor.
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let prepared = &mut *handle.0.cast::<PreparedAotRegex>();
        let haystack = std::slice::from_raw_parts(haystack_ptr, haystack_len);
        let Ok(ticket) = prepared.consume_static_prefix_object(haystack) else {
            return STATUS_RUNTIME_FAILURE;
        };
        if ticket.descriptor_key.version() != STATIC_PREFIX_RESUME_DESCRIPTOR_V2_VERSION {
            return STATUS_RUNTIME_FAILURE;
        }
        let Ok(outcome) = prepared.continue_static_prefix_object(
            haystack,
            ticket,
            resume_state,
            resume_position,
            pending_end,
        ) else {
            return STATUS_RUNTIME_FAILURE;
        };
        match outcome {
            StaticPrefixContinuationOutcome::Native {
                status,
                canonical_state,
                pending_end,
            } => {
                result_ptr.write(FreAotRegexResultV1 {
                    start: canonical_state,
                    end: pending_end,
                });
                status
            }
            StaticPrefixContinuationOutcome::Complete(found) => {
                let (status, result) = encode_match_result(found);
                result_ptr.write(result);
                status
            }
        }
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

/// Authenticate and continue one deferred static-prefix hole in one runtime
/// transaction. Variable-width Span continuations publish the same distinct
/// single-use postflight ticket as the established admitted path when the
/// immutable local tail must recover a selected start.
///
/// This ABI-V2 boundary is the fused counterpart of ABI-V2 preflight followed
/// by ABI-V1 continuation. It consumes a wire-V1 descriptor and is valid only
/// for compiler-selected objects with no
/// complete suffix/cut preflight. The generated caller has already
/// authenticated the immutable owner and run its native prefix; this helper
/// independently authenticates the raw object arguments, binds the
/// descriptor, validates the exact frontier, and either finishes the search
/// or returns an authenticated status-7/8 local handoff. No object ticket is
/// ever published in prepared state; variable-width Span publishes only its
/// distinct postflight ticket after a successful immutable projection.
///
/// # Safety
///
/// `handle`, haystack, result, identity, and descriptor have the same
/// requirements as ABI-V2 preflight. The final three words must be the exact
/// state, first-unconsumed position, and pending endpoint produced by the
/// synchronous native prefix for this window. The descriptor remains live and
/// immutable for the duration of the call.
#[doc(hidden)]
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "the fused deferred-hole boundary authenticates one object, window, and native frontier"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_continue_v2(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    expected_artifact_identity_ptr: *const u8,
    descriptor_ptr: *const u32,
    resume_state: usize,
    resume_position: usize,
    pending_end: usize,
) -> u32 {
    if handle.is_invalid() {
        return STATUS_INVALID_HANDLE;
    }
    // A non-null private handle remains a live exclusive allocation under the
    // unsafe ABI even if another raw argument is malformed. Physically retire
    // every older-generation ABI-V1/V2 capability before every possible outcome.
    // SAFETY: no other raw pointer is inspected by this operation.
    let prepared = unsafe { &mut *handle.0.cast::<PreparedAotRegex>() };
    let _ = prepared.retire_static_prefix_capabilities();
    if haystack_ptr.is_null()
        || result_ptr.is_null()
        || !result_ptr.is_aligned()
        || expected_artifact_identity_ptr.is_null()
        || descriptor_ptr.is_null()
        || !descriptor_ptr.is_aligned()
        || haystack_len > isize::MAX.unsigned_abs()
        || window_start > window_end
        || window_end > haystack_len
    {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: the caller supplies the exclusive owner and all readable,
    // writable, disjoint extents documented above. Descriptor parsing is
    // delegated to the shared bounded continuation transaction only after the
    // exact artifact and structural deferred-route policy are authenticated.
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let prepared = &mut *handle.0.cast::<PreparedAotRegex>();
        let haystack = std::slice::from_raw_parts(haystack_ptr, haystack_len);
        let expected_artifact_identity = expected_artifact_identity_ptr
            .cast::<[u8; ARTIFACT_IDENTITY_BYTES]>()
            .read();
        let window = SearchWindow::new(window_start, window_end);
        if expected_artifact_identity != *prepared.frozen_header.artifact_identity()
            || prepared
                .program
                .compiler_private_static_prefix_complete_proofs_should_run(usize::MAX)
        {
            return STATUS_RUNTIME_FAILURE;
        }
        let Ok(descriptor_key) = StaticPrefixResumeDescriptorKey::new(
            STATIC_PREFIX_RESUME_DESCRIPTOR_V1_VERSION,
            descriptor_ptr.expose_provenance(),
        ) else {
            return STATUS_RUNTIME_FAILURE;
        };
        let ticket = StaticPrefixObjectTicket {
            haystack_address: haystack.as_ptr().expose_provenance(),
            haystack_len: haystack.len(),
            window,
            artifact_identity: expected_artifact_identity,
            descriptor_key,
            invocation_epoch: prepared.static_prefix_invocation_epoch,
        };
        let Ok(outcome) = prepared.continue_static_prefix_object(
            haystack,
            ticket,
            resume_state,
            resume_position,
            pending_end,
        ) else {
            return STATUS_RUNTIME_FAILURE;
        };
        match outcome {
            StaticPrefixContinuationOutcome::Native {
                status,
                canonical_state,
                pending_end,
            } => {
                result_ptr.write(FreAotRegexResultV1 {
                    start: canonical_state,
                    end: pending_end,
                });
                status
            }
            StaticPrefixContinuationOutcome::Complete(found) => {
                let (status, result) = encode_match_result(found);
                result_ptr.write(result);
                status
            }
        }
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

/// Packed-V2 counterpart to the fused deferred-hole continuation. A fresh
/// symbol makes the decoder requirement explicit at object link time.
///
/// # Safety
///
/// The requirements are identical to
/// [`fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_continue_v2`],
/// except that `descriptor_ptr` names a canonical packed V2 descriptor.
#[doc(hidden)]
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "the packed fused deferred-hole boundary authenticates one object, window, and native frontier"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_continue_v4(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    expected_artifact_identity_ptr: *const u8,
    descriptor_ptr: *const u32,
    resume_state: usize,
    resume_position: usize,
    pending_end: usize,
) -> u32 {
    if handle.is_invalid() {
        return STATUS_INVALID_HANDLE;
    }
    // SAFETY: a non-null private handle remains a live exclusive allocation
    // even if another raw argument is malformed.
    let prepared = unsafe { &mut *handle.0.cast::<PreparedAotRegex>() };
    let _ = prepared.retire_static_prefix_capabilities();
    if haystack_ptr.is_null()
        || result_ptr.is_null()
        || !result_ptr.is_aligned()
        || expected_artifact_identity_ptr.is_null()
        || descriptor_ptr.is_null()
        || !descriptor_ptr.is_aligned()
        || haystack_len > isize::MAX.unsigned_abs()
        || window_start > window_end
        || window_end > haystack_len
    {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: the caller supplies the exclusive owner and every documented
    // readable, writable, and disjoint extent.
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let prepared = &mut *handle.0.cast::<PreparedAotRegex>();
        let haystack = std::slice::from_raw_parts(haystack_ptr, haystack_len);
        let expected_artifact_identity = expected_artifact_identity_ptr
            .cast::<[u8; ARTIFACT_IDENTITY_BYTES]>()
            .read();
        let window = SearchWindow::new(window_start, window_end);
        if expected_artifact_identity != *prepared.frozen_header.artifact_identity()
            || prepared
                .program
                .compiler_private_static_prefix_complete_proofs_should_run(usize::MAX)
        {
            return STATUS_RUNTIME_FAILURE;
        }
        let Ok(descriptor_key) = StaticPrefixResumeDescriptorKey::new(
            STATIC_PREFIX_RESUME_DESCRIPTOR_V2_VERSION,
            descriptor_ptr.expose_provenance(),
        ) else {
            return STATUS_RUNTIME_FAILURE;
        };
        let ticket = StaticPrefixObjectTicket {
            haystack_address: haystack.as_ptr().expose_provenance(),
            haystack_len: haystack.len(),
            window,
            artifact_identity: expected_artifact_identity,
            descriptor_key,
            invocation_epoch: prepared.static_prefix_invocation_epoch,
        };
        let Ok(outcome) = prepared.continue_static_prefix_object(
            haystack,
            ticket,
            resume_state,
            resume_position,
            pending_end,
        ) else {
            return STATUS_RUNTIME_FAILURE;
        };
        match outcome {
            StaticPrefixContinuationOutcome::Native {
                status,
                canonical_state,
                pending_end,
            } => {
                result_ptr.write(FreAotRegexResultV1 {
                    start: canonical_state,
                    end: pending_end,
                });
                status
            }
            StaticPrefixContinuationOutcome::Complete(found) => {
                let (status, result) = encode_match_result(found);
                result_ptr.write(result);
                status
            }
        }
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

/// Recover a Span start after a compiler-owned static prefix selected its
/// authoritative endpoint.
///
/// The generated caller must invoke this synchronously after a successful
/// static-prefix preflight and native forward completion over the same exact
/// window. Reverse K0 recovers only the start; it does not replay the forward
/// search. This compiler-private seam is deliberately absent from the public
/// C header.
///
/// # Safety
///
/// The handle, haystack, result, and identity requirements are identical to
/// [`fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_preflight_v1`].
/// `selected_end` must be the endpoint produced by the synchronous native
/// prefix and lie after `window_start` and at or before `window_end`.
#[doc(hidden)]
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "the compiler-private static-prefix postflight authenticates raw generated-code arguments"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_recover_span_v1(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    expected_artifact_identity_ptr: *const u8,
    selected_end: usize,
) -> u32 {
    if handle.is_invalid() {
        return STATUS_INVALID_HANDLE;
    }
    // SAFETY: a non-invalid exclusive handle remains a live unique owner even
    // when another boundary argument is malformed. Clear cross-version ABI-V2
    // tickets before every ABI-V1 postflight outcome.
    let _ = unsafe {
        &mut *handle.0.cast::<PreparedAotRegex>()
    }
    .retire_static_prefix_capabilities();
    if haystack_ptr.is_null()
        || result_ptr.is_null()
        || !result_ptr.is_aligned()
        || expected_artifact_identity_ptr.is_null()
        || haystack_len > isize::MAX.unsigned_abs()
        || window_start > window_end
        || window_end > haystack_len
        || selected_end <= window_start
        || selected_end > window_end
    {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: the caller guarantees one live exclusively owned allocation and
    // every readable/writable disjoint extent documented above.
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let prepared = &mut *handle.0.cast::<PreparedAotRegex>();
        let haystack = std::slice::from_raw_parts(haystack_ptr, haystack_len);
        let expected_artifact_identity = expected_artifact_identity_ptr
            .cast::<[u8; ARTIFACT_IDENTITY_BYTES]>()
            .read();
        let Ok(MatchResult::Span(Some((start, end)))) = prepared
            .recover_static_prefix_span_from_selected_end(
                haystack,
                SearchWindow::new(window_start, window_end),
                expected_artifact_identity,
                selected_end,
                None,
            )
        else {
            return STATUS_RUNTIME_FAILURE;
        };
        result_ptr.write(FreAotRegexResultV1 { start, end });
        STATUS_MATCH
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

/// Recover a Span start after an eager ABI-V2/V3 static-prefix native
/// completion or an authenticated status-7/8 continuation.
///
/// Direct local completion consumes the original single-use object ticket.
/// The continuation helper consumes that object ticket while binding the
/// forward descriptor, then mints a distinct single-use Span postflight ticket
/// only after it successfully projects an immutable local continuation. Both
/// capability kinds authenticate the original haystack, window, and artifact;
/// the descriptor-bearing ticket is never reinserted or consumed twice.
///
/// # Safety
///
/// The raw pointer requirements are identical to the ABI-V1 Span postflight.
/// The generated caller must invoke this synchronously after ABI-V2/V3
/// preflight and either a direct native completion or a successful status-7/8
/// local continuation over the same exact window.
#[doc(hidden)]
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "the ABI-V2 static-prefix postflight authenticates the admitted ticket and endpoint"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_recover_span_v2(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    expected_artifact_identity_ptr: *const u8,
    selected_end: usize,
) -> u32 {
    if handle.is_invalid() {
        return STATUS_INVALID_HANDLE;
    }
    if haystack_ptr.is_null()
        || result_ptr.is_null()
        || !result_ptr.is_aligned()
        || expected_artifact_identity_ptr.is_null()
        || haystack_len > isize::MAX.unsigned_abs()
        || window_start > window_end
        || window_end > haystack_len
        || selected_end <= window_start
        || selected_end > window_end
    {
        // SAFETY: the non-invalid exclusive handle remains live even though a
        // postflight payload or output pointer is malformed.
        let _ = unsafe {
            &mut *handle.0.cast::<PreparedAotRegex>()
        }
        .retire_static_prefix_capabilities();
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: the generated caller guarantees one live exclusive allocation
    // and every readable/writable disjoint extent documented above.
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let prepared = &mut *handle.0.cast::<PreparedAotRegex>();
        let haystack = std::slice::from_raw_parts(haystack_ptr, haystack_len);
        let expected_artifact_identity = expected_artifact_identity_ptr
            .cast::<[u8; ARTIFACT_IDENTITY_BYTES]>()
            .read();
        let window = SearchWindow::new(window_start, window_end);
        let Ok(admission) = prepared.consume_static_prefix_span_recovery_ticket(
            haystack,
            window,
            expected_artifact_identity,
        ) else {
            return STATUS_RUNTIME_FAILURE;
        };
        let Ok(MatchResult::Span(Some((start, end)))) = prepared
            .recover_static_prefix_span_from_selected_end(
                haystack,
                window,
                expected_artifact_identity,
                selected_end,
                admission,
            )
        else {
            return STATUS_RUNTIME_FAILURE;
        };
        result_ptr.write(FreAotRegexResultV1 { start, end });
        STATUS_MATCH
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

/// Authenticate and recover a variable-width Span only after a proof-free
/// static native prefix selects its authoritative endpoint.
///
/// This ABI-V3 boundary is the direct-completion counterpart of fused
/// ABI-V2/V4 hole continuation. The generated entry has already checked every
/// public scalar, compared the immutable artifact identity, and advanced the
/// exclusive owner's invocation epoch before entering native code. It passes
/// that exact epoch as a single-use capability here. This helper independently
/// validates the raw arguments and artifact, consumes the epoch before any
/// reverse work, and admits no program whose complete suffix/cut proofs belong
/// before native execution. Native no-match and fully encoded terminal paths
/// never call this boundary.
///
/// This private ABI is intentionally absent from the public C header. It is
/// versioned separately from ABI-V2 because ABI-V2 consumes an eagerly
/// published object/postflight ticket, while ABI-V3 consumes a generated epoch
/// word. Stale older tickets are retired as non-authoritative state; an
/// ABI-V1/V2 ticket minted in the current epoch is a conflicting route and
/// fails closed.
///
/// # Safety
///
/// The raw pointer and exclusive ownership requirements are identical to ABI-V2.
/// `invocation_epoch` must be the value read from the live prepared owner by
/// the synchronous generated entry after its inline increment and before any
/// other call through that exclusive handle.
#[doc(hidden)]
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "the lazy static-prefix postflight authenticates one generated invocation epoch"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_recover_span_v3(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    expected_artifact_identity_ptr: *const u8,
    selected_end: usize,
    invocation_epoch: u64,
) -> u32 {
    if handle.is_invalid() {
        return STATUS_INVALID_HANDLE;
    }

    // Consume the generated capability before inspecting any other caller
    // pointer. A corrected replay, panic, foreign identity, or malformed
    // output can therefore never reuse the same native completion. The
    // exclusive-handle ABI forbids overlapping calls, so this mutation is the
    // complete synchronization boundary for the owner.
    // SAFETY: every non-invalid handle supplied to this unsafe private ABI is
    // one live exclusively owned PreparedAotRegex allocation.
    let prepared = unsafe { &mut *handle.0.cast::<PreparedAotRegex>() };
    let had_current_capability = {
        let (object, postflight) = prepared.retire_static_prefix_capabilities();
        object.is_some_and(|ticket| {
            ticket.invocation_epoch == prepared.static_prefix_invocation_epoch
        }) || postflight.is_some_and(|ticket| {
            ticket.invocation_epoch == prepared.static_prefix_invocation_epoch
        })
    };
    let epoch_matches = prepared.static_prefix_invocation_epoch == invocation_epoch;
    let Some(next_epoch) = prepared.static_prefix_invocation_epoch.checked_add(1) else {
        prepared.static_prefix_invocation_epoch = 1;
        return STATUS_RUNTIME_FAILURE;
    };
    prepared.static_prefix_invocation_epoch = next_epoch;
    if had_current_capability || !epoch_matches {
        return STATUS_RUNTIME_FAILURE;
    }

    if haystack_ptr.is_null()
        || result_ptr.is_null()
        || !result_ptr.is_aligned()
        || expected_artifact_identity_ptr.is_null()
        || haystack_len > isize::MAX.unsigned_abs()
        || window_start > window_end
        || window_end > haystack_len
        || selected_end <= window_start
        || selected_end > window_end
    {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: the caller supplies the unique prepared owner and every live,
    // readable/writable, disjoint extent documented above. The epoch was
    // consumed before these pointers were inspected.
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let prepared = &mut *handle.0.cast::<PreparedAotRegex>();
        let haystack = std::slice::from_raw_parts(haystack_ptr, haystack_len);
        let expected_artifact_identity = expected_artifact_identity_ptr
            .cast::<[u8; ARTIFACT_IDENTITY_BYTES]>()
            .read();
        if expected_artifact_identity != *prepared.frozen_header.artifact_identity()
            || prepared.program.output_contract() != OutputContract::Span
            || prepared.program.exact_match_width().is_some()
            || prepared
                .program
                .compiler_private_static_prefix_complete_proofs_should_run(usize::MAX)
        {
            return STATUS_RUNTIME_FAILURE;
        }
        let Ok(MatchResult::Span(Some((start, end)))) = prepared
            .recover_static_prefix_span_from_selected_end(
                haystack,
                SearchWindow::new(window_start, window_end),
                expected_artifact_identity,
                selected_end,
                None,
            )
        else {
            return STATUS_RUNTIME_FAILURE;
        };
        result_ptr.write(FreAotRegexResultV1 { start, end });
        STATUS_MATCH
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

/// Compiler-private capability and side exit for a frozen prepared root.
///
/// Future generated direct entries link this distinct symbol instead of a V1
/// legacy search helper. Its presence proves that the runtime allocation begins
/// with the matching versioned header. Entering the helper permanently clears
/// that header's direct-use seal before authenticating the emitted artifact or
/// touching mutable workspace state. Thus a wrong-artifact side exit also
/// retires the projection and leaves the result untouched.
///
/// This symbol is intentionally absent from [`C_API_V1_HEADER`]. Linking a
/// frozen-entry object against an older runtime therefore fails closed.
///
/// # Safety
///
/// `handle` must satisfy the exclusive ownership contract of
/// [`fre_aot_regex_runtime_search_exclusive_v1`]. The haystack and result
/// extents have the same requirements. `expected_artifact_identity_ptr` must
/// address exactly [`ARTIFACT_IDENTITY_BYTES`] readable bytes, disjoint from
/// writable output, for the duration of the call.
#[doc(hidden)]
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "the compiler-private frozen fallback authenticates one exact artifact and search window"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_search_exclusive_frozen_fallback_v1(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    expected_artifact_identity_ptr: *const u8,
) -> u32 {
    if handle.is_invalid() {
        return STATUS_INVALID_HANDLE;
    }
    if haystack_ptr.is_null()
        || result_ptr.is_null()
        || !result_ptr.is_aligned()
        || expected_artifact_identity_ptr.is_null()
        || haystack_len > isize::MAX.unsigned_abs()
        || window_start > window_end
        || window_end > haystack_len
    {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: the caller guarantees one live exclusively owned allocation and
    // all readable/writable disjoint extents documented above.
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let prepared = &mut *handle.0.cast::<PreparedAotRegex>();
        prepared.deactivate_frozen_header();
        let expected_artifact_identity = expected_artifact_identity_ptr
            .cast::<[u8; ARTIFACT_IDENTITY_BYTES]>()
            .read();
        if expected_artifact_identity != *prepared.frozen_header.artifact_identity() {
            return STATUS_RUNTIME_FAILURE;
        }
        let haystack = std::slice::from_raw_parts(haystack_ptr, haystack_len);
        let Ok((status, result)) =
            execute_exclusive_search(prepared, haystack, window_start, window_end)
        else {
            return STATUS_RUNTIME_FAILURE;
        };
        result_ptr.write(result);
        status
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

/// Continue a genuine whole-search side exit from the generated dynamic-row
/// scanner. This private compiler/runtime seam has the same raw ABI and
/// semantic result contract as [`fre_aot_regex_runtime_search_exclusive_v1`],
/// but records adaptive deopt feedback instead of settling a prior local
/// native completion. Its admission ticket also preserves any already-run
/// mandatory cut and the original input-length profitability basis, so the
/// fallback starts at the exact admitted window without replaying that cut.
///
/// # Safety
///
/// Requirements are identical to
/// [`fre_aot_regex_runtime_search_exclusive_v1`]. The caller must use this
/// helper only after the authenticated dynamic-row preflight admitted the
/// same exclusive search transaction.
#[doc(hidden)]
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    reason = "this private generated-code symbol is an audited raw C pointer boundary"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_search_exclusive_dynamic_rows_deopt_v1(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
) -> u32 {
    search_exclusive_with_dynamic_rows_outcome(
        handle,
        haystack_ptr,
        haystack_len,
        window_start,
        window_end,
        result_ptr,
        DynamicNativeRowsFallbackOutcome::Deopt,
    )
}

/// Continue the exact first unpublished cell of a dynamically warmed native
/// row scan without replaying its completed scalar prefix.
///
/// The helper consumes the admitted preflight window before authenticating
/// the artifact, cache, row, unread position, endpoint, and current unfilled
/// cell. A stale or malformed payload completes through the established
/// whole-window deopt path; a valid payload continues in K0 and settles as a
/// local completion.
///
/// # Safety
///
/// The handle, haystack, and result requirements are identical to
/// [`fre_aot_regex_runtime_search_exclusive_v1`].
/// `expected_artifact_identity_ptr` must address exactly
/// [`ARTIFACT_IDENTITY_BYTES`] readable bytes. `continuation_ptr` must be
/// non-null, aligned, readable, and disjoint from `result_ptr` for the
/// synchronous call. The helper is compiler-private and may be called only by
/// the generated entry that owns the immediately preceding dynamic preflight.
#[doc(hidden)]
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "this private generated-code symbol is an audited raw C pointer boundary"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_search_exclusive_dynamic_rows_continue_v1(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    expected_artifact_identity_ptr: *const u8,
    continuation_ptr: *const FreAotRegexDynamicRowsContinuationV1,
) -> u32 {
    if handle.is_invalid() {
        return STATUS_INVALID_HANDLE;
    }
    if haystack_ptr.is_null()
        || result_ptr.is_null()
        || !result_ptr.is_aligned()
        || expected_artifact_identity_ptr.is_null()
        || continuation_ptr.is_null()
        || !continuation_ptr.is_aligned()
        || haystack_len > isize::MAX.unsigned_abs()
        || window_start > window_end
        || window_end > haystack_len
    {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: the caller guarantees the live exclusive session and all
    // readable/disjoint writable extents documented above.
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let prepared = &mut *handle.0.cast::<PreparedAotRegex>();
        let haystack = std::slice::from_raw_parts(haystack_ptr, haystack_len);
        let expected_artifact_identity = expected_artifact_identity_ptr
            .cast::<[u8; ARTIFACT_IDENTITY_BYTES]>()
            .read();
        let continuation = continuation_ptr.read();
        let Ok(found) = prepared.search_from_dynamic_native_rows_hole(
            haystack,
            SearchWindow::new(window_start, window_end),
            expected_artifact_identity,
            continuation,
        ) else {
            return STATUS_RUNTIME_FAILURE;
        };
        let (status, result) = encode_match_result(found);
        result_ptr.write(result);
        status
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

/// Resolve one exact unpublished dynamic-row cell and return control to the
/// generated row loop whenever K0 can publish a durable packed transition.
///
/// This is the repeated-miss successor to
/// [`fre_aot_regex_runtime_search_exclusive_dynamic_rows_continue_v1`]. A
/// cacheable miss returns [`STATUS_DYNAMIC_ROWS_CELL_RESUME`] and temporarily
/// writes the fresh descriptor address and resolved cell to `result_ptr`.
/// The triggering byte remains unread. Capacity-bound inline transitions stay
/// inside K0 and return the ordinary final search status instead.
///
/// # Safety
///
/// The pointer, exclusive-session, exact-window, identity, continuation, and
/// disjointness requirements are identical to
/// [`fre_aot_regex_runtime_search_exclusive_dynamic_rows_continue_v1`]. The
/// status-9 payload is valid only for the synchronous generated invocation;
/// no descriptor address may survive another helper call or workspace entry.
#[doc(hidden)]
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "this private generated-code symbol is an audited raw C pointer boundary"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_search_exclusive_dynamic_rows_continue_v2(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    expected_artifact_identity_ptr: *const u8,
    continuation_ptr: *const FreAotRegexDynamicRowsContinuationV1,
) -> u32 {
    if handle.is_invalid() {
        return STATUS_INVALID_HANDLE;
    }
    if haystack_ptr.is_null()
        || result_ptr.is_null()
        || !result_ptr.is_aligned()
        || expected_artifact_identity_ptr.is_null()
        || continuation_ptr.is_null()
        || !continuation_ptr.is_aligned()
        || haystack_len > isize::MAX.unsigned_abs()
        || window_start > window_end
        || window_end > haystack_len
    {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: the caller guarantees the live exclusive session and all
    // readable/disjoint writable extents documented above.
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let prepared = &mut *handle.0.cast::<PreparedAotRegex>();
        let haystack = std::slice::from_raw_parts(haystack_ptr, haystack_len);
        let expected_artifact_identity = expected_artifact_identity_ptr
            .cast::<[u8; ARTIFACT_IDENTITY_BYTES]>()
            .read();
        let continuation = continuation_ptr.read();
        let Ok(resolved) = prepared.resolve_dynamic_native_rows_hole(
            haystack,
            SearchWindow::new(window_start, window_end),
            expected_artifact_identity,
            continuation,
        ) else {
            return STATUS_RUNTIME_FAILURE;
        };
        match resolved {
            DynamicNativeRowsHoleResolution::PublishedCell {
                cell,
                native_rows_address,
            } => {
                result_ptr.write(FreAotRegexResultV1 {
                    start: native_rows_address,
                    end: usize::try_from(cell)
                        .expect("a packed u32 dynamic-row cell fits usize"),
                });
                STATUS_DYNAMIC_ROWS_CELL_RESUME
            }
            DynamicNativeRowsHoleResolution::Complete(found) => {
                let (status, result) = encode_match_result(found);
                result_ptr.write(result);
                status
            }
        }
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

/// Recover a variable-width Span start after an authenticated dynamic-row
/// scan selected only its authoritative endpoint.
///
/// For mutable rows or legacy V1/V2 headers, the exact
/// `window_start..window_end` must be the single-use window admitted by the
/// immediately preceding successful dynamic-row preflight on this exclusive
/// session. An active immutable V3--V14 header may instead authorize the
/// synchronous endpoint selected from its exact frozen owner, without a
/// preflight ticket. The artifact must be an assertion-free, non-nullable,
/// variable-width ordered-NFA Span program, and `selected_end` must lie
/// strictly after the window start and at or before its end. Reverse K0
/// recovers only the start; the forward search is not replayed. Successful
/// immutable recovery retains the header, while every rejection revokes it.
///
/// On success this function returns [`STATUS_MATCH`] and initializes
/// `result_ptr` with the exact Span. Every rejection returns an error status
/// and leaves `result_ptr` untouched.
///
/// # Safety
///
/// The handle, haystack, result, and identity pointer requirements are the
/// same as for
/// [`fre_aot_regex_runtime_search_exclusive_dynamic_rows_continue_v1`]. The
/// caller must pass the exact admitted window and the endpoint produced by its
/// synchronous native scan. No overlapping call or destroy may use any copy
/// of `handle`.
#[doc(hidden)]
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "this private generated-code postflight authenticates the exact dynamic admission and endpoint"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_search_exclusive_dynamic_rows_recover_span_v1(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    expected_artifact_identity_ptr: *const u8,
    selected_end: usize,
) -> u32 {
    if handle.is_invalid() {
        return STATUS_INVALID_HANDLE;
    }
    if haystack_ptr.is_null()
        || result_ptr.is_null()
        || !result_ptr.is_aligned()
        || expected_artifact_identity_ptr.is_null()
        || haystack_len > isize::MAX.unsigned_abs()
        || window_start > window_end
        || window_end > haystack_len
        || selected_end <= window_start
        || selected_end > window_end
    {
        // A non-null exclusive handle is a live allocation by this unsafe
        // API's contract. Even a malformed postflight payload must revoke a
        // possibly active compact capability before the caller can fall back
        // or retry with another endpoint.
        unsafe { &mut *handle.0.cast::<PreparedAotRegex>() }.deactivate_frozen_header();
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: the caller guarantees one live exclusively owned session plus
    // all readable and writable disjoint extents described above.
    let status = catch_unwind(AssertUnwindSafe(|| unsafe {
        let prepared = &mut *handle.0.cast::<PreparedAotRegex>();
        let haystack = std::slice::from_raw_parts(haystack_ptr, haystack_len);
        let expected_artifact_identity = expected_artifact_identity_ptr
            .cast::<[u8; ARTIFACT_IDENTITY_BYTES]>()
            .read();
        let Ok(MatchResult::Span(Some((start, end)))) = prepared
            .recover_dynamic_native_rows_span_from_selected_end(
                haystack,
                SearchWindow::new(window_start, window_end),
                expected_artifact_identity,
                selected_end,
            )
        else {
            return STATUS_RUNTIME_FAILURE;
        };
        result_ptr.write(FreAotRegexResultV1 { start, end });
        STATUS_MATCH
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE);
    if status != STATUS_MATCH {
        // This also covers an unwind before the Rust recovery wrapper could
        // revoke its active compact capability.
        unsafe { &mut *handle.0.cast::<PreparedAotRegex>() }.deactivate_frozen_header();
    }
    status
}

/// Decide whether a legacy exclusive prepared native entry should execute its
/// retained partial-DFA rows for a window of `input_bytes` bytes.
///
/// Returns [`PARTIAL_ENTRY_ENTER`] or [`PARTIAL_ENTRY_BYPASS`]. This is a
/// compatibility seam for older compiler-emitted entries: on bypass, the
/// entry must immediately invoke [`fre_aot_regex_runtime_search_exclusive_v1`]
/// for the same search so the ordinary prepared path consumes one adaptive
/// bypass. On enter, the emitted scan must either return a complete local
/// result or report its interior hole through
/// [`fre_aot_regex_runtime_search_exclusive_from_partial_v1`].
///
/// # Safety
///
/// `handle` must satisfy the exclusive live-handle requirements of
/// [`fre_aot_regex_runtime_search_exclusive_v1`]. No search, admission, or
/// destroy call may overlap this call or the native search it admits.
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    reason = "this exported symbol is an audited exclusive raw-handle boundary"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_prepared_partial_should_enter_v1(
    handle: FreAotRegexExclusiveHandleV1,
    input_bytes: usize,
) -> u32 {
    if handle.is_invalid() {
        return PARTIAL_ENTRY_BYPASS;
    }
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let prepared = &mut *handle.0.cast::<PreparedAotRegex>();
        u32::from(
            prepared
                .prepared_partial_should_enter(input_bytes)
                .unwrap_or(false),
        )
    }))
    .unwrap_or(PARTIAL_ENTRY_BYPASS)
}

/// Continue an exclusively owned prepared session from an authenticated
/// retained partial-DFA hole without replaying the consumed prefix.
///
/// `expected_artifact_identity_ptr` supplies exactly
/// [`ARTIFACT_IDENTITY_BYTES`] bytes containing the stable serialized-program
/// SHA-256 identity embedded by the native producer. `resume_state` is only a
/// compact index into that artifact's canonical retained frontier table;
/// frontier contents never cross this ABI. `resume_position` is the first
/// unconsumed byte and must lie strictly inside the original search window.
/// `pending_end_present` must be `0` or `1`; when it is `1`, `pending_end`
/// names the selected boundary already committed in the consumed prefix.
///
/// Status and result conventions are identical to
/// [`fre_aot_regex_runtime_search_exclusive_v1`]. A mismatched artifact
/// identity, absent retained table, invalid compact state, incompatible
/// pending mode/value, or invalid resume position returns
/// [`STATUS_RUNTIME_FAILURE`] and leaves `result_ptr` untouched.
///
/// # Safety
///
/// `handle` must satisfy the exclusive live-handle requirements of
/// [`fre_aot_regex_runtime_search_exclusive_v1`]. Haystack and result pointer
/// requirements are identical to that function. Additionally,
/// `expected_artifact_identity_ptr` must be non-null and readable for exactly
/// [`ARTIFACT_IDENTITY_BYTES`] bytes. The result storage must not overlap
/// either readable extent. The compact resume fields must have been emitted
/// after actually executing the retained table in the identified artifact.
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "this exported continuation symbol is an audited raw C pointer boundary with an explicit authenticated prefix state"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_search_exclusive_from_partial_v1(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    expected_artifact_identity_ptr: *const u8,
    resume_state: usize,
    resume_position: usize,
    pending_end_present: u32,
    pending_end: usize,
) -> u32 {
    if handle.is_invalid() {
        return STATUS_INVALID_HANDLE;
    }
    if haystack_ptr.is_null()
        || result_ptr.is_null()
        || !result_ptr.is_aligned()
        || expected_artifact_identity_ptr.is_null()
        || haystack_len > isize::MAX.unsigned_abs()
        || window_start > window_end
        || window_end > haystack_len
        || pending_end_present > 1
    {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: the caller guarantees one live exclusively owned session plus
    // all readable and writable disjoint extents described above.
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let prepared = &mut *handle.0.cast::<PreparedAotRegex>();
        let haystack = std::slice::from_raw_parts(haystack_ptr, haystack_len);
        let expected_artifact_identity = expected_artifact_identity_ptr
            .cast::<[u8; ARTIFACT_IDENTITY_BYTES]>()
            .read();
        let pending_end = (pending_end_present == 1).then_some(pending_end);
        let Ok(found) = prepared.search_from_retained_partial_resume(
            haystack,
            SearchWindow::new(window_start, window_end),
            expected_artifact_identity,
            resume_state,
            resume_position,
            pending_end,
        ) else {
            return STATUS_RUNTIME_FAILURE;
        };
        let (status, result) = encode_match_result(found);
        result_ptr.write(result);
        status
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

/// Continue the exact retained-row transaction admitted by combined native
/// preflight without repeating its artifact and workspace authentication.
///
/// This compiler-private ABI deliberately retains the legacy continuation's
/// argument layout so generated wrappers can select it by relocation alone.
/// `expected_artifact_identity_ptr` is the same embedded identity passed to
/// preflight, but its bytes are not read again. The preflight's single-use
/// exact-window ticket authenticates the handle, program, workspace, and
/// admitted window. Compact state, position, and pending mode remain checked
/// before the K0 continuation executes.
///
/// # Safety
///
/// This function may only be called by the compiler-emitted wrapper after its
/// immediately preceding preflight returned [`STATUS_PARTIAL_PREFLIGHT_ENTER`]
/// and its local native core returned a hole for that exact transaction. All
/// pointers, extents, alignment, disjointness, exclusive ownership, and
/// compact payload requirements of
/// [`fre_aot_regex_runtime_search_exclusive_from_partial_v1`] must still hold.
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "this compiler-private trusted continuation preserves the established machine ABI"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_search_exclusive_from_partial_preflight_v1(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    _expected_artifact_identity_ptr: *const u8,
    resume_state: usize,
    resume_position: usize,
    pending_end_present: u32,
    pending_end: usize,
) -> u32 {
    if pending_end_present > 1 {
        return STATUS_INVALID_ARGUMENT;
    }
    // SAFETY: the compiler-owned preflight transaction established the live
    // exclusive session and exact readable/writable extents; the function's
    // private contract keeps them valid through this immediate continuation.
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let prepared = &mut *handle.0.cast::<PreparedAotRegex>();
        let haystack = std::slice::from_raw_parts(haystack_ptr, haystack_len);
        let pending_end = (pending_end_present == 1).then_some(pending_end);
        let Ok(found) = prepared.search_from_preflight_retained_partial_resume(
            haystack,
            SearchWindow::new(window_start, window_end),
            resume_state,
            resume_position,
            pending_end,
        ) else {
            return STATUS_RUNTIME_FAILURE;
        };
        let (status, result) = encode_match_result(found);
        result_ptr.write(result);
        status
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

/// Continue a combined-preflight transaction without passing its already
/// authenticated identity or exact window back across the private ABI.
///
/// The single-use workspace ticket supplies the admitted window. This compact
/// compiler-private entry therefore needs only the live handle and haystack,
/// untouched result, and native core's state/position/pending payload.
///
/// # Safety
///
/// This function may only be called by the compiler-emitted wrapper after its
/// immediately preceding combined preflight admitted local native execution
/// for this handle and haystack. The handle, haystack, and result pointer must
/// remain live, aligned, disjoint, and exclusively owned until this immediate
/// continuation returns.
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "the compact compiler-private continuation maps one native payload"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_search_exclusive_from_partial_preflight_compact_v1(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    result_ptr: *mut FreAotRegexResultV1,
    resume_state: usize,
    resume_position: usize,
    pending_end_present: u32,
    pending_end: usize,
) -> u32 {
    if pending_end_present > 1 {
        return STATUS_INVALID_ARGUMENT;
    }
    // SAFETY: the compiler-owned ticket proves that the immediately preceding
    // preflight authenticated these live allocations for exclusive use.
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let prepared = &mut *handle.0.cast::<PreparedAotRegex>();
        let haystack = std::slice::from_raw_parts(haystack_ptr, haystack_len);
        let pending_end = (pending_end_present == 1).then_some(pending_end);
        let Ok(found) = prepared.search_from_preflight_retained_partial_resume_ticket(
            haystack,
            resume_state,
            resume_position,
            pending_end,
        ) else {
            return STATUS_RUNTIME_FAILURE;
        };
        let (status, result) = encode_match_result(found);
        result_ptr.write(result);
        status
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

/// Continue a combined-preflight transaction without a redundant pending-mode
/// argument.
///
/// The authenticated canonical resume state determines whether `pending_end`
/// is meaningful. A no-pending state ignores that machine word; a pending
/// state retains it as the selected endpoint already committed by native rows.
/// The single-use workspace ticket supplies the admitted window exactly as in
/// the compact-v1 entry.
///
/// # Safety
///
/// This function may only be called by the compiler-emitted wrapper after its
/// immediately preceding combined preflight admitted local native execution
/// for this handle and haystack. The handle, haystack, and result pointer must
/// remain live, aligned, disjoint, and exclusively owned until this immediate
/// continuation returns. `resume_state`, `resume_position`, and a meaningful
/// `pending_end` must be the native core's authenticated outputs.
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "the compact compiler-private continuation maps one native payload"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_search_exclusive_from_partial_preflight_compact_v2(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    result_ptr: *mut FreAotRegexResultV1,
    resume_state: usize,
    resume_position: usize,
    pending_end: usize,
) -> u32 {
    // SAFETY: the compiler-owned ticket proves that the immediately preceding
    // preflight authenticated these live allocations for exclusive use.
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let prepared = &mut *handle.0.cast::<PreparedAotRegex>();
        let haystack = std::slice::from_raw_parts(haystack_ptr, haystack_len);
        let Ok(found) = prepared.search_from_preflight_retained_partial_resume_ticket_inferred(
            haystack,
            resume_state,
            resume_position,
            pending_end,
        ) else {
            return STATUS_RUNTIME_FAILURE;
        };
        let (status, result) = encode_match_result(found);
        result_ptr.write(result);
        status
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

/// Project a combined-preflight retained hole into the prepared immutable
/// continuation table, or consume it through compact-v2 on a projection
/// decline.
///
/// Unlike compact-v2, status 8 is a successful ownership transfer rather than
/// a semantic search result. In that case `result_ptr.start` is the canonical
/// immutable-table state and `result_ptr.end` is its pending endpoint word;
/// the compiler-emitted wrapper must immediately enter its local continuation
/// tail. The Program ticket remains live under continuation ownership until
/// that tail returns locally, deoptimizes once, or performs one variable-Span
/// recovery. A decline never changes ownership before invoking compact-v2.
///
/// This symbol is intentionally compiler-private. New objects that use status
/// 8 therefore fail to link against an older runtime, while old compact-v2
/// objects retain their exact ABI and behavior.
///
/// # Safety
///
/// Requirements are identical to
/// [`fre_aot_regex_runtime_search_exclusive_from_partial_preflight_compact_v2`].
#[doc(hidden)]
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "the compact-v3 compiler-private continuation maps one native payload"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_search_exclusive_from_partial_preflight_compact_v3(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    result_ptr: *mut FreAotRegexResultV1,
    resume_state: usize,
    resume_position: usize,
    pending_end: usize,
) -> u32 {
    // SAFETY: the compiler-owned ticket proves that the immediately preceding
    // preflight authenticated these live allocations for exclusive use.
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let prepared = &mut *handle.0.cast::<PreparedAotRegex>();
        let haystack = std::slice::from_raw_parts(haystack_ptr, haystack_len);
        match prepared.project_preflight_retained_partial_resume_ticket_to_native_continuation(
            haystack,
            resume_state,
            resume_position,
            pending_end,
        ) {
            Ok(Some((canonical_state, pending_end))) => {
                result_ptr.write(FreAotRegexResultV1 {
                    start: canonical_state,
                    end: pending_end,
                });
                STATUS_STATIC_PREFIX_NATIVE_CONTINUATION_RESUME
            }
            Ok(None) => {
                let Ok(found) = prepared
                    .search_from_preflight_retained_partial_resume_ticket_inferred(
                        haystack,
                        resume_state,
                        resume_position,
                        pending_end,
                    )
                else {
                    return STATUS_RUNTIME_FAILURE;
                };
                let (status, result) = encode_match_result(found);
                result_ptr.write(result);
                status
            }
            Err(_) => STATUS_RUNTIME_FAILURE,
        }
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

/// Recover a Span start after an authenticated native retained-row completion
/// selected only its endpoint.
///
/// This entry accepts only a variable-width, non-nullable Span program with a
/// genuinely incomplete retained table. The exact `window_start..window_end`
/// must be the window returned by the immediately preceding successful
/// [`fre_aot_regex_runtime_search_exclusive_partial_preflight_v1`] call on the
/// same exclusive session. `selected_end` must lie strictly after the window
/// start and at or before its end. Reverse K0 must recover a span whose end is
/// exactly `selected_end`; the forward search is not replayed.
///
/// On success this function returns [`STATUS_MATCH`] and initializes
/// `result_ptr` with the exact Span. Every rejection returns an error status
/// and leaves `result_ptr` untouched. In particular, `Exists`, `SelectedEnd`,
/// nullable Span, fixed-width Span, complete-table, foreign-artifact, stale,
/// and cross-window calls are rejected.
///
/// # Safety
///
/// `handle` must satisfy the exclusive live-handle requirements of
/// [`fre_aot_regex_runtime_search_exclusive_v1`]. Haystack, result, and
/// identity pointer requirements are the same as for
/// [`fre_aot_regex_runtime_search_exclusive_from_partial_v1`]. The caller must
/// pass the same haystack and exact window on which the identified native
/// table ran, and `selected_end` must be the local native completion it
/// produced. No overlapping call or destroy may use any copy of `handle`.
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "this exported postflight is an audited raw C boundary with explicit artifact, exact window, and selected endpoint"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_search_exclusive_recover_partial_span_v1(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    expected_artifact_identity_ptr: *const u8,
    selected_end: usize,
) -> u32 {
    if handle.is_invalid() {
        return STATUS_INVALID_HANDLE;
    }
    if haystack_ptr.is_null()
        || result_ptr.is_null()
        || !result_ptr.is_aligned()
        || expected_artifact_identity_ptr.is_null()
        || haystack_len > isize::MAX.unsigned_abs()
        || window_start > window_end
        || window_end > haystack_len
        || selected_end <= window_start
        || selected_end > window_end
    {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: the caller guarantees one live exclusively owned session plus
    // all readable and writable disjoint extents described above.
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let prepared = &mut *handle.0.cast::<PreparedAotRegex>();
        let haystack = std::slice::from_raw_parts(haystack_ptr, haystack_len);
        let expected_artifact_identity = expected_artifact_identity_ptr
            .cast::<[u8; ARTIFACT_IDENTITY_BYTES]>()
            .read();
        let Ok(MatchResult::Span(Some((start, end)))) = prepared
            .recover_retained_partial_span_from_selected_end(
                haystack,
                SearchWindow::new(window_start, window_end),
                expected_artifact_identity,
                selected_end,
            )
        else {
            return STATUS_RUNTIME_FAILURE;
        };
        result_ptr.write(FreAotRegexResultV1 { start, end });
        STATUS_MATCH
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

/// Authenticate and prepare one native incomplete-retained search.
///
/// The call settles any prior local native completion, runs the complete
/// suffix and cut proofs in portable order, and then applies adaptive native
/// admission. On [`STATUS_NO_MATCH`] or [`STATUS_MATCH`], `result_ptr` is
/// initialized and the search is complete. On
/// [`STATUS_PARTIAL_PREFLIGHT_ENTER`], `window_out` is initialized to the
/// exact non-empty, possibly narrowed window and the native table must enter
/// there. If admission declines, K0 completes from that narrowed window
/// inside this call; the generated entry must not replay the accelerators.
///
/// The expected identity points to exactly [`ARTIFACT_IDENTITY_BYTES`] bytes
/// and binds the emitted native table to the prepared semantic program.
///
/// # Safety
///
/// The exclusive handle, haystack, result, and identity requirements are the
/// same as for [`fre_aot_regex_runtime_search_exclusive_from_partial_v1`].
/// `window_out` must be non-null, aligned, writable, and disjoint from all
/// readable inputs and `result_ptr`. No overlapping search or destroy may use
/// any copy of `handle`.
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "this exported preflight is an audited raw C boundary with explicit artifact and exact-window outputs"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_search_exclusive_partial_preflight_v1(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    expected_artifact_identity_ptr: *const u8,
    window_out: *mut FreAotRegexSearchWindowV1,
) -> u32 {
    // SAFETY: this forwards the exact public boundary and its documented
    // requirements to the shared implementation without dereferencing them.
    unsafe {
        exclusive_partial_preflight(
            handle,
            haystack_ptr,
            haystack_len,
            window_start,
            window_end,
            result_ptr,
            expected_artifact_identity_ptr,
            window_out,
            false,
        )
    }
}

/// Authenticate and project an ordinary warmed K0 root for generated code.
///
/// On status [`STATUS_PARTIAL_PREFLIGHT_ENTER`], `preflight_out` contains the
/// exact admitted search window, a pointer-stable fixed-layout descriptor,
/// and the immutable cache identity that must equal the descriptor's identity
/// before either projected address is read. These exposed-provenance addresses
/// are live only until the admitted native scan returns or calls a runtime
/// helper; generated code must not retain them across that boundary. A cold,
/// loop-owned, adaptively bypassed, or structurally unsupported cache completes
/// through canonical K0 inside this call and returns an ordinary match status.
///
/// # Safety
///
/// The handle, haystack, result, and identity requirements are identical to
/// [`fre_aot_regex_runtime_search_exclusive_partial_preflight_v1`].
/// `preflight_out` must be non-null, aligned, writable, and disjoint from all
/// readable inputs and `result_ptr`.
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "the private dynamic-row boundary carries an authenticated descriptor identity"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_search_exclusive_dynamic_rows_preflight_v1(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    expected_artifact_identity_ptr: *const u8,
    preflight_out: *mut FreAotRegexDynamicRowsPreflightV1,
) -> u32 {
    if handle.is_invalid() {
        return STATUS_INVALID_HANDLE;
    }
    if haystack_ptr.is_null()
        || result_ptr.is_null()
        || !result_ptr.is_aligned()
        || expected_artifact_identity_ptr.is_null()
        || preflight_out.is_null()
        || !preflight_out.is_aligned()
        || haystack_len > isize::MAX.unsigned_abs()
        || window_start > window_end
        || window_end > haystack_len
    {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: the checks above establish the raw extents, alignments, and
    // exact-window contract consumed by the shared transaction.
    unsafe {
        exclusive_dynamic_rows_preflight_prevalidated::<false, true>(
            handle,
            haystack_ptr,
            haystack_len,
            window_start,
            window_end,
            result_ptr,
            expected_artifact_identity_ptr,
            preflight_out,
        )
    }
}

/// Compiler-private dynamic-row preflight for FRE's generated prepared entry.
///
/// This symbol is deliberately absent from the public C header. Its sole
/// producer is the generated prepared wrapper, which has already validated
/// every raw ABI fact below and passes its own static artifact identity plus
/// an aligned stack-resident preflight record. Semantic identity, workspace,
/// program-shape, descriptor, and admission checks remain in the shared
/// transaction.
///
/// # Safety
///
/// `handle` must name one exclusively owned live prepared session.
/// `haystack_ptr` must be non-null and readable for `haystack_len` bytes, with
/// `haystack_len <= isize::MAX`. The exact window must satisfy
/// `window_start <= window_end <= haystack_len`. `result_ptr` and
/// `preflight_out` must be non-null, aligned, writable, mutually disjoint, and
/// disjoint from all readable inputs. `expected_artifact_identity_ptr` must be
/// non-null and readable for exactly [`ARTIFACT_IDENTITY_BYTES`] bytes. No
/// overlapping search or destroy may use any copy of `handle`.
#[doc(hidden)]
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "the generated-only ABI consumes raw facts proved by its emitted caller"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v1(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    expected_artifact_identity_ptr: *const u8,
    preflight_out: *mut FreAotRegexDynamicRowsPreflightV1,
) -> u32 {
    // SAFETY: every raw requirement is part of this compiler-private
    // function's contract and is established by its sole emitted caller.
    unsafe {
        exclusive_dynamic_rows_preflight_prevalidated::<false, true>(
            handle,
            haystack_ptr,
            haystack_len,
            window_start,
            window_end,
            result_ptr,
            expected_artifact_identity_ptr,
            preflight_out,
        )
    }
}

/// Compiler-private trusted dynamic-row preflight for FRE's generated entry.
///
/// This V2 symbol has the same four-word output layout as V1, but strengthens
/// the successful-entry contract. On [`STATUS_PARTIAL_PREFLIGHT_ENTER`], the
/// returned descriptor was constructed by the live prepared workspace and is
/// valid for the complete synchronous native scan: its descriptor, rows, and
/// class-map addresses are non-null and suitably aligned; its cell encoding,
/// live extent, stride, initial row, initial flags, loop-row geometry, and
/// cache identity satisfy the canonical dynamic-row invariants. The output
/// cache identity is the identity stored in that descriptor. Neither the
/// descriptor nor either projected source address may be retained across a
/// helper call, re-entry, or the end of this exclusive search.
/// Calling any deopt, continuation, or recovery helper ends use of the
/// descriptor before that helper may mutate or rebuild the workspace.
///
/// The versioned symbol prevents an object that relies on this stronger
/// contract from linking against an older runtime that only implements V1.
/// It remains deliberately absent from the public C header.
///
/// # Safety
///
/// The raw input, exclusive ownership, and disjoint writable-output
/// requirements are identical to
/// [`fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v1`].
#[doc(hidden)]
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "the generated-only ABI consumes raw facts proved by its emitted caller"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v2(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    expected_artifact_identity_ptr: *const u8,
    preflight_out: *mut FreAotRegexDynamicRowsPreflightV1,
) -> u32 {
    // SAFETY: every raw requirement is part of this compiler-private
    // function's contract and is established by its sole emitted caller.
    unsafe {
        exclusive_dynamic_rows_preflight_prevalidated::<false, true>(
            handle,
            haystack_ptr,
            haystack_len,
            window_start,
            window_end,
            result_ptr,
            expected_artifact_identity_ptr,
            preflight_out,
        )
    }
}

/// Compiler-private trusted dynamic-row preflight with invariant checks
/// specialized out of the admitted-search path.
///
/// V3 preserves V2's four-word output layout and descriptor contract. It also
/// relies on the generated wrapper's exact-window validation and on the
/// prepared runtime's exclusive ownership of the workspace constructed for
/// the authenticated program. Artifact identity remains checked on every
/// call. V1, V2, and the public preflight retain all of their existing checks.
///
/// The versioned symbol prevents a generated object that relies on those
/// stronger premises from linking against a V2 runtime. It is deliberately
/// absent from the public C header.
///
/// # Safety
///
/// The raw pointer requirements are identical to
/// [`fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v2`].
/// In addition, the caller must be FRE's generated dynamic-row wrapper for the
/// program shape owned by `handle`, whose live prepared workspace must remain
/// exclusively owned and unmodified. A foreign expected identity is allowed
/// and is rejected transactionally before the trusted program path proceeds.
#[doc(hidden)]
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "the generated-only V3 ABI consumes wrapper and prepared-workspace invariants"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v3(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    expected_artifact_identity_ptr: *const u8,
    preflight_out: *mut FreAotRegexDynamicRowsPreflightV1,
) -> u32 {
    // SAFETY: every raw and invariant requirement is part of this versioned
    // compiler-private contract and is established by its sole emitted caller
    // plus the runtime-owned prepared handle.
    unsafe {
        exclusive_dynamic_rows_preflight_prevalidated::<true, true>(
            handle,
            haystack_ptr,
            haystack_len,
            window_start,
            window_end,
            result_ptr,
            expected_artifact_identity_ptr,
            preflight_out,
        )
    }
}

/// Compiler-private trusted dynamic-row preflight without a hot identity copy.
///
/// V4 retains V2's descriptor trust contract and calling convention, but on
/// [`STATUS_PARTIAL_PREFLIGHT_ENTER`] initializes only `start`, `end`, and
/// `native_rows_address`. The fourth V1-layout output word is deliberately
/// untouched. Generated code reloads `cache_identity` from the still-live
/// trusted descriptor only on a first-unpublished-cell side exit, before the
/// continuation helper can mutate the workspace. No caller may read the
/// fourth output word after a successful V4 preflight.
///
/// The versioned symbol prevents generated objects with this three-word write
/// contract from linking against an older runtime. It remains deliberately
/// absent from the public C header.
///
/// # Safety
///
/// The raw input, exclusive ownership, and disjoint writable-output
/// requirements are identical to
/// [`fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v2`].
#[doc(hidden)]
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "the generated-only ABI consumes raw facts proved by its emitted caller"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v4(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    expected_artifact_identity_ptr: *const u8,
    preflight_out: *mut FreAotRegexDynamicRowsPreflightV1,
) -> u32 {
    // SAFETY: every raw requirement is part of this compiler-private
    // function's contract and is established by its sole emitted caller.
    unsafe {
        exclusive_dynamic_rows_preflight_prevalidated::<false, false>(
            handle,
            haystack_ptr,
            haystack_len,
            window_start,
            window_end,
            result_ptr,
            expected_artifact_identity_ptr,
            preflight_out,
        )
    }
}

/// Compiler-private trusted dynamic-row preflight with both hot-path contracts.
///
/// V5 combines V3's authenticated static program/workspace premises with V4's
/// three-word successful-entry output. Artifact identity, mutable admission,
/// descriptor readiness, and all transaction checks remain in the runtime.
/// Generated code reloads the descriptor identity only on a rare continuation
/// side exit and must never read the untouched fourth output word.
///
/// # Safety
///
/// The caller must satisfy V3's generated-wrapper and prepared-workspace
/// premises together with V4's three-word output contract.
#[doc(hidden)]
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "the generated-only V5 ABI combines the audited V3 and V4 premises"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v5(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    expected_artifact_identity_ptr: *const u8,
    preflight_out: *mut FreAotRegexDynamicRowsPreflightV1,
) -> u32 {
    // SAFETY: both versioned compiler-private contracts are established by
    // the sole generated caller plus the runtime-owned prepared handle.
    unsafe {
        exclusive_dynamic_rows_preflight_prevalidated::<true, false>(
            handle,
            haystack_ptr,
            haystack_len,
            window_start,
            window_end,
            result_ptr,
            expected_artifact_identity_ptr,
            preflight_out,
        )
    }
}

/// Compiler-private dynamic-row preflight with a return-register descriptor.
///
/// V6 preserves V5's trusted-program, artifact-identity, mutable-admission,
/// descriptor, transaction, and exact-window checks. On
/// [`STATUS_PARTIAL_PREFLIGHT_ENTER`], it writes only the admitted `start` and
/// `end` to `window_out` and returns the authenticated native-row descriptor
/// beside the status in a two-word C aggregate. On every other status the
/// returned descriptor is zero and `window_out` has V5's transactional
/// untouched-output semantics.
///
/// The versioned symbol prevents generated objects that consume the second
/// aggregate return register from linking against a V5-only runtime. It is
/// deliberately absent from the public C header.
///
/// # Safety
///
/// The caller must satisfy V5's generated-wrapper and prepared-workspace
/// premises. `window_out` must be non-null, aligned, writable for exactly one
/// [`FreAotRegexSearchWindowV1`], and disjoint from every readable input and
/// `result_ptr`.
#[doc(hidden)]
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "the generated-only V6 ABI returns its trusted descriptor in native aggregate registers"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v6(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    expected_artifact_identity_ptr: *const u8,
    window_out: *mut FreAotRegexSearchWindowV1,
) -> FreAotRegexDynamicRowsPreflightResultV6 {
    // SAFETY: V6 changes only the successful output transport. The exact
    // V5 premises still establish every raw and runtime-owned input to the
    // shared transaction, and the two-word output is the prefix written by
    // this policy specialization.
    unsafe {
        exclusive_dynamic_rows_preflight_prevalidated_result::<true, false, false>(
            handle,
            haystack_ptr,
            haystack_len,
            window_start,
            window_end,
            result_ptr,
            expected_artifact_identity_ptr,
            window_out.cast::<FreAotRegexDynamicRowsPreflightV1>(),
        )
    }
}

#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "one panic-catching transaction serves checked public and generated-only entry policies"
)]
unsafe fn exclusive_dynamic_rows_preflight_prevalidated<
    const TRUSTED_PROGRAM: bool,
    const WRITE_CACHE_IDENTITY: bool,
>(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    expected_artifact_identity_ptr: *const u8,
    preflight_out: *mut FreAotRegexDynamicRowsPreflightV1,
) -> u32 {
    // SAFETY: the caller establishes the selected legacy policy's raw input
    // and output contract. Legacy V1--V5 always write the descriptor word on
    // admitted entry; V1--V3 additionally write the cache identity.
    let returned = unsafe {
        exclusive_dynamic_rows_preflight_prevalidated_result::<
            TRUSTED_PROGRAM,
            WRITE_CACHE_IDENTITY,
            true,
        >(
            handle,
            haystack_ptr,
            haystack_len,
            window_start,
            window_end,
            result_ptr,
            expected_artifact_identity_ptr,
            preflight_out,
        )
    };
    u32::try_from(returned.status).unwrap_or(STATUS_RUNTIME_FAILURE)
}

#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "one panic-catching transaction serves legacy memory-return and V6 register-return policies"
)]
unsafe fn exclusive_dynamic_rows_preflight_prevalidated_result<
    const TRUSTED_PROGRAM: bool,
    const WRITE_CACHE_IDENTITY: bool,
    const WRITE_NATIVE_ROWS_ADDRESS: bool,
>(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    expected_artifact_identity_ptr: *const u8,
    preflight_out: *mut FreAotRegexDynamicRowsPreflightV1,
) -> FreAotRegexDynamicRowsPreflightResultV6 {
    let returned =
        |status: u32, native_rows_address: usize| FreAotRegexDynamicRowsPreflightResultV6 {
            status: usize::try_from(status).expect("dynamic-row runtime status fits in usize"),
            native_rows_address,
        };
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let prepared = &mut *handle.0.cast::<PreparedAotRegex>();
        let haystack = std::slice::from_raw_parts(haystack_ptr, haystack_len);
        let expected_artifact_identity = expected_artifact_identity_ptr
            .cast::<[u8; ARTIFACT_IDENTITY_BYTES]>()
            .read();
        let window = SearchWindow::new(window_start, window_end);
        let preflight = if TRUSTED_PROGRAM {
            prepared.compiler_private_preflight_dynamic_native_rows_v3(
                haystack,
                window,
                expected_artifact_identity,
            )
        } else {
            prepared.preflight_dynamic_native_rows(
                haystack,
                window,
                expected_artifact_identity,
            )
        };
        let Ok((outcome, native_rows_address, cache_identity)) = preflight else {
            return returned(STATUS_RUNTIME_FAILURE, 0);
        };
        match outcome {
            RetainedPartialPreflight::Complete(found) => {
                let (status, result) = encode_match_result(found);
                result_ptr.write(result);
                returned(status, 0)
            }
            RetainedPartialPreflight::Enter(window) => {
                if WRITE_CACHE_IDENTITY {
                    preflight_out.write(FreAotRegexDynamicRowsPreflightV1 {
                        start: window.start(),
                        end: window.end(),
                        native_rows_address,
                        cache_generation: cache_identity,
                    });
                } else {
                    // V4/V5 write the descriptor word after the exact window;
                    // V6 transports it in the second aggregate return
                    // register. Every version leaves cache identity available
                    // in the trusted descriptor for a rare continuation side
                    // exit instead of copying it on the common path.
                    std::ptr::addr_of_mut!((*preflight_out).start).write(window.start());
                    std::ptr::addr_of_mut!((*preflight_out).end).write(window.end());
                    if WRITE_NATIVE_ROWS_ADDRESS {
                        std::ptr::addr_of_mut!((*preflight_out).native_rows_address)
                            .write(native_rows_address);
                    }
                }
                returned(STATUS_PARTIAL_PREFLIGHT_ENTER, native_rows_address)
            }
        }
    }))
    .unwrap_or_else(|_| returned(STATUS_RUNTIME_FAILURE, 0))
}

/// Authenticate one native-root-owned incomplete-retained search.
///
/// The call settles any prior local native completion and applies adaptive
/// admission before portable whole-window accelerators. On
/// [`STATUS_PARTIAL_PREFLIGHT_ENTER`], `window_out` is initialized to the
/// unchanged non-empty semantic window and the native table must execute that
/// search exactly once. If admission declines (including the input-size
/// floor), the ordinary
/// suffix-then-cut order and K0 complete inside this call. Match/no-match and
/// error output transactions are identical to
/// [`fre_aot_regex_runtime_search_exclusive_partial_preflight_v1`].
///
/// The expected identity points to exactly [`ARTIFACT_IDENTITY_BYTES`] bytes
/// and binds the emitted native table to the prepared semantic program.
///
/// # Safety
///
/// The exclusive handle, haystack, result, identity, and exact-window output
/// requirements are identical to
/// [`fre_aot_regex_runtime_search_exclusive_partial_preflight_v1`].
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "this exported preflight is an audited raw C boundary with explicit artifact and exact-window outputs"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_search_exclusive_partial_native_root_preflight_v1(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    expected_artifact_identity_ptr: *const u8,
    window_out: *mut FreAotRegexSearchWindowV1,
) -> u32 {
    // SAFETY: this forwards the exact public boundary and its documented
    // requirements to the shared implementation without dereferencing them.
    unsafe {
        exclusive_partial_preflight(
            handle,
            haystack_ptr,
            haystack_len,
            window_start,
            window_end,
            result_ptr,
            expected_artifact_identity_ptr,
            window_out,
            true,
        )
    }
}

#[allow(
    unsafe_code,
    clippy::too_many_arguments,
    reason = "shared validation and transactional output keep both versioned preflight policies identical"
)]
unsafe fn exclusive_partial_preflight(
    handle: FreAotRegexExclusiveHandleV1,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    expected_artifact_identity_ptr: *const u8,
    window_out: *mut FreAotRegexSearchWindowV1,
    native_root_owns_admitted_search: bool,
) -> u32 {
    if handle.is_invalid() {
        return STATUS_INVALID_HANDLE;
    }
    if haystack_ptr.is_null()
        || result_ptr.is_null()
        || !result_ptr.is_aligned()
        || expected_artifact_identity_ptr.is_null()
        || window_out.is_null()
        || !window_out.is_aligned()
        || haystack_len > isize::MAX.unsigned_abs()
        || window_start > window_end
        || window_end > haystack_len
    {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: the caller guarantees one exclusively owned live session plus
    // the disjoint readable and writable extents documented above.
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let prepared = &mut *handle.0.cast::<PreparedAotRegex>();
        let haystack = std::slice::from_raw_parts(haystack_ptr, haystack_len);
        let expected_artifact_identity = expected_artifact_identity_ptr
            .cast::<[u8; ARTIFACT_IDENTITY_BYTES]>()
            .read();
        let window = SearchWindow::new(window_start, window_end);
        let outcome = if native_root_owns_admitted_search {
            prepared.preflight_retained_partial_native_root(
                haystack,
                window,
                expected_artifact_identity,
            )
        } else {
            prepared.preflight_retained_partial(haystack, window, expected_artifact_identity)
        };
        let Ok(outcome) = outcome else {
            return STATUS_RUNTIME_FAILURE;
        };
        match outcome {
            RetainedPartialPreflight::Complete(found) => {
                let (status, result) = encode_match_result(found);
                result_ptr.write(result);
                status
            }
            RetainedPartialPreflight::Enter(window) => {
                window_out.write(FreAotRegexSearchWindowV1 {
                    start: window.start(),
                    end: window.end(),
                });
                STATUS_PARTIAL_PREFLIGHT_ENTER
            }
        }
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

/// Invalidate and release one prepared handle.
///
/// Returns [`STATUS_SUCCESS`] after the owned program and workspace are
/// released, [`STATUS_INVALID_HANDLE`] for a zero, unknown, or already
/// destroyed token, and [`STATUS_RUNTIME_FAILURE`] only for an internal
/// registry failure. A successful call waits for an already-running search to
/// finish. Subsequent uses of every copy of the token are invalid.
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    reason = "the stable destroy symbol has no raw-pointer operations but still requires an unmangled C export"
)]
pub extern "C" fn fre_aot_regex_runtime_destroy_prepared_v1(
    handle: FreAotRegexPreparedHandleV1,
) -> u32 {
    if handle.is_invalid() {
        return STATUS_INVALID_HANDLE;
    }
    catch_unwind(AssertUnwindSafe(|| destroy_prepared(handle))).unwrap_or(STATUS_RUNTIME_FAILURE)
}

fn destroy_prepared(handle: FreAotRegexPreparedHandleV1) -> u32 {
    let entry = match remove_prepared_entry(handle) {
        Ok(Some(entry)) => entry,
        Ok(None) => return STATUS_INVALID_HANDLE,
        Err(()) => return STATUS_RUNTIME_FAILURE,
    };
    let mut state = entry
        .prepared
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if state.take().is_some() {
        STATUS_SUCCESS
    } else {
        STATUS_INVALID_HANDLE
    }
}

/// Destroy one exclusively owned direct-pointer prepared session.
///
/// # Safety
///
/// `handle` must be a live value returned by
/// [`fre_aot_regex_runtime_prepare_exclusive_v1`]. No search may overlap this
/// call, and no copy of the handle may be used or destroyed afterward.
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    reason = "this exported symbol releases an exclusively owned opaque allocation"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_destroy_exclusive_v1(
    handle: FreAotRegexExclusiveHandleV1,
) -> u32 {
    if handle.is_invalid() {
        return STATUS_INVALID_HANDLE;
    }
    catch_unwind(AssertUnwindSafe(|| unsafe {
        drop(Box::from_raw(handle.0.cast::<PreparedAotRegex>()));
        STATUS_SUCCESS
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

/// Execute one immutable, serialized general AOT regex program.
///
/// # Status and result semantics
///
/// Status `0` initializes `result_out` to zero and means no match. Status `1`
/// initializes it according to the compiled output contract: `{0, 0}` for
/// `Exists`, `{end, end}` for `SelectedEnd`, and `{start, end}` for `Span`.
/// Status `2` reports an invalid pointer/window and status `3` reports an
/// invalid program or runtime failure; neither failure status initializes the
/// output.
///
/// This raw compatibility ABI has no artifact-lifetime token, so it soundly
/// validates, owns, and prepares the program on every call instead of caching
/// by a potentially reused address. Rust integrations doing repeated
/// runtime-backed calls should use [`PreparedAotRegex`]. Directly lowered DFA
/// object entries do not call this helper.
///
/// # Safety
///
/// `program_ptr` must point to a readable [`PROGRAM_HEADER_LEN`]-byte header
/// and to the complete immutable extent declared by that header for the
/// duration of the call. `haystack_ptr` must be non-null and readable for
/// `haystack_len` bytes. `result_ptr` must be non-null, properly aligned, and
/// writable for one [`FreAotRegexResultV1`]. The result storage must not
/// overlap either readable extent. Each readable extent must reside within one
/// allocated object and be no larger than `isize::MAX`.
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    reason = "this single exported symbol is the audited raw C pointer boundary"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_search_v1(
    program_ptr: *const u8,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
) -> u32 {
    if program_ptr.is_null()
        || haystack_ptr.is_null()
        || result_ptr.is_null()
        || !result_ptr.is_aligned()
        || haystack_len > isize::MAX.unsigned_abs()
        || window_start > window_end
        || window_end > haystack_len
    {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: the function's contract supplies all pointer extents,
    // immutability, alignment, writability, and non-overlap requirements. The
    // helper performs its own null/window checks above and artifact bounds
    // checks before extending the fixed-header slice.
    catch_unwind(AssertUnwindSafe(|| unsafe {
        search_checked_pointers(
            program_ptr,
            haystack_ptr,
            haystack_len,
            window_start,
            window_end,
            result_ptr,
            true,
        )
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

/// Execute a serialized program without its optional portable endpoint
/// existence oracle.
///
/// Generated endpoint-oracle wrappers use this exact semantic fallback after
/// either a native possible-match result or a short-input bypass. Mandatory
/// proofs and the ordered executor are unchanged; only the redundant portable
/// whole-window probe is suppressed. Status, result, and pointer behavior are
/// identical to [`fre_aot_regex_runtime_search_v1`].
///
/// # Safety
///
/// The pointer, extent, alignment, writability, and non-overlap requirements
/// are identical to [`fre_aot_regex_runtime_search_v1`].
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    reason = "this generated-code replay symbol shares the audited raw C pointer boundary"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_search_without_endpoint_oracle_v1(
    program_ptr: *const u8,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
) -> u32 {
    if program_ptr.is_null()
        || haystack_ptr.is_null()
        || result_ptr.is_null()
        || !result_ptr.is_aligned()
        || haystack_len > isize::MAX.unsigned_abs()
        || window_start > window_end
        || window_end > haystack_len
    {
        return STATUS_INVALID_ARGUMENT;
    }

    // SAFETY: this boundary has the same pointer contract and performs the
    // same validation as the ordinary raw compatibility entry above.
    catch_unwind(AssertUnwindSafe(|| unsafe {
        search_checked_pointers(
            program_ptr,
            haystack_ptr,
            haystack_len,
            window_start,
            window_end,
            result_ptr,
            false,
        )
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

#[allow(
    unsafe_code,
    reason = "raw slice construction and the final disjoint result write are confined to this audited helper"
)]
unsafe fn search_checked_pointers(
    program_ptr: *const u8,
    haystack_ptr: *const u8,
    haystack_len: usize,
    window_start: usize,
    window_end: usize,
    result_ptr: *mut FreAotRegexResultV1,
    allow_endpoint_oracle: bool,
) -> u32 {
    // SAFETY: the exported function contract guarantees the fixed readable
    // header extent and the caller cannot mutate it during this call.
    let header = unsafe { std::slice::from_raw_parts(program_ptr, PROGRAM_HEADER_LEN) };
    let Ok(program_len) = CompiledProgram::serialized_len_from_header(header) else {
        return STATUS_RUNTIME_FAILURE;
    };
    // SAFETY: the exported function contract guarantees the complete extent
    // declared by the validated fixed header.
    let program_bytes = unsafe { std::slice::from_raw_parts(program_ptr, program_len) };
    let Ok(mut prepared) = PreparedAotRegex::deserialize(program_bytes) else {
        return STATUS_RUNTIME_FAILURE;
    };
    // SAFETY: the exported function contract guarantees this readable extent,
    // and the checked length is representable by `isize`.
    let haystack = unsafe { std::slice::from_raw_parts(haystack_ptr, haystack_len) };
    let result = if allow_endpoint_oracle {
        execute_search(&mut prepared, haystack, window_start, window_end)
    } else {
        execute_search_without_endpoint_oracle(
            &mut prepared,
            haystack,
            window_start,
            window_end,
        )
    };
    let Ok((status, result)) = result else {
        return STATUS_RUNTIME_FAILURE;
    };
    // End the haystack borrow before writing through the disjoint output
    // pointer promised by the C contract.
    let _ = haystack;
    // SAFETY: the exported function contract guarantees aligned, writable,
    // non-overlapping storage for exactly one result.
    unsafe { result_ptr.write(result) };
    status
}

fn execute_search(
    prepared: &mut PreparedAotRegex,
    haystack: &[u8],
    window_start: usize,
    window_end: usize,
) -> Result<(u32, FreAotRegexResultV1), CompileError> {
    Ok(encode_match_result(prepared.search(
        haystack,
        SearchWindow::new(window_start, window_end),
    )?))
}

fn execute_search_without_endpoint_oracle(
    prepared: &mut PreparedAotRegex,
    haystack: &[u8],
    window_start: usize,
    window_end: usize,
) -> Result<(u32, FreAotRegexResultV1), CompileError> {
    Ok(encode_match_result(prepared.search_without_endpoint_oracle(
        haystack,
        SearchWindow::new(window_start, window_end),
    )?))
}

fn execute_exclusive_search(
    prepared: &mut PreparedAotRegex,
    haystack: &[u8],
    window_start: usize,
    window_end: usize,
) -> Result<(u32, FreAotRegexResultV1), CompileError> {
    Ok(encode_match_result(prepared.search_exclusive(
        haystack,
        SearchWindow::new(window_start, window_end),
    )?))
}

fn encode_match_result(result: MatchResult) -> (u32, FreAotRegexResultV1) {
    match result {
        MatchResult::Exists(false) | MatchResult::SelectedEnd(None) | MatchResult::Span(None) => {
            (STATUS_NO_MATCH, FreAotRegexResultV1::default())
        }
        MatchResult::Exists(true) => {
            // Exists deliberately exposes no endpoint information.
            (STATUS_MATCH, FreAotRegexResultV1::default())
        }
        MatchResult::SelectedEnd(Some(end)) => {
            (STATUS_MATCH, FreAotRegexResultV1 { start: end, end })
        }
        MatchResult::Span(Some((start, end))) => (STATUS_MATCH, FreAotRegexResultV1 { start, end }),
    }
}

#[cfg(test)]
#[allow(
    unsafe_code,
    reason = "tests exercise the exported raw C boundary with explicitly valid or deliberately rejected pointers"
)]
mod tests {
    use std::fmt::Write as _;

    use fre_aot_regex::{
        AotDomainV1, AotOperationSetV1, AotProjectionV1, AotReducerV1, CompileLimitsV1,
        CompileMode, CompileRequest, DeterminizeLimits, EngineKind, EngineSelectionReason,
        AOT_OPERATION_SET_V1_MEMBER_DESCRIPTOR_BYTES,
        AOT_OPERATION_SET_V1_STAGE_DESCRIPTOR_BYTES,
        FROZEN_COMPACT_LOOP_PLAN_V1_BYTES, FROZEN_COMPACT_LOOP_PLAN_V1_MEMBERS_OFFSET,
        FROZEN_COMPACT_LOOP_PLAN_V1_SCANNER_ADDRESS_OFFSET,
        FROZEN_DYNAMIC_ROWS_V6_LOOP_PLAN_COUNT_OFFSET, FROZEN_DYNAMIC_ROWS_V6_LOOP_PLANS_OFFSET,
        FROZEN_PREPARED_HEADER_V1_FLAGS_OFFSET,
        FROZEN_PREPARED_HEADER_V1_FLAG_DYNAMIC_ROWS_V6,
        FROZEN_PREPARED_HEADER_V1_FLAG_DYNAMIC_ROWS_V7,
        FROZEN_PREPARED_HEADER_V6_DYNAMIC_ROWS_OFFSET, MatchResult, OutputContract, Target,
        STATIC_PREFIX_RESUME_DESCRIPTOR_V1_MAGIC, STATIC_PREFIX_RESUME_DESCRIPTOR_V1_STATE_BYTES,
        STATIC_PREFIX_RESUME_DESCRIPTOR_V2_MAGIC,
        compile,
    };

    use super::*;

    fn wide_class_variable_pattern() -> String {
        let mut pattern = String::from("(?-u:(?:");
        for bit in 0_u32..8 {
            if bit != 0 {
                pattern.push('|');
            }
            pattern.push('[');
            for byte in u8::MIN..=u8::MAX {
                let selected = if byte == 0 {
                    7
                } else {
                    byte.trailing_zeros()
                };
                if selected == bit {
                    write!(&mut pattern, "\\x{byte:02X}").unwrap();
                }
            }
            pattern.push(']');
            pattern.push(char::from(b'a' + u8::try_from(bit).unwrap()));
        }
        pattern.push_str(")(?:q)?)");
        pattern
    }

    #[test]
    fn prepared_wide_k0_retains_compact_owner_for_all_outputs() {
        let pattern = wide_class_variable_pattern();
        let assert_owner = |pattern: &str, output: OutputContract| {
            let mut limits = CompileLimitsV1::default();
            limits.determinize.max_states = 0;
            let compiled = compile(
                CompileRequest::new(pattern, Target::x86_64_linux())
                    .mode(CompileMode::Fast)
                    .limits(limits)
                    .output(output),
            )
            .unwrap_or_else(|error| panic!("compile {output:?}: {error}"));
            let bytes = compiled.program().serialize().unwrap();
            let program = CompiledProgram::deserialize(&bytes).unwrap();
            let retained = program
                .prepare_workspace()
                .unwrap()
                .compiler_private_k0_retained_bytes();
            assert!(
                retained > FROZEN_DYNAMIC_SIDECAR_MAX_PACKED_BYTES,
                "{output:?} must exercise the independently larger K0 setup budget"
            );
            assert!(retained <= FROZEN_DYNAMIC_SIDECAR_MAX_K0_BYTES, "{output:?}");
            let prepared = PreparedAotRegex::from_program(program).unwrap();
            assert!(prepared.frozen_dynamic_rows.is_some(), "{output:?}");
            assert!(prepared.frozen_header.has_dynamic_rows(), "{output:?}");
        };
        for output in [OutputContract::Exists, OutputContract::SelectedEnd] {
            assert_owner(&pattern, output);
        }
        assert_owner(r"(?-u:a{16,})", OutputContract::Span);
    }

    fn program(pattern: &str, output: OutputContract) -> Vec<u8> {
        let compiled = compile(
            CompileRequest::new(pattern, Target::x86_64_linux())
                .mode(CompileMode::Fast)
                .output(output),
        )
        .expect("compile general NFA program");
        assert_eq!(compiled.program().engine_kind(), EngineKind::OrderedNfa);
        compiled.program().serialize().expect("serialize program")
    }

    fn operation_set_bytes(operations: &[(AotOperationAxesV1, &[u8])]) -> Vec<u8> {
        AotOperationSetV1::from_operations(operations.iter().copied())
            .expect("build operation set")
            .as_bytes()
            .to_vec()
    }

    fn prepare_operation_set(
        bytes: &[u8],
        config: &FreAotRegexOperationSetPrepareConfigV1,
    ) -> FreAotRegexOperationSetExclusiveHandleV1 {
        let mut handle = FreAotRegexOperationSetExclusiveHandleV1::INVALID;
        // SAFETY: the complete operation-set/config extents are readable and
        // the disjoint aligned output remains live for this call.
        let status = unsafe {
            fre_aot_regex_runtime_prepare_operation_set_exclusive_v1(
                bytes.as_ptr(),
                bytes.len(),
                config,
                &raw mut handle,
            )
        };
        assert_eq!(status, STATUS_SUCCESS);
        assert!(!handle.is_invalid());
        handle
    }

    #[test]
    fn operation_set_planner_unions_shared_members_and_fails_closed() {
        let span = program("(?:ab|c+)", OutputContract::Span);
        let bytes = operation_set_bytes(&[
            (AotOperationAxesV1::SEARCH, span.as_slice()),
            (AotOperationAxesV1::COUNT, span.as_slice()),
            (AotOperationAxesV1::SPAN_SUM, span.as_slice()),
            (AotOperationAxesV1::GREP_COUNT, span.as_slice()),
            (AotOperationAxesV1::SEARCH, span.as_slice()),
        ]);
        let view = AotOperationSetV1View::deserialize(&bytes).unwrap();
        let plan = OperationSetPreparationPlan::from_view(view).unwrap();
        assert_eq!(plan.member_operations.len(), 1);
        assert_eq!(plan.member_operations[0].0, 0b1111);
        assert_eq!(
            plan.roots
                .iter()
                .map(|root| root.operation)
                .collect::<Vec<_>>(),
            [
                Stage1Operation::Search,
                Stage1Operation::Count,
                Stage1Operation::SpanSum,
                Stage1Operation::GrepCount,
                Stage1Operation::Search,
            ]
        );
        assert!(plan.roots.iter().all(|root| root.member_index == 0));

        let unsupported = AotOperationAxesV1::new(
            AotReducerV1::SelectOne,
            AotProjectionV1::Span,
            AotDomainV1::Whole,
        );
        assert_eq!(
            Stage1Operation::from_axes(unsupported),
            Err(OperationSetRuntimeError::UnsupportedOperation)
        );
        assert!(matches!(
            operation_set_fixed_retained_bytes(usize::MAX, 1),
            Err(OperationSetRuntimeError::Arithmetic(_))
        ));

        let first = program("first-unreachable-fixture", OutputContract::Exists);
        let second = program("second-unreachable-fixture", OutputContract::Exists);
        let reachable = operation_set_bytes(&[
            (AotOperationAxesV1::SEARCH, first.as_slice()),
            (AotOperationAxesV1::SEARCH, second.as_slice()),
        ]);
        let stage_offset = usize::try_from(u64::from_le_bytes(
            reachable[72..80].try_into().unwrap(),
        ))
        .unwrap();
        let first_member = u32::from_le_bytes(
            reachable[stage_offset..stage_offset + 4]
                .try_into()
                .unwrap(),
        );
        let second_stage = stage_offset + AOT_OPERATION_SET_V1_STAGE_DESCRIPTOR_BYTES;
        let second_member = u32::from_le_bytes(
            reachable[second_stage..second_stage + 4]
                .try_into()
                .unwrap(),
        );
        assert_ne!(first_member, second_member);
        let member_table_offset = usize::try_from(u64::from_le_bytes(
            reachable[48..56].try_into().unwrap(),
        ))
        .unwrap();
        let unreachable = [
            (second_stage, first_member, second_member),
            (stage_offset, second_member, first_member),
        ]
        .into_iter()
        .find_map(|(duplicate_stage, reached_member, unreachable_member)| {
            let mut candidate = reachable.clone();
            candidate[duplicate_stage..duplicate_stage + 4]
                .copy_from_slice(&reached_member.to_le_bytes());
            let descriptor = member_table_offset
                + usize::try_from(unreachable_member).unwrap()
                    * AOT_OPERATION_SET_V1_MEMBER_DESCRIPTOR_BYTES;
            let payload_offset = usize::try_from(u64::from_le_bytes(
                candidate[descriptor + 16..descriptor + 24]
                    .try_into()
                    .unwrap(),
            ))
            .unwrap();
            // The borrowed envelope accepts a body-only role corruption. Pick
            // the canonical-order-preserving direction, then prove global
            // reachability wins before the unreachable body's census.
            candidate[payload_offset + PROGRAM_HEADER_LEN + 52] = u8::MAX;
            if AotOperationSetV1View::deserialize(&candidate).is_ok() {
                Some(candidate)
            } else {
                None
            }
        })
        .expect("one body mutation preserves the two-member digest order");
        assert!(matches!(
            PreparedAotOperationSet::deserialize_with_config(
                &unreachable,
                FreAotRegexOperationSetPrepareConfigV1::new(),
            ),
            Err(OperationSetRuntimeError::UnreachableMember)
        ));
    }

    #[test]
    fn operation_set_receipt_binds_prospective_and_declined_start_work() {
        let config = FreAotRegexOperationSetPrepareConfigV1 {
            max_start_filter_setup_work: 10,
            ..FreAotRegexOperationSetPrepareConfigV1::new()
        };
        let receipt = |prospective_start_filter_work,
                       actual_start_filter_work,
                       start_filter_aggregate_admitted| {
            OperationSetPreparationReceipt {
                prospective_start_filter_work,
                actual_start_filter_work,
                start_filter_aggregate_admitted,
                grep_count_workspace_bytes: 0,
                prospective_handle_bytes: 0,
                retained_handle_bytes: 0,
            }
        };
        assert!(receipt(Some(10), 10, true).authenticates(config));
        assert!(!receipt(Some(9), 10, true).authenticates(config));
        assert!(!receipt(Some(10), 0, false).authenticates(config));

        let declined = FreAotRegexOperationSetPrepareConfigV1 {
            max_start_filter_setup_work: 9,
            ..config
        };
        assert!(receipt(Some(10), 0, false).authenticates(declined));
        assert!(!receipt(Some(10), 1, false).authenticates(declined));
        assert!(receipt(None, 0, false).authenticates(config));
        assert!(!receipt(None, 1, false).authenticates(config));
        assert!(!receipt(None, 0, true).authenticates(config));
        let mut oversized_handle = receipt(Some(10), 10, true);
        oversized_handle.prospective_handle_bytes = config
            .max_handle_bytes
            .checked_add(1)
            .unwrap();
        assert!(!oversized_handle.authenticates(config));
        let mut exceeds_prospective = receipt(Some(10), 10, true);
        exceeds_prospective.prospective_handle_bytes = 9;
        exceeds_prospective.retained_handle_bytes = 10;
        assert!(!exceeds_prospective.authenticates(config));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one ABI-boundary test covers exact layout, config-first validation, corruption, and retained-cap commits"
    )]
    fn operation_set_prepare_abi_is_exact_bounded_and_transactional() {
        assert_eq!(size_of::<FreAotRegexOperationSetPrepareConfigV1>(), 64);
        assert_eq!(
            align_of::<FreAotRegexOperationSetPrepareConfigV1>(),
            align_of::<u64>()
        );
        assert_eq!(
            core::mem::offset_of!(
                FreAotRegexOperationSetPrepareConfigV1,
                struct_size
            ),
            0
        );
        assert_eq!(
            core::mem::offset_of!(
                FreAotRegexOperationSetPrepareConfigV1,
                config_version
            ),
            4
        );
        assert_eq!(
            core::mem::offset_of!(
                FreAotRegexOperationSetPrepareConfigV1,
                max_handle_bytes
            ),
            8
        );
        assert_eq!(
            core::mem::offset_of!(
                FreAotRegexOperationSetPrepareConfigV1,
                max_start_filter_setup_work
            ),
            16
        );
        assert_eq!(
            core::mem::offset_of!(
                FreAotRegexOperationSetPrepareConfigV1,
                max_grep_count_workspace_bytes
            ),
            24
        );
        assert_eq!(
            core::mem::offset_of!(
                FreAotRegexOperationSetPrepareConfigV1,
                reserved
            ),
            32
        );
        assert_eq!(size_of::<FreAotRegexOperationSetOutputV1>(), 24);
        assert_eq!(
            align_of::<FreAotRegexOperationSetOutputV1>(),
            align_of::<u64>()
        );
        assert_eq!(
            core::mem::offset_of!(FreAotRegexOperationSetOutputV1, kind),
            0
        );
        assert_eq!(
            core::mem::offset_of!(FreAotRegexOperationSetOutputV1, status),
            4
        );
        assert_eq!(
            core::mem::offset_of!(FreAotRegexOperationSetOutputV1, first),
            8
        );
        assert_eq!(
            core::mem::offset_of!(FreAotRegexOperationSetOutputV1, second),
            16
        );
        assert_eq!(
            size_of::<FreAotRegexOperationSetExclusiveHandleV1>(),
            size_of::<*mut std::ffi::c_void>()
        );
        assert_eq!(
            align_of::<FreAotRegexOperationSetExclusiveHandleV1>(),
            align_of::<*mut std::ffi::c_void>()
        );
        assert_eq!(OPERATION_SET_PREPARE_CONFIG_V1_SIZE, 64);
        assert_eq!(OPERATION_SET_PREPARE_CONFIG_V1_VERSION, 1);
        assert_eq!(DEFAULT_OPERATION_SET_MAX_HANDLE_BYTES, 1_073_741_824);
        assert_eq!(OPERATION_SET_OUTPUT_SEARCH_EXISTS, 1);
        assert_eq!(OPERATION_SET_OUTPUT_SEARCH_SELECTED_END, 2);
        assert_eq!(OPERATION_SET_OUTPUT_SEARCH_SPAN, 3);
        assert_eq!(OPERATION_SET_OUTPUT_COUNT, 4);
        assert_eq!(OPERATION_SET_OUTPUT_SPAN_SUM, 5);
        assert_eq!(OPERATION_SET_OUTPUT_GREP_COUNT, 6);
        for declaration in [
            "#include \"fre_aot_regex_runtime_v1.h\"",
            "FRE_AOT_REGEX_OPERATION_SET_PREPARE_CONFIG_V1_SIZE 64u",
            "FRE_AOT_REGEX_OPERATION_SET_PREPARE_CONFIG_V1_VERSION 1u",
            "FRE_AOT_REGEX_DEFAULT_OPERATION_SET_MAX_HANDLE_BYTES UINT64_C(1073741824)",
            "FRE_AOT_REGEX_OPERATION_SET_DEFAULT_START_FILTER_SETUP_WORK UINT64_C(100000000)",
            "FRE_AOT_REGEX_OPERATION_SET_DEFAULT_GREP_COUNT_WORKSPACE_BYTES UINT64_C(67108864)",
            "FRE_AOT_REGEX_OPERATION_SET_OUTPUT_SEARCH_EXISTS 1u",
            "FRE_AOT_REGEX_OPERATION_SET_OUTPUT_SEARCH_SELECTED_END 2u",
            "FRE_AOT_REGEX_OPERATION_SET_OUTPUT_SEARCH_SPAN 3u",
            "FRE_AOT_REGEX_OPERATION_SET_OUTPUT_COUNT 4u",
            "FRE_AOT_REGEX_OPERATION_SET_OUTPUT_SPAN_SUM 5u",
            "FRE_AOT_REGEX_OPERATION_SET_OUTPUT_GREP_COUNT 6u",
            "typedef struct FreAotRegexOperationSetPrepareConfigV1",
            "uint64_t reserved[4]",
            "typedef void *FreAotRegexOperationSetExclusiveHandleV1",
            "typedef struct FreAotRegexOperationSetOutputV1",
            "canonical optimizer-free V4",
            "Every recoverable failure leaves",
            "one destroy",
            "fre_aot_regex_runtime_prepare_operation_set_exclusive_v1",
            "fre_aot_regex_runtime_execute_operation_set_exclusive_v1",
            "fre_aot_regex_runtime_destroy_operation_set_exclusive_v1",
        ] {
            assert!(
                C_API_OPERATION_SET_V1_HEADER.contains(declaration),
                "{declaration}"
            );
        }
        let _: unsafe extern "C" fn(
            *const u8,
            usize,
            *const FreAotRegexOperationSetPrepareConfigV1,
            *mut FreAotRegexOperationSetExclusiveHandleV1,
        ) -> u32 = fre_aot_regex_runtime_prepare_operation_set_exclusive_v1;
        let _: unsafe extern "C" fn(
            FreAotRegexOperationSetExclusiveHandleV1,
            *const u8,
            usize,
            *mut FreAotRegexOperationSetOutputV1,
            usize,
        ) -> u32 = fre_aot_regex_runtime_execute_operation_set_exclusive_v1;
        let _: unsafe extern "C" fn(FreAotRegexOperationSetExclusiveHandleV1) -> u32 =
            fre_aot_regex_runtime_destroy_operation_set_exclusive_v1;

        let malformed = [0_u8];
        let sentinel = FreAotRegexOperationSetExclusiveHandleV1(std::ptr::dangling_mut());
        let valid = FreAotRegexOperationSetPrepareConfigV1::new();
        let mut invalid = vec![
            FreAotRegexOperationSetPrepareConfigV1 {
                struct_size: OPERATION_SET_PREPARE_CONFIG_V1_SIZE - 1,
                ..valid
            },
            FreAotRegexOperationSetPrepareConfigV1 {
                config_version: OPERATION_SET_PREPARE_CONFIG_V1_VERSION + 1,
                ..valid
            },
        ];
        for reserved_index in 0..4 {
            let mut config = valid;
            config.reserved[reserved_index] = 1;
            invalid.push(config);
        }
        for config in &invalid {
            let mut handle = sentinel;
            // SAFETY: all extents are live and disjoint. The malformed wire
            // proves invalid config rejection precedes byte inspection.
            let status = unsafe {
                fre_aot_regex_runtime_prepare_operation_set_exclusive_v1(
                    malformed.as_ptr(),
                    malformed.len(),
                    config,
                    &raw mut handle,
                )
            };
            assert_eq!(status, STATUS_INVALID_ARGUMENT);
            assert_eq!(handle, sentinel);
        }
        let mut handle = sentinel;
        // SAFETY: the null config is deliberately rejected before typed
        // access; the other live extents remain disjoint.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_prepare_operation_set_exclusive_v1(
                    malformed.as_ptr(),
                    malformed.len(),
                    std::ptr::null(),
                    &raw mut handle,
                )
            },
            STATUS_INVALID_ARGUMENT
        );
        assert_eq!(handle, sentinel);
        handle = sentinel;
        // SAFETY: the null wire pointer is deliberately rejected before slice
        // construction; the config/output extents are live and disjoint.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_prepare_operation_set_exclusive_v1(
                    std::ptr::null(),
                    0,
                    &raw const valid,
                    &raw mut handle,
                )
            },
            STATUS_INVALID_ARGUMENT
        );
        assert_eq!(handle, sentinel);
        // SAFETY: the valid config reaches the readable malformed candidate;
        // the disjoint output must remain untouched on rejection.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_prepare_operation_set_exclusive_v1(
                    malformed.as_ptr(),
                    malformed.len(),
                    &raw const valid,
                    &raw mut handle,
                )
            },
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(handle, sentinel);

        let exists = program("(?:ab|ac)+z", OutputContract::Exists);
        let bytes = operation_set_bytes(&[(AotOperationAxesV1::SEARCH, exists.as_slice())]);
        let (prepared, receipt) =
            PreparedAotOperationSet::deserialize_with_config(&bytes, valid).unwrap();
        assert!(receipt.retained_handle_bytes > 0);
        drop(prepared);

        let exact = FreAotRegexOperationSetPrepareConfigV1 {
            max_handle_bytes: receipt.retained_handle_bytes,
            ..valid
        };
        let exact_handle = prepare_operation_set(&bytes, &exact);
        // SAFETY: this test exclusively owns the live handle.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_destroy_operation_set_exclusive_v1(exact_handle)
            },
            STATUS_SUCCESS
        );
        let too_small = FreAotRegexOperationSetPrepareConfigV1 {
            max_handle_bytes: receipt.retained_handle_bytes.checked_sub(1).unwrap(),
            ..valid
        };
        handle = sentinel;
        // SAFETY: all extents are live and disjoint; failure must not publish.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_prepare_operation_set_exclusive_v1(
                    bytes.as_ptr(),
                    bytes.len(),
                    &raw const too_small,
                    &raw mut handle,
                )
            },
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(handle, sentinel);

        let mut unknown_tag = bytes;
        let stage_offset = usize::try_from(u64::from_le_bytes(
            unknown_tag[72..80].try_into().unwrap(),
        ))
        .unwrap();
        let reducer_offset = stage_offset.checked_add(4).unwrap();
        let reducer_end = reducer_offset.checked_add(2).unwrap();
        unknown_tag[reducer_offset..reducer_end]
            .copy_from_slice(&u16::MAX.to_le_bytes());
        handle = sentinel;
        // SAFETY: the corrupted candidate remains a readable extent; failure
        // must leave the output untouched.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_prepare_operation_set_exclusive_v1(
                    unknown_tag.as_ptr(),
                    unknown_tag.len(),
                    &raw const valid,
                    &raw mut handle,
                )
            },
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(handle, sentinel);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "root-order semantics and caller-output transactionality share one prepared fixture"
    )]
    fn operation_set_execute_is_root_ordered_contract_bound_and_transactional() {
        let exists = program("a+", OutputContract::Exists);
        let selected = program("b+", OutputContract::SelectedEnd);
        let span = program("c+", OutputContract::Span);
        let bytes = operation_set_bytes(&[
            (AotOperationAxesV1::SEARCH, exists.as_slice()),
            (AotOperationAxesV1::SEARCH, selected.as_slice()),
            (AotOperationAxesV1::SEARCH, span.as_slice()),
            (AotOperationAxesV1::COUNT, span.as_slice()),
            (AotOperationAxesV1::SPAN_SUM, span.as_slice()),
            (AotOperationAxesV1::GREP_COUNT, exists.as_slice()),
        ]);
        let config = FreAotRegexOperationSetPrepareConfigV1::new();
        // SAFETY: the null handle discriminator is rejected before any source
        // or output pointer is dereferenced.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_execute_operation_set_exclusive_v1(
                    FreAotRegexOperationSetExclusiveHandleV1::INVALID,
                    std::ptr::null(),
                    0,
                    std::ptr::null_mut(),
                    0,
                )
            },
            STATUS_INVALID_HANDLE
        );
        // SAFETY: null is the stable invalid representation and owns nothing.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_destroy_operation_set_exclusive_v1(
                    FreAotRegexOperationSetExclusiveHandleV1::INVALID,
                )
            },
            STATUS_INVALID_HANDLE
        );
        let handle = prepare_operation_set(&bytes, &config);
        let haystack = b"aa\nbbb\ncccc\ncaa\n";
        let mut outputs = [FreAotRegexOperationSetOutputV1 {
            kind: u32::MAX,
            status: u32::MAX,
            first: u64::MAX,
            second: u64::MAX,
        }; 6];
        // SAFETY: this test exclusively owns the handle and supplies complete
        // live, aligned, disjoint source/output extents.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_execute_operation_set_exclusive_v1(
                    handle,
                    haystack.as_ptr(),
                    haystack.len(),
                    outputs.as_mut_ptr(),
                    outputs.len(),
                )
            },
            STATUS_SUCCESS
        );
        let expected = [
            FreAotRegexOperationSetOutputV1 {
                kind: OPERATION_SET_OUTPUT_SEARCH_EXISTS,
                status: STATUS_MATCH,
                first: 0,
                second: 0,
            },
            FreAotRegexOperationSetOutputV1 {
                kind: OPERATION_SET_OUTPUT_SEARCH_SELECTED_END,
                status: STATUS_MATCH,
                first: 6,
                second: 6,
            },
            FreAotRegexOperationSetOutputV1 {
                kind: OPERATION_SET_OUTPUT_SEARCH_SPAN,
                status: STATUS_MATCH,
                first: 7,
                second: 11,
            },
            FreAotRegexOperationSetOutputV1 {
                kind: OPERATION_SET_OUTPUT_COUNT,
                status: STATUS_SUCCESS,
                first: 2,
                second: 0,
            },
            FreAotRegexOperationSetOutputV1 {
                kind: OPERATION_SET_OUTPUT_SPAN_SUM,
                status: STATUS_SUCCESS,
                first: 5,
                second: 0,
            },
            FreAotRegexOperationSetOutputV1 {
                kind: OPERATION_SET_OUTPUT_GREP_COUNT,
                status: STATUS_SUCCESS,
                first: 2,
                second: 0,
            },
        ];
        assert_eq!(outputs, expected);

        let sentinel = FreAotRegexOperationSetOutputV1 {
            kind: 91,
            status: 92,
            first: 93,
            second: 94,
        };
        outputs.fill(sentinel);
        // SAFETY: every pointer is valid; the deliberately wrong count is
        // rejected without writing any caller output record.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_execute_operation_set_exclusive_v1(
                    handle,
                    haystack.as_ptr(),
                    haystack.len(),
                    outputs.as_mut_ptr(),
                    outputs.len().checked_sub(1).unwrap(),
                )
            },
            STATUS_INVALID_ARGUMENT
        );
        assert_eq!(outputs, [sentinel; 6]);
        // SAFETY: the invalid count was checked before source/workspace
        // mutation, so this test still exclusively owns a reusable live handle
        // and supplies complete disjoint extents.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_execute_operation_set_exclusive_v1(
                    handle,
                    haystack.as_ptr(),
                    haystack.len(),
                    outputs.as_mut_ptr(),
                    outputs.len(),
                )
            },
            STATUS_SUCCESS
        );
        assert_eq!(outputs, expected);
        outputs.fill(sentinel);
        // SAFETY: this test exclusively owns the live direct handle.
        let owner = unsafe { &mut *handle.0.cast::<PreparedAotOperationSet>() };
        let failing_member = owner.roots[1].member_index;
        let foreign = program("z+", OutputContract::SelectedEnd);
        let foreign_census = GenericNfaProgramCensus::from_wire(&foreign).unwrap();
        let foreign_program = CompiledProgram::deserialize(&foreign).unwrap();
        owner.members[failing_member].workspace = foreign_program
            .prepare_generic_nfa_workspace(foreign_census)
            .unwrap();
        // SAFETY: all extents are valid; the second root's deliberate binding
        // failure occurs after scratch root zero and must commit no output.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_execute_operation_set_exclusive_v1(
                    handle,
                    haystack.as_ptr(),
                    haystack.len(),
                    outputs.as_mut_ptr(),
                    outputs.len(),
                )
            },
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(outputs, [sentinel; 6]);
        // SAFETY: this test still exclusively owns the live handle.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_operation_set_exclusive_v1(handle) },
            STATUS_SUCCESS
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "whole-handle start-work and Grep byte caps need shared and unique-member boundary fixtures"
    )]
    fn operation_set_caps_are_aggregate_and_never_reused_per_member() {
        let first = program("(?:ab|ac)+z", OutputContract::Span);
        let second = program("(?:xy|xz)+q", OutputContract::Span);
        let search_bytes = operation_set_bytes(&[
            (AotOperationAxesV1::SEARCH, first.as_slice()),
            (AotOperationAxesV1::SEARCH, second.as_slice()),
        ]);
        let default_config = FreAotRegexOperationSetPrepareConfigV1::new();
        let (admitted, admitted_receipt) =
            PreparedAotOperationSet::deserialize_with_config(&search_bytes, default_config)
                .unwrap();
        let required_start = admitted_receipt
            .prospective_start_filter_work
            .expect("finite aggregate proof bound");
        assert!(required_start > 0);
        assert!(admitted_receipt.start_filter_aggregate_admitted);
        assert!(admitted_receipt.actual_start_filter_work <= required_start);
        drop(admitted);

        let declined_config = FreAotRegexOperationSetPrepareConfigV1 {
            max_start_filter_setup_work: required_start.checked_sub(1).unwrap(),
            ..default_config
        };
        let (mut declined, declined_receipt) =
            PreparedAotOperationSet::deserialize_with_config(&search_bytes, declined_config)
                .unwrap();
        assert_eq!(
            declined_receipt.prospective_start_filter_work,
            Some(required_start)
        );
        assert!(!declined_receipt.start_filter_aggregate_admitted);
        assert_eq!(declined_receipt.actual_start_filter_work, 0);
        assert!(
            admitted_receipt.prospective_handle_bytes
                > declined_receipt.prospective_handle_bytes,
            "admitted proof payload maxima must be charged before allocation"
        );
        for member in &mut declined.members {
            let settled = member
                .program
                .prepare_start_filter_with_workspace_limit(
                    &mut member.workspace,
                    u64::MAX,
                )
                .unwrap();
            assert_eq!(settled.work_completed(), 0);
        }
        drop(declined);

        let grep_member = program("a+", OutputContract::Exists);
        let shared_grep_bytes = operation_set_bytes(&[
            (AotOperationAxesV1::GREP_COUNT, grep_member.as_slice()),
            (AotOperationAxesV1::GREP_COUNT, grep_member.as_slice()),
        ]);
        let (shared, shared_receipt) = PreparedAotOperationSet::deserialize_with_config(
            &shared_grep_bytes,
            default_config,
        )
        .unwrap();
        assert_eq!(shared.members.len(), 1);
        assert_eq!(shared.roots.len(), 2);
        let shared_actual = shared.members[0]
            .grep_count_workspace
            .as_ref()
            .unwrap()
            .compiler_private_retained_heap_bytes()
            .unwrap();
        assert_eq!(
            shared_receipt.grep_count_workspace_bytes,
            u64::try_from(shared_actual).unwrap()
        );
        drop(shared);
        let shared_search_bytes = operation_set_bytes(&[
            (AotOperationAxesV1::SEARCH, grep_member.as_slice()),
            (AotOperationAxesV1::SEARCH, grep_member.as_slice()),
        ]);
        let (shared_search, shared_search_receipt) =
            PreparedAotOperationSet::deserialize_with_config(
                &shared_search_bytes,
                FreAotRegexOperationSetPrepareConfigV1 {
                    max_start_filter_setup_work: 0,
                    ..default_config
                },
            )
            .unwrap();
        assert_eq!(
            shared_receipt
                .prospective_handle_bytes
                .checked_sub(shared_search_receipt.prospective_handle_bytes)
                .unwrap(),
            shared_receipt.grep_count_workspace_bytes,
            "Grep logical stores must be charged before workspace allocation"
        );
        drop(shared_search);

        let other_grep_member = program("b+", OutputContract::Exists);
        let unique_grep_bytes = operation_set_bytes(&[
            (AotOperationAxesV1::GREP_COUNT, grep_member.as_slice()),
            (AotOperationAxesV1::GREP_COUNT, other_grep_member.as_slice()),
        ]);
        let (unique, unique_receipt) = PreparedAotOperationSet::deserialize_with_config(
            &unique_grep_bytes,
            default_config,
        )
        .unwrap();
        let required_grep = unique_receipt.grep_count_workspace_bytes;
        assert!(required_grep > shared_receipt.grep_count_workspace_bytes);
        drop(unique);

        let exact = FreAotRegexOperationSetPrepareConfigV1 {
            max_grep_count_workspace_bytes: required_grep,
            ..default_config
        };
        let exact_handle = prepare_operation_set(&unique_grep_bytes, &exact);
        // SAFETY: this test exclusively owns the live handle.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_destroy_operation_set_exclusive_v1(exact_handle)
            },
            STATUS_SUCCESS
        );
        let too_small = FreAotRegexOperationSetPrepareConfigV1 {
            max_grep_count_workspace_bytes: required_grep.checked_sub(1).unwrap(),
            ..default_config
        };
        let sentinel = FreAotRegexOperationSetExclusiveHandleV1(std::ptr::dangling_mut());
        let mut handle = sentinel;
        // SAFETY: all extents are valid and disjoint; aggregate cap refusal
        // must not publish a partial owner.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_prepare_operation_set_exclusive_v1(
                    unique_grep_bytes.as_ptr(),
                    unique_grep_bytes.len(),
                    &raw const too_small,
                    &raw mut handle,
                )
            },
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(handle, sentinel);
    }

    fn prepared(pattern: &str, output: OutputContract, mode: CompileMode) -> PreparedAotRegex {
        let compiled = compile(
            CompileRequest::new(pattern, Target::x86_64_linux())
                .mode(mode)
                .output(output),
        )
        .unwrap_or_else(|error| panic!("compile {mode:?} {pattern:?}: {error}"));
        let bytes = compiled.program().serialize().expect("serialize program");
        PreparedAotRegex::deserialize(&bytes).expect("prepare program")
    }

    #[test]
    fn prepared_header_reports_actual_overlay_generation() {
        let overlay = prepared(
            r"A(?-u:[^Z])*Z|[b-c][a-b]{1,5}(?:x+|y+)",
            OutputContract::SelectedEnd,
            CompileMode::Fast,
        );
        assert_eq!(
            overlay
                .frozen_header
                .compiler_private_dynamic_rows_format_version(),
            Some(fre_aot_regex::FROZEN_DYNAMIC_ROWS_V7_FORMAT_VERSION)
        );
        assert!(overlay.frozen_static_continuation_rows.is_some());
        assert!(overlay.static_continuation_header.has_dynamic_rows());
        assert!(matches!(
            overlay
                .static_continuation_header
                .compiler_private_dynamic_rows_format_version(),
            Some(FROZEN_DYNAMIC_ROWS_V13_FORMAT_VERSION | FROZEN_DYNAMIC_ROWS_V14_FORMAT_VERSION)
        ));

        let plain = prepared(
            r"(?-u:(?:a|[^a][\x00-\xff]){4})",
            OutputContract::SelectedEnd,
            CompileMode::Fast,
        );
        assert_eq!(
            plain
                .frozen_header
                .compiler_private_dynamic_rows_format_version(),
            Some(FROZEN_DYNAMIC_ROWS_V14_FORMAT_VERSION)
        );
        assert!(plain.frozen_static_continuation_rows.is_some());
        assert_eq!(
            plain
                .static_continuation_header
                .compiler_private_dynamic_rows_format_version(),
            Some(FROZEN_DYNAMIC_ROWS_V14_FORMAT_VERSION)
        );

        let unary = prepared(
            r"(?s-u:.{3,})",
            OutputContract::Exists,
            CompileMode::Fast,
        );
        assert_eq!(
            unary
                .frozen_header
                .compiler_private_dynamic_rows_format_version(),
            Some(fre_aot_regex::FROZEN_DYNAMIC_ROWS_V5_FORMAT_VERSION)
        );
        assert!(unary.frozen_static_continuation_rows.is_some());
        assert_eq!(
            unary
                .static_continuation_header
                .compiler_private_dynamic_rows_format_version(),
            Some(FROZEN_DYNAMIC_ROWS_V4_FORMAT_VERSION)
        );

        let mapped = prepared(
            r"(?s-u:.{3,})",
            OutputContract::SelectedEnd,
            CompileMode::Fast,
        );
        assert!(mapped.frozen_static_continuation_rows.is_some());
        assert_eq!(
            mapped
                .static_continuation_header
                .compiler_private_dynamic_rows_format_version(),
            Some(FROZEN_DYNAMIC_ROWS_V12_FORMAT_VERSION),
            "closed mapped-u8 rows must remain available to an arbitrary-state continuation"
        );
    }

    fn collected_spans(prepared: &mut PreparedAotRegex, haystack: &[u8]) -> Vec<(usize, usize)> {
        prepared
            .find_iter(haystack)
            .expect("Span iterator")
            .map(|matched| {
                let matched = matched.expect("successful iterator search");
                (matched.start(), matched.end())
            })
            .collect()
    }

    fn call(
        program: &[u8],
        haystack: &[u8],
        start: usize,
        end: usize,
        result: &mut FreAotRegexResultV1,
    ) -> u32 {
        // SAFETY: all slices and the result outlive this synchronous call and
        // are disjoint; the program was produced by the compiler.
        unsafe {
            fre_aot_regex_runtime_search_v1(
                program.as_ptr(),
                haystack.as_ptr(),
                haystack.len(),
                start,
                end,
                result,
            )
        }
    }

    fn call_without_endpoint_oracle(
        program: &[u8],
        haystack: &[u8],
        start: usize,
        end: usize,
        result: &mut FreAotRegexResultV1,
    ) -> u32 {
        // SAFETY: all slices and the result outlive this synchronous call and
        // are disjoint; the program was produced by the compiler.
        unsafe {
            fre_aot_regex_runtime_search_without_endpoint_oracle_v1(
                program.as_ptr(),
                haystack.as_ptr(),
                haystack.len(),
                start,
                end,
                result,
            )
        }
    }

    fn prepare_handle(program: &[u8]) -> FreAotRegexPreparedHandleV1 {
        let mut handle = FreAotRegexPreparedHandleV1::INVALID;
        // SAFETY: the complete compiler-produced slice is readable for the
        // call and the disjoint aligned output remains live.
        let status = unsafe {
            fre_aot_regex_runtime_prepare_v1(program.as_ptr(), program.len(), &raw mut handle)
        };
        assert_eq!(status, STATUS_SUCCESS);
        assert!(!handle.is_invalid());
        handle
    }

    fn call_prepared(
        handle: FreAotRegexPreparedHandleV1,
        haystack: &[u8],
        start: usize,
        end: usize,
        result: &mut FreAotRegexResultV1,
    ) -> u32 {
        // SAFETY: the readable haystack and disjoint aligned result outlive
        // this synchronous call.
        unsafe {
            fre_aot_regex_runtime_search_prepared_v1(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                start,
                end,
                result,
            )
        }
    }

    fn prepare_exclusive(program: &[u8]) -> FreAotRegexExclusiveHandleV1 {
        let mut handle = FreAotRegexExclusiveHandleV1::INVALID;
        // SAFETY: the complete compiler-produced slice is readable for the
        // call and the disjoint aligned output remains live. This helper owns
        // the returned session until its explicit destroy below.
        let status = unsafe {
            fre_aot_regex_runtime_prepare_exclusive_v1(
                program.as_ptr(),
                program.len(),
                &raw mut handle,
            )
        };
        assert_eq!(status, STATUS_SUCCESS);
        assert!(!handle.is_invalid());
        handle
    }

    fn prepare_exclusive_v2(
        program: &[u8],
        config: &FreAotRegexPrepareConfigV2,
    ) -> FreAotRegexExclusiveHandleV1 {
        let mut handle = FreAotRegexExclusiveHandleV1::INVALID;
        // SAFETY: the compiler-produced program and initialized config are
        // readable; the disjoint aligned output remains live for the call.
        let status = unsafe {
            fre_aot_regex_runtime_prepare_exclusive_v2(
                program.as_ptr(),
                program.len(),
                config,
                &raw mut handle,
            )
        };
        assert_eq!(status, STATUS_SUCCESS);
        assert!(!handle.is_invalid());
        handle
    }

    fn prepare_exclusive_with_cold_dynamic_rows(program: &[u8]) -> FreAotRegexExclusiveHandleV1 {
        let program = CompiledProgram::deserialize(program).expect("deserialize test program");
        let mut workspace = program.prepare_workspace().expect("prepare test workspace");
        let fully_prefilled_fallback = program
            .compiler_private_try_prefill_retained_fallback_with_workspace_receipt(&mut workspace)
            .expect("prefill cold dynamic-row test owner");
        let frozen_dynamic_rows = program
            .compiler_private_frozen_dynamic_rows_storage_v3_with_fallback_receipt(
                &mut workspace,
                fully_prefilled_fallback,
                0,
                0,
            );
        assert!(frozen_dynamic_rows.is_none());
        assert!(fully_prefilled_fallback.is_none());
        let frozen_header = program.compiler_private_frozen_prepared_header_v6(
            &workspace,
            fully_prefilled_fallback,
            frozen_dynamic_rows.as_ref(),
        );
        assert!(!frozen_header.is_active());
        let static_continuation_header =
            program.compiler_private_frozen_prepared_header_v6(&workspace, None, None);
        assert!(!static_continuation_header.is_active());
        let prepared = PreparedAotRegex {
            frozen_header,
            static_continuation_header,
            static_prefix_invocation_epoch: 1,
            program,
            workspace,
            frozen_ordered_nfa_scratch: None,
            frozen_dynamic_rows,
            frozen_static_continuation_rows: None,
            frozen_header_owner_generation_key: None,
            static_continuation_owner_generation_key: None,
            fully_prefilled_fallback,
            static_prefix_object_ticket: None,
            static_prefix_span_postflight_ticket: None,
            grep_count_workspace: None,
            max_grep_count_workspace_bytes:
                fre_aot_regex::DEFAULT_GREP_COUNT_MAX_WORKSPACE_BYTES,
            static_prefix_dense_selections: 0,
            static_prefix_legacy_projection_attempts: 0,
            retained_partial_frozen_owner_handoffs: 0,
            fully_prefilled_fallback_searches: 0,
        };
        FreAotRegexExclusiveHandleV1(
            Box::into_raw(Box::new(prepared)).cast::<std::ffi::c_void>(),
        )
    }

    fn call_exclusive(
        handle: FreAotRegexExclusiveHandleV1,
        haystack: &[u8],
        start: usize,
        end: usize,
        result: &mut FreAotRegexResultV1,
    ) -> u32 {
        // SAFETY: each test keeps exclusive ownership of the live session;
        // the readable haystack and disjoint aligned result outlive the call.
        unsafe {
            fre_aot_regex_runtime_search_exclusive_v1(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                start,
                end,
                result,
            )
        }
    }

    fn call_exclusive_frozen_fallback(
        handle: FreAotRegexExclusiveHandleV1,
        haystack: &[u8],
        start: usize,
        end: usize,
        result: &mut FreAotRegexResultV1,
        expected_artifact_identity: &[u8; ARTIFACT_IDENTITY_BYTES],
    ) -> u32 {
        // SAFETY: each test owns the live exclusive session and supplies
        // readable haystack/identity plus disjoint aligned writable output.
        unsafe {
            fre_aot_regex_runtime_search_exclusive_frozen_fallback_v1(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                start,
                end,
                result,
                expected_artifact_identity.as_ptr(),
            )
        }
    }

    fn call_exclusive_static_prefix_preflight(
        handle: FreAotRegexExclusiveHandleV1,
        haystack: &[u8],
        start: usize,
        end: usize,
        result: &mut FreAotRegexResultV1,
        expected_artifact_identity: &[u8; ARTIFACT_IDENTITY_BYTES],
    ) -> u32 {
        // SAFETY: each test owns the live exclusive session and supplies
        // readable haystack/identity plus disjoint aligned writable output.
        unsafe {
            fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_preflight_v1(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                start,
                end,
                result,
                expected_artifact_identity.as_ptr(),
            )
        }
    }

    fn call_exclusive_static_prefix_preflight_v2(
        handle: FreAotRegexExclusiveHandleV1,
        haystack: &[u8],
        start: usize,
        end: usize,
        result: &mut FreAotRegexResultV1,
        expected_artifact_identity: &[u8; ARTIFACT_IDENTITY_BYTES],
        descriptor: &[u32],
    ) -> u32 {
        // SAFETY: each test owns the live exclusive session and supplies
        // readable haystack, identity, descriptor, and disjoint output.
        unsafe {
            fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_preflight_v2(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                start,
                end,
                result,
                expected_artifact_identity.as_ptr(),
                descriptor.as_ptr(),
            )
        }
    }

    fn call_exclusive_static_prefix_preflight_v3(
        handle: FreAotRegexExclusiveHandleV1,
        haystack: &[u8],
        start: usize,
        end: usize,
        result: &mut FreAotRegexResultV1,
        expected_artifact_identity: &[u8; ARTIFACT_IDENTITY_BYTES],
        descriptor: &[u32],
    ) -> u32 {
        // SAFETY: each test owns the live exclusive session and supplies
        // readable haystack, identity, packed descriptor, and disjoint output.
        unsafe {
            fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_preflight_v3(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                start,
                end,
                result,
                expected_artifact_identity.as_ptr(),
                descriptor.as_ptr(),
            )
        }
    }

    fn call_exclusive_static_prefix_continue_v3(
        handle: FreAotRegexExclusiveHandleV1,
        haystack: &[u8],
        result: &mut FreAotRegexResultV1,
        resume_state: usize,
        resume_position: usize,
        pending_end: usize,
    ) -> u32 {
        // SAFETY: each test owns the live exclusive session and supplies the
        // exact compact frontier for the immediately preceding admission.
        unsafe {
            fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_continue_v3(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                result,
                resume_state,
                resume_position,
                pending_end,
            )
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the test wrapper names every fused object and frontier argument"
    )]
    fn call_exclusive_static_prefix_continue_v2(
        handle: FreAotRegexExclusiveHandleV1,
        haystack: &[u8],
        start: usize,
        end: usize,
        result: &mut FreAotRegexResultV1,
        expected_artifact_identity: &[u8; ARTIFACT_IDENTITY_BYTES],
        descriptor: &[u32],
        resume_state: usize,
        resume_position: usize,
        pending_end: usize,
    ) -> u32 {
        // SAFETY: each test owns the live exclusive session and supplies one
        // synchronous compiler-private object transaction with readable,
        // disjoint extents.
        unsafe {
            fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_continue_v2(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                start,
                end,
                result,
                expected_artifact_identity.as_ptr(),
                descriptor.as_ptr(),
                resume_state,
                resume_position,
                pending_end,
            )
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the test wrapper names every packed fused object and frontier argument"
    )]
    fn call_exclusive_static_prefix_continue_v4(
        handle: FreAotRegexExclusiveHandleV1,
        haystack: &[u8],
        start: usize,
        end: usize,
        result: &mut FreAotRegexResultV1,
        expected_artifact_identity: &[u8; ARTIFACT_IDENTITY_BYTES],
        descriptor: &[u32],
        resume_state: usize,
        resume_position: usize,
        pending_end: usize,
    ) -> u32 {
        // SAFETY: each test owns the live exclusive session and supplies one
        // synchronous packed compiler-private object transaction with
        // readable, disjoint extents.
        unsafe {
            fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_continue_v4(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                start,
                end,
                result,
                expected_artifact_identity.as_ptr(),
                descriptor.as_ptr(),
                resume_state,
                resume_position,
                pending_end,
            )
        }
    }

    fn one_state_static_prefix_descriptor(item: u32, pending: bool) -> Vec<u32> {
        const HEADER_WORDS: usize = STATIC_PREFIX_RESUME_DESCRIPTOR_V1_HEADER_BYTES / 4;
        let total_words = HEADER_WORDS + STATIC_PREFIX_RESUME_DESCRIPTOR_V1_STATE_BYTES / 4 + 1;
        let mut descriptor = vec![
            u32::from_le_bytes(
                STATIC_PREFIX_RESUME_DESCRIPTOR_V1_MAGIC[..4]
                    .try_into()
                    .unwrap(),
            ),
            u32::from_le_bytes(
                STATIC_PREFIX_RESUME_DESCRIPTOR_V1_MAGIC[4..]
                    .try_into()
                    .unwrap(),
            ),
            u32::try_from(total_words).unwrap(),
            1,
            1,
            0,
            0,
            0,
            0,
            1,
            u32::from(pending),
            0,
            item,
        ];
        assert_eq!(descriptor.len(), total_words);
        descriptor.shrink_to_fit();
        descriptor
    }

    fn one_state_packed_static_prefix_descriptor(item: u32, pending: bool) -> Vec<u32> {
        const HEADER_WORDS: usize = STATIC_PREFIX_RESUME_DESCRIPTOR_V2_HEADER_BYTES / 4;
        let item_width = if item <= u32::from(u8::MAX) {
            1_usize
        } else if item <= u32::from(u16::MAX) {
            2
        } else {
            4
        };
        let total_words = HEADER_WORDS + 1 + 1;
        let mut bytes = Vec::with_capacity(total_words * 4);
        bytes.extend_from_slice(STATIC_PREFIX_RESUME_DESCRIPTOR_V2_MAGIC);
        for word in [
            u32::try_from(total_words).unwrap(),
            1,
            1,
            u32::try_from(item_width).unwrap(),
            0,
            0,
            1 | if pending { 1_u32 << 31 } else { 0 },
        ] {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        bytes.extend_from_slice(&item.to_le_bytes()[..item_width]);
        bytes.resize(total_words * 4, 0);
        bytes
            .chunks_exact(4)
            .map(|word| u32::from_le_bytes(word.try_into().unwrap()))
            .collect()
    }

    fn call_exclusive_static_prefix_recover_span(
        handle: FreAotRegexExclusiveHandleV1,
        haystack: &[u8],
        start: usize,
        end: usize,
        result: &mut FreAotRegexResultV1,
        expected_artifact_identity: &[u8; ARTIFACT_IDENTITY_BYTES],
        selected_end: usize,
    ) -> u32 {
        // SAFETY: each test owns the live exclusive session and supplies the
        // synchronous endpoint plus readable/disjoint pointer extents.
        unsafe {
            fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_recover_span_v1(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                start,
                end,
                result,
                expected_artifact_identity.as_ptr(),
                selected_end,
            )
        }
    }

    fn call_exclusive_static_prefix_recover_span_v2(
        handle: FreAotRegexExclusiveHandleV1,
        haystack: &[u8],
        start: usize,
        end: usize,
        result: &mut FreAotRegexResultV1,
        expected_artifact_identity: &[u8; ARTIFACT_IDENTITY_BYTES],
        selected_end: usize,
    ) -> u32 {
        // SAFETY: each test owns the live exclusive session and supplies the
        // synchronous endpoint plus readable/disjoint pointer extents.
        unsafe {
            fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_recover_span_v2(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                start,
                end,
                result,
                expected_artifact_identity.as_ptr(),
                selected_end,
            )
        }
    }

    fn call_exclusive_static_prefix_recover_span_v3(
        handle: FreAotRegexExclusiveHandleV1,
        haystack: &[u8],
        start: usize,
        end: usize,
        result: &mut FreAotRegexResultV1,
        expected_artifact_identity: &[u8; ARTIFACT_IDENTITY_BYTES],
        selected_end: usize,
        invocation_epoch: u64,
    ) -> u32 {
        // SAFETY: each test owns the live exclusive session and supplies the
        // exact generated epoch plus readable/disjoint pointer extents.
        unsafe {
            fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_recover_span_v3(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                start,
                end,
                result,
                expected_artifact_identity.as_ptr(),
                selected_end,
                invocation_epoch,
            )
        }
    }

    fn publish_static_prefix_span_postflight_for_test(
        handle: FreAotRegexExclusiveHandleV1,
        haystack: &[u8],
    ) {
        assert!(haystack.len() > 1);
        // Exercise the production capability transition. Some lifecycle
        // callers intentionally arrive with a malformed outer object ticket;
        // retire it, admit a real one-state descriptor, and synchronously run
        // the actual continuation through projection consumption. Only that
        // path may mint `StaticPrefixSpanRecoveryAdmission`.
        // SAFETY: tests call this only with unique access to a live allocation,
        // and the local descriptor remains live through the continuation.
        let prepared = unsafe { &mut *handle.0.cast::<PreparedAotRegex>() };
        let _ = prepared.retire_static_prefix_capabilities();
        assert_eq!(prepared.program.output_contract(), OutputContract::Span);
        assert!(prepared.program.exact_match_width().is_none());
        let descriptor = one_state_static_prefix_descriptor(0, false);
        let artifact_identity = *prepared.frozen_header.artifact_identity();
        prepared
            .admit_static_prefix_object(
                haystack,
                SearchWindow::full(haystack),
                artifact_identity,
                STATIC_PREFIX_RESUME_DESCRIPTOR_V1_VERSION,
                descriptor.as_ptr().expose_provenance(),
            )
            .expect("admit genuine continuation descriptor");
        let ticket = prepared
            .consume_static_prefix_object(haystack)
            .expect("consume genuine continuation descriptor");
        let resume_position = (haystack.len() / 2).clamp(1, haystack.len() - 1);
        let outcome = unsafe {
            prepared.continue_static_prefix_object(
                haystack,
                ticket,
                0,
                resume_position,
                0,
            )
        }
        .expect("continue genuine variable-Span projection");
        assert!(matches!(
            outcome,
            StaticPrefixContinuationOutcome::Native {
                status: STATUS_STATIC_PREFIX_NATIVE_RESUME
                    | STATUS_STATIC_PREFIX_NATIVE_CONTINUATION_RESUME,
                ..
            }
        ));
        assert!(prepared.static_prefix_object_ticket.is_none());
        assert!(prepared.static_prefix_span_postflight_ticket.is_some());
    }

    fn static_prefix_capability_presence(
        handle: FreAotRegexExclusiveHandleV1,
    ) -> (bool, bool) {
        // SAFETY: lifecycle tests call this only while they uniquely own the
        // live allocation and no search or destruction overlaps the read.
        let prepared = unsafe { &*handle.0.cast::<PreparedAotRegex>() };
        (
            prepared.static_prefix_object_ticket.is_some(),
            prepared.static_prefix_span_postflight_ticket.is_some(),
        )
    }

    fn admit_static_prefix_span_postflight_for_test(
        handle: FreAotRegexExclusiveHandleV1,
        haystack: &[u8],
        result: &mut FreAotRegexResultV1,
        expected_artifact_identity: &[u8; ARTIFACT_IDENTITY_BYTES],
        descriptor: &[u32],
    ) {
        assert_eq!(
            call_exclusive_static_prefix_preflight_v2(
                handle,
                haystack,
                0,
                haystack.len(),
                result,
                expected_artifact_identity,
                descriptor,
            ),
            STATUS_PARTIAL_PREFLIGHT_ENTER
        );
        assert_eq!(static_prefix_capability_presence(handle), (true, false));
        publish_static_prefix_span_postflight_for_test(handle, haystack);
        assert_eq!(static_prefix_capability_presence(handle), (false, true));
    }

    fn exclusive_frozen_header_is_active(handle: FreAotRegexExclusiveHandleV1) -> bool {
        assert!(!handle.is_invalid());
        // SAFETY: lifecycle tests call this only while they uniquely own the
        // live allocation and no search or destruction overlaps the read.
        unsafe {
            (&*handle.0.cast::<PreparedAotRegex>())
                .frozen_header
                .is_active()
        }
    }

    fn exclusive_frozen_header_identity(
        handle: FreAotRegexExclusiveHandleV1,
    ) -> [u8; ARTIFACT_IDENTITY_BYTES] {
        assert!(!handle.is_invalid());
        // SAFETY: identical unique-live-handle reasoning to the active-seal
        // helper immediately above.
        unsafe {
            *(&*handle.0.cast::<PreparedAotRegex>())
                .frozen_header
                .artifact_identity()
        }
    }

    fn call_exclusive_dynamic_rows_deopt(
        handle: FreAotRegexExclusiveHandleV1,
        haystack: &[u8],
        start: usize,
        end: usize,
        result: &mut FreAotRegexResultV1,
    ) -> u32 {
        // SAFETY: each test keeps exclusive ownership of the live admitted
        // transaction; the readable haystack and disjoint aligned result
        // outlive this synchronous side-exit continuation.
        unsafe {
            fre_aot_regex_runtime_search_exclusive_dynamic_rows_deopt_v1(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                start,
                end,
                result,
            )
        }
    }

    fn call_partial_should_enter(
        handle: FreAotRegexExclusiveHandleV1,
        input_bytes: usize,
    ) -> u32 {
        // SAFETY: each test keeps exclusive ownership of the live session and
        // does not overlap admission with search or destruction.
        unsafe {
            fre_aot_regex_runtime_prepared_partial_should_enter_v1(handle, input_bytes)
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the test helper mirrors the explicit authenticated continuation ABI"
    )]
    fn call_exclusive_from_partial(
        handle: FreAotRegexExclusiveHandleV1,
        haystack: &[u8],
        start: usize,
        end: usize,
        result: &mut FreAotRegexResultV1,
        expected_artifact_identity: &[u8; ARTIFACT_IDENTITY_BYTES],
        resume_state: usize,
        resume_position: usize,
        pending_end: Option<usize>,
    ) -> u32 {
        // SAFETY: each test keeps exclusive ownership of the live session;
        // the compiler-produced identity, readable haystack, and disjoint
        // aligned result all outlive the synchronous call.
        unsafe {
            fre_aot_regex_runtime_search_exclusive_from_partial_v1(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                start,
                end,
                result,
                expected_artifact_identity.as_ptr(),
                resume_state,
                resume_position,
                u32::from(pending_end.is_some()),
                pending_end.unwrap_or(0),
            )
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the test helper mirrors the authenticated exact-window preflight ABI"
    )]
    fn call_exclusive_partial_preflight(
        handle: FreAotRegexExclusiveHandleV1,
        haystack: &[u8],
        start: usize,
        end: usize,
        result: &mut FreAotRegexResultV1,
        expected_artifact_identity: &[u8; ARTIFACT_IDENTITY_BYTES],
        window: &mut FreAotRegexSearchWindowV1,
    ) -> u32 {
        // SAFETY: each test keeps exclusive ownership of the live session;
        // all readable and disjoint aligned writable extents outlive the call.
        unsafe {
            fre_aot_regex_runtime_search_exclusive_partial_preflight_v1(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                start,
                end,
                result,
                expected_artifact_identity.as_ptr(),
                window,
            )
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the helper mirrors the private generation-bearing dynamic-row preflight"
    )]
    fn call_exclusive_dynamic_rows_preflight(
        handle: FreAotRegexExclusiveHandleV1,
        haystack: &[u8],
        start: usize,
        end: usize,
        result: &mut FreAotRegexResultV1,
        expected_artifact_identity: &[u8; ARTIFACT_IDENTITY_BYTES],
        output: &mut FreAotRegexDynamicRowsPreflightV1,
    ) -> u32 {
        // SAFETY: the test owns the exclusive session and all readable and
        // disjoint writable extents outlive the synchronous call.
        unsafe {
            fre_aot_regex_runtime_search_exclusive_dynamic_rows_preflight_v1(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                start,
                end,
                result,
                expected_artifact_identity.as_ptr(),
                output,
            )
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the helper mirrors the generated-only dynamic-row preflight ABI"
    )]
    fn call_exclusive_compiler_private_dynamic_rows_preflight_v2(
        handle: FreAotRegexExclusiveHandleV1,
        haystack: &[u8],
        start: usize,
        end: usize,
        result: &mut FreAotRegexResultV1,
        expected_artifact_identity: &[u8; ARTIFACT_IDENTITY_BYTES],
        output: &mut FreAotRegexDynamicRowsPreflightV1,
    ) -> u32 {
        // SAFETY: this test helper supplies the exact live, validated,
        // disjoint inputs established by FRE's generated wrapper.
        unsafe {
            fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v2(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                start,
                end,
                result,
                expected_artifact_identity.as_ptr(),
                output,
            )
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the helper mirrors the generated-only trusted V3 dynamic-row preflight ABI"
    )]
    fn call_exclusive_compiler_private_dynamic_rows_preflight_v3(
        handle: FreAotRegexExclusiveHandleV1,
        haystack: &[u8],
        start: usize,
        end: usize,
        result: &mut FreAotRegexResultV1,
        expected_artifact_identity: &[u8; ARTIFACT_IDENTITY_BYTES],
        output: &mut FreAotRegexDynamicRowsPreflightV1,
    ) -> u32 {
        // SAFETY: this test helper supplies the exact live prepared program,
        // validated window, and disjoint storage required by the V3 contract.
        unsafe {
            fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v3(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                start,
                end,
                result,
                expected_artifact_identity.as_ptr(),
                output,
            )
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the helper mirrors the generated-only V4 dynamic-row preflight ABI"
    )]
    fn call_exclusive_compiler_private_dynamic_rows_preflight_v4(
        handle: FreAotRegexExclusiveHandleV1,
        haystack: &[u8],
        start: usize,
        end: usize,
        result: &mut FreAotRegexResultV1,
        expected_artifact_identity: &[u8; ARTIFACT_IDENTITY_BYTES],
        output: &mut FreAotRegexDynamicRowsPreflightV1,
    ) -> u32 {
        // SAFETY: this test helper supplies the exact live, validated,
        // disjoint inputs established by FRE's generated V4 wrapper.
        unsafe {
            fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v4(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                start,
                end,
                result,
                expected_artifact_identity.as_ptr(),
                output,
            )
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the helper mirrors the generated-only V5 dynamic-row preflight ABI"
    )]
    fn call_exclusive_compiler_private_dynamic_rows_preflight_v5(
        handle: FreAotRegexExclusiveHandleV1,
        haystack: &[u8],
        start: usize,
        end: usize,
        result: &mut FreAotRegexResultV1,
        expected_artifact_identity: &[u8; ARTIFACT_IDENTITY_BYTES],
        output: &mut FreAotRegexDynamicRowsPreflightV1,
    ) -> u32 {
        // SAFETY: this test helper supplies the combined V3 invariant and V4
        // output contracts established by FRE's generated V5 wrapper.
        unsafe {
            fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v5(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                start,
                end,
                result,
                expected_artifact_identity.as_ptr(),
                output,
            )
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the helper mirrors the generated-only V6 return-register dynamic-row preflight ABI"
    )]
    fn call_exclusive_compiler_private_dynamic_rows_preflight_v6(
        handle: FreAotRegexExclusiveHandleV1,
        haystack: &[u8],
        start: usize,
        end: usize,
        result: &mut FreAotRegexResultV1,
        expected_artifact_identity: &[u8; ARTIFACT_IDENTITY_BYTES],
        output: &mut FreAotRegexDynamicRowsPreflightV1,
    ) -> FreAotRegexDynamicRowsPreflightResultV6 {
        // SAFETY: this test helper supplies the exact live, validated,
        // disjoint inputs established by FRE's generated V6 wrapper. The
        // larger sentinel record lets the test prove that V6 writes only its
        // two-word window prefix.
        unsafe {
            fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v6(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                start,
                end,
                result,
                expected_artifact_identity.as_ptr(),
                std::ptr::from_mut(output).cast::<FreAotRegexSearchWindowV1>(),
            )
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the helper mirrors the compiler-private authenticated first-hole continuation"
    )]
    fn call_exclusive_dynamic_rows_continue(
        handle: FreAotRegexExclusiveHandleV1,
        haystack: &[u8],
        start: usize,
        end: usize,
        result: &mut FreAotRegexResultV1,
        expected_artifact_identity: &[u8; ARTIFACT_IDENTITY_BYTES],
        continuation: &FreAotRegexDynamicRowsContinuationV1,
    ) -> u32 {
        // SAFETY: the test owns the immediately preceding exclusive
        // admission and every readable/disjoint writable extent remains live
        // through the synchronous compiler-private call.
        unsafe {
            fre_aot_regex_runtime_search_exclusive_dynamic_rows_continue_v1(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                start,
                end,
                result,
                expected_artifact_identity.as_ptr(),
                continuation,
            )
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the helper mirrors the repeated compiler-private cell resolver"
    )]
    fn call_exclusive_dynamic_rows_resolve_cell(
        handle: FreAotRegexExclusiveHandleV1,
        haystack: &[u8],
        start: usize,
        end: usize,
        result: &mut FreAotRegexResultV1,
        expected_artifact_identity: &[u8; ARTIFACT_IDENTITY_BYTES],
        continuation: &FreAotRegexDynamicRowsContinuationV1,
    ) -> u32 {
        // SAFETY: the test owns the immediately preceding exclusive
        // admission and keeps every pointer live and disjoint for the call.
        unsafe {
            fre_aot_regex_runtime_search_exclusive_dynamic_rows_continue_v2(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                start,
                end,
                result,
                expected_artifact_identity.as_ptr(),
                continuation,
            )
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the test helper mirrors the authenticated dynamic Span postflight ABI"
    )]
    fn call_exclusive_recover_dynamic_span(
        handle: FreAotRegexExclusiveHandleV1,
        haystack: &[u8],
        start: usize,
        end: usize,
        result: &mut FreAotRegexResultV1,
        expected_artifact_identity: &[u8; ARTIFACT_IDENTITY_BYTES],
        selected_end: usize,
    ) -> u32 {
        // SAFETY: each test keeps exclusive ownership of the live session;
        // either its active immutable owner or its immediately preceding
        // admission authenticates the synchronous compiler-private
        // postflight. Readable inputs and disjoint aligned output outlive it.
        unsafe {
            fre_aot_regex_runtime_search_exclusive_dynamic_rows_recover_span_v1(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                start,
                end,
                result,
                expected_artifact_identity.as_ptr(),
                selected_end,
            )
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the test helper mirrors the authenticated exact-window Span postflight ABI"
    )]
    fn call_exclusive_recover_partial_span(
        handle: FreAotRegexExclusiveHandleV1,
        haystack: &[u8],
        start: usize,
        end: usize,
        result: &mut FreAotRegexResultV1,
        expected_artifact_identity: &[u8; ARTIFACT_IDENTITY_BYTES],
        selected_end: usize,
    ) -> u32 {
        // SAFETY: each test keeps exclusive ownership of the live session;
        // all readable and disjoint aligned writable extents outlive the call.
        unsafe {
            fre_aot_regex_runtime_search_exclusive_recover_partial_span_v1(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                start,
                end,
                result,
                expected_artifact_identity.as_ptr(),
                selected_end,
            )
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the test helper mirrors the authenticated native-root preflight ABI"
    )]
    fn call_exclusive_partial_native_root_preflight(
        handle: FreAotRegexExclusiveHandleV1,
        haystack: &[u8],
        start: usize,
        end: usize,
        result: &mut FreAotRegexResultV1,
        expected_artifact_identity: &[u8; ARTIFACT_IDENTITY_BYTES],
        window: &mut FreAotRegexSearchWindowV1,
    ) -> u32 {
        // SAFETY: each test keeps exclusive ownership of the live session;
        // all readable and disjoint aligned writable extents outlive the call.
        unsafe {
            fre_aot_regex_runtime_search_exclusive_partial_native_root_preflight_v1(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                start,
                end,
                result,
                expected_artifact_identity.as_ptr(),
                window,
            )
        }
    }

    fn call_exclusive_from_partial_preflight_compact_v3(
        handle: FreAotRegexExclusiveHandleV1,
        haystack: &[u8],
        result: &mut FreAotRegexResultV1,
        resume_state: usize,
        resume_position: usize,
        pending_end: usize,
    ) -> u32 {
        // SAFETY: each test owns the exact native-root transaction and keeps
        // all readable/disjoint writable extents live through the call.
        unsafe {
            fre_aot_regex_runtime_search_exclusive_from_partial_preflight_compact_v3(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                result,
                resume_state,
                resume_position,
                pending_end,
            )
        }
    }

    fn expected_ffi(result: MatchResult) -> (u32, FreAotRegexResultV1) {
        match result {
            MatchResult::Exists(false)
            | MatchResult::SelectedEnd(None)
            | MatchResult::Span(None) => (STATUS_NO_MATCH, FreAotRegexResultV1::default()),
            MatchResult::Exists(true) => (STATUS_MATCH, FreAotRegexResultV1::default()),
            MatchResult::SelectedEnd(Some(end)) => {
                (STATUS_MATCH, FreAotRegexResultV1 { start: end, end })
            }
            MatchResult::Span(Some((start, end))) => {
                (STATUS_MATCH, FreAotRegexResultV1 { start, end })
            }
        }
    }

    fn generated_haystacks() -> Vec<Vec<u8>> {
        let alphabet = [b'a', b'b', b'x', b'\n'];
        let mut haystacks = vec![Vec::new()];
        let mut frontier = vec![Vec::new()];
        for _ in 0..4 {
            let mut next = Vec::new();
            for prefix in &frontier {
                for &byte in &alphabet {
                    let mut haystack = prefix.clone();
                    haystack.push(byte);
                    haystacks.push(haystack.clone());
                    next.push(haystack);
                }
            }
            frontier = next;
        }
        haystacks.extend([b"abz".to_vec(), b"xxabacadz".to_vec(), b"x\nab\n".to_vec()]);
        haystacks
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the ABI audit keeps every public and compiler-private function type in one ledger"
    )]
    fn c_abi_layout_declarations_and_function_types_are_stable() {
        assert_eq!(std::mem::offset_of!(PreparedAotRegex, frozen_header), 0);
        assert_eq!(
            std::mem::offset_of!(PreparedAotRegex, static_continuation_header),
            FROZEN_PREPARED_HEADER_V6_BYTES
        );
        assert_eq!(
            std::mem::offset_of!(PreparedAotRegex, static_prefix_invocation_epoch),
            STATIC_PREFIX_INVOCATION_EPOCH_OFFSET
        );
        assert_eq!(
            size_of::<fre_aot_regex::FrozenPreparedHeaderV1>(),
            fre_aot_regex::FROZEN_PREPARED_HEADER_V1_BYTES
        );
        assert_eq!(
            size_of::<FrozenPreparedHeaderV2>(),
            fre_aot_regex::FROZEN_PREPARED_HEADER_V2_BYTES
        );
        assert_eq!(
            size_of::<FrozenPreparedHeaderV3>(),
            fre_aot_regex::FROZEN_PREPARED_HEADER_V3_BYTES
        );
        assert_eq!(
            size_of::<FrozenPreparedHeaderV6>(),
            fre_aot_regex::FROZEN_PREPARED_HEADER_V6_BYTES
        );
        assert_eq!(
            fre_aot_regex::FROZEN_PREPARED_HEADER_V1_ACTIVE_SEAL_OFFSET,
            0
        );
        assert_eq!(size_of::<FreAotRegexPreparedHandleV1>(), size_of::<u64>());
        assert_eq!(align_of::<FreAotRegexPreparedHandleV1>(), align_of::<u64>());
        assert_eq!(
            size_of::<FreAotRegexExclusiveHandleV1>(),
            size_of::<*mut std::ffi::c_void>()
        );
        assert_eq!(
            align_of::<FreAotRegexExclusiveHandleV1>(),
            align_of::<*mut std::ffi::c_void>()
        );
        assert_eq!(size_of::<FreAotRegexResultV1>(), size_of::<[usize; 2]>());
        assert_eq!(size_of::<FreAotRegexCaptureSlotV1>(), size_of::<[usize; 2]>());
        assert_eq!(align_of::<FreAotRegexCaptureSlotV1>(), align_of::<usize>());
        assert_eq!(FreAotRegexCaptureSlotV1::default(), FreAotRegexCaptureSlotV1::UNMATCHED);
        assert_eq!(
            size_of::<FreAotRegexIterStateV1>(),
            size_of::<usize>() * 2 + size_of::<u32>() * 2
        );
        assert_eq!(
            align_of::<FreAotRegexIterStateV1>(),
            align_of::<usize>()
        );
        assert_eq!(
            core::mem::offset_of!(FreAotRegexIterStateV1, next_start),
            0
        );
        assert_eq!(
            core::mem::offset_of!(FreAotRegexIterStateV1, last_match_end),
            size_of::<usize>()
        );
        assert_eq!(
            core::mem::offset_of!(FreAotRegexIterStateV1, flags),
            size_of::<usize>() * 2
        );
        assert_eq!(
            core::mem::offset_of!(FreAotRegexIterStateV1, reserved),
            size_of::<usize>() * 2 + size_of::<u32>()
        );
        assert_eq!(
            size_of::<FreAotRegexHaystackV1>(),
            size_of::<[usize; 2]>()
        );
        assert_eq!(
            align_of::<FreAotRegexHaystackV1>(),
            align_of::<usize>()
        );
        assert_eq!(core::mem::offset_of!(FreAotRegexHaystackV1, ptr), 0);
        assert_eq!(
            core::mem::offset_of!(FreAotRegexHaystackV1, len),
            size_of::<usize>()
        );
        assert_eq!(
            size_of::<FreAotRegexSearchWindowV1>(),
            size_of::<[usize; 2]>()
        );
        assert_eq!(
            align_of::<FreAotRegexSearchWindowV1>(),
            align_of::<usize>()
        );
        assert_eq!(
            size_of::<FreAotRegexDynamicRowsPreflightV1>(),
            size_of::<[usize; 4]>()
        );
        assert_eq!(
            align_of::<FreAotRegexDynamicRowsPreflightV1>(),
            align_of::<usize>()
        );
        assert_eq!(
            size_of::<FreAotRegexDynamicRowsPreflightResultV6>(),
            size_of::<[usize; 2]>()
        );
        assert_eq!(
            align_of::<FreAotRegexDynamicRowsPreflightResultV6>(),
            align_of::<usize>()
        );
        assert_eq!(
            core::mem::offset_of!(FreAotRegexDynamicRowsPreflightResultV6, status),
            0
        );
        assert_eq!(
            core::mem::offset_of!(FreAotRegexDynamicRowsPreflightResultV6, native_rows_address),
            size_of::<usize>()
        );
        assert_eq!(
            size_of::<FreAotRegexDynamicRowsContinuationV1>(),
            size_of::<[usize; 5]>()
        );
        assert_eq!(
            align_of::<FreAotRegexDynamicRowsContinuationV1>(),
            align_of::<usize>()
        );
        assert_eq!(ARTIFACT_IDENTITY_BYTES, 32);
        assert!(C_API_V1_HEADER.contains("FRE_AOT_REGEX_ARTIFACT_IDENTITY_BYTES 32u"));
        assert!(C_API_V1_HEADER.contains("FRE_AOT_REGEX_STATUS_PARTIAL_PREFLIGHT_ENTER 6u"));
        assert!(C_API_V1_HEADER.contains("FRE_AOT_REGEX_PARTIAL_ENTRY_BYPASS 0u"));
        assert!(C_API_V1_HEADER.contains("FRE_AOT_REGEX_PARTIAL_ENTRY_ENTER 1u"));
        assert!(C_API_V1_HEADER.contains("FRE_AOT_REGEX_ITER_HAS_LAST 1u"));
        assert!(C_API_V1_HEADER.contains("FRE_AOT_REGEX_ITER_PENDING_EMPTY 2u"));
        assert!(C_API_V1_HEADER.contains("FRE_AOT_REGEX_ITER_FINISHED 4u"));
        assert!(C_API_V1_HEADER.contains("FreAotRegexExclusiveSpanFillV1"));
        assert!(C_API_V1_HEADER.contains("FreAotRegexExclusiveExistsBatchV1"));
        assert!(C_API_V1_HEADER.contains("FreAotRegexIndependentExistsBatchV1"));
        assert!(C_API_V1_HEADER.contains("FreAotRegexExactSingletonFirstCandidateV1"));
        assert!(C_API_V1_HEADER.contains(
            "FRE_AOT_REGEX_EXACT_SINGLETON_FIRST_CANDIDATE_MISS UINT64_MAX"
        ));
        assert!(C_API_V1_HEADER.contains("FreAotRegexMatchingLfLineWitnessV1"));
        assert!(
            C_API_V1_HEADER.contains("FRE_AOT_REGEX_MATCHING_LF_LINE_WITNESS_MISS UINT64_MAX")
        );
        assert!(C_API_V1_HEADER.contains("FreAotRegexExclusiveCountV1"));
        assert!(C_API_V1_HEADER.contains("FreAotRegexExclusiveSpanSumV1"));
        assert!(C_API_V1_HEADER.contains("FreAotRegexExclusiveGrepCountV1"));
        assert!(C_API_NATIVE_CAPTURE_V1_HEADER
            .contains("FRE_AOT_REGEX_STATUS_NATIVE_CAPTURE_UNAVAILABLE 10u"));
        assert!(C_API_NATIVE_CAPTURE_V1_HEADER.contains("FreAotRegexCaptureMaterializeV1"));
        assert!(C_API_NATIVE_CAPTURE_V1_HEADER.contains("FreAotRegexCaptureNextV1"));
        assert!(C_API_NATIVE_CAPTURE_V1_HEADER.contains("FreAotRegexCaptureReducerV1"));
        assert!(
            C_API_NATIVE_CAPTURE_V1_HEADER.contains("FreAotRegexCaptureReducerScratchV1")
        );
        assert_eq!(size_of::<FreAotRegexCaptureMaterializeV1>(), size_of::<usize>());
        assert_eq!(size_of::<FreAotRegexCaptureNextV1>(), size_of::<usize>());
        assert_eq!(size_of::<FreAotRegexCaptureReducerV1>(), size_of::<usize>());
        assert_eq!(
            size_of::<FreAotRegexCaptureReducerScratchV1>(),
            size_of::<usize>()
        );
        assert!(
            C_API_NATIVE_PARTICIPATION_V1_HEADER
                .contains("FRE_AOT_REGEX_STATUS_NATIVE_PARTICIPATION_UNAVAILABLE 10u")
        );
        assert!(
            C_API_NATIVE_PARTICIPATION_V1_HEADER
                .contains("FRE_AOT_REGEX_NATIVE_PARTICIPATION_SCRATCH_BYTES 16u")
        );
        assert!(C_API_NATIVE_PARTICIPATION_V1_HEADER.contains("FreAotRegexParticipationRequestV1"));
        assert!(C_API_NATIVE_PARTICIPATION_V1_HEADER.contains("FreAotRegexParticipationExactV1"));
        assert_eq!(
            size_of::<FreAotRegexParticipationRequestV1>(),
            size_of::<[usize; 8]>(),
        );
        assert_eq!(
            align_of::<FreAotRegexParticipationRequestV1>(),
            align_of::<usize>(),
        );
        assert_eq!(
            size_of::<FreAotRegexParticipationExactV1>(),
            size_of::<usize>(),
        );
        assert_eq!(
            size_of::<FreAotRegexExclusiveSpanFillV1>(),
            size_of::<usize>()
        );
        assert_eq!(
            size_of::<FreAotRegexExclusiveExistsBatchV1>(),
            size_of::<usize>()
        );
        assert_eq!(
            size_of::<FreAotRegexIndependentExistsBatchV1>(),
            size_of::<usize>()
        );
        assert_eq!(
            size_of::<FreAotRegexExactSingletonFirstCandidateV1>(),
            size_of::<usize>()
        );
        assert_eq!(
            size_of::<FreAotRegexMatchingLfLineWitnessV1>(),
            size_of::<usize>()
        );
        assert_eq!(size_of::<FreAotRegexExclusiveCountV1>(), size_of::<usize>());
        assert_eq!(
            size_of::<FreAotRegexExclusiveSpanSumV1>(),
            size_of::<usize>()
        );
        assert_eq!(
            size_of::<FreAotRegexExclusiveGrepCountV1>(),
            size_of::<usize>()
        );
        for symbol in [
            "fre_aot_regex_runtime_search_v1",
            "fre_aot_regex_runtime_search_without_endpoint_oracle_v1",
            "fre_aot_regex_runtime_prepare_v1",
            "fre_aot_regex_runtime_search_prepared_v1",
            "fre_aot_regex_runtime_destroy_prepared_v1",
            "fre_aot_regex_runtime_prepare_exclusive_v1",
            "fre_aot_regex_runtime_search_exclusive_v1",
            "fre_aot_regex_runtime_fill_spans_exclusive_v1",
            "fre_aot_regex_runtime_is_match_batch_exclusive_v1",
            "fre_aot_regex_runtime_count_exclusive_v1",
            "fre_aot_regex_runtime_span_sum_exclusive_v1",
            "fre_aot_regex_runtime_grep_count_exclusive_v1",
            "fre_aot_regex_runtime_prepared_partial_should_enter_v1",
            "fre_aot_regex_runtime_search_exclusive_from_partial_v1",
            "fre_aot_regex_runtime_search_exclusive_recover_partial_span_v1",
            "fre_aot_regex_runtime_search_exclusive_dynamic_rows_recover_span_v1",
            "fre_aot_regex_runtime_search_exclusive_partial_preflight_v1",
            "fre_aot_regex_runtime_search_exclusive_partial_native_root_preflight_v1",
            "fre_aot_regex_runtime_destroy_exclusive_v1",
        ] {
            assert!(C_API_V1_HEADER.contains(symbol), "{symbol}");
        }
        for private_fragment in [
            "fre_aot_regex_runtime_compiler_private_count_exclusive_v1",
            "fre_aot_regex_runtime_compiler_private_span_sum_exclusive_v1",
            "fre_aot_regex_runtime_compiler_private_grep_count_exclusive_v1",
            "fre_aot_regex_runtime_search_exclusive_from_partial_preflight_v1",
            "fre_aot_regex_runtime_search_exclusive_from_partial_preflight_compact_v1",
            "fre_aot_regex_runtime_search_exclusive_from_partial_preflight_compact_v2",
            "fre_aot_regex_runtime_search_exclusive_from_partial_preflight_compact_v3",
            "fre_aot_regex_runtime_search_exclusive_dynamic_rows_preflight_v1",
            "fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v1",
            "fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v2",
            "fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v3",
            "fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v4",
            "fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v5",
            "fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v6",
            "fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_preflight_v1",
            "fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_preflight_v2",
            "fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_preflight_v3",
            "fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_retire_v1",
            "fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_continue_v1",
            "fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_continue_v2",
            "fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_continue_v3",
            "fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_continue_v4",
            "fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_recover_span_v1",
            "fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_recover_span_v2",
            "fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_recover_span_v3",
            "fre_aot_regex_runtime_search_exclusive_dynamic_rows_deopt_v1",
            "fre_aot_regex_runtime_search_exclusive_dynamic_rows_continue_v1",
            "fre_aot_regex_runtime_search_exclusive_dynamic_rows_continue_v2",
            "fre_aot_regex_runtime_search_exclusive_frozen_fallback_v1",
            "fre_aot_regex_runtime_scan_frozen_loop_v1",
            "fre_aot_regex_runtime_scan_frozen_loop_v2",
            "native_rows_address",
            "cache_generation",
            "current_row",
        ] {
            assert!(
                !C_API_V1_HEADER.contains(private_fragment),
                "private ABI fragment leaked into the public header: {private_fragment}"
            );
        }

        let _: unsafe extern "C" fn(
            *const u8,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
        ) -> u32 = fre_aot_regex_runtime_search_v1;
        let _: unsafe extern "C" fn(
            *const u8,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
        ) -> u32 = fre_aot_regex_runtime_search_without_endpoint_oracle_v1;
        let _: unsafe extern "C" fn(*const u8, usize, *mut FreAotRegexPreparedHandleV1) -> u32 =
            fre_aot_regex_runtime_prepare_v1;
        let _: unsafe extern "C" fn(
            FreAotRegexPreparedHandleV1,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
        ) -> u32 = fre_aot_regex_runtime_search_prepared_v1;
        let _: extern "C" fn(FreAotRegexPreparedHandleV1) -> u32 =
            fre_aot_regex_runtime_destroy_prepared_v1;
        let _: unsafe extern "C" fn(*const u8, usize, *mut FreAotRegexExclusiveHandleV1) -> u32 =
            fre_aot_regex_runtime_prepare_exclusive_v1;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
        ) -> u32 = fre_aot_regex_runtime_search_exclusive_v1;
        let _: FreAotRegexExclusiveSpanFillV1 =
            fre_aot_regex_runtime_fill_spans_exclusive_v1;
        let _: FreAotRegexExclusiveExistsBatchV1 =
            fre_aot_regex_runtime_is_match_batch_exclusive_v1;
        let _: FreAotRegexExclusiveCountV1 = fre_aot_regex_runtime_count_exclusive_v1;
        let _: FreAotRegexExclusiveSpanSumV1 = fre_aot_regex_runtime_span_sum_exclusive_v1;
        let _: FreAotRegexExclusiveGrepCountV1 = fre_aot_regex_runtime_grep_count_exclusive_v1;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
            *const u8,
        ) -> u32 = fre_aot_regex_runtime_search_exclusive_frozen_fallback_v1;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
            *const u8,
        ) -> u32 =
            fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_preflight_v1;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
            *const u8,
            *const u32,
        ) -> u32 =
            fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_preflight_v2;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
            *const u8,
            *const u32,
        ) -> u32 =
            fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_preflight_v3;
        let _: unsafe extern "C" fn(FreAotRegexExclusiveHandleV1, u32) -> u32 =
            fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_retire_v1;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            *mut FreAotRegexResultV1,
            usize,
            usize,
            usize,
        ) -> u32 =
            fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_continue_v1;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            *mut FreAotRegexResultV1,
            usize,
            usize,
            usize,
        ) -> u32 =
            fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_continue_v3;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
            *const u8,
            *const u32,
            usize,
            usize,
            usize,
        ) -> u32 =
            fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_continue_v2;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
            *const u8,
            *const u32,
            usize,
            usize,
            usize,
        ) -> u32 =
            fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_continue_v4;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
            *const u8,
            usize,
        ) -> u32 =
            fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_recover_span_v1;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
            *const u8,
            usize,
        ) -> u32 =
            fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_recover_span_v2;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
            *const u8,
            usize,
            u64,
        ) -> u32 =
            fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_recover_span_v3;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
        ) -> u32 = fre_aot_regex_runtime_search_exclusive_dynamic_rows_deopt_v1;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            usize,
            *const u8,
            usize,
        ) -> usize = fre_aot_regex_runtime_scan_frozen_loop_v1;
        let _: unsafe extern "C" fn(
            *const u8,
            *const FrozenCompactLoopScanner,
            usize,
        ) -> usize = fre_aot_regex_runtime_scan_frozen_loop_v2;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
            *const u8,
            *const FreAotRegexDynamicRowsContinuationV1,
        ) -> u32 = fre_aot_regex_runtime_search_exclusive_dynamic_rows_continue_v1;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
            *const u8,
            *const FreAotRegexDynamicRowsContinuationV1,
        ) -> u32 = fre_aot_regex_runtime_search_exclusive_dynamic_rows_continue_v2;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
            *const u8,
            usize,
        ) -> u32 = fre_aot_regex_runtime_search_exclusive_dynamic_rows_recover_span_v1;
        let _: unsafe extern "C" fn(FreAotRegexExclusiveHandleV1, usize) -> u32 =
            fre_aot_regex_runtime_prepared_partial_should_enter_v1;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
            *const u8,
            usize,
            usize,
            u32,
            usize,
        ) -> u32 = fre_aot_regex_runtime_search_exclusive_from_partial_v1;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
            *const u8,
            usize,
            usize,
            u32,
            usize,
        ) -> u32 = fre_aot_regex_runtime_search_exclusive_from_partial_preflight_v1;
        let mut malformed_result = FreAotRegexResultV1 {
            start: 123,
            end: 456,
        };
        // SAFETY: the malformed pending-mode discriminator is rejected before
        // any handle or pointer is dereferenced.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_search_exclusive_from_partial_preflight_v1(
                    FreAotRegexExclusiveHandleV1::INVALID,
                    std::ptr::null(),
                    0,
                    0,
                    0,
                    &raw mut malformed_result,
                    std::ptr::null(),
                    0,
                    0,
                    2,
                    0,
                )
            },
            STATUS_INVALID_ARGUMENT
        );
        assert_eq!(
            malformed_result,
            FreAotRegexResultV1 {
                start: 123,
                end: 456,
            }
        );
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            *mut FreAotRegexResultV1,
            usize,
            usize,
            u32,
            usize,
        ) -> u32 = fre_aot_regex_runtime_search_exclusive_from_partial_preflight_compact_v1;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            *mut FreAotRegexResultV1,
            usize,
            usize,
            usize,
        ) -> u32 = fre_aot_regex_runtime_search_exclusive_from_partial_preflight_compact_v2;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            *mut FreAotRegexResultV1,
            usize,
            usize,
            usize,
        ) -> u32 = fre_aot_regex_runtime_search_exclusive_from_partial_preflight_compact_v3;
        // SAFETY: the malformed discriminator is rejected before dereference.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_search_exclusive_from_partial_preflight_compact_v1(
                    FreAotRegexExclusiveHandleV1::INVALID,
                    std::ptr::null(),
                    0,
                    &raw mut malformed_result,
                    0,
                    0,
                    2,
                    0,
                )
            },
            STATUS_INVALID_ARGUMENT
        );
        assert_eq!(
            malformed_result,
            FreAotRegexResultV1 {
                start: 123,
                end: 456,
            }
        );
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
            *const u8,
            usize,
        ) -> u32 = fre_aot_regex_runtime_search_exclusive_recover_partial_span_v1;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
            *const u8,
            *mut FreAotRegexSearchWindowV1,
        ) -> u32 = fre_aot_regex_runtime_search_exclusive_partial_preflight_v1;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
            *const u8,
            *mut FreAotRegexDynamicRowsPreflightV1,
        ) -> u32 = fre_aot_regex_runtime_search_exclusive_dynamic_rows_preflight_v1;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
            *const u8,
            *mut FreAotRegexDynamicRowsPreflightV1,
        ) -> u32 =
            fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v1;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
            *const u8,
            *mut FreAotRegexDynamicRowsPreflightV1,
        ) -> u32 =
            fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v2;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
            *const u8,
            *mut FreAotRegexDynamicRowsPreflightV1,
        ) -> u32 =
            fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v3;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
            *const u8,
            *mut FreAotRegexDynamicRowsPreflightV1,
        ) -> u32 =
            fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v4;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
            *const u8,
            *mut FreAotRegexDynamicRowsPreflightV1,
        ) -> u32 =
            fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v5;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
            *const u8,
            *mut FreAotRegexSearchWindowV1,
        ) -> FreAotRegexDynamicRowsPreflightResultV6 =
            fre_aot_regex_runtime_compiler_private_search_exclusive_dynamic_rows_preflight_v6;
        let _: unsafe extern "C" fn(
            FreAotRegexExclusiveHandleV1,
            *const u8,
            usize,
            usize,
            usize,
            *mut FreAotRegexResultV1,
            *const u8,
            *mut FreAotRegexSearchWindowV1,
        ) -> u32 = fre_aot_regex_runtime_search_exclusive_partial_native_root_preflight_v1;
        let _: unsafe extern "C" fn(FreAotRegexExclusiveHandleV1) -> u32 =
            fre_aot_regex_runtime_destroy_exclusive_v1;
    }

    #[test]
    fn v2_prepare_config_layout_header_and_function_type_are_exact() {
        assert_eq!(size_of::<FreAotRegexPrepareConfigV2>(), 64);
        assert_eq!(
            align_of::<FreAotRegexPrepareConfigV2>(),
            align_of::<u64>()
        );
        assert_eq!(
            core::mem::offset_of!(FreAotRegexPrepareConfigV2, struct_size),
            0
        );
        assert_eq!(
            core::mem::offset_of!(FreAotRegexPrepareConfigV2, config_version),
            4
        );
        assert_eq!(
            core::mem::offset_of!(FreAotRegexPrepareConfigV2, operation_flags),
            8
        );
        assert_eq!(
            core::mem::offset_of!(
                FreAotRegexPrepareConfigV2,
                max_start_filter_setup_work
            ),
            16
        );
        assert_eq!(
            core::mem::offset_of!(
                FreAotRegexPrepareConfigV2,
                max_grep_count_workspace_bytes
            ),
            24
        );
        assert_eq!(
            core::mem::offset_of!(FreAotRegexPrepareConfigV2, reserved),
            32
        );
        assert_eq!(PREPARE_CONFIG_V2_SIZE, 64);
        assert_eq!(PREPARE_CONFIG_V2_VERSION, 2);
        assert_eq!(DEFAULT_START_FILTER_SETUP_WORK, 100_000_000);
        assert_eq!(DEFAULT_GREP_COUNT_WORKSPACE_BYTES, 67_108_864);
        assert_eq!(PREPARE_OPERATION_SEARCH, 1);
        assert_eq!(PREPARE_OPERATION_COUNT, 2);
        assert_eq!(PREPARE_OPERATION_SPAN_SUM, 4);
        assert_eq!(PREPARE_OPERATION_GREP_COUNT, 8);
        assert_eq!(PREPARE_OPERATION_KNOWN_FLAGS, 15);
        for declaration in [
            "#include \"fre_aot_regex_runtime_v1.h\"",
            "FRE_AOT_REGEX_PREPARE_CONFIG_V2_SIZE 64u",
            "FRE_AOT_REGEX_PREPARE_CONFIG_V2_VERSION 2u",
            "FRE_AOT_REGEX_DEFAULT_START_FILTER_SETUP_WORK UINT64_C(100000000)",
            "FRE_AOT_REGEX_DEFAULT_GREP_COUNT_WORKSPACE_BYTES UINT64_C(67108864)",
            "FRE_AOT_REGEX_PREPARE_OPERATION_SEARCH UINT64_C(1)",
            "FRE_AOT_REGEX_PREPARE_OPERATION_COUNT UINT64_C(2)",
            "FRE_AOT_REGEX_PREPARE_OPERATION_SPAN_SUM UINT64_C(4)",
            "FRE_AOT_REGEX_PREPARE_OPERATION_GREP_COUNT UINT64_C(8)",
            "typedef struct FreAotRegexPrepareConfigV2",
            "uint64_t reserved[4]",
            "fre_aot_regex_runtime_prepare_exclusive_v2",
        ] {
            assert!(C_API_V2_HEADER.contains(declaration), "{declaration}");
        }
        let _: unsafe extern "C" fn(
            *const u8,
            usize,
            *const FreAotRegexPrepareConfigV2,
            *mut FreAotRegexExclusiveHandleV1,
        ) -> u32 = fre_aot_regex_runtime_prepare_exclusive_v2;
    }

    #[test]
    fn v3_prepare_config_preserves_v2_prefix_and_rejects_each_invalid_field() {
        assert_eq!(size_of::<FreAotRegexPrepareConfigV3>(), 112);
        assert_eq!(align_of::<FreAotRegexPrepareConfigV3>(), align_of::<u64>());
        assert_eq!(core::mem::offset_of!(FreAotRegexPrepareConfigV3, struct_size), 0);
        assert_eq!(core::mem::offset_of!(FreAotRegexPrepareConfigV3, config_version), 4);
        assert_eq!(core::mem::offset_of!(FreAotRegexPrepareConfigV3, operation_flags), 8);
        assert_eq!(
            core::mem::offset_of!(FreAotRegexPrepareConfigV3, max_start_filter_setup_work),
            16
        );
        assert_eq!(
            core::mem::offset_of!(FreAotRegexPrepareConfigV3, max_grep_count_workspace_bytes),
            24
        );
        assert_eq!(core::mem::offset_of!(FreAotRegexPrepareConfigV3, v2_reserved), 32);
        assert_eq!(core::mem::offset_of!(FreAotRegexPrepareConfigV3, max_handle_bytes), 64);
        assert_eq!(
            core::mem::offset_of!(FreAotRegexPrepareConfigV3, max_ordered_nfa_scratch_bytes),
            72
        );
        assert_eq!(
            core::mem::offset_of!(FreAotRegexPrepareConfigV3, max_ordered_nfa_setup_work),
            80
        );
        assert_eq!(
            core::mem::offset_of!(FreAotRegexPrepareConfigV3, required_capabilities),
            88
        );
        assert_eq!(core::mem::offset_of!(FreAotRegexPrepareConfigV3, reserved), 96);
        for declaration in [
            "FRE_AOT_REGEX_PREPARE_CONFIG_V3_SIZE 112u",
            "FRE_AOT_REGEX_PREPARE_CONFIG_V3_VERSION 3u",
            "FRE_AOT_REGEX_PREPARE_CAPABILITY_ORDERED_NFA_V15 UINT64_C(1)",
            "uint64_t v2_reserved[4]",
            "uint64_t required_capabilities",
            "fre_aot_regex_runtime_prepare_exclusive_v3",
        ] {
            assert!(C_API_V3_HEADER.contains(declaration), "{declaration}");
        }
        let _: unsafe extern "C" fn(
            *const u8,
            usize,
            *const FreAotRegexPrepareConfigV3,
            *mut FreAotRegexExclusiveHandleV1,
        ) -> u32 = fre_aot_regex_runtime_prepare_exclusive_v3;

        let malformed = [0_u8];
        let sentinel = FreAotRegexExclusiveHandleV1(std::ptr::dangling_mut());
        let valid = FreAotRegexPrepareConfigV3::new(PREPARE_OPERATION_COUNT);
        let mut invalid = vec![
            FreAotRegexPrepareConfigV3 {
                struct_size: PREPARE_CONFIG_V3_SIZE - 1,
                ..valid
            },
            FreAotRegexPrepareConfigV3 {
                config_version: PREPARE_CONFIG_V3_VERSION - 1,
                ..valid
            },
            FreAotRegexPrepareConfigV3 {
                operation_flags: PREPARE_OPERATION_KNOWN_FLAGS + 1,
                ..valid
            },
            FreAotRegexPrepareConfigV3 {
                required_capabilities: PREPARE_CAPABILITY_KNOWN_FLAGS + 1,
                ..valid
            },
            FreAotRegexPrepareConfigV3 {
                operation_flags: PREPARE_OPERATION_SEARCH,
                required_capabilities: PREPARE_CAPABILITY_ORDERED_NFA_V15,
                ..valid
            },
        ];
        for index in 0..4 {
            let mut config = valid;
            config.v2_reserved[index] = 1;
            invalid.push(config);
        }
        for index in 0..2 {
            let mut config = valid;
            config.reserved[index] = 1;
            invalid.push(config);
        }
        for config in invalid {
            let mut handle = sentinel;
            // SAFETY: all extents are valid and disjoint; invalid config must
            // be rejected before the deliberately malformed program byte.
            assert_eq!(
                unsafe {
                    fre_aot_regex_runtime_prepare_exclusive_v3(
                        malformed.as_ptr(),
                        malformed.len(),
                        &raw const config,
                        &raw mut handle,
                    )
                },
                STATUS_INVALID_ARGUMENT
            );
            assert_eq!(handle, sentinel);
        }
    }

    #[test]
    fn v3_ordered_nfa_optional_and_required_caps_are_transactional() {
        let bytes = program(r"(?:ab|a)b?", OutputContract::Span);
        let program = CompiledProgram::deserialize(&bytes).unwrap();
        let owner = program
            .compiler_private_frozen_ordered_nfa_prepared_scratch_v1(
                FrozenOrderedNfaLimitsV1::new(
                    DEFAULT_FROZEN_ORDERED_NFA_V1_MAX_HANDLE_BYTES,
                ),
            )
            .unwrap();
        let accounting = owner.accounting();
        drop(owner);

        let exact = FreAotRegexPrepareConfigV3 {
            operation_flags: PREPARE_OPERATION_COUNT | PREPARE_OPERATION_SPAN_SUM,
            max_handle_bytes: u64::try_from(accounting.retained_handle_bytes()).unwrap(),
            max_ordered_nfa_scratch_bytes: u64::try_from(accounting.scratch_bytes()).unwrap(),
            max_ordered_nfa_setup_work: accounting.setup_work(),
            required_capabilities: PREPARE_CAPABILITY_ORDERED_NFA_V15,
            ..FreAotRegexPrepareConfigV3::new(0)
        };
        let mut admitted =
            PreparedAotRegex::deserialize_with_prepare_config_v3(&bytes, exact).unwrap();
        assert!(admitted.frozen_header.has_ordered_nfa_v15());
        assert!(
            admitted
                .frozen_ordered_nfa_scratch
                .as_ref()
                .is_some_and(FrozenOrderedNfaPreparedScratchV1::is_active)
        );
        admitted.deactivate_frozen_header();
        assert!(!admitted.frozen_header.has_ordered_nfa_v15());
        assert!(
            admitted
                .frozen_ordered_nfa_scratch
                .as_ref()
                .is_some_and(|owner| !owner.is_active())
        );
        drop(admitted);

        let optional_exact = FreAotRegexPrepareConfigV3 {
            required_capabilities: 0,
            ..exact
        };
        let optional_admitted =
            PreparedAotRegex::deserialize_with_prepare_config_v3(&bytes, optional_exact).unwrap();
        assert!(optional_admitted.frozen_header.has_ordered_nfa_v15());
        assert!(
            optional_admitted
                .frozen_ordered_nfa_scratch
                .as_ref()
                .is_some_and(FrozenOrderedNfaPreparedScratchV1::is_active)
        );
        drop(optional_admitted);

        let one_below = [
            FreAotRegexPrepareConfigV3 {
                max_handle_bytes: exact.max_handle_bytes - 1,
                ..exact
            },
            FreAotRegexPrepareConfigV3 {
                max_ordered_nfa_scratch_bytes: exact.max_ordered_nfa_scratch_bytes - 1,
                ..exact
            },
            FreAotRegexPrepareConfigV3 {
                max_ordered_nfa_setup_work: exact.max_ordered_nfa_setup_work - 1,
                ..exact
            },
        ];
        for required in one_below {
            assert!(PreparedAotRegex::deserialize_with_prepare_config_v3(&bytes, required).is_err());
            let optional = FreAotRegexPrepareConfigV3 {
                required_capabilities: 0,
                ..required
            };
            let mut prepared =
                PreparedAotRegex::deserialize_with_prepare_config_v3(&bytes, optional).unwrap();
            assert!(!prepared.frozen_header.has_ordered_nfa_v15());
            assert!(prepared.frozen_ordered_nfa_scratch.is_none());
            assert_eq!(
                prepared.reduce_exclusive_operation(b"ababb", ExclusiveReducer::Count),
                Ok(2)
            );
        }

        let sentinel = FreAotRegexExclusiveHandleV1(std::ptr::dangling_mut());
        let mut handle = sentinel;
        let required_too_small = one_below[0];
        // SAFETY: all extents are valid and disjoint. Required-cap refusal is
        // transactional and must leave the sentinel output untouched.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_prepare_exclusive_v3(
                    bytes.as_ptr(),
                    bytes.len(),
                    &raw const required_too_small,
                    &raw mut handle,
                )
            },
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(handle, sentinel);

        let compiled_dfa = compile(
            CompileRequest::new(r"(?:ab|ac)+z", Target::x86_64_linux())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Span),
        )
        .unwrap();
        assert_ne!(compiled_dfa.program().engine_kind(), EngineKind::OrderedNfa);
        let dfa_bytes = compiled_dfa.program().serialize().unwrap();
        let required_structural = FreAotRegexPrepareConfigV3 {
            operation_flags: PREPARE_OPERATION_COUNT,
            required_capabilities: PREPARE_CAPABILITY_ORDERED_NFA_V15,
            ..FreAotRegexPrepareConfigV3::new(0)
        };
        assert!(
            PreparedAotRegex::deserialize_with_prepare_config_v3(
                &dfa_bytes,
                required_structural,
            )
            .is_err()
        );
        let optional_structural = FreAotRegexPrepareConfigV3 {
            required_capabilities: 0,
            ..required_structural
        };
        let v2 = PreparedAotRegex::deserialize_with_prepare_config_v2(
            &dfa_bytes,
            optional_structural.v2_prefix(),
        )
        .unwrap();
        let mut v3 = PreparedAotRegex::deserialize_with_prepare_config_v3(
            &dfa_bytes,
            optional_structural,
        )
        .unwrap();
        assert!(!v3.frozen_header.has_ordered_nfa_v15());
        assert!(v3.frozen_ordered_nfa_scratch.is_none());
        assert_eq!(v2.program.serialize().unwrap(), v3.program.serialize().unwrap());
        let mut v2 = v2;
        assert_eq!(
            v2.reduce_exclusive_operation(b"abacz", ExclusiveReducer::Count),
            v3.reduce_exclusive_operation(b"abacz", ExclusiveReducer::Count)
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one V2 transaction test covers validation, eager setup, retained limits, and V1 compatibility"
    )]
    fn exclusive_v2_preparation_is_operation_aware_and_transactional() {
        let malformed_program = [0_u8];
        let sentinel = FreAotRegexExclusiveHandleV1(std::ptr::dangling_mut());
        let valid = FreAotRegexPrepareConfigV2::new(0);
        let mut invalid = Vec::new();
        invalid.push(FreAotRegexPrepareConfigV2 {
            struct_size: PREPARE_CONFIG_V2_SIZE - 1,
            ..valid
        });
        invalid.push(FreAotRegexPrepareConfigV2 {
            config_version: PREPARE_CONFIG_V2_VERSION - 1,
            ..valid
        });
        invalid.push(FreAotRegexPrepareConfigV2 {
            operation_flags: PREPARE_OPERATION_KNOWN_FLAGS + 1,
            ..valid
        });
        for reserved_index in 0..4 {
            let mut config = valid;
            config.reserved[reserved_index] = 1;
            invalid.push(config);
        }
        for config in &invalid {
            let mut handle = sentinel;
            // SAFETY: every raw extent is readable/writable and disjoint. The
            // malformed program proves config rejection precedes parsing.
            let status = unsafe {
                fre_aot_regex_runtime_prepare_exclusive_v2(
                    malformed_program.as_ptr(),
                    malformed_program.len(),
                    config,
                    &raw mut handle,
                )
            };
            assert_eq!(status, STATUS_INVALID_ARGUMENT);
            assert_eq!(handle, sentinel);
        }
        let mut handle = sentinel;
        // SAFETY: the null config is deliberately rejected before use; the
        // other readable/writable extents are valid and disjoint.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_prepare_exclusive_v2(
                    malformed_program.as_ptr(),
                    malformed_program.len(),
                    std::ptr::null(),
                    &raw mut handle,
                )
            },
            STATUS_INVALID_ARGUMENT
        );
        assert_eq!(handle, sentinel);
        let config_words = [0_u64; 9];
        // SAFETY: one byte past this aligned array remains readable for more
        // than 64 bytes but is deliberately misaligned and rejected pre-read.
        let misaligned_config = unsafe {
            config_words
                .as_ptr()
                .cast::<u8>()
                .add(1)
                .cast::<FreAotRegexPrepareConfigV2>()
        };
        assert!(!misaligned_config.is_aligned());
        handle = sentinel;
        // SAFETY: the deliberately misaligned config is rejected before typed
        // access; the other extents remain valid and disjoint.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_prepare_exclusive_v2(
                    malformed_program.as_ptr(),
                    malformed_program.len(),
                    misaligned_config,
                    &raw mut handle,
                )
            },
            STATUS_INVALID_ARGUMENT
        );
        assert_eq!(handle, sentinel);
        handle = sentinel;
        // SAFETY: the valid config reaches and rejects the readable malformed
        // program while leaving the disjoint output untouched.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_prepare_exclusive_v2(
                    malformed_program.as_ptr(),
                    malformed_program.len(),
                    &valid,
                    &raw mut handle,
                )
            },
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(handle, sentinel);

        let span_program = program("(?:ab|ac)+z", OutputContract::Span);
        let legacy = prepare_exclusive(&span_program);
        // SAFETY: this test uniquely owns the live direct handle.
        let legacy_prepared = unsafe { &mut *legacy.0.cast::<PreparedAotRegex>() };
        assert_eq!(
            legacy_prepared.max_grep_count_workspace_bytes,
            fre_aot_regex::DEFAULT_GREP_COUNT_MAX_WORKSPACE_BYTES
        );
        assert!(legacy_prepared.grep_count_workspace.is_none());
        let legacy_proof = legacy_prepared
            .program
            .prepare_start_filter_with_workspace(
                &mut legacy_prepared.workspace,
            )
            .expect("V1 retains lazy start-filter setup");
        assert!(legacy_proof.work_completed() > 0);
        // SAFETY: this test still uniquely owns the live handle.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(legacy) },
            STATUS_SUCCESS
        );

        let eager_search = prepare_exclusive_v2(
            &span_program,
            &FreAotRegexPrepareConfigV2::new(PREPARE_OPERATION_SEARCH),
        );
        // SAFETY: this test uniquely owns the live direct handle.
        let eager_prepared = unsafe { &mut *eager_search.0.cast::<PreparedAotRegex>() };
        assert!(eager_prepared.grep_count_workspace.is_none());
        let settled = eager_prepared
            .program
            .prepare_start_filter_with_workspace(
                &mut eager_prepared.workspace,
            )
            .expect("declared Search settled before the first source call");
        assert_eq!(settled.work_completed(), 0);
        assert_eq!(settled.retained_owner_bytes(), 0);
        assert!(!settled.cap_declined());
        // SAFETY: this test still uniquely owns the live handle.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(eager_search) },
            STATUS_SUCCESS
        );

        let capped_search = prepare_exclusive_v2(
            &span_program,
            &FreAotRegexPrepareConfigV2 {
                max_start_filter_setup_work: 0,
                ..FreAotRegexPrepareConfigV2::new(PREPARE_OPERATION_SEARCH)
            },
        );
        // SAFETY: this test uniquely owns the live direct handle.
        let capped_prepared = unsafe { &mut *capped_search.0.cast::<PreparedAotRegex>() };
        let permanently_settled = capped_prepared
            .program
            .prepare_start_filter_with_workspace(
                &mut capped_prepared.workspace,
            )
            .expect("a cap decline permanently settles ordinary K0");
        assert_eq!(permanently_settled.work_completed(), 0);
        assert_eq!(permanently_settled.retained_owner_bytes(), 0);
        // SAFETY: this test still uniquely owns the live handle.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(capped_search) },
            STATUS_SUCCESS
        );

        let exists_program = program("a+", OutputContract::Exists);
        for operation_flags in [PREPARE_OPERATION_COUNT, PREPARE_OPERATION_SPAN_SUM] {
            handle = sentinel;
            let config = FreAotRegexPrepareConfigV2::new(operation_flags);
            // SAFETY: all extents are valid and disjoint; the incompatible
            // output contract is the transactional failure under test.
            assert_eq!(
                unsafe {
                    fre_aot_regex_runtime_prepare_exclusive_v2(
                        exists_program.as_ptr(),
                        exists_program.len(),
                        &config,
                        &raw mut handle,
                    )
                },
                STATUS_RUNTIME_FAILURE
            );
            assert_eq!(handle, sentinel);
        }

        let eager_grep = prepare_exclusive_v2(
            &exists_program,
            &FreAotRegexPrepareConfigV2::new(PREPARE_OPERATION_GREP_COUNT),
        );
        // SAFETY: this test uniquely owns the live direct handle.
        let eager_grep_prepared = unsafe { &*eager_grep.0.cast::<PreparedAotRegex>() };
        let exact_grep_workspace_bytes = eager_grep_prepared
            .grep_count_workspace
            .as_ref()
            .expect("declared GrepCount workspace")
            .construction_receipt()
            .workspace_bytes();
        assert!(exact_grep_workspace_bytes > 0);
        // SAFETY: this test still uniquely owns the live handle.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(eager_grep) },
            STATUS_SUCCESS
        );

        let exact_grep_capacity = u64::try_from(exact_grep_workspace_bytes)
            .expect("logical workspace bytes fit the V2 wire cap");
        let exact_grep = prepare_exclusive_v2(
            &exists_program,
            &FreAotRegexPrepareConfigV2 {
                max_grep_count_workspace_bytes: exact_grep_capacity,
                ..FreAotRegexPrepareConfigV2::new(PREPARE_OPERATION_GREP_COUNT)
            },
        );
        // SAFETY: this test uniquely owns the live direct handle.
        let exact_grep_prepared = unsafe { &*exact_grep.0.cast::<PreparedAotRegex>() };
        assert_eq!(
            exact_grep_prepared
                .grep_count_workspace
                .as_ref()
                .expect("exact cap admits GrepCount workspace")
                .construction_receipt()
                .workspace_bytes(),
            exact_grep_workspace_bytes
        );
        // SAFETY: this test still uniquely owns the live handle.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(exact_grep) },
            STATUS_SUCCESS
        );

        handle = sentinel;
        let one_below_grep_capacity = FreAotRegexPrepareConfigV2 {
            max_grep_count_workspace_bytes: exact_grep_capacity
                .checked_sub(1)
                .expect("fixture retains at least one logical byte"),
            ..FreAotRegexPrepareConfigV2::new(PREPARE_OPERATION_GREP_COUNT)
        };
        // SAFETY: every extent is valid and disjoint; the exact-minus-one
        // logical fixed-store cap is the transactional refusal under test.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_prepare_exclusive_v2(
                    exists_program.as_ptr(),
                    exists_program.len(),
                    &one_below_grep_capacity,
                    &raw mut handle,
                )
            },
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(handle, sentinel);

        handle = sentinel;
        let no_grep_capacity = FreAotRegexPrepareConfigV2 {
            max_grep_count_workspace_bytes: 0,
            ..FreAotRegexPrepareConfigV2::new(PREPARE_OPERATION_GREP_COUNT)
        };
        // SAFETY: every extent is valid and disjoint; the explicit fixed-store
        // limit is the transactional failure under test.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_prepare_exclusive_v2(
                    exists_program.as_ptr(),
                    exists_program.len(),
                    &no_grep_capacity,
                    &raw mut handle,
                )
            },
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(handle, sentinel);

        let lazy_limited = prepare_exclusive_v2(
            &exists_program,
            &FreAotRegexPrepareConfigV2 {
                max_grep_count_workspace_bytes: 0,
                ..FreAotRegexPrepareConfigV2::new(0)
            },
        );
        // SAFETY: this test uniquely owns the live direct handle.
        let lazy_limited_prepared = unsafe { &mut *lazy_limited.0.cast::<PreparedAotRegex>() };
        assert!(lazy_limited_prepared.grep_count_workspace.is_none());
        assert_eq!(lazy_limited_prepared.max_grep_count_workspace_bytes, 0);
        assert!(matches!(
            lazy_limited_prepared.prepare_grep_count(),
            Err(AotRegexGrepCountError::Prepare(
                GrepCountPrepareError::Resource { limit: 0, .. }
            ))
        ));
        // SAFETY: this test still uniquely owns the live handle.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(lazy_limited) },
            STATUS_SUCCESS
        );
    }

    #[test]
    fn frozen_loop_scan_boundary_authenticates_owner_pointer_and_extent() {
        let limits = CompileLimitsV1 {
            determinize: DeterminizeLimits {
                max_states: 0,
                ..DeterminizeLimits::default()
            },
            ..CompileLimitsV1::default()
        };
        let compiled = compile(
            CompileRequest::new(
                r"Q(?-u:[^Q])*@|Q",
                Target::x86_64_linux(),
            )
            .mode(CompileMode::Optimizing)
            .output(OutputContract::SelectedEnd)
            .limits(limits),
        )
        .expect("compile compact-loop helper fixture");
        let serialized = compiled.program().serialize().expect("serialize fixture");
        let handle = prepare_exclusive(&serialized);
        let base = handle.0.cast::<u8>();

        // SAFETY: the exclusive handle owns a live PreparedAotRegex whose
        // offset-zero V6 header has the public target-native layout.
        let flags = unsafe {
            std::ptr::read_unaligned(
                base.add(FROZEN_PREPARED_HEADER_V1_FLAGS_OFFSET)
                    .cast::<u32>(),
            )
        };
        assert!(matches!(
            flags,
            FROZEN_PREPARED_HEADER_V1_FLAG_DYNAMIC_ROWS_V6
                | FROZEN_PREPARED_HEADER_V1_FLAG_DYNAMIC_ROWS_V7
        ));
        let tail = FROZEN_PREPARED_HEADER_V6_DYNAMIC_ROWS_OFFSET;
        // SAFETY: the authenticated flag above proves the complete V6/V7
        // extent remains live in this exclusively owned prepared allocation.
        let plan_count = unsafe {
            std::ptr::read_unaligned(
                base.add(tail + FROZEN_DYNAMIC_ROWS_V6_LOOP_PLAN_COUNT_OFFSET)
                    .cast::<u32>(),
            )
        };
        assert!((1..=4).contains(&plan_count));

        let mut selected = None;
        for slot in 0..usize::try_from(plan_count).unwrap() {
            let plan = tail
                + FROZEN_DYNAMIC_ROWS_V6_LOOP_PLANS_OFFSET
                + slot * FROZEN_COMPACT_LOOP_PLAN_V1_BYTES;
            let mut members = [0_u64; 4];
            for (word, value) in members.iter_mut().enumerate() {
                // SAFETY: every active plan is wholly inside the authenticated
                // fixed-capacity header extent.
                *value = unsafe {
                    std::ptr::read_unaligned(
                        base.add(
                            plan
                                + FROZEN_COMPACT_LOOP_PLAN_V1_MEMBERS_OFFSET
                                + word * std::mem::size_of::<u64>(),
                        )
                        .cast::<u64>(),
                    )
                };
            }
            if members != [u64::MAX; 4] {
                // SAFETY: the scanner-address field is inside this same plan.
                let scanner_address = unsafe {
                    std::ptr::read_unaligned(
                        base.add(plan + FROZEN_COMPACT_LOOP_PLAN_V1_SCANNER_ADDRESS_OFFSET)
                            .cast::<usize>(),
                    )
                };
                selected = Some((members, scanner_address));
                break;
            }
        }
        let (members, scanner_address) =
            selected.expect("the fixture must publish a proper loop subset");
        assert_ne!(scanner_address, 0);
        let scanner = std::ptr::with_exposed_provenance::<FrozenCompactLoopScanner>(
            scanner_address,
        );
        let member = (u8::MIN..=u8::MAX)
            .find(|&byte| {
                members[usize::from(byte >> 6)] & (1_u64 << u32::from(byte & 63)) != 0
            })
            .unwrap();
        let nonmember = (u8::MIN..=u8::MAX)
            .find(|&byte| {
                members[usize::from(byte >> 6)] & (1_u64 << u32::from(byte & 63)) == 0
            })
            .unwrap();

        for prefix in [0_usize, 1, 31, 63, 64, 65, 129] {
            let mut source = vec![member; prefix];
            source.push(nonmember);
            source.extend(std::iter::repeat_n(member, 7));
            // SAFETY: the handle, exact opaque address, and source extent are
            // all live and exclusively owned for this synchronous call.
            let consumed = unsafe {
                fre_aot_regex_runtime_scan_frozen_loop_v1(
                    handle,
                    scanner_address,
                    source.as_ptr(),
                    source.len(),
                )
            };
            assert_eq!(consumed, prefix);
            assert!(consumed <= source.len());
            // SAFETY: setup authenticated this exact typed scanner pointer,
            // the exclusively owned prepared allocation remains active, and
            // `source` supplies the complete synchronous readable extent.
            let trusted = unsafe {
                fre_aot_regex_runtime_scan_frozen_loop_v2(
                    source.as_ptr(),
                    scanner,
                    source.len(),
                )
            };
            assert_eq!(trusted, prefix);
            assert!(trusted <= source.len());
        }

        let source = [member; 64];
        // SAFETY: all raw extents are live; only the opaque address is
        // deliberately foreign and must be rejected before dereference.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_scan_frozen_loop_v1(
                    handle,
                    scanner_address.wrapping_add(1),
                    source.as_ptr(),
                    source.len(),
                )
            },
            FROZEN_LOOP_SCAN_FAILURE
        );
        // SAFETY: malformed arguments are rejected before either raw pointer
        // is followed or a slice is formed.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_scan_frozen_loop_v1(
                    FreAotRegexExclusiveHandleV1::INVALID,
                    scanner_address,
                    std::ptr::null(),
                    0,
                )
            },
            FROZEN_LOOP_SCAN_FAILURE
        );
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_scan_frozen_loop_v1(
                    handle,
                    scanner_address,
                    source.as_ptr(),
                    isize::MAX.unsigned_abs().saturating_add(1),
                )
            },
            FROZEN_LOOP_SCAN_FAILURE
        );

        // Revocation makes the once-valid address inert before the helper can
        // reach the immutable owner.
        // SAFETY: this test uniquely owns the live prepared allocation.
        unsafe { &mut *handle.0.cast::<PreparedAotRegex>() }.deactivate_frozen_header();
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_scan_frozen_loop_v1(
                    handle,
                    scanner_address,
                    source.as_ptr(),
                    source.len(),
                )
            },
            FROZEN_LOOP_SCAN_FAILURE
        );
        // SAFETY: this test uniquely owns the now-revoked session.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
            STATUS_SUCCESS
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn frozen_object_link_fails_against_a_legacy_runtime_without_the_capability_symbol() {
        use std::{fs, process::Command, time::SystemTime};

        const FROZEN_SYMBOL: &str =
            "fre_aot_regex_runtime_search_exclusive_frozen_fallback_v1";
        assert!(!C_API_V1_HEADER.contains(FROZEN_SYMBOL));
        let nonce = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "fre-aot-frozen-old-runtime-link-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).expect("create isolated linker fixture");
        let caller = directory.join("frozen_caller.c");
        let legacy = directory.join("legacy_runtime.c");
        let capable = directory.join("capable_runtime.c");
        let compatible_executable = directory.join("compatible");
        let legacy_executable = directory.join("legacy");
        fs::write(
            &caller,
            r"#include <stddef.h>
#include <stdint.h>
typedef struct { size_t start; size_t end; } result_t;
extern uint32_t fre_aot_regex_runtime_search_exclusive_frozen_fallback_v1(
    void *, const unsigned char *, size_t, size_t, size_t, result_t *,
    const unsigned char *);
int main(void) {
    static const unsigned char haystack[1] = { 0 };
    static const unsigned char identity[32] = { 0 };
    result_t result = { 0, 0 };
    return (int)fre_aot_regex_runtime_search_exclusive_frozen_fallback_v1(
        (void *)1, haystack, 1, 0, 1, &result, identity);
}
",
        )
        .expect("write frozen caller");
        fs::write(
            &legacy,
            r"#include <stdint.h>
uint32_t fre_aot_regex_runtime_search_exclusive_v1(void) { return 0; }
",
        )
        .expect("write legacy runtime stub");
        fs::write(
            &capable,
            r"#include <stddef.h>
#include <stdint.h>
typedef struct { size_t start; size_t end; } result_t;
uint32_t fre_aot_regex_runtime_search_exclusive_frozen_fallback_v1(
    void *h, const unsigned char *p, size_t n, size_t s, size_t e, result_t *r,
    const unsigned char *d) {
    (void)h; (void)p; (void)n; (void)s; (void)e; (void)r; (void)d;
    return 0;
}
",
        )
        .expect("write capable runtime stub");

        let compatible = Command::new("cc")
            .arg(&caller)
            .arg(&legacy)
            .arg(&capable)
            .arg("-o")
            .arg(&compatible_executable)
            .output()
            .expect("invoke host C linker for capable runtime");
        assert!(
            compatible.status.success(),
            "capable fixture failed to link: {}",
            String::from_utf8_lossy(&compatible.stderr)
        );
        let old = Command::new("cc")
            .arg(&caller)
            .arg(&legacy)
            .arg("-o")
            .arg(&legacy_executable)
            .output()
            .expect("invoke host C linker for legacy runtime");
        assert!(
            !old.status.success(),
            "a frozen caller unexpectedly linked without {FROZEN_SYMBOL}"
        );
        fs::remove_dir_all(&directory).expect("remove isolated linker fixture");
    }

    #[test]
    fn assertion_nfa_executes_all_output_contracts() {
        let haystack = b"x\nalpha beta";
        let expected = [
            (
                OutputContract::Exists,
                FreAotRegexResultV1 { start: 0, end: 0 },
            ),
            (
                OutputContract::SelectedEnd,
                FreAotRegexResultV1 { start: 7, end: 7 },
            ),
            (
                OutputContract::Span,
                FreAotRegexResultV1 { start: 2, end: 7 },
            ),
        ];
        for (output, expected_result) in expected {
            let program = program(r"(?m:^alpha\b)", output);
            let mut result = FreAotRegexResultV1 {
                start: usize::MAX,
                end: usize::MAX,
            };
            assert_eq!(
                call(&program, haystack, 0, haystack.len(), &mut result),
                STATUS_MATCH
            );
            assert_eq!(result, expected_result);
        }

        let program = program(r"(?m:^alpha\b)", OutputContract::Span);
        let mut result = FreAotRegexResultV1 {
            start: usize::MAX,
            end: usize::MAX,
        };
        assert_eq!(
            call(&program, b"no match", 0, 8, &mut result),
            STATUS_NO_MATCH
        );
        assert_eq!(result, FreAotRegexResultV1::default());
    }

    #[test]
    #[allow(
        clippy::cast_ptr_alignment,
        clippy::too_many_lines,
        reason = "all ten public raw predicates and both untouched output transactions form one boundary audit"
    )]
    fn public_dynamic_rows_preflight_rejects_every_raw_boundary_violation_transactionally() {
        let compiled = compile(
            CompileRequest::new("(?:ab|ac)+z", Target::x86_64_linux())
                .mode(CompileMode::Fast)
                .output(OutputContract::Exists),
        )
        .expect("compile dynamic-row public-boundary fixture");
        let identity = compiled.receipt().program_sha256;
        let serialized = compiled.program().serialize().unwrap();
        let handle = prepare_exclusive(&serialized);
        let haystack = [b'x'; 80];
        let sentinel_result = FreAotRegexResultV1 { start: 71, end: 73 };
        let sentinel_output = FreAotRegexDynamicRowsPreflightV1 {
            start: 79,
            end: 83,
            native_rows_address: 89,
            cache_generation: 97,
        };
        let mut result: FreAotRegexResultV1;
        let mut output: FreAotRegexDynamicRowsPreflightV1;
        let mut result_words = [0xa5a5_a5a5_a5a5_a5a5_usize; 3];
        let mut output_words = [0x5a5a_5a5a_5a5a_5a5a_usize; 5];
        let result_words_before = result_words;
        let output_words_before = output_words;
        let misaligned_result = result_words
            .as_mut_ptr()
            .cast::<u8>()
            .wrapping_add(1)
            .cast::<FreAotRegexResultV1>();
        let misaligned_output = output_words
            .as_mut_ptr()
            .cast::<u8>()
            .wrapping_add(1)
            .cast::<FreAotRegexDynamicRowsPreflightV1>();
        assert!(!misaligned_result.is_aligned());
        assert!(!misaligned_output.is_aligned());

        macro_rules! reject {
            (
                $name:literal, $case_handle:expr, $haystack_ptr:expr, $haystack_len:expr,
                $start:expr, $end:expr, $result_ptr:expr, $identity_ptr:expr,
                $output_ptr:expr, $expected_status:expr
            ) => {{
                result = sentinel_result;
                output = sentinel_output;
                // SAFETY: every malformed extent is selected so the checked
                // public boundary rejects it before any invalid dereference.
                let status = unsafe {
                    fre_aot_regex_runtime_search_exclusive_dynamic_rows_preflight_v1(
                        $case_handle,
                        $haystack_ptr,
                        $haystack_len,
                        $start,
                        $end,
                        $result_ptr,
                        $identity_ptr,
                        $output_ptr,
                    )
                };
                assert_eq!(status, $expected_status, $name);
                assert_eq!(result, sentinel_result, "result transaction: {}", $name);
                assert_eq!(output, sentinel_output, "preflight transaction: {}", $name);
                assert_eq!(result_words, result_words_before, "result backing: {}", $name);
                assert_eq!(output_words, output_words_before, "output backing: {}", $name);
            }};
        }

        reject!(
            "invalid handle",
            FreAotRegexExclusiveHandleV1::INVALID,
            haystack.as_ptr(), haystack.len(), 8, 72,
            &raw mut result, identity.as_ptr(), &raw mut output,
            STATUS_INVALID_HANDLE
        );
        reject!(
            "null haystack",
            handle, std::ptr::null(), haystack.len(), 8, 72,
            &raw mut result, identity.as_ptr(), &raw mut output,
            STATUS_INVALID_ARGUMENT
        );
        reject!(
            "null result",
            handle, haystack.as_ptr(), haystack.len(), 8, 72,
            std::ptr::null_mut(), identity.as_ptr(), &raw mut output,
            STATUS_INVALID_ARGUMENT
        );
        reject!(
            "misaligned result",
            handle, haystack.as_ptr(), haystack.len(), 8, 72,
            misaligned_result, identity.as_ptr(), &raw mut output,
            STATUS_INVALID_ARGUMENT
        );
        reject!(
            "null identity",
            handle, haystack.as_ptr(), haystack.len(), 8, 72,
            &raw mut result, std::ptr::null(), &raw mut output,
            STATUS_INVALID_ARGUMENT
        );
        reject!(
            "null preflight output",
            handle, haystack.as_ptr(), haystack.len(), 8, 72,
            &raw mut result, identity.as_ptr(), std::ptr::null_mut(),
            STATUS_INVALID_ARGUMENT
        );
        reject!(
            "misaligned preflight output",
            handle, haystack.as_ptr(), haystack.len(), 8, 72,
            &raw mut result, identity.as_ptr(), misaligned_output,
            STATUS_INVALID_ARGUMENT
        );
        reject!(
            "length exceeds isize",
            handle, haystack.as_ptr(), isize::MAX.unsigned_abs().checked_add(1).unwrap(), 0, 0,
            &raw mut result, identity.as_ptr(), &raw mut output,
            STATUS_INVALID_ARGUMENT
        );
        reject!(
            "start after end",
            handle, haystack.as_ptr(), haystack.len(), 73, 72,
            &raw mut result, identity.as_ptr(), &raw mut output,
            STATUS_INVALID_ARGUMENT
        );
        reject!(
            "end after length",
            handle, haystack.as_ptr(), haystack.len(), 8,
            haystack.len().checked_add(1).unwrap(),
            &raw mut result, identity.as_ptr(), &raw mut output,
            STATUS_INVALID_ARGUMENT
        );

        // SAFETY: the rejected calls never consumed or aliased this uniquely
        // owned live session.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
            STATUS_SUCCESS
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "cold, warm, deopt, and identity-failure parity cover checked, V2, and trusted V3 transactions"
    )]
    fn compiler_private_dynamic_rows_preflight_matches_checked_transaction() {
        let compiled = compile(
            CompileRequest::new("(?:ab|ac)+z", Target::x86_64_linux())
                .mode(CompileMode::Fast)
                .output(OutputContract::Exists),
        )
        .expect("compile generated-only dynamic-row fixture");
        let identity = compiled.receipt().program_sha256;
        let serialized = compiled.program().serialize().unwrap();
        let public_handle = prepare_exclusive_with_cold_dynamic_rows(&serialized);
        let private_handle = prepare_exclusive_with_cold_dynamic_rows(&serialized);
        let trusted_handle = prepare_exclusive_with_cold_dynamic_rows(&serialized);
        let mut haystack = vec![b'!'; 80];
        for pair in haystack[8..70].chunks_exact_mut(2) {
            pair.copy_from_slice(b"ab");
        }
        haystack[70] = b'z';
        let sentinel_result = FreAotRegexResultV1 { start: 91, end: 92 };
        let sentinel_output = FreAotRegexDynamicRowsPreflightV1 {
            start: 93,
            end: 94,
            native_rows_address: 95,
            cache_generation: 96,
        };

        for expected_status in [STATUS_MATCH, STATUS_PARTIAL_PREFLIGHT_ENTER] {
            let mut public_result = sentinel_result;
            let mut private_result = sentinel_result;
            let mut trusted_result = sentinel_result;
            let mut public_output = sentinel_output;
            let mut private_output = sentinel_output;
            let mut trusted_output = sentinel_output;
            let public_status = call_exclusive_dynamic_rows_preflight(
                public_handle, &haystack, 8, 72, &mut public_result, &identity,
                &mut public_output,
            );
            let private_status = call_exclusive_compiler_private_dynamic_rows_preflight_v2(
                private_handle, &haystack, 8, 72, &mut private_result, &identity,
                &mut private_output,
            );
            let trusted_status = call_exclusive_compiler_private_dynamic_rows_preflight_v3(
                trusted_handle, &haystack, 8, 72, &mut trusted_result, &identity,
                &mut trusted_output,
            );
            assert_eq!(public_status, expected_status);
            assert_eq!(private_status, public_status);
            assert_eq!(trusted_status, public_status);
            assert_eq!(private_result, public_result);
            assert_eq!(trusted_result, public_result);
            if expected_status == STATUS_MATCH {
                assert_eq!(public_output, sentinel_output);
                assert_eq!(private_output, sentinel_output);
                assert_eq!(trusted_output, sentinel_output);
            } else {
                assert_eq!((private_output.start, private_output.end), (8, 72));
                assert_eq!((trusted_output.start, trusted_output.end), (8, 72));
                assert_eq!(
                    (private_output.start, private_output.end),
                    (public_output.start, public_output.end)
                );
                for output in [public_output, private_output, trusted_output] {
                    assert_ne!(output.native_rows_address, 0);
                    assert_ne!(output.cache_generation, 0);
                    // SAFETY: each descriptor belongs to its still-live,
                    // synchronously admitted exclusive transaction.
                    let descriptor = unsafe {
                        &*std::ptr::with_exposed_provenance::<
                            fre_aot_regex::DynamicNativeRowsV1,
                        >(output.native_rows_address)
                    };
                    assert_eq!(descriptor.cache_identity, output.cache_generation);
                    assert_ne!(descriptor.rows_address, 0);
                    assert_ne!(descriptor.class_map_address, 0);
                }
            }
        }

        let mut public_result = sentinel_result;
        let mut private_result = sentinel_result;
        let mut trusted_result = sentinel_result;
        assert_eq!(
            call_exclusive_dynamic_rows_deopt(
                public_handle, &haystack, 8, 72, &mut public_result,
            ),
            STATUS_MATCH
        );
        assert_eq!(
            call_exclusive_dynamic_rows_deopt(
                private_handle, &haystack, 8, 72, &mut private_result,
            ),
            STATUS_MATCH
        );
        assert_eq!(
            call_exclusive_dynamic_rows_deopt(
                trusted_handle, &haystack, 8, 72, &mut trusted_result,
            ),
            STATUS_MATCH
        );
        assert_eq!(private_result, public_result);
        assert_eq!(trusted_result, public_result);

        let mut wrong_identity = identity;
        wrong_identity[0] ^= 1;
        let mut public_output = sentinel_output;
        let mut private_output = sentinel_output;
        let mut trusted_output = sentinel_output;
        public_result = sentinel_result;
        private_result = sentinel_result;
        trusted_result = sentinel_result;
        assert_eq!(
            call_exclusive_dynamic_rows_preflight(
                public_handle, &haystack, 8, 72, &mut public_result, &wrong_identity,
                &mut public_output,
            ),
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(
            call_exclusive_compiler_private_dynamic_rows_preflight_v2(
                private_handle, &haystack, 8, 72, &mut private_result, &wrong_identity,
                &mut private_output,
            ),
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(
            call_exclusive_compiler_private_dynamic_rows_preflight_v3(
                trusted_handle, &haystack, 8, 72, &mut trusted_result, &wrong_identity,
                &mut trusted_output,
            ),
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(public_result, sentinel_result);
        assert_eq!(private_result, sentinel_result);
        assert_eq!(trusted_result, sentinel_result);
        assert_eq!(public_output, sentinel_output);
        assert_eq!(private_output, sentinel_output);
        assert_eq!(trusted_output, sentinel_output);

        for handle in [public_handle, private_handle, trusted_handle] {
            // SAFETY: each session is live, uniquely owned, and no call
            // overlaps its destruction.
            assert_eq!(
                unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
                STATUS_SUCCESS
            );
        }
    }

    #[test]
    fn compiler_private_v4_v5_preflights_leave_identity_output_word_untouched() {
        let compiled = compile(
            CompileRequest::new("(?:ab|ac)+z", Target::x86_64_linux())
                .mode(CompileMode::Fast)
                .output(OutputContract::Exists),
        )
        .expect("compile generated-only dynamic-row fixture");
        let identity = compiled.receipt().program_sha256;
        let serialized = compiled.program().serialize().unwrap();
        let mut haystack = vec![b'!'; 80];
        for pair in haystack[8..70].chunks_exact_mut(2) {
            pair.copy_from_slice(b"ab");
        }
        haystack[70] = b'z';
        let sentinel_result = FreAotRegexResultV1 { start: 91, end: 92 };
        let sentinel_output = FreAotRegexDynamicRowsPreflightV1 {
            start: 93,
            end: 94,
            native_rows_address: 95,
            cache_generation: 0xfeed_face_cafe_beef,
        };

        type Preflight = fn(
            FreAotRegexExclusiveHandleV1,
            &[u8],
            usize,
            usize,
            &mut FreAotRegexResultV1,
            &[u8; ARTIFACT_IDENTITY_BYTES],
            &mut FreAotRegexDynamicRowsPreflightV1,
        ) -> u32;
        let variants: [(&str, Preflight); 2] = [
            ("V4", call_exclusive_compiler_private_dynamic_rows_preflight_v4),
            ("V5", call_exclusive_compiler_private_dynamic_rows_preflight_v5),
        ];
        for (version, preflight) in variants {
            let handle = prepare_exclusive_with_cold_dynamic_rows(&serialized);
            let mut result = sentinel_result;
            let mut output = sentinel_output;
            assert_eq!(
                preflight(
                    handle,
                    &haystack,
                    8,
                    72,
                    &mut result,
                    &identity,
                    &mut output,
                ),
                STATUS_MATCH,
                "{version} cold completion"
            );
            assert_eq!(output, sentinel_output, "{version} cold output");

            result = sentinel_result;
            output = sentinel_output;
            assert_eq!(
                preflight(
                    handle,
                    &haystack,
                    8,
                    72,
                    &mut result,
                    &identity,
                    &mut output,
                ),
                STATUS_PARTIAL_PREFLIGHT_ENTER,
                "{version} admitted entry"
            );
            assert_eq!((output.start, output.end), (8, 72), "{version}");
            assert_ne!(output.native_rows_address, 0, "{version}");
            assert_eq!(
                output.cache_generation, sentinel_output.cache_generation,
                "{version} must not write the fourth output word"
            );
            // SAFETY: this transaction is still live and exclusively owns
            // the trusted descriptor until the deopt helper ends its use.
            let descriptor = unsafe {
                &*std::ptr::with_exposed_provenance::<fre_aot_regex::DynamicNativeRowsV1>(
                    output.native_rows_address,
                )
            };
            assert_ne!(descriptor.cache_identity, 0, "{version}");

            result = sentinel_result;
            assert_eq!(
                call_exclusive_dynamic_rows_deopt(handle, &haystack, 8, 72, &mut result),
                STATUS_MATCH,
                "{version} deopt"
            );
            let mut wrong_identity = identity;
            wrong_identity[0] ^= 1;
            result = sentinel_result;
            output = sentinel_output;
            assert_eq!(
                preflight(
                    handle,
                    &haystack,
                    8,
                    72,
                    &mut result,
                    &wrong_identity,
                    &mut output,
                ),
                STATUS_RUNTIME_FAILURE,
                "{version} wrong identity"
            );
            assert_eq!(result, sentinel_result, "{version} wrong-identity result");
            assert_eq!(output, sentinel_output, "{version} wrong-identity output");
            // SAFETY: deopt ended the transaction, the rejected identity did
            // not admit a new one, and this test uniquely owns the live handle.
            assert_eq!(
                unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
                STATUS_SUCCESS,
                "{version} destroy"
            );
        }
    }

    #[test]
    fn compiler_private_v6_returns_descriptor_and_writes_only_exact_window() {
        let compiled = compile(
            CompileRequest::new("(?:ab|ac)+z", Target::x86_64_linux())
                .mode(CompileMode::Fast)
                .output(OutputContract::Exists),
        )
        .expect("compile V6 dynamic-row fixture");
        let identity = compiled.receipt().program_sha256;
        let serialized = compiled.program().serialize().unwrap();
        let handle = prepare_exclusive_with_cold_dynamic_rows(&serialized);
        let mut haystack = vec![b'!'; 80];
        for pair in haystack[8..70].chunks_exact_mut(2) {
            pair.copy_from_slice(b"ab");
        }
        haystack[70] = b'z';
        let sentinel_result = FreAotRegexResultV1 { start: 91, end: 92 };
        let sentinel_output = FreAotRegexDynamicRowsPreflightV1 {
            start: 93,
            end: 94,
            native_rows_address: 95,
            cache_generation: 0xfeed_face_cafe_beef,
        };

        let mut result = sentinel_result;
        let mut output = sentinel_output;
        let returned = call_exclusive_compiler_private_dynamic_rows_preflight_v6(
            handle,
            &haystack,
            8,
            72,
            &mut result,
            &identity,
            &mut output,
        );
        assert_eq!(returned.status, usize::try_from(STATUS_MATCH).unwrap());
        assert_eq!(returned.native_rows_address, 0);
        assert_eq!(output, sentinel_output, "cold completion output");

        result = sentinel_result;
        output = sentinel_output;
        let returned = call_exclusive_compiler_private_dynamic_rows_preflight_v6(
            handle,
            &haystack,
            8,
            72,
            &mut result,
            &identity,
            &mut output,
        );
        assert_eq!(
            returned.status,
            usize::try_from(STATUS_PARTIAL_PREFLIGHT_ENTER).unwrap()
        );
        assert_ne!(returned.native_rows_address, 0);
        assert_eq!((output.start, output.end), (8, 72));
        assert_eq!(
            output.native_rows_address, sentinel_output.native_rows_address,
            "V6 must not write the third output word"
        );
        assert_eq!(
            output.cache_generation, sentinel_output.cache_generation,
            "V6 must not write the fourth output word"
        );
        // SAFETY: the admitted exclusive transaction keeps the returned
        // descriptor live until the deopt below ends synchronous native use.
        let descriptor = unsafe {
            &*std::ptr::with_exposed_provenance::<fre_aot_regex::DynamicNativeRowsV1>(
                returned.native_rows_address,
            )
        };
        assert_ne!(descriptor.cache_identity, 0);
        assert_ne!(descriptor.rows_address, 0);
        assert_ne!(descriptor.class_map_address, 0);

        result = sentinel_result;
        assert_eq!(
            call_exclusive_dynamic_rows_deopt(handle, &haystack, 8, 72, &mut result),
            STATUS_MATCH
        );
        let mut wrong_identity = identity;
        wrong_identity[0] ^= 1;
        result = sentinel_result;
        output = sentinel_output;
        let returned = call_exclusive_compiler_private_dynamic_rows_preflight_v6(
            handle,
            &haystack,
            8,
            72,
            &mut result,
            &wrong_identity,
            &mut output,
        );
        assert_eq!(
            returned.status,
            usize::try_from(STATUS_RUNTIME_FAILURE).unwrap()
        );
        assert_eq!(returned.native_rows_address, 0);
        assert_eq!(result, sentinel_result);
        assert_eq!(output, sentinel_output);
        // SAFETY: the failed identity admitted no transaction and this test
        // uniquely owns the still-live handle.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
            STATUS_SUCCESS
        );
    }

    #[test]
    fn exclusive_dynamic_rows_preflight_exposes_identity_bound_pointer_provenance() {
        let compiled = compile(
            CompileRequest::new("(?:ab|ac)+z", Target::x86_64_linux())
                .mode(CompileMode::Fast)
                .output(OutputContract::Exists),
        )
        .expect("compile dynamic-row runtime fixture");
        let identity = compiled.receipt().program_sha256;
        let serialized = compiled.program().serialize().unwrap();
        let handle = prepare_exclusive_with_cold_dynamic_rows(&serialized);
        let mut haystack = vec![b'!'; 80];
        for pair in haystack[8..70].chunks_exact_mut(2) {
            pair.copy_from_slice(b"ab");
        }
        haystack[70] = b'z';
        let start = 8;
        let end = 72;
        let sentinel_result = FreAotRegexResultV1 { start: 91, end: 92 };
        let sentinel_output = FreAotRegexDynamicRowsPreflightV1 {
            start: 93,
            end: 94,
            native_rows_address: 95,
            cache_generation: 96,
        };

        let mut result = sentinel_result;
        let mut output = sentinel_output;
        assert_eq!(
            call_exclusive_dynamic_rows_preflight(
                handle,
                &haystack,
                start,
                end,
                &mut result,
                &identity,
                &mut output,
            ),
            STATUS_MATCH
        );
        assert_eq!(result, FreAotRegexResultV1::default());
        assert_eq!(output, sentinel_output);

        result = sentinel_result;
        output = sentinel_output;
        assert_eq!(
            call_exclusive_dynamic_rows_preflight(
                handle,
                &haystack,
                start,
                end,
                &mut result,
                &identity,
                &mut output,
            ),
            STATUS_PARTIAL_PREFLIGHT_ENTER
        );
        assert_eq!(result, sentinel_result);
        assert_eq!((output.start, output.end), (start, end));
        assert_ne!(output.native_rows_address, 0);
        assert_ne!(output.cache_generation, 0);
        // SAFETY: the exclusive transaction is active and the descriptor is
        // owned by the synchronously borrowed prepared workspace.
        let descriptor = unsafe {
            &*std::ptr::with_exposed_provenance::<fre_aot_regex::DynamicNativeRowsV1>(
                output.native_rows_address,
            )
        };
        assert_eq!(descriptor.cache_identity, output.cache_generation);
        assert_ne!(descriptor.rows_address, 0);
        assert_ne!(descriptor.class_map_address, 0);
        assert_eq!(descriptor.initial_flags, 0);
        // SAFETY: all three addresses were explicitly exposed by the same live
        // prepared workspace, and no helper call or re-entry has ended this
        // exclusive preflight transaction.
        let class_map = unsafe {
            &*std::ptr::with_exposed_provenance::<[u8; 256]>(descriptor.class_map_address)
        };
        // SAFETY: the authenticated descriptor bounds this fixed-capacity row
        // prefix, and the exclusive transaction prevents concurrent mutation.
        let rows = unsafe {
            std::slice::from_raw_parts(
                std::ptr::with_exposed_provenance::<u32>(descriptor.rows_address),
                descriptor.live_cells,
            )
        };
        let first_class = class_map[usize::from(haystack[start])];
        let first_cell = usize::try_from(descriptor.initial_row)
            .unwrap()
            .checked_add(usize::from(first_class))
            .unwrap();
        assert!(first_cell < rows.len());
        assert_ne!(rows[first_cell], descriptor.unfilled_cell);

        // A genuine generated side exit uses its dedicated helper, which
        // records deopt feedback before canonical K0 completes.
        result = sentinel_result;
        assert_eq!(
            call_exclusive_dynamic_rows_deopt(handle, &haystack, start, end, &mut result),
            STATUS_MATCH
        );
        assert_eq!(result, FreAotRegexResultV1::default());

        let mut wrong_identity = identity;
        wrong_identity[0] ^= 1;
        result = sentinel_result;
        output = sentinel_output;
        assert_eq!(
            call_exclusive_dynamic_rows_preflight(
                handle,
                &haystack,
                start,
                end,
                &mut result,
                &wrong_identity,
                &mut output,
            ),
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(result, sentinel_result);
        assert_eq!(output, sentinel_output);

        // SAFETY: the handle remains uniquely owned and no call overlaps its
        // destruction.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
            STATUS_SUCCESS
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one raw-ABI differential covers all value contracts and transactional pointer rejection"
    )]
    fn exclusive_dynamic_rows_first_hole_continues_all_value_contracts() {
        for (output_contract, expected_result) in [
            (OutputContract::Exists, FreAotRegexResultV1::default()),
            (
                OutputContract::SelectedEnd,
                FreAotRegexResultV1 { start: 10, end: 10 },
            ),
            (
                OutputContract::Span,
                FreAotRegexResultV1 { start: 8, end: 10 },
            ),
        ] {
            let compiled = compile(
                CompileRequest::new(
                    r"(?-u:(?:a[\x00-\xFF]|[^a][\x00-\xFF]))",
                    Target::x86_64_linux(),
                )
                    .mode(CompileMode::Fast)
                    .output(output_contract),
            )
            .expect("compile scanner-free dynamic-row fixture");
            assert_eq!(compiled.program().engine_kind(), EngineKind::OrderedNfa);
            assert_eq!(
                compiled.program().exact_match_width(),
                Some(2),
                "{output_contract:?} fixture width"
            );
            let identity = compiled.receipt().program_sha256;
            let serialized = compiled.program().serialize().unwrap();
            let handle = prepare_exclusive_with_cold_dynamic_rows(&serialized);
            let mut warmed = vec![b'!'; 80];
            warmed[8..10].copy_from_slice(b"aa");
            let start = 8;
            let end = 72;
            let mut result = FreAotRegexResultV1 {
                start: usize::MAX,
                end: usize::MAX,
            };
            let mut preflight = FreAotRegexDynamicRowsPreflightV1::default();
            assert_eq!(
                call_exclusive_dynamic_rows_preflight(
                    handle,
                    &warmed,
                    start,
                    end,
                    &mut result,
                    &identity,
                    &mut preflight,
                ),
                STATUS_MATCH,
                "cold {output_contract:?}"
            );
            assert_eq!(result, expected_result);

            let mut novel = warmed.clone();
            novel[start..start + 2].copy_from_slice(b"ba");
            let sentinel = FreAotRegexResultV1 { start: 91, end: 92 };
            result = sentinel;
            preflight = FreAotRegexDynamicRowsPreflightV1::default();
            assert_eq!(
                call_exclusive_dynamic_rows_preflight(
                    handle,
                    &novel,
                    start,
                    end,
                    &mut result,
                    &identity,
                    &mut preflight,
                ),
                STATUS_PARTIAL_PREFLIGHT_ENTER,
                "warm {output_contract:?}"
            );
            assert_eq!(result, sentinel);
            assert_eq!((preflight.start, preflight.end), (start, end));

            // SAFETY: this is the live synchronous transaction admitted just
            // above; descriptor and cache addresses remain exclusively owned
            // until the continuation helper is called.
            let descriptor = unsafe {
                *std::ptr::with_exposed_provenance::<fre_aot_regex::DynamicNativeRowsV1>(
                    preflight.native_rows_address,
                )
            };
            let class_map = unsafe {
                &*std::ptr::with_exposed_provenance::<[u8; 256]>(
                    descriptor.class_map_address,
                )
            };
            let rows = unsafe {
                std::slice::from_raw_parts(
                    std::ptr::with_exposed_provenance::<u32>(descriptor.rows_address),
                    descriptor.live_cells,
                )
            };
            let root_cell = usize::try_from(descriptor.initial_row).unwrap()
                + usize::from(class_map[usize::from(novel[start])]);
            assert_eq!(rows[root_cell], descriptor.unfilled_cell);
            assert_eq!(descriptor.learned_loop_row_count, 0);
            let continuation = FreAotRegexDynamicRowsContinuationV1 {
                current_row: usize::try_from(descriptor.initial_row).unwrap(),
                resume_position: start,
                pending_valid: 0,
                pending_end: 0,
                cache_identity: preflight.cache_generation,
            };

            // Invalid raw storage is rejected transactionally without
            // consuming the valid admission needed by the following call.
            result = sentinel;
            assert_eq!(
                unsafe {
                    fre_aot_regex_runtime_search_exclusive_dynamic_rows_continue_v1(
                        handle,
                        novel.as_ptr(),
                        novel.len(),
                        start,
                        end,
                        &raw mut result,
                        identity.as_ptr(),
                        std::ptr::null(),
                    )
                },
                STATUS_INVALID_ARGUMENT
            );
            assert_eq!(result, sentinel);

            assert_eq!(
                call_exclusive_dynamic_rows_continue(
                    handle,
                    &novel,
                    start,
                    end,
                    &mut result,
                    &identity,
                    &continuation,
                ),
                STATUS_MATCH
            );
            assert_eq!(result, expected_result, "{output_contract:?}");

            // SAFETY: this test uniquely owns the completed session.
            assert_eq!(
                unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
                STATUS_SUCCESS
            );
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the repeated private ABI exercise authenticates each freshly rearmed cache frontier"
    )]
    fn exclusive_dynamic_rows_v2_publishes_repeated_cells_without_consuming_bytes() {
        let compiled = compile(
            CompileRequest::new(
                r"(?-u:(?:a[\x00-\xFF]|[^a][\x00-\xFF]))",
                Target::x86_64_linux(),
            )
            .mode(CompileMode::Fast)
            .output(OutputContract::Exists),
        )
        .expect("compile scanner-free branching dynamic-row fixture");
        assert_eq!(compiled.program().engine_kind(), EngineKind::OrderedNfa);
        let identity = compiled.receipt().program_sha256;
        let serialized = compiled.program().serialize().unwrap();
        let handle = prepare_exclusive_with_cold_dynamic_rows(&serialized);
        let start = 8_usize;
        let end = 72_usize;

        let mut warmed = vec![b'!'; 80];
        warmed[start..start + 2].copy_from_slice(b"aa");
        let mut result = FreAotRegexResultV1::default();
        let mut preflight = FreAotRegexDynamicRowsPreflightV1::default();
        assert_eq!(
            call_exclusive_dynamic_rows_preflight(
                handle,
                &warmed,
                start,
                end,
                &mut result,
                &identity,
                &mut preflight,
            ),
            STATUS_MATCH
        );

        let mut novel = warmed;
        novel[start..start + 2].copy_from_slice(b"bb");
        let sentinel = FreAotRegexResultV1 { start: 91, end: 92 };
        result = sentinel;
        preflight = FreAotRegexDynamicRowsPreflightV1::default();
        assert_eq!(
            call_exclusive_dynamic_rows_preflight(
                handle,
                &novel,
                start,
                end,
                &mut result,
                &identity,
                &mut preflight,
            ),
            STATUS_PARTIAL_PREFLIGHT_ENTER
        );
        assert_eq!(result, sentinel);

        let mut descriptor_address = preflight.native_rows_address;
        let mut row = unsafe {
            usize::try_from(
                (*std::ptr::with_exposed_provenance::<fre_aot_regex::DynamicNativeRowsV1>(
                    descriptor_address,
                ))
                .initial_row,
            )
            .unwrap()
        };
        let mut cache_identity = preflight.cache_generation;
        for (ordinal, position) in (start..start + 2).enumerate() {
            let continuation = FreAotRegexDynamicRowsContinuationV1 {
                current_row: row,
                resume_position: position,
                pending_valid: 0,
                pending_end: 0,
                cache_identity,
            };
            result = sentinel;
            assert_eq!(
                call_exclusive_dynamic_rows_resolve_cell(
                    handle,
                    &novel,
                    start,
                    end,
                    &mut result,
                    &identity,
                    &continuation,
                ),
                STATUS_DYNAMIC_ROWS_CELL_RESUME,
                "unpublished cell {ordinal}"
            );
            descriptor_address = result.start;
            assert_ne!(descriptor_address, 0);
            let cell = u32::try_from(result.end).expect("packed cell fits u32");
            assert_ne!(cell, fre_aot_regex::DYNAMIC_NATIVE_ROWS_V1_UNFILLED_CELL);
            let descriptor = unsafe {
                *std::ptr::with_exposed_provenance::<fre_aot_regex::DynamicNativeRowsV1>(
                    descriptor_address,
                )
            };
            cache_identity = descriptor.cache_identity;
            let class_map = unsafe {
                &*std::ptr::with_exposed_provenance::<[u8; 256]>(
                    descriptor.class_map_address,
                )
            };
            let source_cell = row
                .checked_add(usize::from(class_map[usize::from(novel[position])]))
                .expect("source cell index");
            let rows = unsafe {
                std::slice::from_raw_parts(
                    std::ptr::with_exposed_provenance::<u32>(descriptor.rows_address),
                    descriptor.live_cells,
                )
            };
            assert_eq!(rows[source_cell], cell, "published cell {ordinal}");
            if ordinal == 1 {
                assert_ne!(
                    cell & fre_aot_regex::DYNAMIC_NATIVE_ROWS_V1_ACCEPT_MASK,
                    0,
                    "final transition accepts"
                );
            } else {
                let token = cell & fre_aot_regex::DYNAMIC_NATIVE_ROWS_V1_NEXT_ROW_TOKEN_MASK;
                row = usize::try_from(token.checked_sub(1).expect("live next-row token"))
                    .unwrap();
            }
        }

        // SAFETY: the test uniquely owns the synchronous session. The final
        // status-9 admission is intentionally retired by destruction, just as
        // generated local completion leaves it for the next entry to settle.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
            STATUS_SUCCESS
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "success and raw/private authentication failures share one single-use dynamic Span lifecycle"
    )]
    fn exclusive_dynamic_span_postflight_authenticates_and_recovers() {
        let compiled = compile(
            CompileRequest::new(
                r"(?-u:(?:a|[^a][\x00-\xFF]))",
                Target::x86_64_linux(),
            )
            .mode(CompileMode::Fast)
            .output(OutputContract::Span),
        )
        .expect("compile scanner-free variable Span fixture");
        assert_eq!(compiled.program().engine_kind(), EngineKind::OrderedNfa);
        assert_eq!(compiled.program().exact_match_width(), None);
        assert!(compiled.module().prepared_entry_symbol().is_some());
        assert_eq!(
            compiled
                .module()
                .required_prepared_dynamic_rows_continue_runtime_symbol(),
            Some("fre_aot_regex_runtime_search_exclusive_dynamic_rows_continue_v2")
        );
        assert_eq!(
            compiled
                .module()
                .required_prepared_dynamic_rows_span_recovery_runtime_symbol(),
            Some("fre_aot_regex_runtime_search_exclusive_dynamic_rows_recover_span_v1")
        );

        let identity = compiled.receipt().program_sha256;
        let serialized = compiled.program().serialize().unwrap();
        let handle = prepare_exclusive_with_cold_dynamic_rows(&serialized);
        let mut haystack = vec![b'!'; 80];
        let start = 8_usize;
        let end = 72_usize;
        haystack[start..start + 2].copy_from_slice(b"bq");
        let selected_end = start + 2;
        let expected = FreAotRegexResultV1 {
            start,
            end: selected_end,
        };
        let sentinel = FreAotRegexResultV1 { start: 91, end: 92 };

        let mut result = sentinel;
        let mut preflight = FreAotRegexDynamicRowsPreflightV1::default();
        assert_eq!(
            call_exclusive_dynamic_rows_preflight(
                handle,
                &haystack,
                start,
                end,
                &mut result,
                &identity,
                &mut preflight,
            ),
            STATUS_MATCH
        );
        assert_eq!(result, expected);

        let preflight = || {
            let mut result = sentinel;
            let mut preflight = FreAotRegexDynamicRowsPreflightV1::default();
            assert_eq!(
                call_exclusive_dynamic_rows_preflight(
                    handle,
                    &haystack,
                    start,
                    end,
                    &mut result,
                    &identity,
                    &mut preflight,
                ),
                STATUS_PARTIAL_PREFLIGHT_ENTER
            );
            assert_eq!(result, sentinel);
            assert_eq!((preflight.start, preflight.end), (start, end));
            preflight
        };

        preflight();
        result = sentinel;
        assert_eq!(
            call_exclusive_recover_dynamic_span(
                handle,
                &haystack,
                start,
                end,
                &mut result,
                &identity,
                selected_end,
            ),
            STATUS_MATCH
        );
        assert_eq!(result, expected);

        // The exact dynamic admission is single use.
        result = sentinel;
        assert_eq!(
            call_exclusive_recover_dynamic_span(
                handle,
                &haystack,
                start,
                end,
                &mut result,
                &identity,
                selected_end,
            ),
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(result, sentinel);

        // Raw pointer rejection happens before Rust can consume the otherwise
        // valid ticket; the following authenticated call still succeeds.
        preflight();
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_search_exclusive_dynamic_rows_recover_span_v1(
                    handle,
                    haystack.as_ptr(),
                    haystack.len(),
                    start,
                    end,
                    &raw mut result,
                    std::ptr::null(),
                    selected_end,
                )
            },
            STATUS_INVALID_ARGUMENT
        );
        assert_eq!(result, sentinel);
        assert_eq!(
            call_exclusive_recover_dynamic_span(
                handle,
                &haystack,
                start,
                end,
                &mut result,
                &identity,
                selected_end,
            ),
            STATUS_MATCH
        );
        assert_eq!(result, expected);

        // A foreign identity consumes the capability before rejection.
        preflight();
        result = sentinel;
        let mut wrong_identity = identity;
        wrong_identity[0] ^= 1;
        assert_eq!(
            call_exclusive_recover_dynamic_span(
                handle,
                &haystack,
                start,
                end,
                &mut result,
                &wrong_identity,
                selected_end,
            ),
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(result, sentinel);
        assert_eq!(
            call_exclusive_recover_dynamic_span(
                handle,
                &haystack,
                start,
                end,
                &mut result,
                &identity,
                selected_end,
            ),
            STATUS_RUNTIME_FAILURE,
            "foreign postflight must consume the ticket"
        );

        // A cross-window call and an in-range but semantically impossible
        // endpoint are both authenticated failures that consume their ticket.
        preflight();
        assert_eq!(
            call_exclusive_recover_dynamic_span(
                handle,
                &haystack,
                start + 1,
                end,
                &mut result,
                &identity,
                selected_end,
            ),
            STATUS_RUNTIME_FAILURE
        );
        preflight();
        result = sentinel;
        assert_eq!(
            call_exclusive_recover_dynamic_span(
                handle,
                &haystack,
                start,
                end,
                &mut result,
                &identity,
                start + 1,
            ),
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(result, sentinel);

        // SAFETY: the test uniquely owns the completed exclusive session.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
            STATUS_SUCCESS
        );
    }

    #[test]
    fn exclusive_frozen_dynamic_span_postflight_reuses_owner_across_windows_and_revokes() {
        let compiled = compile(
            CompileRequest::new(
                r"(?-u:(?:a|[^a][\x00-\xFF]))",
                Target::x86_64_linux(),
            )
            .mode(CompileMode::Fast)
            .output(OutputContract::Span),
        )
        .expect("compile scanner-free variable Span fixture");
        let identity = compiled.receipt().program_sha256;
        let serialized = compiled.program().serialize().unwrap();
        let handle = prepare_exclusive(&serialized);
        // SAFETY: the test uniquely owns this live allocation until the
        // explicit destroy below.
        let prepared = unsafe { &*handle.0.cast::<PreparedAotRegex>() };
        assert!(prepared.frozen_header.has_dynamic_rows());
        assert!(prepared.frozen_dynamic_rows.is_some());

        let mut haystack = vec![b'!'; 80];
        let start = 8_usize;
        let end = 72_usize;
        haystack[start..start + 2].copy_from_slice(b"bq");
        let selected_end = start + 2;
        let expected = FreAotRegexResultV1 {
            start,
            end: selected_end,
        };
        let mut alternate = vec![b'!'; 96];
        let alternate_start = 13_usize;
        let alternate_end = 81_usize;
        alternate[alternate_start] = b'a';
        let alternate_selected_end = alternate_start + 1;
        let alternate_expected = FreAotRegexResultV1 {
            start: alternate_start,
            end: alternate_selected_end,
        };
        let sentinel = FreAotRegexResultV1 { start: 91, end: 92 };

        for (label, input, window_start, window_end, endpoint, expected) in [
            ("two-byte", haystack.as_slice(), start, end, selected_end, expected),
            (
                "one-byte",
                alternate.as_slice(),
                alternate_start,
                alternate_end,
                alternate_selected_end,
                alternate_expected,
            ),
        ] {
            let mut result = sentinel;
            assert_eq!(
                call_exclusive_recover_dynamic_span(
                    handle,
                    input,
                    window_start,
                    window_end,
                    &mut result,
                    &identity,
                    endpoint,
                ),
                STATUS_MATCH,
                "compact {label} invocation"
            );
            assert_eq!(result, expected);
            assert!(
                exclusive_frozen_header_is_active(handle),
                "successful reverse-only recovery must retain the compact owner"
            );
        }

        // A foreign identity is authenticated before reverse K0 and revokes
        // the otherwise reusable compact owner.
        let mut rejected = sentinel;
        let mut wrong_identity = identity;
        wrong_identity[0] ^= 1;
        assert_eq!(
            call_exclusive_recover_dynamic_span(
                handle,
                &haystack,
                start,
                end,
                &mut rejected,
                &wrong_identity,
                selected_end,
            ),
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(rejected, sentinel);
        assert!(
            !exclusive_frozen_header_is_active(handle),
            "every compact rejection must permanently revoke the owner"
        );

        assert_eq!(
            call_exclusive_recover_dynamic_span(
                handle,
                &haystack,
                start,
                end,
                &mut rejected,
                &identity,
                selected_end,
            ),
            STATUS_RUNTIME_FAILURE,
            "a revoked owner cannot bypass the missing mutable preflight ticket"
        );
        assert_eq!(rejected, sentinel);

        // SAFETY: the test uniquely owns the completed exclusive session.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
            STATUS_SUCCESS
        );

        // An in-range endpoint that the language cannot produce likewise
        // revokes a fresh owner rather than remaining replayable.
        let impossible_handle = prepare_exclusive(&serialized);
        assert!(exclusive_frozen_header_is_active(impossible_handle));
        let impossible = vec![b'!'; 80];
        let mut impossible_result = sentinel;
        assert_eq!(
            call_exclusive_recover_dynamic_span(
                impossible_handle,
                &impossible,
                start,
                end,
                &mut impossible_result,
                &identity,
                start + 1,
            ),
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(impossible_result, sentinel);
        assert!(!exclusive_frozen_header_is_active(impossible_handle));
        // SAFETY: the test uniquely owns the rejected exclusive session.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(impossible_handle) },
            STATUS_SUCCESS
        );
    }

    #[test]
    fn exclusive_dynamic_rows_continuation_preserves_pending_endpoint() {
        let compiled = compile(
            CompileRequest::new(r"(?-u:(?:ab?|[^a]b?))", Target::x86_64_linux())
                .mode(CompileMode::Fast)
                .output(OutputContract::SelectedEnd),
        )
        .expect("compile scanner-free pending-end fixture");
        let identity = compiled.receipt().program_sha256;
        let serialized = compiled.program().serialize().unwrap();
        let handle = prepare_exclusive_with_cold_dynamic_rows(&serialized);
        let mut warmed = vec![b'!'; 80];
        let start = 8;
        let end = 72;
        warmed[start..start + 2].copy_from_slice(b"ab");
        let mut result = FreAotRegexResultV1::default();
        let mut preflight = FreAotRegexDynamicRowsPreflightV1::default();
        assert_eq!(
            call_exclusive_dynamic_rows_preflight(
                handle,
                &warmed,
                start,
                end,
                &mut result,
                &identity,
                &mut preflight,
            ),
            STATUS_MATCH
        );
        assert_eq!(result, FreAotRegexResultV1 { start: 10, end: 10 });

        let mut novel = warmed.clone();
        novel[start + 1] = b'a';
        assert_eq!(
            call_exclusive_dynamic_rows_preflight(
                handle,
                &novel,
                start,
                end,
                &mut result,
                &identity,
                &mut preflight,
            ),
            STATUS_PARTIAL_PREFLIGHT_ENTER
        );
        // SAFETY: descriptor reads are confined to the just-admitted
        // exclusive transaction and precede its continuation call.
        let descriptor = unsafe {
            *std::ptr::with_exposed_provenance::<fre_aot_regex::DynamicNativeRowsV1>(
                preflight.native_rows_address,
            )
        };
        let class_map = unsafe {
            &*std::ptr::with_exposed_provenance::<[u8; 256]>(descriptor.class_map_address)
        };
        let rows = unsafe {
            std::slice::from_raw_parts(
                std::ptr::with_exposed_provenance::<u32>(descriptor.rows_address),
                descriptor.live_cells,
            )
        };
        let first = rows[usize::try_from(descriptor.initial_row).unwrap()
            + usize::from(class_map[usize::from(novel[start])])];
        assert_ne!(first & descriptor.accept_mask, 0);
        let current_row = (first & descriptor.next_row_token_mask)
            .checked_sub(1)
            .expect("pending root cell retains its higher-priority successor");
        let hole = usize::try_from(current_row).unwrap()
            + usize::from(class_map[usize::from(novel[start + 1])]);
        assert_eq!(rows[hole], descriptor.unfilled_cell);
        let continuation = FreAotRegexDynamicRowsContinuationV1 {
            current_row: usize::try_from(current_row).unwrap(),
            resume_position: start + 1,
            pending_valid: 1,
            pending_end: start + 1,
            cache_identity: preflight.cache_generation,
        };
        assert_eq!(
            call_exclusive_dynamic_rows_continue(
                handle,
                &novel,
                start,
                end,
                &mut result,
                &identity,
                &continuation,
            ),
            STATUS_MATCH
        );
        assert_eq!(result, FreAotRegexResultV1 { start: 9, end: 9 });

        // SAFETY: this test uniquely owns the completed session.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
            STATUS_SUCCESS
        );
    }

    #[test]
    fn exclusive_dynamic_rows_short_fallback_settles_local_success_without_backoff() {
        let compiled = compile(
            CompileRequest::new("(?:ab|ac)+z", Target::x86_64_linux())
                .mode(CompileMode::Fast)
                .output(OutputContract::Exists),
        )
        .expect("compile alternating dynamic-row fixture");
        let identity = compiled.receipt().program_sha256;
        let serialized = compiled.program().serialize().unwrap();
        let handle = prepare_exclusive_with_cold_dynamic_rows(&serialized);
        let mut haystack = vec![b'!'; 80];
        for pair in haystack[8..70].chunks_exact_mut(2) {
            pair.copy_from_slice(b"ab");
        }
        haystack[70] = b'z';
        let start = 8;
        let end = 72;
        let mut result = FreAotRegexResultV1::default();
        let mut output = FreAotRegexDynamicRowsPreflightV1::default();

        assert_eq!(
            call_exclusive_dynamic_rows_preflight(
                handle,
                &haystack,
                start,
                end,
                &mut result,
                &identity,
                &mut output,
            ),
            STATUS_MATCH,
            "cold canonical search warms the K0 root"
        );

        for cycle in 0..3 {
            result = FreAotRegexResultV1::default();
            output = FreAotRegexDynamicRowsPreflightV1::default();
            assert_eq!(
                call_exclusive_dynamic_rows_preflight(
                    handle,
                    &haystack,
                    start,
                    end,
                    &mut result,
                    &identity,
                    &mut output,
                ),
                STATUS_PARTIAL_PREFLIGHT_ENTER,
                "long local-success transaction {cycle} must remain admitted"
            );

            // Model the generated scan returning locally, followed by a
            // separate short call that bypasses preflight in the wrapper.
            // The ordinary helper must settle that success, not report a
            // side exit for the preceding long transaction.
            result = FreAotRegexResultV1::default();
            assert_eq!(
                call_exclusive(handle, &haystack, 0, 16, &mut result),
                STATUS_NO_MATCH,
                "short ordinary fallback {cycle}"
            );
        }

        output = FreAotRegexDynamicRowsPreflightV1::default();
        assert_eq!(
            call_exclusive_dynamic_rows_preflight(
                handle,
                &haystack,
                start,
                end,
                &mut result,
                &identity,
                &mut output,
            ),
            STATUS_PARTIAL_PREFLIGHT_ENTER,
            "alternating local-success/short calls must not trigger deopt backoff"
        );

        // True side exits still advance the adaptive policy and two
        // consecutive deopts activate its first bypass interval.
        assert_eq!(
            call_exclusive_dynamic_rows_deopt(handle, &haystack, start, end, &mut result),
            STATUS_MATCH
        );
        assert_eq!(
            call_exclusive_dynamic_rows_preflight(
                handle,
                &haystack,
                start,
                end,
                &mut result,
                &identity,
                &mut output,
            ),
            STATUS_PARTIAL_PREFLIGHT_ENTER
        );
        assert_eq!(
            call_exclusive_dynamic_rows_deopt(handle, &haystack, start, end, &mut result),
            STATUS_MATCH
        );
        assert_eq!(
            call_exclusive_dynamic_rows_preflight(
                handle,
                &haystack,
                start,
                end,
                &mut result,
                &identity,
                &mut output,
            ),
            STATUS_MATCH,
            "two genuine side exits must retain the existing backoff behavior"
        );

        // SAFETY: the handle remains uniquely owned and no call overlaps its
        // destruction.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
            STATUS_SUCCESS
        );
    }

    #[test]
    #[allow(
        clippy::cast_ptr_alignment,
        reason = "the test deliberately constructs a misaligned out pointer and verifies rejection before use"
    )]
    fn null_misaligned_and_invalid_windows_return_status_two() {
        let program = program("a", OutputContract::Span);
        let haystack = b"a";
        let mut result = FreAotRegexResultV1::default();

        // SAFETY: null is passed deliberately; the helper checks it before
        // constructing any reference or slice.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_search_v1(
                    std::ptr::null(),
                    haystack.as_ptr(),
                    haystack.len(),
                    0,
                    1,
                    &raw mut result,
                )
            },
            STATUS_INVALID_ARGUMENT
        );
        // SAFETY: null is passed deliberately and checked before dereference.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_search_v1(
                    program.as_ptr(),
                    std::ptr::null(),
                    0,
                    0,
                    0,
                    &raw mut result,
                )
            },
            STATUS_INVALID_ARGUMENT
        );
        // SAFETY: null is passed deliberately and checked before dereference.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_search_v1(
                    program.as_ptr(),
                    haystack.as_ptr(),
                    haystack.len(),
                    0,
                    1,
                    std::ptr::null_mut(),
                )
            },
            STATUS_INVALID_ARGUMENT
        );
        assert_eq!(
            call(&program, haystack, 1, 0, &mut result),
            STATUS_INVALID_ARGUMENT
        );
        assert_eq!(
            call(&program, haystack, 0, 2, &mut result),
            STATUS_INVALID_ARGUMENT
        );

        let mut storage = [0_u8; size_of::<FreAotRegexResultV1>() * 2];
        let base = storage.as_mut_ptr();
        let aligned = base.align_offset(align_of::<FreAotRegexResultV1>());
        assert_ne!(aligned, usize::MAX);
        // The extra byte after an aligned address is necessarily misaligned
        // for this two-usize result.
        let misaligned_offset = aligned.checked_add(1).expect("small alignment offset");
        let misaligned = base
            .wrapping_add(misaligned_offset)
            .cast::<FreAotRegexResultV1>();
        // SAFETY: the deliberately misaligned pointer is rejected before use;
        // all readable input extents remain valid.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_search_v1(
                    program.as_ptr(),
                    haystack.as_ptr(),
                    haystack.len(),
                    0,
                    1,
                    misaligned,
                )
            },
            STATUS_INVALID_ARGUMENT
        );
    }

    #[test]
    fn malformed_program_returns_status_three_without_touching_result() {
        let mut program = program("a", OutputContract::Span);
        program[0] ^= 1;
        let mut result = FreAotRegexResultV1 { start: 41, end: 43 };
        // SAFETY: the complete mutated allocation remains readable; only its
        // validated contents are deliberately malformed.
        let status = unsafe {
            fre_aot_regex_runtime_search_v1(
                program.as_ptr(),
                b"a".as_ptr(),
                1,
                0,
                1,
                &raw mut result,
            )
        };
        assert_eq!(status, STATUS_RUNTIME_FAILURE);
        assert_eq!(result, FreAotRegexResultV1 { start: 41, end: 43 });
    }

    #[test]
    fn raw_endpoint_oracle_bypass_preserves_variable_endpoint_semantics() {
        let limits = CompileLimitsV1 {
            determinize: DeterminizeLimits {
                max_states: 0,
                ..DeterminizeLimits::default()
            },
            ..CompileLimitsV1::default()
        };
        for output in [OutputContract::SelectedEnd, OutputContract::Span] {
            let compiled = compile(
                CompileRequest::new(
                    r"(?-u:[ac][\x00-\xff]+)",
                    Target::x86_64_linux(),
                )
                .mode(CompileMode::Optimizing)
                .output(output)
                .limits(limits),
            )
            .expect("compile endpoint-oracle runtime fixture");
            assert_eq!(compiled.program().engine_kind(), EngineKind::OrderedNfa);
            assert!(compiled.program().bit_parallel_exists_stats().is_some());
            assert_eq!(compiled.program().exact_match_width(), None);
            let bytes = compiled.program().serialize().expect("serialize fixture");

            let negative = vec![0_u8; 320];
            let mut positive = negative.clone();
            positive.extend_from_slice(b"aq");
            let short = b"cq";
            for haystack in [&negative[..], &positive[..], &short[..]] {
                let window = SearchWindow::full(haystack);
                let expected = expected_ffi(
                    compiled
                        .program()
                        .search(haystack, window)
                        .expect("portable endpoint search"),
                );
                let mut result = FreAotRegexResultV1 { start: 41, end: 43 };
                assert_eq!(
                    call_without_endpoint_oracle(
                        &bytes,
                        haystack,
                        window.start(),
                        window.end(),
                        &mut result,
                    ),
                    expected.0,
                    "status changed for {output:?}/{haystack:?}",
                );
                assert_eq!(
                    result, expected.1,
                    "result changed for {output:?}/{haystack:?}",
                );
            }

            let mut untouched = FreAotRegexResultV1 { start: 47, end: 53 };
            assert_eq!(
                call_without_endpoint_oracle(&bytes, short, 1, 0, &mut untouched),
                STATUS_INVALID_ARGUMENT,
            );
            assert_eq!(untouched, FreAotRegexResultV1 { start: 47, end: 53 });
        }
    }

    #[test]
    fn runtime_program_round_trip_is_canonical() {
        for (pattern, output) in [
            (r"(?m:^a\b)", OutputContract::Exists),
            (r"\b(?:ab|cd)+$", OutputContract::SelectedEnd),
            (r"(?m:^[[:word:]]+)$", OutputContract::Span),
        ] {
            let bytes = program(pattern, output);
            let decoded = CompiledProgram::deserialize(&bytes).expect("deserialize");
            assert_eq!(decoded.serialize().expect("reserialize"), bytes);
        }
    }

    #[test]
    fn prepared_runtime_reuses_owned_program_and_workspace() {
        let bytes = program(r"(?m:^alpha\b)", OutputContract::Span);
        let mut prepared = PreparedAotRegex::deserialize(&bytes).expect("prepare once");
        for (haystack, expected) in [
            (b"x\nalpha beta".as_slice(), Some((2, 7))),
            (b"alpha".as_slice(), Some((0, 5))),
            (b"xalpha".as_slice(), None),
        ] {
            assert_eq!(
                prepared
                    .search(haystack, SearchWindow::full(haystack))
                    .expect("reused search"),
                MatchResult::Span(expected)
            );
        }
    }

    #[test]
    fn borrowed_aot_match_checks_and_exposes_its_original_bytes() {
        let haystack = b"xabz";
        let matched = AotMatch::from_span(haystack, 1, 3).expect("valid span");
        assert_eq!(matched.start(), 1);
        assert_eq!(matched.end(), 3);
        assert_eq!(matched.len(), 2);
        assert!(!matched.is_empty());
        assert_eq!(matched.range(), 1..3);
        assert_eq!(matched.as_bytes(), b"ab");
        assert_eq!(
            format!("{matched:?}"),
            r#"AotMatch { start: 1, end: 3, bytes: "ab" }"#
        );
        let matched_bytes: &[u8] = matched.into();
        let matched_range: std::ops::Range<usize> = matched.into();
        assert_eq!(matched_bytes, b"ab");
        assert_eq!(matched_range, 1..3);

        let empty = AotMatch::from_span(haystack, 4, 4).expect("empty EOF span");
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        assert_eq!(empty.as_bytes(), b"");
        assert!(AotMatch::from_span(haystack, 3, 2).is_none());
        assert!(AotMatch::from_span(haystack, 0, 5).is_none());

        let invalid_utf8 = [0xff];
        let invalid = AotMatch::from_span(&invalid_utf8, 0, 1).expect("valid byte span");
        assert!(format!("{invalid:?}").contains(r#"bytes: "\xff""#));
    }

    #[test]
    fn prepared_find_and_find_at_return_borrowed_spans() {
        for mode in [CompileMode::Fast, CompileMode::Optimizing] {
            let mut prepared = prepared("ab+", OutputContract::Span, mode);
            let haystack = b"xxabbb ab";
            let first = prepared.find(haystack).expect("find").expect("first match");
            assert_eq!(first.range(), 2..6);
            assert_eq!(first.as_bytes(), b"abbb");

            let second = prepared
                .find_at(haystack, first.end())
                .expect("find_at")
                .expect("second match");
            assert_eq!(second.range(), 7..9);
            assert_eq!(second.as_bytes(), b"ab");
            assert_eq!(
                prepared.find_at(haystack, second.end()).expect("EOF find"),
                None
            );
        }
    }

    #[test]
    fn prepared_find_iter_matches_rust_byte_empty_progress_semantics() {
        let cases: Vec<(&str, &[u8], Vec<(usize, usize)>)> = vec![
            ("", b"", vec![(0, 0)]),
            ("", &[0xC3, 0xA9], vec![(0, 0), (1, 1), (2, 2)]),
            ("", &[0xFF, b'a'], vec![(0, 0), (1, 1), (2, 2)]),
            ("a|", b"a", vec![(0, 1)]),
            ("a?", b"ba", vec![(0, 0), (1, 2)]),
            ("(?:ab|)", b"ab", vec![(0, 2)]),
            ("(?:ab|)", b"xab", vec![(0, 0), (1, 3)]),
        ];
        for mode in [CompileMode::Fast, CompileMode::Optimizing] {
            for (pattern, haystack, expected) in &cases {
                let mut prepared = prepared(pattern, OutputContract::Span, mode);
                assert_eq!(
                    collected_spans(&mut prepared, haystack),
                    *expected,
                    "mode={mode:?}, pattern={pattern:?}, haystack={haystack:?}"
                );
            }
        }
    }

    #[test]
    fn prepared_scalar_reducers_match_span_iteration_and_publish_transactionally() {
        let cases: Vec<(&str, &[u8], Vec<(usize, usize)>)> = vec![
            ("", b"", vec![(0, 0)]),
            ("", &[0xC3, 0xA9], vec![(0, 0), (1, 1), (2, 2)]),
            ("a|", b"a", vec![(0, 1)]),
            ("a?", b"ba", vec![(0, 0), (1, 2)]),
            ("(?:ab|)", b"xab", vec![(0, 0), (1, 3)]),
            ("z+", b"no matches", vec![]),
        ];
        for mode in [CompileMode::Fast, CompileMode::Optimizing] {
            for (pattern, haystack, expected) in &cases {
                let expected_count = u64::try_from(expected.len()).expect("small Count oracle");
                let expected_span_sum = expected.iter().try_fold(0_u64, |sum, &(start, end)| {
                    let width = u64::try_from(end.checked_sub(start)?).ok()?;
                    sum.checked_add(width)
                });
                let expected_span_sum = expected_span_sum.expect("small SpanSum oracle");
                let mut prepared = prepared(pattern, OutputContract::Span, mode);
                assert_eq!(
                    prepared.count_matches(haystack).expect("prepared Count"),
                    expected_count,
                    "mode={mode:?}, pattern={pattern:?}, haystack={haystack:?}",
                );
                assert_eq!(
                    prepared.span_sum(haystack).expect("prepared SpanSum"),
                    expected_span_sum,
                    "mode={mode:?}, pattern={pattern:?}, haystack={haystack:?}",
                );
                prepared.settle_dynamic_native_rows_local_completion();
                assert_eq!(
                    prepared
                        .reduce_spans_exclusive_after_deactivation(
                            haystack,
                            ExclusiveSpanReducer::Count,
                        )
                        .expect("exclusive-route Count"),
                    expected_count,
                    "exclusive mode={mode:?}, pattern={pattern:?}, haystack={haystack:?}",
                );
                assert_eq!(
                    prepared
                        .reduce_spans_exclusive_after_deactivation(
                            haystack,
                            ExclusiveSpanReducer::SpanSum,
                        )
                        .expect("exclusive-route SpanSum"),
                    expected_span_sum,
                    "exclusive mode={mode:?}, pattern={pattern:?}, haystack={haystack:?}",
                );
            }
        }

        let serialized = program("a|bc", OutputContract::Span);
        let handle = prepare_exclusive(&serialized);
        let haystack = b"babc";
        let mut count = u64::MAX;
        let mut span_sum = u64::MAX;
        // SAFETY: the handle is live and exclusively owned; the input and
        // naturally aligned scalar outputs are valid and disjoint.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_count_exclusive_v1(
                    handle,
                    haystack.as_ptr(),
                    haystack.len(),
                    &raw mut count,
                )
            },
            STATUS_SUCCESS,
        );
        assert_eq!(count, 2);
        // SAFETY: identical live/disjoint exclusive-call contract.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_span_sum_exclusive_v1(
                    handle,
                    haystack.as_ptr(),
                    haystack.len(),
                    &raw mut span_sum,
                )
            },
            STATUS_SUCCESS,
        );
        assert_eq!(span_sum, 3);

        let no_match = b"zz";
        count = 91;
        span_sum = 92;
        // SAFETY: the handle is live and exclusively owned; both scalar
        // outputs are aligned and disjoint from this no-match input.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_count_exclusive_v1(
                    handle,
                    no_match.as_ptr(),
                    no_match.len(),
                    &raw mut count,
                )
            },
            STATUS_SUCCESS,
        );
        assert_eq!(count, 0);
        // SAFETY: identical live/disjoint exclusive-call contract.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_span_sum_exclusive_v1(
                    handle,
                    no_match.as_ptr(),
                    no_match.len(),
                    &raw mut span_sum,
                )
            },
            STATUS_SUCCESS,
        );
        assert_eq!(span_sum, 0);

        // SAFETY: the live handle uniquely owns a PreparedAotRegex for this
        // test, so reading its immutable embedded identity does not alias a
        // concurrent operation.
        let identity = unsafe {
            *(&*handle.0.cast::<PreparedAotRegex>())
                .frozen_header
                .artifact_identity()
        };
        count = u64::MAX;
        // SAFETY: the object identity and ordinary reducer extents are live,
        // aligned where required, disjoint, and owned for this call.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_compiler_private_count_exclusive_v1(
                    handle,
                    haystack.as_ptr(),
                    haystack.len(),
                    &raw mut count,
                    identity.as_ptr(),
                )
            },
            STATUS_SUCCESS,
        );
        assert_eq!(count, 2);
        let mut wrong_identity = identity;
        wrong_identity[0] ^= 1;
        count = 47;
        // SAFETY: the mismatched but readable identity is deliberately tested
        // as a recoverable authentication failure.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_compiler_private_count_exclusive_v1(
                    handle,
                    haystack.as_ptr(),
                    haystack.len(),
                    &raw mut count,
                    wrong_identity.as_ptr(),
                )
            },
            STATUS_RUNTIME_FAILURE,
        );
        assert_eq!(count, 47);
        count = 49;
        // SAFETY: the preceding identity mismatch must not mutate the live
        // exclusive owner; retrying with its exact identity must still
        // complete normally.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_compiler_private_count_exclusive_v1(
                    handle,
                    haystack.as_ptr(),
                    haystack.len(),
                    &raw mut count,
                    identity.as_ptr(),
                )
            },
            STATUS_SUCCESS,
        );
        assert_eq!(count, 2);
        count = 48;
        // SAFETY: the null identity pointer is the deliberately malformed
        // compiler-private input and is rejected before output publication.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_compiler_private_count_exclusive_v1(
                    handle,
                    haystack.as_ptr(),
                    haystack.len(),
                    &raw mut count,
                    std::ptr::null(),
                )
            },
            STATUS_INVALID_ARGUMENT,
        );
        assert_eq!(count, 48);

        count = 91;
        // SAFETY: deliberately invalid handle is a recoverable ABI input;
        // all pointer extents are otherwise valid and disjoint.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_count_exclusive_v1(
                    FreAotRegexExclusiveHandleV1::INVALID,
                    haystack.as_ptr(),
                    haystack.len(),
                    &raw mut count,
                )
            },
            STATUS_INVALID_HANDLE,
        );
        assert_eq!(count, 91);
        count = 93;
        // SAFETY: a null haystack is deliberately rejected even for the
        // otherwise empty readable extent.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_count_exclusive_v1(
                    handle,
                    std::ptr::null(),
                    0,
                    &raw mut count,
                )
            },
            STATUS_INVALID_ARGUMENT,
        );
        assert_eq!(count, 93);
        count = 94;
        let oversized_len = usize::try_from(isize::MAX)
            .expect("nonnegative isize maximum")
            .checked_add(1)
            .expect("usize represents one beyond isize maximum");
        // SAFETY: the impossible source extent is rejected before its
        // otherwise nonnull pointer can be dereferenced.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_count_exclusive_v1(
                    handle,
                    haystack.as_ptr(),
                    oversized_len,
                    &raw mut count,
                )
            },
            STATUS_INVALID_ARGUMENT,
        );
        assert_eq!(count, 94);
        #[repr(align(8))]
        struct AlignedBytes([u8; 16]);
        let mut misaligned = AlignedBytes([0xa5; 16]);
        // SAFETY: the pointer is intentionally offset from an 8-byte-aligned
        // allocation and is rejected before any typed access.
        let misaligned_output = unsafe { misaligned.0.as_mut_ptr().add(1).cast::<u64>() };
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_count_exclusive_v1(
                    handle,
                    haystack.as_ptr(),
                    haystack.len(),
                    misaligned_output,
                )
            },
            STATUS_INVALID_ARGUMENT,
        );
        assert_eq!(misaligned.0, [0xa5; 16]);
        count = 95;
        let empty = b"";
        // SAFETY: the empty slice still supplies a nonnull pointer and the
        // aligned/disjoint output is valid for successful zero publication.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_count_exclusive_v1(
                    handle,
                    empty.as_ptr(),
                    empty.len(),
                    &raw mut count,
                )
            },
            STATUS_SUCCESS,
        );
        assert_eq!(count, 0);
        // SAFETY: the null output is deliberately rejected before any write.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_span_sum_exclusive_v1(
                    handle,
                    haystack.as_ptr(),
                    haystack.len(),
                    std::ptr::null_mut(),
                )
            },
            STATUS_INVALID_ARGUMENT,
        );
        // SAFETY: this test still owns the handle and destroys it exactly once.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
            STATUS_SUCCESS,
        );

        let exists = prepare_exclusive(&program("a", OutputContract::Exists));
        count = 73;
        // SAFETY: the live handle and raw extents are valid; the output
        // contract mismatch is the recoverable runtime failure under test.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_count_exclusive_v1(
                    exists,
                    haystack.as_ptr(),
                    haystack.len(),
                    &raw mut count,
                )
            },
            STATUS_RUNTIME_FAILURE,
        );
        assert_eq!(count, 73);
        // SAFETY: this test still owns the handle and destroys it exactly once.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(exists) },
            STATUS_SUCCESS,
        );
    }

    #[test]
    fn exclusive_scalar_reducers_use_the_retained_prefilled_search_route() {
        let pattern = r"a+Q|[b-c][a-b]{1,5}(?:x+|y+)";
        let mut limits = CompileLimitsV1::default();
        limits.determinize.max_states = 16;
        let compiled = compile(
            CompileRequest::new(pattern, Target::x86_64_linux())
                .mode(CompileMode::Optimizing)
                .limits(limits)
                .output(OutputContract::Span),
        )
        .expect("compile retained-resource reducer fixture");
        assert_eq!(
            compiled.receipt().engine_selection_reason,
            EngineSelectionReason::DeterminizationResourceLimit
        );
        let serialized = compiled.program().serialize().expect("serialize fixture");
        let mut haystack = vec![b'x'; 256];
        haystack.extend_from_slice(b"cbbbbx");

        let mut ordinary = PreparedAotRegex::deserialize(&serialized).expect("prepare control");
        assert!(ordinary.fully_prefilled_fallback.is_some());
        assert_eq!(ordinary.count_matches(&haystack).expect("control Count"), 1);
        assert_eq!(ordinary.fully_prefilled_fallback_searches, 0);

        for (reducer, expected) in [
            (ExclusiveSpanReducer::Count, 1_u64),
            (ExclusiveSpanReducer::SpanSum, 6_u64),
        ] {
            let handle = prepare_exclusive(&serialized);
            // SAFETY: this test uniquely owns the live direct handle.
            let before = unsafe { &*handle.0.cast::<PreparedAotRegex>() };
            assert!(before.fully_prefilled_fallback.is_some());
            assert_eq!(before.fully_prefilled_fallback_searches, 0);
            let mut actual = u64::MAX;
            // SAFETY: the live handle, readable haystack, and disjoint aligned
            // scalar output satisfy the selected reducer boundary.
            let status = unsafe {
                match reducer {
                    ExclusiveSpanReducer::Count => fre_aot_regex_runtime_count_exclusive_v1(
                        handle,
                        haystack.as_ptr(),
                        haystack.len(),
                        &raw mut actual,
                    ),
                    ExclusiveSpanReducer::SpanSum => {
                        fre_aot_regex_runtime_span_sum_exclusive_v1(
                            handle,
                            haystack.as_ptr(),
                            haystack.len(),
                            &raw mut actual,
                        )
                    }
                }
            };
            assert_eq!(status, STATUS_SUCCESS, "{reducer:?}");
            assert_eq!(actual, expected, "{reducer:?}");
            // SAFETY: the reducer returned and this test still uniquely owns
            // the live handle, so its test-only route counter is readable.
            let after = unsafe { &*handle.0.cast::<PreparedAotRegex>() };
            assert!(after.fully_prefilled_fallback_searches > 0, "{reducer:?}");
            // SAFETY: this test still uniquely owns the live handle.
            assert_eq!(
                unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
                STATUS_SUCCESS
            );
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the Rust and public/private C audits share one exclusive-handle lifecycle"
    )]
    fn prepared_grep_count_is_output_independent_one_pass_and_transactional() {
        let haystack = b"a\r\nno\naa\n\n";
        for output in [
            OutputContract::Exists,
            OutputContract::SelectedEnd,
            OutputContract::Span,
        ] {
            let serialized = program("^a+$", output);
            let mut prepared =
                PreparedAotRegex::deserialize(&serialized).expect("prepare grep program");
            let construction = prepared
                .prepare_grep_count()
                .expect("eager fixed grep workspace");
            assert!(construction.workspace_bytes() > 0);
            let first = prepared
                .grep_count_report(haystack)
                .expect("one-pass prepared grep");
            assert_eq!(first.count(), 2);
            assert_eq!(first.source_line_domains(), 4);
            assert_eq!(first.execution().actual().allocations(), 0);
            assert_eq!(first.generation_reset_cells(), 0);
            assert_eq!(
                prepared.grep_count(haystack).expect("warm prepared grep"),
                2
            );

            let handle = prepare_exclusive(&serialized);
            let mut value = 91;
            // SAFETY: this test exclusively owns the live handle; source and
            // aligned scalar output are readable/writable and disjoint.
            assert_eq!(
                unsafe {
                    fre_aot_regex_runtime_grep_count_exclusive_v1(
                        handle,
                        haystack.as_ptr(),
                        haystack.len(),
                        &raw mut value,
                    )
                },
                STATUS_SUCCESS,
            );
            assert_eq!(value, 2);

            // SAFETY: the handle uniquely owns its prepared allocation, so
            // reading the immutable embedded identity is non-racing.
            let identity = unsafe {
                *(&*handle.0.cast::<PreparedAotRegex>())
                    .frozen_header
                    .artifact_identity()
            };
            value = 92;
            // SAFETY: the exact identity and ordinary reducer extents remain
            // live and disjoint for the complete call.
            assert_eq!(
                unsafe {
                    fre_aot_regex_runtime_compiler_private_grep_count_exclusive_v1(
                        handle,
                        haystack.as_ptr(),
                        haystack.len(),
                        &raw mut value,
                        identity.as_ptr(),
                    )
                },
                STATUS_SUCCESS,
            );
            assert_eq!(value, 2);

            let mut wrong_identity = identity;
            wrong_identity[0] ^= 1;
            value = 93;
            // SAFETY: the deliberately foreign but readable identity is
            // rejected before workspace mutation or output publication.
            assert_eq!(
                unsafe {
                    fre_aot_regex_runtime_compiler_private_grep_count_exclusive_v1(
                        handle,
                        haystack.as_ptr(),
                        haystack.len(),
                        &raw mut value,
                        wrong_identity.as_ptr(),
                    )
                },
                STATUS_RUNTIME_FAILURE,
            );
            assert_eq!(value, 93);

            value = 94;
            // SAFETY: the failed foreign-identity call cannot consume or
            // corrupt the live owner; its exact identity remains valid.
            assert_eq!(
                unsafe {
                    fre_aot_regex_runtime_compiler_private_grep_count_exclusive_v1(
                        handle,
                        haystack.as_ptr(),
                        haystack.len(),
                        &raw mut value,
                        identity.as_ptr(),
                    )
                },
                STATUS_SUCCESS,
            );
            assert_eq!(value, 2);

            // SAFETY: null output is deliberately invalid and rejected before
            // construction of a mutable result reference.
            assert_eq!(
                unsafe {
                    fre_aot_regex_runtime_grep_count_exclusive_v1(
                        handle,
                        haystack.as_ptr(),
                        haystack.len(),
                        std::ptr::null_mut(),
                    )
                },
                STATUS_INVALID_ARGUMENT,
            );
            // SAFETY: this test still owns the handle and destroys it once.
            assert_eq!(
                unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
                STATUS_SUCCESS,
            );
        }
    }

    #[test]
    fn exclusive_runtime_span_fill_matches_byte_empty_progress_and_fuses() {
        let cases: Vec<(&str, &[u8], Vec<(usize, usize)>)> = vec![
            ("", b"", vec![(0, 0)]),
            ("", &[0xC3, 0xA9], vec![(0, 0), (1, 1), (2, 2)]),
            ("a|", b"a", vec![(0, 1)]),
            ("a?", b"ba", vec![(0, 0), (1, 2)]),
            ("(?:ab|)", b"xab", vec![(0, 0), (1, 3)]),
        ];
        for (pattern, haystack, expected) in cases {
            let serialized = program(pattern, OutputContract::Span);
            let handle = prepare_exclusive(&serialized);
            let mut state = FreAotRegexIterStateV1::default();
            let mut written = usize::MAX;
            // SAFETY: the live handle is exclusively owned; the empty result
            // extent and all other arguments satisfy the documented probe ABI.
            assert_eq!(
                unsafe {
                    fre_aot_regex_runtime_fill_spans_exclusive_v1(
                        handle,
                        haystack.as_ptr(),
                        haystack.len(),
                        &raw mut state,
                        std::ptr::null_mut(),
                        0,
                        &raw mut written,
                    )
                },
                STATUS_MATCH
            );
            assert_eq!(written, 0);
            assert_eq!(state, FreAotRegexIterStateV1::default());

            let mut actual = Vec::new();
            loop {
                let sentinel = FreAotRegexResultV1 {
                    start: usize::MAX,
                    end: usize::MAX,
                };
                let mut output = [sentinel; 2];
                written = usize::MAX;
                // SAFETY: every argument is live, aligned, disjoint, and the
                // handle remains exclusively owned through this refill.
                let status = unsafe {
                    fre_aot_regex_runtime_fill_spans_exclusive_v1(
                        handle,
                        haystack.as_ptr(),
                        haystack.len(),
                        &raw mut state,
                        output.as_mut_ptr(),
                        output.len(),
                        &raw mut written,
                    )
                };
                assert!(written <= output.len());
                actual.extend(output[..written].iter().map(|result| (result.start, result.end)));
                assert!(output[written..].iter().all(|result| *result == sentinel));
                match status {
                    STATUS_NO_MATCH => break,
                    STATUS_MATCH => assert_eq!(written, output.len()),
                    other => panic!("Span fill failed with status {other}"),
                }
            }
            assert_eq!(actual, expected, "pattern={pattern:?}, haystack={haystack:?}");
            assert_eq!(state.flags & ITER_FINISHED, ITER_FINISHED);
            assert_eq!(state.flags & ITER_PENDING_EMPTY, 0);

            written = usize::MAX;
            // SAFETY: the same live handle and fused state remain exclusively
            // owned; capacity zero permits a null result pointer.
            assert_eq!(
                unsafe {
                    fre_aot_regex_runtime_fill_spans_exclusive_v1(
                        handle,
                        haystack.as_ptr(),
                        haystack.len(),
                        &raw mut state,
                        std::ptr::null_mut(),
                        0,
                        &raw mut written,
                    )
                },
                STATUS_NO_MATCH
            );
            assert_eq!(written, 0);
            // SAFETY: this test still uniquely owns the live handle and no
            // search overlaps its one destruction.
            assert_eq!(
                unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
                STATUS_SUCCESS
            );
        }
    }

    #[test]
    fn exclusive_runtime_bulk_entries_validate_transactional_prefixes() {
        let span_serialized = program("a", OutputContract::Span);
        let span_handle = prepare_exclusive(&span_serialized);
        let mut invalid_state = FreAotRegexIterStateV1 {
            next_start: 0,
            last_match_end: 0,
            flags: ITER_PENDING_EMPTY,
            reserved: 0,
        };
        let original_state = invalid_state;
        let sentinel = FreAotRegexResultV1 { start: 7, end: 11 };
        let mut result = sentinel;
        let mut written = 13;
        // SAFETY: pointers are valid and disjoint; the deliberately malformed
        // state is a recoverable raw-ABI argument rejection under test.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_fill_spans_exclusive_v1(
                    span_handle,
                    b"a".as_ptr(),
                    1,
                    &raw mut invalid_state,
                    &raw mut result,
                    1,
                    &raw mut written,
                )
            },
            STATUS_INVALID_ARGUMENT
        );
        assert_eq!(invalid_state, original_state);
        assert_eq!(result, sentinel);
        assert_eq!(written, 13);
        // SAFETY: this test still uniquely owns the live handle and no search
        // overlaps its one destruction.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(span_handle) },
            STATUS_SUCCESS
        );

        let exists_serialized = program("x", OutputContract::Exists);
        let exists_handle = prepare_exclusive(&exists_serialized);
        let inputs: [&[u8]; 4] = [b"x", b"no", b"", b"xx"];
        let mut descriptors = inputs.map(|input| FreAotRegexHaystackV1 {
            ptr: input.as_ptr(),
            len: input.len(),
        });
        let mut matched = [0xaa; 4];
        let mut processed = usize::MAX;
        // SAFETY: every descriptor and output extent is live and disjoint for
        // this synchronous, exclusively owned batch.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_is_match_batch_exclusive_v1(
                    exists_handle,
                    descriptors.as_ptr(),
                    descriptors.len(),
                    matched.as_mut_ptr(),
                    &raw mut processed,
                )
            },
            STATUS_SUCCESS
        );
        assert_eq!(processed, 4);
        assert_eq!(matched, [1, 0, 0, 1]);

        descriptors[2].ptr = std::ptr::null();
        matched = [0xaa; 4];
        processed = usize::MAX;
        // SAFETY: the top-level extents are valid; the null third descriptor
        // is a recoverable later-item validation failure under test.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_is_match_batch_exclusive_v1(
                    exists_handle,
                    descriptors.as_ptr(),
                    descriptors.len(),
                    matched.as_mut_ptr(),
                    &raw mut processed,
                )
            },
            STATUS_INVALID_ARGUMENT
        );
        assert_eq!(processed, 2);
        assert_eq!(matched, [1, 0, 0xaa, 0xaa]);

        processed = usize::MAX;
        // SAFETY: count zero permits null input/output arrays; the processed
        // output is live, aligned, and disjoint.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_is_match_batch_exclusive_v1(
                    exists_handle,
                    std::ptr::null(),
                    0,
                    std::ptr::null_mut(),
                    &raw mut processed,
                )
            },
            STATUS_SUCCESS
        );
        assert_eq!(processed, 0);
        // SAFETY: this test still uniquely owns the live handle and no search
        // overlaps its one destruction.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(exists_handle) },
            STATUS_SUCCESS
        );
    }

    #[test]
    fn prepared_iteration_retains_original_assertion_context() {
        for mode in [CompileMode::Fast, CompileMode::Optimizing] {
            let mut absolute = prepared("^a", OutputContract::Span, mode);
            assert_eq!(absolute.find_at(b"xa", 1).expect("absolute find"), None);

            let mut boundary = prepared(r"\ba", OutputContract::Span, mode);
            assert_eq!(boundary.find_at(b"xa", 1).expect("boundary find"), None);
            assert_eq!(
                boundary
                    .find_at(b"x a", 1)
                    .expect("contextual find")
                    .expect("match")
                    .range(),
                2..3
            );

            let mut multiline = prepared(r"(?m:^a)", OutputContract::Span, mode);
            assert_eq!(collected_spans(&mut multiline, b"x\na\nxa"), vec![(2, 3)]);
        }
    }

    #[test]
    fn prepared_find_reports_output_contract_and_invalid_start() {
        for output in [OutputContract::Exists, OutputContract::SelectedEnd] {
            let mut prepared = prepared("a", output, CompileMode::Fast);
            assert!(matches!(
                prepared.find(b"a"),
                Err(AotRegexFindError::OutputContract { actual }) if actual == output
            ));
            assert!(matches!(
                prepared.find_at(b"a", 0),
                Err(AotRegexFindError::OutputContract { actual }) if actual == output
            ));
            assert!(matches!(
                prepared.find_iter(b"a"),
                Err(AotRegexFindError::OutputContract { actual }) if actual == output
            ));
        }

        let mut prepared = prepared("a", OutputContract::Span, CompileMode::Fast);
        assert!(matches!(
            prepared.find_at(b"a", 2),
            Err(AotRegexFindError::Search(CompileError::InvalidWindow {
                start: 2,
                end: 1,
                haystack_len: 1,
            }))
        ));
    }

    #[test]
    fn prepared_find_iterator_is_fused_and_releases_the_workspace_on_drop() {
        fn assert_fused<I: std::iter::FusedIterator>(_: &I) {}

        let mut prepared = prepared("a", OutputContract::Span, CompileMode::Fast);
        {
            let mut matches = prepared.find_iter(b"a").expect("Span iterator");
            assert_fused(&matches);
            assert_eq!(
                matches.next().expect("one item").expect("search").range(),
                0..1
            );
            assert!(matches.next().is_none());
            assert!(matches.next().is_none());
        }
        assert_eq!(
            prepared
                .find(b"za")
                .expect("reused workspace")
                .expect("match")
                .range(),
            1..2
        );
    }

    #[test]
    fn prepared_c_handle_owns_program_and_matches_generated_nfa_windows() {
        let mut cases = Vec::new();
        for maximum in 1..=3 {
            cases.push((
                format!(r"(?m:^(?:ab|a){{1,{maximum}}}\b)"),
                CompileLimitsV1::default(),
                EngineSelectionReason::ContextAssertions,
            ));
        }
        let mut limited = CompileLimitsV1::default();
        limited.determinize.max_states = 0;
        cases.push((
            "(?:ab|ac|ad)+z".to_owned(),
            limited,
            EngineSelectionReason::DeterminizationResourceLimit,
        ));
        let haystacks = generated_haystacks();

        for (pattern, limits, expected_reason) in cases {
            for output in [
                OutputContract::Exists,
                OutputContract::SelectedEnd,
                OutputContract::Span,
            ] {
                let compiled = compile(
                    CompileRequest::new(&pattern, Target::x86_64_linux())
                        .mode(CompileMode::Optimizing)
                        .limits(limits)
                        .output(output),
                )
                .unwrap_or_else(|error| panic!("compile {pattern:?}: {error}"));
                assert_eq!(compiled.program().engine_kind(), EngineKind::OrderedNfa);
                assert_eq!(compiled.receipt().engine_selection_reason, expected_reason);
                let serialized = compiled.program().serialize().expect("serialize");
                let handle = prepare_handle(&serialized);
                let exclusive = prepare_exclusive(&serialized);
                drop(serialized);

                for haystack in &haystacks {
                    for start in 0..=haystack.len() {
                        for end in start..=haystack.len() {
                            let expected = expected_ffi(
                                compiled
                                    .search(haystack, SearchWindow::new(start, end))
                                    .expect("portable search"),
                            );
                            let mut actual = FreAotRegexResultV1 {
                                start: usize::MAX,
                                end: usize::MAX,
                            };
                            let status = call_prepared(handle, haystack, start, end, &mut actual);
                            assert_eq!(
                                (status, actual),
                                expected,
                                "pattern={pattern:?}, output={output:?}, haystack={haystack:?}, window={start}..{end}"
                            );
                            let mut exclusive_actual = FreAotRegexResultV1 {
                                start: usize::MAX,
                                end: usize::MAX,
                            };
                            let exclusive_status = call_exclusive(
                                exclusive,
                                haystack,
                                start,
                                end,
                                &mut exclusive_actual,
                            );
                            assert_eq!(
                                (exclusive_status, exclusive_actual),
                                expected,
                                "exclusive pattern={pattern:?}, output={output:?}, haystack={haystack:?}, window={start}..{end}"
                            );
                        }
                    }
                }
                assert_eq!(
                    fre_aot_regex_runtime_destroy_prepared_v1(handle),
                    STATUS_SUCCESS
                );
                // SAFETY: this is the unique live exclusive handle and no
                // search overlaps destruction.
                assert_eq!(
                    unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(exclusive) },
                    STATUS_SUCCESS
                );
            }
        }
    }

    #[test]
    fn exclusive_prepared_runtime_executes_retained_resource_rows() {
        let pattern = r"a+Q|[b-c][a-b]{1,5}(?:x+|y+)";
        for output in [
            OutputContract::Exists,
            OutputContract::SelectedEnd,
            OutputContract::Span,
        ] {
            let mut limits = CompileLimitsV1::default();
            limits.determinize.max_states = if output == OutputContract::Exists {
                8
            } else {
                16
            };
            let compiled = compile(
                CompileRequest::new(pattern, Target::x86_64_linux())
                    .mode(CompileMode::Optimizing)
                    .limits(limits)
                    .output(output),
            )
            .expect("compile retained resource fallback");
            let reference = compile(
                CompileRequest::new(pattern, Target::x86_64_linux())
                    .mode(CompileMode::Fast)
                    .output(output),
            )
            .expect("compile universal reference");
            assert_eq!(
                compiled.receipt().engine_selection_reason,
                EngineSelectionReason::DeterminizationResourceLimit
            );
            let stats = compiled
                .program()
                .partial_dfa_stats()
                .expect("partial stats")
                .expect("retained rows");
            assert!(stats.complete_rows > 0);
            assert!(stats.complete_rows < stats.discovered_states);
            assert!(stats.resume_frontiers > 0);

            let serialized = compiled.program().serialize().expect("serialize partial");
            assert_ne!(serialized[15] & (1 << 3), 0, "V4 partial flag");
            let mut direct =
                PreparedAotRegex::deserialize(&serialized).expect("prepare direct resource owner");
            assert!(
                direct.fully_prefilled_fallback.is_some(),
                "resource fallback must retain its setup receipt for {output:?}"
            );
            if output == OutputContract::Span {
                assert_eq!(compiled.program().exact_match_width(), None);
            }
            assert!(
                direct.frozen_dynamic_rows.is_some(),
                "eligible resource fallback must retain a compact owner for {output:?}"
            );
            assert!(direct.frozen_header.has_dynamic_rows(), "{output:?}");
            let exclusive = prepare_exclusive(&serialized);
            let short = b"cbbbbx";
            let mut long = vec![b'x'; 256];
            long.extend_from_slice(short);
            let long_expected = reference
                .search(&long, SearchWindow::full(&long))
                .expect("universal long reference search");
            direct.deactivate_frozen_header();
            assert_eq!(
                direct
                    .search_exclusive(&long, SearchWindow::full(&long))
                    .expect("post-revocation receipt-backed search"),
                long_expected,
                "post-revocation {output:?}"
            );
            assert!(!direct.frozen_header.is_active());
            for haystack in [short.as_slice(), long.as_slice()] {
                let expected = expected_ffi(
                    reference
                        .search(haystack, SearchWindow::full(haystack))
                        .expect("universal reference search"),
                );
                let mut actual = FreAotRegexResultV1::default();
                assert_eq!(
                    (
                        call_exclusive(exclusive, haystack, 0, haystack.len(), &mut actual),
                        actual,
                    ),
                    expected,
                    "output={output:?}, len={}",
                    haystack.len()
                );
            }
            // SAFETY: this test owns the unique live exclusive handle and no
            // call overlaps destruction.
            assert_eq!(
                unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(exclusive) },
                STATUS_SUCCESS
            );
        }

        // Unlike the variable-width Span case above, an exact positive width
        // needs no reverse-row capability and may safely prefer compact rows.
        // Search a small ceiling range so the fixture remains a genuine
        // retained-resource fallback as determinization evolves.
        let fixed_pattern = r"(?:ab|ba|cd|dc|ef|fe){4}";
        let (fixed, serialized, mut direct) = (2..=64)
            .find_map(|max_states| {
                let mut limits = CompileLimitsV1::default();
                limits.determinize.max_states = max_states;
                let candidate = compile(
                    CompileRequest::new(fixed_pattern, Target::x86_64_linux())
                        .mode(CompileMode::Optimizing)
                        .limits(limits)
                        .output(OutputContract::Span),
                )
                .ok()?;
                if candidate.program().exact_match_width() != Some(8)
                    || candidate.receipt().engine_selection_reason
                        != EngineSelectionReason::DeterminizationResourceLimit
                {
                    return None;
                }
                let stats = candidate.program().partial_dfa_stats().ok()??;
                if stats.complete_rows == 0
                    || stats.complete_rows >= stats.discovered_states
                    || stats.resume_frontiers == 0
                {
                    return None;
                }
                let serialized = candidate.program().serialize().ok()?;
                let direct = PreparedAotRegex::deserialize(&serialized).ok()?;
                (direct.fully_prefilled_fallback.is_some()
                    && direct.frozen_dynamic_rows.is_some()
                    && direct.frozen_header.has_dynamic_rows())
                .then_some((candidate, serialized, direct))
            })
            .expect("fixed-width Span with retained receipt and compact owner");
        assert_eq!(fixed.program().exact_match_width(), Some(8));
        assert!(direct.fully_prefilled_fallback.is_some());
        assert!(direct.frozen_dynamic_rows.is_some());
        assert!(direct.frozen_header.has_dynamic_rows());

        let reference = compile(
            CompileRequest::new(fixed_pattern, Target::x86_64_linux())
                .mode(CompileMode::Fast)
                .output(OutputContract::Span),
        )
        .expect("compile fixed-width universal reference");
        let mut haystack = vec![b'!'; 256];
        haystack.extend_from_slice(b"abababab");
        let window = SearchWindow::full(&haystack);
        let expected = reference
            .search(&haystack, window)
            .expect("fixed-width universal reference search");
        direct.deactivate_frozen_header();
        assert_eq!(
            direct
                .search_exclusive(&haystack, window)
                .expect("fixed-width post-revocation receipt-backed search"),
            expected
        );
        assert!(!direct.frozen_header.is_active());

        let exclusive = prepare_exclusive(&serialized);
        let mut actual = FreAotRegexResultV1::default();
        assert_eq!(
            (
                call_exclusive(
                    exclusive,
                    &haystack,
                    window.start(),
                    window.end(),
                    &mut actual,
                ),
                actual,
            ),
            expected_ffi(expected)
        );
        // SAFETY: this test owns the unique live exclusive handle and no call
        // overlaps destruction.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(exclusive) },
            STATUS_SUCCESS
        );
    }

    #[test]
    fn static_prefix_preflight_authenticates_without_consuming_prepared_state() {
        let compiled = compile(
            CompileRequest::new("(?:ab|ac)+z", Target::x86_64_linux())
                .mode(CompileMode::Fast)
                .output(OutputContract::Span),
        )
        .expect("compile static-prefix preflight fixture");
        let identity = compiled.receipt().program_sha256;
        let serialized = compiled.program().serialize().expect("serialize fixture");
        let handle = prepare_exclusive(&serialized);
        let haystack = b"!!abacz??";
        let sentinel = FreAotRegexResultV1 {
            start: 0xfeed_face,
            end: 0xdead_beef,
        };
        let mut result = sentinel;

        assert_eq!(
            call_exclusive_static_prefix_preflight(
                handle,
                haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
            ),
            STATUS_PARTIAL_PREFLIGHT_ENTER
        );
        assert_eq!(result, sentinel);
        assert!(exclusive_frozen_header_is_active(handle));

        let mut wrong_identity = identity;
        wrong_identity[17] ^= 0x80;
        assert_eq!(
            call_exclusive_static_prefix_preflight(
                handle,
                haystack,
                0,
                haystack.len(),
                &mut result,
                &wrong_identity,
            ),
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(result, sentinel);
        assert!(exclusive_frozen_header_is_active(handle));

        let mut fallback = FreAotRegexResultV1::default();
        assert_eq!(
            call_exclusive(handle, haystack, 0, haystack.len(), &mut fallback),
            STATUS_MATCH
        );
        assert_eq!(fallback, FreAotRegexResultV1 { start: 2, end: 7 });
        assert!(!exclusive_frozen_header_is_active(handle));

        // The immutable identity remains authoritative after a general search
        // retires unrelated frozen-row capabilities. A later static-prefix
        // call can still complete natively or deopt through the same handle.
        result = sentinel;
        assert_eq!(
            call_exclusive_static_prefix_preflight(
                handle,
                haystack,
                2,
                7,
                &mut result,
                &identity,
            ),
            STATUS_PARTIAL_PREFLIGHT_ENTER
        );
        assert_eq!(result, sentinel);

        result = sentinel;
        assert_eq!(
            call_exclusive_static_prefix_recover_span(
                handle,
                haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
                7,
            ),
            STATUS_MATCH
        );
        assert_eq!(result, FreAotRegexResultV1 { start: 2, end: 7 });

        // SAFETY: this test owns the unique live handle and no operation
        // overlaps destruction.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
            STATUS_SUCCESS
        );
    }

    #[test]
    fn static_prefix_v1_complete_proofs_use_the_retained_row_crossover() {
        let mut limits = CompileLimitsV1::default();
        limits.determinize.max_states = 0;
        let compiled = compile(
            CompileRequest::new("(?:x|yz)7[A-Za-z]{1,2}", Target::x86_64_linux())
                .mode(CompileMode::Optimizing)
                .limits(limits)
                .output(OutputContract::Span),
        )
        .expect("compile static-prefix V1 proof fixture");
        assert!(!compiled
            .program()
            .compiler_private_static_prefix_complete_proofs_should_run(255));
        assert!(compiled
            .program()
            .compiler_private_static_prefix_complete_proofs_should_run(256));
        let identity = compiled.receipt().program_sha256;
        let serialized = compiled.program().serialize().expect("serialize fixture");
        let handle = prepare_exclusive(&serialized);
        let short = vec![b'x'; 255];
        let long = vec![b'x'; 256];
        let sentinel = FreAotRegexResultV1 {
            start: 0xfeed_face,
            end: 0xdead_beef,
        };
        let mut result = sentinel;

        let mut wrong_identity = identity;
        wrong_identity[0] ^= 0x80;
        assert_eq!(
            call_exclusive_static_prefix_preflight(
                handle,
                &long,
                0,
                long.len(),
                &mut result,
                &wrong_identity,
            ),
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(result, sentinel);
        assert!(exclusive_frozen_header_is_active(handle));

        assert_eq!(
            call_exclusive_static_prefix_preflight(
                handle,
                &short,
                0,
                short.len(),
                &mut result,
                &identity,
            ),
            STATUS_PARTIAL_PREFLIGHT_ENTER
        );
        assert_eq!(result, sentinel);
        assert!(exclusive_frozen_header_is_active(handle));

        result = sentinel;
        assert_eq!(
            call_exclusive_static_prefix_preflight(
                handle,
                &long,
                0,
                long.len(),
                &mut result,
                &identity,
            ),
            STATUS_NO_MATCH
        );
        assert_eq!(result, FreAotRegexResultV1::default());
        assert!(!exclusive_frozen_header_is_active(handle));

        // SAFETY: this test owns the unique live handle and no operation
        // overlaps destruction.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
            STATUS_SUCCESS
        );
    }

    #[test]
    fn packed_static_prefix_v2_eager_and_fused_routes_continue() {
        let compiled = compile(
            CompileRequest::new("(?:ab|ac)+z", Target::x86_64_linux())
                .mode(CompileMode::Fast)
                .output(OutputContract::SelectedEnd),
        )
        .expect("compile packed static-prefix route fixture");
        assert!(!compiled
            .program()
            .compiler_private_static_prefix_complete_proofs_should_run(usize::MAX));
        let identity = compiled.receipt().program_sha256;
        let serialized = compiled.program().serialize().expect("serialize fixture");
        let eager_handle = prepare_exclusive(&serialized);
        let fused_handle = prepare_exclusive(&serialized);
        let haystack = vec![b'x'; 128];
        let descriptor = one_state_packed_static_prefix_descriptor(0, false);
        let sentinel = FreAotRegexResultV1 {
            start: 0x5555_aaaa,
            end: 0xaaaa_5555,
        };
        let mut eager_result = sentinel;
        assert_eq!(
            call_exclusive_static_prefix_preflight_v3(
                eager_handle,
                &haystack,
                0,
                haystack.len(),
                &mut eager_result,
                &identity,
                &descriptor,
            ),
            STATUS_PARTIAL_PREFLIGHT_ENTER
        );
        assert_eq!(static_prefix_capability_presence(eager_handle), (true, false));
        assert_eq!(
            call_exclusive_static_prefix_continue_v3(
                eager_handle,
                &haystack,
                &mut eager_result,
                0,
                64,
                0,
            ),
            STATUS_STATIC_PREFIX_NATIVE_CONTINUATION_RESUME
        );
        assert_eq!(eager_result, FreAotRegexResultV1 { start: 1, end: 0 });
        assert_eq!(static_prefix_capability_presence(eager_handle), (false, false));

        let mut fused_result = sentinel;
        assert_eq!(
            call_exclusive_static_prefix_continue_v4(
                fused_handle,
                &haystack,
                0,
                haystack.len(),
                &mut fused_result,
                &identity,
                &descriptor,
                0,
                64,
                0,
            ),
            STATUS_STATIC_PREFIX_NATIVE_CONTINUATION_RESUME
        );
        assert_eq!(fused_result, FreAotRegexResultV1 { start: 1, end: 0 });
        assert_eq!(static_prefix_capability_presence(fused_handle), (false, false));

        for handle in [eager_handle, fused_handle] {
            // SAFETY: this test owns each distinct live handle and no call
            // overlaps destruction.
            assert_eq!(
                unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
                STATUS_SUCCESS
            );
        }
    }

    #[test]
    fn dense_static_prefix_selection_is_reused_after_continuation_owner_declines() {
        let compiled = compile(
            CompileRequest::new(
                r"(?-u:(?:a|[^a][\x00-\xff]){4})",
                Target::x86_64_linux(),
            )
                .mode(CompileMode::Fast)
                .output(OutputContract::SelectedEnd),
        )
        .expect("compile dense-selection owner fixture");
        let serialized = compiled.program().serialize().expect("serialize fixture");
        let mut direct =
            PreparedAotRegex::deserialize(&serialized).expect("prepare direct owner");
        let haystack = vec![b'x'; 128];
        let descriptor = one_state_packed_static_prefix_descriptor(0, false);
        let identity = *direct.frozen_header.artifact_identity();

        direct
            .admit_static_prefix_object(
                &haystack,
                SearchWindow::full(&haystack),
                identity,
                STATIC_PREFIX_RESUME_DESCRIPTOR_V2_VERSION,
                descriptor.as_ptr().expose_provenance(),
            )
            .expect("admit initial dense descriptor");
        let ticket = direct
            .consume_static_prefix_object(&haystack)
            .expect("consume initial dense descriptor");
        // SAFETY: this test uniquely owns the prepared value and keeps the
        // authenticated descriptor alive through the synchronous call.
        let first = unsafe {
            direct.continue_static_prefix_object(&haystack, ticket, 0, 64, 0)
        }
        .expect("continue initial dense descriptor");
        assert!(matches!(
            first,
            StaticPrefixContinuationOutcome::Native {
                status: STATUS_STATIC_PREFIX_NATIVE_CONTINUATION_RESUME,
                ..
            }
        ));
        assert_eq!(direct.static_prefix_dense_selections, 1);
        assert_eq!(direct.static_prefix_legacy_projection_attempts, 0);

        // Retire only the independently published continuation owner. A safe
        // runtime cannot replace an owner under a live header; republish the
        // unchanged root owner with its current generation key so status 7 is
        // an explicitly available second choice.
        direct.static_continuation_header.deactivate();
        direct.frozen_static_continuation_rows = None;
        direct.static_continuation_owner_generation_key = None;
        let (root_header, root_key) = direct
            .program
            .compiler_private_frozen_prepared_header_v6_with_owner_generation_key(
                &direct.workspace,
                direct
                    .frozen_dynamic_rows
                    .as_ref()
                    .expect("status-7 root owner"),
            )
            .expect("republish status-7 root owner");
        direct.frozen_header = root_header;
        direct.frozen_header_owner_generation_key = Some(root_key);
        assert!(direct.frozen_header.is_active());
        assert!(matches!(
            direct
                .frozen_header
                .compiler_private_dynamic_rows_format_version(),
            Some(
                FROZEN_DYNAMIC_ROWS_V3_FORMAT_VERSION
                    | FROZEN_DYNAMIC_ROWS_V4_FORMAT_VERSION
                    | FROZEN_DYNAMIC_ROWS_V8_FORMAT_VERSION
                    | FROZEN_DYNAMIC_ROWS_V9_FORMAT_VERSION
                    | FROZEN_DYNAMIC_ROWS_V10_FORMAT_VERSION
                    | FROZEN_DYNAMIC_ROWS_V11_FORMAT_VERSION
                    | FROZEN_DYNAMIC_ROWS_V12_FORMAT_VERSION
                    | FROZEN_DYNAMIC_ROWS_V13_FORMAT_VERSION
                    | FROZEN_DYNAMIC_ROWS_V14_FORMAT_VERSION
            )
        ));
        direct
            .admit_static_prefix_object(
                &haystack,
                SearchWindow::full(&haystack),
                identity,
                STATIC_PREFIX_RESUME_DESCRIPTOR_V2_VERSION,
                descriptor.as_ptr().expose_provenance(),
            )
            .expect("readmit warm dense descriptor");
        let ticket = direct
            .consume_static_prefix_object(&haystack)
            .expect("consume warm dense descriptor");
        // SAFETY: the same unique prepared value and local descriptor remain
        // live for the complete synchronous continuation.
        let second = unsafe {
            direct.continue_static_prefix_object(&haystack, ticket, 0, 64, 0)
        }
        .expect("continue after continuation-owner decline");
        let root_owner_present = direct.frozen_dynamic_rows.is_some();
        let root_key_present = direct.frozen_header_owner_generation_key.is_some();
        let root_header_active = direct.frozen_header.is_active();
        let root_header_format = direct
            .frozen_header
            .compiler_private_dynamic_rows_format_version();
        let continuation_header_active = direct.static_continuation_header.is_active();
        assert!(matches!(
            second,
            StaticPrefixContinuationOutcome::Native {
                status: STATUS_STATIC_PREFIX_NATIVE_RESUME,
                ..
            }
        ), "second={second:?}, root_owner={root_owner_present}, root_key={root_key_present}, root_active={root_header_active}, root_format={root_header_format:?}, continuation_active={continuation_header_active}, dense={}, legacy={}", direct.static_prefix_dense_selections, direct.static_prefix_legacy_projection_attempts);
        assert_eq!(
            direct.static_prefix_dense_selections, 2,
            "status-8 decline repeated dense-map selection before status 7",
        );
        assert_eq!(
            direct.static_prefix_legacy_projection_attempts, 0,
            "status-8 decline consulted selected K0 before trying status 7",
        );
    }

    #[test]
    fn dense_static_prefix_both_owner_generation_declines_use_portable_selected_row() {
        let compiled = compile(
            CompileRequest::new("(?:ab|ac)+z", Target::x86_64_linux())
                .mode(CompileMode::Fast)
                .output(OutputContract::SelectedEnd),
        )
        .expect("compile both-owner decline fixture");
        let serialized = compiled.program().serialize().expect("serialize fixture");
        let mut direct =
            PreparedAotRegex::deserialize(&serialized).expect("prepare both-owner decline fixture");
        let haystack = vec![b'x'; 128];
        let descriptor = one_state_packed_static_prefix_descriptor(0, false);
        let identity = *direct.frozen_header.artifact_identity();

        direct
            .admit_static_prefix_object(
                &haystack,
                SearchWindow::full(&haystack),
                identity,
                STATIC_PREFIX_RESUME_DESCRIPTOR_V2_VERSION,
                descriptor.as_ptr().expose_provenance(),
            )
            .expect("admit initial dense descriptor");
        let ticket = direct
            .consume_static_prefix_object(&haystack)
            .expect("consume initial dense descriptor");
        // SAFETY: this test uniquely owns the prepared value and keeps the
        // authenticated descriptor alive through the synchronous call.
        let initial = unsafe {
            direct.continue_static_prefix_object(&haystack, ticket, 0, 64, 0)
        }
        .expect("bind the descriptor and both immutable owners");
        assert!(matches!(
            initial,
            StaticPrefixContinuationOutcome::Native {
                status: STATUS_STATIC_PREFIX_NATIVE_CONTINUATION_RESUME,
                ..
            }
        ));
        assert!(direct.frozen_dynamic_rows.is_some());
        assert!(direct.frozen_static_continuation_rows.is_some());
        assert!(direct.frozen_header_owner_generation_key.is_some());
        assert!(direct.static_continuation_owner_generation_key.is_some());

        // Keep both immutable owners present, but pair each inactive shell with
        // the other owner's opaque generation key. Status 8 and then status 7
        // must both decline publication before the same admission reaches K0.
        direct.deactivate_frozen_header();
        std::mem::swap(
            &mut direct.static_continuation_owner_generation_key,
            &mut direct.frozen_header_owner_generation_key,
        );
        direct.static_prefix_dense_selections = 0;
        direct.static_prefix_legacy_projection_attempts = 0;
        direct
            .admit_static_prefix_object(
                &haystack,
                SearchWindow::full(&haystack),
                identity,
                STATIC_PREFIX_RESUME_DESCRIPTOR_V2_VERSION,
                descriptor.as_ptr().expose_provenance(),
            )
            .expect("readmit warm dense descriptor");
        let ticket = direct
            .consume_static_prefix_object(&haystack)
            .expect("consume warm dense descriptor");
        // SAFETY: the same unique prepared value and local descriptor remain
        // live for the complete synchronous continuation.
        let fallback = unsafe {
            direct.continue_static_prefix_object(&haystack, ticket, 0, 64, 0)
        }
        .expect("both owner-generation declines preserve portable completion");
        assert_eq!(
            fallback,
            StaticPrefixContinuationOutcome::Complete(MatchResult::SelectedEnd(None)),
        );
        assert_eq!(direct.static_prefix_dense_selections, 1);
        assert_eq!(
            direct.static_prefix_legacy_projection_attempts, 2,
            "both failed publications must preserve the established legacy checks before K0",
        );
    }

    #[test]
    fn cold_static_prefix_without_frozen_owner_skips_dense_map() {
        let compiled = compile(
            CompileRequest::new("(?:ab|ac)+z", Target::x86_64_linux())
                .mode(CompileMode::Fast)
                .output(OutputContract::SelectedEnd),
        )
        .expect("compile ownerless dense-map fixture");
        let serialized = compiled.program().serialize().expect("serialize fixture");
        let mut direct =
            PreparedAotRegex::deserialize(&serialized).expect("prepare ownerless fixture");
        direct.deactivate_frozen_header();
        direct.frozen_header = direct.program.compiler_private_frozen_prepared_header_v6(
            &direct.workspace,
            None,
            None,
        );
        direct.static_continuation_header = direct
            .program
            .compiler_private_frozen_prepared_header_v6(&direct.workspace, None, None);
        direct.frozen_dynamic_rows = None;
        direct.frozen_static_continuation_rows = None;
        direct.frozen_header_owner_generation_key = None;
        direct.static_continuation_owner_generation_key = None;

        let haystack = vec![b'x'; 128];
        let descriptor = one_state_packed_static_prefix_descriptor(0, false);
        let identity = *direct.frozen_header.artifact_identity();
        direct
            .admit_static_prefix_object(
                &haystack,
                SearchWindow::full(&haystack),
                identity,
                STATIC_PREFIX_RESUME_DESCRIPTOR_V2_VERSION,
                descriptor.as_ptr().expose_provenance(),
            )
            .expect("admit ownerless descriptor");
        let ticket = direct
            .consume_static_prefix_object(&haystack)
            .expect("consume ownerless descriptor");
        // SAFETY: this test uniquely owns the prepared value and retains the
        // descriptor for the duration of the synchronous continuation.
        let outcome = unsafe {
            direct.continue_static_prefix_object(&haystack, ticket, 0, 64, 0)
        }
        .expect("ownerless descriptor preserves exact fallback");
        assert!(matches!(
            outcome,
            StaticPrefixContinuationOutcome::Native { .. }
                | StaticPrefixContinuationOutcome::Complete(_)
        ));
        assert_eq!(
            direct.static_prefix_dense_selections, 0,
            "an ownerless cold bind allocated and selected a dense map",
        );
    }

    #[test]
    fn post_bind_frozen_owner_loss_releases_dense_map() {
        let compiled = compile(
            CompileRequest::new("(?:ab|ac)+z", Target::x86_64_linux())
                .mode(CompileMode::Fast)
                .output(OutputContract::SelectedEnd),
        )
        .expect("compile post-bind owner-loss fixture");
        let serialized = compiled.program().serialize().expect("serialize fixture");
        let mut direct =
            PreparedAotRegex::deserialize(&serialized).expect("prepare owner-loss fixture");
        let haystack = vec![b'x'; 128];
        let descriptor = one_state_packed_static_prefix_descriptor(0, false);
        let identity = *direct.frozen_header.artifact_identity();

        direct
            .admit_static_prefix_object(
                &haystack,
                SearchWindow::full(&haystack),
                identity,
                STATIC_PREFIX_RESUME_DESCRIPTOR_V2_VERSION,
                descriptor.as_ptr().expose_provenance(),
            )
            .expect("admit dense descriptor before owner loss");
        let ticket = direct
            .consume_static_prefix_object(&haystack)
            .expect("consume dense descriptor before owner loss");
        // SAFETY: this test uniquely owns the prepared value and retains the
        // local descriptor through the synchronous continuation.
        let initial = unsafe {
            direct.continue_static_prefix_object(&haystack, ticket, 0, 64, 0)
        }
        .expect("continue dense descriptor before owner loss");
        assert!(matches!(
            initial,
            StaticPrefixContinuationOutcome::Native { .. }
        ));
        assert_eq!(direct.static_prefix_dense_selections, 1);

        direct.deactivate_frozen_header();
        direct.frozen_header = direct.program.compiler_private_frozen_prepared_header_v6(
            &direct.workspace,
            None,
            None,
        );
        direct.static_continuation_header = direct
            .program
            .compiler_private_frozen_prepared_header_v6(&direct.workspace, None, None);
        direct.frozen_dynamic_rows = None;
        direct.frozen_static_continuation_rows = None;
        direct.frozen_header_owner_generation_key = None;
        direct.static_continuation_owner_generation_key = None;
        direct.install_static_prefix_resume_receipt(None);

        direct
            .admit_static_prefix_object(
                &haystack,
                SearchWindow::full(&haystack),
                identity,
                STATIC_PREFIX_RESUME_DESCRIPTOR_V2_VERSION,
                descriptor.as_ptr().expose_provenance(),
            )
            .expect("readmit dense descriptor after owner loss");
        let ticket = direct
            .consume_static_prefix_object(&haystack)
            .expect("consume dense descriptor after owner loss");
        // SAFETY: this test still uniquely owns the prepared value and the
        // authenticated descriptor remains live for the synchronous call.
        let fallback = unsafe {
            direct.continue_static_prefix_object(&haystack, ticket, 0, 64, 0)
        }
        .expect("owner loss preserves exact fallback");
        assert!(matches!(
            fallback,
            StaticPrefixContinuationOutcome::Complete(_)
        ));
        assert_eq!(
            direct.static_prefix_dense_selections, 1,
            "an ownerless post-bind workspace retained its dense map",
        );
    }

    #[test]
    fn packed_static_prefix_v2_preflight_defers_validation_until_the_hole() {
        let compiled = compile(
            CompileRequest::new("(?:ab|ac)+z", Target::x86_64_linux())
                .mode(CompileMode::Fast)
                .output(OutputContract::SelectedEnd),
        )
        .expect("compile packed lazy-descriptor fixture");
        let identity = compiled.receipt().program_sha256;
        let serialized = compiled.program().serialize().expect("serialize fixture");
        let handle = prepare_exclusive(&serialized);
        let haystack = vec![b'x'; 128];
        let sentinel = FreAotRegexResultV1 {
            start: 0xfeed_face,
            end: 0xdead_beef,
        };
        let mut result = sentinel;
        let mut malformed = [0_u32; STATIC_PREFIX_RESUME_DESCRIPTOR_V2_HEADER_BYTES / 4];
        malformed[2] = u32::try_from(malformed.len()).unwrap();

        assert_eq!(
            call_exclusive_static_prefix_preflight_v3(
                handle,
                &haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
                &malformed,
            ),
            STATUS_PARTIAL_PREFLIGHT_ENTER
        );
        assert_eq!(result, sentinel);
        assert!(exclusive_frozen_header_is_active(handle));
        assert_eq!(
            call_exclusive_static_prefix_continue_v3(
                handle,
                &haystack,
                &mut result,
                0,
                64,
                0,
            ),
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(result, sentinel);
        assert!(!exclusive_frozen_header_is_active(handle));

        // SAFETY: this test owns the unique live handle and no call overlaps
        // destruction.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
            STATUS_SUCCESS
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one fused-boundary ledger covers raw rejection and cross-version capability retirement"
    )]
    fn static_prefix_continue_v2_rejects_raw_and_foreign_inputs_and_retires_capabilities() {
        let compiled = compile(
            CompileRequest::new("(?:ab|ac)+z", Target::x86_64_linux())
                .mode(CompileMode::Fast)
                .output(OutputContract::SelectedEnd),
        )
        .expect("compile fused static-prefix boundary fixture");
        assert!(!compiled
            .program()
            .compiler_private_static_prefix_complete_proofs_should_run(usize::MAX));
        let identity = compiled.receipt().program_sha256;
        let serialized = compiled.program().serialize().expect("serialize fixture");
        let handle = prepare_exclusive(&serialized);
        let haystack = vec![b'x'; 128];
        let descriptor = one_state_static_prefix_descriptor(0, false);
        let sentinel = FreAotRegexResultV1 {
            start: 0xfeed_face,
            end: 0xdead_beef,
        };
        let mut result = sentinel;

        assert_eq!(
            call_exclusive_static_prefix_preflight_v2(
                handle,
                &haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
                &descriptor,
            ),
            STATUS_PARTIAL_PREFLIGHT_ENTER
        );
        assert_eq!(static_prefix_capability_presence(handle), (true, false));
        let mut wrong_identity = identity;
        wrong_identity[0] ^= 1;
        assert_eq!(
            call_exclusive_static_prefix_continue_v2(
                handle,
                &haystack,
                0,
                haystack.len(),
                &mut result,
                &wrong_identity,
                &descriptor,
                0,
                64,
                0,
            ),
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(result, sentinel);
        assert_eq!(static_prefix_capability_presence(handle), (false, false));

        assert_eq!(
            call_exclusive_static_prefix_preflight_v2(
                handle,
                &haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
                &descriptor,
            ),
            STATUS_PARTIAL_PREFLIGHT_ENTER
        );
        // SAFETY: the handle, haystack, identity, and descriptor are valid;
        // the null result deliberately exercises fail-closed raw validation.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_continue_v2(
                    handle,
                    haystack.as_ptr(),
                    haystack.len(),
                    0,
                    haystack.len(),
                    std::ptr::null_mut(),
                    identity.as_ptr(),
                    descriptor.as_ptr(),
                    0,
                    64,
                    0,
                )
            },
            STATUS_INVALID_ARGUMENT
        );
        assert_eq!(static_prefix_capability_presence(handle), (false, false));

        assert_eq!(
            call_exclusive_static_prefix_preflight_v2(
                handle,
                &haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
                &descriptor,
            ),
            STATUS_PARTIAL_PREFLIGHT_ENTER
        );
        assert_eq!(
            call_exclusive_static_prefix_continue_v2(
                handle,
                &haystack,
                haystack.len(),
                0,
                &mut result,
                &identity,
                &descriptor,
                0,
                64,
                0,
            ),
            STATUS_INVALID_ARGUMENT
        );
        assert_eq!(result, sentinel);
        assert_eq!(static_prefix_capability_presence(handle), (false, false));

        // SAFETY: this test owns the unique live handle and no call overlaps
        // destruction.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
            STATUS_SUCCESS
        );
    }

    #[test]
    fn static_prefix_continue_v2_rejects_descriptor_frontier_and_eager_only_owners() {
        let compiled = compile(
            CompileRequest::new("(?:ab|ac)+z", Target::x86_64_linux())
                .mode(CompileMode::Fast)
                .output(OutputContract::SelectedEnd),
        )
        .expect("compile fused descriptor fixture");
        let identity = compiled.receipt().program_sha256;
        let serialized = compiled.program().serialize().expect("serialize fixture");
        let handle = prepare_exclusive(&serialized);
        let haystack = vec![b'x'; 128];
        let sentinel = FreAotRegexResultV1 {
            start: 0x1111_2222,
            end: 0x3333_4444,
        };
        let mut result = sentinel;

        let malformed = [0_u32; STATIC_PREFIX_RESUME_DESCRIPTOR_V1_HEADER_BYTES / 4];
        assert_eq!(
            call_exclusive_static_prefix_continue_v2(
                handle,
                &haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
                &malformed,
                0,
                64,
                0,
            ),
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(result, sentinel);
        assert_eq!(static_prefix_capability_presence(handle), (false, false));

        let bad_frontier = one_state_static_prefix_descriptor(u32::MAX, false);
        assert_eq!(
            call_exclusive_static_prefix_continue_v2(
                handle,
                &haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
                &bad_frontier,
                0,
                64,
                0,
            ),
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(result, sentinel);
        assert_eq!(static_prefix_capability_presence(handle), (false, false));

        let bad_pending = one_state_static_prefix_descriptor(0, true);
        assert_eq!(
            call_exclusive_static_prefix_continue_v2(
                handle,
                &haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
                &bad_pending,
                0,
                64,
                0,
            ),
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(result, sentinel);
        assert_eq!(static_prefix_capability_presence(handle), (false, false));

        let variable = compile(
            CompileRequest::new("(?:ab|ac)+z", Target::x86_64_linux())
                .mode(CompileMode::Fast)
                .output(OutputContract::Span),
        )
        .expect("compile variable-Span rejection fixture");
        assert!(variable.program().exact_match_width().is_none());
        let variable_identity = variable.receipt().program_sha256;
        let variable_serialized = variable.program().serialize().expect("serialize variable");
        let variable_handle = prepare_exclusive(&variable_serialized);
        assert_eq!(
            call_exclusive_static_prefix_preflight_v2(
                variable_handle,
                &haystack,
                0,
                haystack.len(),
                &mut result,
                &variable_identity,
                &malformed,
            ),
            STATUS_PARTIAL_PREFLIGHT_ENTER
        );
        publish_static_prefix_span_postflight_for_test(variable_handle, &haystack);
        assert_eq!(static_prefix_capability_presence(variable_handle), (false, true));
        result = sentinel;
        assert_eq!(
            call_exclusive_static_prefix_continue_v2(
                variable_handle,
                &haystack,
                0,
                haystack.len(),
                &mut result,
                &variable_identity,
                &malformed,
                0,
                64,
                0,
            ),
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(result, sentinel);
        assert_eq!(
            static_prefix_capability_presence(variable_handle),
            (false, false)
        );

        let mut proof_limits = CompileLimitsV1::default();
        proof_limits.determinize.max_states = 0;
        let proof = compile(
            CompileRequest::new("(?:x|yz)7[A-Za-z]{1,2}", Target::x86_64_linux())
                .mode(CompileMode::Optimizing)
                .limits(proof_limits)
                .output(OutputContract::SelectedEnd),
        )
        .expect("compile complete-proof fixture");
        assert!(proof
            .program()
            .compiler_private_static_prefix_complete_proofs_should_run(usize::MAX));
        let proof_identity = proof.receipt().program_sha256;
        let proof_serialized = proof.program().serialize().expect("serialize proof fixture");
        let proof_handle = prepare_exclusive(&proof_serialized);
        result = sentinel;
        assert_eq!(
            call_exclusive_static_prefix_continue_v2(
                proof_handle,
                &haystack,
                0,
                haystack.len(),
                &mut result,
                &proof_identity,
                &malformed,
                0,
                64,
                0,
            ),
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(result, sentinel);
        assert_eq!(static_prefix_capability_presence(proof_handle), (false, false));

        for owned in [handle, variable_handle, proof_handle] {
            // SAFETY: the loop owns each distinct live handle and no call
            // overlaps destruction.
            assert_eq!(
                unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(owned) },
                STATUS_SUCCESS
            );
        }
    }

    #[test]
    fn static_prefix_continue_v2_returns_status_eight_without_an_outer_ticket() {
        let compiled = compile(
            CompileRequest::new("(?:ab|ac)+z", Target::x86_64_linux())
                .mode(CompileMode::Fast)
                .output(OutputContract::SelectedEnd),
        )
        .expect("compile fused completion fixture");
        assert!(!compiled
            .program()
            .compiler_private_static_prefix_complete_proofs_should_run(usize::MAX));
        let identity = compiled.receipt().program_sha256;
        let serialized = compiled.program().serialize().expect("serialize fixture");
        let handle = prepare_exclusive(&serialized);
        let haystack = vec![b'x'; 128];
        let descriptor = one_state_static_prefix_descriptor(0, false);
        let sentinel = FreAotRegexResultV1 {
            start: 0x5555_aaaa,
            end: 0xaaaa_5555,
        };
        let mut result = sentinel;
        assert_eq!(
            call_exclusive_static_prefix_continue_v2(
                handle,
                &haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
                &descriptor,
                0,
                64,
                0,
            ),
            STATUS_STATIC_PREFIX_NATIVE_CONTINUATION_RESUME
        );
        assert_eq!(result, FreAotRegexResultV1 { start: 1, end: 0 });
        assert_eq!(static_prefix_capability_presence(handle), (false, false));

        // SAFETY: this test owns the unique live handle and no call overlaps
        // destruction.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
            STATUS_SUCCESS
        );
    }

    #[test]
    fn static_prefix_continue_v2_variable_span_publishes_only_a_postflight_ticket() {
        let compiled = compile(
            CompileRequest::new("(?:ab|ac)+z", Target::x86_64_linux())
                .mode(CompileMode::Fast)
                .output(OutputContract::Span),
        )
        .expect("compile fused variable-Span fixture");
        assert_eq!(compiled.program().exact_match_width(), None);
        assert!(!compiled
            .program()
            .compiler_private_static_prefix_complete_proofs_should_run(usize::MAX));
        let identity = compiled.receipt().program_sha256;
        let serialized = compiled.program().serialize().expect("serialize fixture");
        let handle = prepare_exclusive(&serialized);
        let haystack = vec![b'x'; 128];
        let descriptor = one_state_static_prefix_descriptor(0, false);
        let mut result = FreAotRegexResultV1 {
            start: 0x5555_aaaa,
            end: 0xaaaa_5555,
        };

        assert_eq!(
            call_exclusive_static_prefix_continue_v2(
                handle,
                &haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
                &descriptor,
                0,
                64,
                0,
            ),
            STATUS_STATIC_PREFIX_NATIVE_CONTINUATION_RESUME
        );
        assert_eq!(result, FreAotRegexResultV1 { start: 1, end: 0 });
        assert_eq!(static_prefix_capability_presence(handle), (false, true));
        // SAFETY: this test uniquely owns the live prepared allocation.
        assert_eq!(
            unsafe { &*handle.0.cast::<PreparedAotRegex>() }
                .static_prefix_dense_selections,
            1,
            "variable-Span recovery bypassed the descriptor-bound dense map",
        );

        // SAFETY: this test owns the unique live handle and no call overlaps
        // destruction.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
            STATUS_SUCCESS
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one V3 ledger test covers success, replay, raw rejection, contamination, and proof gating"
    )]
    fn lazy_static_prefix_span_v3_consumes_exact_epoch_and_fails_closed() {
        let compiled = compile(
            CompileRequest::new("(?:ab|ac)+z", Target::x86_64_linux())
                .mode(CompileMode::Fast)
                .output(OutputContract::Span),
        )
        .expect("compile lazy variable-Span fixture");
        assert!(!compiled
            .program()
            .compiler_private_static_prefix_complete_proofs_should_run(usize::MAX));
        let identity = compiled.receipt().program_sha256;
        let serialized = compiled.program().serialize().expect("serialize lazy fixture");
        let handle = prepare_exclusive(&serialized);
        let haystack = b"xxabacz";
        let descriptor = [0_u32; STATIC_PREFIX_RESUME_DESCRIPTOR_V1_HEADER_BYTES / 4];
        let sentinel = FreAotRegexResultV1 {
            start: 0xfeed_face,
            end: 0xdead_beef,
        };
        let arm_generated_entry = |owned: FreAotRegexExclusiveHandleV1| {
            // SAFETY: this test uniquely owns the prepared allocation and
            // models the generated wrapper's checked inline epoch increment.
            let prepared = unsafe { &mut *owned.0.cast::<PreparedAotRegex>() };
            prepared.static_prefix_invocation_epoch += 1;
            prepared.static_prefix_invocation_epoch
        };

        let epoch = arm_generated_entry(handle);
        let mut result = sentinel;
        assert_eq!(
            call_exclusive_static_prefix_recover_span_v3(
                handle,
                haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
                haystack.len(),
                epoch,
            ),
            STATUS_MATCH
        );
        assert_eq!(result, FreAotRegexResultV1 { start: 2, end: 7 });
        assert_eq!(static_prefix_capability_presence(handle), (false, false));
        assert_eq!(
            unsafe { (&*handle.0.cast::<PreparedAotRegex>()).static_prefix_invocation_epoch },
            epoch + 1
        );

        result = sentinel;
        assert_eq!(
            call_exclusive_static_prefix_recover_span_v3(
                handle,
                haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
                haystack.len(),
                epoch,
            ),
            STATUS_RUNTIME_FAILURE,
            "a consumed generated epoch cannot be replayed"
        );
        assert_eq!(result, sentinel);

        let epoch = arm_generated_entry(handle);
        let mut wrong_identity = identity;
        wrong_identity[7] ^= 0x80;
        assert_eq!(
            call_exclusive_static_prefix_recover_span_v3(
                handle,
                haystack,
                0,
                haystack.len(),
                &mut result,
                &wrong_identity,
                haystack.len(),
                epoch,
            ),
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(result, sentinel);
        assert_eq!(
            call_exclusive_static_prefix_recover_span_v3(
                handle,
                haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
                haystack.len(),
                epoch,
            ),
            STATUS_RUNTIME_FAILURE,
            "corrected identity cannot replay a rejected epoch"
        );

        let epoch = arm_generated_entry(handle);
        // SAFETY: every readable argument is valid; the null result is the
        // deliberate raw-boundary refusal and must still consume the epoch.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_recover_span_v3(
                    handle,
                    haystack.as_ptr(),
                    haystack.len(),
                    0,
                    haystack.len(),
                    std::ptr::null_mut(),
                    identity.as_ptr(),
                    haystack.len(),
                    epoch,
                )
            },
            STATUS_INVALID_ARGUMENT
        );
        assert_eq!(
            call_exclusive_static_prefix_recover_span_v3(
                handle,
                haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
                haystack.len(),
                epoch,
            ),
            STATUS_RUNTIME_FAILURE,
            "corrected raw arguments cannot replay a rejected epoch"
        );

        assert_eq!(
            call_exclusive_static_prefix_preflight_v2(
                handle,
                haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
                &descriptor,
            ),
            STATUS_PARTIAL_PREFLIGHT_ENTER
        );
        assert_eq!(static_prefix_capability_presence(handle), (true, false));
        let epoch = arm_generated_entry(handle);
        assert_eq!(
            call_exclusive_static_prefix_recover_span_v3(
                handle,
                haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
                haystack.len(),
                epoch,
            ),
            STATUS_MATCH,
            "a generated epoch retires but is not blocked by a stale V1/V2 capability"
        );
        assert_eq!(static_prefix_capability_presence(handle), (false, false));
        assert_eq!(result, FreAotRegexResultV1 { start: 2, end: 7 });

        result = sentinel;
        let epoch = arm_generated_entry(handle);
        assert_eq!(
            call_exclusive_static_prefix_preflight_v2(
                handle,
                haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
                &descriptor,
            ),
            STATUS_PARTIAL_PREFLIGHT_ENTER
        );
        assert_eq!(static_prefix_capability_presence(handle), (true, false));
        assert_eq!(
            call_exclusive_static_prefix_recover_span_v3(
                handle,
                haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
                haystack.len(),
                epoch,
            ),
            STATUS_RUNTIME_FAILURE,
            "V3 rejects a V1/V2 capability minted in its current epoch"
        );
        assert_eq!(static_prefix_capability_presence(handle), (false, false));
        assert_eq!(result, sentinel);

        let mut proof_limits = CompileLimitsV1::default();
        proof_limits.determinize.max_states = 0;
        let proof = compile(
            CompileRequest::new("(?:x|yz)7[A-Za-z]{1,2}", Target::x86_64_linux())
                .mode(CompileMode::Optimizing)
                .limits(proof_limits)
                .output(OutputContract::Span),
        )
        .expect("compile complete-proof Span fixture");
        assert!(proof
            .program()
            .compiler_private_static_prefix_complete_proofs_should_run(usize::MAX));
        let proof_identity = proof.receipt().program_sha256;
        let proof_serialized = proof.program().serialize().expect("serialize proof fixture");
        let proof_handle = prepare_exclusive(&proof_serialized);
        let proof_epoch = arm_generated_entry(proof_handle);
        assert_eq!(
            call_exclusive_static_prefix_recover_span_v3(
                proof_handle,
                haystack,
                0,
                haystack.len(),
                &mut result,
                &proof_identity,
                haystack.len(),
                proof_epoch,
            ),
            STATUS_RUNTIME_FAILURE,
            "complete proof owners must remain on eager V2 admission"
        );
        assert_eq!(result, sentinel);

        for owned in [handle, proof_handle] {
            // SAFETY: the loop owns each distinct live handle and no call
            // overlaps destruction.
            assert_eq!(
                unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(owned) },
                STATUS_SUCCESS
            );
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one lifecycle test covers all deferred descriptor rejection boundaries"
    )]
    fn static_prefix_v2_defers_descriptor_validation_until_a_hole() {
        let compiled = compile(
            CompileRequest::new("(?:ab|ac)+z", Target::x86_64_linux())
                .mode(CompileMode::Fast)
                .output(OutputContract::Span),
        )
        .expect("compile static-prefix V2 boundary fixture");
        let identity = compiled.receipt().program_sha256;
        let serialized = compiled.program().serialize().expect("serialize fixture");
        let handle = prepare_exclusive(&serialized);
        let haystack = vec![b'x'; 128];
        let sentinel = FreAotRegexResultV1 {
            start: 0xfeed_face,
            end: 0xdead_beef,
        };
        let mut result = sentinel;

        let truncated = [0_u32; STATIC_PREFIX_RESUME_DESCRIPTOR_V1_HEADER_BYTES / 4];
        assert_eq!(
            call_exclusive_static_prefix_preflight_v2(
                handle,
                &haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
                &truncated,
            ),
            STATUS_PARTIAL_PREFLIGHT_ENTER
        );
        assert_eq!(result, sentinel);
        assert!(exclusive_frozen_header_is_active(handle));
        // SAFETY: this test uniquely owns the live handle and supplies the
        // exact haystack admitted above. The malformed descriptor is backed by
        // a complete fixed header, so continuation can reject it safely.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_continue_v1(
                    handle,
                    haystack.as_ptr(),
                    haystack.len(),
                    &raw mut result,
                    0,
                    64,
                    0,
                )
            },
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(result, sentinel);
        assert!(exclusive_frozen_header_is_active(handle));

        let mut oversized = truncated;
        oversized[2] = u32::try_from(
            STATIC_PREFIX_RESUME_DESCRIPTOR_V1_MAX_BYTES / std::mem::size_of::<u32>() + 1,
        )
        .unwrap();
        assert_eq!(
            call_exclusive_static_prefix_preflight_v2(
                handle,
                &haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
                &oversized,
            ),
            STATUS_PARTIAL_PREFLIGHT_ENTER
        );
        assert_eq!(result, sentinel);
        assert!(exclusive_frozen_header_is_active(handle));
        // SAFETY: as above, continuation owns the exact admitted extents and
        // rejects the bounded oversized declaration before forming its slice.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_continue_v1(
                    handle,
                    haystack.as_ptr(),
                    haystack.len(),
                    &raw mut result,
                    0,
                    64,
                    0,
                )
            },
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(result, sentinel);
        assert!(exclusive_frozen_header_is_active(handle));

        let mut bad_magic = truncated;
        bad_magic[2] = u32::try_from(bad_magic.len()).unwrap();
        assert_eq!(
            call_exclusive_static_prefix_preflight_v2(
                handle,
                &haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
                &bad_magic,
            ),
            STATUS_PARTIAL_PREFLIGHT_ENTER
        );
        assert_eq!(result, sentinel);
        assert!(exclusive_frozen_header_is_active(handle));

        // SAFETY: this test uniquely owns the live handle and all supplied
        // extents. Descriptor parsing now happens here; program binding rejects
        // bad magic and retires the header before touching executor workspace.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_continue_v1(
                    handle,
                    haystack.as_ptr(),
                    haystack.len(),
                    &raw mut result,
                    0,
                    64,
                    0,
                )
            },
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(result, sentinel);
        assert!(!exclusive_frozen_header_is_active(handle));

        // The failed continuation consumed its object ticket, so a second
        // consumer must reject without initializing the result.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_recover_span_v2(
                    handle,
                    haystack.as_ptr(),
                    haystack.len(),
                    0,
                    haystack.len(),
                    &raw mut result,
                    identity.as_ptr(),
                    64,
                )
            },
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(result, sentinel);

        // SAFETY: this test owns the unique live handle and no call overlaps
        // destruction.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
            STATUS_SUCCESS
        );
    }

    #[test]
    fn static_prefix_v2_span_postflight_skips_forward_descriptor_binding() {
        let compiled = compile(
            CompileRequest::new("(?:ab|ac)+z", Target::x86_64_linux())
                .mode(CompileMode::Fast)
                .output(OutputContract::Span),
        )
        .expect("compile static-prefix V2 Span fixture");
        let identity = compiled.receipt().program_sha256;
        let serialized = compiled.program().serialize().expect("serialize fixture");
        let handle = prepare_exclusive(&serialized);
        let haystack = b"xxabacz";
        let malformed = [0_u32; STATIC_PREFIX_RESUME_DESCRIPTOR_V1_HEADER_BYTES / 4];
        let sentinel = FreAotRegexResultV1 {
            start: 0xfeed_face,
            end: 0xdead_beef,
        };
        let mut result = sentinel;

        assert_eq!(
            call_exclusive_static_prefix_preflight_v2(
                handle,
                haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
                &malformed,
            ),
            STATUS_PARTIAL_PREFLIGHT_ENTER
        );
        assert_eq!(result, sentinel);
        assert!(exclusive_frozen_header_is_active(handle));

        // SAFETY: the test owns the live handle; selected_end is the endpoint
        // of `abacz`, and all readable and writable extents are disjoint.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_recover_span_v2(
                    handle,
                    haystack.as_ptr(),
                    haystack.len(),
                    0,
                    haystack.len(),
                    &raw mut result,
                    identity.as_ptr(),
                    haystack.len(),
                )
            },
            STATUS_MATCH
        );
        assert_eq!(result, FreAotRegexResultV1 { start: 2, end: 7 });
        assert!(!exclusive_frozen_header_is_active(handle));

        result = sentinel;
        // The successful postflight consumed the raw object ticket.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_recover_span_v2(
                    handle,
                    haystack.as_ptr(),
                    haystack.len(),
                    0,
                    haystack.len(),
                    &raw mut result,
                    identity.as_ptr(),
                    haystack.len(),
                )
            },
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(result, sentinel);

        // SAFETY: this test owns the unique live handle and no call overlaps
        // destruction.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
            STATUS_SUCCESS
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one capability-ledger test covers mismatched invocation, success, and replay"
    )]
    fn static_prefix_v2_span_postflight_consumes_distinct_continuation_ticket_once() {
        let compiled = compile(
            CompileRequest::new("(?:ab|ac)+z", Target::x86_64_linux())
                .mode(CompileMode::Fast)
                .output(OutputContract::Span),
        )
        .expect("compile static-prefix continuation Span fixture");
        assert_eq!(compiled.program().output_contract(), OutputContract::Span);
        assert_eq!(compiled.program().exact_match_width(), None);
        let identity = compiled.receipt().program_sha256;
        let serialized = compiled.program().serialize().expect("serialize fixture");
        let handle = prepare_exclusive(&serialized);
        let haystack = b"xxabacz";
        let descriptor = [0_u32; STATIC_PREFIX_RESUME_DESCRIPTOR_V1_HEADER_BYTES / 4];
        let sentinel = FreAotRegexResultV1 {
            start: 0xfeed_face,
            end: 0xdead_beef,
        };
        let mut result = sentinel;

        assert_eq!(
            call_exclusive_static_prefix_preflight_v2(
                handle,
                haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
                &descriptor,
            ),
            STATUS_PARTIAL_PREFLIGHT_ENTER
        );
        publish_static_prefix_span_postflight_for_test(handle, haystack);
        let mut wrong_identity = identity;
        wrong_identity[9] ^= 0x80;
        // A mismatched invocation consumes the postflight capability and
        // leaves the caller's result untouched.
        assert_eq!(
            call_exclusive_static_prefix_recover_span_v2(
                handle,
                haystack,
                0,
                haystack.len(),
                &mut result,
                &wrong_identity,
                haystack.len(),
            ),
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(result, sentinel);
        assert_eq!(
            call_exclusive_static_prefix_recover_span_v2(
                handle,
                haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
                haystack.len(),
            ),
            STATUS_RUNTIME_FAILURE,
            "a mismatched postflight cannot be replayed with corrected arguments"
        );
        assert_eq!(result, sentinel);

        assert_eq!(
            call_exclusive_static_prefix_preflight_v2(
                handle,
                haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
                &descriptor,
            ),
            STATUS_PARTIAL_PREFLIGHT_ENTER
        );
        publish_static_prefix_span_postflight_for_test(handle, haystack);
        assert_eq!(
            call_exclusive_static_prefix_recover_span_v2(
                handle,
                haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
                haystack.len(),
            ),
            STATUS_MATCH
        );
        assert_eq!(result, FreAotRegexResultV1 { start: 2, end: 7 });

        result = sentinel;
        assert_eq!(
            call_exclusive_static_prefix_recover_span_v2(
                handle,
                haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
                haystack.len(),
            ),
            STATUS_RUNTIME_FAILURE,
            "a successful continuation postflight is single-use"
        );
        assert_eq!(result, sentinel);

        // SAFETY: this test owns the unique live handle and no call overlaps
        // destruction.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
            STATUS_SUCCESS
        );
    }

    #[test]
    fn static_prefix_retirement_advances_epoch_and_clears_every_capability() {
        let compiled = compile(
            CompileRequest::new("(?:ab|ac)+z", Target::x86_64_linux())
                .mode(CompileMode::Fast)
                .output(OutputContract::Span),
        )
        .expect("compile static-prefix retirement fixture");
        let identity = compiled.receipt().program_sha256;
        let serialized = compiled.program().serialize().expect("serialize fixture");
        let handle = prepare_exclusive(&serialized);
        let haystack = b"xxabacz";
        let descriptor = [0_u32; STATIC_PREFIX_RESUME_DESCRIPTOR_V1_HEADER_BYTES / 4];
        let mut result = FreAotRegexResultV1 {
            start: 0xfeed_face,
            end: 0xdead_beef,
        };

        admit_static_prefix_span_postflight_for_test(
            handle,
            haystack,
            &mut result,
            &identity,
            &descriptor,
        );
        // SAFETY: this test uniquely owns the live allocation throughout the
        // synchronous helper call and private-state observations.
        let initial_epoch = unsafe {
            (&*handle.0.cast::<PreparedAotRegex>()).static_prefix_invocation_epoch
        };
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_retire_v1(
                    handle,
                    STATUS_INVALID_ARGUMENT,
                )
            },
            STATUS_INVALID_ARGUMENT
        );
        assert_eq!(static_prefix_capability_presence(handle), (false, false));
        assert_eq!(
            unsafe { (&*handle.0.cast::<PreparedAotRegex>()).static_prefix_invocation_epoch },
            initial_epoch + 1
        );

        assert_eq!(
            call_exclusive_static_prefix_preflight_v2(
                handle,
                haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
                &descriptor,
            ),
            STATUS_PARTIAL_PREFLIGHT_ENTER
        );
        assert_eq!(static_prefix_capability_presence(handle), (true, false));
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_retire_v1(
                    handle,
                    STATUS_PARTIAL_PREFLIGHT_ENTER,
                )
            },
            STATUS_RUNTIME_FAILURE,
            "private statuses fail closed"
        );
        assert_eq!(static_prefix_capability_presence(handle), (false, false));

        assert_eq!(
            call_exclusive_static_prefix_preflight_v2(
                handle,
                haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
                &descriptor,
            ),
            STATUS_PARTIAL_PREFLIGHT_ENTER
        );
        // Exercise the cold wrap path modeled by generated add-and-CBZ code.
        unsafe {
            (&mut *handle.0.cast::<PreparedAotRegex>()).static_prefix_invocation_epoch = u64::MAX;
        }
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_retire_v1(
                    handle,
                    STATUS_MATCH,
                )
            },
            STATUS_MATCH
        );
        assert_eq!(static_prefix_capability_presence(handle), (false, false));
        assert_eq!(
            unsafe { (&*handle.0.cast::<PreparedAotRegex>()).static_prefix_invocation_epoch },
            1
        );
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_retire_v1(
                    FreAotRegexExclusiveHandleV1::default(),
                    STATUS_MATCH,
                )
            },
            STATUS_INVALID_HANDLE
        );

        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
            STATUS_SUCCESS
        );
    }

    #[test]
    fn static_prefix_tickets_reject_an_advanced_invocation_epoch() {
        let compiled = compile(
            CompileRequest::new("(?:ab|ac)+z", Target::x86_64_linux())
                .mode(CompileMode::Fast)
                .output(OutputContract::Span),
        )
        .expect("compile static-prefix epoch fixture");
        let identity = compiled.receipt().program_sha256;
        let serialized = compiled.program().serialize().expect("serialize fixture");
        let handle = prepare_exclusive(&serialized);
        let haystack = b"xxabacz";
        let descriptor = [0_u32; STATIC_PREFIX_RESUME_DESCRIPTOR_V1_HEADER_BYTES / 4];
        let sentinel = FreAotRegexResultV1 {
            start: 0xfeed_face,
            end: 0xdead_beef,
        };
        let mut result = sentinel;

        assert_eq!(
            call_exclusive_static_prefix_preflight_v2(
                handle,
                haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
                &descriptor,
            ),
            STATUS_PARTIAL_PREFLIGHT_ENTER
        );
        unsafe {
            (&mut *handle.0.cast::<PreparedAotRegex>()).static_prefix_invocation_epoch += 1;
        }
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_continue_v1(
                    handle,
                    haystack.as_ptr(),
                    haystack.len(),
                    &raw mut result,
                    0,
                    1,
                    0,
                )
            },
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(result, sentinel);
        assert_eq!(static_prefix_capability_presence(handle), (false, false));

        admit_static_prefix_span_postflight_for_test(
            handle,
            haystack,
            &mut result,
            &identity,
            &descriptor,
        );
        unsafe {
            (&mut *handle.0.cast::<PreparedAotRegex>()).static_prefix_invocation_epoch += 1;
        }
        assert_eq!(
            call_exclusive_static_prefix_recover_span_v2(
                handle,
                haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
                haystack.len(),
            ),
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(result, sentinel);
        assert_eq!(static_prefix_capability_presence(handle), (false, false));

        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
            STATUS_SUCCESS
        );
    }

    #[test]
    fn static_prefix_v1_boundaries_retire_forged_v2_tickets() {
        let compiled = compile(
            CompileRequest::new("(?:ab|ac)+z", Target::x86_64_linux())
                .mode(CompileMode::Fast)
                .output(OutputContract::Span),
        )
        .expect("compile cross-version static-prefix fixture");
        let identity = compiled.receipt().program_sha256;
        let serialized = compiled.program().serialize().expect("serialize fixture");
        let handle = prepare_exclusive(&serialized);
        let haystack = b"xxabacz";
        let descriptor = [0_u32; STATIC_PREFIX_RESUME_DESCRIPTOR_V1_HEADER_BYTES / 4];
        let sentinel = FreAotRegexResultV1 {
            start: 0xfeed_face,
            end: 0xdead_beef,
        };
        let mut result = sentinel;

        assert_eq!(
            call_exclusive_static_prefix_preflight_v2(
                handle,
                haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
                &descriptor,
            ),
            STATUS_PARTIAL_PREFLIGHT_ENTER
        );
        // SAFETY: all readable inputs are valid; the null V1 output is the
        // deliberate malformed boundary that must still retire the V2 ticket.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_preflight_v1(
                    handle,
                    haystack.as_ptr(),
                    haystack.len(),
                    0,
                    haystack.len(),
                    std::ptr::null_mut(),
                    identity.as_ptr(),
                )
            },
            STATUS_INVALID_ARGUMENT
        );
        assert_eq!(static_prefix_capability_presence(handle), (false, false));
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_continue_v1(
                    handle,
                    haystack.as_ptr(),
                    haystack.len(),
                    &raw mut result,
                    0,
                    1,
                    0,
                )
            },
            STATUS_RUNTIME_FAILURE,
            "corrected continuation cannot replay a V2 ticket retired by V1"
        );
        assert_eq!(result, sentinel);

        assert_eq!(
            call_exclusive_static_prefix_preflight_v2(
                handle,
                haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
                &descriptor,
            ),
            STATUS_PARTIAL_PREFLIGHT_ENTER
        );
        // SAFETY: the null V1 postflight output is rejected before use but
        // must consume the cross-version object ticket first.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_recover_span_v1(
                    handle,
                    haystack.as_ptr(),
                    haystack.len(),
                    0,
                    haystack.len(),
                    std::ptr::null_mut(),
                    identity.as_ptr(),
                    haystack.len(),
                )
            },
            STATUS_INVALID_ARGUMENT
        );
        assert_eq!(static_prefix_capability_presence(handle), (false, false));
        assert_eq!(
            call_exclusive_static_prefix_recover_span_v2(
                handle,
                haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
                haystack.len(),
            ),
            STATUS_RUNTIME_FAILURE,
            "corrected postflight cannot replay a V2 ticket retired by V1"
        );
        assert_eq!(result, sentinel);

        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
            STATUS_SUCCESS
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one boundary test proves every malformed V2 entry retires both capability kinds"
    )]
    fn static_prefix_v2_malformed_boundaries_retire_capabilities() {
        let compiled = compile(
            CompileRequest::new("(?:ab|ac)+z", Target::x86_64_linux())
                .mode(CompileMode::Fast)
                .output(OutputContract::Span),
        )
        .expect("compile malformed-boundary Span fixture");
        let identity = compiled.receipt().program_sha256;
        let serialized = compiled.program().serialize().expect("serialize fixture");
        let handle = prepare_exclusive(&serialized);
        let haystack = b"xxabacz";
        let descriptor = [0_u32; STATIC_PREFIX_RESUME_DESCRIPTOR_V1_HEADER_BYTES / 4];
        let sentinel = FreAotRegexResultV1 {
            start: 0xfeed_face,
            end: 0xdead_beef,
        };
        let mut result = sentinel;
        let mut misaligned_storage = std::mem::MaybeUninit::<FreAotRegexResultV1>::uninit();
        // SAFETY: adding one byte to an aligned live result allocation creates
        // a live but deliberately misaligned pointer. Every tested boundary
        // rejects it before dereference.
        let misaligned_result = unsafe {
            misaligned_storage
                .as_mut_ptr()
                .cast::<u8>()
                .add(1)
                .cast::<FreAotRegexResultV1>()
        };
        assert!(!misaligned_result.is_aligned());

        admit_static_prefix_span_postflight_for_test(
            handle,
            haystack,
            &mut result,
            &identity,
            &descriptor,
        );
        // SAFETY: the test owns the live handle and every readable extent; a
        // null result is deliberately supplied to exercise early retirement.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_preflight_v2(
                    handle,
                    haystack.as_ptr(),
                    haystack.len(),
                    0,
                    haystack.len(),
                    std::ptr::null_mut(),
                    identity.as_ptr(),
                    descriptor.as_ptr(),
                )
            },
            STATUS_INVALID_ARGUMENT
        );
        assert_eq!(static_prefix_capability_presence(handle), (false, false));

        admit_static_prefix_span_postflight_for_test(
            handle,
            haystack,
            &mut result,
            &identity,
            &descriptor,
        );
        // SAFETY: identical live extents to the preceding call; only the
        // deliberately misaligned output differs.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_preflight_v2(
                    handle,
                    haystack.as_ptr(),
                    haystack.len(),
                    0,
                    haystack.len(),
                    misaligned_result,
                    identity.as_ptr(),
                    descriptor.as_ptr(),
                )
            },
            STATUS_INVALID_ARGUMENT
        );
        assert_eq!(static_prefix_capability_presence(handle), (false, false));

        assert_eq!(
            call_exclusive_static_prefix_preflight_v2(
                handle,
                haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
                &descriptor,
            ),
            STATUS_PARTIAL_PREFLIGHT_ENTER
        );
        assert_eq!(static_prefix_capability_presence(handle), (true, false));
        // SAFETY: a null output is the sole malformed continuation argument.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_continue_v1(
                    handle,
                    haystack.as_ptr(),
                    haystack.len(),
                    std::ptr::null_mut(),
                    0,
                    1,
                    0,
                )
            },
            STATUS_INVALID_ARGUMENT
        );
        assert_eq!(static_prefix_capability_presence(handle), (false, false));

        assert_eq!(
            call_exclusive_static_prefix_preflight_v2(
                handle,
                haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
                &descriptor,
            ),
            STATUS_PARTIAL_PREFLIGHT_ENTER
        );
        // SAFETY: the live continuation inputs are valid except for the
        // deliberately misaligned output pointer.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_continue_v1(
                    handle,
                    haystack.as_ptr(),
                    haystack.len(),
                    misaligned_result,
                    0,
                    1,
                    0,
                )
            },
            STATUS_INVALID_ARGUMENT
        );
        assert_eq!(static_prefix_capability_presence(handle), (false, false));

        admit_static_prefix_span_postflight_for_test(
            handle,
            haystack,
            &mut result,
            &identity,
            &descriptor,
        );
        // SAFETY: the postflight carries valid readable inputs and a null
        // output solely to exercise its early invalid-argument path.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_recover_span_v2(
                    handle,
                    haystack.as_ptr(),
                    haystack.len(),
                    0,
                    haystack.len(),
                    std::ptr::null_mut(),
                    identity.as_ptr(),
                    haystack.len(),
                )
            },
            STATUS_INVALID_ARGUMENT
        );
        assert_eq!(static_prefix_capability_presence(handle), (false, false));

        admit_static_prefix_span_postflight_for_test(
            handle,
            haystack,
            &mut result,
            &identity,
            &descriptor,
        );
        // SAFETY: every postflight input except the output alignment is valid.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_recover_span_v2(
                    handle,
                    haystack.as_ptr(),
                    haystack.len(),
                    0,
                    haystack.len(),
                    misaligned_result,
                    identity.as_ptr(),
                    haystack.len(),
                )
            },
            STATUS_INVALID_ARGUMENT
        );
        assert_eq!(static_prefix_capability_presence(handle), (false, false));

        admit_static_prefix_span_postflight_for_test(
            handle,
            haystack,
            &mut result,
            &identity,
            &descriptor,
        );
        result = sentinel;
        assert_eq!(
            call_exclusive_static_prefix_recover_span_v2(
                handle,
                haystack,
                2,
                1,
                &mut result,
                &identity,
                haystack.len(),
            ),
            STATUS_INVALID_ARGUMENT
        );
        assert_eq!(result, sentinel);
        assert_eq!(static_prefix_capability_presence(handle), (false, false));

        admit_static_prefix_span_postflight_for_test(
            handle,
            haystack,
            &mut result,
            &identity,
            &descriptor,
        );
        assert_eq!(
            call_exclusive_static_prefix_recover_span_v2(
                handle,
                haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
                0,
            ),
            STATUS_INVALID_ARGUMENT
        );
        assert_eq!(static_prefix_capability_presence(handle), (false, false));

        admit_static_prefix_span_postflight_for_test(
            handle,
            haystack,
            &mut result,
            &identity,
            &descriptor,
        );
        result = sentinel;
        assert_eq!(
            call_exclusive_static_prefix_recover_span_v2(
                handle,
                haystack,
                1,
                haystack.len(),
                &mut result,
                &identity,
                haystack.len(),
            ),
            STATUS_RUNTIME_FAILURE,
            "a well-formed but wrong window must consume the ticket"
        );
        assert_eq!(result, sentinel);
        assert_eq!(static_prefix_capability_presence(handle), (false, false));
        assert_eq!(
            call_exclusive_static_prefix_recover_span_v2(
                handle,
                haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
                haystack.len(),
            ),
            STATUS_RUNTIME_FAILURE,
            "corrected arguments cannot replay a malformed or mismatched call"
        );
        assert_eq!(result, sentinel);

        // SAFETY: this test owns the unique live handle and no call overlaps
        // destruction.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
            STATUS_SUCCESS
        );
    }

    #[test]
    fn static_prefix_v2_intervening_mutation_retires_capabilities() {
        let compiled = compile(
            CompileRequest::new("(?:ab|ac)+z", Target::x86_64_linux())
                .mode(CompileMode::Fast)
                .output(OutputContract::Span),
        )
        .expect("compile intervening-mutation Span fixture");
        let identity = compiled.receipt().program_sha256;
        let serialized = compiled.program().serialize().expect("serialize fixture");
        let handle = prepare_exclusive(&serialized);
        let haystack = b"xxabacz";
        let descriptor = [0_u32; STATIC_PREFIX_RESUME_DESCRIPTOR_V1_HEADER_BYTES / 4];
        let sentinel = FreAotRegexResultV1 {
            start: 0xfeed_face,
            end: 0xdead_beef,
        };
        let mut result = sentinel;

        assert_eq!(
            call_exclusive_static_prefix_preflight_v2(
                handle,
                haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
                &descriptor,
            ),
            STATUS_PARTIAL_PREFLIGHT_ENTER
        );
        assert_eq!(static_prefix_capability_presence(handle), (true, false));
        assert_eq!(
            call_exclusive(handle, haystack, 0, haystack.len(), &mut result),
            STATUS_MATCH
        );
        assert_eq!(static_prefix_capability_presence(handle), (false, false));
        result = sentinel;
        assert_eq!(
            call_exclusive_static_prefix_recover_span_v2(
                handle,
                haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
                haystack.len(),
            ),
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(result, sentinel);

        admit_static_prefix_span_postflight_for_test(
            handle,
            haystack,
            &mut result,
            &identity,
            &descriptor,
        );
        assert_eq!(
            call_exclusive(handle, haystack, 0, haystack.len(), &mut result),
            STATUS_MATCH
        );
        assert_eq!(static_prefix_capability_presence(handle), (false, false));
        result = sentinel;
        assert_eq!(
            call_exclusive_static_prefix_recover_span_v2(
                handle,
                haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
                haystack.len(),
            ),
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(result, sentinel);

        // SAFETY: this test owns the unique live handle and no call overlaps
        // destruction.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
            STATUS_SUCCESS
        );
    }

    #[test]
    fn static_prefix_v2_complete_proofs_use_the_retained_row_crossover() {
        let mut limits = CompileLimitsV1::default();
        limits.determinize.max_states = 0;
        let compiled = compile(
            CompileRequest::new("(?:x|yz)7[A-Za-z]{1,2}", Target::x86_64_linux())
                .mode(CompileMode::Optimizing)
                .limits(limits)
                .output(OutputContract::Span),
        )
        .expect("compile static-prefix V2 proof fixture");
        assert!(!compiled
            .program()
            .compiler_private_static_prefix_complete_proofs_should_run(255));
        assert!(compiled
            .program()
            .compiler_private_static_prefix_complete_proofs_should_run(256));
        let identity = compiled.receipt().program_sha256;
        let serialized = compiled.program().serialize().expect("serialize fixture");
        let handle = prepare_exclusive(&serialized);
        let descriptor = [0_u32; STATIC_PREFIX_RESUME_DESCRIPTOR_V1_HEADER_BYTES / 4];
        let short = vec![b'x'; 255];
        let long = vec![b'x'; 256];
        let sentinel = FreAotRegexResultV1 {
            start: 0xfeed_face,
            end: 0xdead_beef,
        };
        let mut result = sentinel;

        assert_eq!(
            call_exclusive_static_prefix_preflight_v2(
                handle,
                &short,
                0,
                short.len(),
                &mut result,
                &identity,
                &descriptor,
            ),
            STATUS_PARTIAL_PREFLIGHT_ENTER
        );
        assert_eq!(result, sentinel);
        assert!(exclusive_frozen_header_is_active(handle));

        result = sentinel;
        assert_eq!(
            call_exclusive_static_prefix_preflight_v2(
                handle,
                &long,
                0,
                long.len(),
                &mut result,
                &identity,
                &descriptor,
            ),
            STATUS_NO_MATCH
        );
        assert_eq!(result, FreAotRegexResultV1::default());
        assert!(!exclusive_frozen_header_is_active(handle));

        result = sentinel;
        // A complete proof clears the earlier short-window ticket and does not
        // admit a replacement, so no malformed descriptor can be consumed.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_compiler_private_search_exclusive_static_prefix_continue_v1(
                    handle,
                    long.as_ptr(),
                    long.len(),
                    &raw mut result,
                    0,
                    128,
                    0,
                )
            },
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(result, sentinel);

        // SAFETY: this test owns the unique live handle and no call overlaps
        // destruction.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
            STATUS_SUCCESS
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one lifecycle ledger keeps initial publication, alternate legacy revocation, and wrong-artifact fallback transactional"
    )]
    fn frozen_header_is_first_and_every_legacy_or_fallback_path_revokes_it() {
        let pattern = r"a+Q|[b-c][a-b]{1,5}(?:x+|y+)";
        let mut limits = CompileLimitsV1::default();
        limits.determinize.max_states = 8;
        let compiled = compile(
            CompileRequest::new(pattern, Target::x86_64_linux())
                .mode(CompileMode::Optimizing)
                .limits(limits)
                .output(OutputContract::SelectedEnd),
        )
        .expect("compile retained frozen fixture");
        assert_eq!(
            compiled.receipt().engine_selection_reason,
            EngineSelectionReason::DeterminizationResourceLimit
        );
        let identity = compiled.receipt().program_sha256;
        let serialized = compiled.program().serialize().expect("serialize fixture");
        let haystack = b"xxcbbbbx";
        let window = SearchWindow::full(haystack);
        let expected = compiled
            .search(haystack, window)
            .expect("portable expected result");
        let expected_ffi = expected_ffi(expected);

        let mut direct = PreparedAotRegex::deserialize(&serialized).expect("prepare direct Rust");
        assert!(direct.fully_prefilled_fallback.is_some());
        assert!(
            direct.frozen_dynamic_rows.is_some(),
            "a closed compact projection should own the native entry while the retained receipt remains available to fallbacks"
        );
        assert!(direct.frozen_header.has_dynamic_rows());
        assert!(direct.frozen_header.is_active());
        assert!(direct.frozen_header_owner_generation_key.is_some());
        assert!(direct.frozen_static_continuation_rows.is_some());
        assert!(direct.static_continuation_header.has_dynamic_rows());
        assert!(direct.static_continuation_header.is_active());
        assert!(direct.static_continuation_owner_generation_key.is_some());
        assert_eq!(*direct.frozen_header.artifact_identity(), identity);
        assert_eq!(
            (&raw const direct).cast::<u8>().addr(),
            (&raw const direct.frozen_header).cast::<u8>().addr(),
            "the opaque prepared allocation must begin with the versioned header"
        );
        assert_eq!(direct.search(haystack, window).unwrap(), expected);
        assert!(!direct.frozen_header.is_active());
        assert!(!direct.static_continuation_header.is_active());
        assert!(direct.frozen_header_owner_generation_key.is_some());
        assert!(direct.static_continuation_owner_generation_key.is_some());
        assert_eq!(direct.search(haystack, window).unwrap(), expected);
        assert!(!direct.frozen_header.is_active(), "a legacy search cannot reactivate");

        let legacy = prepare_exclusive(&serialized);
        assert!(exclusive_frozen_header_is_active(legacy));
        assert_eq!(exclusive_frozen_header_identity(legacy), identity);
        let mut legacy_result = FreAotRegexResultV1 {
            start: usize::MAX,
            end: usize::MAX,
        };
        assert_eq!(
            (
                call_exclusive(legacy, haystack, 0, haystack.len(), &mut legacy_result),
                legacy_result,
            ),
            expected_ffi
        );
        assert!(!exclusive_frozen_header_is_active(legacy));
        let mut fallback_after_legacy = FreAotRegexResultV1::default();
        assert_eq!(
            (
                call_exclusive_frozen_fallback(
                    legacy,
                    haystack,
                    0,
                    haystack.len(),
                    &mut fallback_after_legacy,
                    &identity,
                ),
                fallback_after_legacy,
            ),
            expected_ffi
        );
        assert!(
            !exclusive_frozen_header_is_active(legacy),
            "a correct fallback after legacy use cannot restore the seal"
        );
        // SAFETY: this test owns the unique live allocation and no call overlaps
        // its destruction.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(legacy) },
            STATUS_SUCCESS
        );

        let alternate = prepare_exclusive(&serialized);
        assert!(exclusive_frozen_header_is_active(alternate));
        assert!(matches!(
            call_partial_should_enter(alternate, 4_096),
            PARTIAL_ENTRY_BYPASS | PARTIAL_ENTRY_ENTER
        ));
        assert!(
            !exclusive_frozen_header_is_active(alternate),
            "an alternate legacy admission entry must permanently kill the seal"
        );
        // SAFETY: unique, live, non-overlapping handle.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(alternate) },
            STATUS_SUCCESS
        );

        let wrong_artifact = prepare_exclusive(&serialized);
        assert!(exclusive_frozen_header_is_active(wrong_artifact));
        let mut mismatched_identity = identity;
        mismatched_identity[0] ^= 0x80;
        let sentinel = FreAotRegexResultV1 {
            start: 0xfeed_face,
            end: 0xdead_beef,
        };
        let mut wrong_result = sentinel;
        assert_eq!(
            call_exclusive_frozen_fallback(
                wrong_artifact,
                haystack,
                0,
                haystack.len(),
                &mut wrong_result,
                &mismatched_identity,
            ),
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(wrong_result, sentinel, "wrong-artifact output is transactional");
        assert!(
            !exclusive_frozen_header_is_active(wrong_artifact),
            "wrong-artifact fallback must revoke before authentication"
        );
        let mut recovered = FreAotRegexResultV1::default();
        assert_eq!(
            (
                call_exclusive_frozen_fallback(
                    wrong_artifact,
                    haystack,
                    0,
                    haystack.len(),
                    &mut recovered,
                    &identity,
                ),
                recovered,
            ),
            expected_ffi
        );
        assert!(!exclusive_frozen_header_is_active(wrong_artifact));
        // SAFETY: unique, live, non-overlapping handle.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(wrong_artifact) },
            STATUS_SUCCESS
        );
    }

    #[test]
    fn compact_dynamic_owner_survives_moves_and_legacy_revocation() {
        let mut limits = CompileLimitsV1::default();
        limits.determinize.max_states = 0;
        let compiled = compile(
            CompileRequest::new("(?:ab|ac)+z", Target::x86_64_linux())
                .mode(CompileMode::Optimizing)
                .limits(limits)
                .output(OutputContract::Exists),
        )
        .expect("compile compact dynamic owner fixture");
        let serialized = compiled.program().serialize().expect("serialize fixture");
        let haystack = b"xxabacz";
        let window = SearchWindow::full(haystack);
        let expected = compiled.search(haystack, window).expect("portable result");

        let prepared = PreparedAotRegex::deserialize(&serialized).expect("prepare compact owner");
        assert!(prepared.fully_prefilled_fallback.is_none());
        assert!(prepared.frozen_dynamic_rows.is_some());
        assert!(prepared.frozen_header.has_dynamic_rows());
        let mut owners = vec![prepared];
        let mut prepared = owners.pop().expect("move prepared owner through a container");
        assert!(prepared.frozen_header.has_dynamic_rows());
        assert_eq!(prepared.search(haystack, window).unwrap(), expected);
        assert!(!prepared.frozen_header.is_active());
        assert!(prepared.frozen_dynamic_rows.is_some());
        assert_eq!(prepared.search(haystack, window).unwrap(), expected);
        assert!(!prepared.frozen_header.is_active());
    }

    #[test]
    fn compact_v2_retained_holes_fall_through_a_foreign_continuation_owner() {
        let pattern = r"a+Q|[b-c][a-b]{1,5}(?:x+|y+)";
        let mut limits = CompileLimitsV1::default();
        limits.determinize.max_states = 8;
        let compiled = compile(
            CompileRequest::new(pattern, Target::x86_64_linux())
                .mode(CompileMode::Optimizing)
                .limits(limits)
                .output(OutputContract::Exists),
        )
        .expect("compile retained compact-v2 fixture");
        let serialized = compiled.program().serialize().unwrap();
        let mut haystack = b"xxcbbbbyyy".to_vec();
        haystack.resize(320, b'!');
        let window = SearchWindow::full(&haystack);
        let expected = compiled.search(&haystack, window).unwrap();

        let mut batched = PreparedAotRegex::deserialize(&serialized).unwrap();
        let batched_format = batched
            .frozen_static_continuation_rows
            .as_ref()
            .expect("retained fixture has a static continuation owner")
            .compiler_private_format_version();
        assert!(matches!(
            batched_format,
            FROZEN_DYNAMIC_ROWS_V11_FORMAT_VERSION
                | FROZEN_DYNAMIC_ROWS_V13_FORMAT_VERSION
                | FROZEN_DYNAMIC_ROWS_V14_FORMAT_VERSION
        ));
        assert!(batched.fully_prefilled_fallback.is_some());
        assert_eq!(
            batched
                .preflight_retained_partial_native_root(
                    &haystack,
                    window,
                    compiled.receipt().program_sha256,
                )
                .unwrap(),
            RetainedPartialPreflight::Enter(window)
        );
        assert_eq!(batched.retained_partial_frozen_owner_handoffs, 0);
        assert_eq!(
            batched
                .search_from_preflight_retained_partial_resume_ticket_inferred(
                    &haystack,
                    0,
                    5,
                    0,
                )
                .unwrap(),
            expected
        );
        assert_eq!(batched.retained_partial_frozen_owner_handoffs, 1);

        // Obtain a valid V6/V7 arbitrary-state owner from a separate general
        // program, then place it in an otherwise identical retained session.
        // V6/V7 are now eligible formats, but the foreign program/cache
        // lineage must decline before mutation and preserve the established
        // receipt-backed K0 continuation.
        let mut loop_limits = CompileLimitsV1::default();
        loop_limits.determinize.max_states = 0;
        let loop_compiled = compile(
            CompileRequest::new(
                r"Q(?:ab|cd|ef|gh|ij)(?-u:[^Q])*@|Q",
                Target::x86_64_linux(),
            )
            .mode(CompileMode::Optimizing)
            .limits(loop_limits)
            .output(OutputContract::SelectedEnd),
        )
        .expect("compile loop-continuation owner");
        let loop_serialized = loop_compiled.program().serialize().unwrap();
        let mut loop_prepared = PreparedAotRegex::deserialize(&loop_serialized).unwrap();
        let loop_owner = loop_prepared
            .frozen_static_continuation_rows
            .take()
            .expect("loop fixture has a continuation owner");
        assert!(matches!(
            loop_owner.compiler_private_format_version(),
            fre_aot_regex::FROZEN_DYNAMIC_ROWS_V6_FORMAT_VERSION
                | fre_aot_regex::FROZEN_DYNAMIC_ROWS_V7_FORMAT_VERSION
        ));

        let mut legacy_k0 = PreparedAotRegex::deserialize(&serialized).unwrap();
        legacy_k0.deactivate_frozen_header();
        legacy_k0.frozen_static_continuation_rows = Some(loop_owner);
        assert_eq!(
            legacy_k0
                .preflight_retained_partial_native_root(
                    &haystack,
                    window,
                    compiled.receipt().program_sha256,
                )
                .unwrap(),
            RetainedPartialPreflight::Enter(window)
        );
        assert_eq!(
            legacy_k0
                .search_from_preflight_retained_partial_resume_ticket_inferred(
                    &haystack,
                    0,
                    5,
                    0,
                )
                .unwrap(),
            expected
        );
        assert_eq!(legacy_k0.retained_partial_frozen_owner_handoffs, 1);
    }

    #[test]
    fn compact_v3_publishes_one_status8_continuation_and_declines_to_v2_once() {
        let pattern = r"a+Q|[b-c][a-b]{1,5}(?:x+|y+)";
        let mut limits = CompileLimitsV1::default();
        limits.determinize.max_states = 8;
        let compiled = compile(
            CompileRequest::new(pattern, Target::x86_64_linux())
                .mode(CompileMode::Optimizing)
                .limits(limits)
                .output(OutputContract::Exists),
        )
        .expect("compile retained compact-v3 fixture");
        let identity = compiled.receipt().program_sha256;
        let serialized = compiled.program().serialize().unwrap();
        let handle = prepare_exclusive(&serialized);
        let mut haystack = b"xxcbbbbyyy".to_vec();
        haystack.resize(320, b'!');
        let sentinel = FreAotRegexResultV1 {
            start: 0xfeed_face,
            end: 0xdead_beef,
        };
        let mut result = sentinel;
        let mut admitted = FreAotRegexSearchWindowV1 {
            start: usize::MAX,
            end: usize::MAX,
        };
        assert_eq!(
            call_exclusive_partial_native_root_preflight(
                handle,
                &haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
                &mut admitted,
            ),
            STATUS_PARTIAL_PREFLIGHT_ENTER
        );
        assert_eq!(result, sentinel);
        assert_eq!(
            admitted,
            FreAotRegexSearchWindowV1 {
                start: 0,
                end: haystack.len(),
            }
        );

        // SAFETY: this test exclusively owns the live allocation. Projection
        // is read-only and supplies the exact expected ABI payload.
        let (expected_state, expected_pending, expected_format) = unsafe {
            let prepared = &mut *handle.0.cast::<PreparedAotRegex>();
            assert!(!prepared.static_continuation_header.is_active());
            assert!(prepared.static_continuation_owner_generation_key.is_some());
            let receipt = prepared.fully_prefilled_fallback.unwrap();
            let owner = prepared
                .frozen_static_continuation_rows
                .as_ref()
                .expect("batched continuation owner");
            let projection = prepared
                .program
                .try_project_preflight_retained_partial_resume_ticket_with_frozen_static_continuation_rows_workspace(
                    &haystack,
                    &prepared.workspace,
                    owner,
                    0,
                    5,
                    0,
                    receipt,
                )
                .unwrap()
                .expect("compact-v3 projection");
            (
                projection.canonical_state(),
                projection.pending_end_word(),
                projection.format_version(),
            )
        };
        assert!(matches!(
            expected_format,
            FROZEN_DYNAMIC_ROWS_V11_FORMAT_VERSION
                | FROZEN_DYNAMIC_ROWS_V13_FORMAT_VERSION
                | FROZEN_DYNAMIC_ROWS_V14_FORMAT_VERSION
        ));
        assert_eq!(
            call_exclusive_from_partial_preflight_compact_v3(
                handle,
                &haystack,
                &mut result,
                0,
                5,
                0,
            ),
            STATUS_STATIC_PREFIX_NATIVE_CONTINUATION_RESUME
        );
        assert_eq!(
            result,
            FreAotRegexResultV1 {
                start: expected_state,
                end: expected_pending,
            }
        );
        // SAFETY: the allocation remains exclusively owned between calls.
        unsafe {
            let prepared = &mut *handle.0.cast::<PreparedAotRegex>();
            assert!(!prepared.frozen_header.is_active());
            assert!(prepared.static_continuation_header.is_active());
            assert_eq!(
                prepared
                    .static_continuation_header
                    .compiler_private_dynamic_rows_format_version(),
                Some(expected_format)
            );
            assert_eq!(
                (&raw const prepared.static_continuation_header)
                    .cast::<u8>()
                    .addr()
                    - (&raw const *prepared).cast::<u8>().addr(),
                FROZEN_PREPARED_HEADER_V6_BYTES,
            );
        }

        result = sentinel;
        assert_eq!(
            call_exclusive_from_partial_preflight_compact_v3(
                handle,
                &haystack,
                &mut result,
                0,
                5,
                0,
            ),
            STATUS_RUNTIME_FAILURE,
            "compact-v3 cannot replay continuation ownership"
        );
        assert_eq!(result, sentinel);
        // SAFETY: compact-v2 is deliberately invoked out of phase; it must
        // reject without consuming the continuation-owned transaction.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_search_exclusive_from_partial_preflight_compact_v2(
                    handle,
                    haystack.as_ptr(),
                    haystack.len(),
                    &raw mut result,
                    0,
                    5,
                    0,
                )
            },
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(result, sentinel);

        // A following preflight is authoritative evidence that the immutable
        // continuation returned locally, settles it, and arms a fresh root.
        assert_eq!(
            call_exclusive_partial_native_root_preflight(
                handle,
                &haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
                &mut admitted,
            ),
            STATUS_PARTIAL_PREFLIGHT_ENTER
        );
        assert_eq!(result, sentinel);
        assert_eq!(admitted.end, haystack.len());

        // Less than one complete supertransition remains. Projection declines
        // read-only and compact-v2 completes and consumes this root once.
        result = sentinel;
        let decline_position = haystack.len() - 1;
        let declined_status = call_exclusive_from_partial_preflight_compact_v3(
            handle,
            &haystack,
            &mut result,
            0,
            decline_position,
            0,
        );
        assert!(matches!(declined_status, STATUS_NO_MATCH | STATUS_MATCH));
        assert_ne!(result, sentinel);
        result = sentinel;
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_search_exclusive_from_partial_preflight_compact_v2(
                    handle,
                    haystack.as_ptr(),
                    haystack.len(),
                    &raw mut result,
                    0,
                    decline_position,
                    0,
                )
            },
            STATUS_RUNTIME_FAILURE,
            "compact-v3 decline must consume through compact-v2 exactly once"
        );
        assert_eq!(result, sentinel);

        // SAFETY: unique live handle, no overlapping call.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
            STATUS_SUCCESS
        );
    }

    #[test]
    fn retained_span_postflight_consumes_compact_v3_continuation_ownership() {
        let mut limits = CompileLimitsV1::default();
        limits.determinize.max_states = 8;
        let compiled = compile(
            CompileRequest::new(
                r"a+Q|[b-c][a-b]{1,5}(?:x+|y+)",
                Target::x86_64_linux(),
            )
            .mode(CompileMode::Optimizing)
            .limits(limits)
            .output(OutputContract::Span),
        )
        .expect("compile retained compact-v3 Span fixture");
        assert_eq!(compiled.program().exact_match_width(), None);
        let identity = compiled.receipt().program_sha256;
        let serialized = compiled.program().serialize().unwrap();
        let handle = prepare_exclusive(&serialized);
        let mut haystack = b"xxcbbbbyyy".to_vec();
        haystack.resize(320, b'!');
        let expected = compiled.search(&haystack, SearchWindow::full(&haystack)).unwrap();
        let MatchResult::Span(Some((expected_start, selected_end))) = expected else {
            panic!("Span fixture did not match: {expected:?}");
        };
        assert_eq!(selected_end, 10);
        let sentinel = FreAotRegexResultV1 { start: 71, end: 73 };
        let mut result = sentinel;
        let mut admitted = FreAotRegexSearchWindowV1 { start: 79, end: 83 };
        assert_eq!(
            call_exclusive_partial_native_root_preflight(
                handle,
                &haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
                &mut admitted,
            ),
            STATUS_PARTIAL_PREFLIGHT_ENTER
        );
        assert_eq!(result, sentinel);
        assert_eq!(admitted.start, 0);
        assert_eq!(admitted.end, haystack.len());
        assert_eq!(
            call_exclusive_from_partial_preflight_compact_v3(
                handle,
                &haystack,
                &mut result,
                0,
                5,
                0,
            ),
            STATUS_STATIC_PREFIX_NATIVE_CONTINUATION_RESUME
        );
        // The status-8 payload is not a semantic Span; the generated tail
        // would now select `selected_end` before invoking this postflight.
        result = sentinel;
        assert_eq!(
            call_exclusive_recover_partial_span(
                handle,
                &haystack,
                admitted.start,
                admitted.end,
                &mut result,
                &identity,
                selected_end,
            ),
            STATUS_MATCH
        );
        assert_eq!(
            result,
            FreAotRegexResultV1 {
                start: expected_start,
                end: selected_end,
            }
        );
        result = sentinel;
        assert_eq!(
            call_exclusive_recover_partial_span(
                handle,
                &haystack,
                admitted.start,
                admitted.end,
                &mut result,
                &identity,
                selected_end,
            ),
            STATUS_RUNTIME_FAILURE,
            "continuation-owned Span recovery is one shot"
        );
        assert_eq!(result, sentinel);

        // SAFETY: unique live handle, no overlapping call.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
            STATUS_SUCCESS
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "all output contracts and raw-boundary authentication failures share the same exclusive continuation lifecycle"
    )]
    fn exclusive_partial_resume_abi_authenticates_and_continues_without_replay() {
        let cases = [
            (
                r"a+Q|[b-c][a-b]{1,5}(?:x+|y+)",
                OutputContract::Exists,
                8,
                b"xxcbbbbyyy".as_slice(),
                0,
                5,
                None,
            ),
            (
                r"(?:a+Q|[b-c][a-b]{1,10}(?:z[a-b]+|z))",
                OutputContract::SelectedEnd,
                10,
                b"cbza".as_slice(),
                2,
                3,
                Some(3),
            ),
            (
                r"(?:a+Q|[b-c][a-b]{1,10}(?:z[a-b]+|z))",
                OutputContract::Span,
                10,
                b"cbza".as_slice(),
                2,
                3,
                Some(3),
            ),
        ];
        let sentinel = FreAotRegexResultV1 { start: 71, end: 73 };

        for (pattern, output, max_states, haystack, resume_state, resume_position, pending_end) in
            cases
        {
            let mut limits = CompileLimitsV1::default();
            limits.determinize.max_states = max_states;
            let compiled = compile(
                CompileRequest::new(pattern, Target::x86_64_linux())
                    .mode(CompileMode::Optimizing)
                    .limits(limits)
                    .output(output),
            )
            .expect("compile retained partial artifact");
            let stats = compiled
                .program()
                .partial_dfa_stats()
                .expect("partial statistics")
                .expect("retained partial table");
            assert!(resume_state < stats.resume_frontiers);
            let identity = compiled.receipt().program_sha256;
            let serialized = compiled.program().serialize().expect("serialize partial");
            let handle = prepare_exclusive(&serialized);

            let mut expected_result = sentinel;
            let expected_status =
                call_exclusive(handle, haystack, 0, haystack.len(), &mut expected_result);
            let mut resumed_result = sentinel;
            let resumed_status = call_exclusive_from_partial(
                handle,
                haystack,
                0,
                haystack.len(),
                &mut resumed_result,
                &identity,
                resume_state,
                resume_position,
                pending_end,
            );
            assert_eq!(
                (resumed_status, resumed_result),
                (expected_status, expected_result),
                "{output:?}"
            );

            let mut wrong_identity = identity;
            wrong_identity[0] ^= 1;
            let mut result = sentinel;
            {
                let mut reject_resume = |expected_identity: &[u8; ARTIFACT_IDENTITY_BYTES],
                                         state,
                                         position,
                                         pending| {
                    result = sentinel;
                    assert_eq!(
                        call_exclusive_from_partial(
                            handle,
                            haystack,
                            0,
                            haystack.len(),
                            &mut result,
                            expected_identity,
                            state,
                            position,
                            pending,
                        ),
                        STATUS_RUNTIME_FAILURE
                    );
                    assert_eq!(result, sentinel);
                };
                reject_resume(&wrong_identity, resume_state, resume_position, pending_end);
                reject_resume(
                    &identity,
                    stats.resume_frontiers,
                    resume_position,
                    pending_end,
                );
                let wrong_pending = if pending_end.is_some() { None } else { Some(0) };
                reject_resume(&identity, resume_state, resume_position, wrong_pending);
                if pending_end.is_some() {
                    reject_resume(
                        &identity,
                        resume_state,
                        resume_position,
                        resume_position.checked_add(1),
                    );
                }
                for invalid_position in [0, haystack.len()] {
                    reject_resume(&identity, resume_state, invalid_position, pending_end);
                }
            }
            for (invalid_start, invalid_end) in [
                (1, 0),
                (
                    0,
                    haystack.len().checked_add(1).expect("small test haystack"),
                ),
            ] {
                assert_eq!(
                    call_exclusive_from_partial(
                        handle,
                        haystack,
                        invalid_start,
                        invalid_end,
                        &mut result,
                        &identity,
                        resume_state,
                        resume_position,
                        pending_end,
                    ),
                    STATUS_INVALID_ARGUMENT
                );
                assert_eq!(result, sentinel);
            }

            if output == OutputContract::Exists {
                let raw_call =
                    |raw_handle, raw_haystack, raw_result, raw_identity, pending_present| {
                        // SAFETY: every deliberately invalid pointer/flag is
                        // rejected before dereference; all non-null extents remain
                        // live and the exclusive handle has no overlapping call.
                        unsafe {
                            fre_aot_regex_runtime_search_exclusive_from_partial_v1(
                                raw_handle,
                                raw_haystack,
                                haystack.len(),
                                0,
                                haystack.len(),
                                raw_result,
                                raw_identity,
                                resume_state,
                                resume_position,
                                pending_present,
                                pending_end.unwrap_or(0),
                            )
                        }
                    };
                assert_eq!(
                    raw_call(
                        handle,
                        std::ptr::null(),
                        &raw mut result,
                        identity.as_ptr(),
                        u32::from(pending_end.is_some()),
                    ),
                    STATUS_INVALID_ARGUMENT
                );
                assert_eq!(
                    raw_call(
                        handle,
                        haystack.as_ptr(),
                        std::ptr::null_mut(),
                        identity.as_ptr(),
                        u32::from(pending_end.is_some()),
                    ),
                    STATUS_INVALID_ARGUMENT
                );
                assert_eq!(
                    raw_call(
                        handle,
                        haystack.as_ptr(),
                        &raw mut result,
                        std::ptr::null(),
                        u32::from(pending_end.is_some()),
                    ),
                    STATUS_INVALID_ARGUMENT
                );
                assert_eq!(
                    raw_call(
                        handle,
                        haystack.as_ptr(),
                        &raw mut result,
                        identity.as_ptr(),
                        2,
                    ),
                    STATUS_INVALID_ARGUMENT
                );
                assert_eq!(
                    raw_call(
                        FreAotRegexExclusiveHandleV1::INVALID,
                        haystack.as_ptr(),
                        &raw mut result,
                        identity.as_ptr(),
                        u32::from(pending_end.is_some()),
                    ),
                    STATUS_INVALID_HANDLE
                );
                assert_eq!(result, sentinel);
            }

            let plain = compile(
                CompileRequest::new(pattern, Target::x86_64_linux())
                    .mode(CompileMode::Fast)
                    .output(output),
            )
            .expect("compile no-partial artifact");
            assert!(plain.program().partial_dfa_stats().unwrap().is_none());
            let plain_identity = plain.receipt().program_sha256;
            let plain_serialized = plain.program().serialize().expect("serialize plain");
            let plain_handle = prepare_exclusive(&plain_serialized);
            assert_eq!(
                call_exclusive_from_partial(
                    plain_handle,
                    haystack,
                    0,
                    haystack.len(),
                    &mut result,
                    &plain_identity,
                    resume_state,
                    resume_position,
                    pending_end,
                ),
                STATUS_RUNTIME_FAILURE
            );
            assert_eq!(result, sentinel);

            // SAFETY: each handle is still uniquely owned and no call
            // overlaps either destruction.
            assert_eq!(
                unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(plain_handle) },
                STATUS_SUCCESS
            );
            assert_eq!(
                unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
                STATUS_SUCCESS
            );
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the end-to-end adaptive protocol keeps admission, continuation, warm completion, and lazy native completion in one exclusive handle lifecycle"
    )]
    fn exclusive_native_partial_warm_resume_resets_admission() {
        let pattern = r"a+Q|[b-c][a-b]{1,5}(?:x+|y+)";
        let mut limits = CompileLimitsV1::default();
        limits.determinize.max_states = 8;
        let compiled = compile(
            CompileRequest::new(pattern, Target::x86_64_linux())
                .mode(CompileMode::Optimizing)
                .limits(limits)
                .output(OutputContract::Exists),
        )
        .expect("compile adaptive retained partial artifact");
        assert!(compiled.program().partial_dfa_stats().unwrap().is_some());
        let identity = compiled.receipt().program_sha256;
        let serialized = compiled.program().serialize().expect("serialize partial");
        let handle = prepare_exclusive(&serialized);
        let mut haystack = b"xxcbbbbyyy".to_vec();
        haystack.resize(1_024, b'x');
        let expected = expected_ffi(
            compiled
                .search(&haystack, SearchWindow::full(&haystack))
                .expect("portable adaptive result"),
        );

        // The first shallow continuation publishes its missing K0 rows. The
        // second and third continuations complete entirely through immutable
        // warmed rows, so each one resets admission instead of creating a
        // bypass interval.
        for _ in 0..3 {
            assert_eq!(
                call_partial_should_enter(handle, haystack.len()),
                PARTIAL_ENTRY_ENTER
            );
            let mut result = FreAotRegexResultV1::default();
            assert_eq!(
                call_exclusive_from_partial(
                    handle,
                    &haystack,
                    0,
                    haystack.len(),
                    &mut result,
                    &identity,
                    0,
                    5,
                    None,
                ),
                expected.0
            );
            assert_eq!(result, expected.1);
        }

        assert_eq!(
            call_partial_should_enter(handle, haystack.len()),
            PARTIAL_ENTRY_ENTER,
            "warm K0 completion resets adaptive admission"
        );
        // Model a native scan that returned locally: no continuation call is
        // made, so the next admission must settle it as a completion.
        assert_eq!(
            call_partial_should_enter(handle, haystack.len()),
            PARTIAL_ENTRY_ENTER,
            "local native completion resets adaptive backoff"
        );
        let mut result = FreAotRegexResultV1::default();
        assert_eq!(
            call_exclusive_from_partial(
                handle,
                &haystack,
                0,
                haystack.len(),
                &mut result,
                &identity,
                0,
                5,
                None,
            ),
            expected.0
        );
        assert_eq!(result, expected.1);
        assert_eq!(
            call_partial_should_enter(FreAotRegexExclusiveHandleV1::INVALID, haystack.len()),
            PARTIAL_ENTRY_BYPASS
        );

        // SAFETY: the handle remains uniquely owned and no call overlaps its
        // destruction.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
            STATUS_SUCCESS
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "identity, output transactions, exact windows, both ownership orders, and lifecycle form one ABI proof"
    )]
    fn exclusive_partial_preflight_is_transactional_and_returns_exact_windows() {
        let sentinel_result = FreAotRegexResultV1 { start: 71, end: 73 };
        let sentinel_window = FreAotRegexSearchWindowV1 { start: 79, end: 83 };
        let mut limits = CompileLimitsV1::default();
        limits.determinize.max_states = 8;

        let plain = compile(
            CompileRequest::new(
                r"a+Q|[b-c][a-b]{1,5}(?:x+|y+)",
                Target::x86_64_linux(),
            )
            .mode(CompileMode::Optimizing)
            .limits(limits)
            .output(OutputContract::SelectedEnd),
        )
        .expect("compile plain partial preflight artifact");
        assert!(plain.program().partial_dfa_stats().unwrap().is_some());
        let plain_identity = plain.receipt().program_sha256;
        let plain_bytes = plain.program().serialize().unwrap();
        let plain_handle = prepare_exclusive(&plain_bytes);
        let plain_haystack = vec![b'x'; 300];

        // No graph accelerator changes the exact public window. A second call
        // without a continuation also proves that the prior native local
        // completion is settled at the start of this transaction.
        for _ in 0..2 {
            let mut result = sentinel_result;
            let mut window = sentinel_window;
            assert_eq!(
                call_exclusive_partial_preflight(
                    plain_handle,
                    &plain_haystack,
                    11,
                    289,
                    &mut result,
                    &plain_identity,
                    &mut window,
                ),
                STATUS_PARTIAL_PREFLIGHT_ENTER
            );
            assert_eq!(result, sentinel_result);
            assert_eq!(window, FreAotRegexSearchWindowV1 { start: 11, end: 289 });
        }

        // Identity authentication precedes state mutation and both outputs
        // remain transactional on rejection.
        let mut wrong_identity = plain_identity;
        wrong_identity[0] ^= 1;
        let mut result = sentinel_result;
        let mut window = sentinel_window;
        assert_eq!(
            call_exclusive_partial_preflight(
                plain_handle,
                &plain_haystack,
                11,
                289,
                &mut result,
                &wrong_identity,
                &mut window,
            ),
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(result, sentinel_result);
        assert_eq!(window, sentinel_window);

        // The direct ABI remains complete below the native amortization floor.
        assert_eq!(
            call_exclusive_partial_preflight(
                plain_handle,
                &plain_haystack,
                11,
                42,
                &mut result,
                &plain_identity,
                &mut window,
            ),
            STATUS_NO_MATCH
        );
        assert_eq!(result, FreAotRegexResultV1::default());
        assert_eq!(window, sentinel_window);

        result = sentinel_result;
        window = sentinel_window;
        assert_eq!(
            call_exclusive_partial_preflight(
                FreAotRegexExclusiveHandleV1::INVALID,
                &plain_haystack,
                11,
                289,
                &mut result,
                &plain_identity,
                &mut window,
            ),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(result, sentinel_result);
        assert_eq!(window, sentinel_window);
        // SAFETY: all non-null inputs are valid and the deliberately null
        // output is rejected before dereference.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_search_exclusive_partial_preflight_v1(
                    plain_handle,
                    plain_haystack.as_ptr(),
                    plain_haystack.len(),
                    11,
                    289,
                    &raw mut result,
                    plain_identity.as_ptr(),
                    std::ptr::null_mut(),
                )
            },
            STATUS_INVALID_ARGUMENT
        );
        assert_eq!(result, sentinel_result);

        let cut = compile(
            CompileRequest::new(
                r"[b-c][a-b]{1,10}7[A-Za-z]{1,2}",
                Target::x86_64_linux(),
            )
            .mode(CompileMode::Optimizing)
            .limits(limits)
            .output(OutputContract::SelectedEnd),
        )
        .expect("compile cut partial preflight artifact");
        assert!(cut.program().partial_dfa_stats().unwrap().is_some());
        let cut_identity = cut.receipt().program_sha256;
        let cut_bytes = cut.program().serialize().unwrap();
        let cut_handle = prepare_exclusive(&cut_bytes);
        let mut cut_haystack = vec![b'!'; 256 + 16];
        cut_haystack.extend_from_slice(b"cbbbbbbbbbb7AZ");
        result = sentinel_result;
        window = sentinel_window;
        assert_eq!(
            call_exclusive_partial_preflight(
                cut_handle,
                &cut_haystack,
                3,
                cut_haystack.len(),
                &mut result,
                &cut_identity,
                &mut window,
            ),
            STATUS_PARTIAL_PREFLIGHT_ENTER
        );
        assert_eq!(result, sentinel_result);
        assert!(window.start > 3, "mandatory cut did not narrow: {window:?}");
        assert_eq!(window.end, cut_haystack.len());

        // The native-root policy keeps the same authenticated transaction but
        // gives an admitted emitted scanner the original semantic window. The
        // preceding unreported Enter is first settled as a local completion.
        result = sentinel_result;
        window = sentinel_window;
        assert_eq!(
            call_exclusive_partial_native_root_preflight(
                cut_handle,
                &cut_haystack,
                3,
                cut_haystack.len(),
                &mut result,
                &cut_identity,
                &mut window,
            ),
            STATUS_PARTIAL_PREFLIGHT_ENTER
        );
        assert_eq!(result, sentinel_result);
        assert_eq!(
            window,
            FreAotRegexSearchWindowV1 {
                start: 3,
                end: cut_haystack.len(),
            }
        );

        // SAFETY: both handles remain uniquely owned and no call overlaps
        // either destruction.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(cut_handle) },
            STATUS_SUCCESS
        );
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(plain_handle) },
            STATUS_SUCCESS
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "success, exact transaction authentication, all-output rejection, and raw pointer validation share one stable postflight ABI lifecycle"
    )]
    fn exclusive_partial_span_postflight_authenticates_and_recovers() {
        let pattern = r"a+Q|[b-c][a-b]{1,5}(?:x+|y+)";
        let mut limits = CompileLimitsV1::default();
        limits.determinize.max_states = 16;
        let compiled = compile(
            CompileRequest::new(pattern, Target::x86_64_linux())
                .mode(CompileMode::Optimizing)
                .limits(limits)
                .output(OutputContract::Span),
        )
        .expect("compile variable-width retained Span artifact");
        let stats = compiled
            .program()
            .partial_dfa_stats()
            .unwrap()
            .expect("retained Span rows");
        assert!(stats.complete_rows < stats.discovered_states);
        assert_eq!(compiled.program().exact_match_width(), None);

        let identity = compiled.receipt().program_sha256;
        let serialized = compiled.program().serialize().unwrap();
        let handle = prepare_exclusive(&serialized);
        let mut haystack = vec![b'!'; 256];
        haystack.extend_from_slice(b"aQ");
        let public_start = 0_usize;
        let public_end = haystack.len();
        let expected = compiled
            .search(
                &haystack,
                SearchWindow::new(public_start, public_end),
            )
            .unwrap();
        let MatchResult::Span(Some((expected_start, selected_end))) = expected else {
            panic!("fixture did not select a Span: {expected:?}");
        };
        let expected_result = FreAotRegexResultV1 {
            start: expected_start,
            end: selected_end,
        };
        let sentinel_result = FreAotRegexResultV1 { start: 71, end: 73 };
        let sentinel_window = FreAotRegexSearchWindowV1 { start: 79, end: 83 };

        let preflight = || {
            let mut result = sentinel_result;
            let mut window = sentinel_window;
            assert_eq!(
                call_exclusive_partial_preflight(
                    handle,
                    &haystack,
                    public_start,
                    public_end,
                    &mut result,
                    &identity,
                    &mut window,
                ),
                STATUS_PARTIAL_PREFLIGHT_ENTER
            );
            assert_eq!(result, sentinel_result);
            assert_ne!(window, sentinel_window);
            window
        };

        let window = preflight();
        let mut result = sentinel_result;
        assert_eq!(
            call_exclusive_recover_partial_span(
                handle,
                &haystack,
                window.start,
                window.end,
                &mut result,
                &identity,
                selected_end,
            ),
            STATUS_MATCH
        );
        assert_eq!(result, expected_result);

        // The exact preflight transaction is single use.
        result = sentinel_result;
        assert_eq!(
            call_exclusive_recover_partial_span(
                handle,
                &haystack,
                window.start,
                window.end,
                &mut result,
                &identity,
                selected_end,
            ),
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(result, sentinel_result);

        // A foreign identity is rejected before consuming the transaction.
        let window = preflight();
        let mut wrong_identity = identity;
        wrong_identity[0] ^= 1;
        assert_eq!(
            call_exclusive_recover_partial_span(
                handle,
                &haystack,
                window.start,
                window.end,
                &mut result,
                &wrong_identity,
                selected_end,
            ),
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(result, sentinel_result);
        assert_eq!(
            call_exclusive_recover_partial_span(
                handle,
                &haystack,
                window.start,
                window.end,
                &mut result,
                &identity,
                selected_end,
            ),
            STATUS_MATCH
        );
        assert_eq!(result, expected_result);

        // A different valid window aborts the transaction and cannot be
        // followed by a retry against the originally admitted window.
        let window = preflight();
        assert!(selected_end > window.start + 1);
        result = sentinel_result;
        assert_eq!(
            call_exclusive_recover_partial_span(
                handle,
                &haystack,
                window.start + 1,
                window.end,
                &mut result,
                &identity,
                selected_end,
            ),
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(result, sentinel_result);
        assert_eq!(
            call_exclusive_recover_partial_span(
                handle,
                &haystack,
                window.start,
                window.end,
                &mut result,
                &identity,
                selected_end,
            ),
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(result, sentinel_result);

        // An in-range endpoint with no accepting span fails reverse K0 after
        // the in-flight marker has been cleared.
        let window = preflight();
        let wrong_end = window.start + 1;
        assert_ne!(wrong_end, selected_end);
        assert_eq!(
            call_exclusive_recover_partial_span(
                handle,
                &haystack,
                window.start,
                window.end,
                &mut result,
                &identity,
                wrong_end,
            ),
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(result, sentinel_result);
        assert_eq!(
            call_exclusive_recover_partial_span(
                handle,
                &haystack,
                window.start,
                window.end,
                &mut result,
                &identity,
                selected_end,
            ),
            STATUS_RUNTIME_FAILURE
        );

        // Raw pointer and numeric validation precede every read or state
        // mutation. All invalid calls leave both result and transaction live.
        let window = preflight();
        let raw_call = |raw_handle,
                        raw_haystack,
                        raw_len,
                        raw_start,
                        raw_end,
                        raw_result,
                        raw_identity,
                        raw_selected_end| {
            // SAFETY: every deliberately invalid argument is rejected before
            // dereference; all non-null extents remain live and disjoint.
            unsafe {
                fre_aot_regex_runtime_search_exclusive_recover_partial_span_v1(
                    raw_handle,
                    raw_haystack,
                    raw_len,
                    raw_start,
                    raw_end,
                    raw_result,
                    raw_identity,
                    raw_selected_end,
                )
            }
        };
        for status in [
            raw_call(
                handle,
                std::ptr::null(),
                haystack.len(),
                window.start,
                window.end,
                &raw mut result,
                identity.as_ptr(),
                selected_end,
            ),
            raw_call(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                window.start,
                window.end,
                std::ptr::null_mut(),
                identity.as_ptr(),
                selected_end,
            ),
            raw_call(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                window.start,
                window.end,
                &raw mut result,
                std::ptr::null(),
                selected_end,
            ),
            raw_call(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                window.end,
                window.start,
                &raw mut result,
                identity.as_ptr(),
                selected_end,
            ),
            raw_call(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                window.start,
                window.end,
                &raw mut result,
                identity.as_ptr(),
                window.start,
            ),
            raw_call(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                window.start,
                window.end,
                &raw mut result,
                identity.as_ptr(),
                window.end + 1,
            ),
        ] {
            assert_eq!(status, STATUS_INVALID_ARGUMENT);
            assert_eq!(result, sentinel_result);
        }
        assert_eq!(
            raw_call(
                FreAotRegexExclusiveHandleV1::INVALID,
                haystack.as_ptr(),
                haystack.len(),
                window.start,
                window.end,
                &raw mut result,
                identity.as_ptr(),
                selected_end,
            ),
            STATUS_INVALID_HANDLE
        );
        let mut misaligned_storage = vec![
            0_u8;
            size_of::<FreAotRegexResultV1>() + align_of::<FreAotRegexResultV1>()
        ];
        #[allow(
            clippy::cast_ptr_alignment,
            reason = "the raw-boundary test deliberately constructs a more-strictly-aligned result pointer at an unaligned address"
        )]
        let misaligned_result = (0..align_of::<FreAotRegexResultV1>())
            .find_map(|offset| {
                let pointer = misaligned_storage
                    .as_mut_ptr()
                    .wrapping_add(offset)
                    .cast::<FreAotRegexResultV1>();
                (!pointer.is_aligned()).then_some(pointer)
            })
            .expect("misaligned result address");
        assert_eq!(
            raw_call(
                handle,
                haystack.as_ptr(),
                haystack.len(),
                window.start,
                window.end,
                misaligned_result,
                identity.as_ptr(),
                selected_end,
            ),
            STATUS_INVALID_ARGUMENT
        );
        assert_eq!(result, sentinel_result);
        assert_eq!(
            call_exclusive_recover_partial_span(
                handle,
                &haystack,
                window.start,
                window.end,
                &mut result,
                &identity,
                selected_end,
            ),
            STATUS_MATCH,
            "raw validation consumed the authenticated transaction"
        );
        assert_eq!(result, expected_result);

        // Every non-Span output is rejected even when its own retained table
        // and exact artifact identity were successfully preflighted.
        for output in [OutputContract::Exists, OutputContract::SelectedEnd] {
            let mut output_limits = CompileLimitsV1::default();
            output_limits.determinize.max_states =
                if output == OutputContract::Exists { 8 } else { 16 };
            let other = compile(
                CompileRequest::new(pattern, Target::x86_64_linux())
                    .mode(CompileMode::Optimizing)
                    .limits(output_limits)
                    .output(output),
            )
            .unwrap();
            assert!(other.program().partial_dfa_stats().unwrap().is_some());
            let other_identity = other.receipt().program_sha256;
            let other_bytes = other.program().serialize().unwrap();
            let other_handle = prepare_exclusive(&other_bytes);
            let mut other_result = sentinel_result;
            let mut other_window = sentinel_window;
            assert_eq!(
                call_exclusive_partial_preflight(
                    other_handle,
                    &haystack,
                    public_start,
                    public_end,
                    &mut other_result,
                    &other_identity,
                    &mut other_window,
                ),
                STATUS_PARTIAL_PREFLIGHT_ENTER,
                "{output:?}"
            );
            assert_eq!(
                call_exclusive_recover_partial_span(
                    other_handle,
                    &haystack,
                    other_window.start,
                    other_window.end,
                    &mut other_result,
                    &other_identity,
                    selected_end,
                ),
                STATUS_RUNTIME_FAILURE,
                "{output:?}"
            );
            assert_eq!(other_result, sentinel_result);
            // SAFETY: this test uniquely owns the live session.
            assert_eq!(
                unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(other_handle) },
                STATUS_SUCCESS
            );
        }

        // SAFETY: this test uniquely owns the live session and all calls have
        // completed before destruction.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
            STATUS_SUCCESS
        );
    }

    #[test]
    fn exclusive_partial_preflight_runs_concurrently_on_independent_sessions() {
        let mut limits = CompileLimitsV1::default();
        limits.determinize.max_states = 8;
        let compiled = compile(
            CompileRequest::new(
                r"a+Q|[b-c][a-b]{1,5}(?:x+|y+)",
                Target::x86_64_linux(),
            )
            .mode(CompileMode::Optimizing)
            .limits(limits)
            .output(OutputContract::SelectedEnd),
        )
        .expect("compile concurrent partial preflight artifact");
        assert!(compiled.program().partial_dfa_stats().unwrap().is_some());

        let identity = compiled.receipt().program_sha256;
        let serialized = Arc::new(compiled.program().serialize().unwrap());
        let haystack = Arc::new(vec![b'x'; 300]);
        let worker_count = 4_usize;
        let barrier = Arc::new(std::sync::Barrier::new(worker_count));

        // A single exclusive handle may not be used by overlapping calls.
        // Each worker therefore creates, calls, and destroys its own session;
        // the barrier makes the valid independent-session calls overlap.
        std::thread::scope(|scope| {
            for worker in 0..worker_count {
                let serialized = Arc::clone(&serialized);
                let haystack = Arc::clone(&haystack);
                let barrier = Arc::clone(&barrier);
                scope.spawn(move || {
                    barrier.wait();
                    let handle = prepare_exclusive(&serialized);
                    for iteration in 0..64 {
                        let sentinel_result = FreAotRegexResultV1 {
                            start: 1_000 + worker,
                            end: 2_000 + iteration,
                        };
                        let sentinel_window = FreAotRegexSearchWindowV1 {
                            start: 3_000 + worker,
                            end: 4_000 + iteration,
                        };
                        let mut result = sentinel_result;
                        let mut window = sentinel_window;
                        assert_eq!(
                            call_exclusive_partial_preflight(
                                handle,
                                &haystack,
                                11,
                                289,
                                &mut result,
                                &identity,
                                &mut window,
                            ),
                            STATUS_PARTIAL_PREFLIGHT_ENTER
                        );
                        assert_eq!(result, sentinel_result);
                        assert_eq!(
                            window,
                            FreAotRegexSearchWindowV1 { start: 11, end: 289 }
                        );
                    }
                    // SAFETY: the worker has sole ownership of its session and
                    // all of its synchronous calls have returned.
                    assert_eq!(
                        unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
                        STATUS_SUCCESS
                    );
                });
            }
        });
    }

    #[test]
    fn exclusive_partial_span_postflight_runs_concurrently_on_independent_sessions() {
        let mut limits = CompileLimitsV1::default();
        limits.determinize.max_states = 16;
        let compiled = compile(
            CompileRequest::new(
                r"a+Q|[b-c][a-b]{1,5}(?:x+|y+)",
                Target::x86_64_linux(),
            )
            .mode(CompileMode::Optimizing)
            .limits(limits)
            .output(OutputContract::Span),
        )
        .expect("compile concurrent retained Span artifact");
        assert!(compiled.program().partial_dfa_stats().unwrap().is_some());

        let identity = compiled.receipt().program_sha256;
        let serialized = Arc::new(compiled.program().serialize().unwrap());
        let mut source = vec![b'!'; 256];
        source.extend_from_slice(b"aQ");
        let haystack = Arc::new(source);
        let MatchResult::Span(Some((expected_start, selected_end))) = compiled
            .search(&haystack, SearchWindow::full(&haystack))
            .unwrap()
        else {
            panic!("concurrent fixture did not select a Span");
        };
        let expected = FreAotRegexResultV1 {
            start: expected_start,
            end: selected_end,
        };
        let worker_count = 4_usize;
        let barrier = Arc::new(std::sync::Barrier::new(worker_count));

        // An exclusive session is synchronization-free and cannot overlap
        // itself. Independent sessions from the same immutable artifact may
        // preflight and recover concurrently without sharing transaction or
        // bidirectional-workspace state.
        std::thread::scope(|scope| {
            for worker in 0..worker_count {
                let serialized = Arc::clone(&serialized);
                let haystack = Arc::clone(&haystack);
                let barrier = Arc::clone(&barrier);
                scope.spawn(move || {
                    let handle = prepare_exclusive(&serialized);
                    barrier.wait();
                    for iteration in 0..64 {
                        let sentinel = FreAotRegexResultV1 {
                            start: 1_000 + worker,
                            end: 2_000 + iteration,
                        };
                        let mut result = sentinel;
                        let mut window = FreAotRegexSearchWindowV1 {
                            start: 3_000 + worker,
                            end: 4_000 + iteration,
                        };
                        assert_eq!(
                            call_exclusive_partial_preflight(
                                handle,
                                &haystack,
                                0,
                                haystack.len(),
                                &mut result,
                                &identity,
                                &mut window,
                            ),
                            STATUS_PARTIAL_PREFLIGHT_ENTER
                        );
                        assert_eq!(result, sentinel);
                        assert_eq!(
                            call_exclusive_recover_partial_span(
                                handle,
                                &haystack,
                                window.start,
                                window.end,
                                &mut result,
                                &identity,
                                selected_end,
                            ),
                            STATUS_MATCH
                        );
                        assert_eq!(result, expected);
                    }
                    // SAFETY: this worker uniquely owns its session and all
                    // synchronous calls have returned.
                    assert_eq!(
                        unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
                        STATUS_SUCCESS
                    );
                });
            }
        });
    }

    #[test]
    fn prepared_c_lifecycle_accepts_strict_v1_ordered_nfa() {
        // Complete optimizing DFAs now authenticate both class-mass state
        // discovery and its exact construction work as V6, so rewriting only
        // their header would deliberately create a noncanonical V1 artifact.
        // Legacy FIFO-DFA canonical validation remains covered in the program
        // crate; this runtime lifecycle test uses the stable V1 ordered NFA.
        let pattern = "(?:ab|a)+?b";
        let compiled = compile(
            CompileRequest::new(pattern, Target::x86_64_linux())
                .mode(CompileMode::Fast)
                .output(OutputContract::Span),
        )
        .expect("compile ordered NFA");
        assert_eq!(compiled.program().engine_kind(), EngineKind::OrderedNfa);

        let canonical = compiled
            .program()
            .serialize()
            .expect("serialize current program");
        let mut v1 = canonical.clone();
        v1[8..12].copy_from_slice(&1_u32.to_le_bytes());
        v1[14] = 0;
        v1[15] = 0;
        let handle = prepare_handle(&v1);
        drop(v1);
        drop(canonical);

        let mut haystacks = generated_haystacks();
        haystacks.extend([b"xxaaab".to_vec(), b"ababbx".to_vec()]);
        for haystack in &haystacks {
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let expected = expected_ffi(
                        compiled
                            .search(haystack, SearchWindow::new(start, end))
                            .expect("portable DFA search"),
                    );
                    let mut actual = FreAotRegexResultV1 {
                        start: usize::MAX,
                        end: usize::MAX,
                    };
                    let status = call_prepared(handle, haystack, start, end, &mut actual);
                    assert_eq!(
                        (status, actual),
                        expected,
                        "pattern={pattern:?}, haystack={haystack:?}, window={start}..{end}"
                    );
                }
            }
        }
        assert_eq!(
            fre_aot_regex_runtime_destroy_prepared_v1(handle),
            STATUS_SUCCESS
        );
    }

    #[test]
    #[allow(
        clippy::cast_ptr_alignment,
        reason = "the test deliberately passes a misaligned handle output that is rejected before use"
    )]
    fn prepared_handle_rejects_stale_busy_and_malformed_misuse() {
        let bytes = program(r"(?m:^a\b)", OutputContract::Span);
        let mut untouched = FreAotRegexPreparedHandleV1(41);
        let mut malformed = bytes.clone();
        malformed[0] ^= 1;

        // SAFETY: the malformed allocation is fully readable and the output is
        // aligned and disjoint; validation fails before ownership is created.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_prepare_v1(
                    malformed.as_ptr(),
                    malformed.len(),
                    &raw mut untouched,
                )
            },
            STATUS_RUNTIME_FAILURE
        );
        assert_eq!(untouched, FreAotRegexPreparedHandleV1(41));

        let mut storage = [0_u8; size_of::<FreAotRegexPreparedHandleV1>() * 2];
        let base = storage.as_mut_ptr();
        let aligned = base.align_offset(align_of::<FreAotRegexPreparedHandleV1>());
        assert_ne!(aligned, usize::MAX);
        let misaligned = base
            .wrapping_add(aligned.checked_add(1).expect("small alignment offset"))
            .cast::<FreAotRegexPreparedHandleV1>();
        // SAFETY: the deliberately misaligned output is rejected before it is
        // written; the source allocation remains valid.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_prepare_v1(bytes.as_ptr(), bytes.len(), misaligned) },
            STATUS_INVALID_ARGUMENT
        );

        let handle = prepare_handle(&bytes);
        let haystack = b"a";
        let sentinel = FreAotRegexResultV1 { start: 17, end: 19 };
        let mut result = sentinel;
        assert_eq!(
            call_prepared(
                FreAotRegexPreparedHandleV1(u64::MAX),
                haystack,
                0,
                1,
                &mut result
            ),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(result, sentinel);
        assert_eq!(
            call_prepared(handle, haystack, 1, 0, &mut result),
            STATUS_INVALID_ARGUMENT
        );
        assert_eq!(result, sentinel);

        let entry = prepared_entry(handle)
            .expect("registry lock")
            .expect("registered handle");
        let exclusive = entry.prepared.lock().expect("exclusive test lock");
        assert_eq!(
            call_prepared(handle, haystack, 0, 1, &mut result),
            STATUS_HANDLE_BUSY
        );
        assert_eq!(result, sentinel);
        drop(exclusive);

        assert_eq!(
            fre_aot_regex_runtime_destroy_prepared_v1(handle),
            STATUS_SUCCESS
        );
        assert_eq!(
            fre_aot_regex_runtime_destroy_prepared_v1(handle),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            call_prepared(handle, haystack, 0, 1, &mut result),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(result, sentinel);
        assert_eq!(
            fre_aot_regex_runtime_destroy_prepared_v1(FreAotRegexPreparedHandleV1::INVALID),
            STATUS_INVALID_HANDLE
        );
    }
}
