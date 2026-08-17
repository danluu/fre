//! Exact-source runtime session for canonical operation-set wire V2.
//!
//! This module is deliberately additive. The established operation-set V1
//! symbols continue to own and cast only their original V1 handle type.

use core::mem::{align_of, size_of};
use std::panic::{AssertUnwindSafe, catch_unwind};

use fre_aot_regex::{
    AotOperationAxesV2, AotOperationOutputV2, AotOperationSetMemberKindV2,
    AotOperationSetV2StructuralView, AotOperationSetV2View, CompiledProgram,
    GenericNfaProgramCensus, GrepCountWorkspace, GrepCountWorkspaceLimits, MatchResult,
    OutputContract, ProgramWorkspace, SearchWindow,
};
use fre_capture_lab::{
    CaptureProgramV1, CaptureProgramV1Census, CaptureProgramV1Limits,
    CaptureProgramV1RetainedOwnerReceipt, CaptureStream, CaptureStreamDomains, CaptureStreamLimits,
    CaptureStreamOperationProspective, Program as CaptureProgram,
};
use fre_exact_alloc::{ExactVec, try_box_preserve};

use super::{
    DEFAULT_GREP_COUNT_WORKSPACE_BYTES, DEFAULT_OPERATION_SET_MAX_HANDLE_BYTES,
    DEFAULT_START_FILTER_SETUP_WORK, OPERATION_SET_OUTPUT_COUNT, OPERATION_SET_OUTPUT_GREP_COUNT,
    OPERATION_SET_OUTPUT_SEARCH_EXISTS, OPERATION_SET_OUTPUT_SEARCH_SELECTED_END,
    OPERATION_SET_OUTPUT_SEARCH_SPAN, OPERATION_SET_OUTPUT_SPAN_SUM, STATUS_INVALID_ARGUMENT,
    STATUS_INVALID_HANDLE, STATUS_MATCH, STATUS_NO_MATCH, STATUS_RUNTIME_FAILURE, STATUS_SUCCESS,
};

#[cfg(test)]
std::thread_local! {
    static TEST_PREPARATION_PLANS: core::cell::Cell<usize> = const {
        core::cell::Cell::new(0)
    };
    static TEST_CAPTURE_CENSUSES: core::cell::Cell<usize> = const {
        core::cell::Cell::new(0)
    };
    static TEST_CAPTURE_EXECUTIONS: core::cell::Cell<usize> = const {
        core::cell::Cell::new(0)
    };
    static TEST_OUTER_CAPTURE_SCRATCH_DROPPED: core::cell::Cell<bool> = const {
        core::cell::Cell::new(false)
    };
    static TEST_OWNER_DECODES_AFTER_SCRATCH_DROP: core::cell::Cell<usize> = const {
        core::cell::Cell::new(0)
    };
    static TEST_REFUSE_CAPTURE_PROGRAM_OWNER: core::cell::Cell<bool> = const {
        core::cell::Cell::new(false)
    };
}

/// Exact byte size required in [`FreAotRegexOperationSetPrepareConfigV2::struct_size`].
pub const OPERATION_SET_PREPARE_CONFIG_V2_SIZE: u32 = 184;
/// Exact version required in
/// [`FreAotRegexOperationSetPrepareConfigV2::config_version`].
pub const OPERATION_SET_PREPARE_CONFIG_V2_VERSION: u32 = 2;
/// Default aggregate transient capture-validation scratch cap.
pub const DEFAULT_OPERATION_SET_V2_MAX_CAPTURE_VALIDATION_SCRATCH_BYTES: u64 = 16 * 1024 * 1024;
/// Default aggregate retained executable capture-owner logical-payload cap.
pub const DEFAULT_OPERATION_SET_V2_MAX_CAPTURE_OWNER_BYTES: u64 = 512 * 1024 * 1024;
/// Default aggregate mutable capture-workspace logical-payload cap.
pub const DEFAULT_OPERATION_SET_V2_MAX_CAPTURE_WORKSPACE_BYTES: u64 = 512 * 1024 * 1024;
/// Default aggregate source-independent capture operation-work cap.
pub const DEFAULT_OPERATION_SET_V2_MAX_CAPTURE_WORK: u64 = 1 << 40;
/// Default aggregate source-independent capture-schema-event cap.
pub const DEFAULT_OPERATION_SET_V2_MAX_CAPTURE_EVENTS: u64 = 1 << 40;
/// Default aggregate source-independent capture-result cap.
pub const DEFAULT_OPERATION_SET_V2_MAX_CAPTURE_COUNT: u64 = 1 << 40;

const DEFAULT_CAPTURE_MAX_SERIALIZED_BYTES: u64 = 16 * 1024 * 1024;
const DEFAULT_CAPTURE_MAX_STATES: u64 = 65_536;
const DEFAULT_CAPTURE_MAX_BYTE_RANGES: u64 = 1_000_000;
const DEFAULT_CAPTURE_MAX_GROUPS: u64 = 65;
const DEFAULT_CAPTURE_MAX_SLOTS: u64 = 130;
const DEFAULT_CAPTURE_MAX_NAME_BYTES: u64 = 1024 * 1024;
const DEFAULT_CAPTURE_MAX_VALIDATION_WORK: u64 = 4_000_000;
const DEFAULT_CAPTURE_MAX_PROGRAM_BYTES: u64 = 16 * 1024 * 1024;

/// Scalar result kind for whole-domain capture-participation Count.
pub const OPERATION_SET_OUTPUT_CAPTURE_PARTICIPATION_COUNT: u32 = 7;

/// C declarations for the exact-source operation-set V2 runtime ABI.
pub const C_API_OPERATION_SET_V2_HEADER: &str =
    include_str!("../include/fre_aot_regex_runtime_operation_set_v2.h");

/// Bounded preparation policy for one exact-source V2 operation set.
///
/// Every numeric field is validated and converted to the host `usize` domain
/// before the candidate wire is read. Capture-program fields map exactly to
/// [`CaptureProgramV1Limits`]. Reserved words must be zero.
///
/// `max_capture_owner_bytes` covers actual retained `Program` vector/string
/// capacities plus the exact inline `Program` payload in its unique `Box`.
/// It excludes allocator metadata and allocator usable-size rounding.
/// `max_capture_validation_scratch_bytes` bounds both the shared census prefix
/// and each safe owner reconstruction's same-shaped internal prefix; those
/// owners are explicitly sequential and never co-live.
/// `max_capture_workspace_bytes` covers each unique capture stream's inline
/// value and exact allocator-requested workspace bytes, with the unique
/// immutable program excluded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct FreAotRegexOperationSetPrepareConfigV2 {
    pub struct_size: u32,
    pub config_version: u32,
    /// Exact source length bound into every capture workspace.
    pub exact_source_bytes: u64,
    /// Maximum complete retained handle logical payload.
    pub max_handle_bytes: u64,
    /// Maximum aggregate compiled-member start-filter setup work.
    pub max_start_filter_setup_work: u64,
    /// Maximum aggregate compiled-member `GrepCount` fixed-store bytes.
    pub max_grep_count_workspace_bytes: u64,
    /// Maximum exact transient caller-owned V2 capture-preflight scratch.
    pub max_capture_validation_scratch_bytes: u64,
    /// Maximum aggregate retained executable capture-owner payload.
    pub max_capture_owner_bytes: u64,
    /// Maximum aggregate mutable capture-stream workspace payload.
    pub max_capture_workspace_bytes: u64,
    /// Maximum aggregate capture operation work over unique capture members.
    pub max_capture_work: u64,
    /// Maximum aggregate capture schema events over unique capture members.
    pub max_capture_events: u64,
    /// Maximum aggregate capture participation result envelope.
    pub max_capture_count: u64,
    pub capture_max_serialized_bytes: u64,
    pub capture_max_states: u64,
    pub capture_max_byte_ranges: u64,
    pub capture_max_groups: u64,
    pub capture_max_slots: u64,
    pub capture_max_name_bytes: u64,
    pub capture_max_validation_work: u64,
    pub capture_max_program_bytes: u64,
    /// Must contain four zero words.
    pub reserved: [u64; 4],
}

impl FreAotRegexOperationSetPrepareConfigV2 {
    /// Construct the default bounded policy for an exact source length.
    #[must_use]
    pub const fn new(exact_source_bytes: u64) -> Self {
        Self {
            struct_size: OPERATION_SET_PREPARE_CONFIG_V2_SIZE,
            config_version: OPERATION_SET_PREPARE_CONFIG_V2_VERSION,
            exact_source_bytes,
            max_handle_bytes: DEFAULT_OPERATION_SET_MAX_HANDLE_BYTES,
            max_start_filter_setup_work: DEFAULT_START_FILTER_SETUP_WORK,
            max_grep_count_workspace_bytes: DEFAULT_GREP_COUNT_WORKSPACE_BYTES,
            max_capture_validation_scratch_bytes:
                DEFAULT_OPERATION_SET_V2_MAX_CAPTURE_VALIDATION_SCRATCH_BYTES,
            max_capture_owner_bytes: DEFAULT_OPERATION_SET_V2_MAX_CAPTURE_OWNER_BYTES,
            max_capture_workspace_bytes: DEFAULT_OPERATION_SET_V2_MAX_CAPTURE_WORKSPACE_BYTES,
            max_capture_work: DEFAULT_OPERATION_SET_V2_MAX_CAPTURE_WORK,
            max_capture_events: DEFAULT_OPERATION_SET_V2_MAX_CAPTURE_EVENTS,
            max_capture_count: DEFAULT_OPERATION_SET_V2_MAX_CAPTURE_COUNT,
            capture_max_serialized_bytes: DEFAULT_CAPTURE_MAX_SERIALIZED_BYTES,
            capture_max_states: DEFAULT_CAPTURE_MAX_STATES,
            capture_max_byte_ranges: DEFAULT_CAPTURE_MAX_BYTE_RANGES,
            capture_max_groups: DEFAULT_CAPTURE_MAX_GROUPS,
            capture_max_slots: DEFAULT_CAPTURE_MAX_SLOTS,
            capture_max_name_bytes: DEFAULT_CAPTURE_MAX_NAME_BYTES,
            capture_max_validation_work: DEFAULT_CAPTURE_MAX_VALIDATION_WORK,
            capture_max_program_bytes: DEFAULT_CAPTURE_MAX_PROGRAM_BYTES,
            reserved: [0; 4],
        }
    }
}

const _: () = assert!(size_of::<FreAotRegexOperationSetPrepareConfigV2>() == 184);
const _: () = assert!(align_of::<FreAotRegexOperationSetPrepareConfigV2>() == align_of::<u64>());
const _: () =
    assert!(core::mem::offset_of!(FreAotRegexOperationSetPrepareConfigV2, struct_size) == 0);
const _: () =
    assert!(core::mem::offset_of!(FreAotRegexOperationSetPrepareConfigV2, config_version) == 4);
const _: () =
    assert!(core::mem::offset_of!(FreAotRegexOperationSetPrepareConfigV2, exact_source_bytes) == 8);
const _: () =
    assert!(core::mem::offset_of!(FreAotRegexOperationSetPrepareConfigV2, max_handle_bytes) == 16);
const _: () = assert!(
    core::mem::offset_of!(
        FreAotRegexOperationSetPrepareConfigV2,
        max_start_filter_setup_work
    ) == 24
);
const _: () = assert!(
    core::mem::offset_of!(
        FreAotRegexOperationSetPrepareConfigV2,
        max_grep_count_workspace_bytes
    ) == 32
);
const _: () = assert!(
    core::mem::offset_of!(
        FreAotRegexOperationSetPrepareConfigV2,
        max_capture_validation_scratch_bytes
    ) == 40
);
const _: () = assert!(
    core::mem::offset_of!(
        FreAotRegexOperationSetPrepareConfigV2,
        max_capture_owner_bytes
    ) == 48
);
const _: () = assert!(
    core::mem::offset_of!(
        FreAotRegexOperationSetPrepareConfigV2,
        max_capture_workspace_bytes
    ) == 56
);
const _: () =
    assert!(core::mem::offset_of!(FreAotRegexOperationSetPrepareConfigV2, max_capture_work) == 64);
const _: () = assert!(
    core::mem::offset_of!(FreAotRegexOperationSetPrepareConfigV2, max_capture_events) == 72
);
const _: () =
    assert!(core::mem::offset_of!(FreAotRegexOperationSetPrepareConfigV2, max_capture_count) == 80);
const _: () = assert!(
    core::mem::offset_of!(
        FreAotRegexOperationSetPrepareConfigV2,
        capture_max_serialized_bytes
    ) == 88
);
const _: () = assert!(
    core::mem::offset_of!(FreAotRegexOperationSetPrepareConfigV2, capture_max_states) == 96
);
const _: () = assert!(
    core::mem::offset_of!(
        FreAotRegexOperationSetPrepareConfigV2,
        capture_max_byte_ranges
    ) == 104
);
const _: () = assert!(
    core::mem::offset_of!(FreAotRegexOperationSetPrepareConfigV2, capture_max_groups) == 112
);
const _: () = assert!(
    core::mem::offset_of!(FreAotRegexOperationSetPrepareConfigV2, capture_max_slots) == 120
);
const _: () = assert!(
    core::mem::offset_of!(
        FreAotRegexOperationSetPrepareConfigV2,
        capture_max_name_bytes
    ) == 128
);
const _: () = assert!(
    core::mem::offset_of!(
        FreAotRegexOperationSetPrepareConfigV2,
        capture_max_validation_work
    ) == 136
);
const _: () = assert!(
    core::mem::offset_of!(
        FreAotRegexOperationSetPrepareConfigV2,
        capture_max_program_bytes
    ) == 144
);
const _: () =
    assert!(core::mem::offset_of!(FreAotRegexOperationSetPrepareConfigV2, reserved) == 152);

/// Exclusively owned prepared exact-source V2 operation-set state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct FreAotRegexOperationSetExclusiveHandleV2(*mut core::ffi::c_void);

impl FreAotRegexOperationSetExclusiveHandleV2 {
    pub const INVALID: Self = Self(core::ptr::null_mut());

    #[must_use]
    pub const fn is_invalid(self) -> bool {
        self.0.is_null()
    }
}

impl Default for FreAotRegexOperationSetExclusiveHandleV2 {
    fn default() -> Self {
        Self::INVALID
    }
}

/// One root-aligned result from successful V2 execution.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct FreAotRegexOperationSetOutputV2 {
    pub kind: u32,
    pub status: u32,
    pub first: u64,
    pub second: u64,
}

const _: () =
    assert!(size_of::<FreAotRegexOperationSetExclusiveHandleV2>() == size_of::<*mut ()>());
const _: () =
    assert!(align_of::<FreAotRegexOperationSetExclusiveHandleV2>() == align_of::<*mut ()>());
const _: () = assert!(size_of::<FreAotRegexOperationSetOutputV2>() == 24);
const _: () = assert!(align_of::<FreAotRegexOperationSetOutputV2>() == align_of::<u64>());
const _: () = assert!(core::mem::offset_of!(FreAotRegexOperationSetOutputV2, kind) == 0);
const _: () = assert!(core::mem::offset_of!(FreAotRegexOperationSetOutputV2, status) == 4);
const _: () = assert!(core::mem::offset_of!(FreAotRegexOperationSetOutputV2, first) == 8);
const _: () = assert!(core::mem::offset_of!(FreAotRegexOperationSetOutputV2, second) == 16);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OperationSetPrepareConfigV2 {
    exact_source_bytes: usize,
    max_handle_bytes: u64,
    max_start_filter_setup_work: u64,
    max_grep_count_workspace_bytes: u64,
    max_capture_validation_scratch_bytes: u64,
    max_capture_owner_bytes: u64,
    max_capture_workspace_bytes: u64,
    max_capture_work: u64,
    max_capture_events: u64,
    max_capture_count: u64,
    capture_limits: CaptureProgramV1Limits,
}

impl OperationSetPrepareConfigV2 {
    fn from_ffi(config: FreAotRegexOperationSetPrepareConfigV2) -> Option<Self> {
        if config.struct_size != OPERATION_SET_PREPARE_CONFIG_V2_SIZE
            || config.config_version != OPERATION_SET_PREPARE_CONFIG_V2_VERSION
            || config.reserved != [0; 4]
        {
            return None;
        }
        let exact_source_bytes = usize_from_u64(config.exact_source_bytes).ok()?;
        if exact_source_bytes > isize::MAX.unsigned_abs() {
            return None;
        }
        Some(Self {
            exact_source_bytes,
            max_handle_bytes: config.max_handle_bytes,
            max_start_filter_setup_work: config.max_start_filter_setup_work,
            max_grep_count_workspace_bytes: config.max_grep_count_workspace_bytes,
            max_capture_validation_scratch_bytes: config.max_capture_validation_scratch_bytes,
            max_capture_owner_bytes: config.max_capture_owner_bytes,
            max_capture_workspace_bytes: config.max_capture_workspace_bytes,
            max_capture_work: config.max_capture_work,
            max_capture_events: config.max_capture_events,
            max_capture_count: config.max_capture_count,
            capture_limits: CaptureProgramV1Limits {
                max_serialized_bytes: usize_from_u64(config.capture_max_serialized_bytes).ok()?,
                max_states: usize_from_u64(config.capture_max_states).ok()?,
                max_byte_ranges: usize_from_u64(config.capture_max_byte_ranges).ok()?,
                max_groups: usize_from_u64(config.capture_max_groups).ok()?,
                max_slots: usize_from_u64(config.capture_max_slots).ok()?,
                max_name_bytes: usize_from_u64(config.capture_max_name_bytes).ok()?,
                max_validation_work: usize_from_u64(config.capture_max_validation_work).ok()?,
                max_program_bytes: usize_from_u64(config.capture_max_program_bytes).ok()?,
            },
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OperationSetV2RuntimeError {
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

impl core::fmt::Display for OperationSetV2RuntimeError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "operation-set V2 runtime error: {self:?}")
    }
}

impl std::error::Error for OperationSetV2RuntimeError {}

fn usize_from_u64(value: u64) -> Result<usize, OperationSetV2RuntimeError> {
    usize::try_from(value)
        .map_err(|_| OperationSetV2RuntimeError::Arithmetic("u64 to usize conversion"))
}

fn u64_from_usize(
    value: usize,
    computation: &'static str,
) -> Result<u64, OperationSetV2RuntimeError> {
    u64::try_from(value).map_err(|_| OperationSetV2RuntimeError::Arithmetic(computation))
}

fn add_u64(
    total: u64,
    value: u64,
    computation: &'static str,
) -> Result<u64, OperationSetV2RuntimeError> {
    total
        .checked_add(value)
        .ok_or(OperationSetV2RuntimeError::Arithmetic(computation))
}

fn add_usize(
    total: u64,
    value: usize,
    computation: &'static str,
) -> Result<u64, OperationSetV2RuntimeError> {
    add_u64(total, u64_from_usize(value, computation)?, computation)
}

const COMPILED_MEMBER_SEARCH: u8 = 1 << 0;
const COMPILED_MEMBER_COUNT: u8 = 1 << 1;
const COMPILED_MEMBER_SPAN_SUM: u8 = 1 << 2;
const COMPILED_MEMBER_GREP_COUNT: u8 = 1 << 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CompiledOperationV2 {
    Search,
    Count,
    SpanSum,
    GrepCount,
}

impl CompiledOperationV2 {
    const fn flag(self) -> u8 {
        match self {
            Self::Search => COMPILED_MEMBER_SEARCH,
            Self::Count => COMPILED_MEMBER_COUNT,
            Self::SpanSum => COMPILED_MEMBER_SPAN_SUM,
            Self::GrepCount => COMPILED_MEMBER_GREP_COUNT,
        }
    }

    const fn expected_output(self) -> AotOperationOutputV2 {
        match self {
            Self::Search => AotOperationOutputV2::OneRecord,
            Self::Count | Self::SpanSum | Self::GrepCount => AotOperationOutputV2::ScalarU64,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct CompiledOperationUnionV2(u8);

impl CompiledOperationUnionV2 {
    fn insert(&mut self, operation: CompiledOperationV2) {
        self.0 |= operation.flag();
    }

    const fn is_empty(self) -> bool {
        self.0 == 0
    }

    const fn requires_start_filter(self) -> bool {
        self.0 & (COMPILED_MEMBER_SEARCH | COMPILED_MEMBER_COUNT | COMPILED_MEMBER_SPAN_SUM) != 0
    }

    const fn requires_grep_count(self) -> bool {
        self.0 & COMPILED_MEMBER_GREP_COUNT != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PlannedMemberV2 {
    Compiled(CompiledOperationUnionV2),
    Capture { reached: bool },
}

impl PlannedMemberV2 {
    const fn is_reached(self) -> bool {
        match self {
            Self::Compiled(operations) => !operations.is_empty(),
            Self::Capture { reached } => reached,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RootOperationV2 {
    Compiled(CompiledOperationV2),
    CaptureParticipationCount,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PreparedOperationSetRootV2 {
    member_index: usize,
    operation: RootOperationV2,
}

#[derive(Debug)]
struct OperationSetPreparationPlanV2 {
    members: Vec<PlannedMemberV2>,
    roots: Vec<PreparedOperationSetRootV2>,
}

impl OperationSetPreparationPlanV2 {
    fn from_view(
        view: AotOperationSetV2StructuralView<'_>,
    ) -> Result<Self, OperationSetV2RuntimeError> {
        #[cfg(test)]
        TEST_PREPARATION_PLANS.with(|calls| calls.set(calls.get().saturating_add(1)));
        let mut members = Vec::new();
        members
            .try_reserve_exact(view.member_count())
            .map_err(|_| OperationSetV2RuntimeError::Allocation("member operation plan"))?;
        for member in view.members() {
            members.push(match member.kind() {
                AotOperationSetMemberKindV2::CompiledProgram => {
                    PlannedMemberV2::Compiled(CompiledOperationUnionV2::default())
                }
                AotOperationSetMemberKindV2::CaptureProgramV1 => {
                    PlannedMemberV2::Capture { reached: false }
                }
            });
        }

        let mut roots = Vec::new();
        roots
            .try_reserve_exact(view.operation_count())
            .map_err(|_| OperationSetV2RuntimeError::Allocation("root execution plan"))?;
        for root in view.roots() {
            let member_index = usize::try_from(root.member_index()).map_err(|_| {
                OperationSetV2RuntimeError::Arithmetic("root member index conversion")
            })?;
            let operation = if root.axes() == AotOperationAxesV2::SEARCH {
                RootOperationV2::Compiled(CompiledOperationV2::Search)
            } else if root.axes() == AotOperationAxesV2::COUNT {
                RootOperationV2::Compiled(CompiledOperationV2::Count)
            } else if root.axes() == AotOperationAxesV2::SPAN_SUM {
                RootOperationV2::Compiled(CompiledOperationV2::SpanSum)
            } else if root.axes() == AotOperationAxesV2::GREP {
                RootOperationV2::Compiled(CompiledOperationV2::GrepCount)
            } else if root.axes() == AotOperationAxesV2::CAPTURE_PARTICIPATION_COUNT {
                RootOperationV2::CaptureParticipationCount
            } else {
                return Err(OperationSetV2RuntimeError::UnsupportedOperation);
            };
            match (members.get_mut(member_index), operation, root.output()) {
                (
                    Some(PlannedMemberV2::Compiled(operations)),
                    RootOperationV2::Compiled(operation),
                    output,
                ) if output == operation.expected_output() => operations.insert(operation),
                (
                    Some(PlannedMemberV2::Capture { reached }),
                    RootOperationV2::CaptureParticipationCount,
                    AotOperationOutputV2::ScalarU64,
                ) => *reached = true,
                (Some(_), _, _) => return Err(OperationSetV2RuntimeError::UnsupportedOperation),
                (None, _, _) => {
                    return Err(OperationSetV2RuntimeError::Malformed(
                        "root member index is out of bounds",
                    ));
                }
            }
            roots.push(PreparedOperationSetRootV2 {
                member_index,
                operation,
            });
        }
        if members.iter().copied().any(|member| !member.is_reached()) {
            return Err(OperationSetV2RuntimeError::UnreachableMember);
        }
        Ok(Self { members, roots })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_field_names,
    reason = "explicit byte-unit suffixes keep retained-owner accounting formulas auditable"
)]
struct CaptureExecutionOwnerAccounting {
    nested_program_capacity_bytes: usize,
    inline_program_bytes: usize,
    retained_owner_bytes: usize,
}

const fn capture_box_inline_program_bytes() -> usize {
    // Exact requested Box payload. Allocator metadata and usable-size rounding
    // are deliberately outside this logical retained-owner boundary.
    size_of::<CaptureProgram>()
}

fn capture_execution_owner_accounting(
    receipt: &CaptureProgramV1RetainedOwnerReceipt,
    census: CaptureProgramV1Census,
) -> Result<CaptureExecutionOwnerAccounting, OperationSetV2RuntimeError> {
    // This receipt came directly from deserialize_with_census immediately
    // before this call. That safe constructor already revalidated and
    // canonically reconstructed the full wire. Close only the receipt/census
    // accounting here; hashing the potentially large member again would add
    // no new authenticated fact.
    if !receipt.authenticates_census_accounting(&census) {
        return Err(OperationSetV2RuntimeError::InternalInvariant(
            "capture retained-owner receipt does not authenticate census accounting",
        ));
    }
    let nested_program_capacity_bytes = receipt
        .program_states_capacity_bytes()
        .checked_add(receipt.program_groups_capacity_bytes())
        .and_then(|bytes| bytes.checked_add(receipt.byte_range_payload_capacity_bytes()))
        .and_then(|bytes| bytes.checked_add(receipt.program_name_capacity_bytes()))
        .ok_or(OperationSetV2RuntimeError::Arithmetic(
            "capture execution Program capacity bytes",
        ))?;
    if nested_program_capacity_bytes != census.usage().program_bytes {
        return Err(OperationSetV2RuntimeError::InternalInvariant(
            "capture execution Program capacities disagree with exact census",
        ));
    }
    let inline_program_bytes = capture_box_inline_program_bytes();
    let retained_owner_bytes = nested_program_capacity_bytes
        .checked_add(inline_program_bytes)
        .ok_or(OperationSetV2RuntimeError::Arithmetic(
            "capture execution owner bytes",
        ))?;
    Ok(CaptureExecutionOwnerAccounting {
        nested_program_capacity_bytes,
        inline_program_bytes,
        retained_owner_bytes,
    })
}

fn try_capture_program_owner(
    program: CaptureProgram,
) -> Result<Box<CaptureProgram>, OperationSetV2RuntimeError> {
    #[cfg(test)]
    if TEST_REFUSE_CAPTURE_PROGRAM_OWNER.with(core::cell::Cell::get) {
        return Err(OperationSetV2RuntimeError::Allocation(
            "unique capture Program owner",
        ));
    }
    try_box_preserve(program)
        .map_err(|_| OperationSetV2RuntimeError::Allocation("unique capture Program owner"))
}

#[derive(Debug)]
struct DecodedCompiledMemberV2 {
    operations: CompiledOperationUnionV2,
    program: CompiledProgram,
    workspace: ProgramWorkspace,
    census: GenericNfaProgramCensus,
    grep_count_workspace: Option<GrepCountWorkspace>,
}

#[derive(Debug)]
struct DecodedCaptureMemberV2 {
    program: CaptureProgram,
    owner: CaptureExecutionOwnerAccounting,
    operation: CaptureStreamOperationProspective,
}

#[derive(Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "decoded members stay inline so preparation introduces no unaccounted owner allocation"
)]
enum DecodedMemberV2 {
    Compiled(DecodedCompiledMemberV2),
    Capture(DecodedCaptureMemberV2),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MemberCensusV2 {
    Compiled(GenericNfaProgramCensus),
    Capture(CaptureProgramV1Census),
}

#[derive(Debug)]
struct PreparedCompiledMemberV2 {
    operations: CompiledOperationUnionV2,
    program: CompiledProgram,
    workspace: ProgramWorkspace,
    grep_count_workspace: Option<GrepCountWorkspace>,
    census: GenericNfaProgramCensus,
}

#[derive(Debug)]
struct PreparedCaptureMemberV2 {
    stream: CaptureStream,
    owner: CaptureExecutionOwnerAccounting,
    cached_value: Option<u64>,
}

#[derive(Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "prepared members stay inline in the exactly accounted retained member vector"
)]
enum PreparedOperationSetMemberV2 {
    Compiled(PreparedCompiledMemberV2),
    Capture(PreparedCaptureMemberV2),
}

#[derive(Debug)]
struct PreparedAotOperationSetV2 {
    exact_source_bytes: usize,
    members: Vec<PreparedOperationSetMemberV2>,
    roots: Vec<PreparedOperationSetRootV2>,
    output_scratch: Vec<FreAotRegexOperationSetOutputV2>,
    reusable: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OperationSetPreparationReceiptV2 {
    capture_validation_scratch_bytes: u64,
    prospective_start_filter_work: Option<u64>,
    actual_start_filter_work: u64,
    start_filter_aggregate_admitted: bool,
    grep_count_workspace_bytes: u64,
    capture_owner_bytes: u64,
    capture_workspace_bytes: u64,
    capture_work: u64,
    capture_events: u64,
    capture_count: u64,
    prospective_handle_bytes: u64,
    retained_handle_bytes: u64,
}

impl OperationSetPreparationReceiptV2 {
    const fn authenticates(self, config: OperationSetPrepareConfigV2) -> bool {
        let start_filter_authenticates = match (
            self.prospective_start_filter_work,
            self.start_filter_aggregate_admitted,
        ) {
            (Some(required), true) => {
                required <= config.max_start_filter_setup_work
                    && self.actual_start_filter_work <= required
            }
            (Some(required), false) => {
                required > config.max_start_filter_setup_work && self.actual_start_filter_work == 0
            }
            (None, false) => self.actual_start_filter_work == 0,
            (None, true) => false,
        };
        start_filter_authenticates
            && self.capture_validation_scratch_bytes <= config.max_capture_validation_scratch_bytes
            && self.grep_count_workspace_bytes <= config.max_grep_count_workspace_bytes
            && self.capture_owner_bytes <= config.max_capture_owner_bytes
            && self.capture_workspace_bytes <= config.max_capture_workspace_bytes
            && self.capture_work <= config.max_capture_work
            && self.capture_events <= config.max_capture_events
            && self.capture_count <= config.max_capture_count
            && self.capture_count <= self.capture_events
            && self.prospective_handle_bytes <= config.max_handle_bytes
            && self.retained_handle_bytes <= self.prospective_handle_bytes
            && self.retained_handle_bytes <= config.max_handle_bytes
    }
}

fn operation_set_v2_fixed_retained_bytes(
    member_capacity: usize,
    root_capacity: usize,
    output_capacity: usize,
) -> Result<u64, OperationSetV2RuntimeError> {
    let bytes = size_of::<PreparedAotOperationSetV2>()
        .checked_add(
            member_capacity
                .checked_mul(size_of::<PreparedOperationSetMemberV2>())
                .ok_or(OperationSetV2RuntimeError::Arithmetic(
                    "prepared V2 member vector bytes",
                ))?,
        )
        .and_then(|bytes| {
            root_capacity
                .checked_mul(size_of::<PreparedOperationSetRootV2>())
                .and_then(|part| bytes.checked_add(part))
        })
        .and_then(|bytes| {
            output_capacity
                .checked_mul(size_of::<FreAotRegexOperationSetOutputV2>())
                .and_then(|part| bytes.checked_add(part))
        })
        .ok_or(OperationSetV2RuntimeError::Arithmetic(
            "prepared V2 fixed owner bytes",
        ))?;
    u64_from_usize(bytes, "prepared V2 fixed owner byte conversion")
}

fn capture_workspace_bytes(
    operation: &CaptureStreamOperationProspective,
) -> Result<usize, OperationSetV2RuntimeError> {
    let exact = size_of::<CaptureStream>()
        .checked_add(operation.construction.allocator_bytes)
        .ok_or(OperationSetV2RuntimeError::Arithmetic(
            "capture workspace bytes",
        ))?;
    let without_program = operation
        .construction
        .persistent_bytes
        .checked_sub(operation.construction.program_bytes)
        .ok_or(OperationSetV2RuntimeError::InternalInvariant(
            "capture persistent bytes are smaller than program bytes",
        ))?;
    if without_program != exact {
        return Err(OperationSetV2RuntimeError::InternalInvariant(
            "capture persistent bytes do not split into workspace and unique program",
        ));
    }
    Ok(exact)
}

fn exact_capture_stream_limits(
    operation: &CaptureStreamOperationProspective,
) -> CaptureStreamLimits {
    CaptureStreamLimits {
        max_source_bytes: operation.construction.source_bytes,
        max_states: operation.construction.states,
        max_build_work: operation.construction.build_work,
        max_persistent_bytes: operation.construction.persistent_bytes,
        max_combined_peak_bytes: operation.construction.combined_peak_bytes,
        max_allocations: operation.construction.allocations,
        max_line_domains: operation.line_domains,
        max_searches: operation.searches,
        max_matches: operation.matches,
        max_bytes_examined: operation.bytes_examined,
        max_starts_injected: operation.starts_injected,
        max_state_visits: operation.state_visits,
        max_tag_actions: operation.tag_actions,
        max_history_nodes: operation.history_nodes,
        max_history_walk: operation.history_walk,
        max_history_reads: operation.history_reads,
        max_materialization_reads: operation.materialization_reads,
        max_materialization_writes: operation.materialization_writes,
        max_materialization_preview_writes: operation.materialization_preview_writes,
        max_mask_states: operation
            .mask_states
            .max(operation.construction.participation_cache_cells()),
        max_mask_word_copies: operation.mask_word_copies,
        max_mask_word_reads: operation.mask_word_reads,
        max_reset_cells: operation.reset_cells,
        max_capture_events: operation.capture_events,
        max_capture_count: operation.capture_count,
        max_line_source_reads: operation.line_source_reads,
        max_work: operation.work,
    }
}

fn exact_zeroed_words(words: usize) -> Result<ExactVec<u32>, OperationSetV2RuntimeError> {
    let mut scratch = ExactVec::try_with_capacity(words)
        .map_err(|_| OperationSetV2RuntimeError::Allocation("capture validation scratch"))?;
    for _ in 0..words {
        scratch.try_push(0).map_err(|_| {
            OperationSetV2RuntimeError::InternalInvariant(
                "exact capture scratch refused an admitted word",
            )
        })?;
    }
    Ok(scratch)
}

fn census_capture_member(
    bytes: &[u8],
    limits: CaptureProgramV1Limits,
    scratch: &mut [u32],
) -> Result<CaptureProgramV1Census, fre_capture_lab::CaptureProgramV1Error> {
    #[cfg(test)]
    TEST_CAPTURE_CENSUSES.with(|calls| calls.set(calls.get().saturating_add(1)));
    CaptureProgramV1Census::from_wire(bytes, limits, scratch)
}

impl PreparedAotOperationSetV2 {
    #[allow(
        clippy::too_many_lines,
        reason = "the ordered V2 validation, aggregate admission, allocation, and publication transaction remains visible"
    )]
    fn deserialize_with_config(
        bytes: &[u8],
        config: OperationSetPrepareConfigV2,
    ) -> Result<(Self, OperationSetPreparationReceiptV2), OperationSetV2RuntimeError> {
        // The first pass is allocation-free and discovers the exact maximum
        // capture census prefix from fixed authenticated member extents.
        let structural = AotOperationSetV2View::deserialize_structure(bytes, config.capture_limits)
            .map_err(|_| {
                OperationSetV2RuntimeError::Malformed(
                    "operation-set V2 structure validation failed",
                )
            })?;
        let fixed_retained_handle_bytes = operation_set_v2_fixed_retained_bytes(
            structural.member_count(),
            structural.operation_count(),
            structural.operation_count(),
        )?;
        if fixed_retained_handle_bytes > config.max_handle_bytes {
            return Err(OperationSetV2RuntimeError::Resource(
                "fixed retained handle bytes",
            ));
        }
        // Global reachability is resolved from fixed descriptors before any
        // capture scratch allocation or full capture-body census.
        let plan = OperationSetPreparationPlanV2::from_view(structural)?;
        let scratch_words = structural.capture_validation_scratch_words();
        let scratch_bytes = scratch_words.checked_mul(size_of::<u32>()).ok_or(
            OperationSetV2RuntimeError::Arithmetic("capture validation scratch bytes"),
        )?;
        let scratch_bytes_u64 =
            u64_from_usize(scratch_bytes, "capture validation scratch byte conversion")?;
        if scratch_bytes_u64 > config.max_capture_validation_scratch_bytes {
            return Err(OperationSetV2RuntimeError::Resource(
                "capture validation scratch bytes",
            ));
        }
        let mut capture_scratch = exact_zeroed_words(scratch_words)?;
        #[cfg(test)]
        TEST_OUTER_CAPTURE_SCRATCH_DROPPED.with(|dropped| dropped.set(false));

        let inline_program_bytes = capture_box_inline_program_bytes();
        let mut preliminary_handle_bytes = fixed_retained_handle_bytes;
        let mut prospective_capture_owner_bytes = 0_u64;
        let mut censuses = Vec::new();
        censuses
            .try_reserve_exact(structural.member_count())
            .map_err(|_| OperationSetV2RuntimeError::Allocation("member census table"))?;
        // This is the only pre-owner capture census pass. Structural validation
        // deliberately stopped at fixed capture headers; every reachable unique
        // capture member's census value is derived exactly once and retained.
        // Safe owner reconstruction later independently revalidates each wire
        // as its own publication boundary, but does not derive a second runtime
        // census table or add another post-construction hash pass.
        for (index, member) in structural.members().enumerate() {
            let planned = plan.members.get(index).copied().ok_or(
                OperationSetV2RuntimeError::InternalInvariant(
                    "member plan is shorter than the V2 member table",
                ),
            )?;
            match (member.kind(), planned) {
                (AotOperationSetMemberKindV2::CompiledProgram, PlannedMemberV2::Compiled(_)) => {
                    let census =
                        GenericNfaProgramCensus::from_wire(member.as_bytes()).map_err(|_| {
                            OperationSetV2RuntimeError::Malformed(
                                "compiled V2 member is not a canonical scalar generic NFA",
                            )
                        })?;
                    preliminary_handle_bytes = add_usize(
                        preliminary_handle_bytes,
                        census.semantic_graph_logical_bytes(),
                        "prospective compiled semantic graph bytes",
                    )?;
                    preliminary_handle_bytes = add_usize(
                        preliminary_handle_bytes,
                        census.workspace_layout().logical_bytes(),
                        "prospective compiled workspace bytes",
                    )?;
                    censuses.push(MemberCensusV2::Compiled(census));
                }
                (
                    AotOperationSetMemberKindV2::CaptureProgramV1,
                    PlannedMemberV2::Capture { reached: true },
                ) => {
                    let census = census_capture_member(
                        member.as_bytes(),
                        config.capture_limits,
                        capture_scratch.as_mut_slice(),
                    )
                    .map_err(|_| {
                        OperationSetV2RuntimeError::Malformed(
                            "capture V2 member census validation failed",
                        )
                    })?;
                    if census.can_match_empty() {
                        return Err(OperationSetV2RuntimeError::UnsupportedOperation);
                    }
                    let prospective_owner = census
                        .usage()
                        .program_bytes
                        .checked_add(inline_program_bytes)
                        .ok_or(OperationSetV2RuntimeError::Arithmetic(
                            "prospective capture execution owner bytes",
                        ))?;
                    prospective_capture_owner_bytes = add_usize(
                        prospective_capture_owner_bytes,
                        prospective_owner,
                        "prospective aggregate capture owner bytes",
                    )?;
                    preliminary_handle_bytes = add_usize(
                        preliminary_handle_bytes,
                        prospective_owner,
                        "prospective capture owner handle bytes",
                    )?;
                    censuses.push(MemberCensusV2::Capture(census));
                }
                _ => return Err(OperationSetV2RuntimeError::UnsupportedOperation),
            }
            if preliminary_handle_bytes > config.max_handle_bytes {
                return Err(OperationSetV2RuntimeError::Resource(
                    "retained handle bytes",
                ));
            }
            if prospective_capture_owner_bytes > config.max_capture_owner_bytes {
                return Err(OperationSetV2RuntimeError::Resource(
                    "capture execution owner bytes",
                ));
            }
        }
        if censuses.len() != structural.member_count() {
            return Err(OperationSetV2RuntimeError::InternalInvariant(
                "member census count differs from V2 member count",
            ));
        }
        // The retained census table contains every fact needed by owned
        // reconstruction. Release the shared outer prefix before any
        // deserialize_with_census call allocates its own exact validation
        // scratch, so those two equal-bound transient owners are sequential,
        // never co-live.
        drop(capture_scratch);
        #[cfg(test)]
        TEST_OUTER_CAPTURE_SCRATCH_DROPPED.with(|dropped| dropped.set(true));

        let mut decoded = Vec::new();
        decoded
            .try_reserve_exact(structural.member_count())
            .map_err(|_| OperationSetV2RuntimeError::Allocation("decoded member table"))?;
        let mut actual_capture_owner_bytes = 0_u64;
        let mut aggregate_capture_workspace_bytes = 0_u64;
        let mut aggregate_capture_work = 0_u64;
        let mut aggregate_capture_events = 0_u64;
        let mut aggregate_capture_count = 0_u64;
        for (index, member) in structural.members().enumerate() {
            match (plan.members[index], censuses[index], member.kind()) {
                (
                    PlannedMemberV2::Compiled(operations),
                    MemberCensusV2::Compiled(census),
                    AotOperationSetMemberKindV2::CompiledProgram,
                ) => {
                    let program =
                        CompiledProgram::deserialize(member.as_bytes()).map_err(|_| {
                            OperationSetV2RuntimeError::Malformed(
                                "compiled V2 member reconstruction failed",
                            )
                        })?;
                    if program.output_contract() != census.output_contract() {
                        return Err(OperationSetV2RuntimeError::InternalInvariant(
                            "compiled V2 member output changed after census",
                        ));
                    }
                    if operations.0 & (COMPILED_MEMBER_COUNT | COMPILED_MEMBER_SPAN_SUM) != 0
                        && program.output_contract() != OutputContract::Span
                    {
                        return Err(OperationSetV2RuntimeError::IncompatibleOutput);
                    }
                    let workspace =
                        program.prepare_generic_nfa_workspace(census).map_err(|_| {
                            OperationSetV2RuntimeError::Allocation("compiled member workspace")
                        })?;
                    decoded.push(DecodedMemberV2::Compiled(DecodedCompiledMemberV2 {
                        operations,
                        program,
                        workspace,
                        census,
                        grep_count_workspace: None,
                    }));
                }
                (
                    PlannedMemberV2::Capture { reached: true },
                    MemberCensusV2::Capture(census),
                    AotOperationSetMemberKindV2::CaptureProgramV1,
                ) => {
                    #[cfg(test)]
                    TEST_OUTER_CAPTURE_SCRATCH_DROPPED.with(|dropped| {
                        assert!(
                            dropped.get(),
                            "owned capture decode started before outer census scratch dropped",
                        );
                        TEST_OWNER_DECODES_AFTER_SCRATCH_DROP.with(|calls| {
                            calls.set(calls.get().saturating_add(1));
                        });
                    });
                    let (owner, receipt) = CaptureProgramV1::deserialize_with_census(
                        member.as_bytes(),
                        config.capture_limits,
                        &census,
                        census.owned_retained_logical_bytes(),
                    )
                    .map_err(|_| {
                        OperationSetV2RuntimeError::Malformed(
                            "capture V2 member reconstruction failed",
                        )
                    })?;
                    let owner_accounting = capture_execution_owner_accounting(&receipt, census)?;
                    if owner.semantic_digest() != census.semantic_digest()
                        || !owner.program().build_report_closes()
                        || owner.program().build_report().program_bytes
                            != owner_accounting.nested_program_capacity_bytes
                    {
                        return Err(OperationSetV2RuntimeError::InternalInvariant(
                            "capture execution Program does not close against actual capacities",
                        ));
                    }
                    // The full wrapper receipt has now authenticated every
                    // capacity that survives this move. Canonical bytes, the
                    // duplicate public schema, and the full receipt are not
                    // retained or charged after into_program.
                    let program = owner.into_program();
                    let operation = CaptureStream::operation_prospective(
                        &program,
                        config.exact_source_bytes,
                        CaptureStreamDomains::Whole,
                    )
                    .map_err(|_| {
                        OperationSetV2RuntimeError::Resource(
                            "capture operation prospective envelope",
                        )
                    })?;
                    if !operation.authenticates_program(&program)
                        || operation.domains != CaptureStreamDomains::Whole
                        || operation.construction.program_bytes
                            != owner_accounting.nested_program_capacity_bytes
                    {
                        return Err(OperationSetV2RuntimeError::InternalInvariant(
                            "capture operation prospective does not authenticate Program",
                        ));
                    }
                    actual_capture_owner_bytes = add_usize(
                        actual_capture_owner_bytes,
                        owner_accounting.retained_owner_bytes,
                        "actual aggregate capture owner bytes",
                    )?;
                    aggregate_capture_workspace_bytes = add_usize(
                        aggregate_capture_workspace_bytes,
                        capture_workspace_bytes(&operation)?,
                        "aggregate capture workspace bytes",
                    )?;
                    aggregate_capture_work = add_usize(
                        aggregate_capture_work,
                        operation.work,
                        "aggregate capture work",
                    )?;
                    aggregate_capture_events = add_usize(
                        aggregate_capture_events,
                        operation.capture_events,
                        "aggregate capture events",
                    )?;
                    aggregate_capture_count = add_usize(
                        aggregate_capture_count,
                        operation.capture_count,
                        "aggregate capture count",
                    )?;
                    decoded.push(DecodedMemberV2::Capture(DecodedCaptureMemberV2 {
                        program,
                        owner: owner_accounting,
                        operation,
                    }));
                }
                _ => {
                    return Err(OperationSetV2RuntimeError::InternalInvariant(
                        "V2 member plan, census, and kind disagree",
                    ));
                }
            }
        }
        if actual_capture_owner_bytes != prospective_capture_owner_bytes {
            return Err(OperationSetV2RuntimeError::InternalInvariant(
                "actual capture owner bytes differ from census prospective",
            ));
        }
        if actual_capture_owner_bytes > config.max_capture_owner_bytes {
            return Err(OperationSetV2RuntimeError::Resource(
                "capture execution owner bytes",
            ));
        }
        if aggregate_capture_workspace_bytes > config.max_capture_workspace_bytes {
            return Err(OperationSetV2RuntimeError::Resource(
                "capture workspace bytes",
            ));
        }
        if aggregate_capture_work > config.max_capture_work {
            return Err(OperationSetV2RuntimeError::Resource(
                "capture operation work",
            ));
        }
        if aggregate_capture_events > config.max_capture_events {
            return Err(OperationSetV2RuntimeError::Resource(
                "capture schema events",
            ));
        }
        if aggregate_capture_count > config.max_capture_count {
            return Err(OperationSetV2RuntimeError::Resource(
                "capture participation result",
            ));
        }
        if aggregate_capture_count > aggregate_capture_events {
            return Err(OperationSetV2RuntimeError::InternalInvariant(
                "capture result envelope exceeds capture events",
            ));
        }

        let OperationSetPreparationPlanV2 { members: _, roots } = plan;
        let mut prepared_members = Vec::new();
        prepared_members
            .try_reserve_exact(decoded.len())
            .map_err(|_| OperationSetV2RuntimeError::Allocation("prepared V2 member table"))?;
        let mut output_scratch = Vec::new();
        output_scratch
            .try_reserve_exact(roots.len())
            .map_err(|_| OperationSetV2RuntimeError::Allocation("V2 output transaction scratch"))?;
        output_scratch.resize(roots.len(), FreAotRegexOperationSetOutputV2::default());

        let mut base_retained_handle_bytes = operation_set_v2_fixed_retained_bytes(
            prepared_members.capacity(),
            roots.capacity(),
            output_scratch.capacity(),
        )?;
        for member in &decoded {
            match member {
                DecodedMemberV2::Compiled(member) => {
                    base_retained_handle_bytes = add_usize(
                        base_retained_handle_bytes,
                        member
                            .program
                            .generic_nfa_retained_heap_bytes(member.census)
                            .map_err(|_| {
                                OperationSetV2RuntimeError::InternalInvariant(
                                    "compiled member retained accounting failed",
                                )
                            })?,
                        "retained compiled member bytes",
                    )?;
                    base_retained_handle_bytes = add_usize(
                        base_retained_handle_bytes,
                        member.workspace.compiler_private_k0_retained_bytes(),
                        "retained compiled workspace bytes",
                    )?;
                }
                DecodedMemberV2::Capture(member) => {
                    base_retained_handle_bytes = add_usize(
                        base_retained_handle_bytes,
                        member.owner.retained_owner_bytes,
                        "retained capture owner bytes",
                    )?;
                    // CaptureStream's inline value is already in the final
                    // member-vector capacity. Add only its exact heap payload;
                    // the unique Program is charged independently above.
                    base_retained_handle_bytes = add_usize(
                        base_retained_handle_bytes,
                        member.operation.construction.allocator_bytes,
                        "retained capture workspace heap bytes",
                    )?;
                }
            }
        }
        if base_retained_handle_bytes > config.max_handle_bytes {
            return Err(OperationSetV2RuntimeError::Resource(
                "retained handle bytes",
            ));
        }

        let mut prospective_start_filter_work = Some(0_u64);
        let mut prospective_start_filter_proof_bytes = 0_u64;
        let mut prospective_grep_count_bytes = 0_u64;
        for member in &decoded {
            let DecodedMemberV2::Compiled(member) = member else {
                continue;
            };
            if member.operations.requires_start_filter() {
                let bound = member
                    .program
                    .generic_nfa_start_filter_setup_work_bound(member.census)
                    .map_err(|_| {
                        OperationSetV2RuntimeError::InternalInvariant(
                            "compiled start-filter sizing failed",
                        )
                    })?;
                prospective_start_filter_work = match (prospective_start_filter_work, bound) {
                    (Some(total), Some(work)) => total.checked_add(work),
                    _ => None,
                };
                prospective_start_filter_proof_bytes = add_usize(
                    prospective_start_filter_proof_bytes,
                    member
                        .program
                        .generic_nfa_start_filter_proof_retained_bytes_bound(member.census)
                        .map_err(|_| {
                            OperationSetV2RuntimeError::InternalInvariant(
                                "compiled start-filter proof sizing failed",
                            )
                        })?,
                    "aggregate compiled start-filter proof bytes",
                )?;
            }
            if member.operations.requires_grep_count() {
                prospective_grep_count_bytes = add_usize(
                    prospective_grep_count_bytes,
                    member
                        .program
                        .generic_nfa_grep_count_workspace_logical_bytes(member.census)
                        .map_err(|_| {
                            OperationSetV2RuntimeError::InternalInvariant(
                                "compiled GrepCount sizing failed",
                            )
                        })?,
                    "aggregate compiled GrepCount bytes",
                )?;
            }
        }
        if prospective_grep_count_bytes > config.max_grep_count_workspace_bytes {
            return Err(OperationSetV2RuntimeError::Resource(
                "aggregate GrepCount workspace bytes",
            ));
        }
        let start_filter_aggregate_admitted = prospective_start_filter_work
            .is_some_and(|required| required <= config.max_start_filter_setup_work);
        let admitted_proof_bytes = if start_filter_aggregate_admitted {
            prospective_start_filter_proof_bytes
        } else {
            0
        };
        let prospective_handle_bytes = base_retained_handle_bytes
            .checked_add(admitted_proof_bytes)
            .and_then(|bytes| bytes.checked_add(prospective_grep_count_bytes))
            .ok_or(OperationSetV2RuntimeError::Arithmetic(
                "prospective complete V2 handle bytes",
            ))?;
        if prospective_handle_bytes > config.max_handle_bytes {
            return Err(OperationSetV2RuntimeError::Resource(
                "retained handle bytes",
            ));
        }

        let mut actual_start_filter_work = 0_u64;
        for member in &mut decoded {
            let DecodedMemberV2::Compiled(member) = member else {
                continue;
            };
            if !member.operations.requires_start_filter() {
                continue;
            }
            let member_limit = if start_filter_aggregate_admitted {
                member
                    .program
                    .generic_nfa_start_filter_setup_work_bound(member.census)
                    .map_err(|_| {
                        OperationSetV2RuntimeError::InternalInvariant(
                            "compiled start-filter sizing changed",
                        )
                    })?
                    .ok_or(OperationSetV2RuntimeError::InternalInvariant(
                        "admitted V2 aggregate contains unbounded start-filter work",
                    ))?
            } else {
                0
            };
            let receipt = member
                .program
                .prepare_start_filter_with_workspace_limit(&mut member.workspace, member_limit)
                .map_err(|_| OperationSetV2RuntimeError::Execution)?;
            actual_start_filter_work = add_u64(
                actual_start_filter_work,
                receipt.work_completed(),
                "actual aggregate compiled start-filter work",
            )?;
        }
        let start_work_closes = match (
            prospective_start_filter_work,
            start_filter_aggregate_admitted,
        ) {
            (Some(prospective), true) => actual_start_filter_work <= prospective,
            _ => actual_start_filter_work == 0,
        };
        if !start_work_closes || actual_start_filter_work > config.max_start_filter_setup_work {
            return Err(OperationSetV2RuntimeError::InternalInvariant(
                "actual compiled start-filter work exceeded admission",
            ));
        }

        let mut actual_grep_count_bytes = 0_u64;
        for member in &mut decoded {
            let DecodedMemberV2::Compiled(member) = member else {
                continue;
            };
            if !member.operations.requires_grep_count() {
                continue;
            }
            let required = member
                .program
                .generic_nfa_grep_count_workspace_logical_bytes(member.census)
                .map_err(|_| {
                    OperationSetV2RuntimeError::InternalInvariant(
                        "compiled GrepCount sizing changed",
                    )
                })?;
            let workspace = member
                .program
                .prepare_grep_count_workspace_with_limits(GrepCountWorkspaceLimits {
                    max_workspace_bytes: required,
                })
                .map_err(|_| OperationSetV2RuntimeError::Allocation("GrepCount workspace"))?;
            let actual = workspace.compiler_private_retained_heap_bytes().ok_or(
                OperationSetV2RuntimeError::Arithmetic("actual GrepCount retained bytes"),
            )?;
            if actual != required {
                return Err(OperationSetV2RuntimeError::InternalInvariant(
                    "actual GrepCount capacity changed after sizing",
                ));
            }
            actual_grep_count_bytes = add_usize(
                actual_grep_count_bytes,
                actual,
                "actual aggregate GrepCount bytes",
            )?;
            member.grep_count_workspace = Some(workspace);
        }
        if actual_grep_count_bytes != prospective_grep_count_bytes {
            return Err(OperationSetV2RuntimeError::InternalInvariant(
                "actual GrepCount bytes differ from prospective",
            ));
        }

        for member in decoded {
            let prepared = match member {
                DecodedMemberV2::Compiled(member) => {
                    PreparedOperationSetMemberV2::Compiled(PreparedCompiledMemberV2 {
                        operations: member.operations,
                        program: member.program,
                        workspace: member.workspace,
                        grep_count_workspace: member.grep_count_workspace,
                        census: member.census,
                    })
                }
                DecodedMemberV2::Capture(member) => {
                    let expected = member.operation;
                    let program = try_capture_program_owner(member.program)?;
                    let stream = CaptureStream::new_unique(
                        program,
                        config.exact_source_bytes,
                        CaptureStreamDomains::Whole,
                        exact_capture_stream_limits(&expected),
                    )
                    .map_err(|_| {
                        OperationSetV2RuntimeError::Allocation("capture member workspace")
                    })?;
                    if stream.operation_report() != expected
                        || stream.build_report() != expected.construction
                    {
                        return Err(OperationSetV2RuntimeError::InternalInvariant(
                            "constructed capture stream differs from prospective",
                        ));
                    }
                    PreparedOperationSetMemberV2::Capture(PreparedCaptureMemberV2 {
                        stream,
                        owner: member.owner,
                        cached_value: None,
                    })
                }
            };
            prepared_members.push(prepared);
        }
        if prepared_members.len() != censuses.len() {
            return Err(OperationSetV2RuntimeError::InternalInvariant(
                "prepared V2 member count differs from census count",
            ));
        }
        let prepared = Self {
            exact_source_bytes: config.exact_source_bytes,
            members: prepared_members,
            roots,
            output_scratch,
            reusable: true,
        };
        let retained_handle_bytes = prepared.actual_retained_handle_bytes()?;
        if retained_handle_bytes > config.max_handle_bytes {
            return Err(OperationSetV2RuntimeError::Resource(
                "retained handle bytes",
            ));
        }
        let receipt = OperationSetPreparationReceiptV2 {
            capture_validation_scratch_bytes: scratch_bytes_u64,
            prospective_start_filter_work,
            actual_start_filter_work,
            start_filter_aggregate_admitted,
            grep_count_workspace_bytes: actual_grep_count_bytes,
            capture_owner_bytes: actual_capture_owner_bytes,
            capture_workspace_bytes: aggregate_capture_workspace_bytes,
            capture_work: aggregate_capture_work,
            capture_events: aggregate_capture_events,
            capture_count: aggregate_capture_count,
            prospective_handle_bytes,
            retained_handle_bytes,
        };
        if !receipt.authenticates(config) {
            return Err(OperationSetV2RuntimeError::InternalInvariant(
                "final V2 preparation receipt does not authenticate config",
            ));
        }
        Ok((prepared, receipt))
    }

    fn actual_retained_handle_bytes(&self) -> Result<u64, OperationSetV2RuntimeError> {
        let mut bytes = operation_set_v2_fixed_retained_bytes(
            self.members.capacity(),
            self.roots.capacity(),
            self.output_scratch.capacity(),
        )?;
        for member in &self.members {
            match member {
                PreparedOperationSetMemberV2::Compiled(member) => {
                    bytes = add_usize(
                        bytes,
                        member
                            .program
                            .generic_nfa_retained_heap_bytes(member.census)
                            .map_err(|_| {
                                OperationSetV2RuntimeError::InternalInvariant(
                                    "retained compiled member accounting failed",
                                )
                            })?,
                        "actual retained compiled member bytes",
                    )?;
                    bytes = add_usize(
                        bytes,
                        member.workspace.compiler_private_k0_retained_bytes(),
                        "actual retained compiled workspace bytes",
                    )?;
                    if let Some(grep) = member.grep_count_workspace.as_ref() {
                        bytes = add_usize(
                            bytes,
                            grep.compiler_private_retained_heap_bytes().ok_or(
                                OperationSetV2RuntimeError::Arithmetic(
                                    "actual retained GrepCount bytes",
                                ),
                            )?,
                            "actual retained GrepCount bytes",
                        )?;
                    }
                }
                PreparedOperationSetMemberV2::Capture(member) => {
                    if member
                        .owner
                        .nested_program_capacity_bytes
                        .checked_add(member.owner.inline_program_bytes)
                        != Some(member.owner.retained_owner_bytes)
                    {
                        return Err(OperationSetV2RuntimeError::InternalInvariant(
                            "retained capture owner accounting no longer closes",
                        ));
                    }
                    bytes = add_usize(
                        bytes,
                        member.owner.retained_owner_bytes,
                        "actual retained capture owner bytes",
                    )?;
                    bytes = add_usize(
                        bytes,
                        member.stream.build_report().allocator_bytes,
                        "actual retained capture workspace heap bytes",
                    )?;
                }
            }
        }
        Ok(bytes)
    }

    fn execute(&mut self, haystack: &[u8]) -> Result<(), OperationSetV2RuntimeError> {
        if haystack.len() != self.exact_source_bytes {
            return Err(OperationSetV2RuntimeError::InternalInvariant(
                "exact source length changed after C-boundary validation",
            ));
        }
        for member in &mut self.members {
            if let PreparedOperationSetMemberV2::Capture(member) = member {
                member.cached_value = None;
            }
        }
        for (output_index, root) in self.roots.iter().copied().enumerate() {
            let member = self.members.get_mut(root.member_index).ok_or(
                OperationSetV2RuntimeError::InternalInvariant(
                    "prepared V2 root member index is out of bounds",
                ),
            )?;
            let output = match (root.operation, member) {
                (
                    RootOperationV2::Compiled(operation),
                    PreparedOperationSetMemberV2::Compiled(member),
                ) => {
                    if member.operations.0 & operation.flag() == 0 {
                        return Err(OperationSetV2RuntimeError::InternalInvariant(
                            "compiled root operation is absent from its member union",
                        ));
                    }
                    execute_compiled_root(member, operation, haystack)?
                }
                (
                    RootOperationV2::CaptureParticipationCount,
                    PreparedOperationSetMemberV2::Capture(member),
                ) => {
                    let value = if let Some(value) = member.cached_value {
                        value
                    } else {
                        let expected_operation = member.stream.operation_report();
                        let expected_limits = exact_capture_stream_limits(&expected_operation);
                        #[cfg(test)]
                        TEST_CAPTURE_EXECUTIONS.with(|calls| {
                            calls.set(calls.get().saturating_add(1));
                        });
                        let report = member
                            .stream
                            .execute(haystack)
                            .map_err(|_| OperationSetV2RuntimeError::Execution)?;
                        if report.operation != expected_operation || !report.closes(expected_limits)
                        {
                            return Err(OperationSetV2RuntimeError::InternalInvariant(
                                "capture execution receipt does not close against preparation",
                            ));
                        }
                        let value = u64_from_usize(
                            report.captures.count,
                            "capture participation output conversion",
                        )?;
                        member.cached_value = Some(value);
                        value
                    };
                    FreAotRegexOperationSetOutputV2 {
                        kind: OPERATION_SET_OUTPUT_CAPTURE_PARTICIPATION_COUNT,
                        status: STATUS_SUCCESS,
                        first: value,
                        second: 0,
                    }
                }
                _ => {
                    return Err(OperationSetV2RuntimeError::InternalInvariant(
                        "prepared V2 root and member kinds disagree",
                    ));
                }
            };
            *self.output_scratch.get_mut(output_index).ok_or(
                OperationSetV2RuntimeError::InternalInvariant(
                    "prepared V2 output scratch is shorter than the root table",
                ),
            )? = output;
        }
        Ok(())
    }
}

fn execute_compiled_root(
    member: &mut PreparedCompiledMemberV2,
    operation: CompiledOperationV2,
    haystack: &[u8],
) -> Result<FreAotRegexOperationSetOutputV2, OperationSetV2RuntimeError> {
    match operation {
        CompiledOperationV2::Search => {
            let found = member
                .program
                .search_with_workspace(
                    haystack,
                    SearchWindow::full(haystack),
                    &mut member.workspace,
                )
                .map_err(|_| OperationSetV2RuntimeError::Execution)?;
            encode_compiled_search(found)
        }
        CompiledOperationV2::Count => Ok(FreAotRegexOperationSetOutputV2 {
            kind: OPERATION_SET_OUTPUT_COUNT,
            status: STATUS_SUCCESS,
            first: reduce_compiled_spans(
                &member.program,
                &mut member.workspace,
                haystack,
                SpanReducerV2::Count,
            )?,
            second: 0,
        }),
        CompiledOperationV2::SpanSum => Ok(FreAotRegexOperationSetOutputV2 {
            kind: OPERATION_SET_OUTPUT_SPAN_SUM,
            status: STATUS_SUCCESS,
            first: reduce_compiled_spans(
                &member.program,
                &mut member.workspace,
                haystack,
                SpanReducerV2::SpanSum,
            )?,
            second: 0,
        }),
        CompiledOperationV2::GrepCount => {
            let workspace = member.grep_count_workspace.as_mut().ok_or(
                OperationSetV2RuntimeError::InternalInvariant(
                    "compiled GrepCount root has no prepared workspace",
                ),
            )?;
            let count = member
                .program
                .grep_count_with_workspace(haystack, workspace)
                .map_err(|_| OperationSetV2RuntimeError::Execution)?
                .count();
            Ok(FreAotRegexOperationSetOutputV2 {
                kind: OPERATION_SET_OUTPUT_GREP_COUNT,
                status: STATUS_SUCCESS,
                first: count,
                second: 0,
            })
        }
    }
}

fn encode_compiled_search(
    found: MatchResult,
) -> Result<FreAotRegexOperationSetOutputV2, OperationSetV2RuntimeError> {
    let (kind, status, first, second) = match found {
        MatchResult::Exists(false) => (OPERATION_SET_OUTPUT_SEARCH_EXISTS, STATUS_NO_MATCH, 0, 0),
        MatchResult::Exists(true) => (OPERATION_SET_OUTPUT_SEARCH_EXISTS, STATUS_MATCH, 0, 0),
        MatchResult::SelectedEnd(None) => (
            OPERATION_SET_OUTPUT_SEARCH_SELECTED_END,
            STATUS_NO_MATCH,
            0,
            0,
        ),
        MatchResult::SelectedEnd(Some(end)) => {
            let end = u64_from_usize(end, "SelectedEnd output conversion")?;
            (
                OPERATION_SET_OUTPUT_SEARCH_SELECTED_END,
                STATUS_MATCH,
                end,
                end,
            )
        }
        MatchResult::Span(None) => (OPERATION_SET_OUTPUT_SEARCH_SPAN, STATUS_NO_MATCH, 0, 0),
        MatchResult::Span(Some((start, end))) => (
            OPERATION_SET_OUTPUT_SEARCH_SPAN,
            STATUS_MATCH,
            u64_from_usize(start, "Span start output conversion")?,
            u64_from_usize(end, "Span end output conversion")?,
        ),
    };
    Ok(FreAotRegexOperationSetOutputV2 {
        kind,
        status,
        first,
        second,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SpanReducerV2 {
    Count,
    SpanSum,
}

fn reduce_compiled_spans(
    program: &CompiledProgram,
    workspace: &mut ProgramWorkspace,
    haystack: &[u8],
    reducer: SpanReducerV2,
) -> Result<u64, OperationSetV2RuntimeError> {
    if program.output_contract() != OutputContract::Span {
        return Err(OperationSetV2RuntimeError::IncompatibleOutput);
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
                .ok_or(OperationSetV2RuntimeError::Arithmetic(
                    "compiled empty-match progress",
                ))?;
        }
        let search_start = start;
        let result = program
            .search_with_workspace(
                haystack,
                SearchWindow::new(search_start, haystack.len()),
                workspace,
            )
            .map_err(|_| OperationSetV2RuntimeError::Execution)?;
        let MatchResult::Span(found) = result else {
            return Err(OperationSetV2RuntimeError::IncompatibleOutput);
        };
        let Some((match_start, match_end)) = found else {
            return Ok(value);
        };
        if match_start < search_start || match_start > match_end || match_end > haystack.len() {
            return Err(OperationSetV2RuntimeError::InternalInvariant(
                "compiled Span reducer received an out-of-window match",
            ));
        }
        if match_start == match_end && last_match_end == Some(match_end) {
            if start == haystack.len() {
                return Ok(value);
            }
            start = start
                .checked_add(1)
                .ok_or(OperationSetV2RuntimeError::Arithmetic(
                    "compiled repeated-empty progress",
                ))?;
            continue;
        }
        let contribution = match reducer {
            SpanReducerV2::Count => 1,
            SpanReducerV2::SpanSum => u64_from_usize(
                match_end.checked_sub(match_start).ok_or(
                    OperationSetV2RuntimeError::InternalInvariant(
                        "compiled Span reducer received an inverted match",
                    ),
                )?,
                "compiled SpanSum width conversion",
            )?,
        };
        value = value
            .checked_add(contribution)
            .ok_or(OperationSetV2RuntimeError::Arithmetic(
                "compiled scalar reducer result",
            ))?;
        start = match_end;
        last_match_end = Some(match_end);
        pending_empty_progress = match_start == match_end;
    }
}

/// Validate and prepare one exact-source canonical operation-set V2.
///
/// Configuration is copied and validated before the wire extent is read.
/// The complete handle is published only after all unique members, roots,
/// exact workspaces, and prospective/actual resource receipts close.
/// Null/misaligned pointers, unsupported signed extents, or invalid config
/// return [`STATUS_INVALID_ARGUMENT`]. Malformed/unsupported wire, resource or
/// allocation refusal, preparation failure, or panic returns
/// [`STATUS_RUNTIME_FAILURE`]. Every recoverable failure leaves `handle_out`
/// untouched.
///
/// # Safety
///
/// `operation_set_ptr` must be non-null and readable for `operation_set_len`
/// bytes, including when that length is zero, with length no greater than
/// `isize::MAX`. `config_ptr` must be non-null, aligned, and readable for one
/// complete V2 config. `handle_out` must be non-null, aligned, and writable for
/// one V2 handle. All three complete live extents must be pairwise disjoint.
/// Dangling, short, read-only, or overlapping storage is not recoverably
/// validated. A successful handle is exclusively owned, must not be copied for
/// concurrent use, and must be destroyed exactly once.
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    reason = "this exported symbol is an audited raw C pointer boundary"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_prepare_operation_set_exclusive_v2(
    operation_set_ptr: *const u8,
    operation_set_len: usize,
    config_ptr: *const FreAotRegexOperationSetPrepareConfigV2,
    handle_out: *mut FreAotRegexOperationSetExclusiveHandleV2,
) -> u32 {
    if operation_set_ptr.is_null()
        || operation_set_len > isize::MAX.unsigned_abs()
        || config_ptr.is_null()
        || !config_ptr.is_aligned()
        || handle_out.is_null()
        || !handle_out.is_aligned()
    {
        return STATUS_INVALID_ARGUMENT;
    }
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: the caller contract supplies one aligned readable config.
        // It is copied and fully validated before constructing the wire slice.
        let config = unsafe { config_ptr.read() };
        let Some(config) = OperationSetPrepareConfigV2::from_ffi(config) else {
            return STATUS_INVALID_ARGUMENT;
        };
        // SAFETY: the caller contract supplies this complete readable extent.
        let bytes = unsafe { core::slice::from_raw_parts(operation_set_ptr, operation_set_len) };
        let Ok((prepared, _receipt)) =
            PreparedAotOperationSetV2::deserialize_with_config(bytes, config)
        else {
            return STATUS_RUNTIME_FAILURE;
        };
        let Ok(owner) = try_box_preserve(prepared) else {
            return STATUS_RUNTIME_FAILURE;
        };
        let allocation = Box::into_raw(owner).cast::<core::ffi::c_void>();
        // SAFETY: the caller supplies aligned writable disjoint storage. This
        // is the complete preparation transaction's final observable write.
        unsafe {
            handle_out.write(FreAotRegexOperationSetExclusiveHandleV2(allocation));
        }
        STATUS_SUCCESS
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

/// Execute every V2 root against the exact source length bound at prepare.
///
/// Argument validation, including exact source equality, happens before
/// source access or workspace mutation. All roots write handle-owned scratch;
/// only complete success copies the whole output array. Any runtime failure
/// leaves caller output untouched and the handle terminal/destroy-only.
/// A null handle returns [`STATUS_INVALID_HANDLE`]. Null/misaligned pointers,
/// unsupported signed extents, wrong output count, or non-exact source length
/// return [`STATUS_INVALID_ARGUMENT`] before mutation and leave a live handle
/// reusable. Execution failure or panic returns [`STATUS_RUNTIME_FAILURE`]. An
/// otherwise valid retry of a terminal handle returns runtime failure before
/// source access, workspace mutation, or caller-output publication.
///
/// # Safety
///
/// `handle` must be the live uniquely owned value returned by the V2 prepare
/// symbol. `haystack_ptr` must be non-null and readable for `haystack_len`
/// bytes, including when that length is zero. `outputs` must be non-null,
/// aligned, and writable for `output_count` records. Source, output, handle
/// allocation, and every handle-owned extent must be pairwise disjoint and
/// remain live for the call. Execute and destroy may not overlap. Dangling,
/// short, read-only, overlapping, copied-concurrent, stale, or destroyed
/// storage is not recoverably validated.
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    reason = "this exported symbol validates raw extents and commits outputs only after complete execution"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_execute_operation_set_exclusive_v2(
    handle: FreAotRegexOperationSetExclusiveHandleV2,
    haystack_ptr: *const u8,
    haystack_len: usize,
    outputs: *mut FreAotRegexOperationSetOutputV2,
    output_count: usize,
) -> u32 {
    if handle.is_invalid() {
        return STATUS_INVALID_HANDLE;
    }
    let output_bytes = output_count.checked_mul(size_of::<FreAotRegexOperationSetOutputV2>());
    if haystack_ptr.is_null()
        || haystack_len > isize::MAX.unsigned_abs()
        || outputs.is_null()
        || !outputs.is_aligned()
        || !matches!(output_bytes, Some(bytes) if bytes <= isize::MAX.unsigned_abs())
    {
        return STATUS_INVALID_ARGUMENT;
    }
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let prepared = &mut *handle.0.cast::<PreparedAotOperationSetV2>();
        if output_count != prepared.roots.len() || haystack_len != prepared.exact_source_bytes {
            return STATUS_INVALID_ARGUMENT;
        }
        if !prepared.reusable {
            return STATUS_RUNTIME_FAILURE;
        }
        // Mark terminal before any source/workspace work. Only a successful
        // complete caller-output commit restores reusable state.
        prepared.reusable = false;
        let haystack = core::slice::from_raw_parts(haystack_ptr, haystack_len);
        if prepared.execute(haystack).is_err() {
            return STATUS_RUNTIME_FAILURE;
        }
        core::ptr::copy_nonoverlapping(prepared.output_scratch.as_ptr(), outputs, output_count);
        prepared.reusable = true;
        STATUS_SUCCESS
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

/// Release one exclusively owned V2 operation-set handle.
///
/// A null handle returns [`STATUS_INVALID_HANDLE`], successful destruction
/// returns [`STATUS_SUCCESS`], and an unexpected panic returns
/// [`STATUS_RUNTIME_FAILURE`].
///
/// # Safety
///
/// `handle` must be a live value returned by the V2 prepare symbol. No call
/// may overlap, and no copy may be used or destroyed afterward. A dangling,
/// copied-concurrent, stale, or previously destroyed nonnull handle is not
/// recoverably validated.
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    reason = "this exported symbol releases an exclusively owned opaque allocation"
)]
pub unsafe extern "C" fn fre_aot_regex_runtime_destroy_operation_set_exclusive_v2(
    handle: FreAotRegexOperationSetExclusiveHandleV2,
) -> u32 {
    if handle.is_invalid() {
        return STATUS_INVALID_HANDLE;
    }
    catch_unwind(AssertUnwindSafe(|| unsafe {
        drop(Box::from_raw(handle.0.cast::<PreparedAotOperationSetV2>()));
        STATUS_SUCCESS
    }))
    .unwrap_or(STATUS_RUNTIME_FAILURE)
}

#[cfg(test)]
mod tests {
    #![allow(
        unsafe_code,
        reason = "FFI contract tests call unsafe C entries only with documented valid geometry"
    )]
    #![allow(
        clippy::arithmetic_side_effects,
        reason = "test fixtures use bounded canonical V2 wire offsets"
    )]

    use super::*;
    use fre_aot_regex::{
        AOT_OPERATION_SET_V2_HEADER_BYTES, AOT_OPERATION_SET_V2_MAGIC,
        AOT_OPERATION_SET_V2_MEMBER_DESCRIPTOR_BYTES, AOT_OPERATION_SET_V2_OUTPUT_DESCRIPTOR_BYTES,
        AOT_OPERATION_SET_V2_ROOT_DESCRIPTOR_BYTES, AOT_OPERATION_SET_V2_STAGE_DESCRIPTOR_BYTES,
        AOT_OPERATION_SET_V2_VERSION, AotOperationSetMemberInputV2, AotOperationSetV2,
    };
    use fre_capture_lab::{Ast, BuildLimits, Greed};

    fn put_u16(bytes: &mut Vec<u8>, value: u16) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut Vec<u8>, value: u32) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut Vec<u8>, value: u64) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn put_usize(bytes: &mut Vec<u8>, value: usize) {
        put_u64(
            bytes,
            u64::try_from(value).expect("V2 test offset fits u64"),
        );
    }

    fn read_u64(bytes: &[u8], offset: usize) -> usize {
        let value = u64::from_le_bytes(
            bytes[offset..offset + size_of::<u64>()]
                .try_into()
                .expect("complete V2 test u64"),
        );
        usize::try_from(value).expect("V2 test offset fits usize")
    }

    fn overwrite_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + size_of::<u32>()].copy_from_slice(&value.to_le_bytes());
    }

    fn capture_program(ast: &Ast) -> Vec<u8> {
        let program = CaptureProgram::compile(ast, BuildLimits::default())
            .expect("compile capture-runtime fixture");
        CaptureProgramV1::from_program(program, CaptureProgramV1Limits::default())
            .expect("serialize capture-runtime fixture")
            .as_bytes()
            .to_vec()
    }

    fn capture_set<'a>(
        operations: impl IntoIterator<
            Item = (AotOperationAxesV2, AotOperationSetMemberInputV2<&'a [u8]>),
        >,
    ) -> AotOperationSetV2 {
        AotOperationSetV2::from_operations(operations, CaptureProgramV1Limits::default())
            .expect("build capture-runtime operation set")
    }

    fn decoded_config(source_bytes: usize) -> OperationSetPrepareConfigV2 {
        OperationSetPrepareConfigV2::from_ffi(FreAotRegexOperationSetPrepareConfigV2::new(
            u64::try_from(source_bytes).expect("test source length fits u64"),
        ))
        .expect("default V2 runtime config")
    }

    fn payload_extent(bytes: &[u8], member_index: usize) -> core::ops::Range<usize> {
        let view =
            AotOperationSetV2View::deserialize_structure(bytes, CaptureProgramV1Limits::default())
                .expect("structurally valid capture-runtime fixture");
        let payload = view
            .member(member_index)
            .expect("fixture member")
            .as_bytes();
        let start = payload
            .as_ptr()
            .addr()
            .checked_sub(bytes.as_ptr().addr())
            .expect("member payload lies inside fixture wire");
        start..start + payload.len()
    }

    fn corrupt_body_preserving_structure(bytes: &[u8], member_index: usize) -> Vec<u8> {
        let extent = payload_extent(bytes, member_index);
        let byte = extent
            .end
            .checked_sub(1)
            .expect("capture payload is nonempty");
        for delta in 1..=u8::MAX {
            let mut candidate = bytes.to_vec();
            candidate[byte] ^= delta;
            if AotOperationSetV2View::deserialize_structure(
                &candidate,
                CaptureProgramV1Limits::default(),
            )
            .is_ok()
            {
                return candidate;
            }
        }
        panic!("no corrupt capture body preserved canonical structural order");
    }

    fn raw_single_capture_set(payload: &[u8]) -> Vec<u8> {
        const MEMBER_KIND_CAPTURE_PROGRAM_V1: u32 = 2;
        const REDUCER_COUNT: u16 = 2;
        const PROJECTION_CAPTURE_PARTICIPATION: u16 = 3;
        const DOMAIN_WHOLE: u16 = 1;
        const OUTPUT_SCALAR_U64: u16 = 2;

        let member_table_offset = AOT_OPERATION_SET_V2_HEADER_BYTES;
        let shared_table_offset =
            member_table_offset + AOT_OPERATION_SET_V2_MEMBER_DESCRIPTOR_BYTES;
        let root_table_offset = shared_table_offset;
        let stage_table_offset = root_table_offset + AOT_OPERATION_SET_V2_ROOT_DESCRIPTOR_BYTES;
        let output_table_offset = stage_table_offset + AOT_OPERATION_SET_V2_STAGE_DESCRIPTOR_BYTES;
        let payload_offset = output_table_offset + AOT_OPERATION_SET_V2_OUTPUT_DESCRIPTOR_BYTES;
        let total_bytes = payload_offset + payload.len();
        let mut wire = Vec::with_capacity(total_bytes);
        wire.extend_from_slice(&AOT_OPERATION_SET_V2_MAGIC);
        put_u16(&mut wire, AOT_OPERATION_SET_V2_VERSION);
        put_u16(
            &mut wire,
            u16::try_from(AOT_OPERATION_SET_V2_HEADER_BYTES).expect("V2 header fits u16"),
        );
        put_u32(&mut wire, 0);
        put_usize(&mut wire, total_bytes);
        put_u32(&mut wire, 1);
        put_u32(&mut wire, 0);
        put_u32(&mut wire, 1);
        put_u32(&mut wire, 1);
        put_u32(&mut wire, 1);
        put_u32(&mut wire, 0);
        put_usize(&mut wire, member_table_offset);
        put_usize(&mut wire, shared_table_offset);
        put_usize(&mut wire, root_table_offset);
        put_usize(&mut wire, stage_table_offset);
        put_usize(&mut wire, output_table_offset);
        put_usize(&mut wire, payload_offset);
        for _ in 0..4 {
            put_u64(&mut wire, 0);
        }
        assert_eq!(wire.len(), AOT_OPERATION_SET_V2_HEADER_BYTES);

        put_u32(&mut wire, MEMBER_KIND_CAPTURE_PROGRAM_V1);
        put_u32(&mut wire, 0);
        put_u32(&mut wire, u32::MAX);
        put_u32(&mut wire, u32::MAX);
        put_usize(&mut wire, payload_offset);
        put_usize(&mut wire, payload.len());

        put_u32(&mut wire, 0);
        put_u32(&mut wire, 1);
        put_u32(&mut wire, 0);
        put_u32(&mut wire, 1);
        put_u32(&mut wire, 0);
        put_u32(&mut wire, 0);

        put_u32(&mut wire, 0);
        put_u16(&mut wire, REDUCER_COUNT);
        put_u16(&mut wire, PROJECTION_CAPTURE_PARTICIPATION);
        put_u16(&mut wire, DOMAIN_WHOLE);
        put_u16(&mut wire, 0);
        put_u32(&mut wire, 0);
        put_u64(&mut wire, 0);
        put_u64(&mut wire, 0);
        put_u64(&mut wire, 0);

        put_u16(&mut wire, OUTPUT_SCALAR_U64);
        put_u16(&mut wire, 0);
        put_u32(&mut wire, 0);
        put_u64(&mut wire, 1);
        wire.extend_from_slice(payload);
        assert_eq!(wire.len(), total_bytes);
        wire
    }

    fn reset_test_counters() {
        TEST_PREPARATION_PLANS.with(|calls| calls.set(0));
        TEST_CAPTURE_CENSUSES.with(|calls| calls.set(0));
        TEST_CAPTURE_EXECUTIONS.with(|calls| calls.set(0));
        TEST_OUTER_CAPTURE_SCRATCH_DROPPED.with(|dropped| dropped.set(false));
        TEST_OWNER_DECODES_AFTER_SCRATCH_DROP.with(|calls| calls.set(0));
        TEST_REFUSE_CAPTURE_PROGRAM_OWNER.with(|refuse| refuse.set(false));
    }

    #[test]
    fn unreachable_corrupt_capture_is_rejected_before_scratch_or_body_census() {
        let first = capture_program(&Ast::Byte(b'a').capture(1));
        let second = capture_program(&Ast::Byte(b'b').capture(1));
        let set = capture_set([
            (
                AotOperationAxesV2::CAPTURE_PARTICIPATION_COUNT,
                AotOperationSetMemberInputV2::CaptureProgramV1(first.as_slice()),
            ),
            (
                AotOperationAxesV2::CAPTURE_PARTICIPATION_COUNT,
                AotOperationSetMemberInputV2::CaptureProgramV1(second.as_slice()),
            ),
        ]);
        let mut wire = set.as_bytes().to_vec();
        let structural =
            AotOperationSetV2View::deserialize_structure(&wire, CaptureProgramV1Limits::default())
                .expect("valid two-member structure");
        let first_member = structural.root(0).expect("first root").member_index();
        let unreachable_member = structural.root(1).expect("second root").member_index();
        assert_ne!(first_member, unreachable_member);
        let stage_table_offset = read_u64(&wire, 72);
        overwrite_u32(
            &mut wire,
            stage_table_offset + AOT_OPERATION_SET_V2_STAGE_DESCRIPTOR_BYTES,
            first_member,
        );
        let wire = corrupt_body_preserving_structure(
            &wire,
            usize::try_from(unreachable_member).expect("member index fits usize"),
        );
        let structural =
            AotOperationSetV2View::deserialize_structure(&wire, CaptureProgramV1Limits::default())
                .expect("corrupt unreachable body remains structurally valid");
        let mut scratch = vec![0; structural.capture_validation_scratch_words()];
        assert!(
            structural
                .validate_capture_members(scratch.as_mut_slice())
                .is_err(),
            "fixture must contain a malformed capture body",
        );

        reset_test_counters();
        let error = PreparedAotOperationSetV2::deserialize_with_config(&wire, decoded_config(4))
            .expect_err("unreachable member must win before body validation");
        assert_eq!(error, OperationSetV2RuntimeError::UnreachableMember);
        TEST_PREPARATION_PLANS.with(|calls| assert_eq!(calls.get(), 1));
        TEST_CAPTURE_CENSUSES.with(|calls| assert_eq!(calls.get(), 0));
        TEST_OUTER_CAPTURE_SCRATCH_DROPPED.with(|dropped| assert!(!dropped.get()));
    }

    #[test]
    fn reachable_corrupt_and_nullable_capture_bodies_reach_exactly_one_census() {
        let nonnullable = capture_program(&Ast::Byte(b'a').capture(1));
        let set = capture_set([(
            AotOperationAxesV2::CAPTURE_PARTICIPATION_COUNT,
            AotOperationSetMemberInputV2::CaptureProgramV1(nonnullable.as_slice()),
        )]);
        let corrupt = corrupt_body_preserving_structure(set.as_bytes(), 0);
        reset_test_counters();
        let error = PreparedAotOperationSetV2::deserialize_with_config(&corrupt, decoded_config(4))
            .expect_err("reachable corrupt capture must fail its census");
        assert!(matches!(error, OperationSetV2RuntimeError::Malformed(_)));
        TEST_CAPTURE_CENSUSES.with(|calls| assert_eq!(calls.get(), 1));

        let nullable = capture_program(&Ast::Empty);
        let nullable = raw_single_capture_set(&nullable);
        AotOperationSetV2View::deserialize_structure(&nullable, CaptureProgramV1Limits::default())
            .expect("nullable fixture is structurally valid");
        reset_test_counters();
        let error =
            PreparedAotOperationSetV2::deserialize_with_config(&nullable, decoded_config(4))
                .expect_err("nullable capture is unsupported by exact-source runtime");
        assert_eq!(error, OperationSetV2RuntimeError::UnsupportedOperation);
        TEST_CAPTURE_CENSUSES.with(|calls| assert_eq!(calls.get(), 1));
    }

    #[test]
    fn unique_capture_is_censused_decoded_and_executed_once_per_invocation() {
        let optional_b = Ast::Byte(b'b').capture(2).repeat(0, Some(1), Greed::Greedy);
        let capture = capture_program(&Ast::concat([Ast::Byte(b'a').capture(1), optional_b]));
        let set = capture_set([
            (
                AotOperationAxesV2::CAPTURE_PARTICIPATION_COUNT,
                AotOperationSetMemberInputV2::CaptureProgramV1(capture.as_slice()),
            ),
            (
                AotOperationAxesV2::CAPTURE_PARTICIPATION_COUNT,
                AotOperationSetMemberInputV2::CaptureProgramV1(capture.as_slice()),
            ),
        ]);
        assert_eq!(set.member_count(), 1);
        assert_eq!(set.operation_count(), 2);

        reset_test_counters();
        let (mut prepared, receipt) =
            PreparedAotOperationSetV2::deserialize_with_config(set.as_bytes(), decoded_config(4))
                .expect("prepare one unique capture member");
        assert!(receipt.capture_validation_scratch_bytes > 0);
        TEST_CAPTURE_CENSUSES.with(|calls| assert_eq!(calls.get(), 1));
        TEST_OUTER_CAPTURE_SCRATCH_DROPPED.with(|dropped| assert!(dropped.get()));
        TEST_OWNER_DECODES_AFTER_SCRATCH_DROP.with(|calls| assert_eq!(calls.get(), 1));

        prepared
            .execute(b"abax")
            .expect("first exact-source execution");
        assert_eq!(prepared.output_scratch[0].first, 5);
        assert_eq!(prepared.output_scratch[1].first, 5);
        TEST_CAPTURE_EXECUTIONS.with(|calls| assert_eq!(calls.get(), 1));

        prepared
            .execute(b"xaxx")
            .expect("same-length execution resets duplicate-root cache");
        assert_eq!(prepared.output_scratch[0].first, 2);
        assert_eq!(prepared.output_scratch[1].first, 2);
        TEST_CAPTURE_EXECUTIONS.with(|calls| assert_eq!(calls.get(), 2));
    }

    #[test]
    fn every_capture_aggregate_cap_refuses_one_below_its_exact_receipt() {
        let capture = capture_program(&Ast::Byte(b'a').capture(1));
        let set = capture_set([
            (
                AotOperationAxesV2::CAPTURE_PARTICIPATION_COUNT,
                AotOperationSetMemberInputV2::CaptureProgramV1(capture.as_slice()),
            ),
            (
                AotOperationAxesV2::CAPTURE_PARTICIPATION_COUNT,
                AotOperationSetMemberInputV2::CaptureProgramV1(capture.as_slice()),
            ),
        ]);
        let (_, exact) =
            PreparedAotOperationSetV2::deserialize_with_config(set.as_bytes(), decoded_config(4))
                .expect("derive exact aggregate receipt");
        assert!(exact.capture_validation_scratch_bytes > 0);
        assert!(exact.capture_owner_bytes > 0);
        assert!(exact.capture_workspace_bytes > 0);
        assert!(exact.capture_work > 0);
        assert!(exact.capture_events > 0);
        assert!(exact.capture_count > 0);
        assert!(exact.prospective_handle_bytes > 0);

        let mut cases = Vec::new();
        let mut config = FreAotRegexOperationSetPrepareConfigV2::new(4);
        config.max_capture_validation_scratch_bytes = exact.capture_validation_scratch_bytes - 1;
        cases.push(("capture validation scratch", config));
        let mut config = FreAotRegexOperationSetPrepareConfigV2::new(4);
        config.max_capture_owner_bytes = exact.capture_owner_bytes - 1;
        cases.push(("capture owner", config));
        let mut config = FreAotRegexOperationSetPrepareConfigV2::new(4);
        config.max_capture_workspace_bytes = exact.capture_workspace_bytes - 1;
        cases.push(("capture workspace", config));
        let mut config = FreAotRegexOperationSetPrepareConfigV2::new(4);
        config.max_capture_work = exact.capture_work - 1;
        cases.push(("capture work", config));
        let mut config = FreAotRegexOperationSetPrepareConfigV2::new(4);
        config.max_capture_events = exact.capture_events - 1;
        cases.push(("capture events", config));
        let mut config = FreAotRegexOperationSetPrepareConfigV2::new(4);
        config.max_capture_count = exact.capture_count - 1;
        cases.push(("capture count", config));
        let mut config = FreAotRegexOperationSetPrepareConfigV2::new(4);
        config.max_handle_bytes = exact.prospective_handle_bytes - 1;
        cases.push(("complete handle", config));

        for (label, config) in cases {
            let config = OperationSetPrepareConfigV2::from_ffi(config)
                .expect("one-below test config is structurally valid");
            let error = PreparedAotOperationSetV2::deserialize_with_config(set.as_bytes(), config)
                .expect_err("one-below aggregate cap must refuse");
            assert!(
                matches!(error, OperationSetV2RuntimeError::Resource(_)),
                "one-below {label} returned {error:?}",
            );
        }
    }

    #[test]
    fn duplicate_roots_do_not_multiply_unique_capture_resource_ledgers() {
        let capture = capture_program(&Ast::Byte(b'a').capture(1));
        let single = capture_set([(
            AotOperationAxesV2::CAPTURE_PARTICIPATION_COUNT,
            AotOperationSetMemberInputV2::CaptureProgramV1(capture.as_slice()),
        )]);
        let duplicate = capture_set([
            (
                AotOperationAxesV2::CAPTURE_PARTICIPATION_COUNT,
                AotOperationSetMemberInputV2::CaptureProgramV1(capture.as_slice()),
            ),
            (
                AotOperationAxesV2::CAPTURE_PARTICIPATION_COUNT,
                AotOperationSetMemberInputV2::CaptureProgramV1(capture.as_slice()),
            ),
        ]);
        let (_, single) = PreparedAotOperationSetV2::deserialize_with_config(
            single.as_bytes(),
            decoded_config(4),
        )
        .expect("prepare single-root capture set");
        let (_, duplicate) = PreparedAotOperationSetV2::deserialize_with_config(
            duplicate.as_bytes(),
            decoded_config(4),
        )
        .expect("prepare duplicate-root capture set");
        assert_eq!(duplicate.capture_owner_bytes, single.capture_owner_bytes);
        assert_eq!(
            duplicate.capture_workspace_bytes,
            single.capture_workspace_bytes,
        );
        assert_eq!(duplicate.capture_work, single.capture_work);
        assert_eq!(duplicate.capture_events, single.capture_events);
        assert_eq!(duplicate.capture_count, single.capture_count);
        assert!(duplicate.retained_handle_bytes > single.retained_handle_bytes);
    }

    #[test]
    fn capture_handle_accounting_counts_inline_stream_exactly_once() {
        let capture = capture_program(&Ast::Byte(b'a').capture(1));
        let set = capture_set([(
            AotOperationAxesV2::CAPTURE_PARTICIPATION_COUNT,
            AotOperationSetMemberInputV2::CaptureProgramV1(capture.as_slice()),
        )]);
        let structural = AotOperationSetV2View::deserialize_structure(
            set.as_bytes(),
            CaptureProgramV1Limits::default(),
        )
        .expect("accounting fixture structure");
        let payload = structural.member(0).expect("capture member").as_bytes();
        let mut census_scratch = vec![0; structural.capture_validation_scratch_words()];
        let census = CaptureProgramV1Census::from_wire(
            payload,
            CaptureProgramV1Limits::default(),
            &mut census_scratch,
        )
        .expect("accounting fixture census");
        let (prepared, receipt) =
            PreparedAotOperationSetV2::deserialize_with_config(set.as_bytes(), decoded_config(4))
                .expect("prepare accounting fixture");
        let PreparedOperationSetMemberV2::Capture(member) = &prepared.members[0] else {
            panic!("fixture member changed family");
        };
        let allocator_bytes = member.stream.build_report().allocator_bytes;
        let expected_workspace = size_of::<CaptureStream>()
            .checked_add(allocator_bytes)
            .expect("capture workspace fits usize");
        assert_eq!(
            receipt.capture_workspace_bytes,
            u64::try_from(expected_workspace).expect("workspace fits u64"),
        );
        let expected_owner = census
            .usage()
            .program_bytes
            .checked_add(size_of::<CaptureProgram>())
            .expect("capture owner fits usize");
        assert_eq!(
            receipt.capture_owner_bytes,
            u64::try_from(expected_owner).expect("owner fits u64"),
        );
        let fixed = operation_set_v2_fixed_retained_bytes(
            prepared.members.capacity(),
            prepared.roots.capacity(),
            prepared.output_scratch.capacity(),
        )
        .expect("fixed capture handle accounting");
        let expected_handle = fixed
            .checked_add(u64::try_from(expected_owner).expect("owner fits u64"))
            .and_then(|bytes| {
                bytes.checked_add(u64::try_from(allocator_bytes).expect("allocator bytes fit u64"))
            })
            .expect("capture handle accounting fits u64");
        assert_eq!(receipt.retained_handle_bytes, expected_handle);
    }

    #[test]
    fn ffi_validates_config_before_malformed_wire_and_exports_distinct_v2_types() {
        let malformed_wire = [0_u8];
        let mut invalid_config = FreAotRegexOperationSetPrepareConfigV2::new(1);
        invalid_config.reserved[0] = 1;
        let mut handle = FreAotRegexOperationSetExclusiveHandleV2::INVALID;
        // SAFETY: all supplied extents are complete, aligned, live, and
        // disjoint. The config and wire are deliberately recoverably invalid.
        let status = unsafe {
            fre_aot_regex_runtime_prepare_operation_set_exclusive_v2(
                malformed_wire.as_ptr(),
                malformed_wire.len(),
                &raw const invalid_config,
                &raw mut handle,
            )
        };
        assert_eq!(status, STATUS_INVALID_ARGUMENT);
        assert!(handle.is_invalid());

        let _: unsafe extern "C" fn(
            *const u8,
            usize,
            *const FreAotRegexOperationSetPrepareConfigV2,
            *mut FreAotRegexOperationSetExclusiveHandleV2,
        ) -> u32 = fre_aot_regex_runtime_prepare_operation_set_exclusive_v2;
        let _: unsafe extern "C" fn(
            FreAotRegexOperationSetExclusiveHandleV2,
            *const u8,
            usize,
            *mut FreAotRegexOperationSetOutputV2,
            usize,
        ) -> u32 = fre_aot_regex_runtime_execute_operation_set_exclusive_v2;
        let _: unsafe extern "C" fn(FreAotRegexOperationSetExclusiveHandleV2) -> u32 =
            fre_aot_regex_runtime_destroy_operation_set_exclusive_v2;
        assert!(
            C_API_OPERATION_SET_V2_HEADER
                .contains("fre_aot_regex_runtime_prepare_operation_set_exclusive_v2",)
        );
        assert!(
            C_API_OPERATION_SET_V2_HEADER
                .contains("FRE_AOT_REGEX_OPERATION_SET_PREPARE_CONFIG_V2_SIZE 184u",)
        );
    }

    #[test]
    fn fixed_handle_gate_wins_before_plan_and_capture_scratch() {
        let capture = capture_program(&Ast::Byte(b'a').capture(1));
        let set = capture_set([(
            AotOperationAxesV2::CAPTURE_PARTICIPATION_COUNT,
            AotOperationSetMemberInputV2::CaptureProgramV1(capture.as_slice()),
        )]);
        let mut config = FreAotRegexOperationSetPrepareConfigV2::new(4);
        config.max_handle_bytes = 0;
        let config = OperationSetPrepareConfigV2::from_ffi(config).expect("zero handle cap");
        reset_test_counters();
        let error = PreparedAotOperationSetV2::deserialize_with_config(set.as_bytes(), config)
            .expect_err("fixed handle lower bound must refuse");
        assert_eq!(
            error,
            OperationSetV2RuntimeError::Resource("fixed retained handle bytes"),
        );
        TEST_PREPARATION_PLANS.with(|calls| assert_eq!(calls.get(), 0));
        TEST_CAPTURE_CENSUSES.with(|calls| assert_eq!(calls.get(), 0));
        TEST_OUTER_CAPTURE_SCRATCH_DROPPED.with(|dropped| assert!(!dropped.get()));
    }

    #[test]
    fn fallible_capture_owner_refusal_leaves_ffi_handle_unpublished() {
        let capture = capture_program(&Ast::Byte(b'a').capture(1));
        let set = capture_set([(
            AotOperationAxesV2::CAPTURE_PARTICIPATION_COUNT,
            AotOperationSetMemberInputV2::CaptureProgramV1(capture.as_slice()),
        )]);
        let config = FreAotRegexOperationSetPrepareConfigV2::new(4);
        let mut handle = FreAotRegexOperationSetExclusiveHandleV2::INVALID;
        reset_test_counters();
        TEST_REFUSE_CAPTURE_PROGRAM_OWNER.with(|refuse| refuse.set(true));
        // SAFETY: every supplied extent is complete, aligned, live, writable
        // where required, and disjoint for this synchronous preparation call.
        let status = unsafe {
            fre_aot_regex_runtime_prepare_operation_set_exclusive_v2(
                set.as_bytes().as_ptr(),
                set.as_bytes().len(),
                &raw const config,
                &raw mut handle,
            )
        };
        TEST_REFUSE_CAPTURE_PROGRAM_OWNER.with(|refuse| refuse.set(false));
        assert_eq!(status, STATUS_RUNTIME_FAILURE);
        assert!(handle.is_invalid());
        TEST_CAPTURE_CENSUSES.with(|calls| assert_eq!(calls.get(), 1));
        TEST_OWNER_DECODES_AFTER_SCRATCH_DROP.with(|calls| assert_eq!(calls.get(), 1));
    }

    #[test]
    fn partial_root_failure_keeps_output_atomic_and_makes_handle_destroy_only() {
        let capture = capture_program(&Ast::Byte(b'a').capture(1));
        let set = capture_set([
            (
                AotOperationAxesV2::CAPTURE_PARTICIPATION_COUNT,
                AotOperationSetMemberInputV2::CaptureProgramV1(capture.as_slice()),
            ),
            (
                AotOperationAxesV2::CAPTURE_PARTICIPATION_COUNT,
                AotOperationSetMemberInputV2::CaptureProgramV1(capture.as_slice()),
            ),
        ]);
        let (mut prepared, _) =
            PreparedAotOperationSetV2::deserialize_with_config(set.as_bytes(), decoded_config(4))
                .expect("prepare terminality fixture");
        prepared.roots[1].member_index = usize::MAX;
        let owner = try_box_preserve(prepared).expect("fallible test handle owner");
        let handle = FreAotRegexOperationSetExclusiveHandleV2(
            Box::into_raw(owner).cast::<core::ffi::c_void>(),
        );
        let sentinel = FreAotRegexOperationSetOutputV2 {
            kind: u32::MAX,
            status: u32::MAX,
            first: u64::MAX,
            second: u64::MAX,
        };
        let mut outputs = [sentinel; 2];
        TEST_CAPTURE_EXECUTIONS.with(|calls| calls.set(0));

        // SAFETY: the test uniquely owns the live prepared allocation and
        // supplies complete, aligned, live, pairwise-disjoint exact extents.
        let status = unsafe {
            fre_aot_regex_runtime_execute_operation_set_exclusive_v2(
                handle,
                b"aaaa".as_ptr(),
                4,
                outputs.as_mut_ptr(),
                outputs.len(),
            )
        };
        assert_eq!(status, STATUS_RUNTIME_FAILURE);
        assert_eq!(outputs, [sentinel; 2]);
        TEST_CAPTURE_EXECUTIONS.with(|calls| assert_eq!(calls.get(), 1));

        // A terminal retry with otherwise valid geometry is rejected before
        // source/workspace work and cannot leak the prior private root result.
        let status = unsafe {
            fre_aot_regex_runtime_execute_operation_set_exclusive_v2(
                handle,
                b"bbbb".as_ptr(),
                4,
                outputs.as_mut_ptr(),
                outputs.len(),
            )
        };
        assert_eq!(status, STATUS_RUNTIME_FAILURE);
        assert_eq!(outputs, [sentinel; 2]);
        TEST_CAPTURE_EXECUTIONS.with(|calls| assert_eq!(calls.get(), 1));

        // SAFETY: terminal runtime state is still one live exclusively owned
        // allocation and is transferred exactly once to destruction.
        assert_eq!(
            unsafe { fre_aot_regex_runtime_destroy_operation_set_exclusive_v2(handle) },
            STATUS_SUCCESS,
        );
    }
}
