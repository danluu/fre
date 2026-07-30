//! Shared `AArch64` Unix strict-W^X implementation.
//!
//! The core invariants are: the reservation owns its complete address range;
//! only the middle payload is ever writable/executable; a callable is
//! constructed only after audit, byte verification, RX transition, and cache
//! invalidation; and the mapping is held by an `Arc` for the complete duration
//! of every call.

use core::{
    ffi::c_void,
    mem::{self, MaybeUninit},
    ptr::NonNull,
    slice,
};
use std::{io, ptr};

#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};

use fre_jit_aarch64::{
    AuditedNativeImage, AuditedSelectedEndRegisterImageV2, BackendVersion, CpuFeatures,
    NativeAggregateImage, NativeAggregateResult, NativeImage, NativeResult, TargetSpec, audit,
    audit_aggregate, audit_selected_end_register_v2,
};
use fre_kernel_ir::{AggregateOutput, OutputKind, SearchWindow};

use crate::{
    CallError, FailureStage, NativeHostCapabilities, PublishError, RuntimeIdentity, WxMode,
    limits::PublicationPlan,
    operation::{RawAggregateCallResult, RawCallResult},
};

use super::{FailureInjection, Mapping, host};

type EntryFunction = unsafe extern "C" fn(*const u8, usize, usize, usize, *mut NativeResult) -> u64;
type SelectedEndRegisterEntryFunctionV2 =
    unsafe extern "C" fn(*const u8, usize, usize, usize) -> usize;
type AggregateEntryFunction =
    unsafe extern "C" fn(*const u8, usize, *mut NativeAggregateResult) -> u64;

#[cfg(any(test, feature = "sve-hardware-qualification"))]
macro_rules! define_vector_callee_saved_canary {
    ($symbol:literal) => {
        core::arch::global_asm!(concat!(
            r#"
    .text
    .p2align 2
    .globl "#,
            $symbol,
            "\n",
            $symbol,
            r#":
    sub sp, sp, #80
    stp x19, x30, [sp, #0]
    stp d8, d9, [sp, #16]
    stp d10, d11, [sp, #32]
    stp d12, d13, [sp, #48]
    stp d14, d15, [sp, #64]
    mov x16, x0
    mov x19, x6
    ldp d8, d9, [x19, #0]
    ldp d10, d11, [x19, #16]
    ldp d12, d13, [x19, #32]
    ldp d14, d15, [x19, #48]
    mov x0, x1
    mov x1, x2
    mov x2, x3
    mov x3, x4
    mov x4, x5
    blr x16
    stp d8, d9, [x19, #64]
    stp d10, d11, [x19, #80]
    stp d12, d13, [x19, #96]
    stp d14, d15, [x19, #112]
    ldp d8, d9, [sp, #16]
    ldp d10, d11, [sp, #32]
    ldp d12, d13, [sp, #48]
    ldp d14, d15, [sp, #64]
    ldp x19, x30, [sp, #0]
    add sp, sp, #80
    ret
"#
        ));
    };
}

#[cfg(any(test, feature = "sve-hardware-qualification"))]
macro_rules! define_selected_end_register_v2_vector_callee_saved_canary {
    ($symbol:literal) => {
        core::arch::global_asm!(concat!(
            r#"
    .text
    .p2align 2
    .globl "#,
            $symbol,
            "\n",
            $symbol,
            r#":
    sub sp, sp, #80
    stp x19, x30, [sp, #0]
    stp d8, d9, [sp, #16]
    stp d10, d11, [sp, #32]
    stp d12, d13, [sp, #48]
    stp d14, d15, [sp, #64]
    mov x16, x0
    mov x19, x5
    mov x5, xzr
    mov x6, xzr
    mov x7, xzr
    ldp d8, d9, [x19, #0]
    ldp d10, d11, [x19, #16]
    ldp d12, d13, [x19, #32]
    ldp d14, d15, [x19, #48]
    mov x0, x1
    mov x1, x2
    mov x2, x3
    mov x3, x4
    mov x4, xzr
    blr x16
    stp d8, d9, [x19, #64]
    stp d10, d11, [x19, #80]
    stp d12, d13, [x19, #96]
    stp d14, d15, [x19, #112]
    ldp d8, d9, [sp, #16]
    ldp d10, d11, [sp, #32]
    ldp d12, d13, [sp, #48]
    ldp d14, d15, [sp, #64]
    ldp x19, x30, [sp, #0]
    add sp, sp, #80
    ret
"#
        ));
    };
}

#[cfg(all(any(test, feature = "sve-hardware-qualification"), target_os = "macos"))]
define_vector_callee_saved_canary!("_fre_jit_test_vector_callee_saved_canary");

#[cfg(all(any(test, feature = "sve-hardware-qualification"), target_os = "linux"))]
define_vector_callee_saved_canary!("fre_jit_test_vector_callee_saved_canary");

#[cfg(all(any(test, feature = "sve-hardware-qualification"), target_os = "macos"))]
define_selected_end_register_v2_vector_callee_saved_canary!(
    "_fre_jit_test_selected_end_register_v2_vector_callee_saved_canary"
);

#[cfg(all(any(test, feature = "sve-hardware-qualification"), target_os = "linux"))]
define_selected_end_register_v2_vector_callee_saved_canary!(
    "fre_jit_test_selected_end_register_v2_vector_callee_saved_canary"
);

#[cfg(any(test, feature = "sve-hardware-qualification"))]
unsafe extern "C" {
    fn fre_jit_test_vector_callee_saved_canary(
        entry: *const c_void,
        haystack: *const u8,
        haystack_len: usize,
        window_start: usize,
        window_end: usize,
        result: *mut NativeResult,
        canaries: *mut u64,
    ) -> u64;

    fn fre_jit_test_selected_end_register_v2_vector_callee_saved_canary(
        entry: *const c_void,
        haystack: *const u8,
        haystack_len: usize,
        window_start: usize,
        window_end: usize,
        canaries: *mut u64,
    ) -> usize;
}

#[cfg(test)]
static LIVE_CODE_MAPPINGS: AtomicUsize = AtomicUsize::new(0);

#[cfg(any(test, feature = "sve-hardware-qualification"))]
pub(crate) fn invoke_with_vector_callee_saved_canary(
    mapping: &ExecutableMapping,
    haystack: &[u8],
    window: SearchWindow,
    canaries: [u64; 8],
) -> (RawCallResult, [u64; 8]) {
    let mut result = NativeResult {
        start: usize::MAX,
        end: usize::MAX,
    };
    let mut slots = [0_u64; 16];
    slots[..8].copy_from_slice(&canaries);
    // SAFETY: the test wrapper preserves its own AAPCS64 state, forwards the
    // same five audited call arguments as `invoke`, and stores only into the
    // two caller-owned output buffers that remain live for the whole call.
    let status = unsafe {
        fre_jit_test_vector_callee_saved_canary(
            mapping.entry.as_ptr(),
            haystack.as_ptr(),
            haystack.len(),
            window.start(),
            window.end(),
            ptr::addr_of_mut!(result),
            slots.as_mut_ptr(),
        )
    };
    let observed = slots[8..].try_into().expect("eight vector canary slots");
    (
        RawCallResult {
            status,
            slot: result,
        },
        observed,
    )
}

#[cfg(any(test, feature = "sve-hardware-qualification"))]
pub(crate) fn invoke_selected_end_register_v2_with_vector_callee_saved_canary(
    entry: SelectedEndRegisterEntryV2,
    haystack: &[u8],
    window: SearchWindow,
    canaries: [u64; 8],
) -> (usize, [u64; 8]) {
    let mut slots = [0_u64; 16];
    slots[..8].copy_from_slice(&canaries);
    // SAFETY: the session-bound typed entry was decoded only from a P1-audited
    // immutable ABI2 mapping. The wrapper forwards exactly haystack, length,
    // start, and end in x0..x3, clears x4 instead of passing a result slot,
    // returns the generated entry's x0 unchanged, and stores only into the
    // live canary buffer.
    let end_or_zero = unsafe {
        fre_jit_test_selected_end_register_v2_vector_callee_saved_canary(
            entry.0 as *const () as *const c_void,
            haystack.as_ptr(),
            haystack.len(),
            window.start(),
            window.end(),
            slots.as_mut_ptr(),
        )
    };
    let observed = slots[8..].try_into().expect("eight vector canary slots");
    (end_or_zero, observed)
}

#[derive(Debug)]
pub(crate) struct ExecutableMapping {
    reservation: Reservation,
    entry: NonNull<c_void>,
    identity: RuntimeIdentity,
    output: OutputKind,
    aggregate: Option<AggregateMappingContract>,
    selected_end_register_literal_bytes_v2: Option<u32>,
    backend_version: BackendVersion,
    target: TargetSpec,
    sve_vector_bytes_at_publication: Option<u16>,
}

/// Typed search entry retained only while its owning RX mapping stays live.
///
/// `PublishedKernel` stores this value beside the `Arc<ExecutableMapping>`
/// from which it was derived. Keeping the callable separate avoids decoding
/// the same immutable entry address on every search without exposing it
/// outside the runtime crate.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SearchEntry(EntryFunction);

/// Exact register-return ABI2 entry retained only with its owning RX mapping.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SelectedEndRegisterEntryV2(SelectedEndRegisterEntryFunctionV2);

impl SearchEntry {
    #[inline]
    pub(crate) fn invoke<O: crate::RuntimeOperation>(
        self,
        haystack: &[u8],
        window: SearchWindow,
    ) -> RawCallResult {
        let mut slot = MaybeUninit::<NativeResult>::uninit();
        // SAFETY: construction decoded the callable only from a completely
        // audited mapping after its final RX transition. The owning
        // `PublishedKernel` retains that mapping for this complete call. The
        // sealed `O` is the output checked when that kernel was constructed;
        // the result slot has the exact `NativeResult` layout and remains
        // writable.
        let status = unsafe {
            (self.0)(
                haystack.as_ptr(),
                haystack.len(),
                window.start(),
                window.end(),
                slot.as_mut_ptr(),
            )
        };
        let slot = match (status, O::KIND) {
            // SAFETY: every published search image passes the independent
            // whole-template audit. A successful `Span` return is immediately
            // preceded by stores to both result fields.
            (1, OutputKind::Span) => unsafe { slot.assume_init() },
            // SAFETY: the same audit requires a successful `SelectedEnd`
            // return to initialize `end`. `start` deliberately retains the
            // prior diagnostic sentinel without being read from native memory.
            (1, OutputKind::SelectedEnd) => NativeResult {
                start: usize::MAX,
                end: unsafe { ptr::addr_of!((*slot.as_ptr()).end).read() },
            },
            // Exists never consumes the slot. Misses and backend-fault status
            // values are decoded without consuming it for every operation.
            _ => NativeResult {
                start: usize::MAX,
                end: usize::MAX,
            },
        };
        RawCallResult { status, slot }
    }
}

impl SelectedEndRegisterEntryV2 {
    #[inline(always)]
    pub(crate) fn invoke(self, haystack: &[u8], window: SearchWindow) -> usize {
        // SAFETY: construction decoded this exact four-argument callable only
        // from a P1-audited ABI2 mapping after its final RX transition. The
        // borrowing session retains the owning mapping for this complete leaf
        // call, and scalar preflight validated both window bounds first.
        unsafe {
            (self.0)(
                haystack.as_ptr(),
                haystack.len(),
                window.start(),
                window.end(),
            )
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AggregateMappingContract {
    output: AggregateOutput,
    literal_bytes: u32,
}

// SAFETY: after construction the entire payload is immutable RX, guard pages
// stay inaccessible, and the only mutation is OS unmapping in final `Drop`.
unsafe impl Send for ExecutableMapping {}
// SAFETY: native calls only read mapping bytes and write to caller-owned result
// slots. Each call's haystack and result have disjoint Rust borrow lifetimes.
unsafe impl Sync for ExecutableMapping {}

impl Mapping for ExecutableMapping {
    fn identity(&self) -> RuntimeIdentity {
        self.identity
    }

    fn output(&self) -> OutputKind {
        self.output
    }

    fn sve_vector_bytes_at_publication(&self) -> Option<u16> {
        self.sve_vector_bytes_at_publication
    }

    fn call_contract_valid(&self, expected_output: OutputKind) -> bool {
        let expected = TargetSpec::AARCH64_AAPCS64;
        self.reservation.state == MappingState::Executable
            && matches!(
                self.backend_version,
                BackendVersion::SEARCH_V1
                    | BackendVersion::SEARCH_V2
                    | BackendVersion::SEARCH_V3
                    | BackendVersion::SEARCH_V4
                    | BackendVersion::SEARCH_V5
                    | BackendVersion::SEARCH_V6
                    | BackendVersion::SEARCH_V7
                    | BackendVersion::SEARCH_V8
                    | BackendVersion::SEARCH_V9
                    | BackendVersion::SEARCH_SVE16_V1
                    | BackendVersion::SEARCH_SVE2_16_V1
                    | BackendVersion::SEARCH_SVE16_V6
                    | BackendVersion::SEARCH_SVE2_FIXED16_V2
            )
            && self.aggregate.is_none()
            && self.selected_end_register_literal_bytes_v2.is_none()
            && self.output == expected_output
            && self.target.architecture == expected.architecture
            && self.target.little_endian == expected.little_endian
            && self.target.pointer_width == expected.pointer_width
            && self.target.abi == expected.abi
            && crate::search_vector_length_contract_valid(
                self.backend_version,
                self.sve_vector_bytes_at_publication,
            )
            && target_features_available(self.target.features)
    }

    fn selected_end_register_v2_contract_valid(&self, literal_bytes: u32) -> bool {
        let expected = TargetSpec::AARCH64_AAPCS64;
        self.reservation.state == MappingState::Executable
            && matches!(
                self.backend_version,
                BackendVersion::SEARCH_V8
                    | BackendVersion::SEARCH_SVE16_V6
                    | BackendVersion::SEARCH_SVE2_FIXED16_V2
            )
            && self.aggregate.is_none()
            && literal_bytes != 0
            && self.selected_end_register_literal_bytes_v2 == Some(literal_bytes)
            && self.output == OutputKind::SelectedEnd
            && self.sve_vector_bytes_at_publication.is_none()
            && match self.backend_version {
                BackendVersion::SEARCH_V8 => {
                    self.target.features == CpuFeatures::NONE
                        || self.target.features == CpuFeatures::ASIMD
                }
                BackendVersion::SEARCH_SVE16_V6 => self.target.features == CpuFeatures::ASIMD_SVE,
                BackendVersion::SEARCH_SVE2_FIXED16_V2 => {
                    self.target.features == CpuFeatures::ASIMD_SVE2
                }
                _ => false,
            }
            && self.target.architecture == expected.architecture
            && self.target.little_endian == expected.little_endian
            && self.target.pointer_width == expected.pointer_width
            && self.target.abi == expected.abi
            && target_features_available(self.target.features)
    }

    fn aggregate_contract_valid(
        &self,
        expected_output: AggregateOutput,
        literal_bytes: u32,
    ) -> bool {
        let expected = TargetSpec::AARCH64_AAPCS64;
        self.reservation.state == MappingState::Executable
            && matches!(
                self.backend_version,
                BackendVersion::AGGREGATE_V1
                    | BackendVersion::AGGREGATE_HISTORICAL_V2
                    | BackendVersion::AGGREGATE_SVE2_FIXED16_COUNT_EXPERIMENTAL_V1
                    | BackendVersion::AGGREGATE_SVE2_FIXED16_SPAN_SUM_EXPERIMENTAL_V1
                    | BackendVersion::AGGREGATE_SVE2_FIXED16_PAIR_COUNT_EXPERIMENTAL_V1
                    | BackendVersion::AGGREGATE_SVE2_FIXED16_PAIR_SPAN_SUM_EXPERIMENTAL_V1
            )
            && self.selected_end_register_literal_bytes_v2.is_none()
            && self.aggregate
                == Some(AggregateMappingContract {
                    output: expected_output,
                    literal_bytes,
                })
            && self.target.architecture == expected.architecture
            && self.target.little_endian == expected.little_endian
            && self.target.pointer_width == expected.pointer_width
            && self.target.abi == expected.abi
            && target_features_available(self.target.features)
    }

    fn invoke_aggregate(&self, haystack: &[u8]) -> Result<RawAggregateCallResult, CallError> {
        debug_assert_eq!(self.reservation.state, MappingState::Executable);
        let mut slot = NativeAggregateResult { value: u64::MAX };
        // SAFETY: aggregate publication independently audited the distinct
        // three-argument ABI and the RX mapping remains owned for this borrow.
        let function: AggregateEntryFunction = unsafe { mem::transmute(self.entry.as_ptr()) };
        // SAFETY: the readable slice and aligned result slot live across this
        // leaf call; decoded aggregate code cannot call indirectly or unwind.
        let status =
            unsafe { function(haystack.as_ptr(), haystack.len(), ptr::addr_of_mut!(slot)) };
        Ok(RawAggregateCallResult { status, slot })
    }
}

impl ExecutableMapping {
    /// Decode the already-audited search address once for an owning kernel.
    pub(crate) fn search_entry(&self) -> SearchEntry {
        debug_assert_eq!(self.reservation.state, MappingState::Executable);
        debug_assert!(self.selected_end_register_literal_bytes_v2.is_none());
        // SAFETY: `entry` was decoded and independently audited before being
        // copied at the exact image-relative offset. It now names an immutable
        // RX AAPCS64-v1 search function for the complete mapping lifetime.
        SearchEntry(unsafe { mem::transmute::<*mut c_void, EntryFunction>(self.entry.as_ptr()) })
    }

    /// Decode the P1-audited four-argument entry once for an owning ABI2
    /// publication.
    pub(crate) fn selected_end_register_entry_v2(&self) -> SelectedEndRegisterEntryV2 {
        debug_assert_eq!(self.reservation.state, MappingState::Executable);
        debug_assert!(
            self.selected_end_register_literal_bytes_v2
                .is_some_and(|literal_bytes| literal_bytes != 0)
        );
        // SAFETY: the distinct P1 audit authenticated the exact ABI2 entry and
        // prohibited the removed x4 result pointer before these bytes became
        // immutable RX. The owning publication retains this mapping.
        SelectedEndRegisterEntryV2(unsafe {
            mem::transmute::<*mut c_void, SelectedEndRegisterEntryFunctionV2>(self.entry.as_ptr())
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MappingState {
    Reserved,
    Writable,
    Executable,
}

struct Reservation {
    base: NonNull<c_void>,
    total_bytes: usize,
    payload: NonNull<u8>,
    payload_bytes: usize,
    state: MappingState,
}

impl core::fmt::Debug for Reservation {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Reservation")
            .field("total_bytes", &self.total_bytes)
            .field("payload_bytes", &self.payload_bytes)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        // SAFETY: `base..base+total_bytes` is the exact live reservation owned
        // solely by this value. Drop happens only after the final owning Arc
        // and all borrows of that Arc have ended. A rare `munmap` failure can
        // only leave unreachable pages mapped; it cannot expose a callable.
        let _result = unsafe { libc::munmap(self.base.as_ptr(), self.total_bytes) };
        #[cfg(test)]
        LIVE_CODE_MAPPINGS.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(any(test, feature = "sve-hardware-qualification"))]
struct GuardedTestMapping(NonNull<c_void>, usize);

#[cfg(any(test, feature = "sve-hardware-qualification"))]
impl Drop for GuardedTestMapping {
    fn drop(&mut self) {
        // SAFETY: this helper solely owns the exact test reservation.
        let _result = unsafe { libc::munmap(self.0.as_ptr(), self.1) };
    }
}

#[allow(
    clippy::unnecessary_wraps,
    reason = "the uniform platform interface is fallible on unsupported targets"
)]
pub(crate) const fn ensure_host_supported() -> Result<(), PublishError> {
    Ok(())
}

pub(crate) fn page_size() -> Result<usize, PublishError> {
    // SAFETY: `sysconf` has no pointer arguments and `_SC_PAGESIZE` is a valid
    // selector on the admitted Unix targets.
    let result = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if result <= 0 {
        return Err(syscall_error(FailureStage::PageSize));
    }
    usize::try_from(result).map_err(|_| syscall_error(FailureStage::PageSize))
}

pub(crate) fn capabilities() -> Result<NativeHostCapabilities, PublishError> {
    ensure_host_supported()?;
    Ok(NativeHostCapabilities::new(
        has_asimd(),
        has_sve(),
        has_sve2(),
        host::sve_vector_bytes(),
    ))
}

pub(crate) fn current_thread_sve_vector_bytes() -> Result<Option<u16>, PublishError> {
    ensure_host_supported()?;
    Ok(host::sve_vector_bytes())
}

pub(crate) fn has_asimd() -> bool {
    host::has_asimd()
}

pub(crate) fn has_sve() -> bool {
    host::has_sve()
}

pub(crate) fn has_sve2() -> bool {
    host::has_sve2()
}

fn target_features_available(features: CpuFeatures) -> bool {
    let known = CpuFeatures::ASIMD_SVE2;
    features.bits() & !known.bits() == 0
        && (!features.contains(CpuFeatures::ASIMD) || has_asimd())
        && (!features.contains(CpuFeatures::SVE) || has_sve())
        && (!features.contains(CpuFeatures::SVE2) || has_sve2())
}

#[derive(Clone, Copy)]
enum PublicationSource<'a> {
    Search(&'a NativeImage),
    EmitterAttested(&'a AuditedNativeImage),
    SelectedEndRegisterV2(&'a AuditedSelectedEndRegisterImageV2),
    Aggregate(&'a NativeAggregateImage),
}

impl<'a> PublicationSource<'a> {
    fn code(self) -> &'a [u8] {
        match self {
            Self::Search(image) => image.code(),
            Self::EmitterAttested(image) => image.as_image().code(),
            Self::SelectedEndRegisterV2(image) => image.code(),
            Self::Aggregate(image) => image.code(),
        }
    }

    fn rodata(self) -> &'a [u8] {
        match self {
            Self::Search(image) => image.rodata(),
            Self::EmitterAttested(image) => image.as_image().rodata(),
            Self::SelectedEndRegisterV2(image) => image.rodata(),
            Self::Aggregate(image) => image.rodata(),
        }
    }

    const fn backend_version(self) -> BackendVersion {
        match self {
            Self::Search(image) => image.backend_version(),
            Self::EmitterAttested(image) => image.as_image().backend_version(),
            Self::SelectedEndRegisterV2(image) => image.backend_version(),
            Self::Aggregate(image) => image.backend_version(),
        }
    }

    const fn target(self) -> TargetSpec {
        match self {
            Self::Search(image) => image.target(),
            Self::EmitterAttested(image) => image.as_image().target(),
            Self::SelectedEndRegisterV2(image) => image.target(),
            Self::Aggregate(image) => image.target(),
        }
    }

    const fn contract(self) -> (OutputKind, Option<AggregateMappingContract>, Option<u32>) {
        match self {
            Self::Search(image) => (image.output(), None, None),
            Self::EmitterAttested(image) => (image.as_image().output(), None, None),
            Self::SelectedEndRegisterV2(image) => {
                (image.output(), None, Some(image.literal_bytes()))
            }
            Self::Aggregate(image) => (
                OutputKind::Span,
                Some(AggregateMappingContract {
                    output: image.output(),
                    literal_bytes: image.literal_bytes(),
                }),
                None,
            ),
        }
    }

    fn reaudit(self) -> Result<(), PublishError> {
        match self {
            Self::Search(image) => audit(image).map(|_| ()).map_err(PublishError::ImageAudit),
            Self::EmitterAttested(_) => Ok(()),
            Self::SelectedEndRegisterV2(image) => audit_selected_end_register_v2(image)
                .map(|_| ())
                .map_err(PublishError::ImageAudit),
            Self::Aggregate(image) => audit_aggregate(image)
                .map(|_| ())
                .map_err(PublishError::ImageAudit),
        }
    }
}

pub(crate) fn publish(
    image: &NativeImage,
    plan: PublicationPlan,
    identity: RuntimeIdentity,
    sve_vector_bytes_at_publication: Option<u16>,
    failure: FailureInjection,
) -> Result<ExecutableMapping, PublishError> {
    publish_source(
        PublicationSource::Search(image),
        plan,
        identity,
        sve_vector_bytes_at_publication,
        failure,
    )
}

pub(crate) fn publish_audited(
    audited: &AuditedNativeImage,
    plan: PublicationPlan,
    identity: RuntimeIdentity,
    sve_vector_bytes_at_publication: Option<u16>,
    failure: FailureInjection,
) -> Result<ExecutableMapping, PublishError> {
    publish_source(
        PublicationSource::EmitterAttested(audited),
        plan,
        identity,
        sve_vector_bytes_at_publication,
        failure,
    )
}

pub(crate) fn publish_selected_end_register_v2(
    image: &AuditedSelectedEndRegisterImageV2,
    plan: PublicationPlan,
    identity: RuntimeIdentity,
    literal_bytes: u32,
    failure: FailureInjection,
) -> Result<ExecutableMapping, PublishError> {
    if literal_bytes == 0 || literal_bytes != image.literal_bytes() {
        return Err(PublishError::PublicationIdentityMismatch);
    }
    publish_source(
        PublicationSource::SelectedEndRegisterV2(image),
        plan,
        identity,
        None,
        failure,
    )
}

pub(crate) fn publish_aggregate(
    image: &NativeAggregateImage,
    plan: PublicationPlan,
    identity: RuntimeIdentity,
    failure: FailureInjection,
) -> Result<ExecutableMapping, PublishError> {
    publish_source(
        PublicationSource::Aggregate(image),
        plan,
        identity,
        None,
        failure,
    )
}

fn publish_source(
    image: PublicationSource<'_>,
    plan: PublicationPlan,
    identity: RuntimeIdentity,
    sve_vector_bytes_at_publication: Option<u16>,
    failure: FailureInjection,
) -> Result<ExecutableMapping, PublishError> {
    inject(failure, FailureStage::Reserve)?;
    let accounting = plan.accounting;
    // SAFETY: all numeric arguments are checked and fd/offset are the required
    // anonymous-map values. The returned range is owned immediately on success.
    let raw = unsafe {
        libc::mmap(
            ptr::null_mut(),
            accounting.total_mapped_bytes,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        )
    };
    if raw == libc::MAP_FAILED {
        return Err(map_syscall_error(FailureStage::Reserve));
    }
    let base = own_mapping(raw, accounting.total_mapped_bytes, FailureStage::Reserve)?;
    // SAFETY: the first guard page lies inside the successful reservation;
    // checked planning guarantees a nonempty page-rounded payload follows it.
    let payload_ptr = unsafe { base.as_ptr().cast::<u8>().add(accounting.page_bytes) };
    let Some(payload) = NonNull::new(payload_ptr) else {
        // SAFETY: ownership has not yet moved into `Reservation`; release the
        // exact successful mapping before reporting the impossible address
        // arithmetic outcome.
        let _result = unsafe { libc::munmap(base.as_ptr(), accounting.total_mapped_bytes) };
        return Err(PublishError::ArithmeticOverflow {
            site: crate::ArithmeticSite::GuardPages,
        });
    };
    let mut reservation = Reservation {
        base,
        total_bytes: accounting.total_mapped_bytes,
        payload,
        payload_bytes: accounting.payload_mapped_bytes,
        state: MappingState::Reserved,
    };
    #[cfg(test)]
    LIVE_CODE_MAPPINGS.fetch_add(1, Ordering::SeqCst);

    inject(failure, FailureStage::MakeWritable)?;
    // SAFETY: payload is exactly the middle page-aligned range and excludes
    // both guards. It is currently PROT_NONE and wholly owned.
    let writable = unsafe {
        libc::mprotect(
            reservation.payload.as_ptr().cast(),
            reservation.payload_bytes,
            libc::PROT_READ | libc::PROT_WRITE,
        )
    };
    if writable != 0 {
        return Err(map_syscall_error(FailureStage::MakeWritable));
    }
    reservation.state = MappingState::Writable;

    inject(failure, FailureStage::Copy)?;
    // SAFETY: the destination is a live RW range of payload_bytes. Planning
    // proves code and rodata (with the required zero gap) fit without overlap.
    unsafe {
        ptr::write_bytes(reservation.payload.as_ptr(), 0, reservation.payload_bytes);
        ptr::copy_nonoverlapping(
            image.code().as_ptr(),
            reservation.payload.as_ptr(),
            image.code().len(),
        );
        ptr::copy_nonoverlapping(
            image.rodata().as_ptr(),
            reservation.payload.as_ptr().add(plan.rodata_offset),
            image.rodata().len(),
        );
    }
    if failure == FailureInjection::CorruptCopy {
        // SAFETY: still in the owned writable state and code is nonempty by audit.
        unsafe { *reservation.payload.as_ptr() ^= 1 };
    }
    inject(failure, FailureStage::Verify)?;
    verify_copy(&reservation, image, plan)?;

    inject(failure, FailureStage::Reaudit)?;
    image.reaudit()?;

    inject(failure, FailureStage::MakeExecutable)?;
    // SAFETY: this removes write access from the complete middle payload and
    // adds execute access. No call pointer exists, so concurrent execution is
    // impossible. RWX is never requested.
    let executable = unsafe {
        libc::mprotect(
            reservation.payload.as_ptr().cast(),
            reservation.payload_bytes,
            libc::PROT_READ | libc::PROT_EXEC,
        )
    };
    if executable != 0 {
        return Err(map_syscall_error(FailureStage::MakeExecutable));
    }
    reservation.state = MappingState::Executable;

    inject(failure, FailureStage::InvalidateInstructionCache)?;
    // SAFETY: the range contains initialized AArch64 instructions in a live RX
    // mapping. The target-specific synchronization primitive accepts this exact
    // process-local byte range and has no fallible return channel.
    unsafe {
        host::synchronize_instruction_cache(
            reservation.payload.as_ptr().cast(),
            accounting.code_bytes,
        );
    }

    inject(failure, FailureStage::Publish)?;
    // SAFETY: entry_offset is within the audited code section and aligned to a
    // decoded instruction. Pointer creation itself does not execute code.
    let entry_ptr = unsafe { reservation.payload.as_ptr().add(plan.entry_offset) };
    let entry = NonNull::new(entry_ptr.cast()).ok_or(PublishError::PublicationIdentityMismatch)?;
    let (output, aggregate, selected_end_register_literal_bytes_v2) = image.contract();
    Ok(ExecutableMapping {
        reservation,
        entry,
        identity,
        output,
        aggregate,
        selected_end_register_literal_bytes_v2,
        backend_version: image.backend_version(),
        target: image.target(),
        sve_vector_bytes_at_publication,
    })
}

fn verify_copy(
    reservation: &Reservation,
    image: PublicationSource<'_>,
    plan: PublicationPlan,
) -> Result<(), PublishError> {
    // SAFETY: publication owns a live initialized payload and remains in the
    // readable writable state for this complete comparison.
    let copied =
        unsafe { slice::from_raw_parts(reservation.payload.as_ptr(), reservation.payload_bytes) };
    let rodata_end = plan.rodata_offset.checked_add(image.rodata().len()).ok_or(
        PublishError::ArithmeticOverflow {
            site: crate::ArithmeticSite::ImageLayout,
        },
    )?;
    if copied.get(..image.code().len()) != Some(image.code())
        || copied.get(plan.rodata_offset..rodata_end) != Some(image.rodata())
        || !copied[image.code().len()..plan.rodata_offset]
            .iter()
            .all(|byte| *byte == 0)
        || !copied[plan.accounting.payload_used_bytes..]
            .iter()
            .all(|byte| *byte == 0)
    {
        return Err(PublishError::CopyVerificationFailed);
    }
    Ok(())
}

fn inject(failure: FailureInjection, stage: FailureStage) -> Result<(), PublishError> {
    if failure == FailureInjection::At(stage) {
        return Err(PublishError::InjectedFailure { stage });
    }
    Ok(())
}

fn syscall_error(stage: FailureStage) -> PublishError {
    let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
    PublishError::SystemCall { stage, errno }
}

fn map_syscall_error(stage: FailureStage) -> PublishError {
    let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
    if matches!(errno, libc::EPERM | libc::EACCES) {
        PublishError::JitDenied {
            stage,
            errno,
            attempted: WxMode::StrictAnonymous,
        }
    } else {
        PublishError::SystemCall { stage, errno }
    }
}

fn own_mapping(
    raw: *mut c_void,
    bytes: usize,
    stage: FailureStage,
) -> Result<NonNull<c_void>, PublishError> {
    if let Some(pointer) = NonNull::new(raw) {
        return Ok(pointer);
    }
    // SAFETY: even address zero denotes a successful mmap result distinct from
    // MAP_FAILED. Ownership has not moved into an RAII value yet, so this path
    // explicitly releases the exact reservation before reporting it unusable.
    let _result = unsafe { libc::munmap(raw, bytes) };
    Err(PublishError::NullMapping { stage })
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MappingProtections {
    pub(crate) left_guard: i32,
    pub(crate) payload: i32,
    pub(crate) right_guard: i32,
}

#[cfg(test)]
impl ExecutableMapping {
    pub(crate) fn protections(&self) -> Result<MappingProtections, PublishError> {
        let guard_bytes = self
            .reservation
            .total_bytes
            .checked_sub(self.reservation.payload_bytes)
            .ok_or(PublishError::PublicationIdentityMismatch)?;
        let page = guard_bytes.checked_div(2).expect("two equal guard pages");
        let base = self.reservation.base.as_ptr().addr();
        let payload = self.reservation.payload.as_ptr().addr();
        let right = payload.checked_add(self.reservation.payload_bytes).ok_or(
            PublishError::ArithmeticOverflow {
                site: crate::ArithmeticSite::GuardPages,
            },
        )?;
        debug_assert_eq!(payload, base.checked_add(page).expect("mapped guard page"));
        Ok(MappingProtections {
            left_guard: query_protection(base)?,
            payload: query_protection(payload)?,
            right_guard: query_protection(right)?,
        })
    }

    pub(crate) fn post_publication_write_is_blocked(&self) -> Result<bool, PublishError> {
        // SAFETY: `fork` duplicates the current process. The child performs
        // only one volatile store followed by async-signal-safe `_exit`; it
        // neither allocates nor touches Rust synchronization after the fork.
        let child = unsafe { libc::fork() };
        if child < 0 {
            return Err(syscall_error(FailureStage::Publish));
        }
        if child == 0 {
            // SAFETY: the address is mapped and readable/executable. The test
            // deliberately attempts a volatile write, which must be rejected
            // by the OS before changing the byte. If it unexpectedly succeeds,
            // `_exit(0)` reports the policy failure without running destructors.
            unsafe {
                ptr::write_volatile(self.reservation.payload.as_ptr(), 0);
                libc::_exit(0);
            }
        }
        let mut status = 0;
        loop {
            // SAFETY: `child` is the positive PID returned above and `status`
            // is live writable storage. No other thread waits for this child.
            let waited = unsafe { libc::waitpid(child, &raw mut status, 0) };
            if waited == child {
                break;
            }
            if waited < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(syscall_error(FailureStage::Publish));
        }
        Ok(libc::WIFSIGNALED(status)
            && matches!(libc::WTERMSIG(status), libc::SIGBUS | libc::SIGSEGV))
    }
}

#[cfg(test)]
pub(crate) fn live_code_mappings() -> usize {
    LIVE_CODE_MAPPINGS.load(Ordering::SeqCst)
}

#[cfg(test)]
fn query_protection(pointer: usize) -> Result<i32, PublishError> {
    host::query_protection(pointer)
}

#[cfg(any(test, feature = "sve-hardware-qualification"))]
pub(crate) fn with_guarded_haystack<T>(
    bytes: &[u8],
    at_right_boundary: bool,
    callback: impl for<'a> FnOnce(&'a [u8]) -> T,
) -> Result<T, PublishError> {
    let page = page_size()?;
    if bytes.len() > page {
        return Err(PublishError::ResourceLimit {
            resource: crate::ResourceKind::PayloadBytes,
            limit: u64::try_from(page).unwrap_or(u64::MAX),
            required: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        });
    }
    let total = page
        .checked_mul(3)
        .ok_or(PublishError::ArithmeticOverflow {
            site: crate::ArithmeticSite::GuardPages,
        })?;
    // SAFETY: valid anonymous reservation arguments; success is owned below.
    let raw = unsafe {
        libc::mmap(
            ptr::null_mut(),
            total,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        )
    };
    if raw == libc::MAP_FAILED {
        return Err(map_syscall_error(FailureStage::Reserve));
    }
    let base = own_mapping(raw, total, FailureStage::Reserve)?;
    let guard = GuardedTestMapping(base, total);
    // SAFETY: the middle page is within the reservation and page aligned.
    let middle = unsafe { base.as_ptr().cast::<u8>().add(page) };
    // SAFETY: changes only the middle page from inaccessible to RW.
    if unsafe { libc::mprotect(middle.cast(), page, libc::PROT_READ | libc::PROT_WRITE) } != 0 {
        return Err(map_syscall_error(FailureStage::MakeWritable));
    }
    let offset = if at_right_boundary {
        page.checked_sub(bytes.len())
            .expect("guarded bytes were bounded by one page")
    } else {
        0
    };
    // SAFETY: bytes fit wholly within the writable middle page.
    unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), middle.add(offset), bytes.len()) };
    // SAFETY: removes write access while retaining readability for the call.
    if unsafe { libc::mprotect(middle.cast(), page, libc::PROT_READ) } != 0 {
        return Err(map_syscall_error(FailureStage::MakeExecutable));
    }
    // SAFETY: initialized bytes occupy this exact readable range and the guard
    // owner remains live across the higher-ranked callback.
    let slice = unsafe { slice::from_raw_parts(middle.add(offset), bytes.len()) };
    let result = callback(slice);
    drop(guard);
    Ok(result)
}
