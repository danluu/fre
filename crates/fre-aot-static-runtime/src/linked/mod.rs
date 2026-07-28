use core::{cell::Cell, mem, ptr};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::OnceLock,
};

use fre_aot_count_contract::{
    ClaimedCountMetadataV2, METADATA_BYTES_V2, STATIC_COUNT_EXPECTATION_BYTES_V2,
    STATIC_COUNT_EXPECTATION_PROJECTION_WORK_UPPER_BOUND_V2, inspect_count_metadata_v2,
};
use fre_kernel_ir::{AggregateExecutionLimits, AggregateOutput, preflight_exact_aggregate};
use sha2::Sha256;

use crate::{
    CallError, StaticAdoptionErrorV2, StaticContractField, StaticVerifyError,
    call::{POISONED_COUNT_RESULT_V2, RawAggregateCallV2, decode_count_v2},
    error::require,
    expected::ExpectedStaticCountV2,
    support::{self, HARD_MAX_STATIC_COUNT_QUALIFICATION_ROWS_V2, QualifiedStaticCountRowV2},
};

pub const HARD_MAX_STATIC_COUNT_OBJECTS_V2: usize = HARD_MAX_STATIC_COUNT_QUALIFICATION_ROWS_V2;

/// Raw Count-v2 result slot fixed by call ABI schema 2.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
#[doc(hidden)]
pub struct RawAggregateResultV2 {
    pub value: u64,
}

pub const STATIC_COUNT_ADOPT_STATUS_OK_V2: u32 = 0;
pub const STATIC_COUNT_ADOPT_STATUS_NO_QUALIFIED_ROW_V2: u32 = 1;
pub const STATIC_COUNT_ADOPT_STATUS_UNQUALIFIED_SELECTOR_V2: u32 = 2;
pub const STATIC_COUNT_ADOPT_STATUS_REFUSED_V2: u32 = 3;

/// Out-parameter written only after complete static Count verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
#[doc(hidden)]
pub struct RawStaticCountAdoptionOutputV2 {
    /// Opaque address returned by the private authenticated registry.
    pub verified: *const core::ffi::c_void,
}

/// Raw Count-v2 entry fixed by call ABI schema 2.
#[allow(
    unsafe_code,
    reason = "generated glue names the audited raw aggregate callable"
)]
#[doc(hidden)]
pub type StaticAggregateEntryV2 =
    unsafe extern "C" fn(*const u8, usize, *mut RawAggregateResultV2) -> u64;

pub(super) type AggregateEntryV2 = StaticAggregateEntryV2;

const _: () = assert!(mem::size_of::<AggregateEntryV2>() == mem::size_of::<usize>());
const _: () = assert!(mem::size_of::<RawAggregateResultV2>() == 8);
const _: () = assert!(mem::align_of::<RawAggregateResultV2>() == 8);

#[cfg(all(
    feature = "linked-count-v2",
    target_arch = "aarch64",
    target_os = "macos",
    target_pointer_width = "64",
    target_endian = "little"
))]
mod macos_aarch64;

#[cfg(all(
    feature = "linked-count-v2",
    target_arch = "aarch64",
    target_os = "macos",
    target_pointer_width = "64",
    target_endian = "little"
))]
use macos_aarch64 as implementation;

#[cfg(not(all(
    feature = "linked-count-v2",
    target_arch = "aarch64",
    target_os = "macos",
    target_pointer_width = "64",
    target_endian = "little"
)))]
mod unavailable;

#[cfg(not(all(
    feature = "linked-count-v2",
    target_arch = "aarch64",
    target_os = "macos",
    target_pointer_width = "64",
    target_endian = "little"
)))]
use unavailable as implementation;

/// Exposed-provenance address retained without creating a reference or call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
#[doc(hidden)]
pub struct StaticLinkedAddressV2(usize);

impl StaticLinkedAddressV2 {
    /// Retain one untrusted link-editor address without reading it.
    #[must_use]
    pub const fn from_exposed_address(address: usize) -> Self {
        Self(address)
    }

    #[must_use]
    pub const fn expose_address(self) -> usize {
        self.0
    }
}

/// Raw addresses selected from one private final-image row.
///
/// No generated entry function pointer exists in this value. Conversion to
/// the callable ABI happens only after VM protection, extent, identity, and
/// payload-hash verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LinkedStaticCountSymbolsV2 {
    claimed_compile_identity: [u8; 32],
    entry_address: StaticLinkedAddressV2,
    payload_address: StaticLinkedAddressV2,
    metadata_address: StaticLinkedAddressV2,
}

impl LinkedStaticCountSymbolsV2 {
    const fn from_qualified_row(
        row: &QualifiedStaticCountRowV2,
        entry_address: StaticLinkedAddressV2,
        payload_address: StaticLinkedAddressV2,
        metadata_address: StaticLinkedAddressV2,
    ) -> Self {
        Self {
            claimed_compile_identity: *row.compile_identity(),
            entry_address,
            payload_address,
            metadata_address,
        }
    }

    #[cfg(test)]
    const fn test_only(
        claimed_compile_identity: [u8; 32],
        entry_address: StaticLinkedAddressV2,
        payload_address: StaticLinkedAddressV2,
        metadata_address: StaticLinkedAddressV2,
    ) -> Self {
        Self {
            claimed_compile_identity,
            entry_address,
            payload_address,
            metadata_address,
        }
    }
}

/// Explicit accounting for one successful mapped-image inspection.
///
/// The retention values report the fixed process-wide static registry
/// reservation and its components. They are measurements only: none of these
/// values qualify a support row, authenticate bytes, or authorize a raw call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StaticRuntimeInspectionAccountingV2 {
    expectation_bytes: usize,
    metadata_bytes: usize,
    payload_bytes: usize,
    vm_regions_checked: usize,
    payload_bytes_hashed: usize,
    work_upper_bound: u64,
    scratch_bytes_upper_bound: u64,
    allocations: u8,
}

impl StaticRuntimeInspectionAccountingV2 {
    #[allow(
        dead_code,
        reason = "successful mapped-image accounting is feature-gated while the production row table remains empty"
    )]
    pub(super) fn checked(
        payload_bytes: usize,
        vm_regions_checked: usize,
    ) -> Result<Self, StaticVerifyError> {
        const COPY_AND_DECODE_PASSES: u64 = 3;
        const HASH_FINALIZE_WORK: u64 = 256;
        const VM_REGION_FIXED_WORK: u64 = 64;

        let fixed_bytes = STATIC_COUNT_EXPECTATION_BYTES_V2
            .checked_add(METADATA_BYTES_V2)
            .ok_or(StaticVerifyError::InspectionAccountingOverflow)?;
        let copied_and_decoded = u64::try_from(fixed_bytes)
            .ok()
            .and_then(|bytes| bytes.checked_mul(COPY_AND_DECODE_PASSES))
            .ok_or(StaticVerifyError::InspectionAccountingOverflow)?;
        let hashed = u64::try_from(payload_bytes)
            .map_err(|_| StaticVerifyError::InspectionAccountingOverflow)?;
        let region_work = u64::try_from(vm_regions_checked)
            .ok()
            .and_then(|regions| regions.checked_mul(VM_REGION_FIXED_WORK))
            .ok_or(StaticVerifyError::InspectionAccountingOverflow)?;
        let work_upper_bound = STATIC_COUNT_EXPECTATION_PROJECTION_WORK_UPPER_BOUND_V2
            .checked_add(copied_and_decoded)
            .and_then(|work| work.checked_add(hashed))
            .and_then(|work| work.checked_add(HASH_FINALIZE_WORK))
            .and_then(|work| work.checked_add(region_work))
            .ok_or(StaticVerifyError::InspectionAccountingOverflow)?;
        let scratch_bytes_upper_bound = mem::size_of::<ExpectedStaticCountV2>()
            .checked_add(mem::size_of::<CopiedExpectationV2>())
            .and_then(|bytes| bytes.checked_add(METADATA_BYTES_V2))
            .and_then(|bytes| bytes.checked_add(mem::size_of::<ClaimedCountMetadataV2>()))
            .and_then(|bytes| bytes.checked_add(mem::size_of::<Sha256>()))
            .and_then(|bytes| bytes.checked_add(32))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(StaticVerifyError::InspectionAccountingOverflow)?;
        Ok(Self {
            expectation_bytes: STATIC_COUNT_EXPECTATION_BYTES_V2,
            metadata_bytes: METADATA_BYTES_V2,
            payload_bytes,
            vm_regions_checked,
            payload_bytes_hashed: payload_bytes,
            work_upper_bound,
            scratch_bytes_upper_bound,
            allocations: 0,
        })
    }

    #[must_use]
    pub const fn expectation_bytes(&self) -> usize {
        self.expectation_bytes
    }

    #[must_use]
    pub const fn metadata_bytes(&self) -> usize {
        self.metadata_bytes
    }

    #[must_use]
    pub const fn payload_bytes(&self) -> usize {
        self.payload_bytes
    }

    #[must_use]
    pub const fn vm_regions_checked(&self) -> usize {
        self.vm_regions_checked
    }

    #[must_use]
    pub const fn payload_bytes_hashed(&self) -> usize {
        self.payload_bytes_hashed
    }

    #[must_use]
    pub const fn work_upper_bound(&self) -> u64 {
        self.work_upper_bound
    }

    #[must_use]
    pub const fn scratch_bytes_upper_bound(&self) -> u64 {
        self.scratch_bytes_upper_bound
    }

    /// Bytes occupied by the verified value retained in a successful result.
    #[must_use]
    pub const fn verified_value_bytes(&self) -> usize {
        VERIFIED_STATIC_COUNT_BYTES_V2
    }

    /// Bytes inside the inner `OnceLock`, including expectation, symbols, and
    /// the sticky success/error result.
    #[must_use]
    pub const fn registered_initialization_bytes(&self) -> usize {
        REGISTERED_INITIALIZATION_BYTES_V2
    }

    /// Compile-identity bytes retained for open-addressed slot selection.
    #[must_use]
    pub const fn registry_identity_bytes(&self) -> usize {
        REGISTRY_IDENTITY_BYTES_V2
    }

    /// Both `OnceLock` state words plus target-layout padding in one slot.
    #[must_use]
    pub const fn registry_once_lock_and_padding_bytes(&self) -> usize {
        REGISTRY_ONCE_LOCK_AND_PADDING_BYTES_V2
    }

    /// Complete bytes reserved by one process-static registry slot.
    #[must_use]
    pub const fn registry_slot_bytes(&self) -> usize {
        REGISTRY_SLOT_BYTES_V2
    }

    /// Fixed number of slots reserved in the process-static registry.
    #[must_use]
    pub const fn static_registry_capacity_entries(&self) -> usize {
        HARD_MAX_STATIC_COUNT_OBJECTS_V2
    }

    /// Complete fixed process-wide registry reservation.
    ///
    /// This value is charged once per process, not once per registered object.
    #[must_use]
    pub const fn static_registry_capacity_bytes(&self) -> usize {
        STATIC_REGISTRY_CAPACITY_BYTES_V2
    }

    /// Alias for the complete fixed process-wide retained reservation.
    ///
    /// This is not a per-row authorization budget.
    #[must_use]
    pub const fn retained_bytes(&self) -> usize {
        STATIC_REGISTRY_CAPACITY_BYTES_V2
    }

    #[must_use]
    pub const fn allocations(&self) -> u8 {
        self.allocations
    }
}

struct RegisteredInitializationV2<T> {
    expectation_bytes: [u8; STATIC_COUNT_EXPECTATION_BYTES_V2],
    symbols: LinkedStaticCountSymbolsV2,
    result: Result<T, StaticVerifyError>,
}

struct IdentitySlotV2<T> {
    identity: [u8; 32],
    initialization: OnceLock<RegisteredInitializationV2<T>>,
}

impl<T> IdentitySlotV2<T> {
    const fn new(identity: [u8; 32]) -> Self {
        Self {
            identity,
            initialization: OnceLock::new(),
        }
    }
}

struct StaticRegistryV2<T, const ENTRIES: usize> {
    entries: [OnceLock<IdentitySlotV2<T>>; ENTRIES],
}

const VERIFIED_STATIC_COUNT_BYTES_V2: usize = mem::size_of::<VerifiedStaticCountV2>();
const REGISTERED_INITIALIZATION_BYTES_V2: usize =
    mem::size_of::<RegisteredInitializationV2<VerifiedStaticCountV2>>();
const REGISTRY_IDENTITY_BYTES_V2: usize = mem::size_of::<[u8; 32]>();
const REGISTRY_SLOT_BYTES_V2: usize =
    mem::size_of::<OnceLock<IdentitySlotV2<VerifiedStaticCountV2>>>();
const STATIC_REGISTRY_CAPACITY_BYTES_V2: usize =
    mem::size_of::<StaticRegistryV2<VerifiedStaticCountV2, HARD_MAX_STATIC_COUNT_OBJECTS_V2>>();
const _: () = assert!(
    REGISTRY_SLOT_BYTES_V2 >= REGISTERED_INITIALIZATION_BYTES_V2 + REGISTRY_IDENTITY_BYTES_V2
);
#[allow(
    clippy::arithmetic_side_effects,
    reason = "the adjacent compile-time assertion proves the exact layout subtraction"
)]
const REGISTRY_ONCE_LOCK_AND_PADDING_BYTES_V2: usize =
    REGISTRY_SLOT_BYTES_V2 - REGISTERED_INITIALIZATION_BYTES_V2 - REGISTRY_IDENTITY_BYTES_V2;
const _: () = assert!(
    STATIC_REGISTRY_CAPACITY_BYTES_V2 == REGISTRY_SLOT_BYTES_V2 * HARD_MAX_STATIC_COUNT_OBJECTS_V2
);

thread_local! {
    static STATIC_REGISTRY_INITIALIZATION_ACTIVE_V2: Cell<bool> =
        const { Cell::new(false) };
}

struct StaticRegistryInitializationGuardV2;

impl StaticRegistryInitializationGuardV2 {
    fn enter() -> Result<Self, StaticVerifyError> {
        let already_active = STATIC_REGISTRY_INITIALIZATION_ACTIVE_V2
            .try_with(|active| active.replace(true))
            .map_err(|_| StaticVerifyError::StaticRegistryThreadLocalUnavailable)?;
        if already_active {
            Err(StaticVerifyError::StaticRegistryReentrantInitialization)
        } else {
            Ok(Self)
        }
    }
}

impl Drop for StaticRegistryInitializationGuardV2 {
    fn drop(&mut self) {
        let _ = STATIC_REGISTRY_INITIALIZATION_ACTIVE_V2.try_with(|active| active.set(false));
    }
}

impl<T, const ENTRIES: usize> StaticRegistryV2<T, ENTRIES> {
    const fn new() -> Self {
        Self {
            entries: [const { OnceLock::new() }; ENTRIES],
        }
    }

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "nonzero capacity plus checked addition bounds both open-addressing modulo operations"
    )]
    fn identity_slot(&self, identity: [u8; 32]) -> Result<&IdentitySlotV2<T>, StaticVerifyError> {
        if ENTRIES == 0 {
            return Err(StaticVerifyError::StaticRegistryFull { limit: 0 });
        }
        let mut prefix = [0_u8; 8];
        prefix.copy_from_slice(&identity[..8]);
        let entry_count =
            u64::try_from(ENTRIES).map_err(|_| StaticVerifyError::StaticRegistryInvariant)?;
        let start = usize::try_from(u64::from_le_bytes(prefix) % entry_count)
            .map_err(|_| StaticVerifyError::StaticRegistryInvariant)?;
        for probe in 0..ENTRIES {
            let index = start
                .checked_add(probe)
                .ok_or(StaticVerifyError::StaticRegistryInvariant)?
                % ENTRIES;
            let cell = &self.entries[index];
            if let Some(slot) = cell.get() {
                if slot.identity == identity {
                    return Ok(slot);
                }
                continue;
            }
            let _ = cell.set(IdentitySlotV2::new(identity));
            let slot = cell
                .get()
                .ok_or(StaticVerifyError::StaticRegistryInvariant)?;
            if slot.identity == identity {
                return Ok(slot);
            }
        }
        Err(StaticVerifyError::StaticRegistryFull { limit: ENTRIES })
    }

    fn adopt(
        &self,
        bytes: &[u8; STATIC_COUNT_EXPECTATION_BYTES_V2],
        symbols: LinkedStaticCountSymbolsV2,
        initialize: impl FnOnce() -> Result<T, StaticVerifyError>,
    ) -> Result<&T, StaticVerifyError> {
        match STATIC_REGISTRY_INITIALIZATION_ACTIVE_V2.try_with(Cell::get) {
            Ok(false) => {}
            Ok(true) => {
                return Err(StaticVerifyError::StaticRegistryReentrantInitialization);
            }
            Err(_) => {
                return Err(StaticVerifyError::StaticRegistryThreadLocalUnavailable);
            }
        }
        let identity = symbols.claimed_compile_identity;
        let slot = self.identity_slot(identity)?;
        let state = slot.initialization.get_or_init(|| {
            let result = match StaticRegistryInitializationGuardV2::enter() {
                Ok(_guard) => match catch_unwind(AssertUnwindSafe(initialize)) {
                    Ok(result) => result,
                    Err(_) => Err(StaticVerifyError::StaticRegistryInitializationPanicked),
                },
                Err(error) => Err(error),
            };
            RegisteredInitializationV2 {
                expectation_bytes: *bytes,
                symbols,
                result,
            }
        });
        if state.expectation_bytes != *bytes {
            return Err(StaticVerifyError::AlreadyInitializedForDifferentExpectation);
        }
        if state.symbols != symbols {
            return Err(StaticVerifyError::AlreadyInitializedForDifferentSymbols);
        }
        state.result.as_ref().map_err(Clone::clone)
    }

    fn registered_value(&self, pointer: *const T) -> Option<&T> {
        if pointer.is_null() {
            return None;
        }
        for cell in &self.entries {
            let Some(slot) = cell.get() else {
                continue;
            };
            let Some(initialization) = slot.initialization.get() else {
                continue;
            };
            let Ok(value) = &initialization.result else {
                continue;
            };
            if ptr::eq(ptr::from_ref(value), pointer) {
                return Some(value);
            }
        }
        None
    }
}

type StaticCountRegistryV2 =
    StaticRegistryV2<VerifiedStaticCountV2, HARD_MAX_STATIC_COUNT_OBJECTS_V2>;

static PRODUCTION_STATIC_REGISTRY_V2: StaticCountRegistryV2 = StaticRegistryV2::new();
#[cfg(feature = "c5-qualification-private-v2")]
static QUALIFICATION_STATIC_REGISTRY_V2: StaticCountRegistryV2 = StaticRegistryV2::new();

pub(super) struct CopiedExpectationV2 {
    pub(super) bytes: [u8; STATIC_COUNT_EXPECTATION_BYTES_V2],
    pub(super) vm_regions_checked: usize,
}

/// Process-lifetime proof of one qualified linked Count-v2 tuple.
#[derive(Debug)]
pub struct VerifiedStaticCountV2 {
    expected: ExpectedStaticCountV2,
    entry: AggregateEntryV2,
    row_selector: u16,
    accounting: StaticRuntimeInspectionAccountingV2,
}

/// Invoke one linked generated-glue entry and retrieve its verified handle.
///
/// The callback is invoked exactly once with a writable initialized output
/// slot. A successful status is accepted only when the returned pointer is the
/// exact address of a successful value already owned by the private
/// process-static registry. A forged, stale, foreign, null, or merely
/// well-typed pointer therefore cannot become a Rust reference.
///
/// This adapter does not qualify an object. The raw adopter selects a literal
/// authorized runtime row before reading any final-image address. Ordinary
/// production builds cannot select an unpromoted candidate row.
pub fn adopt_linked_static_count_v2(
    invoke_glue: impl FnOnce(*mut RawStaticCountAdoptionOutputV2) -> u32,
) -> Result<&'static VerifiedStaticCountV2, StaticAdoptionErrorV2> {
    invoke_and_resolve_adoption(&PRODUCTION_STATIC_REGISTRY_V2, invoke_glue)
}

fn invoke_and_resolve_adoption(
    registry: &'static StaticCountRegistryV2,
    invoke_glue: impl FnOnce(*mut RawStaticCountAdoptionOutputV2) -> u32,
) -> Result<&'static VerifiedStaticCountV2, StaticAdoptionErrorV2> {
    let mut output = RawStaticCountAdoptionOutputV2 {
        verified: ptr::null(),
    };
    let status = invoke_glue(ptr::addr_of_mut!(output));
    resolve_adoption_output(registry, status, output.verified.cast())
}

/// Invoke one private qualification-only glue entry.
///
/// Unlike [`adopt_linked_static_count_v2`], this adapter resolves only handles
/// owned by the isolated qualification registry. Enabling the Cargo feature
/// does not add rows to the production registry or change the safe adapter.
///
/// # Safety
///
/// `invoke_glue` must invoke exactly the retained qualification glue whose
/// unresolved adopter symbol is
/// `fre_aot_static_count_adopt_qualification_raw_v2`. Its linked expectation,
/// implementation, payload, and metadata must remain immutable and live for
/// the process lifetime.
#[cfg(feature = "c5-qualification-private-v2")]
#[doc(hidden)]
#[allow(
    unsafe_code,
    reason = "this explicitly unsafe adapter is the only Rust entry to the private qualification registry"
)]
pub unsafe fn adopt_linked_static_count_qualification_v2(
    invoke_glue: impl FnOnce(*mut RawStaticCountAdoptionOutputV2) -> u32,
) -> Result<&'static VerifiedStaticCountV2, StaticAdoptionErrorV2> {
    invoke_and_resolve_adoption(&QUALIFICATION_STATIC_REGISTRY_V2, invoke_glue)
}

impl VerifiedStaticCountV2 {
    /// Invoke the verified whole-haystack non-overlapping match counter.
    #[inline]
    pub fn count(
        &self,
        haystack: &[u8],
        limits: AggregateExecutionLimits,
    ) -> Result<u64, CallError> {
        checked_count_v2(self.expected.live_literal_bytes(), haystack, limits, || {
            implementation::invoke_count(self.entry, haystack)
        })
    }

    #[must_use]
    pub const fn compile_identity(&self) -> &[u8; 32] {
        self.expected.compile_identity()
    }

    #[must_use]
    pub const fn row_selector(&self) -> u16 {
        self.row_selector
    }

    #[must_use]
    pub const fn object_identity(&self) -> &[u8; 32] {
        self.expected.object_identity()
    }

    #[must_use]
    pub const fn expectation_identity(&self) -> &[u8; 32] {
        self.expected.expectation_identity()
    }

    #[must_use]
    pub const fn receipt_identity(&self) -> &[u8; 32] {
        self.expected.receipt_identity()
    }

    #[must_use]
    pub const fn resource_receipt_identity(&self) -> &[u8; 32] {
        self.expected.resource_receipt_identity()
    }

    #[must_use]
    pub const fn literal_bytes(&self) -> u32 {
        self.expected.live_literal_bytes()
    }

    #[must_use]
    pub const fn inspection_accounting(&self) -> StaticRuntimeInspectionAccountingV2 {
        self.accounting
    }
}

fn resolve_adoption_output<T, const ENTRIES: usize>(
    registry: &StaticRegistryV2<T, ENTRIES>,
    status: u32,
    pointer: *const T,
) -> Result<&T, StaticAdoptionErrorV2> {
    match status {
        STATIC_COUNT_ADOPT_STATUS_NO_QUALIFIED_ROW_V2 => {
            Err(StaticAdoptionErrorV2::NoQualifiedStaticCountRow)
        }
        STATIC_COUNT_ADOPT_STATUS_UNQUALIFIED_SELECTOR_V2 => {
            Err(StaticAdoptionErrorV2::UnqualifiedStaticCountSelector)
        }
        STATIC_COUNT_ADOPT_STATUS_REFUSED_V2 => Err(StaticAdoptionErrorV2::VerificationRefused),
        STATIC_COUNT_ADOPT_STATUS_OK_V2 if pointer.is_null() => {
            Err(StaticAdoptionErrorV2::MissingVerifiedHandle)
        }
        STATIC_COUNT_ADOPT_STATUS_OK_V2 => registry
            .registered_value(pointer)
            .ok_or(StaticAdoptionErrorV2::UnregisteredVerifiedHandle),
        status => Err(StaticAdoptionErrorV2::UnknownStatus { status }),
    }
}

#[inline]
fn checked_count_v2(
    live_literal_bytes: u32,
    haystack: &[u8],
    limits: AggregateExecutionLimits,
    invoke: impl FnOnce() -> RawAggregateCallV2,
) -> Result<u64, CallError> {
    let literal_len =
        usize::try_from(live_literal_bytes).map_err(|_| CallError::InvalidNativeCount {
            value: u64::MAX,
            haystack_len: haystack.len(),
            literal_len: usize::MAX,
        })?;
    let upper =
        preflight_exact_aggregate(haystack.len(), literal_len, AggregateOutput::Count, limits)?;
    decode_count_v2(invoke(), upper.count, haystack.len(), literal_len)
}

/// Hardware-matrix-only exercise of the isolated raw ABI call boundary.
///
/// # Safety
///
/// `entry` must obey the complete [`StaticAggregateEntryV2`] contract.
#[cfg(feature = "linked-hardware-matrix-v2")]
#[doc(hidden)]
#[allow(
    unsafe_code,
    reason = "the explicit hardware matrix supplies an audited raw entry"
)]
pub unsafe fn invoke_raw_count_hardware_matrix_v2(
    entry: StaticAggregateEntryV2,
    live_literal_bytes: u32,
    haystack: &[u8],
    limits: AggregateExecutionLimits,
) -> Result<u64, CallError> {
    checked_count_v2(live_literal_bytes, haystack, limits, || {
        implementation::invoke_count(entry, haystack)
    })
}

/// Row-selector-first raw final-image adoption boundary.
///
/// The literal runtime table is indexed before `output` or any linked
/// address is inspected. An authorized selector proceeds to immutable VM-range,
/// expectation, metadata, entry-offset, payload-hash, and identity checks.
///
/// # Safety
///
/// If `row_selector` selects an authorized row, `output` must be writable
/// for one [`RawStaticCountAdoptionOutputV2`], and every input address must name
/// the exact process-lifetime final-image symbol selected by that row, without
/// interposition, unload, remap, or mutation.
#[doc(hidden)]
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    reason = "this audited C boundary receives unresolved raw final-image addresses and writes output only after verification"
)]
pub unsafe extern "C" fn fre_aot_static_count_adopt_raw_v2(
    output: *mut RawStaticCountAdoptionOutputV2,
    row_selector: u32,
    expectation: *const u8,
    entry: *const u8,
    payload: *const u8,
    metadata: *const u8,
) -> u32 {
    let row = match support::require_runtime_row(row_selector) {
        Ok(row) => row,
        Err(StaticVerifyError::NoQualifiedStaticCountRowV2) => {
            return STATIC_COUNT_ADOPT_STATUS_NO_QUALIFIED_ROW_V2;
        }
        Err(StaticVerifyError::UnqualifiedStaticCountSelectorV2) => {
            return STATIC_COUNT_ADOPT_STATUS_UNQUALIFIED_SELECTOR_V2;
        }
        Err(_) => return STATIC_COUNT_ADOPT_STATUS_REFUSED_V2,
    };
    // SAFETY: the production row was selected before any pointer use, and the
    // caller supplies the complete raw-boundary contract documented above.
    unsafe {
        adopt_selected_static_count_v2(
            &PRODUCTION_STATIC_REGISTRY_V2,
            output,
            expectation,
            entry,
            payload,
            metadata,
            row,
        )
    }
}

/// Private qualification-only raw final-image adoption boundary.
///
/// This symbol has a distinct name, row table, and registry from the
/// production boundary. Merely enabling its Cargo feature cannot change
/// [`fre_aot_static_count_adopt_raw_v2`] or
/// [`adopt_linked_static_count_v2`].
///
/// # Safety
///
/// If `row_selector` selects the retained candidate row, `output` must be
/// writable for one [`RawStaticCountAdoptionOutputV2`], and every input address
/// must name the exact process-lifetime qualification image selected by that
/// row, without interposition, unload, remap, or mutation.
#[cfg(feature = "c5-qualification-private-v2")]
#[doc(hidden)]
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    reason = "this separately named audited C boundary is reachable only from explicit qualification glue"
)]
pub unsafe extern "C" fn fre_aot_static_count_adopt_qualification_raw_v2(
    output: *mut RawStaticCountAdoptionOutputV2,
    row_selector: u32,
    expectation: *const u8,
    entry: *const u8,
    payload: *const u8,
    metadata: *const u8,
) -> u32 {
    let row = match support::require_candidate_row(row_selector) {
        Ok(row) => row,
        Err(StaticVerifyError::UnqualifiedStaticCountSelectorV2) => {
            return STATIC_COUNT_ADOPT_STATUS_UNQUALIFIED_SELECTOR_V2;
        }
        Err(_) => return STATIC_COUNT_ADOPT_STATUS_REFUSED_V2,
    };
    // SAFETY: the candidate row was selected before any pointer use, and the
    // caller supplies the complete qualification contract documented above.
    unsafe {
        adopt_selected_static_count_v2(
            &QUALIFICATION_STATIC_REGISTRY_V2,
            output,
            expectation,
            entry,
            payload,
            metadata,
            row,
        )
    }
}

#[allow(
    unsafe_code,
    reason = "the selected raw boundary owns all unresolved final-image pointer inspection"
)]
unsafe fn adopt_selected_static_count_v2(
    registry: &'static StaticCountRegistryV2,
    output: *mut RawStaticCountAdoptionOutputV2,
    expectation: *const u8,
    entry: *const u8,
    payload: *const u8,
    metadata: *const u8,
    row: &'static QualifiedStaticCountRowV2,
) -> u32 {
    if output.is_null() {
        return STATIC_COUNT_ADOPT_STATUS_REFUSED_V2;
    }
    let symbols = LinkedStaticCountSymbolsV2::from_qualified_row(
        row,
        StaticLinkedAddressV2::from_exposed_address(entry.expose_provenance()),
        StaticLinkedAddressV2::from_exposed_address(payload.expose_provenance()),
        StaticLinkedAddressV2::from_exposed_address(metadata.expose_provenance()),
    );
    // SAFETY: the selector was resolved before any pointer use. The caller's
    // contract supplies exact process-lifetime final-image allocations.
    let Ok(verified) = (unsafe {
        adopt_qualified_static_count_v2(
            registry,
            expectation.cast::<[u8; STATIC_COUNT_EXPECTATION_BYTES_V2]>(),
            symbols,
            row,
        )
    }) else {
        return STATIC_COUNT_ADOPT_STATUS_REFUSED_V2;
    };
    // SAFETY: the caller's contract supplies one writable output slot, and it
    // is touched only after complete row-selected verification.
    unsafe {
        output.write(RawStaticCountAdoptionOutputV2 {
            verified: ptr::from_ref(verified).cast(),
        });
    }
    STATIC_COUNT_ADOPT_STATUS_OK_V2
}

#[allow(
    unsafe_code,
    reason = "all raw reads are delegated to the platform verifier"
)]
unsafe fn adopt_qualified_static_count_v2(
    registry: &'static StaticCountRegistryV2,
    expectation: *const [u8; STATIC_COUNT_EXPECTATION_BYTES_V2],
    symbols: LinkedStaticCountSymbolsV2,
    row: &QualifiedStaticCountRowV2,
) -> Result<&'static VerifiedStaticCountV2, StaticVerifyError> {
    // SAFETY: the runtime boundary established the caller obligations; test
    // injection calls only byte-level helpers and never this function.
    let copied = unsafe { implementation::copy_expectation(expectation)? };
    let expected = ExpectedStaticCountV2::from_qualified_bytes(
        &copied.bytes,
        row,
        &symbols.claimed_compile_identity,
    )?;
    registry.adopt(&copied.bytes, symbols, || {
        let (entry, accounting) =
            implementation::verify(&expected, symbols, copied.vm_regions_checked)?;
        Ok(VerifiedStaticCountV2 {
            expected,
            entry,
            row_selector: row.selector(),
            accounting,
        })
    })
}

#[allow(
    dead_code,
    reason = "mapped metadata verification is feature-gated while its mutation test is always available"
)]
pub(super) fn validate_mapped_metadata(
    bytes: &[u8; METADATA_BYTES_V2],
    expected: ClaimedCountMetadataV2,
) -> Result<ClaimedCountMetadataV2, StaticVerifyError> {
    let actual = inspect_count_metadata_v2(bytes)?;
    require(actual == expected, StaticContractField::Metadata)?;
    Ok(actual)
}

#[allow(
    dead_code,
    unsafe_code,
    reason = "the feature-gated caller possesses either the verifier proof or the explicit hardware-matrix contract"
)]
#[inline]
pub(super) fn raw_call(
    entry: AggregateEntryV2,
    haystack: &[u8],
    haystack_pointer: *const u8,
) -> RawAggregateCallV2 {
    let mut result = RawAggregateResultV2 {
        value: POISONED_COUNT_RESULT_V2,
    };
    // SAFETY: this helper is reachable only through the platform module after
    // verification, or the explicitly unsafe hardware matrix.
    let status = unsafe { entry(haystack_pointer, haystack.len(), ptr::addr_of_mut!(result)) };
    RawAggregateCallV2 {
        status,
        value: result.value,
    }
}

#[cfg(test)]
mod tests {
    use core::ptr;
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
            mpsc,
        },
        thread,
        time::Duration,
    };

    use super::*;
    use crate::test_fixture::static_fixture_v2;

    #[allow(
        unsafe_code,
        reason = "the inert fixture supplies an ABI-compatible symbol"
    )]
    unsafe extern "C" fn dummy_entry(
        _haystack: *const u8,
        _haystack_len: usize,
        _result: *mut RawAggregateResultV2,
    ) -> u64 {
        panic!("inert registry and empty-table tests must not call the entry")
    }

    static TEST_PAYLOAD_A: [u8; 1] = [0];
    static TEST_PAYLOAD_B: [u8; 1] = [0];
    static TEST_PAYLOAD_WIDE: [u8; 2] = [0; 2];
    static TEST_METADATA_A: [u8; METADATA_BYTES_V2] = [0; METADATA_BYTES_V2];
    static TEST_METADATA_B: [u8; METADATA_BYTES_V2] = [0; METADATA_BYTES_V2];

    #[allow(
        clippy::as_conversions,
        reason = "the inert registry fixture records, but never calls, one ABI-compatible function address"
    )]
    fn symbols(identity_byte: u8, tuple: u8) -> LinkedStaticCountSymbolsV2 {
        let entry = StaticLinkedAddressV2::from_exposed_address(
            (dummy_entry as *const ()).expose_provenance(),
        );
        match tuple {
            1 => LinkedStaticCountSymbolsV2::test_only(
                [identity_byte; 32],
                entry,
                StaticLinkedAddressV2::from_exposed_address(
                    ptr::addr_of!(TEST_PAYLOAD_A)
                        .cast::<u8>()
                        .expose_provenance(),
                ),
                StaticLinkedAddressV2::from_exposed_address(
                    ptr::addr_of!(TEST_METADATA_A)
                        .cast::<u8>()
                        .expose_provenance(),
                ),
            ),
            2 => LinkedStaticCountSymbolsV2::test_only(
                [identity_byte; 32],
                entry,
                StaticLinkedAddressV2::from_exposed_address(
                    ptr::addr_of!(TEST_PAYLOAD_B)
                        .cast::<u8>()
                        .expose_provenance(),
                ),
                StaticLinkedAddressV2::from_exposed_address(
                    ptr::addr_of!(TEST_METADATA_B)
                        .cast::<u8>()
                        .expose_provenance(),
                ),
            ),
            3 => LinkedStaticCountSymbolsV2::test_only(
                [identity_byte; 32],
                entry,
                StaticLinkedAddressV2::from_exposed_address(
                    ptr::addr_of!(TEST_PAYLOAD_WIDE)
                        .cast::<u8>()
                        .expose_provenance(),
                ),
                StaticLinkedAddressV2::from_exposed_address(
                    ptr::addr_of!(TEST_METADATA_A)
                        .cast::<u8>()
                        .expose_provenance(),
                ),
            ),
            _ => panic!("unknown test symbol tuple"),
        }
    }

    const fn expectation(distinguishing_byte: u8) -> [u8; STATIC_COUNT_EXPECTATION_BYTES_V2] {
        let mut bytes = [0_u8; STATIC_COUNT_EXPECTATION_BYTES_V2];
        bytes[0] = distinguishing_byte;
        bytes
    }

    #[test]
    #[allow(
        unsafe_code,
        reason = "the test proves the unsafe boundary refuses before reading intentionally invalid pointers"
    )]
    fn unavailable_selector_refuses_invalid_raw_pointers_before_dereference() {
        let conversions_before = implementation::verified_entry_conversion_count();
        let expected_status = if support::require_runtime_row(11).is_ok() {
            STATIC_COUNT_ADOPT_STATUS_UNQUALIFIED_SELECTOR_V2
        } else {
            STATIC_COUNT_ADOPT_STATUS_NO_QUALIFIED_ROW_V2
        };
        // SAFETY: selector lookup returns before inspecting any raw pointer.
        // Intentionally invalid pointers make the ordering executable.
        let status = unsafe {
            fre_aot_static_count_adopt_raw_v2(
                ptr::without_provenance_mut::<RawStaticCountAdoptionOutputV2>(1),
                0,
                ptr::without_provenance::<u8>(3),
                ptr::without_provenance::<u8>(5),
                ptr::without_provenance::<u8>(7),
                ptr::without_provenance::<u8>(9),
            )
        };
        assert_eq!(status, expected_status);
        assert_eq!(
            implementation::verified_entry_conversion_count(),
            conversions_before
        );
    }

    #[cfg(feature = "c5-qualification-private-v2")]
    #[test]
    #[allow(
        unsafe_code,
        reason = "the test proves all-features production adoption rejects an unavailable selector before reading intentionally invalid pointers"
    )]
    fn private_feature_cannot_change_the_production_selector_set() {
        let conversions_before = implementation::verified_entry_conversion_count();
        let expected = if support::require_runtime_row(11).is_ok() {
            StaticAdoptionErrorV2::UnqualifiedStaticCountSelector
        } else {
            StaticAdoptionErrorV2::NoQualifiedStaticCountRow
        };
        let result = adopt_linked_static_count_v2(|output| {
            // SAFETY: selector zero is never present in either production
            // table state, so lookup returns before inspecting the
            // intentionally invalid final-image pointers.
            unsafe {
                fre_aot_static_count_adopt_raw_v2(
                    output,
                    0,
                    ptr::without_provenance::<u8>(3),
                    ptr::without_provenance::<u8>(5),
                    ptr::without_provenance::<u8>(7),
                    ptr::without_provenance::<u8>(9),
                )
            }
        });
        assert!(matches!(result, Err(error) if error == expected));
        assert_eq!(
            implementation::verified_entry_conversion_count(),
            conversions_before
        );
    }

    #[cfg(feature = "c5-qualification-private-v2")]
    #[test]
    fn production_and_qualification_registries_have_distinct_storage() {
        assert!(!ptr::eq(
            &raw const PRODUCTION_STATIC_REGISTRY_V2,
            &raw const QUALIFICATION_STATIC_REGISTRY_V2,
        ));
    }

    #[cfg(feature = "c5-qualification-private-v2")]
    #[test]
    #[allow(
        unsafe_code,
        reason = "the test exercises the separately named qualification boundary only at pre-pointer refusal cases"
    )]
    fn qualification_raw_boundary_has_a_separate_candidate_table() {
        let conversions_before = implementation::verified_entry_conversion_count();
        // SAFETY: the missing selector returns before inspecting any pointer.
        let missing = unsafe {
            fre_aot_static_count_adopt_qualification_raw_v2(
                ptr::without_provenance_mut::<RawStaticCountAdoptionOutputV2>(1),
                0,
                ptr::without_provenance::<u8>(3),
                ptr::without_provenance::<u8>(5),
                ptr::without_provenance::<u8>(7),
                ptr::without_provenance::<u8>(9),
            )
        };
        assert_eq!(missing, STATIC_COUNT_ADOPT_STATUS_UNQUALIFIED_SELECTOR_V2);
        // SAFETY: the null output is refused before any final-image pointer is
        // converted or read, even for the exact candidate selector.
        let exact_but_null = unsafe {
            fre_aot_static_count_adopt_qualification_raw_v2(
                ptr::null_mut(),
                11,
                ptr::without_provenance::<u8>(3),
                ptr::without_provenance::<u8>(5),
                ptr::without_provenance::<u8>(7),
                ptr::without_provenance::<u8>(9),
            )
        };
        assert_eq!(exact_but_null, STATIC_COUNT_ADOPT_STATUS_REFUSED_V2);
        assert_eq!(
            implementation::verified_entry_conversion_count(),
            conversions_before
        );
    }

    #[test]
    fn safe_linked_adapter_preserves_no_row_status_mapping() {
        let status = adopt_linked_static_count_v2(|output| {
            assert!(!output.is_null());
            STATIC_COUNT_ADOPT_STATUS_NO_QUALIFIED_ROW_V2
        });
        assert!(matches!(
            status,
            Err(StaticAdoptionErrorV2::NoQualifiedStaticCountRow)
        ));
    }

    #[test]
    fn typed_adoption_accepts_only_registry_owned_successes() {
        let registry = StaticRegistryV2::<u64, 2>::new();
        let foreign_registry = StaticRegistryV2::<u64, 2>::new();
        let bytes = expectation(1);
        let tuple = symbols(1, 1);
        let registered = registry
            .adopt(&bytes, tuple, || Ok(17))
            .expect("test registration");
        assert_eq!(
            resolve_adoption_output(
                &registry,
                STATIC_COUNT_ADOPT_STATUS_OK_V2,
                ptr::from_ref(registered),
            ),
            Ok(&17)
        );
        assert_eq!(
            resolve_adoption_output(
                &foreign_registry,
                STATIC_COUNT_ADOPT_STATUS_OK_V2,
                ptr::from_ref(registered),
            ),
            Err(StaticAdoptionErrorV2::UnregisteredVerifiedHandle)
        );
        assert_eq!(
            resolve_adoption_output(
                &registry,
                STATIC_COUNT_ADOPT_STATUS_OK_V2,
                ptr::without_provenance(1),
            ),
            Err(StaticAdoptionErrorV2::UnregisteredVerifiedHandle)
        );
        assert_eq!(
            resolve_adoption_output(&registry, STATIC_COUNT_ADOPT_STATUS_OK_V2, ptr::null()),
            Err(StaticAdoptionErrorV2::MissingVerifiedHandle)
        );
    }

    #[test]
    fn typed_adoption_maps_every_status_without_inspecting_output() {
        let registry = StaticRegistryV2::<u64, 0>::new();
        let foreign = ptr::without_provenance(1);
        for (status, expected) in [
            (
                STATIC_COUNT_ADOPT_STATUS_NO_QUALIFIED_ROW_V2,
                StaticAdoptionErrorV2::NoQualifiedStaticCountRow,
            ),
            (
                STATIC_COUNT_ADOPT_STATUS_UNQUALIFIED_SELECTOR_V2,
                StaticAdoptionErrorV2::UnqualifiedStaticCountSelector,
            ),
            (
                STATIC_COUNT_ADOPT_STATUS_REFUSED_V2,
                StaticAdoptionErrorV2::VerificationRefused,
            ),
            (
                u32::MAX,
                StaticAdoptionErrorV2::UnknownStatus { status: u32::MAX },
            ),
        ] {
            assert_eq!(
                resolve_adoption_output(&registry, status, foreign),
                Err(expected)
            );
        }
    }

    #[test]
    fn raw_addresses_and_abis_are_retained_without_a_callable_entry() {
        assert_ne!(symbols(1, 1), symbols(1, 3));
        assert_eq!(mem::size_of::<RawAggregateResultV2>(), 8);
        assert_eq!(mem::align_of::<RawAggregateResultV2>(), 8);
        assert_eq!(mem::size_of::<StaticAggregateEntryV2>(), 8);
        assert_eq!(mem::size_of::<StaticLinkedAddressV2>(), 8);
        assert_eq!(mem::size_of::<RawStaticCountAdoptionOutputV2>(), 8);
        assert_eq!(
            mem::align_of::<RawStaticCountAdoptionOutputV2>(),
            mem::align_of::<*const core::ffi::c_void>()
        );
    }

    #[test]
    fn retention_accounts_for_the_complete_static_registry_once() {
        let accounting =
            StaticRuntimeInspectionAccountingV2::checked(16, 3).expect("bounded accounting");
        assert_eq!(accounting.expectation_bytes(), 672);
        assert_eq!(accounting.metadata_bytes(), 232);
        assert_eq!(accounting.payload_bytes(), 16);
        assert_eq!(accounting.payload_bytes_hashed(), 16);
        assert_eq!(accounting.vm_regions_checked(), 3);
        assert_eq!(accounting.allocations(), 0);
        assert_eq!(
            accounting.registry_slot_bytes(),
            accounting
                .registered_initialization_bytes()
                .checked_add(accounting.registry_identity_bytes())
                .and_then(|bytes| {
                    bytes.checked_add(accounting.registry_once_lock_and_padding_bytes())
                })
                .expect("slot component sum")
        );
        assert_eq!(
            accounting.static_registry_capacity_bytes(),
            accounting
                .registry_slot_bytes()
                .checked_mul(accounting.static_registry_capacity_entries())
                .expect("registry capacity")
        );
        assert_eq!(
            accounting.retained_bytes(),
            accounting.static_registry_capacity_bytes()
        );
        assert!(accounting.registered_initialization_bytes() >= accounting.verified_value_bytes());
        assert!(accounting.registry_once_lock_and_padding_bytes() > 0);
    }

    #[test]
    fn every_metadata_byte_mutation_is_refused_against_expectation() {
        let fixture = static_fixture_v2();
        let original = fixture.metadata;
        let expected = inspect_count_metadata_v2(&original).expect("canonical metadata");
        assert_eq!(validate_mapped_metadata(&original, expected), Ok(expected));
        for index in 0..original.len() {
            let mut mutated = original;
            mutated[index] ^= 1;
            assert!(
                validate_mapped_metadata(&mutated, expected).is_err(),
                "mutated metadata byte {index} was accepted"
            );
        }
    }

    #[test]
    fn every_preflight_limit_refuses_before_native_invocation() {
        let base = AggregateExecutionLimits::unlimited();
        let cases = [
            AggregateExecutionLimits {
                max_haystack_bytes: 3,
                ..base
            },
            AggregateExecutionLimits {
                max_literal_bytes: 0,
                ..base
            },
            AggregateExecutionLimits {
                max_candidate_positions: 3,
                ..base
            },
            AggregateExecutionLimits {
                max_work: 8,
                ..base
            },
            AggregateExecutionLimits {
                max_match_events: 3,
                ..base
            },
            AggregateExecutionLimits {
                max_output: 3,
                ..base
            },
            AggregateExecutionLimits {
                max_reducer_steps: 4,
                ..base
            },
            AggregateExecutionLimits {
                max_native_invocations: 0,
                ..base
            },
        ];
        for limits in cases {
            let invoked = Cell::new(false);
            let result = checked_count_v2(1, b"aaaa", limits, || {
                invoked.set(true);
                RawAggregateCallV2 {
                    status: 0,
                    value: 4,
                }
            });
            assert!(matches!(result, Err(CallError::Preflight(_))));
            assert!(!invoked.get());
        }
    }

    #[test]
    fn registry_idempotence_conflicts_capacity_and_sticky_failure() {
        let registry = StaticRegistryV2::<u64, 2>::new();
        let bytes = expectation(1);
        let tuple = symbols(1, 1);
        let initializations = AtomicUsize::new(0);
        assert_eq!(
            registry
                .adopt(&bytes, tuple, || {
                    initializations.fetch_add(1, Ordering::SeqCst);
                    Ok(41)
                })
                .copied(),
            Ok(41)
        );
        assert_eq!(
            registry
                .adopt(&bytes, tuple, || {
                    initializations.fetch_add(1, Ordering::SeqCst);
                    Ok(99)
                })
                .copied(),
            Ok(41)
        );
        assert_eq!(initializations.load(Ordering::SeqCst), 1);
        assert_eq!(
            registry.adopt(&expectation(2), tuple, || Ok(2)),
            Err(StaticVerifyError::AlreadyInitializedForDifferentExpectation)
        );
        assert_eq!(
            registry.adopt(&bytes, symbols(1, 2), || Ok(3)),
            Err(StaticVerifyError::AlreadyInitializedForDifferentSymbols)
        );

        let sticky = StaticRegistryV2::<u64, 2>::new();
        let error = StaticVerifyError::EntryAddressMismatch;
        assert_eq!(
            sticky.adopt(&bytes, tuple, || Err(error.clone())),
            Err(error.clone())
        );
        assert_eq!(sticky.adopt(&bytes, tuple, || Ok(9)), Err(error));

        let full = StaticRegistryV2::<u64, 1>::new();
        assert_eq!(
            full.adopt(&expectation(1), symbols(1, 1), || Ok(1))
                .copied(),
            Ok(1)
        );
        assert_eq!(
            full.adopt(&expectation(2), symbols(2, 1), || Ok(2)),
            Err(StaticVerifyError::StaticRegistryFull { limit: 1 })
        );
    }

    #[test]
    fn registry_panic_and_reentrancy_are_typed_and_sticky() {
        let panic_registry = StaticRegistryV2::<u64, 2>::new();
        let bytes = expectation(1);
        let tuple = symbols(1, 1);
        assert_eq!(
            panic_registry.adopt(&bytes, tuple, || {
                panic!("deliberate initializer panic");
            }),
            Err(StaticVerifyError::StaticRegistryInitializationPanicked)
        );
        assert_eq!(
            panic_registry.adopt(&bytes, tuple, || Ok(13)),
            Err(StaticVerifyError::StaticRegistryInitializationPanicked)
        );

        let reentrant = StaticRegistryV2::<u64, 2>::new();
        assert_eq!(
            reentrant
                .adopt(&expectation(1), symbols(1, 1), || {
                    assert_eq!(
                        reentrant.adopt(&expectation(2), symbols(2, 2), || Ok(29),),
                        Err(StaticVerifyError::StaticRegistryReentrantInitialization)
                    );
                    Ok(23)
                })
                .copied(),
            Ok(23)
        );
        assert_eq!(
            reentrant
                .adopt(&expectation(2), symbols(2, 2), || Ok(29),)
                .copied(),
            Ok(29)
        );
    }

    #[test]
    fn concurrent_same_identity_initializes_once() {
        let registry = Arc::new(StaticRegistryV2::<u64, 2>::new());
        let initializations = Arc::new(AtomicUsize::new(0));
        let mut workers = Vec::new();
        for _ in 0..4 {
            let registry = Arc::clone(&registry);
            let initializations = Arc::clone(&initializations);
            workers.push(thread::spawn(move || {
                registry
                    .adopt(&expectation(1), symbols(1, 1), || {
                        initializations.fetch_add(1, Ordering::SeqCst);
                        Ok(17)
                    })
                    .copied()
            }));
        }
        for worker in workers {
            assert_eq!(worker.join().expect("registry worker"), Ok(17));
        }
        assert_eq!(initializations.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn different_identities_initialize_without_cross_identity_locking() {
        let registry = Arc::new(StaticRegistryV2::<u64, 4>::new());
        let (started_sender, started_receiver) = mpsc::channel();
        let (first_release_sender, first_release_receiver) = mpsc::channel();
        let (second_release_sender, second_release_receiver) = mpsc::channel();

        let first_registry = Arc::clone(&registry);
        let first_started = started_sender.clone();
        let first = thread::spawn(move || {
            first_registry
                .adopt(&expectation(1), symbols(1, 1), || {
                    first_started.send(1_u8).expect("send first start");
                    first_release_receiver
                        .recv_timeout(Duration::from_secs(10))
                        .expect("release first initializer");
                    Ok(31)
                })
                .copied()
        });
        let second_registry = Arc::clone(&registry);
        let second = thread::spawn(move || {
            second_registry
                .adopt(&expectation(2), symbols(2, 2), || {
                    started_sender.send(2_u8).expect("send second start");
                    second_release_receiver
                        .recv_timeout(Duration::from_secs(10))
                        .expect("release second initializer");
                    Ok(37)
                })
                .copied()
        });
        let mut starts = [
            started_receiver
                .recv_timeout(Duration::from_secs(2))
                .expect("first start"),
            started_receiver
                .recv_timeout(Duration::from_secs(2))
                .expect("second start"),
        ];
        starts.sort_unstable();
        first_release_sender.send(()).expect("release first");
        second_release_sender.send(()).expect("release second");
        assert_eq!(starts, [1, 2]);
        assert_eq!(first.join().expect("first worker"), Ok(31));
        assert_eq!(second.join().expect("second worker"), Ok(37));
    }
}
