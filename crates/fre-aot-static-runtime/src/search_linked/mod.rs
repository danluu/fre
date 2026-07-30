use core::{
    cell::Cell,
    marker::PhantomData,
    mem::{self, MaybeUninit},
    ptr,
};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    rc::Rc,
    sync::OnceLock,
};

use fre_aot_search_contract::{
    ClaimedSearchMetadataV1, SEARCH_BACKEND_SVE2_FIXED16_TAG21_V1, SEARCH_BACKEND_VERSION_V1,
    SEARCH_METADATA_BYTES_V1, STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1, inspect_search_metadata_v1,
};
use fre_jit_aarch64::{EmitLimits, SearchBackendPolicy, TargetSpec, emit_audited_with_backend};
use fre_kernel_ir::{
    AnchorFlags, MatchSpan, SearchWindow, Span, ValidateLimits, build_exact_literal,
};
use fre_kernels::{LiteralAccounting, LiteralSearchLimits, Window, preflight_literal_window};
use sha2::{Digest, Sha256};

use crate::{
    RawSearchCallV1, RawSearchResultV1, StaticSearchSpanAdoptionErrorV1,
    StaticSearchSpanCallErrorV1, StaticSearchSpanContractFieldV1,
    StaticSearchSpanThreadContractErrorV1, StaticSearchSpanVerifyErrorV1, decode_search_call_v1,
    error::require_search_span_v1,
    search_expected::ExpectedStaticSearchSpanV1,
    search_support::{
        self, HARD_MAX_STATIC_SEARCH_SPAN_QUALIFICATION_ROWS_V1,
        SourceQualifiedStaticSearchSpanFamilyV1, SourceQualifiedStaticSearchSpanRowV1,
    },
};

pub const HARD_MAX_STATIC_SEARCH_SPAN_OBJECTS_V1: usize =
    HARD_MAX_STATIC_SEARCH_SPAN_QUALIFICATION_ROWS_V1;

pub const STATIC_SEARCH_SPAN_ADOPT_STATUS_OK_V1: u32 = 0;
pub const STATIC_SEARCH_SPAN_ADOPT_STATUS_NO_QUALIFIED_ROW_V1: u32 = 1;
pub const STATIC_SEARCH_SPAN_ADOPT_STATUS_UNQUALIFIED_SELECTOR_V1: u32 = 2;
pub const STATIC_SEARCH_SPAN_ADOPT_STATUS_REFUSED_V1: u32 = 3;

/// Out-parameter written only after complete static Search-v1 Span
/// verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
#[doc(hidden)]
pub struct RawStaticSearchSpanAdoptionOutputV1 {
    /// Opaque address returned by the private authenticated Search registry.
    pub verified: *const core::ffi::c_void,
}

/// Exact five-argument Search-v1 Span raw entry ABI.
#[allow(
    unsafe_code,
    reason = "generated glue names the audited raw Search-v1 Span callable"
)]
#[doc(hidden)]
pub type StaticSearchSpanEntryV1 =
    unsafe extern "C" fn(*const u8, usize, usize, usize, *mut RawSearchResultV1) -> u64;

pub(super) type SearchSpanEntryV1 = StaticSearchSpanEntryV1;

const _: () = assert!(mem::size_of::<SearchSpanEntryV1>() == mem::size_of::<usize>());
const _: () = assert!(mem::size_of::<RawSearchResultV1>() == mem::size_of::<[usize; 2]>());
const _: () = assert!(mem::align_of::<RawSearchResultV1>() == mem::align_of::<usize>());

#[cfg(all(
    feature = "linked-search-span-v1",
    target_arch = "aarch64",
    target_os = "macos",
    target_pointer_width = "64",
    target_endian = "little"
))]
mod macos_aarch64;

#[cfg(all(
    feature = "linked-search-span-v1",
    target_arch = "aarch64",
    target_os = "macos",
    target_pointer_width = "64",
    target_endian = "little"
))]
use macos_aarch64 as implementation;

#[cfg(all(
    feature = "linked-search-span-v1",
    target_arch = "aarch64",
    target_os = "linux",
    target_pointer_width = "64",
    target_endian = "little"
))]
mod linux_aarch64;

#[cfg(all(
    feature = "linked-search-span-v1",
    target_arch = "aarch64",
    target_os = "linux",
    target_pointer_width = "64",
    target_endian = "little"
))]
use linux_aarch64 as implementation;

#[cfg(not(any(
    all(
        feature = "linked-search-span-v1",
        target_arch = "aarch64",
        target_os = "macos",
        target_pointer_width = "64",
        target_endian = "little"
    ),
    all(
        feature = "linked-search-span-v1",
        target_arch = "aarch64",
        target_os = "linux",
        target_pointer_width = "64",
        target_endian = "little"
    )
)))]
mod unavailable;

#[cfg(not(any(
    all(
        feature = "linked-search-span-v1",
        target_arch = "aarch64",
        target_os = "macos",
        target_pointer_width = "64",
        target_endian = "little"
    ),
    all(
        feature = "linked-search-span-v1",
        target_arch = "aarch64",
        target_os = "linux",
        target_pointer_width = "64",
        target_endian = "little"
    )
)))]
use unavailable as implementation;

/// Exposed-provenance final-image address retained without reading it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
#[doc(hidden)]
pub struct StaticSearchSpanLinkedAddressV1(usize);

impl StaticSearchSpanLinkedAddressV1 {
    /// Retain one untrusted link-editor address without dereferencing it.
    #[must_use]
    pub const fn from_exposed_address(address: usize) -> Self {
        Self(address)
    }

    #[must_use]
    pub const fn expose_address(self) -> usize {
        self.0
    }
}

/// Raw final-image addresses admitted only after source-row selection.
///
/// This value contains no callable function pointer. Its sole conversion to a
/// callable occurs in the platform verifier after all mapped-image checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LinkedStaticSearchSpanSymbolsV1 {
    row_selector: u16,
    claimed_compile_identity: [u8; 32],
    expectation_address: StaticSearchSpanLinkedAddressV1,
    entry_address: StaticSearchSpanLinkedAddressV1,
    payload_address: StaticSearchSpanLinkedAddressV1,
    metadata_address: StaticSearchSpanLinkedAddressV1,
}

impl LinkedStaticSearchSpanSymbolsV1 {
    const fn from_source_qualified_row(
        row: &SourceQualifiedStaticSearchSpanRowV1,
        expectation_address: StaticSearchSpanLinkedAddressV1,
        entry_address: StaticSearchSpanLinkedAddressV1,
        payload_address: StaticSearchSpanLinkedAddressV1,
        metadata_address: StaticSearchSpanLinkedAddressV1,
    ) -> Self {
        Self {
            row_selector: row.selector(),
            claimed_compile_identity: *row.compile_identity(),
            expectation_address,
            entry_address,
            payload_address,
            metadata_address,
        }
    }

    const fn from_source_qualified_family(
        family: &SourceQualifiedStaticSearchSpanFamilyV1,
        expectation_address: StaticSearchSpanLinkedAddressV1,
        entry_address: StaticSearchSpanLinkedAddressV1,
        payload_address: StaticSearchSpanLinkedAddressV1,
        metadata_address: StaticSearchSpanLinkedAddressV1,
    ) -> Self {
        Self {
            row_selector: family.selector(),
            // A broad family cannot pin an artifact-specific compile identity
            // before address inspection. The neutral expectation recomputes
            // that identity and deterministic payload reconstruction binds the
            // concrete mapped image instead.
            claimed_compile_identity: [0; 32],
            expectation_address,
            entry_address,
            payload_address,
            metadata_address,
        }
    }

    #[cfg(test)]
    const fn test_only(
        row_selector: u16,
        claimed_compile_identity: [u8; 32],
        expectation_address: StaticSearchSpanLinkedAddressV1,
        entry_address: StaticSearchSpanLinkedAddressV1,
        payload_address: StaticSearchSpanLinkedAddressV1,
        metadata_address: StaticSearchSpanLinkedAddressV1,
    ) -> Self {
        Self {
            row_selector,
            claimed_compile_identity,
            expectation_address,
            entry_address,
            payload_address,
            metadata_address,
        }
    }
}

/// Explicit accounting for one successful mapped Search-v1 Span inspection.
///
/// These are measurements and fixed retention charges, never qualification
/// evidence or runtime authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StaticSearchSpanInspectionAccountingV1 {
    expectation_bytes: usize,
    metadata_bytes: usize,
    payload_bytes: usize,
    vm_regions_checked: usize,
    payload_bytes_hashed: usize,
    work_upper_bound: u64,
    scratch_bytes_upper_bound: u64,
    allocations: u8,
}

impl StaticSearchSpanInspectionAccountingV1 {
    #[allow(
        dead_code,
        reason = "successful mapped verification remains feature and source-row gated"
    )]
    pub(super) fn checked(
        payload_bytes: usize,
        vm_regions_checked: usize,
    ) -> Result<Self, StaticSearchSpanVerifyErrorV1> {
        // This intentionally overcharges fixed contract projection. It bounds
        // copies, scalar decoding/correlation, and both fixed SHA-256 inputs.
        const FIXED_CONTRACT_WORK_PER_BYTE: u64 = 32;
        const HASH_FINALIZE_WORK: u64 = 256;
        const VM_REGION_FIXED_WORK: u64 = 64;

        let fixed_bytes = STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1
            .checked_add(SEARCH_METADATA_BYTES_V1)
            .ok_or(StaticSearchSpanVerifyErrorV1::InspectionAccountingOverflow)?;
        let fixed_work = u64::try_from(fixed_bytes)
            .ok()
            .and_then(|bytes| bytes.checked_mul(FIXED_CONTRACT_WORK_PER_BYTE))
            .ok_or(StaticSearchSpanVerifyErrorV1::InspectionAccountingOverflow)?;
        let hashed = u64::try_from(payload_bytes)
            .map_err(|_| StaticSearchSpanVerifyErrorV1::InspectionAccountingOverflow)?;
        let region_work = u64::try_from(vm_regions_checked)
            .ok()
            .and_then(|regions| regions.checked_mul(VM_REGION_FIXED_WORK))
            .ok_or(StaticSearchSpanVerifyErrorV1::InspectionAccountingOverflow)?;
        let work_upper_bound = fixed_work
            .checked_add(hashed)
            .and_then(|work| work.checked_add(HASH_FINALIZE_WORK))
            .and_then(|work| work.checked_add(region_work))
            .ok_or(StaticSearchSpanVerifyErrorV1::InspectionAccountingOverflow)?;
        let scratch_bytes_upper_bound = mem::size_of::<ExpectedStaticSearchSpanV1>()
            .checked_add(mem::size_of::<CopiedSearchSpanExpectationV1>())
            .and_then(|bytes| bytes.checked_add(SEARCH_METADATA_BYTES_V1))
            .and_then(|bytes| bytes.checked_add(mem::size_of::<ClaimedSearchMetadataV1>()))
            .and_then(|bytes| bytes.checked_add(mem::size_of::<Sha256>()))
            .and_then(|bytes| bytes.checked_add(32))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(StaticSearchSpanVerifyErrorV1::InspectionAccountingOverflow)?;
        Ok(Self {
            expectation_bytes: STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1,
            metadata_bytes: SEARCH_METADATA_BYTES_V1,
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

    #[must_use]
    pub const fn allocations(&self) -> u8 {
        self.allocations
    }

    #[must_use]
    pub const fn verified_value_bytes(&self) -> usize {
        VERIFIED_STATIC_SEARCH_SPAN_BYTES_V1
    }

    #[must_use]
    pub const fn registered_initialization_bytes(&self) -> usize {
        REGISTERED_SEARCH_SPAN_INITIALIZATION_BYTES_V1
    }

    #[must_use]
    pub const fn registry_identity_bytes(&self) -> usize {
        SEARCH_SPAN_REGISTRY_IDENTITY_BYTES_V1
    }

    #[must_use]
    pub const fn registry_once_lock_and_padding_bytes(&self) -> usize {
        SEARCH_SPAN_REGISTRY_ONCE_LOCK_AND_PADDING_BYTES_V1
    }

    #[must_use]
    pub const fn registry_slot_bytes(&self) -> usize {
        SEARCH_SPAN_REGISTRY_SLOT_BYTES_V1
    }

    #[must_use]
    pub const fn static_registry_capacity_entries(&self) -> usize {
        HARD_MAX_STATIC_SEARCH_SPAN_OBJECTS_V1
    }

    /// Number of disjoint Search registries compiled into this process.
    #[must_use]
    pub const fn static_registry_count(&self) -> usize {
        STATIC_SEARCH_SPAN_REGISTRY_COUNT_V1
    }

    /// Fixed reservation for one production or qualification registry.
    #[must_use]
    pub const fn static_registry_capacity_bytes_per_registry(&self) -> usize {
        STATIC_SEARCH_SPAN_REGISTRY_CAPACITY_BYTES_PER_REGISTRY_V1
    }

    /// Complete fixed process-wide Search registry reservation.
    ///
    /// An all-features qualification binary pays for two disjoint registries;
    /// an ordinary build pays for only the production registry.
    #[must_use]
    pub const fn static_registry_capacity_bytes(&self) -> usize {
        STATIC_SEARCH_SPAN_REGISTRY_CAPACITY_BYTES_V1
    }

    #[must_use]
    pub const fn retained_bytes(&self) -> usize {
        STATIC_SEARCH_SPAN_REGISTRY_CAPACITY_BYTES_V1
    }
}

struct RegisteredSearchSpanInitializationV1<T> {
    expectation_bytes: [u8; STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1],
    symbols: LinkedStaticSearchSpanSymbolsV1,
    result: Result<T, StaticSearchSpanVerifyErrorV1>,
}

struct SearchSpanIdentitySlotV1<T> {
    identity: [u8; 32],
    initialization: OnceLock<RegisteredSearchSpanInitializationV1<T>>,
}

impl<T> SearchSpanIdentitySlotV1<T> {
    const fn new(identity: [u8; 32]) -> Self {
        Self {
            identity,
            initialization: OnceLock::new(),
        }
    }
}

struct StaticSearchSpanRegistryV1<T, const ENTRIES: usize> {
    entries: [OnceLock<SearchSpanIdentitySlotV1<T>>; ENTRIES],
}

const VERIFIED_STATIC_SEARCH_SPAN_BYTES_V1: usize = mem::size_of::<VerifiedStaticSearchSpanV1>();
const REGISTERED_SEARCH_SPAN_INITIALIZATION_BYTES_V1: usize =
    mem::size_of::<RegisteredSearchSpanInitializationV1<VerifiedStaticSearchSpanV1>>();
const SEARCH_SPAN_REGISTRY_IDENTITY_BYTES_V1: usize = mem::size_of::<[u8; 32]>();
const SEARCH_SPAN_REGISTRY_SLOT_BYTES_V1: usize =
    mem::size_of::<OnceLock<SearchSpanIdentitySlotV1<VerifiedStaticSearchSpanV1>>>();
const STATIC_SEARCH_SPAN_REGISTRY_CAPACITY_BYTES_PER_REGISTRY_V1: usize = mem::size_of::<
    StaticSearchSpanRegistryV1<VerifiedStaticSearchSpanV1, HARD_MAX_STATIC_SEARCH_SPAN_OBJECTS_V1>,
>();
const STATIC_SEARCH_SPAN_REGISTRY_COUNT_V1: usize =
    if cfg!(feature = "search-span-qualification-private-v1") {
        2
    } else {
        1
    };
const STATIC_SEARCH_SPAN_REGISTRY_CAPACITY_BYTES_V1: usize =
    match STATIC_SEARCH_SPAN_REGISTRY_CAPACITY_BYTES_PER_REGISTRY_V1
        .checked_mul(STATIC_SEARCH_SPAN_REGISTRY_COUNT_V1)
    {
        Some(bytes) => bytes,
        None => panic!("static Search registry accounting overflow"),
    };
const _: () = assert!(
    SEARCH_SPAN_REGISTRY_SLOT_BYTES_V1
        >= REGISTERED_SEARCH_SPAN_INITIALIZATION_BYTES_V1 + SEARCH_SPAN_REGISTRY_IDENTITY_BYTES_V1
);
#[allow(
    clippy::arithmetic_side_effects,
    reason = "the adjacent assertion proves this exact layout subtraction"
)]
const SEARCH_SPAN_REGISTRY_ONCE_LOCK_AND_PADDING_BYTES_V1: usize =
    SEARCH_SPAN_REGISTRY_SLOT_BYTES_V1
        - REGISTERED_SEARCH_SPAN_INITIALIZATION_BYTES_V1
        - SEARCH_SPAN_REGISTRY_IDENTITY_BYTES_V1;
const _: () = assert!(
    STATIC_SEARCH_SPAN_REGISTRY_CAPACITY_BYTES_PER_REGISTRY_V1
        == SEARCH_SPAN_REGISTRY_SLOT_BYTES_V1 * HARD_MAX_STATIC_SEARCH_SPAN_OBJECTS_V1
);
const _: () = assert!(
    STATIC_SEARCH_SPAN_REGISTRY_CAPACITY_BYTES_V1
        == match STATIC_SEARCH_SPAN_REGISTRY_CAPACITY_BYTES_PER_REGISTRY_V1
            .checked_mul(STATIC_SEARCH_SPAN_REGISTRY_COUNT_V1)
        {
            Some(bytes) => bytes,
            None => panic!("static Search registry accounting overflow"),
        }
);

thread_local! {
    static STATIC_SEARCH_SPAN_REGISTRY_INITIALIZATION_ACTIVE_V1: Cell<bool> =
        const { Cell::new(false) };
}

struct StaticSearchSpanRegistryInitializationGuardV1;

impl StaticSearchSpanRegistryInitializationGuardV1 {
    fn enter() -> Result<Self, StaticSearchSpanVerifyErrorV1> {
        let already_active = STATIC_SEARCH_SPAN_REGISTRY_INITIALIZATION_ACTIVE_V1
            .try_with(|active| active.replace(true))
            .map_err(|_| StaticSearchSpanVerifyErrorV1::StaticRegistryThreadLocalUnavailable)?;
        if already_active {
            Err(StaticSearchSpanVerifyErrorV1::StaticRegistryReentrantInitialization)
        } else {
            Ok(Self)
        }
    }
}

impl Drop for StaticSearchSpanRegistryInitializationGuardV1 {
    fn drop(&mut self) {
        let _ = STATIC_SEARCH_SPAN_REGISTRY_INITIALIZATION_ACTIVE_V1
            .try_with(|active| active.set(false));
    }
}

impl<T, const ENTRIES: usize> StaticSearchSpanRegistryV1<T, ENTRIES> {
    const fn new() -> Self {
        Self {
            entries: [const { OnceLock::new() }; ENTRIES],
        }
    }

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "nonzero capacity and checked addition bound both modulo operations"
    )]
    fn identity_slot(
        &self,
        identity: [u8; 32],
    ) -> Result<&SearchSpanIdentitySlotV1<T>, StaticSearchSpanVerifyErrorV1> {
        if ENTRIES == 0 {
            return Err(StaticSearchSpanVerifyErrorV1::StaticRegistryFull { limit: 0 });
        }
        let mut prefix = [0_u8; 8];
        prefix.copy_from_slice(&identity[..8]);
        let entry_count = u64::try_from(ENTRIES)
            .map_err(|_| StaticSearchSpanVerifyErrorV1::StaticRegistryInvariant)?;
        let start = usize::try_from(u64::from_le_bytes(prefix) % entry_count)
            .map_err(|_| StaticSearchSpanVerifyErrorV1::StaticRegistryInvariant)?;
        for probe in 0..ENTRIES {
            let index = start
                .checked_add(probe)
                .ok_or(StaticSearchSpanVerifyErrorV1::StaticRegistryInvariant)?
                % ENTRIES;
            let cell = &self.entries[index];
            if let Some(slot) = cell.get() {
                if slot.identity == identity {
                    return Ok(slot);
                }
                continue;
            }
            let _ = cell.set(SearchSpanIdentitySlotV1::new(identity));
            let slot = cell
                .get()
                .ok_or(StaticSearchSpanVerifyErrorV1::StaticRegistryInvariant)?;
            if slot.identity == identity {
                return Ok(slot);
            }
        }
        Err(StaticSearchSpanVerifyErrorV1::StaticRegistryFull { limit: ENTRIES })
    }

    fn adopt(
        &self,
        bytes: &[u8; STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1],
        symbols: LinkedStaticSearchSpanSymbolsV1,
        initialize: impl FnOnce() -> Result<T, StaticSearchSpanVerifyErrorV1>,
    ) -> Result<&T, StaticSearchSpanVerifyErrorV1> {
        match STATIC_SEARCH_SPAN_REGISTRY_INITIALIZATION_ACTIVE_V1.try_with(Cell::get) {
            Ok(false) => {}
            Ok(true) => {
                return Err(StaticSearchSpanVerifyErrorV1::StaticRegistryReentrantInitialization);
            }
            Err(_) => {
                return Err(StaticSearchSpanVerifyErrorV1::StaticRegistryThreadLocalUnavailable);
            }
        }
        let identity = symbols.claimed_compile_identity;
        let slot = self.identity_slot(identity)?;
        let state = slot.initialization.get_or_init(|| {
            let result = match StaticSearchSpanRegistryInitializationGuardV1::enter() {
                Ok(_guard) => match catch_unwind(AssertUnwindSafe(initialize)) {
                    Ok(result) => result,
                    Err(_) => {
                        Err(StaticSearchSpanVerifyErrorV1::StaticRegistryInitializationPanicked)
                    }
                },
                Err(error) => Err(error),
            };
            RegisteredSearchSpanInitializationV1 {
                expectation_bytes: *bytes,
                symbols,
                result,
            }
        });
        if state.expectation_bytes != *bytes {
            return Err(StaticSearchSpanVerifyErrorV1::AlreadyInitializedForDifferentExpectation);
        }
        if state.symbols != symbols {
            return Err(StaticSearchSpanVerifyErrorV1::AlreadyInitializedForDifferentSymbols);
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

type VerifiedSearchSpanRegistryV1 =
    StaticSearchSpanRegistryV1<VerifiedStaticSearchSpanV1, HARD_MAX_STATIC_SEARCH_SPAN_OBJECTS_V1>;

static PRODUCTION_STATIC_SEARCH_SPAN_REGISTRY_V1: VerifiedSearchSpanRegistryV1 =
    StaticSearchSpanRegistryV1::new();
#[cfg(feature = "search-span-qualification-private-v1")]
static PRIVATE_QUALIFICATION_STATIC_SEARCH_SPAN_REGISTRY_V1: VerifiedSearchSpanRegistryV1 =
    StaticSearchSpanRegistryV1::new();

pub(super) struct CopiedSearchSpanExpectationV1 {
    pub(super) bytes: [u8; STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1],
    pub(super) vm_regions_checked: usize,
}

/// Process-lifetime proof of one source-qualified linked Search-v1 Span tuple.
#[derive(Debug)]
pub struct VerifiedStaticSearchSpanV1 {
    expected: ExpectedStaticSearchSpanV1,
    entry: SearchSpanEntryV1,
    row_selector: u16,
    accounting: StaticSearchSpanInspectionAccountingV1,
}

/// Current-thread invocation token for one already adopted Search handle.
///
/// The token is deliberately neither `Send` nor `Sync`. For tag21, creation
/// observes exact VL16 once; its `search`/`find` methods perform no `prctl` and
/// are suitable for measured batches on the same thread. The independently
/// audited tag21 stream begins with `PTRUE ..., VL16`, so wider architectural
/// SVE lengths remain confined to sixteen active byte lanes; exact VL16 is a
/// qualification/deployment policy, not a per-call memory-safety crutch.
/// Session construction also snapshots the verified entry and literal width,
/// while retaining the originating handle for their complete lifetime.
/// Changing the calling thread's VL after creating this token invalidates that
/// qualification and requires a new token.
#[derive(Debug)]
pub struct StaticSearchSpanThreadSessionV1<'handle> {
    entry: SearchSpanEntryV1,
    live_literal_bytes: u32,
    handle: &'handle VerifiedStaticSearchSpanV1,
    thread_bound: PhantomData<Rc<()>>,
}

/// Invoke production linked glue and resolve only a registry-owned handle.
///
/// The isolated production table begins empty and can contain only a
/// source-reviewed promotion. Missing or unqualified selectors fail closed
/// before any final-image address can be inspected.
pub fn adopt_linked_static_search_span_v1(
    invoke_glue: impl FnOnce(*mut RawStaticSearchSpanAdoptionOutputV1) -> u32,
) -> Result<&'static VerifiedStaticSearchSpanV1, StaticSearchSpanAdoptionErrorV1> {
    invoke_and_resolve_search_span_adoption(&PRODUCTION_STATIC_SEARCH_SPAN_REGISTRY_V1, invoke_glue)
}

fn invoke_and_resolve_search_span_adoption(
    registry: &'static VerifiedSearchSpanRegistryV1,
    invoke_glue: impl FnOnce(*mut RawStaticSearchSpanAdoptionOutputV1) -> u32,
) -> Result<&'static VerifiedStaticSearchSpanV1, StaticSearchSpanAdoptionErrorV1> {
    let mut output = RawStaticSearchSpanAdoptionOutputV1 {
        verified: ptr::null(),
    };
    let status = invoke_glue(ptr::addr_of_mut!(output));
    resolve_search_span_adoption_output(registry, status, output.verified.cast())
}

/// Invoke separately named private qualification glue.
///
/// The private qualification row table begins empty. It can contain only an
/// exact compiler/link-derived row independently reviewed and pinned in
/// source; the feature alone cannot populate it.
///
/// # Safety
///
/// `invoke_glue` must invoke only the retained glue for
/// `fre_aot_static_search_span_adopt_qualification_raw_v1`.
#[cfg(feature = "search-span-qualification-private-v1")]
#[doc(hidden)]
#[allow(
    unsafe_code,
    reason = "this explicitly unsafe adapter is the only Rust entry to the disjoint private Search qualification registry"
)]
pub unsafe fn adopt_linked_static_search_span_qualification_v1(
    invoke_glue: impl FnOnce(*mut RawStaticSearchSpanAdoptionOutputV1) -> u32,
) -> Result<&'static VerifiedStaticSearchSpanV1, StaticSearchSpanAdoptionErrorV1> {
    invoke_and_resolve_search_span_adoption(
        &PRIVATE_QUALIFICATION_STATIC_SEARCH_SPAN_REGISTRY_V1,
        invoke_glue,
    )
}

impl VerifiedStaticSearchSpanV1 {
    /// Search one checked window with the exact live literal embedded in the
    /// authenticated payload.
    ///
    /// Shared scalar preflight completes before this method derives a
    /// haystack pointer or invokes native code. The returned accounting is the
    /// exact certificate produced by that shared preflight. Tag21 refuses this
    /// convenience boundary because it requires a same-thread session.
    #[inline]
    pub fn search(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: LiteralSearchLimits,
    ) -> Result<(Option<MatchSpan>, LiteralAccounting), StaticSearchSpanCallErrorV1> {
        if self.requires_thread_session() {
            return Err(StaticSearchSpanCallErrorV1::ThreadSessionRequired {
                backend_version: self.backend_version(),
            });
        }
        self.search_with_current_thread_contract(haystack, window, limits)
    }

    #[inline]
    fn search_with_current_thread_contract(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: LiteralSearchLimits,
    ) -> Result<(Option<MatchSpan>, LiteralAccounting), StaticSearchSpanCallErrorV1> {
        checked_static_search_span_v1(
            self.expected.live_literal_bytes(),
            haystack,
            window,
            limits,
            || implementation::invoke_search_span(self.entry, haystack, window),
        )
    }

    /// Search the complete haystack.
    #[inline]
    pub fn find(
        &self,
        haystack: &[u8],
        limits: LiteralSearchLimits,
    ) -> Result<(Option<MatchSpan>, LiteralAccounting), StaticSearchSpanCallErrorV1> {
        self.search(haystack, SearchWindow::new(0, haystack.len()), limits)
    }

    /// Establish one current-thread session. V8 requires no system call;
    /// tag21 performs one exact `PR_SVE_GET_VL` qualification check here.
    pub fn begin_current_thread_session(
        &self,
    ) -> Result<StaticSearchSpanThreadSessionV1<'_>, StaticSearchSpanThreadContractErrorV1> {
        if self.requires_thread_session() {
            require_current_thread_sve_vl16_v1()?;
        }
        Ok(StaticSearchSpanThreadSessionV1 {
            entry: self.entry,
            live_literal_bytes: self.expected.live_literal_bytes(),
            handle: self,
            thread_bound: PhantomData,
        })
    }

    #[must_use]
    pub const fn backend_version(&self) -> u16 {
        self.expected.metadata().backend_version()
    }

    #[must_use]
    pub const fn requires_thread_session(&self) -> bool {
        self.backend_version() == SEARCH_BACKEND_SVE2_FIXED16_TAG21_V1
    }

    #[must_use]
    pub const fn row_selector(&self) -> u16 {
        self.row_selector
    }

    #[must_use]
    pub const fn live_literal_bytes(&self) -> u32 {
        self.expected.live_literal_bytes()
    }

    #[must_use]
    pub const fn manifest_identity(&self) -> &[u8; 32] {
        self.expected.manifest_identity()
    }

    #[must_use]
    pub const fn semantic_binding_identity(&self) -> &[u8; 32] {
        self.expected.semantic_binding_identity()
    }

    #[must_use]
    pub const fn literal_identity(&self) -> &[u8; 32] {
        self.expected.literal_identity()
    }

    #[must_use]
    pub const fn kir_identity(&self) -> &[u8; 32] {
        self.expected.kir_identity()
    }

    #[must_use]
    pub const fn artifact_identity(&self) -> &[u8; 32] {
        self.expected.artifact_identity()
    }

    #[must_use]
    pub const fn binding_identity(&self) -> &[u8; 32] {
        self.expected.binding_identity()
    }

    #[must_use]
    pub const fn compile_identity(&self) -> &[u8; 32] {
        self.expected.compile_identity()
    }

    #[must_use]
    pub const fn object_identity(&self) -> &[u8; 32] {
        self.expected.object_identity()
    }

    #[must_use]
    pub const fn receipt_identity(&self) -> &[u8; 32] {
        self.expected.receipt_identity()
    }

    #[must_use]
    pub const fn expectation_identity(&self) -> &[u8; 32] {
        self.expected.expectation_identity()
    }

    #[must_use]
    pub const fn payload_identity(&self) -> [u8; 32] {
        self.expected.payload_identity()
    }

    #[must_use]
    pub const fn inspection_accounting(&self) -> StaticSearchSpanInspectionAccountingV1 {
        self.accounting
    }
}

impl StaticSearchSpanThreadSessionV1<'_> {
    /// Search one checked window without a per-call vector-length syscall.
    #[inline]
    pub fn search(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: LiteralSearchLimits,
    ) -> Result<(Option<MatchSpan>, LiteralAccounting), StaticSearchSpanCallErrorV1> {
        checked_static_search_span_v1(self.live_literal_bytes, haystack, window, limits, || {
            implementation::invoke_search_span(self.entry, haystack, window)
        })
    }

    /// Search the complete haystack without a per-call vector-length syscall.
    #[inline]
    pub fn find(
        &self,
        haystack: &[u8],
        limits: LiteralSearchLimits,
    ) -> Result<(Option<MatchSpan>, LiteralAccounting), StaticSearchSpanCallErrorV1> {
        self.search(haystack, SearchWindow::new(0, haystack.len()), limits)
    }

    #[must_use]
    pub const fn handle(&self) -> &VerifiedStaticSearchSpanV1 {
        self.handle
    }
}

/// Qualification-only mutation of the calling thread's Linux SVE state.
///
/// This performs `PR_SVE_SET_VL(16)` followed by an independent
/// `PR_SVE_GET_VL` check. It is not called by adoption or any measured search
/// entry. Each benchmark worker must invoke it before adoption/session
/// creation on that same thread.
#[cfg(feature = "search-span-qualification-private-v1")]
#[doc(hidden)]
pub fn configure_current_thread_sve_vl16_for_search_qualification_v1()
-> Result<u16, StaticSearchSpanThreadContractErrorV1> {
    configure_current_thread_sve_vl16_v1()
}

fn require_current_thread_sve_vl16_v1() -> Result<(), StaticSearchSpanThreadContractErrorV1> {
    #[cfg(all(
        feature = "linked-search-span-v1",
        target_arch = "aarch64",
        target_os = "linux",
        target_pointer_width = "64",
        target_endian = "little"
    ))]
    {
        implementation::require_current_thread_sve_vl16_v1()
    }
    #[cfg(not(all(
        feature = "linked-search-span-v1",
        target_arch = "aarch64",
        target_os = "linux",
        target_pointer_width = "64",
        target_endian = "little"
    )))]
    {
        Err(StaticSearchSpanThreadContractErrorV1::UnsupportedHost)
    }
}

#[cfg(feature = "search-span-qualification-private-v1")]
fn configure_current_thread_sve_vl16_v1() -> Result<u16, StaticSearchSpanThreadContractErrorV1> {
    #[cfg(all(
        feature = "linked-search-span-v1",
        target_arch = "aarch64",
        target_os = "linux",
        target_pointer_width = "64",
        target_endian = "little"
    ))]
    {
        implementation::configure_current_thread_sve_vl16_v1()
    }
    #[cfg(not(all(
        feature = "linked-search-span-v1",
        target_arch = "aarch64",
        target_os = "linux",
        target_pointer_width = "64",
        target_endian = "little"
    )))]
    {
        Err(StaticSearchSpanThreadContractErrorV1::UnsupportedHost)
    }
}

fn resolve_search_span_adoption_output<T, const ENTRIES: usize>(
    registry: &StaticSearchSpanRegistryV1<T, ENTRIES>,
    status: u32,
    pointer: *const T,
) -> Result<&T, StaticSearchSpanAdoptionErrorV1> {
    match status {
        STATIC_SEARCH_SPAN_ADOPT_STATUS_NO_QUALIFIED_ROW_V1 => {
            Err(StaticSearchSpanAdoptionErrorV1::NoQualifiedStaticSearchSpanRow)
        }
        STATIC_SEARCH_SPAN_ADOPT_STATUS_UNQUALIFIED_SELECTOR_V1 => {
            Err(StaticSearchSpanAdoptionErrorV1::UnqualifiedStaticSearchSpanSelector)
        }
        STATIC_SEARCH_SPAN_ADOPT_STATUS_REFUSED_V1 => {
            Err(StaticSearchSpanAdoptionErrorV1::VerificationRefused)
        }
        STATIC_SEARCH_SPAN_ADOPT_STATUS_OK_V1 if pointer.is_null() => {
            Err(StaticSearchSpanAdoptionErrorV1::MissingVerifiedHandle)
        }
        STATIC_SEARCH_SPAN_ADOPT_STATUS_OK_V1 => registry
            .registered_value(pointer)
            .ok_or(StaticSearchSpanAdoptionErrorV1::UnregisteredVerifiedHandle),
        status => Err(StaticSearchSpanAdoptionErrorV1::UnknownStatus { status }),
    }
}

#[inline]
fn checked_static_search_span_v1(
    live_literal_bytes: u32,
    haystack: &[u8],
    window: SearchWindow,
    limits: LiteralSearchLimits,
    invoke: impl FnOnce() -> RawSearchCallV1,
) -> Result<(Option<MatchSpan>, LiteralAccounting), StaticSearchSpanCallErrorV1> {
    let literal_len = usize::try_from(live_literal_bytes).map_err(|_| {
        StaticSearchSpanCallErrorV1::LiteralWidthNotRepresentable {
            bytes: live_literal_bytes,
        }
    })?;
    let accounting = preflight_literal_window(
        literal_len,
        haystack.len(),
        Window::new(window.start(), window.end()),
        limits,
    )?;
    let output = decode_search_call_v1::<Span>(invoke(), window, literal_len)?;
    Ok((output, accounting))
}

/// Row-selector-first production Search-v1 Span adoption boundary.
///
/// The literal production table is queried before `output` or any final-image
/// pointer is inspected. An empty table or unqualified selector therefore
/// returns without exposing, converting, or reading any supplied pointer.
///
/// # Safety
///
/// If a future source revision selects `row_selector`, `output` must be
/// writable and all four addresses must name immutable process-lifetime
/// symbols from that exact retained final image.
#[doc(hidden)]
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    reason = "this audited C boundary receives unresolved final-image addresses and writes output only after complete verification"
)]
pub unsafe extern "C" fn fre_aot_static_search_span_adopt_raw_v1(
    output: *mut RawStaticSearchSpanAdoptionOutputV1,
    row_selector: u32,
    expectation: *const u8,
    entry: *const u8,
    payload: *const u8,
    metadata: *const u8,
) -> u32 {
    let family = match search_support::require_production_search_span_family_v1(row_selector) {
        Ok(family) => family,
        Err(StaticSearchSpanVerifyErrorV1::NoQualifiedStaticSearchSpanRowV1) => {
            return STATIC_SEARCH_SPAN_ADOPT_STATUS_NO_QUALIFIED_ROW_V1;
        }
        Err(StaticSearchSpanVerifyErrorV1::UnqualifiedStaticSearchSpanSelectorV1) => {
            return STATIC_SEARCH_SPAN_ADOPT_STATUS_UNQUALIFIED_SELECTOR_V1;
        }
        Err(_) => return STATIC_SEARCH_SPAN_ADOPT_STATUS_REFUSED_V1,
    };
    // SAFETY: the source-qualified production row was selected before any
    // pointer use and the caller owns the complete documented raw contract.
    unsafe {
        adopt_selected_static_search_span_family_v1(
            &PRODUCTION_STATIC_SEARCH_SPAN_REGISTRY_V1,
            output,
            expectation,
            entry,
            payload,
            metadata,
            family,
        )
    }
}

#[allow(
    unsafe_code,
    reason = "the selected family boundary owns final-image address retention and the one verified output write"
)]
unsafe fn adopt_selected_static_search_span_family_v1(
    registry: &'static VerifiedSearchSpanRegistryV1,
    output: *mut RawStaticSearchSpanAdoptionOutputV1,
    expectation: *const u8,
    entry: *const u8,
    payload: *const u8,
    metadata: *const u8,
    family: &'static SourceQualifiedStaticSearchSpanFamilyV1,
) -> u32 {
    if output.is_null() {
        return STATIC_SEARCH_SPAN_ADOPT_STATUS_REFUSED_V1;
    }
    let symbols = LinkedStaticSearchSpanSymbolsV1::from_source_qualified_family(
        family,
        StaticSearchSpanLinkedAddressV1::from_exposed_address(expectation.expose_provenance()),
        StaticSearchSpanLinkedAddressV1::from_exposed_address(entry.expose_provenance()),
        StaticSearchSpanLinkedAddressV1::from_exposed_address(payload.expose_provenance()),
        StaticSearchSpanLinkedAddressV1::from_exposed_address(metadata.expose_provenance()),
    );
    // SAFETY: family resolution preceded every address operation and the raw
    // boundary supplies process-lifetime final-image symbols.
    let Ok(verified) =
        (unsafe { adopt_source_qualified_static_search_span_family_v1(registry, symbols, family) })
    else {
        return STATIC_SEARCH_SPAN_ADOPT_STATUS_REFUSED_V1;
    };
    // SAFETY: output is a caller-owned writable slot touched only after the
    // complete family, mapped-image, and semantic reconstruction audit.
    unsafe {
        output.write(RawStaticSearchSpanAdoptionOutputV1 {
            verified: ptr::from_ref(verified).cast(),
        });
    }
    STATIC_SEARCH_SPAN_ADOPT_STATUS_OK_V1
}

/// Separately named private qualification-only raw adoption boundary.
///
/// Its row table, symbol, and registry are disjoint from production. The table
/// begins empty and the feature alone grants no authority. Row lookup always
/// completes before any pointer is inspected.
///
/// # Safety
///
/// If a future source revision selects `row_selector`, `output` must be
/// writable and all four addresses must name immutable process-lifetime
/// symbols from the exact retained qualification image pinned by that row.
#[cfg(feature = "search-span-qualification-private-v1")]
#[doc(hidden)]
#[unsafe(no_mangle)]
#[allow(
    unsafe_code,
    reason = "this separately named C boundary is reachable only from explicit private qualification glue"
)]
pub unsafe extern "C" fn fre_aot_static_search_span_adopt_qualification_raw_v1(
    output: *mut RawStaticSearchSpanAdoptionOutputV1,
    row_selector: u32,
    expectation: *const u8,
    entry: *const u8,
    payload: *const u8,
    metadata: *const u8,
) -> u32 {
    let row = match search_support::require_private_qualification_search_span_row_v1(row_selector) {
        Ok(row) => row,
        Err(StaticSearchSpanVerifyErrorV1::NoQualifiedStaticSearchSpanRowV1) => {
            return STATIC_SEARCH_SPAN_ADOPT_STATUS_NO_QUALIFIED_ROW_V1;
        }
        Err(StaticSearchSpanVerifyErrorV1::UnqualifiedStaticSearchSpanSelectorV1) => {
            return STATIC_SEARCH_SPAN_ADOPT_STATUS_UNQUALIFIED_SELECTOR_V1;
        }
        Err(_) => return STATIC_SEARCH_SPAN_ADOPT_STATUS_REFUSED_V1,
    };
    // SAFETY: the private source-qualified row was selected before pointer use.
    unsafe {
        adopt_selected_static_search_span_v1(
            &PRIVATE_QUALIFICATION_STATIC_SEARCH_SPAN_REGISTRY_V1,
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
    reason = "the selected raw boundary owns final-image address retention and the one verified output write"
)]
unsafe fn adopt_selected_static_search_span_v1(
    registry: &'static VerifiedSearchSpanRegistryV1,
    output: *mut RawStaticSearchSpanAdoptionOutputV1,
    expectation: *const u8,
    entry: *const u8,
    payload: *const u8,
    metadata: *const u8,
    row: &'static SourceQualifiedStaticSearchSpanRowV1,
) -> u32 {
    if output.is_null() {
        return STATIC_SEARCH_SPAN_ADOPT_STATUS_REFUSED_V1;
    }
    let symbols = LinkedStaticSearchSpanSymbolsV1::from_source_qualified_row(
        row,
        StaticSearchSpanLinkedAddressV1::from_exposed_address(expectation.expose_provenance()),
        StaticSearchSpanLinkedAddressV1::from_exposed_address(entry.expose_provenance()),
        StaticSearchSpanLinkedAddressV1::from_exposed_address(payload.expose_provenance()),
        StaticSearchSpanLinkedAddressV1::from_exposed_address(metadata.expose_provenance()),
    );
    // SAFETY: selector resolution preceded every address operation; the raw
    // boundary contract supplies process-lifetime exact final-image symbols.
    let Ok(verified) =
        (unsafe { adopt_source_qualified_static_search_span_v1(registry, symbols, row) })
    else {
        return STATIC_SEARCH_SPAN_ADOPT_STATUS_REFUSED_V1;
    };
    // SAFETY: output is one caller-owned writable slot and is touched only
    // after complete source-row and mapped-image verification.
    unsafe {
        output.write(RawStaticSearchSpanAdoptionOutputV1 {
            verified: ptr::from_ref(verified).cast(),
        });
    }
    STATIC_SEARCH_SPAN_ADOPT_STATUS_OK_V1
}

#[allow(
    unsafe_code,
    reason = "the platform verifier owns all raw final-image reads"
)]
unsafe fn adopt_source_qualified_static_search_span_v1(
    registry: &'static VerifiedSearchSpanRegistryV1,
    symbols: LinkedStaticSearchSpanSymbolsV1,
    row: &SourceQualifiedStaticSearchSpanRowV1,
) -> Result<&'static VerifiedStaticSearchSpanV1, StaticSearchSpanVerifyErrorV1> {
    require_search_span_v1(
        symbols.row_selector == row.selector(),
        StaticSearchSpanContractFieldV1::SelectedRow,
    )?;
    // SAFETY: the source-qualified raw boundary established all caller
    // obligations before passing retained addresses to the platform verifier.
    let copied = unsafe { implementation::copy_expectation(symbols.expectation_address)? };
    let expected = ExpectedStaticSearchSpanV1::from_source_qualified_bytes(
        &copied.bytes,
        row,
        &symbols.claimed_compile_identity,
    )?;
    registry.adopt(&copied.bytes, symbols, || {
        let (entry, accounting) =
            implementation::verify(&expected, symbols, copied.vm_regions_checked)?;
        Ok(VerifiedStaticSearchSpanV1 {
            expected,
            entry,
            row_selector: row.selector(),
            accounting,
        })
    })
}

#[allow(
    unsafe_code,
    reason = "the platform verifier owns all raw final-image reads after source-family selection"
)]
unsafe fn adopt_source_qualified_static_search_span_family_v1(
    registry: &'static VerifiedSearchSpanRegistryV1,
    symbols: LinkedStaticSearchSpanSymbolsV1,
    family: &SourceQualifiedStaticSearchSpanFamilyV1,
) -> Result<&'static VerifiedStaticSearchSpanV1, StaticSearchSpanVerifyErrorV1> {
    require_search_span_v1(
        symbols.row_selector == family.selector(),
        StaticSearchSpanContractFieldV1::ProductionFamily,
    )?;
    // SAFETY: the source-qualified raw boundary established all caller
    // obligations before passing retained addresses to the platform verifier.
    let copied = unsafe { implementation::copy_expectation(symbols.expectation_address)? };
    let expected =
        ExpectedStaticSearchSpanV1::from_source_qualified_family_bytes(&copied.bytes, family)?;
    registry.adopt(&copied.bytes, symbols, || {
        let (entry, accounting) =
            implementation::verify(&expected, symbols, copied.vm_regions_checked)?;
        Ok(VerifiedStaticSearchSpanV1 {
            expected,
            entry,
            row_selector: family.selector(),
            accounting,
        })
    })
}

#[allow(
    dead_code,
    reason = "mapped verification is feature and source-row gated while its strict source tests remain available"
)]
pub(super) fn validate_mapped_search_span_metadata_v1(
    bytes: &[u8; SEARCH_METADATA_BYTES_V1],
    expected: ClaimedSearchMetadataV1,
) -> Result<ClaimedSearchMetadataV1, StaticSearchSpanVerifyErrorV1> {
    let actual = inspect_search_metadata_v1(bytes)?;
    require_search_span_v1(
        actual == expected,
        StaticSearchSpanContractFieldV1::Metadata,
    )?;
    Ok(actual)
}

/// Rebuild the exact semantic KIR and canonical native payload from mapped
/// rodata before a source-family-qualified image becomes callable.
///
/// This is deliberately independent of compiler/object identities. It turns a
/// broad source-reviewed compiler family into per-artifact proof: arbitrary
/// self-consistent expectation bytes are insufficient unless their immutable
/// code and literal bytes are exactly what the reviewed emitter regenerates.
pub(super) fn require_semantic_payload_reconstruction_v1(
    expected: &ExpectedStaticSearchSpanV1,
    payload: &[u8],
) -> Result<(), StaticSearchSpanVerifyErrorV1> {
    const LITERAL_IDENTITY_DOMAIN_V1: &[u8] = b"FRE-AOT-LINUX-SEARCH-LITERAL\0\x01";

    let metadata = expected.metadata();
    let code_end = usize::try_from(metadata.code_bytes())
        .map_err(|_| StaticSearchSpanVerifyErrorV1::SemanticPayloadReconstruction)?;
    let rodata_start = usize::try_from(metadata.rodata_offset())
        .map_err(|_| StaticSearchSpanVerifyErrorV1::SemanticPayloadReconstruction)?;
    let rodata_bytes = usize::try_from(metadata.rodata_bytes())
        .map_err(|_| StaticSearchSpanVerifyErrorV1::SemanticPayloadReconstruction)?;
    let rodata_end = rodata_start
        .checked_add(rodata_bytes)
        .ok_or(StaticSearchSpanVerifyErrorV1::SemanticPayloadReconstruction)?;
    let code = payload
        .get(..code_end)
        .ok_or(StaticSearchSpanVerifyErrorV1::SemanticPayloadReconstruction)?;
    let padding = payload
        .get(code_end..rodata_start)
        .ok_or(StaticSearchSpanVerifyErrorV1::SemanticPayloadReconstruction)?;
    let literal = payload
        .get(rodata_start..rodata_end)
        .ok_or(StaticSearchSpanVerifyErrorV1::SemanticPayloadReconstruction)?;
    if rodata_end != payload.len() || padding.iter().any(|byte| *byte != 0) {
        return Err(StaticSearchSpanVerifyErrorV1::SemanticPayloadReconstruction);
    }

    let mut literal_hasher = Sha256::new();
    literal_hasher.update(LITERAL_IDENTITY_DOMAIN_V1);
    literal_hasher.update(
        u64::try_from(literal.len())
            .map_err(|_| StaticSearchSpanVerifyErrorV1::SemanticPayloadReconstruction)?
            .to_le_bytes(),
    );
    literal_hasher.update(literal);
    let literal_identity: [u8; 32] = literal_hasher.finalize().into();
    if &literal_identity != expected.literal_identity() {
        return Err(StaticSearchSpanVerifyErrorV1::SemanticPayloadReconstruction);
    }

    let program =
        build_exact_literal::<Span>(literal, AnchorFlags::default(), ValidateLimits::default())
            .map_err(|_| StaticSearchSpanVerifyErrorV1::SemanticPayloadReconstruction)?;
    if program.cache_identity().as_bytes() != expected.kir_identity() {
        return Err(StaticSearchSpanVerifyErrorV1::SemanticPayloadReconstruction);
    }
    let policy = match metadata.backend_version() {
        SEARCH_BACKEND_VERSION_V1 => SearchBackendPolicy::AsimdV8,
        SEARCH_BACKEND_SVE2_FIXED16_TAG21_V1 => SearchBackendPolicy::Sve2Fixed16V2,
        _ => return Err(StaticSearchSpanVerifyErrorV1::SemanticPayloadReconstruction),
    };
    let rebuilt = emit_audited_with_backend(&program, policy, EmitLimits::default())
        .map_err(|_| StaticSearchSpanVerifyErrorV1::SemanticPayloadReconstruction)?;
    let image = rebuilt.as_image();
    let target = TargetSpec {
        architecture: metadata.architecture(),
        little_endian: metadata.little_endian(),
        pointer_width: metadata.pointer_width(),
        abi: metadata.target_abi(),
        features: image.target().features,
    };
    let layout = image.layout();
    if image.backend_version().0 != metadata.backend_version()
        || image.target() != target
        || image.source_identity().as_bytes() != expected.kir_identity()
        || image.artifact_identity().as_bytes() != expected.artifact_identity()
        || image.code() != code
        || image.rodata() != literal
        || image.stats().code_bytes != metadata.code_bytes()
        || image.stats().data_bytes != metadata.rodata_bytes()
        || layout.rodata_from_code_start != metadata.rodata_offset()
        || layout.total_mapped_bytes != metadata.payload_bytes()
    {
        return Err(StaticSearchSpanVerifyErrorV1::SemanticPayloadReconstruction);
    }
    Ok(())
}

#[allow(
    dead_code,
    unsafe_code,
    reason = "only a completely verified platform handle can reach this exact raw ABI helper"
)]
#[inline]
pub(super) fn raw_search_span_call_v1(
    entry: SearchSpanEntryV1,
    haystack: &[u8],
    haystack_pointer: *const u8,
    window: SearchWindow,
) -> RawSearchCallV1 {
    let mut result = RawSearchResultV1::poisoned();
    // SAFETY: the caller owns either the complete mapped-image proof or an
    // explicitly unsafe test-only raw-entry contract.
    let status = unsafe {
        entry(
            haystack_pointer,
            haystack.len(),
            window.start(),
            window.end(),
            ptr::addr_of_mut!(result),
        )
    };
    RawSearchCallV1 { status, result }
}

#[allow(
    dead_code,
    unsafe_code,
    reason = "only a completely verified immutable Span entry can reach this initialization-eliding hot-call helper"
)]
#[inline]
pub(super) fn verified_search_span_call_v1(
    entry: SearchSpanEntryV1,
    haystack: &[u8],
    haystack_pointer: *const u8,
    window: SearchWindow,
) -> RawSearchCallV1 {
    let mut result = MaybeUninit::<RawSearchResultV1>::uninit();
    // SAFETY: static adoption accepted this entry only after matching the
    // source-qualified expectation, immutable mapped payload, metadata, and
    // complete independently audited Span machine-code contract. That
    // contract receives this exact writable two-word slot and initializes both
    // words immediately before returning match status one.
    let status = unsafe {
        entry(
            haystack_pointer,
            haystack.len(),
            window.start(),
            window.end(),
            result.as_mut_ptr(),
        )
    };
    let result = if status == 1 {
        // SAFETY: the verified Span entry's only status-one return follows
        // stores to both words. Miss and fault paths are handled below without
        // reading the uninitialized slot.
        unsafe { result.assume_init() }
    } else {
        // Preserve the inert decoder's fail-closed miss/fault representation
        // without writing poison words into the native out-parameter before
        // every call.
        RawSearchResultV1::poisoned()
    };
    RawSearchCallV1 { status, result }
}

#[cfg(test)]
mod tests {
    use core::ptr;
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        thread,
    };

    use super::*;
    use crate::search_test_fixture::static_search_span_fixture_v1;

    #[allow(
        unsafe_code,
        reason = "the inert fixture supplies an ABI-compatible address that must never be called"
    )]
    unsafe extern "C" fn dummy_entry(
        _haystack: *const u8,
        _haystack_len: usize,
        _window_start: usize,
        _window_end: usize,
        _result: *mut RawSearchResultV1,
    ) -> u64 {
        panic!("inert Search registry tests must not call the entry")
    }

    #[allow(
        unsafe_code,
        reason = "the test stub implements the verified Span ABI, including the rule that only status one initializes both result words"
    )]
    unsafe extern "C" fn initialization_elision_test_entry(
        _haystack: *const u8,
        _haystack_len: usize,
        window_start: usize,
        _window_end: usize,
        result: *mut RawSearchResultV1,
    ) -> u64 {
        match window_start {
            0 => 0,
            1 => {
                // SAFETY: the test calls this stub with a live, aligned
                // two-word result slot.
                unsafe { result.write(RawSearchResultV1 { start: 1, end: 2 }) };
                1
            }
            _ => 7,
        }
    }

    #[cfg(all(
        feature = "linked-search-span-v1",
        target_arch = "aarch64",
        target_pointer_width = "64",
        target_endian = "little",
        any(target_os = "linux", target_os = "macos")
    ))]
    static SESSION_TEST_ENTRY_CALLS: AtomicUsize = AtomicUsize::new(0);

    #[cfg(all(
        feature = "linked-search-span-v1",
        target_arch = "aarch64",
        target_pointer_width = "64",
        target_endian = "little",
        any(target_os = "linux", target_os = "macos")
    ))]
    #[allow(
        unsafe_code,
        reason = "the test stub implements the exact raw Search-v1 Span ABI and publishes into its caller-owned result slot"
    )]
    unsafe extern "C" fn session_test_entry(
        haystack: *const u8,
        haystack_len: usize,
        window_start: usize,
        window_end: usize,
        result: *mut RawSearchResultV1,
    ) -> u64 {
        SESSION_TEST_ENTRY_CALLS.fetch_add(1, Ordering::SeqCst);
        if result.is_null()
            || haystack.is_null()
            || window_start > window_end
            || window_end > haystack_len
        {
            return u64::MAX;
        }
        let Some(match_end) = window_start.checked_add(16) else {
            return u64::MAX;
        };
        if match_end > window_end {
            return 0;
        }
        // SAFETY: the raw caller supplies a live, aligned result slot for the
        // complete duration of this ABI call.
        unsafe {
            result.write(RawSearchResultV1 {
                start: window_start,
                end: match_end,
            });
        }
        1
    }

    static TEST_EXPECTATION_A: [u8; STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1] =
        [0; STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1];

    #[test]
    fn verified_span_call_reads_the_result_slot_only_for_match_status() {
        let haystack = b"abc";
        let call = |window_start| {
            verified_search_span_call_v1(
                initialization_elision_test_entry,
                haystack,
                haystack.as_ptr(),
                SearchWindow::new(window_start, haystack.len()),
            )
        };
        assert_eq!(
            call(0),
            RawSearchCallV1 {
                status: 0,
                result: RawSearchResultV1::poisoned(),
            }
        );
        assert_eq!(
            call(1),
            RawSearchCallV1 {
                status: 1,
                result: RawSearchResultV1 { start: 1, end: 2 },
            }
        );
        assert_eq!(
            call(2),
            RawSearchCallV1 {
                status: 7,
                result: RawSearchResultV1::poisoned(),
            }
        );
    }
    static TEST_EXPECTATION_B: [u8; STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1] =
        [1; STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1];
    static TEST_PAYLOAD_A: [u8; 1] = [0];
    static TEST_PAYLOAD_B: [u8; 1] = [1];
    static TEST_METADATA_A: [u8; SEARCH_METADATA_BYTES_V1] = [0; SEARCH_METADATA_BYTES_V1];
    static TEST_METADATA_B: [u8; SEARCH_METADATA_BYTES_V1] = [1; SEARCH_METADATA_BYTES_V1];

    #[allow(
        clippy::as_conversions,
        reason = "the inert fixture records but never calls one ABI-compatible function address"
    )]
    fn symbols(identity_byte: u8, tuple: u8) -> LinkedStaticSearchSpanSymbolsV1 {
        let entry = StaticSearchSpanLinkedAddressV1::from_exposed_address(
            (dummy_entry as *const ()).expose_provenance(),
        );
        let (expectation, payload, metadata) = match tuple {
            1 => (
                ptr::addr_of!(TEST_EXPECTATION_A).cast::<u8>(),
                ptr::addr_of!(TEST_PAYLOAD_A).cast::<u8>(),
                ptr::addr_of!(TEST_METADATA_A).cast::<u8>(),
            ),
            2 => (
                ptr::addr_of!(TEST_EXPECTATION_B).cast::<u8>(),
                ptr::addr_of!(TEST_PAYLOAD_B).cast::<u8>(),
                ptr::addr_of!(TEST_METADATA_B).cast::<u8>(),
            ),
            _ => panic!("unknown Search test tuple"),
        };
        LinkedStaticSearchSpanSymbolsV1::test_only(
            u16::from(identity_byte),
            [identity_byte; 32],
            StaticSearchSpanLinkedAddressV1::from_exposed_address(expectation.expose_provenance()),
            entry,
            StaticSearchSpanLinkedAddressV1::from_exposed_address(payload.expose_provenance()),
            StaticSearchSpanLinkedAddressV1::from_exposed_address(metadata.expose_provenance()),
        )
    }

    const fn expectation(distinguishing_byte: u8) -> [u8; STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1] {
        let mut bytes = [0_u8; STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1];
        bytes[0] = distinguishing_byte;
        bytes
    }

    #[test]
    #[allow(
        unsafe_code,
        reason = "the test proves every production authority state rejects an unrepresentable selector before intentionally invalid pointers"
    )]
    fn production_table_refuses_unrepresentable_selector_before_every_pointer_use() {
        let conversions_before = implementation::verified_entry_conversion_count();
        let unrepresentable_selector = u32::from(u16::MAX) + 1;
        let expected_status = if search_support::production_rows_are_empty_for_test_v1() {
            STATIC_SEARCH_SPAN_ADOPT_STATUS_NO_QUALIFIED_ROW_V1
        } else {
            STATIC_SEARCH_SPAN_ADOPT_STATUS_UNQUALIFIED_SELECTOR_V1
        };
        // SAFETY: no source row can have this out-of-u16 selector. Both the
        // empty and promoted-table paths return before any pointer is exposed,
        // converted, or read.
        let status = unsafe {
            fre_aot_static_search_span_adopt_raw_v1(
                ptr::without_provenance_mut::<RawStaticSearchSpanAdoptionOutputV1>(1),
                unrepresentable_selector,
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

    #[cfg(feature = "search-span-qualification-private-v1")]
    #[test]
    #[allow(
        unsafe_code,
        reason = "the test proves every unqualified private selector returns before invalid pointers"
    )]
    fn private_source_rows_remain_disjoint_and_refuse_unqualified_before_pointers() {
        let conversions_before = implementation::verified_entry_conversion_count();
        let unrepresentable_selector = u32::from(u16::MAX) + 1;
        let expected_status = if search_support::private_qualification_rows_are_empty_for_test_v1()
        {
            STATIC_SEARCH_SPAN_ADOPT_STATUS_NO_QUALIFIED_ROW_V1
        } else {
            STATIC_SEARCH_SPAN_ADOPT_STATUS_UNQUALIFIED_SELECTOR_V1
        };
        // SAFETY: no source row can have this out-of-u16 selector. Both the
        // empty and nonempty private-table paths return before any pointer use.
        let private = unsafe {
            fre_aot_static_search_span_adopt_qualification_raw_v1(
                ptr::without_provenance_mut::<RawStaticSearchSpanAdoptionOutputV1>(1),
                unrepresentable_selector,
                ptr::without_provenance::<u8>(3),
                ptr::without_provenance::<u8>(5),
                ptr::without_provenance::<u8>(7),
                ptr::without_provenance::<u8>(9),
            )
        };
        assert_eq!(private, expected_status);
        assert_eq!(
            implementation::verified_entry_conversion_count(),
            conversions_before
        );
        assert!(!ptr::eq(
            &raw const PRODUCTION_STATIC_SEARCH_SPAN_REGISTRY_V1,
            &raw const PRIVATE_QUALIFICATION_STATIC_SEARCH_SPAN_REGISTRY_V1,
        ));
    }

    #[test]
    fn safe_adapter_preserves_no_qualified_row_status() {
        let result = adopt_linked_static_search_span_v1(|output| {
            assert!(!output.is_null());
            STATIC_SEARCH_SPAN_ADOPT_STATUS_NO_QUALIFIED_ROW_V1
        });
        assert!(matches!(
            result,
            Err(StaticSearchSpanAdoptionErrorV1::NoQualifiedStaticSearchSpanRow)
        ));
    }

    #[test]
    fn safe_adapter_accepts_only_exact_registry_owned_successes() {
        let registry = StaticSearchSpanRegistryV1::<u64, 2>::new();
        let foreign_registry = StaticSearchSpanRegistryV1::<u64, 2>::new();
        let bytes = expectation(1);
        let tuple = symbols(1, 1);
        let registered = registry
            .adopt(&bytes, tuple, || Ok(17))
            .expect("test registration");
        assert_eq!(
            resolve_search_span_adoption_output(
                &registry,
                STATIC_SEARCH_SPAN_ADOPT_STATUS_OK_V1,
                ptr::from_ref(registered),
            ),
            Ok(&17)
        );
        assert_eq!(
            resolve_search_span_adoption_output(
                &foreign_registry,
                STATIC_SEARCH_SPAN_ADOPT_STATUS_OK_V1,
                ptr::from_ref(registered),
            ),
            Err(StaticSearchSpanAdoptionErrorV1::UnregisteredVerifiedHandle)
        );
        assert_eq!(
            resolve_search_span_adoption_output(
                &registry,
                STATIC_SEARCH_SPAN_ADOPT_STATUS_OK_V1,
                ptr::without_provenance(1),
            ),
            Err(StaticSearchSpanAdoptionErrorV1::UnregisteredVerifiedHandle)
        );
        assert_eq!(
            resolve_search_span_adoption_output(
                &registry,
                STATIC_SEARCH_SPAN_ADOPT_STATUS_OK_V1,
                ptr::null(),
            ),
            Err(StaticSearchSpanAdoptionErrorV1::MissingVerifiedHandle)
        );
    }

    #[test]
    fn registry_refuses_expectation_and_symbol_splices_after_first_use() {
        let registry = StaticSearchSpanRegistryV1::<u64, 2>::new();
        let bytes = expectation(1);
        let tuple = symbols(1, 1);
        let initializations = AtomicUsize::new(0);
        assert_eq!(
            registry.adopt(&bytes, tuple, || {
                initializations.fetch_add(1, Ordering::SeqCst);
                Ok(17)
            }),
            Ok(&17)
        );
        assert_eq!(
            registry.adopt(&expectation(2), tuple, || Ok(19)),
            Err(StaticSearchSpanVerifyErrorV1::AlreadyInitializedForDifferentExpectation)
        );
        assert_eq!(
            registry.adopt(&bytes, symbols(1, 2), || Ok(19)),
            Err(StaticSearchSpanVerifyErrorV1::AlreadyInitializedForDifferentSymbols)
        );
        assert_eq!(
            registry.adopt(&bytes, tuple, || {
                initializations.fetch_add(1, Ordering::SeqCst);
                Ok(19)
            }),
            Ok(&17)
        );
        assert_eq!(initializations.load(Ordering::SeqCst), 1);

        let sticky = StaticSearchSpanRegistryV1::<u64, 2>::new();
        assert_eq!(
            sticky.adopt(&bytes, tuple, || {
                Err(StaticSearchSpanVerifyErrorV1::EntryAddressMismatch)
            }),
            Err(StaticSearchSpanVerifyErrorV1::EntryAddressMismatch)
        );
        assert_eq!(
            sticky.adopt(&bytes, tuple, || Ok(23)),
            Err(StaticSearchSpanVerifyErrorV1::EntryAddressMismatch)
        );

        let full = StaticSearchSpanRegistryV1::<u64, 1>::new();
        assert_eq!(full.adopt(&expectation(1), symbols(1, 1), || Ok(1)), Ok(&1));
        assert_eq!(
            full.adopt(&expectation(2), symbols(2, 2), || Ok(2)),
            Err(StaticSearchSpanVerifyErrorV1::StaticRegistryFull { limit: 1 })
        );
    }

    #[test]
    fn registry_sticks_panics_and_rejects_reentrant_initialization() {
        let panic_registry = StaticSearchSpanRegistryV1::<u64, 2>::new();
        let bytes = expectation(1);
        let tuple = symbols(1, 1);
        assert_eq!(
            panic_registry.adopt(&bytes, tuple, || panic!("injected")),
            Err(StaticSearchSpanVerifyErrorV1::StaticRegistryInitializationPanicked)
        );
        assert_eq!(
            panic_registry.adopt(&bytes, tuple, || Ok(17)),
            Err(StaticSearchSpanVerifyErrorV1::StaticRegistryInitializationPanicked)
        );

        let reentrant_registry = StaticSearchSpanRegistryV1::<u64, 2>::new();
        assert_eq!(
            reentrant_registry.adopt(&bytes, tuple, || {
                reentrant_registry
                    .adopt(&expectation(2), symbols(2, 2), || Ok(23))
                    .map(|_| 19)
            }),
            Err(StaticSearchSpanVerifyErrorV1::StaticRegistryReentrantInitialization)
        );
    }

    #[test]
    fn concurrent_same_identity_initializes_exactly_once() {
        let registry = Arc::new(StaticSearchSpanRegistryV1::<u64, 2>::new());
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
            assert_eq!(worker.join().expect("Search registry worker"), Ok(17));
        }
        assert_eq!(initializations.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn preflight_completes_before_native_invocation_and_returns_its_accounting() {
        let calls = AtomicUsize::new(0);
        let haystack = b"xxneedlezz";
        let window = SearchWindow::new(2, 8);
        let result = checked_static_search_span_v1(
            6,
            haystack,
            window,
            LiteralSearchLimits::unlimited(),
            || {
                calls.fetch_add(1, Ordering::SeqCst);
                RawSearchCallV1 {
                    status: 1,
                    result: RawSearchResultV1 { start: 2, end: 8 },
                }
            },
        )
        .expect("checked Span call");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(result.0, Some(MatchSpan::new(2, 8)));
        assert_eq!(result.1.needle_bytes, 6);
        assert_eq!(result.1.searched_bytes, 6);
        assert_eq!(result.1.linear_terms, 12);
        assert_eq!(result.1.scratch_bytes, 0);

        for (bad_window, limits) in [
            (SearchWindow::new(9, 8), LiteralSearchLimits::unlimited()),
            (
                SearchWindow::new(0, haystack.len() + 1),
                LiteralSearchLimits::unlimited(),
            ),
            (
                SearchWindow::new(0, haystack.len()),
                LiteralSearchLimits {
                    max_linear_terms: 1,
                },
            ),
        ] {
            let before = calls.load(Ordering::SeqCst);
            let refused = checked_static_search_span_v1(6, haystack, bad_window, limits, || {
                calls.fetch_add(1, Ordering::SeqCst);
                RawSearchCallV1 {
                    status: 0,
                    result: RawSearchResultV1::poisoned(),
                }
            });
            assert!(matches!(
                refused,
                Err(StaticSearchSpanCallErrorV1::Preflight(_))
            ));
            assert_eq!(calls.load(Ordering::SeqCst), before);
        }
    }

    #[test]
    fn exact_span_poison_status_and_width_contract_is_preserved() {
        let haystack = b"xxneedlezz";
        let window = SearchWindow::new(0, haystack.len());
        let invoke = |raw| {
            checked_static_search_span_v1(
                6,
                haystack,
                window,
                LiteralSearchLimits::unlimited(),
                || raw,
            )
        };
        assert_eq!(
            invoke(RawSearchCallV1 {
                status: 0,
                result: RawSearchResultV1::poisoned(),
            })
            .expect("no match")
            .0,
            None
        );
        assert_eq!(
            invoke(RawSearchCallV1 {
                status: 1,
                result: RawSearchResultV1 { start: 2, end: 8 },
            })
            .expect("exact match")
            .0,
            Some(MatchSpan::new(2, 8))
        );
        for invalid in [
            RawSearchCallV1 {
                status: 0,
                result: RawSearchResultV1 { start: 2, end: 8 },
            },
            RawSearchCallV1 {
                status: 1,
                result: RawSearchResultV1 { start: 2, end: 9 },
            },
            RawSearchCallV1 {
                status: 7,
                result: RawSearchResultV1 { start: 2, end: 8 },
            },
        ] {
            assert!(matches!(
                invoke(invalid),
                Err(StaticSearchSpanCallErrorV1::Decode(_))
            ));
        }
    }

    #[test]
    fn mapped_metadata_requires_exact_canonical_equality() {
        let fixture = static_search_span_fixture_v1();
        let expected = fre_aot_search_contract::inspect_search_metadata_v1(&fixture.metadata)
            .expect("fixture metadata");
        assert_eq!(
            validate_mapped_search_span_metadata_v1(&fixture.metadata, expected),
            Ok(expected)
        );
        for offset in 0..fixture.metadata.len() {
            let mut changed = fixture.metadata;
            changed[offset] ^= 1;
            assert!(
                validate_mapped_search_span_metadata_v1(&changed, expected).is_err(),
                "mapped metadata mutation {offset} was accepted"
            );
        }
    }

    #[test]
    fn raw_addresses_abis_and_retention_are_explicit() {
        assert_ne!(symbols(1, 1), symbols(1, 2));
        assert_eq!(
            mem::size_of::<RawSearchResultV1>(),
            2 * mem::size_of::<usize>()
        );
        assert_eq!(
            mem::size_of::<StaticSearchSpanEntryV1>(),
            mem::size_of::<usize>()
        );
        assert_eq!(
            mem::size_of::<StaticSearchSpanLinkedAddressV1>(),
            mem::size_of::<usize>()
        );
        assert_eq!(
            mem::size_of::<RawStaticSearchSpanAdoptionOutputV1>(),
            mem::size_of::<*const core::ffi::c_void>()
        );

        let accounting =
            StaticSearchSpanInspectionAccountingV1::checked(256, 3).expect("bounded accounting");
        assert_eq!(accounting.expectation_bytes(), 584);
        assert_eq!(accounting.metadata_bytes(), 216);
        assert_eq!(accounting.payload_bytes(), 256);
        assert_eq!(accounting.payload_bytes_hashed(), 256);
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
                .static_registry_capacity_bytes_per_registry()
                .checked_mul(accounting.static_registry_count())
                .expect("capacity product")
        );
        assert_eq!(
            accounting.static_registry_capacity_bytes_per_registry(),
            accounting
                .registry_slot_bytes()
                .checked_mul(accounting.static_registry_capacity_entries())
                .expect("per-registry capacity product")
        );
        assert_eq!(
            accounting.retained_bytes(),
            accounting.static_registry_capacity_bytes()
        );
    }

    #[test]
    fn v8_session_creation_is_platform_independent_and_preserves_the_handle() {
        let fixture = static_search_span_fixture_v1();
        let expected = ExpectedStaticSearchSpanV1::from_source_qualified_bytes(
            &fixture.expectation,
            &fixture.row,
            fixture.row.compile_identity(),
        )
        .expect("source-qualified V8 fixture");
        let handle = VerifiedStaticSearchSpanV1 {
            expected,
            entry: dummy_entry,
            row_selector: fixture.row.selector(),
            accounting: StaticSearchSpanInspectionAccountingV1::checked(256, 0)
                .expect("bounded test accounting"),
        };

        assert_eq!(
            handle.backend_version(),
            fre_aot_search_contract::SEARCH_BACKEND_VERSION_V1
        );
        assert!(!handle.requires_thread_session());
        let session = handle
            .begin_current_thread_session()
            .expect("V8 session creation must not consult Linux SVE state");
        assert!(ptr::eq(session.handle(), &raw const handle));
        assert_eq!(session.live_literal_bytes, handle.live_literal_bytes());
        assert!(ptr::fn_addr_eq(session.entry, handle.entry));
    }

    #[cfg(all(
        feature = "linked-search-span-v1",
        target_arch = "aarch64",
        target_pointer_width = "64",
        target_endian = "little",
        any(target_os = "linux", target_os = "macos")
    ))]
    #[test]
    fn v8_session_cached_entry_and_width_preserve_checked_call_semantics() {
        let fixture = static_search_span_fixture_v1();
        let expected = ExpectedStaticSearchSpanV1::from_source_qualified_bytes(
            &fixture.expectation,
            &fixture.row,
            fixture.row.compile_identity(),
        )
        .expect("source-qualified V8 fixture");
        let handle = VerifiedStaticSearchSpanV1 {
            expected,
            entry: session_test_entry,
            row_selector: fixture.row.selector(),
            accounting: StaticSearchSpanInspectionAccountingV1::checked(256, 0)
                .expect("bounded test accounting"),
        };
        let session = handle
            .begin_current_thread_session()
            .expect("V8 session creation must not consult Linux SVE state");
        let haystack = [b'x'; 24];
        let search_window = SearchWindow::new(2, 20);
        let limits = LiteralSearchLimits::unlimited();

        SESSION_TEST_ENTRY_CALLS.store(0, Ordering::SeqCst);
        let handle_search = handle
            .search(&haystack, search_window, limits)
            .expect("checked handle search");
        let session_search = session
            .search(&haystack, search_window, limits)
            .expect("checked session search");
        assert_eq!(session_search, handle_search);
        assert_eq!(session_search.0, Some(MatchSpan::new(2, 18)));
        assert_eq!(session_search.1.needle_bytes, 16);
        assert_eq!(session_search.1.searched_bytes, 18);
        assert_eq!(session_search.1.linear_terms, 34);
        assert_eq!(session_search.1.scratch_bytes, 0);

        let handle_find = handle.find(&haystack, limits).expect("checked handle find");
        let session_find = session
            .find(&haystack, limits)
            .expect("checked session find");
        assert_eq!(session_find, handle_find);
        assert_eq!(session_find.0, Some(MatchSpan::new(0, 16)));
        assert_eq!(session_find.1.needle_bytes, 16);
        assert_eq!(session_find.1.searched_bytes, haystack.len());
        assert_eq!(session_find.1.linear_terms, haystack.len() + 16);
        assert_eq!(session_find.1.scratch_bytes, 0);
        assert_eq!(SESSION_TEST_ENTRY_CALLS.load(Ordering::SeqCst), 4);

        for invalid_window in [
            SearchWindow::new(8, 7),
            SearchWindow::new(0, haystack.len() + 1),
        ] {
            let calls_before = SESSION_TEST_ENTRY_CALLS.load(Ordering::SeqCst);
            assert!(matches!(
                session.search(&haystack, invalid_window, limits),
                Err(StaticSearchSpanCallErrorV1::Preflight(_))
            ));
            assert_eq!(
                SESSION_TEST_ENTRY_CALLS.load(Ordering::SeqCst),
                calls_before
            );
        }
    }
}
