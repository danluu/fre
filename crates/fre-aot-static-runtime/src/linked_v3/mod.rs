//! Static final-image adoption for optimizing Count-v3.

use core::{mem, ptr, slice};

use fre_aot_aarch64::{
    AotCountCpuFeatures, AotCountMappedMetadataV3, CountAuditReportV3, CountEmitLimitsV3,
    audit_count_mapped_code_v3,
};
use fre_aot_count_contract::v3::{
    ClaimedCountMetadataV3, CountGeneralEligibilityTupleV3, METADATA_BYTES_V3,
    STATIC_COUNT_EXPECTATION_BYTES_V3, inspect_count_metadata_v3,
};
use fre_aot_optimizer::decode_count_recipe_v3;
use fre_kernel_ir::{
    AggregateExecutionLimits, AggregateOutput, Count, ValidateLimits, build_exact_aggregate,
    preflight_exact_aggregate,
};
use sha2::{Digest, Sha256};

use crate::{
    StaticCountCallErrorV3, StaticCountContractFieldV3, StaticCountVerifyErrorV3,
    expected_v3::ExpectedStaticCountV3, support_v3,
};

#[cfg(all(
    feature = "linked-count-v3",
    target_arch = "aarch64",
    target_os = "macos",
    target_pointer_width = "64",
    target_endian = "little"
))]
mod macos_aarch64;
#[cfg(all(
    feature = "linked-count-v3",
    target_arch = "aarch64",
    target_os = "macos",
    target_pointer_width = "64",
    target_endian = "little"
))]
use macos_aarch64 as platform;

#[cfg(all(
    feature = "linked-count-v3",
    target_arch = "aarch64",
    target_os = "linux",
    target_pointer_width = "64",
    target_endian = "little"
))]
mod linux_aarch64;
#[cfg(all(
    feature = "linked-count-v3",
    target_arch = "aarch64",
    target_os = "linux",
    target_pointer_width = "64",
    target_endian = "little"
))]
use linux_aarch64 as platform;

#[cfg(not(any(
    all(
        feature = "linked-count-v3",
        target_arch = "aarch64",
        target_os = "macos",
        target_pointer_width = "64",
        target_endian = "little"
    ),
    all(
        feature = "linked-count-v3",
        target_arch = "aarch64",
        target_os = "linux",
        target_pointer_width = "64",
        target_endian = "little"
    )
)))]
mod unavailable;
#[cfg(not(any(
    all(
        feature = "linked-count-v3",
        target_arch = "aarch64",
        target_os = "macos",
        target_pointer_width = "64",
        target_endian = "little"
    ),
    all(
        feature = "linked-count-v3",
        target_arch = "aarch64",
        target_os = "linux",
        target_pointer_width = "64",
        target_endian = "little"
    )
)))]
use unavailable as platform;

const POISONED_COUNT_RESULT_V3: u64 = u64::MAX;
const HARD_MAX_MAPPED_PAYLOAD_BYTES_V3: usize = 4 << 20;
static EMPTY_HAYSTACK_SENTINEL_V3: u8 = 0;

/// Raw result slot fixed by Count call ABI schema 2.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
#[doc(hidden)]
pub struct RawAggregateResultV3 {
    pub value: u64,
}

/// Raw entry type retained only after final mapped-code verification.
#[allow(
    unsafe_code,
    reason = "the type describes the audited three-argument native ABI"
)]
#[doc(hidden)]
pub type StaticAggregateEntryV3 =
    unsafe extern "C" fn(*const u8, usize, *mut RawAggregateResultV3) -> u64;

const _: () = assert!(mem::size_of::<StaticAggregateEntryV3>() == mem::size_of::<usize>());
const _: () = assert!(mem::size_of::<RawAggregateResultV3>() == 8);
const _: () = assert!(mem::align_of::<RawAggregateResultV3>() == 8);

/// Untrusted process-lifetime addresses for the production adopter.
///
/// Constructing this inert value reads nothing. The unsafe adopter owns all
/// immutable-range, fixed-record, target, digest, KIR, recipe, and code checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StaticCountLinkedAddressesV3 {
    addresses: LinkedAddressesV3,
}

impl StaticCountLinkedAddressesV3 {
    #[must_use]
    pub const fn from_exposed_addresses(
        expectation: usize,
        payload: usize,
        metadata: usize,
        entry: usize,
    ) -> Self {
        Self {
            addresses: LinkedAddressesV3 {
                expectation,
                payload,
                metadata,
                entry,
            },
        }
    }
}

/// Qualification-only address carrier, intentionally type-disjoint from the
/// production adopter.
#[cfg(feature = "count-v3-qualification-private")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub struct StaticCountQualificationLinkedAddressesV3 {
    addresses: LinkedAddressesV3,
}

/// Borrowed facade proof supplied to the qualification-only adopter.
///
/// The adopter compares all three values after complete byte/code inspection
/// and before private authority is granted. Production has no analogous
/// caller-supplied authority input.
#[cfg(feature = "count-v3-qualification-private")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub struct StaticCountQualificationFacadeBindingV3<'a> {
    literal: &'a [u8],
    semantic_binding_identity: [u8; 32],
    planning_receipt_identity: [u8; 32],
}

#[cfg(feature = "count-v3-qualification-private")]
impl<'a> StaticCountQualificationFacadeBindingV3<'a> {
    #[must_use]
    pub const fn new(
        literal: &'a [u8],
        semantic_binding_identity: [u8; 32],
        planning_receipt_identity: [u8; 32],
    ) -> Self {
        Self {
            literal,
            semantic_binding_identity,
            planning_receipt_identity,
        }
    }
}

#[cfg(feature = "count-v3-qualification-private")]
impl StaticCountQualificationLinkedAddressesV3 {
    #[must_use]
    pub const fn from_exposed_addresses(
        expectation: usize,
        payload: usize,
        metadata: usize,
        entry: usize,
    ) -> Self {
        Self {
            addresses: LinkedAddressesV3 {
                expectation,
                payload,
                metadata,
                entry,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LinkedAddressesV3 {
    expectation: usize,
    payload: usize,
    metadata: usize,
    entry: usize,
}

/// Cold-path inspection accounting retained by every authenticated handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StaticCountInspectionAccountingV3 {
    pub expectation_bytes_copied: u32,
    pub metadata_bytes_copied: u32,
    pub payload_bytes_hashed: u32,
    pub vm_query_input_bytes_upper_bound: u32,
    pub vm_regions_checked: u32,
    pub audit: CountAuditReportV3,
}

#[derive(Debug)]
struct VerifiedCoreV3 {
    entry: StaticAggregateEntryV3,
    literal_manifest: [u8; 32],
    literal_bytes: u8,
    semantic_binding_identity: [u8; 32],
    planning_receipt_identity: [u8; 32],
    expectation_identity: [u8; 32],
    compile_identity: [u8; 32],
    object_identity: [u8; 32],
    eligibility_tuple: CountGeneralEligibilityTupleV3,
    accounting: StaticCountInspectionAccountingV3,
}

/// Production-only callable Count-v3 handle.
///
/// Its fields are private and the production adopter can construct it only
/// after an exact source-row match. The currently empty production table means
/// no ordinary build can yet obtain this value.
#[derive(Debug)]
pub struct VerifiedStaticCountV3 {
    core: VerifiedCoreV3,
}

/// Qualification-only callable handle.
///
/// This distinct type cannot be passed where production evidence is required.
#[cfg(feature = "count-v3-qualification-private")]
#[derive(Debug)]
#[doc(hidden)]
pub struct VerifiedStaticCountQualificationV3 {
    core: VerifiedCoreV3,
}

macro_rules! verified_accessors_v3 {
    ($type:ty) => {
        impl $type {
            /// Invoke the already-verified whole-haystack non-overlapping
            /// counter. This path performs one value preflight and one direct
            /// native call; it performs no lookup, compilation, allocation,
            /// target selection, recipe decoding, or code audit.
            #[inline]
            pub fn count(
                &self,
                haystack: &[u8],
                limits: AggregateExecutionLimits,
            ) -> Result<u64, StaticCountCallErrorV3> {
                self.core.count(haystack, limits)
            }

            #[must_use]
            pub fn literal(&self) -> &[u8] {
                &self.core.literal_manifest[..usize::from(self.core.literal_bytes)]
            }

            #[must_use]
            pub const fn semantic_binding_identity(&self) -> &[u8; 32] {
                &self.core.semantic_binding_identity
            }

            #[must_use]
            pub const fn planning_receipt_identity(&self) -> &[u8; 32] {
                &self.core.planning_receipt_identity
            }

            #[must_use]
            pub const fn expectation_identity(&self) -> &[u8; 32] {
                &self.core.expectation_identity
            }

            #[must_use]
            pub const fn compile_identity(&self) -> &[u8; 32] {
                &self.core.compile_identity
            }

            #[must_use]
            pub const fn object_identity(&self) -> &[u8; 32] {
                &self.core.object_identity
            }

            #[must_use]
            pub const fn eligibility_tuple(&self) -> CountGeneralEligibilityTupleV3 {
                self.core.eligibility_tuple
            }

            #[must_use]
            pub const fn inspection_accounting(&self) -> StaticCountInspectionAccountingV3 {
                self.core.accounting
            }
        }
    };
}

verified_accessors_v3!(VerifiedStaticCountV3);
#[cfg(feature = "count-v3-qualification-private")]
verified_accessors_v3!(VerifiedStaticCountQualificationV3);

impl VerifiedCoreV3 {
    #[allow(
        unsafe_code,
        reason = "the private entry exists only after complete static mapped-code verification"
    )]
    #[inline]
    fn count(
        &self,
        haystack: &[u8],
        limits: AggregateExecutionLimits,
    ) -> Result<u64, StaticCountCallErrorV3> {
        let literal_len = usize::from(self.literal_bytes);
        let upper =
            preflight_exact_aggregate(haystack.len(), literal_len, AggregateOutput::Count, limits)?;
        let haystack_pointer = if haystack.is_empty() {
            ptr::addr_of!(EMPTY_HAYSTACK_SENTINEL_V3)
        } else {
            haystack.as_ptr()
        };
        let mut result = RawAggregateResultV3 {
            value: POISONED_COUNT_RESULT_V3,
        };
        // SAFETY: this entry exists only after exact mapped-code audit and the
        // slices/result slot satisfy the fixed three-argument ABI.
        let status =
            unsafe { (self.entry)(haystack_pointer, haystack.len(), ptr::addr_of_mut!(result)) };
        decode_count_result_v3(
            status,
            result.value,
            upper.count,
            haystack.len(),
            literal_len,
        )
    }
}

/// Adopt one production-linked image.
///
/// The empty production table is checked before any supplied address is read.
///
/// # Safety
///
/// Every address must name the exact process-lifetime final-image symbol
/// described by the linked expectation, without interposition, unload, remap,
/// or mutation for the lifetime of the returned handle.
#[allow(
    unsafe_code,
    reason = "this is the sole production raw-address adoption boundary"
)]
pub unsafe fn adopt_linked_static_count_v3(
    linked: StaticCountLinkedAddressesV3,
) -> Result<VerifiedStaticCountV3, StaticCountVerifyErrorV3> {
    support_v3::require_nonempty_production_authority()?;
    if !cfg!(feature = "linked-count-v3") {
        return Err(StaticCountVerifyErrorV3::LinkedCountV3FeatureDisabled);
    }
    // SAFETY: forwarded caller contract; `adopt_core_v3` performs every check
    // before the address-to-function conversion.
    let core = unsafe { adopt_core_v3(linked.addresses, AuthorityV3::Production)? };
    Ok(VerifiedStaticCountV3 { core })
}

/// Adopt one image solely for qualification evidence gathering.
///
/// This symbol, address type, authority mode, and returned handle are all
/// disjoint from production. The exact full eligibility tuple is retained on
/// the handle but is never inserted into the production table.
///
/// # Safety
///
/// The same process-lifetime final-image contract as
/// [`adopt_linked_static_count_v3`] applies. In addition, `facade` must have
/// been projected from the live fixed-policy planned candidate that will own
/// every use of the returned qualification handle, and that owner must remain
/// alive and immutable for those uses. The safe FRE qualification wrapper
/// retains this owner and repeats the complete binding check.
#[cfg(feature = "count-v3-qualification-private")]
#[doc(hidden)]
#[allow(
    unsafe_code,
    reason = "this is the sole qualification-private raw-address adoption boundary"
)]
pub unsafe fn adopt_linked_static_count_qualification_v3(
    linked: StaticCountQualificationLinkedAddressesV3,
    facade: StaticCountQualificationFacadeBindingV3<'_>,
) -> Result<VerifiedStaticCountQualificationV3, StaticCountVerifyErrorV3> {
    // SAFETY: forwarded caller contract; authority remains private.
    let core = unsafe { adopt_core_v3(linked.addresses, AuthorityV3::Qualification { facade })? };
    Ok(VerifiedStaticCountQualificationV3 { core })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuthorityV3<'a> {
    Production,
    #[cfg(feature = "count-v3-qualification-private")]
    Qualification {
        facade: StaticCountQualificationFacadeBindingV3<'a>,
    },
}

#[allow(
    unsafe_code,
    reason = "copies and views happen only after platform range verification under the caller's process-lifetime contract"
)]
unsafe fn adopt_core_v3(
    linked: LinkedAddressesV3,
    authority: AuthorityV3<'_>,
) -> Result<VerifiedCoreV3, StaticCountVerifyErrorV3> {
    let expectation_regions = platform::verify_range(
        linked.expectation,
        STATIC_COUNT_EXPECTATION_BYTES_V3,
        platform::RegionPurposeV3::Expectation,
    )?;
    // SAFETY: the exact fixed range is verified read-only and process-lifetime.
    let expectation_bytes =
        unsafe { copy_fixed_array::<STATIC_COUNT_EXPECTATION_BYTES_V3>(linked.expectation) };
    let expected = ExpectedStaticCountV3::inspect(&expectation_bytes)?;

    let metadata_regions = platform::verify_range(
        linked.metadata,
        METADATA_BYTES_V3,
        platform::RegionPurposeV3::Metadata,
    )?;
    // SAFETY: the exact fixed range is verified read-only and process-lifetime.
    let metadata_bytes = unsafe { copy_fixed_array::<METADATA_BYTES_V3>(linked.metadata) };
    let metadata = inspect_count_metadata_v3(&metadata_bytes)?;

    let payload_bytes = bounded_payload_bytes_v3(metadata.payload_bytes())?;
    let payload_regions = platform::verify_range(
        linked.payload,
        payload_bytes,
        platform::RegionPurposeV3::Payload,
    )?;
    let entry_offset = usize::try_from(metadata.entry_offset())
        .map_err(|_| StaticCountVerifyErrorV3::AddressRangeOverflow)?;
    require_entry_address_v3(linked.payload, entry_offset, linked.entry)?;
    require_thread_safe_asimd_handle_v3(
        metadata.actual_features(),
        metadata.sve_vector_length_bytes(),
    )?;
    platform::require_host_contract(
        metadata.actual_features(),
        metadata.sve_vector_length_bytes(),
    )?;

    // SAFETY: the complete nonempty range is verified RX and the unsafe caller
    // promises stable process-lifetime provenance.
    let payload = unsafe {
        slice::from_raw_parts(
            ptr::with_exposed_provenance::<u8>(linked.payload),
            payload_bytes,
        )
    };
    let inert = inspect_inert_candidate_v3(expected, metadata, payload)?;

    let eligibility_tuple = inert.eligibility_tuple;
    match authority {
        AuthorityV3::Production => support_v3::require_production_tuple(eligibility_tuple)?,
        #[cfg(feature = "count-v3-qualification-private")]
        AuthorityV3::Qualification { facade } => {
            require(
                facade.literal == inert.literal(),
                StaticCountContractFieldV3::Literal,
            )?;
            require(
                facade.semantic_binding_identity == *expected.semantic_binding_identity(),
                StaticCountContractFieldV3::SemanticBindingIdentity,
            )?;
            require(
                facade.planning_receipt_identity == *expected.planning_receipt_identity(),
                StaticCountContractFieldV3::PlanningReceiptIdentity,
            )?;
            if !support_v3::qualification_accepts_inspected_tuple(eligibility_tuple) {
                return Err(StaticCountVerifyErrorV3::EligibilityTupleNotAuthorized);
            }
        }
    }

    let vm_regions_checked = expectation_regions
        .checked_add(metadata_regions)
        .and_then(|regions| regions.checked_add(payload_regions))
        .and_then(|regions| u32::try_from(regions).ok())
        .ok_or(StaticCountVerifyErrorV3::InspectionAccountingOverflow)?;
    // SAFETY: this is deliberately last, after immutable-range, ABI, exact
    // entry offset, host, digest, semantic, recipe, code, and authority checks.
    let entry = unsafe { entry_from_verified_address(linked.entry) };
    Ok(VerifiedCoreV3 {
        entry,
        literal_manifest: inert.literal_manifest,
        literal_bytes: inert.literal_bytes,
        semantic_binding_identity: *expected.semantic_binding_identity(),
        planning_receipt_identity: *expected.planning_receipt_identity(),
        expectation_identity: *expected.expectation_identity(),
        compile_identity: *expected.compile_identity(),
        object_identity: *expected.object_identity(),
        eligibility_tuple,
        accounting: StaticCountInspectionAccountingV3 {
            expectation_bytes_copied: u32::try_from(STATIC_COUNT_EXPECTATION_BYTES_V3)
                .expect("fixed expectation width"),
            metadata_bytes_copied: u32::try_from(METADATA_BYTES_V3).expect("fixed metadata width"),
            payload_bytes_hashed: u32::try_from(payload_bytes)
                .map_err(|_| StaticCountVerifyErrorV3::InspectionAccountingOverflow)?,
            vm_query_input_bytes_upper_bound: platform::VM_QUERY_INPUT_BYTES_UPPER_BOUND_V3,
            vm_regions_checked,
            audit: inert.audit,
        },
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InertInspectionV3 {
    literal_manifest: [u8; 32],
    literal_bytes: u8,
    eligibility_tuple: CountGeneralEligibilityTupleV3,
    audit: CountAuditReportV3,
}

impl InertInspectionV3 {
    fn literal(&self) -> &[u8] {
        &self.literal_manifest[..usize::from(self.literal_bytes)]
    }
}

/// Complete byte-level validation shared by mapped adoption and inert
/// mutation tests. It creates no callable and consults no authority table.
fn inspect_inert_candidate_v3(
    expected: ExpectedStaticCountV3,
    metadata: ClaimedCountMetadataV3,
    payload: &[u8],
) -> Result<InertInspectionV3, StaticCountVerifyErrorV3> {
    require(
        metadata == expected.metadata(),
        StaticCountContractFieldV3::Metadata,
    )?;
    require(
        metadata.compile_identity() == expected.compile_identity(),
        StaticCountContractFieldV3::CompileIdentity,
    )?;
    if payload.len() != bounded_payload_bytes_v3(metadata.payload_bytes())? {
        return Err(StaticCountVerifyErrorV3::ContractMismatch {
            field: StaticCountContractFieldV3::MappedCode,
        });
    }
    let payload_digest: [u8; 32] = Sha256::digest(payload).into();
    if &payload_digest != metadata.payload_sha256() {
        return Err(StaticCountVerifyErrorV3::PayloadDigestMismatch);
    }
    let code_bytes = usize::try_from(metadata.code_bytes())
        .map_err(|_| StaticCountVerifyErrorV3::AddressRangeOverflow)?;
    let mapped_code =
        payload
            .get(..code_bytes)
            .ok_or(StaticCountVerifyErrorV3::ContractMismatch {
                field: StaticCountContractFieldV3::MappedCode,
            })?;
    if payload[code_bytes..].iter().any(|byte| *byte != 0) {
        return Err(StaticCountVerifyErrorV3::ContractMismatch {
            field: StaticCountContractFieldV3::MappedCode,
        });
    }

    let literal_len = usize::try_from(metadata.literal_bytes())
        .map_err(|_| StaticCountVerifyErrorV3::AddressRangeOverflow)?;
    let literal = metadata.literal_manifest().get(..literal_len).ok_or(
        StaticCountVerifyErrorV3::ContractMismatch {
            field: StaticCountContractFieldV3::Literal,
        },
    )?;
    let program = build_exact_aggregate::<Count>(literal, ValidateLimits::default())?;
    require(
        program.cache_identity().as_bytes() == metadata.program_identity(),
        StaticCountContractFieldV3::ProgramIdentity,
    )?;
    // Decode explicitly before the independent mapped-code auditor performs
    // its own closed decode/regeneration pass.
    let recipe = decode_count_recipe_v3(&program, metadata.canonical_recipe())?;
    require(
        recipe.identity().as_bytes() == metadata.recipe_identity(),
        StaticCountContractFieldV3::Recipe,
    )?;
    let mapped_metadata = mapped_metadata_v3(metadata)?;
    let audit = audit_count_mapped_code_v3(
        &program,
        metadata.canonical_recipe(),
        mapped_code,
        mapped_metadata,
        CountEmitLimitsV3::default(),
    )?;

    let literal_bytes =
        u8::try_from(literal_len).map_err(|_| StaticCountVerifyErrorV3::ContractMismatch {
            field: StaticCountContractFieldV3::Literal,
        })?;
    let mut literal_manifest = [0_u8; 32];
    literal_manifest[..literal_len].copy_from_slice(literal);
    Ok(InertInspectionV3 {
        literal_manifest,
        literal_bytes,
        eligibility_tuple: expected.eligibility_tuple(),
        audit,
    })
}

fn mapped_metadata_v3(
    metadata: ClaimedCountMetadataV3,
) -> Result<AotCountMappedMetadataV3, StaticCountVerifyErrorV3> {
    AotCountMappedMetadataV3::from_wire_parts(
        metadata.backend_version(),
        metadata.algorithm_version(),
        metadata.kir_semantics_version(),
        metadata.kir_abi_version(),
        metadata.output_kind(),
        metadata.architecture(),
        metadata.little_endian(),
        metadata.pointer_width(),
        metadata.target_abi(),
        metadata.actual_features(),
        metadata.allowed_features(),
        metadata.max_literal_bytes(),
        metadata.candidate_block_starts(),
        metadata.vector_bytes(),
        metadata.sve_vector_length_bytes(),
        *metadata.program_identity(),
        metadata.literal_bytes(),
        *metadata.recipe_identity(),
        *metadata.artifact_identity(),
        metadata.code_bytes(),
    )
    .ok_or(StaticCountVerifyErrorV3::ContractMismatch {
        field: StaticCountContractFieldV3::Metadata,
    })
}

/// This handle is freely movable between threads. Linux SVE VL is a mutable
/// per-thread property, so adding an SVE/SVE2 support row must introduce a
/// separate same-thread session/token instead of broadening this check.
fn require_thread_safe_asimd_handle_v3(
    actual_features: u64,
    sve_vector_length_bytes: u16,
) -> Result<(), StaticCountVerifyErrorV3> {
    let features = AotCountCpuFeatures::from_bits(actual_features)
        .ok_or(StaticCountVerifyErrorV3::RequiredCpuFeaturesUnavailable)?;
    if features.contains(AotCountCpuFeatures::SVE)
        || features.contains(AotCountCpuFeatures::SVE2)
        || sve_vector_length_bytes != 0
    {
        Err(StaticCountVerifyErrorV3::RequiredCpuFeaturesUnavailable)
    } else {
        Ok(())
    }
}

fn bounded_payload_bytes_v3(claimed: u32) -> Result<usize, StaticCountVerifyErrorV3> {
    let claimed =
        usize::try_from(claimed).map_err(|_| StaticCountVerifyErrorV3::AddressRangeOverflow)?;
    if claimed == 0 || claimed > HARD_MAX_MAPPED_PAYLOAD_BYTES_V3 {
        Err(StaticCountVerifyErrorV3::MappedPayloadExtentOutOfBounds {
            claimed,
            hard_maximum: HARD_MAX_MAPPED_PAYLOAD_BYTES_V3,
        })
    } else {
        Ok(claimed)
    }
}

fn require_entry_address_v3(
    payload: usize,
    entry_offset: usize,
    entry: usize,
) -> Result<(), StaticCountVerifyErrorV3> {
    let expected = payload
        .checked_add(entry_offset)
        .ok_or(StaticCountVerifyErrorV3::AddressRangeOverflow)?;
    if expected == entry {
        Ok(())
    } else {
        Err(StaticCountVerifyErrorV3::EntryAddressMismatch)
    }
}

fn require(
    condition: bool,
    field: StaticCountContractFieldV3,
) -> Result<(), StaticCountVerifyErrorV3> {
    if condition {
        Ok(())
    } else {
        Err(StaticCountVerifyErrorV3::ContractMismatch { field })
    }
}

#[allow(
    unsafe_code,
    reason = "caller first verifies the exact immutable fixed-size mapping"
)]
unsafe fn copy_fixed_array<const BYTES: usize>(address: usize) -> [u8; BYTES] {
    let mut bytes = [0_u8; BYTES];
    // SAFETY: upheld by this function's caller.
    unsafe {
        ptr::copy_nonoverlapping(
            ptr::with_exposed_provenance::<u8>(address),
            bytes.as_mut_ptr(),
            BYTES,
        );
    }
    bytes
}

#[allow(
    unsafe_code,
    reason = "called only after complete mapped-image and authority verification"
)]
unsafe fn entry_from_verified_address(address: usize) -> StaticAggregateEntryV3 {
    let pointer = ptr::with_exposed_provenance::<()>(address);
    // SAFETY: the complete entry proof precedes this sole conversion.
    unsafe { mem::transmute::<*const (), StaticAggregateEntryV3>(pointer) }
}

fn decode_count_result_v3(
    status: u64,
    value: u64,
    admitted_count_upper_bound: u64,
    haystack_len: usize,
    literal_len: usize,
) -> Result<u64, StaticCountCallErrorV3> {
    if status != 0 && value != POISONED_COUNT_RESULT_V3 {
        return Err(StaticCountCallErrorV3::NativeResultChangedOnFault { status, value });
    }
    match status {
        0 => {}
        1 => return Err(StaticCountCallErrorV3::BackendArithmeticOverflow),
        status => return Err(StaticCountCallErrorV3::BackendFault { status }),
    }
    if value == POISONED_COUNT_RESULT_V3 {
        return Err(StaticCountCallErrorV3::PoisonedNativeResult);
    }
    if value > admitted_count_upper_bound {
        return Err(StaticCountCallErrorV3::InvalidNativeCount {
            value,
            haystack_len,
            literal_len,
        });
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fre_aot_count_compiler::{
        CountCompileLimitsV3, CountCompileRequestV3, CountCompileTargetV3, CountObjectFormatV3,
        CountObjectLimitsV3, CountSemanticCandidateV3, FocusedCompiledCountV3, compile_count_v3,
        inspect_count_implementation_object_v3,
    };
    use fre_aot_optimizer::{CountV3RequiredIsa, CountV3TuningClass};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn compiled_fixture_v3() -> FocusedCompiledCountV3 {
        compile_count_v3(
            CountCompileRequestV3 {
                literal: b"needle",
                semantic_candidate: CountSemanticCandidateV3 {
                    manifest_identity: [1; 32],
                    policy_limits_identity: [2; 32],
                    semantic_binding_identity: [3; 32],
                    planning_receipt_identity: [4; 32],
                    object_binding_identity: [5; 32],
                    claimed_receipt_identity: [6; 32],
                    claimed_resource_receipt_identity: [7; 32],
                },
                target: CountCompileTargetV3 {
                    object_format: CountObjectFormatV3::MachOArm64,
                    tuning_class: CountV3TuningClass::AppleMSeries,
                    required_isa: CountV3RequiredIsa::Aarch64Neon128,
                },
            },
            CountCompileLimitsV3::default(),
        )
        .expect("inert optimizing Count-v3 fixture")
    }

    static DIRECT_ENTRY_CALLS_V3: AtomicUsize = AtomicUsize::new(0);

    #[allow(
        unsafe_code,
        reason = "ABI-compatible inert entry used only by the private call-shape test"
    )]
    unsafe extern "C" fn counted_dummy_entry_v3(
        _haystack: *const u8,
        _haystack_len: usize,
        result: *mut RawAggregateResultV3,
    ) -> u64 {
        DIRECT_ENTRY_CALLS_V3.fetch_add(1, Ordering::SeqCst);
        // SAFETY: the private caller supplies its initialized result slot.
        unsafe {
            (*result).value = 2;
        }
        0
    }

    #[test]
    #[allow(
        unsafe_code,
        reason = "source-empty authority proves refusal precedes address use"
    )]
    fn production_refuses_before_reading_any_address() {
        let linked = StaticCountLinkedAddressesV3::from_exposed_addresses(1, 2, 3, 4);
        // SAFETY: source-empty production authority must return before any
        // supplied address is inspected.
        assert_eq!(
            unsafe { adopt_linked_static_count_v3(linked) }.unwrap_err(),
            StaticCountVerifyErrorV3::NoProductionAuthority
        );
    }

    #[test]
    fn result_decoder_is_strict() {
        assert_eq!(decode_count_result_v3(0, 3, 3, 9, 3), Ok(3));
        assert!(matches!(
            decode_count_result_v3(0, 4, 3, 9, 3),
            Err(StaticCountCallErrorV3::InvalidNativeCount { .. })
        ));
        assert_eq!(
            decode_count_result_v3(7, 2, 3, 9, 3),
            Err(StaticCountCallErrorV3::NativeResultChangedOnFault {
                status: 7,
                value: 2
            })
        );
    }

    #[test]
    fn every_expectation_byte_mutation_is_refused() {
        let compiled = compiled_fixture_v3();
        let original = *compiled.expectation();
        for index in 0..original.len() {
            let mut changed = original;
            changed[index] ^= 1;
            assert!(
                ExpectedStaticCountV3::inspect(&changed).is_err(),
                "mutated expectation byte {index} was accepted"
            );
        }
    }

    #[test]
    fn metadata_and_payload_tampering_fail_before_a_callable() {
        let compiled = compiled_fixture_v3();
        let expected = ExpectedStaticCountV3::inspect(compiled.expectation()).unwrap();
        let inspection = inspect_count_implementation_object_v3(
            compiled.implementation_object().as_bytes(),
            CountObjectLimitsV3::default(),
        )
        .unwrap();
        let metadata = inspect_count_metadata_v3(inspection.metadata_bytes()).unwrap();
        assert!(inspect_inert_candidate_v3(expected, metadata, inspection.payload()).is_ok());

        let mut changed_payload = inspection.payload().to_vec();
        changed_payload[0] ^= 1;
        assert_eq!(
            inspect_inert_candidate_v3(expected, metadata, &changed_payload).unwrap_err(),
            StaticCountVerifyErrorV3::PayloadDigestMismatch
        );

        let mut changed_metadata = *inspection.metadata_bytes();
        // This lies within the canonical recipe. Whether the strict metadata
        // decoder or the exact expectation comparison rejects first, no code
        // audit or callable can be reached.
        changed_metadata[160] ^= 1;
        match inspect_count_metadata_v3(&changed_metadata) {
            Err(_) => {}
            Ok(changed) => assert!(matches!(
                inspect_inert_candidate_v3(expected, changed, inspection.payload()),
                Err(StaticCountVerifyErrorV3::ContractMismatch {
                    field: StaticCountContractFieldV3::Metadata
                })
            )),
        }
    }

    #[test]
    fn verified_value_path_makes_exactly_one_direct_entry_call() {
        let compiled = compiled_fixture_v3();
        let expected = ExpectedStaticCountV3::inspect(compiled.expectation()).unwrap();
        let mut literal_manifest = [0_u8; 32];
        literal_manifest[..6].copy_from_slice(b"needle");
        let core = VerifiedCoreV3 {
            entry: counted_dummy_entry_v3,
            literal_manifest,
            literal_bytes: 6,
            semantic_binding_identity: [1; 32],
            planning_receipt_identity: [2; 32],
            expectation_identity: [3; 32],
            compile_identity: [4; 32],
            object_identity: [5; 32],
            eligibility_tuple: expected.eligibility_tuple(),
            accounting: StaticCountInspectionAccountingV3 {
                expectation_bytes_copied: 0,
                metadata_bytes_copied: 0,
                payload_bytes_hashed: 0,
                vm_query_input_bytes_upper_bound: 0,
                vm_regions_checked: 0,
                audit: CountAuditReportV3::default(),
            },
        };
        DIRECT_ENTRY_CALLS_V3.store(0, Ordering::SeqCst);
        assert_eq!(
            core.count(b"............", AggregateExecutionLimits::unlimited()),
            Ok(2)
        );
        assert_eq!(DIRECT_ENTRY_CALLS_V3.load(Ordering::SeqCst), 1);
        assert_eq!(core.accounting.payload_bytes_hashed, 0);
    }
}
