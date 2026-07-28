use core::{mem, ptr, slice};

use fre_aot_aarch64::AotCountCpuFeatures;
use fre_aot_count_contract::{METADATA_BYTES_V2, STATIC_COUNT_EXPECTATION_BYTES_V2};
use sha2::{Digest, Sha256};

use crate::{
    StaticVerifyError,
    call::RawAggregateCallV2,
    expected::ExpectedStaticCountV2,
    linked::{
        AggregateEntryV2, CopiedExpectationV2, LinkedStaticCountSymbolsV2, StaticLinkedAddressV2,
        StaticRuntimeInspectionAccountingV2, raw_call, validate_mapped_metadata,
    },
};

#[allow(
    unsafe_code,
    reason = "these two reviewed declarations are the read-only Mach VM query and returned-port release boundary"
)]
unsafe extern "C" {
    fn mach_vm_region(
        target_task: libc::mach_port_t,
        address: *mut libc::mach_vm_address_t,
        size: *mut libc::mach_vm_size_t,
        flavor: libc::c_int,
        info: *mut libc::c_int,
        info_count: *mut libc::mach_msg_type_number_t,
        object_name: *mut libc::mach_port_t,
    ) -> libc::kern_return_t;

    fn mach_port_deallocate(
        task: libc::mach_port_t,
        name: libc::mach_port_t,
    ) -> libc::kern_return_t;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RegionPurpose {
    Payload,
    Metadata,
    Expectation,
}

#[repr(C)]
struct BasicInfo64 {
    protection: libc::vm_prot_t,
    max_protection: libc::vm_prot_t,
    inheritance: libc::c_int,
    shared: libc::c_int,
    reserved: libc::c_int,
    offset: u64,
    behavior: libc::c_int,
    user_wired_count: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Region {
    start: usize,
    bytes: usize,
    protection: i32,
    maximum_protection: i32,
}

static EMPTY_HAYSTACK_SENTINEL_V2: u8 = 0;
// This is a runtime VM-inspection defense-in-depth ceiling, not part of the
// Count-v2 wire contract. It bounds hostile mapped-range traversal before any
// payload bytes are viewed or hashed.
const HARD_MAX_MAPPED_PAYLOAD_BYTES_V2: usize = 4 << 20;
#[cfg(test)]
static VERIFIED_ENTRY_CONVERSIONS_V2: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[allow(
    unsafe_code,
    reason = "this reviewed function copies only after proving the exact expectation range is current/max read-only"
)]
pub(super) unsafe fn copy_expectation(
    expectation: *const [u8; STATIC_COUNT_EXPECTATION_BYTES_V2],
) -> Result<CopiedExpectationV2, StaticVerifyError> {
    let address = expectation.cast::<u8>().expose_provenance();
    let vm_regions_checked = verify_range(
        address,
        STATIC_COUNT_EXPECTATION_BYTES_V2,
        RegionPurpose::Expectation,
    )?;
    let mut bytes = [0_u8; STATIC_COUNT_EXPECTATION_BYTES_V2];
    // SAFETY: the caller promises an exact process-lifetime array allocation;
    // verify_range proved its entire fixed extent currently and maximally R--.
    unsafe {
        ptr::copy_nonoverlapping(
            expectation.cast::<u8>(),
            bytes.as_mut_ptr(),
            STATIC_COUNT_EXPECTATION_BYTES_V2,
        );
    }
    Ok(CopiedExpectationV2 {
        bytes,
        vm_regions_checked,
    })
}

#[allow(
    unsafe_code,
    reason = "this reviewed function copies metadata and views payload only after exact immutable VM-range proof"
)]
pub(super) fn verify(
    expected: &ExpectedStaticCountV2,
    symbols: LinkedStaticCountSymbolsV2,
    expectation_regions: usize,
) -> Result<(AggregateEntryV2, StaticRuntimeInspectionAccountingV2), StaticVerifyError> {
    let expected_metadata = expected.metadata();
    let payload_bytes = bounded_payload_bytes(expected_metadata.payload_bytes())?;

    let metadata_address = symbols.metadata_address.expose_address();
    let metadata_regions =
        verify_range(metadata_address, METADATA_BYTES_V2, RegionPurpose::Metadata)?;
    let mut metadata_bytes = [0_u8; METADATA_BYTES_V2];
    // SAFETY: the exact metadata extent is mapped current/max R--; the caller
    // promises it is the process-lifetime exact-sized extern allocation.
    unsafe {
        ptr::copy_nonoverlapping(
            ptr::with_exposed_provenance::<u8>(metadata_address),
            metadata_bytes.as_mut_ptr(),
            METADATA_BYTES_V2,
        );
    }
    let actual_metadata = validate_mapped_metadata(&metadata_bytes, expected_metadata)?;
    if actual_metadata.compile_identity() != expected.compile_identity() {
        return Err(StaticVerifyError::ContractMismatch {
            field: crate::StaticContractField::CompileIdentity,
        });
    }
    require_host_features(actual_metadata.actual_features(), host_has_asimd())?;

    let payload_address = symbols.payload_address.expose_address();
    let payload_regions = verify_range(payload_address, payload_bytes, RegionPurpose::Payload)?;
    let entry_offset = usize::try_from(actual_metadata.entry_offset())
        .map_err(|_| StaticVerifyError::EntryAddressOverflow)?;
    require_entry_address(
        payload_address,
        entry_offset,
        symbols.entry_address.expose_address(),
    )?;

    // SAFETY: the complete nonempty exact payload extent is current/max RX and
    // the caller supplies the process-lifetime exact-sized extern provenance.
    let payload = unsafe {
        slice::from_raw_parts(
            ptr::with_exposed_provenance::<u8>(payload_address),
            payload_bytes,
        )
    };
    require_payload_digest(payload, actual_metadata.payload_sha256())?;
    let vm_regions_checked = expectation_regions
        .checked_add(metadata_regions)
        .and_then(|regions| regions.checked_add(payload_regions))
        .ok_or(StaticVerifyError::InspectionAccountingOverflow)?;
    let accounting =
        StaticRuntimeInspectionAccountingV2::checked(payload_bytes, vm_regions_checked)?;
    let entry = verified_entry(symbols.entry_address);
    Ok((entry, accounting))
}

#[allow(
    unsafe_code,
    reason = "the sole address-to-callable conversion occurs after complete immutable VM, extent, entry-offset, metadata, identity, and payload-hash proof"
)]
fn verified_entry(address: StaticLinkedAddressV2) -> AggregateEntryV2 {
    #[cfg(test)]
    VERIFIED_ENTRY_CONVERSIONS_V2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let pointer = ptr::with_exposed_provenance::<()>(address.expose_address());
    // SAFETY: the caller reaches this conversion only after the complete
    // generated-entry proof above; the ABI-size assertion is crate-global.
    unsafe { mem::transmute::<*const (), AggregateEntryV2>(pointer) }
}

#[cfg(test)]
pub(super) fn verified_entry_conversion_count() -> usize {
    VERIFIED_ENTRY_CONVERSIONS_V2.load(std::sync::atomic::Ordering::SeqCst)
}

fn bounded_payload_bytes(claimed: u32) -> Result<usize, StaticVerifyError> {
    let claimed = usize::try_from(claimed).map_err(|_| StaticVerifyError::AddressRangeOverflow)?;
    if claimed == 0 || claimed > HARD_MAX_MAPPED_PAYLOAD_BYTES_V2 {
        Err(StaticVerifyError::MappedPayloadExtentOutOfBounds {
            claimed,
            hard_maximum: HARD_MAX_MAPPED_PAYLOAD_BYTES_V2,
        })
    } else {
        Ok(claimed)
    }
}

fn require_entry_address(
    payload_address: usize,
    entry_offset: usize,
    entry_address: usize,
) -> Result<(), StaticVerifyError> {
    let expected = payload_address
        .checked_add(entry_offset)
        .ok_or(StaticVerifyError::EntryAddressOverflow)?;
    if entry_address == expected {
        Ok(())
    } else {
        Err(StaticVerifyError::EntryAddressMismatch)
    }
}

fn require_payload_digest(payload: &[u8], expected: &[u8; 32]) -> Result<(), StaticVerifyError> {
    let actual: [u8; 32] = Sha256::digest(payload).into();
    if &actual == expected {
        Ok(())
    } else {
        Err(StaticVerifyError::MappedPayloadDigestMismatch)
    }
}

fn require_host_features(
    actual_features: u64,
    host_has_asimd: bool,
) -> Result<(), StaticVerifyError> {
    if actual_features & AotCountCpuFeatures::ASIMD.bits() != 0 && !host_has_asimd {
        Err(StaticVerifyError::RequiredCpuFeaturesUnavailable)
    } else {
        Ok(())
    }
}

#[inline]
pub(super) fn invoke_count(entry: AggregateEntryV2, haystack: &[u8]) -> RawAggregateCallV2 {
    let haystack_pointer = if haystack.is_empty() {
        ptr::addr_of!(EMPTY_HAYSTACK_SENTINEL_V2)
    } else {
        haystack.as_ptr()
    };
    raw_call(entry, haystack, haystack_pointer)
}

const fn host_has_asimd() -> bool {
    true
}

fn verify_range(
    start: usize,
    bytes: usize,
    purpose: RegionPurpose,
) -> Result<usize, StaticVerifyError> {
    if bytes == 0 {
        return Err(StaticVerifyError::VmRegionDoesNotCoverRange);
    }
    let end = start
        .checked_add(bytes)
        .ok_or(StaticVerifyError::AddressRangeOverflow)?;
    let mut cursor = start;
    let mut regions = 0_usize;
    while cursor < end {
        let region = query_region(cursor)?;
        let region_end = region
            .start
            .checked_add(region.bytes)
            .ok_or(StaticVerifyError::AddressRangeOverflow)?;
        if region.start > cursor || region_end <= cursor {
            return Err(StaticVerifyError::VmRegionDoesNotCoverRange);
        }
        require_protection(region, purpose)?;
        cursor = region_end.min(end);
        regions = regions
            .checked_add(1)
            .ok_or(StaticVerifyError::InspectionAccountingOverflow)?;
    }
    Ok(regions)
}

fn require_protection(region: Region, purpose: RegionPurpose) -> Result<(), StaticVerifyError> {
    let current = region.protection;
    let maximum = region.maximum_protection;
    let valid = match purpose {
        RegionPurpose::Payload => {
            current == (libc::PROT_READ | libc::PROT_EXEC)
                && maximum == (libc::PROT_READ | libc::PROT_EXEC)
        }
        RegionPurpose::Metadata | RegionPurpose::Expectation => {
            current == libc::PROT_READ && maximum == libc::PROT_READ
        }
    };
    if valid {
        return Ok(());
    }
    Err(match purpose {
        RegionPurpose::Payload => StaticVerifyError::PayloadProtectionMismatch {
            protection: current,
            maximum_protection: maximum,
        },
        RegionPurpose::Metadata => StaticVerifyError::MetadataProtectionMismatch {
            protection: current,
            maximum_protection: maximum,
        },
        RegionPurpose::Expectation => StaticVerifyError::ExpectationProtectionMismatch {
            protection: current,
            maximum_protection: maximum,
        },
    })
}

#[allow(
    deprecated,
    reason = "Mach VM region inspection uses the libc current-task-port shim"
)]
#[allow(
    unsafe_code,
    reason = "this reviewed function owns the complete Mach VM query and returned-port release transaction"
)]
fn query_region(pointer: usize) -> Result<Region, StaticVerifyError> {
    const VM_REGION_BASIC_INFO_64: libc::c_int = 9;

    let mut address =
        u64::try_from(pointer).map_err(|_| StaticVerifyError::AddressRangeOverflow)?;
    let mut size = 0_u64;
    let mut info = BasicInfo64 {
        protection: 0,
        max_protection: 0,
        inheritance: 0,
        shared: 0,
        reserved: 0,
        offset: 0,
        behavior: 0,
        user_wired_count: 0,
    };
    let info_words = mem::size_of::<BasicInfo64>()
        .checked_div(mem::size_of::<libc::c_int>())
        .ok_or(StaticVerifyError::AddressRangeOverflow)?;
    let mut info_count =
        u32::try_from(info_words).map_err(|_| StaticVerifyError::AddressRangeOverflow)?;
    let mut object: libc::mach_port_t = 0;
    // SAFETY: this libc shim returns the current task port name.
    let task = unsafe { libc::mach_task_self() };
    // SAFETY: every out-pointer names initialized, correctly sized writable
    // storage and the current process task port is valid for this query.
    let result = unsafe {
        mach_vm_region(
            task,
            &raw mut address,
            &raw mut size,
            VM_REGION_BASIC_INFO_64,
            (&raw mut info).cast(),
            &raw mut info_count,
            &raw mut object,
        )
    };
    if result != libc::KERN_SUCCESS {
        return Err(StaticVerifyError::VmRegionQueryFailed { code: result });
    }
    if object != 0 {
        // SAFETY: object is the send right returned by this query.
        let deallocated = unsafe { mach_port_deallocate(task, object) };
        if deallocated != libc::KERN_SUCCESS {
            return Err(StaticVerifyError::VmRegionQueryFailed { code: deallocated });
        }
    }
    Ok(Region {
        start: usize::try_from(address).map_err(|_| StaticVerifyError::AddressRangeOverflow)?,
        bytes: usize::try_from(size).map_err(|_| StaticVerifyError::AddressRangeOverflow)?,
        protection: info.protection,
        maximum_protection: info.max_protection,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixture::static_fixture_v2;

    #[test]
    fn protection_policy_checks_current_and_maximum_exactly() {
        let region = |protection, maximum_protection| Region {
            start: 0x1000,
            bytes: 0x1000,
            protection,
            maximum_protection,
        };
        let read = libc::PROT_READ;
        let execute = libc::PROT_EXEC;
        let write = libc::PROT_WRITE;
        assert_eq!(
            require_protection(
                region(read | execute, read | execute),
                RegionPurpose::Payload,
            ),
            Ok(())
        );
        assert_eq!(
            require_protection(region(read, read), RegionPurpose::Metadata),
            Ok(())
        );
        assert_eq!(
            require_protection(region(read, read), RegionPurpose::Expectation),
            Ok(())
        );
        for (current, maximum) in [
            (read | write | execute, read | write | execute),
            (read | execute, read | write | execute),
            (read, read | execute),
        ] {
            assert!(require_protection(region(current, maximum), RegionPurpose::Payload,).is_err());
        }
        for purpose in [RegionPurpose::Metadata, RegionPurpose::Expectation] {
            for (current, maximum) in [
                (read | write, read | write),
                (read, read | write),
                (read | execute, read | execute),
            ] {
                assert!(require_protection(region(current, maximum), purpose,).is_err());
            }
        }
    }

    #[test]
    #[allow(
        unsafe_code,
        reason = "the test reads the known process-static one-byte sentinel"
    )]
    fn empty_haystack_uses_nonnull_process_lifetime_sentinel() {
        let pointer = ptr::addr_of!(EMPTY_HAYSTACK_SENTINEL_V2);
        assert!(!pointer.is_null());
        assert_eq!(unsafe { *pointer }, 0);
    }

    #[test]
    fn payload_extent_address_and_entry_offset_boundaries_are_exact() {
        let hard_maximum =
            u32::try_from(HARD_MAX_MAPPED_PAYLOAD_BYTES_V2).expect("small hard maximum");
        assert_eq!(bounded_payload_bytes(1), Ok(1));
        assert_eq!(
            bounded_payload_bytes(hard_maximum),
            Ok(HARD_MAX_MAPPED_PAYLOAD_BYTES_V2)
        );
        for claimed in [
            0,
            hard_maximum
                .checked_add(1)
                .expect("hard maximum has headroom"),
            u32::MAX,
        ] {
            assert!(matches!(
                bounded_payload_bytes(claimed),
                Err(StaticVerifyError::MappedPayloadExtentOutOfBounds { .. })
            ));
        }

        assert_eq!(require_entry_address(0x1000, 0, 0x1000), Ok(()));
        assert_eq!(
            require_entry_address(0x1000, 1, 0x1000),
            Err(StaticVerifyError::EntryAddressMismatch)
        );
        assert_eq!(
            require_entry_address(usize::MAX, 1, 0),
            Err(StaticVerifyError::EntryAddressOverflow)
        );
        assert_eq!(
            verify_range(usize::MAX, 2, RegionPurpose::Payload),
            Err(StaticVerifyError::AddressRangeOverflow)
        );
        assert_eq!(
            verify_range(0, 0, RegionPurpose::Payload),
            Err(StaticVerifyError::VmRegionDoesNotCoverRange)
        );
    }

    #[test]
    fn payload_digest_features_and_metadata_abi_refuse_exact_mismatches() {
        let digest: [u8; 32] = Sha256::digest(b"payload").into();
        assert_eq!(require_payload_digest(b"payload", &digest), Ok(()));
        assert_eq!(
            require_payload_digest(b"payloae", &digest),
            Err(StaticVerifyError::MappedPayloadDigestMismatch)
        );
        assert_eq!(
            require_host_features(AotCountCpuFeatures::ASIMD.bits(), false),
            Err(StaticVerifyError::RequiredCpuFeaturesUnavailable)
        );
        assert_eq!(
            require_host_features(AotCountCpuFeatures::ASIMD.bits(), true),
            Ok(())
        );
        assert_eq!(require_host_features(0, false), Ok(()));

        let fixture = static_fixture_v2();
        let expected = fre_aot_count_contract::inspect_count_metadata_v2(&fixture.metadata)
            .expect("fixture metadata");
        for offset in [20, 32, 168] {
            let mut changed = fixture.metadata;
            changed[offset] ^= 1;
            assert!(
                validate_mapped_metadata(&changed, expected).is_err(),
                "metadata mismatch at byte {offset} was accepted"
            );
        }
    }
}
