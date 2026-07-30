use core::{mem, ptr, slice};

use fre_aot_search_contract::{
    SEARCH_BACKEND_ASIMD_TAG22_V1, SEARCH_BACKEND_ASIMD_TAG23_V1, SEARCH_BACKEND_VERSION_V1,
    SEARCH_METADATA_BYTES_V1, SEARCH_PLATFORM_MACOS_V1, SEARCH_REQUIRED_ASIMD_FEATURES_V1,
    STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1,
};
use fre_kernel_ir::SearchWindow;
use sha2::{Digest, Sha256};

use crate::{
    RawSearchCallV1, StaticSearchSpanContractFieldV1, StaticSearchSpanVerifyErrorV1,
    error::require_search_span_v1,
    search_expected::ExpectedStaticSearchSpanV1,
    search_linked::{
        CopiedSearchSpanExpectationV1, LinkedStaticSearchSpanSymbolsV1, SearchSpanEntryV1,
        StaticSearchSpanInspectionAccountingV1, StaticSearchSpanLinkedAddressV1,
        require_semantic_payload_reconstruction_v1, validate_mapped_search_span_metadata_v1,
        verified_search_span_call_v1,
    },
};

#[allow(
    unsafe_code,
    reason = "these reviewed declarations are the read-only Mach VM query and returned-port release boundary"
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

static EMPTY_SEARCH_HAYSTACK_SENTINEL_V1: u8 = 0;
// Defense-in-depth ceiling for hostile mapped extents. The canonical Search
// contract remains the source of the exact payload length.
const HARD_MAX_MAPPED_SEARCH_PAYLOAD_BYTES_V1: usize = 4 << 20;
#[cfg(test)]
static VERIFIED_SEARCH_ENTRY_CONVERSIONS_V1: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[allow(
    unsafe_code,
    reason = "this copies only after proving the exact expectation extent current/max read-only"
)]
pub(super) unsafe fn copy_expectation(
    expectation: StaticSearchSpanLinkedAddressV1,
) -> Result<CopiedSearchSpanExpectationV1, StaticSearchSpanVerifyErrorV1> {
    let address = expectation.expose_address();
    let vm_regions_checked = verify_range(
        address,
        STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1,
        RegionPurpose::Expectation,
    )?;
    let mut bytes = [0_u8; STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1];
    // SAFETY: the exact fixed range was proven mapped current/max R-- and the
    // raw-boundary contract retains its process-lifetime allocation.
    unsafe {
        ptr::copy_nonoverlapping(
            ptr::with_exposed_provenance::<u8>(address),
            bytes.as_mut_ptr(),
            STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1,
        );
    }
    Ok(CopiedSearchSpanExpectationV1 {
        bytes,
        vm_regions_checked,
    })
}

#[allow(
    unsafe_code,
    reason = "metadata is copied and payload viewed only after exact immutable VM-range proof"
)]
pub(super) fn verify(
    expected: &ExpectedStaticSearchSpanV1,
    symbols: LinkedStaticSearchSpanSymbolsV1,
    expectation_regions: usize,
) -> Result<
    (SearchSpanEntryV1, StaticSearchSpanInspectionAccountingV1),
    StaticSearchSpanVerifyErrorV1,
> {
    let expected_metadata = expected.metadata();
    let payload_bytes = bounded_payload_bytes(expected_metadata.payload_bytes())?;

    let metadata_address = symbols.metadata_address.expose_address();
    let metadata_regions = verify_range(
        metadata_address,
        SEARCH_METADATA_BYTES_V1,
        RegionPurpose::Metadata,
    )?;
    let mut metadata_bytes = [0_u8; SEARCH_METADATA_BYTES_V1];
    // SAFETY: the complete fixed metadata range is current/max R-- and the
    // raw-boundary contract retains its exact process-lifetime allocation.
    unsafe {
        ptr::copy_nonoverlapping(
            ptr::with_exposed_provenance::<u8>(metadata_address),
            metadata_bytes.as_mut_ptr(),
            SEARCH_METADATA_BYTES_V1,
        );
    }
    let actual_metadata =
        validate_mapped_search_span_metadata_v1(&metadata_bytes, expected_metadata)?;
    require_mapped_metadata_correlations(actual_metadata, expected)?;
    require_host_asimd(actual_metadata.features(), host_has_asimd())?;

    let payload_address = symbols.payload_address.expose_address();
    require_address_alignment(payload_address, 16, false)?;
    let payload_regions = verify_range(payload_address, payload_bytes, RegionPurpose::Payload)?;
    let entry_offset = usize::try_from(actual_metadata.entry_offset())
        .map_err(|_| StaticSearchSpanVerifyErrorV1::EntryAddressOverflow)?;
    require_address_alignment(symbols.entry_address.expose_address(), 4, true)?;
    require_entry_address(
        payload_address,
        entry_offset,
        symbols.entry_address.expose_address(),
    )?;

    // SAFETY: the complete nonempty exact payload is current/max RX and the
    // raw-boundary contract retains its exact process-lifetime allocation.
    let payload = unsafe {
        slice::from_raw_parts(
            ptr::with_exposed_provenance::<u8>(payload_address),
            payload_bytes,
        )
    };
    require_payload_digest(payload, actual_metadata.payload_sha256())?;
    require_semantic_payload_reconstruction_v1(expected, payload)?;

    let vm_regions_checked = expectation_regions
        .checked_add(metadata_regions)
        .and_then(|regions| regions.checked_add(payload_regions))
        .ok_or(StaticSearchSpanVerifyErrorV1::InspectionAccountingOverflow)?;
    let accounting =
        StaticSearchSpanInspectionAccountingV1::checked(payload_bytes, vm_regions_checked)?;
    let entry = verified_entry(symbols.entry_address);
    Ok((entry, accounting))
}

fn require_mapped_metadata_correlations(
    actual: fre_aot_search_contract::ClaimedSearchMetadataV1,
    expected: &ExpectedStaticSearchSpanV1,
) -> Result<(), StaticSearchSpanVerifyErrorV1> {
    require_search_span_v1(
        matches!(
            actual.backend_version(),
            SEARCH_BACKEND_VERSION_V1
                | SEARCH_BACKEND_ASIMD_TAG22_V1
                | SEARCH_BACKEND_ASIMD_TAG23_V1
        ) && actual.platform() == SEARCH_PLATFORM_MACOS_V1
            && actual.features() == SEARCH_REQUIRED_ASIMD_FEATURES_V1,
        StaticSearchSpanContractFieldV1::Metadata,
    )?;
    require_search_span_v1(
        actual.source_identity() == expected.kir_identity(),
        StaticSearchSpanContractFieldV1::KirIdentity,
    )?;
    require_search_span_v1(
        actual.artifact_identity() == expected.artifact_identity(),
        StaticSearchSpanContractFieldV1::ArtifactIdentity,
    )?;
    require_search_span_v1(
        actual.binding_identity() == expected.binding_identity(),
        StaticSearchSpanContractFieldV1::BindingIdentity,
    )?;
    require_search_span_v1(
        actual.compile_identity() == expected.compile_identity(),
        StaticSearchSpanContractFieldV1::CompileIdentity,
    )?;
    require_search_span_v1(
        actual.rodata_bytes() == expected.live_literal_bytes(),
        StaticSearchSpanContractFieldV1::LiveLiteralBytes,
    )?;
    let layout_end = actual
        .rodata_offset()
        .checked_add(actual.rodata_bytes())
        .ok_or(StaticSearchSpanVerifyErrorV1::AddressRangeOverflow)?;
    require_search_span_v1(
        actual.code_bytes() != 0
            && actual.code_bytes().is_multiple_of(4)
            && actual.rodata_offset().is_multiple_of(16)
            && actual.rodata_offset() >= actual.code_bytes()
            && layout_end == actual.payload_bytes()
            && actual.entry_offset() < actual.code_bytes(),
        StaticSearchSpanContractFieldV1::Metadata,
    )
}

#[allow(
    unsafe_code,
    reason = "the sole address-to-callable conversion follows every row, VM, extent, metadata, host, offset, and digest check"
)]
fn verified_entry(address: StaticSearchSpanLinkedAddressV1) -> SearchSpanEntryV1 {
    #[cfg(test)]
    VERIFIED_SEARCH_ENTRY_CONVERSIONS_V1.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let pointer = ptr::with_exposed_provenance::<()>(address.expose_address());
    // SAFETY: the complete proof above established the exact generated entry
    // and the crate-global ABI-size assertion holds.
    unsafe { mem::transmute::<*const (), SearchSpanEntryV1>(pointer) }
}

#[cfg(test)]
pub(super) fn verified_entry_conversion_count() -> usize {
    VERIFIED_SEARCH_ENTRY_CONVERSIONS_V1.load(std::sync::atomic::Ordering::SeqCst)
}

fn bounded_payload_bytes(claimed: u32) -> Result<usize, StaticSearchSpanVerifyErrorV1> {
    let claimed = usize::try_from(claimed)
        .map_err(|_| StaticSearchSpanVerifyErrorV1::AddressRangeOverflow)?;
    if claimed == 0 || claimed > HARD_MAX_MAPPED_SEARCH_PAYLOAD_BYTES_V1 {
        Err(
            StaticSearchSpanVerifyErrorV1::MappedPayloadExtentOutOfBounds {
                claimed,
                hard_maximum: HARD_MAX_MAPPED_SEARCH_PAYLOAD_BYTES_V1,
            },
        )
    } else {
        Ok(claimed)
    }
}

fn require_entry_address(
    payload_address: usize,
    entry_offset: usize,
    entry_address: usize,
) -> Result<(), StaticSearchSpanVerifyErrorV1> {
    let expected = payload_address
        .checked_add(entry_offset)
        .ok_or(StaticSearchSpanVerifyErrorV1::EntryAddressOverflow)?;
    if entry_address == expected {
        Ok(())
    } else {
        Err(StaticSearchSpanVerifyErrorV1::EntryAddressMismatch)
    }
}

fn require_address_alignment(
    address: usize,
    required_alignment: usize,
    is_entry: bool,
) -> Result<(), StaticSearchSpanVerifyErrorV1> {
    if required_alignment != 0 && address.is_multiple_of(required_alignment) {
        Ok(())
    } else if is_entry {
        Err(StaticSearchSpanVerifyErrorV1::EntryAddressMisaligned {
            address,
            required_alignment,
        })
    } else {
        Err(StaticSearchSpanVerifyErrorV1::PayloadAddressMisaligned {
            address,
            required_alignment,
        })
    }
}

fn require_payload_digest(
    payload: &[u8],
    expected: &[u8; 32],
) -> Result<(), StaticSearchSpanVerifyErrorV1> {
    let actual: [u8; 32] = Sha256::digest(payload).into();
    if &actual == expected {
        Ok(())
    } else {
        Err(StaticSearchSpanVerifyErrorV1::MappedPayloadDigestMismatch)
    }
}

fn require_host_asimd(
    required_features: u64,
    host_has_asimd: bool,
) -> Result<(), StaticSearchSpanVerifyErrorV1> {
    if required_features & SEARCH_REQUIRED_ASIMD_FEATURES_V1 != 0 && !host_has_asimd {
        Err(StaticSearchSpanVerifyErrorV1::RequiredAsimdUnavailable)
    } else {
        Ok(())
    }
}

#[inline]
pub(super) fn invoke_search_span(
    entry: SearchSpanEntryV1,
    haystack: &[u8],
    window: SearchWindow,
) -> RawSearchCallV1 {
    let haystack_pointer = if haystack.is_empty() {
        ptr::addr_of!(EMPTY_SEARCH_HAYSTACK_SENTINEL_V1)
    } else {
        haystack.as_ptr()
    };
    verified_search_span_call_v1(entry, haystack, haystack_pointer, window)
}

fn host_has_asimd() -> bool {
    std::arch::is_aarch64_feature_detected!("neon")
}

fn verify_range(
    start: usize,
    bytes: usize,
    purpose: RegionPurpose,
) -> Result<usize, StaticSearchSpanVerifyErrorV1> {
    if bytes == 0 {
        return Err(StaticSearchSpanVerifyErrorV1::VmRegionDoesNotCoverRange);
    }
    let end = start
        .checked_add(bytes)
        .ok_or(StaticSearchSpanVerifyErrorV1::AddressRangeOverflow)?;
    let mut cursor = start;
    let mut regions = 0_usize;
    while cursor < end {
        let region = query_region(cursor)?;
        let region_end = region
            .start
            .checked_add(region.bytes)
            .ok_or(StaticSearchSpanVerifyErrorV1::AddressRangeOverflow)?;
        if region.start > cursor || region_end <= cursor {
            return Err(StaticSearchSpanVerifyErrorV1::VmRegionDoesNotCoverRange);
        }
        require_protection(region, purpose)?;
        cursor = region_end.min(end);
        regions = regions
            .checked_add(1)
            .ok_or(StaticSearchSpanVerifyErrorV1::InspectionAccountingOverflow)?;
    }
    Ok(regions)
}

fn require_protection(
    region: Region,
    purpose: RegionPurpose,
) -> Result<(), StaticSearchSpanVerifyErrorV1> {
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
        RegionPurpose::Payload => StaticSearchSpanVerifyErrorV1::PayloadProtectionMismatch {
            protection: current,
            maximum_protection: maximum,
        },
        RegionPurpose::Metadata => StaticSearchSpanVerifyErrorV1::MetadataProtectionMismatch {
            protection: current,
            maximum_protection: maximum,
        },
        RegionPurpose::Expectation => {
            StaticSearchSpanVerifyErrorV1::ExpectationProtectionMismatch {
                protection: current,
                maximum_protection: maximum,
            }
        }
    })
}

#[allow(
    deprecated,
    reason = "Mach VM region inspection uses the libc current-task-port shim"
)]
#[allow(
    unsafe_code,
    reason = "this function owns the complete Mach VM query and returned-port release transaction"
)]
fn query_region(pointer: usize) -> Result<Region, StaticSearchSpanVerifyErrorV1> {
    const VM_REGION_BASIC_INFO_64: libc::c_int = 9;

    let mut address =
        u64::try_from(pointer).map_err(|_| StaticSearchSpanVerifyErrorV1::AddressRangeOverflow)?;
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
        .ok_or(StaticSearchSpanVerifyErrorV1::AddressRangeOverflow)?;
    let mut info_count = u32::try_from(info_words)
        .map_err(|_| StaticSearchSpanVerifyErrorV1::AddressRangeOverflow)?;
    let mut object: libc::mach_port_t = 0;
    // SAFETY: this libc shim returns the current task port name.
    let task = unsafe { libc::mach_task_self() };
    // SAFETY: every out-pointer names initialized, correctly sized writable
    // storage and the current task port is valid for this read-only query.
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
        return Err(StaticSearchSpanVerifyErrorV1::VmRegionQueryFailed { code: result });
    }
    if object != 0 {
        // SAFETY: object is the send right returned by this query.
        let deallocated = unsafe { mach_port_deallocate(task, object) };
        if deallocated != libc::KERN_SUCCESS {
            return Err(StaticSearchSpanVerifyErrorV1::VmRegionQueryFailed { code: deallocated });
        }
    }
    Ok(Region {
        start: usize::try_from(address)
            .map_err(|_| StaticSearchSpanVerifyErrorV1::AddressRangeOverflow)?,
        bytes: usize::try_from(size)
            .map_err(|_| StaticSearchSpanVerifyErrorV1::AddressRangeOverflow)?,
        protection: info.protection,
        maximum_protection: info.max_protection,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::search_test_fixture::static_search_span_fixture_v1;

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
            assert!(require_protection(region(current, maximum), RegionPurpose::Payload).is_err());
        }
        for purpose in [RegionPurpose::Metadata, RegionPurpose::Expectation] {
            for (current, maximum) in [
                (read | write, read | write),
                (read, read | write),
                (read | execute, read | execute),
            ] {
                assert!(require_protection(region(current, maximum), purpose).is_err());
            }
        }
    }

    #[test]
    #[allow(
        unsafe_code,
        reason = "the test reads the known process-static one-byte sentinel"
    )]
    fn empty_haystack_sentinel_is_nonnull_and_process_lifetime() {
        let pointer = ptr::addr_of!(EMPTY_SEARCH_HAYSTACK_SENTINEL_V1);
        assert!(!pointer.is_null());
        assert_eq!(unsafe { *pointer }, 0);
    }

    #[test]
    fn payload_extent_address_digest_and_feature_boundaries_are_exact() {
        let hard_maximum =
            u32::try_from(HARD_MAX_MAPPED_SEARCH_PAYLOAD_BYTES_V1).expect("small maximum");
        assert_eq!(bounded_payload_bytes(1), Ok(1));
        assert_eq!(
            bounded_payload_bytes(hard_maximum),
            Ok(HARD_MAX_MAPPED_SEARCH_PAYLOAD_BYTES_V1)
        );
        for claimed in [
            0,
            hard_maximum.checked_add(1).expect("maximum has headroom"),
            u32::MAX,
        ] {
            assert!(matches!(
                bounded_payload_bytes(claimed),
                Err(StaticSearchSpanVerifyErrorV1::MappedPayloadExtentOutOfBounds { .. })
            ));
        }
        assert_eq!(require_entry_address(0x1000, 0, 0x1000), Ok(()));
        assert_eq!(
            require_entry_address(0x1000, 1, 0x1000),
            Err(StaticSearchSpanVerifyErrorV1::EntryAddressMismatch)
        );
        assert_eq!(
            require_entry_address(usize::MAX, 1, 0),
            Err(StaticSearchSpanVerifyErrorV1::EntryAddressOverflow)
        );
        assert_eq!(require_address_alignment(0x1000, 16, false), Ok(()));
        assert_eq!(require_address_alignment(0x1000, 4, true), Ok(()));
        assert!(matches!(
            require_address_alignment(0x1001, 16, false),
            Err(StaticSearchSpanVerifyErrorV1::PayloadAddressMisaligned { .. })
        ));
        assert!(matches!(
            require_address_alignment(0x1002, 4, true),
            Err(StaticSearchSpanVerifyErrorV1::EntryAddressMisaligned { .. })
        ));

        let digest: [u8; 32] = Sha256::digest(b"payload").into();
        assert_eq!(require_payload_digest(b"payload", &digest), Ok(()));
        assert_eq!(
            require_payload_digest(b"payloae", &digest),
            Err(StaticSearchSpanVerifyErrorV1::MappedPayloadDigestMismatch)
        );
        assert_eq!(
            require_host_asimd(SEARCH_REQUIRED_ASIMD_FEATURES_V1, false),
            Err(StaticSearchSpanVerifyErrorV1::RequiredAsimdUnavailable)
        );
        assert_eq!(
            require_host_asimd(SEARCH_REQUIRED_ASIMD_FEATURES_V1, true),
            Ok(())
        );
    }

    #[test]
    fn mapped_metadata_correlations_repeat_every_runtime_critical_relation() {
        let fixture = static_search_span_fixture_v1();
        let expected = ExpectedStaticSearchSpanV1::from_source_qualified_bytes(
            &fixture.expectation,
            &fixture.row,
            fixture.row.compile_identity(),
        )
        .expect("qualified fixture");
        let actual = fre_aot_search_contract::inspect_search_metadata_v1(&fixture.metadata)
            .expect("metadata fixture");
        assert_eq!(
            require_mapped_metadata_correlations(actual, &expected),
            Ok(())
        );
    }

    #[test]
    fn range_arithmetic_refuses_before_query() {
        assert_eq!(
            verify_range(usize::MAX, 2, RegionPurpose::Payload),
            Err(StaticSearchSpanVerifyErrorV1::AddressRangeOverflow)
        );
        assert_eq!(
            verify_range(0, 0, RegionPurpose::Payload),
            Err(StaticSearchSpanVerifyErrorV1::VmRegionDoesNotCoverRange)
        );
    }
}
