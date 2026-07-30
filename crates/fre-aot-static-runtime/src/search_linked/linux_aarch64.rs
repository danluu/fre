use core::{mem, ptr, slice};
use std::io::{ErrorKind, Read};

use fre_aot_search_contract::{
    SEARCH_BACKEND_ASIMD_TAG22_V1, SEARCH_BACKEND_ASIMD_TAG23_V1, SEARCH_BACKEND_ASIMD_TAG25_V1,
    SEARCH_BACKEND_ASIMD_TAG26_V1, SEARCH_BACKEND_ASIMD_TAG28_V1, SEARCH_BACKEND_ASIMD_TAG29_V1,
    SEARCH_BACKEND_ASIMD_TAG30_V1, SEARCH_BACKEND_ASIMD_TAG37_V1, SEARCH_BACKEND_ASIMD_TAG38_V1,
    SEARCH_BACKEND_SVE2_FIXED16_TAG21_V1, SEARCH_BACKEND_VERSION_V1, SEARCH_METADATA_BYTES_V1,
    SEARCH_PLATFORM_LINUX_V1, SEARCH_REQUIRED_ASIMD_FEATURES_V1,
    SEARCH_REQUIRED_SVE2_FIXED16_FEATURES_V1, STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1,
    search_backend_literal_width_is_valid_v1,
};
use fre_kernel_ir::SearchWindow;
use fre_target_features::TuningClass;
use sha2::{Digest, Sha256};

use crate::{
    RawSearchCallV1, StaticSearchSpanContractFieldV1, StaticSearchSpanThreadContractErrorV1,
    StaticSearchSpanVerifyErrorV1,
    error::require_search_span_v1,
    search_expected::ExpectedStaticSearchSpanV1,
    search_linked::{
        CopiedSearchSpanExpectationV1, LinkedStaticSearchSpanSymbolsV1, SearchSpanEntryV1,
        StaticSearchSpanInspectionAccountingV1, StaticSearchSpanLinkedAddressV1,
        require_semantic_payload_reconstruction_v1, validate_mapped_search_span_metadata_v1,
        verified_search_span_call_v1,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SegmentPurpose {
    Payload,
    Metadata,
    Expectation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the four booleans preserve independently audited Linux HWCAP and exact-CPU admission gates"
)]
struct HostFeaturesV1 {
    asimd: bool,
    sve: bool,
    sve2: bool,
    sve_vector_bytes: Option<u16>,
    tag21_tuning: bool,
}

struct SegmentQueryV1 {
    start: usize,
    end: usize,
    purpose: SegmentPurpose,
    found: bool,
    failure: Option<StaticSearchSpanVerifyErrorV1>,
}

static EMPTY_SEARCH_HAYSTACK_SENTINEL_V1: u8 = 0;
const HARD_MAX_MAPPED_SEARCH_PAYLOAD_BYTES_V1: usize = 4 << 20;
const AT_HWCAP_V1: libc::c_ulong = 16;
const AT_HWCAP2_V1: libc::c_ulong = 26;
const AARCH64_HWCAP_ASIMD_V1: libc::c_ulong = 0x0000_0002;
const AARCH64_HWCAP_SVE_V1: libc::c_ulong = 0x0040_0000;
const AARCH64_HWCAP2_SVE2_V1: libc::c_ulong = 0x0000_0002;
const PR_SVE_SET_VL_V1: libc::c_int = 50;
const PR_SVE_GET_VL_V1: libc::c_int = 51;
const PR_SVE_VL_LEN_MASK_V1: libc::c_int = 0xffff;
const TAG21_VECTOR_BYTES_V1: u16 = 16;
const PRCTL_ZERO_V1: libc::c_ulong = 0;
const MAX_PROC_MAPS_BYTES_V1: usize = 4 << 20;
const PROC_MAPS_READ_BUFFER_BYTES_V1: usize = 4 << 10;
const MAX_PROC_MAPS_LINE_BYTES_V1: usize = 16 << 10;

#[cfg(test)]
static VERIFIED_SEARCH_ENTRY_CONVERSIONS_V1: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[allow(
    unsafe_code,
    reason = "this copies only after the exact expectation extent is proved to occupy a read-only ELF load segment"
)]
pub(super) unsafe fn copy_expectation(
    expectation: StaticSearchSpanLinkedAddressV1,
) -> Result<CopiedSearchSpanExpectationV1, StaticSearchSpanVerifyErrorV1> {
    let address = expectation.expose_address();
    let vm_regions_checked = verify_mapped_range(
        address,
        STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1,
        SegmentPurpose::Expectation,
    )?;
    let mut bytes = [0_u8; STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1];
    // SAFETY: the exact fixed range was proved present in a read-only PT_LOAD
    // and the raw adopter requires its process-lifetime allocation.
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
    reason = "metadata is copied and payload viewed only after exact final-image ELF segment proof"
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
    let metadata_regions = verify_mapped_range(
        metadata_address,
        SEARCH_METADATA_BYTES_V1,
        SegmentPurpose::Metadata,
    )?;
    let mut metadata_bytes = [0_u8; SEARCH_METADATA_BYTES_V1];
    // SAFETY: the complete metadata record is in a read-only PT_LOAD and the
    // raw adopter retains its exact process-lifetime allocation.
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
    require_host_features(actual_metadata.features(), host_features())?;

    let payload_address = symbols.payload_address.expose_address();
    require_address_alignment(payload_address, 16, false)?;
    let payload_regions =
        verify_mapped_range(payload_address, payload_bytes, SegmentPurpose::Payload)?;
    let entry_offset = usize::try_from(actual_metadata.entry_offset())
        .map_err(|_| StaticSearchSpanVerifyErrorV1::EntryAddressOverflow)?;
    require_address_alignment(symbols.entry_address.expose_address(), 4, true)?;
    require_entry_address(
        payload_address,
        entry_offset,
        symbols.entry_address.expose_address(),
    )?;

    // SAFETY: the complete nonempty payload is in an exact read-execute
    // PT_LOAD and the raw adopter retains its process-lifetime allocation.
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
    let valid_profile = match actual.backend_version() {
        SEARCH_BACKEND_VERSION_V1
        | SEARCH_BACKEND_ASIMD_TAG22_V1
        | SEARCH_BACKEND_ASIMD_TAG23_V1
        | SEARCH_BACKEND_ASIMD_TAG25_V1
        | SEARCH_BACKEND_ASIMD_TAG26_V1
        | SEARCH_BACKEND_ASIMD_TAG28_V1
        | SEARCH_BACKEND_ASIMD_TAG29_V1
        | SEARCH_BACKEND_ASIMD_TAG30_V1
        | SEARCH_BACKEND_ASIMD_TAG37_V1
        | SEARCH_BACKEND_ASIMD_TAG38_V1 => actual.features() == SEARCH_REQUIRED_ASIMD_FEATURES_V1,
        SEARCH_BACKEND_SVE2_FIXED16_TAG21_V1 => {
            actual.features() == SEARCH_REQUIRED_SVE2_FIXED16_FEATURES_V1
                && expected.live_literal_bytes() == 16
        }
        _ => false,
    };
    require_search_span_v1(
        actual.platform() == SEARCH_PLATFORM_LINUX_V1
            && valid_profile
            && search_backend_literal_width_is_valid_v1(
                actual.backend_version(),
                expected.live_literal_bytes(),
            ),
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

fn require_host_features(
    required_features: u64,
    host: HostFeaturesV1,
) -> Result<(), StaticSearchSpanVerifyErrorV1> {
    if required_features & SEARCH_REQUIRED_ASIMD_FEATURES_V1 != 0 && !host.asimd {
        return Err(StaticSearchSpanVerifyErrorV1::RequiredAsimdUnavailable);
    }
    if required_features & 2 != 0 && !host.sve {
        return Err(StaticSearchSpanVerifyErrorV1::RequiredSveUnavailable);
    }
    if required_features & 4 != 0 && !host.sve2 {
        return Err(StaticSearchSpanVerifyErrorV1::RequiredSve2Unavailable);
    }
    if required_features == SEARCH_REQUIRED_SVE2_FIXED16_FEATURES_V1
        && host.sve_vector_bytes != Some(TAG21_VECTOR_BYTES_V1)
    {
        return Err(
            StaticSearchSpanVerifyErrorV1::RequiredSveVectorLengthUnavailable {
                required_bytes: TAG21_VECTOR_BYTES_V1,
                actual_bytes: host.sve_vector_bytes,
            },
        );
    }
    if required_features == SEARCH_REQUIRED_SVE2_FIXED16_FEATURES_V1 && !host.tag21_tuning {
        return Err(StaticSearchSpanVerifyErrorV1::RequiredTag21TuningUnavailable);
    }
    Ok(())
}

#[allow(
    unsafe_code,
    reason = "Linux auxv is the kernel-provided architectural feature boundary"
)]
fn host_features() -> HostFeaturesV1 {
    // SAFETY: getauxval reads the immutable process auxiliary vector and has no
    // pointer preconditions.
    let hwcap = unsafe { libc::getauxval(AT_HWCAP_V1) };
    // SAFETY: same boundary for the second architectural capability word.
    let hwcap2 = unsafe { libc::getauxval(AT_HWCAP2_V1) };
    let sve = hwcap & AARCH64_HWCAP_SVE_V1 != 0;
    let sve_vector_bytes = if sve {
        current_thread_sve_vector_bytes_v1().ok()
    } else {
        None
    };
    let tag21_tuning = matches!(
        fre_target_features::host().tuning(),
        TuningClass::ArmServer { cpu: Some(cpu) }
            if cpu.implementer == 0x41 && cpu.part == 0x0d84
    );
    HostFeaturesV1 {
        asimd: hwcap & AARCH64_HWCAP_ASIMD_V1 != 0,
        sve,
        sve2: sve && hwcap2 & AARCH64_HWCAP2_SVE2_V1 != 0,
        sve_vector_bytes,
        tag21_tuning,
    }
}

#[allow(
    unsafe_code,
    reason = "PR_SVE_GET_VL reads only the calling thread's architectural SVE state"
)]
fn current_thread_sve_vector_bytes_v1() -> Result<u16, StaticSearchSpanThreadContractErrorV1> {
    // SAFETY: PR_SVE_GET_VL ignores its four unsigned-long arguments and
    // returns only the calling thread's SVE vector-length state.
    let raw = unsafe {
        libc::prctl(
            PR_SVE_GET_VL_V1,
            PRCTL_ZERO_V1,
            PRCTL_ZERO_V1,
            PRCTL_ZERO_V1,
            PRCTL_ZERO_V1,
        )
    };
    if raw < 0 {
        return Err(
            StaticSearchSpanThreadContractErrorV1::SveVectorLengthQueryFailed {
                errno: std::io::Error::last_os_error().raw_os_error(),
            },
        );
    }
    u16::try_from(raw & PR_SVE_VL_LEN_MASK_V1).map_err(|_| {
        StaticSearchSpanThreadContractErrorV1::RequiredSveVectorLengthUnavailable {
            required_bytes: TAG21_VECTOR_BYTES_V1,
            actual_bytes: None,
        }
    })
}

pub(super) fn require_current_thread_sve_vl16_v1()
-> Result<(), StaticSearchSpanThreadContractErrorV1> {
    let actual = current_thread_sve_vector_bytes_v1()?;
    if actual == TAG21_VECTOR_BYTES_V1 {
        Ok(())
    } else {
        Err(
            StaticSearchSpanThreadContractErrorV1::RequiredSveVectorLengthUnavailable {
                required_bytes: TAG21_VECTOR_BYTES_V1,
                actual_bytes: Some(actual),
            },
        )
    }
}

#[allow(
    unsafe_code,
    reason = "the private qualification boundary changes only the calling thread's SVE VL and immediately verifies it"
)]
pub(super) fn configure_current_thread_sve_vl16_v1()
-> Result<u16, StaticSearchSpanThreadContractErrorV1> {
    // SAFETY: PR_SVE_SET_VL changes only the calling thread's architectural
    // SVE state. No inherit/on-exec flags are requested.
    let status = unsafe {
        libc::prctl(
            PR_SVE_SET_VL_V1,
            libc::c_ulong::from(TAG21_VECTOR_BYTES_V1),
            PRCTL_ZERO_V1,
            PRCTL_ZERO_V1,
            PRCTL_ZERO_V1,
        )
    };
    if status < 0 {
        return Err(
            StaticSearchSpanThreadContractErrorV1::SveVectorLengthSetFailed {
                errno: std::io::Error::last_os_error().raw_os_error(),
            },
        );
    }
    let actual = current_thread_sve_vector_bytes_v1()?;
    if actual == TAG21_VECTOR_BYTES_V1 {
        Ok(actual)
    } else {
        Err(
            StaticSearchSpanThreadContractErrorV1::RequiredSveVectorLengthUnavailable {
                required_bytes: TAG21_VECTOR_BYTES_V1,
                actual_bytes: Some(actual),
            },
        )
    }
}

#[allow(
    unsafe_code,
    reason = "the sole address-to-callable conversion follows row, ELF segment, metadata, feature, offset, and digest checks"
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

fn required_protection(purpose: SegmentPurpose) -> i32 {
    match purpose {
        SegmentPurpose::Payload => libc::PROT_READ | libc::PROT_EXEC,
        SegmentPurpose::Metadata | SegmentPurpose::Expectation => libc::PROT_READ,
    }
}

fn segment_protection(flags: u32) -> i32 {
    let mut protection = 0;
    if flags & libc::PF_R != 0 {
        protection |= libc::PROT_READ;
    }
    if flags & libc::PF_W != 0 {
        protection |= libc::PROT_WRITE;
    }
    if flags & libc::PF_X != 0 {
        protection |= libc::PROT_EXEC;
    }
    protection
}

fn protection_error(purpose: SegmentPurpose, protection: i32) -> StaticSearchSpanVerifyErrorV1 {
    match purpose {
        SegmentPurpose::Payload => StaticSearchSpanVerifyErrorV1::PayloadProtectionMismatch {
            protection,
            maximum_protection: protection,
        },
        SegmentPurpose::Metadata => StaticSearchSpanVerifyErrorV1::MetadataProtectionMismatch {
            protection,
            maximum_protection: protection,
        },
        SegmentPurpose::Expectation => {
            StaticSearchSpanVerifyErrorV1::ExpectationProtectionMismatch {
                protection,
                maximum_protection: protection,
            }
        }
    }
}

#[allow(
    unsafe_code,
    reason = "the callback reads loader-owned immutable ELF program headers and updates only its caller-owned query"
)]
unsafe extern "C" fn inspect_load_segments(
    info: *mut libc::dl_phdr_info,
    _size: usize,
    data: *mut libc::c_void,
) -> libc::c_int {
    if info.is_null() || data.is_null() {
        return 0;
    }
    // SAFETY: dl_iterate_phdr supplies a valid info record and this call
    // supplied the exact SegmentQueryV1 pointer as callback data.
    let info = unsafe { &*info };
    if info.dlpi_phnum == 0 || info.dlpi_phdr.is_null() {
        return 0;
    }
    // SAFETY: a nonzero program-header count from the loader names that many
    // immutable headers and the null case was rejected above.
    let headers = unsafe { slice::from_raw_parts(info.dlpi_phdr, usize::from(info.dlpi_phnum)) };
    // SAFETY: data is the unique callback-duration borrow of the query.
    let query = unsafe { &mut *data.cast::<SegmentQueryV1>() };
    for header in headers {
        if header.p_type != libc::PT_LOAD {
            continue;
        }
        let Ok(base) = usize::try_from(info.dlpi_addr) else {
            query.failure = Some(StaticSearchSpanVerifyErrorV1::AddressRangeOverflow);
            return 1;
        };
        let Ok(virtual_address) = usize::try_from(header.p_vaddr) else {
            query.failure = Some(StaticSearchSpanVerifyErrorV1::AddressRangeOverflow);
            return 1;
        };
        let Ok(bytes) = usize::try_from(header.p_memsz) else {
            query.failure = Some(StaticSearchSpanVerifyErrorV1::AddressRangeOverflow);
            return 1;
        };
        let Some(start) = base.checked_add(virtual_address) else {
            query.failure = Some(StaticSearchSpanVerifyErrorV1::AddressRangeOverflow);
            return 1;
        };
        let Some(end) = start.checked_add(bytes) else {
            query.failure = Some(StaticSearchSpanVerifyErrorV1::AddressRangeOverflow);
            return 1;
        };
        if start <= query.start && query.end <= end {
            let protection = segment_protection(header.p_flags);
            if protection == required_protection(query.purpose) {
                query.found = true;
            } else {
                query.failure = Some(protection_error(query.purpose, protection));
            }
            return 1;
        }
    }
    0
}

#[allow(
    unsafe_code,
    reason = "dl_iterate_phdr is the allocation-free final-image ELF load-segment query boundary"
)]
fn verify_load_segment_range(
    start: usize,
    bytes: usize,
    purpose: SegmentPurpose,
) -> Result<usize, StaticSearchSpanVerifyErrorV1> {
    if bytes == 0 {
        return Err(StaticSearchSpanVerifyErrorV1::VmRegionDoesNotCoverRange);
    }
    let end = start
        .checked_add(bytes)
        .ok_or(StaticSearchSpanVerifyErrorV1::AddressRangeOverflow)?;
    let mut query = SegmentQueryV1 {
        start,
        end,
        purpose,
        found: false,
        failure: None,
    };
    // SAFETY: the callback and data pointer share this exact call lifetime;
    // neither is retained by dl_iterate_phdr.
    let status = unsafe {
        libc::dl_iterate_phdr(
            Some(inspect_load_segments),
            ptr::from_mut(&mut query).cast::<libc::c_void>(),
        )
    };
    if let Some(error) = query.failure {
        return Err(error);
    }
    if status < 0 {
        return Err(StaticSearchSpanVerifyErrorV1::VmRegionQueryFailed { code: status });
    }
    if !query.found {
        return Err(StaticSearchSpanVerifyErrorV1::VmRegionDoesNotCoverRange);
    }
    Ok(1)
}

fn verify_mapped_range(
    start: usize,
    bytes: usize,
    purpose: SegmentPurpose,
) -> Result<usize, StaticSearchSpanVerifyErrorV1> {
    let load_segments = verify_load_segment_range(start, bytes, purpose)?;
    let live_regions = verify_live_vma_range(start, bytes, purpose)?;
    load_segments
        .checked_add(live_regions)
        .ok_or(StaticSearchSpanVerifyErrorV1::InspectionAccountingOverflow)
}

fn verify_live_vma_range(
    start: usize,
    bytes: usize,
    purpose: SegmentPurpose,
) -> Result<usize, StaticSearchSpanVerifyErrorV1> {
    if bytes == 0 {
        return Err(StaticSearchSpanVerifyErrorV1::VmRegionDoesNotCoverRange);
    }
    let end = start
        .checked_add(bytes)
        .ok_or(StaticSearchSpanVerifyErrorV1::AddressRangeOverflow)?;
    let file = std::fs::File::open("/proc/self/maps").map_err(|error| map_io_error(&error))?;
    find_live_vma(file, start, end, purpose)
}

fn find_live_vma(
    mut reader: impl Read,
    start: usize,
    end: usize,
    purpose: SegmentPurpose,
) -> Result<usize, StaticSearchSpanVerifyErrorV1> {
    let mut read_buffer = [0_u8; PROC_MAPS_READ_BUFFER_BYTES_V1];
    let mut line_buffer = [0_u8; MAX_PROC_MAPS_LINE_BYTES_V1];
    let mut line_bytes = 0_usize;
    let mut total_bytes = 0_usize;
    loop {
        let bytes_read = match reader.read(&mut read_buffer) {
            Ok(0) => break,
            Ok(bytes_read) => bytes_read,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(map_io_error(&error)),
        };
        total_bytes = total_bytes
            .checked_add(bytes_read)
            .ok_or(StaticSearchSpanVerifyErrorV1::InspectionAccountingOverflow)?;
        if total_bytes > MAX_PROC_MAPS_BYTES_V1 {
            return Err(StaticSearchSpanVerifyErrorV1::VmRegionQueryFailed {
                code: libc::EOVERFLOW,
            });
        }
        for &byte in &read_buffer[..bytes_read] {
            if byte == b'\n' {
                if inspect_maps_line(&line_buffer[..line_bytes], start, end, purpose)? {
                    return Ok(1);
                }
                line_bytes = 0;
            } else {
                let destination = line_buffer.get_mut(line_bytes).ok_or(
                    StaticSearchSpanVerifyErrorV1::VmRegionQueryFailed {
                        code: libc::EOVERFLOW,
                    },
                )?;
                *destination = byte;
                line_bytes = line_bytes
                    .checked_add(1)
                    .ok_or(StaticSearchSpanVerifyErrorV1::InspectionAccountingOverflow)?;
            }
        }
    }
    if line_bytes != 0 && inspect_maps_line(&line_buffer[..line_bytes], start, end, purpose)? {
        return Ok(1);
    }
    Err(StaticSearchSpanVerifyErrorV1::VmRegionDoesNotCoverRange)
}

fn inspect_maps_line(
    line: &[u8],
    required_start: usize,
    required_end: usize,
    purpose: SegmentPurpose,
) -> Result<bool, StaticSearchSpanVerifyErrorV1> {
    let line = core::str::from_utf8(line)
        .map_err(|_| StaticSearchSpanVerifyErrorV1::VmRegionQueryFailed { code: libc::EINVAL })?;
    let mut fields = line.split_ascii_whitespace();
    let range = fields
        .next()
        .ok_or(StaticSearchSpanVerifyErrorV1::VmRegionQueryFailed { code: libc::EINVAL })?;
    let permissions = fields
        .next()
        .ok_or(StaticSearchSpanVerifyErrorV1::VmRegionQueryFailed { code: libc::EINVAL })?;
    let (start, end) = range
        .split_once('-')
        .ok_or(StaticSearchSpanVerifyErrorV1::VmRegionQueryFailed { code: libc::EINVAL })?;
    let start = usize::from_str_radix(start, 16)
        .map_err(|_| StaticSearchSpanVerifyErrorV1::VmRegionQueryFailed { code: libc::EINVAL })?;
    let end = usize::from_str_radix(end, 16)
        .map_err(|_| StaticSearchSpanVerifyErrorV1::VmRegionQueryFailed { code: libc::EINVAL })?;
    if start > required_start || required_end > end {
        return Ok(false);
    }
    let permissions = permissions.as_bytes();
    if permissions.len() != 4 {
        return Err(StaticSearchSpanVerifyErrorV1::VmRegionQueryFailed { code: libc::EINVAL });
    }
    let mut protection = libc::PROT_NONE;
    if permissions[0] == b'r' {
        protection |= libc::PROT_READ;
    } else if permissions[0] != b'-' {
        return Err(StaticSearchSpanVerifyErrorV1::VmRegionQueryFailed { code: libc::EINVAL });
    }
    if permissions[1] == b'w' {
        protection |= libc::PROT_WRITE;
    } else if permissions[1] != b'-' {
        return Err(StaticSearchSpanVerifyErrorV1::VmRegionQueryFailed { code: libc::EINVAL });
    }
    if permissions[2] == b'x' {
        protection |= libc::PROT_EXEC;
    } else if permissions[2] != b'-' {
        return Err(StaticSearchSpanVerifyErrorV1::VmRegionQueryFailed { code: libc::EINVAL });
    }
    if permissions[3] != b'p' {
        return Err(StaticSearchSpanVerifyErrorV1::LiveVmRegionIsNotPrivate);
    }
    if protection != required_protection(purpose) {
        return Err(protection_error(purpose, protection));
    }
    Ok(true)
}

fn map_io_error(error: &std::io::Error) -> StaticSearchSpanVerifyErrorV1 {
    StaticSearchSpanVerifyErrorV1::VmRegionQueryFailed {
        code: error.raw_os_error().unwrap_or(libc::EIO),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_elf_segment_protections_are_distinct() {
        assert_eq!(
            segment_protection(libc::PF_R | libc::PF_X),
            libc::PROT_READ | libc::PROT_EXEC
        );
        assert_eq!(segment_protection(libc::PF_R), libc::PROT_READ);
        assert_ne!(
            segment_protection(libc::PF_R | libc::PF_W | libc::PF_X),
            required_protection(SegmentPurpose::Payload)
        );
        assert_ne!(
            segment_protection(libc::PF_R | libc::PF_X),
            required_protection(SegmentPurpose::Metadata)
        );
    }

    #[test]
    fn tag21_requires_the_complete_linux_feature_envelope() {
        let all = HostFeaturesV1 {
            asimd: true,
            sve: true,
            sve2: true,
            sve_vector_bytes: Some(TAG21_VECTOR_BYTES_V1),
            tag21_tuning: true,
        };
        assert_eq!(
            require_host_features(SEARCH_REQUIRED_SVE2_FIXED16_FEATURES_V1, all),
            Ok(())
        );
        for missing in [
            HostFeaturesV1 {
                asimd: false,
                ..all
            },
            HostFeaturesV1 { sve: false, ..all },
            HostFeaturesV1 { sve2: false, ..all },
            HostFeaturesV1 {
                sve_vector_bytes: Some(32),
                ..all
            },
            HostFeaturesV1 {
                tag21_tuning: false,
                ..all
            },
        ] {
            assert!(
                require_host_features(SEARCH_REQUIRED_SVE2_FIXED16_FEATURES_V1, missing).is_err()
            );
        }
    }

    #[test]
    fn range_arithmetic_refuses_before_loader_query() {
        assert_eq!(
            verify_load_segment_range(usize::MAX, 2, SegmentPurpose::Payload),
            Err(StaticSearchSpanVerifyErrorV1::AddressRangeOverflow)
        );
        assert_eq!(
            verify_load_segment_range(0, 0, SegmentPurpose::Payload),
            Err(StaticSearchSpanVerifyErrorV1::VmRegionDoesNotCoverRange)
        );
    }

    #[test]
    fn proc_maps_parser_requires_one_exact_private_vma() {
        let source = b"1000-2000 r-xp 00000000 00:00 0\n2000-3000 r--p 00000000 00:00 0\n";
        assert_eq!(
            find_live_vma(source.as_slice(), 0x1100, 0x1200, SegmentPurpose::Payload),
            Ok(1)
        );
        assert_eq!(
            find_live_vma(source.as_slice(), 0x2100, 0x2200, SegmentPurpose::Metadata),
            Ok(1)
        );
        assert!(find_live_vma(source.as_slice(), 0x1f00, 0x2100, SegmentPurpose::Payload).is_err());
        assert!(
            find_live_vma(
                b"1000-2000 rwxp 00000000 00:00 0\n".as_slice(),
                0x1100,
                0x1200,
                SegmentPurpose::Payload
            )
            .is_err()
        );
        assert_eq!(
            find_live_vma(
                b"1000-2000 r-xs 00000000 00:00 0\n".as_slice(),
                0x1100,
                0x1200,
                SegmentPurpose::Payload,
            ),
            Err(StaticSearchSpanVerifyErrorV1::LiveVmRegionIsNotPrivate)
        );
    }
}
