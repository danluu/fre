use core::mem;

use fre_aot_aarch64::AotCountCpuFeatures;

use crate::StaticCountSveThreadContractErrorV3;
use crate::StaticCountVerifyErrorV3;

pub(super) const VM_QUERY_INPUT_BYTES_UPPER_BOUND_V3: u32 = 0;

#[allow(
    unsafe_code,
    reason = "reviewed read-only Mach VM query and returned-port release declarations"
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
pub(super) enum RegionPurposeV3 {
    Expectation,
    Metadata,
    Payload,
}

impl RegionPurposeV3 {
    const fn name(self) -> &'static str {
        match self {
            Self::Expectation => "expectation",
            Self::Metadata => "metadata",
            Self::Payload => "payload",
        }
    }
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

pub(super) fn verify_range(
    start: usize,
    bytes: usize,
    purpose: RegionPurposeV3,
) -> Result<usize, StaticCountVerifyErrorV3> {
    if bytes == 0 {
        return Err(StaticCountVerifyErrorV3::VmRegionDoesNotCoverRange);
    }
    let end = start
        .checked_add(bytes)
        .ok_or(StaticCountVerifyErrorV3::AddressRangeOverflow)?;
    let mut cursor = start;
    let mut regions = 0_usize;
    while cursor < end {
        let region = query_region(cursor)?;
        let region_end = region
            .start
            .checked_add(region.bytes)
            .ok_or(StaticCountVerifyErrorV3::AddressRangeOverflow)?;
        if region.start > cursor || region_end <= cursor {
            return Err(StaticCountVerifyErrorV3::VmRegionDoesNotCoverRange);
        }
        require_protection(region, purpose)?;
        cursor = region_end.min(end);
        regions = regions
            .checked_add(1)
            .ok_or(StaticCountVerifyErrorV3::InspectionAccountingOverflow)?;
    }
    Ok(regions)
}

fn require_protection(
    region: Region,
    purpose: RegionPurposeV3,
) -> Result<(), StaticCountVerifyErrorV3> {
    let current = region.protection;
    let maximum = region.maximum_protection;
    let read = libc::PROT_READ;
    let write = libc::PROT_WRITE;
    let execute = libc::PROT_EXEC;
    let required = match purpose {
        RegionPurposeV3::Payload => read | execute,
        RegionPurposeV3::Metadata | RegionPurposeV3::Expectation => read,
    };
    if current == required && maximum == required {
        return Ok(());
    }
    Err(StaticCountVerifyErrorV3::ProtectionMismatch {
        purpose: purpose.name(),
        readable: current & read != 0,
        writable: current & write != 0,
        executable: current & execute != 0,
    })
}

#[allow(
    deprecated,
    reason = "Mach VM region inspection uses the libc current-task-port shim"
)]
#[allow(
    unsafe_code,
    reason = "owns the complete initialized Mach VM query and port-release transaction"
)]
fn query_region(pointer: usize) -> Result<Region, StaticCountVerifyErrorV3> {
    const VM_REGION_BASIC_INFO_64: libc::c_int = 9;

    let mut address =
        u64::try_from(pointer).map_err(|_| StaticCountVerifyErrorV3::AddressRangeOverflow)?;
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
        .ok_or(StaticCountVerifyErrorV3::AddressRangeOverflow)?;
    let mut info_count =
        u32::try_from(info_words).map_err(|_| StaticCountVerifyErrorV3::AddressRangeOverflow)?;
    let mut object: libc::mach_port_t = 0;
    // SAFETY: libc returns the current task port name.
    let task = unsafe { libc::mach_task_self() };
    // SAFETY: every out-pointer names initialized correctly sized storage.
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
        return Err(StaticCountVerifyErrorV3::VmRegionQueryFailed { code: result });
    }
    if object != 0 {
        // SAFETY: object is the send right returned by this query.
        let deallocated = unsafe { mach_port_deallocate(task, object) };
        if deallocated != libc::KERN_SUCCESS {
            return Err(StaticCountVerifyErrorV3::VmRegionQueryFailed { code: deallocated });
        }
    }
    Ok(Region {
        start: usize::try_from(address)
            .map_err(|_| StaticCountVerifyErrorV3::AddressRangeOverflow)?,
        bytes: usize::try_from(size).map_err(|_| StaticCountVerifyErrorV3::AddressRangeOverflow)?,
        protection: info.protection,
        maximum_protection: info.max_protection,
    })
}

pub(super) fn require_asimd_host_contract(
    actual_features: u64,
    sve_vector_length_bytes: u16,
) -> Result<(), StaticCountVerifyErrorV3> {
    let features = AotCountCpuFeatures::from_bits(actual_features)
        .ok_or(StaticCountVerifyErrorV3::RequiredCpuFeaturesUnavailable)?;
    if features.contains(AotCountCpuFeatures::SVE)
        || features.contains(AotCountCpuFeatures::SVE2)
        || sve_vector_length_bytes != 0
    {
        return Err(StaticCountVerifyErrorV3::RequiredCpuFeaturesUnavailable);
    }
    // Advanced SIMD is architectural on the reviewed arm64 macOS target.
    Ok(())
}

pub(super) fn require_sve_host_contract(
    _actual_features: u64,
    _required_isa_id: u8,
    _sve_vector_length_bytes: u16,
) -> Result<(), StaticCountVerifyErrorV3> {
    Err(StaticCountVerifyErrorV3::UnsupportedHost)
}

pub(super) fn require_current_thread_sve_target_v3(
    _required_isa_id: u8,
    _actual_features: u64,
    _sve_vector_length_bytes: u16,
) -> Result<(), StaticCountSveThreadContractErrorV3> {
    Err(StaticCountSveThreadContractErrorV3::UnsupportedHost)
}

#[cfg(feature = "count-v3-qualification-private")]
pub(super) fn configure_current_thread_sve_vl16_v3()
-> Result<u16, StaticCountSveThreadContractErrorV3> {
    Err(StaticCountSveThreadContractErrorV3::UnsupportedHost)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protection_policy_checks_current_and_maximum() {
        let region = |protection, maximum_protection| Region {
            start: 0x1000,
            bytes: 0x1000,
            protection,
            maximum_protection,
        };
        assert!(
            require_protection(
                region(
                    libc::PROT_READ | libc::PROT_EXEC,
                    libc::PROT_READ | libc::PROT_EXEC
                ),
                RegionPurposeV3::Payload
            )
            .is_ok()
        );
        assert!(
            require_protection(
                region(libc::PROT_READ, libc::PROT_READ),
                RegionPurposeV3::Metadata
            )
            .is_ok()
        );
        assert!(
            require_protection(
                region(libc::PROT_READ, libc::PROT_READ | libc::PROT_WRITE),
                RegionPurposeV3::Expectation
            )
            .is_err()
        );
    }
}
