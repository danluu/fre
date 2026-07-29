use std::{fs::File, io::Read};

use fre_aot_aarch64::AotCountCpuFeatures;

use crate::StaticCountSveThreadContractErrorV3;
use crate::StaticCountVerifyErrorV3;

const HARD_MAX_PROC_MAPS_BYTES_V3: usize = 4 << 20;
pub(super) const VM_QUERY_INPUT_BYTES_UPPER_BOUND_V3: u32 = (4 << 20) + 1;
const AT_HWCAP_V3: libc::c_ulong = 16;
const AT_HWCAP2_V3: libc::c_ulong = 26;
const AARCH64_HWCAP_SVE_V3: libc::c_ulong = 0x0040_0000;
const AARCH64_HWCAP2_SVE2_V3: libc::c_ulong = 0x0000_0002;
#[cfg(feature = "count-v3-qualification-private")]
const PR_SVE_SET_VL_V3: libc::c_int = 50;
const PR_SVE_GET_VL_V3: libc::c_int = 51;
const PR_SVE_VL_LEN_MASK_V3: libc::c_int = 0xffff;
const COUNT_V3_SVE_VECTOR_BYTES: u16 = 16;
const PRCTL_ZERO_V3: libc::c_ulong = 0;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Region {
    start: usize,
    end: usize,
    readable: bool,
    writable: bool,
    executable: bool,
    private: bool,
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
    let maps = read_bounded_proc_maps_v3()?;
    let mut cursor = start;
    let mut regions = 0_usize;
    for line in maps.lines() {
        let Some(region) = parse_region(line) else {
            continue;
        };
        if region.end <= cursor {
            continue;
        }
        if region.start > cursor {
            break;
        }
        if !region.private {
            return Err(StaticCountVerifyErrorV3::VmRegionIsNotPrivate);
        }
        require_protection(region, purpose)?;
        cursor = region.end.min(end);
        regions = regions
            .checked_add(1)
            .ok_or(StaticCountVerifyErrorV3::InspectionAccountingOverflow)?;
        if cursor == end {
            return Ok(regions);
        }
    }
    Err(StaticCountVerifyErrorV3::VmRegionDoesNotCoverRange)
}

fn read_bounded_proc_maps_v3() -> Result<String, StaticCountVerifyErrorV3> {
    let file = File::open("/proc/self/maps").map_err(vm_query_error)?;
    let read_limit = HARD_MAX_PROC_MAPS_BYTES_V3
        .checked_add(1)
        .ok_or(StaticCountVerifyErrorV3::InspectionAccountingOverflow)?;
    let mut maps = String::new();
    maps.try_reserve_exact(read_limit)
        .map_err(|_| StaticCountVerifyErrorV3::InspectionAllocationFailed)?;
    file.take(
        u64::try_from(read_limit)
            .map_err(|_| StaticCountVerifyErrorV3::InspectionAccountingOverflow)?,
    )
    .read_to_string(&mut maps)
    .map_err(vm_query_error)?;
    if maps.len() > HARD_MAX_PROC_MAPS_BYTES_V3 {
        return Err(StaticCountVerifyErrorV3::VmRegionQueryFailed { code: libc::E2BIG });
    }
    Ok(maps)
}

fn vm_query_error(error: std::io::Error) -> StaticCountVerifyErrorV3 {
    StaticCountVerifyErrorV3::VmRegionQueryFailed {
        code: error.raw_os_error().unwrap_or(-1),
    }
}

fn parse_region(line: &str) -> Option<Region> {
    let mut fields = line.split_ascii_whitespace();
    let range = fields.next()?;
    let permissions = fields.next()?.as_bytes();
    if permissions.len() != 4 {
        return None;
    }
    let (start, end) = range.split_once('-')?;
    Some(Region {
        start: usize::from_str_radix(start, 16).ok()?,
        end: usize::from_str_radix(end, 16).ok()?,
        readable: permissions[0] == b'r',
        writable: permissions[1] == b'w',
        executable: permissions[2] == b'x',
        private: permissions[3] == b'p',
    })
}

fn require_protection(
    region: Region,
    purpose: RegionPurposeV3,
) -> Result<(), StaticCountVerifyErrorV3> {
    let valid = match purpose {
        RegionPurposeV3::Payload => region.readable && !region.writable && region.executable,
        RegionPurposeV3::Expectation | RegionPurposeV3::Metadata => {
            region.readable && !region.writable && !region.executable
        }
    };
    if valid {
        Ok(())
    } else {
        Err(StaticCountVerifyErrorV3::ProtectionMismatch {
            purpose: purpose.name(),
            readable: region.readable,
            writable: region.writable,
            executable: region.executable,
        })
    }
}

pub(super) fn require_asimd_host_contract(
    actual_features: u64,
    sve_vector_length_bytes: u16,
) -> Result<(), StaticCountVerifyErrorV3> {
    let features = AotCountCpuFeatures::from_bits(actual_features)
        .ok_or(StaticCountVerifyErrorV3::RequiredCpuFeaturesUnavailable)?;
    if features.contains(AotCountCpuFeatures::ASIMD)
        && !std::arch::is_aarch64_feature_detected!("neon")
    {
        return Err(StaticCountVerifyErrorV3::RequiredCpuFeaturesUnavailable);
    }
    // This movable handle is deliberately ASIMD-only. Any production
    // SVE/SVE2 promotion needs its own source-authorized same-thread session.
    if features.contains(AotCountCpuFeatures::SVE)
        || features.contains(AotCountCpuFeatures::SVE2)
        || sve_vector_length_bytes != 0
    {
        return Err(StaticCountVerifyErrorV3::RequiredCpuFeaturesUnavailable);
    }
    Ok(())
}

pub(super) fn require_sve_host_contract(
    actual_features: u64,
    required_isa_id: u8,
    sve_vector_length_bytes: u16,
) -> Result<(), StaticCountVerifyErrorV3> {
    let (hwcap, hwcap2) = host_hwcap_v3();
    let exact_features = match required_isa_id {
        2 => actual_features == AotCountCpuFeatures::SVE.bits(),
        3 => {
            actual_features
                == AotCountCpuFeatures::SVE
                    .union(AotCountCpuFeatures::SVE2)
                    .bits()
        }
        _ => false,
    };
    if sve_vector_length_bytes != COUNT_V3_SVE_VECTOR_BYTES
        || !exact_features
        || hwcap & AARCH64_HWCAP_SVE_V3 == 0
    {
        return Err(StaticCountVerifyErrorV3::RequiredCpuFeaturesUnavailable);
    }
    if required_isa_id == 3 && hwcap2 & AARCH64_HWCAP2_SVE2_V3 == 0 {
        return Err(StaticCountVerifyErrorV3::RequiredCpuFeaturesUnavailable);
    }
    require_current_thread_sve_target_v3(required_isa_id, actual_features, sve_vector_length_bytes)
        .map_err(
            |_| StaticCountVerifyErrorV3::RequiredSveVectorLengthUnavailable {
                required_bytes: COUNT_V3_SVE_VECTOR_BYTES,
            },
        )
}

#[allow(
    unsafe_code,
    reason = "Linux auxv is the immutable kernel-provided architectural feature boundary"
)]
fn host_hwcap_v3() -> (libc::c_ulong, libc::c_ulong) {
    // SAFETY: getauxval reads the immutable process auxiliary vector.
    unsafe { (libc::getauxval(AT_HWCAP_V3), libc::getauxval(AT_HWCAP2_V3)) }
}

#[allow(
    unsafe_code,
    reason = "PR_SVE_GET_VL reads only the calling thread's architectural SVE state"
)]
fn current_thread_sve_vector_bytes_v3() -> Result<u16, StaticCountSveThreadContractErrorV3> {
    // SAFETY: PR_SVE_GET_VL ignores all four unsigned-long arguments.
    let raw = unsafe {
        libc::prctl(
            PR_SVE_GET_VL_V3,
            PRCTL_ZERO_V3,
            PRCTL_ZERO_V3,
            PRCTL_ZERO_V3,
            PRCTL_ZERO_V3,
        )
    };
    if raw < 0 {
        return Err(
            StaticCountSveThreadContractErrorV3::SveVectorLengthQueryFailed {
                errno: std::io::Error::last_os_error().raw_os_error(),
            },
        );
    }
    u16::try_from(raw & PR_SVE_VL_LEN_MASK_V3).map_err(|_| {
        StaticCountSveThreadContractErrorV3::RequiredSveVectorLengthUnavailable {
            required_bytes: COUNT_V3_SVE_VECTOR_BYTES,
            actual_bytes: None,
        }
    })
}

pub(super) fn require_current_thread_sve_vl16_v3() -> Result<(), StaticCountSveThreadContractErrorV3>
{
    let actual = current_thread_sve_vector_bytes_v3()?;
    if actual == COUNT_V3_SVE_VECTOR_BYTES {
        Ok(())
    } else {
        Err(
            StaticCountSveThreadContractErrorV3::RequiredSveVectorLengthUnavailable {
                required_bytes: COUNT_V3_SVE_VECTOR_BYTES,
                actual_bytes: Some(actual),
            },
        )
    }
}

pub(super) fn require_current_thread_sve_target_v3(
    required_isa_id: u8,
    actual_features: u64,
    sve_vector_length_bytes: u16,
) -> Result<(), StaticCountSveThreadContractErrorV3> {
    let (hwcap, hwcap2) = host_hwcap_v3();
    if sve_vector_length_bytes != COUNT_V3_SVE_VECTOR_BYTES {
        return Err(
            StaticCountSveThreadContractErrorV3::RequiredSveVectorLengthUnavailable {
                required_bytes: COUNT_V3_SVE_VECTOR_BYTES,
                actual_bytes: Some(sve_vector_length_bytes),
            },
        );
    }
    if hwcap & AARCH64_HWCAP_SVE_V3 == 0 {
        return Err(StaticCountSveThreadContractErrorV3::RequiredSveUnavailable);
    }
    match required_isa_id {
        2 if actual_features == AotCountCpuFeatures::SVE.bits() => {}
        2 => return Err(StaticCountSveThreadContractErrorV3::RequiredSveUnavailable),
        3 if actual_features
            != AotCountCpuFeatures::SVE
                .union(AotCountCpuFeatures::SVE2)
                .bits() =>
        {
            return Err(StaticCountSveThreadContractErrorV3::RequiredSve2Unavailable);
        }
        3 if hwcap2 & AARCH64_HWCAP2_SVE2_V3 != 0 => {}
        3 => return Err(StaticCountSveThreadContractErrorV3::RequiredSve2Unavailable),
        _ => return Err(StaticCountSveThreadContractErrorV3::RequiredSveUnavailable),
    }
    require_current_thread_sve_vl16_v3()
}

#[cfg(feature = "count-v3-qualification-private")]
#[allow(
    unsafe_code,
    reason = "qualification changes only this thread's SVE VL and immediately checks the result"
)]
pub(super) fn configure_current_thread_sve_vl16_v3()
-> Result<u16, StaticCountSveThreadContractErrorV3> {
    let (hwcap, _) = host_hwcap_v3();
    if hwcap & AARCH64_HWCAP_SVE_V3 == 0 {
        return Err(StaticCountSveThreadContractErrorV3::RequiredSveUnavailable);
    }
    // SAFETY: no inherit/on-exec flags are requested; only this thread changes.
    let status = unsafe {
        libc::prctl(
            PR_SVE_SET_VL_V3,
            libc::c_ulong::from(COUNT_V3_SVE_VECTOR_BYTES),
            PRCTL_ZERO_V3,
            PRCTL_ZERO_V3,
            PRCTL_ZERO_V3,
        )
    };
    if status < 0 {
        return Err(
            StaticCountSveThreadContractErrorV3::SveVectorLengthSetFailed {
                errno: std::io::Error::last_os_error().raw_os_error(),
            },
        );
    }
    let actual = current_thread_sve_vector_bytes_v3()?;
    if actual == COUNT_V3_SVE_VECTOR_BYTES {
        Ok(actual)
    } else {
        Err(
            StaticCountSveThreadContractErrorV3::RequiredSveVectorLengthUnavailable {
                required_bytes: COUNT_V3_SVE_VECTOR_BYTES,
                actual_bytes: Some(actual),
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_maps_parser_is_strict() {
        let region = parse_region("1000-2000 r-xp 00000000 00:00 0").unwrap();
        assert_eq!(region.start, 0x1000);
        assert_eq!(region.end, 0x2000);
        assert!(region.readable);
        assert!(region.executable);
        assert!(region.private);
        assert!(!region.writable);
        assert!(parse_region("not-a-map-line").is_none());
    }
}
