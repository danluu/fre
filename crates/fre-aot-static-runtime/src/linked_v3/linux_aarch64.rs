use std::{fs::File, io::Read};

use fre_aot_aarch64::AotCountCpuFeatures;

use crate::StaticCountVerifyErrorV3;

const HARD_MAX_PROC_MAPS_BYTES_V3: usize = 4 << 20;
pub(super) const VM_QUERY_INPUT_BYTES_UPPER_BOUND_V3: u32 = (4 << 20) + 1;

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

pub(super) fn require_host_contract(
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
    // This movable handle is deliberately ASIMD-only. Any future SVE/SVE2
    // row needs a same-thread, non-Send/non-Sync exact-VL session.
    if features.contains(AotCountCpuFeatures::SVE)
        || features.contains(AotCountCpuFeatures::SVE2)
        || sve_vector_length_bytes != 0
    {
        return Err(StaticCountVerifyErrorV3::RequiredCpuFeaturesUnavailable);
    }
    Ok(())
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
