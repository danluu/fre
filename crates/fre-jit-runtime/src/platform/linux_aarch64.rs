//! Linux hooks for the shared `AArch64` strict-W^X publisher.

use core::{arch::asm, ffi::c_void};
use std::sync::OnceLock;

#[cfg(test)]
use crate::{FailureStage, PublishError};

const CTR_EL0_IMINLINE_SHIFT: u32 = 0;
const CTR_EL0_DMINLINE_SHIFT: u32 = 16;
const CTR_EL0_IDC: usize = 1 << 28;
const CTR_EL0_DIC: usize = 1 << 29;

// Linux UAPI values from asm/hwcap.h and linux/auxvec.h. The pinned libc
// exposes HWCAP_SVE but does not expose the SVE2 selector and bit on every
// supported toolchain.
const AT_HWCAP2: libc::c_ulong = 26;
const HWCAP2_SVE2: libc::c_ulong = 1 << 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HostFeatures {
    asimd: bool,
    sve: bool,
    sve2: bool,
}

static HOST_FEATURES: OnceLock<HostFeatures> = OnceLock::new();

fn host_features() -> HostFeatures {
    *HOST_FEATURES.get_or_init(|| {
        // SAFETY: `getauxval` takes scalar selectors with no pointer contract.
        let hwcap = unsafe { libc::getauxval(libc::AT_HWCAP) };
        // SAFETY: `AT_HWCAP2` is the Linux UAPI scalar selector.
        let hwcap2 = unsafe { libc::getauxval(AT_HWCAP2) };
        let sve = hwcap & libc::HWCAP_SVE != 0;
        HostFeatures {
            asimd: hwcap & libc::HWCAP_ASIMD != 0,
            sve,
            // SVE2 architecturally depends on SVE. Preserve that dependency
            // even if a malformed or virtualized auxv advertises only SVE2.
            sve2: sve && hwcap2 & HWCAP2_SVE2 != 0,
        }
    })
}

pub(super) fn has_asimd() -> bool {
    host_features().asimd
}

pub(super) fn has_sve() -> bool {
    host_features().sve
}

pub(super) fn has_sve2() -> bool {
    host_features().sve2
}

/// Synchronize one initialized code range before its entry becomes callable.
///
/// # Safety
///
/// `start..start+length` must be a live process-local mapping containing the
/// instructions just published by the shared state machine.
pub(super) unsafe fn synchronize_instruction_cache(start: *mut c_void, length: usize) {
    let start_address = start.addr();
    let end_address = start_address
        .checked_add(length)
        .expect("a live mmap range cannot wrap the address space");
    let ctr_el0: usize;
    // SAFETY: Linux/AArch64 permits EL0 to read CTR_EL0. The instruction has no
    // memory operands and does not modify the stack or condition flags.
    unsafe {
        asm!(
            "mrs {value}, ctr_el0",
            value = out(reg) ctr_el0,
            options(nomem, nostack, preserves_flags)
        );
    }

    if ctr_el0 & CTR_EL0_IDC == 0 {
        let line_bytes = cache_line_bytes(ctr_el0, CTR_EL0_DMINLINE_SHIFT);
        // SAFETY: every address belongs to a cache line intersecting the live
        // mapped code range supplied by the caller.
        unsafe { clean_data_cache(start_address, end_address, line_bytes) };
    }
    // This orders the initialized instruction bytes before instruction-cache
    // maintenance, including machines that report IDC.
    // SAFETY: `dsb ish` has no operands and only strengthens memory ordering.
    unsafe { asm!("dsb ish", options(nostack, preserves_flags)) };

    if ctr_el0 & CTR_EL0_DIC == 0 {
        let line_bytes = cache_line_bytes(ctr_el0, CTR_EL0_IMINLINE_SHIFT);
        // SAFETY: every address belongs to a cache line intersecting the live
        // mapped code range supplied by the caller.
        unsafe { invalidate_instruction_cache(start_address, end_address, line_bytes) };
    }
    // Complete invalidation throughout the inner-shareable domain before any
    // subsequent instruction fetch can observe the newly published entry.
    // SAFETY: these barriers have no operands and preserve the stack and flags.
    unsafe {
        asm!("dsb ish", "isb", options(nostack, preserves_flags));
    }
}

fn cache_line_bytes(ctr_el0: usize, shift: u32) -> usize {
    let encoded = ctr_el0.checked_shr(shift).unwrap_or(0) & 0xf;
    4_usize
        .checked_shl(u32::try_from(encoded).expect("four-bit cache line encoding"))
        .expect("architectural cache line encoding fits usize")
}

unsafe fn clean_data_cache(start: usize, end: usize, line_bytes: usize) {
    let mask = line_bytes
        .checked_sub(1)
        .expect("architectural cache lines are nonempty");
    let mut address = start & !mask;
    while address < end {
        // SAFETY: the caller established the live range and this is the
        // architectural data-cache clean operation required for JIT code.
        unsafe {
            asm!(
                "dc cvau, {address}",
                address = in(reg) address,
                options(nostack, preserves_flags)
            );
        }
        address = address
            .checked_add(line_bytes)
            .expect("a live mmap range cannot wrap the address space");
    }
}

unsafe fn invalidate_instruction_cache(start: usize, end: usize, line_bytes: usize) {
    let mask = line_bytes
        .checked_sub(1)
        .expect("architectural cache lines are nonempty");
    let mut address = start & !mask;
    while address < end {
        // SAFETY: the caller established the live range and this is the
        // architectural instruction-cache invalidation required for JIT code.
        unsafe {
            asm!(
                "ic ivau, {address}",
                address = in(reg) address,
                options(nostack, preserves_flags)
            );
        }
        address = address
            .checked_add(line_bytes)
            .expect("a live mmap range cannot wrap the address space");
    }
}

#[cfg(test)]
pub(super) fn query_protection(pointer: usize) -> Result<i32, PublishError> {
    let maps =
        std::fs::read_to_string("/proc/self/maps").map_err(|error| PublishError::SystemCall {
            stage: FailureStage::Publish,
            errno: error.raw_os_error().unwrap_or(0),
        })?;
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let Some(range) = fields.next() else {
            continue;
        };
        let Some(permissions) = fields.next() else {
            continue;
        };
        let Some((start, end)) = range.split_once('-') else {
            continue;
        };
        let Ok(start) = usize::from_str_radix(start, 16) else {
            continue;
        };
        let Ok(end) = usize::from_str_radix(end, 16) else {
            continue;
        };
        if start <= pointer && pointer < end {
            let bytes = permissions.as_bytes();
            let mut protection = libc::PROT_NONE;
            if bytes.first() == Some(&b'r') {
                protection |= libc::PROT_READ;
            }
            if bytes.get(1) == Some(&b'w') {
                protection |= libc::PROT_WRITE;
            }
            if bytes.get(2) == Some(&b'x') {
                protection |= libc::PROT_EXEC;
            }
            return Ok(protection);
        }
    }
    Err(PublishError::PublicationIdentityMismatch)
}

#[cfg(test)]
mod tests {
    #[test]
    fn cached_feature_detection_matches_linux_auxv() {
        // SAFETY: `getauxval` takes only scalar auxv selectors.
        let hwcap = unsafe { libc::getauxval(libc::AT_HWCAP) };
        // SAFETY: `AT_HWCAP2` is the Linux UAPI scalar selector.
        let hwcap2 = unsafe { libc::getauxval(super::AT_HWCAP2) };
        assert_eq!(super::has_asimd(), hwcap & libc::HWCAP_ASIMD != 0);
        assert_eq!(super::has_sve(), hwcap & libc::HWCAP_SVE != 0);
        assert_eq!(
            super::has_sve2(),
            super::has_sve() && hwcap2 & super::HWCAP2_SVE2 != 0
        );
    }
}
