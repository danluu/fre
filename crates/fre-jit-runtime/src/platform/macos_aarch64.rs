//! macOS hooks for the shared `AArch64` strict-W^X publisher.

use core::ffi::c_void;

#[cfg(test)]
use core::mem;

#[cfg(test)]
use crate::{FailureStage, PublishError};

unsafe extern "C" {
    fn sys_icache_invalidate(start: *mut c_void, length: usize);

    #[cfg(test)]
    fn mach_vm_region(
        target_task: libc::mach_port_t,
        address: *mut libc::mach_vm_address_t,
        size: *mut libc::mach_vm_size_t,
        flavor: libc::c_int,
        info: *mut libc::c_int,
        info_count: *mut libc::mach_msg_type_number_t,
        object_name: *mut libc::mach_port_t,
    ) -> libc::kern_return_t;

    #[cfg(test)]
    fn mach_port_deallocate(
        task: libc::mach_port_t,
        name: libc::mach_port_t,
    ) -> libc::kern_return_t;
}

pub(super) const fn has_asimd() -> bool {
    // Advanced SIMD is mandatory in the admitted AArch64 Apple ABI.
    true
}

pub(super) const fn has_sve() -> bool {
    false
}

pub(super) const fn has_sve2() -> bool {
    false
}

pub(super) const fn sve_vector_bytes() -> Option<u16> {
    None
}

/// Synchronize one initialized code range before its entry becomes callable.
///
/// # Safety
///
/// `start..start+length` must be a live process-local mapping containing the
/// instructions just published by the shared state machine.
pub(super) unsafe fn synchronize_instruction_cache(start: *mut c_void, length: usize) {
    // SAFETY: the caller provides the exact live initialized code range.
    unsafe { sys_icache_invalidate(start, length) };
}

#[cfg(test)]
#[allow(
    deprecated,
    reason = "test-only VM protection introspection uses the libc task-port shim"
)]
pub(super) fn query_protection(pointer: usize) -> Result<i32, PublishError> {
    const VM_REGION_BASIC_INFO_64: libc::c_int = 9;

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

    let mut address = u64::try_from(pointer).map_err(|_| PublishError::ArithmeticOverflow {
        site: crate::ArithmeticSite::ImageLayout,
    })?;
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
        .expect("nonzero C integer size");
    let mut count = u32::try_from(info_words).expect("small fixed structure");
    let mut object: libc::mach_port_t = 0;
    // SAFETY: reading the process's own task port through libc has no pointer
    // arguments and returns a copied scalar name.
    let task = unsafe { libc::mach_task_self() };
    // SAFETY: every out-pointer names initialized, correctly sized writable
    // storage and the current task port is valid for this diagnostic query.
    let result = unsafe {
        mach_vm_region(
            task,
            &raw mut address,
            &raw mut size,
            VM_REGION_BASIC_INFO_64,
            (&raw mut info).cast(),
            &raw mut count,
            &raw mut object,
        )
    };
    if result != libc::KERN_SUCCESS {
        return Err(PublishError::SystemCall {
            stage: FailureStage::Publish,
            errno: result,
        });
    }
    if object != 0 {
        // SAFETY: `object` is the send right returned by `mach_vm_region` for
        // this call and has not otherwise been transferred or deallocated.
        let deallocated = unsafe { mach_port_deallocate(task, object) };
        if deallocated != libc::KERN_SUCCESS {
            return Err(PublishError::SystemCall {
                stage: FailureStage::Publish,
                errno: deallocated,
            });
        }
    }
    let requested = u64::try_from(pointer).expect("usize is 64-bit on admitted host");
    if address > requested || requested >= address.saturating_add(size) {
        return Err(PublishError::PublicationIdentityMismatch);
    }
    Ok(info.protection)
}
