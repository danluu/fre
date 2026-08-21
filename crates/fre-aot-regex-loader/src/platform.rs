use core::ffi::c_void;

#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    any(target_os = "linux", target_os = "macos"),
    target_pointer_width = "64",
    target_endian = "little"
))]
mod implementation {
    use core::{ffi::c_void, ptr::NonNull, slice};

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    use core::arch::asm;
    #[cfg(all(test, target_os = "macos"))]
    use core::mem;
    #[cfg(test)]
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[cfg(test)]
    static LIVE_MAPPINGS: AtomicUsize = AtomicUsize::new(0);

    #[cfg(all(test, target_os = "macos"))]
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

    #[derive(Debug)]
    pub(crate) struct Mapping {
        base: NonNull<u8>,
        bytes: usize,
    }

    // SAFETY: the mapping has one owning value, becomes immutable before it is
    // shared, and final Drop is the only operation that releases its pages.
    unsafe impl Send for Mapping {}
    // SAFETY: published pages are RX or R and generated calls mutate only
    // caller-owned result storage.
    unsafe impl Sync for Mapping {}

    impl Mapping {
        pub(crate) fn reserve(bytes: usize) -> Result<Self, i32> {
            // SAFETY: all arguments are scalar, the mapping is anonymous, and
            // ownership of a successful range is established immediately.
            let raw = unsafe {
                libc::mmap(
                    core::ptr::null_mut(),
                    bytes,
                    libc::PROT_NONE,
                    libc::MAP_PRIVATE | libc::MAP_ANON,
                    -1,
                    0,
                )
            };
            if raw == libc::MAP_FAILED {
                return Err(errno());
            }
            let Some(base) = NonNull::new(raw.cast::<u8>()) else {
                // SAFETY: ownership has not moved and this is the exact range
                // returned by mmap, even if the platform chose address zero.
                let _ = unsafe { libc::munmap(raw, bytes) };
                return Err(libc::EFAULT);
            };
            #[cfg(test)]
            LIVE_MAPPINGS.fetch_add(1, Ordering::SeqCst);
            Ok(Self { base, bytes })
        }

        pub(crate) fn address(&self) -> usize {
            self.base.as_ptr().addr()
        }

        pub(crate) fn make_writable(&self, offset: usize, bytes: usize) -> Result<(), i32> {
            self.protect(offset, bytes, libc::PROT_READ | libc::PROT_WRITE)
        }

        pub(crate) fn make_read_only(&self, offset: usize, bytes: usize) -> Result<(), i32> {
            self.protect(offset, bytes, libc::PROT_READ)
        }

        pub(crate) fn make_executable(&self, offset: usize, bytes: usize) -> Result<(), i32> {
            self.protect(offset, bytes, libc::PROT_READ | libc::PROT_EXEC)
        }

        fn protect(&self, offset: usize, bytes: usize, protection: i32) -> Result<(), i32> {
            if bytes == 0 || offset.checked_add(bytes).is_none_or(|end| end > self.bytes) {
                return Err(libc::EINVAL);
            }
            // SAFETY: bounds were checked against this live owned mapping.
            let start = unsafe { self.base.as_ptr().add(offset) };
            // SAFETY: callers provide page-aligned section ranges and this
            // mapping owns the complete interval.
            let status = unsafe { libc::mprotect(start.cast(), bytes, protection) };
            if status == 0 { Ok(()) } else { Err(errno()) }
        }

        /// Copy bytes into a range whose caller-established protection is RW.
        ///
        /// # Safety
        ///
        /// The selected range must currently be writable and may not overlap
        /// `source`.
        pub(crate) unsafe fn copy_from(&self, offset: usize, source: &[u8]) {
            debug_assert!(
                offset
                    .checked_add(source.len())
                    .is_some_and(|end| end <= self.bytes)
            );
            // SAFETY: the caller established the writable, live, disjoint
            // destination and the debug assertion mirrors checked planning.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    source.as_ptr(),
                    self.base.as_ptr().add(offset),
                    source.len(),
                );
            }
        }

        /// Borrow an initialized mapped interval.
        ///
        /// # Safety
        ///
        /// The selected range must be readable and completely initialized.
        pub(crate) unsafe fn bytes(&self, offset: usize, bytes: usize) -> &[u8] {
            debug_assert!(
                offset
                    .checked_add(bytes)
                    .is_some_and(|end| end <= self.bytes)
            );
            // SAFETY: the caller established the readable initialized range.
            unsafe { slice::from_raw_parts(self.base.as_ptr().add(offset), bytes) }
        }

        pub(crate) fn pointer(&self, offset: usize) -> Option<NonNull<c_void>> {
            if offset >= self.bytes {
                return None;
            }
            // SAFETY: the offset lies inside the live mapping.
            NonNull::new(unsafe { self.base.as_ptr().add(offset) }.cast())
        }

        #[cfg(test)]
        pub(crate) fn protection(&self, offset: usize) -> Result<i32, i32> {
            if offset >= self.bytes {
                return Err(libc::EINVAL);
            }
            let address = self.address().checked_add(offset).ok_or(libc::EOVERFLOW)?;
            query_protection(address)
        }
    }

    impl Drop for Mapping {
        fn drop(&mut self) {
            // SAFETY: this value owns the exact still-live mmap range and
            // releases it once.
            let _ = unsafe { libc::munmap(self.base.as_ptr().cast(), self.bytes) };
            #[cfg(test)]
            LIVE_MAPPINGS.fetch_sub(1, Ordering::SeqCst);
        }
    }

    pub(crate) fn page_size() -> Result<usize, i32> {
        // SAFETY: sysconf takes a scalar selector and has no pointer contract.
        let raw = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if raw <= 0 {
            return Err(errno());
        }
        usize::try_from(raw).map_err(|_| libc::EOVERFLOW)
    }

    #[cfg(all(test, target_arch = "aarch64", target_os = "linux"))]
    pub(crate) fn with_guarded_haystack<T>(
        bytes: &[u8],
        at_right_boundary: bool,
        callback: impl for<'a> FnOnce(&'a [u8]) -> T,
    ) -> Result<T, i32> {
        let page = page_size()?;
        if !page.is_power_of_two() {
            return Err(libc::EPROTO);
        }
        let payload_bytes = bytes
            .len()
            .max(1)
            .checked_add(page.checked_sub(1).ok_or(libc::EOVERFLOW)?)
            .map(|rounded| rounded & !(page - 1))
            .ok_or(libc::EOVERFLOW)?;
        let total = payload_bytes
            .checked_add(page.checked_mul(2).ok_or(libc::EOVERFLOW)?)
            .ok_or(libc::EOVERFLOW)?;
        let mapping = Mapping::reserve(total)?;
        mapping.make_writable(page, payload_bytes)?;
        let placement = if at_right_boundary {
            page.checked_add(payload_bytes)
                .and_then(|end| end.checked_sub(bytes.len()))
                .ok_or(libc::EOVERFLOW)?
        } else {
            page
        };
        // SAFETY: the payload is the exact writable middle-page range, and
        // `placement` keeps the disjoint source wholly within that range.
        unsafe { mapping.copy_from(placement, bytes) };
        mapping.make_read_only(page, payload_bytes)?;
        // SAFETY: the copied bytes are initialized and readable, while the
        // owned mapping outlives the higher-ranked callback.
        let guarded = unsafe { mapping.bytes(placement, bytes.len()) };
        let result = callback(guarded);
        drop(mapping);
        Ok(result)
    }

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    pub(crate) fn current_thread_sve_vector_length_bytes() -> Result<Option<u16>, i32> {
        const PR_SVE_GET_VL: libc::c_int = 51;
        const PR_SVE_VL_LEN_MASK: libc::c_int = 0xffff;
        // SAFETY: PR_SVE_GET_VL ignores its four unsigned-long arguments and
        // reads only the calling thread's architectural SVE state.
        let raw = unsafe { libc::prctl(PR_SVE_GET_VL, 0, 0, 0, 0) };
        if raw < 0 {
            return Err(errno());
        }
        let bytes = u16::try_from(raw & PR_SVE_VL_LEN_MASK).map_err(|_| libc::EOVERFLOW)?;
        if !(16..=256).contains(&bytes) || !bytes.is_multiple_of(16) {
            return Err(libc::EPROTO);
        }
        Ok(Some(bytes))
    }

    #[cfg(not(all(target_arch = "aarch64", target_os = "linux")))]
    #[allow(
        clippy::unnecessary_wraps,
        reason = "all cfg variants share the Linux prctl failure-capable signature"
    )]
    pub(crate) const fn current_thread_sve_vector_length_bytes() -> Result<Option<u16>, i32> {
        Ok(None)
    }

    #[cfg(target_arch = "x86_64")]
    pub(crate) unsafe fn synchronize_instruction_cache(_start: *mut c_void, _bytes: usize) {}

    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    unsafe extern "C" {
        fn sys_icache_invalidate(start: *mut c_void, length: usize);
    }

    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    pub(crate) unsafe fn synchronize_instruction_cache(start: *mut c_void, bytes: usize) {
        // SAFETY: the caller supplies the exact initialized text range.
        unsafe { sys_icache_invalidate(start, bytes) };
    }

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    const CTR_EL0_IMINLINE_SHIFT: u32 = 0;
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    const CTR_EL0_DMINLINE_SHIFT: u32 = 16;
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    const CTR_EL0_IDC: usize = 1 << 28;
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    const CTR_EL0_DIC: usize = 1 << 29;

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    pub(crate) unsafe fn synchronize_instruction_cache(start: *mut c_void, bytes: usize) {
        let start_address = start.addr();
        let end_address = start_address
            .checked_add(bytes)
            .expect("a live mmap range cannot wrap the address space");
        let ctr_el0: usize;
        // SAFETY: Linux/AArch64 permits EL0 to read CTR_EL0.
        unsafe {
            asm!(
                "mrs {value}, ctr_el0",
                value = out(reg) ctr_el0,
                options(nomem, nostack, preserves_flags)
            );
        }
        if ctr_el0 & CTR_EL0_IDC == 0 {
            let line_bytes = cache_line_bytes(ctr_el0, CTR_EL0_DMINLINE_SHIFT);
            // SAFETY: every touched cache line intersects the supplied mapping.
            unsafe { clean_data_cache(start_address, end_address, line_bytes) };
        }
        // SAFETY: the barrier only strengthens ordering.
        unsafe { asm!("dsb ish", options(nostack, preserves_flags)) };
        if ctr_el0 & CTR_EL0_DIC == 0 {
            let line_bytes = cache_line_bytes(ctr_el0, CTR_EL0_IMINLINE_SHIFT);
            // SAFETY: every touched cache line intersects the supplied mapping.
            unsafe { invalidate_instruction_cache(start_address, end_address, line_bytes) };
        }
        // SAFETY: the barriers complete publication before instruction fetch.
        unsafe { asm!("dsb ish", "isb", options(nostack, preserves_flags)) };
    }

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    fn cache_line_bytes(ctr_el0: usize, shift: u32) -> usize {
        let encoded = ctr_el0.checked_shr(shift).unwrap_or(0) & 0xf;
        4_usize
            .checked_shl(u32::try_from(encoded).expect("four-bit cache-line encoding"))
            .expect("architectural cache-line encoding fits usize")
    }

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    unsafe fn clean_data_cache(start: usize, end: usize, line_bytes: usize) {
        let mask = line_bytes.checked_sub(1).expect("nonempty cache line");
        let mut address = start & !mask;
        while address < end {
            // SAFETY: caller established the intersecting live range.
            unsafe {
                asm!(
                    "dc cvau, {address}",
                    address = in(reg) address,
                    options(nostack, preserves_flags)
                );
            }
            address = address
                .checked_add(line_bytes)
                .expect("a live mmap range cannot wrap");
        }
    }

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    unsafe fn invalidate_instruction_cache(start: usize, end: usize, line_bytes: usize) {
        let mask = line_bytes.checked_sub(1).expect("nonempty cache line");
        let mut address = start & !mask;
        while address < end {
            // SAFETY: caller established the intersecting live range.
            unsafe {
                asm!(
                    "ic ivau, {address}",
                    address = in(reg) address,
                    options(nostack, preserves_flags)
                );
            }
            address = address
                .checked_add(line_bytes)
                .expect("a live mmap range cannot wrap");
        }
    }

    fn errno() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }

    #[cfg(test)]
    pub(crate) fn live_mappings() -> usize {
        LIVE_MAPPINGS.load(Ordering::SeqCst)
    }

    #[cfg(all(test, target_os = "linux"))]
    fn query_protection(pointer: usize) -> Result<i32, i32> {
        let maps = std::fs::read_to_string("/proc/self/maps")
            .map_err(|error| error.raw_os_error().unwrap_or(libc::EIO))?;
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
            let (Ok(start), Ok(end)) = (
                usize::from_str_radix(start, 16),
                usize::from_str_radix(end, 16),
            ) else {
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
        Err(libc::EFAULT)
    }

    #[cfg(all(test, target_os = "macos"))]
    #[allow(
        deprecated,
        reason = "test-only VM protection introspection uses the libc task-port shim"
    )]
    fn query_protection(pointer: usize) -> Result<i32, i32> {
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

        let mut address = u64::try_from(pointer).map_err(|_| libc::EOVERFLOW)?;
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
        let words = mem::size_of::<BasicInfo64>()
            .checked_div(mem::size_of::<libc::c_int>())
            .expect("nonzero C integer size");
        let mut count = u32::try_from(words).expect("small fixed structure");
        let mut object: libc::mach_port_t = 0;
        // SAFETY: this reads the current process task-port scalar.
        let task = unsafe { libc::mach_task_self() };
        // SAFETY: all out-pointers name initialized correctly sized storage.
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
            return Err(result);
        }
        if object != 0 {
            // SAFETY: this is the send right returned by `mach_vm_region`.
            let result = unsafe { mach_port_deallocate(task, object) };
            if result != libc::KERN_SUCCESS {
                return Err(result);
            }
        }
        let requested = u64::try_from(pointer).expect("admitted host uses 64-bit usize");
        if address > requested || requested >= address.saturating_add(size) {
            return Err(libc::EFAULT);
        }
        Ok(info.protection)
    }
}

#[cfg(not(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    any(target_os = "linux", target_os = "macos"),
    target_pointer_width = "64",
    target_endian = "little"
)))]
mod implementation {
    use core::{ffi::c_void, ptr::NonNull};

    #[derive(Debug)]
    pub(crate) struct Mapping;

    impl Mapping {
        pub(crate) fn reserve(_bytes: usize) -> Result<Self, i32> {
            Err(0)
        }

        pub(crate) fn address(&self) -> usize {
            0
        }

        pub(crate) fn make_writable(&self, _offset: usize, _bytes: usize) -> Result<(), i32> {
            Err(0)
        }

        pub(crate) fn make_read_only(&self, _offset: usize, _bytes: usize) -> Result<(), i32> {
            Err(0)
        }

        pub(crate) fn make_executable(&self, _offset: usize, _bytes: usize) -> Result<(), i32> {
            Err(0)
        }

        pub(crate) unsafe fn copy_from(&self, _offset: usize, _source: &[u8]) {}

        pub(crate) unsafe fn bytes(&self, _offset: usize, _bytes: usize) -> &[u8] {
            &[]
        }

        pub(crate) fn pointer(&self, _offset: usize) -> Option<NonNull<c_void>> {
            None
        }

        #[cfg(test)]
        pub(crate) fn protection(&self, _offset: usize) -> Result<i32, i32> {
            Err(0)
        }
    }

    pub(crate) fn page_size() -> Result<usize, i32> {
        Err(0)
    }

    #[allow(
        clippy::unnecessary_wraps,
        reason = "all cfg variants share the Linux prctl failure-capable signature"
    )]
    pub(crate) const fn current_thread_sve_vector_length_bytes() -> Result<Option<u16>, i32> {
        Ok(None)
    }

    #[cfg(all(test, target_arch = "aarch64", target_os = "linux"))]
    pub(crate) fn with_guarded_haystack<T>(
        _bytes: &[u8],
        _at_right_boundary: bool,
        _callback: impl for<'a> FnOnce(&'a [u8]) -> T,
    ) -> Result<T, i32> {
        Err(0)
    }

    pub(crate) unsafe fn synchronize_instruction_cache(_start: *mut c_void, _bytes: usize) {}

    #[cfg(test)]
    pub(crate) fn live_mappings() -> usize {
        0
    }
}

pub(crate) use implementation::{
    Mapping, current_thread_sve_vector_length_bytes, page_size, synchronize_instruction_cache,
};

#[cfg(test)]
pub(crate) use implementation::live_mappings;

#[cfg(all(test, target_arch = "aarch64", target_os = "linux"))]
pub(crate) use implementation::with_guarded_haystack;

pub(crate) const fn supported() -> bool {
    cfg!(all(
        any(target_arch = "x86_64", target_arch = "aarch64"),
        any(target_os = "linux", target_os = "macos"),
        target_pointer_width = "64",
        target_endian = "little"
    ))
}

#[allow(
    dead_code,
    reason = "keeps the platform module's C pointer type explicit"
)]
const _: Option<*mut c_void> = None;
