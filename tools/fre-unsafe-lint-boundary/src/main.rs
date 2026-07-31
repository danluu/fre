//! Fail-closed audit of Cargo targets and package-local unsafe-lint exceptions.

#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{self, Read as _},
    path::{Path, PathBuf},
    process::ExitCode,
};

use serde::Deserialize;
use sha2::{Digest as _, Sha256};

const KERNEL_PACKAGE: &str = "fre-kernels";
const KERNEL_LIBRARY: &str = "fre_kernels";
const EXACT_ALLOC_PACKAGE: &str = "fre-exact-alloc";
const EXACT_ALLOC_LIBRARY: &str = "fre_exact_alloc";
const TARGET_FEATURES_PACKAGE: &str = "fre-target-features";
const TARGET_FEATURES_LIBRARY: &str = "fre_target_features";
const SIMD_KERNELS_PACKAGE: &str = "fre-simd-kernels";
const SIMD_KERNELS_LIBRARY: &str = "fre_simd_kernels";
const STATIC_RUNTIME_PACKAGE: &str = "fre-aot-static-runtime";
const STATIC_RUNTIME_LIBRARY: &str = "fre_aot_static_runtime";
const FORBID_ATTRIBUTE: &str = "#![forbid(unsafe_code)]";
const DENY_ATTRIBUTE: &str = "#![deny(unsafe_code)]";
const STATIC_RUNTIME_DENY_ATTRIBUTE: &str = "#![deny(unsafe_code, unsafe_op_in_unsafe_fn)]";
const EXACT_ALLOC_SOURCE_SHA256: [u8; 32] = [
    0x29, 0xdf, 0x6f, 0x2e, 0x56, 0x96, 0xf9, 0x70, 0x5e, 0x5b, 0x48, 0x88, 0x7f, 0x52, 0x18, 0xfa,
    0xf7, 0x6b, 0xc5, 0x97, 0xdc, 0x56, 0x50, 0xca, 0x39, 0xb1, 0x51, 0xdd, 0x01, 0xb5, 0xf7, 0x26,
];
const EXACT_BOX_BORROW_REVIEWED_BLOCK: &str = r#"#[allow(
        unsafe_code,
        reason = "the tagged word recovers only the exposed provenance of its live owned allocation"
    )]
    pub fn boxed(&self) -> Option<&T> {
        if self.encoded & 1 == 0 {
            return None;
        }
        let address = self.encoded & !1;
        // SAFETY: the odd variant is created only from the exposed address of
        // a live, aligned `Box<T>` allocation retained exclusively by `self`.
        unsafe { ptr::with_exposed_provenance::<T>(address).as_ref() }
    }"#;
const EXACT_BOX_MUT_BORROW_REVIEWED_BLOCK: &str = r#"#[allow(
        unsafe_code,
        reason = "the exclusive handle borrow recovers only the exposed provenance of its live exclusively owned allocation"
    )]
    pub fn boxed_mut(&mut self) -> Option<&mut T> {
        if self.encoded & 1 == 0 {
            return None;
        }
        let address = self.encoded & !1;
        // SAFETY: the odd variant exclusively owns this live allocation and
        // `&mut self` prevents any overlapping borrow through the handle.
        unsafe { ptr::with_exposed_provenance_mut::<T>(address).as_mut() }
    }"#;
const EXACT_BOX_DROP_REVIEWED_BLOCK: &str = r#"#[allow(
        unsafe_code,
        reason = "the tagged word reconstructs its uniquely owned exact allocation for one drop"
    )]
    fn drop(&mut self) {
        if self.encoded & 1 == 0 {
            return;
        }
        let address = self.encoded & !1;
        // SAFETY: this object uniquely owns the allocation encoded by the odd
        // variant, and Drop runs exactly once.
        unsafe {
            drop(Box::from_raw(ptr::with_exposed_provenance_mut::<T>(
                address,
            )));
        }
    }"#;
const EXACT_BOX_CONSTRUCTION_REVIEWED_BLOCK: &str = r#"#[allow(
    unsafe_code,
    reason = "this reviewed function owns FRE's exact-layout single-value allocation boundary"
)]
fn exact_box_or_usize_with<T>(
    value: T,
    force_failure: bool,
) -> Result<ExactBoxOrUsize<T>, CopyError> {
    if size_of::<T>() == 0 || align_of::<T>() < 2 {
        return Err(CopyError::LayoutOverflow);
    }
    let layout = Layout::new::<T>();
    let allocation = if force_failure {
        ptr::null_mut()
    } else {
        unsafe { alloc(layout) }
    };
    if allocation.is_null() {
        return Err(CopyError::AllocationFailed);
    }
    // SAFETY: `alloc` returned a fresh allocation for exactly one `T`.
    // Writing initializes that object. Its exposed address retains recoverable
    // provenance, and alignment proves the low tag bit was zero.
    unsafe {
        let typed = allocation.cast::<T>();
        typed.write(value);
        Ok(ExactBoxOrUsize {
            encoded: typed.expose_provenance() | 1,
            marker: PhantomData,
        })
    }
}"#;
const EXACT_PLAIN_BOX_REVIEWED_BLOCK: &str = r#"#[allow(
    unsafe_code,
    reason = "this reviewed function owns FRE's exact-layout single-value allocation boundary"
)]
fn exact_box_preserve_with<T>(value: T, force_failure: bool) -> Result<Box<T>, (CopyError, T)> {
    if size_of::<T>() == 0 {
        return Err((CopyError::LayoutOverflow, value));
    }
    let layout = Layout::new::<T>();
    let allocation = if force_failure {
        ptr::null_mut()
    } else {
        unsafe { alloc(layout) }
    };
    if allocation.is_null() {
        return Err((CopyError::AllocationFailed, value));
    }
    // SAFETY: `alloc` returned a fresh allocation for exactly one `T`; the
    // write initializes it and transfers unique ownership to the returned Box.
    unsafe {
        let typed = allocation.cast::<T>();
        typed.write(value);
        Ok(Box::from_raw(typed))
    }
}"#;
const EXACT_VEC_REVIEWED_BLOCK: &str = r#"#[allow(
    unsafe_code,
    reason = "this reviewed function owns FRE's exact-layout typed allocation boundary"
)]
fn exact_vec_with_capacity<T>(
    capacity: usize,
    force_failure: bool,
) -> Result<ExactVec<T>, CopyError> {
    if size_of::<T>() == 0 {
        return Err(CopyError::LayoutOverflow);
    }
    if capacity == 0 {
        return Ok(ExactVec { inner: Vec::new() });
    }
    let layout = Layout::array::<T>(capacity).map_err(|_| CopyError::LayoutOverflow)?;
    let allocation = if force_failure {
        ptr::null_mut()
    } else {
        unsafe { alloc(layout) }
    };
    if allocation.is_null() {
        return Err(CopyError::AllocationFailed);
    }
    // SAFETY: `alloc` returned exactly `layout`; a zero-length Vec owns the
    // uninitialized spare capacity and later deallocates with the same layout.
    let inner = unsafe { Vec::from_raw_parts(allocation.cast::<T>(), 0, capacity) };
    Ok(ExactVec { inner })
}"#;
const ZEROED_EXACT_REVIEWED_BLOCK: &str = r#"#[allow(
    unsafe_code,
    reason = "this reviewed function owns FRE's exact-layout zero-initialization boundary"
)]
fn zeroed_exact_with(len: usize, force_failure: bool) -> Result<Vec<u8>, CopyError> {
    if len == 0 {
        return Ok(Vec::new());
    }
    let layout = Layout::array::<u8>(len).map_err(|_| CopyError::LayoutOverflow)?;
    let allocation = if force_failure {
        ptr::null_mut()
    } else {
        unsafe { alloc_zeroed(layout) }
    };
    if allocation.is_null() {
        return Err(CopyError::AllocationFailed);
    }

    // SAFETY: `alloc_zeroed` returned a fresh allocation for exactly `layout`
    // and initialized every byte. With `len == capacity`, `Vec` later uses the
    // identical layout for deallocation.
    unsafe { Ok(Vec::from_raw_parts(allocation, len, len)) }
}"#;
const COPY_EXACT_REVIEWED_BLOCK: &str = r#"#[allow(
    unsafe_code,
    reason = "this one reviewed function owns FRE's exact-layout allocation boundary"
)]
fn copy_exact_with(bytes: &[u8], force_failure: bool) -> Result<Vec<u8>, CopyError> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let layout = Layout::array::<u8>(bytes.len()).map_err(|_| CopyError::LayoutOverflow)?;
    let allocation = if force_failure {
        ptr::null_mut()
    } else {
        unsafe { alloc(layout) }
    };
    if allocation.is_null() {
        return Err(CopyError::AllocationFailed);
    }

    // SAFETY: `alloc` returned a fresh global allocation for exactly `layout`.
    // Every `u8` alignment is valid, the allocation is disjoint from the input,
    // and the copy initializes all `len` bytes. No panicking operation occurs
    // between successful allocation and `Vec` ownership. Since `len == capacity`,
    // `Vec` later deallocates with the same layout.
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), allocation, bytes.len());
        Ok(Vec::from_raw_parts(allocation, bytes.len(), bytes.len()))
    }
}"#;
const EXACT_ALLOC_REVIEWED_BLOCKS: [&str; 8] = [
    EXACT_BOX_BORROW_REVIEWED_BLOCK,
    EXACT_BOX_MUT_BORROW_REVIEWED_BLOCK,
    EXACT_BOX_DROP_REVIEWED_BLOCK,
    EXACT_BOX_CONSTRUCTION_REVIEWED_BLOCK,
    EXACT_PLAIN_BOX_REVIEWED_BLOCK,
    EXACT_VEC_REVIEWED_BLOCK,
    ZEROED_EXACT_REVIEWED_BLOCK,
    COPY_EXACT_REVIEWED_BLOCK,
];
const EXACT_ALLOC_UNSAFE_CODE_SPELLINGS: usize = 9;
const TARGET_FEATURES_UNSAFE_CODE_SPELLINGS: usize = 3;
const TARGET_FEATURES_SOURCE_SHA256: [u8; 32] = [
    0x6f, 0x80, 0xcd, 0x38, 0x23, 0x9e, 0x5f, 0xed, 0x06, 0x40, 0x0c, 0x56, 0x3c, 0xc6, 0xb5, 0xea,
    0x52, 0x85, 0xdd, 0xe3, 0x72, 0xea, 0xa8, 0x45, 0xb8, 0xf3, 0xe7, 0xf3, 0xf3, 0x28, 0xae, 0xe0,
];
const TARGET_FEATURES_X86_REVIEWED_BLOCK: &str = r#"#[cfg(all(not(feature = "static-dispatch"), target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "CPUID leaf 0/1 are architecture-defined, side-effect-free tuning queries; instruction safety still comes from std feature detection"
)]
fn x86_tuning() -> TuningClass {
    use core::arch::x86_64::__cpuid;

    // SAFETY: CPUID is architecturally available on x86-64. Leaf 0 reports
    // the maximum basic leaf before leaf 1 is queried.
    let leaf0 = unsafe { __cpuid(0) };
    let mut vendor_bytes = [0_u8; 12];
    vendor_bytes[..4].copy_from_slice(&leaf0.ebx.to_ne_bytes());
    vendor_bytes[4..8].copy_from_slice(&leaf0.edx.to_ne_bytes());
    vendor_bytes[8..].copy_from_slice(&leaf0.ecx.to_ne_bytes());
    let vendor = match &vendor_bytes {
        b"AuthenticAMD" => X86Vendor::Amd,
        b"GenuineIntel" => X86Vendor::Intel,
        _ => X86Vendor::Other(vendor_bytes),
    };
    if leaf0.eax < 1 {
        return TuningClass::X86 {
            vendor,
            family: 0,
            model: 0,
        };
    }
    // SAFETY: leaf 0 proved that basic leaf 1 exists.
    let leaf1 = unsafe { __cpuid(1) };
    let base_family = u16::try_from((leaf1.eax >> 8) & 0x0F).expect("four bits fit");
    let extended_family = u16::try_from((leaf1.eax >> 20) & 0xFF).expect("eight bits fit");
    let family = if base_family == 0x0F {
        base_family.saturating_add(extended_family)
    } else {
        base_family
    };
    let base_model = u16::try_from((leaf1.eax >> 4) & 0x0F).expect("four bits fit");
    let extended_model = u16::try_from((leaf1.eax >> 16) & 0x0F).expect("four bits fit");
    let model = if base_family == 0x06 || base_family == 0x0F {
        (extended_model << 4) | base_model
    } else {
        base_model
    };
    TuningClass::X86 {
        vendor,
        family,
        model,
    }
}"#;
const TARGET_FEATURES_MACOS_REVIEWED_BLOCK: &str = r#"#[allow(
        unsafe_code,
        reason = "read-only sysctlbyname writes into one initialized fixed-size integer and receives no mutable input"
    )]
    fn integer(name: &CStr) -> Option<i32> {
        let mut value = 0_i32;
        let mut length = size_of::<i32>();
        // SAFETY: `name` is NUL terminated. `value` and `length` point to
        // initialized writable objects of the declared size. Null new-value
        // arguments make this a read-only query.
        let status = unsafe {
            libc::sysctlbyname(
                name.as_ptr(),
                (&raw mut value).cast(),
                &raw mut length,
                core::ptr::null_mut(),
                0,
            )
        };
        (status == 0 && length == size_of::<i32>()).then_some(value)
    }"#;

#[derive(Clone, Copy, Debug)]
struct ReviewedFile {
    relative: &'static str,
    sha256: [u8; 32],
}

const SIMD_KERNELS_REVIEWED_FILES: [ReviewedFile; 7] = [
    ReviewedFile {
        relative: "Cargo.toml",
        sha256: [
            0xdb, 0x85, 0xa0, 0x20, 0xc9, 0xbf, 0x13, 0x4a, 0x50, 0x0e, 0x78, 0x1e, 0x96, 0x1b,
            0x19, 0x95, 0xd7, 0xcb, 0xe2, 0x71, 0x79, 0x71, 0xe3, 0xd7, 0xd1, 0x66, 0xb6, 0x5a,
            0xdd, 0xc8, 0xc2, 0xd6,
        ],
    },
    ReviewedFile {
        relative: "src/lib.rs",
        sha256: [
            0xc8, 0xb3, 0xdb, 0x6b, 0xbe, 0x0f, 0x88, 0x19, 0x26, 0x8e, 0x5d, 0x6f, 0x18, 0x6d,
            0x14, 0x7f, 0x70, 0x95, 0xeb, 0x4a, 0x39, 0xea, 0xfc, 0x35, 0x6d, 0xa2, 0x42, 0xd8,
            0xf5, 0x66, 0x27, 0xea,
        ],
    },
    ReviewedFile {
        relative: "src/scalar.rs",
        sha256: [
            0x5c, 0x5a, 0xa0, 0xb9, 0x72, 0xf2, 0x7e, 0x83, 0x95, 0x32, 0xbb, 0x8d, 0x7a, 0x6b,
            0x45, 0xe2, 0x6b, 0x97, 0xe5, 0x66, 0xc1, 0x75, 0xf8, 0xe4, 0x31, 0x11, 0xea, 0x08,
            0xd9, 0xed, 0xeb, 0x54,
        ],
    },
    ReviewedFile {
        relative: "src/aarch64.rs",
        sha256: [
            0x1a, 0xf9, 0xe4, 0x28, 0xbe, 0x30, 0x36, 0x3f, 0x3d, 0x60, 0x85, 0x21, 0x3a, 0x28,
            0x95, 0x87, 0x15, 0xe6, 0x77, 0x7e, 0x95, 0x9b, 0x10, 0xb9, 0xeb, 0x4e, 0x54, 0xc3,
            0x00, 0x0c, 0x81, 0xf0,
        ],
    },
    ReviewedFile {
        relative: "src/aarch64_sve2.rs",
        sha256: [
            0xa3, 0xed, 0xc9, 0x5f, 0xfb, 0xae, 0x86, 0xa3, 0x8b, 0x0c, 0x11, 0x45, 0x63, 0x06,
            0x4f, 0xba, 0x51, 0xad, 0x34, 0x22, 0xe3, 0xa4, 0xe5, 0x39, 0xbc, 0x6e, 0xae, 0xc7,
            0xfe, 0x6b, 0x67, 0xcc,
        ],
    },
    ReviewedFile {
        relative: "src/x86_64.rs",
        sha256: [
            0x01, 0x72, 0x72, 0x7a, 0x3c, 0xe7, 0x6b, 0xe5, 0xe7, 0x45, 0xb7, 0xcd, 0x5e, 0xfe,
            0x8a, 0x32, 0xa1, 0x4c, 0xa0, 0x4f, 0x2e, 0x80, 0x4a, 0x92, 0x5c, 0x09, 0x43, 0xb3,
            0xfb, 0x87, 0x28, 0x34,
        ],
    },
    ReviewedFile {
        relative: "src/tests.rs",
        sha256: [
            0xc3, 0xad, 0xe3, 0x30, 0xda, 0x55, 0x34, 0xd3, 0x8f, 0xe8, 0x1b, 0x20, 0xf0, 0xee,
            0x4b, 0xb8, 0x20, 0xad, 0x56, 0xdb, 0x08, 0xe5, 0xa8, 0xf2, 0x56, 0xd4, 0xf0, 0x2b,
            0xae, 0xeb, 0x04, 0x3e,
        ],
    },
];

const KERNEL_LINTS: &str = r#"
[lints.rust]
unsafe_code = "forbid"
missing_debug_implementations = "warn"
rust_2018_idioms = { level = "deny", priority = -1 }
unreachable_pub = "warn"

[lints.clippy]
all = { level = "warn", priority = -1 }
pedantic = { level = "warn", priority = -1 }
allow_attributes_without_reason = "warn"
arithmetic_side_effects = "warn"
as_conversions = "warn"
missing_errors_doc = "allow"
missing_panics_doc = "allow"
module_name_repetitions = "allow"
"#;

const WARN_UNSAFE_LINTS: &str = r#"
[lints.rust]
unsafe_code = "warn"
unsafe_op_in_unsafe_fn = "deny"
missing_debug_implementations = "warn"
rust_2018_idioms = { level = "deny", priority = -1 }
unreachable_pub = "warn"

[lints.clippy]
all = { level = "warn", priority = -1 }
pedantic = { level = "warn", priority = -1 }
allow_attributes_without_reason = "warn"
arithmetic_side_effects = "warn"
as_conversions = "warn"
missing_errors_doc = "allow"
missing_panics_doc = "allow"
module_name_repetitions = "allow"
"#;

const EXACT_ALLOC_LINTS: &str = r#"
[lints.rust]
unsafe_code = "deny"
missing_debug_implementations = "warn"
rust_2018_idioms = { level = "deny", priority = -1 }
unreachable_pub = "warn"

[lints.clippy]
all = { level = "warn", priority = -1 }
pedantic = { level = "warn", priority = -1 }
allow_attributes_without_reason = "warn"
arithmetic_side_effects = "warn"
as_conversions = "warn"
missing_errors_doc = "allow"
missing_panics_doc = "allow"
module_name_repetitions = "allow"
"#;

const TARGET_FEATURES_LINTS: &str = r#"
[lints.rust]
unsafe_code = "deny"
unsafe_op_in_unsafe_fn = "deny"
missing_debug_implementations = "warn"
rust_2018_idioms = { level = "deny", priority = -1 }
unreachable_pub = "warn"
[lints.clippy]
all = { level = "warn", priority = -1 }
pedantic = { level = "warn", priority = -1 }
allow_attributes_without_reason = "warn"
arithmetic_side_effects = "warn"
as_conversions = "warn"
missing_errors_doc = "allow"
missing_panics_doc = "allow"
module_name_repetitions = "allow"
"#;

const SIMD_KERNELS_LINTS: &str = r#"
[lints.rust]
unsafe_code = "deny"
unsafe_op_in_unsafe_fn = "deny"
missing_debug_implementations = "warn"
rust_2018_idioms = { level = "deny", priority = -1 }
unreachable_pub = "warn"

[lints.clippy]
all = { level = "warn", priority = -1 }
pedantic = { level = "warn", priority = -1 }
allow_attributes_without_reason = "warn"
arithmetic_side_effects = "warn"
as_conversions = "warn"
missing_errors_doc = "allow"
missing_panics_doc = "allow"
module_name_repetitions = "allow"
"#;

const STATIC_RUNTIME_LINTS: &str = r#"
[lints.rust]
unsafe_code = "deny"
unsafe_op_in_unsafe_fn = "deny"
missing_debug_implementations = "warn"
rust_2018_idioms = { level = "deny", priority = -1 }
unreachable_pub = "warn"

[lints.clippy]
all = { level = "warn", priority = -1 }
pedantic = { level = "warn", priority = -1 }
allow_attributes_without_reason = "warn"
arithmetic_side_effects = "warn"
as_conversions = "warn"
missing_errors_doc = "allow"
missing_panics_doc = "allow"
module_name_repetitions = "allow"
"#;

#[derive(Clone, Copy, Debug)]
struct ReviewedUnsafeSource {
    relative: &'static str,
    sha256: [u8; 32],
    unsafe_code: usize,
    unsafe_blocks: usize,
    unsafe_functions: usize,
    unsafe_externs: usize,
    unsafe_impls: usize,
    unsafe_traits: usize,
}

const STATIC_RUNTIME_REVIEWED_UNSAFE_SOURCES: [ReviewedUnsafeSource; 7] = [
    ReviewedUnsafeSource {
        relative: "src/linked/macos_aarch64.rs",
        sha256: [
            0xc1, 0x06, 0xbc, 0xb7, 0xe6, 0xc5, 0xaf, 0xc4, 0x72, 0xc6, 0xf3, 0x08, 0x83, 0xd6,
            0xb6, 0x3d, 0x32, 0xb7, 0xe7, 0x7d, 0xbe, 0x59, 0xb6, 0xd5, 0x06, 0xd2, 0xd8, 0x4a,
            0x04, 0xc4, 0x7f, 0x59,
        ],
        unsafe_code: 6,
        unsafe_blocks: 8,
        unsafe_functions: 1,
        unsafe_externs: 1,
        unsafe_impls: 0,
        unsafe_traits: 0,
    },
    ReviewedUnsafeSource {
        relative: "src/linked/mod.rs",
        sha256: [
            0x2c, 0xfe, 0x13, 0xa9, 0x60, 0x8d, 0x62, 0x5d, 0xa0, 0xc1, 0x50, 0xa2, 0xef, 0xfe,
            0xb1, 0xbc, 0xbd, 0xf5, 0xd4, 0x8f, 0x92, 0x97, 0xbd, 0x49, 0x83, 0x6e, 0x7a, 0xd6,
            0xc5, 0x4e, 0x61, 0x48,
        ],
        unsafe_code: 12,
        unsafe_blocks: 10,
        unsafe_functions: 4,
        unsafe_externs: 4,
        unsafe_impls: 0,
        unsafe_traits: 0,
    },
    ReviewedUnsafeSource {
        relative: "src/linked/unavailable.rs",
        sha256: [
            0xc9, 0xa3, 0x94, 0xb3, 0x74, 0x60, 0xcc, 0xef, 0x57, 0xae, 0x4e, 0xf0, 0xf1, 0x3e,
            0xd7, 0xb2, 0x02, 0x13, 0xd9, 0x70, 0x3d, 0x67, 0xf2, 0x0f, 0xcb, 0x4b, 0x1e, 0x9a,
            0x77, 0xd0, 0x70, 0x80,
        ],
        unsafe_code: 1,
        unsafe_blocks: 0,
        unsafe_functions: 1,
        unsafe_externs: 0,
        unsafe_impls: 0,
        unsafe_traits: 0,
    },
    ReviewedUnsafeSource {
        relative: "src/search_linked/linux_aarch64.rs",
        sha256: [
            0x35, 0xe8, 0xc4, 0xb0, 0x39, 0xfa, 0x9d, 0xe5, 0xe4, 0x34, 0x4a, 0x50, 0x45, 0x3c,
            0x76, 0x32, 0x73, 0x09, 0x2e, 0x89, 0xa2, 0xb1, 0x60, 0x7f, 0xe2, 0x5c, 0x8b, 0x53,
            0x5e, 0x1d, 0xf7, 0x5f,
        ],
        unsafe_code: 8,
        unsafe_blocks: 12,
        unsafe_functions: 1,
        unsafe_externs: 1,
        unsafe_impls: 0,
        unsafe_traits: 0,
    },
    ReviewedUnsafeSource {
        relative: "src/search_linked/macos_aarch64.rs",
        sha256: [
            0x00, 0x8a, 0x21, 0xc8, 0x9a, 0xb5, 0x40, 0xf0, 0xc8, 0x4b, 0x63, 0x0b, 0x61, 0x7f,
            0xb2, 0x99, 0x48, 0x7b, 0x41, 0xb7, 0xf3, 0xbf, 0xa0, 0x32, 0x7e, 0xb7, 0x9c, 0x84,
            0xb8, 0x10, 0x3a, 0x51,
        ],
        unsafe_code: 6,
        unsafe_blocks: 8,
        unsafe_functions: 1,
        unsafe_externs: 1,
        unsafe_impls: 0,
        unsafe_traits: 0,
    },
    ReviewedUnsafeSource {
        relative: "src/search_linked/mod.rs",
        sha256: [
            0xa9, 0x7e, 0x72, 0xe6, 0x82, 0x64, 0x31, 0x18, 0x5e, 0xe3, 0x68, 0x4c, 0x9b, 0x2c,
            0x03, 0xa3, 0xab, 0x1f, 0xe5, 0xd8, 0xab, 0xe8, 0x25, 0x1a, 0x85, 0x79, 0x77, 0x41,
            0x5c, 0x8b, 0xfb, 0xcf,
        ],
        unsafe_code: 13,
        unsafe_blocks: 12,
        unsafe_functions: 3,
        unsafe_externs: 6,
        unsafe_impls: 0,
        unsafe_traits: 0,
    },
    ReviewedUnsafeSource {
        relative: "src/search_linked/unavailable.rs",
        sha256: [
            0xea, 0xd1, 0x33, 0xb8, 0xa9, 0xdf, 0xe1, 0x82, 0x9f, 0xbc, 0xcd, 0x57, 0x40, 0xe6,
            0xb3, 0xaa, 0xef, 0x8e, 0x18, 0xe0, 0x8f, 0xc8, 0xaa, 0x55, 0xac, 0xbf, 0x38, 0x85,
            0xc2, 0x3b, 0x1d, 0xa3,
        ],
        unsafe_code: 4,
        unsafe_blocks: 1,
        unsafe_functions: 1,
        unsafe_externs: 1,
        unsafe_impls: 0,
        unsafe_traits: 0,
    },
];

const STATIC_RUNTIME_FILES: [&str; 32] = [
    "Cargo.toml",
    "qualification/linux-search-private-rows/README.md",
    "qualification/linux-search-private-rows/source_row_tool.py",
    "qualification/linux-search-private-rows/test_promotion_delta.sh",
    "qualification/linux-search-private-rows/test_source_row_tool.py",
    "qualification/linux-search-private-rows/verify-promotion-delta.sh",
    "qualification/linux-search-production-rows/README.md",
    "qualification/linux-search-production-rows/production_row_tool.py",
    "qualification/linux-search-production-rows/templates/production-authorization-v1.tsv.template",
    "qualification/linux-search-production-rows/templates/promotion-inputs-v1.txt.template",
    "qualification/linux-search-production-rows/test_production_row_tool.py",
    "qualification/linux-search-production-rows/test_promotion_delta.sh",
    "qualification/linux-search-production-rows/verify-promotion-delta.sh",
    "src/call.rs",
    "src/error.rs",
    "src/expected.rs",
    "src/lib.rs",
    "src/linked/macos_aarch64.rs",
    "src/linked/mod.rs",
    "src/linked/unavailable.rs",
    "src/search_call.rs",
    "src/search_expected.rs",
    "src/search_linked/linux_aarch64.rs",
    "src/search_linked/macos_aarch64.rs",
    "src/search_linked/mod.rs",
    "src/search_linked/unavailable.rs",
    "src/search_support.rs",
    "src/search_support/private_rows.rs",
    "src/search_support/production_rows.rs",
    "src/search_test_fixture.rs",
    "src/support.rs",
    "src/test_fixture.rs",
];

#[derive(Debug, Deserialize)]
struct Metadata {
    workspace_root: PathBuf,
    workspace_members: Vec<String>,
    packages: Vec<Package>,
}

#[derive(Debug, Deserialize)]
struct Package {
    id: String,
    name: String,
    manifest_path: PathBuf,
    dependencies: Vec<serde_json::Value>,
    targets: Vec<Target>,
}

#[derive(Debug, Deserialize)]
struct Target {
    name: String,
    kind: Vec<String>,
    src_path: PathBuf,
}

#[derive(Clone, Copy, Debug)]
struct LocalException {
    package: &'static str,
    manifest: &'static str,
    expected_lints: &'static str,
}

const LOCAL_EXCEPTIONS: [LocalException; 6] = [
    LocalException {
        package: "fre-capi",
        manifest: "crates/fre-capi/Cargo.toml",
        expected_lints: WARN_UNSAFE_LINTS,
    },
    LocalException {
        package: "fre-jit-runtime",
        manifest: "crates/fre-jit-runtime/Cargo.toml",
        expected_lints: WARN_UNSAFE_LINTS,
    },
    LocalException {
        package: EXACT_ALLOC_PACKAGE,
        manifest: "crates/fre-exact-alloc/Cargo.toml",
        expected_lints: EXACT_ALLOC_LINTS,
    },
    LocalException {
        package: STATIC_RUNTIME_PACKAGE,
        manifest: "crates/fre-aot-static-runtime/Cargo.toml",
        expected_lints: STATIC_RUNTIME_LINTS,
    },
    LocalException {
        package: TARGET_FEATURES_PACKAGE,
        manifest: "crates/fre-target-features/Cargo.toml",
        expected_lints: TARGET_FEATURES_LINTS,
    },
    LocalException {
        package: SIMD_KERNELS_PACKAGE,
        manifest: "crates/fre-simd-kernels/Cargo.toml",
        expected_lints: SIMD_KERNELS_LINTS,
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AuditSummary {
    workspace_packages: usize,
    local_exceptions: usize,
    kernel_targets: usize,
    protected_kernel_targets: usize,
}

fn main() -> ExitCode {
    match read_and_audit() {
        Ok(summary) => {
            println!(
                "PASS metadata-packages={} local-exceptions={} kernel-targets={} protected-nonlib={}",
                summary.workspace_packages,
                summary.local_exceptions,
                summary.kernel_targets,
                summary.protected_kernel_targets
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("unsafe lint metadata failure: {error}");
            ExitCode::FAILURE
        }
    }
}

fn read_and_audit() -> Result<AuditSummary, String> {
    let mut input = Vec::new();
    io::stdin()
        .read_to_end(&mut input)
        .map_err(|error| format!("read Cargo metadata from stdin: {error}"))?;
    let metadata: Metadata = serde_json::from_slice(&input)
        .map_err(|error| format!("parse Cargo metadata JSON: {error}"))?;
    audit(&metadata)
}

fn audit(metadata: &Metadata) -> Result<AuditSummary, String> {
    let workspace_root = canonical(&metadata.workspace_root, "workspace root")?;
    let packages_by_id = index_packages(&metadata.packages)?;
    let mut member_ids = BTreeSet::new();
    let mut members = Vec::with_capacity(metadata.workspace_members.len());
    for id in &metadata.workspace_members {
        if !member_ids.insert(id.as_str()) {
            return Err(format!("duplicate workspace member id: {id}"));
        }
        members.push(
            *packages_by_id
                .get(id.as_str())
                .ok_or_else(|| format!("workspace member missing from packages: {id}"))?,
        );
    }
    if members.is_empty() {
        return Err("Cargo metadata contains no workspace members".to_owned());
    }

    let mut packages_by_name = BTreeMap::new();
    for package in &members {
        if packages_by_name
            .insert(package.name.as_str(), *package)
            .is_some()
        {
            return Err(format!(
                "duplicate workspace package name: {}",
                package.name
            ));
        }
        let manifest = canonical(
            &package.manifest_path,
            &format!("manifest for {}", package.name),
        )?;
        if !manifest.starts_with(&workspace_root) {
            return Err(format!(
                "workspace package {} has manifest outside workspace root: {}",
                package.name,
                manifest.display()
            ));
        }
    }

    audit_package_lint_inheritance(&workspace_root, &packages_by_name)?;
    let kernel = packages_by_name
        .get(KERNEL_PACKAGE)
        .ok_or_else(|| format!("missing {KERNEL_PACKAGE} workspace package"))?;
    let protected_kernel_targets = audit_kernel_targets(kernel, &workspace_root)?;
    audit_kernel_sources(&workspace_root)?;
    audit_exact_allocator(&packages_by_name, &workspace_root)?;
    audit_target_features(&packages_by_name, &workspace_root)?;
    audit_simd_kernels(&packages_by_name, &workspace_root)?;
    audit_static_runtime(&packages_by_name, &workspace_root)?;

    Ok(AuditSummary {
        workspace_packages: members.len(),
        local_exceptions: LOCAL_EXCEPTIONS.len(),
        kernel_targets: kernel.targets.len(),
        protected_kernel_targets,
    })
}

fn index_packages(packages: &[Package]) -> Result<BTreeMap<&str, &Package>, String> {
    let mut indexed = BTreeMap::new();
    for package in packages {
        if indexed.insert(package.id.as_str(), package).is_some() {
            return Err(format!("duplicate Cargo package id: {}", package.id));
        }
    }
    Ok(indexed)
}

fn audit_package_lint_inheritance(
    workspace_root: &Path,
    packages: &BTreeMap<&str, &Package>,
) -> Result<(), String> {
    let exceptions: BTreeMap<_, _> = LOCAL_EXCEPTIONS
        .iter()
        .map(|exception| (exception.package, exception))
        .collect();
    if exceptions.len() != LOCAL_EXCEPTIONS.len() {
        return Err("duplicate package in local lint exception allowlist".to_owned());
    }

    let mut observed_exceptions = BTreeSet::new();
    for (name, package) in packages {
        let manifest_path = canonical(&package.manifest_path, &format!("manifest for {name}"))?;
        let manifest_bytes = fs::read(&manifest_path)
            .map_err(|error| format!("read {}: {error}", manifest_path.display()))?;
        let manifest_text = std::str::from_utf8(&manifest_bytes)
            .map_err(|error| format!("{} is not UTF-8: {error}", manifest_path.display()))?;
        let manifest: toml::Value = toml::from_str(manifest_text)
            .map_err(|error| format!("parse {} as TOML: {error}", manifest_path.display()))?;
        let lints = manifest
            .get("lints")
            .and_then(toml::Value::as_table)
            .ok_or_else(|| format!("package {name} has no [lints] table"))?;

        if let Some(exception) = exceptions.get(name) {
            observed_exceptions.insert(*name);
            let expected_manifest = canonical(
                &workspace_root.join(exception.manifest),
                &format!("expected manifest for {name}"),
            )?;
            if manifest_path != expected_manifest {
                return Err(format!(
                    "local lint exception {name} moved from {} to {}",
                    expected_manifest.display(),
                    manifest_path.display()
                ));
            }
            require_exact_lints(name, lints, exception.expected_lints)?;
        } else if *name == KERNEL_PACKAGE {
            require_exact_lints(name, lints, KERNEL_LINTS)?;
        } else if lints.len() != 1
            || lints.get("workspace").and_then(toml::Value::as_bool) != Some(true)
        {
            return Err(format!(
                "workspace package {name} must inherit [lints] workspace = true"
            ));
        }
    }

    let expected_exceptions: BTreeSet<_> = exceptions.keys().copied().collect();
    if observed_exceptions != expected_exceptions {
        return Err(format!(
            "local lint exceptions differ: observed={observed_exceptions:?} expected={expected_exceptions:?}"
        ));
    }
    Ok(())
}

fn require_exact_lints(
    package: &str,
    actual: &toml::map::Map<String, toml::Value>,
    expected_source: &str,
) -> Result<(), String> {
    let expected_document: toml::Value = toml::from_str(expected_source)
        .map_err(|error| format!("parse expected lint table for {package}: {error}"))?;
    let expected = expected_document
        .get("lints")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| format!("expected lint table for {package} is malformed"))?;
    if actual != expected {
        return Err(format!(
            "local lint table for {package} drifted: actual={actual:?} expected={expected:?}"
        ));
    }
    Ok(())
}

fn audit_kernel_targets(package: &Package, workspace_root: &Path) -> Result<usize, String> {
    let kernel_root = canonical(
        &workspace_root.join("crates/fre-kernels"),
        "fre-kernels package root",
    )?;
    let expected_library = canonical(
        &kernel_root.join("src/lib.rs"),
        "expected fre-kernels library",
    )?;
    let mut library_count = 0_usize;
    let mut protected = 0_usize;

    for target in &package.targets {
        let source = canonical(
            &target.src_path,
            &format!("source for fre-kernels target {}", target.name),
        )?;
        if !source.starts_with(&kernel_root) {
            return Err(format!(
                "fre-kernels target {} escapes its package root: {}",
                target.name,
                source.display()
            ));
        }

        if source == expected_library {
            library_count = library_count
                .checked_add(1)
                .ok_or_else(|| "fre-kernels library count overflow".to_owned())?;
            if target.name != KERNEL_LIBRARY || target.kind.as_slice() != ["lib"] {
                return Err(format!(
                    "expected library path belongs to unexpected target {} kind {:?}",
                    target.name, target.kind
                ));
            }
            require_attribute(&source, FORBID_ATTRIBUTE, false, &target.name)?;
            continue;
        }

        if target.kind.iter().any(|kind| kind == "lib") {
            return Err(format!(
                "unexpected additional fre-kernels library target {} at {}",
                target.name,
                source.display()
            ));
        }
        require_attribute(&source, FORBID_ATTRIBUTE, true, &target.name)?;
        protected = protected
            .checked_add(1)
            .ok_or_else(|| "protected target count overflow".to_owned())?;
    }

    if library_count != 1 {
        return Err(format!(
            "expected exactly one fre-kernels library target, observed {library_count}"
        ));
    }
    Ok(protected)
}

fn audit_kernel_sources(workspace_root: &Path) -> Result<(), String> {
    let source_root = canonical(
        &workspace_root.join("crates/fre-kernels/src"),
        "fre-kernels source root",
    )?;
    let library = canonical(&source_root.join("lib.rs"), "fre-kernels library source")?;
    let mut files = BTreeSet::new();
    collect_regular_files(&source_root, &source_root, &mut files)?;
    for relative in files {
        if relative
            .extension()
            .and_then(|extension| extension.to_str())
            != Some("rs")
        {
            return Err(format!(
                "unexpected non-Rust file in fre-kernels source root: {}",
                relative.display()
            ));
        }
        let path = source_root.join(&relative);
        let source = fs::read_to_string(&path)
            .map_err(|error| format!("read kernel source {}: {error}", path.display()))?;
        if path == library {
            if source.matches("unsafe_code").count() != 1 || !source.contains(FORBID_ATTRIBUTE) {
                return Err("fre-kernels library unsafe boundary drifted".to_owned());
            }
        } else if source.contains("unsafe_code") {
            return Err(format!(
                "fre-kernels source {} contains an unsafe lint lowering",
                path.display()
            ));
        }
        for forbidden in ["unsafe {", "unsafe fn", "unsafe impl", "unsafe trait"] {
            if source.contains(forbidden) {
                return Err(format!(
                    "fre-kernels source {} contains forbidden token {forbidden:?}",
                    path.display()
                ));
            }
        }
    }
    Ok(())
}

fn audit_exact_allocator(
    packages: &BTreeMap<&str, &Package>,
    workspace_root: &Path,
) -> Result<(), String> {
    let package = packages
        .get(EXACT_ALLOC_PACKAGE)
        .ok_or_else(|| format!("missing {EXACT_ALLOC_PACKAGE} workspace package"))?;
    if !package.dependencies.is_empty() {
        return Err(format!(
            "{EXACT_ALLOC_PACKAGE} must have no dependencies, observed {}",
            package.dependencies.len()
        ));
    }
    if package.targets.len() != 1 {
        return Err(format!(
            "{EXACT_ALLOC_PACKAGE} must have exactly one target, observed {}",
            package.targets.len()
        ));
    }

    let package_root = canonical(
        &workspace_root.join("crates/fre-exact-alloc"),
        "fre-exact-alloc package root",
    )?;
    let expected_manifest =
        canonical(&package_root.join("Cargo.toml"), "fre-exact-alloc manifest")?;
    if canonical(&package.manifest_path, "fre-exact-alloc package manifest")? != expected_manifest {
        return Err("fre-exact-alloc manifest path drifted".to_owned());
    }
    let expected_source = canonical(
        &package_root.join("src/lib.rs"),
        "fre-exact-alloc library source",
    )?;
    let target = &package.targets[0];
    if target.name != EXACT_ALLOC_LIBRARY
        || target.kind.as_slice() != ["lib"]
        || canonical(&target.src_path, "fre-exact-alloc target source")? != expected_source
    {
        return Err(format!(
            "unexpected fre-exact-alloc target {} kind {:?} source {}",
            target.name,
            target.kind,
            target.src_path.display()
        ));
    }

    let mut files = BTreeSet::new();
    collect_regular_files(&package_root, &package_root, &mut files)?;
    let expected_files = BTreeSet::from([PathBuf::from("Cargo.toml"), PathBuf::from("src/lib.rs")]);
    if files != expected_files {
        return Err(format!(
            "fre-exact-alloc file inventory drifted: actual={files:?} expected={expected_files:?}"
        ));
    }
    audit_exact_allocator_source(&expected_source)
}

fn audit_exact_allocator_source(source_path: &Path) -> Result<(), String> {
    let source_bytes =
        fs::read(source_path).map_err(|error| format!("read exact allocator source: {error}"))?;
    if Sha256::digest(&source_bytes)[..] != EXACT_ALLOC_SOURCE_SHA256 {
        return Err("exact allocator complete source digest drifted".to_owned());
    }
    let source = std::str::from_utf8(&source_bytes)
        .map_err(|error| format!("exact allocator source is not UTF-8: {error}"))?;
    audit_exact_allocator_source_text(source)
}

fn audit_exact_allocator_source_text(source: &str) -> Result<(), String> {
    if source.matches(DENY_ATTRIBUTE).count() != 1
        || source
            .lines()
            .filter(|line| *line == DENY_ATTRIBUTE)
            .count()
            != 1
    {
        return Err(format!(
            "exact allocator source must contain exactly one {DENY_ATTRIBUTE}"
        ));
    }
    if source.matches("unsafe_code").count() != EXACT_ALLOC_UNSAFE_CODE_SPELLINGS {
        return Err("exact allocator unsafe-lint lowering inventory drifted".to_owned());
    }
    let mut prior_end = 0;
    for block in EXACT_ALLOC_REVIEWED_BLOCKS {
        if source.matches(block).count() != 1 {
            return Err("exact allocator reviewed unsafe site binding drifted".to_owned());
        }
        let offset = source
            .find(block)
            .ok_or_else(|| "exact allocator reviewed unsafe site disappeared".to_owned())?;
        if offset < prior_end {
            return Err("exact allocator reviewed unsafe site order drifted".to_owned());
        }
        prior_end = offset
            .checked_add(block.len())
            .ok_or_else(|| "exact allocator reviewed unsafe site offset overflow".to_owned())?;
    }
    for forbidden in [
        "include!",
        "include_bytes!",
        "include_str!",
        "#[path",
        "macro_rules!",
        "proc_macro",
        "env!",
        "option_env!",
    ] {
        if source.contains(forbidden) {
            return Err(format!(
                "exact allocator source contains forbidden expansion path {forbidden:?}"
            ));
        }
    }
    Ok(())
}

fn audit_static_runtime(
    packages: &BTreeMap<&str, &Package>,
    workspace_root: &Path,
) -> Result<(), String> {
    let package = packages
        .get(STATIC_RUNTIME_PACKAGE)
        .ok_or_else(|| format!("missing {STATIC_RUNTIME_PACKAGE} workspace package"))?;
    if package.targets.len() != 1 {
        return Err(format!(
            "{STATIC_RUNTIME_PACKAGE} must have exactly one target, observed {}",
            package.targets.len()
        ));
    }
    for dependency in &package.dependencies {
        let name = dependency
            .get("name")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                format!("{STATIC_RUNTIME_PACKAGE} dependency lacks an exact package name")
            })?;
        if matches!(
            name,
            "fre" | "fre-aot-compiler" | "fre-aot-macho" | "fre-jit-aarch64" | "fre-jit-runtime"
        ) {
            return Err(format!(
                "{STATIC_RUNTIME_PACKAGE} has forbidden compiler/JIT dependency {name}"
            ));
        }
    }

    let package_root = canonical(
        &workspace_root.join("crates/fre-aot-static-runtime"),
        "fre-aot-static-runtime package root",
    )?;
    let expected_manifest = canonical(
        &package_root.join("Cargo.toml"),
        "fre-aot-static-runtime manifest",
    )?;
    if canonical(
        &package.manifest_path,
        "fre-aot-static-runtime package manifest",
    )? != expected_manifest
    {
        return Err("fre-aot-static-runtime manifest path drifted".to_owned());
    }
    let expected_source = canonical(
        &package_root.join("src/lib.rs"),
        "fre-aot-static-runtime library source",
    )?;
    let target = &package.targets[0];
    if target.name != STATIC_RUNTIME_LIBRARY
        || target.kind.as_slice() != ["lib"]
        || canonical(&target.src_path, "fre-aot-static-runtime target source")? != expected_source
    {
        return Err(format!(
            "unexpected fre-aot-static-runtime target {} kind {:?} source {}",
            target.name,
            target.kind,
            target.src_path.display()
        ));
    }

    let mut files = BTreeSet::new();
    collect_regular_files(&package_root, &package_root, &mut files)?;
    require_static_runtime_file_inventory(&files)?;

    let reviewed: BTreeMap<_, _> = STATIC_RUNTIME_REVIEWED_UNSAFE_SOURCES
        .iter()
        .map(|source| (PathBuf::from(source.relative), source))
        .collect();
    if reviewed.len() != STATIC_RUNTIME_REVIEWED_UNSAFE_SOURCES.len() {
        return Err("duplicate fre-aot-static-runtime reviewed unsafe source".to_owned());
    }
    let mut observed_reviewed = BTreeSet::new();
    for relative in files
        .iter()
        .filter(|relative| relative.extension().and_then(|value| value.to_str()) == Some("rs"))
    {
        let path = package_root.join(relative);
        let source_bytes = fs::read(&path)
            .map_err(|error| format!("read static runtime source {}: {error}", path.display()))?;
        if let Some(specification) = reviewed.get(relative) {
            observed_reviewed.insert(relative.clone());
            audit_static_runtime_unsafe_source(&source_bytes, specification)?;
        } else {
            audit_static_runtime_safe_source(relative, &source_bytes)?;
        }
    }
    let expected_reviewed: BTreeSet<_> = reviewed.keys().cloned().collect();
    if observed_reviewed != expected_reviewed {
        return Err(format!(
            "fre-aot-static-runtime unsafe source inventory drifted: observed={observed_reviewed:?} expected={expected_reviewed:?}"
        ));
    }
    Ok(())
}

fn require_static_runtime_file_inventory(files: &BTreeSet<PathBuf>) -> Result<(), String> {
    let expected: BTreeSet<_> = STATIC_RUNTIME_FILES
        .iter()
        .map(|relative| PathBuf::from(*relative))
        .collect();
    if files != &expected {
        return Err(format!(
            "fre-aot-static-runtime file inventory drifted: actual={files:?} expected={expected:?}"
        ));
    }
    Ok(())
}

fn audit_static_runtime_unsafe_source(
    source_bytes: &[u8],
    specification: &ReviewedUnsafeSource,
) -> Result<(), String> {
    if Sha256::digest(source_bytes)[..] != specification.sha256 {
        return Err(format!(
            "fre-aot-static-runtime complete source digest drifted for {}",
            specification.relative
        ));
    }
    let source = std::str::from_utf8(source_bytes).map_err(|error| {
        format!(
            "fre-aot-static-runtime source {} is not UTF-8: {error}",
            specification.relative
        )
    })?;
    if source.contains("#![allow") {
        return Err(format!(
            "fre-aot-static-runtime source {} contains a crate/module-wide allow",
            specification.relative
        ));
    }
    let observed = [
        ("unsafe_code", source.matches("unsafe_code").count()),
        ("unsafe {", source.matches("unsafe {").count()),
        ("unsafe fn", source.matches("unsafe fn").count()),
        ("unsafe extern", source.matches("unsafe extern").count()),
        ("unsafe impl", source.matches("unsafe impl").count()),
        ("unsafe trait", source.matches("unsafe trait").count()),
    ];
    let expected = [
        ("unsafe_code", specification.unsafe_code),
        ("unsafe {", specification.unsafe_blocks),
        ("unsafe fn", specification.unsafe_functions),
        ("unsafe extern", specification.unsafe_externs),
        ("unsafe impl", specification.unsafe_impls),
        ("unsafe trait", specification.unsafe_traits),
    ];
    if observed != expected {
        return Err(format!(
            "fre-aot-static-runtime unsafe token inventory drifted for {}: observed={observed:?} expected={expected:?}",
            specification.relative
        ));
    }
    let item_allow_lines = source
        .lines()
        .filter(|line| line.trim() == "unsafe_code,")
        .count();
    if item_allow_lines != specification.unsafe_code {
        return Err(format!(
            "fre-aot-static-runtime item-scoped unsafe allowance inventory drifted for {}",
            specification.relative
        ));
    }
    reject_static_runtime_expansion_paths(specification.relative, source)
}

fn audit_static_runtime_safe_source(relative: &Path, source_bytes: &[u8]) -> Result<(), String> {
    let source = std::str::from_utf8(source_bytes).map_err(|error| {
        format!(
            "fre-aot-static-runtime source {} is not UTF-8: {error}",
            relative.display()
        )
    })?;
    let is_library = relative == Path::new("src/lib.rs");
    let expected_unsafe_code = usize::from(is_library);
    if source.matches("unsafe_code").count() != expected_unsafe_code
        || (is_library
            && (source.matches(STATIC_RUNTIME_DENY_ATTRIBUTE).count() != 1
                || !source
                    .lines()
                    .any(|line| line == STATIC_RUNTIME_DENY_ATTRIBUTE)))
    {
        return Err(format!(
            "fre-aot-static-runtime safe source {} unsafe-lint boundary drifted",
            relative.display()
        ));
    }
    for forbidden in [
        "#![allow",
        "unsafe {",
        "unsafe fn",
        "unsafe extern",
        "unsafe impl",
        "unsafe trait",
    ] {
        if source.contains(forbidden) {
            return Err(format!(
                "fre-aot-static-runtime safe source {} contains forbidden token {forbidden:?}",
                relative.display()
            ));
        }
    }
    reject_static_runtime_expansion_paths(&relative.to_string_lossy(), source)
}

fn reject_static_runtime_expansion_paths(relative: &str, source: &str) -> Result<(), String> {
    for forbidden in [
        "include!",
        "include_bytes!",
        "include_str!",
        "#[path",
        "proc_macro",
        "env!",
        "option_env!",
    ] {
        if source.contains(forbidden) {
            return Err(format!(
                "fre-aot-static-runtime source {relative} contains forbidden expansion path {forbidden:?}"
            ));
        }
    }
    Ok(())
}

fn audit_target_features(
    packages: &BTreeMap<&str, &Package>,
    workspace_root: &Path,
) -> Result<(), String> {
    let package = packages
        .get(TARGET_FEATURES_PACKAGE)
        .ok_or_else(|| format!("missing {TARGET_FEATURES_PACKAGE} workspace package"))?;
    if package.dependencies.len() != 1
        || package.dependencies[0]
            .get("name")
            .and_then(serde_json::Value::as_str)
            != Some("libc")
    {
        return Err(format!(
            "{TARGET_FEATURES_PACKAGE} must have only its audited macOS libc dependency"
        ));
    }

    let package_root = canonical(
        &workspace_root.join("crates/fre-target-features"),
        "fre-target-features package root",
    )?;
    let expected_library = canonical(
        &package_root.join("src/lib.rs"),
        "fre-target-features library source",
    )?;
    let expected_example = canonical(
        &package_root.join("examples/host_features.rs"),
        "fre-target-features host evidence example",
    )?;
    let mut library_count = 0_usize;
    let mut example_count = 0_usize;
    for target in &package.targets {
        let source = canonical(
            &target.src_path,
            &format!("source for fre-target-features target {}", target.name),
        )?;
        if target.name == TARGET_FEATURES_LIBRARY
            && target.kind.as_slice() == ["lib"]
            && source == expected_library
        {
            library_count = library_count
                .checked_add(1)
                .ok_or_else(|| "fre-target-features library count overflow".to_owned())?;
        } else if target.name == "host_features"
            && target.kind.as_slice() == ["example"]
            && source == expected_example
        {
            example_count = example_count
                .checked_add(1)
                .ok_or_else(|| "fre-target-features example count overflow".to_owned())?;
            require_attribute(&source, FORBID_ATTRIBUTE, true, &target.name)?;
        } else {
            return Err(format!(
                "unexpected fre-target-features target {} kind {:?} source {}",
                target.name,
                target.kind,
                target.src_path.display()
            ));
        }
    }
    if library_count != 1 || example_count != 1 || package.targets.len() != 2 {
        return Err(format!(
            "fre-target-features target inventory drifted: libraries={library_count} examples={example_count} total={}",
            package.targets.len()
        ));
    }

    let mut files = BTreeSet::new();
    collect_regular_files(&package_root, &package_root, &mut files)?;
    let expected_files = BTreeSet::from([
        PathBuf::from("Cargo.toml"),
        PathBuf::from("examples/host_features.rs"),
        PathBuf::from("src/lib.rs"),
    ]);
    if files != expected_files {
        return Err(format!(
            "fre-target-features file inventory drifted: actual={files:?} expected={expected_files:?}"
        ));
    }

    let source_bytes = fs::read(&expected_library)
        .map_err(|error| format!("read target feature source: {error}"))?;
    if Sha256::digest(&source_bytes)[..] != TARGET_FEATURES_SOURCE_SHA256 {
        return Err("target feature complete source digest drifted".to_owned());
    }
    let source = std::str::from_utf8(&source_bytes)
        .map_err(|error| format!("target feature source is not UTF-8: {error}"))?;
    audit_target_feature_source_text(source)
}

fn audit_target_feature_source_text(source: &str) -> Result<(), String> {
    if source.matches(DENY_ATTRIBUTE).count() != 1
        || source
            .lines()
            .filter(|line| *line == DENY_ATTRIBUTE)
            .count()
            != 1
    {
        return Err(format!(
            "target feature source must contain exactly one {DENY_ATTRIBUTE}"
        ));
    }
    if source.matches("unsafe_code").count() != TARGET_FEATURES_UNSAFE_CODE_SPELLINGS {
        return Err("target feature unsafe-lint lowering inventory drifted".to_owned());
    }
    for block in [
        TARGET_FEATURES_X86_REVIEWED_BLOCK,
        TARGET_FEATURES_MACOS_REVIEWED_BLOCK,
    ] {
        if source.matches(block).count() != 1 {
            return Err("target feature reviewed unsafe site binding drifted".to_owned());
        }
    }
    if source.matches("unsafe {").count() != 3 {
        return Err("target feature unsafe block inventory drifted".to_owned());
    }
    for forbidden in [
        "unsafe fn",
        "unsafe impl",
        "unsafe trait",
        "unsafe extern",
        "#[unsafe(",
        "include!",
        "include_bytes!",
        "include_str!",
        "#[path",
        "proc_macro",
        "env!",
        "option_env!",
    ] {
        if source.contains(forbidden) {
            return Err(format!(
                "target feature source contains forbidden unsafe or expansion path {forbidden:?}"
            ));
        }
    }
    Ok(())
}

fn audit_simd_kernels(
    packages: &BTreeMap<&str, &Package>,
    workspace_root: &Path,
) -> Result<(), String> {
    let package = packages
        .get(SIMD_KERNELS_PACKAGE)
        .ok_or_else(|| format!("missing {SIMD_KERNELS_PACKAGE} workspace package"))?;
    if package.dependencies.len() != 1
        || package.dependencies[0]
            .get("name")
            .and_then(serde_json::Value::as_str)
            != Some(TARGET_FEATURES_PACKAGE)
    {
        return Err(format!(
            "{SIMD_KERNELS_PACKAGE} must depend only on {TARGET_FEATURES_PACKAGE}"
        ));
    }
    if package.targets.len() != 1 {
        return Err(format!(
            "{SIMD_KERNELS_PACKAGE} must have exactly one target, observed {}",
            package.targets.len()
        ));
    }

    let package_root = canonical(
        &workspace_root.join("crates/fre-simd-kernels"),
        "fre-simd-kernels package root",
    )?;
    let expected_manifest = canonical(
        &package_root.join("Cargo.toml"),
        "fre-simd-kernels manifest",
    )?;
    if canonical(&package.manifest_path, "fre-simd-kernels package manifest")? != expected_manifest
    {
        return Err("fre-simd-kernels manifest path drifted".to_owned());
    }
    let expected_library = canonical(
        &package_root.join("src/lib.rs"),
        "fre-simd-kernels library source",
    )?;
    let target = &package.targets[0];
    if target.name != SIMD_KERNELS_LIBRARY
        || target.kind.as_slice() != ["lib"]
        || canonical(&target.src_path, "fre-simd-kernels target source")? != expected_library
    {
        return Err(format!(
            "unexpected fre-simd-kernels target {} kind {:?} source {}",
            target.name,
            target.kind,
            target.src_path.display()
        ));
    }

    let mut files = BTreeSet::new();
    collect_regular_files(&package_root, &package_root, &mut files)?;
    let expected_files: BTreeSet<_> = SIMD_KERNELS_REVIEWED_FILES
        .iter()
        .map(|reviewed| PathBuf::from(reviewed.relative))
        .collect();
    if files != expected_files {
        return Err(format!(
            "fre-simd-kernels file inventory drifted: actual={files:?} expected={expected_files:?}"
        ));
    }
    for reviewed in SIMD_KERNELS_REVIEWED_FILES {
        let path = package_root.join(reviewed.relative);
        let bytes = fs::read(&path)
            .map_err(|error| format!("read reviewed SIMD kernel {}: {error}", path.display()))?;
        if Sha256::digest(&bytes)[..] != reviewed.sha256 {
            return Err(format!(
                "reviewed SIMD kernel digest drifted: {}",
                reviewed.relative
            ));
        }
    }
    require_attribute(
        &expected_library,
        DENY_ATTRIBUTE,
        false,
        SIMD_KERNELS_LIBRARY,
    )
}

fn collect_regular_files(
    root: &Path,
    directory: &Path,
    files: &mut BTreeSet<PathBuf>,
) -> Result<(), String> {
    let entries = fs::read_dir(directory)
        .map_err(|error| format!("read directory {}: {error}", directory.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("read directory entry: {error}"))?;
        let file_type = entry
            .file_type()
            .map_err(|error| format!("read file type for {}: {error}", entry.path().display()))?;
        let path = entry.path();
        if file_type.is_symlink() {
            return Err(format!(
                "symlink is forbidden in audited source: {}",
                path.display()
            ));
        }
        if file_type.is_dir() {
            collect_regular_files(root, &path, files)?;
        } else if file_type.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|error| format!("strip source root from {}: {error}", path.display()))?;
            if !files.insert(relative.to_path_buf()) {
                return Err(format!("duplicate audited source file: {}", path.display()));
            }
        } else {
            return Err(format!("unexpected filesystem entry: {}", path.display()));
        }
    }
    Ok(())
}

fn require_attribute(
    path: &Path,
    attribute: &str,
    must_be_first_line: bool,
    target: &str,
) -> Result<(), String> {
    let source = fs::read_to_string(path)
        .map_err(|error| format!("read target {target} at {}: {error}", path.display()))?;
    let present = if must_be_first_line {
        source.lines().next() == Some(attribute)
    } else {
        source.lines().any(|line| line == attribute)
    };
    if !present {
        let placement = if must_be_first_line {
            "as its first line"
        } else {
            "as an exact crate attribute"
        };
        return Err(format!(
            "target {target} at {} must contain {attribute} {placement}",
            path.display()
        ));
    }
    Ok(())
}

fn canonical(path: &Path, description: &str) -> Result<PathBuf, String> {
    path.canonicalize()
        .map_err(|error| format!("canonicalize {description} {}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::{
        DENY_ATTRIBUTE, EXACT_ALLOC_LINTS, EXACT_ALLOC_REVIEWED_BLOCKS, EXACT_VEC_REVIEWED_BLOCK,
        Package, ReviewedUnsafeSource, STATIC_RUNTIME_FILES, STATIC_RUNTIME_LINTS,
        STATIC_RUNTIME_REVIEWED_UNSAFE_SOURCES, TARGET_FEATURES_MACOS_REVIEWED_BLOCK,
        TARGET_FEATURES_X86_REVIEWED_BLOCK, Target, WARN_UNSAFE_LINTS, ZEROED_EXACT_REVIEWED_BLOCK,
        audit_exact_allocator, audit_exact_allocator_source, audit_exact_allocator_source_text,
        audit_kernel_targets, audit_static_runtime_safe_source, audit_static_runtime_unsafe_source,
        audit_target_feature_source_text, require_exact_lints,
        require_static_runtime_file_inventory,
    };
    use sha2::{Digest as _, Sha256};
    use std::{
        collections::{BTreeMap, BTreeSet},
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_TREE: AtomicU64 = AtomicU64::new(0);

    struct TestTree(PathBuf);

    impl TestTree {
        fn new() -> Self {
            for _ in 0..100 {
                let sequence = NEXT_TREE.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "fre-unsafe-lint-boundary-test-{}-{sequence}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("create test tree {}: {error}", path.display()),
                }
            }
            panic!("could not create unique lint-boundary test tree");
        }

        fn root(&self) -> &Path {
            &self.0
        }

        fn write(&self, relative: &str, source: &str) -> PathBuf {
            let path = self.0.join(relative);
            fs::create_dir_all(path.parent().expect("fixture path has a parent"))
                .expect("create fixture parent");
            fs::write(&path, source).expect("write fixture source");
            path
        }
    }

    impl Drop for TestTree {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("remove lint-boundary test tree");
        }
    }

    fn kernel_package(tree: &TestTree, additional: Vec<Target>) -> Package {
        let library = tree.write(
            "crates/fre-kernels/src/lib.rs",
            "//! fixture\n#![forbid(unsafe_code)]\n",
        );
        let manifest = tree.write(
            "crates/fre-kernels/Cargo.toml",
            "[package]\nname='fixture'\n",
        );
        let mut targets = vec![Target {
            name: "fre_kernels".to_owned(),
            kind: vec!["lib".to_owned()],
            src_path: library,
        }];
        targets.extend(additional);
        Package {
            id: "fixture fre-kernels".to_owned(),
            name: "fre-kernels".to_owned(),
            manifest_path: manifest,
            dependencies: Vec::new(),
            targets,
        }
    }

    fn target(name: &str, kind: &str, source: PathBuf) -> Target {
        Target {
            name: name.to_owned(),
            kind: vec![kind.to_owned()],
            src_path: source,
        }
    }

    fn exact_source() -> String {
        let mut source = "//! fixture\n#![deny(unsafe_code)]\n\n".to_owned();
        for block in EXACT_ALLOC_REVIEWED_BLOCKS {
            source.push_str(block);
            source.push_str("\n\n");
        }
        source
    }

    fn canonical_exact_source() -> &'static str {
        include_str!("../../../crates/fre-exact-alloc/src/lib.rs")
    }

    fn canonical_target_feature_source() -> &'static str {
        include_str!("../../../crates/fre-target-features/src/lib.rs")
    }

    fn canonical_static_runtime_unsafe_source(relative: &str) -> &'static [u8] {
        match relative {
            "src/linked/macos_aarch64.rs" => {
                include_bytes!("../../../crates/fre-aot-static-runtime/src/linked/macos_aarch64.rs")
            }
            "src/linked/mod.rs" => {
                include_bytes!("../../../crates/fre-aot-static-runtime/src/linked/mod.rs")
            }
            "src/linked/unavailable.rs" => {
                include_bytes!("../../../crates/fre-aot-static-runtime/src/linked/unavailable.rs")
            }
            "src/search_linked/linux_aarch64.rs" => {
                include_bytes!(
                    "../../../crates/fre-aot-static-runtime/src/search_linked/linux_aarch64.rs"
                )
            }
            "src/search_linked/macos_aarch64.rs" => {
                include_bytes!(
                    "../../../crates/fre-aot-static-runtime/src/search_linked/macos_aarch64.rs"
                )
            }
            "src/search_linked/mod.rs" => {
                include_bytes!("../../../crates/fre-aot-static-runtime/src/search_linked/mod.rs")
            }
            "src/search_linked/unavailable.rs" => {
                include_bytes!(
                    "../../../crates/fre-aot-static-runtime/src/search_linked/unavailable.rs"
                )
            }
            _ => panic!("unknown reviewed static runtime source"),
        }
    }

    fn assert_exact_source_rejected(source: &str) {
        assert!(audit_exact_allocator_source_text(source).is_err());
    }

    fn exact_package(tree: &TestTree, additional: Vec<Target>) -> Package {
        let source = tree.write(
            "crates/fre-exact-alloc/src/lib.rs",
            canonical_exact_source(),
        );
        let manifest = tree.write(
            "crates/fre-exact-alloc/Cargo.toml",
            "[package]\nname='fre-exact-alloc'\n",
        );
        let mut targets = vec![Target {
            name: "fre_exact_alloc".to_owned(),
            kind: vec!["lib".to_owned()],
            src_path: source,
        }];
        targets.extend(additional);
        Package {
            id: "fixture fre-exact-alloc".to_owned(),
            name: "fre-exact-alloc".to_owned(),
            manifest_path: manifest,
            dependencies: Vec::new(),
            targets,
        }
    }

    #[test]
    fn integration_test_escape_is_rejected() {
        let tree = TestTree::new();
        let escape = tree.write(
            "crates/fre-kernels/tests/lint_escape.rs",
            "#![allow(unsafe_code)]\nfn escape() {}\n",
        );
        let package = kernel_package(&tree, vec![target("lint_escape", "test", escape)]);
        let error = audit_kernel_targets(&package, tree.root()).unwrap_err();
        assert!(error.contains("lint_escape"));
        assert!(error.contains("#![forbid(unsafe_code)]"));
    }

    #[test]
    fn manifest_declared_custom_target_escape_is_rejected() {
        let tree = TestTree::new();
        let escape = tree.write(
            "crates/fre-kernels/custom/escape.rs",
            "#![allow(unsafe_code)]\nfn main() {}\n",
        );
        let package = kernel_package(&tree, vec![target("custom_escape", "example", escape)]);
        let error = audit_kernel_targets(&package, tree.root()).unwrap_err();
        assert!(error.contains("custom_escape"));
        assert!(error.contains("#![forbid(unsafe_code)]"));
    }

    #[test]
    fn every_nonlibrary_metadata_target_with_first_line_forbid_is_accepted() {
        let tree = TestTree::new();
        let integration = tree.write(
            "crates/fre-kernels/tests/protected.rs",
            "#![forbid(unsafe_code)]\n#[test]\nfn protected() {}\n",
        );
        let custom = tree.write(
            "crates/fre-kernels/custom/protected.rs",
            "#![forbid(unsafe_code)]\nfn main() {}\n",
        );
        let package = kernel_package(
            &tree,
            vec![
                target("protected", "test", integration),
                target("custom_protected", "example", custom),
            ],
        );
        assert_eq!(audit_kernel_targets(&package, tree.root()), Ok(2));
    }

    #[test]
    fn additional_unsafe_lowering_is_rejected() {
        let source = format!(
            "{}\n#[allow(unsafe_code)]\nunsafe fn escaped() {{}}\n",
            exact_source()
        );
        let error = audit_exact_allocator_source_text(&source).unwrap_err();
        assert!(error.contains("lowering inventory drifted"));
    }

    #[test]
    fn canonical_target_feature_unsafe_inventory_is_accepted() {
        assert_eq!(
            audit_target_feature_source_text(canonical_target_feature_source()),
            Ok(())
        );
    }

    #[test]
    fn target_feature_unsafe_inventory_and_reviewed_sites_are_fail_closed() {
        let canonical = canonical_target_feature_source();
        for mutation in [
            canonical.replace(
                TARGET_FEATURES_X86_REVIEWED_BLOCK,
                &TARGET_FEATURES_X86_REVIEWED_BLOCK.replace("__cpuid(1)", "__cpuid(2)"),
            ),
            canonical.replace(TARGET_FEATURES_MACOS_REVIEWED_BLOCK, ""),
            format!(
                "{canonical}\n#[allow(unsafe_code, reason = \"unreviewed\")]\nfn extra() {{ unsafe {{ core::hint::unreachable_unchecked() }} }}\n"
            ),
        ] {
            assert!(audit_target_feature_source_text(&mutation).is_err());
        }
    }

    #[test]
    fn exactly_seven_reviewed_unsafe_blocks_in_order_are_accepted() {
        assert_eq!(audit_exact_allocator_source_text(&exact_source()), Ok(()));
    }

    #[test]
    fn canonical_complete_source_digest_is_accepted() {
        let tree = TestTree::new();
        let path = tree.write(
            "crates/fre-exact-alloc/src/lib.rs",
            canonical_exact_source(),
        );
        assert_eq!(audit_exact_allocator_source(&path), Ok(()));
    }

    #[test]
    fn inactive_or_replaced_reviewed_blocks_fail_complete_digest() {
        let tree = TestTree::new();
        let cfg_test = canonical_exact_source().replace(
            "#[allow(\n    unsafe_code,",
            "#[cfg(test)]\n#[allow(\n    unsafe_code,",
        );
        let cfg_pair = format!(
            "{cfg_test}\n\
             #[cfg(not(test))]\nfn exact_vec_with_capacity<T>(_: usize, _: bool) -> Result<ExactVec<T>, CopyError> {{ unreachable!() }}\n\
             #[cfg(not(test))]\nfn zeroed_exact_with(_: usize, _: bool) -> Result<Vec<u8>, CopyError> {{ unreachable!() }}\n\
             #[cfg(not(test))]\nfn copy_exact_with(_: &[u8], _: bool) -> Result<Vec<u8>, CopyError> {{ unreachable!() }}\n"
        );
        let cfg_attr = canonical_exact_source().replace(
            "#[allow(\n    unsafe_code,",
            "#[cfg_attr(not(test), cfg(any()))]\n#[allow(\n    unsafe_code,",
        );
        let commented = canonical_exact_source().replacen(
            EXACT_VEC_REVIEWED_BLOCK,
            &format!("/*\n{EXACT_VEC_REVIEWED_BLOCK}\n*/"),
            1,
        );
        let string_inert = canonical_exact_source().replacen(
            EXACT_VEC_REVIEWED_BLOCK,
            &format!(
                "const INERT_REVIEWED_BLOCK: &str = r###\"{EXACT_VEC_REVIEWED_BLOCK}\"###;\n\
                 fn exact_vec_with_capacity<T>(_: usize, _: bool) -> Result<ExactVec<T>, CopyError> {{ unreachable!() }}"
            ),
            1,
        );
        for (name, source) in [
            ("cfg-test-and-active-replacement.rs", cfg_pair),
            ("cfg-attr.rs", cfg_attr),
            ("comment-inert.rs", commented),
            ("string-inert-and-active-replacement.rs", string_inert),
        ] {
            let path = tree.write(name, &source);
            assert!(
                audit_exact_allocator_source(&path)
                    .unwrap_err()
                    .contains("complete source digest")
            );
        }
    }

    #[test]
    fn every_missing_or_duplicated_reviewed_unsafe_block_is_rejected() {
        for block in EXACT_ALLOC_REVIEWED_BLOCKS {
            assert_exact_source_rejected(&exact_source().replace(block, ""));
            assert_exact_source_rejected(&format!("{}\n{block}\n", exact_source()));
        }
    }

    #[test]
    fn reviewed_unsafe_block_order_and_alternate_allowance_are_rejected() {
        let reordered = exact_source().replace(
            &format!("{EXACT_VEC_REVIEWED_BLOCK}\n\n{ZEROED_EXACT_REVIEWED_BLOCK}"),
            &format!("{ZEROED_EXACT_REVIEWED_BLOCK}\n\n{EXACT_VEC_REVIEWED_BLOCK}"),
        );
        assert_exact_source_rejected(&reordered);
        assert_exact_source_rejected(&format!(
            "{}\n#[allow( unsafe_code, reason = \"fourth\" )]\nunsafe fn fourth() {{}}\n",
            exact_source()
        ));
        assert_exact_source_rejected(&exact_source().replacen(
            "#[allow(\n    unsafe_code,",
            "#[allow( unsafe_code,",
            1,
        ));
    }

    #[test]
    fn every_reviewed_function_name_and_reason_is_exact() {
        for (original, replacement) in [
            ("pub fn boxed(&self)", "pub fn renamed_boxed(&self)"),
            (
                "pub fn boxed_mut(&mut self)",
                "pub fn renamed_boxed_mut(&mut self)",
            ),
            ("fn drop(&mut self)", "fn renamed_drop(&mut self)"),
            (
                "fn exact_box_or_usize_with<T>(",
                "fn renamed_exact_box_or_usize_with<T>(",
            ),
            ("fn exact_vec_with_capacity<T>(", "fn renamed_exact_vec<T>("),
            ("fn zeroed_exact_with(", "fn renamed_zeroed_exact_with("),
            ("fn copy_exact_with(", "fn renamed_copy_exact_with("),
            (
                "the tagged word recovers only the exposed provenance of its live owned allocation",
                "changed tagged borrow boundary",
            ),
            (
                "the exclusive handle borrow recovers only the exposed provenance of its live exclusively owned allocation",
                "changed tagged mutable-borrow boundary",
            ),
            (
                "the tagged word reconstructs its uniquely owned exact allocation for one drop",
                "changed tagged drop boundary",
            ),
            (
                "this reviewed function owns FRE's exact-layout single-value allocation boundary",
                "changed single-value allocation boundary",
            ),
            (
                "this reviewed function owns FRE's exact-layout typed allocation boundary",
                "changed typed allocation boundary",
            ),
            (
                "this reviewed function owns FRE's exact-layout zero-initialization boundary",
                "changed zero-initialization boundary",
            ),
            (
                "this one reviewed function owns FRE's exact-layout allocation boundary",
                "changed copy allocation boundary",
            ),
        ] {
            let mutated = exact_source().replacen(original, replacement, 1);
            assert_ne!(mutated, exact_source());
            assert_exact_source_rejected(&mutated);
        }
    }

    #[test]
    fn every_reviewed_unsafe_body_is_exact() {
        for (original, replacement) in [
            (
                "ptr::with_exposed_provenance::<T>(address).as_ref()",
                "ptr::without_provenance::<T>(address).as_ref()",
            ),
            (
                "ptr::with_exposed_provenance_mut::<T>(address).as_mut()",
                "ptr::without_provenance_mut::<T>(address).as_mut()",
            ),
            (
                "Box::from_raw(ptr::with_exposed_provenance_mut::<T>(\n                address,\n            ))",
                "Box::from_raw(ptr::without_provenance_mut::<T>(address))",
            ),
            (
                "encoded: typed.expose_provenance() | 1",
                "encoded: typed.expose_provenance()",
            ),
            (
                "unsafe { alloc(layout) }",
                "unsafe { alloc_zeroed(layout) }",
            ),
            ("ptr::null_mut()", "core::ptr::null_mut()"),
            (
                "Vec::from_raw_parts(allocation.cast::<T>(), 0, capacity)",
                "Vec::from_raw_parts(allocation.cast::<T>(), 0, capacity - 1)",
            ),
            (
                "Vec::from_raw_parts(allocation, len, len)",
                "Vec::from_raw_parts(allocation, len, len + 1)",
            ),
            (
                "ptr::copy_nonoverlapping(bytes.as_ptr(), allocation, bytes.len());",
                "ptr::copy(bytes.as_ptr(), allocation, bytes.len());",
            ),
            (
                "Vec::from_raw_parts(allocation, bytes.len(), bytes.len())",
                "Vec::from_raw_parts(allocation, bytes.len(), bytes.len() + 1)",
            ),
        ] {
            let mutated = exact_source().replacen(original, replacement, 1);
            assert_ne!(mutated, exact_source());
            assert_exact_source_rejected(&mutated);
        }
    }

    #[test]
    fn exact_allocator_deny_attribute_is_unique() {
        assert_exact_source_rejected(&exact_source().replace(DENY_ATTRIBUTE, ""));
        assert_exact_source_rejected(&format!("{DENY_ATTRIBUTE}\n{}", exact_source()));
        assert_exact_source_rejected(
            &exact_source().replace(DENY_ATTRIBUTE, &format!("// {DENY_ATTRIBUTE}")),
        );
    }

    #[test]
    fn static_runtime_reviewed_sources_match_hash_and_token_inventory() {
        for specification in &STATIC_RUNTIME_REVIEWED_UNSAFE_SOURCES {
            assert_eq!(
                audit_static_runtime_unsafe_source(
                    canonical_static_runtime_unsafe_source(specification.relative),
                    specification,
                ),
                Ok(())
            );
        }
    }

    #[test]
    fn static_runtime_source_hash_and_unsafe_token_drift_are_rejected() {
        let specification = STATIC_RUNTIME_REVIEWED_UNSAFE_SOURCES[2];
        let canonical = canonical_static_runtime_unsafe_source(specification.relative);

        let mut hash_drift = canonical.to_vec();
        hash_drift.push(b'\n');
        assert!(
            audit_static_runtime_unsafe_source(&hash_drift, &specification)
                .unwrap_err()
                .contains("complete source digest")
        );

        let mut token_drift = canonical.to_vec();
        token_drift.extend_from_slice(b"// unsafe {\n");
        let mut token_specification = ReviewedUnsafeSource {
            sha256: Sha256::digest(&token_drift).into(),
            ..specification
        };
        assert!(
            audit_static_runtime_unsafe_source(&token_drift, &token_specification)
                .unwrap_err()
                .contains("unsafe token inventory")
        );
        token_specification.unsafe_blocks = token_specification
            .unsafe_blocks
            .checked_add(1)
            .expect("fixture token count");
        assert_eq!(
            audit_static_runtime_unsafe_source(&token_drift, &token_specification),
            Ok(())
        );
    }

    #[test]
    fn static_runtime_missing_or_extra_file_is_rejected() {
        let mut files: BTreeSet<_> = STATIC_RUNTIME_FILES
            .iter()
            .map(|relative| PathBuf::from(*relative))
            .collect();
        assert_eq!(require_static_runtime_file_inventory(&files), Ok(()));
        files.remove(Path::new("src/linked/unavailable.rs"));
        assert!(
            require_static_runtime_file_inventory(&files)
                .unwrap_err()
                .contains("file inventory")
        );
        files.insert(PathBuf::from("src/linked/unavailable.rs"));
        files.insert(PathBuf::from("src/linked/unsafe_escape.rs"));
        assert!(
            require_static_runtime_file_inventory(&files)
                .unwrap_err()
                .contains("file inventory")
        );
    }

    #[test]
    fn static_runtime_safe_source_cannot_lower_or_contain_unsafe() {
        assert_eq!(
            audit_static_runtime_safe_source(
                Path::new("src/lib.rs"),
                b"#![deny(unsafe_code, unsafe_op_in_unsafe_fn)]\npub fn safe() {}\n",
            ),
            Ok(())
        );
        for source in [
            b"#![allow(unsafe_code)]\n".as_slice(),
            b"unsafe fn escape() {}\n".as_slice(),
            b"fn escape() { unsafe {} }\n".as_slice(),
        ] {
            assert!(audit_static_runtime_safe_source(Path::new("src/escape.rs"), source).is_err());
        }
    }

    #[test]
    fn missing_reviewed_unsafe_lowering_is_rejected() {
        let source = exact_source().replace(ZEROED_EXACT_REVIEWED_BLOCK, "");
        let error = audit_exact_allocator_source_text(&source).unwrap_err();
        assert!(error.contains("lowering inventory drifted"));
    }

    #[test]
    fn reviewed_unsafe_lowering_reason_drift_is_rejected() {
        let source = exact_source().replace(
            "exact-layout zero-initialization boundary",
            "changed boundary",
        );
        let error = audit_exact_allocator_source_text(&source).unwrap_err();
        assert!(error.contains("reviewed unsafe site binding drifted"));
    }

    #[test]
    fn reviewed_unsafe_lowering_function_binding_drift_is_rejected() {
        let source =
            exact_source().replace("fn zeroed_exact_with(", "fn renamed_zeroed_exact_with(");
        let error = audit_exact_allocator_source_text(&source).unwrap_err();
        assert!(error.contains("reviewed unsafe site binding drifted"));
    }

    #[test]
    fn generated_or_additional_allocator_target_is_rejected() {
        let tree = TestTree::new();
        let generated = tree.write(
            "crates/fre-exact-alloc/build.rs",
            "#![forbid(unsafe_code)]\nfn main() {}\n",
        );
        let package = exact_package(
            &tree,
            vec![target("build-script-build", "custom-build", generated)],
        );
        let packages = BTreeMap::from([("fre-exact-alloc", &package)]);
        let error = audit_exact_allocator(&packages, tree.root()).unwrap_err();
        assert!(error.contains("exactly one target"));
    }

    #[test]
    fn local_exception_lint_drift_is_rejected() {
        let document: toml::Value = toml::from_str(WARN_UNSAFE_LINTS).unwrap();
        let mut actual = document.get("lints").unwrap().as_table().unwrap().clone();
        actual
            .get_mut("rust")
            .unwrap()
            .as_table_mut()
            .unwrap()
            .insert(
                "unsafe_op_in_unsafe_fn".to_owned(),
                toml::Value::String("allow".to_owned()),
            );
        let error = require_exact_lints("fre-capi", &actual, WARN_UNSAFE_LINTS).unwrap_err();
        assert!(error.contains("drifted"));
    }

    #[test]
    fn static_runtime_has_exact_deny_lint_exception() {
        let document: toml::Value = toml::from_str(STATIC_RUNTIME_LINTS).unwrap();
        let actual = document.get("lints").unwrap().as_table().unwrap();
        assert_eq!(
            require_exact_lints("fre-aot-static-runtime", actual, STATIC_RUNTIME_LINTS,),
            Ok(())
        );
        let mut drifted = actual.clone();
        drifted
            .get_mut("rust")
            .unwrap()
            .as_table_mut()
            .unwrap()
            .insert(
                "unsafe_code".to_owned(),
                toml::Value::String("warn".to_owned()),
            );
        assert!(
            require_exact_lints("fre-aot-static-runtime", &drifted, STATIC_RUNTIME_LINTS,)
                .unwrap_err()
                .contains("drifted")
        );
    }

    #[test]
    fn exact_allocator_layout_is_accepted() {
        let tree = TestTree::new();
        let package = exact_package(&tree, Vec::new());
        let packages = BTreeMap::from([("fre-exact-alloc", &package)]);
        assert_eq!(audit_exact_allocator(&packages, tree.root()), Ok(()));

        let document: toml::Value = toml::from_str(EXACT_ALLOC_LINTS).unwrap();
        let actual = document.get("lints").unwrap().as_table().unwrap();
        assert_eq!(
            require_exact_lints("fre-exact-alloc", actual, EXACT_ALLOC_LINTS),
            Ok(())
        );
    }

    #[test]
    fn allocator_dependency_and_source_expansion_are_rejected() {
        let tree = TestTree::new();
        let mut package = exact_package(&tree, Vec::new());
        package
            .dependencies
            .push(serde_json::json!({"name": "escape"}));
        let packages = BTreeMap::from([("fre-exact-alloc", &package)]);
        assert!(
            audit_exact_allocator(&packages, tree.root())
                .unwrap_err()
                .contains("no dependencies")
        );

        drop(packages);
        package.dependencies.clear();
        tree.write(
            "crates/fre-exact-alloc/src/escape.rs",
            "pub fn escape() {}\n",
        );
        let packages = BTreeMap::from([("fre-exact-alloc", &package)]);
        assert!(
            audit_exact_allocator(&packages, tree.root())
                .unwrap_err()
                .contains("file inventory")
        );
    }

    #[test]
    fn include_and_macro_expansion_paths_are_rejected() {
        let source = format!("{}\ninclude!(\"generated.rs\");\n", exact_source());
        assert!(
            audit_exact_allocator_source_text(&source)
                .unwrap_err()
                .contains("expansion path")
        );
    }
}
