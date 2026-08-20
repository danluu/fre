//! Stable, C-layout v1 data records and numeric tags.

use core::fmt;

/// Implemented ABI major version.
pub const FRE_V1_ABI_VERSION: u32 = 1;

/// Successful operation.
pub const FRE_V1_STATUS_OK: u32 = 0;
pub const FRE_V1_STATUS_INVALID_ARGUMENT: u32 = 1;
pub const FRE_V1_STATUS_ABI_MISMATCH: u32 = 2;
pub const FRE_V1_STATUS_STRUCT_TOO_SMALL: u32 = 3;
pub const FRE_V1_STATUS_INVALID_PATTERN_ENCODING: u32 = 4;
pub const FRE_V1_STATUS_UNSUPPORTED_PROFILE: u32 = 5;
pub const FRE_V1_STATUS_UNSUPPORTED_CONFIG: u32 = 6;
pub const FRE_V1_STATUS_COMPILE_ERROR: u32 = 7;
pub const FRE_V1_STATUS_SEARCH_ERROR: u32 = 8;
pub const FRE_V1_STATUS_PANIC: u32 = 9;
pub const FRE_V1_STATUS_NULL_WITH_NONZERO_LENGTH: u32 = 10;
pub const FRE_V1_STATUS_LENGTH_OVERFLOW: u32 = 11;
pub const FRE_V1_STATUS_MAX: u32 = FRE_V1_STATUS_LENGTH_OVERFLOW;

pub const FRE_V1_DIAGNOSTIC_NONE: u32 = 0;
pub const FRE_V1_DIAGNOSTIC_ARGUMENT: u32 = 1;
pub const FRE_V1_DIAGNOSTIC_CONFIG: u32 = 2;
pub const FRE_V1_DIAGNOSTIC_PATTERN_ENCODING: u32 = 3;
pub const FRE_V1_DIAGNOSTIC_COMPILE: u32 = 4;
pub const FRE_V1_DIAGNOSTIC_SEARCH: u32 = 5;
pub const FRE_V1_DIAGNOSTIC_PANIC: u32 = 6;

/// The sole profile currently admitted by the C facade.
pub const FRE_V1_PROFILE_RUST_BYTES: u32 = 1;
pub const FRE_V1_JIT_DENY: u32 = 1;

pub const FRE_V1_ENDIAN_LITTLE: u32 = 1;
pub const FRE_V1_ENDIAN_BIG: u32 = 2;

pub const FRE_V1_FEATURE_RUST_BYTES: u64 = 1 << 0;
pub const FRE_V1_FEATURE_EXISTS: u64 = 1 << 1;
pub const FRE_V1_FEATURE_SELECTED_END: u64 = 1 << 2;
pub const FRE_V1_FEATURE_SPAN: u64 = 1 << 3;
pub const FRE_V1_FEATURE_PLAN_INFO: u64 = 1 << 4;
pub const FRE_V1_FEATURE_THREAD_SAFE_REGEX: u64 = 1 << 5;
pub const FRE_V1_FEATURES: u64 = FRE_V1_FEATURE_RUST_BYTES
    | FRE_V1_FEATURE_EXISTS
    | FRE_V1_FEATURE_SELECTED_END
    | FRE_V1_FEATURE_SPAN
    | FRE_V1_FEATURE_PLAN_INFO
    | FRE_V1_FEATURE_THREAD_SAFE_REGEX;

pub const FRE_V1_PLAN_EXACT_LITERAL: u32 = 1;
pub const FRE_V1_PLAN_PACKED_LITERAL_SET: u32 = 2;
pub const FRE_V1_PLAN_LITERAL_SET_DFA: u32 = 3;
pub const FRE_V1_PLAN_REQUIRED_LITERAL: u32 = 4;
pub const FRE_V1_PLAN_FORWARD_ANCHORED: u32 = 5;
pub const FRE_V1_PLAN_K0: u32 = 6;
pub const FRE_V1_PLAN_UNICODE_WORD_RUN: u32 = 7;
pub const FRE_V1_PLAN_UNICODE_FOLDED_LITERAL: u32 = 8;
pub const FRE_V1_PLAN_LITERAL_CLASS_RUN_LITERAL: u32 = 9;
pub const FRE_V1_PLAN_PURE_BYTE_CLASS_REPEAT: u32 = 10;
pub const FRE_V1_PLAN_FIXED_PREDICATE_WORD64: u32 = 11;
pub const FRE_V1_PLAN_BOUNDED_BYTE_CLASS_SEQUENCE: u32 = 12;
pub const FRE_V1_PLAN_REVERSE_INNER: u32 = 13;
pub const FRE_V1_PLAN_PREFIX_CLASS_ALTERNATION: u32 = 14;
pub const FRE_V1_PLAN_UNICODE_SCALAR_RUN: u32 = 15;
pub const FRE_V1_PLAN_LINE_DOMAIN_BYTE_ATOMS: u32 = 16;

/// Local syntax, configuration and non-resource diagnostics were checked.
///
/// This does not promise the pinned upstream compiled-size threshold.
pub const FRE_V1_ADMISSION_STRICT_CHECKED: u32 = 1;

pub const FRE_V1_DIAGNOSTIC_CAPACITY: usize = 256;

/// Common caller-initialized prefix of every public record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct FreV1Header {
    pub abi_version: u32,
    pub struct_size: u32,
}

impl FreV1Header {
    #[must_use]
    pub fn for_type<T>() -> Self {
        Self {
            abi_version: FRE_V1_ABI_VERSION,
            struct_size: u32::try_from(core::mem::size_of::<T>()).expect("ABI record fits u32"),
        }
    }
}

/// Runtime descriptor for dynamic-loader/header compatibility checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct FreV1AbiDescriptor {
    pub abi_version: u32,
    pub struct_size: u32,
    pub abi_major: u32,
    pub abi_minor: u32,
    pub feature_bits: u64,
    pub pointer_width: u32,
    pub endian: u32,
    pub config_size: u32,
    pub diagnostic_size: u32,
    pub plan_info_size: u32,
    pub exists_result_size: u32,
    pub selected_end_result_size: u32,
    pub match_result_size: u32,
    pub status_max: u32,
    pub reserved: u32,
}

impl FreV1AbiDescriptor {
    #[must_use]
    pub fn caller_init() -> Self {
        Self {
            abi_version: FRE_V1_ABI_VERSION,
            struct_size: size_u32::<Self>(),
            abi_major: 0,
            abi_minor: 0,
            feature_bits: 0,
            pointer_width: 0,
            endian: 0,
            config_size: 0,
            diagnostic_size: 0,
            plan_info_size: 0,
            exists_result_size: 0,
            selected_end_result_size: 0,
            match_result_size: 0,
            status_max: 0,
            reserved: 0,
        }
    }

    #[must_use]
    pub fn current() -> Self {
        Self {
            abi_version: FRE_V1_ABI_VERSION,
            struct_size: size_u32::<Self>(),
            abi_major: 1,
            abi_minor: 0,
            feature_bits: FRE_V1_FEATURES,
            pointer_width: usize::BITS,
            endian: if cfg!(target_endian = "little") {
                FRE_V1_ENDIAN_LITTLE
            } else {
                FRE_V1_ENDIAN_BIG
            },
            config_size: size_u32::<FreV1Config>(),
            diagnostic_size: size_u32::<FreV1Diagnostic>(),
            plan_info_size: size_u32::<FreV1PlanInfo>(),
            exists_result_size: size_u32::<FreV1ExistsResult>(),
            selected_end_result_size: size_u32::<FreV1SelectedEndResult>(),
            match_result_size: size_u32::<FreV1MatchResult>(),
            status_max: FRE_V1_STATUS_MAX,
            reserved: 0,
        }
    }
}

/// Checked configuration implemented by v1.
///
/// Compile limits remain the current fixed `PortableRegex` defaults. These fields
/// expose only knobs that map exactly to an implemented contract today.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct FreV1Config {
    pub abi_version: u32,
    pub struct_size: u32,
    pub profile: u32,
    pub unicode: u32,
    pub jit_policy: u32,
    pub reserved: u32,
    pub search_work: u64,
    pub search_scratch_bytes: u64,
}

impl FreV1Config {
    #[must_use]
    pub fn caller_init() -> Self {
        Self {
            abi_version: FRE_V1_ABI_VERSION,
            struct_size: size_u32::<Self>(),
            profile: 0,
            unicode: 0,
            jit_policy: 0,
            reserved: 0,
            search_work: 0,
            search_scratch_bytes: 0,
        }
    }

    #[must_use]
    pub fn checked_default() -> Self {
        let limits = fre::SearchLimits::default();
        Self {
            abi_version: FRE_V1_ABI_VERSION,
            struct_size: size_u32::<Self>(),
            profile: FRE_V1_PROFILE_RUST_BYTES,
            unicode: 1,
            jit_policy: FRE_V1_JIT_DENY,
            reserved: 0,
            search_work: limits.max_work,
            search_scratch_bytes: u64::try_from(limits.max_scratch_bytes)
                .expect("default search scratch fits u64"),
        }
    }
}

/// Caller-owned fixed diagnostic record.
#[derive(Clone, Copy, Eq, PartialEq)]
#[repr(C)]
pub struct FreV1Diagnostic {
    pub abi_version: u32,
    pub struct_size: u32,
    pub category: u32,
    pub message_length: u32,
    pub message_truncated: u32,
    pub reserved: u32,
    pub message: [u8; FRE_V1_DIAGNOSTIC_CAPACITY],
}

impl FreV1Diagnostic {
    #[must_use]
    pub fn caller_init() -> Self {
        Self {
            abi_version: FRE_V1_ABI_VERSION,
            struct_size: size_u32::<Self>(),
            category: FRE_V1_DIAGNOSTIC_NONE,
            message_length: 0,
            message_truncated: 0,
            reserved: 0,
            message: [0; FRE_V1_DIAGNOSTIC_CAPACITY],
        }
    }

    #[must_use]
    pub fn message_bytes(&self) -> &[u8] {
        let length = usize::try_from(self.message_length)
            .unwrap_or(0)
            .min(self.message.len());
        &self.message[..length]
    }
}

impl fmt::Debug for FreV1Diagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FreV1Diagnostic")
            .field("abi_version", &self.abi_version)
            .field("struct_size", &self.struct_size)
            .field("category", &self.category)
            .field("message_length", &self.message_length)
            .field("message", &String::from_utf8_lossy(self.message_bytes()))
            .field("message_truncated", &self.message_truncated)
            .field("reserved", &self.reserved)
            .finish()
    }
}

/// Caller-owned stable construction-plan explanation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct FreV1PlanInfo {
    pub abi_version: u32,
    pub struct_size: u32,
    pub plan: u32,
    pub admission: u32,
    pub planner_work: u64,
    pub states: u64,
    pub edges: u64,
    pub plan_storage_bytes: u64,
    pub minimum_match_present: u32,
    pub reserved: u32,
    pub minimum_match_bytes: u64,
}

impl FreV1PlanInfo {
    #[must_use]
    pub fn caller_init() -> Self {
        Self {
            abi_version: FRE_V1_ABI_VERSION,
            struct_size: size_u32::<Self>(),
            plan: 0,
            admission: 0,
            planner_work: 0,
            states: 0,
            edges: 0,
            plan_storage_bytes: 0,
            minimum_match_present: 0,
            reserved: 0,
            minimum_match_bytes: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct FreV1ExistsResult {
    pub abi_version: u32,
    pub struct_size: u32,
    pub matched: u32,
    pub reserved: u32,
}

impl FreV1ExistsResult {
    #[must_use]
    pub fn caller_init() -> Self {
        Self {
            abi_version: FRE_V1_ABI_VERSION,
            struct_size: size_u32::<Self>(),
            matched: 0,
            reserved: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct FreV1SelectedEndResult {
    pub abi_version: u32,
    pub struct_size: u32,
    pub found: u32,
    pub reserved: u32,
    pub end: usize,
}

impl FreV1SelectedEndResult {
    #[must_use]
    pub fn caller_init() -> Self {
        Self {
            abi_version: FRE_V1_ABI_VERSION,
            struct_size: size_u32::<Self>(),
            found: 0,
            reserved: 0,
            end: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct FreV1MatchResult {
    pub abi_version: u32,
    pub struct_size: u32,
    pub found: u32,
    pub reserved: u32,
    pub start: usize,
    pub end: usize,
}

impl FreV1MatchResult {
    #[must_use]
    pub fn caller_init() -> Self {
        Self {
            abi_version: FRE_V1_ABI_VERSION,
            struct_size: size_u32::<Self>(),
            found: 0,
            reserved: 0,
            start: 0,
            end: 0,
        }
    }
}

/// Incomplete in C; values are created only by `fre_v1_regex_compile`.
#[derive(Debug)]
#[repr(C)]
pub struct FreV1Regex {
    _private: [u8; 0],
}

fn size_u32<T>() -> u32 {
    u32::try_from(core::mem::size_of::<T>()).expect("ABI record fits u32")
}
