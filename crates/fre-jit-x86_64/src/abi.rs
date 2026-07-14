//! Public ABI and CPU-feature stamps.

/// Machine architecture encoded in every native and AOT image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Architecture {
    /// AMD64/x86-64 in little-endian 64-bit mode.
    X86_64 = 1,
}

/// Calling convention encoded in every native and AOT image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CallingConvention {
    /// FRE's C-compatible leaf entry contract on System V AMD64.
    SystemVAMD64V1 = 1,
    /// Reserved identity. Emission is intentionally unsupported today.
    WindowsX64V1 = 2,
}

/// Complete target identity. No host-target inference occurs in this crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TargetStamp {
    pub architecture: Architecture,
    pub calling_convention: CallingConvention,
    pub pointer_width: u8,
    pub little_endian: bool,
}

impl TargetStamp {
    /// The only target accepted by this backend version.
    #[must_use]
    pub const fn system_v_amd64_v1() -> Self {
        Self {
            architecture: Architecture::X86_64,
            calling_convention: CallingConvention::SystemVAMD64V1,
            pointer_width: 64,
            little_endian: true,
        }
    }

    /// Typed future Windows target. Passing it to the emitter is an error.
    #[must_use]
    pub const fn windows_x64_v1() -> Self {
        Self {
            architecture: Architecture::X86_64,
            calling_convention: CallingConvention::WindowsX64V1,
            pointer_width: 64,
            little_endian: true,
        }
    }
}

/// Maximum x86 feature tier selected at compile time.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum FeatureTier {
    /// Baseline x86-64 integer instructions only.
    Scalar = 0,
    /// SSE2 vector confirmation (architecturally present on x86-64).
    Sse2 = 1,
    /// AVX2 vector confirmation, requiring publisher-side feature checks.
    Avx2 = 2,
}

impl FeatureTier {
    #[must_use]
    pub(crate) const fn vector_width(self) -> usize {
        match self {
            Self::Scalar => 1,
            Self::Sse2 => 16,
            Self::Avx2 => 32,
        }
    }
}

/// C-layout result storage required by the v1 entry contract.
///
/// The generated leaf has the conceptual signature
/// `u32 entry(*const u8, usize, usize, usize, *mut NativeMatchV1)`. The five
/// arguments are haystack pointer, haystack length, window start, window end
/// and a non-null writable result pointer. The publisher must validate the
/// pointer contract before entering native code.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct NativeMatchV1 {
    pub start: usize,
    pub end: usize,
}

/// Value returned in EAX by a v1 entry point.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum NativeStatus {
    NoMatch = 0,
    Match = 1,
    InvalidWindow = 2,
}
