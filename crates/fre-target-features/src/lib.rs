//! CPU capability facts and reusable kernel-variant selection.
//!
//! FRE builds portable binaries by default and selects an already-qualified
//! kernel implementation once, outside its hot loop. Target-specific
//! deployments can instead enable `static-dispatch`; in that profile,
//! the compiler's `cfg(target_feature)` facts become the immutable snapshot and
//! no runtime feature detector is entered by [`host`].
//!
//! Hardware/OS facts are kept separate from performance policy: seeing
//! AVX-512, SVE2 or SME2 does not imply that every operation should use it.
//! Each operation publishes an ordered table of variants with exact feature
//! requirements and thresholds. The process-wide snapshot is immutable. Test
//! and benchmark policies can remove features or require a feature to be
//! present, but can never add a feature that the snapshot did not report as
//! usable. Compiler-specialized kernel handles may use those policies only as
//! construction-time assertions and report their normalized profile receipt.

#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

use core::fmt;
#[cfg(not(feature = "static-dispatch"))]
use std::sync::OnceLock;

/// Version of the feature vocabulary and variant-selection contract.
pub const DISPATCH_POLICY_VERSION: u16 = 2;

#[cfg(all(
    not(feature = "static-dispatch"),
    feature = "static-dispatch-arm-41-d84"
))]
compile_error!("static-dispatch-arm-41-d84 requires static-dispatch");

#[cfg(all(
    feature = "static-dispatch-arm-41-d84",
    not(all(target_arch = "aarch64", target_os = "linux", target_endian = "little"))
))]
compile_error!("static-dispatch-arm-41-d84 requires little-endian Linux AArch64");

#[cfg(all(
    feature = "static-dispatch-arm-41-d84",
    not(all(
        target_feature = "neon",
        target_feature = "sve",
        target_feature = "sve2"
    ))
))]
compile_error!("static-dispatch-arm-41-d84 requires compiler-enabled neon, sve, and sve2");

/// Source of the process-wide SIMD capability snapshot.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum DispatchProfile {
    /// Portable binary using OS-aware runtime feature detection.
    RuntimeDetected,
    /// Target-specific binary using compiler-enabled target features.
    CompileTimeTarget,
    /// Target-specific Arm `0x41`/`0xd84` binary with declared tuning.
    CompileTimeArm41D84,
}

impl DispatchProfile {
    /// Stable profile name for build and benchmark identity.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::RuntimeDetected => "runtime-detected",
            Self::CompileTimeTarget => "compile-time-target",
            Self::CompileTimeArm41D84 => "compile-time-arm-41-d84",
        }
    }
}

/// Return the dispatch profile compiled into this crate.
#[must_use]
pub const fn dispatch_profile() -> DispatchProfile {
    if cfg!(feature = "static-dispatch-arm-41-d84") {
        DispatchProfile::CompileTimeArm41D84
    } else if cfg!(feature = "static-dispatch") {
        DispatchProfile::CompileTimeTarget
    } else {
        DispatchProfile::RuntimeDetected
    }
}

/// CPU architecture relevant to native kernel selection.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum Architecture {
    Aarch64,
    X86_64,
    Other,
}

impl Architecture {
    #[must_use]
    pub const fn host() -> Self {
        if cfg!(target_arch = "aarch64") {
            Self::Aarch64
        } else if cfg!(target_arch = "x86_64") {
            Self::X86_64
        } else {
            Self::Other
        }
    }
}

/// A CPU instruction-set extension that can affect FRE kernels.
///
/// These are independent facts rather than a linear "highest tier." For
/// example, an x86 nibble-table kernel can require SSSE3 plus POPCNT, while a
/// different AVX2 kernel need not require BMI2.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum Feature {
    ArmNeon = 0,
    ArmAes = 1,
    ArmPmull = 2,
    ArmSha2 = 3,
    ArmSha3 = 4,
    ArmCrc = 5,
    ArmFp16 = 6,
    ArmFhm = 7,
    ArmRdm = 8,
    ArmDotprod = 9,
    ArmFcma = 10,
    ArmBf16 = 11,
    ArmI8mm = 12,
    ArmSve = 13,
    ArmSve2 = 14,
    ArmSve2Aes = 15,
    ArmSve2Bitperm = 16,
    ArmSve2Sha3 = 17,
    ArmSve2Sm4 = 18,
    ArmSme = 19,
    ArmSme2 = 20,
    ArmSme2p1 = 21,
    ArmSm4 = 22,
    ArmF32mm = 23,
    ArmF64mm = 24,
    ArmSve2p1 = 25,
    ArmSveB16b16 = 26,
    ArmSmeB16b16 = 27,
    ArmSmeF16f16 = 28,
    ArmSmeF64f64 = 29,
    ArmSmeI16i64 = 30,
    ArmSmeFa64 = 31,
    ArmCssc = 32,
    ArmFaminmax = 33,
    ArmLut = 34,
    ArmMops = 35,
    X86Sse2 = 64,
    X86Sse3 = 65,
    X86Ssse3 = 66,
    X86Sse41 = 67,
    X86Sse42 = 68,
    X86Popcnt = 69,
    X86Pclmulqdq = 70,
    X86Aes = 71,
    X86Avx = 72,
    X86Avx2 = 73,
    X86Fma = 74,
    X86Bmi1 = 75,
    X86Bmi2 = 76,
    X86Lzcnt = 77,
    X86Avx512F = 78,
    X86Avx512Bw = 79,
    X86Avx512Vl = 80,
    X86Avx512Dq = 81,
    X86Avx512Cd = 82,
    X86Avx512Vbmi = 83,
    X86Avx512Vbmi2 = 84,
    X86Avx512Vnni = 85,
    X86Avx512Bitalg = 86,
    X86Avx512Vpopcntdq = 87,
    X86Gfni = 88,
    X86Vaes = 89,
    X86Vpclmulqdq = 90,
    X86AvxVnni = 91,
}

impl Feature {
    const ALL: [Self; 64] = [
        Self::ArmNeon,
        Self::ArmAes,
        Self::ArmPmull,
        Self::ArmSha2,
        Self::ArmSha3,
        Self::ArmCrc,
        Self::ArmFp16,
        Self::ArmFhm,
        Self::ArmRdm,
        Self::ArmDotprod,
        Self::ArmFcma,
        Self::ArmBf16,
        Self::ArmI8mm,
        Self::ArmSve,
        Self::ArmSve2,
        Self::ArmSve2Aes,
        Self::ArmSve2Bitperm,
        Self::ArmSve2Sha3,
        Self::ArmSve2Sm4,
        Self::ArmSme,
        Self::ArmSme2,
        Self::ArmSme2p1,
        Self::ArmSm4,
        Self::ArmF32mm,
        Self::ArmF64mm,
        Self::ArmSve2p1,
        Self::ArmSveB16b16,
        Self::ArmSmeB16b16,
        Self::ArmSmeF16f16,
        Self::ArmSmeF64f64,
        Self::ArmSmeI16i64,
        Self::ArmSmeFa64,
        Self::ArmCssc,
        Self::ArmFaminmax,
        Self::ArmLut,
        Self::ArmMops,
        Self::X86Sse2,
        Self::X86Sse3,
        Self::X86Ssse3,
        Self::X86Sse41,
        Self::X86Sse42,
        Self::X86Popcnt,
        Self::X86Pclmulqdq,
        Self::X86Aes,
        Self::X86Avx,
        Self::X86Avx2,
        Self::X86Fma,
        Self::X86Bmi1,
        Self::X86Bmi2,
        Self::X86Lzcnt,
        Self::X86Avx512F,
        Self::X86Avx512Bw,
        Self::X86Avx512Vl,
        Self::X86Avx512Dq,
        Self::X86Avx512Cd,
        Self::X86Avx512Vbmi,
        Self::X86Avx512Vbmi2,
        Self::X86Avx512Vnni,
        Self::X86Avx512Bitalg,
        Self::X86Avx512Vpopcntdq,
        Self::X86Gfni,
        Self::X86Vaes,
        Self::X86Vpclmulqdq,
        Self::X86AvxVnni,
    ];

    #[allow(
        clippy::as_conversions,
        reason = "the repr(u8) discriminant is an audited bit number below 128"
    )]
    const fn mask(self) -> u128 {
        1_u128 << (self as u8)
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ArmNeon => "arm.neon",
            Self::ArmAes => "arm.aes",
            Self::ArmPmull => "arm.pmull",
            Self::ArmSha2 => "arm.sha2",
            Self::ArmSha3 => "arm.sha3",
            Self::ArmCrc => "arm.crc",
            Self::ArmFp16 => "arm.fp16",
            Self::ArmFhm => "arm.fhm",
            Self::ArmRdm => "arm.rdm",
            Self::ArmDotprod => "arm.dotprod",
            Self::ArmFcma => "arm.fcma",
            Self::ArmBf16 => "arm.bf16",
            Self::ArmI8mm => "arm.i8mm",
            Self::ArmSve => "arm.sve",
            Self::ArmSve2 => "arm.sve2",
            Self::ArmSve2Aes => "arm.sve2-aes",
            Self::ArmSve2Bitperm => "arm.sve2-bitperm",
            Self::ArmSve2Sha3 => "arm.sve2-sha3",
            Self::ArmSve2Sm4 => "arm.sve2-sm4",
            Self::ArmSme => "arm.sme",
            Self::ArmSme2 => "arm.sme2",
            Self::ArmSme2p1 => "arm.sme2p1",
            Self::ArmSm4 => "arm.sm4",
            Self::ArmF32mm => "arm.f32mm",
            Self::ArmF64mm => "arm.f64mm",
            Self::ArmSve2p1 => "arm.sve2p1",
            Self::ArmSveB16b16 => "arm.sve-b16b16",
            Self::ArmSmeB16b16 => "arm.sme-b16b16",
            Self::ArmSmeF16f16 => "arm.sme-f16f16",
            Self::ArmSmeF64f64 => "arm.sme-f64f64",
            Self::ArmSmeI16i64 => "arm.sme-i16i64",
            Self::ArmSmeFa64 => "arm.sme-fa64",
            Self::ArmCssc => "arm.cssc",
            Self::ArmFaminmax => "arm.faminmax",
            Self::ArmLut => "arm.lut",
            Self::ArmMops => "arm.mops",
            Self::X86Sse2 => "x86.sse2",
            Self::X86Sse3 => "x86.sse3",
            Self::X86Ssse3 => "x86.ssse3",
            Self::X86Sse41 => "x86.sse4.1",
            Self::X86Sse42 => "x86.sse4.2",
            Self::X86Popcnt => "x86.popcnt",
            Self::X86Pclmulqdq => "x86.pclmulqdq",
            Self::X86Aes => "x86.aes",
            Self::X86Avx => "x86.avx",
            Self::X86Avx2 => "x86.avx2",
            Self::X86Fma => "x86.fma",
            Self::X86Bmi1 => "x86.bmi1",
            Self::X86Bmi2 => "x86.bmi2",
            Self::X86Lzcnt => "x86.lzcnt",
            Self::X86Avx512F => "x86.avx512f",
            Self::X86Avx512Bw => "x86.avx512bw",
            Self::X86Avx512Vl => "x86.avx512vl",
            Self::X86Avx512Dq => "x86.avx512dq",
            Self::X86Avx512Cd => "x86.avx512cd",
            Self::X86Avx512Vbmi => "x86.avx512vbmi",
            Self::X86Avx512Vbmi2 => "x86.avx512vbmi2",
            Self::X86Avx512Vnni => "x86.avx512vnni",
            Self::X86Avx512Bitalg => "x86.avx512bitalg",
            Self::X86Avx512Vpopcntdq => "x86.avx512vpopcntdq",
            Self::X86Gfni => "x86.gfni",
            Self::X86Vaes => "x86.vaes",
            Self::X86Vpclmulqdq => "x86.vpclmulqdq",
            Self::X86AvxVnni => "x86.avxvnni",
        }
    }
}

/// Compact, non-linear set of CPU features.
#[derive(Clone, Copy, Default, Eq, Hash, PartialEq)]
pub struct FeatureSet(u128);

impl FeatureSet {
    pub const EMPTY: Self = Self(0);

    #[must_use]
    pub const fn of(feature: Feature) -> Self {
        Self(feature.mask())
    }

    #[must_use]
    pub const fn with(self, feature: Feature) -> Self {
        Self(self.0 | feature.mask())
    }

    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    #[must_use]
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    #[must_use]
    pub const fn without(self, denied: Self) -> Self {
        Self(self.0 & !denied.0)
    }

    #[must_use]
    pub const fn contains(self, feature: Feature) -> bool {
        self.0 & feature.mask() != 0
    }

    #[must_use]
    pub const fn contains_all(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    #[must_use]
    pub const fn bits(self) -> u128 {
        self.0
    }

    pub fn iter(self) -> impl Iterator<Item = Feature> {
        Feature::ALL
            .into_iter()
            .filter(move |feature| self.contains(*feature))
    }
}

impl fmt::Debug for FeatureSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_list()
            .entries(self.iter().map(Feature::name))
            .finish()
    }
}

/// Coarse tuning identity, deliberately separate from ISA safety.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum TuningClass {
    Generic,
    AppleSilicon {
        cpu_family: Option<u32>,
    },
    ArmServer {
        cpu: Option<ArmCpuIdentity>,
    },
    X86 {
        vendor: X86Vendor,
        family: u16,
        model: u16,
    },
}

/// Homogeneous Linux `AArch64` CPU identity from `/proc/cpuinfo`.
///
/// The numeric implementer and part values are architecture identities, not
/// instruction-safety evidence. Variant tables may use them for thresholds or
/// scheduling preferences only.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ArmCpuIdentity {
    pub implementer: u16,
    pub part: u16,
    pub variant: Option<u8>,
    pub revision: Option<u8>,
}

/// Vendor identity obtained from the architecture-defined x86 CPUID leaf.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum X86Vendor {
    Amd,
    Intel,
    Other([u8; 12]),
    Unknown,
}

/// Evidence sources contributing to a capability snapshot.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Evidence(u8);

impl Evidence {
    pub const NONE: Self = Self(0);
    pub const STD_ARCH: Self = Self(1);
    pub const APPLE_SYSCTL: Self = Self(2);
    pub const X86_CPUID: Self = Self(4);
    pub const LINUX_CPUINFO: Self = Self(8);
    pub const COMPILE_TIME: Self = Self(16);
    pub const DECLARED_TUNING: Self = Self(32);

    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// Immutable hardware and OS-usable capability facts for one host.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CpuCapabilities {
    architecture: Architecture,
    reported: FeatureSet,
    usable: FeatureSet,
    tuning: TuningClass,
    evidence: Evidence,
}

impl CpuCapabilities {
    #[must_use]
    pub const fn architecture(self) -> Architecture {
        self.architecture
    }

    /// Features reported by the hardware/OS capability interface.
    #[must_use]
    pub const fn reported(self) -> FeatureSet {
        self.reported
    }

    /// Features safe for ordinary userspace code under the current OS state.
    ///
    /// This deliberately excludes SME today. Operating systems can report SME
    /// hardware, but FRE has not yet qualified the streaming-mode ABI/state
    /// boundary.
    #[must_use]
    pub const fn usable(self) -> FeatureSet {
        self.usable
    }

    #[must_use]
    pub const fn tuning(self) -> TuningClass {
        self.tuning
    }

    #[must_use]
    pub const fn evidence(self) -> Evidence {
        self.evidence
    }

    /// Return a capability view that can only disable real host features.
    #[must_use]
    pub const fn masked(self, allowed: FeatureSet) -> Self {
        Self {
            usable: self.usable.intersection(allowed),
            ..self
        }
    }

    #[cfg(test)]
    const fn synthetic(architecture: Architecture, usable: FeatureSet) -> Self {
        Self::synthetic_with_tuning(architecture, usable, TuningClass::Generic)
    }

    #[cfg(test)]
    const fn synthetic_with_tuning(
        architecture: Architecture,
        usable: FeatureSet,
        tuning: TuningClass,
    ) -> Self {
        Self {
            architecture,
            reported: usable,
            usable,
            tuning,
            evidence: Evidence::NONE,
        }
    }
}

#[cfg(not(feature = "static-dispatch"))]
static HOST_CAPABILITIES: OnceLock<CpuCapabilities> = OnceLock::new();

#[cfg(feature = "static-dispatch")]
static HOST_CAPABILITIES: CpuCapabilities = compile_time_capabilities();

/// Return the immutable process-wide CPU capability snapshot.
///
/// Portable builds initialize this once using OS-aware runtime detection.
/// Builds made with `static-dispatch` return a constant snapshot
/// derived from compiler-enabled target features.
#[must_use]
#[cfg(not(feature = "static-dispatch"))]
pub fn host() -> &'static CpuCapabilities {
    HOST_CAPABILITIES.get_or_init(detect_host)
}

/// Return the compiler-specialized CPU capability snapshot.
#[must_use]
#[cfg(feature = "static-dispatch")]
pub const fn host() -> &'static CpuCapabilities {
    &HOST_CAPABILITIES
}

#[cfg(feature = "static-dispatch")]
const fn compile_time_capabilities() -> CpuCapabilities {
    let features = compile_time_features();
    let evidence = if cfg!(feature = "static-dispatch-arm-41-d84") {
        Evidence::COMPILE_TIME.union(Evidence::DECLARED_TUNING)
    } else {
        Evidence::COMPILE_TIME
    };
    CpuCapabilities {
        architecture: Architecture::host(),
        reported: features,
        usable: features,
        tuning: compile_time_tuning(),
        evidence,
    }
}

#[cfg(feature = "static-dispatch")]
#[allow(
    clippy::too_many_lines,
    reason = "keeping each compiler cfg adjacent to its public feature prevents mapping drift"
)]
const fn compile_time_features() -> FeatureSet {
    let mut features = FeatureSet::EMPTY;
    if cfg!(all(target_arch = "aarch64", target_feature = "neon")) {
        features = features.with(Feature::ArmNeon);
    }
    if cfg!(all(target_arch = "aarch64", target_feature = "aes")) {
        features = features.with(Feature::ArmAes);
    }
    if cfg!(all(target_arch = "aarch64", target_feature = "sha2")) {
        features = features.with(Feature::ArmSha2);
    }
    if cfg!(all(target_arch = "aarch64", target_feature = "sha3")) {
        features = features.with(Feature::ArmSha3);
    }
    if cfg!(all(target_arch = "aarch64", target_feature = "crc")) {
        features = features.with(Feature::ArmCrc);
    }
    if cfg!(all(target_arch = "aarch64", target_feature = "fp16")) {
        features = features.with(Feature::ArmFp16);
    }
    if cfg!(all(target_arch = "aarch64", target_feature = "fhm")) {
        features = features.with(Feature::ArmFhm);
    }
    if cfg!(all(target_arch = "aarch64", target_feature = "rdm")) {
        features = features.with(Feature::ArmRdm);
    }
    if cfg!(all(target_arch = "aarch64", target_feature = "dotprod")) {
        features = features.with(Feature::ArmDotprod);
    }
    if cfg!(all(target_arch = "aarch64", target_feature = "fcma")) {
        features = features.with(Feature::ArmFcma);
    }
    if cfg!(all(target_arch = "aarch64", target_feature = "bf16")) {
        features = features.with(Feature::ArmBf16);
    }
    if cfg!(all(target_arch = "aarch64", target_feature = "i8mm")) {
        features = features.with(Feature::ArmI8mm);
    }
    if cfg!(all(target_arch = "aarch64", target_feature = "sve")) {
        features = features.with(Feature::ArmSve);
    }
    if cfg!(all(target_arch = "aarch64", target_feature = "sve2")) {
        features = features.with(Feature::ArmSve2);
    }
    if cfg!(all(target_arch = "aarch64", target_feature = "sve2-aes")) {
        features = features.with(Feature::ArmSve2Aes);
    }
    if cfg!(all(
        target_arch = "aarch64",
        target_feature = "sve2-bitperm"
    )) {
        features = features.with(Feature::ArmSve2Bitperm);
    }
    if cfg!(all(target_arch = "aarch64", target_feature = "sve2-sha3")) {
        features = features.with(Feature::ArmSve2Sha3);
    }
    if cfg!(all(target_arch = "aarch64", target_feature = "sve2-sm4")) {
        features = features.with(Feature::ArmSve2Sm4);
    }
    if cfg!(all(target_arch = "aarch64", target_feature = "sm4")) {
        features = features.with(Feature::ArmSm4);
    }
    if cfg!(all(target_arch = "aarch64", target_feature = "f32mm")) {
        features = features.with(Feature::ArmF32mm);
    }
    if cfg!(all(target_arch = "aarch64", target_feature = "f64mm")) {
        features = features.with(Feature::ArmF64mm);
    }
    if cfg!(all(target_arch = "x86_64", target_feature = "sse2")) {
        features = features.with(Feature::X86Sse2);
    }
    if cfg!(all(target_arch = "x86_64", target_feature = "sse3")) {
        features = features.with(Feature::X86Sse3);
    }
    if cfg!(all(target_arch = "x86_64", target_feature = "ssse3")) {
        features = features.with(Feature::X86Ssse3);
    }
    if cfg!(all(target_arch = "x86_64", target_feature = "sse4.1")) {
        features = features.with(Feature::X86Sse41);
    }
    if cfg!(all(target_arch = "x86_64", target_feature = "sse4.2")) {
        features = features.with(Feature::X86Sse42);
    }
    if cfg!(all(target_arch = "x86_64", target_feature = "popcnt")) {
        features = features.with(Feature::X86Popcnt);
    }
    if cfg!(all(target_arch = "x86_64", target_feature = "pclmulqdq")) {
        features = features.with(Feature::X86Pclmulqdq);
    }
    if cfg!(all(target_arch = "x86_64", target_feature = "aes")) {
        features = features.with(Feature::X86Aes);
    }
    if cfg!(all(target_arch = "x86_64", target_feature = "avx")) {
        features = features.with(Feature::X86Avx);
    }
    if cfg!(all(target_arch = "x86_64", target_feature = "avx2")) {
        features = features.with(Feature::X86Avx2);
    }
    if cfg!(all(target_arch = "x86_64", target_feature = "fma")) {
        features = features.with(Feature::X86Fma);
    }
    if cfg!(all(target_arch = "x86_64", target_feature = "bmi1")) {
        features = features.with(Feature::X86Bmi1);
    }
    if cfg!(all(target_arch = "x86_64", target_feature = "bmi2")) {
        features = features.with(Feature::X86Bmi2);
    }
    if cfg!(all(target_arch = "x86_64", target_feature = "lzcnt")) {
        features = features.with(Feature::X86Lzcnt);
    }
    if cfg!(all(target_arch = "x86_64", target_feature = "avx512f")) {
        features = features.with(Feature::X86Avx512F);
    }
    if cfg!(all(target_arch = "x86_64", target_feature = "avx512bw")) {
        features = features.with(Feature::X86Avx512Bw);
    }
    if cfg!(all(target_arch = "x86_64", target_feature = "avx512vl")) {
        features = features.with(Feature::X86Avx512Vl);
    }
    if cfg!(all(target_arch = "x86_64", target_feature = "avx512dq")) {
        features = features.with(Feature::X86Avx512Dq);
    }
    if cfg!(all(target_arch = "x86_64", target_feature = "avx512cd")) {
        features = features.with(Feature::X86Avx512Cd);
    }
    if cfg!(all(target_arch = "x86_64", target_feature = "avx512vbmi")) {
        features = features.with(Feature::X86Avx512Vbmi);
    }
    if cfg!(all(target_arch = "x86_64", target_feature = "avx512vbmi2")) {
        features = features.with(Feature::X86Avx512Vbmi2);
    }
    if cfg!(all(target_arch = "x86_64", target_feature = "avx512vnni")) {
        features = features.with(Feature::X86Avx512Vnni);
    }
    if cfg!(all(target_arch = "x86_64", target_feature = "avx512bitalg")) {
        features = features.with(Feature::X86Avx512Bitalg);
    }
    if cfg!(all(
        target_arch = "x86_64",
        target_feature = "avx512vpopcntdq"
    )) {
        features = features.with(Feature::X86Avx512Vpopcntdq);
    }
    if cfg!(all(target_arch = "x86_64", target_feature = "gfni")) {
        features = features.with(Feature::X86Gfni);
    }
    if cfg!(all(target_arch = "x86_64", target_feature = "vaes")) {
        features = features.with(Feature::X86Vaes);
    }
    if cfg!(all(target_arch = "x86_64", target_feature = "vpclmulqdq")) {
        features = features.with(Feature::X86Vpclmulqdq);
    }
    if cfg!(all(target_arch = "x86_64", target_feature = "avxvnni")) {
        features = features.with(Feature::X86AvxVnni);
    }
    features
}

#[cfg(feature = "static-dispatch")]
const fn compile_time_tuning() -> TuningClass {
    if cfg!(feature = "static-dispatch-arm-41-d84") {
        TuningClass::ArmServer {
            cpu: Some(ArmCpuIdentity {
                implementer: 0x41,
                part: 0x0d84,
                variant: None,
                revision: None,
            }),
        }
    } else if cfg!(all(target_arch = "aarch64", target_os = "macos")) {
        TuningClass::AppleSilicon { cpu_family: None }
    } else if cfg!(target_arch = "aarch64") {
        TuningClass::ArmServer { cpu: None }
    } else if cfg!(target_arch = "x86_64") {
        TuningClass::X86 {
            vendor: X86Vendor::Unknown,
            family: 0,
            model: 0,
        }
    } else {
        TuningClass::Generic
    }
}

#[cfg(not(feature = "static-dispatch"))]
fn detect_host() -> CpuCapabilities {
    match Architecture::host() {
        Architecture::Aarch64 => detect_aarch64(),
        Architecture::X86_64 => detect_x86_64(),
        Architecture::Other => CpuCapabilities {
            architecture: Architecture::Other,
            reported: FeatureSet::EMPTY,
            usable: FeatureSet::EMPTY,
            tuning: TuningClass::Generic,
            evidence: Evidence::NONE,
        },
    }
}

#[cfg(all(not(feature = "static-dispatch"), target_arch = "aarch64"))]
fn detect_aarch64() -> CpuCapabilities {
    let reported = detect_aarch64_std();
    let mut evidence = Evidence::STD_ARCH;
    #[cfg(all(not(target_os = "macos"), target_os = "linux"))]
    let tuning = {
        let cpu = linux_aarch64::detect_cpu_identity();
        if cpu.is_some() {
            evidence = evidence.union(Evidence::LINUX_CPUINFO);
        }
        TuningClass::ArmServer { cpu }
    };
    #[cfg(all(not(target_os = "macos"), not(target_os = "linux")))]
    let tuning = TuningClass::ArmServer { cpu: None };

    #[cfg(target_os = "macos")]
    let (tuning, reported) = {
        let apple = macos::detect_aarch64();
        evidence = evidence.union(Evidence::APPLE_SYSCTL);
        (
            TuningClass::AppleSilicon {
                cpu_family: apple.cpu_family,
            },
            reported.union(apple.features),
        )
    };

    let mut unqualified_stateful = FeatureSet::EMPTY
        .with(Feature::ArmSme)
        .with(Feature::ArmSme2)
        .with(Feature::ArmSme2p1)
        .with(Feature::ArmSmeB16b16)
        .with(Feature::ArmSmeF16f16)
        .with(Feature::ArmSmeF64f64)
        .with(Feature::ArmSmeI16i64)
        .with(Feature::ArmSmeFa64);
    if !reported.contains(Feature::ArmSve) {
        // FEAT_SVE_B16B16 can describe SME Z-targeting instructions even on a
        // machine without ordinary SVE. Until SME state/ABI is qualified, it
        // is only independently usable when ordinary SVE is also reported.
        unqualified_stateful = unqualified_stateful.with(Feature::ArmSveB16b16);
    }
    CpuCapabilities {
        architecture: Architecture::Aarch64,
        reported,
        usable: reported.without(unqualified_stateful),
        tuning,
        evidence,
    }
}

#[cfg(all(not(feature = "static-dispatch"), not(target_arch = "aarch64")))]
fn detect_aarch64() -> CpuCapabilities {
    unreachable!("architecture dispatch only calls the matching detector")
}

#[cfg(all(not(feature = "static-dispatch"), target_arch = "aarch64"))]
#[allow(
    clippy::too_many_lines,
    reason = "keeping each stable std feature spelling adjacent to its FRE feature prevents mapping drift"
)]
fn detect_aarch64_std() -> FeatureSet {
    let mut features = FeatureSet::EMPTY;
    if std::arch::is_aarch64_feature_detected!("neon") {
        features = features.with(Feature::ArmNeon);
    }
    if std::arch::is_aarch64_feature_detected!("aes") {
        features = features.with(Feature::ArmAes);
    }
    if std::arch::is_aarch64_feature_detected!("pmull") {
        features = features.with(Feature::ArmPmull);
    }
    if std::arch::is_aarch64_feature_detected!("sha2") {
        features = features.with(Feature::ArmSha2);
    }
    if std::arch::is_aarch64_feature_detected!("sha3") {
        features = features.with(Feature::ArmSha3);
    }
    if std::arch::is_aarch64_feature_detected!("sm4") {
        features = features.with(Feature::ArmSm4);
    }
    if std::arch::is_aarch64_feature_detected!("crc") {
        features = features.with(Feature::ArmCrc);
    }
    if std::arch::is_aarch64_feature_detected!("fp16") {
        features = features.with(Feature::ArmFp16);
    }
    if std::arch::is_aarch64_feature_detected!("fhm") {
        features = features.with(Feature::ArmFhm);
    }
    if std::arch::is_aarch64_feature_detected!("rdm") {
        features = features.with(Feature::ArmRdm);
    }
    if std::arch::is_aarch64_feature_detected!("dotprod") {
        features = features.with(Feature::ArmDotprod);
    }
    if std::arch::is_aarch64_feature_detected!("fcma") {
        features = features.with(Feature::ArmFcma);
    }
    if std::arch::is_aarch64_feature_detected!("bf16") {
        features = features.with(Feature::ArmBf16);
    }
    if std::arch::is_aarch64_feature_detected!("i8mm") {
        features = features.with(Feature::ArmI8mm);
    }
    if std::arch::is_aarch64_feature_detected!("f32mm") {
        features = features.with(Feature::ArmF32mm);
    }
    if std::arch::is_aarch64_feature_detected!("f64mm") {
        features = features.with(Feature::ArmF64mm);
    }
    if std::arch::is_aarch64_feature_detected!("sve") {
        features = features.with(Feature::ArmSve);
    }
    if std::arch::is_aarch64_feature_detected!("sve2") {
        features = features.with(Feature::ArmSve2);
    }
    if std::arch::is_aarch64_feature_detected!("sve2-aes") {
        features = features.with(Feature::ArmSve2Aes);
    }
    if std::arch::is_aarch64_feature_detected!("sve2-bitperm") {
        features = features.with(Feature::ArmSve2Bitperm);
    }
    if std::arch::is_aarch64_feature_detected!("sve2-sha3") {
        features = features.with(Feature::ArmSve2Sha3);
    }
    if std::arch::is_aarch64_feature_detected!("sve2-sm4") {
        features = features.with(Feature::ArmSve2Sm4);
    }
    // Rust 1.93 does not yet expose stable runtime probes for SVE2.1, SME or
    // newer Armv9 extensions. Apple fills those facts through sysctl below;
    // Linux leaves them unavailable until a reviewed auxv mapping is added.
    features
}

#[cfg(all(not(feature = "static-dispatch"), target_arch = "x86_64"))]
#[allow(
    clippy::too_many_lines,
    reason = "keeping each std feature spelling adjacent to its FRE feature prevents mapping drift"
)]
fn detect_x86_64() -> CpuCapabilities {
    let mut features = FeatureSet::EMPTY;
    if std::arch::is_x86_feature_detected!("sse2") {
        features = features.with(Feature::X86Sse2);
    }
    if std::arch::is_x86_feature_detected!("sse3") {
        features = features.with(Feature::X86Sse3);
    }
    if std::arch::is_x86_feature_detected!("ssse3") {
        features = features.with(Feature::X86Ssse3);
    }
    if std::arch::is_x86_feature_detected!("sse4.1") {
        features = features.with(Feature::X86Sse41);
    }
    if std::arch::is_x86_feature_detected!("sse4.2") {
        features = features.with(Feature::X86Sse42);
    }
    if std::arch::is_x86_feature_detected!("popcnt") {
        features = features.with(Feature::X86Popcnt);
    }
    if std::arch::is_x86_feature_detected!("pclmulqdq") {
        features = features.with(Feature::X86Pclmulqdq);
    }
    if std::arch::is_x86_feature_detected!("aes") {
        features = features.with(Feature::X86Aes);
    }
    if std::arch::is_x86_feature_detected!("avx") {
        features = features.with(Feature::X86Avx);
    }
    if std::arch::is_x86_feature_detected!("avx2") {
        features = features.with(Feature::X86Avx2);
    }
    if std::arch::is_x86_feature_detected!("fma") {
        features = features.with(Feature::X86Fma);
    }
    if std::arch::is_x86_feature_detected!("bmi1") {
        features = features.with(Feature::X86Bmi1);
    }
    if std::arch::is_x86_feature_detected!("bmi2") {
        features = features.with(Feature::X86Bmi2);
    }
    if std::arch::is_x86_feature_detected!("lzcnt") {
        features = features.with(Feature::X86Lzcnt);
    }
    if std::arch::is_x86_feature_detected!("avx512f") {
        features = features.with(Feature::X86Avx512F);
    }
    if std::arch::is_x86_feature_detected!("avx512bw") {
        features = features.with(Feature::X86Avx512Bw);
    }
    if std::arch::is_x86_feature_detected!("avx512vl") {
        features = features.with(Feature::X86Avx512Vl);
    }
    if std::arch::is_x86_feature_detected!("avx512dq") {
        features = features.with(Feature::X86Avx512Dq);
    }
    if std::arch::is_x86_feature_detected!("avx512cd") {
        features = features.with(Feature::X86Avx512Cd);
    }
    if std::arch::is_x86_feature_detected!("avx512vbmi") {
        features = features.with(Feature::X86Avx512Vbmi);
    }
    if std::arch::is_x86_feature_detected!("avx512vbmi2") {
        features = features.with(Feature::X86Avx512Vbmi2);
    }
    if std::arch::is_x86_feature_detected!("avx512vnni") {
        features = features.with(Feature::X86Avx512Vnni);
    }
    if std::arch::is_x86_feature_detected!("avx512bitalg") {
        features = features.with(Feature::X86Avx512Bitalg);
    }
    if std::arch::is_x86_feature_detected!("avx512vpopcntdq") {
        features = features.with(Feature::X86Avx512Vpopcntdq);
    }
    if std::arch::is_x86_feature_detected!("gfni") {
        features = features.with(Feature::X86Gfni);
    }
    if std::arch::is_x86_feature_detected!("vaes") {
        features = features.with(Feature::X86Vaes);
    }
    if std::arch::is_x86_feature_detected!("vpclmulqdq") {
        features = features.with(Feature::X86Vpclmulqdq);
    }
    if std::arch::is_x86_feature_detected!("avxvnni") {
        features = features.with(Feature::X86AvxVnni);
    }
    let tuning = x86_tuning();
    CpuCapabilities {
        architecture: Architecture::X86_64,
        reported: features,
        usable: features,
        tuning,
        evidence: Evidence::STD_ARCH.union(Evidence::X86_CPUID),
    }
}

#[cfg(all(not(feature = "static-dispatch"), not(target_arch = "x86_64")))]
fn detect_x86_64() -> CpuCapabilities {
    unreachable!("architecture dispatch only calls the matching detector")
}

#[cfg(all(not(feature = "static-dispatch"), target_arch = "x86_64"))]
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
}

/// Policy applied to real host facts before selecting a kernel.
///
/// Runtime-dispatch consumers may retain the resulting implementation.
/// Compiler-specialized consumers use the same policy to authenticate their
/// fixed implementation and reject a policy that would select another leaf.
/// They may discard the authenticating policy and expose a normalized
/// compiler-profile [`DispatchPolicy::Auto`] receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DispatchPolicy {
    /// Use all OS-usable host features.
    Auto,
    /// Force the architecture-neutral fallback.
    Portable,
    /// Permit only this subset of real host features.
    AllowOnly(FeatureSet),
    /// Reject selection unless all of these real host features are usable.
    Require(FeatureSet),
}

/// Failure to satisfy a non-forgeable dispatch policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnsupportedRequiredFeatures {
    pub required: FeatureSet,
    pub usable: FeatureSet,
}

impl fmt::Display for UnsupportedRequiredFeatures {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "required CPU features {:?} are not a subset of usable host features {:?}",
            self.required, self.usable
        )
    }
}

impl std::error::Error for UnsupportedRequiredFeatures {}

impl DispatchPolicy {
    fn apply(
        self,
        capabilities: CpuCapabilities,
    ) -> Result<FeatureSet, UnsupportedRequiredFeatures> {
        match self {
            Self::Auto => Ok(capabilities.usable),
            Self::Portable => Ok(FeatureSet::EMPTY),
            Self::AllowOnly(allowed) => Ok(capabilities.usable.intersection(allowed)),
            Self::Require(required) => {
                if capabilities.usable.contains_all(required) {
                    Ok(capabilities.usable)
                } else {
                    Err(UnsupportedRequiredFeatures {
                        required,
                        usable: capabilities.usable,
                    })
                }
            }
        }
    }
}

/// Architecture constraint for one kernel variant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchitectureRequirement {
    Any,
    Exact(Architecture),
}

impl ArchitectureRequirement {
    fn matches(self, actual: Architecture) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(required) => required == actual,
        }
    }
}

/// Vector shape used by one selected implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum VectorKind {
    Scalar,
    Fixed { bytes: u16 },
    Scalable,
}

/// One already-qualified implementation of an operation.
#[derive(Clone, Copy, Debug)]
pub struct KernelVariant<F: Copy> {
    stable_id: &'static str,
    architecture: ArchitectureRequirement,
    required: FeatureSet,
    tuning_matches: fn(TuningClass) -> bool,
    vector: VectorKind,
    minimum_input_bytes: usize,
    preference: u16,
    entry: F,
}

const fn any_tuning(_: TuningClass) -> bool {
    true
}

impl<F: Copy> KernelVariant<F> {
    #[must_use]
    pub const fn new(
        stable_id: &'static str,
        architecture: ArchitectureRequirement,
        required: FeatureSet,
        vector: VectorKind,
        minimum_input_bytes: usize,
        preference: u16,
        entry: F,
    ) -> Self {
        Self {
            stable_id,
            architecture,
            required,
            tuning_matches: any_tuning,
            vector,
            minimum_input_bytes,
            preference,
            entry,
        }
    }

    /// Restrict this performance choice to a microarchitecture predicate.
    ///
    /// The predicate is only a tuning filter. Exact ISA requirements remain in
    /// `required`, and selection checks those independently before returning
    /// the entry point.
    #[must_use]
    pub const fn when_tuning(mut self, tuning_matches: fn(TuningClass) -> bool) -> Self {
        self.tuning_matches = tuning_matches;
        self
    }
}

/// Stable evidence for a one-time variant decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelectionReceipt {
    pub policy_version: u16,
    pub variant_id: &'static str,
    /// Exact child variant used when `variant_id` names a composite
    /// implementation. `None` means the selected variant executes directly.
    pub delegate_variant_id: Option<&'static str>,
    /// Policy represented by this receipt. Compiler-specialized handles may
    /// normalize this to [`DispatchPolicy::Auto`] because custom policies are
    /// authenticated at construction and are not retained per handle.
    pub policy: DispatchPolicy,
    pub architecture: Architecture,
    pub host_tuning: TuningClass,
    pub host_evidence: Evidence,
    pub host_reported: FeatureSet,
    pub policy_usable: FeatureSet,
    pub required: FeatureSet,
    pub vector: VectorKind,
    pub selection_input_bytes: usize,
    pub minimum_input_bytes: usize,
}

/// Selected direct entry point and its auditable receipt.
#[derive(Clone, Copy, Debug)]
pub struct SelectedKernel<F: Copy> {
    entry: F,
    receipt: SelectionReceipt,
}

impl<F: Copy> SelectedKernel<F> {
    #[must_use]
    pub const fn entry(self) -> F {
        self.entry
    }

    #[must_use]
    pub const fn receipt(self) -> SelectionReceipt {
        self.receipt
    }
}

/// Select the highest-preference compatible variant once.
///
/// Equal preference values retain source-table order. An operation should
/// always include an architecture-neutral scalar fallback. `input_bytes` must
/// describe an invariant operation width (for example a 16-byte classifier or
/// a compiled literal's length) if the result is retained in a reusable plan;
/// do not select once using one haystack's varying length and reuse that result
/// for differently sized haystacks.
pub fn select_kernel<F: Copy>(
    capabilities: CpuCapabilities,
    policy: DispatchPolicy,
    input_bytes: usize,
    variants: &[KernelVariant<F>],
) -> Result<Option<SelectedKernel<F>>, UnsupportedRequiredFeatures> {
    let usable = policy.apply(capabilities)?;
    let selected = variants.iter().fold(None, |selected, variant| {
        let compatible = variant.architecture.matches(capabilities.architecture)
            && usable.contains_all(variant.required)
            && (variant.tuning_matches)(capabilities.tuning)
            && input_bytes >= variant.minimum_input_bytes;
        if compatible
            && selected
                .is_none_or(|current: &KernelVariant<F>| variant.preference > current.preference)
        {
            Some(variant)
        } else {
            selected
        }
    });
    Ok(selected.map(|variant| SelectedKernel {
        entry: variant.entry,
        receipt: SelectionReceipt {
            policy_version: DISPATCH_POLICY_VERSION,
            variant_id: variant.stable_id,
            delegate_variant_id: None,
            policy,
            architecture: capabilities.architecture,
            host_tuning: capabilities.tuning,
            host_evidence: capabilities.evidence,
            host_reported: capabilities.reported,
            policy_usable: usable,
            required: variant.required,
            vector: variant.vector,
            selection_input_bytes: input_bytes,
            minimum_input_bytes: variant.minimum_input_bytes,
        },
    }))
}

#[cfg(any(
    all(
        not(feature = "static-dispatch"),
        target_arch = "aarch64",
        target_os = "linux"
    ),
    test
))]
mod linux_aarch64 {
    use std::io::{ErrorKind, Read};

    use super::ArmCpuIdentity;

    const MAX_CPUINFO_BYTES: usize = 1 << 20;
    const READ_BUFFER_BYTES: usize = 4 << 10;
    const MAX_CPUINFO_LINE_BYTES: usize = 16 << 10;

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    pub(super) fn detect_cpu_identity() -> Option<ArmCpuIdentity> {
        let file = std::fs::File::open("/proc/cpuinfo").ok()?;
        read_cpu_identity(file)
    }

    fn read_cpu_identity(mut reader: impl Read) -> Option<ArmCpuIdentity> {
        let mut parser = CpuInfoParser::default();
        let mut read_buffer = [0_u8; READ_BUFFER_BYTES];
        let mut line_buffer = [0_u8; MAX_CPUINFO_LINE_BYTES];
        let mut line_bytes = 0_usize;
        let mut total_bytes = 0_usize;

        loop {
            let bytes_read = match reader.read(&mut read_buffer) {
                Ok(0) => break,
                Ok(bytes_read) => bytes_read,
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(_) => return None,
            };
            total_bytes = total_bytes.checked_add(bytes_read)?;
            if total_bytes > MAX_CPUINFO_BYTES {
                return None;
            }
            for &byte in &read_buffer[..bytes_read] {
                if byte == b'\n' {
                    parser.line(std::str::from_utf8(&line_buffer[..line_bytes]).ok()?)?;
                    line_bytes = 0;
                } else {
                    let destination = line_buffer.get_mut(line_bytes)?;
                    *destination = byte;
                    line_bytes = line_bytes.checked_add(1)?;
                }
            }
        }
        if line_bytes != 0 {
            parser.line(std::str::from_utf8(&line_buffer[..line_bytes]).ok()?)?;
        }
        parser.finish()
    }

    #[cfg(test)]
    pub(super) fn parse_cpuinfo(source: &str) -> Option<ArmCpuIdentity> {
        let mut parser = CpuInfoParser::default();
        for line in source.lines() {
            parser.line(line)?;
        }
        parser.finish()
    }

    #[derive(Default)]
    struct CpuInfoParser {
        homogeneous: Option<ArmCpuIdentity>,
        record: CpuInfoRecord,
    }

    impl CpuInfoParser {
        fn line(&mut self, line: &str) -> Option<()> {
            if line.trim().is_empty() {
                return self.finish_record();
            }

            let Some((name, value)) = line.split_once(':') else {
                return Some(());
            };
            match name.trim() {
                "processor" => {
                    // A second processor line is also a record boundary. This
                    // preserves homogeneous proof if a producer omits the
                    // customary blank line between processor records.
                    if self.record.processor {
                        self.finish_record()?;
                    }
                    self.record.processor = true;
                }
                "CPU implementer" => {
                    self.record.identity_field = true;
                    self.record.implementer = Some(parse_u16(value)?);
                }
                "CPU part" => {
                    self.record.identity_field = true;
                    self.record.part = Some(parse_u16(value)?);
                }
                "CPU variant" => {
                    self.record.identity_field = true;
                    self.record.variant = Some(parse_u8(value)?);
                }
                "CPU revision" => {
                    self.record.identity_field = true;
                    self.record.revision = Some(parse_u8(value)?);
                }
                _ => {}
            }
            Some(())
        }

        fn finish(mut self) -> Option<ArmCpuIdentity> {
            self.finish_record()?;
            self.homogeneous
        }

        fn finish_record(&mut self) -> Option<()> {
            if !self.record.processor && !self.record.identity_field {
                self.record = CpuInfoRecord::default();
                return Some(());
            }
            let (Some(implementer), Some(part)) = (self.record.implementer, self.record.part)
            else {
                // A partially described processor cannot prove that every CPU
                // has the same tuning identity. Fail closed instead of
                // deriving a tuning class from only the complete subset.
                return None;
            };
            let identity = ArmCpuIdentity {
                implementer,
                part,
                variant: self.record.variant,
                revision: self.record.revision,
            };
            if self.homogeneous.is_some_and(|first| first != identity) {
                return None;
            }
            self.homogeneous = Some(identity);
            self.record = CpuInfoRecord::default();
            Some(())
        }
    }

    #[derive(Default)]
    struct CpuInfoRecord {
        processor: bool,
        identity_field: bool,
        implementer: Option<u16>,
        part: Option<u16>,
        variant: Option<u8>,
        revision: Option<u8>,
    }

    fn parse_u16(source: &str) -> Option<u16> {
        let value = source.trim();
        value.strip_prefix("0x").map_or_else(
            || value.parse().ok(),
            |hex| u16::from_str_radix(hex, 16).ok(),
        )
    }

    fn parse_u8(source: &str) -> Option<u8> {
        let value = parse_u16(source)?;
        u8::try_from(value).ok()
    }

    #[cfg(test)]
    pub(super) fn parse_cpuinfo_bounded_for_test(source: &str) -> Option<ArmCpuIdentity> {
        read_cpu_identity(source.as_bytes())
    }

    #[cfg(test)]
    pub(super) fn parse_cpuinfo_chunked_for_test(
        source: &str,
        maximum_chunk_bytes: usize,
    ) -> Option<ArmCpuIdentity> {
        struct Chunked<'a> {
            remaining: &'a [u8],
            maximum_chunk_bytes: usize,
        }

        impl Read for Chunked<'_> {
            fn read(&mut self, destination: &mut [u8]) -> std::io::Result<usize> {
                let bytes = self
                    .remaining
                    .len()
                    .min(destination.len())
                    .min(self.maximum_chunk_bytes);
                destination[..bytes].copy_from_slice(&self.remaining[..bytes]);
                self.remaining = &self.remaining[bytes..];
                Ok(bytes)
            }
        }

        if maximum_chunk_bytes == 0 {
            return None;
        }
        read_cpu_identity(Chunked {
            remaining: source.as_bytes(),
            maximum_chunk_bytes,
        })
    }
}

#[cfg(all(
    not(feature = "static-dispatch"),
    target_os = "macos",
    target_arch = "aarch64"
))]
mod macos {
    use core::{ffi::CStr, mem::size_of};

    use super::{Feature, FeatureSet};

    pub(super) struct Aarch64Facts {
        pub(super) features: FeatureSet,
        pub(super) cpu_family: Option<u32>,
    }

    pub(super) fn detect_aarch64() -> Aarch64Facts {
        let mut features = FeatureSet::EMPTY;
        macro_rules! add {
            ($name:literal, $feature:expr) => {
                if flag(c_str($name)) {
                    features = features.with($feature);
                }
            };
        }
        add!(b"hw.optional.arm.AdvSIMD\0", Feature::ArmNeon);
        add!(b"hw.optional.arm.FEAT_AES\0", Feature::ArmAes);
        add!(b"hw.optional.arm.FEAT_PMULL\0", Feature::ArmPmull);
        add!(b"hw.optional.arm.FEAT_SHA256\0", Feature::ArmSha2);
        add!(b"hw.optional.arm.FEAT_SHA3\0", Feature::ArmSha3);
        add!(b"hw.optional.arm.FEAT_SM4\0", Feature::ArmSm4);
        add!(b"hw.optional.arm.FEAT_CRC32\0", Feature::ArmCrc);
        add!(b"hw.optional.arm.FEAT_FP16\0", Feature::ArmFp16);
        add!(b"hw.optional.arm.FEAT_FHM\0", Feature::ArmFhm);
        add!(b"hw.optional.arm.FEAT_RDM\0", Feature::ArmRdm);
        add!(b"hw.optional.arm.FEAT_DotProd\0", Feature::ArmDotprod);
        add!(b"hw.optional.arm.FEAT_FCMA\0", Feature::ArmFcma);
        add!(b"hw.optional.arm.FEAT_BF16\0", Feature::ArmBf16);
        add!(b"hw.optional.arm.FEAT_I8MM\0", Feature::ArmI8mm);
        add!(b"hw.optional.arm.FEAT_F32MM\0", Feature::ArmF32mm);
        add!(b"hw.optional.arm.FEAT_F64MM\0", Feature::ArmF64mm);
        add!(b"hw.optional.arm.FEAT_SVE\0", Feature::ArmSve);
        add!(b"hw.optional.arm.FEAT_SVE2\0", Feature::ArmSve2);
        add!(b"hw.optional.arm.FEAT_SVE2p1\0", Feature::ArmSve2p1);
        add!(b"hw.optional.arm.FEAT_SVE_B16B16\0", Feature::ArmSveB16b16);
        add!(b"hw.optional.arm.FEAT_SVE_AES\0", Feature::ArmSve2Aes);
        add!(
            b"hw.optional.arm.FEAT_SVE_BitPerm\0",
            Feature::ArmSve2Bitperm
        );
        add!(b"hw.optional.arm.FEAT_SVE_SHA3\0", Feature::ArmSve2Sha3);
        add!(b"hw.optional.arm.FEAT_SVE_SM4\0", Feature::ArmSve2Sm4);
        add!(b"hw.optional.arm.FEAT_SME\0", Feature::ArmSme);
        add!(b"hw.optional.arm.FEAT_SME2\0", Feature::ArmSme2);
        add!(b"hw.optional.arm.FEAT_SME2p1\0", Feature::ArmSme2p1);
        add!(b"hw.optional.arm.FEAT_SME_B16B16\0", Feature::ArmSmeB16b16);
        add!(b"hw.optional.arm.FEAT_SME_F16F16\0", Feature::ArmSmeF16f16);
        add!(b"hw.optional.arm.FEAT_SME_F64F64\0", Feature::ArmSmeF64f64);
        add!(b"hw.optional.arm.FEAT_SME_I16I64\0", Feature::ArmSmeI16i64);
        add!(b"hw.optional.arm.FEAT_SME_FA64\0", Feature::ArmSmeFa64);
        add!(b"hw.optional.arm.FEAT_CSSC\0", Feature::ArmCssc);
        add!(b"hw.optional.arm.FEAT_FAMINMAX\0", Feature::ArmFaminmax);
        add!(b"hw.optional.arm.FEAT_LUT\0", Feature::ArmLut);
        add!(b"hw.optional.arm.FEAT_MOPS\0", Feature::ArmMops);
        Aarch64Facts {
            features,
            cpu_family: integer(c_str(b"hw.cpufamily\0")).map(i32::cast_unsigned),
        }
    }

    const fn c_str(bytes: &'static [u8]) -> &'static CStr {
        match CStr::from_bytes_with_nul(bytes) {
            Ok(value) => value,
            Err(_) => panic!("internal sysctl name must have one trailing NUL"),
        }
    }

    fn flag(name: &CStr) -> bool {
        integer(name).is_some_and(|value| value != 0)
    }

    #[allow(
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar(_: &[u8]) -> usize {
        0
    }

    fn neon(_: &[u8]) -> usize {
        1
    }

    fn sve2(_: &[u8]) -> usize {
        2
    }

    fn avx2(_: &[u8]) -> usize {
        3
    }

    fn avx512(_: &[u8]) -> usize {
        4
    }

    fn apple_family_42(tuning: TuningClass) -> bool {
        matches!(
            tuning,
            TuningClass::AppleSilicon {
                cpu_family: Some(42)
            }
        )
    }

    fn intel_family_6(tuning: TuningClass) -> bool {
        matches!(
            tuning,
            TuningClass::X86 {
                vendor: X86Vendor::Intel,
                family: 6,
                ..
            }
        )
    }

    #[test]
    fn feature_names_and_bits_are_unique() {
        let mut seen = FeatureSet::EMPTY;
        for feature in Feature::ALL {
            assert!(!seen.contains(feature), "duplicate bit for {feature:?}");
            seen = seen.with(feature);
            assert!(!feature.name().is_empty());
        }
        assert_eq!(seen.iter().count(), Feature::ALL.len());
    }

    #[test]
    fn dispatch_profile_matches_snapshot_evidence() {
        match dispatch_profile() {
            DispatchProfile::RuntimeDetected => {
                assert!(!host().evidence().contains(Evidence::COMPILE_TIME));
                assert!(!host().evidence().contains(Evidence::DECLARED_TUNING));
            }
            DispatchProfile::CompileTimeTarget => {
                assert!(host().evidence().contains(Evidence::COMPILE_TIME));
                assert!(!host().evidence().contains(Evidence::DECLARED_TUNING));
            }
            DispatchProfile::CompileTimeArm41D84 => {
                assert!(host().evidence().contains(Evidence::COMPILE_TIME));
                assert!(host().evidence().contains(Evidence::DECLARED_TUNING));
            }
        }
    }

    #[cfg(feature = "static-dispatch")]
    #[test]
    fn static_snapshot_contains_exactly_the_mapped_target_features() {
        let expected = compile_time_features();
        assert_eq!(host().reported(), expected);
        assert_eq!(host().usable(), expected);
        macro_rules! assert_target_feature {
            ($feature:expr, $enabled:expr) => {
                assert_eq!(
                    host().usable().contains($feature),
                    $enabled,
                    "{}",
                    $feature.name()
                );
            };
        }
        assert_target_feature!(
            Feature::ArmNeon,
            cfg!(all(target_arch = "aarch64", target_feature = "neon"))
        );
        assert_target_feature!(
            Feature::ArmAes,
            cfg!(all(target_arch = "aarch64", target_feature = "aes"))
        );
        assert_target_feature!(
            Feature::ArmSve,
            cfg!(all(target_arch = "aarch64", target_feature = "sve"))
        );
        assert_target_feature!(
            Feature::ArmSve2,
            cfg!(all(target_arch = "aarch64", target_feature = "sve2"))
        );
        assert_target_feature!(
            Feature::ArmSve2Aes,
            cfg!(all(target_arch = "aarch64", target_feature = "sve2-aes"))
        );
        assert_target_feature!(
            Feature::ArmF64mm,
            cfg!(all(target_arch = "aarch64", target_feature = "f64mm"))
        );
        assert_target_feature!(
            Feature::X86Sse2,
            cfg!(all(target_arch = "x86_64", target_feature = "sse2"))
        );
        assert_target_feature!(
            Feature::X86Ssse3,
            cfg!(all(target_arch = "x86_64", target_feature = "ssse3"))
        );
        assert_target_feature!(
            Feature::X86Avx2,
            cfg!(all(target_arch = "x86_64", target_feature = "avx2"))
        );
        assert_target_feature!(
            Feature::X86Fma,
            cfg!(all(target_arch = "x86_64", target_feature = "fma"))
        );
        assert_target_feature!(
            Feature::X86Bmi2,
            cfg!(all(target_arch = "x86_64", target_feature = "bmi2"))
        );
        assert_target_feature!(
            Feature::X86Avx512F,
            cfg!(all(target_arch = "x86_64", target_feature = "avx512f"))
        );
        assert_target_feature!(
            Feature::X86Avx512Bw,
            cfg!(all(target_arch = "x86_64", target_feature = "avx512bw"))
        );
        assert_target_feature!(
            Feature::X86Avx512Vl,
            cfg!(all(target_arch = "x86_64", target_feature = "avx512vl"))
        );
        assert!(!host().usable().contains(Feature::ArmSme));
        assert!(!host().usable().contains(Feature::ArmSme2));
    }

    #[cfg(feature = "static-dispatch-arm-41-d84")]
    #[test]
    fn static_arm_41_d84_profile_has_separate_isa_and_tuning_evidence() {
        let required = FeatureSet::EMPTY
            .with(Feature::ArmNeon)
            .with(Feature::ArmSve)
            .with(Feature::ArmSve2);
        assert!(host().usable().contains_all(required));
        assert!(matches!(
            host().tuning(),
            TuningClass::ArmServer {
                cpu: Some(ArmCpuIdentity {
                    implementer: 0x41,
                    part: 0x0d84,
                    ..
                })
            }
        ));
        assert!(host().evidence().contains(Evidence::COMPILE_TIME));
        assert!(host().evidence().contains(Evidence::DECLARED_TUNING));
        assert!(!host().evidence().contains(Evidence::STD_ARCH));
        assert!(!host().evidence().contains(Evidence::LINUX_CPUINFO));
    }

    #[test]
    fn masks_and_policies_cannot_invent_features() {
        let original = FeatureSet::EMPTY
            .with(Feature::ArmNeon)
            .with(Feature::ArmSve2);
        let capabilities = CpuCapabilities::synthetic(Architecture::Aarch64, original);
        let requested = FeatureSet::EMPTY
            .with(Feature::ArmSve2)
            .with(Feature::X86Avx512Bw);
        let masked = capabilities.masked(requested);
        assert_eq!(masked.usable(), FeatureSet::of(Feature::ArmSve2));
        assert_eq!(masked.reported(), original);
        assert!(matches!(
            DispatchPolicy::Require(FeatureSet::of(Feature::X86Avx512Bw)).apply(capabilities),
            Err(UnsupportedRequiredFeatures { .. })
        ));
    }

    #[test]
    fn arm_selection_prefers_sve2_then_neon_then_scalar() {
        type Entry = fn(&[u8]) -> usize;
        let variants: [KernelVariant<Entry>; 3] = [
            KernelVariant::new(
                "scalar.v1",
                ArchitectureRequirement::Any,
                FeatureSet::EMPTY,
                VectorKind::Scalar,
                0,
                0,
                scalar,
            ),
            KernelVariant::new(
                "neon.v1",
                ArchitectureRequirement::Exact(Architecture::Aarch64),
                FeatureSet::of(Feature::ArmNeon),
                VectorKind::Fixed { bytes: 16 },
                16,
                10,
                neon,
            ),
            KernelVariant::new(
                "sve2.v1",
                ArchitectureRequirement::Exact(Architecture::Aarch64),
                FeatureSet::of(Feature::ArmSve2),
                VectorKind::Scalable,
                32,
                20,
                sve2,
            ),
        ];
        let capabilities = CpuCapabilities::synthetic(
            Architecture::Aarch64,
            FeatureSet::EMPTY
                .with(Feature::ArmNeon)
                .with(Feature::ArmSve2),
        );
        let selected = select_kernel(capabilities, DispatchPolicy::Auto, 128, &variants)
            .unwrap()
            .unwrap();
        assert_eq!(selected.receipt().variant_id, "sve2.v1");
        assert_eq!((selected.entry())(&[]), 2);

        let selected = select_kernel(
            capabilities,
            DispatchPolicy::AllowOnly(FeatureSet::of(Feature::ArmNeon)),
            128,
            &variants,
        )
        .unwrap()
        .unwrap();
        assert_eq!(selected.receipt().variant_id, "neon.v1");

        let selected = select_kernel(capabilities, DispatchPolicy::Portable, 128, &variants)
            .unwrap()
            .unwrap();
        assert_eq!(selected.receipt().variant_id, "scalar.v1");
    }

    #[test]
    fn x86_threshold_and_non_linear_requirements_control_selection() {
        type Entry = fn(&[u8]) -> usize;
        let avx512_requirements = FeatureSet::EMPTY
            .with(Feature::X86Avx512F)
            .with(Feature::X86Avx512Bw)
            .with(Feature::X86Avx512Vl);
        let variants: [KernelVariant<Entry>; 3] = [
            KernelVariant::new(
                "scalar.v1",
                ArchitectureRequirement::Any,
                FeatureSet::EMPTY,
                VectorKind::Scalar,
                0,
                0,
                scalar,
            ),
            KernelVariant::new(
                "avx2.v1",
                ArchitectureRequirement::Exact(Architecture::X86_64),
                FeatureSet::of(Feature::X86Avx2),
                VectorKind::Fixed { bytes: 32 },
                32,
                20,
                avx2,
            ),
            KernelVariant::new(
                "avx512.v1",
                ArchitectureRequirement::Exact(Architecture::X86_64),
                avx512_requirements,
                VectorKind::Fixed { bytes: 64 },
                256,
                30,
                avx512,
            ),
        ];
        let capabilities = CpuCapabilities::synthetic(
            Architecture::X86_64,
            FeatureSet::of(Feature::X86Avx2).union(avx512_requirements),
        );
        assert_eq!(
            select_kernel(capabilities, DispatchPolicy::Auto, 64, &variants)
                .unwrap()
                .unwrap()
                .receipt()
                .variant_id,
            "avx2.v1"
        );
        assert_eq!(
            select_kernel(capabilities, DispatchPolicy::Auto, 256, &variants)
                .unwrap()
                .unwrap()
                .receipt()
                .variant_id,
            "avx512.v1"
        );
    }

    #[test]
    fn x86_tuning_and_advanced_features_cannot_authorize_avx2() {
        type Entry = fn(&[u8]) -> usize;
        let tuned_avx2_entry: Entry = avx2;
        let avx2_requirement = FeatureSet::of(Feature::X86Avx2);
        let advanced_features = FeatureSet::EMPTY
            .with(Feature::X86Avx512F)
            .with(Feature::X86Avx512Bw)
            .with(Feature::X86Avx512Vl);
        let variants: [KernelVariant<Entry>; 3] = [
            KernelVariant::new(
                "scalar.v1",
                ArchitectureRequirement::Any,
                FeatureSet::EMPTY,
                VectorKind::Scalar,
                0,
                0,
                scalar,
            ),
            KernelVariant::new(
                "avx2.generic.v1",
                ArchitectureRequirement::Exact(Architecture::X86_64),
                avx2_requirement,
                VectorKind::Fixed { bytes: 32 },
                32,
                10,
                avx2,
            ),
            KernelVariant::new(
                "avx2.intel-family-6.v1",
                ArchitectureRequirement::Exact(Architecture::X86_64),
                avx2_requirement,
                VectorKind::Fixed { bytes: 32 },
                32,
                20,
                tuned_avx2_entry,
            )
            .when_tuning(intel_family_6),
        ];
        let intel_tuning = TuningClass::X86 {
            vendor: X86Vendor::Intel,
            family: 6,
            model: 0x8f,
        };
        let advanced_only = CpuCapabilities::synthetic_with_tuning(
            Architecture::X86_64,
            advanced_features,
            intel_tuning,
        );
        let selected = select_kernel(advanced_only, DispatchPolicy::Auto, 32, &variants)
            .unwrap()
            .unwrap();
        assert_eq!(selected.receipt().variant_id, "scalar.v1");
        assert!(selected.receipt().required.is_empty());

        let intel_all = CpuCapabilities::synthetic_with_tuning(
            Architecture::X86_64,
            advanced_features.with(Feature::X86Avx2),
            intel_tuning,
        );
        let selected = select_kernel(intel_all, DispatchPolicy::Auto, 32, &variants)
            .unwrap()
            .unwrap();
        assert_eq!(selected.receipt().variant_id, "avx2.intel-family-6.v1");
        assert_eq!(selected.receipt().required, avx2_requirement);

        let masked = select_kernel(
            intel_all,
            DispatchPolicy::AllowOnly(advanced_features),
            32,
            &variants,
        )
        .unwrap()
        .unwrap();
        assert_eq!(masked.receipt().variant_id, "scalar.v1");
        assert!(masked.receipt().required.is_empty());

        for vendor in [X86Vendor::Amd, X86Vendor::Unknown] {
            let capabilities = CpuCapabilities::synthetic_with_tuning(
                Architecture::X86_64,
                avx2_requirement,
                TuningClass::X86 {
                    vendor,
                    family: 6,
                    model: 0x8f,
                },
            );
            let selected = select_kernel(capabilities, DispatchPolicy::Auto, 32, &variants)
                .unwrap()
                .unwrap();
            assert_eq!(selected.receipt().variant_id, "avx2.generic.v1");
            assert_eq!(selected.receipt().required, avx2_requirement);
        }
    }

    #[test]
    fn tuning_filters_performance_without_authorizing_instructions() {
        type Entry = fn(&[u8]) -> usize;
        let apple_entry: Entry = sve2;
        let variants: [KernelVariant<Entry>; 3] = [
            KernelVariant::new(
                "scalar.v1",
                ArchitectureRequirement::Any,
                FeatureSet::EMPTY,
                VectorKind::Scalar,
                0,
                0,
                scalar,
            ),
            KernelVariant::new(
                "neon.generic.v1",
                ArchitectureRequirement::Exact(Architecture::Aarch64),
                FeatureSet::of(Feature::ArmNeon),
                VectorKind::Fixed { bytes: 16 },
                16,
                10,
                neon,
            ),
            KernelVariant::new(
                "neon.apple-family-42.v1",
                ArchitectureRequirement::Exact(Architecture::Aarch64),
                FeatureSet::of(Feature::ArmNeon),
                VectorKind::Fixed { bytes: 16 },
                16,
                20,
                apple_entry,
            )
            .when_tuning(apple_family_42),
        ];
        let features = FeatureSet::of(Feature::ArmNeon);
        let apple = CpuCapabilities::synthetic_with_tuning(
            Architecture::Aarch64,
            features,
            TuningClass::AppleSilicon {
                cpu_family: Some(42),
            },
        );
        let server = CpuCapabilities::synthetic_with_tuning(
            Architecture::Aarch64,
            features,
            TuningClass::ArmServer { cpu: None },
        );
        assert_eq!(
            select_kernel(apple, DispatchPolicy::Auto, 128, &variants)
                .unwrap()
                .unwrap()
                .receipt()
                .variant_id,
            "neon.apple-family-42.v1"
        );
        assert_eq!(
            select_kernel(server, DispatchPolicy::Auto, 128, &variants)
                .unwrap()
                .unwrap()
                .receipt()
                .variant_id,
            "neon.generic.v1"
        );

        let no_neon = CpuCapabilities::synthetic_with_tuning(
            Architecture::Aarch64,
            FeatureSet::EMPTY,
            TuningClass::AppleSilicon {
                cpu_family: Some(42),
            },
        );
        assert_eq!(
            select_kernel(no_neon, DispatchPolicy::Auto, 128, &variants)
                .unwrap()
                .unwrap()
                .receipt()
                .variant_id,
            "scalar.v1"
        );
    }

    #[test]
    fn linux_arm_identity_requires_homogeneous_implementer_and_part() {
        const HOMOGENEOUS: &str = "\
processor\t: 0\n\
CPU implementer\t: 0x41\n\
CPU variant\t: 0x1\n\
CPU part\t: 0xd84\n\
CPU revision\t: 1\n\
\n\
processor\t: 1\n\
CPU implementer\t: 0x41\n\
CPU variant\t: 0x1\n\
CPU part\t: 0xd84\n\
CPU revision\t: 1\n";
        let expected = ArmCpuIdentity {
            implementer: 0x41,
            part: 0x0d84,
            variant: Some(1),
            revision: Some(1),
        };
        assert_eq!(linux_aarch64::parse_cpuinfo(HOMOGENEOUS), Some(expected));
        assert_eq!(
            linux_aarch64::parse_cpuinfo_bounded_for_test(HOMOGENEOUS),
            Some(expected)
        );
        assert_eq!(
            linux_aarch64::parse_cpuinfo_chunked_for_test(HOMOGENEOUS, 1),
            Some(expected)
        );
        let oversized = format!("{HOMOGENEOUS}{}", " ".repeat(1 << 20));
        assert_eq!(
            linux_aarch64::parse_cpuinfo_bounded_for_test(&oversized),
            None
        );
        let overlong_line = format!("{}\n{HOMOGENEOUS}", "x".repeat((16 << 10) + 1));
        assert_eq!(
            linux_aarch64::parse_cpuinfo_bounded_for_test(&overlong_line),
            None
        );
        assert_eq!(
            linux_aarch64::parse_cpuinfo(&HOMOGENEOUS.replacen("0xd84", "0xd4f", 1)),
            None
        );
        assert_eq!(
            linux_aarch64::parse_cpuinfo(&HOMOGENEOUS.replacen("\n\n", "\n", 1)),
            Some(expected)
        );
        assert_eq!(
            linux_aarch64::parse_cpuinfo(
                &HOMOGENEOUS
                    .replacen("\n\n", "\n", 1)
                    .replacen("0xd84", "0xd4f", 1)
            ),
            None
        );
        assert_eq!(
            linux_aarch64::parse_cpuinfo(&format!(
                "{HOMOGENEOUS}\n\nprocessor\t: 2\nCPU implementer\t: 0x41\n"
            )),
            None
        );
        assert_eq!(
            linux_aarch64::parse_cpuinfo(
                "processor\t: 0\nCPU implementer\t: 0x41\nCPU revision\t: 1\n"
            ),
            None
        );
        assert_eq!(
            linux_aarch64::parse_cpuinfo_bounded_for_test(
                "processor\t: 0\nCPU implementer\t: 0x41\nCPU part\t: 0x"
            ),
            None
        );
    }

    #[test]
    fn live_snapshot_is_stable_and_usable_is_reported_subset() {
        assert!(core::ptr::eq(host(), host()));
        assert!(host().reported().contains_all(host().usable()));
        match host().architecture() {
            Architecture::Aarch64 => {
                assert!(host().usable().contains(Feature::ArmNeon));
            }
            Architecture::X86_64 => {
                assert!(host().usable().contains(Feature::X86Sse2));
            }
            Architecture::Other => assert!(host().usable().is_empty()),
        }
    }

    #[cfg(all(
        not(feature = "static-dispatch"),
        target_arch = "aarch64",
        target_os = "macos"
    ))]
    #[test]
    fn apple_stateful_sme_is_visible_but_not_selectable() {
        let reported_sme = host().reported().contains(Feature::ArmSme);
        if reported_sme {
            assert!(!host().usable().contains(Feature::ArmSme));
        }
        assert!(host().evidence().contains(Evidence::APPLE_SYSCTL));
        assert!(matches!(host().tuning(), TuningClass::AppleSilicon { .. }));
    }
}
