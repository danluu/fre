use core::fmt;

use fre_jit_aarch64::{AuditError, EmitError};
use fre_kernel_ir::{AggregateExecuteError, AggregateOutput, OutputKind};

/// Strict executable-memory policy implemented by this crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WxMode {
    /// Anonymous pages transition from RW to RX and are never RWX.
    StrictAnonymous,
    /// Apple `MAP_JIT` requires an entitlement and a distinct write-protect
    /// protocol; it is intentionally unsupported by this publisher.
    AppleMapJit,
}

/// Why this process cannot use the current native publisher.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostSupportReason {
    Architecture,
    OperatingSystem,
    PointerWidth,
    Endianness,
}

/// Publication state-machine stage used by typed syscall and injected errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureStage {
    HostCheck,
    PageSize,
    Reserve,
    MakeWritable,
    Copy,
    Verify,
    Reaudit,
    MakeExecutable,
    InvalidateInstructionCache,
    Publish,
}

/// Deterministically limited publication resource.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceKind {
    CodeBytes,
    DataBytes,
    PayloadBytes,
    MappedBytes,
    Pages,
}

/// Checked-arithmetic site in layout planning.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArithmeticSite {
    PageRounding,
    GuardPages,
    PageCount,
    ImageLayout,
}

/// Failure before a native callable has been published.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublishError {
    UnsupportedHost {
        reason: HostSupportReason,
    },
    ImageAudit(AuditError),
    ImageIdentity(EmitError),
    BackendVersionMismatch {
        expected: u16,
        actual: u16,
    },
    TargetMismatch,
    UnknownCpuFeatures {
        bits: u64,
    },
    CpuFeatureUnavailable {
        feature: &'static str,
    },
    CpuTuningUnavailable {
        required: &'static str,
    },
    SveVectorLengthMismatch {
        expected: u16,
        actual: Option<u16>,
    },
    OutputContractMismatch {
        expected: OutputKind,
        actual: OutputKind,
    },
    AggregateOutputContractMismatch {
        expected: AggregateOutput,
        actual: AggregateOutput,
    },
    InvalidPageSize {
        bytes: usize,
    },
    InvalidImageLayout,
    ResourceLimit {
        resource: ResourceKind,
        limit: u64,
        required: u64,
    },
    ArithmeticOverflow {
        site: ArithmeticSite,
    },
    SystemCall {
        stage: FailureStage,
        errno: i32,
    },
    NullMapping {
        stage: FailureStage,
    },
    JitDenied {
        stage: FailureStage,
        errno: i32,
        attempted: WxMode,
    },
    CopyFailed,
    CopyVerificationFailed,
    CacheInvalidationFailed,
    PublicationIdentityMismatch,
    InjectedFailure {
        stage: FailureStage,
    },
}

impl fmt::Display for PublishError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "native publication failed: {self:?}")
    }
}

impl std::error::Error for PublishError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ImageAudit(error) => Some(error),
            Self::ImageIdentity(error) => Some(error),
            _ => None,
        }
    }
}

/// Failure to establish a current-thread contract for a published kernel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KernelThreadContractError {
    /// The host capability query itself could not run.
    HostCapabilities(PublishError),
    /// A plan-bound fast session was requested for a literal that differs
    /// from the exact literal sealed into the native artifact.
    LiteralIdentityMismatch,
    /// A fixed-VL SVE/SVE2 kernel requires a different current-thread vector
    /// length.
    RequiredSveVectorLengthUnavailable {
        required_bytes: u16,
        actual_bytes: Option<u16>,
    },
}

impl fmt::Display for KernelThreadContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "native search thread contract failed: {self:?}")
    }
}

impl std::error::Error for KernelThreadContractError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::HostCapabilities(error) => Some(error),
            Self::LiteralIdentityMismatch | Self::RequiredSveVectorLengthUnavailable { .. } => None,
        }
    }
}

/// Failure at the safe generated-code call boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CallError {
    InvalidWindow {
        start: usize,
        end: usize,
        haystack_len: usize,
    },
    PublicationIdentityMismatch,
    AggregatePreflight(AggregateExecuteError),
    AggregateArithmeticOverflow,
    AggregateBackendFault {
        status: u64,
    },
    BackendFault {
        status: u64,
    },
    InvalidNativeOutput {
        output: OutputKind,
        start: usize,
        end: usize,
        window_start: usize,
        window_end: usize,
    },
    InvalidNativeAggregateOutput {
        output: AggregateOutput,
        value: u64,
        haystack_len: usize,
        literal_len: usize,
    },
}

impl fmt::Display for CallError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "native call failed: {self:?}")
    }
}

impl std::error::Error for CallError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::AggregatePreflight(error) => Some(error),
            _ => None,
        }
    }
}
