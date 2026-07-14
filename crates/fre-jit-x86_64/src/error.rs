use core::fmt;

use fre_kernel_ir::ValidateError;

use crate::{CallingConvention, TargetStamp};

/// Bounded emission dimension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmitResource {
    CodeBytes,
    DataBytes,
    ImageBytes,
    Relocations,
    InternalBranches,
    BranchDisplacement,
    RelocationDisplacement,
    EmitWork,
    EmitScratchBytes,
    AuditInstructions,
    AuditWork,
    AuditScratchBytes,
    RuntimeWorkFactor,
    RuntimeScratchBytes,
    AotBytes,
    AotWork,
    AotScratchBytes,
}

/// Target mismatch which is never silently treated as System V.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnsupportedTarget {
    pub target: TargetStamp,
    pub supported_calling_convention: CallingConvention,
}

/// Validated Kernel IR shape that this backend version cannot lower.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnsupportedKernel {
    MissingCanonicalOperation,
    MissingData,
    WrongDataKind,
    LiteralTooLarge,
}

/// Total failure from native-image construction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EmitError {
    KernelValidation(ValidateError),
    UnsupportedTarget(UnsupportedTarget),
    UnsupportedKernel(UnsupportedKernel),
    ResourceLimit {
        resource: EmitResource,
        limit: u64,
        required: u64,
    },
    ArithmeticOverflow,
    AllocationFailed {
        resource: EmitResource,
    },
    UnboundLabel,
    DuplicateLabel,
    InternalInvariant,
    Audit(AuditError),
}

impl From<ValidateError> for EmitError {
    fn from(value: ValidateError) -> Self {
        Self::KernelValidation(value)
    }
}

impl From<AuditError> for EmitError {
    fn from(value: AuditError) -> Self {
        Self::Audit(value)
    }
}

impl fmt::Display for EmitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "x86-64 emission failed: {self:?}")
    }
}

impl std::error::Error for EmitError {}

/// Failure from the independent decoder/authenticity audit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuditError {
    ResourceLimit {
        resource: EmitResource,
        limit: u64,
        required: u64,
    },
    ArithmeticOverflow,
    TruncatedInstruction {
        offset: usize,
    },
    UnknownInstruction {
        offset: usize,
    },
    ForbiddenControlFlow {
        offset: usize,
    },
    BranchTargetOutOfRange {
        offset: usize,
    },
    BranchTargetNotInstruction {
        offset: usize,
        target: usize,
    },
    RelocationManifestMismatch {
        offset: usize,
    },
    DataTargetOutOfRange {
        offset: usize,
    },
    TierMismatch {
        offset: usize,
    },
    MissingAvxCleanup {
        offset: usize,
    },
    ImageLayout,
}

impl fmt::Display for AuditError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "x86-64 image audit failed: {self:?}")
    }
}

impl std::error::Error for AuditError {}

/// Failure while serializing or inspecting the deterministic AOT container.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AotError {
    ResourceLimit {
        resource: EmitResource,
        limit: u64,
        required: u64,
    },
    ArithmeticOverflow,
    AllocationFailed,
    InvalidMagic,
    UnsupportedVersion {
        actual: u16,
    },
    Truncated,
    InvalidField,
}

impl fmt::Display for AotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "x86-64 AOT image failed: {self:?}")
    }
}

impl std::error::Error for AotError {}
