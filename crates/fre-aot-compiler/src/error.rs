use core::fmt;

use fre::AggregateBuildError as FacadeBuildError;
use fre_aot_aarch64::CountAotError;
use fre_aot_macho::{BindingIdentityError, ObjectError};
use fre_jit_aarch64::EmitError;
use fre_kernel_ir::AggregateBuildError;

/// Compiler-level resource checked in addition to stage-local typed limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CompileResource {
    SourceBytes,
    SourceCapacityBytes,
    LiteralBytes,
    FacadePlanningWork,
    CandidateIdentityWork,
    CompilerIdentityWork,
    PipelineWork,
    FinalPersistentBytes,
    PeakScratchBytes,
    PipelinePeakLiveBytes,
}

/// Impossible mismatch between private facade candidate fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CandidateContractViolation {
    Operation,
    Semantics,
    KernelOperation,
    BuildLiteralBytes,
    UnicodeLiteral,
    PlanningReceipt,
}

/// A field that failed to agree across KIR, native image, object, and receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ContractField {
    ManifestIdentity,
    KernelLiteral,
    KernelOutput,
    NativeSourceIdentity,
    NativeBackendVersion,
    NativeOutput,
    NativeLiteralBytes,
    NativeArchitecture,
    NativeByteOrder,
    NativePointerWidth,
    NativeAbi,
    NativeFeatures,
    MetadataVersion,
    MetadataRecordBytes,
    MetadataBackendVersion,
    MetadataAlgorithmVersion,
    MetadataKirSemanticsVersion,
    MetadataKirAbiVersion,
    MetadataMaxLiteralBytes,
    MetadataAbiKind,
    MetadataOutput,
    MetadataArchitecture,
    MetadataByteOrder,
    MetadataPointerWidth,
    MetadataTargetAbi,
    MetadataPlatform,
    MetadataStatusBits,
    MetadataAbiSchema,
    MetadataFeatures,
    MetadataAllowedFeatures,
    MetadataPayloadBytes,
    MetadataEntryOffset,
    MetadataCodeBytes,
    MetadataRodataOffset,
    MetadataRodataBytes,
    MetadataLiteralBytes,
    MetadataSourceIdentity,
    MetadataArtifactIdentity,
    MetadataBindingIdentity,
    MetadataCompileIdentity,
    ObjectReportCompileIdentity,
    ObjectReportObjectIdentity,
}

/// Checked-arithmetic site in compiler-owned composition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CompileArithmeticSite {
    SourceLength,
    LiteralLength,
    IdentityEncoding,
    WorkAccounting,
    PersistentAccounting,
    ScratchAccounting,
    PipelineLiveAccounting,
}

/// Typed refusal from the authenticated AOT compilation pipeline.
#[allow(
    clippy::large_enum_variant,
    reason = "offline compilation preserves allocation-free typed stage failures instead of erasing them behind indirection"
)]
#[derive(Debug)]
#[non_exhaustive]
pub enum CompileError {
    ResourceLimit {
        resource: CompileResource,
        limit: u64,
        required: u64,
    },
    CandidateContract {
        violation: CandidateContractViolation,
    },
    /// Source bytes passed their byte/capacity gates but were not UTF-8.
    InvalidUtf8Source,
    FacadePlanning(FacadeBuildError),
    Kernel(AggregateBuildError),
    /// Refusal from the independent, direct Count AOT backend.
    CountNative(CountAotError),
    /// Refusal from the legacy generic aggregate-image backend.
    Native(EmitError),
    ObjectBinding(BindingIdentityError),
    Object(ObjectError),
    ContractMismatch {
        field: ContractField,
    },
    ArithmeticOverflow {
        site: CompileArithmeticSite,
    },
    InternalInvariant {
        at: &'static str,
    },
}

impl fmt::Display for CompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "FRE AOT compilation failed: {self:?}")
    }
}

impl std::error::Error for CompileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::FacadePlanning(error) => Some(error),
            Self::Kernel(error) => Some(error),
            Self::CountNative(error) => Some(error),
            Self::Native(error) => Some(error),
            Self::ObjectBinding(error) => Some(error),
            Self::Object(error) => Some(error),
            _ => None,
        }
    }
}

impl From<AggregateBuildError> for CompileError {
    fn from(value: AggregateBuildError) -> Self {
        Self::Kernel(value)
    }
}

impl From<EmitError> for CompileError {
    fn from(value: EmitError) -> Self {
        Self::Native(value)
    }
}

impl From<CountAotError> for CompileError {
    fn from(value: CountAotError) -> Self {
        Self::CountNative(value)
    }
}

impl From<BindingIdentityError> for CompileError {
    fn from(value: BindingIdentityError) -> Self {
        Self::ObjectBinding(value)
    }
}

impl From<ObjectError> for CompileError {
    fn from(value: ObjectError) -> Self {
        Self::Object(value)
    }
}

/// Trusted receipt field that disagreed with inspected caller bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ReceiptMismatch {
    ReceiptIdentity,
    ManifestIdentity,
    ObjectIdentity,
    CompileIdentity,
    BindingIdentity,
    Metadata,
    ObjectBytes,
}

/// Strict inspection or external-receipt authentication failure.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ReceiptValidationError {
    Object(ObjectError),
    Mismatch { field: ReceiptMismatch },
    ArithmeticOverflow,
}

impl fmt::Display for ReceiptValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "FRE AOT receipt validation failed: {self:?}")
    }
}

impl std::error::Error for ReceiptValidationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Object(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ObjectError> for ReceiptValidationError {
    fn from(value: ObjectError) -> Self {
        Self::Object(value)
    }
}
