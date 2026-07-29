use core::fmt;

use fre_aot_aarch64::CountAotError;
use fre_aot_count_contract::v3::{CountMetadataErrorV3, StaticCountExpectationErrorV3};
use fre_aot_optimizer::CountV3RecipeDecodeError;
use fre_kernel_ir::{AggregateBuildError, AggregateExecuteError};

/// One independently reconstructed Count-v3 contract field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum StaticCountContractFieldV3 {
    Metadata,
    CompileIdentity,
    ProgramIdentity,
    PayloadIdentity,
    EntryAddress,
    Literal,
    SemanticBindingIdentity,
    PlanningReceiptIdentity,
    Recipe,
    MappedCode,
}

/// Fail-closed refusal before a Count-v3 callable handle can exist.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum StaticCountVerifyErrorV3 {
    /// The reviewed production promotion table is empty.
    NoProductionAuthority,
    /// An inspected full eligibility tuple is absent from production rows.
    EligibilityTupleNotAuthorized,
    /// The default-off static Count-v3 implementation is not compiled in.
    LinkedCountV3FeatureDisabled,
    /// The current OS/architecture has no reviewed mapped-image verifier.
    UnsupportedHost,
    Expectation(StaticCountExpectationErrorV3),
    Metadata(CountMetadataErrorV3),
    ContractMismatch {
        field: StaticCountContractFieldV3,
    },
    Kernel(AggregateBuildError),
    Recipe(CountV3RecipeDecodeError),
    MappedCodeAudit(CountAotError),
    AddressRangeOverflow,
    MappedPayloadExtentOutOfBounds {
        claimed: usize,
        hard_maximum: usize,
    },
    VmRegionQueryFailed {
        code: i32,
    },
    VmRegionDoesNotCoverRange,
    VmRegionIsNotPrivate,
    ProtectionMismatch {
        purpose: &'static str,
        readable: bool,
        writable: bool,
        executable: bool,
    },
    RequiredCpuFeaturesUnavailable,
    RequiredSveVectorLengthUnavailable {
        required_bytes: u16,
    },
    EntryAddressMismatch,
    PayloadDigestMismatch,
    InspectionAllocationFailed,
    InspectionAccountingOverflow,
}

impl fmt::Display for StaticCountVerifyErrorV3 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "FRE optimizing Count-v3 static verification failed: {self:?}"
        )
    }
}

impl std::error::Error for StaticCountVerifyErrorV3 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Expectation(error) => Some(error),
            Self::Metadata(error) => Some(error),
            Self::Kernel(error) => Some(error),
            Self::Recipe(error) => Some(error),
            Self::MappedCodeAudit(error) => Some(error),
            _ => None,
        }
    }
}

impl From<StaticCountExpectationErrorV3> for StaticCountVerifyErrorV3 {
    fn from(value: StaticCountExpectationErrorV3) -> Self {
        Self::Expectation(value)
    }
}

impl From<CountMetadataErrorV3> for StaticCountVerifyErrorV3 {
    fn from(value: CountMetadataErrorV3) -> Self {
        Self::Metadata(value)
    }
}

impl From<AggregateBuildError> for StaticCountVerifyErrorV3 {
    fn from(value: AggregateBuildError) -> Self {
        Self::Kernel(value)
    }
}

impl From<CountV3RecipeDecodeError> for StaticCountVerifyErrorV3 {
    fn from(value: CountV3RecipeDecodeError) -> Self {
        Self::Recipe(value)
    }
}

impl From<CountAotError> for StaticCountVerifyErrorV3 {
    fn from(value: CountAotError) -> Self {
        Self::MappedCodeAudit(value)
    }
}

/// Failure at the safe, already-authenticated Count-v3 value call.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum StaticCountCallErrorV3 {
    /// Production evidence authorizes native execution only at or above this
    /// haystack-size floor. Qualification call surfaces do not apply it.
    ProductionRouteBelowEvidenceFloor {
        required_bytes: usize,
        actual_bytes: usize,
    },
    Preflight(AggregateExecuteError),
    BackendArithmeticOverflow,
    BackendFault {
        status: u64,
    },
    NativeResultChangedOnFault {
        status: u64,
        value: u64,
    },
    PoisonedNativeResult,
    InvalidNativeCount {
        value: u64,
        haystack_len: usize,
        literal_len: usize,
    },
}

impl fmt::Display for StaticCountCallErrorV3 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "FRE optimizing Count-v3 static call failed: {self:?}"
        )
    }
}

impl std::error::Error for StaticCountCallErrorV3 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Preflight(error) => Some(error),
            _ => None,
        }
    }
}

impl From<AggregateExecuteError> for StaticCountCallErrorV3 {
    fn from(value: AggregateExecuteError) -> Self {
        Self::Preflight(value)
    }
}

/// Current-thread Linux SVE contract failure for Count-v3 production or
/// qualification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum StaticCountSveThreadContractErrorV3 {
    UnsupportedHost,
    RequiredSveUnavailable,
    RequiredSve2Unavailable,
    SveVectorLengthQueryFailed {
        errno: Option<i32>,
    },
    SveVectorLengthSetFailed {
        errno: Option<i32>,
    },
    RequiredSveVectorLengthUnavailable {
        required_bytes: u16,
        actual_bytes: Option<u16>,
    },
}

impl fmt::Display for StaticCountSveThreadContractErrorV3 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "FRE Count-v3 SVE current-thread contract failed: {self:?}"
        )
    }
}

impl std::error::Error for StaticCountSveThreadContractErrorV3 {}

/// Failure at a same-thread SVE/SVE2 production or qualification call
/// boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum StaticCountSveCallErrorV3 {
    ThreadContract(StaticCountSveThreadContractErrorV3),
    Count(StaticCountCallErrorV3),
}

impl fmt::Display for StaticCountSveCallErrorV3 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "FRE Count-v3 SVE call failed: {self:?}")
    }
}

impl std::error::Error for StaticCountSveCallErrorV3 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ThreadContract(error) => Some(error),
            Self::Count(error) => Some(error),
        }
    }
}

impl From<StaticCountSveThreadContractErrorV3> for StaticCountSveCallErrorV3 {
    fn from(value: StaticCountSveThreadContractErrorV3) -> Self {
        Self::ThreadContract(value)
    }
}

impl From<StaticCountCallErrorV3> for StaticCountSveCallErrorV3 {
    fn from(value: StaticCountCallErrorV3) -> Self {
        Self::Count(value)
    }
}
