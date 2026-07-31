use core::fmt;

use fre_aot_compiler::{ReceiptValidationError, StaticCountExpectationError};
use fre_aot_count_contract::{CountMetadataErrorV2, StaticCountExpectationErrorV2};
use fre_aot_macho::ObjectError;

/// One independently authenticated field in the compiler-to-linker contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PrelinkContractFieldV2 {
    CompiledObjectBytes,
    Metadata,
    ObjectAccounting,
    ExpectationAccounting,
    Support,
    ManifestIdentity,
    PolicyLimitsIdentity,
    SemanticBindingIdentity,
    PlanningReceiptIdentity,
    LiveLiteralIdentity,
    LiveLiteralBytes,
    ProgramIdentity,
    ImageIdentity,
    ObjectBindingIdentity,
    CompileIdentity,
    ObjectIdentity,
    ReceiptIdentity,
    ResourceReceiptIdentity,
    ExpectationIdentity,
    NeutralWireContract,
}

/// Failure to authenticate exact compiler output for the static linker.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PrelinkErrorV2 {
    Receipt(ReceiptValidationError),
    Expectation(StaticCountExpectationError),
    Metadata(ObjectError),
    NeutralExpectation(StaticCountExpectationErrorV2),
    NeutralMetadata(CountMetadataErrorV2),
    ContractMismatch { field: PrelinkContractFieldV2 },
    InspectionAccountingOverflow,
}

impl fmt::Display for PrelinkErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "FRE Count-v2 prelink validation failed: {self:?}"
        )
    }
}

impl std::error::Error for PrelinkErrorV2 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Receipt(error) => Some(error),
            Self::Expectation(error) => Some(error),
            Self::Metadata(error) => Some(error),
            Self::NeutralExpectation(error) => Some(error),
            Self::NeutralMetadata(error) => Some(error),
            Self::ContractMismatch { .. } | Self::InspectionAccountingOverflow => None,
        }
    }
}

impl From<ReceiptValidationError> for PrelinkErrorV2 {
    fn from(value: ReceiptValidationError) -> Self {
        Self::Receipt(value)
    }
}

impl From<StaticCountExpectationError> for PrelinkErrorV2 {
    fn from(value: StaticCountExpectationError) -> Self {
        Self::Expectation(value)
    }
}

impl From<ObjectError> for PrelinkErrorV2 {
    fn from(value: ObjectError) -> Self {
        Self::Metadata(value)
    }
}

impl From<StaticCountExpectationErrorV2> for PrelinkErrorV2 {
    fn from(value: StaticCountExpectationErrorV2) -> Self {
        Self::NeutralExpectation(value)
    }
}

impl From<CountMetadataErrorV2> for PrelinkErrorV2 {
    fn from(value: CountMetadataErrorV2) -> Self {
        Self::NeutralMetadata(value)
    }
}

pub(crate) const fn require(
    condition: bool,
    field: PrelinkContractFieldV2,
) -> Result<(), PrelinkErrorV2> {
    if condition {
        Ok(())
    } else {
        Err(PrelinkErrorV2::ContractMismatch { field })
    }
}
