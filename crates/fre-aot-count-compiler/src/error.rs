use core::fmt;

use fre_aot_aarch64::CountAotError;
use fre_kernel_ir::AggregateBuildError;

/// One typed refusal from the focused Count-v2 compiler.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CountCompileErrorV2 {
    Kernel(AggregateBuildError),
    Image(CountAotError),
    ClaimMismatch {
        field: &'static str,
    },
    InvalidClaim {
        field: &'static str,
    },
    ArithmeticOverflow {
        at: &'static str,
    },
    ResourceLimit {
        resource: &'static str,
        limit: u64,
        required: u64,
    },
    AllocationFailed,
    InvalidObject {
        at: &'static str,
    },
    InvalidExpectation,
    InvalidUnsignedReceipt,
    InvalidFinalImageGlue {
        at: &'static str,
    },
    InvalidFinalImageReceipt,
}

impl fmt::Display for CountCompileErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "focused Count-v2 compilation failed: {self:?}")
    }
}

impl std::error::Error for CountCompileErrorV2 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Kernel(error) => Some(error),
            Self::Image(error) => Some(error),
            _ => None,
        }
    }
}

impl From<AggregateBuildError> for CountCompileErrorV2 {
    fn from(value: AggregateBuildError) -> Self {
        Self::Kernel(value)
    }
}

impl From<CountAotError> for CountCompileErrorV2 {
    fn from(value: CountAotError) -> Self {
        Self::Image(value)
    }
}
