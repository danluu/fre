use core::fmt;

use fre_aot_aarch64::CountAotError;
use fre_aot_optimizer::CountV3OptimizeError;
use fre_kernel_ir::AggregateBuildError;

/// One typed refusal from the focused optimizing Count-v3 compiler.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CountCompileErrorV3 {
    Kernel(AggregateBuildError),
    Optimizer(CountV3OptimizeError),
    Image(CountAotError),
    InvalidSemanticCandidate {
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
    InvalidExpectation {
        at: &'static str,
    },
    InvalidUnsignedReceipt {
        at: &'static str,
    },
}

impl fmt::Display for CountCompileErrorV3 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "focused Count-v3 compilation failed: {self:?}")
    }
}

impl std::error::Error for CountCompileErrorV3 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Kernel(error) => Some(error),
            Self::Optimizer(error) => Some(error),
            Self::Image(error) => Some(error),
            _ => None,
        }
    }
}

impl From<AggregateBuildError> for CountCompileErrorV3 {
    fn from(value: AggregateBuildError) -> Self {
        Self::Kernel(value)
    }
}

impl From<CountV3OptimizeError> for CountCompileErrorV3 {
    fn from(value: CountV3OptimizeError) -> Self {
        Self::Optimizer(value)
    }
}

impl From<CountAotError> for CountCompileErrorV3 {
    fn from(value: CountAotError) -> Self {
        Self::Image(value)
    }
}
