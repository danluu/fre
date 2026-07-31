//! Typed construction, admission, and build failures.

use core::fmt;

use fre_jit_aarch64::EmitError;
use fre_jit_runtime::{PublishError, RuntimeIdentity};
use fre_kernel_ir::BuildError;

/// A resource controlled by the cache policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheResource {
    Entries,
    InFlightBuilds,
    LiveMappings,
    MappedBytes,
    PayloadBytes,
    CodeBytes,
    DataBytes,
    Pages,
    BookkeepingBytes,
    PlatformUsize,
    Counter,
}

/// Failure to construct a bounded cache.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CacheCreateError {
    ResourceLimit {
        resource: CacheResource,
        limit: u64,
        required: u64,
    },
    ArithmeticOverflow {
        resource: CacheResource,
    },
    AllocationFailed {
        resource: CacheResource,
        entries: u64,
    },
}

/// Failure of one cache lookup/build request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CacheError<I = RuntimeIdentity> {
    KernelIr(BuildError),
    Emit(EmitError),
    Publish(PublishError),
    RequestLiteralBytes {
        max: usize,
        actual: usize,
    },
    Refused {
        resource: CacheResource,
        limit: u64,
        current: u64,
        required: u64,
    },
    BuildPanicked,
    ReentrantBuild {
        identity: I,
    },
    BuilderIdentityMismatch {
        expected: I,
        actual: I,
    },
    BuilderSharedMapping {
        identity: I,
    },
    BuilderContractMismatch {
        identity: I,
    },
    BuilderPublicationLimit {
        resource: CacheResource,
        limit: u64,
        required: u64,
    },
    AccountingOverflow {
        resource: CacheResource,
    },
}

impl fmt::Display for CacheCreateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "native kernel cache construction failed: {self:?}"
        )
    }
}

impl std::error::Error for CacheCreateError {}

impl<I: fmt::Debug> fmt::Display for CacheError<I> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "native kernel cache request failed: {self:?}")
    }
}

impl<I: fmt::Debug + 'static> std::error::Error for CacheError<I> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::KernelIr(error) => Some(error),
            Self::Emit(error) => Some(error),
            Self::Publish(error) => Some(error),
            _ => None,
        }
    }
}
