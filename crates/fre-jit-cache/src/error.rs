//! Typed construction, admission, and build failures.

use core::fmt;

use fre_jit_runtime::{PublishError, RuntimeIdentity};

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
pub enum CacheError {
    Publish(PublishError),
    Refused {
        resource: CacheResource,
        limit: u64,
        current: u64,
        required: u64,
    },
    BuildPanicked,
    ReentrantBuild {
        identity: RuntimeIdentity,
    },
    BuilderIdentityMismatch {
        expected: RuntimeIdentity,
        actual: RuntimeIdentity,
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

impl fmt::Display for CacheError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "native kernel cache request failed: {self:?}")
    }
}

impl std::error::Error for CacheError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Publish(error) => Some(error),
            _ => None,
        }
    }
}
