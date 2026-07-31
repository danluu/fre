use core::fmt;

use fre_jit_aarch64::AuditError;

/// Bounded ELF resource whose caller-selected limit was exceeded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ElfObjectResource {
    ObjectBytes,
    PersistentBytes,
    PayloadBytes,
    Work,
}

/// Deterministic object emission or strict inspection refusal.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ElfObjectError {
    ResourceLimit {
        resource: ElfObjectResource,
        limit: u64,
        required: u64,
    },
    AllocationFailed,
    ArithmeticOverflow {
        at: &'static str,
    },
    InvalidObject {
        at: &'static str,
    },
    ImageAudit(AuditError),
    PayloadDigestMismatch,
    CompileIdentityMismatch,
}

impl fmt::Display for ElfObjectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "FRE Linux AArch64 ELF object failure: {self:?}")
    }
}

impl std::error::Error for ElfObjectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ImageAudit(error) => Some(error),
            _ => None,
        }
    }
}
