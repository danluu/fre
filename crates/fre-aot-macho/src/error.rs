use core::fmt;

use fre_aot_aarch64::CountAotError;
use fre_jit_aarch64::AuditError;

/// Bounded resource selected by object construction or inspection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ObjectResource {
    ObjectBytes,
    PersistentBytes,
    PayloadBytes,
    Work,
    ScratchBytes,
    Sections,
    Symbols,
}

/// Checked arithmetic site in the object format.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ArithmeticSite {
    ImageLayout,
    ObjectLayout,
    FileOffset,
    StringTable,
    Work,
    Conversion,
}

/// Refusal to construct an unauthenticated planner/build binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BindingIdentityError;

impl fmt::Display for BindingIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the FRE AOT binding identity must not be all zero")
    }
}

impl std::error::Error for BindingIdentityError {}

/// Typed refusal from deterministic object construction or strict inspection.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ObjectError {
    ImageAudit(AuditError),
    CountImageAudit(CountAotError),
    ArithmeticOverflow {
        site: ArithmeticSite,
    },
    ResourceLimit {
        resource: ObjectResource,
        limit: u64,
        required: u64,
    },
    AllocationFailed,
    Truncated {
        at: &'static str,
    },
    InvalidObject {
        at: &'static str,
    },
    PayloadDigestMismatch,
    CompileIdentityMismatch,
    ImageBindingMismatch {
        field: &'static str,
    },
    InternalInvariant {
        at: &'static str,
    },
}

impl fmt::Display for ObjectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ImageAudit(error) => write!(formatter, "native image audit failed: {error}"),
            Self::CountImageAudit(error) => {
                write!(formatter, "Count AOT image audit failed: {error}")
            }
            Self::ArithmeticOverflow { site } => {
                write!(formatter, "Mach-O arithmetic overflow at {site:?}")
            }
            Self::ResourceLimit {
                resource,
                limit,
                required,
            } => write!(
                formatter,
                "Mach-O {resource:?} limit {limit} is below required {required}"
            ),
            Self::AllocationFailed => formatter.write_str("Mach-O object allocation failed"),
            Self::Truncated { at } => write!(formatter, "truncated Mach-O object at {at}"),
            Self::InvalidObject { at } => write!(formatter, "invalid Mach-O object at {at}"),
            Self::PayloadDigestMismatch => {
                formatter.write_str("Mach-O payload SHA-256 does not match metadata")
            }
            Self::CompileIdentityMismatch => {
                formatter.write_str("Mach-O compile identity does not match metadata")
            }
            Self::ImageBindingMismatch { field } => {
                write!(
                    formatter,
                    "Mach-O object does not bind the expected {field}"
                )
            }
            Self::InternalInvariant { at } => {
                write!(
                    formatter,
                    "internal Mach-O construction invariant failed at {at}"
                )
            }
        }
    }
}

impl std::error::Error for ObjectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ImageAudit(error) => Some(error),
            Self::CountImageAudit(error) => Some(error),
            _ => None,
        }
    }
}
