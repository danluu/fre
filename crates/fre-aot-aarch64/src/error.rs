use core::fmt;

/// Compiler-owned resource enforced before emission, hashing, or audit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CountAotResource {
    CodeBytes,
    DataBytes,
    Labels,
    Relocations,
    Work,
    ScratchBytes,
    PersistentBytes,
}

/// Checked arithmetic site in the typed Count backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CountAotArithmeticSite {
    Prospective,
    CodeOffset,
    ImageLayout,
    Relocation,
    Identity,
    Audit,
    Persistent,
}

/// Unsupported semantic or target contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CountAotUnsupported {
    Output,
    LiteralWidth,
    KernelShape,
    BackendTuple,
}

/// Typed refusal from Count AOT preflight, emission, identity, or audit.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CountAotError {
    ResourceLimit {
        resource: CountAotResource,
        limit: u64,
        required: u64,
    },
    ArithmeticOverflow {
        site: CountAotArithmeticSite,
    },
    Unsupported {
        reason: CountAotUnsupported,
    },
    AllocationFailed {
        resource: CountAotResource,
    },
    InvalidImage {
        at: &'static str,
    },
    UnknownInstruction {
        offset: u32,
        word: u32,
    },
    InternalInvariant {
        at: &'static str,
    },
}

impl fmt::Display for CountAotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "FRE AArch64 Count AOT failed: {self:?}")
    }
}

impl std::error::Error for CountAotError {}
