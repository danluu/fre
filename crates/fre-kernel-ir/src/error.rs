use core::fmt;

/// Resource dimension guarded while validating or lowering a kernel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceKind {
    Blocks,
    Instructions,
    DataBlobs,
    DataBytes,
    SerializedBytes,
    EstimatedCodeBytes,
    ValidationWork,
    ValidationScratchBytes,
    WorkFactor,
}

/// Location of a checked-arithmetic failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArithmeticSite {
    DataBytes,
    SerializedBytes,
    EstimatedCodeBytes,
    ValidationWork,
    WorkFactor,
    SearchWorkBound,
    SearchPosition,
}

/// A structural violation in an untrusted raw kernel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InvalidProgram {
    SchemaVersion { actual: u16 },
    SemanticsVersion { actual: u16 },
    AbiVersion { actual: u16 },
    OutputContract,
    EmptyBlocks,
    EntryOutOfRange,
    EntryIsNotEntry,
    BlockTargetOutOfRange { block: u32, target: u32 },
    DataTargetOutOfRange { block: u32, data: u32 },
    WrongDataKind { block: u32, data: u32 },
    EmptyClass { data: u32 },
    EmptySuffix { data: u32 },
    SuffixOverlapsClass { class: u32, suffix: u32 },
    DuplicateData { first: u32, second: u32 },
    UnusedData { data: u32 },
    UnreachableBlock { block: u32 },
    FlowStateMismatch { block: u32 },
    NonCanonicalTopology { block: u32 },
    InvalidCycle { block: u32 },
    DominanceViolation { dominator: u32, block: u32 },
}

/// Total validation failure for an untrusted raw program.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValidateError {
    Invalid(InvalidProgram),
    ResourceLimit {
        resource: ResourceKind,
        limit: u64,
        required: u64,
    },
    ArithmeticOverflow {
        site: ArithmeticSite,
    },
    AllocationFailed {
        resource: ResourceKind,
    },
}

impl From<InvalidProgram> for ValidateError {
    fn from(value: InvalidProgram) -> Self {
        Self::Invalid(value)
    }
}

impl fmt::Display for ValidateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "kernel validation failed: {self:?}")
    }
}

impl std::error::Error for ValidateError {}

/// Failure while constructing and then validating a known kernel shape.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BuildError {
    Validate(ValidateError),
    AllocationFailed { resource: ResourceKind },
}

impl From<ValidateError> for BuildError {
    fn from(value: ValidateError) -> Self {
        Self::Validate(value)
    }
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "kernel build failed: {self:?}")
    }
}

impl std::error::Error for BuildError {}

/// Checked failure from the portable semantic oracle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecuteError {
    InvalidWindow {
        start: usize,
        end: usize,
        haystack_len: usize,
    },
    WorkLimitExceeded {
        limit: u64,
        consumed: u64,
    },
    ArithmeticOverflow {
        site: ArithmeticSite,
    },
    InternalInvariant {
        block: u32,
    },
}

impl fmt::Display for ExecuteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "kernel execution failed: {self:?}")
    }
}

impl std::error::Error for ExecuteError {}
