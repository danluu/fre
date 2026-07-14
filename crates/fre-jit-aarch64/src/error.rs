use core::fmt;

/// Bounded emitter resource dimension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceKind {
    CodeBytes,
    DataBytes,
    Relocations,
    Labels,
    EmissionWork,
    ScratchBytes,
    AotBytes,
}

/// Checked-arithmetic site.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArithmeticSite {
    CodeOffset,
    DataOffset,
    ImageLayout,
    RelocationDisplacement,
    EmissionWork,
    ScratchBytes,
    AotSize,
}

/// `AArch64` PC-relative encoding whose signed range was exceeded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BranchKind {
    Unconditional26,
    Conditional19,
    Compare19,
    Address21,
}

/// Kernel shape or target contract deliberately not admitted by this backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnsupportedReason {
    KernelShape,
    AbiVersion,
    SemanticsVersion,
    OutputContract,
    DataLayout,
}

/// Repeated candidate-confirmation shape subject to the semantic hard cap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfirmationKind {
    ExactLiteral,
    ClassSuffix,
}

/// Total failure from bounded image emission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EmitError {
    ResourceLimit {
        resource: ResourceKind,
        limit: u64,
        required: u64,
    },
    ArithmeticOverflow {
        site: ArithmeticSite,
    },
    BranchOutOfRange {
        kind: BranchKind,
        from: u64,
        to: u64,
        minimum: i64,
        maximum: i64,
    },
    Unsupported {
        reason: UnsupportedReason,
    },
    /// Refusal that keeps repeated naive confirmation a fixed-factor linear
    /// kernel. A higher-level planner must select a proved-linear fallback.
    ConfirmationLengthLimit {
        kind: ConfirmationKind,
        limit: usize,
        required: usize,
    },
    AllocationFailed {
        resource: ResourceKind,
    },
    InternalInvariant,
}

impl fmt::Display for EmitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "AArch64 emission failed: {self:?}")
    }
}

impl std::error::Error for EmitError {}
