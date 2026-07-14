//! Verified pattern-specialized kernel IR for FRE native backends.
//!
//! This is deliberately not a regex bytecode virtual machine. A validated
//! program is one of a small number of structured, pattern-specialized native
//! kernels. Blocks describe scan loops, candidate confirmation and terminal
//! results so that an x86-64 or `AArch64` backend can lower them to ordinary
//! control flow and vector instructions. The safe portable interpreter exists
//! only as a semantic oracle for backend differential testing.

#![forbid(unsafe_code)]

mod aggregate;
mod contract;
mod error;
mod interpret;
mod ir;
mod lower;
mod serialize;
mod validate;

pub use aggregate::{
    AggregateBuildError, AggregateExecuteError, AggregateExecutionLimits, AggregateExecutionReport,
    AggregateOperation, AggregateOutput, AggregateProgramIdentity, AggregateUpperBounds, Count,
    ExactAggregateProgram, MAX_EXACT_AGGREGATE_LITERAL_BYTES, SpanSum, build_exact_aggregate,
    exact_aggregate_upper_bounds, preflight_exact_aggregate,
};
pub use contract::{Exists, MatchSpan, Operation, OutputKind, SearchWindow, SelectedEnd, Span};
pub use error::{
    ArithmeticSite, BuildError, ExecuteError, InvalidProgram, ResourceKind, ValidateError,
};
pub use interpret::{ExecutionLimits, ExecutionReport};
pub use ir::{
    AbiVersion, AnchorFlags, Block, BlockId, BlockOp, ByteClass, DataBlob, DataId, RawProgram,
    SemanticsVersion,
};
pub use lower::{build_class_suffix, build_exact_literal};
pub use serialize::{CacheIdentity, SerializedProgram};
pub use validate::{ProgramStats, ValidateLimits, ValidatedProgram};

#[cfg(test)]
mod tests;
