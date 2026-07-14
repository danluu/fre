//! Bounded `AArch64` native-image emission for verified FRE Kernel IR.
//!
//! This crate stops at an immutable, position-independent image. It never
//! allocates executable memory and contains no unsafe code. A separate,
//! platform-specific publisher must audit the image again, copy it into a
//! writable mapping, apply the required W^X transition, flush the instruction
//! cache and only then publish an AAPCS64 function pointer.

#![forbid(unsafe_code)]

mod abi;
mod audit;
mod decode;
mod emit;
mod error;
mod image;

pub use abi::{
    Aapcs64V1, AggregateAapcs64V1, AggregateResultLayout, NativeAggregateResult, NativeResult,
    Register, ResultLayout,
};
pub use audit::{AuditError, AuditReport, audit, audit_aggregate};
pub use decode::{Condition, DecodeError, DecodedInstruction, decode, decode_one};
pub use emit::{EmitLimits, MAX_REPEATED_CONFIRM_BYTES, emit, emit_exact_aggregate};
pub use error::{
    ArithmeticSite, BranchKind, ConfirmationKind, EmitError, ResourceKind, UnsupportedReason,
};
pub use image::{
    AotArtifact, AotLimits, ArtifactIdentity, ArtifactIdentityReceipt, BackendVersion, CodeLabel,
    CpuFeatures, DataSymbol, DataSymbolKind, ImageLayout, ImageStats, LabelKind,
    NativeAggregateImage, NativeImage, Relocation, RelocationKind, RelocationTarget, TargetSpec,
};

#[cfg(test)]
mod tests;
