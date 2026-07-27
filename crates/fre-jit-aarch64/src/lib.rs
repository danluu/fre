//! Bounded `AArch64` native-image emission for verified FRE Kernel IR.
//!
//! This crate stops at an immutable, position-independent image. It never
//! allocates executable memory and contains no unsafe code. A separate,
//! platform-specific publisher must audit the image again, copy it into a
//! writable mapping, apply the required W^X transition, flush the instruction
//! cache and only then publish an AAPCS64 function pointer.
//!
//! The current unanchored exact-literal backend ranks four deterministic byte
//! columns. It loads the third and fourth columns only while the preceding
//! mask still has multiple candidates, then recovers surviving lanes in exact
//! ascending order. Historical search backend encodings remain versioned and
//! byte-stable.

#![forbid(unsafe_code)]

mod abi;
mod audit;
mod decode;
mod emit;
mod error;
mod image;
mod search_template;

pub use abi::{
    Aapcs64V1, AggregateAapcs64V1, AggregateResultLayout, NativeAggregateResult, NativeResult,
    Register, ResultLayout,
};
pub use audit::{AuditError, AuditReport, audit, audit_aggregate};
pub use decode::{Condition, DecodeError, DecodedInstruction, decode, decode_one};
pub use emit::{
    EmitLimits, MAX_REPEATED_CONFIRM_BYTES, SearchBackendPolicy, emit, emit_exact_aggregate,
    emit_exact_aggregate_sve2_fixed16_count_experimental,
    emit_exact_aggregate_sve2_fixed16_span_sum_experimental, emit_sve2_16, emit_sve16,
    emit_with_backend,
};
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
