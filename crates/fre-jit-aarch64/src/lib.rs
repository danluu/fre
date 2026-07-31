//! Bounded `AArch64` native-image emission for verified FRE Kernel IR.
//!
//! This crate stops at an immutable, position-independent image. It never
//! allocates executable memory and contains no unsafe code. Finalization runs
//! the independent whole-image auditor. Plain images enter a platform-specific
//! publisher that repeats that same auditor; the repeat detects intervening
//! mutation but adds no independent audit-logic coverage. Fresh emission may
//! instead retain the result as privately constructed [`AuditedNativeImage`]
//! typestate. Both publisher paths copy into a writable mapping, apply the
//! required W^X transition, flush the instruction cache and only then publish
//! an AAPCS64 function pointer.
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
mod selected_end_v2;

pub use abi::{
    Aapcs64V1, AggregateAapcs64V1, AggregateResultLayout, NativeAggregateResult, NativeResult,
    Register, ResultLayout, SelectedEndAapcs64V2,
};
pub use audit::{AuditError, AuditReport, audit, audit_aggregate, audit_selected_end_register_v2};
pub use decode::{Condition, DecodeError, DecodedInstruction, decode, decode_one};
pub use emit::{
    EmitLimits, MAX_REPEATED_CONFIRM_BYTES, SEARCH_V26_MAX_LITERAL_BYTES,
    SEARCH_V26_MIN_LITERAL_BYTES, SEARCH_V26_V17_MAX_LITERAL_BYTES,
    SEARCH_V26_V25_MIN_LITERAL_BYTES, SEARCH_V27_MAX_LITERAL_BYTES, SEARCH_V27_MIN_LITERAL_BYTES,
    SearchBackendPolicy, SearchV26Codegen, SearchV27Codegen, emit, emit_audited_with_backend,
    emit_exact_aggregate, emit_exact_aggregate_sve2_fixed16_count_experimental,
    emit_exact_aggregate_sve2_fixed16_pair_count_experimental,
    emit_exact_aggregate_sve2_fixed16_pair_span_sum_experimental,
    emit_exact_aggregate_sve2_fixed16_span_sum_experimental, emit_selected_end_register_v2,
    emit_sve2_16, emit_sve2_fixed16_v2, emit_sve16, emit_sve16_v6, emit_with_backend,
    search_v26_codegen_for_literal_width,
};
pub use error::{
    ArithmeticSite, BranchKind, ConfirmationKind, EmitError, ResourceKind, UnsupportedReason,
};
pub use image::{
    AotArtifact, AotLimits, ArtifactIdentity, ArtifactIdentityReceipt, AuditedNativeImage,
    BackendVersion, CodeLabel, CpuFeatures, DataSymbol, DataSymbolKind, ImageLayout, ImageStats,
    LabelKind, NativeAggregateImage, NativeImage, Relocation, RelocationKind, RelocationTarget,
    SearchImageShape, TargetSpec,
};
pub use selected_end_v2::{
    AuditedSelectedEndRegisterImageV2, SELECTED_END_REGISTER_CALL_ABI_SCHEMA_V2,
    SELECTED_END_REGISTER_RETURN_ENCODING_V2, SelectedEndRegisterAotArtifactV2,
    SelectedEndRegisterArtifactIdentityV2, SelectedEndRegisterBackendV2,
    selected_end_register_target_v2,
};

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_selected_end_v2;
