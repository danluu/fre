//! Focused, JIT-neutral Count-v2 compiler and implementation-object publisher.
//!
//! The production dependency closure is only typed exact-literal KIR, the
//! independent `AArch64` Count backend, fixed wire contracts, exact allocation,
//! and SHA-256. Planner-provenance fields are untrusted claims: locally
//! reproducible literal, KIR, image, metadata, object, and expectation facts
//! are recomputed. The resulting canonical prelink receipt is unsigned and
//! never authorizes runtime adoption.

#![forbid(unsafe_code)]

mod error;
mod glue;
mod object;
mod receipt;

pub use error::CountCompileErrorV2;
pub use glue::{
    COUNT_FINAL_IMAGE_GLUE_CODE_BYTES_V2, COUNT_FINAL_IMAGE_GLUE_RELOCATIONS_V2,
    CountFinalImageAdopterV2, CountFinalImageGlueInspectionV2, CountFinalImageGlueLimitsV2,
    CountFinalImageGlueObjectV2, PublishedCountFinalImageGlueV2,
    UNSIGNED_COUNT_FINAL_IMAGE_RECEIPT_BYTES_V2, UnsignedCountFinalImageReceiptV2,
    inspect_count_final_image_glue_v2, publish_count_final_image_glue_v2,
    publish_count_qualification_final_image_glue_v2,
};
pub use object::{
    CountImplementationInspectionV2, CountImplementationObjectV2, CountObjectLimitsV2,
    inspect_count_implementation_object_v2,
};
pub use receipt::{
    CountCompileClaimsV2, CountCompileLimitsV2, CountCompileRequestV2, FocusedCompiledCountV2,
    RuntimeAuthorityV2, UNSIGNED_COUNT_PRELINK_RECEIPT_BYTES_V2, UnsignedCountPrelinkReceiptV2,
    compile_count_v2,
};

#[cfg(test)]
mod tests;
