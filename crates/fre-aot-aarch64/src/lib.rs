//! Independent bounded `AArch64` AOT backend for exact-literal Count KIR.
//!
//! This crate consumes only the sealed [`fre_kernel_ir::ExactAggregateProgram`]
//! Count type. It emits an immutable inert image with a numerically disjoint
//! aggregate-backend version, a domain-separated artifact identity, and an
//! independently decoded audit receipt. It never constructs a generic JIT
//! image, maps executable memory, invokes a linker, or publishes a function
//! pointer.

#![forbid(unsafe_code)]

mod audit;
mod audit_cfg_v3;
mod audit_v2;
mod audit_v3;
mod emit;
mod emit_v2;
mod emit_v3;
mod error;
mod image;
mod image_v2;
mod image_v3;

pub use audit::{ConditionV1, CountAuditReportV1, DecodedInstructionV1, audit_count_image_v1};
pub use audit_v2::{ConditionV2, CountAuditReportV2, DecodedInstructionV2, audit_count_image_v2};
pub use audit_v3::{
    ConditionV3, CountAuditReportV3, DecodedInstructionV3, audit_count_image_v3,
    audit_count_image_view_v3, audit_count_mapped_code_v3,
};
pub use emit::{CountEmitLimitsV1, CountProspectiveReportV1, emit_count_v1, prospective_count_v1};
pub use emit_v2::{
    CountEmitLimitsV2, CountProspectiveReportV2, emit_count_v2, prospective_count_v2,
};
pub use emit_v3::{
    CountEmitLimitsV3, CountProspectiveReportV3, emit_count_v3, prospective_count_v3,
};
pub use error::{CountAotArithmeticSite, CountAotError, CountAotResource, CountAotUnsupported};
pub use image::{
    AOT_COUNT_BACKEND_ALGORITHM_VERSION_V1, AOT_COUNT_BACKEND_VERSION_V1,
    AOT_COUNT_IMAGE_SCHEMA_VERSION_V1, AOT_COUNT_KIR_ABI_VERSION_V1,
    AOT_COUNT_KIR_SEMANTICS_VERSION_V1, AotCountArtifactIdentity, AotCountBackendSupportV1,
    AotCountBackendVersion, AotCountCpuFeatures, AotCountImageBuildReceiptV1,
    AotCountImageLayoutV1, AotCountImageStatsV1, AotCountImageV1, AotCountLiteralManifestV1,
    AotCountTargetSpec, CodeLabelV1, LabelKindV1, RelocationKindV1, RelocationTargetV1,
    RelocationV1, SUPPORTED_AOT_COUNT_BACKEND_TUPLES_V1, is_supported_aot_count_backend_tuple_v1,
};
pub use image_v2::{
    AOT_COUNT_BACKEND_ALGORITHM_VERSION_SPARSE_V3, AOT_COUNT_BACKEND_ALGORITHM_VERSION_V2,
    AOT_COUNT_BACKEND_VERSION_V2, AOT_COUNT_IMAGE_SCHEMA_VERSION_V2, AOT_COUNT_KIR_ABI_VERSION_V2,
    AOT_COUNT_KIR_SEMANTICS_VERSION_V2, AotCountArtifactIdentityV2, AotCountBackendSupportV2,
    AotCountImageBuildReceiptV2, AotCountImageLayoutV2, AotCountImageStatsV2, AotCountImageV2,
    AotCountLiteralManifestV2, CodeLabelV2, LabelKindV2, RelocationKindV2, RelocationTargetV2,
    RelocationV2, SUPPORTED_AOT_COUNT_BACKEND_TUPLES_V2, is_supported_aot_count_backend_tuple_v2,
};
pub use image_v3::{
    AOT_COUNT_BACKEND_ALGORITHM_VERSION_V3, AOT_COUNT_BACKEND_VERSION_V3,
    AOT_COUNT_CODE_ALIGNMENT_V3, AOT_COUNT_IMAGE_SCHEMA_VERSION_V3, AOT_COUNT_KIR_ABI_VERSION_V3,
    AOT_COUNT_KIR_SEMANTICS_VERSION_V3, AotCountArtifactIdentityV3, AotCountBackendSupportV3,
    AotCountImageBuildReceiptV3, AotCountImageLayoutV3, AotCountImageStatsV3, AotCountImageV3,
    AotCountImageViewV3, AotCountLiteralManifestV3, AotCountMappedMetadataV3,
    AotCountRecipeManifestV3, CodeLabelV3, LabelKindV3, RelocationKindV3, RelocationTargetV3,
    RelocationV3, SUPPORTED_AOT_COUNT_BACKEND_TUPLES_V3, is_supported_aot_count_backend_tuple_v3,
};

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_v2;
#[cfg(test)]
mod tests_v3;
