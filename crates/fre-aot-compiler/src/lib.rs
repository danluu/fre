//! Authenticated AOT compilation for versioned Count vertical slices and an
//! inert nonempty exact-literal Search V1 compiler candidate.
//!
//! Each source-first entry accepts owned bytes plus a sealed manifest,
//! refuses byte length/capacity before UTF-8 or syntax work, constructs the
//! fixed exact-literal facade plan, rebuilds validated aggregate KIR, and
//! returns deterministic Mach-O bytes with a private-field receipt and cached
//! static expectation. Compiler v1 retains the generic aggregate emitter;
//! compiler v2 explicitly uses the independent direct-Count backend and keeps
//! its typed support, image, audit, and resource receipts. Neither path invokes
//! a linker, loads code, allocates executable memory, or calls generated code.
//!
//! Search V1 is intentionally narrower: macOS emits typed, deterministic V8
//! objects for all three output kinds, while Linux emits authenticated `AArch64`
//! ELF candidates for the default V8 backend and the fixed-VL16 tag21 backend.
//! Every path grants [`SearchAotRuntimeAuthorityV1::Absent`]. V26 exposes
//! source-first, width-9..=32 implementation-object builders for `Exists` and
//! `SelectedEnd` on macOS and Linux; V27/tag40 extends that inert surface to
//! every nonempty width 1..=32 and every literal topology. Separate,
//! versioned manual static-link seams emit output-specific C declarations and
//! one-instruction direct binding objects; they create no expectation,
//! adopter, qualification row, or runtime authority. Span has deterministic
//! platform-specific final-image glue; each unsigned receipt binds compiler,
//! implementation-object, compiler-receipt, expectation, glue, and code
//! identities but still grants no runtime authority or source qualification
//! row. The V1 C header describes Span's two-word success publication only;
//! `Exists` and `SelectedEnd` use only their separate output-specific
//! declarations and remain an explicit authority-free static ABI. This crate
//! consumes `fre` with its default JIT feature disabled, so portable facade
//! authentication does not pull
//! `fre-jit-runtime` into the standalone compiler. The direct
//! `fre-jit-aarch64` dependency is the inert custom machine-code emitter; this
//! crate never publishes its output as executable memory.
//!
//! The parallel Linux tag21 `SelectedEnd` V2 slice is register-return only:
//! source, semantic plan, validated KIR, sealed fixed-VL16 SVE2 image, ELF
//! object, 608-byte neutral expectation, generated direct-call assembly/header,
//! and qualification receipt are all identity-bound. Its private wrapper has
//! one hidden `R_AARCH64_CALL26` `bl` to the exact four-argument entry and no
//! function-pointer API, x4 argument, or result slot. Final-image disassembly
//! remains an explicit pending qualification obligation; no V2 artifact grants
//! runtime or deployment authority. A separate deterministic, receipt-bound
//! Rust consumer module can retain the exact direct symbol call behind the
//! default-off static-runtime same-thread session; this qualification-private
//! candidate likewise grants no production authority.

#![forbid(unsafe_code)]

mod canonical;
mod compiler;
mod compiler_v2;
mod error;
mod identity;
mod manifest;
mod manifest_v2;
mod receipt;
mod receipt_v2;
mod search;
mod search_class_suffix;
mod search_glue;
mod search_linux;
mod search_linux_expectation;
mod search_linux_glue;
mod search_selected_end_bundle_v2;
mod search_selected_end_deployment_v2;
mod search_selected_end_expectation_v2;
mod search_selected_end_v2;
mod search_static_expectation;
mod search_v25_production;
mod search_v26_output;
mod search_v26_production;
mod search_v26_static_abi;
mod search_v27_output;
mod search_v27_production;
mod search_v27_static_abi;
mod static_expectation;
mod static_expectation_v2;

pub use compiler::{compile_macos_aarch64_count_candidate, plan_and_compile_macos_aarch64_count};
pub use compiler_v2::{
    compile_macos_aarch64_count_v2_candidate, plan_and_compile_macos_aarch64_count_v2,
};
pub use error::{
    CandidateContractViolation, CompileArithmeticSite, CompileError, CompileResource,
    ContractField, ReceiptMismatch, ReceiptValidationError,
};
pub use identity::{
    CompileReceiptIdentity, LiveLiteralIdentity, ManifestIdentity, PolicyLimitsIdentity,
    ResourceReceiptIdentity, StaticCountExpectationIdentity,
};
pub use manifest::{
    AOT_AGGREGATE_BACKEND_VERSION_V1, AOT_COMPILER_VERSION_V1, AOT_MANIFEST_SCHEMA_VERSION_V1,
    CompilePolicyV1, MAX_AOT_SOURCE_BYTES_V1, MAX_COMPILER_IDENTITY_WORK_V1,
    MAX_NATIVE_AGGREGATE_AUDIT_WORK_V1, MIN_PIPELINE_PEAK_LIVE_BYTES_V1,
    MacosAarch64CountManifestV1, ManifestError, SUPPORTED_AOT_AGGREGATE_BACKEND_VERSIONS_V1,
};
pub use manifest_v2::{
    AOT_COMPILE_RECEIPT_SCHEMA_VERSION_V2, AOT_COMPILER_VERSION_V2, AOT_COUNT_COMPILER_SUPPORT_V2,
    AOT_MANIFEST_SCHEMA_VERSION_V2, AOT_STATIC_EXPECTATION_SCHEMA_VERSION_V2, CompilePolicyV2,
    MAX_AOT_SOURCE_BYTES_V2, MAX_COMPILER_IDENTITY_WORK_V2, MIN_PIPELINE_PEAK_LIVE_BYTES_V2,
    MacosAarch64CountManifestV2, POLICY_LIMITS_CANONICAL_BYTES_V2,
};
pub use receipt::{
    AOT_COMPILE_RECEIPT_SCHEMA_VERSION_V1, CompileAccountingV1, CompileReceiptV1, CompiledObject,
    KernelBuildAccountingV1, KernelProgramShapeV1, PipelineLiveAccountingV1,
};
pub use receipt_v2::{
    CompileAccountingV2, CompileReceiptV2, CompiledObjectV2, CompilerIdentityAccountingV2,
    ObjectValidationAccountingV2, PipelineLiveAccountingV2,
};
pub use search::{
    AOT_SEARCH_COMPILE_RECEIPT_SCHEMA_VERSION_V1, AOT_SEARCH_COMPILER_VERSION_V1,
    AOT_SEARCH_MANIFEST_SCHEMA_VERSION_V1, MAX_AOT_SEARCH_LITERAL_BYTES_V1,
    MAX_AOT_SEARCH_SOURCE_BYTES_V1, MIN_AOT_SEARCH_LITERAL_BYTES_V1,
    MacosAarch64ExactSearchManifestV1, MacosAarch64SearchBackendV1,
    SEARCH_COMPILE_RECEIPT_CANONICAL_BYTES_V1, SearchAotRuntimeAuthorityV1,
    SearchCompileAccountingV1, SearchCompileErrorV1, SearchCompilePolicyV1,
    SearchCompileReceiptIdentityV1, SearchCompileReceiptV1, SearchCompiledObjectV1,
    SearchLiteralIdentityV1, SearchManifestErrorV1, SearchManifestIdentityV1,
    SearchReceiptMismatchV1, SearchReceiptValidationErrorV1,
    plan_and_compile_macos_aarch64_exact_search_v1,
};
pub use search_class_suffix::{
    AOT_CLASS_SUFFIX_COMPILER_VERSION_V1, CLASS_SUFFIX_MAX_CLASS_RANGES_V1,
    CLASS_SUFFIX_MAX_HIR_NODES_V1, CLASS_SUFFIX_MAX_SOURCE_BYTES_V1,
    CLASS_SUFFIX_MAX_SUFFIX_BYTES_V1, ClassSuffixAotCompileErrorV1, ClassSuffixAotCompiledObjectV1,
    ClassSuffixAotObjectV1, ClassSuffixAotReceiptV1, ClassSuffixAotTargetV1,
    ClassSuffixAotValidationV1, ClassSuffixShapeRefusalV1,
    compile_linux_aarch64_class_suffix_span_v1, compile_macos_aarch64_class_suffix_span_v1,
};
pub use search_glue::{
    PublishedSearchSpanFinalImageGlueV1, SEARCH_SPAN_FINAL_IMAGE_GLUE_CODE_BYTES_V1,
    SEARCH_SPAN_FINAL_IMAGE_GLUE_INSPECTION_ALLOCATIONS_V1,
    SEARCH_SPAN_FINAL_IMAGE_GLUE_RELOCATIONS_V1, SearchSpanFinalImageAdopterV1,
    SearchSpanFinalImageGlueErrorV1, SearchSpanFinalImageGlueInspectionV1,
    SearchSpanFinalImageGlueLimitsV1, SearchSpanFinalImageGlueObjectV1,
    UNSIGNED_SEARCH_SPAN_FINAL_IMAGE_RECEIPT_BYTES_V1, UnsignedSearchSpanFinalImageReceiptV1,
    inspect_search_span_final_image_glue_v1,
    publish_search_span_family_qualification_final_image_glue_v1,
    publish_search_span_final_image_glue_v1, publish_search_span_qualification_final_image_glue_v1,
};
pub use search_linux::{
    AOT_LINUX_SEARCH_COMPILE_RECEIPT_SCHEMA_VERSION_V1, AOT_LINUX_SEARCH_COMPILER_VERSION_V1,
    AOT_LINUX_SEARCH_MANIFEST_SCHEMA_VERSION_V1, LINUX_SEARCH_COMPILE_RECEIPT_CANONICAL_BYTES_V1,
    LinuxAarch64ExactSearchManifestV1, LinuxAarch64SearchBackendV1,
    LinuxAarch64SearchCompilePolicyV1, LinuxSearchCompileErrorV1,
    LinuxSearchCompileReceiptIdentityV1, LinuxSearchCompileReceiptInspectionV1,
    LinuxSearchCompileReceiptV1, LinuxSearchCompiledObjectV1, LinuxSearchLiteralIdentityV1,
    LinuxSearchManifestErrorV1, LinuxSearchManifestIdentityV1,
    compute_linux_search_literal_identity_v1, inspect_linux_search_compile_receipt_v1,
    plan_and_compile_linux_aarch64_exact_search_v1,
};
pub use search_linux_expectation::{
    LinuxStaticSearchSpanExpectationBuildErrorV1, LinuxStaticSearchSpanExpectationIdentityV1,
    LinuxStaticSearchSpanExpectationV1, build_linux_static_search_span_expectation_v1,
};
pub use search_linux_glue::{
    HARD_MAX_LINUX_SEARCH_SPAN_GLUE_OBJECT_BYTES_V1,
    LINUX_SEARCH_SPAN_FINAL_IMAGE_GLUE_CODE_BYTES_V1,
    LINUX_SEARCH_SPAN_FINAL_IMAGE_GLUE_RELOCATIONS_V1,
    LINUX_UNSIGNED_SEARCH_SPAN_FINAL_IMAGE_RECEIPT_BYTES_V1, LinuxSearchSpanFinalImageGlueErrorV1,
    LinuxSearchSpanFinalImageGlueInspectionV1, LinuxSearchSpanFinalImageGlueLimitsV1,
    LinuxSearchSpanFinalImageGlueObjectV1, LinuxSearchSpanFinalImageReceiptIdentityV1,
    LinuxSearchSpanFinalImageSymbolNameV1, LinuxSearchSpanFinalImageSymbolsV1,
    LinuxSearchSpanGlueCodeIdentityV1, LinuxSearchSpanGlueObjectIdentityV1,
    LinuxUnsignedSearchSpanFinalImageReceiptV1, PublishedLinuxSearchSpanFinalImageGlueV1,
    inspect_linux_search_span_final_image_glue_v1,
    publish_linux_search_span_family_qualification_final_image_glue_v1,
    publish_linux_search_span_final_image_glue_v1,
    publish_linux_search_span_qualification_final_image_glue_v1,
};
pub use search_selected_end_bundle_v2::{
    HARD_MAX_LINUX_SELECTED_END_DIRECT_GLUE_OBJECT_BYTES_V2,
    HARD_MAX_LINUX_SELECTED_END_DIRECT_GLUE_SOURCE_BYTES_V2,
    HARD_MAX_LINUX_SELECTED_END_DIRECT_HEADER_BYTES_V2,
    LINUX_SELECTED_END_DIRECT_GLUE_CALL_OFFSET_V2, LINUX_SELECTED_END_DIRECT_GLUE_CODE_BYTES_V2,
    LINUX_SELECTED_END_DIRECT_GLUE_CODE_V2, LINUX_SELECTED_END_DIRECT_GLUE_INSTRUCTIONS_V2,
    LINUX_SELECTED_END_DIRECT_GLUE_RELOCATIONS_V2,
    LINUX_SELECTED_END_QUALIFICATION_RECEIPT_BYTES_V2, LinuxSelectedEndCandidateBundleIdentityV2,
    LinuxSelectedEndDirectGlueCodeIdentityV2, LinuxSelectedEndDirectGlueErrorV2,
    LinuxSelectedEndDirectGlueInspectionV2, LinuxSelectedEndDirectGlueLimitsV2,
    LinuxSelectedEndDirectGlueObjectIdentityV2, LinuxSelectedEndDirectGlueObjectV2,
    LinuxSelectedEndDirectGlueSourceIdentityV2, LinuxSelectedEndDirectGlueSourceV2,
    LinuxSelectedEndDirectHeaderIdentityV2, LinuxSelectedEndDirectHeaderV2,
    LinuxSelectedEndDirectSymbolNameV2, LinuxSelectedEndDirectSymbolsV2,
    LinuxSelectedEndPostLinkDisassemblyRequirementsV2, LinuxSelectedEndQualificationBundleV2,
    LinuxSelectedEndQualificationReceiptV2, POST_LINK_DISASSEMBLY_REQUIREMENTS_V2,
    POST_LINK_REJECT_BLR_V2, POST_LINK_REJECT_PLT_V2, POST_LINK_REJECT_RESULT_SLOT_V2,
    POST_LINK_REJECT_X4_ARGUMENT_V2, POST_LINK_REQUIRE_DIRECT_BL_V2,
    POST_LINK_REQUIRE_HIDDEN_BINDINGS_V2, POST_LINK_REQUIRE_IDENTITY_SUFFIXED_BINDINGS_V2,
    R_AARCH64_CALL26_V2, build_linux_selected_end_qualification_bundle_v2,
    inspect_linux_selected_end_direct_glue_v2,
};
pub use search_selected_end_deployment_v2::{
    HARD_MAX_LINUX_SELECTED_END_QUALIFICATION_RUST_BINDING_BYTES_V2,
    LINUX_SELECTED_END_QUALIFICATION_DEPLOYMENT_RECEIPT_BYTES_V2,
    LinuxSelectedEndQualificationDeploymentErrorV2,
    LinuxSelectedEndQualificationDeploymentLimitsV2,
    LinuxSelectedEndQualificationDeploymentReceiptIdentityV2,
    LinuxSelectedEndQualificationDeploymentReceiptV2, LinuxSelectedEndQualificationDeploymentV2,
    LinuxSelectedEndQualificationRustBindingIdentityV2, LinuxSelectedEndQualificationRustBindingV2,
    build_linux_selected_end_qualification_deployment_v2,
};
pub use search_selected_end_expectation_v2::{
    LinuxStaticSearchSelectedEndExpectationBuildErrorV2,
    LinuxStaticSearchSelectedEndExpectationIdentityV2, LinuxStaticSearchSelectedEndExpectationV2,
    build_linux_static_search_selected_end_expectation_v2,
};
pub use search_selected_end_v2::{
    AOT_LINUX_SELECTED_END_COMPILE_RECEIPT_SCHEMA_VERSION_V2,
    AOT_LINUX_SELECTED_END_COMPILER_VERSION_V2, AOT_LINUX_SELECTED_END_MANIFEST_SCHEMA_VERSION_V2,
    LINUX_SELECTED_END_COMPILE_RECEIPT_BODY_BYTES_V2, LINUX_SELECTED_END_COMPILE_RECEIPT_BYTES_V2,
    LinuxAarch64SelectedEndCompilePolicyV2, LinuxAarch64SelectedEndManifestV2,
    LinuxSelectedEndCompileErrorV2, LinuxSelectedEndCompileReceiptIdentityV2,
    LinuxSelectedEndCompileReceiptInspectionV2, LinuxSelectedEndCompileReceiptV2,
    LinuxSelectedEndCompiledObjectV2, LinuxSelectedEndLiteralIdentityV2,
    LinuxSelectedEndManifestErrorV2, LinuxSelectedEndManifestIdentityV2,
    LinuxSelectedEndSourceIdentityV2, MAX_AOT_LINUX_SELECTED_END_SOURCE_BYTES_V2,
    SelectedEndAotRuntimeAuthorityV2, compute_linux_selected_end_literal_identity_v2,
    compute_linux_selected_end_source_identity_v2, inspect_linux_selected_end_compile_receipt_v2,
    plan_and_compile_linux_aarch64_selected_end_v2,
};
pub use search_static_expectation::{
    STATIC_SEARCH_SPAN_EXPECTATION_BUILD_ALLOCATIONS_V1,
    STATIC_SEARCH_SPAN_EXPECTATION_RETAINED_BYTES_V1, StaticSearchSpanExpectationBuildErrorV1,
    StaticSearchSpanExpectationIdentityV1, StaticSearchSpanExpectationV1,
    build_static_search_span_expectation_v1,
};
pub use search_v25_production::{
    LinuxAarch64SearchV25ProductionSourceV1, MacosAarch64SearchV25ProductionSourceV1,
    SearchV25ProductionSourceErrorV1, build_linux_aarch64_search_v25_production_source_v1,
    build_macos_aarch64_search_v25_production_source_v1,
};
pub use search_v26_output::{
    SearchV26OutputObjectErrorV1, build_linux_aarch64_search_v26_exists_object_v1,
    build_linux_aarch64_search_v26_selected_end_object_v1,
    build_macos_aarch64_search_v26_exists_object_v1,
    build_macos_aarch64_search_v26_selected_end_object_v1,
};
pub use search_v26_production::{
    LinuxAarch64SearchV26ProductionSourceV1, MacosAarch64SearchV26ProductionSourceV1,
    SearchV26ProductionSourceErrorV1, build_linux_aarch64_search_v26_production_source_v1,
    build_macos_aarch64_search_v26_production_source_v1,
};
pub use search_v26_static_abi::{
    HARD_MAX_SEARCH_V26_STATIC_GLUE_OBJECT_BYTES_V1, SEARCH_V26_STATIC_ELF_RELOCATION_V1,
    SEARCH_V26_STATIC_GLUE_CODE_V1, SEARCH_V26_STATIC_GLUE_RELOCATIONS_V1,
    SEARCH_V26_STATIC_MACHO_RELOCATION_V1, SearchV26StaticAbiErrorV1,
    SearchV26StaticBindingClaimsV1, SearchV26StaticBindingV1, SearchV26StaticGlueIdentityV1,
    SearchV26StaticGlueInspectionV1, SearchV26StaticHeaderIdentityV1, SearchV26StaticPlatformV1,
    SearchV26StaticSymbolNameV1, SearchV26StaticSymbolsV1,
    build_linux_aarch64_search_v26_exists_static_binding_v1,
    build_linux_aarch64_search_v26_selected_end_static_binding_v1,
    build_macos_aarch64_search_v26_exists_static_binding_v1,
    build_macos_aarch64_search_v26_selected_end_static_binding_v1,
    inspect_search_v26_static_glue_v1,
};
pub use search_v27_output::{
    SearchV27OutputObjectErrorV1, build_linux_aarch64_search_v27_exists_object_v1,
    build_linux_aarch64_search_v27_selected_end_object_v1,
    build_macos_aarch64_search_v27_exists_object_v1,
    build_macos_aarch64_search_v27_selected_end_object_v1,
};
pub use search_v27_production::{
    LinuxAarch64SearchV27ProductionSourceV1, MacosAarch64SearchV27ProductionSourceV1,
    SearchV27ProductionSourceErrorV1, build_linux_aarch64_search_v27_production_source_v1,
    build_macos_aarch64_search_v27_production_source_v1,
};
pub use search_v27_static_abi::{
    HARD_MAX_SEARCH_V27_STATIC_GLUE_OBJECT_BYTES_V1, SEARCH_V27_STATIC_ELF_RELOCATION_V1,
    SEARCH_V27_STATIC_GLUE_CODE_V1, SEARCH_V27_STATIC_GLUE_RELOCATIONS_V1,
    SEARCH_V27_STATIC_MACHO_RELOCATION_V1, SearchV27StaticAbiErrorV1,
    SearchV27StaticBindingClaimsV1, SearchV27StaticBindingV1, SearchV27StaticGlueIdentityV1,
    SearchV27StaticGlueInspectionV1, SearchV27StaticHeaderIdentityV1, SearchV27StaticPlatformV1,
    SearchV27StaticSymbolNameV1, SearchV27StaticSymbolsV1,
    build_linux_aarch64_search_v27_exists_static_binding_v1,
    build_linux_aarch64_search_v27_selected_end_static_binding_v1,
    build_macos_aarch64_search_v27_exists_static_binding_v1,
    build_macos_aarch64_search_v27_selected_end_static_binding_v1,
    inspect_search_v27_static_glue_v1,
};
pub use static_expectation::{
    ClaimedStaticCountExpectationV1, STATIC_COUNT_EXPECTATION_BYTES_V1,
    STATIC_COUNT_EXPECTATION_CANONICAL_BYTES_HASHED_UPPER_BOUND_V1,
    STATIC_COUNT_EXPECTATION_PROJECTION_SCRATCH_UPPER_BOUND_V1,
    STATIC_COUNT_EXPECTATION_PROJECTION_WORK_UPPER_BOUND_V1,
    STATIC_COUNT_EXPECTATION_RETAINED_BYTES_V1, STATIC_COUNT_EXPECTATION_SCHEMA_VERSION_V1,
    StaticCountExpectationBuildReportV1, StaticCountExpectationError, StaticCountExpectationV1,
    inspect_static_count_expectation_v1,
};
pub use static_expectation_v2::{
    ClaimedStaticCountExpectationV2, STATIC_COUNT_EXPECTATION_BYTES_V2,
    STATIC_COUNT_EXPECTATION_CANONICAL_BYTES_HASHED_UPPER_BOUND_V2,
    STATIC_COUNT_EXPECTATION_CANONICAL_BYTES_TRAVERSED_V2,
    STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V2, STATIC_COUNT_EXPECTATION_METADATA_OFFSET_V2,
    STATIC_COUNT_EXPECTATION_PROJECTION_SCRATCH_UPPER_BOUND_V2,
    STATIC_COUNT_EXPECTATION_PROJECTION_WORK_UPPER_BOUND_V2,
    STATIC_COUNT_EXPECTATION_RETAINED_BYTES_V2, StaticCountExpectationBuildReportV2,
    StaticCountExpectationV2, inspect_static_count_expectation_v2,
};

/// Stable V1 C declarations for generated entries, payload, metadata, status,
/// and metadata layout.
///
/// The Search success-result wording is directly valid only for Span. Inert
/// Exists and `SelectedEnd` Search objects have output-specific stores and this
/// constant does not grant runtime authority for them.
pub const C_BINDINGS_HEADER_V1: &str = fre_aot_macho::C_HEADER;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_v2;
