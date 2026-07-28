use fre::{
    AggregateCountExactLiteralAotIdentityProjectionAccounting,
    AggregateCountExactLiteralAotPlanningAccounting,
    AggregateCountExactLiteralAotPlanningReceiptIdentity,
    AggregateCountExactLiteralAotSemanticBindingIdentity, LiteralAggregateBuildAccounting,
};
use fre_aot_aarch64::{
    AotCountArtifactIdentityV2, AotCountBackendSupportV2, AotCountImageBuildReceiptV2,
    AotCountImageStatsV2, CountAuditReportV2, CountProspectiveReportV2,
};
use fre_aot_macho::{
    AbiKind, BindingIdentity, BuiltCountObjectV2, CountCompileIdentityV2, CountObjectBuildReportV2,
    CountObjectIdentityV2, CountObjectInspectionV2, MetadataV2, inspect_count_object_v2,
};
use fre_kernel_ir::{AggregateProgramIdentity, ResourceAccounting};

use crate::{
    canonical::{
        CANONICAL_TRAVERSAL_FIXED_WORK_V2, CURRENT_IDENTITY_SCRATCH_BYTES_UPPER_BOUND_V2,
        CanonicalEncoder, CanonicalError, IDENTITY_HASH_FINALIZE_WORK_V2,
    },
    error::{ReceiptMismatch, ReceiptValidationError},
    identity::{
        CompileReceiptIdentity, LiveLiteralIdentity, ManifestIdentity, ResourceReceiptIdentity,
    },
    manifest_v2::{
        AOT_COMPILE_RECEIPT_SCHEMA_VERSION_V2, AOT_COUNT_COMPILER_SUPPORT_V2,
        MacosAarch64CountManifestV2,
    },
    receipt::{
        KernelBuildAccountingV1, encode_construction_actual, encode_construction_prospective,
    },
    static_expectation_v2::{
        StaticCountExpectationBuildReportV2, StaticCountExpectationV2,
        build_static_count_expectation_v2,
    },
};

const RECEIPT_DOMAIN_V2: &[u8] = b"FRE-AOT-COMPILER-RECEIPT\0\x02";
const RESOURCE_RECEIPT_DOMAIN_V2: &[u8] = b"FRE-AOT-COMPILER-RESOURCE-RECEIPT\0\x02";

/// Exact multiplicities and byte widths for every compiler-owned v2 identity
/// traversal. Counting passes are charged just like hashing passes; hashing
/// passes additionally pay an explicit SHA-256 finalize envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompilerIdentityAccountingV2 {
    manifest_canonical_bytes: u64,
    manifest_authentication_hash_passes: u8,
    policy_limits_canonical_bytes: u64,
    policy_limits_hash_passes: u8,
    literal_identity_bytes: u64,
    literal_hash_passes: u8,
    object_binding_canonical_bytes: u64,
    object_binding_hash_passes: u8,
    resource_receipt_canonical_bytes: u64,
    resource_receipt_count_passes: u8,
    resource_receipt_hash_passes: u8,
    compile_receipt_canonical_bytes: u64,
    compile_receipt_count_passes: u8,
    compile_receipt_hash_passes: u8,
    canonical_bytes_traversed: u64,
    traversal_fixed_work: u64,
    hash_finalize_work: u64,
    total_work_upper_bound: u64,
    identity_scratch_bytes_upper_bound: u64,
}

impl CompilerIdentityAccountingV2 {
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "each argument is one exact canonical body width bound to the typed receipt"
    )]
    pub(crate) fn current(
        manifest_canonical_bytes: u64,
        policy_limits_canonical_bytes: u64,
        literal_identity_bytes: u64,
        object_binding_canonical_bytes: u64,
        resource_receipt_canonical_bytes: u64,
        compile_receipt_canonical_bytes: u64,
    ) -> Result<Self, CanonicalError> {
        const MANIFEST_HASH_PASSES: u8 = 1;
        const POLICY_LIMITS_HASH_PASSES: u8 = 1;
        const LITERAL_HASH_PASSES: u8 = 1;
        const OBJECT_BINDING_HASH_PASSES: u8 = 1;
        const RESOURCE_COUNT_PASSES: u8 = 2;
        const RESOURCE_HASH_PASSES: u8 = 1;
        const RECEIPT_COUNT_PASSES: u8 = 2;
        const RECEIPT_HASH_PASSES: u8 = 1;
        const RESOURCE_TRAVERSAL_PASSES: u64 = 3;
        const RECEIPT_TRAVERSAL_PASSES: u64 = 3;
        const TOTAL_TRAVERSAL_PASSES: u64 = 10;
        const TOTAL_HASH_PASSES: u64 = 6;

        let canonical_bytes_traversed = manifest_canonical_bytes
            .checked_add(policy_limits_canonical_bytes)
            .and_then(|work| work.checked_add(literal_identity_bytes))
            .and_then(|work| work.checked_add(object_binding_canonical_bytes))
            .and_then(|work| {
                weighted_bytes(resource_receipt_canonical_bytes, RESOURCE_TRAVERSAL_PASSES)
                    .ok()
                    .and_then(|value| work.checked_add(value))
            })
            .and_then(|work| {
                weighted_bytes(compile_receipt_canonical_bytes, RECEIPT_TRAVERSAL_PASSES)
                    .ok()
                    .and_then(|value| work.checked_add(value))
            })
            .ok_or(CanonicalError::ByteCountOverflow)?;
        let traversal_fixed_work = TOTAL_TRAVERSAL_PASSES
            .checked_mul(CANONICAL_TRAVERSAL_FIXED_WORK_V2)
            .ok_or(CanonicalError::ByteCountOverflow)?;
        let hash_finalize_work = TOTAL_HASH_PASSES
            .checked_mul(IDENTITY_HASH_FINALIZE_WORK_V2)
            .ok_or(CanonicalError::ByteCountOverflow)?;
        let total_work_upper_bound = canonical_bytes_traversed
            .checked_add(traversal_fixed_work)
            .and_then(|work| work.checked_add(hash_finalize_work))
            .ok_or(CanonicalError::ByteCountOverflow)?;
        Ok(Self {
            manifest_canonical_bytes,
            manifest_authentication_hash_passes: MANIFEST_HASH_PASSES,
            policy_limits_canonical_bytes,
            policy_limits_hash_passes: POLICY_LIMITS_HASH_PASSES,
            literal_identity_bytes,
            literal_hash_passes: LITERAL_HASH_PASSES,
            object_binding_canonical_bytes,
            object_binding_hash_passes: OBJECT_BINDING_HASH_PASSES,
            resource_receipt_canonical_bytes,
            resource_receipt_count_passes: RESOURCE_COUNT_PASSES,
            resource_receipt_hash_passes: RESOURCE_HASH_PASSES,
            compile_receipt_canonical_bytes,
            compile_receipt_count_passes: RECEIPT_COUNT_PASSES,
            compile_receipt_hash_passes: RECEIPT_HASH_PASSES,
            canonical_bytes_traversed,
            traversal_fixed_work,
            hash_finalize_work,
            total_work_upper_bound,
            identity_scratch_bytes_upper_bound: CURRENT_IDENTITY_SCRATCH_BYTES_UPPER_BOUND_V2,
        })
    }

    pub(crate) const fn empty() -> Self {
        Self {
            manifest_canonical_bytes: 0,
            manifest_authentication_hash_passes: 0,
            policy_limits_canonical_bytes: 0,
            policy_limits_hash_passes: 0,
            literal_identity_bytes: 0,
            literal_hash_passes: 0,
            object_binding_canonical_bytes: 0,
            object_binding_hash_passes: 0,
            resource_receipt_canonical_bytes: 0,
            resource_receipt_count_passes: 0,
            resource_receipt_hash_passes: 0,
            compile_receipt_canonical_bytes: 0,
            compile_receipt_count_passes: 0,
            compile_receipt_hash_passes: 0,
            canonical_bytes_traversed: 0,
            traversal_fixed_work: 0,
            hash_finalize_work: 0,
            total_work_upper_bound: 0,
            identity_scratch_bytes_upper_bound: 0,
        }
    }

    #[must_use]
    pub const fn manifest_canonical_bytes(&self) -> u64 {
        self.manifest_canonical_bytes
    }
    #[must_use]
    pub const fn manifest_authentication_hash_passes(&self) -> u8 {
        self.manifest_authentication_hash_passes
    }
    #[must_use]
    pub const fn policy_limits_canonical_bytes(&self) -> u64 {
        self.policy_limits_canonical_bytes
    }
    #[must_use]
    pub const fn policy_limits_hash_passes(&self) -> u8 {
        self.policy_limits_hash_passes
    }
    #[must_use]
    pub const fn literal_identity_bytes(&self) -> u64 {
        self.literal_identity_bytes
    }
    #[must_use]
    pub const fn literal_hash_passes(&self) -> u8 {
        self.literal_hash_passes
    }
    #[must_use]
    pub const fn object_binding_canonical_bytes(&self) -> u64 {
        self.object_binding_canonical_bytes
    }
    #[must_use]
    pub const fn object_binding_hash_passes(&self) -> u8 {
        self.object_binding_hash_passes
    }
    #[must_use]
    pub const fn resource_receipt_canonical_bytes(&self) -> u64 {
        self.resource_receipt_canonical_bytes
    }
    #[must_use]
    pub const fn resource_receipt_count_passes(&self) -> u8 {
        self.resource_receipt_count_passes
    }
    #[must_use]
    pub const fn resource_receipt_hash_passes(&self) -> u8 {
        self.resource_receipt_hash_passes
    }
    #[must_use]
    pub const fn compile_receipt_canonical_bytes(&self) -> u64 {
        self.compile_receipt_canonical_bytes
    }
    #[must_use]
    pub const fn compile_receipt_count_passes(&self) -> u8 {
        self.compile_receipt_count_passes
    }
    #[must_use]
    pub const fn compile_receipt_hash_passes(&self) -> u8 {
        self.compile_receipt_hash_passes
    }
    #[must_use]
    pub const fn canonical_bytes_traversed(&self) -> u64 {
        self.canonical_bytes_traversed
    }
    #[must_use]
    pub const fn traversal_fixed_work(&self) -> u64 {
        self.traversal_fixed_work
    }
    #[must_use]
    pub const fn hash_finalize_work(&self) -> u64 {
        self.hash_finalize_work
    }
    #[must_use]
    pub const fn total_work_upper_bound(&self) -> u64 {
        self.total_work_upper_bound
    }
    #[must_use]
    pub const fn identity_scratch_bytes_upper_bound(&self) -> u64 {
        self.identity_scratch_bytes_upper_bound
    }
}

fn weighted_bytes(bytes: u64, passes: u64) -> Result<u64, CanonicalError> {
    bytes
        .checked_mul(passes)
        .ok_or(CanonicalError::ByteCountOverflow)
}

/// Accounting for the mandatory post-publication v2 object validation pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectValidationAccountingV2 {
    inspection_work: u64,
    image_audit_work_upper_bound: u64,
    image_binding_work_upper_bound: u64,
    total_work_upper_bound: u64,
    object_scratch_bytes_upper_bound: u64,
    image_audit_scratch_upper_bound: u64,
    scratch_bytes_upper_bound: u64,
    image_audit: CountAuditReportV2,
}

impl ObjectValidationAccountingV2 {
    #[must_use]
    pub const fn inspection_work(&self) -> u64 {
        self.inspection_work
    }

    #[must_use]
    pub const fn image_audit_work_upper_bound(&self) -> u64 {
        self.image_audit_work_upper_bound
    }

    #[must_use]
    pub const fn image_binding_work_upper_bound(&self) -> u64 {
        self.image_binding_work_upper_bound
    }

    #[must_use]
    pub const fn total_work_upper_bound(&self) -> u64 {
        self.total_work_upper_bound
    }

    #[must_use]
    pub const fn scratch_bytes_upper_bound(&self) -> u64 {
        self.scratch_bytes_upper_bound
    }

    #[must_use]
    pub const fn object_scratch_bytes_upper_bound(&self) -> u64 {
        self.object_scratch_bytes_upper_bound
    }

    #[must_use]
    pub const fn image_audit_scratch_upper_bound(&self) -> u64 {
        self.image_audit_scratch_upper_bound
    }

    #[must_use]
    pub const fn image_audit(&self) -> CountAuditReportV2 {
        self.image_audit
    }

    pub(crate) fn new(
        inspection_work: u64,
        image_audit_work_upper_bound: u64,
        image_binding_work_upper_bound: u64,
        object_scratch_bytes_upper_bound: u64,
        image_audit_scratch_upper_bound: u64,
        scratch_bytes_upper_bound: u64,
        image_audit: CountAuditReportV2,
    ) -> Result<Self, CanonicalError> {
        let total_work_upper_bound = inspection_work
            .checked_add(image_audit_work_upper_bound)
            .and_then(|work| work.checked_add(image_binding_work_upper_bound))
            .ok_or(CanonicalError::ByteCountOverflow)?;
        if object_scratch_bytes_upper_bound
            .checked_add(image_audit_scratch_upper_bound)
            .ok_or(CanonicalError::ByteCountOverflow)?
            != scratch_bytes_upper_bound
        {
            return Err(CanonicalError::ByteCountOverflow);
        }
        Ok(Self {
            inspection_work,
            image_audit_work_upper_bound,
            image_binding_work_upper_bound,
            total_work_upper_bound,
            object_scratch_bytes_upper_bound,
            image_audit_scratch_upper_bound,
            scratch_bytes_upper_bound,
            image_audit,
        })
    }
}

/// Conservative co-live accounting for the explicit compiler-v2 stages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PipelineLiveAccountingV2 {
    facade_live_persistent_bytes: usize,
    facade_high_water_bytes: usize,
    kir_retained_bytes: usize,
    image_retained_bytes: usize,
    image_inline_bytes: usize,
    object_retained_bytes: usize,
    compiled_object_inline_bytes: usize,
    static_expectation_inline_bytes: usize,
    identity_scratch_bytes_upper_bound: u64,
    planning_peak_live_bytes: u64,
    kir_peak_live_bytes: u64,
    image_peak_live_bytes: u64,
    object_peak_live_bytes: u64,
    identity_peak_live_bytes: u64,
    expectation_peak_live_bytes: u64,
    final_peak_live_bytes: u64,
    pipeline_peak_live_bytes_upper_bound: u64,
}

impl PipelineLiveAccountingV2 {
    #[must_use]
    pub const fn facade_live_persistent_bytes(&self) -> usize {
        self.facade_live_persistent_bytes
    }

    #[must_use]
    pub const fn facade_high_water_bytes(&self) -> usize {
        self.facade_high_water_bytes
    }

    #[must_use]
    pub const fn kir_retained_bytes(&self) -> usize {
        self.kir_retained_bytes
    }

    #[must_use]
    pub const fn image_retained_bytes(&self) -> usize {
        self.image_retained_bytes
    }

    #[must_use]
    pub const fn image_inline_bytes(&self) -> usize {
        self.image_inline_bytes
    }

    #[must_use]
    pub const fn object_retained_bytes(&self) -> usize {
        self.object_retained_bytes
    }

    #[must_use]
    pub const fn compiled_object_inline_bytes(&self) -> usize {
        self.compiled_object_inline_bytes
    }

    #[must_use]
    pub const fn static_expectation_inline_bytes(&self) -> usize {
        self.static_expectation_inline_bytes
    }

    #[must_use]
    pub const fn identity_scratch_bytes_upper_bound(&self) -> u64 {
        self.identity_scratch_bytes_upper_bound
    }

    #[must_use]
    pub const fn planning_peak_live_bytes(&self) -> u64 {
        self.planning_peak_live_bytes
    }

    #[must_use]
    pub const fn kir_peak_live_bytes(&self) -> u64 {
        self.kir_peak_live_bytes
    }

    #[must_use]
    pub const fn image_peak_live_bytes(&self) -> u64 {
        self.image_peak_live_bytes
    }

    #[must_use]
    pub const fn object_peak_live_bytes(&self) -> u64 {
        self.object_peak_live_bytes
    }

    #[must_use]
    pub const fn identity_peak_live_bytes(&self) -> u64 {
        self.identity_peak_live_bytes
    }

    #[must_use]
    pub const fn expectation_peak_live_bytes(&self) -> u64 {
        self.expectation_peak_live_bytes
    }

    #[must_use]
    pub const fn final_peak_live_bytes(&self) -> u64 {
        self.final_peak_live_bytes
    }

    #[must_use]
    pub const fn pipeline_peak_live_bytes_upper_bound(&self) -> u64 {
        self.pipeline_peak_live_bytes_upper_bound
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the crate-private constructor names every compiler-v2 co-live component"
    )]
    pub(crate) const fn new(
        facade_live_persistent_bytes: usize,
        facade_high_water_bytes: usize,
        kir_retained_bytes: usize,
        image_retained_bytes: usize,
        image_inline_bytes: usize,
        object_retained_bytes: usize,
        compiled_object_inline_bytes: usize,
        static_expectation_inline_bytes: usize,
        identity_scratch_bytes_upper_bound: u64,
        planning_peak_live_bytes: u64,
        kir_peak_live_bytes: u64,
        image_peak_live_bytes: u64,
        object_peak_live_bytes: u64,
        identity_peak_live_bytes: u64,
        expectation_peak_live_bytes: u64,
        final_peak_live_bytes: u64,
        pipeline_peak_live_bytes_upper_bound: u64,
    ) -> Self {
        Self {
            facade_live_persistent_bytes,
            facade_high_water_bytes,
            kir_retained_bytes,
            image_retained_bytes,
            image_inline_bytes,
            object_retained_bytes,
            compiled_object_inline_bytes,
            static_expectation_inline_bytes,
            identity_scratch_bytes_upper_bound,
            planning_peak_live_bytes,
            kir_peak_live_bytes,
            image_peak_live_bytes,
            object_peak_live_bytes,
            identity_peak_live_bytes,
            expectation_peak_live_bytes,
            final_peak_live_bytes,
            pipeline_peak_live_bytes_upper_bound,
        }
    }
}

/// Lossless composition of the frontend, KIR, direct-AOT image, independent
/// image audit, Mach-O publication, and post-publication validation receipts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompileAccountingV2 {
    planning: AggregateCountExactLiteralAotPlanningAccounting,
    candidate_identity_projection: AggregateCountExactLiteralAotIdentityProjectionAccounting,
    candidate_build: LiteralAggregateBuildAccounting,
    kernel_build: KernelBuildAccountingV1,
    image_prospective: CountProspectiveReportV2,
    image_stats: AotCountImageStatsV2,
    image_build_receipt: AotCountImageBuildReceiptV2,
    object_report: CountObjectBuildReportV2,
    object_validation: ObjectValidationAccountingV2,
    source_utf8_validation_work: u64,
    static_expectation_build: StaticCountExpectationBuildReportV2,
    compiler_identity: CompilerIdentityAccountingV2,
    compiler_identity_work: u64,
    reported_pipeline_work_upper_bound: u64,
    final_persistent_bytes: usize,
    peak_scratch_bytes_upper_bound: u64,
    pipeline_live: PipelineLiveAccountingV2,
}

impl CompileAccountingV2 {
    #[must_use]
    pub const fn planning(&self) -> AggregateCountExactLiteralAotPlanningAccounting {
        self.planning
    }

    #[must_use]
    pub const fn candidate_identity_projection(
        &self,
    ) -> AggregateCountExactLiteralAotIdentityProjectionAccounting {
        self.candidate_identity_projection
    }

    #[must_use]
    pub const fn candidate_build(&self) -> LiteralAggregateBuildAccounting {
        self.candidate_build
    }

    #[must_use]
    pub const fn kernel_build(&self) -> KernelBuildAccountingV1 {
        self.kernel_build
    }

    #[must_use]
    pub const fn image_prospective(&self) -> CountProspectiveReportV2 {
        self.image_prospective
    }

    #[must_use]
    pub const fn image_stats(&self) -> AotCountImageStatsV2 {
        self.image_stats
    }

    #[must_use]
    pub const fn image_build_receipt(&self) -> AotCountImageBuildReceiptV2 {
        self.image_build_receipt
    }

    #[must_use]
    pub const fn image_audit(&self) -> CountAuditReportV2 {
        self.image_build_receipt.audit
    }

    #[must_use]
    pub const fn object_report(&self) -> CountObjectBuildReportV2 {
        self.object_report
    }

    #[must_use]
    pub const fn object_validation(&self) -> ObjectValidationAccountingV2 {
        self.object_validation
    }

    #[must_use]
    pub const fn source_utf8_validation_work(&self) -> u64 {
        self.source_utf8_validation_work
    }

    #[must_use]
    pub const fn static_expectation_build(&self) -> StaticCountExpectationBuildReportV2 {
        self.static_expectation_build
    }

    #[must_use]
    pub const fn compiler_identity(&self) -> CompilerIdentityAccountingV2 {
        self.compiler_identity
    }

    #[must_use]
    pub const fn compiler_identity_work(&self) -> u64 {
        self.compiler_identity_work
    }

    #[must_use]
    pub const fn reported_pipeline_work_upper_bound(&self) -> u64 {
        self.reported_pipeline_work_upper_bound
    }

    #[must_use]
    pub const fn final_persistent_bytes(&self) -> usize {
        self.final_persistent_bytes
    }

    #[must_use]
    pub const fn peak_scratch_bytes_upper_bound(&self) -> u64 {
        self.peak_scratch_bytes_upper_bound
    }

    #[must_use]
    pub const fn pipeline_live(&self) -> PipelineLiveAccountingV2 {
        self.pipeline_live
    }

    #[allow(
        clippy::large_types_passed_by_value,
        clippy::too_many_arguments,
        reason = "all exact stage receipts enter this crate-private lossless adapter"
    )]
    pub(crate) const fn draft(
        planning: AggregateCountExactLiteralAotPlanningAccounting,
        candidate_identity_projection: AggregateCountExactLiteralAotIdentityProjectionAccounting,
        candidate_build: LiteralAggregateBuildAccounting,
        kernel_build: KernelBuildAccountingV1,
        image_prospective: CountProspectiveReportV2,
        image_stats: AotCountImageStatsV2,
        image_build_receipt: AotCountImageBuildReceiptV2,
        object_report: CountObjectBuildReportV2,
        object_validation: ObjectValidationAccountingV2,
        source_utf8_validation_work: u64,
        static_expectation_build: StaticCountExpectationBuildReportV2,
        final_persistent_bytes: usize,
        peak_scratch_bytes_upper_bound: u64,
        pipeline_live: PipelineLiveAccountingV2,
    ) -> Self {
        Self {
            planning,
            candidate_identity_projection,
            candidate_build,
            kernel_build,
            image_prospective,
            image_stats,
            image_build_receipt,
            object_report,
            object_validation,
            source_utf8_validation_work,
            static_expectation_build,
            compiler_identity: CompilerIdentityAccountingV2::empty(),
            compiler_identity_work: 0,
            reported_pipeline_work_upper_bound: 0,
            final_persistent_bytes,
            peak_scratch_bytes_upper_bound,
            pipeline_live,
        }
    }

    pub(crate) fn close(
        &mut self,
        compiler_identity: CompilerIdentityAccountingV2,
    ) -> Result<(), CanonicalError> {
        self.compiler_identity = compiler_identity;
        self.compiler_identity_work = compiler_identity.total_work_upper_bound();
        self.reported_pipeline_work_upper_bound = self
            .planning
            .construction_actual()
            .work
            .checked_add(self.source_utf8_validation_work)
            .and_then(|work| work.checked_add(self.kernel_build.total_work_upper_bound()))
            .and_then(|work| work.checked_add(self.image_stats.total_work_upper_bound))
            .and_then(|work| work.checked_add(self.object_report.total_work_upper_bound))
            .and_then(|work| work.checked_add(self.object_validation.total_work_upper_bound))
            .and_then(|work| work.checked_add(self.compiler_identity_work))
            .and_then(|work| work.checked_add(self.static_expectation_build.work_upper_bound()))
            .ok_or(CanonicalError::ByteCountOverflow)?;
        Ok(())
    }
}

/// Non-forgeable receipt for the explicit direct-Count compiler-v2 path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompileReceiptV2 {
    manifest: MacosAarch64CountManifestV2,
    support: AotCountBackendSupportV2,
    semantic_binding_identity: AggregateCountExactLiteralAotSemanticBindingIdentity,
    planning_receipt_identity: AggregateCountExactLiteralAotPlanningReceiptIdentity,
    live_literal_identity: LiveLiteralIdentity,
    live_literal_bytes: u32,
    program_identity: AggregateProgramIdentity,
    image_identity: AotCountArtifactIdentityV2,
    object_binding_identity: BindingIdentity,
    metadata: MetadataV2,
    compile_identity: CountCompileIdentityV2,
    object_identity: CountObjectIdentityV2,
    accounting: CompileAccountingV2,
    resource_receipt_identity: ResourceReceiptIdentity,
    receipt_identity: CompileReceiptIdentity,
}

impl CompileReceiptV2 {
    #[must_use]
    pub const fn manifest(&self) -> MacosAarch64CountManifestV2 {
        self.manifest
    }

    #[must_use]
    pub const fn manifest_identity(&self) -> ManifestIdentity {
        self.manifest.identity()
    }

    #[must_use]
    pub const fn support(&self) -> AotCountBackendSupportV2 {
        self.support
    }

    #[must_use]
    pub const fn semantic_binding_identity(
        &self,
    ) -> AggregateCountExactLiteralAotSemanticBindingIdentity {
        self.semantic_binding_identity
    }

    #[must_use]
    pub const fn planning_receipt_identity(
        &self,
    ) -> AggregateCountExactLiteralAotPlanningReceiptIdentity {
        self.planning_receipt_identity
    }

    #[must_use]
    pub const fn source_identity(&self) -> AggregateCountExactLiteralAotSemanticBindingIdentity {
        self.semantic_binding_identity
    }

    #[must_use]
    pub const fn live_literal_identity(&self) -> LiveLiteralIdentity {
        self.live_literal_identity
    }

    #[must_use]
    pub const fn live_literal_bytes(&self) -> u32 {
        self.live_literal_bytes
    }

    #[must_use]
    pub const fn program_identity(&self) -> AggregateProgramIdentity {
        self.program_identity
    }

    #[must_use]
    pub const fn image_identity(&self) -> AotCountArtifactIdentityV2 {
        self.image_identity
    }

    #[must_use]
    pub const fn object_binding_identity(&self) -> BindingIdentity {
        self.object_binding_identity
    }

    #[must_use]
    pub const fn metadata(&self) -> MetadataV2 {
        self.metadata
    }

    #[must_use]
    pub const fn compile_identity(&self) -> CountCompileIdentityV2 {
        self.compile_identity
    }

    #[must_use]
    pub const fn object_identity(&self) -> CountObjectIdentityV2 {
        self.object_identity
    }

    #[must_use]
    pub const fn accounting(&self) -> CompileAccountingV2 {
        self.accounting
    }

    #[must_use]
    pub const fn resource_receipt_identity(&self) -> ResourceReceiptIdentity {
        self.resource_receipt_identity
    }

    #[must_use]
    pub const fn receipt_identity(&self) -> CompileReceiptIdentity {
        self.receipt_identity
    }

    /// Strictly inspect arbitrary bytes and bind all externally persisted
    /// object, compile, binding, metadata, and complete-file identities.
    ///
    /// The compiler additionally runs `validate_count_object_v2` while the
    /// typed KIR and image are live; its audit is retained in `accounting`.
    pub fn validate_object_bytes<'a>(
        &self,
        bytes: &'a [u8],
    ) -> Result<CountObjectInspectionV2<'a>, ReceiptValidationError> {
        if !self.authenticates_itself() {
            return Err(ReceiptValidationError::Mismatch {
                field: ReceiptMismatch::ReceiptIdentity,
            });
        }
        let inspection = inspect_count_object_v2(bytes, self.manifest.policy().object)?;
        if !self
            .object_identity
            .matches_claim(inspection.claimed_object_identity())
        {
            return Err(ReceiptValidationError::Mismatch {
                field: ReceiptMismatch::ObjectIdentity,
            });
        }
        if !self
            .compile_identity
            .matches_claim(inspection.claimed_compile_identity())
        {
            return Err(ReceiptValidationError::Mismatch {
                field: ReceiptMismatch::CompileIdentity,
            });
        }
        if !self
            .object_binding_identity
            .matches_claim(inspection.metadata().claimed_binding_identity())
        {
            return Err(ReceiptValidationError::Mismatch {
                field: ReceiptMismatch::BindingIdentity,
            });
        }
        if inspection.metadata() != self.metadata {
            return Err(ReceiptValidationError::Mismatch {
                field: ReceiptMismatch::Metadata,
            });
        }
        if inspection.object_bytes() != self.accounting.object_report.object_bytes {
            return Err(ReceiptValidationError::Mismatch {
                field: ReceiptMismatch::ObjectBytes,
            });
        }
        Ok(inspection)
    }

    #[allow(
        clippy::large_types_passed_by_value,
        clippy::too_many_arguments,
        reason = "every independently authenticated compiler-v2 identity enters the private constructor"
    )]
    pub(crate) const fn unsealed(
        manifest: MacosAarch64CountManifestV2,
        support: AotCountBackendSupportV2,
        semantic_binding_identity: AggregateCountExactLiteralAotSemanticBindingIdentity,
        planning_receipt_identity: AggregateCountExactLiteralAotPlanningReceiptIdentity,
        live_literal_identity: LiveLiteralIdentity,
        live_literal_bytes: u32,
        program_identity: AggregateProgramIdentity,
        image_identity: AotCountArtifactIdentityV2,
        object_binding_identity: BindingIdentity,
        metadata: MetadataV2,
        compile_identity: CountCompileIdentityV2,
        object_identity: CountObjectIdentityV2,
        accounting: CompileAccountingV2,
    ) -> Self {
        Self {
            manifest,
            support,
            semantic_binding_identity,
            planning_receipt_identity,
            live_literal_identity,
            live_literal_bytes,
            program_identity,
            image_identity,
            object_binding_identity,
            metadata,
            compile_identity,
            object_identity,
            accounting,
            resource_receipt_identity: ResourceReceiptIdentity::new([0; 32]),
            receipt_identity: CompileReceiptIdentity::new([0; 32]),
        }
    }

    pub(crate) fn canonical_body_bytes(&self) -> Result<u64, CanonicalError> {
        let mut encoder = CanonicalEncoder::counting();
        encode_receipt_body_v2(&mut encoder, self)?;
        Ok(encoder.bytes_written())
    }

    pub(crate) fn resource_receipt_body_bytes(&self) -> Result<u64, CanonicalError> {
        let mut encoder = CanonicalEncoder::counting();
        encoder.raw(RESOURCE_RECEIPT_DOMAIN_V2)?;
        encode_accounting_v2(&mut encoder, &self.accounting)?;
        Ok(encoder.bytes_written())
    }

    #[allow(
        clippy::large_types_passed_by_value,
        reason = "the closed accounting value is moved once into its sealed receipt"
    )]
    pub(crate) fn replace_accounting(&mut self, accounting: CompileAccountingV2) {
        self.accounting = accounting;
    }

    pub(crate) fn seal_resource_receipt(&mut self) -> Result<(), CanonicalError> {
        self.resource_receipt_identity = compute_resource_receipt_identity(&self.accounting)?;
        Ok(())
    }

    pub(crate) fn seal(&mut self) -> Result<(), CanonicalError> {
        self.receipt_identity = self.recompute_identity()?;
        Ok(())
    }

    /// Consume the only mutable receipt state and produce the private witness
    /// required by `CompiledObjectV2`. Identities are computed exactly once
    /// here; subsequent compiler construction never re-hashes the receipt.
    pub(crate) fn seal_for_compiled_object(
        mut self,
        object: &BuiltCountObjectV2,
    ) -> Result<SealedCompileReceiptV2, ReceiptValidationError> {
        self.seal_resource_receipt()
            .map_err(|_| ReceiptValidationError::ArithmeticOverflow)?;
        self.seal()
            .map_err(|_| ReceiptValidationError::ArithmeticOverflow)?;
        if self.support != AOT_COUNT_COMPILER_SUPPORT_V2
            || self.support != self.manifest.support()
            || self.accounting.image_build_receipt.support != self.support
            || !self.structurally_matches_built_object(object)
        {
            return Err(ReceiptValidationError::Mismatch {
                field: ReceiptMismatch::Metadata,
            });
        }
        Ok(SealedCompileReceiptV2(self))
    }

    pub(crate) fn authenticates_itself(&self) -> bool {
        self.manifest.authenticates_itself()
            && self.support == AOT_COUNT_COMPILER_SUPPORT_V2
            && self.support == self.manifest.support()
            && self.accounting.image_build_receipt.support == self.support
            && compute_resource_receipt_identity(&self.accounting)
                .is_ok_and(|identity| identity == self.resource_receipt_identity)
            && self
                .recompute_identity()
                .is_ok_and(|identity| identity == self.receipt_identity)
    }

    fn recompute_identity(&self) -> Result<CompileReceiptIdentity, CanonicalError> {
        #[cfg(test)]
        receipt_hash_trace::record();
        let mut encoder = CanonicalEncoder::hashing();
        encode_receipt_body_v2(&mut encoder, self)?;
        Ok(CompileReceiptIdentity::new(encoder.finish()?.bytes))
    }

    fn structurally_matches_built_object(&self, object: &BuiltCountObjectV2) -> bool {
        self.metadata == object.metadata()
            && self.compile_identity == object.compile_identity()
            && self.object_identity == object.object_identity()
            && self.accounting.object_report == object.report()
            && self
                .object_binding_identity
                .matches_claim(object.metadata().claimed_binding_identity())
    }
}

/// Private typestate proving that the resource and receipt identities were
/// sealed from the final accounting and that all object fields matched.
pub(crate) struct SealedCompileReceiptV2(CompileReceiptV2);

impl SealedCompileReceiptV2 {
    pub(crate) const fn receipt(&self) -> &CompileReceiptV2 {
        &self.0
    }

    pub(crate) const fn resource_receipt_identity(&self) -> ResourceReceiptIdentity {
        self.0.resource_receipt_identity
    }

    pub(crate) const fn receipt_identity(&self) -> CompileReceiptIdentity {
        self.0.receipt_identity
    }

    pub(crate) fn into_inner(self) -> CompileReceiptV2 {
        self.0
    }
}

/// Inert Mach-O bytes plus compiler-v2 receipt and unsigned static expectation.
#[derive(Debug, Eq, PartialEq)]
pub struct CompiledObjectV2 {
    object: BuiltCountObjectV2,
    receipt: CompileReceiptV2,
    static_expectation: StaticCountExpectationV2,
}

impl CompiledObjectV2 {
    #[must_use]
    pub const fn object(&self) -> &BuiltCountObjectV2 {
        &self.object
    }

    #[must_use]
    pub const fn receipt(&self) -> &CompileReceiptV2 {
        &self.receipt
    }

    #[must_use]
    pub const fn static_count_expectation(&self) -> &StaticCountExpectationV2 {
        &self.static_expectation
    }

    #[allow(
        clippy::large_types_passed_by_value,
        reason = "the object and sealed receipt are moved into one immutable compiler result"
    )]
    pub(crate) fn new(
        object: BuiltCountObjectV2,
        sealed_receipt: SealedCompileReceiptV2,
        expected_expectation_report: StaticCountExpectationBuildReportV2,
    ) -> Result<Self, ReceiptValidationError> {
        let static_expectation =
            build_static_count_expectation_v2(&sealed_receipt, expected_expectation_report)
                .map_err(|_| ReceiptValidationError::ArithmeticOverflow)?;
        let receipt = sealed_receipt.into_inner();
        Ok(Self {
            object,
            receipt,
            static_expectation,
        })
    }
}

fn compute_resource_receipt_identity(
    accounting: &CompileAccountingV2,
) -> Result<ResourceReceiptIdentity, CanonicalError> {
    #[cfg(test)]
    resource_receipt_hash_trace::record();
    let mut encoder = CanonicalEncoder::hashing();
    encoder.raw(RESOURCE_RECEIPT_DOMAIN_V2)?;
    encode_accounting_v2(&mut encoder, accounting)?;
    Ok(ResourceReceiptIdentity::new(encoder.finish()?.bytes))
}

fn encode_receipt_body_v2(
    encoder: &mut CanonicalEncoder,
    receipt: &CompileReceiptV2,
) -> Result<(), CanonicalError> {
    encoder.raw(RECEIPT_DOMAIN_V2)?;
    encoder.u16(AOT_COMPILE_RECEIPT_SCHEMA_VERSION_V2)?;
    encoder.raw(receipt.manifest.identity().as_bytes())?;
    encode_support(encoder, receipt.support)?;
    encoder.raw(receipt.semantic_binding_identity.as_bytes())?;
    encoder.raw(receipt.planning_receipt_identity.as_bytes())?;
    encoder.raw(receipt.live_literal_identity.as_bytes())?;
    encoder.u32(receipt.live_literal_bytes)?;
    encoder.raw(receipt.program_identity.as_bytes())?;
    encoder.raw(receipt.image_identity.as_bytes())?;
    encoder.raw(receipt.object_binding_identity.as_bytes())?;
    encode_metadata_v2(encoder, receipt.metadata)?;
    encoder.raw(receipt.compile_identity.as_bytes())?;
    encoder.raw(receipt.object_identity.as_bytes())?;
    encode_accounting_v2(encoder, &receipt.accounting)?;
    encoder.raw(receipt.resource_receipt_identity.as_bytes())
}

pub(crate) fn encode_accounting_v2(
    encoder: &mut CanonicalEncoder,
    accounting: &CompileAccountingV2,
) -> Result<(), CanonicalError> {
    let planning = accounting.planning;
    encoder.u64(planning.source_bytes())?;
    encoder.usize(planning.source_capacity_bytes())?;
    let syntax_prospective = planning.syntax_prospective();
    encoder.u64(syntax_prospective.source_bytes)?;
    encoder.u64(syntax_prospective.max_observed_work)?;
    encoder.u64(syntax_prospective.max_hir_nodes)?;
    encoder.u64(syntax_prospective.max_nesting)?;
    encoder.u64(syntax_prospective.max_traversal_stack_items)?;
    encoder.u8(syntax_prospective.max_source_admission_checks)?;
    encoder.u8(syntax_prospective.max_configuration_checks)?;
    encoder.u8(syntax_prospective.max_opaque_parser_invocations)?;
    let syntax_actual = planning.syntax_actual();
    encoder.u8(syntax_actual.source_admission_checks)?;
    encoder.u8(syntax_actual.configuration_checks)?;
    encoder.u8(syntax_actual.opaque_parser_invocations)?;
    encoder.u64(syntax_actual.availability_work)?;
    encoder.u64(syntax_actual.hir_summary_work)?;
    encoder.u64(syntax_actual.observed_work)?;
    encoder.u64(syntax_actual.hir_nodes)?;
    encoder.u64(syntax_actual.literal_bytes)?;
    encoder.u64(syntax_actual.class_ranges)?;
    encoder.u64(syntax_actual.captures)?;
    encoder.u64(syntax_actual.repetitions)?;
    encoder.u64(syntax_actual.max_depth)?;
    encoder.u64(syntax_actual.traversal_stack_peak)?;
    encode_construction_prospective(encoder, planning.construction_prospective())?;
    encode_construction_actual(encoder, planning.construction_actual())?;
    encoder.u8(planning.construction_ledger_entries())?;
    encoder.u64(planning.report_planner_work())?;
    encoder.usize(planning.report_retained_capacity_bytes())?;
    encoder.u64(planning.identity_bytes_hashed())?;

    let projection = accounting.candidate_identity_projection;
    encoder.u64(projection.semantic_identity_bytes_hashed())?;
    encoder.u64(projection.planning_identity_bytes_hashed())?;
    encoder.u64(projection.projection_work_upper_bound())?;
    encoder.u64(projection.scratch_bytes_upper_bound())?;
    encoder.u8(projection.allocations())?;

    let candidate = accounting.candidate_build;
    encoder.usize(candidate.needle_bytes)?;
    encoder.usize(candidate.temporary_capacity_bytes)?;
    encoder.u64(candidate.work_upper_bound)?;
    encoder.usize(candidate.scratch_bytes)?;
    encoder.usize(candidate.persistent_bytes)?;
    encoder.usize(candidate.peak_bytes)?;

    encode_kernel_build(encoder, accounting.kernel_build)?;
    encode_prospective(encoder, accounting.image_prospective)?;
    encode_image_stats(encoder, accounting.image_stats)?;
    encode_image_build_receipt(encoder, accounting.image_build_receipt)?;
    encode_count_object_report_v2(encoder, accounting.object_report)?;
    encode_object_validation(encoder, accounting.object_validation)?;
    encoder.u64(accounting.source_utf8_validation_work)?;
    encode_static_expectation_build(encoder, accounting.static_expectation_build)?;
    encode_compiler_identity(encoder, accounting.compiler_identity)?;
    encoder.u64(accounting.compiler_identity_work)?;
    encoder.u64(accounting.reported_pipeline_work_upper_bound)?;
    encoder.usize(accounting.final_persistent_bytes)?;
    encoder.u64(accounting.peak_scratch_bytes_upper_bound)?;
    encode_pipeline_live(encoder, accounting.pipeline_live)
}

fn encode_compiler_identity(
    encoder: &mut CanonicalEncoder,
    identity: CompilerIdentityAccountingV2,
) -> Result<(), CanonicalError> {
    encoder.u64(identity.manifest_canonical_bytes)?;
    encoder.u8(identity.manifest_authentication_hash_passes)?;
    encoder.u64(identity.policy_limits_canonical_bytes)?;
    encoder.u8(identity.policy_limits_hash_passes)?;
    encoder.u64(identity.literal_identity_bytes)?;
    encoder.u8(identity.literal_hash_passes)?;
    encoder.u64(identity.object_binding_canonical_bytes)?;
    encoder.u8(identity.object_binding_hash_passes)?;
    encoder.u64(identity.resource_receipt_canonical_bytes)?;
    encoder.u8(identity.resource_receipt_count_passes)?;
    encoder.u8(identity.resource_receipt_hash_passes)?;
    encoder.u64(identity.compile_receipt_canonical_bytes)?;
    encoder.u8(identity.compile_receipt_count_passes)?;
    encoder.u8(identity.compile_receipt_hash_passes)?;
    encoder.u64(identity.canonical_bytes_traversed)?;
    encoder.u64(identity.traversal_fixed_work)?;
    encoder.u64(identity.hash_finalize_work)?;
    encoder.u64(identity.total_work_upper_bound)?;
    encoder.u64(identity.identity_scratch_bytes_upper_bound)
}

fn encode_static_expectation_build(
    encoder: &mut CanonicalEncoder,
    report: StaticCountExpectationBuildReportV2,
) -> Result<(), CanonicalError> {
    encoder.u64(report.canonical_bytes_hashed())?;
    encoder.u64(report.canonical_bytes_traversed())?;
    encoder.u8(report.canonical_count_passes())?;
    encoder.u8(report.canonical_hash_passes())?;
    encoder.u64(report.work_upper_bound())?;
    encoder.u64(report.scratch_bytes_upper_bound())?;
    encoder.usize(report.retained_bytes())?;
    encoder.u8(report.allocations())
}

fn encode_kernel_build(
    encoder: &mut CanonicalEncoder,
    kernel_build: KernelBuildAccountingV1,
) -> Result<(), CanonicalError> {
    let shape = kernel_build.search_shape();
    encoder.usize(shape.blocks())?;
    encoder.usize(shape.instructions())?;
    encoder.usize(shape.data_blobs())?;
    encoder.usize(shape.data_bytes())?;
    encoder.usize(shape.serialized_bytes())?;
    encoder.usize(shape.estimated_code_bytes())?;
    encoder.u64(shape.validation_work())?;
    encoder.u64(shape.work_factor())?;
    encode_kernel_resources(encoder, kernel_build.resources())
}

fn encode_kernel_resources(
    encoder: &mut CanonicalEncoder,
    resources: ResourceAccounting,
) -> Result<(), CanonicalError> {
    encoder.u16(resources.version())?;
    encoder.u8(resources.allocation_requests())?;
    encoder.usize(resources.literal_allocation_request_bytes())?;
    encoder.usize(resources.block_allocation_request_bytes())?;
    encoder.usize(resources.data_table_allocation_request_bytes())?;
    encoder.usize(resources.raw_allocation_request_bytes())?;
    encoder.usize(resources.serialized_allocation_request_bytes())?;
    encoder.usize(resources.allocation_request_bytes())?;
    encoder.usize(resources.literal_capacity_bytes())?;
    encoder.usize(resources.block_capacity_bytes())?;
    encoder.usize(resources.data_table_capacity_bytes())?;
    encoder.usize(resources.raw_program_capacity_bytes())?;
    encoder.usize(resources.serialized_capacity_bytes())?;
    encoder.u64(resources.planning_work())?;
    encoder.u64(resources.initialization_work())?;
    encoder.u64(resources.copy_work())?;
    encoder.u8(resources.hash_invocations())?;
    encoder.u64(resources.hash_work())?;
    encoder.u64(resources.validation_work())?;
    encoder.u64(resources.validation_work_upper_bound())?;
    encoder.u64(resources.construction_work())?;
    encoder.usize(resources.validation_scratch_bytes())?;
    encoder.usize(resources.validation_phase_peak_bytes())?;
    encoder.usize(resources.serialization_phase_peak_bytes())?;
    encoder.usize(resources.identity_phase_peak_bytes())?;
    encoder.usize(resources.retained_program_bytes())
}

fn encode_prospective(
    encoder: &mut CanonicalEncoder,
    report: CountProspectiveReportV2,
) -> Result<(), CanonicalError> {
    encoder.u64(report.code_bytes_upper_bound)?;
    encoder.u64(report.data_bytes_upper_bound)?;
    encoder.u64(report.labels_upper_bound)?;
    encoder.u64(report.relocations_upper_bound)?;
    encoder.u64(report.identity_bytes_hashed_upper_bound)?;
    encoder.u64(report.audit_work_upper_bound)?;
    encoder.u64(report.audit_scratch_bytes_upper_bound)?;
    encoder.u64(report.emission_scratch_bytes_upper_bound)?;
    encoder.u64(report.image_backing_bytes_upper_bound)?;
    encoder.u64(report.total_work_upper_bound)?;
    encoder.u64(report.scratch_bytes_upper_bound)?;
    encoder.u64(report.persistent_bytes_upper_bound)
}

fn encode_image_stats(
    encoder: &mut CanonicalEncoder,
    stats: AotCountImageStatsV2,
) -> Result<(), CanonicalError> {
    encoder.u32(stats.code_bytes)?;
    encoder.u32(stats.data_bytes)?;
    encoder.u32(stats.labels)?;
    encoder.u32(stats.relocations)?;
    encoder.u32(stats.emitted_instructions)?;
    encoder.u32(stats.vector_instructions)?;
    encoder.u8(stats.candidate_filter_bytes)?;
    encoder.u8(stats.confirmation_chunks)?;
    encoder.u8(stats.confirmation_tail_bytes)?;
    encoder.u64(stats.emission_work)?;
    encoder.u64(stats.identity_bytes_hashed)?;
    encoder.u64(stats.audit_work_upper_bound)?;
    encoder.u64(stats.total_work_upper_bound)?;
    encoder.u64(stats.scratch_bytes_upper_bound)
}

fn encode_image_build_receipt(
    encoder: &mut CanonicalEncoder,
    receipt: AotCountImageBuildReceiptV2,
) -> Result<(), CanonicalError> {
    encode_support(encoder, receipt.support)?;
    encoder.usize(receipt.code_capacity_bytes)?;
    encoder.usize(receipt.label_capacity_bytes)?;
    encoder.usize(receipt.relocation_capacity_bytes)?;
    encoder.usize(receipt.retained_heap_bytes)?;
    encoder.usize(receipt.inline_bytes)?;
    encoder.u64(receipt.emission_peak_scratch_bytes)?;
    encoder.u64(receipt.work_upper_bound)?;
    encoder.u64(receipt.scratch_bytes_upper_bound)?;
    encode_count_audit(encoder, receipt.audit)
}

pub(crate) fn encode_support(
    encoder: &mut CanonicalEncoder,
    support: AotCountBackendSupportV2,
) -> Result<(), CanonicalError> {
    crate::manifest_v2::encode_support(encoder, support)
}

fn encode_count_audit(
    encoder: &mut CanonicalEncoder,
    audit: CountAuditReportV2,
) -> Result<(), CanonicalError> {
    encoder.u32(audit.decode_passes)?;
    encoder.u32(audit.source_identity_rebuilds)?;
    encoder.u32(audit.instructions)?;
    encoder.u32(audit.direct_branches)?;
    encoder.u32(audit.vector_instructions)?;
    encoder.u32(audit.simd_candidate_blocks)?;
    encoder.u32(audit.staged_filter_checks)?;
    encoder.u32(audit.sparse_lane_recoveries)?;
    encoder.u32(audit.stores)?;
    encoder.u32(audit.returns)?;
    encoder.u64(audit.work_upper_bound)?;
    encoder.u64(audit.scratch_bytes_upper_bound)
}

fn encode_object_validation(
    encoder: &mut CanonicalEncoder,
    validation: ObjectValidationAccountingV2,
) -> Result<(), CanonicalError> {
    encoder.u64(validation.inspection_work)?;
    encoder.u64(validation.image_audit_work_upper_bound)?;
    encoder.u64(validation.image_binding_work_upper_bound)?;
    encoder.u64(validation.total_work_upper_bound)?;
    encoder.u64(validation.object_scratch_bytes_upper_bound)?;
    encoder.u64(validation.image_audit_scratch_upper_bound)?;
    encoder.u64(validation.scratch_bytes_upper_bound)?;
    encode_count_audit(encoder, validation.image_audit)
}

pub(crate) fn encode_metadata_v2(
    encoder: &mut CanonicalEncoder,
    metadata: MetadataV2,
) -> Result<(), CanonicalError> {
    encoder.u16(metadata.format_version())?;
    encoder.u16(metadata.record_bytes())?;
    encoder.u16(metadata.backend_version())?;
    encoder.u16(metadata.algorithm_version())?;
    encoder.u16(metadata.kir_semantics_version())?;
    encoder.u16(metadata.kir_abi_version())?;
    encoder.u16(metadata.abi_schema())?;
    encoder.u16(metadata.max_literal_bytes())?;
    encoder.u8(match metadata.abi_kind() {
        AbiKind::Search => 1,
        AbiKind::Aggregate => 2,
    })?;
    encoder.u8(metadata.output_kind())?;
    encoder.u8(metadata.architecture())?;
    encoder.boolean(metadata.little_endian())?;
    encoder.u8(metadata.pointer_width())?;
    encoder.u8(metadata.target_abi())?;
    encoder.u8(metadata.platform())?;
    encoder.u8(metadata.status_bits())?;
    encoder.u64(metadata.actual_features())?;
    encoder.u64(metadata.allowed_features())?;
    encoder.u32(metadata.payload_bytes())?;
    encoder.u32(metadata.entry_offset())?;
    encoder.u32(metadata.code_bytes())?;
    encoder.u32(metadata.rodata_offset())?;
    encoder.u32(metadata.rodata_bytes())?;
    encoder.u32(metadata.literal_bytes())?;
    encoder.raw(metadata.source_identity())?;
    encoder.raw(metadata.artifact_identity())?;
    encoder.raw(metadata.claimed_binding_identity().as_bytes())?;
    encoder.raw(metadata.payload_sha256())?;
    encoder.raw(metadata.claimed_compile_identity().as_bytes())
}

fn encode_count_object_report_v2(
    encoder: &mut CanonicalEncoder,
    report: CountObjectBuildReportV2,
) -> Result<(), CanonicalError> {
    encoder.usize(report.object_bytes)?;
    encoder.usize(report.persistent_capacity_bytes)?;
    encoder.usize(report.payload_bytes)?;
    encoder.u64(report.image_audit_work_upper_bound)?;
    encoder.u64(report.image_binding_work_upper_bound)?;
    encoder.u64(report.object_work_upper_bound)?;
    encoder.u64(report.total_work_upper_bound)?;
    encoder.u64(report.object_scratch_bytes_upper_bound)?;
    encoder.u64(report.image_audit_scratch_upper_bound)?;
    encoder.u64(report.scratch_bytes_upper_bound)?;
    encoder.u32(report.sections)?;
    encoder.u32(report.symbols)?;
    encode_count_audit(encoder, report.image_audit)?;
    encoder.raw(report.compile_identity.as_bytes())?;
    encoder.raw(report.object_identity.as_bytes())
}

fn encode_pipeline_live(
    encoder: &mut CanonicalEncoder,
    live: PipelineLiveAccountingV2,
) -> Result<(), CanonicalError> {
    encoder.usize(live.facade_live_persistent_bytes)?;
    encoder.usize(live.facade_high_water_bytes)?;
    encoder.usize(live.kir_retained_bytes)?;
    encoder.usize(live.image_retained_bytes)?;
    encoder.usize(live.image_inline_bytes)?;
    encoder.usize(live.object_retained_bytes)?;
    encoder.usize(live.compiled_object_inline_bytes)?;
    encoder.usize(live.static_expectation_inline_bytes)?;
    encoder.u64(live.identity_scratch_bytes_upper_bound)?;
    encoder.u64(live.planning_peak_live_bytes)?;
    encoder.u64(live.kir_peak_live_bytes)?;
    encoder.u64(live.image_peak_live_bytes)?;
    encoder.u64(live.object_peak_live_bytes)?;
    encoder.u64(live.identity_peak_live_bytes)?;
    encoder.u64(live.expectation_peak_live_bytes)?;
    encoder.u64(live.final_peak_live_bytes)?;
    encoder.u64(live.pipeline_peak_live_bytes_upper_bound)
}

#[cfg(test)]
pub(crate) mod resource_receipt_hash_trace {
    use std::cell::Cell;

    std::thread_local! {
        static HASH_PASSES: Cell<u64> = const { Cell::new(0) };
    }

    pub(crate) fn record() {
        HASH_PASSES.with(|passes| passes.set(passes.get().saturating_add(1)));
    }

    pub(crate) fn reset() {
        HASH_PASSES.with(|passes| passes.set(0));
    }

    pub(crate) fn passes() -> u64 {
        HASH_PASSES.with(Cell::get)
    }
}

#[cfg(test)]
pub(crate) mod receipt_hash_trace {
    use std::cell::Cell;

    std::thread_local! {
        static HASH_PASSES: Cell<u64> = const { Cell::new(0) };
    }

    pub(crate) fn record() {
        HASH_PASSES.with(|passes| passes.set(passes.get().saturating_add(1)));
    }

    pub(crate) fn reset() {
        HASH_PASSES.with(|passes| passes.set(0));
    }

    pub(crate) fn passes() -> u64 {
        HASH_PASSES.with(Cell::get)
    }
}

#[cfg(test)]
mod canonical_tests {
    use fre::RustProfile;

    use super::CompileReceiptV2;
    use crate::{MacosAarch64CountManifestV2, plan_and_compile_macos_aarch64_count_v2};

    fn compile_receipt() -> CompileReceiptV2 {
        let mut profile = RustProfile::default();
        profile.options.unicode = false;
        *plan_and_compile_macos_aarch64_count_v2(
            MacosAarch64CountManifestV2::default(),
            b"receipt-binding".to_vec(),
            profile,
        )
        .expect("compiler-v2 Count AOT compile")
        .receipt()
    }

    fn assert_resealed_accounting_change(
        original: &CompileReceiptV2,
        mut changed: CompileReceiptV2,
    ) {
        changed
            .seal_resource_receipt()
            .expect("reseal changed resource receipt");
        changed.seal().expect("reseal changed compile receipt");
        assert!(changed.authenticates_itself());
        assert_ne!(
            changed.resource_receipt_identity(),
            original.resource_receipt_identity()
        );
        assert_ne!(changed.receipt_identity(), original.receipt_identity());
    }

    #[test]
    fn object_image_binding_work_is_bound_by_resource_and_compile_receipt_identities() {
        let original = compile_receipt();
        let mut changed = original;
        changed
            .accounting
            .object_report
            .image_binding_work_upper_bound += 1;
        changed
            .seal_resource_receipt()
            .expect("reseal changed resource receipt");
        changed.seal().expect("reseal changed compile receipt");

        assert_ne!(
            changed.resource_receipt_identity(),
            original.resource_receipt_identity()
        );
        assert_ne!(changed.receipt_identity(), original.receipt_identity());
    }

    #[test]
    fn typed_count_object_audit_and_validation_fields_are_all_identity_bound() {
        let original = compile_receipt();

        macro_rules! mutate_object_report {
            ($field:ident) => {{
                let mut changed = original;
                changed.accounting.object_report.$field = changed
                    .accounting
                    .object_report
                    .$field
                    .checked_add(1)
                    .unwrap();
                assert_resealed_accounting_change(&original, changed);
            }};
        }
        mutate_object_report!(object_work_upper_bound);
        mutate_object_report!(total_work_upper_bound);
        mutate_object_report!(object_scratch_bytes_upper_bound);
        mutate_object_report!(image_audit_scratch_upper_bound);
        mutate_object_report!(scratch_bytes_upper_bound);

        macro_rules! mutate_object_audit {
            ($field:ident) => {{
                let mut changed = original;
                changed.accounting.object_report.image_audit.$field = changed
                    .accounting
                    .object_report
                    .image_audit
                    .$field
                    .checked_add(1)
                    .unwrap();
                assert_resealed_accounting_change(&original, changed);
            }};
        }
        mutate_object_audit!(decode_passes);
        mutate_object_audit!(source_identity_rebuilds);

        macro_rules! mutate_validation {
            ($field:ident) => {{
                let mut changed = original;
                changed.accounting.object_validation.$field = changed
                    .accounting
                    .object_validation
                    .$field
                    .checked_add(1)
                    .unwrap();
                assert_resealed_accounting_change(&original, changed);
            }};
        }
        mutate_validation!(inspection_work);
        mutate_validation!(image_audit_work_upper_bound);
        mutate_validation!(image_binding_work_upper_bound);
        mutate_validation!(total_work_upper_bound);
        mutate_validation!(object_scratch_bytes_upper_bound);
        mutate_validation!(image_audit_scratch_upper_bound);
        mutate_validation!(scratch_bytes_upper_bound);

        macro_rules! mutate_validation_audit {
            ($field:ident) => {{
                let mut changed = original;
                changed.accounting.object_validation.image_audit.$field = changed
                    .accounting
                    .object_validation
                    .image_audit
                    .$field
                    .checked_add(1)
                    .unwrap();
                assert_resealed_accounting_change(&original, changed);
            }};
        }
        mutate_validation_audit!(decode_passes);
        mutate_validation_audit!(source_identity_rebuilds);

        macro_rules! mutate_image_build_audit {
            ($field:ident) => {{
                let mut changed = original;
                changed.accounting.image_build_receipt.audit.$field = changed
                    .accounting
                    .image_build_receipt
                    .audit
                    .$field
                    .checked_add(1)
                    .unwrap();
                assert_resealed_accounting_change(&original, changed);
            }};
        }
        mutate_image_build_audit!(decode_passes);
        mutate_image_build_audit!(source_identity_rebuilds);
    }

    #[test]
    fn every_compiler_identity_and_final_phase_field_is_bound() {
        let original = compile_receipt();
        let identity = original.accounting.compiler_identity;
        assert_eq!(
            original.canonical_body_bytes().unwrap(),
            identity.compile_receipt_canonical_bytes
        );
        assert_eq!(
            original.resource_receipt_body_bytes().unwrap(),
            identity.resource_receipt_canonical_bytes
        );

        macro_rules! mutate_identity {
            ($field:ident) => {{
                let mut changed = original;
                changed.accounting.compiler_identity.$field = changed
                    .accounting
                    .compiler_identity
                    .$field
                    .checked_add(1)
                    .unwrap();
                assert_resealed_accounting_change(&original, changed);
            }};
        }
        mutate_identity!(manifest_canonical_bytes);
        mutate_identity!(manifest_authentication_hash_passes);
        mutate_identity!(policy_limits_canonical_bytes);
        mutate_identity!(policy_limits_hash_passes);
        mutate_identity!(literal_identity_bytes);
        mutate_identity!(literal_hash_passes);
        mutate_identity!(object_binding_canonical_bytes);
        mutate_identity!(object_binding_hash_passes);
        mutate_identity!(resource_receipt_canonical_bytes);
        mutate_identity!(resource_receipt_count_passes);
        mutate_identity!(resource_receipt_hash_passes);
        mutate_identity!(compile_receipt_canonical_bytes);
        mutate_identity!(compile_receipt_count_passes);
        mutate_identity!(compile_receipt_hash_passes);
        mutate_identity!(canonical_bytes_traversed);
        mutate_identity!(traversal_fixed_work);
        mutate_identity!(hash_finalize_work);
        mutate_identity!(total_work_upper_bound);
        mutate_identity!(identity_scratch_bytes_upper_bound);

        macro_rules! mutate_expectation {
            ($field:ident) => {{
                let mut changed = original;
                changed.accounting.static_expectation_build.$field = changed
                    .accounting
                    .static_expectation_build
                    .$field
                    .checked_add(1)
                    .unwrap();
                assert_resealed_accounting_change(&original, changed);
            }};
        }
        mutate_expectation!(canonical_bytes_hashed);
        mutate_expectation!(canonical_bytes_traversed);
        mutate_expectation!(canonical_count_passes);
        mutate_expectation!(canonical_hash_passes);
        mutate_expectation!(work_upper_bound);
        mutate_expectation!(scratch_bytes_upper_bound);
        mutate_expectation!(retained_bytes);
        mutate_expectation!(allocations);

        macro_rules! mutate_live {
            ($field:ident) => {{
                let mut changed = original;
                changed.accounting.pipeline_live.$field = changed
                    .accounting
                    .pipeline_live
                    .$field
                    .checked_add(1)
                    .unwrap();
                assert_resealed_accounting_change(&original, changed);
            }};
        }
        mutate_live!(static_expectation_inline_bytes);
        mutate_live!(identity_scratch_bytes_upper_bound);
        mutate_live!(identity_peak_live_bytes);
        mutate_live!(expectation_peak_live_bytes);
    }
}
