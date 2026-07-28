use fre::{
    AggregateCountExactLiteralAotIdentityProjectionAccounting,
    AggregateCountExactLiteralAotPlanningAccounting,
    AggregateCountExactLiteralAotPlanningReceiptIdentity,
    AggregateCountExactLiteralAotSemanticBindingIdentity, LiteralAggregateBuildAccounting,
};
use fre_aot_macho::{
    AbiKind, BindingIdentity, BuiltObject, CompileIdentity, MetadataV1, ObjectBuildReport,
    ObjectIdentity, ObjectInspection, inspect_object,
};
use fre_jit_aarch64::{ArtifactIdentity, ImageStats};
use fre_kernel_ir::{AggregateProgramIdentity, ResourceAccounting};

use crate::{
    canonical::{CanonicalEncoder, CanonicalError, EncodedDigest},
    error::{ReceiptMismatch, ReceiptValidationError},
    identity::{CompileReceiptIdentity, LiveLiteralIdentity, ManifestIdentity},
    manifest::MacosAarch64CountManifestV1,
    static_expectation::{
        STATIC_COUNT_EXPECTATION_BYTES_V1,
        STATIC_COUNT_EXPECTATION_CANONICAL_BYTES_HASHED_UPPER_BOUND_V1,
        STATIC_COUNT_EXPECTATION_PROJECTION_SCRATCH_UPPER_BOUND_V1,
        STATIC_COUNT_EXPECTATION_PROJECTION_WORK_UPPER_BOUND_V1,
        STATIC_COUNT_EXPECTATION_RETAINED_BYTES_V1, StaticCountExpectationV1,
        build_static_count_expectation,
    },
};

pub const AOT_COMPILE_RECEIPT_SCHEMA_VERSION_V1: u16 = 1;
const RECEIPT_DOMAIN: &[u8] = b"FRE-AOT-COMPILER-RECEIPT\0\x01";

/// Conservative co-live accounting across the complete manifest-first
/// pipeline, including retained earlier stages and active-stage scratch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PipelineLiveAccountingV1 {
    facade_live_persistent_bytes: usize,
    facade_high_water_bytes: usize,
    kir_retained_heap_bytes: usize,
    kir_inline_bytes: usize,
    native_retained_heap_bytes: usize,
    native_inline_bytes: usize,
    native_audit_scratch_upper_bound: u64,
    object_retained_bytes: usize,
    compiled_object_inline_bytes: usize,
    expectation_projection_scratch_upper_bound: u64,
    planning_peak_live_bytes: u64,
    kir_peak_live_bytes: u64,
    native_peak_live_bytes: u64,
    object_peak_live_bytes: u64,
    final_peak_live_bytes: u64,
    pipeline_peak_live_bytes_upper_bound: u64,
}

impl PipelineLiveAccountingV1 {
    #[must_use]
    pub const fn facade_live_persistent_bytes(&self) -> usize {
        self.facade_live_persistent_bytes
    }

    #[must_use]
    pub const fn facade_high_water_bytes(&self) -> usize {
        self.facade_high_water_bytes
    }

    #[must_use]
    pub const fn kir_retained_heap_bytes(&self) -> usize {
        self.kir_retained_heap_bytes
    }

    #[must_use]
    pub const fn native_retained_heap_bytes(&self) -> usize {
        self.native_retained_heap_bytes
    }

    #[must_use]
    pub const fn kir_inline_bytes(&self) -> usize {
        self.kir_inline_bytes
    }

    #[must_use]
    pub const fn native_inline_bytes(&self) -> usize {
        self.native_inline_bytes
    }

    #[must_use]
    pub const fn native_audit_scratch_upper_bound(&self) -> u64 {
        self.native_audit_scratch_upper_bound
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
    pub const fn expectation_projection_scratch_upper_bound(&self) -> u64 {
        self.expectation_projection_scratch_upper_bound
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
    pub const fn native_peak_live_bytes(&self) -> u64 {
        self.native_peak_live_bytes
    }

    #[must_use]
    pub const fn object_peak_live_bytes(&self) -> u64 {
        self.object_peak_live_bytes
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
        reason = "the constructor is crate-private and names every co-live stage component"
    )]
    pub(crate) const fn new(
        facade_live_persistent_bytes: usize,
        facade_high_water_bytes: usize,
        kir_retained_heap_bytes: usize,
        kir_inline_bytes: usize,
        native_retained_heap_bytes: usize,
        native_inline_bytes: usize,
        native_audit_scratch_upper_bound: u64,
        object_retained_bytes: usize,
        compiled_object_inline_bytes: usize,
        expectation_projection_scratch_upper_bound: u64,
        planning_peak_live_bytes: u64,
        kir_peak_live_bytes: u64,
        native_peak_live_bytes: u64,
        object_peak_live_bytes: u64,
        final_peak_live_bytes: u64,
        pipeline_peak_live_bytes_upper_bound: u64,
    ) -> Self {
        Self {
            facade_live_persistent_bytes,
            facade_high_water_bytes,
            kir_retained_heap_bytes,
            kir_inline_bytes,
            native_retained_heap_bytes,
            native_inline_bytes,
            native_audit_scratch_upper_bound,
            object_retained_bytes,
            compiled_object_inline_bytes,
            expectation_projection_scratch_upper_bound,
            planning_peak_live_bytes,
            kir_peak_live_bytes,
            native_peak_live_bytes,
            object_peak_live_bytes,
            final_peak_live_bytes,
            pipeline_peak_live_bytes_upper_bound,
        }
    }
}

/// Narrow structural witness for the sealed exact-Count KIR shape.
///
/// This is derived from the typed program constructor and literal width. It is
/// intentionally local to the compiler instead of reopening generic KIR
/// internals through a broad statistics accessor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelProgramShapeV1 {
    blocks: usize,
    instructions: usize,
    data_blobs: usize,
    data_bytes: usize,
    serialized_bytes: usize,
    estimated_code_bytes: usize,
    validation_work: u64,
    work_factor: u64,
}

impl KernelProgramShapeV1 {
    #[allow(
        clippy::too_many_arguments,
        reason = "the crate-private constructor names the complete fixed-shape witness"
    )]
    pub(crate) const fn new(
        blocks: usize,
        instructions: usize,
        data_blobs: usize,
        data_bytes: usize,
        serialized_bytes: usize,
        estimated_code_bytes: usize,
        validation_work: u64,
        work_factor: u64,
    ) -> Self {
        Self {
            blocks,
            instructions,
            data_blobs,
            data_bytes,
            serialized_bytes,
            estimated_code_bytes,
            validation_work,
            work_factor,
        }
    }

    #[must_use]
    pub const fn blocks(self) -> usize {
        self.blocks
    }

    #[must_use]
    pub const fn instructions(self) -> usize {
        self.instructions
    }

    #[must_use]
    pub const fn data_blobs(self) -> usize {
        self.data_blobs
    }

    #[must_use]
    pub const fn data_bytes(self) -> usize {
        self.data_bytes
    }

    #[must_use]
    pub const fn serialized_bytes(self) -> usize {
        self.serialized_bytes
    }

    #[must_use]
    pub const fn estimated_code_bytes(self) -> usize {
        self.estimated_code_bytes
    }

    #[must_use]
    pub const fn validation_work(self) -> u64 {
        self.validation_work
    }

    #[must_use]
    pub const fn work_factor(self) -> u64 {
        self.work_factor
    }
}

/// Lossless compiler adapter for the accepted KIR resource receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelBuildAccountingV1 {
    shape: KernelProgramShapeV1,
    resources: ResourceAccounting,
}

impl KernelBuildAccountingV1 {
    pub(crate) const fn new(shape: KernelProgramShapeV1, resources: ResourceAccounting) -> Self {
        Self { shape, resources }
    }

    #[must_use]
    pub const fn search_shape(self) -> KernelProgramShapeV1 {
        self.shape
    }

    #[must_use]
    pub const fn resources(self) -> ResourceAccounting {
        self.resources
    }

    #[must_use]
    pub const fn construction_work_upper_bound(self) -> u64 {
        self.resources.construction_work()
    }

    #[must_use]
    pub const fn total_work_upper_bound(self) -> u64 {
        self.resources.construction_work()
    }

    #[must_use]
    pub const fn retained_program_bytes(self) -> usize {
        self.resources.retained_program_bytes()
    }

    #[must_use]
    pub const fn identity_phase_peak_bytes(self) -> usize {
        self.resources.identity_phase_peak_bytes()
    }
}

/// Lossless composition of exact stage receipts and explicitly named bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompileAccountingV1 {
    planning: AggregateCountExactLiteralAotPlanningAccounting,
    candidate_identity_projection: AggregateCountExactLiteralAotIdentityProjectionAccounting,
    candidate_build: LiteralAggregateBuildAccounting,
    kernel_build: KernelBuildAccountingV1,
    native_stats: ImageStats,
    object_report: ObjectBuildReport,
    native_internal_audit_work_upper_bound: u64,
    source_utf8_validation_work: u64,
    manifest_identity_bytes_hashed: u64,
    literal_identity_bytes_hashed: u64,
    object_binding_identity_bytes_hashed: u64,
    receipt_identity_bytes_hashed: u64,
    compiler_identity_work: u64,
    reported_pipeline_work_upper_bound: u64,
    final_persistent_bytes: usize,
    peak_scratch_bytes_upper_bound: u64,
    pipeline_live: PipelineLiveAccountingV1,
}

impl CompileAccountingV1 {
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
    pub const fn kernel_stats(&self) -> KernelProgramShapeV1 {
        self.kernel_build.search_shape()
    }

    #[must_use]
    pub const fn kernel_build(&self) -> KernelBuildAccountingV1 {
        self.kernel_build
    }

    #[must_use]
    pub const fn native_stats(&self) -> ImageStats {
        self.native_stats
    }

    #[must_use]
    pub const fn object_report(&self) -> ObjectBuildReport {
        self.object_report
    }

    #[must_use]
    pub const fn kernel_construction_work_upper_bound(&self) -> u64 {
        self.kernel_build.construction_work_upper_bound()
    }

    #[must_use]
    pub const fn native_internal_audit_work_upper_bound(&self) -> u64 {
        self.native_internal_audit_work_upper_bound
    }

    #[must_use]
    pub const fn source_utf8_validation_work(&self) -> u64 {
        self.source_utf8_validation_work
    }

    #[must_use]
    pub const fn manifest_identity_bytes_hashed(&self) -> u64 {
        self.manifest_identity_bytes_hashed
    }

    #[must_use]
    pub const fn literal_identity_bytes_hashed(&self) -> u64 {
        self.literal_identity_bytes_hashed
    }

    #[must_use]
    pub const fn object_binding_identity_bytes_hashed(&self) -> u64 {
        self.object_binding_identity_bytes_hashed
    }

    #[must_use]
    pub const fn receipt_identity_bytes_hashed(&self) -> u64 {
        self.receipt_identity_bytes_hashed
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
    pub const fn pipeline_live(&self) -> PipelineLiveAccountingV1 {
        self.pipeline_live
    }

    #[must_use]
    pub const fn static_expectation_projection_work_upper_bound(&self) -> u64 {
        STATIC_COUNT_EXPECTATION_PROJECTION_WORK_UPPER_BOUND_V1
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the crate-private draft constructor names every independently authenticated stage receipt and bound"
    )]
    pub(crate) const fn draft(
        planning: &AggregateCountExactLiteralAotPlanningAccounting,
        candidate_identity_projection: AggregateCountExactLiteralAotIdentityProjectionAccounting,
        candidate_build: LiteralAggregateBuildAccounting,
        kernel_build: KernelBuildAccountingV1,
        native_stats: ImageStats,
        object_report: ObjectBuildReport,
        native_internal_audit_work_upper_bound: u64,
        source_utf8_validation_work: u64,
        manifest_identity_bytes_hashed: u64,
        literal_identity_bytes_hashed: u64,
        object_binding_identity_bytes_hashed: u64,
        final_persistent_bytes: usize,
        peak_scratch_bytes_upper_bound: u64,
        pipeline_live: PipelineLiveAccountingV1,
    ) -> Self {
        Self {
            planning: *planning,
            candidate_identity_projection,
            candidate_build,
            kernel_build,
            native_stats,
            object_report,
            native_internal_audit_work_upper_bound,
            source_utf8_validation_work,
            manifest_identity_bytes_hashed,
            literal_identity_bytes_hashed,
            object_binding_identity_bytes_hashed,
            receipt_identity_bytes_hashed: 0,
            compiler_identity_work: 0,
            reported_pipeline_work_upper_bound: 0,
            final_persistent_bytes,
            peak_scratch_bytes_upper_bound,
            pipeline_live,
        }
    }

    pub(crate) fn close(
        &mut self,
        receipt_identity_bytes_hashed: u64,
    ) -> Result<(), CanonicalError> {
        self.receipt_identity_bytes_hashed = receipt_identity_bytes_hashed;
        self.compiler_identity_work = self
            .manifest_identity_bytes_hashed
            .checked_add(self.literal_identity_bytes_hashed)
            .and_then(|work| work.checked_add(self.object_binding_identity_bytes_hashed))
            .and_then(|work| work.checked_add(receipt_identity_bytes_hashed))
            .ok_or(CanonicalError::ByteCountOverflow)?;
        self.reported_pipeline_work_upper_bound = self
            .planning
            .construction_actual()
            .work
            // The cached semantic/planning identities are already charged in
            // `construction_actual`; candidate access itself is O(1).
            .checked_add(self.source_utf8_validation_work)
            .and_then(|work| work.checked_add(self.kernel_build.total_work_upper_bound()))
            .and_then(|work| work.checked_add(self.native_stats.emission_work))
            .and_then(|work| work.checked_add(self.native_internal_audit_work_upper_bound))
            .and_then(|work| work.checked_add(self.object_report.total_work))
            .and_then(|work| work.checked_add(self.compiler_identity_work))
            .and_then(|work| {
                work.checked_add(STATIC_COUNT_EXPECTATION_PROJECTION_WORK_UPPER_BOUND_V1)
            })
            .ok_or(CanonicalError::ByteCountOverflow)?;
        Ok(())
    }
}

/// Non-forgeable trusted receipt for one exact-literal count object.
///
/// Every field is private. The only constructor is the compiler path that
/// consumes an opaque facade candidate, and every getter returns an immutable
/// copy suitable for a static-link verifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompileReceiptV1 {
    manifest: MacosAarch64CountManifestV1,
    semantic_binding_identity: AggregateCountExactLiteralAotSemanticBindingIdentity,
    planning_receipt_identity: AggregateCountExactLiteralAotPlanningReceiptIdentity,
    live_literal_identity: LiveLiteralIdentity,
    live_literal_bytes: u32,
    kir_identity: AggregateProgramIdentity,
    native_artifact_identity: ArtifactIdentity,
    object_binding_identity: BindingIdentity,
    metadata: MetadataV1,
    compile_identity: CompileIdentity,
    object_identity: ObjectIdentity,
    accounting: CompileAccountingV1,
    receipt_identity: CompileReceiptIdentity,
}

impl CompileReceiptV1 {
    #[must_use]
    pub const fn manifest(&self) -> MacosAarch64CountManifestV1 {
        self.manifest
    }

    #[must_use]
    pub const fn manifest_identity(&self) -> ManifestIdentity {
        self.manifest.identity()
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
    pub const fn live_literal_identity(&self) -> LiveLiteralIdentity {
        self.live_literal_identity
    }

    #[must_use]
    pub const fn live_literal_bytes(&self) -> u32 {
        self.live_literal_bytes
    }

    #[must_use]
    pub const fn kir_identity(&self) -> AggregateProgramIdentity {
        self.kir_identity
    }

    #[must_use]
    pub const fn native_artifact_identity(&self) -> ArtifactIdentity {
        self.native_artifact_identity
    }

    #[must_use]
    pub const fn object_binding_identity(&self) -> BindingIdentity {
        self.object_binding_identity
    }

    #[must_use]
    pub const fn metadata(&self) -> MetadataV1 {
        self.metadata
    }

    #[must_use]
    pub const fn compile_identity(&self) -> CompileIdentity {
        self.compile_identity
    }

    #[must_use]
    pub const fn object_identity(&self) -> ObjectIdentity {
        self.object_identity
    }

    #[must_use]
    pub const fn accounting(&self) -> CompileAccountingV1 {
        self.accounting
    }

    pub(crate) const fn manifest_ref(&self) -> &MacosAarch64CountManifestV1 {
        &self.manifest
    }

    pub(crate) const fn accounting_ref(&self) -> &CompileAccountingV1 {
        &self.accounting
    }

    #[must_use]
    pub const fn receipt_identity(&self) -> CompileReceiptIdentity {
        self.receipt_identity
    }

    /// Strictly inspect arbitrary object bytes and compare every trusted
    /// external identity before returning the untrusted inspection view.
    pub fn validate_object_bytes<'a>(
        &self,
        bytes: &'a [u8],
    ) -> Result<ObjectInspection<'a>, ReceiptValidationError> {
        if !self.manifest.authenticates_itself() {
            return Err(ReceiptValidationError::Mismatch {
                field: ReceiptMismatch::ManifestIdentity,
            });
        }
        let recomputed = self
            .recompute_identity()
            .map_err(|_| ReceiptValidationError::ArithmeticOverflow)?;
        if recomputed != self.receipt_identity {
            return Err(ReceiptValidationError::Mismatch {
                field: ReceiptMismatch::ReceiptIdentity,
            });
        }
        let inspection = inspect_object(bytes, self.manifest.policy().object)?;
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
        clippy::too_many_arguments,
        reason = "all independently authenticated identities must enter the private receipt constructor"
    )]
    pub(crate) const fn unsealed(
        manifest: &MacosAarch64CountManifestV1,
        semantic_binding_identity: AggregateCountExactLiteralAotSemanticBindingIdentity,
        planning_receipt_identity: AggregateCountExactLiteralAotPlanningReceiptIdentity,
        live_literal_identity: LiveLiteralIdentity,
        live_literal_bytes: u32,
        kir_identity: AggregateProgramIdentity,
        native_artifact_identity: ArtifactIdentity,
        object_binding_identity: BindingIdentity,
        metadata: MetadataV1,
        compile_identity: CompileIdentity,
        object_identity: ObjectIdentity,
        accounting: &CompileAccountingV1,
    ) -> Self {
        Self {
            manifest: *manifest,
            semantic_binding_identity,
            planning_receipt_identity,
            live_literal_identity,
            live_literal_bytes,
            kir_identity,
            native_artifact_identity,
            object_binding_identity,
            metadata,
            compile_identity,
            object_identity,
            accounting: *accounting,
            receipt_identity: CompileReceiptIdentity::new([0; 32]),
        }
    }

    pub(crate) fn canonical_body_bytes(&self) -> Result<u64, CanonicalError> {
        let mut encoder = CanonicalEncoder::counting();
        encode_receipt_body(&mut encoder, self)?;
        Ok(encoder.bytes_written())
    }

    pub(crate) fn replace_accounting(&mut self, accounting: &CompileAccountingV1) {
        self.accounting = *accounting;
    }

    pub(crate) fn seal(&mut self) -> Result<(), CanonicalError> {
        self.receipt_identity = self.recompute_identity()?;
        Ok(())
    }

    fn recompute_identity(&self) -> Result<CompileReceiptIdentity, CanonicalError> {
        let mut encoder = CanonicalEncoder::hashing();
        encode_receipt_body(&mut encoder, self)?;
        let EncodedDigest { bytes, .. } = encoder.finish()?;
        Ok(CompileReceiptIdentity::new(bytes))
    }

    pub(crate) fn authenticates_built_object(&self, object: &BuiltObject) -> bool {
        self.metadata == object.metadata()
            && self.compile_identity == object.compile_identity()
            && self.object_identity == object.object_identity()
            && self.accounting.object_report == object.report()
            && self
                .object_binding_identity
                .matches_claim(object.metadata().claimed_binding_identity())
            && self
                .compile_identity
                .matches_claim(object.metadata().claimed_compile_identity())
    }
}

/// Normal Mach-O bytes and the only trusted receipt that authenticates them.
#[derive(Debug, Eq, PartialEq)]
pub struct CompiledObject {
    object: BuiltObject,
    receipt: CompileReceiptV1,
    static_expectation: StaticCountExpectationV1,
}

impl CompiledObject {
    #[must_use]
    pub const fn object(&self) -> &BuiltObject {
        &self.object
    }

    #[must_use]
    pub const fn receipt(&self) -> &CompileReceiptV1 {
        &self.receipt
    }

    #[must_use]
    pub const fn static_count_expectation(&self) -> &StaticCountExpectationV1 {
        &self.static_expectation
    }

    #[must_use]
    pub const fn static_count_expectation_bytes(&self) -> &[u8; STATIC_COUNT_EXPECTATION_BYTES_V1] {
        self.static_expectation.as_bytes()
    }

    #[allow(
        clippy::large_types_passed_by_value,
        reason = "the sealed receipt is deliberately consumed into the returned trusted object"
    )]
    pub(crate) fn new(
        object: BuiltObject,
        receipt: CompileReceiptV1,
    ) -> Result<Self, ReceiptValidationError> {
        if !receipt.authenticates_built_object(&object) {
            return Err(ReceiptValidationError::Mismatch {
                field: ReceiptMismatch::Metadata,
            });
        }
        let static_expectation = build_static_count_expectation(&receipt)
            .map_err(|_| ReceiptValidationError::ArithmeticOverflow)?;
        Ok(Self {
            object,
            receipt,
            static_expectation,
        })
    }
}

fn encode_receipt_body(
    encoder: &mut CanonicalEncoder,
    receipt: &CompileReceiptV1,
) -> Result<(), CanonicalError> {
    encoder.raw(RECEIPT_DOMAIN)?;
    encoder.u16(AOT_COMPILE_RECEIPT_SCHEMA_VERSION_V1)?;
    encoder.raw(receipt.manifest.identity().as_bytes())?;
    encoder.raw(receipt.semantic_binding_identity.as_bytes())?;
    encoder.raw(receipt.planning_receipt_identity.as_bytes())?;
    encoder.raw(receipt.live_literal_identity.as_bytes())?;
    encoder.u32(receipt.live_literal_bytes)?;
    encoder.raw(receipt.kir_identity.as_bytes())?;
    encoder.raw(receipt.native_artifact_identity.as_bytes())?;
    encoder.raw(receipt.object_binding_identity.as_bytes())?;
    encode_metadata(encoder, receipt.metadata)?;
    encoder.raw(receipt.compile_identity.as_bytes())?;
    encoder.raw(receipt.object_identity.as_bytes())?;
    encode_accounting(encoder, &receipt.accounting)
}

pub(crate) fn encode_metadata(
    encoder: &mut CanonicalEncoder,
    metadata: MetadataV1,
) -> Result<(), CanonicalError> {
    encoder.u16(metadata.format_version())?;
    encoder.u16(metadata.record_bytes())?;
    encoder.u16(metadata.backend_version())?;
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
    encoder.u16(metadata.abi_schema())?;
    encoder.u64(metadata.features())?;
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

#[allow(
    clippy::too_many_lines,
    reason = "the canonical receipt projection must enumerate every accounting field in one stable schema order"
)]
pub(crate) fn encode_accounting(
    encoder: &mut CanonicalEncoder,
    accounting: &CompileAccountingV1,
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

    let kernel_build = accounting.kernel_build;
    let kernel = kernel_build.search_shape();
    encoder.usize(kernel.blocks())?;
    encoder.usize(kernel.instructions())?;
    encoder.usize(kernel.data_blobs())?;
    encoder.usize(kernel.data_bytes())?;
    encoder.usize(kernel.serialized_bytes())?;
    encoder.usize(kernel.estimated_code_bytes())?;
    encoder.u64(kernel.validation_work())?;
    encoder.u64(kernel.work_factor())?;
    let resources = kernel_build.resources();
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
    encoder.usize(resources.retained_program_bytes())?;

    let native = accounting.native_stats;
    encoder.u32(native.code_bytes)?;
    encoder.u32(native.data_bytes)?;
    encoder.u32(native.relocations)?;
    encoder.u32(native.labels)?;
    encoder.u64(native.emission_work)?;
    encoder.u64(native.scratch_bytes)?;
    encoder.u32(native.vector_instructions)?;

    encode_object_report(encoder, accounting.object_report)?;
    encoder.u64(accounting.native_internal_audit_work_upper_bound)?;
    encoder.u64(accounting.source_utf8_validation_work)?;
    encoder.u64(accounting.manifest_identity_bytes_hashed)?;
    encoder.u64(accounting.literal_identity_bytes_hashed)?;
    encoder.u64(accounting.object_binding_identity_bytes_hashed)?;
    encoder.u64(accounting.receipt_identity_bytes_hashed)?;
    encoder.u64(accounting.compiler_identity_work)?;
    encoder.u64(accounting.reported_pipeline_work_upper_bound)?;
    encoder.usize(accounting.final_persistent_bytes)?;
    encoder.u64(accounting.peak_scratch_bytes_upper_bound)?;
    encoder.u64(STATIC_COUNT_EXPECTATION_CANONICAL_BYTES_HASHED_UPPER_BOUND_V1)?;
    encoder.u64(STATIC_COUNT_EXPECTATION_PROJECTION_WORK_UPPER_BOUND_V1)?;
    encoder.u64(STATIC_COUNT_EXPECTATION_PROJECTION_SCRATCH_UPPER_BOUND_V1)?;
    encoder.usize(STATIC_COUNT_EXPECTATION_BYTES_V1)?;
    encoder.usize(STATIC_COUNT_EXPECTATION_RETAINED_BYTES_V1)?;
    encode_pipeline_live(encoder, accounting.pipeline_live)
}

pub(crate) fn encode_construction_prospective(
    encoder: &mut CanonicalEncoder,
    prospective: fre::AggregateConstructionProspective,
) -> Result<(), CanonicalError> {
    encoder.u64(prospective.work)?;
    encoder.usize(prospective.allocations)?;
    encoder.usize(prospective.allocated_bytes)?;
    encoder.usize(prospective.copied_bytes)?;
    encoder.usize(prospective.initialized_bytes)?;
    encoder.u64(prospective.abandoned_work)?;
    encoder.usize(prospective.abandoned_allocations)?;
    encoder.usize(prospective.abandoned_bytes)?;
    encoder.usize(prospective.live_persistent_bytes)?;
    encoder.usize(prospective.high_water_bytes)
}

pub(crate) fn encode_construction_actual(
    encoder: &mut CanonicalEncoder,
    actual: fre::AggregateConstructionActual,
) -> Result<(), CanonicalError> {
    encoder.u64(actual.work)?;
    encoder.usize(actual.allocations)?;
    encoder.usize(actual.allocated_bytes)?;
    encoder.usize(actual.copied_bytes)?;
    encoder.usize(actual.initialized_bytes)?;
    encoder.u64(actual.abandoned_work)?;
    encoder.usize(actual.abandoned_allocations)?;
    encoder.usize(actual.abandoned_bytes)?;
    encoder.usize(actual.live_persistent_bytes)?;
    encoder.usize(actual.high_water_bytes)
}

fn encode_pipeline_live(
    encoder: &mut CanonicalEncoder,
    live: PipelineLiveAccountingV1,
) -> Result<(), CanonicalError> {
    encoder.usize(live.facade_live_persistent_bytes)?;
    encoder.usize(live.facade_high_water_bytes)?;
    encoder.usize(live.kir_retained_heap_bytes)?;
    encoder.usize(live.kir_inline_bytes)?;
    encoder.usize(live.native_retained_heap_bytes)?;
    encoder.usize(live.native_inline_bytes)?;
    encoder.u64(live.native_audit_scratch_upper_bound)?;
    encoder.usize(live.object_retained_bytes)?;
    encoder.usize(live.compiled_object_inline_bytes)?;
    encoder.u64(live.expectation_projection_scratch_upper_bound)?;
    encoder.u64(live.planning_peak_live_bytes)?;
    encoder.u64(live.kir_peak_live_bytes)?;
    encoder.u64(live.native_peak_live_bytes)?;
    encoder.u64(live.object_peak_live_bytes)?;
    encoder.u64(live.final_peak_live_bytes)?;
    encoder.u64(live.pipeline_peak_live_bytes_upper_bound)
}

pub(crate) fn encode_object_report(
    encoder: &mut CanonicalEncoder,
    report: ObjectBuildReport,
) -> Result<(), CanonicalError> {
    encoder.usize(report.object_bytes)?;
    encoder.usize(report.persistent_capacity_bytes)?;
    encoder.usize(report.payload_bytes)?;
    encoder.u64(report.image_audit_work_upper_bound)?;
    encoder.u64(report.image_binding_work_upper_bound)?;
    encoder.u64(report.object_work)?;
    encoder.u64(report.total_work)?;
    encoder.u64(report.object_scratch_bytes)?;
    encoder.u64(report.image_audit_scratch_upper_bound)?;
    encoder.u64(report.scratch_bytes)?;
    encoder.u32(report.sections)?;
    encoder.u32(report.symbols)?;
    // These proof-work counters were added before the V1 AOT receipt was
    // production-qualified. Binding them here deliberately invalidates every
    // earlier source-only receipt identity instead of silently omitting part
    // of the authenticated object report.
    encoder.u32(report.image_audit.decode_passes)?;
    encoder.u32(report.image_audit.source_identity_rebuilds)?;
    encoder.u32(report.image_audit.instructions)?;
    encoder.u32(report.image_audit.direct_branches)?;
    encoder.u32(report.image_audit.data_addresses)?;
    encoder.u32(report.image_audit.vector_instructions)?;
    encoder.u32(report.image_audit.stores)?;
    encoder.u32(report.image_audit.returns)?;
    encoder.raw(report.compile_identity.as_bytes())?;
    encoder.raw(report.object_identity.as_bytes())
}

#[cfg(test)]
pub(crate) fn object_report_identity_projection_for_test(
    report: ObjectBuildReport,
) -> Result<([u8; 32], u64), CanonicalError> {
    let mut encoder = CanonicalEncoder::hashing();
    encode_object_report(&mut encoder, report)?;
    let projection = encoder.finish()?;
    Ok((projection.bytes, projection.hashed_bytes))
}
