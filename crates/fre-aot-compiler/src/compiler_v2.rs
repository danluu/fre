use core::mem::size_of;

use fre::{
    AGGREGATE_COUNT_EXACT_LITERAL_AOT_CANDIDATE_IDENTITY_WORK_UPPER_BOUND_V1,
    AGGREGATE_COUNT_EXACT_LITERAL_AOT_PLANNING_WORK_UPPER_BOUND_V1, AggregateBuildLimits,
    AggregateBuilder, AggregateCountExactLiteralAotIdentityProjectionAccounting,
    AggregateCountExactLiteralAotPlannedCandidate, AggregatePlanSelection, AggregateStrategy,
    LiteralAggregateBuildAccounting, RustProfile,
};
use fre_aot_aarch64::{
    AOT_COUNT_BACKEND_VERSION_V2, AOT_COUNT_IMAGE_SCHEMA_VERSION_V2, AotCountCpuFeatures,
    AotCountImageBuildReceiptV2, AotCountImageStatsV2, AotCountImageV2, emit_count_v2,
    is_supported_aot_count_backend_tuple_v2, prospective_count_v2,
};
use fre_aot_macho::{
    AbiKind, BindingIdentity, BuiltCountObjectV2, CALL_ABI_SCHEMA_V2, CountObjectBuildReportV2,
    ENTRY_OFFSET_V2, METADATA_BYTES_V2, METADATA_VERSION_V2, PLATFORM_MACOS, STATUS_BITS_V2,
    emit_count_object_v2, validate_count_object_v2,
};
use fre_kernel_ir::{Count, ExactAggregateProgram, build_exact_aggregate};

use crate::{
    canonical::{
        CURRENT_IDENTITY_SCRATCH_BYTES_UPPER_BOUND_V2, CanonicalEncoder, CanonicalError,
        EncodedDigest,
    },
    compiler::{
        as_u64, authenticate_candidate, authenticate_kernel, checked_sum, enforce,
        hash_live_literal, kernel_build_accounting, require,
    },
    error::{CompileArithmeticSite, CompileError, CompileResource, ContractField},
    manifest_v2::{
        AOT_COUNT_COMPILER_SUPPORT_V2, MAX_AOT_SOURCE_BYTES_V2, MAX_COMPILER_IDENTITY_WORK_V2,
        MacosAarch64CountManifestV2, POLICY_LIMITS_CANONICAL_BYTES_V2,
    },
    receipt::{KernelBuildAccountingV1, KernelProgramShapeV1},
    receipt_v2::{
        CompileAccountingV2, CompileReceiptV2, CompiledObjectV2, CompilerIdentityAccountingV2,
        ObjectValidationAccountingV2, PipelineLiveAccountingV2,
    },
    static_expectation_v2::{
        StaticCountExpectationBuildReportV2, StaticCountExpectationV2,
        prospective_static_count_expectation_v2,
    },
};

const OBJECT_BINDING_DOMAIN_V2: &[u8] = b"FRE-AOT-COMPILER-OBJECT-BINDING\0\x02";
const HARD_MANIFEST_CANONICAL_BYTES_V2: u64 = 1 << 10;
const HARD_POLICY_LIMITS_CANONICAL_BYTES_V2: u64 = 1 << 10;
const HARD_LITERAL_IDENTITY_BYTES_V2: u64 = 32;
const HARD_OBJECT_BINDING_CANONICAL_BYTES_V2: u64 = 1 << 10;
const HARD_RESOURCE_RECEIPT_CANONICAL_BYTES_V2: u64 = 4 << 10;
const HARD_COMPILE_RECEIPT_CANONICAL_BYTES_V2: u64 = 4 << 10;
const HARD_PROSPECTIVE_COMPILER_IDENTITY_WORK_V2: u64 = HARD_MANIFEST_CANONICAL_BYTES_V2
    + HARD_POLICY_LIMITS_CANONICAL_BYTES_V2
    + HARD_LITERAL_IDENTITY_BYTES_V2
    + HARD_OBJECT_BINDING_CANONICAL_BYTES_V2
    + 3 * HARD_RESOURCE_RECEIPT_CANONICAL_BYTES_V2
    + 3 * HARD_COMPILE_RECEIPT_CANONICAL_BYTES_V2
    + 10 * crate::canonical::CANONICAL_TRAVERSAL_FIXED_WORK_V2
    + 6 * crate::canonical::IDENTITY_HASH_FINALIZE_WORK_V2;
const _: () = assert!(POLICY_LIMITS_CANONICAL_BYTES_V2 <= HARD_POLICY_LIMITS_CANONICAL_BYTES_V2);
const _: () = assert!(HARD_PROSPECTIVE_COMPILER_IDENTITY_WORK_V2 <= MAX_COMPILER_IDENTITY_WORK_V2);

/// Plan and compile owned UTF-8 source through the explicit Count AOT v2 path.
///
/// The source length and capacity are refused before UTF-8, syntax, or hashing
/// work. The result is inert `MH_OBJECT` bytes, a lossless typed receipt, and
/// an unsigned expectation; this function does not link or adopt static code.
#[allow(
    clippy::large_types_passed_by_value,
    clippy::result_large_err,
    reason = "the public source-first boundary owns its sealed manifest and preserves the crate's typed unboxed error contract"
)]
pub fn plan_and_compile_macos_aarch64_count_v2(
    manifest: MacosAarch64CountManifestV2,
    pattern: Vec<u8>,
    profile: RustProfile,
) -> Result<CompiledObjectV2, CompileError> {
    enforce_hard_identity_envelope_v2()?;
    let source_bytes =
        u64::try_from(pattern.len()).map_err(|_| CompileError::ArithmeticOverflow {
            site: CompileArithmeticSite::SourceLength,
        })?;
    let source_capacity =
        u64::try_from(pattern.capacity()).map_err(|_| CompileError::ArithmeticOverflow {
            site: CompileArithmeticSite::SourceLength,
        })?;
    // These process-wide hard bounds do not trust any field of the still
    // unauthenticated manifest. In particular, an oversized owned buffer is
    // refused before the first manifest canonical traversal.
    enforce(
        CompileResource::SourceBytes,
        source_bytes,
        MAX_AOT_SOURCE_BYTES_V2,
    )?;
    enforce(
        CompileResource::SourceCapacityBytes,
        source_capacity,
        MAX_AOT_SOURCE_BYTES_V2,
    )?;
    let manifest = authenticate_manifest_v2(&manifest)?;
    enforce(
        CompileResource::SourceBytes,
        source_bytes,
        manifest.0.policy().max_source_bytes,
    )?;
    enforce(
        CompileResource::SourceCapacityBytes,
        source_capacity,
        manifest.0.policy().max_source_bytes,
    )?;
    enforce(
        CompileResource::FacadePlanningWork,
        AGGREGATE_COUNT_EXACT_LITERAL_AOT_PLANNING_WORK_UPPER_BOUND_V1,
        manifest.0.policy().max_facade_planning_work,
    )?;
    enforce(
        CompileResource::CandidateIdentityWork,
        AGGREGATE_COUNT_EXACT_LITERAL_AOT_CANDIDATE_IDENTITY_WORK_UPPER_BOUND_V1,
        manifest.0.policy().max_candidate_identity_work,
    )?;
    let pattern = String::from_utf8(pattern).map_err(|_| CompileError::InvalidUtf8Source)?;
    let regex = AggregateBuilder::new(pattern)
        .profile(profile)
        .limits(AggregateBuildLimits::aot_count_exact_literal_v1())
        .plan_selection(AggregatePlanSelection::ForceExactLiteral)
        .strategy(AggregateStrategy::ReverseSequentialRows)
        .build_count()
        .map_err(CompileError::FacadePlanning)?;
    let candidate = regex.exact_literal_aot_planned_candidate().ok_or(
        CompileError::InternalInvariant {
            at: "fixed facade policy did not publish a complete planned exact-literal candidate",
        },
    )?;
    compile_macos_aarch64_count_v2_candidate_inner(&candidate, manifest, source_bytes)
}

/// Compile an already-spent fixed-policy candidate through direct Count AOT v2.
///
/// The candidate's authenticated planning receipt is retained, but only
/// [`plan_and_compile_macos_aarch64_count_v2`] provides the manifest-before-
/// planning resource boundary.
#[allow(
    clippy::large_types_passed_by_value,
    clippy::needless_pass_by_value,
    clippy::result_large_err,
    reason = "this public boundary mirrors compiler-v1 ownership while the inner transaction borrows the authenticated values"
)]
pub fn compile_macos_aarch64_count_v2_candidate(
    candidate: AggregateCountExactLiteralAotPlannedCandidate<'_>,
    manifest: MacosAarch64CountManifestV2,
) -> Result<CompiledObjectV2, CompileError> {
    enforce_hard_identity_envelope_v2()?;
    let planning = candidate.planning_accounting();
    enforce(
        CompileResource::SourceBytes,
        planning.source_bytes(),
        MAX_AOT_SOURCE_BYTES_V2,
    )?;
    enforce(
        CompileResource::SourceCapacityBytes,
        as_u64(
            planning.source_capacity_bytes(),
            CompileArithmeticSite::SourceLength,
        )?,
        MAX_AOT_SOURCE_BYTES_V2,
    )?;
    let manifest = authenticate_manifest_v2(&manifest)?;
    compile_macos_aarch64_count_v2_candidate_inner(&candidate, manifest, 0)
}

/// Proof that this invocation has performed the single admitted manifest
/// canonical authentication pass.
#[derive(Clone, Copy)]
struct AuthenticatedManifestV2<'a>(&'a MacosAarch64CountManifestV2);

#[allow(
    clippy::result_large_err,
    reason = "the crate preserves the typed unboxed compile error contract"
)]
fn enforce_hard_identity_envelope_v2() -> Result<(), CompileError> {
    #[cfg(test)]
    hard_identity_gate_trace::record(crate::manifest_v2::manifest_encode_trace::passes());
    enforce(
        CompileResource::CompilerIdentityWork,
        HARD_PROSPECTIVE_COMPILER_IDENTITY_WORK_V2,
        MAX_COMPILER_IDENTITY_WORK_V2,
    )
}

#[allow(
    clippy::result_large_err,
    clippy::too_many_lines,
    reason = "the ordered transaction keeps every compiler-v2 contract and stage receipt visible"
)]
fn compile_macos_aarch64_count_v2_candidate_inner(
    candidate: &AggregateCountExactLiteralAotPlannedCandidate<'_>,
    authenticated_manifest: AuthenticatedManifestV2<'_>,
    source_utf8_validation_work: u64,
) -> Result<CompiledObjectV2, CompileError> {
    let manifest = authenticated_manifest.0;
    let planning = candidate.planning_accounting();
    enforce(
        CompileResource::SourceBytes,
        planning.source_bytes(),
        manifest.policy().max_source_bytes,
    )?;
    enforce(
        CompileResource::SourceCapacityBytes,
        as_u64(
            planning.source_capacity_bytes(),
            CompileArithmeticSite::SourceLength,
        )?,
        manifest.policy().max_source_bytes,
    )?;
    if source_utf8_validation_work > planning.source_bytes() {
        return Err(CompileError::InternalInvariant {
            at: "UTF-8 validation work exceeds authenticated source bytes",
        });
    }
    enforce(
        CompileResource::FacadePlanningWork,
        planning.construction_prospective().work,
        manifest.policy().max_facade_planning_work,
    )?;
    let projection = candidate.identity_projection_accounting();
    enforce(
        CompileResource::CandidateIdentityWork,
        projection.projection_work_upper_bound(),
        manifest.policy().max_candidate_identity_work,
    )?;
    authenticate_candidate(candidate)?;

    let literal = candidate.literal();
    let literal_bytes =
        u64::try_from(literal.len()).map_err(|_| CompileError::ArithmeticOverflow {
            site: CompileArithmeticSite::LiteralLength,
        })?;
    enforce(
        CompileResource::LiteralBytes,
        literal_bytes,
        manifest.policy().max_literal_bytes,
    )?;
    let live_literal_identity = hash_live_literal(literal);
    let semantic_binding_identity = candidate.semantic_binding_identity();
    let planning_receipt_identity = candidate.planning_receipt_identity();
    let candidate_build = candidate.build_accounting();

    let program = build_exact_aggregate::<Count>(literal, manifest.policy().kernel_ir)?;
    authenticate_kernel(&program, literal)?;
    let program_identity = program.cache_identity();
    let kernel_build = kernel_build_accounting(&program)?;
    let image_prospective = prospective_count_v2(&program)?;
    let image = emit_count_v2(&program, manifest.policy().native)?;
    authenticate_image_v2(&program, &image, manifest)?;
    let image_identity = image.artifact_identity();
    let image_stats = image.stats();
    let image_build_receipt = image.build_receipt();

    let binding_digest = object_binding_digest_v2(
        manifest,
        semantic_binding_identity.as_bytes(),
        planning_receipt_identity.as_bytes(),
        live_literal_identity.as_bytes(),
        projection,
        candidate_build,
        kernel_build.search_shape(),
        &image,
    )
    .map_err(map_canonical)?;
    let object_binding_identity = BindingIdentity::new(binding_digest.bytes)?;
    let object = emit_count_object_v2(
        &program,
        &image,
        object_binding_identity,
        manifest.policy().object,
    )?;
    let validation = validate_count_object_v2(
        &program,
        &image,
        object_binding_identity,
        object.as_bytes(),
        manifest.policy().object,
    )?;
    authenticate_object_v2(&object, &image, &program, object_binding_identity)?;
    require(
        validation.inspection.metadata() == object.metadata(),
        ContractField::MetadataCompileIdentity,
    )?;
    require(
        validation.image_audit == object.report().image_audit,
        ContractField::ObjectReportCompileIdentity,
    )?;

    let object_report = object.report();
    if validation.object_scratch_bytes_upper_bound != object_report.object_scratch_bytes_upper_bound
        || validation.image_audit_scratch_upper_bound
            != object_report.image_audit_scratch_upper_bound
        || validation.scratch_bytes_upper_bound != object_report.scratch_bytes_upper_bound
    {
        return Err(CompileError::InternalInvariant {
            at: "compiler-v2 typed Count object validation scratch receipt",
        });
    }
    let object_validation = ObjectValidationAccountingV2::new(
        validation.inspection.work_upper_bound(),
        object_report.image_audit_work_upper_bound,
        object_report.image_binding_work_upper_bound,
        validation.object_scratch_bytes_upper_bound,
        validation.image_audit_scratch_upper_bound,
        validation.scratch_bytes_upper_bound,
        validation.image_audit,
    )
    .map_err(map_canonical)?;
    let expectation_build_report =
        prospective_static_count_expectation_v2().map_err(map_canonical)?;
    let pipeline_live = pipeline_live_accounting_v2(
        &planning,
        kernel_build,
        image_build_receipt,
        object_report,
        object_validation,
        expectation_build_report,
    )?;
    let final_persistent_bytes = object_report
        .persistent_capacity_bytes
        .checked_add(size_of::<CompiledObjectV2>())
        .ok_or(CompileError::ArithmeticOverflow {
            site: CompileArithmeticSite::PersistentAccounting,
        })?;
    let peak_scratch_bytes_upper_bound = peak_scratch_upper_bound_v2(
        candidate_build,
        projection,
        kernel_build,
        image_build_receipt,
        object_report,
        object_validation,
        expectation_build_report,
    )?;
    let source_bytes_u32 =
        u32::try_from(literal.len()).map_err(|_| CompileError::ArithmeticOverflow {
            site: CompileArithmeticSite::LiteralLength,
        })?;
    let metadata = object.metadata();
    let compile_identity = object.compile_identity();
    let object_identity = object.object_identity();

    let mut accounting = CompileAccountingV2::draft(
        planning,
        projection,
        candidate_build,
        kernel_build,
        image_prospective,
        image_stats,
        image_build_receipt,
        object_report,
        object_validation,
        source_utf8_validation_work,
        expectation_build_report,
        final_persistent_bytes,
        peak_scratch_bytes_upper_bound,
        pipeline_live,
    );
    let mut receipt = CompileReceiptV2::unsealed(
        *manifest,
        image.support(),
        semantic_binding_identity,
        planning_receipt_identity,
        live_literal_identity,
        source_bytes_u32,
        program_identity,
        image_identity,
        object_binding_identity,
        metadata,
        compile_identity,
        object_identity,
        accounting,
    );
    let receipt_identity_bytes = receipt.canonical_body_bytes().map_err(map_canonical)?;
    let resource_receipt_identity_bytes = receipt
        .resource_receipt_body_bytes()
        .map_err(map_canonical)?;
    for (required, limit) in [
        (
            manifest.identity_bytes_hashed(),
            HARD_MANIFEST_CANONICAL_BYTES_V2,
        ),
        (
            manifest.policy_limits_identity_bytes_hashed(),
            HARD_POLICY_LIMITS_CANONICAL_BYTES_V2,
        ),
        (literal_bytes, HARD_LITERAL_IDENTITY_BYTES_V2),
        (
            binding_digest.hashed_bytes,
            HARD_OBJECT_BINDING_CANONICAL_BYTES_V2,
        ),
        (
            resource_receipt_identity_bytes,
            HARD_RESOURCE_RECEIPT_CANONICAL_BYTES_V2,
        ),
        (
            receipt_identity_bytes,
            HARD_COMPILE_RECEIPT_CANONICAL_BYTES_V2,
        ),
    ] {
        enforce(CompileResource::CompilerIdentityWork, required, limit)?;
    }
    let compiler_identity_accounting = CompilerIdentityAccountingV2::current(
        manifest.identity_bytes_hashed(),
        manifest.policy_limits_identity_bytes_hashed(),
        literal_bytes,
        binding_digest.hashed_bytes,
        resource_receipt_identity_bytes,
        receipt_identity_bytes,
    )
    .map_err(map_canonical)?;
    accounting
        .close(compiler_identity_accounting)
        .map_err(map_canonical)?;
    receipt.replace_accounting(accounting);
    if receipt.canonical_body_bytes().map_err(map_canonical)? != receipt_identity_bytes
        || receipt
            .resource_receipt_body_bytes()
            .map_err(map_canonical)?
            != resource_receipt_identity_bytes
    {
        return Err(CompileError::InternalInvariant {
            at: "compiler-v2 fixed-width receipt/resource closure changed canonical length",
        });
    }
    // This is the last work/resource gate before resource receipt hashing,
    // compile receipt hashing, and expectation construction.
    enforce(
        CompileResource::CompilerIdentityWork,
        accounting.compiler_identity_work(),
        MAX_COMPILER_IDENTITY_WORK_V2,
    )?;
    enforce(
        CompileResource::PipelineWork,
        accounting.reported_pipeline_work_upper_bound(),
        manifest.policy().max_pipeline_work,
    )?;
    enforce(
        CompileResource::FinalPersistentBytes,
        as_u64(
            final_persistent_bytes,
            CompileArithmeticSite::PersistentAccounting,
        )?,
        manifest.policy().max_final_persistent_bytes,
    )?;
    enforce(
        CompileResource::PeakScratchBytes,
        peak_scratch_bytes_upper_bound,
        manifest.policy().max_peak_scratch_bytes,
    )?;
    enforce(
        CompileResource::PipelinePeakLiveBytes,
        pipeline_live.pipeline_peak_live_bytes_upper_bound(),
        manifest.policy().max_pipeline_peak_live_bytes,
    )?;
    let sealed_receipt =
        receipt
            .seal_for_compiled_object(&object)
            .map_err(|_| CompileError::InternalInvariant {
                at: "compiler-v2 receipt/object typestate seal",
            })?;
    CompiledObjectV2::new(object, sealed_receipt, expectation_build_report).map_err(|_| {
        CompileError::InternalInvariant {
            at: "sealed compiler-v2 receipt did not authenticate its object and expectation",
        }
    })
}

#[allow(
    clippy::result_large_err,
    reason = "the crate preserves detailed typed planning and backend failures"
)]
fn authenticate_manifest_v2(
    manifest: &MacosAarch64CountManifestV2,
) -> Result<AuthenticatedManifestV2<'_>, CompileError> {
    require(
        manifest.authenticates_itself(),
        ContractField::ManifestIdentity,
    )?;
    Ok(AuthenticatedManifestV2(manifest))
}

#[allow(
    clippy::result_large_err,
    reason = "the crate preserves detailed typed planning and backend failures"
)]
fn authenticate_image_v2(
    program: &ExactAggregateProgram<Count>,
    image: &AotCountImageV2,
    manifest: &MacosAarch64CountManifestV2,
) -> Result<(), CompileError> {
    let support = image.support();
    require(
        support == manifest.support()
            && support == AOT_COUNT_COMPILER_SUPPORT_V2
            && is_supported_aot_count_backend_tuple_v2(support),
        ContractField::NativeBackendVersion,
    )?;
    require(
        image.backend_version() == AOT_COUNT_BACKEND_VERSION_V2,
        ContractField::NativeBackendVersion,
    )?;
    require(
        image.source_identity() == program.cache_identity(),
        ContractField::NativeSourceIdentity,
    )?;
    require(image.output_kind() == 1, ContractField::NativeOutput)?;
    require(
        image.literal_manifest().literal() == program.literal(),
        ContractField::KernelLiteral,
    )?;
    require(
        usize::try_from(image.literal_bytes()).ok() == Some(program.literal().len()),
        ContractField::NativeLiteralBytes,
    )?;
    let target = image.target();
    require(
        target.architecture == support.architecture,
        ContractField::NativeArchitecture,
    )?;
    require(
        target.little_endian == support.little_endian,
        ContractField::NativeByteOrder,
    )?;
    require(
        target.pointer_width == support.pointer_width,
        ContractField::NativePointerWidth,
    )?;
    require(target.abi == support.target_abi, ContractField::NativeAbi)?;
    let required_features = if program.literal().is_empty() {
        AotCountCpuFeatures::NONE
    } else {
        AotCountCpuFeatures::ASIMD
    };
    require(
        target.features == required_features
            && support.allowed_features.contains(target.features)
            && manifest.allowed_cpu_features().contains(target.features),
        ContractField::NativeFeatures,
    )?;
    let receipt = image.build_receipt();
    let stats = image.stats();
    require(
        receipt.support == support
            && stats.audit_work_upper_bound == receipt.audit.work_upper_bound
            && stats.scratch_bytes_upper_bound == receipt.scratch_bytes_upper_bound
            && stats.total_work_upper_bound == receipt.work_upper_bound,
        ContractField::NativeBackendVersion,
    )
}

#[allow(
    clippy::result_large_err,
    clippy::too_many_lines,
    reason = "the explicit metadata comparison is intentionally linear and preserves typed failures"
)]
fn authenticate_object_v2(
    object: &BuiltCountObjectV2,
    image: &AotCountImageV2,
    program: &ExactAggregateProgram<Count>,
    binding: BindingIdentity,
) -> Result<(), CompileError> {
    let metadata = object.metadata();
    let support = image.support();
    require(
        metadata.format_version() == METADATA_VERSION_V2,
        ContractField::MetadataVersion,
    )?;
    require(
        usize::from(metadata.record_bytes()) == METADATA_BYTES_V2,
        ContractField::MetadataRecordBytes,
    )?;
    require(
        metadata.backend_version() == support.backend_version.0,
        ContractField::MetadataBackendVersion,
    )?;
    require(
        metadata.algorithm_version() == support.algorithm_version,
        ContractField::MetadataAlgorithmVersion,
    )?;
    require(
        metadata.kir_semantics_version() == support.kir_semantics_version,
        ContractField::MetadataKirSemanticsVersion,
    )?;
    require(
        metadata.kir_abi_version() == support.kir_abi_version,
        ContractField::MetadataKirAbiVersion,
    )?;
    require(
        metadata.max_literal_bytes() == support.max_literal_bytes,
        ContractField::MetadataMaxLiteralBytes,
    )?;
    require(
        metadata.abi_kind() == AbiKind::Aggregate,
        ContractField::MetadataAbiKind,
    )?;
    require(
        metadata.output_kind() == support.output_kind,
        ContractField::MetadataOutput,
    )?;
    let target = image.target();
    require(
        metadata.architecture() == target.architecture,
        ContractField::MetadataArchitecture,
    )?;
    require(
        metadata.little_endian() == target.little_endian,
        ContractField::MetadataByteOrder,
    )?;
    require(
        metadata.pointer_width() == target.pointer_width,
        ContractField::MetadataPointerWidth,
    )?;
    require(
        metadata.target_abi() == target.abi,
        ContractField::MetadataTargetAbi,
    )?;
    require(
        metadata.platform() == PLATFORM_MACOS,
        ContractField::MetadataPlatform,
    )?;
    require(
        metadata.status_bits() == STATUS_BITS_V2,
        ContractField::MetadataStatusBits,
    )?;
    require(
        metadata.abi_schema() == CALL_ABI_SCHEMA_V2,
        ContractField::MetadataAbiSchema,
    )?;
    require(
        metadata.actual_features() == target.features.bits(),
        ContractField::MetadataFeatures,
    )?;
    require(
        metadata.allowed_features() == support.allowed_features.bits(),
        ContractField::MetadataAllowedFeatures,
    )?;
    let layout = image.layout();
    require(
        metadata.payload_bytes() == layout.total_mapped_bytes,
        ContractField::MetadataPayloadBytes,
    )?;
    require(
        metadata.entry_offset() == ENTRY_OFFSET_V2,
        ContractField::MetadataEntryOffset,
    )?;
    require(
        usize::try_from(metadata.code_bytes()).ok() == Some(image.code().len()),
        ContractField::MetadataCodeBytes,
    )?;
    require(
        metadata.rodata_offset() == layout.rodata_from_code_start,
        ContractField::MetadataRodataOffset,
    )?;
    require(
        usize::try_from(metadata.rodata_bytes()).ok() == Some(image.rodata().len()),
        ContractField::MetadataRodataBytes,
    )?;
    require(
        metadata.literal_bytes() == image.literal_bytes(),
        ContractField::MetadataLiteralBytes,
    )?;
    require(
        metadata.source_identity() == program.cache_identity().as_bytes()
            && metadata.source_identity() == image.source_identity().as_bytes(),
        ContractField::MetadataSourceIdentity,
    )?;
    require(
        metadata.artifact_identity() == image.artifact_identity().as_bytes(),
        ContractField::MetadataArtifactIdentity,
    )?;
    require(
        binding.matches_claim(metadata.claimed_binding_identity()),
        ContractField::MetadataBindingIdentity,
    )?;
    require(
        object
            .compile_identity()
            .matches_claim(metadata.claimed_compile_identity()),
        ContractField::MetadataCompileIdentity,
    )?;
    require(
        object.report().compile_identity == object.compile_identity(),
        ContractField::ObjectReportCompileIdentity,
    )?;
    require(
        object.report().object_identity == object.object_identity(),
        ContractField::ObjectReportObjectIdentity,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "the domain-separated object binding covers every pre-object identity and typed v2 receipt"
)]
fn object_binding_digest_v2(
    manifest: &MacosAarch64CountManifestV2,
    semantic_binding_identity: &[u8; 32],
    planning_receipt_identity: &[u8; 32],
    source_identity: &[u8; 32],
    projection: AggregateCountExactLiteralAotIdentityProjectionAccounting,
    candidate_build: LiteralAggregateBuildAccounting,
    kernel_shape: KernelProgramShapeV1,
    image: &AotCountImageV2,
) -> Result<EncodedDigest, CanonicalError> {
    let mut encoder = CanonicalEncoder::hashing();
    encoder.raw(OBJECT_BINDING_DOMAIN_V2)?;
    encoder.raw(manifest.identity().as_bytes())?;
    encoder.raw(semantic_binding_identity)?;
    encoder.raw(planning_receipt_identity)?;
    encoder.raw(source_identity)?;
    encoder.u64(projection.semantic_identity_bytes_hashed())?;
    encoder.u64(projection.planning_identity_bytes_hashed())?;
    encoder.u64(projection.projection_work_upper_bound())?;
    encoder.u64(projection.scratch_bytes_upper_bound())?;
    encoder.u8(projection.allocations())?;
    encode_candidate_build(&mut encoder, candidate_build)?;
    encoder.raw(image.source_identity().as_bytes())?;
    encode_kernel_shape(&mut encoder, kernel_shape)?;
    encoder.u16(AOT_COUNT_IMAGE_SCHEMA_VERSION_V2)?;
    crate::manifest_v2::encode_support(&mut encoder, image.support())?;
    let target = image.target();
    encoder.u8(target.architecture)?;
    encoder.boolean(target.little_endian)?;
    encoder.u8(target.pointer_width)?;
    encoder.u8(target.abi)?;
    encoder.u64(target.features.bits())?;
    let literal_manifest = image.literal_manifest();
    encoder.u8(literal_manifest.len())?;
    encoder.raw(literal_manifest.literal())?;
    encoder.u8(literal_manifest.candidate_filter_len())?;
    encoder.raw(literal_manifest.candidate_filter_offsets())?;
    let layout = image.layout();
    encoder.u32(layout.code_alignment)?;
    encoder.u32(layout.rodata_alignment)?;
    encoder.u32(layout.rodata_from_code_start)?;
    encoder.u32(layout.total_mapped_bytes)?;
    encode_image_stats(&mut encoder, image.stats())?;
    encode_image_build_receipt(&mut encoder, image.build_receipt())?;
    encoder.raw(image.artifact_identity().as_bytes())?;
    encoder.finish()
}

fn encode_candidate_build(
    encoder: &mut CanonicalEncoder,
    build: LiteralAggregateBuildAccounting,
) -> Result<(), CanonicalError> {
    encoder.usize(build.needle_bytes)?;
    encoder.usize(build.temporary_capacity_bytes)?;
    encoder.u64(build.work_upper_bound)?;
    encoder.usize(build.scratch_bytes)?;
    encoder.usize(build.persistent_bytes)?;
    encoder.usize(build.peak_bytes)
}

fn encode_kernel_shape(
    encoder: &mut CanonicalEncoder,
    shape: KernelProgramShapeV1,
) -> Result<(), CanonicalError> {
    encoder.usize(shape.blocks())?;
    encoder.usize(shape.instructions())?;
    encoder.usize(shape.data_blobs())?;
    encoder.usize(shape.data_bytes())?;
    encoder.usize(shape.serialized_bytes())?;
    encoder.usize(shape.estimated_code_bytes())?;
    encoder.u64(shape.validation_work())?;
    encoder.u64(shape.work_factor())
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
    crate::manifest_v2::encode_support(encoder, receipt.support)?;
    encoder.usize(receipt.code_capacity_bytes)?;
    encoder.usize(receipt.label_capacity_bytes)?;
    encoder.usize(receipt.relocation_capacity_bytes)?;
    encoder.usize(receipt.retained_heap_bytes)?;
    encoder.usize(receipt.inline_bytes)?;
    encoder.u64(receipt.emission_peak_scratch_bytes)?;
    encoder.u64(receipt.work_upper_bound)?;
    encoder.u64(receipt.scratch_bytes_upper_bound)?;
    let audit = receipt.audit;
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

#[allow(
    clippy::result_large_err,
    clippy::too_many_lines,
    reason = "the named co-live calculation keeps all stage peaks auditable in one transaction"
)]
fn pipeline_live_accounting_v2(
    planning: &fre::AggregateCountExactLiteralAotPlanningAccounting,
    kernel: KernelBuildAccountingV1,
    image: AotCountImageBuildReceiptV2,
    object: CountObjectBuildReportV2,
    validation: ObjectValidationAccountingV2,
    expectation: StaticCountExpectationBuildReportV2,
) -> Result<PipelineLiveAccountingV2, CompileError> {
    let facade = planning.construction_actual();
    let facade_live_usize = facade
        .live_persistent_bytes
        .checked_add(planning.source_capacity_bytes())
        .ok_or(CompileError::ArithmeticOverflow {
            site: CompileArithmeticSite::PipelineLiveAccounting,
        })?;
    let facade_high_water_usize = facade
        .high_water_bytes
        .checked_add(planning.source_capacity_bytes())
        .ok_or(CompileError::ArithmeticOverflow {
            site: CompileArithmeticSite::PipelineLiveAccounting,
        })?;
    let facade_live = as_u64(
        facade_live_usize,
        CompileArithmeticSite::PipelineLiveAccounting,
    )?;
    let planning_peak = as_u64(
        facade_high_water_usize,
        CompileArithmeticSite::PipelineLiveAccounting,
    )?;
    let kir_retained_usize = kernel.retained_program_bytes();
    let kir_retained = as_u64(
        kir_retained_usize,
        CompileArithmeticSite::PipelineLiveAccounting,
    )?;
    let kernel_resources = kernel.resources();
    let kir_active = [
        kernel_resources.validation_phase_peak_bytes(),
        kernel_resources.serialization_phase_peak_bytes(),
        kernel_resources.identity_phase_peak_bytes(),
    ]
    .into_iter()
    .max()
    .ok_or(CompileError::InternalInvariant {
        at: "compiler-v2 KIR phase set",
    })?;
    let kir_peak = facade_live
        .checked_add(as_u64(
            kir_active,
            CompileArithmeticSite::PipelineLiveAccounting,
        )?)
        .ok_or(CompileError::ArithmeticOverflow {
            site: CompileArithmeticSite::PipelineLiveAccounting,
        })?;
    let image_retained_usize = image.retained_heap_bytes;
    let image_retained = as_u64(
        image_retained_usize,
        CompileArithmeticSite::PipelineLiveAccounting,
    )?;
    let image_inline = as_u64(
        image.inline_bytes,
        CompileArithmeticSite::PipelineLiveAccounting,
    )?;
    let image_peak = checked_sum(&[
        facade_live,
        kir_retained,
        image_retained,
        image_inline,
        image.scratch_bytes_upper_bound,
    ])?;
    let object_retained = as_u64(
        object.persistent_capacity_bytes,
        CompileArithmeticSite::PipelineLiveAccounting,
    )?;
    let object_peak = checked_sum(&[
        facade_live,
        kir_retained,
        image_retained,
        image_inline,
        object_retained,
        object
            .scratch_bytes_upper_bound
            .max(validation.scratch_bytes_upper_bound()),
    ])?;
    let compiled_inline_usize = size_of::<CompiledObjectV2>();
    let compiled_inline = as_u64(
        compiled_inline_usize,
        CompileArithmeticSite::PipelineLiveAccounting,
    )?;
    let static_expectation_inline_usize = size_of::<StaticCountExpectationV2>();
    if expectation.retained_bytes() != static_expectation_inline_usize {
        return Err(CompileError::InternalInvariant {
            at: "compiler-v2 static expectation retained layout",
        });
    }
    let compiled_without_expectation = compiled_inline
        .checked_sub(as_u64(
            static_expectation_inline_usize,
            CompileArithmeticSite::PipelineLiveAccounting,
        )?)
        .ok_or(CompileError::InternalInvariant {
            at: "compiler-v2 compiled object contains static expectation",
        })?;
    let base_without_expectation = checked_sum(&[
        facade_live,
        kir_retained,
        image_retained,
        image_inline,
        object_retained,
        compiled_without_expectation,
    ])?;
    let identity_peak = base_without_expectation
        .checked_add(CURRENT_IDENTITY_SCRATCH_BYTES_UPPER_BOUND_V2)
        .ok_or(CompileError::ArithmeticOverflow {
            site: CompileArithmeticSite::PipelineLiveAccounting,
        })?;
    let expectation_peak = base_without_expectation
        .checked_add(expectation.scratch_bytes_upper_bound())
        .ok_or(CompileError::ArithmeticOverflow {
            site: CompileArithmeticSite::PipelineLiveAccounting,
        })?;
    let final_peak = base_without_expectation
        .checked_add(as_u64(
            expectation.retained_bytes(),
            CompileArithmeticSite::PipelineLiveAccounting,
        )?)
        .ok_or(CompileError::ArithmeticOverflow {
            site: CompileArithmeticSite::PipelineLiveAccounting,
        })?;
    let pipeline_peak = planning_peak
        .max(kir_peak)
        .max(image_peak)
        .max(object_peak)
        .max(identity_peak)
        .max(expectation_peak)
        .max(final_peak);
    Ok(PipelineLiveAccountingV2::new(
        facade_live_usize,
        facade_high_water_usize,
        kir_retained_usize,
        image_retained_usize,
        image.inline_bytes,
        object.persistent_capacity_bytes,
        compiled_inline_usize,
        static_expectation_inline_usize,
        CURRENT_IDENTITY_SCRATCH_BYTES_UPPER_BOUND_V2,
        planning_peak,
        kir_peak,
        image_peak,
        object_peak,
        identity_peak,
        expectation_peak,
        final_peak,
        pipeline_peak,
    ))
}

#[allow(
    clippy::result_large_err,
    reason = "the crate preserves detailed typed planning and backend failures"
)]
fn peak_scratch_upper_bound_v2(
    candidate: LiteralAggregateBuildAccounting,
    projection: AggregateCountExactLiteralAotIdentityProjectionAccounting,
    kernel: KernelBuildAccountingV1,
    image: AotCountImageBuildReceiptV2,
    object: CountObjectBuildReportV2,
    validation: ObjectValidationAccountingV2,
    expectation: StaticCountExpectationBuildReportV2,
) -> Result<u64, CompileError> {
    Ok(as_u64(
        candidate.scratch_bytes,
        CompileArithmeticSite::ScratchAccounting,
    )?
    .max(projection.scratch_bytes_upper_bound())
    .max(as_u64(
        kernel.resources().validation_scratch_bytes(),
        CompileArithmeticSite::ScratchAccounting,
    )?)
    .max(image.scratch_bytes_upper_bound)
    .max(object.scratch_bytes_upper_bound)
    .max(validation.scratch_bytes_upper_bound())
    .max(CURRENT_IDENTITY_SCRATCH_BYTES_UPPER_BOUND_V2)
    .max(expectation.scratch_bytes_upper_bound()))
}

fn map_canonical(_error: CanonicalError) -> CompileError {
    CompileError::ArithmeticOverflow {
        site: CompileArithmeticSite::IdentityEncoding,
    }
}

#[cfg(test)]
pub(crate) mod hard_identity_gate_trace {
    use std::cell::Cell;

    std::thread_local! {
        static CALLS: Cell<u64> = const { Cell::new(0) };
        static MANIFEST_PASSES_AT_LAST_GATE: Cell<u64> = const { Cell::new(u64::MAX) };
    }

    pub(crate) fn record(manifest_passes: u64) {
        CALLS.with(|calls| calls.set(calls.get().saturating_add(1)));
        MANIFEST_PASSES_AT_LAST_GATE.with(|passes| passes.set(manifest_passes));
    }

    pub(crate) fn reset() {
        CALLS.with(|calls| calls.set(0));
        MANIFEST_PASSES_AT_LAST_GATE.with(|passes| passes.set(u64::MAX));
    }

    pub(crate) fn observation() -> (u64, u64) {
        (
            CALLS.with(Cell::get),
            MANIFEST_PASSES_AT_LAST_GATE.with(Cell::get),
        )
    }
}
