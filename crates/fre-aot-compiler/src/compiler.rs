#![allow(
    clippy::result_large_err,
    reason = "the typed refusal retains complete allocation-accounted facade diagnostics inline; boxing would add an unaccounted error-path allocation"
)]

use core::mem::size_of;

use fre::{
    AGGREGATE_COUNT_EXACT_LITERAL_AOT_CANDIDATE_IDENTITY_WORK_UPPER_BOUND_V1,
    AGGREGATE_COUNT_EXACT_LITERAL_AOT_PLANNING_WORK_UPPER_BOUND_V1, AggregateBuildLimits,
    AggregateBuilder, AggregateCountExactLiteralAotIdentityProjectionAccounting,
    AggregateCountExactLiteralAotPlannedCandidate, AggregateExactLiteralSemantics,
    AggregateOperation, AggregatePlanSelection, AggregateStrategy, LiteralAggregateBuildAccounting,
    LiteralAggregateOperation, RustProfile,
};
use fre_aot_macho::{
    AbiKind, BindingIdentity, BuiltObject, CALL_ABI_SCHEMA_V1, ENTRY_OFFSET_V1, METADATA_BYTES_V1,
    METADATA_VERSION, PLATFORM_MACOS, STATUS_BITS_V1, emit_aggregate_object,
};
use fre_jit_aarch64::{
    CodeLabel, DataSymbol, DecodedInstruction, NativeAggregateImage, Relocation, TargetSpec,
    emit_exact_aggregate,
};
use fre_kernel_ir::{
    AggregateOutput, Block, Count, DataBlob, ExactAggregateProgram, ResourceAccounting,
    build_exact_aggregate,
};
use sha2::{Digest, Sha256};

use crate::{
    canonical::{CanonicalEncoder, CanonicalError, EncodedDigest},
    error::{
        CandidateContractViolation, CompileArithmeticSite, CompileError, CompileResource,
        ContractField,
    },
    identity::LiveLiteralIdentity,
    manifest::{
        AOT_AGGREGATE_BACKEND_VERSION_V1, MAX_COMPILER_IDENTITY_WORK_V1,
        MAX_NATIVE_AGGREGATE_AUDIT_WORK_V1, MacosAarch64CountManifestV1,
    },
    receipt::{
        CompileAccountingV1, CompileReceiptV1, CompiledObject, KernelBuildAccountingV1,
        KernelProgramShapeV1, PipelineLiveAccountingV1,
    },
    static_expectation::STATIC_COUNT_EXPECTATION_PROJECTION_SCRATCH_UPPER_BOUND_V1,
};

const OBJECT_BINDING_DOMAIN: &[u8] = b"FRE-AOT-COMPILER-OBJECT-BINDING\0\x01";

/// Plan and compile one owned UTF-8 source under the manifest's fixed policy.
///
/// Length and allocation capacity are checked on raw bytes before UTF-8
/// validation, syntax parsing, literal extraction, or identity hashing. The
/// allocation is then transferred into `String` without copying. This is the
/// complete manifest-first production entry.
pub fn plan_and_compile_macos_aarch64_count(
    manifest: MacosAarch64CountManifestV1,
    pattern: Vec<u8>,
    profile: RustProfile,
) -> Result<CompiledObject, CompileError> {
    authenticate_manifest(&manifest)?;
    let source_bytes =
        u64::try_from(pattern.len()).map_err(|_| CompileError::ArithmeticOverflow {
            site: CompileArithmeticSite::SourceLength,
        })?;
    enforce(
        CompileResource::SourceBytes,
        source_bytes,
        manifest.policy().max_source_bytes,
    )?;
    enforce(
        CompileResource::SourceCapacityBytes,
        u64::try_from(pattern.capacity()).map_err(|_| CompileError::ArithmeticOverflow {
            site: CompileArithmeticSite::SourceLength,
        })?,
        manifest.policy().max_source_bytes,
    )?;
    enforce(
        CompileResource::FacadePlanningWork,
        AGGREGATE_COUNT_EXACT_LITERAL_AOT_PLANNING_WORK_UPPER_BOUND_V1,
        manifest.policy().max_facade_planning_work,
    )?;
    enforce(
        CompileResource::CandidateIdentityWork,
        AGGREGATE_COUNT_EXACT_LITERAL_AOT_CANDIDATE_IDENTITY_WORK_UPPER_BOUND_V1,
        manifest.policy().max_candidate_identity_work,
    )?;
    let source_utf8_validation_work = source_bytes;
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
    compile_macos_aarch64_count_candidate_inner(&candidate, &manifest, source_utf8_validation_work)
}

/// Lower-level compilation of an already-spent fixed-policy facade plan.
///
/// This path validates and reports the authenticated planning receipt, but it
/// cannot prospectively refuse the facade effects because they happened
/// before entry. Use [`plan_and_compile_macos_aarch64_count`] for the complete
/// manifest-before-planning boundary.
#[allow(
    clippy::needless_pass_by_value,
    reason = "the public lower-level API preserves its existing opaque-candidate ownership boundary"
)]
pub fn compile_macos_aarch64_count_candidate(
    candidate: AggregateCountExactLiteralAotPlannedCandidate<'_>,
    manifest: MacosAarch64CountManifestV1,
) -> Result<CompiledObject, CompileError> {
    compile_macos_aarch64_count_candidate_inner(&candidate, &manifest, 0)
}

#[allow(
    clippy::too_many_lines,
    reason = "the linear compiler transaction keeps all authenticated stage receipts and resource gates visible in one ownership scope"
)]
fn compile_macos_aarch64_count_candidate_inner(
    candidate: &AggregateCountExactLiteralAotPlannedCandidate<'_>,
    manifest: &MacosAarch64CountManifestV1,
    source_utf8_validation_work: u64,
) -> Result<CompiledObject, CompileError> {
    authenticate_manifest(manifest)?;
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
    let candidate_identity_projection = candidate.identity_projection_accounting();
    enforce(
        CompileResource::CandidateIdentityWork,
        candidate_identity_projection.projection_work_upper_bound(),
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
    let kir_identity = program.cache_identity();
    let kernel_build = kernel_build_accounting(&program)?;
    let kernel_stats = kernel_build.search_shape();

    let native_audit_scratch_preflight = native_audit_scratch_upper_bound_for_code(
        manifest.policy().native.max_code_bytes,
        manifest,
    )?;
    enforce(
        CompileResource::PeakScratchBytes,
        native_audit_scratch_preflight,
        manifest.policy().max_peak_scratch_bytes,
    )?;
    let image = emit_exact_aggregate(&program, manifest.policy().native)?;
    authenticate_native(&image, kir_identity, literal.len(), manifest)?;
    let native_artifact_identity = image.artifact_identity();
    let native_stats = image.stats();

    let binding_digest = object_binding_digest(
        manifest,
        semantic_binding_identity.as_bytes(),
        planning_receipt_identity.as_bytes(),
        live_literal_identity,
        literal_bytes,
        candidate_identity_projection,
        candidate_build,
        kir_identity.as_bytes(),
        kernel_stats,
        &image,
    )
    .map_err(map_canonical)?;
    let object_binding_identity = BindingIdentity::new(binding_digest.bytes)?;
    let object = emit_aggregate_object(&image, object_binding_identity, manifest.policy().object)?;
    authenticate_object(&object, &image, object_binding_identity)?;

    let metadata = object.metadata();
    let object_report = object.report();
    let compile_identity = object.compile_identity();
    let object_identity = object.object_identity();
    let literal_bytes_u32 =
        u32::try_from(literal.len()).map_err(|_| CompileError::ArithmeticOverflow {
            site: CompileArithmeticSite::LiteralLength,
        })?;
    let final_persistent_bytes = object_report
        .persistent_capacity_bytes
        .checked_add(size_of::<CompiledObject>())
        .ok_or(CompileError::ArithmeticOverflow {
            site: CompileArithmeticSite::PersistentAccounting,
        })?;
    let peak_scratch_bytes_upper_bound = peak_scratch_upper_bound(
        candidate_build,
        candidate_identity_projection,
        manifest,
        native_stats.scratch_bytes,
        object_report.scratch_bytes,
    )?;
    let pipeline_live = pipeline_live_accounting(
        &planning,
        kernel_build,
        &image,
        native_stats.scratch_bytes,
        object_report,
        manifest,
    )?;

    let mut accounting = CompileAccountingV1::draft(
        &planning,
        candidate_identity_projection,
        candidate_build,
        kernel_build,
        native_stats,
        object_report,
        MAX_NATIVE_AGGREGATE_AUDIT_WORK_V1,
        source_utf8_validation_work,
        manifest.identity_bytes_hashed(),
        literal_bytes,
        binding_digest.hashed_bytes,
        final_persistent_bytes,
        peak_scratch_bytes_upper_bound,
        pipeline_live,
    );
    let mut receipt = CompileReceiptV1::unsealed(
        manifest,
        semantic_binding_identity,
        planning_receipt_identity,
        live_literal_identity,
        literal_bytes_u32,
        kir_identity,
        native_artifact_identity,
        object_binding_identity,
        metadata,
        compile_identity,
        object_identity,
        &accounting,
    );
    let receipt_identity_bytes_hashed = receipt.canonical_body_bytes().map_err(map_canonical)?;
    accounting
        .close(receipt_identity_bytes_hashed)
        .map_err(map_canonical)?;
    enforce(
        CompileResource::CompilerIdentityWork,
        accounting.compiler_identity_work(),
        MAX_COMPILER_IDENTITY_WORK_V1,
    )?;
    enforce(
        CompileResource::PipelineWork,
        accounting.reported_pipeline_work_upper_bound(),
        manifest.policy().max_pipeline_work,
    )?;
    enforce(
        CompileResource::FinalPersistentBytes,
        u64::try_from(final_persistent_bytes).map_err(|_| CompileError::ArithmeticOverflow {
            site: CompileArithmeticSite::PersistentAccounting,
        })?,
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
    receipt.replace_accounting(&accounting);
    if receipt.canonical_body_bytes().map_err(map_canonical)? != receipt_identity_bytes_hashed {
        return Err(CompileError::InternalInvariant {
            at: "receipt canonical length changed after fixed-width accounting closure",
        });
    }
    receipt.seal().map_err(map_canonical)?;
    CompiledObject::new(object, receipt).map_err(|_| CompileError::InternalInvariant {
        at: "sealed receipt did not authenticate its freshly built object",
    })
}

pub(crate) fn authenticate_candidate(
    candidate: &AggregateCountExactLiteralAotPlannedCandidate<'_>,
) -> Result<(), CompileError> {
    if candidate.operation() != AggregateOperation::Count {
        return Err(CompileError::CandidateContract {
            violation: CandidateContractViolation::Operation,
        });
    }
    let plan = candidate.plan_identity();
    if plan.semantics != candidate.semantics()
        || !matches!(
            candidate.semantics(),
            AggregateExactLiteralSemantics::UnicodeOffByteBoundaries
                | AggregateExactLiteralSemantics::UnicodeOnNonemptyUtf8Literal
        )
    {
        return Err(CompileError::CandidateContract {
            violation: CandidateContractViolation::Semantics,
        });
    }
    if candidate.semantics() == AggregateExactLiteralSemantics::UnicodeOnNonemptyUtf8Literal
        && (candidate.literal().is_empty() || core::str::from_utf8(candidate.literal()).is_err())
    {
        return Err(CompileError::CandidateContract {
            violation: CandidateContractViolation::UnicodeLiteral,
        });
    }
    if plan.kernel.operation != LiteralAggregateOperation::Count {
        return Err(CompileError::CandidateContract {
            violation: CandidateContractViolation::KernelOperation,
        });
    }
    if candidate.build_accounting().needle_bytes != candidate.literal().len() {
        return Err(CompileError::CandidateContract {
            violation: CandidateContractViolation::BuildLiteralBytes,
        });
    }
    let planning = candidate.planning_accounting();
    let projection = candidate.identity_projection_accounting();
    if projection.allocations() != 0
        || projection.planning_identity_bytes_hashed() != planning.identity_bytes_hashed()
        || planning.source_bytes() != planning.syntax_prospective().source_bytes
        || planning.construction_actual().work > planning.construction_prospective().work
    {
        return Err(CompileError::CandidateContract {
            violation: CandidateContractViolation::PlanningReceipt,
        });
    }
    Ok(())
}

pub(crate) fn authenticate_kernel(
    program: &ExactAggregateProgram<Count>,
    literal: &[u8],
) -> Result<(), CompileError> {
    if program.literal() != literal {
        return Err(CompileError::ContractMismatch {
            field: ContractField::KernelLiteral,
        });
    }
    if program.output() != AggregateOutput::Count {
        return Err(CompileError::ContractMismatch {
            field: ContractField::KernelOutput,
        });
    }
    Ok(())
}

pub(crate) fn kernel_build_accounting(
    program: &ExactAggregateProgram<Count>,
) -> Result<KernelBuildAccountingV1, CompileError> {
    let literal_len = program.literal().len();
    let serialized_bytes = literal_len
        .checked_add(53)
        .ok_or(CompileError::ArithmeticOverflow {
            site: CompileArithmeticSite::WorkAccounting,
        })?;
    let padded_literal = literal_len.checked_add(15).map(|bytes| bytes & !15).ok_or(
        CompileError::ArithmeticOverflow {
            site: CompileArithmeticSite::WorkAccounting,
        },
    )?;
    let estimated_code_bytes =
        padded_literal
            .checked_add(240)
            .ok_or(CompileError::ArithmeticOverflow {
                site: CompileArithmeticSite::WorkAccounting,
            })?;
    let work_factor = u64::try_from(literal_len)
        .ok()
        .and_then(|bytes| bytes.checked_add(8))
        .ok_or(CompileError::ArithmeticOverflow {
            site: CompileArithmeticSite::WorkAccounting,
        })?;
    let resources = program.construction_resources();
    let block_request =
        4_usize
            .checked_mul(size_of::<Block>())
            .ok_or(CompileError::ArithmeticOverflow {
                site: CompileArithmeticSite::PersistentAccounting,
            })?;
    let data_table_request = size_of::<DataBlob>();
    let raw_request = literal_len
        .checked_add(block_request)
        .and_then(|bytes| bytes.checked_add(data_table_request))
        .ok_or(CompileError::ArithmeticOverflow {
            site: CompileArithmeticSite::PersistentAccounting,
        })?;
    let allocation_request =
        raw_request
            .checked_add(serialized_bytes)
            .ok_or(CompileError::ArithmeticOverflow {
                site: CompileArithmeticSite::PersistentAccounting,
            })?;
    if resources.version() != ResourceAccounting::VERSION
        || resources.allocation_requests() != 4
        || resources.literal_allocation_request_bytes() != literal_len
        || resources.block_allocation_request_bytes() != block_request
        || resources.data_table_allocation_request_bytes() != data_table_request
        || resources.raw_allocation_request_bytes() != raw_request
        || resources.serialized_allocation_request_bytes() != serialized_bytes
        || resources.allocation_request_bytes() != allocation_request
        || resources.hash_invocations() != 2
    {
        return Err(CompileError::InternalInvariant {
            at: "typed KIR construction receipt shape",
        });
    }
    let shape = KernelProgramShapeV1::new(
        4,
        4,
        1,
        literal_len,
        serialized_bytes,
        estimated_code_bytes,
        resources.validation_work(),
        work_factor,
    );
    Ok(KernelBuildAccountingV1::new(shape, resources))
}

fn authenticate_native(
    image: &NativeAggregateImage,
    kir_identity: fre_kernel_ir::AggregateProgramIdentity,
    literal_bytes: usize,
    manifest: &MacosAarch64CountManifestV1,
) -> Result<(), CompileError> {
    require(
        image.backend_version().0 == AOT_AGGREGATE_BACKEND_VERSION_V1,
        ContractField::NativeBackendVersion,
    )?;
    require(
        image.source_identity() == kir_identity,
        ContractField::NativeSourceIdentity,
    )?;
    require(
        image.output() == AggregateOutput::Count,
        ContractField::NativeOutput,
    )?;
    require(
        usize::try_from(image.literal_bytes()).ok() == Some(literal_bytes),
        ContractField::NativeLiteralBytes,
    )?;
    let target = image.target();
    let expected = TargetSpec::AARCH64_AAPCS64;
    require(
        target.architecture == expected.architecture,
        ContractField::NativeArchitecture,
    )?;
    require(
        target.little_endian == expected.little_endian,
        ContractField::NativeByteOrder,
    )?;
    require(
        target.pointer_width == expected.pointer_width,
        ContractField::NativePointerWidth,
    )?;
    require(target.abi == expected.abi, ContractField::NativeAbi)?;
    require(
        target.features.contains(manifest.required_cpu_features())
            && target.features.bits() & !manifest.allowed_cpu_features().bits() == 0,
        ContractField::NativeFeatures,
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "the object authenticator enumerates the complete metadata and identity contract field by field"
)]
fn authenticate_object(
    object: &BuiltObject,
    image: &NativeAggregateImage,
    binding: BindingIdentity,
) -> Result<(), CompileError> {
    let metadata = object.metadata();
    require(
        metadata.format_version() == METADATA_VERSION,
        ContractField::MetadataVersion,
    )?;
    require(
        usize::from(metadata.record_bytes()) == METADATA_BYTES_V1,
        ContractField::MetadataRecordBytes,
    )?;
    require(
        metadata.backend_version() == AOT_AGGREGATE_BACKEND_VERSION_V1,
        ContractField::MetadataBackendVersion,
    )?;
    require(
        metadata.abi_kind() == AbiKind::Aggregate,
        ContractField::MetadataAbiKind,
    )?;
    require(metadata.output_kind() == 1, ContractField::MetadataOutput)?;
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
        metadata.status_bits() == STATUS_BITS_V1,
        ContractField::MetadataStatusBits,
    )?;
    require(
        metadata.abi_schema() == CALL_ABI_SCHEMA_V1,
        ContractField::MetadataAbiSchema,
    )?;
    require(
        metadata.features() == target.features.bits(),
        ContractField::MetadataFeatures,
    )?;
    let layout = image.layout();
    require(
        metadata.payload_bytes() == layout.total_mapped_bytes,
        ContractField::MetadataPayloadBytes,
    )?;
    require(
        metadata.entry_offset() == ENTRY_OFFSET_V1,
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
        metadata.source_identity() == image.source_identity().as_bytes(),
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
    )?;
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "the binding intentionally covers every pre-object identity and stage receipt"
)]
fn object_binding_digest(
    manifest: &MacosAarch64CountManifestV1,
    semantic_binding_identity: &[u8; 32],
    planning_receipt_identity: &[u8; 32],
    live_literal_identity: LiveLiteralIdentity,
    literal_bytes: u64,
    candidate_identity_projection: AggregateCountExactLiteralAotIdentityProjectionAccounting,
    candidate_build: LiteralAggregateBuildAccounting,
    kir_identity: &[u8; 32],
    kernel_stats: KernelProgramShapeV1,
    image: &NativeAggregateImage,
) -> Result<EncodedDigest, CanonicalError> {
    let mut encoder = CanonicalEncoder::hashing();
    encoder.raw(OBJECT_BINDING_DOMAIN)?;
    encoder.raw(manifest.identity().as_bytes())?;
    encoder.raw(semantic_binding_identity)?;
    encoder.raw(planning_receipt_identity)?;
    encoder.raw(live_literal_identity.as_bytes())?;
    encoder.u64(literal_bytes)?;
    encoder.u64(candidate_identity_projection.semantic_identity_bytes_hashed())?;
    encoder.u64(candidate_identity_projection.planning_identity_bytes_hashed())?;
    encoder.u64(candidate_identity_projection.projection_work_upper_bound())?;
    encoder.u64(candidate_identity_projection.scratch_bytes_upper_bound())?;
    encoder.u8(candidate_identity_projection.allocations())?;
    encode_candidate_build(&mut encoder, candidate_build)?;
    encoder.raw(kir_identity)?;
    encode_kernel_stats(&mut encoder, kernel_stats)?;
    encoder.u16(image.backend_version().0)?;
    let target = image.target();
    encoder.u8(target.architecture)?;
    encoder.boolean(target.little_endian)?;
    encoder.u8(target.pointer_width)?;
    encoder.u8(target.abi)?;
    encoder.u64(target.features.bits())?;
    encoder.u8(1)?; // AggregateOutput::Count.
    encoder.u32(image.literal_bytes())?;
    encoder.raw(image.artifact_identity().as_bytes())?;
    let layout = image.layout();
    encoder.u32(layout.code_alignment)?;
    encoder.u32(layout.rodata_alignment)?;
    encoder.u32(layout.rodata_from_code_start)?;
    encoder.u32(layout.total_mapped_bytes)?;
    let stats = image.stats();
    encoder.u32(stats.code_bytes)?;
    encoder.u32(stats.data_bytes)?;
    encoder.u32(stats.relocations)?;
    encoder.u32(stats.labels)?;
    encoder.u64(stats.emission_work)?;
    encoder.u64(stats.scratch_bytes)?;
    encoder.u32(stats.vector_instructions)?;
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

fn encode_kernel_stats(
    encoder: &mut CanonicalEncoder,
    stats: KernelProgramShapeV1,
) -> Result<(), CanonicalError> {
    encoder.usize(stats.blocks())?;
    encoder.usize(stats.instructions())?;
    encoder.usize(stats.data_blobs())?;
    encoder.usize(stats.data_bytes())?;
    encoder.usize(stats.serialized_bytes())?;
    encoder.usize(stats.estimated_code_bytes())?;
    encoder.u64(stats.validation_work())?;
    encoder.u64(stats.work_factor())
}

pub(crate) fn hash_live_literal(literal: &[u8]) -> LiveLiteralIdentity {
    let digest = Sha256::digest(literal);
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(&digest);
    LiveLiteralIdentity::new(bytes)
}

fn peak_scratch_upper_bound(
    candidate_build: LiteralAggregateBuildAccounting,
    candidate_identity_projection: AggregateCountExactLiteralAotIdentityProjectionAccounting,
    manifest: &MacosAarch64CountManifestV1,
    native_scratch: u64,
    object_scratch: u64,
) -> Result<u64, CompileError> {
    let candidate_scratch = u64::try_from(candidate_build.scratch_bytes).map_err(|_| {
        CompileError::ArithmeticOverflow {
            site: CompileArithmeticSite::ScratchAccounting,
        }
    })?;
    let identity_scratch =
        u64::try_from(size_of::<Sha256>()).map_err(|_| CompileError::ArithmeticOverflow {
            site: CompileArithmeticSite::ScratchAccounting,
        })?;
    Ok(candidate_scratch
        .max(manifest.policy().kernel_ir.max_validation_scratch_bytes)
        .max(native_scratch)
        .max(object_scratch)
        .max(candidate_identity_projection.scratch_bytes_upper_bound())
        .max(STATIC_COUNT_EXPECTATION_PROJECTION_SCRATCH_UPPER_BOUND_V1)
        .max(identity_scratch))
}

#[allow(
    clippy::too_many_lines,
    reason = "the co-live proof names each pipeline phase and retained predecessor explicitly"
)]
fn pipeline_live_accounting(
    planning: &fre::AggregateCountExactLiteralAotPlanningAccounting,
    kernel: KernelBuildAccountingV1,
    image: &NativeAggregateImage,
    native_scratch: u64,
    object: fre_aot_macho::ObjectBuildReport,
    manifest: &MacosAarch64CountManifestV1,
) -> Result<PipelineLiveAccountingV1, CompileError> {
    let facade_actual = planning.construction_actual();
    let facade_live_usize = facade_actual
        .live_persistent_bytes
        .checked_add(planning.source_capacity_bytes())
        .ok_or(CompileError::ArithmeticOverflow {
            site: CompileArithmeticSite::PipelineLiveAccounting,
        })?;
    let facade_high_water_usize = facade_actual
        .high_water_bytes
        .checked_add(planning.source_capacity_bytes())
        .ok_or(CompileError::ArithmeticOverflow {
            site: CompileArithmeticSite::PipelineLiveAccounting,
        })?;
    let facade_live = as_u64(
        facade_live_usize,
        CompileArithmeticSite::PersistentAccounting,
    )?;
    let facade_high_water = as_u64(
        facade_high_water_usize,
        CompileArithmeticSite::PersistentAccounting,
    )?;
    // Facade construction already includes the once-computed identity
    // projection scratch and the returned aggregate owner inline.
    let planning_peak = facade_high_water;

    let kir_inline_usize = size_of::<ExactAggregateProgram<Count>>();
    let kir_retained_total_usize = kernel.retained_program_bytes();
    let kir_retained_usize = kir_retained_total_usize
        .checked_sub(kir_inline_usize)
        .ok_or(CompileError::InternalInvariant {
            at: "KIR retained receipt excludes typed program",
        })?;
    let kir_retained = as_u64(
        kir_retained_usize,
        CompileArithmeticSite::PersistentAccounting,
    )?;
    let kir_inline = as_u64(
        kir_inline_usize,
        CompileArithmeticSite::PersistentAccounting,
    )?;
    let kernel_resources = kernel.resources();
    let kir_construction_peak = [
        kernel_resources.validation_phase_peak_bytes(),
        kernel_resources.serialization_phase_peak_bytes(),
        kernel_resources.identity_phase_peak_bytes(),
    ]
    .into_iter()
    .max()
    .ok_or(CompileError::InternalInvariant {
        at: "KIR construction phase set",
    })?;
    let kir_peak = facade_live
        .checked_add(as_u64(
            kir_construction_peak,
            CompileArithmeticSite::PipelineLiveAccounting,
        )?)
        .ok_or(CompileError::ArithmeticOverflow {
            site: CompileArithmeticSite::PipelineLiveAccounting,
        })?;

    let native_retained_usize = native_retained_bytes(image)?;
    let native_retained = as_u64(
        native_retained_usize,
        CompileArithmeticSite::PersistentAccounting,
    )?;
    let native_inline_usize = size_of::<NativeAggregateImage>();
    let native_inline = as_u64(
        native_inline_usize,
        CompileArithmeticSite::PersistentAccounting,
    )?;
    let native_audit_scratch = native_audit_scratch_upper_bound(image, manifest)?;
    // Finalization may keep assembler vectors and the exact boxed result
    // co-live. The doubled retained term conservatively covers both copies;
    // the independent contract audit bound covers its second KIR and graph
    // work vectors.
    let native_transient = native_retained
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(native_scratch))
        .map(|bytes| bytes.max(native_retained.saturating_add(native_audit_scratch)))
        .ok_or(CompileError::ArithmeticOverflow {
            site: CompileArithmeticSite::PipelineLiveAccounting,
        })?;
    let native_peak = checked_sum(&[
        facade_live,
        kir_retained,
        kir_inline,
        native_inline,
        native_transient,
    ])?;

    let object_retained = as_u64(
        object.persistent_capacity_bytes,
        CompileArithmeticSite::PersistentAccounting,
    )?;
    let object_active_scratch = object
        .scratch_bytes
        .max(native_audit_scratch)
        .max(object.image_audit_scratch_upper_bound);
    let object_peak = checked_sum(&[
        facade_live,
        kir_retained,
        kir_inline,
        native_retained,
        native_inline,
        object_retained,
        object_active_scratch,
    ])?;

    let compiled_object_inline_usize = size_of::<CompiledObject>();
    let compiled_object_inline = as_u64(
        compiled_object_inline_usize,
        CompileArithmeticSite::PersistentAccounting,
    )?;
    let final_peak = checked_sum(&[
        facade_live,
        kir_retained,
        kir_inline,
        native_retained,
        native_inline,
        object_retained,
        compiled_object_inline,
        STATIC_COUNT_EXPECTATION_PROJECTION_SCRATCH_UPPER_BOUND_V1,
    ])?;
    let pipeline_peak = planning_peak
        .max(kir_peak)
        .max(native_peak)
        .max(object_peak)
        .max(final_peak);
    Ok(PipelineLiveAccountingV1::new(
        facade_live_usize,
        facade_high_water_usize,
        kir_retained_usize,
        kir_inline_usize,
        native_retained_usize,
        native_inline_usize,
        native_audit_scratch,
        object.persistent_capacity_bytes,
        compiled_object_inline_usize,
        STATIC_COUNT_EXPECTATION_PROJECTION_SCRATCH_UPPER_BOUND_V1,
        planning_peak,
        kir_peak,
        native_peak,
        object_peak,
        final_peak,
        pipeline_peak,
    ))
}

fn native_retained_bytes(image: &NativeAggregateImage) -> Result<usize, CompileError> {
    image
        .code()
        .len()
        .checked_add(image.rodata().len())
        .and_then(|bytes| {
            image
                .labels()
                .len()
                .checked_mul(size_of::<CodeLabel>())
                .and_then(|part| bytes.checked_add(part))
        })
        .and_then(|bytes| {
            image
                .symbols()
                .len()
                .checked_mul(size_of::<DataSymbol>())
                .and_then(|part| bytes.checked_add(part))
        })
        .and_then(|bytes| {
            image
                .relocations()
                .len()
                .checked_mul(size_of::<Relocation>())
                .and_then(|part| bytes.checked_add(part))
        })
        .ok_or(CompileError::ArithmeticOverflow {
            site: CompileArithmeticSite::PersistentAccounting,
        })
}

fn native_audit_scratch_upper_bound(
    image: &NativeAggregateImage,
    manifest: &MacosAarch64CountManifestV1,
) -> Result<u64, CompileError> {
    native_audit_scratch_upper_bound_for_code(
        as_u64(
            image.code().len(),
            CompileArithmeticSite::PipelineLiveAccounting,
        )?,
        manifest,
    )
}

fn native_audit_scratch_upper_bound_for_code(
    code_bytes: u64,
    manifest: &MacosAarch64CountManifestV1,
) -> Result<u64, CompileError> {
    let instructions = code_bytes
        .checked_add(3)
        .and_then(|bytes| bytes.checked_div(4))
        .ok_or(CompileError::ArithmeticOverflow {
            site: CompileArithmeticSite::PipelineLiveAccounting,
        })?;
    let decoded = instructions
        .checked_mul(as_u64(
            size_of::<DecodedInstruction>(),
            CompileArithmeticSite::PipelineLiveAccounting,
        )?)
        .ok_or(CompileError::ArithmeticOverflow {
            site: CompileArithmeticSite::PipelineLiveAccounting,
        })?;
    // Audit uses decoded instructions, store/protection sets, definite-init
    // state/pending, and reachability state/pending. Eight words per decoded
    // instruction conservatively cover all of those vector capacities.
    let graph_vectors = instructions
        .checked_mul(as_u64(
            size_of::<usize>(),
            CompileArithmeticSite::PipelineLiveAccounting,
        )?)
        .and_then(|bytes| bytes.checked_mul(8))
        .ok_or(CompileError::ArithmeticOverflow {
            site: CompileArithmeticSite::PipelineLiveAccounting,
        })?;
    let limits = manifest.policy().kernel_ir;
    let second_kir = u64::try_from(size_of::<Block>())
        .ok()
        .and_then(|width| width.checked_mul(limits.max_blocks))
        .and_then(|bytes| {
            u64::try_from(size_of::<DataBlob>())
                .ok()
                .and_then(|width| width.checked_mul(limits.max_data_blobs))
                .and_then(|part| bytes.checked_add(part))
        })
        .and_then(|bytes| bytes.checked_add(limits.max_data_bytes))
        .and_then(|bytes| bytes.checked_add(limits.max_serialized_bytes))
        .ok_or(CompileError::ArithmeticOverflow {
            site: CompileArithmeticSite::PipelineLiveAccounting,
        })?;
    checked_sum(&[
        decoded,
        graph_vectors,
        second_kir,
        as_u64(
            size_of::<Sha256>(),
            CompileArithmeticSite::PipelineLiveAccounting,
        )?,
    ])
}

pub(crate) fn checked_sum(values: &[u64]) -> Result<u64, CompileError> {
    values.iter().try_fold(0_u64, |sum, value| {
        sum.checked_add(*value)
            .ok_or(CompileError::ArithmeticOverflow {
                site: CompileArithmeticSite::PipelineLiveAccounting,
            })
    })
}

pub(crate) fn as_u64(value: usize, site: CompileArithmeticSite) -> Result<u64, CompileError> {
    u64::try_from(value).map_err(|_| CompileError::ArithmeticOverflow { site })
}

fn authenticate_manifest(manifest: &MacosAarch64CountManifestV1) -> Result<(), CompileError> {
    if !manifest.authenticates_itself() {
        return Err(CompileError::ContractMismatch {
            field: ContractField::ManifestIdentity,
        });
    }
    Ok(())
}

pub(crate) fn enforce(
    resource: CompileResource,
    required: u64,
    limit: u64,
) -> Result<(), CompileError> {
    if required > limit {
        return Err(CompileError::ResourceLimit {
            resource,
            limit,
            required,
        });
    }
    Ok(())
}

pub(crate) fn require(condition: bool, field: ContractField) -> Result<(), CompileError> {
    if !condition {
        return Err(CompileError::ContractMismatch { field });
    }
    Ok(())
}

fn map_canonical(_error: CanonicalError) -> CompileError {
    CompileError::ArithmeticOverflow {
        site: CompileArithmeticSite::IdentityEncoding,
    }
}
