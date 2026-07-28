use core::mem::size_of;

use fre_exact_alloc::{CopyError, ExactVec};
use fre_kernel_ir::{
    AggregateOutput, Count, ExactAggregateProgram, MAX_EXACT_AGGREGATE_LITERAL_BYTES,
};
use sha2::{Digest, Sha256};

use crate::{
    AOT_COUNT_IMAGE_SCHEMA_VERSION_V1, AotCountArtifactIdentity, AotCountCpuFeatures,
    AotCountImageBuildReceiptV1, AotCountImageLayoutV1, AotCountImageStatsV1, AotCountImageV1,
    AotCountLiteralManifestV1, AotCountTargetSpec, CodeLabelV1, CountAotArithmeticSite,
    CountAotError, CountAotResource, CountAotUnsupported, CountAuditReportV1, LabelKindV1,
    RelocationKindV1, RelocationTargetV1, RelocationV1, SUPPORTED_AOT_COUNT_BACKEND_TUPLES_V1,
    audit::{
        ConditionV1, audit_candidate_wrapper_inline_bytes_v1, audit_count_image_candidate_v1,
        audit_count_image_v1, audit_public_wrapper_inline_bytes_v1,
        audit_scratch_upper_bound_for_dimensions, audit_work_upper_bound_for_dimensions,
    },
};

const CODE_ALIGNMENT: usize = 16;
const MAX_CODE_BYTES_V1: u64 = 4 << 10;
const MAX_LABELS_V1: u64 = 16;
const MAX_RELOCATIONS_V1: u64 = 48;
const MAX_WORK_V1: u64 = 2 << 20;
const MAX_SCRATCH_BYTES_V1: u64 = 64 << 10;
const MAX_PERSISTENT_BYTES_V1: u64 = 64 << 10;
const IDENTITY_DOMAIN: &[u8] = b"FRE-AOT-AARCH64-COUNT-IMAGE\0\x01";

const X0: u8 = 0;
const X1: u8 = 1;
const X2: u8 = 2;
const X3: u8 = 3;
const X4: u8 = 4;
const X5: u8 = 5;
const X6: u8 = 6;
const X7: u8 = 7;
const X9: u8 = 9;
const X10: u8 = 10;
const X11: u8 = 11;
const X13: u8 = 13;
const X14: u8 = 14;
const X15: u8 = 15;

/// Caller-selected emission limits, each additionally capped by a hard bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountEmitLimitsV1 {
    pub max_code_bytes: u64,
    pub max_data_bytes: u64,
    pub max_labels: u64,
    pub max_relocations: u64,
    pub max_work: u64,
    pub max_scratch_bytes: u64,
    pub max_persistent_bytes: u64,
}

impl Default for CountEmitLimitsV1 {
    fn default() -> Self {
        Self {
            max_code_bytes: MAX_CODE_BYTES_V1,
            max_data_bytes: 0,
            max_labels: MAX_LABELS_V1,
            max_relocations: MAX_RELOCATIONS_V1,
            max_work: MAX_WORK_V1,
            max_scratch_bytes: MAX_SCRATCH_BYTES_V1,
            max_persistent_bytes: MAX_PERSISTENT_BYTES_V1,
        }
    }
}

/// O(1), source-bound conservative envelope for one Count image build.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountProspectiveReportV1 {
    pub code_bytes_upper_bound: u64,
    pub data_bytes_upper_bound: u64,
    pub labels_upper_bound: u64,
    pub relocations_upper_bound: u64,
    pub identity_bytes_hashed_upper_bound: u64,
    pub emission_scratch_bytes_upper_bound: u64,
    pub audit_work_upper_bound: u64,
    pub audit_scratch_bytes_upper_bound: u64,
    pub total_work_upper_bound: u64,
    pub scratch_bytes_upper_bound: u64,
    pub persistent_bytes_upper_bound: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Prospective {
    pub(crate) code_bytes: usize,
    pub(crate) labels: usize,
    pub(crate) relocations: usize,
    pub(crate) identity_bytes_hashed: u64,
    pub(crate) assembler_scratch: u64,
    pub(crate) emission_scratch: u64,
    pub(crate) image_backing: u64,
    pub(crate) image_assembly_scratch: u64,
    pub(crate) audit_work: u64,
    pub(crate) audit_scratch: u64,
    pub(crate) candidate_audit_scratch: u64,
    pub(crate) sealed_audit_scratch: u64,
    pub(crate) initial_identity_scratch: u64,
    pub(crate) sealed_identity_length_scratch: u64,
    pub(crate) sealed_identity_hash_scratch: u64,
    pub(crate) identity_scratch: u64,
    pub(crate) work: u64,
    pub(crate) scratch: u64,
    pub(crate) persistent: u64,
    pub(crate) scratch_limit: u64,
    pub(crate) persistent_limit: u64,
}

/// Compute the complete conservative build envelope without reading a literal
/// byte, allocating, hashing, emitting, or decoding.
pub fn prospective_count_v1(
    program: &ExactAggregateProgram<Count>,
) -> Result<CountProspectiveReportV1, CountAotError> {
    let literal_len = preflight_program_dimensions(program)?;
    let prospective = prospective(literal_len)?;
    Ok(CountProspectiveReportV1 {
        code_bytes_upper_bound: to_u64(
            prospective.code_bytes,
            CountAotArithmeticSite::Prospective,
        )?,
        data_bytes_upper_bound: 0,
        labels_upper_bound: to_u64(prospective.labels, CountAotArithmeticSite::Prospective)?,
        relocations_upper_bound: to_u64(
            prospective.relocations,
            CountAotArithmeticSite::Prospective,
        )?,
        identity_bytes_hashed_upper_bound: prospective.identity_bytes_hashed,
        emission_scratch_bytes_upper_bound: prospective.emission_scratch,
        audit_work_upper_bound: prospective.audit_work,
        audit_scratch_bytes_upper_bound: prospective.audit_scratch,
        total_work_upper_bound: prospective.work,
        scratch_bytes_upper_bound: prospective.scratch,
        persistent_bytes_upper_bound: prospective.persistent,
    })
}

/// Emit one genuine Count image directly from the sealed exact-aggregate KIR.
///
/// All caller and hard bounds are prospectively refused from O(1) dimensions
/// before literal traversal, instruction emission, identity hashing, decoding,
/// or audit.
#[allow(
    clippy::too_many_lines,
    reason = "one ordered build keeps every preflight, allocation, phase observation, and seal visible"
)]
pub fn emit_count_v1(
    program: &ExactAggregateProgram<Count>,
    limits: CountEmitLimitsV1,
) -> Result<AotCountImageV1, CountAotError> {
    let literal_len = preflight_program_dimensions(program)?;
    let mut prospective = prospective(literal_len)?;
    enforce_all(
        CountAotResource::CodeBytes,
        to_u64(prospective.code_bytes, CountAotArithmeticSite::Prospective)?,
        limits.max_code_bytes,
        MAX_CODE_BYTES_V1,
    )?;
    enforce_all(CountAotResource::DataBytes, 0, limits.max_data_bytes, 0)?;
    enforce_all(
        CountAotResource::Labels,
        to_u64(prospective.labels, CountAotArithmeticSite::Prospective)?,
        limits.max_labels,
        MAX_LABELS_V1,
    )?;
    enforce_all(
        CountAotResource::Relocations,
        to_u64(prospective.relocations, CountAotArithmeticSite::Prospective)?,
        limits.max_relocations,
        MAX_RELOCATIONS_V1,
    )?;
    enforce_all(
        CountAotResource::Work,
        prospective.work,
        limits.max_work,
        MAX_WORK_V1,
    )?;
    enforce_all(
        CountAotResource::ScratchBytes,
        prospective.scratch,
        limits.max_scratch_bytes,
        MAX_SCRATCH_BYTES_V1,
    )?;
    enforce_all(
        CountAotResource::PersistentBytes,
        prospective.persistent,
        limits.max_persistent_bytes,
        MAX_PERSISTENT_BYTES_V1,
    )?;
    prospective.scratch_limit = limits.max_scratch_bytes.min(MAX_SCRATCH_BYTES_V1);
    prospective.persistent_limit = limits.max_persistent_bytes.min(MAX_PERSISTENT_BYTES_V1);

    // The first literal byte access occurs only after complete prospective
    // admission above.
    let literal = program.literal();
    let literal_manifest = AotCountLiteralManifestV1::from_literal(literal).ok_or(
        CountAotError::InternalInvariant {
            at: "literal manifest",
        },
    )?;
    let finalized = canonical_template(literal, prospective)?;
    if finalized.code.len() > prospective.code_bytes
        || finalized.labels.len() > prospective.labels
        || finalized.relocations.len() > prospective.relocations
    {
        return Err(CountAotError::InternalInvariant {
            at: "emission exceeded prospective dimensions",
        });
    }
    let image_assembly_scratch = image_assembly_scratch_for_capacities(
        finalized.code.capacity(),
        finalized.labels.capacity(),
        finalized.relocations.capacity(),
    )?;
    if image_assembly_scratch != prospective.image_assembly_scratch {
        return Err(CountAotError::InternalInvariant {
            at: "image assembly scratch prospective",
        });
    }
    if image_assembly_scratch > prospective.scratch_limit {
        return Err(CountAotError::ResourceLimit {
            resource: CountAotResource::ScratchBytes,
            limit: prospective.scratch_limit,
            required: image_assembly_scratch,
        });
    }
    let Finalized {
        code,
        labels,
        relocations,
        code_bytes,
        label_count,
        relocation_count,
        emission_work,
        vector_instructions,
        code_capacity_bytes,
        label_capacity_bytes,
        relocation_capacity_bytes,
        emission_peak_scratch_bytes: assembler_peak_scratch_bytes,
    } = finalized;
    if assembler_peak_scratch_bytes != prospective.assembler_scratch {
        return Err(CountAotError::InternalInvariant {
            at: "assembler scratch seal",
        });
    }
    let emission_peak_scratch_bytes = assembler_peak_scratch_bytes.max(image_assembly_scratch);
    if emission_peak_scratch_bytes != prospective.emission_scratch {
        return Err(CountAotError::InternalInvariant {
            at: "emission scratch seal",
        });
    }
    let rodata_offset = align_up(code.len(), CODE_ALIGNMENT)?;
    let layout = AotCountImageLayoutV1 {
        code_alignment: u32::try_from(CODE_ALIGNMENT).expect("small alignment"),
        rodata_alignment: u32::try_from(CODE_ALIGNMENT).expect("small alignment"),
        rodata_from_code_start: to_u32(rodata_offset, CountAotArithmeticSite::ImageLayout)?,
        total_mapped_bytes: to_u32(rodata_offset, CountAotArithmeticSite::ImageLayout)?,
    };
    let target = AotCountTargetSpec {
        features: if vector_instructions == 0 {
            AotCountCpuFeatures::NONE
        } else {
            AotCountCpuFeatures::ASIMD
        },
        ..AotCountTargetSpec::AARCH64_AAPCS64_BASELINE
    };
    let support = SUPPORTED_AOT_COUNT_BACKEND_TUPLES_V1[0];
    let retained_heap_bytes = AotCountImageV1::retained_heap_bytes(
        code_capacity_bytes,
        label_capacity_bytes,
        relocation_capacity_bytes,
    )
    .ok_or(CountAotError::ArithmeticOverflow {
        site: CountAotArithmeticSite::Persistent,
    })?;
    let actual_persistent_bytes = retained_heap_bytes
        .checked_add(size_of::<AotCountImageV1>())
        .ok_or(CountAotError::ArithmeticOverflow {
            site: CountAotArithmeticSite::Persistent,
        })?;
    let actual_persistent_u64 =
        to_u64(actual_persistent_bytes, CountAotArithmeticSite::Persistent)?;
    if actual_persistent_u64 > prospective.persistent_limit {
        return Err(CountAotError::ResourceLimit {
            resource: CountAotResource::PersistentBytes,
            limit: prospective.persistent_limit,
            required: actual_persistent_u64,
        });
    }
    let mut image = AotCountImageV1 {
        support,
        target,
        source_identity: program.cache_identity(),
        literal_bytes: to_u32(literal.len(), CountAotArithmeticSite::ImageLayout)?,
        literal_manifest,
        layout,
        code,
        labels,
        relocations,
        stats: AotCountImageStatsV1 {
            code_bytes,
            data_bytes: 0,
            labels: label_count,
            relocations: relocation_count,
            emitted_instructions: code_bytes / 4,
            vector_instructions,
            emission_work,
            identity_bytes_hashed: 0,
            audit_work_upper_bound: prospective.audit_work,
            total_work_upper_bound: prospective.work,
            scratch_bytes_upper_bound: 0,
        },
        artifact_identity: AotCountArtifactIdentity::ZERO,
        build_receipt: AotCountImageBuildReceiptV1 {
            support,
            code_capacity_bytes,
            label_capacity_bytes,
            relocation_capacity_bytes,
            retained_heap_bytes,
            inline_bytes: size_of::<AotCountImageV1>(),
            emission_peak_scratch_bytes,
            work_upper_bound: prospective.work,
            scratch_bytes_upper_bound: 0,
            audit: CountAuditReportV1::default(),
        },
    };
    observe_emit_image_phase_scratch(&image, prospective, EmitImagePhaseV1::InitialIdentityLength)?;
    let identity_bytes_hashed = artifact_identity_encoded_len(&image)?;
    if identity_bytes_hashed > prospective.identity_bytes_hashed {
        return Err(CountAotError::InternalInvariant {
            at: "artifact identity exceeded prospective bytes",
        });
    }
    image.stats.identity_bytes_hashed = identity_bytes_hashed;
    let candidate_audit_scratch =
        observe_emit_image_phase_scratch(&image, prospective, EmitImagePhaseV1::CandidateAudit)?;
    let audit = audit_count_image_candidate_v1(program, &image, prospective)?;
    if audit.work_upper_bound != prospective.audit_work
        || audit.scratch_bytes_upper_bound != prospective.audit_scratch
    {
        return Err(CountAotError::InternalInvariant {
            at: "audit prospective seal",
        });
    }
    let scratch_bytes_upper_bound = emission_peak_scratch_bytes
        .max(candidate_audit_scratch)
        .max(prospective.sealed_audit_scratch)
        .max(prospective.identity_scratch);
    if scratch_bytes_upper_bound != prospective.scratch {
        return Err(CountAotError::InternalInvariant {
            at: "complete scratch seal",
        });
    }
    if scratch_bytes_upper_bound > prospective.scratch_limit {
        return Err(CountAotError::ResourceLimit {
            resource: CountAotResource::ScratchBytes,
            limit: prospective.scratch_limit,
            required: scratch_bytes_upper_bound,
        });
    }
    image.stats.scratch_bytes_upper_bound = scratch_bytes_upper_bound;
    image.build_receipt.scratch_bytes_upper_bound = scratch_bytes_upper_bound;
    image.build_receipt.audit = audit;
    observe_emit_image_phase_scratch(&image, prospective, EmitImagePhaseV1::SealedIdentityLength)?;
    let sealed_identity_bytes = artifact_identity_encoded_len(&image)?;
    if sealed_identity_bytes != identity_bytes_hashed {
        return Err(CountAotError::InternalInvariant {
            at: "artifact identity encoded length changed",
        });
    }
    observe_emit_image_phase_scratch(&image, prospective, EmitImagePhaseV1::SealedIdentityHash)?;
    let (artifact_identity, observed_identity_bytes) = compute_artifact_identity(&image)?;
    if observed_identity_bytes != identity_bytes_hashed {
        return Err(CountAotError::InternalInvariant {
            at: "artifact identity byte count",
        });
    }
    image.artifact_identity = artifact_identity;
    observe_emit_image_phase_scratch(&image, prospective, EmitImagePhaseV1::SealedAudit)?;
    let sealed_audit = audit_count_image_v1(program, &image)?;
    if sealed_audit != audit {
        return Err(CountAotError::InternalInvariant {
            at: "sealed audit report changed",
        });
    }
    Ok(image)
}

fn preflight_program_dimensions(
    program: &ExactAggregateProgram<Count>,
) -> Result<usize, CountAotError> {
    if program.output() != AggregateOutput::Count {
        return Err(CountAotError::Unsupported {
            reason: CountAotUnsupported::Output,
        });
    }
    let literal_len = program.literal().len();
    let support = SUPPORTED_AOT_COUNT_BACKEND_TUPLES_V1[0];
    if literal_len > MAX_EXACT_AGGREGATE_LITERAL_BYTES
        || literal_len > usize::from(support.max_literal_bytes)
    {
        return Err(CountAotError::Unsupported {
            reason: CountAotUnsupported::LiteralWidth,
        });
    }
    // `ExactAggregateProgram<Count>` is the structural witness: its fields
    // and constructors are private to `fre-kernel-ir`, and the only safe
    // constructor seals the fixed four-block/four-instruction exact-literal
    // shape with one literal blob. Do not reopen the generic KIR or expose a
    // broad statistics accessor merely to repeat that sealed invariant here.
    Ok(literal_len)
}

#[allow(
    clippy::items_after_statements,
    clippy::too_many_lines,
    reason = "named work constants stay next to the phase formula they justify"
)]
pub(crate) fn prospective(literal_len: usize) -> Result<Prospective, CountAotError> {
    const FIXED_MOV64_INSTRUCTIONS: usize = 4;
    const RETURN_INSTRUCTIONS: usize =
        1 + FIXED_MOV64_INSTRUCTIONS + 1 + FIXED_MOV64_INSTRUCTIONS + 1;
    const EMPTY_BODY_INSTRUCTIONS: usize = FIXED_MOV64_INSTRUCTIONS + 1 + 1 + 1 + 1;
    const SINGLE_SETUP_INSTRUCTIONS: usize = (3 * FIXED_MOV64_INSTRUCTIONS) + 1;
    const SINGLE_VECTOR_INSTRUCTIONS: usize = 20;
    const SINGLE_TAIL_INSTRUCTIONS: usize = 11;
    const CHUNKED_SETUP_INSTRUCTIONS: usize = 14;
    const CHUNKED_FINISH_INSTRUCTIONS: usize = 8;
    const FULL_CHUNK_INSTRUCTIONS: usize = 11;
    const TAIL_BYTE_INSTRUCTIONS: usize = 7;
    let (instructions, labels, relocations) = if literal_len == 0 {
        (
            EMPTY_BODY_INSTRUCTIONS + RETURN_INSTRUCTIONS,
            3_usize,
            2_usize,
        )
    } else if literal_len == 1 {
        (
            SINGLE_SETUP_INSTRUCTIONS
                + SINGLE_VECTOR_INSTRUCTIONS
                + SINGLE_TAIL_INSTRUCTIONS
                + RETURN_INSTRUCTIONS,
            6,
            7,
        )
    } else {
        let chunks = literal_len / 8;
        let tail = literal_len % 8;
        let instructions = CHUNKED_SETUP_INSTRUCTIONS
            .checked_add(CHUNKED_FINISH_INSTRUCTIONS)
            .and_then(|value| value.checked_add(RETURN_INSTRUCTIONS))
            .and_then(|value| value.checked_add(chunks.checked_mul(FULL_CHUNK_INSTRUCTIONS)?))
            .and_then(|value| value.checked_add(tail.checked_mul(TAIL_BYTE_INSTRUCTIONS)?))
            .ok_or(arithmetic_prospective())?;
        let relocations = 5_usize
            .checked_add(chunks)
            .and_then(|value| value.checked_add(tail))
            .ok_or(arithmetic_prospective())?;
        (instructions, 5, relocations)
    };
    let code_bytes = instructions
        .checked_mul(4)
        .ok_or(arithmetic_prospective())?;
    let identity_bytes_hashed = identity_bytes_upper_bound(code_bytes, labels, relocations)?;
    let label_order = label_order_work_upper_bound(labels)?;
    let audit_work = audit_work_upper_bound_for_dimensions(code_bytes, labels, relocations)?;
    let audit_scratch = audit_scratch_upper_bound_for_dimensions(code_bytes, labels, relocations)?;
    let assembler_scratch =
        assembler_scratch_upper_bound_for_dimensions(code_bytes, labels, relocations)?;
    let image_backing = image_backing_bytes_for_capacities(code_bytes, labels, relocations)?;
    let image_assembly_scratch =
        image_assembly_scratch_for_capacities(code_bytes, labels, relocations)?;
    let emission_scratch = assembler_scratch.max(image_assembly_scratch);
    let candidate_audit_scratch =
        emit_audit_phase_scratch(audit_scratch, image_backing, EmitAuditPhaseV1::Candidate)?;
    let sealed_audit_scratch =
        emit_audit_phase_scratch(audit_scratch, image_backing, EmitAuditPhaseV1::Sealed)?;
    let initial_identity_scratch =
        emit_identity_phase_scratch(image_backing, EmitIdentityPhaseV1::InitialLength)?;
    let sealed_identity_length_scratch =
        emit_identity_phase_scratch(image_backing, EmitIdentityPhaseV1::SealedLength)?;
    let sealed_identity_hash_scratch =
        emit_identity_phase_scratch(image_backing, EmitIdentityPhaseV1::SealedHash)?;
    let identity_scratch = initial_identity_scratch
        .max(sealed_identity_length_scratch)
        .max(sealed_identity_hash_scratch);
    let scratch = emission_scratch
        .max(candidate_audit_scratch)
        .max(sealed_audit_scratch)
        .max(identity_scratch);
    let persistent = to_u64(
        AotCountImageV1::retained_heap_bytes(
            code_bytes,
            labels
                .checked_mul(size_of::<CodeLabelV1>())
                .ok_or(arithmetic_prospective())?,
            relocations
                .checked_mul(size_of::<RelocationV1>())
                .ok_or(arithmetic_prospective())?,
        )
        .and_then(|bytes| bytes.checked_add(size_of::<AotCountImageV1>()))
        .ok_or(arithmetic_prospective())?,
        CountAotArithmeticSite::Prospective,
    )?;
    let label_work = labels.checked_mul(2).ok_or(arithmetic_prospective())?;
    let relocation_work = relocations.checked_mul(2).ok_or(arithmetic_prospective())?;
    const IDENTITY_HASH_PASSES_V1: u64 = 2;
    const AUDIT_PASSES_V1: u64 = 2;
    const INITIAL_LITERAL_BYTE_PASSES_V1: u64 = 3;
    // O(1) work outside the dimensioned loops is the checked sum of named
    // build phases, rather than an opaque fixed allowance.
    const RESOURCE_ADMISSION_SCALAR_WORK_V1: u64 = 7 * 3;
    const IMAGE_FIELD_CONSTRUCTION_WORK_V1: u64 = 12 + 11 + 10;
    const MANIFEST_AND_LAYOUT_SCALAR_WORK_V1: u64 = 3 + 5;
    const CAPACITY_RECEIPT_SCALAR_WORK_V1: u64 = 8;
    const IDENTITY_LENGTH_SCALAR_WORK_V1: u64 = 8;
    const IDENTITY_HASH_SCALAR_WORK_V1: u64 = 12;
    const CANDIDATE_AUDIT_SCALAR_WORK_V1: u64 = 8;
    const SEALED_AUDIT_SCALAR_WORK_V1: u64 = 8;
    const SCRATCH_SEAL_SCALAR_WORK_V1: u64 = 7;
    const FINAL_RECEIPT_SCALAR_WORK_V1: u64 = 7;
    const PROSPECTIVE_IMAGE_BACKING_DERIVATION_WORK_V1: u64 = 5;
    // Two capacity multiplications, three checked additions, and one result
    // conversion derive the image-assembly phase.
    const PROSPECTIVE_IMAGE_ASSEMBLY_DERIVATION_WORK_V1: u64 = 6;
    const PROSPECTIVE_AUDIT_PHASE_DERIVATION_WORK_V1: u64 = 2 * 5;
    const PROSPECTIVE_IDENTITY_PHASE_DERIVATION_WORK_V1: u64 = 3 * 4;
    // One emission maximum, two identity maxima, and three complete-build
    // maxima select the phase envelope.
    const PROSPECTIVE_PHASE_MAX_WORK_V1: u64 = 6;
    const OBSERVED_IMAGE_BACKING_DERIVATIONS_V1: u64 = 5 * 5;
    const OBSERVED_IMAGE_BACKING_SEALS_V1: u64 = 5;
    const OBSERVED_IMAGE_PHASE_DERIVATIONS_V1: u64 = (3 * 4) + (2 * 5);
    const OBSERVED_IMAGE_PHASE_DISPATCHES_V1: u64 = 5;
    const OBSERVED_IMAGE_PHASE_SEALS_AND_REFUSALS_V1: u64 = 5 * 2;
    let observed_assembler_scratch_work = assembler_scratch_observation_work_components_v1();
    let scratch_accounting_work = assembler_scratch_derivation_work_upper_bound_v1()
        .checked_add(PROSPECTIVE_IMAGE_BACKING_DERIVATION_WORK_V1)
        .and_then(|value| value.checked_add(PROSPECTIVE_IMAGE_ASSEMBLY_DERIVATION_WORK_V1))
        .and_then(|value| value.checked_add(PROSPECTIVE_AUDIT_PHASE_DERIVATION_WORK_V1))
        .and_then(|value| value.checked_add(PROSPECTIVE_IDENTITY_PHASE_DERIVATION_WORK_V1))
        .and_then(|value| value.checked_add(PROSPECTIVE_PHASE_MAX_WORK_V1))
        .and_then(|value| value.checked_add(observed_assembler_scratch_work.total))
        .and_then(|value| value.checked_add(OBSERVED_IMAGE_BACKING_DERIVATIONS_V1))
        .and_then(|value| value.checked_add(OBSERVED_IMAGE_BACKING_SEALS_V1))
        .and_then(|value| value.checked_add(OBSERVED_IMAGE_PHASE_DERIVATIONS_V1))
        .and_then(|value| value.checked_add(OBSERVED_IMAGE_PHASE_DISPATCHES_V1))
        .and_then(|value| value.checked_add(OBSERVED_IMAGE_PHASE_SEALS_AND_REFUSALS_V1))
        .ok_or(arithmetic_prospective())?;
    let image_seal_scalar_work = RESOURCE_ADMISSION_SCALAR_WORK_V1
        .checked_add(IMAGE_FIELD_CONSTRUCTION_WORK_V1)
        .and_then(|value| value.checked_add(MANIFEST_AND_LAYOUT_SCALAR_WORK_V1))
        .and_then(|value| value.checked_add(CAPACITY_RECEIPT_SCALAR_WORK_V1))
        .and_then(|value| value.checked_add(IDENTITY_LENGTH_SCALAR_WORK_V1))
        .and_then(|value| value.checked_add(IDENTITY_HASH_SCALAR_WORK_V1))
        .and_then(|value| value.checked_add(CANDIDATE_AUDIT_SCALAR_WORK_V1))
        .and_then(|value| value.checked_add(SEALED_AUDIT_SCALAR_WORK_V1))
        .and_then(|value| value.checked_add(SCRATCH_SEAL_SCALAR_WORK_V1))
        .and_then(|value| value.checked_add(FINAL_RECEIPT_SCALAR_WORK_V1))
        .and_then(|value| value.checked_add(scratch_accounting_work))
        .ok_or(arithmetic_prospective())?;
    let identity_count_work = identity_count_work_upper_bound_v1(
        to_u64(labels, CountAotArithmeticSite::Prospective)?,
        to_u64(relocations, CountAotArithmeticSite::Prospective)?,
    )
    .ok_or(arithmetic_prospective())?;
    let initial_literal_work = to_u64(literal_len, CountAotArithmeticSite::Prospective)?
        .checked_mul(INITIAL_LITERAL_BYTE_PASSES_V1)
        .ok_or(arithmetic_prospective())?;
    let work = initial_literal_work
        .checked_add(to_u64(instructions, CountAotArithmeticSite::Prospective)?)
        .and_then(|value| {
            value.checked_add(to_u64(label_work, CountAotArithmeticSite::Prospective).ok()?)
        })
        .and_then(|value| {
            value.checked_add(to_u64(relocation_work, CountAotArithmeticSite::Prospective).ok()?)
        })
        .and_then(|value| value.checked_add(label_order.total))
        .and_then(|value| value.checked_add(identity_count_work))
        .and_then(|value| {
            value.checked_add(identity_bytes_hashed.checked_mul(IDENTITY_HASH_PASSES_V1)?)
        })
        .and_then(|value| value.checked_add(audit_work.checked_mul(AUDIT_PASSES_V1)?))
        .and_then(|value| value.checked_add(image_seal_scalar_work))
        .ok_or(arithmetic_prospective())?;
    Ok(Prospective {
        code_bytes,
        labels,
        relocations,
        identity_bytes_hashed,
        assembler_scratch,
        emission_scratch,
        image_backing,
        image_assembly_scratch,
        audit_work,
        audit_scratch,
        candidate_audit_scratch,
        sealed_audit_scratch,
        initial_identity_scratch,
        sealed_identity_length_scratch,
        sealed_identity_hash_scratch,
        identity_scratch,
        work,
        scratch,
        persistent,
        scratch_limit: MAX_SCRATCH_BYTES_V1,
        persistent_limit: MAX_PERSISTENT_BYTES_V1,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LabelOrderWorkV1 {
    pub(crate) comparisons: u64,
    pub(crate) moves: u64,
    pub(crate) placements: u64,
    pub(crate) total: u64,
}

pub(crate) fn label_order_work_upper_bound(
    labels: usize,
) -> Result<LabelOrderWorkV1, CountAotError> {
    let labels = to_u64(labels, CountAotArithmeticSite::Prospective)?;
    let prior = labels.saturating_sub(1);
    // Insertion ordering performs at most 1 + ... + (n - 1)
    // comparisons and shifts, then one key placement for each nonfirst item.
    let pairs = labels
        .checked_mul(prior)
        .and_then(|value| value.checked_div(2))
        .ok_or(arithmetic_prospective())?;
    let total = pairs
        .checked_add(pairs)
        .and_then(|value| value.checked_add(prior))
        .ok_or(arithmetic_prospective())?;
    Ok(LabelOrderWorkV1 {
        comparisons: pairs,
        moves: pairs,
        placements: prior,
        total,
    })
}

type CanonicalChunkIteratorV1 = core::iter::Enumerate<core::slice::ChunksExact<'static, u8>>;
type CanonicalTailIteratorV1 = core::slice::Iter<'static, u8>;
type WordByteIteratorV1 = core::array::IntoIter<u8, 4>;
type EmissionBuildInlineStateV1 = (
    &'static ExactAggregateProgram<Count>,
    CountEmitLimitsV1,
    usize,
    Prospective,
    &'static [u8],
    AotCountLiteralManifestV1,
    [u8; 32],
    CountAotError,
);
type CanonicalTemplateCallerInlineStateV1 = (
    &'static [u8],
    Prospective,
    Result<Finalized, CountAotError>,
    CountAotError,
);
type ScratchObservationInlineStateV1 = (
    &'static Assembler,
    [usize; 10],
    EmissionPhaseV1,
    u64,
    CountAotError,
);
type AssemblerOperationInlineStateV1 = (
    &'static Assembler,
    core::ops::Range<u8>,
    WordByteIteratorV1,
    [u8; 4],
    [u8; 5],
    [u16; 2],
    [u32; 3],
    [u64; 2],
    Label,
    Fixup,
    CountAotError,
);
type CanonicalEmissionInlineStateV1 = (
    EmissionBuildInlineStateV1,
    ScratchObservationInlineStateV1,
    AssemblerOperationInlineStateV1,
    Prospective,
    [Label; 6],
    &'static [u8],
    CanonicalChunkIteratorV1,
    CanonicalTailIteratorV1,
    &'static [u8],
    [usize; 4],
    [u16; 2],
    [u8; 8],
    u64,
    CountAotError,
);
type FinalizeRelocationInlineStateV1 = (
    EmissionBuildInlineStateV1,
    ScratchObservationInlineStateV1,
    AssemblerOperationInlineStateV1,
    core::ops::Range<usize>,
    usize,
    Fixup,
    LabelRecord,
    &'static LabelRecord,
    RelocationV1,
    [u32; 4],
    CountAotError,
);
type FinalizeLabelCollectionIteratorV1 =
    core::iter::Copied<core::slice::Iter<'static, LabelRecord>>;
type FinalizeLabelCollectionInlineStateV1 = (
    EmissionBuildInlineStateV1,
    ScratchObservationInlineStateV1,
    FinalizeLabelCollectionIteratorV1,
    LabelRecord,
    CodeLabelV1,
    [usize; 4],
    CountAotError,
);
type LabelOrderInlineStateV1 = (
    EmissionBuildInlineStateV1,
    ScratchObservationInlineStateV1,
    &'static mut [CodeLabelV1],
    core::ops::Range<usize>,
    [usize; 3],
    CodeLabelV1,
    CodeLabelV1,
    LabelOrderWorkV1,
    [u64; 4],
    CountAotError,
);
type FinalizeReturnInlineStateV1 = (
    EmissionBuildInlineStateV1,
    ScratchObservationInlineStateV1,
    Finalized,
    u32,
    u32,
    u32,
    usize,
    usize,
    usize,
    CountAotError,
);
type ImageAssemblyInlineStateV1 = (
    EmissionBuildInlineStateV1,
    Finalized,
    AotCountImageV1,
    AotCountImageLayoutV1,
    AotCountImageStatsV1,
    AotCountImageBuildReceiptV1,
    AotCountTargetSpec,
    crate::AotCountBackendSupportV1,
    [usize; 6],
    [u32; 6],
    [u64; 6],
    CountAotError,
);
type CandidateAuditCallerInlineStateV1 = (
    EmissionBuildInlineStateV1,
    AotCountImageV1,
    CountAuditReportV1,
    [usize; 4],
    [u64; 6],
    CountAotError,
);
type SealedAuditCallerInlineStateV1 = (
    EmissionBuildInlineStateV1,
    AotCountImageV1,
    CountAuditReportV1,
    CountAuditReportV1,
    AotCountArtifactIdentity,
    [usize; 4],
    [u64; 6],
    CountAotError,
);
type InitialIdentityCallerInlineStateV1 = (
    EmissionBuildInlineStateV1,
    AotCountImageV1,
    u64,
    CountAotError,
);
type SealedIdentityLengthCallerInlineStateV1 = (
    EmissionBuildInlineStateV1,
    AotCountImageV1,
    CountAuditReportV1,
    u64,
    CountAotError,
);
type SealedIdentityHashCallerInlineStateV1 = (
    EmissionBuildInlineStateV1,
    AotCountImageV1,
    CountAuditReportV1,
    AotCountArtifactIdentity,
    u64,
    CountAotError,
);

fn image_backing_bytes_for_capacities(
    code_capacity_bytes: usize,
    label_capacity: usize,
    relocation_capacity: usize,
) -> Result<u64, CountAotError> {
    let bytes = code_capacity_bytes
        .checked_add(
            label_capacity
                .checked_mul(size_of::<CodeLabelV1>())
                .ok_or(arithmetic_prospective())?,
        )
        .and_then(|value| {
            value.checked_add(relocation_capacity.checked_mul(size_of::<RelocationV1>())?)
        })
        .ok_or(arithmetic_prospective())?;
    to_u64(bytes, CountAotArithmeticSite::Prospective)
}

fn image_assembly_scratch_for_capacities(
    code_capacity_bytes: usize,
    label_capacity: usize,
    relocation_capacity: usize,
) -> Result<u64, CountAotError> {
    // The retained backings stay single-owned while the returned `Finalized`
    // fields are destructured and their three ExactVec headers move into the
    // destination image. The phase-local inline state names both aggregates so
    // the source headers and partially constructed destination are co-live.
    let bytes = code_capacity_bytes
        .checked_add(
            label_capacity
                .checked_mul(size_of::<CodeLabelV1>())
                .ok_or(arithmetic_prospective())?,
        )
        .and_then(|value| {
            value.checked_add(relocation_capacity.checked_mul(size_of::<RelocationV1>())?)
        })
        .and_then(|value| value.checked_add(size_of::<ImageAssemblyInlineStateV1>()))
        .ok_or(arithmetic_prospective())?;
    to_u64(bytes, CountAotArithmeticSite::Prospective)
}

fn emit_audit_phase_scratch(
    audit_scratch: u64,
    image_backing: u64,
    phase: EmitAuditPhaseV1,
) -> Result<u64, CountAotError> {
    // The emitted image remains owned by the caller while the audit
    // regenerates canonical, decode, and policy storage. The wrapper frame is
    // distinct from both the outer emitter and `audit_impl`.
    let (caller_inline, wrapper_inline) = match phase {
        EmitAuditPhaseV1::Candidate => (
            size_of::<CandidateAuditCallerInlineStateV1>(),
            audit_candidate_wrapper_inline_bytes_v1(),
        ),
        EmitAuditPhaseV1::Sealed => (
            size_of::<SealedAuditCallerInlineStateV1>(),
            audit_public_wrapper_inline_bytes_v1(),
        ),
    };
    image_backing
        .checked_add(audit_scratch)
        .and_then(|bytes| {
            bytes.checked_add(to_u64(caller_inline, CountAotArithmeticSite::Prospective).ok()?)
        })
        .and_then(|bytes| {
            bytes.checked_add(to_u64(wrapper_inline, CountAotArithmeticSite::Prospective).ok()?)
        })
        .ok_or(arithmetic_prospective())
}

fn emit_identity_phase_scratch(
    image_backing: u64,
    phase: EmitIdentityPhaseV1,
) -> Result<u64, CountAotError> {
    let caller_inline = match phase {
        EmitIdentityPhaseV1::InitialLength => size_of::<InitialIdentityCallerInlineStateV1>(),
        EmitIdentityPhaseV1::SealedLength => size_of::<SealedIdentityLengthCallerInlineStateV1>(),
        EmitIdentityPhaseV1::SealedHash => size_of::<SealedIdentityHashCallerInlineStateV1>(),
    };
    image_backing
        .checked_add(to_u64(caller_inline, CountAotArithmeticSite::Prospective)?)
        .and_then(|bytes| {
            bytes.checked_add(
                to_u64(
                    identity_encoder_scratch_bytes_v1(),
                    CountAotArithmeticSite::Prospective,
                )
                .ok()?,
            )
        })
        .ok_or(arithmetic_prospective())
}

fn observe_emit_image_phase_scratch(
    image: &AotCountImageV1,
    prospective: Prospective,
    phase: EmitImagePhaseV1,
) -> Result<u64, CountAotError> {
    // Re-read the allocator-owned capacities at the last point before each
    // audit or identity traversal. A forged receipt therefore cannot hide an
    // over-capacity allocation from phase admission.
    let image_backing = image_backing_bytes_for_capacities(
        image.code.capacity(),
        image.labels.capacity(),
        image.relocations.capacity(),
    )?;
    if image_backing != prospective.image_backing {
        return Err(CountAotError::InternalInvariant {
            at: "image backing prospective",
        });
    }
    let (observed, expected) = match phase {
        EmitImagePhaseV1::InitialIdentityLength => (
            emit_identity_phase_scratch(image_backing, EmitIdentityPhaseV1::InitialLength)?,
            prospective.initial_identity_scratch,
        ),
        EmitImagePhaseV1::CandidateAudit => (
            emit_audit_phase_scratch(
                prospective.audit_scratch,
                image_backing,
                EmitAuditPhaseV1::Candidate,
            )?,
            prospective.candidate_audit_scratch,
        ),
        EmitImagePhaseV1::SealedIdentityLength => (
            emit_identity_phase_scratch(image_backing, EmitIdentityPhaseV1::SealedLength)?,
            prospective.sealed_identity_length_scratch,
        ),
        EmitImagePhaseV1::SealedIdentityHash => (
            emit_identity_phase_scratch(image_backing, EmitIdentityPhaseV1::SealedHash)?,
            prospective.sealed_identity_hash_scratch,
        ),
        EmitImagePhaseV1::SealedAudit => (
            emit_audit_phase_scratch(
                prospective.audit_scratch,
                image_backing,
                EmitAuditPhaseV1::Sealed,
            )?,
            prospective.sealed_audit_scratch,
        ),
    };
    if observed != expected {
        return Err(CountAotError::InternalInvariant {
            at: "image phase scratch prospective",
        });
    }
    if observed > prospective.scratch_limit {
        return Err(CountAotError::ResourceLimit {
            resource: CountAotResource::ScratchBytes,
            limit: prospective.scratch_limit,
            required: observed,
        });
    }
    Ok(observed)
}

#[derive(Clone, Copy)]
enum EmitAuditPhaseV1 {
    Candidate,
    Sealed,
}

#[derive(Clone, Copy)]
enum EmitIdentityPhaseV1 {
    InitialLength,
    SealedLength,
    SealedHash,
}

#[derive(Clone, Copy)]
enum EmitImagePhaseV1 {
    InitialIdentityLength,
    CandidateAudit,
    SealedIdentityLength,
    SealedIdentityHash,
    SealedAudit,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EmitImagePhaseForTestV1 {
    InitialIdentityLength,
    CandidateAudit,
    SealedIdentityLength,
    SealedIdentityHash,
    SealedAudit,
}

#[cfg(test)]
pub(crate) fn observe_emit_image_phase_scratch_for_test(
    program: &ExactAggregateProgram<Count>,
    image: &AotCountImageV1,
    phase: EmitImagePhaseForTestV1,
    scratch_limit: u64,
) -> Result<u64, CountAotError> {
    let mut prospective = prospective(preflight_program_dimensions(program)?)?;
    prospective.scratch_limit = prospective.scratch_limit.min(scratch_limit);
    let phase = match phase {
        EmitImagePhaseForTestV1::InitialIdentityLength => EmitImagePhaseV1::InitialIdentityLength,
        EmitImagePhaseForTestV1::CandidateAudit => EmitImagePhaseV1::CandidateAudit,
        EmitImagePhaseForTestV1::SealedIdentityLength => EmitImagePhaseV1::SealedIdentityLength,
        EmitImagePhaseForTestV1::SealedIdentityHash => EmitImagePhaseV1::SealedIdentityHash,
        EmitImagePhaseForTestV1::SealedAudit => EmitImagePhaseV1::SealedAudit,
    };
    observe_emit_image_phase_scratch(image, prospective, phase)
}

pub(crate) fn assembler_scratch_upper_bound_for_dimensions(
    code_bytes: usize,
    labels: usize,
    relocations: usize,
) -> Result<u64, CountAotError> {
    let label_record_bytes = labels
        .checked_mul(size_of::<LabelRecord>())
        .ok_or(arithmetic_prospective())?;
    let fixup_bytes = relocations
        .checked_mul(size_of::<Fixup>())
        .ok_or(arithmetic_prospective())?;
    let output_label_bytes = labels
        .checked_mul(size_of::<CodeLabelV1>())
        .ok_or(arithmetic_prospective())?;
    let output_relocation_bytes = relocations
        .checked_mul(size_of::<RelocationV1>())
        .ok_or(arithmetic_prospective())?;
    let assembler_backing = code_bytes
        .checked_add(label_record_bytes)
        .and_then(|bytes| bytes.checked_add(fixup_bytes))
        .ok_or(arithmetic_prospective())?;

    let canonical = assembler_backing
        .checked_add(size_of::<Assembler>())
        .and_then(|bytes| bytes.checked_add(size_of::<CanonicalTemplateCallerInlineStateV1>()))
        .and_then(|bytes| bytes.checked_add(size_of::<CanonicalEmissionInlineStateV1>()))
        .ok_or(arithmetic_prospective())?;
    let finalize_relocations = assembler_backing
        .checked_add(output_relocation_bytes)
        .and_then(|bytes| bytes.checked_add(size_of::<Assembler>()))
        .and_then(|bytes| bytes.checked_add(size_of::<CanonicalTemplateCallerInlineStateV1>()))
        .and_then(|bytes| bytes.checked_add(size_of::<ExactVec<RelocationV1>>()))
        .and_then(|bytes| bytes.checked_add(size_of::<FinalizeRelocationInlineStateV1>()))
        .ok_or(arithmetic_prospective())?;
    let collect_labels = assembler_backing
        .checked_add(output_relocation_bytes)
        .and_then(|bytes| bytes.checked_add(output_label_bytes))
        .and_then(|bytes| bytes.checked_add(size_of::<Assembler>()))
        .and_then(|bytes| bytes.checked_add(size_of::<CanonicalTemplateCallerInlineStateV1>()))
        .and_then(|bytes| bytes.checked_add(size_of::<ExactVec<RelocationV1>>()))
        .and_then(|bytes| bytes.checked_add(size_of::<ExactVec<CodeLabelV1>>()))
        .and_then(|bytes| bytes.checked_add(size_of::<FinalizeLabelCollectionInlineStateV1>()))
        .ok_or(arithmetic_prospective())?;
    let order_labels = assembler_backing
        .checked_add(output_relocation_bytes)
        .and_then(|bytes| bytes.checked_add(output_label_bytes))
        .and_then(|bytes| bytes.checked_add(size_of::<Assembler>()))
        .and_then(|bytes| bytes.checked_add(size_of::<CanonicalTemplateCallerInlineStateV1>()))
        .and_then(|bytes| bytes.checked_add(size_of::<ExactVec<RelocationV1>>()))
        .and_then(|bytes| bytes.checked_add(size_of::<ExactVec<CodeLabelV1>>()))
        .and_then(|bytes| bytes.checked_add(size_of::<LabelOrderInlineStateV1>()))
        .ok_or(arithmetic_prospective())?;
    // Constructing the return value may keep the source assembler, the two
    // source-local output-vector headers, and the destination aggregate inline
    // values live together. Backing allocations are counted once because
    // ownership moves rather than copies.
    let finalize_return = assembler_backing
        .checked_add(output_relocation_bytes)
        .and_then(|bytes| bytes.checked_add(output_label_bytes))
        .and_then(|bytes| bytes.checked_add(size_of::<Assembler>()))
        .and_then(|bytes| bytes.checked_add(size_of::<CanonicalTemplateCallerInlineStateV1>()))
        .and_then(|bytes| bytes.checked_add(size_of::<ExactVec<RelocationV1>>()))
        .and_then(|bytes| bytes.checked_add(size_of::<ExactVec<CodeLabelV1>>()))
        .and_then(|bytes| bytes.checked_add(size_of::<FinalizeReturnInlineStateV1>()))
        .ok_or(arithmetic_prospective())?;
    let requested = canonical
        .max(finalize_relocations)
        .max(collect_labels)
        .max(order_labels)
        .max(finalize_return);
    to_u64(requested, CountAotArithmeticSite::Prospective)
}

pub(crate) const fn assembler_scratch_derivation_work_upper_bound_v1() -> u64 {
    const CAPACITY_MULTIPLICATIONS: u64 = 4;
    const ASSEMBLER_BACKING_ADDITIONS: u64 = 2;
    const CANONICAL_PHASE_ADDITIONS: u64 = 3;
    const RELOCATION_PHASE_ADDITIONS: u64 = 5;
    const LABEL_COLLECTION_PHASE_ADDITIONS: u64 = 7;
    const LABEL_ORDER_PHASE_ADDITIONS: u64 = 7;
    const FINAL_RETURN_PHASE_ADDITIONS: u64 = 7;
    const PHASE_MAX_COMPARISONS: u64 = 4;
    const RESULT_CONVERSION: u64 = 1;
    CAPACITY_MULTIPLICATIONS
        + ASSEMBLER_BACKING_ADDITIONS
        + CANONICAL_PHASE_ADDITIONS
        + RELOCATION_PHASE_ADDITIONS
        + LABEL_COLLECTION_PHASE_ADDITIONS
        + LABEL_ORDER_PHASE_ADDITIONS
        + FINAL_RETURN_PHASE_ADDITIONS
        + PHASE_MAX_COMPARISONS
        + RESULT_CONVERSION
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AssemblerScratchObservationWorkV1 {
    pub(crate) capacity_multiplications: u64,
    pub(crate) backing_additions: u64,
    pub(crate) phase_additions: u64,
    pub(crate) conversions: u64,
    pub(crate) admission_checks_and_peak_maxima: u64,
    pub(crate) total: u64,
}

pub(crate) const fn assembler_scratch_observation_work_components_v1()
-> AssemblerScratchObservationWorkV1 {
    // `Assembler::observe_scratch` executes once in canonical emission and
    // once in each of the four finalize phases.
    let capacity_multiplications = 5_u64 * 4;
    let backing_additions = 5 * 2;
    let phase_additions = 3 + 5 + 7 + 7 + 7;
    let conversions = 5;
    let admission_checks_and_peak_maxima = 5 * 3;
    let total = capacity_multiplications
        .saturating_add(backing_additions)
        .saturating_add(phase_additions)
        .saturating_add(conversions)
        .saturating_add(admission_checks_and_peak_maxima);
    AssemblerScratchObservationWorkV1 {
        capacity_multiplications,
        backing_additions,
        phase_additions,
        conversions,
        admission_checks_and_peak_maxima,
        total,
    }
}

pub(crate) fn identity_structural_traversal_work_v1(labels: u64, relocations: u64) -> Option<u64> {
    const FIXED_ENCODER_WRITES: u64 = 68;
    const WRITES_PER_LABEL: u64 = 2;
    const WRITES_PER_RELOCATION: u64 = 4;
    FIXED_ENCODER_WRITES
        .checked_add(labels.checked_mul(WRITES_PER_LABEL)?)
        .and_then(|work| work.checked_add(relocations.checked_mul(WRITES_PER_RELOCATION)?))
}

pub(crate) fn identity_count_work_upper_bound_v1(labels: u64, relocations: u64) -> Option<u64> {
    // Initial length, candidate-audit length, sealed length, and sealed-audit
    // length each traverse the complete canonical identity encoding.
    const IDENTITY_COUNT_PASSES_V1: u64 = 4;
    identity_structural_traversal_work_v1(labels, relocations)?
        .checked_mul(IDENTITY_COUNT_PASSES_V1)
}

// Encoder-local state is separated from the emitter or audit caller. Callers
// add their own owned image, backing allocations, and wrapper frames.
type IdentityEncoderInlineStateV1 = (
    IdentityEncoder,
    &'static AotCountImageV1,
    CountAuditReportV1,
    AotCountArtifactIdentity,
    AotCountTargetSpec,
    AotCountImageLayoutV1,
    AotCountImageStatsV1,
    AotCountImageBuildReceiptV1,
    crate::AotCountBackendSupportV1,
    core::slice::Iter<'static, CodeLabelV1>,
    core::slice::Iter<'static, RelocationV1>,
    &'static CodeLabelV1,
    &'static RelocationV1,
    [u8; 32],
    [u8; 32],
    [u32; 4],
    [u64; 4],
    CountAotError,
);

pub(crate) const fn identity_encoder_scratch_bytes_v1() -> usize {
    size_of::<IdentityEncoderInlineStateV1>()
}

fn observed_emission_phase_scratch(
    code_capacity: usize,
    label_record_capacity: usize,
    fixup_capacity: usize,
    output_label_capacity: usize,
    output_relocation_capacity: usize,
    phase: EmissionPhaseV1,
) -> Result<u64, CountAotError> {
    let assembler_backing = code_capacity
        .checked_add(
            label_record_capacity
                .checked_mul(size_of::<LabelRecord>())
                .ok_or(arithmetic_prospective())?,
        )
        .and_then(|bytes| bytes.checked_add(fixup_capacity.checked_mul(size_of::<Fixup>())?))
        .ok_or(arithmetic_prospective())?;
    let output_labels = output_label_capacity
        .checked_mul(size_of::<CodeLabelV1>())
        .ok_or(arithmetic_prospective())?;
    let output_relocations = output_relocation_capacity
        .checked_mul(size_of::<RelocationV1>())
        .ok_or(arithmetic_prospective())?;
    let bytes = match phase {
        EmissionPhaseV1::Canonical => assembler_backing
            .checked_add(size_of::<Assembler>())
            .and_then(|value| value.checked_add(size_of::<CanonicalTemplateCallerInlineStateV1>()))
            .and_then(|value| value.checked_add(size_of::<CanonicalEmissionInlineStateV1>())),
        EmissionPhaseV1::FinalizeRelocations => assembler_backing
            .checked_add(output_relocations)
            .and_then(|value| value.checked_add(size_of::<Assembler>()))
            .and_then(|value| value.checked_add(size_of::<CanonicalTemplateCallerInlineStateV1>()))
            .and_then(|value| value.checked_add(size_of::<ExactVec<RelocationV1>>()))
            .and_then(|value| value.checked_add(size_of::<FinalizeRelocationInlineStateV1>())),
        EmissionPhaseV1::CollectLabels => assembler_backing
            .checked_add(output_relocations)
            .and_then(|value| value.checked_add(output_labels))
            .and_then(|value| value.checked_add(size_of::<Assembler>()))
            .and_then(|value| value.checked_add(size_of::<CanonicalTemplateCallerInlineStateV1>()))
            .and_then(|value| value.checked_add(size_of::<ExactVec<RelocationV1>>()))
            .and_then(|value| value.checked_add(size_of::<ExactVec<CodeLabelV1>>()))
            .and_then(|value| value.checked_add(size_of::<FinalizeLabelCollectionInlineStateV1>())),
        EmissionPhaseV1::OrderLabels => assembler_backing
            .checked_add(output_relocations)
            .and_then(|value| value.checked_add(output_labels))
            .and_then(|value| value.checked_add(size_of::<Assembler>()))
            .and_then(|value| value.checked_add(size_of::<CanonicalTemplateCallerInlineStateV1>()))
            .and_then(|value| value.checked_add(size_of::<ExactVec<RelocationV1>>()))
            .and_then(|value| value.checked_add(size_of::<ExactVec<CodeLabelV1>>()))
            .and_then(|value| value.checked_add(size_of::<LabelOrderInlineStateV1>())),
        EmissionPhaseV1::FinalizeReturn => assembler_backing
            .checked_add(output_relocations)
            .and_then(|value| value.checked_add(output_labels))
            .and_then(|value| value.checked_add(size_of::<Assembler>()))
            .and_then(|value| value.checked_add(size_of::<CanonicalTemplateCallerInlineStateV1>()))
            .and_then(|value| value.checked_add(size_of::<ExactVec<RelocationV1>>()))
            .and_then(|value| value.checked_add(size_of::<ExactVec<CodeLabelV1>>()))
            .and_then(|value| value.checked_add(size_of::<FinalizeReturnInlineStateV1>())),
    }
    .ok_or(arithmetic_prospective())?;
    to_u64(bytes, CountAotArithmeticSite::Prospective)
}

#[derive(Clone, Copy)]
enum EmissionPhaseV1 {
    Canonical,
    FinalizeRelocations,
    CollectLabels,
    OrderLabels,
    FinalizeReturn,
}

pub(crate) fn canonical_template(
    literal: &[u8],
    prospective: Prospective,
) -> Result<Finalized, CountAotError> {
    let mut assembler = Assembler::new(prospective)?;
    let entry = assembler.new_label(LabelKindV1::Entry)?;
    let success = assembler.new_label(LabelKindV1::Success)?;
    let overflow = assembler.new_label(LabelKindV1::Overflow)?;
    assembler.bind(entry)?;
    if literal.is_empty() {
        emit_empty(&mut assembler, success, overflow)?;
    } else if literal.len() == 1 {
        emit_single_byte(&mut assembler, literal[0], success, overflow)?;
    } else {
        emit_chunked_literal(&mut assembler, literal, success, overflow)?;
    }
    emit_returns(&mut assembler, success, overflow)?;
    assembler.finalize()
}

pub(crate) fn identity_bytes_upper_bound(
    code_bytes: usize,
    labels: usize,
    relocations: usize,
) -> Result<u64, CountAotError> {
    const SUPPORT_BYTES: u64 = (4 * 2) + 5 + 8 + 2;
    const TARGET_BYTES: u64 = 4 + 8;
    const SOURCE_AND_LITERAL_BYTES: u64 = 32 + 4 + 1 + 32;
    const LAYOUT_BYTES: u64 = 4 * 4;
    const VECTOR_LENGTH_PREFIX_BYTES: u64 = 8 + 4 + 4;
    const STATS_BYTES: u64 = (6 * 4) + (5 * 8);
    const RECEIPT_BYTES: u64 = SUPPORT_BYTES + (5 * 8) + (3 * 8);
    const AUDIT_REPORT_BYTES: u64 = (6 * 4) + (2 * 8);
    const FIXED_ENCODING_BYTES_EXCLUDING_DOMAIN: u64 = 2
        + SUPPORT_BYTES
        + TARGET_BYTES
        + SOURCE_AND_LITERAL_BYTES
        + LAYOUT_BYTES
        + VECTOR_LENGTH_PREFIX_BYTES
        + STATS_BYTES
        + RECEIPT_BYTES
        + AUDIT_REPORT_BYTES;
    to_u64(IDENTITY_DOMAIN.len(), CountAotArithmeticSite::Identity)?
        .checked_add(FIXED_ENCODING_BYTES_EXCLUDING_DOMAIN)
        .and_then(|value| {
            value.checked_add(to_u64(code_bytes, CountAotArithmeticSite::Identity).ok()?)
        })
        .and_then(|value| {
            value
                .checked_add(to_u64(labels.checked_mul(5)?, CountAotArithmeticSite::Identity).ok()?)
        })
        .and_then(|value| {
            value.checked_add(
                to_u64(
                    relocations.checked_mul(13)?,
                    CountAotArithmeticSite::Identity,
                )
                .ok()?,
            )
        })
        .ok_or(CountAotError::ArithmeticOverflow {
            site: CountAotArithmeticSite::Identity,
        })
}

fn emit_empty(
    assembler: &mut Assembler,
    success: Label,
    overflow: Label,
) -> Result<(), CountAotError> {
    assembler.mov_imm64(X10, u64::MAX)?;
    assembler.cmp_reg64(X1, X10)?;
    assembler.branch_cond(ConditionV1::Equal, overflow)?;
    assembler.add_imm(X13, X1, 1)?;
    assembler.branch(success)
}

fn emit_single_byte(
    assembler: &mut Assembler,
    literal: u8,
    success: Label,
    overflow: Label,
) -> Result<(), CountAotError> {
    let vector = assembler.new_label(LabelKindV1::Loop)?;
    let tail = assembler.new_label(LabelKindV1::SlowPath)?;
    let tail_miss = assembler.new_label(LabelKindV1::Internal)?;
    assembler.mov_imm64(X13, 0)?;
    assembler.mov_imm64(X3, 0)?;
    assembler.mov_imm64(X11, u64::from(literal))?;
    assembler.dup_byte16(1, X11)?;
    assembler.bind(vector)?;
    assembler.sub_reg(X10, X1, X3)?;
    assembler.cmp_imm64(X10, 16)?;
    assembler.branch_cond(ConditionV1::CarryClear, tail)?;
    assembler.add_reg(X15, X0, X3)?;
    assembler.load_vector128(0, X15, 0)?;
    assembler.compare_equal_bytes16(0, 0, 1)?;
    assembler.add_across_bytes16(0, 0)?;
    assembler.move_vector_byte_to32(X10, 0)?;
    assembler.mov_imm64(X5, 256)?;
    assembler.sub_reg(X10, X5, X10)?;
    assembler.and_low_bits(X10, X10, 8)?;
    emit_add_register(assembler, X10, overflow)?;
    assembler.add_imm(X3, X3, 16)?;
    assembler.branch(vector)?;

    assembler.bind(tail)?;
    assembler.cmp_reg64(X3, X1)?;
    assembler.branch_cond(ConditionV1::CarrySet, success)?;
    assembler.load_byte_reg(X10, X0, X3)?;
    assembler.cmp_reg32(X10, X11)?;
    assembler.branch_cond(ConditionV1::NotEqual, tail_miss)?;
    emit_add_immediate(assembler, 1, overflow)?;
    assembler.bind(tail_miss)?;
    assembler.add_imm(X3, X3, 1)?;
    assembler.branch(tail)
}

fn emit_chunked_literal(
    assembler: &mut Assembler,
    literal: &[u8],
    success: Label,
    overflow: Label,
) -> Result<(), CountAotError> {
    let loop_label = assembler.new_label(LabelKindV1::Loop)?;
    let miss = assembler.new_label(LabelKindV1::Internal)?;
    let width = u16::try_from(literal.len()).map_err(|_| CountAotError::ArithmeticOverflow {
        site: CountAotArithmeticSite::CodeOffset,
    })?;
    assembler.mov_imm64(X13, 0)?;
    assembler.cmp_imm64(X1, width)?;
    assembler.branch_cond(ConditionV1::CarryClear, success)?;
    assembler.sub_imm(X4, X1, width)?;
    assembler.mov_imm64(X3, 0)?;
    assembler.bind(loop_label)?;
    assembler.cmp_reg64(X3, X4)?;
    assembler.branch_cond(ConditionV1::Higher, success)?;
    assembler.add_reg(X15, X0, X3)?;

    let mut offset = 0_usize;
    for (chunk_index, chunk) in literal.chunks_exact(8).enumerate() {
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(chunk);
        assembler.mov_imm64(
            X9,
            u64::try_from(chunk_index).map_err(|_| CountAotError::ArithmeticOverflow {
                site: CountAotArithmeticSite::CodeOffset,
            })?,
        )?;
        assembler.load64_reg_scaled(X6, X15, X9)?;
        assembler.mov_imm64(X7, u64::from_le_bytes(bytes))?;
        assembler.cmp_reg64(X6, X7)?;
        assembler.branch_cond(ConditionV1::NotEqual, miss)?;
        offset = offset
            .checked_add(8)
            .ok_or(CountAotError::ArithmeticOverflow {
                site: CountAotArithmeticSite::CodeOffset,
            })?;
    }
    for byte in literal.chunks_exact(8).remainder() {
        assembler.load_byte(
            X6,
            X15,
            u16::try_from(offset).map_err(|_| CountAotError::ArithmeticOverflow {
                site: CountAotArithmeticSite::CodeOffset,
            })?,
        )?;
        assembler.mov_imm64(X7, u64::from(*byte))?;
        assembler.cmp_reg32(X6, X7)?;
        assembler.branch_cond(ConditionV1::NotEqual, miss)?;
        offset = offset
            .checked_add(1)
            .ok_or(CountAotError::ArithmeticOverflow {
                site: CountAotArithmeticSite::CodeOffset,
            })?;
    }
    emit_add_immediate(assembler, 1, overflow)?;
    assembler.add_imm(X3, X3, width)?;
    assembler.branch(loop_label)?;
    assembler.bind(miss)?;
    assembler.add_imm(X3, X3, 1)?;
    assembler.branch(loop_label)
}

fn emit_add_register(
    assembler: &mut Assembler,
    delta: u8,
    overflow: Label,
) -> Result<(), CountAotError> {
    assembler.mov_reg(X14, X13)?;
    assembler.add_reg(X13, X13, delta)?;
    assembler.cmp_reg64(X13, X14)?;
    assembler.branch_cond(ConditionV1::CarryClear, overflow)
}

fn emit_add_immediate(
    assembler: &mut Assembler,
    delta: u16,
    overflow: Label,
) -> Result<(), CountAotError> {
    assembler.mov_reg(X14, X13)?;
    assembler.add_imm(X13, X13, delta)?;
    assembler.cmp_reg64(X13, X14)?;
    assembler.branch_cond(ConditionV1::CarryClear, overflow)
}

fn emit_returns(
    assembler: &mut Assembler,
    success: Label,
    overflow: Label,
) -> Result<(), CountAotError> {
    assembler.bind(success)?;
    assembler.store64(X13, X2, 0)?;
    assembler.mov_imm64(X0, 0)?;
    assembler.ret()?;
    assembler.bind(overflow)?;
    assembler.mov_imm64(X0, 1)?;
    assembler.ret()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Label(u32);

#[derive(Clone, Copy)]
struct LabelRecord {
    offset: Option<u32>,
    kind: LabelKindV1,
}

#[derive(Clone, Copy)]
struct Fixup {
    at: u32,
    kind: RelocationKindV1,
    target: Label,
}

struct Assembler {
    code: ExactVec<u8>,
    labels: ExactVec<LabelRecord>,
    fixups: ExactVec<Fixup>,
    prospective: Prospective,
    emission_work: u64,
    vector_instructions: u32,
    peak_scratch_bytes: u64,
}

impl Assembler {
    fn new(prospective: Prospective) -> Result<Self, CountAotError> {
        let code = exact_vec(prospective.code_bytes, CountAotResource::CodeBytes)?;
        let labels = exact_vec(prospective.labels, CountAotResource::Labels)?;
        let fixups = exact_vec(prospective.relocations, CountAotResource::Relocations)?;
        let mut assembler = Self {
            code,
            labels,
            fixups,
            prospective,
            emission_work: 0,
            vector_instructions: 0,
            peak_scratch_bytes: 0,
        };
        assembler.observe_scratch(0, 0, EmissionPhaseV1::Canonical)?;
        Ok(assembler)
    }

    fn observe_scratch(
        &mut self,
        output_label_capacity: usize,
        output_relocation_capacity: usize,
        phase: EmissionPhaseV1,
    ) -> Result<(), CountAotError> {
        let actual = observed_emission_phase_scratch(
            self.code.capacity(),
            self.labels.capacity(),
            self.fixups.capacity(),
            output_label_capacity,
            output_relocation_capacity,
            phase,
        )?;
        if actual > self.prospective.emission_scratch {
            return Err(CountAotError::InternalInvariant {
                at: "emission scratch prospective",
            });
        }
        if actual > self.prospective.scratch_limit {
            return Err(CountAotError::ResourceLimit {
                resource: CountAotResource::ScratchBytes,
                limit: self.prospective.scratch_limit,
                required: actual,
            });
        }
        self.peak_scratch_bytes = self.peak_scratch_bytes.max(actual);
        Ok(())
    }

    fn charge(&mut self, amount: u64) -> Result<(), CountAotError> {
        self.emission_work =
            self.emission_work
                .checked_add(amount)
                .ok_or(CountAotError::ArithmeticOverflow {
                    site: CountAotArithmeticSite::CodeOffset,
                })?;
        Ok(())
    }

    fn new_label(&mut self, kind: LabelKindV1) -> Result<Label, CountAotError> {
        if self.labels.len() >= self.prospective.labels {
            return Err(CountAotError::InternalInvariant {
                at: "label prospective",
            });
        }
        self.charge(1)?;
        let label = Label(to_u32(
            self.labels.len(),
            CountAotArithmeticSite::CodeOffset,
        )?);
        push_exact(
            &mut self.labels,
            LabelRecord { offset: None, kind },
            "label prospective",
        )?;
        Ok(label)
    }

    fn bind(&mut self, label: Label) -> Result<(), CountAotError> {
        self.charge(1)?;
        let offset = to_u32(self.code.len(), CountAotArithmeticSite::CodeOffset)?;
        let record = self
            .labels
            .get_mut(usize::try_from(label.0).expect("u32 fits usize"))
            .ok_or(CountAotError::InternalInvariant { at: "label index" })?;
        if record.offset.replace(offset).is_some() {
            return Err(CountAotError::InternalInvariant {
                at: "label rebound",
            });
        }
        Ok(())
    }

    fn emit_word(&mut self, word: u32, vector: bool) -> Result<(), CountAotError> {
        if self
            .code
            .len()
            .checked_add(4)
            .is_none_or(|required| required > self.prospective.code_bytes)
        {
            return Err(CountAotError::InternalInvariant {
                at: "code prospective",
            });
        }
        self.charge(1)?;
        for byte in word.to_le_bytes() {
            push_exact(&mut self.code, byte, "code prospective")?;
        }
        if vector {
            self.vector_instructions = self.vector_instructions.checked_add(1).ok_or(
                CountAotError::ArithmeticOverflow {
                    site: CountAotArithmeticSite::CodeOffset,
                },
            )?;
        }
        Ok(())
    }

    fn add_fixup(
        &mut self,
        kind: RelocationKindV1,
        target: Label,
        placeholder: u32,
    ) -> Result<(), CountAotError> {
        if self.fixups.len() >= self.prospective.relocations {
            return Err(CountAotError::InternalInvariant {
                at: "relocation prospective",
            });
        }
        let at = to_u32(self.code.len(), CountAotArithmeticSite::CodeOffset)?;
        self.emit_word(placeholder, false)?;
        push_exact(
            &mut self.fixups,
            Fixup { at, kind, target },
            "fixup prospective",
        )?;
        Ok(())
    }

    fn mov_reg(&mut self, destination: u8, source: u8) -> Result<(), CountAotError> {
        self.emit_word(
            0xaa00_03e0 | register_field(source, 16) | register_field(destination, 0),
            false,
        )
    }

    fn mov_imm64(&mut self, destination: u8, value: u64) -> Result<(), CountAotError> {
        for halfword in 0_u8..4 {
            let shift = u32::from(halfword) * 16;
            let immediate = u16::try_from((value >> shift) & 0xffff).expect("masked halfword");
            let base = if halfword == 0 {
                0xd280_0000
            } else {
                0xf280_0000
            };
            self.emit_word(
                base | (u32::from(halfword) << 21)
                    | (u32::from(immediate) << 5)
                    | u32::from(destination),
                false,
            )?;
        }
        Ok(())
    }

    fn cmp_reg64(&mut self, left: u8, right: u8) -> Result<(), CountAotError> {
        self.emit_word(
            0xeb00_001f | register_field(right, 16) | register_field(left, 5),
            false,
        )
    }

    fn cmp_reg32(&mut self, left: u8, right: u8) -> Result<(), CountAotError> {
        self.emit_word(
            0x6b00_001f | register_field(right, 16) | register_field(left, 5),
            false,
        )
    }

    fn cmp_imm64(&mut self, register: u8, immediate: u16) -> Result<(), CountAotError> {
        self.emit_word(
            0xf100_001f | (u32::from(immediate) << 10) | register_field(register, 5),
            false,
        )
    }

    fn add_reg(&mut self, destination: u8, left: u8, right: u8) -> Result<(), CountAotError> {
        self.emit_word(
            0x8b00_0000
                | register_field(right, 16)
                | register_field(left, 5)
                | u32::from(destination),
            false,
        )
    }

    fn add_imm(
        &mut self,
        destination: u8,
        source: u8,
        immediate: u16,
    ) -> Result<(), CountAotError> {
        self.emit_word(
            0x9100_0000
                | (u32::from(immediate) << 10)
                | register_field(source, 5)
                | u32::from(destination),
            false,
        )
    }

    fn sub_reg(&mut self, destination: u8, left: u8, right: u8) -> Result<(), CountAotError> {
        self.emit_word(
            0xcb00_0000
                | register_field(right, 16)
                | register_field(left, 5)
                | u32::from(destination),
            false,
        )
    }

    fn sub_imm(
        &mut self,
        destination: u8,
        source: u8,
        immediate: u16,
    ) -> Result<(), CountAotError> {
        self.emit_word(
            0xd100_0000
                | (u32::from(immediate) << 10)
                | register_field(source, 5)
                | u32::from(destination),
            false,
        )
    }

    fn and_low_bits(&mut self, destination: u8, source: u8, bits: u8) -> Result<(), CountAotError> {
        let mask = u32::from(
            bits.checked_sub(1)
                .ok_or(CountAotError::InternalInvariant {
                    at: "zero low-bit mask",
                })?,
        ) << 10;
        self.emit_word(
            0x9240_0000 | mask | register_field(source, 5) | u32::from(destination),
            false,
        )
    }

    fn load_byte(&mut self, destination: u8, base: u8, offset: u16) -> Result<(), CountAotError> {
        self.emit_word(
            0x3940_0000
                | (u32::from(offset) << 10)
                | register_field(base, 5)
                | u32::from(destination),
            false,
        )
    }

    fn load_byte_reg(&mut self, destination: u8, base: u8, index: u8) -> Result<(), CountAotError> {
        self.emit_word(
            0x3860_6800
                | register_field(index, 16)
                | register_field(base, 5)
                | u32::from(destination),
            false,
        )
    }

    fn load64_reg_scaled(
        &mut self,
        destination: u8,
        base: u8,
        index: u8,
    ) -> Result<(), CountAotError> {
        self.emit_word(
            0xf860_7800
                | register_field(index, 16)
                | register_field(base, 5)
                | u32::from(destination),
            false,
        )
    }

    fn store64(&mut self, source: u8, base: u8, offset: u16) -> Result<(), CountAotError> {
        self.emit_word(
            0xf900_0000
                | (u32::from(offset / 8) << 10)
                | register_field(base, 5)
                | u32::from(source),
            false,
        )
    }

    fn load_vector128(
        &mut self,
        destination: u8,
        base: u8,
        offset: u16,
    ) -> Result<(), CountAotError> {
        self.emit_word(
            0x3dc0_0000
                | (u32::from(offset / 16) << 10)
                | register_field(base, 5)
                | u32::from(destination),
            true,
        )
    }

    fn dup_byte16(&mut self, destination: u8, source: u8) -> Result<(), CountAotError> {
        self.emit_word(
            0x4e01_0c00 | register_field(source, 5) | u32::from(destination),
            true,
        )
    }

    fn compare_equal_bytes16(
        &mut self,
        destination: u8,
        left: u8,
        right: u8,
    ) -> Result<(), CountAotError> {
        self.emit_word(
            0x6e20_8c00
                | register_field(right, 16)
                | register_field(left, 5)
                | u32::from(destination),
            true,
        )
    }

    fn add_across_bytes16(&mut self, destination: u8, source: u8) -> Result<(), CountAotError> {
        self.emit_word(
            0x4e31_b800 | register_field(source, 5) | u32::from(destination),
            true,
        )
    }

    fn move_vector_byte_to32(&mut self, destination: u8, source: u8) -> Result<(), CountAotError> {
        self.emit_word(
            0x0e01_3c00 | register_field(source, 5) | u32::from(destination),
            true,
        )
    }

    fn branch(&mut self, target: Label) -> Result<(), CountAotError> {
        self.add_fixup(RelocationKindV1::Branch26, target, 0x1400_0000)
    }

    fn branch_cond(&mut self, condition: ConditionV1, target: Label) -> Result<(), CountAotError> {
        self.add_fixup(
            RelocationKindV1::ConditionalBranch19,
            target,
            0x5400_0000 | u32::from(condition_encoding(condition)),
        )
    }

    fn ret(&mut self) -> Result<(), CountAotError> {
        self.emit_word(0xd65f_03c0, false)
    }

    fn order_labels(&mut self, labels: &mut [CodeLabelV1]) -> Result<(), CountAotError> {
        let budget = label_order_work_upper_bound(labels.len())?;
        let recomposed = budget
            .comparisons
            .checked_add(budget.moves)
            .and_then(|value| value.checked_add(budget.placements))
            .ok_or(arithmetic_prospective())?;
        if recomposed != budget.total {
            return Err(CountAotError::InternalInvariant {
                at: "label order work envelope",
            });
        }
        // Refuse and charge the complete derived worst case before the first
        // comparison or move. No library sort can hide unmetered work here.
        self.charge(budget.total)?;
        let mut comparisons = 0_u64;
        let mut moves = 0_u64;
        let mut placements = 0_u64;
        for insertion in 1..labels.len() {
            let key = labels[insertion];
            let mut cursor = insertion;
            while cursor != 0 {
                comparisons = comparisons.checked_add(1).ok_or(arithmetic_prospective())?;
                let previous_index = cursor.checked_sub(1).ok_or(arithmetic_prospective())?;
                let previous = labels[previous_index];
                if !label_is_after(previous, key) {
                    break;
                }
                labels[cursor] = previous;
                moves = moves.checked_add(1).ok_or(arithmetic_prospective())?;
                cursor = previous_index;
            }
            labels[cursor] = key;
            placements = placements.checked_add(1).ok_or(arithmetic_prospective())?;
        }
        if comparisons > budget.comparisons
            || moves > budget.moves
            || placements != budget.placements
        {
            return Err(CountAotError::InternalInvariant {
                at: "label order observed work",
            });
        }
        Ok(())
    }

    fn finalize(mut self) -> Result<Finalized, CountAotError> {
        let mut relocations = exact_vec(self.fixups.len(), CountAotResource::Relocations)?;
        self.observe_scratch(
            0,
            relocations.capacity(),
            EmissionPhaseV1::FinalizeRelocations,
        )?;
        for index in 0..self.fixups.len() {
            let fixup = self.fixups[index];
            self.charge(1)?;
            let record = self
                .labels
                .get(usize::try_from(fixup.target.0).expect("u32 fits usize"))
                .ok_or(CountAotError::InternalInvariant { at: "fixup target" })?;
            let target = record.offset.ok_or(CountAotError::InternalInvariant {
                at: "unbound fixup target",
            })?;
            let word = read_word(&self.code, fixup.at)?;
            let resolved = resolve_branch(word, fixup.kind, fixup.at, target)?;
            write_word(&mut self.code, fixup.at, resolved)?;
            push_exact(
                &mut relocations,
                RelocationV1 {
                    code_offset: fixup.at,
                    kind: fixup.kind,
                    target: RelocationTargetV1::CodeOffset(target),
                    resolved_word: resolved,
                },
                "final relocation capacity",
            )?;
        }
        let mut labels = exact_vec(self.labels.len(), CountAotResource::Labels)?;
        self.observe_scratch(
            labels.capacity(),
            relocations.capacity(),
            EmissionPhaseV1::CollectLabels,
        )?;
        let code_capacity_bytes = self.code.capacity();
        let label_capacity_bytes = labels
            .capacity()
            .checked_mul(size_of::<CodeLabelV1>())
            .ok_or(CountAotError::ArithmeticOverflow {
                site: CountAotArithmeticSite::Persistent,
            })?;
        let relocation_capacity_bytes = relocations
            .capacity()
            .checked_mul(size_of::<RelocationV1>())
            .ok_or(CountAotError::ArithmeticOverflow {
                site: CountAotArithmeticSite::Persistent,
            })?;
        for record in self.labels.iter().copied() {
            push_exact(
                &mut labels,
                CodeLabelV1 {
                    offset: record.offset.ok_or(CountAotError::InternalInvariant {
                        at: "unbound label",
                    })?,
                    kind: record.kind,
                },
                "final label capacity",
            )?;
        }
        self.observe_scratch(
            labels.capacity(),
            relocations.capacity(),
            EmissionPhaseV1::OrderLabels,
        )?;
        self.order_labels(&mut labels)?;
        let code_bytes = to_u32(self.code.len(), CountAotArithmeticSite::CodeOffset)?;
        let label_count = to_u32(labels.len(), CountAotArithmeticSite::CodeOffset)?;
        let relocation_count = to_u32(relocations.len(), CountAotArithmeticSite::CodeOffset)?;
        self.observe_scratch(
            labels.capacity(),
            relocations.capacity(),
            EmissionPhaseV1::FinalizeReturn,
        )?;
        Ok(Finalized {
            code: self.code,
            labels,
            relocations,
            code_bytes,
            label_count,
            relocation_count,
            emission_work: self.emission_work,
            vector_instructions: self.vector_instructions,
            code_capacity_bytes,
            label_capacity_bytes,
            relocation_capacity_bytes,
            emission_peak_scratch_bytes: self.peak_scratch_bytes,
        })
    }
}

const fn label_is_after(left: CodeLabelV1, right: CodeLabelV1) -> bool {
    left.offset > right.offset
        || (left.offset == right.offset
            && label_kind_order(left.kind) > label_kind_order(right.kind))
}

const fn label_kind_order(kind: LabelKindV1) -> u8 {
    match kind {
        LabelKindV1::Entry => 1,
        LabelKindV1::Loop => 2,
        LabelKindV1::SlowPath => 3,
        LabelKindV1::Success => 4,
        LabelKindV1::Overflow => 5,
        LabelKindV1::Internal => 6,
    }
}

const fn condition_encoding(condition: ConditionV1) -> u8 {
    match condition {
        ConditionV1::Equal => 0,
        ConditionV1::NotEqual => 1,
        ConditionV1::CarrySet => 2,
        ConditionV1::CarryClear => 3,
        ConditionV1::Higher => 8,
    }
}

const fn label_kind_encoding(kind: LabelKindV1) -> u8 {
    match kind {
        LabelKindV1::Entry => 1,
        LabelKindV1::Loop => 2,
        LabelKindV1::SlowPath => 3,
        LabelKindV1::Success => 4,
        LabelKindV1::Overflow => 5,
        LabelKindV1::Internal => 6,
    }
}

const fn relocation_kind_encoding(kind: RelocationKindV1) -> u8 {
    match kind {
        RelocationKindV1::Branch26 => 1,
        RelocationKindV1::ConditionalBranch19 => 2,
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Finalized {
    pub(crate) code: ExactVec<u8>,
    pub(crate) labels: ExactVec<CodeLabelV1>,
    pub(crate) relocations: ExactVec<RelocationV1>,
    pub(crate) code_bytes: u32,
    pub(crate) label_count: u32,
    pub(crate) relocation_count: u32,
    pub(crate) emission_work: u64,
    pub(crate) vector_instructions: u32,
    pub(crate) code_capacity_bytes: usize,
    pub(crate) label_capacity_bytes: usize,
    pub(crate) relocation_capacity_bytes: usize,
    pub(crate) emission_peak_scratch_bytes: u64,
}

pub(crate) fn compute_artifact_identity(
    image: &AotCountImageV1,
) -> Result<(AotCountArtifactIdentity, u64), CountAotError> {
    let mut encoder = IdentityEncoder::hasher();
    encode_artifact_identity(&mut encoder, image)?;
    encoder.finish()
}

pub(crate) fn artifact_identity_encoded_len(image: &AotCountImageV1) -> Result<u64, CountAotError> {
    let mut encoder = IdentityEncoder::counter();
    encode_artifact_identity(&mut encoder, image)?;
    Ok(encoder.bytes)
}

fn encode_artifact_identity(
    encoder: &mut IdentityEncoder,
    image: &AotCountImageV1,
) -> Result<(), CountAotError> {
    encoder.raw(IDENTITY_DOMAIN)?;
    encoder.u16(AOT_COUNT_IMAGE_SCHEMA_VERSION_V1)?;
    encode_support(encoder, image.support)?;
    let target = image.target;
    encoder.u8(target.architecture)?;
    encoder.boolean(target.little_endian)?;
    encoder.u8(target.pointer_width)?;
    encoder.u8(target.abi)?;
    encoder.u64(target.features.bits())?;
    encoder.raw(image.source_identity.as_bytes())?;
    encoder.u32(image.literal_bytes)?;
    encoder.u8(image.literal_manifest.len())?;
    encoder.raw(&image.literal_manifest.padded_bytes())?;
    let layout = image.layout;
    encoder.u32(layout.code_alignment)?;
    encoder.u32(layout.rodata_alignment)?;
    encoder.u32(layout.rodata_from_code_start)?;
    encoder.u32(layout.total_mapped_bytes)?;
    encoder.bytes(&image.code)?;
    encoder.u32(u32::try_from(image.labels.len()).map_err(|_| {
        CountAotError::ArithmeticOverflow {
            site: CountAotArithmeticSite::Identity,
        }
    })?)?;
    for label in &image.labels {
        encoder.u32(label.offset)?;
        encoder.u8(label_kind_encoding(label.kind))?;
    }
    encoder.u32(u32::try_from(image.relocations.len()).map_err(|_| {
        CountAotError::ArithmeticOverflow {
            site: CountAotArithmeticSite::Identity,
        }
    })?)?;
    for relocation in &image.relocations {
        encoder.u32(relocation.code_offset)?;
        encoder.u8(relocation_kind_encoding(relocation.kind))?;
        let RelocationTargetV1::CodeOffset(target) = relocation.target;
        encoder.u32(target)?;
        encoder.u32(relocation.resolved_word)?;
    }
    encoder.u32(image.stats.code_bytes)?;
    encoder.u32(image.stats.data_bytes)?;
    encoder.u32(image.stats.labels)?;
    encoder.u32(image.stats.relocations)?;
    encoder.u32(image.stats.emitted_instructions)?;
    encoder.u32(image.stats.vector_instructions)?;
    encoder.u64(image.stats.emission_work)?;
    encoder.u64(image.stats.identity_bytes_hashed)?;
    encoder.u64(image.stats.audit_work_upper_bound)?;
    encoder.u64(image.stats.total_work_upper_bound)?;
    encoder.u64(image.stats.scratch_bytes_upper_bound)?;
    encode_support(encoder, image.build_receipt.support)?;
    encoder.u64(to_u64(
        image.build_receipt.code_capacity_bytes,
        CountAotArithmeticSite::Identity,
    )?)?;
    encoder.u64(to_u64(
        image.build_receipt.label_capacity_bytes,
        CountAotArithmeticSite::Identity,
    )?)?;
    encoder.u64(to_u64(
        image.build_receipt.relocation_capacity_bytes,
        CountAotArithmeticSite::Identity,
    )?)?;
    encoder.u64(to_u64(
        image.build_receipt.retained_heap_bytes,
        CountAotArithmeticSite::Identity,
    )?)?;
    encoder.u64(to_u64(
        image.build_receipt.inline_bytes,
        CountAotArithmeticSite::Identity,
    )?)?;
    encoder.u64(image.build_receipt.emission_peak_scratch_bytes)?;
    encoder.u64(image.build_receipt.work_upper_bound)?;
    encoder.u64(image.build_receipt.scratch_bytes_upper_bound)?;
    let audit = image.build_receipt.audit;
    encoder.u32(audit.instructions)?;
    encoder.u32(audit.direct_branches)?;
    encoder.u32(audit.data_addresses)?;
    encoder.u32(audit.vector_instructions)?;
    encoder.u32(audit.stores)?;
    encoder.u32(audit.returns)?;
    encoder.u64(audit.work_upper_bound)?;
    encoder.u64(audit.scratch_bytes_upper_bound)
}

fn encode_support(
    encoder: &mut IdentityEncoder,
    support: crate::AotCountBackendSupportV1,
) -> Result<(), CountAotError> {
    encoder.u16(support.backend_version.0)?;
    encoder.u16(support.algorithm_version)?;
    encoder.u16(support.kir_semantics_version)?;
    encoder.u16(support.kir_abi_version)?;
    encoder.u8(support.output_kind)?;
    encoder.u8(support.architecture)?;
    encoder.boolean(support.little_endian)?;
    encoder.u8(support.pointer_width)?;
    encoder.u8(support.target_abi)?;
    encoder.u64(support.allowed_features.bits())?;
    encoder.u16(support.max_literal_bytes)
}

struct IdentityEncoder {
    hasher: Option<Sha256>,
    bytes: u64,
}

impl IdentityEncoder {
    fn hasher() -> Self {
        Self {
            hasher: Some(Sha256::new()),
            bytes: 0,
        }
    }

    const fn counter() -> Self {
        Self {
            hasher: None,
            bytes: 0,
        }
    }

    fn raw(&mut self, bytes: &[u8]) -> Result<(), CountAotError> {
        self.bytes = self
            .bytes
            .checked_add(to_u64(bytes.len(), CountAotArithmeticSite::Identity)?)
            .ok_or(CountAotError::ArithmeticOverflow {
                site: CountAotArithmeticSite::Identity,
            })?;
        if let Some(hasher) = &mut self.hasher {
            hasher.update(bytes);
        }
        Ok(())
    }

    fn bytes(&mut self, bytes: &[u8]) -> Result<(), CountAotError> {
        self.u64(to_u64(bytes.len(), CountAotArithmeticSite::Identity)?)?;
        self.raw(bytes)
    }

    fn boolean(&mut self, value: bool) -> Result<(), CountAotError> {
        self.u8(u8::from(value))
    }

    fn u8(&mut self, value: u8) -> Result<(), CountAotError> {
        self.raw(&[value])
    }

    fn u16(&mut self, value: u16) -> Result<(), CountAotError> {
        self.raw(&value.to_le_bytes())
    }

    fn u32(&mut self, value: u32) -> Result<(), CountAotError> {
        self.raw(&value.to_le_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), CountAotError> {
        self.raw(&value.to_le_bytes())
    }

    fn finish(self) -> Result<(AotCountArtifactIdentity, u64), CountAotError> {
        let digest = self
            .hasher
            .ok_or(CountAotError::InternalInvariant {
                at: "finish identity counter",
            })?
            .finalize();
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(&digest);
        Ok((AotCountArtifactIdentity::new(bytes), self.bytes))
    }
}

fn resolve_branch(
    word: u32,
    kind: RelocationKindV1,
    from: u32,
    target: u32,
) -> Result<u32, CountAotError> {
    let displacement = i64::from(target).checked_sub(i64::from(from)).ok_or(
        CountAotError::ArithmeticOverflow {
            site: CountAotArithmeticSite::Relocation,
        },
    )?;
    let (bits, shift) = match kind {
        RelocationKindV1::Branch26 => (26_u8, 0_u8),
        RelocationKindV1::ConditionalBranch19 => (19, 5),
    };
    if displacement % 4 != 0 {
        return Err(CountAotError::InternalInvariant {
            at: "unaligned branch",
        });
    }
    let scaled = displacement / 4;
    let magnitude_shift = bits
        .checked_sub(1)
        .ok_or(CountAotError::InternalInvariant {
            at: "branch magnitude bits",
        })?;
    let magnitude =
        1_i64
            .checked_shl(u32::from(magnitude_shift))
            .ok_or(CountAotError::InternalInvariant {
                at: "branch magnitude",
            })?;
    let negative_magnitude = magnitude
        .checked_neg()
        .ok_or(CountAotError::InternalInvariant {
            at: "negative branch magnitude",
        })?;
    if scaled < negative_magnitude || scaled >= magnitude {
        return Err(CountAotError::InvalidImage { at: "branch range" });
    }
    let mask = 1_u32
        .checked_shl(u32::from(bits))
        .and_then(|value| value.checked_sub(1))
        .ok_or(CountAotError::InternalInvariant { at: "branch mask" })?;
    let encoded = u32::try_from(scaled & i64::from(mask)).expect("masked displacement");
    Ok(word
        | encoded
            .checked_shl(u32::from(shift))
            .ok_or(CountAotError::InternalInvariant {
                at: "branch field shift",
            })?)
}

fn read_word(code: &[u8], offset: u32) -> Result<u32, CountAotError> {
    let offset = usize::try_from(offset).expect("u32 fits usize");
    let bytes = code
        .get(
            offset
                ..offset
                    .checked_add(4)
                    .ok_or(CountAotError::ArithmeticOverflow {
                        site: CountAotArithmeticSite::CodeOffset,
                    })?,
        )
        .ok_or(CountAotError::InternalInvariant {
            at: "read relocation word",
        })?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn write_word(code: &mut [u8], offset: u32, word: u32) -> Result<(), CountAotError> {
    let offset = usize::try_from(offset).expect("u32 fits usize");
    let end = offset
        .checked_add(4)
        .ok_or(CountAotError::ArithmeticOverflow {
            site: CountAotArithmeticSite::CodeOffset,
        })?;
    code.get_mut(offset..end)
        .ok_or(CountAotError::InternalInvariant {
            at: "write relocation word",
        })?
        .copy_from_slice(&word.to_le_bytes());
    Ok(())
}

fn register_field(register: u8, shift: u8) -> u32 {
    debug_assert!(register < 32);
    u32::from(register) << shift
}

fn align_up(value: usize, alignment: usize) -> Result<usize, CountAotError> {
    let mask = alignment
        .checked_sub(1)
        .ok_or(CountAotError::InternalInvariant {
            at: "zero alignment",
        })?;
    value
        .checked_add(mask)
        .map(|sum| sum & !mask)
        .ok_or(CountAotError::ArithmeticOverflow {
            site: CountAotArithmeticSite::ImageLayout,
        })
}

fn exact_vec<T>(capacity: usize, resource: CountAotResource) -> Result<ExactVec<T>, CountAotError> {
    ExactVec::try_with_capacity(capacity).map_err(|error| match error {
        CopyError::LayoutOverflow => CountAotError::ArithmeticOverflow {
            site: CountAotArithmeticSite::Prospective,
        },
        CopyError::AllocationFailed => CountAotError::AllocationFailed { resource },
    })
}

fn push_exact<T>(
    values: &mut ExactVec<T>,
    value: T,
    at: &'static str,
) -> Result<(), CountAotError> {
    values
        .try_push(value)
        .map_err(|_| CountAotError::InternalInvariant { at })
}

fn enforce_all(
    resource: CountAotResource,
    required: u64,
    caller_limit: u64,
    hard_limit: u64,
) -> Result<(), CountAotError> {
    let limit = caller_limit.min(hard_limit);
    if required > limit {
        return Err(CountAotError::ResourceLimit {
            resource,
            limit,
            required,
        });
    }
    Ok(())
}

fn to_u32(value: usize, site: CountAotArithmeticSite) -> Result<u32, CountAotError> {
    u32::try_from(value).map_err(|_| CountAotError::ArithmeticOverflow { site })
}

fn to_u64(value: usize, site: CountAotArithmeticSite) -> Result<u64, CountAotError> {
    u64::try_from(value).map_err(|_| CountAotError::ArithmeticOverflow { site })
}

const fn arithmetic_prospective() -> CountAotError {
    CountAotError::ArithmeticOverflow {
        site: CountAotArithmeticSite::Prospective,
    }
}
