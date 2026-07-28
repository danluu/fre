#![allow(
    clippy::arithmetic_side_effects,
    reason = "instruction encoding arithmetic is over bounded ISA fields and literal widths; resource formulas use checked operations"
)]

use core::mem::size_of;

use fre_exact_alloc::{CopyError, ExactVec};
use fre_kernel_ir::{
    AggregateOutput, Count, ExactAggregateProgram, MAX_EXACT_AGGREGATE_LITERAL_BYTES,
};
use sha2::{Digest, Sha256};

use crate::{
    AOT_COUNT_IMAGE_SCHEMA_VERSION_V2, AotCountArtifactIdentityV2, AotCountCpuFeatures,
    AotCountImageBuildReceiptV2, AotCountImageLayoutV2, AotCountImageStatsV2, AotCountImageV2,
    AotCountLiteralManifestV2, AotCountTargetSpec, CodeLabelV2, ConditionV2,
    CountAotArithmeticSite, CountAotError, CountAotResource, CountAotUnsupported,
    CountAuditReportV2, LabelKindV2, RelocationKindV2, RelocationTargetV2, RelocationV2,
    SUPPORTED_AOT_COUNT_BACKEND_TUPLES_V2,
    audit_v2::{
        audit_candidate_wrapper_inline_bytes_v2, audit_count_image_candidate_v2,
        audit_count_image_v2, audit_public_wrapper_inline_bytes_v2, audit_scratch_upper_bound_v2,
        audit_work_upper_bound_v2,
    },
};

const CODE_ALIGNMENT_V2: usize = 16;
const MAX_CODE_BYTES_V2: u64 = 16 << 10;
const MAX_LABELS_V2: u64 = 18;
const MAX_RELOCATIONS_V2: u64 = 96;
const MAX_WORK_V2: u64 = 2 << 20;
const MAX_SCRATCH_BYTES_V2: u64 = 128 << 10;
const MAX_PERSISTENT_BYTES_V2: u64 = 128 << 10;
const IDENTITY_DOMAIN_V2: &[u8] = b"FRE-AOT-AARCH64-COUNT-IMAGE\0\x02";
const SIMD_CANDIDATE_STARTS_V2: u16 = 16;
const SPARSE_SCAN_BLOCKS_V2: u16 = 4;
const SPARSE_SCAN_STARTS_V2: u16 = SIMD_CANDIDATE_STARTS_V2 * SPARSE_SCAN_BLOCKS_V2;
const SPARSE_NIBBLE_BITS_V2: u64 = 0x1111_1111_1111_1111;
const SPARSE_BLOCK_MASK_BASE_V2: u8 = 24;
const SPARSE_FIRST_HALF_MASK_V2: u8 = 28;
const SPARSE_SECOND_HALF_MASK_V2: u8 = 29;

const X0: u8 = 0;
const X1: u8 = 1;
const X2: u8 = 2;
const X3: u8 = 3;
const X4: u8 = 4;
const X5: u8 = 5;
const X6: u8 = 6;
const X7: u8 = 7;
const X8: u8 = 8;
const X9: u8 = 9;
const X10: u8 = 10;
const X11: u8 = 11;
const X12: u8 = 12;
const X13: u8 = 13;
const X14: u8 = 14;
const X15: u8 = 15;
const X16: u8 = 16;
const X17: u8 = 17;

/// Caller-selected experimental v2 limits, each capped by a hard bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountEmitLimitsV2 {
    pub max_code_bytes: u64,
    pub max_data_bytes: u64,
    pub max_labels: u64,
    pub max_relocations: u64,
    pub max_work: u64,
    pub max_scratch_bytes: u64,
    pub max_persistent_bytes: u64,
}

impl Default for CountEmitLimitsV2 {
    fn default() -> Self {
        Self {
            max_code_bytes: MAX_CODE_BYTES_V2,
            max_data_bytes: 0,
            max_labels: MAX_LABELS_V2,
            max_relocations: MAX_RELOCATIONS_V2,
            max_work: MAX_WORK_V2,
            max_scratch_bytes: MAX_SCRATCH_BYTES_V2,
            max_persistent_bytes: MAX_PERSISTENT_BYTES_V2,
        }
    }
}

/// O(1), source-dimension conservative envelope for a v2 Count image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountProspectiveReportV2 {
    pub code_bytes_upper_bound: u64,
    pub data_bytes_upper_bound: u64,
    pub labels_upper_bound: u64,
    pub relocations_upper_bound: u64,
    pub identity_bytes_hashed_upper_bound: u64,
    pub audit_work_upper_bound: u64,
    pub audit_scratch_bytes_upper_bound: u64,
    pub emission_scratch_bytes_upper_bound: u64,
    pub image_backing_bytes_upper_bound: u64,
    pub total_work_upper_bound: u64,
    pub scratch_bytes_upper_bound: u64,
    pub persistent_bytes_upper_bound: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProspectiveV2 {
    pub(crate) code_bytes: usize,
    pub(crate) labels: usize,
    pub(crate) relocations: usize,
    pub(crate) identity_bytes_hashed: u64,
    pub(crate) audit_work: u64,
    pub(crate) audit_scratch: u64,
    pub(crate) assembler_scratch: u64,
    pub(crate) emission_scratch: u64,
    pub(crate) image_backing: u64,
    pub(crate) image_assembly_scratch: u64,
    pub(crate) candidate_audit_scratch: u64,
    pub(crate) sealed_audit_scratch: u64,
    pub(crate) initial_identity_scratch: u64,
    pub(crate) sealed_identity_length_scratch: u64,
    pub(crate) sealed_identity_hash_scratch: u64,
    pub(crate) filter_selection_work: u64,
    pub(crate) work: u64,
    pub(crate) scratch: u64,
    pub(crate) persistent: u64,
    pub(crate) scratch_limit: u64,
    pub(crate) persistent_limit: u64,
}

/// Source-only work envelope for ranked candidate-filter selection.
///
/// The initial pair plus the remaining initial scan visit each literal byte
/// once. The first additional scan has two selected offsets, so each byte can
/// require one byte visit, two index-membership probes and two selected-value
/// probes. The second additional scan has three selected offsets and therefore
/// requires one plus three plus three touches per literal byte.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CandidateFilterWorkEnvelopeV2 {
    pub(crate) initial_scan: u64,
    pub(crate) two_offset_scan: u64,
    pub(crate) three_offset_scan: u64,
    pub(crate) total: u64,
}

pub(crate) fn candidate_filter_work_envelope_v2(
    literal_len: usize,
) -> Result<CandidateFilterWorkEnvelopeV2, CountAotError> {
    const TWO_OFFSET_TOUCHES_PER_BYTE_V2: u64 = 1 + 2 + 2;
    const THREE_OFFSET_TOUCHES_PER_BYTE_V2: u64 = 1 + 3 + 3;
    let literal = to_u64(literal_len, CountAotArithmeticSite::Prospective)?;
    let initial_scan = literal;
    let two_offset_scan = literal
        .checked_mul(TWO_OFFSET_TOUCHES_PER_BYTE_V2)
        .ok_or(arithmetic_prospective_v2())?;
    let three_offset_scan = literal
        .checked_mul(THREE_OFFSET_TOUCHES_PER_BYTE_V2)
        .ok_or(arithmetic_prospective_v2())?;
    let total = initial_scan
        .checked_add(two_offset_scan)
        .and_then(|work| work.checked_add(three_offset_scan))
        .ok_or(arithmetic_prospective_v2())?;
    Ok(CandidateFilterWorkEnvelopeV2 {
        initial_scan,
        two_offset_scan,
        three_offset_scan,
        total,
    })
}

/// Compute the complete v2 build envelope without reading a literal byte.
pub fn prospective_count_v2(
    program: &ExactAggregateProgram<Count>,
) -> Result<CountProspectiveReportV2, CountAotError> {
    let literal_len = preflight_program_dimensions_v2(program)?;
    let prospective = prospective_v2(literal_len)?;
    Ok(CountProspectiveReportV2 {
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
        audit_work_upper_bound: prospective.audit_work,
        audit_scratch_bytes_upper_bound: prospective.audit_scratch,
        emission_scratch_bytes_upper_bound: prospective.emission_scratch,
        image_backing_bytes_upper_bound: prospective.image_backing,
        total_work_upper_bound: prospective.work,
        scratch_bytes_upper_bound: prospective.scratch,
        persistent_bytes_upper_bound: prospective.persistent,
    })
}

/// Emit a genuine direct-AOT Count v2 image from sealed exact-aggregate KIR.
///
/// Widths 2 through 32 use two rare literal bytes to filter exactly sixteen
/// candidate starts per ASIMD block. A bounded reduction of that pair mask
/// distinguishes absent, single-lane, and pair-dense blocks. Single-lane
/// blocks retain staged rare-byte filtering; pair-dense blocks use a
/// first/last mask before candidate recovery. Confirmed matches enter an
/// exact-width full-literal run loop, and absent blocks retain the four-block
/// sparse scan. No route depends on a caller or benchmark name.
#[allow(
    clippy::too_many_lines,
    reason = "one ordered build transaction keeps every preflight, allocation, phase observation, and seal visible"
)]
pub fn emit_count_v2(
    program: &ExactAggregateProgram<Count>,
    limits: CountEmitLimitsV2,
) -> Result<AotCountImageV2, CountAotError> {
    let literal_len = preflight_program_dimensions_v2(program)?;
    let mut prospective = prospective_v2(literal_len)?;
    enforce_all_v2(
        CountAotResource::CodeBytes,
        to_u64(prospective.code_bytes, CountAotArithmeticSite::Prospective)?,
        limits.max_code_bytes,
        MAX_CODE_BYTES_V2,
    )?;
    enforce_all_v2(CountAotResource::DataBytes, 0, limits.max_data_bytes, 0)?;
    enforce_all_v2(
        CountAotResource::Labels,
        to_u64(prospective.labels, CountAotArithmeticSite::Prospective)?,
        limits.max_labels,
        MAX_LABELS_V2,
    )?;
    enforce_all_v2(
        CountAotResource::Relocations,
        to_u64(prospective.relocations, CountAotArithmeticSite::Prospective)?,
        limits.max_relocations,
        MAX_RELOCATIONS_V2,
    )?;
    enforce_all_v2(
        CountAotResource::Work,
        prospective.work,
        limits.max_work,
        MAX_WORK_V2,
    )?;
    enforce_all_v2(
        CountAotResource::ScratchBytes,
        prospective.scratch,
        limits.max_scratch_bytes,
        MAX_SCRATCH_BYTES_V2,
    )?;
    enforce_all_v2(
        CountAotResource::PersistentBytes,
        prospective.persistent,
        limits.max_persistent_bytes,
        MAX_PERSISTENT_BYTES_V2,
    )?;
    prospective.scratch_limit = limits.max_scratch_bytes.min(MAX_SCRATCH_BYTES_V2);
    prospective.persistent_limit = limits.max_persistent_bytes.min(MAX_PERSISTENT_BYTES_V2);

    // No literal byte is read until every caller and hard bound is admitted.
    let literal = program.literal();
    let filter_selection = select_candidate_filter_v2(literal)?;
    if filter_selection.observed.total()? > prospective.filter_selection_work {
        return Err(CountAotError::InternalInvariant {
            at: "v2 candidate-filter work envelope",
        });
    }
    let filter = filter_selection.filter;
    let filter_offsets = filter.as_ref().map_or(&[][..], CandidateFilterV2::offsets);
    let literal_manifest =
        AotCountLiteralManifestV2::from_literal_and_offsets(literal, filter_offsets).ok_or(
            CountAotError::InternalInvariant {
                at: "v2 literal manifest",
            },
        )?;
    let finalized = canonical_template_v2(literal, filter, prospective)?;
    if finalized.code.len() > prospective.code_bytes
        || finalized.labels.len() > prospective.labels
        || finalized.relocations.len() > prospective.relocations
    {
        return Err(CountAotError::InternalInvariant {
            at: "v2 emission exceeded prospective dimensions",
        });
    }
    let observed_image_assembly_scratch = image_assembly_scratch_for_capacities_v2(
        finalized.code.capacity(),
        finalized.labels.capacity(),
        finalized.relocations.capacity(),
    )?;
    if observed_image_assembly_scratch > prospective.image_assembly_scratch {
        return Err(CountAotError::InternalInvariant {
            at: "v2 image assembly scratch prospective",
        });
    }
    if observed_image_assembly_scratch > prospective.scratch_limit {
        return Err(CountAotError::ResourceLimit {
            resource: CountAotResource::ScratchBytes,
            limit: prospective.scratch_limit,
            required: observed_image_assembly_scratch,
        });
    }
    let FinalizedV2 {
        code,
        labels,
        relocations,
        emission_work,
        vector_instructions,
        code_capacity_bytes,
        label_capacity_bytes,
        relocation_capacity_bytes,
        emission_peak_scratch_bytes: assembler_peak_scratch_bytes,
    } = finalized;
    let recomputed_assembler_peak_scratch = assembler_scratch_for_capacities_v2(
        code_capacity_bytes,
        prospective.labels,
        prospective.relocations,
        labels.capacity(),
        relocations.capacity(),
    )?;
    if assembler_peak_scratch_bytes != recomputed_assembler_peak_scratch
        || assembler_peak_scratch_bytes > prospective.assembler_scratch
    {
        return Err(CountAotError::InternalInvariant {
            at: "v2 assembler scratch seal",
        });
    }
    let emission_peak_scratch_bytes =
        assembler_peak_scratch_bytes.max(observed_image_assembly_scratch);
    if observed_image_assembly_scratch > prospective.image_assembly_scratch
        || emission_peak_scratch_bytes > prospective.emission_scratch
    {
        return Err(CountAotError::InternalInvariant {
            at: "v2 emission scratch seal",
        });
    }
    let code_bytes = to_u32(code.len(), CountAotArithmeticSite::ImageLayout)?;
    let rodata_offset = align_up_v2(code.len(), CODE_ALIGNMENT_V2)?;
    let layout = AotCountImageLayoutV2 {
        code_alignment: u32::try_from(CODE_ALIGNMENT_V2).expect("small alignment"),
        rodata_alignment: u32::try_from(CODE_ALIGNMENT_V2).expect("small alignment"),
        rodata_from_code_start: to_u32(rodata_offset, CountAotArithmeticSite::ImageLayout)?,
        total_mapped_bytes: to_u32(rodata_offset, CountAotArithmeticSite::ImageLayout)?,
    };
    let support = SUPPORTED_AOT_COUNT_BACKEND_TUPLES_V2[0];
    let target = AotCountTargetSpec {
        features: if vector_instructions == 0 {
            AotCountCpuFeatures::NONE
        } else {
            AotCountCpuFeatures::ASIMD
        },
        ..AotCountTargetSpec::AARCH64_AAPCS64_BASELINE
    };
    let retained_heap_bytes = AotCountImageV2::retained_heap_bytes(
        code_capacity_bytes,
        label_capacity_bytes,
        relocation_capacity_bytes,
    )
    .ok_or(CountAotError::ArithmeticOverflow {
        site: CountAotArithmeticSite::Persistent,
    })?;
    let actual_persistent_bytes = retained_heap_bytes
        .checked_add(size_of::<AotCountImageV2>())
        .ok_or(CountAotError::ArithmeticOverflow {
            site: CountAotArithmeticSite::Persistent,
        })?;
    let actual_persistent_u64 =
        to_u64(actual_persistent_bytes, CountAotArithmeticSite::Persistent)?;
    if actual_persistent_u64 > prospective.persistent {
        return Err(CountAotError::InternalInvariant {
            at: "v2 persistent prospective",
        });
    }
    if actual_persistent_u64 > prospective.persistent_limit {
        return Err(CountAotError::ResourceLimit {
            resource: CountAotResource::PersistentBytes,
            limit: prospective.persistent_limit,
            required: actual_persistent_u64,
        });
    }
    let mut image = AotCountImageV2 {
        support,
        target,
        source_identity: program.cache_identity(),
        literal_manifest,
        layout,
        code,
        labels,
        relocations,
        stats: AotCountImageStatsV2 {
            code_bytes,
            data_bytes: 0,
            labels: 0,
            relocations: 0,
            emitted_instructions: code_bytes / 4,
            vector_instructions,
            candidate_filter_bytes: filter.map_or(0, CandidateFilterV2::len),
            confirmation_chunks: u8::try_from(literal.len() / 8).expect("bounded literal chunks"),
            confirmation_tail_bytes: u8::try_from(literal.len() % 8).expect("bounded literal tail"),
            emission_work,
            identity_bytes_hashed: 0,
            audit_work_upper_bound: prospective.audit_work,
            total_work_upper_bound: prospective.work,
            scratch_bytes_upper_bound: 0,
        },
        artifact_identity: AotCountArtifactIdentityV2::ZERO,
        build_receipt: AotCountImageBuildReceiptV2 {
            support,
            code_capacity_bytes,
            label_capacity_bytes,
            relocation_capacity_bytes,
            retained_heap_bytes,
            inline_bytes: size_of::<AotCountImageV2>(),
            emission_peak_scratch_bytes,
            work_upper_bound: prospective.work,
            scratch_bytes_upper_bound: 0,
            audit: CountAuditReportV2::default(),
        },
    };
    image.stats.labels = to_u32(image.labels.len(), CountAotArithmeticSite::ImageLayout)?;
    image.stats.relocations = to_u32(image.relocations.len(), CountAotArithmeticSite::ImageLayout)?;
    observe_emit_image_phase_scratch_v2(
        &image,
        prospective,
        EmitImagePhaseV2::InitialIdentityLength,
    )?;
    let identity_bytes_hashed = artifact_identity_encoded_len_v2(&image)?;
    if identity_bytes_hashed > prospective.identity_bytes_hashed {
        return Err(CountAotError::InternalInvariant {
            at: "v2 identity exceeded prospective bytes",
        });
    }
    image.stats.identity_bytes_hashed = identity_bytes_hashed;
    observe_emit_image_phase_scratch_v2(&image, prospective, EmitImagePhaseV2::CandidateAudit)?;
    let audit = audit_count_image_candidate_v2(program, &image, prospective)?;
    if audit.work_upper_bound != prospective.audit_work
        || audit.scratch_bytes_upper_bound != prospective.audit_scratch
    {
        return Err(CountAotError::InternalInvariant {
            at: "v2 audit prospective seal",
        });
    }
    if prospective.scratch > prospective.scratch_limit {
        return Err(CountAotError::ResourceLimit {
            resource: CountAotResource::ScratchBytes,
            limit: prospective.scratch_limit,
            required: prospective.scratch,
        });
    }
    image.stats.scratch_bytes_upper_bound = prospective.scratch;
    image.build_receipt.scratch_bytes_upper_bound = prospective.scratch;
    image.build_receipt.audit = audit;
    observe_emit_image_phase_scratch_v2(
        &image,
        prospective,
        EmitImagePhaseV2::SealedIdentityLength,
    )?;
    let sealed_identity_len = artifact_identity_encoded_len_v2(&image)?;
    if sealed_identity_len != identity_bytes_hashed {
        return Err(CountAotError::InternalInvariant {
            at: "v2 identity encoded length changed",
        });
    }
    observe_emit_image_phase_scratch_v2(&image, prospective, EmitImagePhaseV2::SealedIdentityHash)?;
    let (artifact_identity, observed_identity_bytes) = compute_artifact_identity_v2(&image)?;
    if observed_identity_bytes != identity_bytes_hashed {
        return Err(CountAotError::InternalInvariant {
            at: "v2 artifact identity byte count",
        });
    }
    image.artifact_identity = artifact_identity;
    observe_emit_image_phase_scratch_v2(&image, prospective, EmitImagePhaseV2::SealedAudit)?;
    let sealed_audit = audit_count_image_v2(program, &image)?;
    if sealed_audit != audit {
        return Err(CountAotError::InternalInvariant {
            at: "v2 sealed audit report changed",
        });
    }
    Ok(image)
}

fn preflight_program_dimensions_v2(
    program: &ExactAggregateProgram<Count>,
) -> Result<usize, CountAotError> {
    if program.output() != AggregateOutput::Count {
        return Err(CountAotError::Unsupported {
            reason: CountAotUnsupported::Output,
        });
    }
    let literal_len = program.literal().len();
    let support = SUPPORTED_AOT_COUNT_BACKEND_TUPLES_V2[0];
    if literal_len > MAX_EXACT_AGGREGATE_LITERAL_BYTES
        || literal_len > usize::from(support.max_literal_bytes)
    {
        return Err(CountAotError::Unsupported {
            reason: CountAotUnsupported::LiteralWidth,
        });
    }
    // `ExactAggregateProgram<Count>` itself is the structural witness. The
    // KIR crate keeps its representation and constructors private and only
    // admits the fixed exact-aggregate shape, so a generic statistics escape
    // hatch would weaken rather than strengthen this boundary.
    Ok(literal_len)
}

#[allow(
    clippy::items_after_statements,
    clippy::too_many_lines,
    reason = "named prospective-work constants stay next to the exact phase formula they justify"
)]
pub(crate) fn prospective_v2(literal_len: usize) -> Result<ProspectiveV2, CountAotError> {
    let (instruction_upper_bound, labels, relocations) = match literal_len {
        0 => (24_usize, 3_usize, 4_usize),
        1 => (64, 6, 12),
        _ => {
            let chunks = literal_len / 8;
            let tail = literal_len % 8;
            let confirmation_units = chunks
                .checked_add(tail)
                .ok_or(arithmetic_prospective_v2())?;
            (
                320_usize
                    .checked_add(
                        literal_len
                            .checked_mul(8)
                            .ok_or(arithmetic_prospective_v2())?,
                    )
                    .ok_or(arithmetic_prospective_v2())?,
                18,
                64_usize
                    .checked_add(
                        confirmation_units
                            .checked_mul(3)
                            .ok_or(arithmetic_prospective_v2())?,
                    )
                    .ok_or(arithmetic_prospective_v2())?,
            )
        }
    };
    let code_bytes = instruction_upper_bound
        .checked_mul(4)
        .ok_or(arithmetic_prospective_v2())?;
    let identity_bytes_hashed = identity_bytes_upper_bound_v2(code_bytes, labels, relocations)?;
    let audit_work = audit_work_upper_bound_v2(code_bytes, labels, relocations, literal_len)?;
    let audit_scratch = audit_scratch_upper_bound_v2(code_bytes, labels, relocations)?;
    let assembler_scratch = assembler_scratch_upper_bound_v2(code_bytes, labels, relocations)?;
    let image_backing = image_backing_bytes_for_capacities_v2(code_bytes, labels, relocations)?;
    let image_assembly_scratch =
        image_assembly_scratch_for_capacities_v2(code_bytes, labels, relocations)?;
    let emission_scratch = assembler_scratch.max(image_assembly_scratch);
    let candidate_audit_scratch =
        emit_audit_phase_scratch_v2(audit_scratch, image_backing, EmitAuditPhaseV2::Candidate)?;
    let sealed_audit_scratch =
        emit_audit_phase_scratch_v2(audit_scratch, image_backing, EmitAuditPhaseV2::Sealed)?;
    let initial_identity_scratch =
        emit_identity_phase_scratch_v2(image_backing, EmitIdentityPhaseV2::InitialLength)?;
    let sealed_identity_length_scratch =
        emit_identity_phase_scratch_v2(image_backing, EmitIdentityPhaseV2::SealedLength)?;
    let sealed_identity_hash_scratch =
        emit_identity_phase_scratch_v2(image_backing, EmitIdentityPhaseV2::SealedHash)?;
    let scratch = emission_scratch
        .max(candidate_audit_scratch)
        .max(sealed_audit_scratch)
        .max(initial_identity_scratch)
        .max(sealed_identity_length_scratch)
        .max(sealed_identity_hash_scratch);
    let persistent = image_backing
        .checked_add(to_u64(
            size_of::<AotCountImageV2>(),
            CountAotArithmeticSite::Prospective,
        )?)
        .ok_or(arithmetic_prospective_v2())?;
    // Literal preparation covers the complete ranked filter selection,
    // manifest validation/copy, and width-specific canonical
    // setup/confirmation traversals.
    let filter_selection_work = candidate_filter_work_envelope_v2(literal_len)?.total;
    const MANIFEST_AND_CANONICAL_WORK_PER_LITERAL_BYTE_V2: u64 = 1 + 8;
    const LITERAL_PREPARATION_FIXED_WORK_V2: u64 = 16 + 16 + 32;
    let literal = to_u64(literal_len, CountAotArithmeticSite::Prospective)?;
    let literal_preparation_work = literal
        .checked_mul(MANIFEST_AND_CANONICAL_WORK_PER_LITERAL_BYTE_V2)
        .and_then(|work| work.checked_add(filter_selection_work))
        .and_then(|work| work.checked_add(LITERAL_PREPARATION_FIXED_WORK_V2))
        .ok_or(arithmetic_prospective_v2())?;
    let label_emission_work = to_u64(labels, CountAotArithmeticSite::Prospective)?
        .checked_mul(2)
        .ok_or(arithmetic_prospective_v2())?;
    let relocation_emission_work = to_u64(relocations, CountAotArithmeticSite::Prospective)?
        .checked_mul(2)
        .ok_or(arithmetic_prospective_v2())?;
    let emission_upper = to_u64(instruction_upper_bound, CountAotArithmeticSite::Prospective)?
        .checked_add(label_emission_work)
        .and_then(|work| work.checked_add(relocation_emission_work))
        .and_then(|work| work.checked_add(literal_preparation_work))
        .ok_or(arithmetic_prospective_v2())?;
    let label_order = label_order_work_upper_bound_v2(labels)?;
    let labels_u64 = to_u64(labels, CountAotArithmeticSite::Prospective)?;
    let relocations_u64 = to_u64(relocations, CountAotArithmeticSite::Prospective)?;
    let identity_structural = identity_structural_traversal_work_v2(labels_u64, relocations_u64)
        .ok_or(arithmetic_prospective_v2())?;
    // Initial length, sealed length, and sealed hash each traverse every
    // encoder field. Only the hash pass consumes the encoded bytes.
    const DIRECT_IDENTITY_STRUCTURAL_PASSES_V2: u64 = 3;
    const DIRECT_IDENTITY_HASH_PASSES_V2: u64 = 1;
    const DIRECT_IDENTITY_HASH_FINALIZATION_WORK_V2: u64 = 8;
    const AUDIT_PASSES_V2: u64 = 2;
    const RESOURCE_ADMISSION_SCALAR_WORK_V2: u64 = 7 * 3;
    const IMAGE_FIELD_CONSTRUCTION_WORK_V2: u64 = 12 + 14 + 10;
    const MANIFEST_FILTER_AND_LAYOUT_SCALAR_WORK_V2: u64 = 5 + 5;
    const CAPACITY_AND_PERSISTENT_SEAL_WORK_V2: u64 = 18;
    const SCRATCH_PHASE_DERIVATION_AND_SEAL_WORK_V2: u64 = 6 * 8;
    const FINAL_RECEIPT_AND_AUDIT_SEAL_WORK_V2: u64 = 24;
    let named_scalar_work = RESOURCE_ADMISSION_SCALAR_WORK_V2
        .checked_add(IMAGE_FIELD_CONSTRUCTION_WORK_V2)
        .and_then(|work| work.checked_add(MANIFEST_FILTER_AND_LAYOUT_SCALAR_WORK_V2))
        .and_then(|work| work.checked_add(CAPACITY_AND_PERSISTENT_SEAL_WORK_V2))
        .and_then(|work| work.checked_add(SCRATCH_PHASE_DERIVATION_AND_SEAL_WORK_V2))
        .and_then(|work| work.checked_add(FINAL_RECEIPT_AND_AUDIT_SEAL_WORK_V2))
        .ok_or(arithmetic_prospective_v2())?;
    let work = emission_upper
        .checked_add(label_order.total)
        .and_then(|value| {
            value
                .checked_add(identity_structural.checked_mul(DIRECT_IDENTITY_STRUCTURAL_PASSES_V2)?)
        })
        .and_then(|value| {
            value.checked_add(identity_bytes_hashed.checked_mul(DIRECT_IDENTITY_HASH_PASSES_V2)?)
        })
        .and_then(|value| value.checked_add(DIRECT_IDENTITY_HASH_FINALIZATION_WORK_V2))
        .and_then(|value| value.checked_add(audit_work.checked_mul(AUDIT_PASSES_V2)?))
        .and_then(|value| value.checked_add(named_scalar_work))
        .ok_or(arithmetic_prospective_v2())?;
    Ok(ProspectiveV2 {
        code_bytes,
        labels,
        relocations,
        identity_bytes_hashed,
        audit_work,
        audit_scratch,
        assembler_scratch,
        emission_scratch,
        image_backing,
        image_assembly_scratch,
        candidate_audit_scratch,
        sealed_audit_scratch,
        initial_identity_scratch,
        sealed_identity_length_scratch,
        sealed_identity_hash_scratch,
        filter_selection_work,
        work,
        scratch,
        persistent,
        scratch_limit: MAX_SCRATCH_BYTES_V2,
        persistent_limit: MAX_PERSISTENT_BYTES_V2,
    })
}

type EmissionBuildInlineStateV2 = (
    &'static ExactAggregateProgram<Count>,
    CountEmitLimitsV2,
    usize,
    ProspectiveV2,
    &'static [u8],
    Option<CandidateFilterV2>,
    AotCountLiteralManifestV2,
    CountAotError,
);
type CanonicalTemplateCallerInlineStateV2 = (
    EmissionBuildInlineStateV2,
    Result<FinalizedV2, CountAotError>,
);
type CanonicalEmissionInlineStateV2 = (
    CanonicalTemplateCallerInlineStateV2,
    AssemblerV2,
    [LabelV2; 10],
    [usize; 8],
    [u8; 16],
    [u16; 4],
    [u32; 4],
    [u64; 4],
    CountAotError,
);
type FinalizeRelocationInlineStateV2 = (
    CanonicalTemplateCallerInlineStateV2,
    AssemblerV2,
    ExactVec<RelocationV2>,
    core::ops::Range<usize>,
    FixupV2,
    RelocationV2,
    [usize; 4],
    [u32; 4],
    CountAotError,
);
type FinalizeLabelCollectionInlineStateV2 = (
    CanonicalTemplateCallerInlineStateV2,
    AssemblerV2,
    ExactVec<RelocationV2>,
    ExactVec<CodeLabelV2>,
    LabelRecordV2,
    CodeLabelV2,
    [usize; 4],
    CountAotError,
);
type LabelOrderInlineStateV2 = (
    CanonicalTemplateCallerInlineStateV2,
    AssemblerV2,
    ExactVec<RelocationV2>,
    ExactVec<CodeLabelV2>,
    LabelOrderWorkV2,
    CodeLabelV2,
    [usize; 4],
    [u64; 4],
    CountAotError,
);
type FinalizeReturnInlineStateV2 = (
    CanonicalTemplateCallerInlineStateV2,
    AssemblerV2,
    ExactVec<RelocationV2>,
    ExactVec<CodeLabelV2>,
    FinalizedV2,
    [usize; 6],
    [u32; 4],
    CountAotError,
);
type ImageAssemblyInlineStateV2 = (
    EmissionBuildInlineStateV2,
    FinalizedV2,
    AotCountImageV2,
    AotCountImageLayoutV2,
    AotCountImageStatsV2,
    AotCountImageBuildReceiptV2,
    AotCountTargetSpec,
    [usize; 8],
    [u32; 8],
    [u64; 8],
    CountAotError,
);
type CandidateAuditCallerInlineStateV2 = (
    EmissionBuildInlineStateV2,
    AotCountImageV2,
    CountAuditReportV2,
    [usize; 4],
    [u64; 8],
    CountAotError,
);
type SealedAuditCallerInlineStateV2 = (
    EmissionBuildInlineStateV2,
    AotCountImageV2,
    CountAuditReportV2,
    CountAuditReportV2,
    AotCountArtifactIdentityV2,
    [usize; 4],
    [u64; 8],
    CountAotError,
);
type InitialIdentityCallerInlineStateV2 = (
    EmissionBuildInlineStateV2,
    AotCountImageV2,
    u64,
    CountAotError,
);
type SealedIdentityLengthCallerInlineStateV2 = (
    EmissionBuildInlineStateV2,
    AotCountImageV2,
    CountAuditReportV2,
    u64,
    CountAotError,
);
type SealedIdentityHashCallerInlineStateV2 = (
    EmissionBuildInlineStateV2,
    AotCountImageV2,
    CountAuditReportV2,
    AotCountArtifactIdentityV2,
    u64,
    CountAotError,
);

#[derive(Clone, Copy)]
enum EmissionPhaseV2 {
    Canonical,
    FinalizeRelocations,
    CollectLabels,
    OrderLabels,
    FinalizeReturn,
}

#[derive(Clone, Copy)]
enum EmitAuditPhaseV2 {
    Candidate,
    Sealed,
}

#[derive(Clone, Copy)]
enum EmitIdentityPhaseV2 {
    InitialLength,
    SealedLength,
    SealedHash,
}

#[derive(Clone, Copy)]
enum EmitImagePhaseV2 {
    InitialIdentityLength,
    CandidateAudit,
    SealedIdentityLength,
    SealedIdentityHash,
    SealedAudit,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EmitImagePhaseForTestV2 {
    InitialIdentityLength,
    CandidateAudit,
    SealedIdentityLength,
    SealedIdentityHash,
    SealedAudit,
}

fn image_backing_bytes_for_capacities_v2(
    code_capacity_bytes: usize,
    label_capacity: usize,
    relocation_capacity: usize,
) -> Result<u64, CountAotError> {
    let bytes = code_capacity_bytes
        .checked_add(
            label_capacity
                .checked_mul(size_of::<CodeLabelV2>())
                .ok_or(arithmetic_prospective_v2())?,
        )
        .and_then(|value| {
            value.checked_add(relocation_capacity.checked_mul(size_of::<RelocationV2>())?)
        })
        .ok_or(arithmetic_prospective_v2())?;
    to_u64(bytes, CountAotArithmeticSite::Prospective)
}

pub(crate) fn image_assembly_scratch_for_capacities_v2(
    code_capacity_bytes: usize,
    label_capacity: usize,
    relocation_capacity: usize,
) -> Result<u64, CountAotError> {
    image_backing_bytes_for_capacities_v2(code_capacity_bytes, label_capacity, relocation_capacity)?
        .checked_add(to_u64(
            size_of::<ImageAssemblyInlineStateV2>(),
            CountAotArithmeticSite::Prospective,
        )?)
        .ok_or(arithmetic_prospective_v2())
}

fn emit_audit_phase_scratch_v2(
    audit_scratch: u64,
    image_backing: u64,
    phase: EmitAuditPhaseV2,
) -> Result<u64, CountAotError> {
    let (caller_inline, wrapper_inline) = match phase {
        EmitAuditPhaseV2::Candidate => (
            size_of::<CandidateAuditCallerInlineStateV2>(),
            audit_candidate_wrapper_inline_bytes_v2(),
        ),
        EmitAuditPhaseV2::Sealed => (
            size_of::<SealedAuditCallerInlineStateV2>(),
            audit_public_wrapper_inline_bytes_v2(),
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
        .ok_or(arithmetic_prospective_v2())
}

fn emit_identity_phase_scratch_v2(
    image_backing: u64,
    phase: EmitIdentityPhaseV2,
) -> Result<u64, CountAotError> {
    let caller_inline = match phase {
        EmitIdentityPhaseV2::InitialLength => size_of::<InitialIdentityCallerInlineStateV2>(),
        EmitIdentityPhaseV2::SealedLength => size_of::<SealedIdentityLengthCallerInlineStateV2>(),
        EmitIdentityPhaseV2::SealedHash => size_of::<SealedIdentityHashCallerInlineStateV2>(),
    };
    image_backing
        .checked_add(to_u64(caller_inline, CountAotArithmeticSite::Prospective)?)
        .and_then(|bytes| {
            bytes.checked_add(
                to_u64(
                    identity_scratch_bytes_v2(),
                    CountAotArithmeticSite::Prospective,
                )
                .ok()?,
            )
        })
        .ok_or(arithmetic_prospective_v2())
}

pub(crate) fn assembler_scratch_upper_bound_v2(
    code_bytes: usize,
    labels: usize,
    relocations: usize,
) -> Result<u64, CountAotError> {
    assembler_scratch_for_capacities_v2(code_bytes, labels, relocations, labels, relocations)
}

pub(crate) fn assembler_scratch_for_capacities_v2(
    code_capacity_bytes: usize,
    label_record_capacity: usize,
    fixup_capacity: usize,
    output_label_capacity: usize,
    output_relocation_capacity: usize,
) -> Result<u64, CountAotError> {
    let phases = [
        observed_emission_phase_scratch_v2(
            code_capacity_bytes,
            label_record_capacity,
            fixup_capacity,
            0,
            0,
            EmissionPhaseV2::Canonical,
        )?,
        observed_emission_phase_scratch_v2(
            code_capacity_bytes,
            label_record_capacity,
            fixup_capacity,
            0,
            output_relocation_capacity,
            EmissionPhaseV2::FinalizeRelocations,
        )?,
        observed_emission_phase_scratch_v2(
            code_capacity_bytes,
            label_record_capacity,
            fixup_capacity,
            output_label_capacity,
            output_relocation_capacity,
            EmissionPhaseV2::CollectLabels,
        )?,
        observed_emission_phase_scratch_v2(
            code_capacity_bytes,
            label_record_capacity,
            fixup_capacity,
            output_label_capacity,
            output_relocation_capacity,
            EmissionPhaseV2::OrderLabels,
        )?,
        observed_emission_phase_scratch_v2(
            code_capacity_bytes,
            label_record_capacity,
            fixup_capacity,
            output_label_capacity,
            output_relocation_capacity,
            EmissionPhaseV2::FinalizeReturn,
        )?,
    ];
    phases
        .into_iter()
        .max()
        .ok_or(CountAotError::InternalInvariant {
            at: "v2 emission phase set",
        })
}

pub(crate) const fn assembler_scratch_derivation_work_upper_bound_v2() -> u64 {
    // Five phase derivations, each with four capacity multiplications, five
    // checked additions (including inline state), and one result conversion;
    // four comparisons select the maximum.
    (5 * (4 + 5 + 1)) + 4
}

fn observed_emission_phase_scratch_v2(
    code_capacity_bytes: usize,
    label_record_capacity: usize,
    fixup_capacity: usize,
    output_label_capacity: usize,
    output_relocation_capacity: usize,
    phase: EmissionPhaseV2,
) -> Result<u64, CountAotError> {
    let backing = code_capacity_bytes
        .checked_add(
            label_record_capacity
                .checked_mul(size_of::<LabelRecordV2>())
                .ok_or(arithmetic_prospective_v2())?,
        )
        .and_then(|bytes| bytes.checked_add(fixup_capacity.checked_mul(size_of::<FixupV2>())?))
        .and_then(|bytes| {
            bytes.checked_add(output_label_capacity.checked_mul(size_of::<CodeLabelV2>())?)
        })
        .and_then(|bytes| {
            bytes.checked_add(output_relocation_capacity.checked_mul(size_of::<RelocationV2>())?)
        })
        .ok_or(arithmetic_prospective_v2())?;
    let inline = match phase {
        EmissionPhaseV2::Canonical => size_of::<CanonicalEmissionInlineStateV2>(),
        EmissionPhaseV2::FinalizeRelocations => size_of::<FinalizeRelocationInlineStateV2>(),
        EmissionPhaseV2::CollectLabels => size_of::<FinalizeLabelCollectionInlineStateV2>(),
        EmissionPhaseV2::OrderLabels => size_of::<LabelOrderInlineStateV2>(),
        EmissionPhaseV2::FinalizeReturn => size_of::<FinalizeReturnInlineStateV2>(),
    };
    to_u64(
        backing
            .checked_add(inline)
            .ok_or(arithmetic_prospective_v2())?,
        CountAotArithmeticSite::Prospective,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LabelOrderWorkV2 {
    pub(crate) comparisons: u64,
    pub(crate) moves: u64,
    pub(crate) placements: u64,
    pub(crate) total: u64,
}

pub(crate) fn label_order_work_upper_bound_v2(
    labels: usize,
) -> Result<LabelOrderWorkV2, CountAotError> {
    let labels = to_u64(labels, CountAotArithmeticSite::Prospective)?;
    let prior = labels.saturating_sub(1);
    let pairs = labels
        .checked_mul(prior)
        .and_then(|value| value.checked_div(2))
        .ok_or(arithmetic_prospective_v2())?;
    let total = pairs
        .checked_add(pairs)
        .and_then(|value| value.checked_add(prior))
        .ok_or(arithmetic_prospective_v2())?;
    Ok(LabelOrderWorkV2 {
        comparisons: pairs,
        moves: pairs,
        placements: prior,
        total,
    })
}

pub(crate) fn identity_structural_traversal_work_v2(labels: u64, relocations: u64) -> Option<u64> {
    // Keep this synchronized with every fixed scalar/raw write in
    // `encode_artifact_identity_v2`, including the complete audit receipt.
    const FIXED_ENCODER_WRITES_V2: u64 = 65;
    const WRITES_PER_LABEL_V2: u64 = 2;
    const WRITES_PER_RELOCATION_V2: u64 = 4;
    FIXED_ENCODER_WRITES_V2
        .checked_add(labels.checked_mul(WRITES_PER_LABEL_V2)?)
        .and_then(|work| work.checked_add(relocations.checked_mul(WRITES_PER_RELOCATION_V2)?))
}

fn observe_emit_image_phase_scratch_v2(
    image: &AotCountImageV2,
    prospective: ProspectiveV2,
    phase: EmitImagePhaseV2,
) -> Result<u64, CountAotError> {
    // Capacity is allocator-owned state. Re-read it immediately before every
    // identity or audit phase rather than trusting the identity-bound receipt.
    let image_backing = image_backing_bytes_for_capacities_v2(
        image.code.capacity(),
        image.labels.capacity(),
        image.relocations.capacity(),
    )?;
    if image_backing > prospective.image_backing {
        return Err(CountAotError::InternalInvariant {
            at: "v2 image backing prospective",
        });
    }
    let (observed, expected) = match phase {
        EmitImagePhaseV2::InitialIdentityLength => (
            emit_identity_phase_scratch_v2(image_backing, EmitIdentityPhaseV2::InitialLength)?,
            prospective.initial_identity_scratch,
        ),
        EmitImagePhaseV2::CandidateAudit => (
            emit_audit_phase_scratch_v2(
                prospective.audit_scratch,
                image_backing,
                EmitAuditPhaseV2::Candidate,
            )?,
            prospective.candidate_audit_scratch,
        ),
        EmitImagePhaseV2::SealedIdentityLength => (
            emit_identity_phase_scratch_v2(image_backing, EmitIdentityPhaseV2::SealedLength)?,
            prospective.sealed_identity_length_scratch,
        ),
        EmitImagePhaseV2::SealedIdentityHash => (
            emit_identity_phase_scratch_v2(image_backing, EmitIdentityPhaseV2::SealedHash)?,
            prospective.sealed_identity_hash_scratch,
        ),
        EmitImagePhaseV2::SealedAudit => (
            emit_audit_phase_scratch_v2(
                prospective.audit_scratch,
                image_backing,
                EmitAuditPhaseV2::Sealed,
            )?,
            prospective.sealed_audit_scratch,
        ),
    };
    if observed > expected {
        return Err(CountAotError::InternalInvariant {
            at: "v2 image phase scratch prospective",
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

#[cfg(test)]
pub(crate) fn observe_emit_image_phase_scratch_for_test_v2(
    program: &ExactAggregateProgram<Count>,
    image: &AotCountImageV2,
    phase: EmitImagePhaseForTestV2,
    scratch_limit: u64,
) -> Result<u64, CountAotError> {
    let mut prospective = prospective_v2(preflight_program_dimensions_v2(program)?)?;
    prospective.scratch_limit = prospective.scratch_limit.min(scratch_limit);
    let phase = match phase {
        EmitImagePhaseForTestV2::InitialIdentityLength => EmitImagePhaseV2::InitialIdentityLength,
        EmitImagePhaseForTestV2::CandidateAudit => EmitImagePhaseV2::CandidateAudit,
        EmitImagePhaseForTestV2::SealedIdentityLength => EmitImagePhaseV2::SealedIdentityLength,
        EmitImagePhaseForTestV2::SealedIdentityHash => EmitImagePhaseV2::SealedIdentityHash,
        EmitImagePhaseForTestV2::SealedAudit => EmitImagePhaseV2::SealedAudit,
    };
    observe_emit_image_phase_scratch_v2(image, prospective, phase)
}

pub(crate) fn canonical_template_v2(
    literal: &[u8],
    filter: Option<CandidateFilterV2>,
    prospective: ProspectiveV2,
) -> Result<FinalizedV2, CountAotError> {
    let mut assembler = AssemblerV2::new(prospective)?;
    let entry = assembler.new_label(LabelKindV2::Entry)?;
    let done = assembler.new_label(LabelKindV2::Success)?;
    assembler.bind(entry)?;
    match literal.len() {
        0 => emit_empty_v2(&mut assembler, done)?,
        1 => emit_single_v2(&mut assembler, literal[0], done)?,
        _ => emit_multi_v2(
            &mut assembler,
            literal,
            filter.ok_or(CountAotError::InternalInvariant {
                at: "missing v2 candidate filter",
            })?,
            done,
        )?,
    }
    assembler.bind(done)?;
    assembler.store64(X13, X2, 0)?;
    assembler.mov_imm64_minimal(X0, 0)?;
    assembler.ret()?;
    assembler.finalize()
}

fn emit_empty_v2(assembler: &mut AssemblerV2, done: LabelV2) -> Result<(), CountAotError> {
    let overflow = assembler.new_label(LabelKindV2::Overflow)?;
    assembler.mov_imm64_minimal(X10, u64::MAX)?;
    assembler.cmp_reg64(X1, X10)?;
    assembler.branch_cond(ConditionV2::Equal, overflow)?;
    assembler.add_imm(X13, X1, 1)?;
    assembler.branch(done)?;
    assembler.bind(overflow)?;
    assembler.mov_imm64_minimal(X0, 1)?;
    assembler.ret()
}

fn emit_single_v2(
    assembler: &mut AssemblerV2,
    literal: u8,
    done: LabelV2,
) -> Result<(), CountAotError> {
    let vector = assembler.new_label(LabelKindV2::VectorLoop)?;
    let tail = assembler.new_label(LabelKindV2::ScalarTail)?;
    let tail_miss = assembler.new_label(LabelKindV2::Miss)?;
    assembler.mov_imm64_minimal(X13, 0)?;
    assembler.mov_imm64_minimal(X3, 0)?;
    assembler.mov_imm64_minimal(X10, u64::from(literal))?;
    assembler.dup_byte16(1, X10)?;
    // Hoisted: v1 rematerialized 256 in every vector iteration.
    assembler.mov_imm64_minimal(X5, 256)?;
    assembler.bind(vector)?;
    assembler.sub_reg(X6, X1, X3)?;
    assembler.cmp_imm64(X6, SIMD_CANDIDATE_STARTS_V2)?;
    assembler.branch_cond(ConditionV2::CarryClear, tail)?;
    assembler.add_reg(X15, X0, X3)?;
    assembler.load_vector128(0, X15)?;
    assembler.compare_equal_bytes16(0, 0, 1)?;
    assembler.add_across_bytes16(0, 0)?;
    assembler.move_vector_byte_to32(X6, 0)?;
    assembler.sub_reg(X6, X5, X6)?;
    assembler.and_low_bits(X6, X6, 8)?;
    assembler.add_reg(X13, X13, X6)?;
    assembler.add_imm(X3, X3, SIMD_CANDIDATE_STARTS_V2)?;
    assembler.branch(vector)?;
    assembler.bind(tail)?;
    assembler.cmp_reg64(X3, X1)?;
    assembler.branch_cond(ConditionV2::CarrySet, done)?;
    assembler.load_byte_reg(X6, X0, X3)?;
    assembler.cmp_reg32(X6, X10)?;
    assembler.branch_cond(ConditionV2::NotEqual, tail_miss)?;
    assembler.add_imm(X13, X13, 1)?;
    assembler.bind(tail_miss)?;
    assembler.add_imm(X3, X3, 1)?;
    assembler.branch(tail)
}

#[allow(
    clippy::too_many_lines,
    reason = "the complete 16-start mask and successor graph is intentionally explicit"
)]
fn emit_multi_v2(
    assembler: &mut AssemblerV2,
    literal: &[u8],
    filter: CandidateFilterV2,
    done: LabelV2,
) -> Result<(), CountAotError> {
    let vector = assembler.new_label(LabelKindV2::VectorLoop)?;
    let sparse_scan = assembler.new_label(LabelKindV2::VectorLoop)?;
    let sparse_hit = assembler.new_label(LabelKindV2::Internal)?;
    let sparse_first_half = assembler.new_label(LabelKindV2::Internal)?;
    let pair_absent = assembler.new_label(LabelKindV2::Internal)?;
    let pair_single = assembler.new_label(LabelKindV2::Internal)?;
    let pair_dense = assembler.new_label(LabelKindV2::Internal)?;
    let candidate = assembler.new_label(LabelKindV2::CandidateLoop)?;
    let candidate_miss = assembler.new_label(LabelKindV2::Miss)?;
    let block_advance = assembler.new_label(LabelKindV2::Internal)?;
    let dense_scan = assembler.new_label(LabelKindV2::VectorLoop)?;
    let dense_absent = assembler.new_label(LabelKindV2::Internal)?;
    let match_run = assembler.new_label(LabelKindV2::CandidateLoop)?;
    let match_run_miss = assembler.new_label(LabelKindV2::Miss)?;
    let scalar = assembler.new_label(LabelKindV2::ScalarTail)?;
    let scalar_miss = assembler.new_label(LabelKindV2::Miss)?;
    let width = u16::try_from(literal.len()).map_err(|_| CountAotError::ArithmeticOverflow {
        site: CountAotArithmeticSite::CodeOffset,
    })?;
    let primary = u16::from(filter.offsets[0]);
    let secondary = u16::from(filter.offsets[1]);
    assembler.mov_imm64_minimal(X13, 0)?;
    assembler.cmp_imm64(X1, width)?;
    assembler.branch_cond(ConditionV2::CarryClear, done)?;
    assembler.sub_imm(X4, X1, width)?;
    assembler.mov_imm64_minimal(X3, 0)?;
    assembler.mov_imm64_minimal(X10, u64::from(literal[usize::from(filter.offsets[0])]))?;
    assembler.mov_imm64_minimal(X11, u64::from(literal[usize::from(filter.offsets[1])]))?;
    assembler.dup_byte16(2, X10)?;
    assembler.dup_byte16(3, X11)?;
    if filter.len >= 3 {
        assembler.mov_imm64_minimal(X12, u64::from(literal[usize::from(filter.offsets[2])]))?;
        assembler.dup_byte16(16, X12)?;
    }
    if filter.len >= 4 {
        assembler.mov_imm64_minimal(X14, u64::from(literal[usize::from(filter.offsets[3])]))?;
        assembler.dup_byte16(17, X14)?;
    }
    assembler.mov_imm64_minimal(X17, SPARSE_NIBBLE_BITS_V2)?;
    assembler.mov_imm64_minimal(X8, u64::from(literal[0]))?;
    assembler.dup_byte16(19, X8)?;
    assembler.mov_imm64_minimal(
        X8,
        u64::from(literal[literal.len().checked_sub(1).expect("nonempty literal")]),
    )?;
    assembler.dup_byte16(20, X8)?;

    // Full 16-byte constants are assembled once in v21/v22. The optional
    // remaining 8-byte chunk keeps its global v4..v7 slot so the mapping is
    // mechanically tied to the literal offset.
    for (chunk_index, chunk) in literal.chunks_exact(16).enumerate() {
        let mut low = [0_u8; 8];
        let mut high = [0_u8; 8];
        low.copy_from_slice(&chunk[..8]);
        high.copy_from_slice(&chunk[8..]);
        let vector = u8::try_from(21_usize + chunk_index).expect("at most v22");
        assembler.mov_imm64_minimal(X8, u64::from_le_bytes(low))?;
        assembler.move_x_to_vector_double(vector, X8)?;
        assembler.mov_imm64_minimal(X8, u64::from_le_bytes(high))?;
        assembler.insert_x_to_vector_double_lane1(vector, X8)?;
    }
    let full_vector_bytes = literal.len() / 16 * 16;
    for (tail_index, chunk) in literal[full_vector_bytes..].chunks_exact(8).enumerate() {
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(chunk);
        assembler.mov_imm64_minimal(X8, u64::from_le_bytes(bytes))?;
        let global_chunk = full_vector_bytes / 8 + tail_index;
        assembler.move_x_to_vector_double(
            u8::try_from(4_usize + global_chunk).expect("at most v7"),
            X8,
        )?;
    }

    assembler.bind(vector)?;
    assembler.cmp_reg64(X3, X4)?;
    assembler.branch_cond(ConditionV2::Higher, done)?;
    assembler.sub_reg(X5, X4, X3)?;
    assembler.cmp_imm64(X5, 15)?;
    assembler.branch_cond(ConditionV2::CarryClear, scalar)?;
    assembler.add_reg(X15, X0, X3)?;
    assembler.add_imm(X8, X15, primary)?;
    assembler.load_vector128(0, X8)?;
    assembler.add_imm(X9, X15, secondary)?;
    assembler.load_vector128(1, X9)?;
    assembler.compare_equal_bytes16(0, 0, 2)?;
    assembler.compare_equal_bytes16(1, 1, 3)?;
    assembler.and_bytes16(0, 0, 1)?;
    // ADDV is a bounded content-derived density probe. Equality lanes are
    // either 0x00 or 0xff: zero means absent, 0xff means exactly one lane, and
    // every other value means at least two lanes (there are at most sixteen).
    assembler.add_across_bytes16(1, 0)?;
    assembler.move_vector_byte_to32(X8, 1)?;
    assembler.cmp_imm64(X8, 0)?;
    assembler.branch_cond(ConditionV2::Equal, pair_absent)?;
    assembler.cmp_imm64(X8, 255)?;
    assembler.branch_cond(ConditionV2::NotEqual, pair_dense)?;

    assembler.bind(pair_single)?;
    if filter.len >= 3 {
        // The third column is paid only by a one-lane rare-pair block.
        assembler.add_imm(X8, X15, u16::from(filter.offsets[2]))?;
        assembler.load_vector128(1, X8)?;
        assembler.compare_equal_bytes16(1, 1, 16)?;
        assembler.and_bytes16(0, 0, 1)?;
    }
    if filter.len >= 4 {
        // Likewise, a fourth distinct byte is loaded only after a triple hit.
        assembler.unsigned_max_across_bytes16(1, 0)?;
        assembler.move_vector_byte_to32(X8, 1)?;
        assembler.cmp_imm64(X8, 0)?;
        assembler.branch_cond(ConditionV2::Equal, block_advance)?;
        assembler.add_imm(X8, X15, u16::from(filter.offsets[3]))?;
        assembler.load_vector128(1, X8)?;
        assembler.compare_equal_bytes16(1, 1, 17)?;
        assembler.and_bytes16(0, 0, 1)?;
    }
    // Each adjacent pair of FF/00 equality lanes becomes two F/0 nibbles.
    assembler.shrink_narrow_bytes_from_halfwords(0, 0, 4)?;
    assembler.move_vector_double_to64(X6, 0)?;
    assembler.and_reg(X6, X6, X17)?;
    assembler.cmp_imm64(X6, 0)?;
    assembler.branch_cond(ConditionV2::Equal, block_advance)?;
    assembler.branch(candidate)?;

    // Pair-dense rare filters are vulnerable to content that happens to
    // repeat those internal columns. Re-filter the same sixteen valid starts
    // by the semantic first and last bytes before recovering candidates.
    assembler.bind(pair_dense)?;
    assembler.or_bytes16(18, 0, 0)?;
    assembler.load_vector128(0, X15)?;
    assembler.compare_equal_bytes16(0, 0, 19)?;
    assembler.add_imm(
        X8,
        X15,
        u16::try_from(literal.len() - 1).expect("bounded last offset"),
    )?;
    assembler.load_vector128(1, X8)?;
    assembler.compare_equal_bytes16(1, 1, 20)?;
    assembler.and_bytes16(0, 0, 1)?;
    assembler.and_bytes16(0, 0, 18)?;
    assembler.shrink_narrow_bytes_from_halfwords(0, 0, 4)?;
    assembler.move_vector_double_to64(X6, 0)?;
    assembler.and_reg(X6, X6, X17)?;
    assembler.cmp_imm64(X6, 0)?;
    assembler.branch_cond(ConditionV2::Equal, dense_absent)?;
    assembler.branch(candidate)?;

    assembler.bind(candidate)?;
    assembler.reverse_bits(X7, X6)?;
    assembler.count_leading_zeros(X7, X7)?;
    assembler.sub_imm(X16, X6, 1)?;
    assembler.and_reg(X6, X6, X16)?;
    assembler.lsr_imm(X7, X7, 2)?;
    assembler.add_reg(X5, X3, X7)?;
    assembler.add_reg(X15, X0, X5)?;
    emit_confirmation_v2(assembler, literal, X15, candidate_miss)?;
    assembler.add_imm(X13, X13, 1)?;
    // Discard the old mask and enter a full-confirmation successor run.
    assembler.add_imm(X3, X5, width)?;
    assembler.branch(match_run)?;

    assembler.bind(candidate_miss)?;
    assembler.cmp_imm64(X6, 0)?;
    assembler.branch_cond(ConditionV2::NotEqual, candidate)?;
    assembler.bind(block_advance)?;
    assembler.add_imm(X3, X3, SIMD_CANDIDATE_STARTS_V2)?;
    assembler.branch(vector)?;

    // Match-heavy input avoids rebuilding filter masks at every exact
    // semantic successor. The first failed successor is consumed once before
    // returning to adaptive SIMD filtering.
    assembler.bind(match_run)?;
    assembler.cmp_reg64(X3, X4)?;
    assembler.branch_cond(ConditionV2::Higher, done)?;
    assembler.add_reg(X15, X0, X3)?;
    emit_confirmation_v2(assembler, literal, X15, match_run_miss)?;
    assembler.add_imm(X13, X13, 1)?;
    assembler.add_imm(X3, X3, width)?;
    assembler.branch(match_run)?;
    assembler.bind(match_run_miss)?;
    assembler.add_imm(X3, X3, 1)?;
    assembler.branch(vector)?;

    // Once a pair-dense block has no semantic first/last candidate, four
    // consecutive first/last blocks share one reduction. Any possible match
    // returns at the unchanged start to the complete adaptive filter; a
    // sustained adversarial rare pair therefore pays its discovery only once.
    assembler.bind(dense_absent)?;
    assembler.add_imm(X3, X3, SIMD_CANDIDATE_STARTS_V2)?;
    assembler.branch(dense_scan)?;
    assembler.bind(dense_scan)?;
    assembler.cmp_reg64(X3, X4)?;
    assembler.branch_cond(ConditionV2::Higher, done)?;
    assembler.sub_reg(X5, X4, X3)?;
    assembler.cmp_imm64(X5, SPARSE_SCAN_STARTS_V2 - 1)?;
    assembler.branch_cond(ConditionV2::CarryClear, vector)?;
    assembler.add_reg(X15, X0, X3)?;
    assembler.add_imm(
        X9,
        X15,
        u16::try_from(literal.len() - 1).expect("bounded last offset"),
    )?;
    for block in 0..SPARSE_SCAN_BLOCKS_V2 {
        let offset = block.checked_mul(SIMD_CANDIDATE_STARTS_V2).ok_or(
            CountAotError::ArithmeticOverflow {
                site: CountAotArithmeticSite::CodeOffset,
            },
        )?;
        assembler.load_vector128_offset(0, X15, offset)?;
        assembler.load_vector128_offset(1, X9, offset)?;
        assembler.compare_equal_bytes16(0, 0, 19)?;
        assembler.compare_equal_bytes16(1, 1, 20)?;
        if block == 0 {
            assembler.and_bytes16(18, 0, 1)?;
        } else {
            assembler.and_bytes16(0, 0, 1)?;
            assembler.or_bytes16(18, 18, 0)?;
        }
    }
    assembler.unsigned_max_across_bytes16(1, 18)?;
    assembler.move_vector_byte_to32(X8, 1)?;
    assembler.cmp_imm64(X8, 0)?;
    assembler.branch_cond(ConditionV2::NotEqual, vector)?;
    assembler.add_imm(X3, X3, SPARSE_SCAN_STARTS_V2)?;
    assembler.branch(dense_scan)?;

    // A block with no rare-byte pair enters a separate sparse-run loop. Four
    // consecutive 16-start masks share one horizontal reduction; a hit group
    // returns to the ordinary block path at its earliest hit-bearing block.
    // Dense and match-heavy blocks never enter this loop, so their existing
    // candidate and successor path remains unchanged.
    assembler.bind(pair_absent)?;
    assembler.add_imm(X3, X3, SIMD_CANDIDATE_STARTS_V2)?;
    assembler.branch(sparse_scan)?;
    assembler.bind(sparse_scan)?;
    assembler.cmp_reg64(X3, X4)?;
    assembler.branch_cond(ConditionV2::Higher, done)?;
    assembler.sub_reg(X5, X4, X3)?;
    assembler.cmp_imm64(X5, SPARSE_SCAN_STARTS_V2 - 1)?;
    assembler.branch_cond(ConditionV2::CarryClear, vector)?;
    assembler.add_reg(X15, X0, X3)?;
    assembler.add_imm(X8, X15, primary)?;
    assembler.add_imm(X9, X15, secondary)?;
    for block in 0..SPARSE_SCAN_BLOCKS_V2 {
        let offset = block.checked_mul(SIMD_CANDIDATE_STARTS_V2).ok_or(
            CountAotError::ArithmeticOverflow {
                site: CountAotArithmeticSite::CodeOffset,
            },
        )?;
        assembler.load_vector128_offset(0, X8, offset)?;
        assembler.load_vector128_offset(1, X9, offset)?;
        assembler.compare_equal_bytes16(0, 0, 2)?;
        assembler.compare_equal_bytes16(1, 1, 3)?;
        assembler.and_bytes16(
            u8::try_from(u16::from(SPARSE_BLOCK_MASK_BASE_V2) + block)
                .expect("four caller-saved sparse block masks"),
            0,
            1,
        )?;
    }
    assembler.or_bytes16(
        SPARSE_FIRST_HALF_MASK_V2,
        SPARSE_BLOCK_MASK_BASE_V2,
        SPARSE_BLOCK_MASK_BASE_V2 + 1,
    )?;
    assembler.or_bytes16(
        SPARSE_SECOND_HALF_MASK_V2,
        SPARSE_BLOCK_MASK_BASE_V2 + 2,
        SPARSE_BLOCK_MASK_BASE_V2 + 3,
    )?;
    assembler.or_bytes16(18, SPARSE_FIRST_HALF_MASK_V2, SPARSE_SECOND_HALF_MASK_V2)?;
    assembler.unsigned_max_across_bytes16(1, 18)?;
    assembler.move_vector_byte_to32(X8, 1)?;
    assembler.cmp_imm64(X8, 0)?;
    assembler.branch_cond(ConditionV2::NotEqual, sparse_hit)?;
    assembler.add_imm(X3, X3, SPARSE_SCAN_STARTS_V2)?;
    assembler.branch(sparse_scan)?;

    // Preserve each 16-start mask while building the same four-block OR.
    // Classification is paid only by a hit-bearing 64-start group, and moves
    // directly to its earliest hit-bearing block. This avoids repeatedly
    // rescanning overlapping 64-start windows when rare-pair false positives
    // are sparse.
    assembler.bind(sparse_hit)?;
    assembler.unsigned_max_across_bytes16(1, SPARSE_FIRST_HALF_MASK_V2)?;
    assembler.move_vector_byte_to32(X8, 1)?;
    assembler.cmp_imm64(X8, 0)?;
    assembler.branch_cond(ConditionV2::NotEqual, sparse_first_half)?;
    assembler.add_imm(X3, X3, SIMD_CANDIDATE_STARTS_V2 * 2)?;
    assembler.unsigned_max_across_bytes16(1, SPARSE_BLOCK_MASK_BASE_V2 + 2)?;
    assembler.move_vector_byte_to32(X8, 1)?;
    assembler.cmp_imm64(X8, 0)?;
    assembler.branch_cond(ConditionV2::NotEqual, vector)?;
    assembler.add_imm(X3, X3, SIMD_CANDIDATE_STARTS_V2)?;
    assembler.branch(vector)?;
    assembler.bind(sparse_first_half)?;
    assembler.unsigned_max_across_bytes16(1, SPARSE_BLOCK_MASK_BASE_V2)?;
    assembler.move_vector_byte_to32(X8, 1)?;
    assembler.cmp_imm64(X8, 0)?;
    assembler.branch_cond(ConditionV2::NotEqual, vector)?;
    assembler.add_imm(X3, X3, SIMD_CANDIDATE_STARTS_V2)?;
    assembler.branch(vector)?;

    assembler.bind(scalar)?;
    assembler.cmp_reg64(X3, X4)?;
    assembler.branch_cond(ConditionV2::Higher, done)?;
    assembler.add_reg(X15, X0, X3)?;
    assembler.load_byte(X8, X15, primary)?;
    assembler.cmp_reg32(X8, X10)?;
    assembler.branch_cond(ConditionV2::NotEqual, scalar_miss)?;
    assembler.load_byte(X8, X15, secondary)?;
    assembler.cmp_reg32(X8, X11)?;
    assembler.branch_cond(ConditionV2::NotEqual, scalar_miss)?;
    if filter.len >= 3 {
        assembler.load_byte(X8, X15, u16::from(filter.offsets[2]))?;
        assembler.cmp_reg32(X8, X12)?;
        assembler.branch_cond(ConditionV2::NotEqual, scalar_miss)?;
    }
    if filter.len >= 4 {
        assembler.load_byte(X8, X15, u16::from(filter.offsets[3]))?;
        assembler.cmp_reg32(X8, X14)?;
        assembler.branch_cond(ConditionV2::NotEqual, scalar_miss)?;
    }
    emit_confirmation_v2(assembler, literal, X15, scalar_miss)?;
    assembler.add_imm(X13, X13, 1)?;
    assembler.add_imm(X3, X3, width)?;
    assembler.branch(match_run)?;
    assembler.bind(scalar_miss)?;
    assembler.add_imm(X3, X3, 1)?;
    assembler.branch(scalar)
}

fn emit_confirmation_v2(
    assembler: &mut AssemblerV2,
    literal: &[u8],
    candidate_pointer: u8,
    mismatch: LabelV2,
) -> Result<(), CountAotError> {
    let vector_chunks = literal.len() / 16;
    for chunk_index in 0..vector_chunks {
        let offset = u16::try_from(chunk_index * 16).expect("bounded chunk offset");
        assembler.load_vector128_offset(0, candidate_pointer, offset)?;
        assembler.compare_equal_bytes16(
            0,
            0,
            u8::try_from(21_usize + chunk_index).expect("at most v22"),
        )?;
        assembler.unsigned_min_across_bytes16(0, 0)?;
        assembler.move_vector_byte_to32(X8, 0)?;
        assembler.cmp_imm32(X8, 255)?;
        assembler.branch_cond(ConditionV2::NotEqual, mismatch)?;
    }
    let vector_tail_offset = vector_chunks * 16;
    let double_chunks = (literal.len() - vector_tail_offset) / 8;
    for chunk_index in 0..double_chunks {
        let global_chunk = vector_tail_offset / 8 + chunk_index;
        let offset =
            u16::try_from(vector_tail_offset + chunk_index * 8).expect("bounded chunk offset");
        assembler.load_vector_double(0, candidate_pointer, offset)?;
        assembler.compare_equal_bytes8(
            0,
            0,
            u8::try_from(4_usize + global_chunk).expect("at most v7"),
        )?;
        assembler.unsigned_min_across_bytes8(0, 0)?;
        assembler.move_vector_byte_to32(X8, 0)?;
        assembler.cmp_imm32(X8, 255)?;
        assembler.branch_cond(ConditionV2::NotEqual, mismatch)?;
    }
    let tail_offset = vector_tail_offset + double_chunks * 8;
    for (index, byte) in literal[tail_offset..].iter().copied().enumerate() {
        let offset = u16::try_from(tail_offset + index).expect("bounded byte offset");
        assembler.load_byte(X8, candidate_pointer, offset)?;
        assembler.mov_imm64_minimal(X9, u64::from(byte))?;
        assembler.cmp_reg32(X8, X9)?;
        assembler.branch_cond(ConditionV2::NotEqual, mismatch)?;
    }
    Ok(())
}

/// Pinned memchr-2.8.3 default frequency ranks. Lower values are rarer.
const EMITTER_FREQUENCY_RANK_V2: [u8; 256] = [
    55, 52, 51, 50, 49, 48, 47, 46, 45, 103, 242, 66, 67, 229, 44, 43, 42, 41, 40, 39, 38, 37, 36,
    35, 34, 33, 56, 32, 31, 30, 29, 28, 255, 148, 164, 149, 136, 160, 155, 173, 221, 222, 134, 122,
    232, 202, 215, 224, 208, 220, 204, 187, 183, 179, 177, 168, 178, 200, 226, 195, 154, 184, 174,
    126, 120, 191, 157, 194, 170, 189, 162, 161, 150, 193, 142, 137, 171, 176, 185, 167, 186, 112,
    175, 192, 188, 156, 140, 143, 123, 133, 128, 147, 138, 146, 114, 223, 151, 249, 216, 238, 236,
    253, 227, 218, 230, 247, 135, 180, 241, 233, 246, 244, 231, 139, 245, 243, 251, 235, 201, 196,
    240, 214, 152, 182, 205, 181, 127, 27, 212, 211, 210, 213, 228, 197, 169, 159, 131, 172, 105,
    80, 98, 96, 97, 81, 207, 145, 116, 115, 144, 130, 153, 121, 107, 132, 109, 110, 124, 111, 82,
    108, 118, 141, 113, 129, 119, 125, 165, 117, 92, 106, 83, 72, 99, 93, 65, 79, 166, 237, 163,
    199, 190, 225, 209, 203, 198, 217, 219, 206, 234, 248, 158, 239, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CandidateFilterV2 {
    offsets: [u8; 4],
    len: u8,
}

impl CandidateFilterV2 {
    pub(crate) fn offsets(&self) -> &[u8] {
        &self.offsets[..usize::from(self.len)]
    }

    pub(crate) const fn len(self) -> u8 {
        self.len
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct CandidateFilterObservedWorkV2 {
    pub(crate) initial_byte_visits: u64,
    pub(crate) two_offset_byte_visits: u64,
    pub(crate) two_offset_contains_probes: u64,
    pub(crate) two_offset_value_probes: u64,
    pub(crate) three_offset_byte_visits: u64,
    pub(crate) three_offset_contains_probes: u64,
    pub(crate) three_offset_value_probes: u64,
}

impl CandidateFilterObservedWorkV2 {
    fn tick_initial_byte(&mut self) -> Result<(), CountAotError> {
        checked_filter_tick_v2(&mut self.initial_byte_visits)
    }

    fn tick_byte(&mut self, selected: usize) -> Result<(), CountAotError> {
        match selected {
            2 => checked_filter_tick_v2(&mut self.two_offset_byte_visits),
            3 => checked_filter_tick_v2(&mut self.three_offset_byte_visits),
            _ => Err(CountAotError::InternalInvariant {
                at: "v2 candidate-filter selected width",
            }),
        }
    }

    fn tick_contains_probe(&mut self, selected: usize) -> Result<(), CountAotError> {
        match selected {
            2 => checked_filter_tick_v2(&mut self.two_offset_contains_probes),
            3 => checked_filter_tick_v2(&mut self.three_offset_contains_probes),
            _ => Err(CountAotError::InternalInvariant {
                at: "v2 candidate-filter contains width",
            }),
        }
    }

    fn tick_value_probe(&mut self, selected: usize) -> Result<(), CountAotError> {
        match selected {
            2 => checked_filter_tick_v2(&mut self.two_offset_value_probes),
            3 => checked_filter_tick_v2(&mut self.three_offset_value_probes),
            _ => Err(CountAotError::InternalInvariant {
                at: "v2 candidate-filter value width",
            }),
        }
    }

    pub(crate) fn total(self) -> Result<u64, CountAotError> {
        self.initial_byte_visits
            .checked_add(self.two_offset_byte_visits)
            .and_then(|work| work.checked_add(self.two_offset_contains_probes))
            .and_then(|work| work.checked_add(self.two_offset_value_probes))
            .and_then(|work| work.checked_add(self.three_offset_byte_visits))
            .and_then(|work| work.checked_add(self.three_offset_contains_probes))
            .and_then(|work| work.checked_add(self.three_offset_value_probes))
            .ok_or(arithmetic_prospective_v2())
    }
}

fn checked_filter_tick_v2(counter: &mut u64) -> Result<(), CountAotError> {
    *counter = counter.checked_add(1).ok_or(arithmetic_prospective_v2())?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CandidateFilterSelectionV2 {
    filter: Option<CandidateFilterV2>,
    observed: CandidateFilterObservedWorkV2,
}

#[allow(
    clippy::similar_names,
    reason = "rare1/rare2 and index1/index2 preserve the pinned pair policy vocabulary"
)]
fn select_candidate_filter_v2(literal: &[u8]) -> Result<CandidateFilterSelectionV2, CountAotError> {
    let mut observed = CandidateFilterObservedWorkV2::default();
    if literal.len() < 2 {
        return Ok(CandidateFilterSelectionV2 {
            filter: None,
            observed,
        });
    }
    observed.tick_initial_byte()?;
    let (mut rare1, mut index1) = (literal[0], 0_u8);
    observed.tick_initial_byte()?;
    let (mut rare2, mut index2) = (literal[1], 1_u8);
    if emitter_rank_v2(rare2) < emitter_rank_v2(rare1) {
        core::mem::swap(&mut rare1, &mut rare2);
        core::mem::swap(&mut index1, &mut index2);
    }
    for (index, byte) in literal.iter().copied().enumerate().skip(2) {
        observed.tick_initial_byte()?;
        let index = u8::try_from(index).expect("literal width is at most 32");
        if emitter_rank_v2(byte) < emitter_rank_v2(rare1) {
            rare2 = rare1;
            index2 = index1;
            rare1 = byte;
            index1 = index;
        } else if byte != rare1 && emitter_rank_v2(byte) < emitter_rank_v2(rare2) {
            rare2 = byte;
            index2 = index;
        }
    }
    let mut filter = CandidateFilterV2 {
        offsets: [index1, index2, 0, 0],
        len: 2,
    };
    while filter.len < 4 {
        let selected = usize::from(filter.len);
        let mut best = None;
        for (index, byte) in literal.iter().copied().enumerate() {
            observed.tick_byte(selected)?;
            let index = u8::try_from(index).expect("literal width is at most 32");
            let mut already_selected = false;
            for offset in filter.offsets() {
                observed.tick_contains_probe(selected)?;
                if *offset == index {
                    already_selected = true;
                    break;
                }
            }
            if already_selected {
                continue;
            }
            let mut duplicate_value = false;
            for offset in filter.offsets() {
                observed.tick_value_probe(selected)?;
                if literal[usize::from(*offset)] == byte {
                    duplicate_value = true;
                    break;
                }
            }
            if duplicate_value {
                continue;
            }
            if best.is_none_or(|best_index| {
                emitter_rank_v2(byte) < emitter_rank_v2(literal[usize::from(best_index)])
            }) {
                best = Some(index);
            }
        }
        let Some(best) = best else {
            break;
        };
        filter.offsets[usize::from(filter.len)] = best;
        filter.len += 1;
    }
    Ok(CandidateFilterSelectionV2 {
        filter: Some(filter),
        observed,
    })
}

#[cfg(test)]
pub(crate) fn candidate_filter_v2(literal: &[u8]) -> Option<CandidateFilterV2> {
    select_candidate_filter_v2(literal)
        .expect("width-32 candidate-filter accounting cannot overflow")
        .filter
}

#[cfg(test)]
pub(crate) fn candidate_filter_observed_work_for_test_v2(
    literal: &[u8],
) -> Result<CandidateFilterObservedWorkV2, CountAotError> {
    select_candidate_filter_v2(literal).map(|selection| selection.observed)
}

#[cfg(test)]
pub(crate) fn candidate_filter_meter_overflow_for_test_v2() -> Result<(), CountAotError> {
    let mut observed = CandidateFilterObservedWorkV2 {
        initial_byte_visits: u64::MAX,
        ..CandidateFilterObservedWorkV2::default()
    };
    observed.tick_initial_byte()
}

#[cfg(test)]
pub(crate) fn rare_pair_v2(literal: &[u8]) -> Option<(u8, u8)> {
    let filter = candidate_filter_v2(literal)?;
    Some((filter.offsets[0], filter.offsets[1]))
}

fn emitter_rank_v2(byte: u8) -> u8 {
    EMITTER_FREQUENCY_RANK_V2[usize::from(byte)]
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LabelV2(u32);

#[derive(Clone, Copy, Debug)]
struct LabelRecordV2 {
    offset: Option<u32>,
    kind: LabelKindV2,
}

#[derive(Clone, Copy, Debug)]
struct FixupV2 {
    at: u32,
    kind: RelocationKindV2,
    target: LabelV2,
}

struct AssemblerV2 {
    code: ExactVec<u8>,
    labels: ExactVec<LabelRecordV2>,
    fixups: ExactVec<FixupV2>,
    prospective: ProspectiveV2,
    emission_work: u64,
    vector_instructions: u32,
    peak_scratch_bytes: u64,
}

impl AssemblerV2 {
    fn new(prospective: ProspectiveV2) -> Result<Self, CountAotError> {
        let code = exact_vec_v2(
            prospective.code_bytes,
            CountAotResource::CodeBytes,
            prospective.scratch,
            prospective.scratch_limit,
        )?;
        let labels = exact_vec_v2(
            prospective.labels,
            CountAotResource::Labels,
            prospective.scratch,
            prospective.scratch_limit,
        )?;
        let fixups = exact_vec_v2(
            prospective.relocations,
            CountAotResource::Relocations,
            prospective.scratch,
            prospective.scratch_limit,
        )?;
        let mut assembler = Self {
            code,
            labels,
            fixups,
            prospective,
            emission_work: 0,
            vector_instructions: 0,
            peak_scratch_bytes: 0,
        };
        assembler.observe_scratch(0, 0, EmissionPhaseV2::Canonical)?;
        Ok(assembler)
    }

    fn observe_scratch(
        &mut self,
        output_labels: usize,
        output_relocations: usize,
        phase: EmissionPhaseV2,
    ) -> Result<(), CountAotError> {
        let actual = observed_emission_phase_scratch_v2(
            self.code.capacity(),
            self.labels.capacity(),
            self.fixups.capacity(),
            output_labels,
            output_relocations,
            phase,
        )?;
        if actual > self.prospective.emission_scratch {
            return Err(CountAotError::InternalInvariant {
                at: "v2 emission scratch prospective",
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

    fn new_label(&mut self, kind: LabelKindV2) -> Result<LabelV2, CountAotError> {
        if self.labels.len() >= self.prospective.labels {
            return Err(CountAotError::InternalInvariant {
                at: "v2 label prospective",
            });
        }
        self.charge(1)?;
        let label = LabelV2(to_u32(
            self.labels.len(),
            CountAotArithmeticSite::CodeOffset,
        )?);
        push_exact_v2(
            &mut self.labels,
            LabelRecordV2 { offset: None, kind },
            "v2 label capacity",
        )?;
        Ok(label)
    }

    fn bind(&mut self, label: LabelV2) -> Result<(), CountAotError> {
        self.charge(1)?;
        let offset = to_u32(self.code.len(), CountAotArithmeticSite::CodeOffset)?;
        let record = self
            .labels
            .get_mut(usize::try_from(label.0).expect("u32 fits usize"))
            .ok_or(CountAotError::InternalInvariant {
                at: "v2 label index",
            })?;
        if record.offset.replace(offset).is_some() {
            return Err(CountAotError::InternalInvariant {
                at: "v2 label rebound",
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
                at: "v2 code prospective",
            });
        }
        self.charge(1)?;
        for byte in word.to_le_bytes() {
            push_exact_v2(&mut self.code, byte, "v2 code capacity")?;
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
        kind: RelocationKindV2,
        target: LabelV2,
        placeholder: u32,
    ) -> Result<(), CountAotError> {
        if self.fixups.len() >= self.prospective.relocations {
            return Err(CountAotError::InternalInvariant {
                at: "v2 relocation prospective",
            });
        }
        let at = to_u32(self.code.len(), CountAotArithmeticSite::CodeOffset)?;
        self.emit_word(placeholder, false)?;
        push_exact_v2(
            &mut self.fixups,
            FixupV2 { at, kind, target },
            "v2 fixup capacity",
        )
    }

    fn mov_imm64_minimal(&mut self, destination: u8, value: u64) -> Result<(), CountAotError> {
        let first = (0_u8..4).find(|halfword| {
            let shift = u32::from(*halfword) * 16;
            ((value >> shift) & 0xffff) != 0
        });
        let first = first.unwrap_or(0);
        let shift = u32::from(first) * 16;
        let immediate = u16::try_from((value >> shift) & 0xffff).expect("masked halfword");
        self.emit_word(
            0xd280_0000
                | (u32::from(first) << 21)
                | (u32::from(immediate) << 5)
                | u32::from(destination),
            false,
        )?;
        for halfword in 0_u8..4 {
            if halfword == first {
                continue;
            }
            let shift = u32::from(halfword) * 16;
            let immediate = u16::try_from((value >> shift) & 0xffff).expect("masked halfword");
            if immediate == 0 {
                continue;
            }
            self.emit_word(
                0xf280_0000
                    | (u32::from(halfword) << 21)
                    | (u32::from(immediate) << 5)
                    | u32::from(destination),
                false,
            )?;
        }
        Ok(())
    }

    fn cmp_reg64(&mut self, left: u8, right: u8) -> Result<(), CountAotError> {
        self.emit_word(
            0xeb00_001f | register_field_v2(right, 16) | register_field_v2(left, 5),
            false,
        )
    }

    fn cmp_reg32(&mut self, left: u8, right: u8) -> Result<(), CountAotError> {
        self.emit_word(
            0x6b00_001f | register_field_v2(right, 16) | register_field_v2(left, 5),
            false,
        )
    }

    fn cmp_imm64(&mut self, register: u8, immediate: u16) -> Result<(), CountAotError> {
        self.emit_word(
            0xf100_001f | (u32::from(immediate) << 10) | register_field_v2(register, 5),
            false,
        )
    }

    fn cmp_imm32(&mut self, register: u8, immediate: u16) -> Result<(), CountAotError> {
        self.emit_word(
            0x7100_001f | (u32::from(immediate) << 10) | register_field_v2(register, 5),
            false,
        )
    }

    fn add_reg(&mut self, destination: u8, left: u8, right: u8) -> Result<(), CountAotError> {
        self.emit_word(
            0x8b00_0000
                | register_field_v2(right, 16)
                | register_field_v2(left, 5)
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
                | register_field_v2(source, 5)
                | u32::from(destination),
            false,
        )
    }

    fn sub_reg(&mut self, destination: u8, left: u8, right: u8) -> Result<(), CountAotError> {
        self.emit_word(
            0xcb00_0000
                | register_field_v2(right, 16)
                | register_field_v2(left, 5)
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
                | register_field_v2(source, 5)
                | u32::from(destination),
            false,
        )
    }

    fn and_reg(&mut self, destination: u8, left: u8, right: u8) -> Result<(), CountAotError> {
        self.emit_word(
            0x8a00_0000
                | register_field_v2(right, 16)
                | register_field_v2(left, 5)
                | u32::from(destination),
            false,
        )
    }

    fn and_low_bits(&mut self, destination: u8, source: u8, bits: u8) -> Result<(), CountAotError> {
        let mask = u32::from(
            bits.checked_sub(1)
                .ok_or(CountAotError::InternalInvariant {
                    at: "v2 zero low-bit mask",
                })?,
        ) << 10;
        self.emit_word(
            0x9240_0000 | mask | register_field_v2(source, 5) | u32::from(destination),
            false,
        )
    }

    fn lsr_imm(&mut self, destination: u8, source: u8, shift: u8) -> Result<(), CountAotError> {
        self.emit_word(
            0xd340_0000
                | (u32::from(shift) << 16)
                | (63 << 10)
                | register_field_v2(source, 5)
                | u32::from(destination),
            false,
        )
    }

    fn reverse_bits(&mut self, destination: u8, source: u8) -> Result<(), CountAotError> {
        self.emit_word(
            0xdac0_0000 | register_field_v2(source, 5) | u32::from(destination),
            false,
        )
    }

    fn count_leading_zeros(&mut self, destination: u8, source: u8) -> Result<(), CountAotError> {
        self.emit_word(
            0xdac0_1000 | register_field_v2(source, 5) | u32::from(destination),
            false,
        )
    }

    fn load_byte(&mut self, destination: u8, base: u8, offset: u16) -> Result<(), CountAotError> {
        self.emit_word(
            0x3940_0000
                | (u32::from(offset) << 10)
                | register_field_v2(base, 5)
                | u32::from(destination),
            false,
        )
    }

    fn load_byte_reg(&mut self, destination: u8, base: u8, index: u8) -> Result<(), CountAotError> {
        self.emit_word(
            0x3860_6800
                | register_field_v2(index, 16)
                | register_field_v2(base, 5)
                | u32::from(destination),
            false,
        )
    }

    fn store64(&mut self, source: u8, base: u8, offset: u16) -> Result<(), CountAotError> {
        self.emit_word(
            0xf900_0000
                | (u32::from(offset / 8) << 10)
                | register_field_v2(base, 5)
                | u32::from(source),
            false,
        )
    }

    fn load_vector128(&mut self, destination: u8, base: u8) -> Result<(), CountAotError> {
        self.load_vector128_offset(destination, base, 0)
    }

    fn load_vector128_offset(
        &mut self,
        destination: u8,
        base: u8,
        offset: u16,
    ) -> Result<(), CountAotError> {
        if !offset.is_multiple_of(16) {
            return Err(CountAotError::InternalInvariant {
                at: "v2 vector load alignment",
            });
        }
        self.emit_word(
            0x3dc0_0000
                | (u32::from(offset / 16) << 10)
                | register_field_v2(base, 5)
                | u32::from(destination),
            true,
        )
    }

    fn load_vector_double(
        &mut self,
        destination: u8,
        base: u8,
        offset: u16,
    ) -> Result<(), CountAotError> {
        self.emit_word(
            0xfd40_0000
                | (u32::from(offset / 8) << 10)
                | register_field_v2(base, 5)
                | u32::from(destination),
            true,
        )
    }

    fn dup_byte16(&mut self, destination: u8, source: u8) -> Result<(), CountAotError> {
        self.emit_word(
            0x4e01_0c00 | register_field_v2(source, 5) | u32::from(destination),
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
                | register_field_v2(right, 16)
                | register_field_v2(left, 5)
                | u32::from(destination),
            true,
        )
    }

    fn compare_equal_bytes8(
        &mut self,
        destination: u8,
        left: u8,
        right: u8,
    ) -> Result<(), CountAotError> {
        self.emit_word(
            0x2e20_8c00
                | register_field_v2(right, 16)
                | register_field_v2(left, 5)
                | u32::from(destination),
            true,
        )
    }

    fn and_bytes16(&mut self, destination: u8, left: u8, right: u8) -> Result<(), CountAotError> {
        self.emit_word(
            0x4e20_1c00
                | register_field_v2(right, 16)
                | register_field_v2(left, 5)
                | u32::from(destination),
            true,
        )
    }

    fn or_bytes16(&mut self, destination: u8, left: u8, right: u8) -> Result<(), CountAotError> {
        self.emit_word(
            0x4ea0_1c00
                | register_field_v2(right, 16)
                | register_field_v2(left, 5)
                | u32::from(destination),
            true,
        )
    }

    fn shrink_narrow_bytes_from_halfwords(
        &mut self,
        destination: u8,
        source: u8,
        shift: u8,
    ) -> Result<(), CountAotError> {
        if shift != 4 {
            return Err(CountAotError::InternalInvariant {
                at: "v2 SHRN shift",
            });
        }
        self.emit_word(
            0x0f0c_8400 | register_field_v2(source, 5) | u32::from(destination),
            true,
        )
    }

    fn add_across_bytes16(&mut self, destination: u8, source: u8) -> Result<(), CountAotError> {
        self.emit_word(
            0x4e31_b800 | register_field_v2(source, 5) | u32::from(destination),
            true,
        )
    }

    fn unsigned_max_across_bytes16(
        &mut self,
        destination: u8,
        source: u8,
    ) -> Result<(), CountAotError> {
        self.emit_word(
            0x6e30_a800 | register_field_v2(source, 5) | u32::from(destination),
            true,
        )
    }

    fn unsigned_min_across_bytes8(
        &mut self,
        destination: u8,
        source: u8,
    ) -> Result<(), CountAotError> {
        self.emit_word(
            0x2e31_a800 | register_field_v2(source, 5) | u32::from(destination),
            true,
        )
    }

    fn unsigned_min_across_bytes16(
        &mut self,
        destination: u8,
        source: u8,
    ) -> Result<(), CountAotError> {
        self.emit_word(
            0x6e31_a800 | register_field_v2(source, 5) | u32::from(destination),
            true,
        )
    }

    fn move_vector_byte_to32(&mut self, destination: u8, source: u8) -> Result<(), CountAotError> {
        self.emit_word(
            0x0e01_3c00 | register_field_v2(source, 5) | u32::from(destination),
            true,
        )
    }

    fn move_vector_double_to64(
        &mut self,
        destination: u8,
        source: u8,
    ) -> Result<(), CountAotError> {
        self.emit_word(
            0x9e66_0000 | register_field_v2(source, 5) | u32::from(destination),
            true,
        )
    }

    fn move_x_to_vector_double(
        &mut self,
        destination: u8,
        source: u8,
    ) -> Result<(), CountAotError> {
        self.emit_word(
            0x9e67_0000 | register_field_v2(source, 5) | u32::from(destination),
            true,
        )
    }

    fn insert_x_to_vector_double_lane1(
        &mut self,
        destination: u8,
        source: u8,
    ) -> Result<(), CountAotError> {
        self.emit_word(
            0x4e18_1c00 | register_field_v2(source, 5) | u32::from(destination),
            true,
        )
    }

    fn branch(&mut self, target: LabelV2) -> Result<(), CountAotError> {
        self.add_fixup(RelocationKindV2::Branch26, target, 0x1400_0000)
    }

    fn branch_cond(
        &mut self,
        condition: ConditionV2,
        target: LabelV2,
    ) -> Result<(), CountAotError> {
        self.add_fixup(
            RelocationKindV2::ConditionalBranch19,
            target,
            0x5400_0000 | u32::from(condition_encoding_v2(condition)),
        )
    }

    fn ret(&mut self) -> Result<(), CountAotError> {
        self.emit_word(0xd65f_03c0, false)
    }

    fn order_labels(&mut self, labels: &mut [CodeLabelV2]) -> Result<(), CountAotError> {
        let budget = label_order_work_upper_bound_v2(labels.len())?;
        let recomposed = budget
            .comparisons
            .checked_add(budget.moves)
            .and_then(|work| work.checked_add(budget.placements))
            .ok_or(arithmetic_prospective_v2())?;
        if recomposed != budget.total {
            return Err(CountAotError::InternalInvariant {
                at: "v2 label order work envelope",
            });
        }
        // Refuse and charge a complete insertion-ordering envelope before the
        // first comparison. No unmetered library sort remains on this path.
        self.charge(budget.total)?;
        let mut comparisons = 0_u64;
        let mut moves = 0_u64;
        let mut placements = 0_u64;
        for insertion in 1..labels.len() {
            let key = labels[insertion];
            let mut cursor = insertion;
            while cursor != 0 {
                comparisons = comparisons
                    .checked_add(1)
                    .ok_or(arithmetic_prospective_v2())?;
                let previous_index = cursor.checked_sub(1).ok_or(arithmetic_prospective_v2())?;
                let previous = labels[previous_index];
                if previous <= key {
                    break;
                }
                labels[cursor] = previous;
                moves = moves.checked_add(1).ok_or(arithmetic_prospective_v2())?;
                cursor = previous_index;
            }
            labels[cursor] = key;
            placements = placements
                .checked_add(1)
                .ok_or(arithmetic_prospective_v2())?;
        }
        if comparisons > budget.comparisons
            || moves > budget.moves
            || placements != budget.placements
        {
            return Err(CountAotError::InternalInvariant {
                at: "v2 label order observed work",
            });
        }
        Ok(())
    }

    fn finalize(mut self) -> Result<FinalizedV2, CountAotError> {
        let mut relocations = exact_vec_v2(
            self.fixups.len(),
            CountAotResource::Relocations,
            self.prospective.scratch,
            self.prospective.scratch_limit,
        )?;
        self.observe_scratch(
            0,
            relocations.capacity(),
            EmissionPhaseV2::FinalizeRelocations,
        )?;
        for index in 0..self.fixups.len() {
            let fixup = self.fixups[index];
            self.charge(1)?;
            let target = self
                .labels
                .get(usize::try_from(fixup.target.0).expect("u32 fits usize"))
                .and_then(|record| record.offset)
                .ok_or(CountAotError::InternalInvariant {
                    at: "v2 unbound fixup target",
                })?;
            let word = read_word_v2(&self.code, fixup.at)?;
            let resolved = resolve_branch_v2(word, fixup.kind, fixup.at, target)?;
            write_word_v2(&mut self.code, fixup.at, resolved)?;
            push_exact_v2(
                &mut relocations,
                RelocationV2 {
                    code_offset: fixup.at,
                    kind: fixup.kind,
                    target: RelocationTargetV2::CodeOffset(target),
                    resolved_word: resolved,
                },
                "v2 finalized relocation capacity",
            )?;
        }
        let mut labels = exact_vec_v2(
            self.labels.len(),
            CountAotResource::Labels,
            self.prospective.scratch,
            self.prospective.scratch_limit,
        )?;
        self.observe_scratch(
            labels.capacity(),
            relocations.capacity(),
            EmissionPhaseV2::CollectLabels,
        )?;
        for record in self.labels.iter().copied() {
            push_exact_v2(
                &mut labels,
                CodeLabelV2 {
                    offset: record.offset.ok_or(CountAotError::InternalInvariant {
                        at: "v2 unbound label",
                    })?,
                    kind: record.kind,
                },
                "v2 finalized label capacity",
            )?;
        }
        self.observe_scratch(
            labels.capacity(),
            relocations.capacity(),
            EmissionPhaseV2::OrderLabels,
        )?;
        self.order_labels(&mut labels)?;
        let code_capacity_bytes = self.code.capacity();
        let label_capacity_bytes = labels
            .capacity()
            .checked_mul(size_of::<CodeLabelV2>())
            .ok_or(CountAotError::ArithmeticOverflow {
                site: CountAotArithmeticSite::Persistent,
            })?;
        let relocation_capacity_bytes = relocations
            .capacity()
            .checked_mul(size_of::<RelocationV2>())
            .ok_or(CountAotError::ArithmeticOverflow {
                site: CountAotArithmeticSite::Persistent,
            })?;
        self.observe_scratch(
            labels.capacity(),
            relocations.capacity(),
            EmissionPhaseV2::FinalizeReturn,
        )?;
        Ok(FinalizedV2 {
            code: self.code,
            labels,
            relocations,
            emission_work: self.emission_work,
            vector_instructions: self.vector_instructions,
            code_capacity_bytes,
            label_capacity_bytes,
            relocation_capacity_bytes,
            emission_peak_scratch_bytes: self.peak_scratch_bytes,
        })
    }
}

const fn condition_encoding_v2(condition: ConditionV2) -> u8 {
    match condition {
        ConditionV2::Equal => 0,
        ConditionV2::NotEqual => 1,
        ConditionV2::CarrySet => 2,
        ConditionV2::CarryClear => 3,
        ConditionV2::Higher => 8,
    }
}

const fn label_kind_encoding_v2(kind: LabelKindV2) -> u8 {
    match kind {
        LabelKindV2::Entry => 1,
        LabelKindV2::VectorLoop => 2,
        LabelKindV2::CandidateLoop => 3,
        LabelKindV2::ScalarTail => 4,
        LabelKindV2::Miss => 5,
        LabelKindV2::Success => 6,
        LabelKindV2::Overflow => 7,
        LabelKindV2::Internal => 8,
    }
}

const fn relocation_kind_encoding_v2(kind: RelocationKindV2) -> u8 {
    match kind {
        RelocationKindV2::Branch26 => 1,
        RelocationKindV2::ConditionalBranch19 => 2,
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct FinalizedV2 {
    pub(crate) code: ExactVec<u8>,
    pub(crate) labels: ExactVec<CodeLabelV2>,
    pub(crate) relocations: ExactVec<RelocationV2>,
    pub(crate) emission_work: u64,
    pub(crate) vector_instructions: u32,
    pub(crate) code_capacity_bytes: usize,
    pub(crate) label_capacity_bytes: usize,
    pub(crate) relocation_capacity_bytes: usize,
    pub(crate) emission_peak_scratch_bytes: u64,
}

pub(crate) fn compute_artifact_identity_v2(
    image: &AotCountImageV2,
) -> Result<(AotCountArtifactIdentityV2, u64), CountAotError> {
    let mut encoder = IdentityEncoderV2::hasher();
    encode_artifact_identity_v2(&mut encoder, image)?;
    encoder.finish()
}

pub(crate) fn artifact_identity_encoded_len_v2(
    image: &AotCountImageV2,
) -> Result<u64, CountAotError> {
    let mut encoder = IdentityEncoderV2::counter();
    encode_artifact_identity_v2(&mut encoder, image)?;
    Ok(encoder.bytes)
}

fn encode_artifact_identity_v2(
    encoder: &mut IdentityEncoderV2,
    image: &AotCountImageV2,
) -> Result<(), CountAotError> {
    encoder.raw(IDENTITY_DOMAIN_V2)?;
    encoder.u16(AOT_COUNT_IMAGE_SCHEMA_VERSION_V2)?;
    let support = image.support;
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
    encoder.u16(support.max_literal_bytes)?;
    encoder.u8(support.candidate_block_starts)?;
    encoder.u8(image.target.architecture)?;
    encoder.boolean(image.target.little_endian)?;
    encoder.u8(image.target.pointer_width)?;
    encoder.u8(image.target.abi)?;
    encoder.u64(image.target.features.bits())?;
    encoder.raw(image.source_identity.as_bytes())?;
    encoder.u8(image.literal_manifest.len())?;
    encoder.u8(image.literal_manifest.candidate_filter_len())?;
    encoder.raw(&image.literal_manifest.padded_filter_offsets())?;
    encoder.raw(&image.literal_manifest.padded_bytes())?;
    encoder.u32(image.layout.code_alignment)?;
    encoder.u32(image.layout.rodata_alignment)?;
    encoder.u32(image.layout.rodata_from_code_start)?;
    encoder.u32(image.layout.total_mapped_bytes)?;
    encoder.bytes(&image.code)?;
    encoder.u32(to_u32(
        image.labels.len(),
        CountAotArithmeticSite::Identity,
    )?)?;
    for label in &image.labels {
        encoder.u32(label.offset)?;
        encoder.u8(label_kind_encoding_v2(label.kind))?;
    }
    encoder.u32(to_u32(
        image.relocations.len(),
        CountAotArithmeticSite::Identity,
    )?)?;
    for relocation in &image.relocations {
        encoder.u32(relocation.code_offset)?;
        encoder.u8(relocation_kind_encoding_v2(relocation.kind))?;
        let RelocationTargetV2::CodeOffset(target) = relocation.target;
        encoder.u32(target)?;
        encoder.u32(relocation.resolved_word)?;
    }
    let stats = image.stats;
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
    encoder.u64(stats.scratch_bytes_upper_bound)?;
    let receipt = image.build_receipt;
    encoder.u64(to_u64(
        receipt.code_capacity_bytes,
        CountAotArithmeticSite::Identity,
    )?)?;
    encoder.u64(to_u64(
        receipt.label_capacity_bytes,
        CountAotArithmeticSite::Identity,
    )?)?;
    encoder.u64(to_u64(
        receipt.relocation_capacity_bytes,
        CountAotArithmeticSite::Identity,
    )?)?;
    encoder.u64(to_u64(
        receipt.retained_heap_bytes,
        CountAotArithmeticSite::Identity,
    )?)?;
    encoder.u64(to_u64(
        receipt.inline_bytes,
        CountAotArithmeticSite::Identity,
    )?)?;
    encoder.u64(receipt.emission_peak_scratch_bytes)?;
    encoder.u64(receipt.work_upper_bound)?;
    encoder.u64(receipt.scratch_bytes_upper_bound)?;
    encode_audit_identity_v2(encoder, receipt.audit)
}

fn encode_audit_identity_v2(
    encoder: &mut IdentityEncoderV2,
    audit: CountAuditReportV2,
) -> Result<(), CountAotError> {
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

pub(crate) fn identity_bytes_upper_bound_v2(
    code_bytes: usize,
    labels: usize,
    relocations: usize,
) -> Result<u64, CountAotError> {
    // Exact fixed-width encoding, excluding the domain, code, label records,
    // and relocation records: schema/support 26, target 12, source 32,
    // manifest 38, layout 16, code length 8, two record counts 8, stats 67,
    // build receipt 64, and audit receipt 56.
    const FIXED_IDENTITY_BYTES_V2: u64 = 327;
    to_u64(IDENTITY_DOMAIN_V2.len(), CountAotArithmeticSite::Identity)?
        .checked_add(FIXED_IDENTITY_BYTES_V2)
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

type IdentityEncoderInlineStateV2 = (
    IdentityEncoderV2,
    &'static AotCountImageV2,
    AotCountArtifactIdentityV2,
    AotCountImageStatsV2,
    AotCountImageBuildReceiptV2,
    CountAuditReportV2,
    core::slice::Iter<'static, CodeLabelV2>,
    core::slice::Iter<'static, RelocationV2>,
    &'static CodeLabelV2,
    &'static RelocationV2,
    [u8; 64],
    [u8; 32],
    [u64; 4],
    CountAotError,
);

pub(crate) const fn identity_scratch_bytes_v2() -> usize {
    size_of::<IdentityEncoderInlineStateV2>()
}

struct IdentityEncoderV2 {
    hasher: Option<Sha256>,
    bytes: u64,
}

impl IdentityEncoderV2 {
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

    fn finish(self) -> Result<(AotCountArtifactIdentityV2, u64), CountAotError> {
        let digest = self
            .hasher
            .ok_or(CountAotError::InternalInvariant {
                at: "finish v2 identity counter",
            })?
            .finalize();
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(&digest);
        Ok((AotCountArtifactIdentityV2::new(bytes), self.bytes))
    }
}

fn resolve_branch_v2(
    word: u32,
    kind: RelocationKindV2,
    from: u32,
    target: u32,
) -> Result<u32, CountAotError> {
    let displacement = i64::from(target).checked_sub(i64::from(from)).ok_or(
        CountAotError::ArithmeticOverflow {
            site: CountAotArithmeticSite::Relocation,
        },
    )?;
    let (bits, shift) = match kind {
        RelocationKindV2::Branch26 => (26_u8, 0_u8),
        RelocationKindV2::ConditionalBranch19 => (19, 5),
    };
    if displacement % 4 != 0 {
        return Err(CountAotError::InternalInvariant {
            at: "v2 unaligned branch",
        });
    }
    let scaled = displacement / 4;
    let magnitude = 1_i64 << u32::from(bits - 1);
    if scaled < -magnitude || scaled >= magnitude {
        return Err(CountAotError::InvalidImage {
            at: "v2 branch range",
        });
    }
    let mask = (1_u32 << u32::from(bits)) - 1;
    let encoded = u32::try_from(scaled & i64::from(mask)).expect("masked displacement");
    Ok(word | (encoded << u32::from(shift)))
}

fn read_word_v2(code: &[u8], offset: u32) -> Result<u32, CountAotError> {
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
            at: "v2 read relocation word",
        })?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn write_word_v2(code: &mut [u8], offset: u32, word: u32) -> Result<(), CountAotError> {
    let offset = usize::try_from(offset).expect("u32 fits usize");
    let end = offset
        .checked_add(4)
        .ok_or(CountAotError::ArithmeticOverflow {
            site: CountAotArithmeticSite::CodeOffset,
        })?;
    code.get_mut(offset..end)
        .ok_or(CountAotError::InternalInvariant {
            at: "v2 write relocation word",
        })?
        .copy_from_slice(&word.to_le_bytes());
    Ok(())
}

fn register_field_v2(register: u8, shift: u8) -> u32 {
    debug_assert!(register < 32);
    u32::from(register) << shift
}

fn align_up_v2(value: usize, alignment: usize) -> Result<usize, CountAotError> {
    let mask = alignment
        .checked_sub(1)
        .ok_or(CountAotError::InternalInvariant {
            at: "v2 zero alignment",
        })?;
    value
        .checked_add(mask)
        .map(|sum| sum & !mask)
        .ok_or(CountAotError::ArithmeticOverflow {
            site: CountAotArithmeticSite::ImageLayout,
        })
}

fn exact_vec_v2<T>(
    capacity: usize,
    resource: CountAotResource,
    required_scratch: u64,
    scratch_limit: u64,
) -> Result<ExactVec<T>, CountAotError> {
    // This check is intentionally adjacent to every allocator call. It makes
    // allocation impossible until the complete source-derived phase envelope
    // has passed both the caller and hard limit.
    if required_scratch > scratch_limit {
        return Err(CountAotError::ResourceLimit {
            resource: CountAotResource::ScratchBytes,
            limit: scratch_limit,
            required: required_scratch,
        });
    }
    ExactVec::try_with_capacity(capacity).map_err(|error| match error {
        CopyError::LayoutOverflow => CountAotError::ArithmeticOverflow {
            site: CountAotArithmeticSite::Prospective,
        },
        CopyError::AllocationFailed => CountAotError::AllocationFailed { resource },
    })
}

fn push_exact_v2<T>(
    values: &mut ExactVec<T>,
    value: T,
    at: &'static str,
) -> Result<(), CountAotError> {
    values
        .try_push(value)
        .map_err(|_| CountAotError::InternalInvariant { at })
}

fn enforce_all_v2(
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

const fn arithmetic_prospective_v2() -> CountAotError {
    CountAotError::ArithmeticOverflow {
        site: CountAotArithmeticSite::Prospective,
    }
}
