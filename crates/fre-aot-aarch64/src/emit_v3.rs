#![allow(
    clippy::arithmetic_side_effects,
    reason = "instruction encoding arithmetic is over bounded ISA fields and literal widths; resource formulas use checked operations"
)]

use core::mem::size_of;

use fre_aot_optimizer::{
    CountRecipeV3, CountV3RegisterPlanId, CountV3RequiredIsa, CountV3ScheduleId, CountV3Strategy,
    CountV3SuccessorMode, decode_count_recipe_v3, encode_count_recipe_v3, validate_count_recipe_v3,
};
use fre_exact_alloc::{CopyError, ExactVec};
use fre_kernel_ir::{
    AggregateOutput, Count, ExactAggregateProgram, MAX_EXACT_AGGREGATE_LITERAL_BYTES,
};
use sha2::{Digest, Sha256};

use crate::{
    AOT_COUNT_IMAGE_SCHEMA_VERSION_V3, AotCountArtifactIdentityV3, AotCountCpuFeatures,
    AotCountImageBuildReceiptV3, AotCountImageLayoutV3, AotCountImageStatsV3, AotCountImageV3,
    AotCountLiteralManifestV3, AotCountRecipeManifestV3, AotCountTargetSpec, CodeLabelV3,
    ConditionV3, CountAotArithmeticSite, CountAotError, CountAotResource, CountAotUnsupported,
    CountAuditReportV3, LabelKindV3, RelocationKindV3, RelocationTargetV3, RelocationV3,
    SUPPORTED_AOT_COUNT_BACKEND_TUPLES_V3,
    audit_v3::{
        audit_candidate_wrapper_inline_bytes_v3, audit_count_image_candidate_v3,
        audit_count_image_v3, audit_public_wrapper_inline_bytes_v3, audit_scratch_upper_bound_v3,
        audit_work_upper_bound_v3,
    },
};

const CODE_ALIGNMENT_V3: usize = 16;
const MAX_CODE_BYTES_V3: u64 = 16 << 10;
const MAX_LABELS_V3: u64 = 48;
const MAX_RELOCATIONS_V3: u64 = 256;
const MAX_WORK_V3: u64 = 2 << 20;
const MAX_SCRATCH_BYTES_V3: u64 = 256 << 10;
const MAX_PERSISTENT_BYTES_V3: u64 = 128 << 10;
pub(crate) const IDENTITY_DOMAIN_V3: &[u8] = b"FRE-AOT-AARCH64-COUNT-IMAGE\0\x03";
const SIMD_CANDIDATE_STARTS_V3: u16 = 16;
const SPARSE_SCAN_BLOCKS_V3: u16 = 8;
const SPARSE_SCAN_STARTS_V3: u16 = SIMD_CANDIDATE_STARTS_V3 * SPARSE_SCAN_BLOCKS_V3;
const SPARSE_NIBBLE_BITS_V3: u64 = 0x1111_1111_1111_1111;
const SPARSE_BLOCK_MASK_BASE_V3: u8 = 24;
const SPARSE_PAIR_01_MASK_V3: u8 = SPARSE_BLOCK_MASK_BASE_V3;
const SPARSE_PAIR_23_MASK_V3: u8 = SPARSE_BLOCK_MASK_BASE_V3 + 2;
const SPARSE_PAIR_45_MASK_V3: u8 = SPARSE_BLOCK_MASK_BASE_V3 + 4;
const SPARSE_PAIR_67_MASK_V3: u8 = SPARSE_BLOCK_MASK_BASE_V3 + 6;
const SEMANTIC_SECONDARY_VECTOR_V3: u8 = 18;
const SEMANTIC_PREFIX_VECTOR_V3: u8 = 19;
const OVERLAPPING_SUFFIX_VECTOR_V3: u8 = 23;

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

/// Backend-local closed projection of the optimizer strategy.
///
/// Keeping this private prevents arbitrary instruction graphs from crossing
/// the optimizer/backend boundary. Only these reviewed templates can reach
/// the macro assembler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LoweringStrategyV3 {
    Incumbent,
    SparseRareColumns,
    EndpointDense,
    PeriodicRun,
    DirectExactMask,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CandidateFilterV3 {
    offsets: [u8; 4],
    len: u8,
}

impl CandidateFilterV3 {
    pub(crate) fn offsets(&self) -> &[u8] {
        &self.offsets[..usize::from(self.len)]
    }

    pub(crate) const fn len(self) -> u8 {
        self.len
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LoweringRecipeV3 {
    pub(crate) strategy: LoweringStrategyV3,
    pub(crate) required_isa: CountV3RequiredIsa,
    pub(crate) filter: Option<CandidateFilterV3>,
    pub(crate) confirmation_order: [u8; 32],
    pub(crate) confirmation_len: u8,
    pub(crate) periodic_stride: u8,
}

impl LoweringRecipeV3 {
    fn confirmation_order(&self) -> &[u8] {
        &self.confirmation_order[..usize::from(self.confirmation_len)]
    }
}

/// Caller-selected optimizing-v3 limits, each capped by a hard bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountEmitLimitsV3 {
    pub max_code_bytes: u64,
    pub max_data_bytes: u64,
    pub max_labels: u64,
    pub max_relocations: u64,
    pub max_work: u64,
    pub max_scratch_bytes: u64,
    pub max_persistent_bytes: u64,
}

impl Default for CountEmitLimitsV3 {
    fn default() -> Self {
        Self {
            max_code_bytes: MAX_CODE_BYTES_V3,
            max_data_bytes: 0,
            max_labels: MAX_LABELS_V3,
            max_relocations: MAX_RELOCATIONS_V3,
            max_work: MAX_WORK_V3,
            max_scratch_bytes: MAX_SCRATCH_BYTES_V3,
            max_persistent_bytes: MAX_PERSISTENT_BYTES_V3,
        }
    }
}

/// O(1), source-dimension conservative envelope for a v3 Count image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountProspectiveReportV3 {
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
pub(crate) struct ProspectiveV3 {
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
    pub(crate) recipe_validation_work: u64,
    pub(crate) work: u64,
    pub(crate) scratch: u64,
    pub(crate) persistent: u64,
    pub(crate) scratch_limit: u64,
    pub(crate) persistent_limit: u64,
}

/// Conservative source-only work envelope for authenticating a sealed recipe.
///
/// Validation binds both identities, checks each bounded recipe field, proves
/// the confirmation order is a permutation, and validates filter membership.
/// The quadratic term is intentional and harmless at the sealed 32-byte
/// maximum; it avoids scratch allocation and keeps the check deterministic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RecipeValidationWorkEnvelopeV3 {
    pub(crate) identity_and_literal: u64,
    pub(crate) filter_membership: u64,
    pub(crate) confirmation_permutation: u64,
    pub(crate) fixed_manifest: u64,
    pub(crate) total: u64,
}

pub(crate) fn recipe_validation_work_envelope_v3(
    literal_len: usize,
) -> Result<RecipeValidationWorkEnvelopeV3, CountAotError> {
    let literal = to_u64(literal_len, CountAotArithmeticSite::Prospective)?;
    let identity_and_literal = literal.checked_mul(3).ok_or(arithmetic_prospective_v3())?;
    let filter_membership = literal.checked_mul(4).ok_or(arithmetic_prospective_v3())?;
    let confirmation_permutation = literal
        .checked_mul(literal)
        .and_then(|work| work.checked_mul(2))
        .ok_or(arithmetic_prospective_v3())?;
    let fixed_manifest = 96;
    let total = identity_and_literal
        .checked_add(filter_membership)
        .and_then(|work| work.checked_add(confirmation_permutation))
        .and_then(|work| work.checked_add(fixed_manifest))
        .ok_or(arithmetic_prospective_v3())?;
    Ok(RecipeValidationWorkEnvelopeV3 {
        identity_and_literal,
        filter_membership,
        confirmation_permutation,
        fixed_manifest,
        total,
    })
}

/// Compute the complete v3 build envelope for one authenticated sealed recipe.
pub fn prospective_count_v3(
    program: &ExactAggregateProgram<Count>,
    recipe: &CountRecipeV3,
) -> Result<CountProspectiveReportV3, CountAotError> {
    let literal_len = preflight_program_dimensions_v3(program)?;
    let _ = project_recipe_v3(program, recipe)?;
    let prospective = prospective_v3(literal_len)?;
    Ok(CountProspectiveReportV3 {
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

/// Emit a genuine direct-AOT Count v3 image from sealed exact-aggregate KIR.
///
/// The backend accepts no arbitrary instruction graph. It authenticates one
/// optimizer-produced closed recipe and lowers only the named incumbent,
/// sparse rare-column, endpoint-dense, or periodic-successor schedule.
#[allow(
    clippy::too_many_lines,
    reason = "one ordered build transaction keeps every preflight, allocation, phase observation, and seal visible"
)]
pub fn emit_count_v3(
    program: &ExactAggregateProgram<Count>,
    recipe: &CountRecipeV3,
    limits: CountEmitLimitsV3,
) -> Result<AotCountImageV3, CountAotError> {
    let literal_len = preflight_program_dimensions_v3(program)?;
    let mut prospective = prospective_v3(literal_len)?;
    enforce_all_v3(
        CountAotResource::CodeBytes,
        to_u64(prospective.code_bytes, CountAotArithmeticSite::Prospective)?,
        limits.max_code_bytes,
        MAX_CODE_BYTES_V3,
    )?;
    enforce_all_v3(CountAotResource::DataBytes, 0, limits.max_data_bytes, 0)?;
    enforce_all_v3(
        CountAotResource::Labels,
        to_u64(prospective.labels, CountAotArithmeticSite::Prospective)?,
        limits.max_labels,
        MAX_LABELS_V3,
    )?;
    enforce_all_v3(
        CountAotResource::Relocations,
        to_u64(prospective.relocations, CountAotArithmeticSite::Prospective)?,
        limits.max_relocations,
        MAX_RELOCATIONS_V3,
    )?;
    enforce_all_v3(
        CountAotResource::Work,
        prospective.work,
        limits.max_work,
        MAX_WORK_V3,
    )?;
    enforce_all_v3(
        CountAotResource::ScratchBytes,
        prospective.scratch,
        limits.max_scratch_bytes,
        MAX_SCRATCH_BYTES_V3,
    )?;
    enforce_all_v3(
        CountAotResource::PersistentBytes,
        prospective.persistent,
        limits.max_persistent_bytes,
        MAX_PERSISTENT_BYTES_V3,
    )?;
    prospective.scratch_limit = limits.max_scratch_bytes.min(MAX_SCRATCH_BYTES_V3);
    prospective.persistent_limit = limits.max_persistent_bytes.min(MAX_PERSISTENT_BYTES_V3);

    // No literal or recipe array is traversed until every caller and hard
    // resource bound is admitted.
    let literal = program.literal();
    let (lowering_recipe, recipe_manifest) = project_recipe_v3(program, recipe)?;
    let filter = lowering_recipe.filter;
    let filter_offsets = filter.as_ref().map_or(&[][..], CandidateFilterV3::offsets);
    let literal_manifest =
        AotCountLiteralManifestV3::from_literal_and_offsets(literal, filter_offsets).ok_or(
            CountAotError::InternalInvariant {
                at: "v3 literal manifest",
            },
        )?;
    let finalized = canonical_template_v3(literal, lowering_recipe, prospective)?;
    if finalized.code.len() > prospective.code_bytes
        || finalized.labels.len() > prospective.labels
        || finalized.relocations.len() > prospective.relocations
    {
        return Err(CountAotError::InternalInvariant {
            at: "v3 emission exceeded prospective dimensions",
        });
    }
    let observed_image_assembly_scratch = image_assembly_scratch_for_capacities_v3(
        finalized.code.capacity(),
        finalized.labels.capacity(),
        finalized.relocations.capacity(),
    )?;
    if observed_image_assembly_scratch > prospective.image_assembly_scratch {
        return Err(CountAotError::InternalInvariant {
            at: "v3 image assembly scratch prospective",
        });
    }
    if observed_image_assembly_scratch > prospective.scratch_limit {
        return Err(CountAotError::ResourceLimit {
            resource: CountAotResource::ScratchBytes,
            limit: prospective.scratch_limit,
            required: observed_image_assembly_scratch,
        });
    }
    let FinalizedV3 {
        code,
        labels,
        relocations,
        emission_work,
        vector_instructions,
        actual_features,
        code_capacity_bytes,
        label_capacity_bytes,
        relocation_capacity_bytes,
        emission_peak_scratch_bytes: assembler_peak_scratch_bytes,
    } = finalized;
    let recomputed_assembler_peak_scratch = assembler_scratch_for_capacities_v3(
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
            at: "v3 assembler scratch seal",
        });
    }
    let emission_peak_scratch_bytes =
        assembler_peak_scratch_bytes.max(observed_image_assembly_scratch);
    if observed_image_assembly_scratch > prospective.image_assembly_scratch
        || emission_peak_scratch_bytes > prospective.emission_scratch
    {
        return Err(CountAotError::InternalInvariant {
            at: "v3 emission scratch seal",
        });
    }
    let code_bytes = to_u32(code.len(), CountAotArithmeticSite::ImageLayout)?;
    let rodata_offset = align_up_v3(code.len(), CODE_ALIGNMENT_V3)?;
    let layout = AotCountImageLayoutV3 {
        code_alignment: u32::try_from(CODE_ALIGNMENT_V3).expect("small alignment"),
        rodata_alignment: u32::try_from(CODE_ALIGNMENT_V3).expect("small alignment"),
        rodata_from_code_start: to_u32(rodata_offset, CountAotArithmeticSite::ImageLayout)?,
        total_mapped_bytes: to_u32(rodata_offset, CountAotArithmeticSite::ImageLayout)?,
    };
    let support = match lowering_recipe.required_isa {
        CountV3RequiredIsa::Aarch64Neon128 => SUPPORTED_AOT_COUNT_BACKEND_TUPLES_V3[0],
        CountV3RequiredIsa::Aarch64SveVl16 => SUPPORTED_AOT_COUNT_BACKEND_TUPLES_V3[1],
        CountV3RequiredIsa::Aarch64Sve2Vl16 => SUPPORTED_AOT_COUNT_BACKEND_TUPLES_V3[2],
    };
    let expected_features = if literal.is_empty() {
        AotCountCpuFeatures::NONE
    } else {
        support.allowed_features
    };
    if actual_features != expected_features || !support.allowed_features.contains(actual_features) {
        return Err(CountAotError::InternalInvariant {
            at: "v3 emitted target feature closure",
        });
    }
    let target = AotCountTargetSpec {
        features: actual_features,
        ..AotCountTargetSpec::AARCH64_AAPCS64_BASELINE
    };
    let retained_heap_bytes = AotCountImageV3::retained_heap_bytes(
        code_capacity_bytes,
        label_capacity_bytes,
        relocation_capacity_bytes,
    )
    .ok_or(CountAotError::ArithmeticOverflow {
        site: CountAotArithmeticSite::Persistent,
    })?;
    let actual_persistent_bytes = retained_heap_bytes
        .checked_add(size_of::<AotCountImageV3>())
        .ok_or(CountAotError::ArithmeticOverflow {
            site: CountAotArithmeticSite::Persistent,
        })?;
    let actual_persistent_u64 =
        to_u64(actual_persistent_bytes, CountAotArithmeticSite::Persistent)?;
    if actual_persistent_u64 > prospective.persistent {
        return Err(CountAotError::InternalInvariant {
            at: "v3 persistent prospective",
        });
    }
    if actual_persistent_u64 > prospective.persistent_limit {
        return Err(CountAotError::ResourceLimit {
            resource: CountAotResource::PersistentBytes,
            limit: prospective.persistent_limit,
            required: actual_persistent_u64,
        });
    }
    let mut image = AotCountImageV3 {
        support,
        target,
        source_identity: program.cache_identity(),
        literal_manifest,
        recipe_manifest,
        layout,
        code,
        labels,
        relocations,
        stats: AotCountImageStatsV3 {
            code_bytes,
            data_bytes: 0,
            labels: 0,
            relocations: 0,
            emitted_instructions: code_bytes / 4,
            vector_instructions,
            strategy_id: recipe_manifest.strategy_id,
            schedule_id: recipe_manifest.schedule_id,
            register_plan_id: recipe_manifest.register_plan_id,
            candidate_filter_bytes: filter.map_or(0, CandidateFilterV3::len),
            confirmation_chunks: u8::try_from(literal.len() / 8).expect("bounded literal chunks"),
            confirmation_tail_bytes: u8::try_from(literal.len() % 8).expect("bounded literal tail"),
            emission_work,
            identity_bytes_hashed: 0,
            audit_work_upper_bound: prospective.audit_work,
            total_work_upper_bound: prospective.work,
            scratch_bytes_upper_bound: 0,
        },
        artifact_identity: AotCountArtifactIdentityV3::ZERO,
        build_receipt: AotCountImageBuildReceiptV3 {
            support,
            recipe: recipe_manifest,
            code_capacity_bytes,
            label_capacity_bytes,
            relocation_capacity_bytes,
            retained_heap_bytes,
            inline_bytes: size_of::<AotCountImageV3>(),
            emission_peak_scratch_bytes,
            work_upper_bound: prospective.work,
            scratch_bytes_upper_bound: 0,
            audit: CountAuditReportV3::default(),
        },
    };
    image.stats.labels = to_u32(image.labels.len(), CountAotArithmeticSite::ImageLayout)?;
    image.stats.relocations = to_u32(image.relocations.len(), CountAotArithmeticSite::ImageLayout)?;
    observe_emit_image_phase_scratch_v3(
        &image,
        prospective,
        EmitImagePhaseV3::InitialIdentityLength,
    )?;
    let identity_bytes_hashed = artifact_identity_encoded_len_v3(&image)?;
    if identity_bytes_hashed > prospective.identity_bytes_hashed {
        return Err(CountAotError::InternalInvariant {
            at: "v3 identity exceeded prospective bytes",
        });
    }
    image.stats.identity_bytes_hashed = identity_bytes_hashed;
    observe_emit_image_phase_scratch_v3(&image, prospective, EmitImagePhaseV3::CandidateAudit)?;
    let audit = audit_count_image_candidate_v3(program, recipe, &image, prospective)?;
    if audit.work_upper_bound != prospective.audit_work
        || audit.scratch_bytes_upper_bound != prospective.audit_scratch
    {
        return Err(CountAotError::InternalInvariant {
            at: "v3 audit prospective seal",
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
    observe_emit_image_phase_scratch_v3(
        &image,
        prospective,
        EmitImagePhaseV3::SealedIdentityLength,
    )?;
    let sealed_identity_len = artifact_identity_encoded_len_v3(&image)?;
    if sealed_identity_len != identity_bytes_hashed {
        return Err(CountAotError::InternalInvariant {
            at: "v3 identity encoded length changed",
        });
    }
    observe_emit_image_phase_scratch_v3(&image, prospective, EmitImagePhaseV3::SealedIdentityHash)?;
    let (artifact_identity, observed_identity_bytes) = compute_artifact_identity_v3(&image)?;
    if observed_identity_bytes != identity_bytes_hashed {
        return Err(CountAotError::InternalInvariant {
            at: "v3 artifact identity byte count",
        });
    }
    image.artifact_identity = artifact_identity;
    observe_emit_image_phase_scratch_v3(&image, prospective, EmitImagePhaseV3::SealedAudit)?;
    let sealed_audit = audit_count_image_v3(program, recipe, &image)?;
    if sealed_audit != audit {
        return Err(CountAotError::InternalInvariant {
            at: "v3 sealed audit report changed",
        });
    }
    Ok(image)
}

fn project_recipe_v3(
    program: &ExactAggregateProgram<Count>,
    recipe: &CountRecipeV3,
) -> Result<(LoweringRecipeV3, AotCountRecipeManifestV3), CountAotError> {
    validate_count_recipe_v3(program, recipe).map_err(|_| CountAotError::Unsupported {
        reason: CountAotUnsupported::OptimizerRecipe,
    })?;
    let canonical_recipe = encode_count_recipe_v3(recipe);
    match decode_count_recipe_v3(program, &canonical_recipe) {
        Ok(decoded) if decoded == *recipe => {}
        _ => {
            return Err(CountAotError::Unsupported {
                reason: CountAotUnsupported::OptimizerRecipe,
            });
        }
    }
    let expected_register_plan = match recipe.required_isa() {
        CountV3RequiredIsa::Aarch64Neon128 => CountV3RegisterPlanId::Aarch64NeonV1,
        CountV3RequiredIsa::Aarch64SveVl16 => CountV3RegisterPlanId::Aarch64NeonSveVl16V1,
        CountV3RequiredIsa::Aarch64Sve2Vl16 => CountV3RegisterPlanId::Aarch64NeonSve2Vl16V1,
    };
    if recipe.register_plan_id() != expected_register_plan {
        return Err(CountAotError::Unsupported {
            reason: CountAotUnsupported::TargetFeature,
        });
    }
    if recipe.successor_mode() != CountV3SuccessorMode::NonOverlapping {
        return Err(CountAotError::Unsupported {
            reason: CountAotUnsupported::RecipeSchedule,
        });
    }
    let expected_schedule = match recipe.strategy() {
        CountV3Strategy::Incumbent => CountV3ScheduleId::IncumbentV2,
        CountV3Strategy::SparseRareColumns => CountV3ScheduleId::SparseColumnsV1,
        CountV3Strategy::EndpointDense => CountV3ScheduleId::EndpointDenseV1,
        CountV3Strategy::PeriodicRun => CountV3ScheduleId::PeriodicRunV1,
        CountV3Strategy::DirectExactMask => CountV3ScheduleId::DirectExactMaskV1,
    };
    if recipe.schedule_id() != expected_schedule {
        return Err(CountAotError::Unsupported {
            reason: CountAotUnsupported::RecipeSchedule,
        });
    }

    let literal = program.literal();
    let width = literal.len();
    let filters = recipe.filter_offsets();
    if (width < 2 && !filters.is_empty())
        || (width >= 2 && !(2..=4).contains(&filters.len()))
        || filters.iter().any(|offset| usize::from(*offset) >= width)
        || filters
            .iter()
            .enumerate()
            .any(|(index, offset)| filters[..index].contains(offset))
    {
        return Err(CountAotError::Unsupported {
            reason: CountAotUnsupported::OptimizerRecipe,
        });
    }
    match recipe.strategy() {
        CountV3Strategy::EndpointDense => {
            let last = u8::try_from(width.saturating_sub(1)).expect("bounded literal width");
            let endpoints = filters.len() >= 2
                && ((filters[0] == 0 && filters[1] == last)
                    || (filters[0] == last && filters[1] == 0));
            if width < 2 || !(2..=3).contains(&filters.len()) || !endpoints {
                return Err(CountAotError::Unsupported {
                    reason: CountAotUnsupported::RecipeSchedule,
                });
            }
        }
        CountV3Strategy::PeriodicRun
            if width < 2 || usize::from(recipe.periodic_stride()) >= width =>
        {
            return Err(CountAotError::Unsupported {
                reason: CountAotUnsupported::RecipeSchedule,
            });
        }
        CountV3Strategy::DirectExactMask => {
            let covers_literal = (2..=4).contains(&width)
                && filters.len() == width
                && filters
                    .iter()
                    .copied()
                    .enumerate()
                    .all(|(offset, filter)| usize::from(filter) == offset);
            if !covers_literal || minimum_period_v3(literal) != width {
                return Err(CountAotError::Unsupported {
                    reason: CountAotUnsupported::RecipeSchedule,
                });
            }
        }
        _ => {}
    }
    let expected_period = minimum_period_v3(literal);
    let valid_periodic_stride = if recipe.strategy() == CountV3Strategy::PeriodicRun {
        width >= 2
            && expected_period < width
            && usize::from(recipe.periodic_stride()) == expected_period
    } else {
        recipe.periodic_stride() == 0
    };
    if recipe.mismatch_stride() != 1
        || usize::from(recipe.match_stride()) != width
        || !valid_periodic_stride
    {
        return Err(CountAotError::Unsupported {
            reason: CountAotUnsupported::RecipeSchedule,
        });
    }

    let mut filter_offsets = [0_u8; 4];
    filter_offsets[..filters.len()].copy_from_slice(filters);
    let filter = if filters.is_empty() {
        None
    } else {
        Some(CandidateFilterV3 {
            offsets: filter_offsets,
            len: u8::try_from(filters.len()).expect("at most four filters"),
        })
    };
    let order = recipe.confirmation_order();
    if order.len() != width {
        return Err(CountAotError::Unsupported {
            reason: CountAotUnsupported::OptimizerRecipe,
        });
    }
    let mut confirmation_order = [0_u8; 32];
    confirmation_order[..order.len()].copy_from_slice(order);

    let groups = recipe.sparse_group_blocks();
    if groups.len() > 4 {
        return Err(CountAotError::Unsupported {
            reason: CountAotUnsupported::RecipeSchedule,
        });
    }
    let mut sparse_group_first_offsets = [0_u8; 4];
    let mut sparse_group_lengths = [0_u8; 4];
    let mut covered = [false; 32];
    for (index, group) in groups.iter().copied().enumerate() {
        let first = usize::from(group.first_offset());
        let len = usize::from(group.len());
        let end = first.checked_add(len).ok_or(CountAotError::Unsupported {
            reason: CountAotUnsupported::RecipeSchedule,
        })?;
        if len == 0 || end > width || covered[first..end].iter().any(|byte| *byte) {
            return Err(CountAotError::Unsupported {
                reason: CountAotUnsupported::RecipeSchedule,
            });
        }
        covered[first..end].fill(true);
        sparse_group_first_offsets[index] = group.first_offset();
        sparse_group_lengths[index] = group.len();
    }

    let strategy = match recipe.strategy() {
        CountV3Strategy::Incumbent => LoweringStrategyV3::Incumbent,
        CountV3Strategy::SparseRareColumns => LoweringStrategyV3::SparseRareColumns,
        CountV3Strategy::EndpointDense => LoweringStrategyV3::EndpointDense,
        CountV3Strategy::PeriodicRun => LoweringStrategyV3::PeriodicRun,
        CountV3Strategy::DirectExactMask => LoweringStrategyV3::DirectExactMask,
    };
    let manifest = AotCountRecipeManifestV3 {
        recipe_schema_version: recipe.schema_version(),
        optimizer_version: recipe.optimizer_version(),
        tuning_class_id: recipe.tuning_class().wire_id(),
        strategy_id: recipe.strategy().wire_id(),
        schedule_id: recipe.schedule_id().wire_id(),
        register_plan_id: recipe.register_plan_id().wire_id(),
        required_isa_id: recipe.required_isa().wire_id(),
        successor_mode_id: recipe.successor_mode().wire_id(),
        filter_len: u8::try_from(filters.len()).expect("at most four filters"),
        confirmation_len: u8::try_from(order.len()).expect("bounded literal width"),
        sparse_group_count: u8::try_from(groups.len()).expect("at most four groups"),
        mismatch_stride: recipe.mismatch_stride(),
        match_stride: recipe.match_stride(),
        periodic_stride: recipe.periodic_stride(),
        filter_offsets,
        confirmation_order,
        sparse_group_first_offsets,
        sparse_group_lengths,
        literal_identity: *recipe.literal_identity(),
        recipe_identity: *recipe.identity().as_bytes(),
        canonical_recipe,
    };
    Ok((
        LoweringRecipeV3 {
            strategy,
            required_isa: recipe.required_isa(),
            filter,
            confirmation_order,
            confirmation_len: u8::try_from(order.len()).expect("bounded literal width"),
            periodic_stride: recipe.periodic_stride(),
        },
        manifest,
    ))
}

fn minimum_period_v3(literal: &[u8]) -> usize {
    if literal.is_empty() {
        return 0;
    }
    for period in 1..=literal.len() {
        if literal[period..]
            .iter()
            .zip(&literal[..literal.len() - period])
            .all(|(right, left)| right == left)
        {
            return period;
        }
    }
    literal.len()
}

fn preflight_program_dimensions_v3(
    program: &ExactAggregateProgram<Count>,
) -> Result<usize, CountAotError> {
    if program.output() != AggregateOutput::Count {
        return Err(CountAotError::Unsupported {
            reason: CountAotUnsupported::Output,
        });
    }
    let literal_len = program.literal().len();
    let support = SUPPORTED_AOT_COUNT_BACKEND_TUPLES_V3[0];
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
pub(crate) fn prospective_v3(literal_len: usize) -> Result<ProspectiveV3, CountAotError> {
    let (instruction_upper_bound, labels, relocations) = match literal_len {
        0 => (24_usize, 3_usize, 4_usize),
        1 => (96, 8, 20),
        _ => {
            let chunks = literal_len / 8;
            let tail = literal_len % 8;
            let confirmation_units = chunks
                .checked_add(tail)
                .ok_or(arithmetic_prospective_v3())?;
            (
                // The non-periodic specialized template contains a sealed
                // 128-start primary batch. Its worst case spells out eight
                // block-local staged refinements and candidate recoveries so
                // every false-positive block continues without overlapping
                // any already-proved start.
                1_024_usize
                    .checked_add(
                        literal_len
                            .checked_mul(8)
                            .ok_or(arithmetic_prospective_v3())?,
                    )
                    .ok_or(arithmetic_prospective_v3())?,
                48,
                160_usize
                    .checked_add(
                        confirmation_units
                            .checked_mul(3)
                            .ok_or(arithmetic_prospective_v3())?,
                    )
                    .ok_or(arithmetic_prospective_v3())?,
            )
        }
    };
    let code_bytes = instruction_upper_bound
        .checked_mul(4)
        .ok_or(arithmetic_prospective_v3())?;
    let identity_bytes_hashed = identity_bytes_upper_bound_v3(code_bytes, labels, relocations)?;
    let audit_work = audit_work_upper_bound_v3(code_bytes, labels, relocations, literal_len)?;
    let audit_scratch = audit_scratch_upper_bound_v3(code_bytes, labels, relocations)?;
    let assembler_scratch = assembler_scratch_upper_bound_v3(code_bytes, labels, relocations)?;
    let image_backing = image_backing_bytes_for_capacities_v3(code_bytes, labels, relocations)?;
    let image_assembly_scratch =
        image_assembly_scratch_for_capacities_v3(code_bytes, labels, relocations)?;
    let emission_scratch = assembler_scratch.max(image_assembly_scratch);
    let candidate_audit_scratch =
        emit_audit_phase_scratch_v3(audit_scratch, image_backing, EmitAuditPhaseV3::Candidate)?;
    let sealed_audit_scratch =
        emit_audit_phase_scratch_v3(audit_scratch, image_backing, EmitAuditPhaseV3::Sealed)?;
    let initial_identity_scratch =
        emit_identity_phase_scratch_v3(image_backing, EmitIdentityPhaseV3::InitialLength)?;
    let sealed_identity_length_scratch =
        emit_identity_phase_scratch_v3(image_backing, EmitIdentityPhaseV3::SealedLength)?;
    let sealed_identity_hash_scratch =
        emit_identity_phase_scratch_v3(image_backing, EmitIdentityPhaseV3::SealedHash)?;
    let scratch = emission_scratch
        .max(candidate_audit_scratch)
        .max(sealed_audit_scratch)
        .max(initial_identity_scratch)
        .max(sealed_identity_length_scratch)
        .max(sealed_identity_hash_scratch);
    let persistent = image_backing
        .checked_add(to_u64(
            size_of::<AotCountImageV3>(),
            CountAotArithmeticSite::Prospective,
        )?)
        .ok_or(arithmetic_prospective_v3())?;
    // Literal preparation covers sealed-recipe validation, manifest
    // validation/copy, and width-specific canonical setup/confirmation
    // traversals.
    let recipe_validation_work = recipe_validation_work_envelope_v3(literal_len)?.total;
    const MANIFEST_AND_CANONICAL_WORK_PER_LITERAL_BYTE_V3: u64 = 1 + 8;
    const LITERAL_PREPARATION_FIXED_WORK_V3: u64 = 16 + 16 + 32;
    let literal = to_u64(literal_len, CountAotArithmeticSite::Prospective)?;
    let literal_preparation_work = literal
        .checked_mul(MANIFEST_AND_CANONICAL_WORK_PER_LITERAL_BYTE_V3)
        .and_then(|work| work.checked_add(recipe_validation_work))
        .and_then(|work| work.checked_add(LITERAL_PREPARATION_FIXED_WORK_V3))
        .ok_or(arithmetic_prospective_v3())?;
    let label_emission_work = to_u64(labels, CountAotArithmeticSite::Prospective)?
        .checked_mul(2)
        .ok_or(arithmetic_prospective_v3())?;
    let relocation_emission_work = to_u64(relocations, CountAotArithmeticSite::Prospective)?
        .checked_mul(2)
        .ok_or(arithmetic_prospective_v3())?;
    let emission_upper = to_u64(instruction_upper_bound, CountAotArithmeticSite::Prospective)?
        .checked_add(label_emission_work)
        .and_then(|work| work.checked_add(relocation_emission_work))
        .and_then(|work| work.checked_add(literal_preparation_work))
        .ok_or(arithmetic_prospective_v3())?;
    let label_order = label_order_work_upper_bound_v3(labels)?;
    let labels_u64 = to_u64(labels, CountAotArithmeticSite::Prospective)?;
    let relocations_u64 = to_u64(relocations, CountAotArithmeticSite::Prospective)?;
    let identity_structural = identity_structural_traversal_work_v3(labels_u64, relocations_u64)
        .ok_or(arithmetic_prospective_v3())?;
    // Initial length, sealed length, and sealed hash each traverse every
    // encoder field. Only the hash pass consumes the encoded bytes.
    const DIRECT_IDENTITY_STRUCTURAL_PASSES_V3: u64 = 3;
    const DIRECT_IDENTITY_HASH_PASSES_V3: u64 = 1;
    const DIRECT_IDENTITY_HASH_FINALIZATION_WORK_V3: u64 = 8;
    const AUDIT_PASSES_V3: u64 = 2;
    const RESOURCE_ADMISSION_SCALAR_WORK_V3: u64 = 7 * 3;
    const IMAGE_FIELD_CONSTRUCTION_WORK_V3: u64 = 12 + 14 + 10;
    const MANIFEST_FILTER_AND_LAYOUT_SCALAR_WORK_V3: u64 = 5 + 5;
    const CAPACITY_AND_PERSISTENT_SEAL_WORK_V3: u64 = 18;
    const SCRATCH_PHASE_DERIVATION_AND_SEAL_WORK_V3: u64 = 6 * 8;
    const FINAL_RECEIPT_AND_AUDIT_SEAL_WORK_V3: u64 = 24;
    let named_scalar_work = RESOURCE_ADMISSION_SCALAR_WORK_V3
        .checked_add(IMAGE_FIELD_CONSTRUCTION_WORK_V3)
        .and_then(|work| work.checked_add(MANIFEST_FILTER_AND_LAYOUT_SCALAR_WORK_V3))
        .and_then(|work| work.checked_add(CAPACITY_AND_PERSISTENT_SEAL_WORK_V3))
        .and_then(|work| work.checked_add(SCRATCH_PHASE_DERIVATION_AND_SEAL_WORK_V3))
        .and_then(|work| work.checked_add(FINAL_RECEIPT_AND_AUDIT_SEAL_WORK_V3))
        .ok_or(arithmetic_prospective_v3())?;
    let work = emission_upper
        .checked_add(label_order.total)
        .and_then(|value| {
            value
                .checked_add(identity_structural.checked_mul(DIRECT_IDENTITY_STRUCTURAL_PASSES_V3)?)
        })
        .and_then(|value| {
            value.checked_add(identity_bytes_hashed.checked_mul(DIRECT_IDENTITY_HASH_PASSES_V3)?)
        })
        .and_then(|value| value.checked_add(DIRECT_IDENTITY_HASH_FINALIZATION_WORK_V3))
        .and_then(|value| value.checked_add(audit_work.checked_mul(AUDIT_PASSES_V3)?))
        .and_then(|value| value.checked_add(named_scalar_work))
        .ok_or(arithmetic_prospective_v3())?;
    Ok(ProspectiveV3 {
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
        recipe_validation_work,
        work,
        scratch,
        persistent,
        scratch_limit: MAX_SCRATCH_BYTES_V3,
        persistent_limit: MAX_PERSISTENT_BYTES_V3,
    })
}

type EmissionBuildInlineStateV3 = (
    &'static ExactAggregateProgram<Count>,
    CountEmitLimitsV3,
    usize,
    ProspectiveV3,
    &'static [u8],
    Option<CandidateFilterV3>,
    AotCountLiteralManifestV3,
    CountAotError,
);
type CanonicalTemplateCallerInlineStateV3 = (
    EmissionBuildInlineStateV3,
    Result<FinalizedV3, CountAotError>,
);
type CanonicalEmissionInlineStateV3 = (
    CanonicalTemplateCallerInlineStateV3,
    AssemblerV3,
    [LabelV3; 10],
    [usize; 8],
    [u8; 16],
    [u16; 4],
    [u32; 4],
    [u64; 4],
    CountAotError,
);
type FinalizeRelocationInlineStateV3 = (
    CanonicalTemplateCallerInlineStateV3,
    AssemblerV3,
    ExactVec<RelocationV3>,
    core::ops::Range<usize>,
    FixupV3,
    RelocationV3,
    [usize; 4],
    [u32; 4],
    CountAotError,
);
type FinalizeLabelCollectionInlineStateV3 = (
    CanonicalTemplateCallerInlineStateV3,
    AssemblerV3,
    ExactVec<RelocationV3>,
    ExactVec<CodeLabelV3>,
    LabelRecordV3,
    CodeLabelV3,
    [usize; 4],
    CountAotError,
);
type LabelOrderInlineStateV3 = (
    CanonicalTemplateCallerInlineStateV3,
    AssemblerV3,
    ExactVec<RelocationV3>,
    ExactVec<CodeLabelV3>,
    LabelOrderWorkV3,
    CodeLabelV3,
    [usize; 4],
    [u64; 4],
    CountAotError,
);
type FinalizeReturnInlineStateV3 = (
    CanonicalTemplateCallerInlineStateV3,
    AssemblerV3,
    ExactVec<RelocationV3>,
    ExactVec<CodeLabelV3>,
    FinalizedV3,
    [usize; 6],
    [u32; 4],
    CountAotError,
);
type ImageAssemblyInlineStateV3 = (
    EmissionBuildInlineStateV3,
    FinalizedV3,
    AotCountImageV3,
    AotCountImageLayoutV3,
    AotCountImageStatsV3,
    AotCountImageBuildReceiptV3,
    AotCountTargetSpec,
    [usize; 8],
    [u32; 8],
    [u64; 8],
    CountAotError,
);
type CandidateAuditCallerInlineStateV3 = (
    EmissionBuildInlineStateV3,
    AotCountImageV3,
    CountAuditReportV3,
    [usize; 4],
    [u64; 8],
    CountAotError,
);
type SealedAuditCallerInlineStateV3 = (
    EmissionBuildInlineStateV3,
    AotCountImageV3,
    CountAuditReportV3,
    CountAuditReportV3,
    AotCountArtifactIdentityV3,
    [usize; 4],
    [u64; 8],
    CountAotError,
);
type InitialIdentityCallerInlineStateV3 = (
    EmissionBuildInlineStateV3,
    AotCountImageV3,
    u64,
    CountAotError,
);
type SealedIdentityLengthCallerInlineStateV3 = (
    EmissionBuildInlineStateV3,
    AotCountImageV3,
    CountAuditReportV3,
    u64,
    CountAotError,
);
type SealedIdentityHashCallerInlineStateV3 = (
    EmissionBuildInlineStateV3,
    AotCountImageV3,
    CountAuditReportV3,
    AotCountArtifactIdentityV3,
    u64,
    CountAotError,
);

#[derive(Clone, Copy)]
enum EmissionPhaseV3 {
    Canonical,
    FinalizeRelocations,
    CollectLabels,
    OrderLabels,
    FinalizeReturn,
}

#[derive(Clone, Copy)]
enum EmitAuditPhaseV3 {
    Candidate,
    Sealed,
}

#[derive(Clone, Copy)]
enum EmitIdentityPhaseV3 {
    InitialLength,
    SealedLength,
    SealedHash,
}

#[derive(Clone, Copy)]
enum EmitImagePhaseV3 {
    InitialIdentityLength,
    CandidateAudit,
    SealedIdentityLength,
    SealedIdentityHash,
    SealedAudit,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EmitImagePhaseForTestV3 {
    InitialIdentityLength,
    CandidateAudit,
    SealedIdentityLength,
    SealedIdentityHash,
    SealedAudit,
}

fn image_backing_bytes_for_capacities_v3(
    code_capacity_bytes: usize,
    label_capacity: usize,
    relocation_capacity: usize,
) -> Result<u64, CountAotError> {
    let bytes = code_capacity_bytes
        .checked_add(
            label_capacity
                .checked_mul(size_of::<CodeLabelV3>())
                .ok_or(arithmetic_prospective_v3())?,
        )
        .and_then(|value| {
            value.checked_add(relocation_capacity.checked_mul(size_of::<RelocationV3>())?)
        })
        .ok_or(arithmetic_prospective_v3())?;
    to_u64(bytes, CountAotArithmeticSite::Prospective)
}

pub(crate) fn image_assembly_scratch_for_capacities_v3(
    code_capacity_bytes: usize,
    label_capacity: usize,
    relocation_capacity: usize,
) -> Result<u64, CountAotError> {
    image_backing_bytes_for_capacities_v3(code_capacity_bytes, label_capacity, relocation_capacity)?
        .checked_add(to_u64(
            size_of::<ImageAssemblyInlineStateV3>(),
            CountAotArithmeticSite::Prospective,
        )?)
        .ok_or(arithmetic_prospective_v3())
}

fn emit_audit_phase_scratch_v3(
    audit_scratch: u64,
    image_backing: u64,
    phase: EmitAuditPhaseV3,
) -> Result<u64, CountAotError> {
    let (caller_inline, wrapper_inline) = match phase {
        EmitAuditPhaseV3::Candidate => (
            size_of::<CandidateAuditCallerInlineStateV3>(),
            audit_candidate_wrapper_inline_bytes_v3(),
        ),
        EmitAuditPhaseV3::Sealed => (
            size_of::<SealedAuditCallerInlineStateV3>(),
            audit_public_wrapper_inline_bytes_v3(),
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
        .ok_or(arithmetic_prospective_v3())
}

fn emit_identity_phase_scratch_v3(
    image_backing: u64,
    phase: EmitIdentityPhaseV3,
) -> Result<u64, CountAotError> {
    let caller_inline = match phase {
        EmitIdentityPhaseV3::InitialLength => size_of::<InitialIdentityCallerInlineStateV3>(),
        EmitIdentityPhaseV3::SealedLength => size_of::<SealedIdentityLengthCallerInlineStateV3>(),
        EmitIdentityPhaseV3::SealedHash => size_of::<SealedIdentityHashCallerInlineStateV3>(),
    };
    image_backing
        .checked_add(to_u64(caller_inline, CountAotArithmeticSite::Prospective)?)
        .and_then(|bytes| {
            bytes.checked_add(
                to_u64(
                    identity_scratch_bytes_v3(),
                    CountAotArithmeticSite::Prospective,
                )
                .ok()?,
            )
        })
        .ok_or(arithmetic_prospective_v3())
}

pub(crate) fn assembler_scratch_upper_bound_v3(
    code_bytes: usize,
    labels: usize,
    relocations: usize,
) -> Result<u64, CountAotError> {
    assembler_scratch_for_capacities_v3(code_bytes, labels, relocations, labels, relocations)
}

pub(crate) fn assembler_scratch_for_capacities_v3(
    code_capacity_bytes: usize,
    label_record_capacity: usize,
    fixup_capacity: usize,
    output_label_capacity: usize,
    output_relocation_capacity: usize,
) -> Result<u64, CountAotError> {
    let phases = [
        observed_emission_phase_scratch_v3(
            code_capacity_bytes,
            label_record_capacity,
            fixup_capacity,
            0,
            0,
            EmissionPhaseV3::Canonical,
        )?,
        observed_emission_phase_scratch_v3(
            code_capacity_bytes,
            label_record_capacity,
            fixup_capacity,
            0,
            output_relocation_capacity,
            EmissionPhaseV3::FinalizeRelocations,
        )?,
        observed_emission_phase_scratch_v3(
            code_capacity_bytes,
            label_record_capacity,
            fixup_capacity,
            output_label_capacity,
            output_relocation_capacity,
            EmissionPhaseV3::CollectLabels,
        )?,
        observed_emission_phase_scratch_v3(
            code_capacity_bytes,
            label_record_capacity,
            fixup_capacity,
            output_label_capacity,
            output_relocation_capacity,
            EmissionPhaseV3::OrderLabels,
        )?,
        observed_emission_phase_scratch_v3(
            code_capacity_bytes,
            label_record_capacity,
            fixup_capacity,
            output_label_capacity,
            output_relocation_capacity,
            EmissionPhaseV3::FinalizeReturn,
        )?,
    ];
    phases
        .into_iter()
        .max()
        .ok_or(CountAotError::InternalInvariant {
            at: "v3 emission phase set",
        })
}

pub(crate) const fn assembler_scratch_derivation_work_upper_bound_v3() -> u64 {
    // Five phase derivations, each with four capacity multiplications, five
    // checked additions (including inline state), and one result conversion;
    // four comparisons select the maximum.
    (5 * (4 + 5 + 1)) + 4
}

fn observed_emission_phase_scratch_v3(
    code_capacity_bytes: usize,
    label_record_capacity: usize,
    fixup_capacity: usize,
    output_label_capacity: usize,
    output_relocation_capacity: usize,
    phase: EmissionPhaseV3,
) -> Result<u64, CountAotError> {
    let backing = code_capacity_bytes
        .checked_add(
            label_record_capacity
                .checked_mul(size_of::<LabelRecordV3>())
                .ok_or(arithmetic_prospective_v3())?,
        )
        .and_then(|bytes| bytes.checked_add(fixup_capacity.checked_mul(size_of::<FixupV3>())?))
        .and_then(|bytes| {
            bytes.checked_add(output_label_capacity.checked_mul(size_of::<CodeLabelV3>())?)
        })
        .and_then(|bytes| {
            bytes.checked_add(output_relocation_capacity.checked_mul(size_of::<RelocationV3>())?)
        })
        .ok_or(arithmetic_prospective_v3())?;
    let inline = match phase {
        EmissionPhaseV3::Canonical => size_of::<CanonicalEmissionInlineStateV3>(),
        EmissionPhaseV3::FinalizeRelocations => size_of::<FinalizeRelocationInlineStateV3>(),
        EmissionPhaseV3::CollectLabels => size_of::<FinalizeLabelCollectionInlineStateV3>(),
        EmissionPhaseV3::OrderLabels => size_of::<LabelOrderInlineStateV3>(),
        EmissionPhaseV3::FinalizeReturn => size_of::<FinalizeReturnInlineStateV3>(),
    };
    to_u64(
        backing
            .checked_add(inline)
            .ok_or(arithmetic_prospective_v3())?,
        CountAotArithmeticSite::Prospective,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LabelOrderWorkV3 {
    pub(crate) comparisons: u64,
    pub(crate) moves: u64,
    pub(crate) placements: u64,
    pub(crate) total: u64,
}

pub(crate) fn label_order_work_upper_bound_v3(
    labels: usize,
) -> Result<LabelOrderWorkV3, CountAotError> {
    let labels = to_u64(labels, CountAotArithmeticSite::Prospective)?;
    let prior = labels.saturating_sub(1);
    let pairs = labels
        .checked_mul(prior)
        .and_then(|value| value.checked_div(2))
        .ok_or(arithmetic_prospective_v3())?;
    let total = pairs
        .checked_add(pairs)
        .and_then(|value| value.checked_add(prior))
        .ok_or(arithmetic_prospective_v3())?;
    Ok(LabelOrderWorkV3 {
        comparisons: pairs,
        moves: pairs,
        placements: prior,
        total,
    })
}

pub(crate) fn identity_structural_traversal_work_v3(labels: u64, relocations: u64) -> Option<u64> {
    // Keep this synchronized with every fixed scalar/raw write in
    // `encode_artifact_identity_v3`, including the complete audit receipt.
    const FIXED_ENCODER_WRITES_V3: u64 = 112;
    const WRITES_PER_LABEL_V3: u64 = 2;
    const WRITES_PER_RELOCATION_V3: u64 = 4;
    FIXED_ENCODER_WRITES_V3
        .checked_add(labels.checked_mul(WRITES_PER_LABEL_V3)?)
        .and_then(|work| work.checked_add(relocations.checked_mul(WRITES_PER_RELOCATION_V3)?))
}

fn observe_emit_image_phase_scratch_v3(
    image: &AotCountImageV3,
    prospective: ProspectiveV3,
    phase: EmitImagePhaseV3,
) -> Result<u64, CountAotError> {
    // Capacity is allocator-owned state. Re-read it immediately before every
    // identity or audit phase rather than trusting the identity-bound receipt.
    let image_backing = image_backing_bytes_for_capacities_v3(
        image.code.capacity(),
        image.labels.capacity(),
        image.relocations.capacity(),
    )?;
    if image_backing > prospective.image_backing {
        return Err(CountAotError::InternalInvariant {
            at: "v3 image backing prospective",
        });
    }
    let (observed, expected) = match phase {
        EmitImagePhaseV3::InitialIdentityLength => (
            emit_identity_phase_scratch_v3(image_backing, EmitIdentityPhaseV3::InitialLength)?,
            prospective.initial_identity_scratch,
        ),
        EmitImagePhaseV3::CandidateAudit => (
            emit_audit_phase_scratch_v3(
                prospective.audit_scratch,
                image_backing,
                EmitAuditPhaseV3::Candidate,
            )?,
            prospective.candidate_audit_scratch,
        ),
        EmitImagePhaseV3::SealedIdentityLength => (
            emit_identity_phase_scratch_v3(image_backing, EmitIdentityPhaseV3::SealedLength)?,
            prospective.sealed_identity_length_scratch,
        ),
        EmitImagePhaseV3::SealedIdentityHash => (
            emit_identity_phase_scratch_v3(image_backing, EmitIdentityPhaseV3::SealedHash)?,
            prospective.sealed_identity_hash_scratch,
        ),
        EmitImagePhaseV3::SealedAudit => (
            emit_audit_phase_scratch_v3(
                prospective.audit_scratch,
                image_backing,
                EmitAuditPhaseV3::Sealed,
            )?,
            prospective.sealed_audit_scratch,
        ),
    };
    if observed > expected {
        return Err(CountAotError::InternalInvariant {
            at: "v3 image phase scratch prospective",
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
pub(crate) fn observe_emit_image_phase_scratch_for_test_v3(
    program: &ExactAggregateProgram<Count>,
    image: &AotCountImageV3,
    phase: EmitImagePhaseForTestV3,
    scratch_limit: u64,
) -> Result<u64, CountAotError> {
    let mut prospective = prospective_v3(preflight_program_dimensions_v3(program)?)?;
    prospective.scratch_limit = prospective.scratch_limit.min(scratch_limit);
    let phase = match phase {
        EmitImagePhaseForTestV3::InitialIdentityLength => EmitImagePhaseV3::InitialIdentityLength,
        EmitImagePhaseForTestV3::CandidateAudit => EmitImagePhaseV3::CandidateAudit,
        EmitImagePhaseForTestV3::SealedIdentityLength => EmitImagePhaseV3::SealedIdentityLength,
        EmitImagePhaseForTestV3::SealedIdentityHash => EmitImagePhaseV3::SealedIdentityHash,
        EmitImagePhaseForTestV3::SealedAudit => EmitImagePhaseV3::SealedAudit,
    };
    observe_emit_image_phase_scratch_v3(image, prospective, phase)
}

pub(crate) fn canonical_template_v3(
    literal: &[u8],
    recipe: LoweringRecipeV3,
    prospective: ProspectiveV3,
) -> Result<FinalizedV3, CountAotError> {
    let mut assembler = AssemblerV3::new(prospective)?;
    let entry = assembler.new_label(LabelKindV3::Entry)?;
    let done = assembler.new_label(LabelKindV3::Success)?;
    assembler.bind(entry)?;
    if literal.is_empty() {
        emit_empty_v3(&mut assembler, done)?;
    } else {
        match recipe.required_isa {
            CountV3RequiredIsa::Aarch64Neon128 => match literal.len() {
                1 => emit_single_v3(&mut assembler, literal[0], None, done)?,
                _ => {
                    let filter = recipe.filter.ok_or(CountAotError::InternalInvariant {
                        at: "missing v3 candidate filter",
                    })?;
                    match recipe.strategy {
                        LoweringStrategyV3::Incumbent => {
                            emit_multi_incumbent_v3(&mut assembler, literal, filter, None, done)?;
                        }
                        LoweringStrategyV3::DirectExactMask => {
                            emit_direct_exact_mask_v3(&mut assembler, literal, filter, None, done)?;
                        }
                        LoweringStrategyV3::SparseRareColumns
                        | LoweringStrategyV3::EndpointDense => emit_multi_specialized_v3(
                            &mut assembler,
                            literal,
                            filter,
                            recipe.confirmation_order(),
                            recipe.strategy,
                            None,
                            done,
                        )?,
                        LoweringStrategyV3::PeriodicRun => emit_periodic_neon_v3(
                            &mut assembler,
                            literal,
                            filter,
                            recipe.confirmation_order(),
                            recipe.periodic_stride,
                            None,
                            done,
                        )?,
                    }
                }
            },
            CountV3RequiredIsa::Aarch64SveVl16 | CountV3RequiredIsa::Aarch64Sve2Vl16 => {
                let sve_tail = Some(
                    if recipe.required_isa == CountV3RequiredIsa::Aarch64Sve2Vl16 {
                        HybridSveTailV3::Sve2
                    } else {
                        HybridSveTailV3::Sve
                    },
                );
                if literal.len() == 1 {
                    emit_single_v3(&mut assembler, literal[0], sve_tail, done)?;
                } else {
                    let filter = recipe.filter.ok_or(CountAotError::InternalInvariant {
                        at: "missing v3 hybrid candidate filter",
                    })?;
                    match recipe.strategy {
                        LoweringStrategyV3::Incumbent => {
                            emit_multi_incumbent_v3(
                                &mut assembler,
                                literal,
                                filter,
                                sve_tail,
                                done,
                            )?;
                        }
                        LoweringStrategyV3::DirectExactMask => {
                            emit_direct_exact_mask_v3(
                                &mut assembler,
                                literal,
                                filter,
                                sve_tail,
                                done,
                            )?;
                        }
                        LoweringStrategyV3::SparseRareColumns
                        | LoweringStrategyV3::EndpointDense => emit_multi_specialized_v3(
                            &mut assembler,
                            literal,
                            filter,
                            recipe.confirmation_order(),
                            recipe.strategy,
                            sve_tail,
                            done,
                        )?,
                        LoweringStrategyV3::PeriodicRun => emit_periodic_neon_v3(
                            &mut assembler,
                            literal,
                            filter,
                            recipe.confirmation_order(),
                            recipe.periodic_stride,
                            sve_tail,
                            done,
                        )?,
                    }
                }
            }
        }
    }
    assembler.bind(done)?;
    assembler.store64(X13, X2, 0)?;
    assembler.mov_imm64_minimal(X0, 0)?;
    assembler.ret()?;
    assembler.finalize()
}

fn emit_empty_v3(assembler: &mut AssemblerV3, done: LabelV3) -> Result<(), CountAotError> {
    let overflow = assembler.new_label(LabelKindV3::Overflow)?;
    assembler.mov_imm64_minimal(X10, u64::MAX)?;
    assembler.cmp_reg64(X1, X10)?;
    assembler.branch_cond(ConditionV3::Equal, overflow)?;
    assembler.add_imm(X13, X1, 1)?;
    assembler.branch(done)?;
    assembler.bind(overflow)?;
    assembler.mov_imm64_minimal(X0, 1)?;
    assembler.ret()
}

/// Feature-exact mixed register plan: Advanced SIMD owns the hot loops and
/// the final complete 16-start block is consumed by a real SVE predicate
/// kernel. The lower 128 bits of Z0/Z1 alias V0/V1, but the mixed graph never
/// returns to an Advanced SIMD body after entering this tail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HybridSveTailV3 {
    Sve,
    Sve2,
}

impl HybridSveTailV3 {
    const fn is_sve2(self) -> bool {
        matches!(self, Self::Sve2)
    }
}

fn emit_single_v3(
    assembler: &mut AssemblerV3,
    literal: u8,
    sve_tail: Option<HybridSveTailV3>,
    done: LabelV3,
) -> Result<(), CountAotError> {
    let vector64 = assembler.new_label(LabelKindV3::VectorLoop)?;
    let vector16 = assembler.new_label(LabelKindV3::VectorLoop)?;
    let tail = assembler.new_label(LabelKindV3::ScalarTail)?;
    let scalar = if sve_tail.is_some() {
        assembler.new_label(LabelKindV3::ScalarTail)?
    } else {
        tail
    };
    let tail_miss = assembler.new_label(LabelKindV3::Miss)?;
    assembler.mov_imm64_minimal(X13, 0)?;
    assembler.mov_imm64_minimal(X3, 0)?;
    assembler.mov_imm64_minimal(X10, u64::from(literal))?;
    assembler.dup_byte16(1, X10)?;
    // Hoisted: v1 rematerialized 256 in every vector iteration.
    assembler.mov_imm64_minimal(X5, 256)?;
    assembler.bind(vector64)?;
    assembler.sub_reg(X6, X1, X3)?;
    assembler.cmp_imm64(X6, 64)?;
    assembler.branch_cond(ConditionV3::CarryClear, vector16)?;
    assembler.add_reg(X15, X0, X3)?;
    assembler.load_vector128_offset(0, X15, 0)?;
    assembler.load_vector128_offset(2, X15, 16)?;
    assembler.load_vector128_offset(3, X15, 32)?;
    assembler.load_vector128_offset(4, X15, 48)?;
    assembler.compare_equal_bytes16(0, 0, 1)?;
    assembler.compare_equal_bytes16(2, 2, 1)?;
    assembler.compare_equal_bytes16(3, 3, 1)?;
    assembler.compare_equal_bytes16(4, 4, 1)?;
    assembler.add_bytes16(0, 0, 2)?;
    assembler.add_bytes16(0, 0, 3)?;
    assembler.add_bytes16(0, 0, 4)?;
    assembler.add_across_bytes16(0, 0)?;
    assembler.move_vector_byte_to32(X6, 0)?;
    assembler.sub_reg(X6, X5, X6)?;
    assembler.and_low_bits(X6, X6, 8)?;
    assembler.add_reg(X13, X13, X6)?;
    assembler.add_imm(X3, X3, 64)?;
    assembler.branch(vector64)?;
    assembler.bind(vector16)?;
    assembler.sub_reg(X6, X1, X3)?;
    assembler.cmp_imm64(X6, SIMD_CANDIDATE_STARTS_V3)?;
    assembler.branch_cond(ConditionV3::CarryClear, scalar)?;
    if sve_tail.is_some() {
        assembler.cmp_imm64(X6, SIMD_CANDIDATE_STARTS_V3)?;
        assembler.branch_cond(ConditionV3::Equal, tail)?;
    }
    assembler.add_reg(X15, X0, X3)?;
    assembler.load_vector128(0, X15)?;
    assembler.compare_equal_bytes16(0, 0, 1)?;
    assembler.add_across_bytes16(0, 0)?;
    assembler.move_vector_byte_to32(X6, 0)?;
    assembler.sub_reg(X6, X5, X6)?;
    assembler.and_low_bits(X6, X6, 8)?;
    assembler.add_reg(X13, X13, X6)?;
    assembler.add_imm(X3, X3, SIMD_CANDIDATE_STARTS_V3)?;
    assembler.branch(vector16)?;
    assembler.bind(tail)?;
    if let Some(sve_tail) = sve_tail {
        emit_hybrid_sve_exact_tail_v3(
            assembler,
            core::slice::from_ref(&literal),
            sve_tail,
            scalar,
            done,
        )?;
        assembler.bind(scalar)?;
    }
    assembler.cmp_reg64(X3, X1)?;
    assembler.branch_cond(ConditionV3::CarrySet, done)?;
    assembler.load_byte_reg(X6, X0, X3)?;
    assembler.cmp_reg32(X6, X10)?;
    assembler.branch_cond(ConditionV3::NotEqual, tail_miss)?;
    assembler.add_imm(X13, X13, 1)?;
    assembler.bind(tail_miss)?;
    assembler.add_imm(X3, X3, 1)?;
    assembler.branch(scalar)
}

/// Count an exact, self-non-overlapping literal directly from equality masks.
///
/// The optimizer admits this schedule only for widths two through four when
/// every byte offset is a filter column and the KMP minimum period equals the
/// full width. Consequently every equality lane is a semantic match and no
/// lane recovery or per-candidate confirmation is required.
fn emit_direct_exact_mask_v3(
    assembler: &mut AssemblerV3,
    literal: &[u8],
    filter: CandidateFilterV3,
    sve_tail: Option<HybridSveTailV3>,
    done: LabelV3,
) -> Result<(), CountAotError> {
    let vector64 = assembler.new_label(LabelKindV3::VectorLoop)?;
    let vector64_advance = if filter.len >= 3 {
        Some(assembler.new_label(LabelKindV3::Internal)?)
    } else {
        None
    };
    let vector16 = assembler.new_label(LabelKindV3::VectorLoop)?;
    let tail = assembler.new_label(LabelKindV3::ScalarTail)?;
    let scalar = if sve_tail.is_some() {
        assembler.new_label(LabelKindV3::ScalarTail)?
    } else {
        tail
    };
    let tail_miss = assembler.new_label(LabelKindV3::Miss)?;
    let width = u16::try_from(literal.len()).map_err(|_| CountAotError::ArithmeticOverflow {
        site: CountAotArithmeticSite::CodeOffset,
    })?;
    let value_registers = [X10, X11, X12, X14];
    let vector_registers = [2_u8, 3, 16, 17];
    let pointer_registers = [X8, X9, X16, X17];
    let block_masks = [0_u8, 18, 19, 20];

    assembler.mov_imm64_minimal(X13, 0)?;
    assembler.cmp_imm64(X1, width)?;
    assembler.branch_cond(ConditionV3::CarryClear, done)?;
    assembler.sub_imm(X4, X1, width)?;
    assembler.mov_imm64_minimal(X3, 0)?;
    for index in 0..usize::from(filter.len) {
        let offset = usize::from(filter.offsets[index]);
        assembler.mov_imm64_minimal(value_registers[index], u64::from(literal[offset]))?;
        assembler.dup_byte16(vector_registers[index], value_registers[index])?;
    }
    assembler.mov_imm64_minimal(X5, 256)?;

    assembler.bind(vector64)?;
    assembler.cmp_reg64(X3, X4)?;
    assembler.branch_cond(ConditionV3::Higher, done)?;
    assembler.sub_reg(X6, X4, X3)?;
    assembler.cmp_imm64(X6, 63)?;
    assembler.branch_cond(ConditionV3::CarryClear, vector16)?;
    assembler.add_reg(X15, X0, X3)?;
    for index in 0..usize::from(filter.len) {
        assembler.add_imm(
            pointer_registers[index],
            X15,
            u16::from(filter.offsets[index]),
        )?;
    }
    if filter.len < 3 {
        for (block, mask) in block_masks.into_iter().enumerate() {
            let block_offset = u16::try_from(block * usize::from(SIMD_CANDIDATE_STARTS_V3))
                .expect("four direct-mask blocks");
            for index in 0..usize::from(filter.len) {
                let destination = if index == 0 { mask } else { 1 };
                assembler.load_vector128_offset(
                    destination,
                    pointer_registers[index],
                    block_offset,
                )?;
                assembler.compare_equal_bytes16(
                    destination,
                    destination,
                    vector_registers[index],
                )?;
                if index != 0 {
                    assembler.and_bytes16(mask, mask, destination)?;
                }
            }
        }
    } else {
        // Form two-column masks for the whole 64-start batch first. If their
        // union is empty, later exact columns and the horizontal count are
        // provably unnecessary. Dense batches retain the direct count path.
        for (block, mask) in block_masks.into_iter().enumerate() {
            let block_offset = u16::try_from(block * usize::from(SIMD_CANDIDATE_STARTS_V3))
                .expect("four direct-mask blocks");
            assembler.load_vector128_offset(mask, pointer_registers[0], block_offset)?;
            assembler.compare_equal_bytes16(mask, mask, vector_registers[0])?;
            assembler.load_vector128_offset(1, pointer_registers[1], block_offset)?;
            assembler.compare_equal_bytes16(1, 1, vector_registers[1])?;
            assembler.and_bytes16(mask, mask, 1)?;
        }
        assembler.or_bytes16(21, block_masks[0], block_masks[1])?;
        assembler.or_bytes16(22, block_masks[2], block_masks[3])?;
        assembler.or_bytes16(21, 21, 22)?;
        assembler.unsigned_max_across_bytes16(1, 21)?;
        assembler.move_vector_byte_to32(X6, 1)?;
        assembler.cmp_imm64(X6, 0)?;
        assembler.branch_cond(
            ConditionV3::Equal,
            vector64_advance.expect("wide direct advance"),
        )?;
        for index in 2..usize::from(filter.len) {
            for (block, mask) in block_masks.into_iter().enumerate() {
                let block_offset = u16::try_from(block * usize::from(SIMD_CANDIDATE_STARTS_V3))
                    .expect("four direct-mask blocks");
                assembler.load_vector128_offset(1, pointer_registers[index], block_offset)?;
                assembler.compare_equal_bytes16(1, 1, vector_registers[index])?;
                assembler.and_bytes16(mask, mask, 1)?;
            }
        }
    }
    for mask in &block_masks[1..] {
        assembler.add_bytes16(0, 0, *mask)?;
    }
    assembler.add_across_bytes16(0, 0)?;
    assembler.move_vector_byte_to32(X6, 0)?;
    assembler.sub_reg(X6, X5, X6)?;
    assembler.and_low_bits(X6, X6, 8)?;
    assembler.add_reg(X13, X13, X6)?;
    if let Some(vector64_advance) = vector64_advance {
        assembler.bind(vector64_advance)?;
    }
    assembler.add_imm(X3, X3, 64)?;
    assembler.branch(vector64)?;

    assembler.bind(vector16)?;
    assembler.cmp_reg64(X3, X4)?;
    assembler.branch_cond(ConditionV3::Higher, done)?;
    assembler.sub_reg(X6, X4, X3)?;
    assembler.cmp_imm64(X6, SIMD_CANDIDATE_STARTS_V3 - 1)?;
    assembler.branch_cond(ConditionV3::CarryClear, scalar)?;
    if sve_tail.is_some() {
        assembler.cmp_imm64(X6, SIMD_CANDIDATE_STARTS_V3 - 1)?;
        assembler.branch_cond(ConditionV3::Equal, tail)?;
    }
    assembler.add_reg(X15, X0, X3)?;
    for index in 0..usize::from(filter.len) {
        assembler.add_imm(
            pointer_registers[index],
            X15,
            u16::from(filter.offsets[index]),
        )?;
        let destination = if index == 0 { 0 } else { 1 };
        assembler.load_vector128(destination, pointer_registers[index])?;
        assembler.compare_equal_bytes16(destination, destination, vector_registers[index])?;
        if index != 0 {
            assembler.and_bytes16(0, 0, destination)?;
        }
    }
    assembler.add_across_bytes16(0, 0)?;
    assembler.move_vector_byte_to32(X6, 0)?;
    assembler.sub_reg(X6, X5, X6)?;
    assembler.and_low_bits(X6, X6, 8)?;
    assembler.add_reg(X13, X13, X6)?;
    assembler.add_imm(X3, X3, SIMD_CANDIDATE_STARTS_V3)?;
    assembler.branch(vector16)?;

    assembler.bind(tail)?;
    if let Some(sve_tail) = sve_tail {
        emit_hybrid_sve_exact_tail_v3(assembler, literal, sve_tail, scalar, done)?;
        assembler.bind(scalar)?;
    }
    assembler.cmp_reg64(X3, X4)?;
    assembler.branch_cond(ConditionV3::Higher, done)?;
    assembler.add_reg(X15, X0, X3)?;
    for index in 0..usize::from(filter.len) {
        assembler.load_byte(X6, X15, u16::from(filter.offsets[index]))?;
        assembler.cmp_reg32(X6, value_registers[index])?;
        assembler.branch_cond(ConditionV3::NotEqual, tail_miss)?;
    }
    assembler.add_imm(X13, X13, 1)?;
    assembler.bind(tail_miss)?;
    assembler.add_imm(X3, X3, 1)?;
    assembler.branch(scalar)
}

fn emit_sve_compare_bytes_v3(
    assembler: &mut AssemblerV3,
    destination: u8,
    predicate: u8,
    left: u8,
    right: u8,
    sve2: bool,
) -> Result<(), CountAotError> {
    if sve2 {
        assembler.sve2_match_bytes(destination, predicate, left, right)
    } else {
        assembler.sve_compare_equal_bytes(destination, predicate, left, right)
    }
}

/// Consume every complete 16-start block remaining after the Advanced SIMD
/// graph, then transfer fewer than 16 starts to the scalar suffix.
///
/// Every literal column participates in the predicate, so a set lane is
/// already an exact semantic match. BRKB/CNTP recover the earliest lane and
/// the width successor enforces non-overlap before the next predicate block.
fn emit_hybrid_sve_exact_tail_v3(
    assembler: &mut AssemblerV3,
    literal: &[u8],
    sve_tail: HybridSveTailV3,
    scalar: LabelV3,
    done: LabelV3,
) -> Result<(), CountAotError> {
    let no_match = assembler.new_label(LabelKindV3::Miss)?;
    let width = u16::try_from(literal.len()).map_err(|_| CountAotError::ArithmeticOverflow {
        site: CountAotArithmeticSite::CodeOffset,
    })?;

    assembler.sve_ptrue_bytes_vl16(0)?;
    assembler.cmp_reg64(X3, X4)?;
    assembler.branch_cond(ConditionV3::Higher, done)?;
    assembler.sub_reg(X6, X4, X3)?;
    assembler.cmp_imm64(X6, SIMD_CANDIDATE_STARTS_V3 - 1)?;
    assembler.branch_cond(ConditionV3::CarryClear, scalar)?;
    assembler.add_reg(X15, X0, X3)?;
    for (offset, byte) in literal.iter().copied().enumerate() {
        assembler.mov_imm64_minimal(X8, u64::from(byte))?;
        assembler.sve_duplicate_byte(1, X8)?;
        let base = if offset == 0 {
            X15
        } else {
            assembler.add_imm(
                X9,
                X15,
                u16::try_from(offset).expect("bounded literal offset"),
            )?;
            X9
        };
        assembler.sve_load_bytes(0, 0, base)?;
        let destination = if offset == 0 { 1 } else { 2 };
        emit_sve_compare_bytes_v3(assembler, destination, 0, 0, 1, sve_tail.is_sve2())?;
        if offset != 0 {
            assembler.sve_and_predicate_bytes(1, 0, 1, 2)?;
        }
    }
    assembler.sve_test_predicate_bytes(0, 1)?;
    assembler.branch_cond(ConditionV3::Equal, no_match)?;
    assembler.sve_break_before_bytes(3, 0, 1)?;
    assembler.sve_count_predicate_bytes(X7, 0, 3)?;
    assembler.add_reg(X5, X3, X7)?;
    assembler.add_imm(X13, X13, 1)?;
    assembler.add_imm(X3, X5, width)?;
    assembler.branch(scalar)?;

    assembler.bind(no_match)?;
    assembler.add_imm(X3, X3, SIMD_CANDIDATE_STARTS_V3)?;
    assembler.branch(scalar)
}

#[allow(
    dead_code,
    reason = "retained as a reference for the superseded pure-SVE lowering"
)]
fn emit_scalar_confirmation_sve_v3(
    assembler: &mut AssemblerV3,
    literal: &[u8],
    confirmation_order: &[u8],
    proven_filter_offsets: &[u8],
    candidate_pointer: u8,
    mismatch: LabelV3,
) -> Result<(), CountAotError> {
    for offset in confirmation_order.iter().copied() {
        if proven_filter_offsets.contains(&offset) {
            continue;
        }
        assembler.load_byte(X8, candidate_pointer, u16::from(offset))?;
        assembler.cmp_imm32(X8, u16::from(literal[usize::from(offset)]))?;
        assembler.branch_cond(ConditionV3::NotEqual, mismatch)?;
    }
    Ok(())
}

/// Count width-one or self-non-overlapping width-two-through-four literals
/// directly with fixed-VL16 SVE predicates.
///
/// The SVE2 row replaces every equality compare with the genuinely SVE2-only
/// MATCH instruction. Duplicating one byte across the right-hand vector makes
/// MATCH's set-membership result exactly byte equality.
#[allow(
    dead_code,
    reason = "retained as a reference for the superseded pure-SVE lowering"
)]
fn emit_sve_direct_exact_v3(
    assembler: &mut AssemblerV3,
    literal: &[u8],
    sve2: bool,
    done: LabelV3,
) -> Result<(), CountAotError> {
    let vector64 = assembler.new_label(LabelKindV3::VectorLoop)?;
    let vector16 = assembler.new_label(LabelKindV3::VectorLoop)?;
    let tail = assembler.new_label(LabelKindV3::ScalarTail)?;
    let tail_miss = assembler.new_label(LabelKindV3::Miss)?;
    let width = u16::try_from(literal.len()).map_err(|_| CountAotError::ArithmeticOverflow {
        site: CountAotArithmeticSite::CodeOffset,
    })?;
    let constants = [2_u8, 3, 16, 17];

    assembler.mov_imm64_minimal(X13, 0)?;
    assembler.cmp_imm64(X1, width)?;
    assembler.branch_cond(ConditionV3::CarryClear, done)?;
    assembler.sub_imm(X4, X1, width)?;
    assembler.mov_imm64_minimal(X3, 0)?;
    assembler.sve_ptrue_bytes_vl16(0)?;
    for (offset, byte) in literal.iter().copied().enumerate() {
        assembler.mov_imm64_minimal(X8, u64::from(byte))?;
        assembler.sve_duplicate_byte(constants[offset], X8)?;
    }

    assembler.bind(vector64)?;
    assembler.cmp_reg64(X3, X4)?;
    assembler.branch_cond(ConditionV3::Higher, done)?;
    assembler.sub_reg(X6, X4, X3)?;
    assembler.cmp_imm64(X6, 63)?;
    assembler.branch_cond(ConditionV3::CarryClear, vector16)?;
    assembler.add_reg(X15, X0, X3)?;
    // Column-major lowering amortizes each scalar column-base calculation
    // across four VL16 blocks. The block masks remain live in p4-p7 while
    // LD1B's MUL VL immediate selects starts 0, 16, 32, and 48.
    for (index, constant) in constants[..literal.len()].iter().copied().enumerate() {
        assembler.add_imm(X8, X15, u16::try_from(index).expect("direct literal width"))?;
        for block in 0_u8..4 {
            assembler.sve_load_bytes_mul_vl(
                0,
                0,
                X8,
                i8::try_from(block).expect("nonnegative imm4"),
            )?;
            let block_predicate = 4_u8.checked_add(block).expect("p4 through p7");
            let result = if index == 0 { block_predicate } else { 1 };
            emit_sve_compare_bytes_v3(assembler, result, 0, 0, constant, sve2)?;
            if index != 0 {
                assembler.sve_and_predicate_bytes(block_predicate, 0, block_predicate, result)?;
            }
        }
    }
    // Count each retained 16-start block mask after all columns have refined it.
    for block_predicate in 4_u8..8 {
        assembler.sve_count_predicate_bytes(X6, 0, block_predicate)?;
        assembler.add_reg(X13, X13, X6)?;
    }
    assembler.add_imm(X3, X3, 64)?;
    assembler.branch(vector64)?;

    assembler.bind(vector16)?;
    assembler.cmp_reg64(X3, X4)?;
    assembler.branch_cond(ConditionV3::Higher, done)?;
    assembler.sub_reg(X6, X4, X3)?;
    assembler.cmp_imm64(X6, 15)?;
    assembler.branch_cond(ConditionV3::CarryClear, tail)?;
    assembler.add_reg(X15, X0, X3)?;
    for (index, constant) in constants[..literal.len()].iter().copied().enumerate() {
        assembler.add_imm(X8, X15, u16::try_from(index).expect("direct literal width"))?;
        assembler.sve_load_bytes(0, 0, X8)?;
        let result = if index == 0 { 1 } else { 2 };
        emit_sve_compare_bytes_v3(assembler, result, 0, 0, constant, sve2)?;
        if index != 0 {
            assembler.sve_and_predicate_bytes(1, 0, 1, result)?;
        }
    }
    assembler.sve_count_predicate_bytes(X6, 0, 1)?;
    assembler.add_reg(X13, X13, X6)?;
    assembler.add_imm(X3, X3, SIMD_CANDIDATE_STARTS_V3)?;
    assembler.branch(vector16)?;

    assembler.bind(tail)?;
    assembler.cmp_reg64(X3, X4)?;
    assembler.branch_cond(ConditionV3::Higher, done)?;
    assembler.add_reg(X15, X0, X3)?;
    for (offset, byte) in literal.iter().copied().enumerate() {
        assembler.load_byte(
            X6,
            X15,
            u16::try_from(offset).expect("direct literal width"),
        )?;
        assembler.cmp_imm32(X6, u16::from(byte))?;
        assembler.branch_cond(ConditionV3::NotEqual, tail_miss)?;
    }
    assembler.add_imm(X13, X13, 1)?;
    assembler.bind(tail_miss)?;
    assembler.add_imm(X3, X3, 1)?;
    assembler.branch(tail)
}

/// Fixed-VL16 SVE filter and scalar exact-confirmation template.
///
/// Predicate recovery retains every candidate lane in the current block:
/// BRKB/CNTP materialize the first lane, while BRKA/BICS remove only a rejected
/// lane. A confirmed match resumes at its semantic non-overlapping successor.
#[allow(
    dead_code,
    reason = "retained as a reference for the superseded pure-SVE lowering"
)]
fn emit_sve_filtered_v3(
    assembler: &mut AssemblerV3,
    literal: &[u8],
    filter: CandidateFilterV3,
    confirmation_order: &[u8],
    sve2: bool,
    done: LabelV3,
) -> Result<(), CountAotError> {
    let vector = assembler.new_label(LabelKindV3::VectorLoop)?;
    let candidate = assembler.new_label(LabelKindV3::CandidateLoop)?;
    let candidate_miss = assembler.new_label(LabelKindV3::Miss)?;
    let advance = assembler.new_label(LabelKindV3::Internal)?;
    let primary_sparse_scan = assembler.new_label(LabelKindV3::VectorLoop)?;
    let primary_sparse_hit = assembler.new_label(LabelKindV3::Internal)?;
    let primary_sparse_first_half = assembler.new_label(LabelKindV3::Internal)?;
    let tail = assembler.new_label(LabelKindV3::ScalarTail)?;
    let tail_miss = assembler.new_label(LabelKindV3::Miss)?;
    let width = u16::try_from(literal.len()).map_err(|_| CountAotError::ArithmeticOverflow {
        site: CountAotArithmeticSite::CodeOffset,
    })?;
    let constants = [2_u8, 3, 16, 17];

    assembler.mov_imm64_minimal(X13, 0)?;
    assembler.cmp_imm64(X1, width)?;
    assembler.branch_cond(ConditionV3::CarryClear, done)?;
    assembler.sub_imm(X4, X1, width)?;
    assembler.mov_imm64_minimal(X3, 0)?;
    assembler.sve_ptrue_bytes_vl16(0)?;
    for (index, offset) in filter.offsets().iter().copied().enumerate() {
        assembler.mov_imm64_minimal(X8, u64::from(literal[usize::from(offset)]))?;
        assembler.sve_duplicate_byte(constants[index], X8)?;
    }

    assembler.bind(vector)?;
    assembler.cmp_reg64(X3, X4)?;
    assembler.branch_cond(ConditionV3::Higher, done)?;
    assembler.sub_reg(X6, X4, X3)?;
    assembler.cmp_imm64(X6, SIMD_CANDIDATE_STARTS_V3 - 1)?;
    assembler.branch_cond(ConditionV3::CarryClear, tail)?;
    assembler.add_reg(X15, X0, X3)?;
    let primary_offset = filter.offsets[0];
    let primary_base = if primary_offset == 0 {
        X15
    } else {
        assembler.add_imm(X8, X15, u16::from(primary_offset))?;
        X8
    };
    assembler.sve_load_bytes(0, 0, primary_base)?;
    emit_sve_compare_bytes_v3(assembler, 1, 0, 0, constants[0], sve2)?;
    assembler.sve_test_predicate_bytes(0, 1)?;
    assembler.branch_cond(ConditionV3::Equal, primary_sparse_scan)?;
    for (index, offset) in filter.offsets()[1..].iter().copied().enumerate() {
        let base = if offset == 0 {
            X15
        } else {
            assembler.add_imm(X8, X15, u16::from(offset))?;
            X8
        };
        assembler.sve_load_bytes(0, 0, base)?;
        emit_sve_compare_bytes_v3(assembler, 2, 0, 0, constants[index + 1], sve2)?;
        assembler.sve_and_predicate_bytes(1, 0, 1, 2)?;
        assembler.sve_test_predicate_bytes(0, 1)?;
        assembler.branch_cond(ConditionV3::Equal, advance)?;
    }

    assembler.bind(candidate)?;
    assembler.sve_break_before_bytes(3, 0, 1)?;
    assembler.sve_count_predicate_bytes(X7, 0, 3)?;
    assembler.add_reg(X5, X3, X7)?;
    assembler.add_reg(X15, X0, X5)?;
    emit_scalar_confirmation_sve_v3(
        assembler,
        literal,
        confirmation_order,
        filter.offsets(),
        X15,
        candidate_miss,
    )?;
    assembler.add_imm(X13, X13, 1)?;
    assembler.add_imm(X3, X5, width)?;
    assembler.branch(vector)?;

    assembler.bind(candidate_miss)?;
    assembler.sve_break_after_bytes(3, 0, 1)?;
    assembler.sve_bit_clear_predicate_bytes_set_flags(1, 0, 1, 3)?;
    assembler.branch_cond(ConditionV3::NotEqual, candidate)?;

    assembler.bind(advance)?;
    assembler.add_imm(X3, X3, SIMD_CANDIDATE_STARTS_V3)?;
    assembler.branch(vector)?;

    // A primary-empty block admits a fixed-VL16 128-start one-column scan.
    // LD1B's MUL VL immediate addresses the eight blocks without scalar
    // pointer arithmetic. Predicate OR reductions classify the earliest
    // hit-bearing 32-start quarter, which always re-enters the complete filter.
    assembler.bind(primary_sparse_scan)?;
    assembler.add_imm(X3, X3, SIMD_CANDIDATE_STARTS_V3)?;
    assembler.cmp_reg64(X3, X4)?;
    assembler.branch_cond(ConditionV3::Higher, done)?;
    assembler.sub_reg(X6, X4, X3)?;
    assembler.cmp_imm64(X6, SPARSE_SCAN_STARTS_V3 - 1)?;
    assembler.branch_cond(ConditionV3::CarryClear, vector)?;
    assembler.add_reg(X15, X0, X3)?;
    let primary_base = if primary_offset == 0 {
        X15
    } else {
        assembler.add_imm(X8, X15, u16::from(primary_offset))?;
        X8
    };
    for block in 0_u8..8 {
        let block_predicate = 4_u8.checked_add(block).expect("p4 through p11");
        assembler.sve_load_bytes_mul_vl(
            0,
            0,
            primary_base,
            i8::try_from(block).expect("nonnegative imm4"),
        )?;
        emit_sve_compare_bytes_v3(assembler, block_predicate, 0, 0, constants[0], sve2)?;
    }
    for (destination, left, right) in [(12, 4, 5), (13, 6, 7), (14, 8, 9), (15, 10, 11)] {
        assembler.sve_or_predicate_bytes(destination, 0, left, right)?;
    }
    assembler.sve_or_predicate_bytes(1, 0, 12, 13)?;
    assembler.sve_or_predicate_bytes(2, 0, 14, 15)?;
    assembler.sve_or_predicate_bytes(1, 0, 1, 2)?;
    assembler.sve_test_predicate_bytes(0, 1)?;
    assembler.branch_cond(ConditionV3::NotEqual, primary_sparse_hit)?;
    assembler.add_imm(X3, X3, SPARSE_SCAN_STARTS_V3 - SIMD_CANDIDATE_STARTS_V3)?;
    assembler.branch(primary_sparse_scan)?;

    assembler.bind(primary_sparse_hit)?;
    assembler.sve_or_predicate_bytes(1, 0, 12, 13)?;
    assembler.sve_test_predicate_bytes(0, 1)?;
    assembler.branch_cond(ConditionV3::NotEqual, primary_sparse_first_half)?;
    assembler.add_imm(X3, X3, SIMD_CANDIDATE_STARTS_V3 * 4)?;
    assembler.sve_test_predicate_bytes(0, 14)?;
    assembler.branch_cond(ConditionV3::NotEqual, vector)?;
    assembler.add_imm(X3, X3, SIMD_CANDIDATE_STARTS_V3 * 2)?;
    assembler.branch(vector)?;

    assembler.bind(primary_sparse_first_half)?;
    assembler.sve_test_predicate_bytes(0, 12)?;
    assembler.branch_cond(ConditionV3::NotEqual, vector)?;
    assembler.add_imm(X3, X3, SIMD_CANDIDATE_STARTS_V3 * 2)?;
    assembler.branch(vector)?;

    assembler.bind(tail)?;
    assembler.cmp_reg64(X3, X4)?;
    assembler.branch_cond(ConditionV3::Higher, done)?;
    assembler.add_reg(X15, X0, X3)?;
    emit_scalar_confirmation_sve_v3(assembler, literal, confirmation_order, &[], X15, tail_miss)?;
    assembler.add_imm(X13, X13, 1)?;
    assembler.add_imm(X3, X3, width)?;
    assembler.branch(tail)?;
    assembler.bind(tail_miss)?;
    assembler.add_imm(X3, X3, 1)?;
    assembler.branch(tail)
}

/// Fixed-VL16 SVE/SVE2 periodic scan.
///
/// The sealed periodic recipe supplies the two adjacent period-boundary
/// columns. Both columns are intersected before a predicate test, so a common
/// period byte cannot enter scalar confirmation alone. A confirmed match
/// enters a straight non-overlapping successor run.
#[allow(
    dead_code,
    clippy::too_many_lines,
    reason = "retained as an explicit reference for the superseded pure-SVE periodic graph"
)]
fn emit_periodic_sve_v3(
    assembler: &mut AssemblerV3,
    literal: &[u8],
    filter: CandidateFilterV3,
    confirmation_order: &[u8],
    periodic_stride: u8,
    sve2: bool,
    done: LabelV3,
) -> Result<(), CountAotError> {
    if periodic_stride == 0 || usize::from(periodic_stride) >= literal.len() || filter.len != 2 {
        return Err(CountAotError::InternalInvariant {
            at: "invalid periodic SVE stride",
        });
    }
    let wide = assembler.new_label(LabelKindV3::VectorLoop)?;
    let wide_hit = assembler.new_label(LabelKindV3::Internal)?;
    let vector = assembler.new_label(LabelKindV3::VectorLoop)?;
    let candidate = assembler.new_label(LabelKindV3::CandidateLoop)?;
    let candidate_miss = assembler.new_label(LabelKindV3::Miss)?;
    let advance = assembler.new_label(LabelKindV3::Internal)?;
    let match_run = assembler.new_label(LabelKindV3::CandidateLoop)?;
    let match_run_miss = assembler.new_label(LabelKindV3::Miss)?;
    let tail = assembler.new_label(LabelKindV3::ScalarTail)?;
    let tail_miss = assembler.new_label(LabelKindV3::Miss)?;
    let width = u16::try_from(literal.len()).map_err(|_| CountAotError::ArithmeticOverflow {
        site: CountAotArithmeticSite::CodeOffset,
    })?;
    let constants = [2_u8, 3, 16, 17];

    assembler.mov_imm64_minimal(X13, 0)?;
    assembler.cmp_imm64(X1, width)?;
    assembler.branch_cond(ConditionV3::CarryClear, done)?;
    assembler.sub_imm(X4, X1, width)?;
    assembler.mov_imm64_minimal(X3, 0)?;
    assembler.sve_ptrue_bytes_vl16(0)?;
    for (index, offset) in filter.offsets().iter().copied().enumerate() {
        assembler.mov_imm64_minimal(X8, u64::from(literal[usize::from(offset)]))?;
        assembler.sve_duplicate_byte(constants[index], X8)?;
    }

    // Scan eight fixed-VL16 blocks before paying lane recovery. P4-P11 retain
    // the exact two-column masks, so a rare hit can re-enter the existing
    // complete 16-start graph at its earliest block without semantic risk.
    assembler.bind(wide)?;
    assembler.cmp_reg64(X3, X4)?;
    assembler.branch_cond(ConditionV3::Higher, done)?;
    assembler.sub_reg(X6, X4, X3)?;
    assembler.cmp_imm64(X6, SPARSE_SCAN_STARTS_V3 - 1)?;
    assembler.branch_cond(ConditionV3::CarryClear, vector)?;
    assembler.add_reg(X15, X0, X3)?;
    let first_offset = filter.offsets[0];
    let first_base = if first_offset == 0 {
        X15
    } else {
        assembler.add_imm(X8, X15, u16::from(first_offset))?;
        X8
    };
    let second_offset = filter.offsets[1];
    let second_base = if second_offset == 0 {
        X15
    } else {
        assembler.add_imm(X9, X15, u16::from(second_offset))?;
        X9
    };
    for block in 0_u8..8 {
        let block_predicate = 4_u8.checked_add(block).expect("p4 through p11");
        let vector_offset = i8::try_from(block).expect("nonnegative imm4");
        assembler.sve_load_bytes_mul_vl(0, 0, first_base, vector_offset)?;
        emit_sve_compare_bytes_v3(assembler, block_predicate, 0, 0, constants[0], sve2)?;
        assembler.sve_load_bytes_mul_vl(0, 0, second_base, vector_offset)?;
        emit_sve_compare_bytes_v3(assembler, 2, 0, 0, constants[1], sve2)?;
        assembler.sve_and_predicate_bytes(block_predicate, 0, block_predicate, 2)?;
    }
    for (destination, left, right) in [(12, 4, 5), (13, 6, 7), (14, 8, 9), (15, 10, 11)] {
        assembler.sve_or_predicate_bytes(destination, 0, left, right)?;
    }
    assembler.sve_or_predicate_bytes(1, 0, 12, 13)?;
    assembler.sve_or_predicate_bytes(2, 0, 14, 15)?;
    assembler.sve_or_predicate_bytes(1, 0, 1, 2)?;
    assembler.sve_test_predicate_bytes(0, 1)?;
    assembler.branch_cond(ConditionV3::NotEqual, wide_hit)?;
    assembler.add_imm(X3, X3, SPARSE_SCAN_STARTS_V3)?;
    assembler.branch(wide)?;

    assembler.bind(wide_hit)?;
    for block_predicate in 4_u8..11 {
        assembler.sve_test_predicate_bytes(0, block_predicate)?;
        assembler.branch_cond(ConditionV3::NotEqual, vector)?;
        assembler.add_imm(X3, X3, SIMD_CANDIDATE_STARTS_V3)?;
    }
    assembler.branch(vector)?;

    assembler.bind(vector)?;
    assembler.cmp_reg64(X3, X4)?;
    assembler.branch_cond(ConditionV3::Higher, done)?;
    assembler.sub_reg(X6, X4, X3)?;
    assembler.cmp_imm64(X6, SIMD_CANDIDATE_STARTS_V3 - 1)?;
    assembler.branch_cond(ConditionV3::CarryClear, tail)?;
    assembler.add_reg(X15, X0, X3)?;
    for (index, offset) in filter.offsets().iter().copied().enumerate() {
        let base = if offset == 0 {
            X15
        } else {
            assembler.add_imm(X8, X15, u16::from(offset))?;
            X8
        };
        assembler.sve_load_bytes(0, 0, base)?;
        let destination = if index == 0 { 1 } else { 2 };
        emit_sve_compare_bytes_v3(assembler, destination, 0, 0, constants[index], sve2)?;
        if index != 0 {
            assembler.sve_and_predicate_bytes(1, 0, 1, 2)?;
        }
    }
    assembler.sve_test_predicate_bytes(0, 1)?;
    assembler.branch_cond(ConditionV3::Equal, advance)?;

    assembler.bind(candidate)?;
    assembler.sve_break_before_bytes(3, 0, 1)?;
    assembler.sve_count_predicate_bytes(X7, 0, 3)?;
    assembler.add_reg(X5, X3, X7)?;
    assembler.add_reg(X15, X0, X5)?;
    emit_scalar_confirmation_sve_v3(
        assembler,
        literal,
        confirmation_order,
        filter.offsets(),
        X15,
        candidate_miss,
    )?;
    assembler.add_imm(X13, X13, 1)?;
    assembler.add_imm(X3, X5, width)?;
    assembler.branch(match_run)?;

    assembler.bind(candidate_miss)?;
    assembler.sve_break_after_bytes(3, 0, 1)?;
    assembler.sve_bit_clear_predicate_bytes_set_flags(1, 0, 1, 3)?;
    assembler.branch_cond(ConditionV3::NotEqual, candidate)?;
    assembler.bind(advance)?;
    assembler.add_imm(X3, X3, SIMD_CANDIDATE_STARTS_V3)?;
    assembler.branch(wide)?;

    assembler.bind(match_run)?;
    assembler.cmp_reg64(X3, X4)?;
    assembler.branch_cond(ConditionV3::Higher, done)?;
    assembler.add_reg(X15, X0, X3)?;
    emit_scalar_confirmation_sve_v3(
        assembler,
        literal,
        confirmation_order,
        &[],
        X15,
        match_run_miss,
    )?;
    assembler.add_imm(X13, X13, 1)?;
    assembler.add_imm(X3, X3, width)?;
    assembler.branch(match_run)?;
    assembler.bind(match_run_miss)?;
    assembler.add_imm(X3, X3, 1)?;
    assembler.branch(wide)?;

    assembler.bind(tail)?;
    assembler.cmp_reg64(X3, X4)?;
    assembler.branch_cond(ConditionV3::Higher, done)?;
    assembler.add_reg(X15, X0, X3)?;
    emit_scalar_confirmation_sve_v3(assembler, literal, confirmation_order, &[], X15, tail_miss)?;
    assembler.add_imm(X13, X13, 1)?;
    assembler.add_imm(X3, X3, width)?;
    assembler.branch(match_run)?;
    assembler.bind(tail_miss)?;
    assembler.add_imm(X3, X3, 1)?;
    assembler.branch(tail)
}

#[allow(
    clippy::too_many_lines,
    reason = "the complete 16-start mask and successor graph is intentionally explicit"
)]
fn emit_multi_incumbent_v3(
    assembler: &mut AssemblerV3,
    literal: &[u8],
    filter: CandidateFilterV3,
    sve_tail: Option<HybridSveTailV3>,
    done: LabelV3,
) -> Result<(), CountAotError> {
    let vector = assembler.new_label(LabelKindV3::VectorLoop)?;
    let sparse_scan = assembler.new_label(LabelKindV3::VectorLoop)?;
    let sparse_hit = assembler.new_label(LabelKindV3::Internal)?;
    let sparse_first_half = assembler.new_label(LabelKindV3::Internal)?;
    let pair_absent = assembler.new_label(LabelKindV3::Internal)?;
    let pair_single = assembler.new_label(LabelKindV3::Internal)?;
    let pair_dense = assembler.new_label(LabelKindV3::Internal)?;
    let candidate = assembler.new_label(LabelKindV3::CandidateLoop)?;
    let candidate_miss = assembler.new_label(LabelKindV3::Miss)?;
    let block_advance = assembler.new_label(LabelKindV3::Internal)?;
    let dense_scan = assembler.new_label(LabelKindV3::VectorLoop)?;
    let dense_absent = assembler.new_label(LabelKindV3::Internal)?;
    let match_run = if sve_tail.is_none() {
        Some(assembler.new_label(LabelKindV3::CandidateLoop)?)
    } else {
        None
    };
    let match_run_miss = if sve_tail.is_none() {
        Some(assembler.new_label(LabelKindV3::Miss)?)
    } else {
        None
    };
    let scalar = assembler.new_label(LabelKindV3::ScalarTail)?;
    let scalar_loop = if sve_tail.is_some() {
        assembler.new_label(LabelKindV3::ScalarTail)?
    } else {
        scalar
    };
    let scalar_miss = assembler.new_label(LabelKindV3::Miss)?;
    let width = u16::try_from(literal.len()).map_err(|_| CountAotError::ArithmeticOverflow {
        site: CountAotArithmeticSite::CodeOffset,
    })?;
    let primary = u16::from(filter.offsets[0]);
    let secondary = u16::from(filter.offsets[1]);
    assembler.mov_imm64_minimal(X13, 0)?;
    assembler.cmp_imm64(X1, width)?;
    assembler.branch_cond(ConditionV3::CarryClear, done)?;
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
    assembler.mov_imm64_minimal(X17, SPARSE_NIBBLE_BITS_V3)?;
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
    if let Some(suffix_offset) = overlapping_suffix_offset_v3(literal.len()) {
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(&literal[suffix_offset..]);
        assembler.mov_imm64_minimal(X8, u64::from_le_bytes(bytes))?;
        assembler.move_x_to_vector_double(OVERLAPPING_SUFFIX_VECTOR_V3, X8)?;
    }

    assembler.bind(vector)?;
    assembler.cmp_reg64(X3, X4)?;
    assembler.branch_cond(ConditionV3::Higher, done)?;
    assembler.sub_reg(X5, X4, X3)?;
    assembler.cmp_imm64(X5, SIMD_CANDIDATE_STARTS_V3 - 1)?;
    assembler.branch_cond(ConditionV3::CarryClear, scalar_loop)?;
    if sve_tail.is_some() {
        assembler.cmp_imm64(X5, SIMD_CANDIDATE_STARTS_V3 - 1)?;
        assembler.branch_cond(ConditionV3::Equal, scalar)?;
    }
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
    assembler.branch_cond(ConditionV3::Equal, pair_absent)?;
    assembler.cmp_imm64(X8, 255)?;
    assembler.branch_cond(ConditionV3::NotEqual, pair_dense)?;

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
        assembler.branch_cond(ConditionV3::Equal, block_advance)?;
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
    assembler.branch_cond(ConditionV3::Equal, block_advance)?;
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
    assembler.branch_cond(ConditionV3::Equal, dense_absent)?;
    assembler.branch(candidate)?;

    assembler.bind(candidate)?;
    assembler.reverse_bits(X7, X6)?;
    assembler.count_leading_zeros(X7, X7)?;
    assembler.sub_imm(X16, X6, 1)?;
    assembler.and_reg(X6, X6, X16)?;
    assembler.lsr_imm(X7, X7, 2)?;
    assembler.add_reg(X5, X3, X7)?;
    assembler.add_reg(X15, X0, X5)?;
    emit_confirmation_v3(assembler, literal, filter.offsets(), X15, candidate_miss)?;
    assembler.add_imm(X13, X13, 1)?;
    // Discard the old mask and enter a full-confirmation successor run.
    assembler.add_imm(X3, X5, width)?;
    assembler.branch(match_run.unwrap_or(vector))?;

    assembler.bind(candidate_miss)?;
    assembler.cmp_imm64(X6, 0)?;
    assembler.branch_cond(ConditionV3::NotEqual, candidate)?;
    assembler.bind(block_advance)?;
    assembler.add_imm(X3, X3, SIMD_CANDIDATE_STARTS_V3)?;
    assembler.branch(vector)?;

    // Match-heavy input avoids rebuilding filter masks at every exact
    // semantic successor. The first failed successor is consumed once before
    // returning to adaptive SIMD filtering.
    if let (Some(match_run), Some(match_run_miss)) = (match_run, match_run_miss) {
        assembler.bind(match_run)?;
        assembler.cmp_reg64(X3, X4)?;
        assembler.branch_cond(ConditionV3::Higher, done)?;
        assembler.add_reg(X15, X0, X3)?;
        emit_confirmation_v3(assembler, literal, &[], X15, match_run_miss)?;
        assembler.add_imm(X13, X13, 1)?;
        assembler.add_imm(X3, X3, width)?;
        assembler.branch(match_run)?;
        assembler.bind(match_run_miss)?;
        assembler.add_imm(X3, X3, 1)?;
        assembler.branch(vector)?;
    }

    // Once a pair-dense block has no semantic first/last candidate, eight
    // consecutive first/last blocks share one reduction. Any possible match
    // returns at the unchanged start to the complete adaptive filter; a
    // sustained adversarial rare pair therefore pays its discovery only once.
    assembler.bind(dense_absent)?;
    assembler.add_imm(X3, X3, SIMD_CANDIDATE_STARTS_V3)?;
    assembler.branch(dense_scan)?;
    assembler.bind(dense_scan)?;
    assembler.cmp_reg64(X3, X4)?;
    assembler.branch_cond(ConditionV3::Higher, done)?;
    assembler.sub_reg(X5, X4, X3)?;
    assembler.cmp_imm64(X5, SPARSE_SCAN_STARTS_V3 - 1)?;
    assembler.branch_cond(ConditionV3::CarryClear, vector)?;
    assembler.add_reg(X15, X0, X3)?;
    assembler.add_imm(
        X9,
        X15,
        u16::try_from(literal.len() - 1).expect("bounded last offset"),
    )?;
    for block in 0..SPARSE_SCAN_BLOCKS_V3 {
        let offset = block.checked_mul(SIMD_CANDIDATE_STARTS_V3).ok_or(
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
    assembler.branch_cond(ConditionV3::NotEqual, vector)?;
    assembler.add_imm(X3, X3, SPARSE_SCAN_STARTS_V3)?;
    assembler.branch(dense_scan)?;

    // A block with no rare-byte pair enters a separate sparse-run loop. Eight
    // consecutive 16-start masks share one horizontal reduction; a hit group
    // returns to the ordinary block path at its earliest hit-bearing
    // two-block quarter.
    // Dense and match-heavy blocks never enter this loop, so their existing
    // candidate and successor path remains unchanged.
    assembler.bind(pair_absent)?;
    assembler.add_imm(X3, X3, SIMD_CANDIDATE_STARTS_V3)?;
    assembler.branch(sparse_scan)?;
    assembler.bind(sparse_scan)?;
    assembler.cmp_reg64(X3, X4)?;
    assembler.branch_cond(ConditionV3::Higher, done)?;
    assembler.sub_reg(X5, X4, X3)?;
    assembler.cmp_imm64(X5, SPARSE_SCAN_STARTS_V3 - 1)?;
    assembler.branch_cond(ConditionV3::CarryClear, vector)?;
    assembler.add_reg(X15, X0, X3)?;
    assembler.add_imm(X8, X15, primary)?;
    assembler.add_imm(X9, X15, secondary)?;
    for block in 0..SPARSE_SCAN_BLOCKS_V3 {
        let offset = block.checked_mul(SIMD_CANDIDATE_STARTS_V3).ok_or(
            CountAotError::ArithmeticOverflow {
                site: CountAotArithmeticSite::CodeOffset,
            },
        )?;
        assembler.load_vector128_offset(0, X8, offset)?;
        assembler.load_vector128_offset(1, X9, offset)?;
        assembler.compare_equal_bytes16(0, 0, 2)?;
        assembler.compare_equal_bytes16(1, 1, 3)?;
        assembler.and_bytes16(
            u8::try_from(u16::from(SPARSE_BLOCK_MASK_BASE_V3) + block)
                .expect("eight caller-saved sparse block masks"),
            0,
            1,
        )?;
    }
    assembler.or_bytes16(
        SPARSE_PAIR_01_MASK_V3,
        SPARSE_BLOCK_MASK_BASE_V3,
        SPARSE_BLOCK_MASK_BASE_V3 + 1,
    )?;
    assembler.or_bytes16(
        SPARSE_PAIR_23_MASK_V3,
        SPARSE_BLOCK_MASK_BASE_V3 + 2,
        SPARSE_BLOCK_MASK_BASE_V3 + 3,
    )?;
    assembler.or_bytes16(
        SPARSE_PAIR_45_MASK_V3,
        SPARSE_BLOCK_MASK_BASE_V3 + 4,
        SPARSE_BLOCK_MASK_BASE_V3 + 5,
    )?;
    assembler.or_bytes16(
        SPARSE_PAIR_67_MASK_V3,
        SPARSE_BLOCK_MASK_BASE_V3 + 6,
        SPARSE_BLOCK_MASK_BASE_V3 + 7,
    )?;
    assembler.or_bytes16(1, SPARSE_PAIR_01_MASK_V3, SPARSE_PAIR_23_MASK_V3)?;
    assembler.or_bytes16(0, SPARSE_PAIR_45_MASK_V3, SPARSE_PAIR_67_MASK_V3)?;
    assembler.or_bytes16(1, 1, 0)?;
    assembler.unsigned_max_across_bytes16(1, 1)?;
    assembler.move_vector_byte_to32(X8, 1)?;
    assembler.cmp_imm64(X8, 0)?;
    assembler.branch_cond(ConditionV3::NotEqual, sparse_hit)?;
    assembler.add_imm(X3, X3, SPARSE_SCAN_STARTS_V3)?;
    assembler.branch(sparse_scan)?;

    // Classification is paid only by a hit-bearing 128-start group. Pair
    // unions retained in caller-saved vectors move directly to its earliest
    // hit-bearing 32-start quarter, bounding any rescan to one 16-start block.
    assembler.bind(sparse_hit)?;
    assembler.or_bytes16(1, SPARSE_PAIR_01_MASK_V3, SPARSE_PAIR_23_MASK_V3)?;
    assembler.unsigned_max_across_bytes16(1, 1)?;
    assembler.move_vector_byte_to32(X8, 1)?;
    assembler.cmp_imm64(X8, 0)?;
    assembler.branch_cond(ConditionV3::NotEqual, sparse_first_half)?;
    assembler.add_imm(X3, X3, SIMD_CANDIDATE_STARTS_V3 * 4)?;
    assembler.unsigned_max_across_bytes16(1, SPARSE_PAIR_45_MASK_V3)?;
    assembler.move_vector_byte_to32(X8, 1)?;
    assembler.cmp_imm64(X8, 0)?;
    assembler.branch_cond(ConditionV3::NotEqual, vector)?;
    assembler.add_imm(X3, X3, SIMD_CANDIDATE_STARTS_V3 * 2)?;
    assembler.branch(vector)?;
    assembler.bind(sparse_first_half)?;
    assembler.unsigned_max_across_bytes16(1, SPARSE_PAIR_01_MASK_V3)?;
    assembler.move_vector_byte_to32(X8, 1)?;
    assembler.cmp_imm64(X8, 0)?;
    assembler.branch_cond(ConditionV3::NotEqual, vector)?;
    assembler.add_imm(X3, X3, SIMD_CANDIDATE_STARTS_V3 * 2)?;
    assembler.branch(vector)?;

    assembler.bind(scalar)?;
    if let Some(sve_tail) = sve_tail {
        emit_hybrid_sve_exact_tail_v3(assembler, literal, sve_tail, scalar_loop, done)?;
        assembler.bind(scalar_loop)?;
    }
    assembler.cmp_reg64(X3, X4)?;
    assembler.branch_cond(ConditionV3::Higher, done)?;
    assembler.add_reg(X15, X0, X3)?;
    assembler.load_byte(X8, X15, primary)?;
    assembler.cmp_reg32(X8, X10)?;
    assembler.branch_cond(ConditionV3::NotEqual, scalar_miss)?;
    assembler.load_byte(X8, X15, secondary)?;
    assembler.cmp_reg32(X8, X11)?;
    assembler.branch_cond(ConditionV3::NotEqual, scalar_miss)?;
    if filter.len >= 3 {
        assembler.load_byte(X8, X15, u16::from(filter.offsets[2]))?;
        assembler.cmp_reg32(X8, X12)?;
        assembler.branch_cond(ConditionV3::NotEqual, scalar_miss)?;
    }
    if filter.len >= 4 {
        assembler.load_byte(X8, X15, u16::from(filter.offsets[3]))?;
        assembler.cmp_reg32(X8, X14)?;
        assembler.branch_cond(ConditionV3::NotEqual, scalar_miss)?;
    }
    emit_confirmation_v3(assembler, literal, filter.offsets(), X15, scalar_miss)?;
    assembler.add_imm(X13, X13, 1)?;
    assembler.add_imm(X3, X3, width)?;
    assembler.branch(if sve_tail.is_some() {
        scalar_loop
    } else {
        match_run.expect("incumbent match run")
    })?;
    assembler.bind(scalar_miss)?;
    assembler.add_imm(X3, X3, 1)?;
    assembler.branch(scalar_loop)
}

/// Return the max-cursor slack required for an aligned sliding-window pair
/// scan. The lookahead load deliberately rounds the higher column up to a
/// whole Q register, so the ordinary 128-start guard alone is not always
/// enough near the haystack boundary.
fn sliding_pair_required_remaining_v3(
    width: u16,
    low_offset: u8,
    delta: u8,
) -> Result<u16, CountAotError> {
    if delta == 0 || delta > 31 {
        return Err(CountAotError::InternalInvariant {
            at: "v3 sliding pair delta",
        });
    }
    let lookahead_vectors = if delta <= 16 { 1_u16 } else { 2 };
    let loaded_extent = u16::from(low_offset)
        .checked_add(SPARSE_SCAN_STARTS_V3)
        .and_then(|extent| extent.checked_add(lookahead_vectors * 16))
        .ok_or(CountAotError::ArithmeticOverflow {
            site: CountAotArithmeticSite::CodeOffset,
        })?;
    Ok(loaded_extent
        .checked_sub(width)
        .ok_or(CountAotError::InternalInvariant {
            at: "v3 sliding pair extent",
        })?
        .max(SPARSE_SCAN_STARTS_V3 - 1))
}

/// Form eight complete two-column masks from one contiguous byte stream.
///
/// For deltas through 16, two vector registers form a sliding ring and nine
/// Q loads cover 128 starts. Deltas 17 through 31 use a three-register ring
/// and ten Q loads. `EXT` derives the unaligned higher column entirely in
/// registers; delta 16 is the exact adjacent-register case and needs no EXT.
fn emit_sliding_pair_masks_v3(
    assembler: &mut AssemblerV3,
    stream_base: u8,
    delta: u8,
    low_constant: u8,
    high_constant: u8,
) -> Result<(), CountAotError> {
    if delta == 0 || delta > 31 {
        return Err(CountAotError::InternalInvariant {
            at: "v3 sliding pair delta",
        });
    }
    let stream_registers = [0_u8, 1, 20];
    let ring_len = if delta <= 16 { 2_usize } else { 3 };
    for (index, register) in stream_registers[..ring_len].iter().copied().enumerate() {
        assembler.load_vector128_offset(
            register,
            stream_base,
            u16::try_from(index * 16).expect("three sliding preload vectors"),
        )?;
    }
    for block in 0_usize..8 {
        let low = stream_registers[block % ring_len];
        let high_left = stream_registers[(block + 1) % ring_len];
        let mask =
            SPARSE_BLOCK_MASK_BASE_V3 + u8::try_from(block).expect("eight sliding pair masks");
        match delta.cmp(&16) {
            core::cmp::Ordering::Less => {
                assembler.extract_bytes16(mask, low, high_left, delta)?;
            }
            core::cmp::Ordering::Equal => {
                assembler.compare_equal_bytes16(mask, high_left, high_constant)?;
            }
            core::cmp::Ordering::Greater => {
                let high_right = stream_registers[(block + 2) % ring_len];
                assembler.extract_bytes16(mask, high_left, high_right, delta - 16)?;
            }
        }
        if delta != 16 {
            assembler.compare_equal_bytes16(mask, mask, high_constant)?;
        }
        assembler.compare_equal_bytes16(low, low, low_constant)?;
        assembler.and_bytes16(mask, mask, low)?;
        if block != 7 {
            assembler.load_vector128_offset(
                low,
                stream_base,
                u16::try_from((block + ring_len) * 16).expect("ten sliding stream vectors"),
            )?;
        }
    }
    Ok(())
}

/// Lower one of the three recipe-specialized Count kernels.
///
/// Unlike the incumbent-compatible template, this loop does not retain the
/// runtime pair-density classifier and both of its cold subgraphs. Sparse
/// recipes batch eight absent rare-column blocks, endpoint recipes recover
/// candidates directly from the endpoint mask, and periodic recipes enter a
/// straight non-overlapping successor run after the first confirmed match.
#[allow(
    clippy::too_many_lines,
    reason = "one explicit closed template keeps strategy-dependent control flow reviewable"
)]
fn emit_multi_specialized_v3(
    assembler: &mut AssemblerV3,
    literal: &[u8],
    filter: CandidateFilterV3,
    confirmation_order: &[u8],
    strategy: LoweringStrategyV3,
    sve_tail: Option<HybridSveTailV3>,
    done: LabelV3,
) -> Result<(), CountAotError> {
    let vector = assembler.new_label(LabelKindV3::VectorLoop)?;
    let candidate = assembler.new_label(LabelKindV3::CandidateLoop)?;
    let candidate_miss = assembler.new_label(LabelKindV3::Miss)?;
    let block_advance = assembler.new_label(LabelKindV3::Internal)?;
    let primary_sparse_scan = assembler.new_label(LabelKindV3::VectorLoop)?;
    let sparse_scan = assembler.new_label(LabelKindV3::VectorLoop)?;
    let sparse_hit = assembler.new_label(LabelKindV3::Internal)?;
    let sparse_first_half = assembler.new_label(LabelKindV3::Internal)?;
    let wide_batch = if strategy != LoweringStrategyV3::PeriodicRun {
        Some(assembler.new_label(LabelKindV3::VectorLoop)?)
    } else {
        None
    };
    let wide_batch_empty = if wide_batch.is_some() {
        Some(assembler.new_label(LabelKindV3::Internal)?)
    } else {
        None
    };
    let narrow_vector = if wide_batch.is_some() {
        Some(assembler.new_label(LabelKindV3::VectorLoop)?)
    } else {
        None
    };
    let wide_pair_batch = if wide_batch.is_some() {
        Some(assembler.new_label(LabelKindV3::VectorLoop)?)
    } else {
        None
    };
    let wide_pair_hit = if wide_batch.is_some() {
        Some(assembler.new_label(LabelKindV3::Internal)?)
    } else {
        None
    };
    let wide_pair_to_narrow = if wide_batch.is_some() {
        Some(assembler.new_label(LabelKindV3::Internal)?)
    } else {
        None
    };
    let wide_batch_done = if wide_batch.is_some() {
        Some(assembler.new_label(LabelKindV3::Internal)?)
    } else {
        None
    };
    let wide_candidates = if wide_batch.is_some() {
        Some([
            assembler.new_label(LabelKindV3::CandidateLoop)?,
            assembler.new_label(LabelKindV3::CandidateLoop)?,
            assembler.new_label(LabelKindV3::CandidateLoop)?,
            assembler.new_label(LabelKindV3::CandidateLoop)?,
            assembler.new_label(LabelKindV3::CandidateLoop)?,
            assembler.new_label(LabelKindV3::CandidateLoop)?,
            assembler.new_label(LabelKindV3::CandidateLoop)?,
            assembler.new_label(LabelKindV3::CandidateLoop)?,
        ])
    } else {
        None
    };
    let wide_candidate_misses = if wide_batch.is_some() {
        Some([
            assembler.new_label(LabelKindV3::Miss)?,
            assembler.new_label(LabelKindV3::Miss)?,
            assembler.new_label(LabelKindV3::Miss)?,
            assembler.new_label(LabelKindV3::Miss)?,
            assembler.new_label(LabelKindV3::Miss)?,
            assembler.new_label(LabelKindV3::Miss)?,
            assembler.new_label(LabelKindV3::Miss)?,
            assembler.new_label(LabelKindV3::Miss)?,
        ])
    } else {
        None
    };
    let wide_advances = if wide_batch.is_some() {
        Some([
            assembler.new_label(LabelKindV3::Internal)?,
            assembler.new_label(LabelKindV3::Internal)?,
            assembler.new_label(LabelKindV3::Internal)?,
            assembler.new_label(LabelKindV3::Internal)?,
            assembler.new_label(LabelKindV3::Internal)?,
            assembler.new_label(LabelKindV3::Internal)?,
            assembler.new_label(LabelKindV3::Internal)?,
            assembler.new_label(LabelKindV3::Internal)?,
        ])
    } else {
        None
    };
    let last_offset = u8::try_from(literal.len() - 1).expect("bounded nonempty literal");
    let semantic_secondary_offset = if filter.offsets[0] == last_offset {
        0
    } else {
        last_offset
    };
    let (sliding_low_offset, sliding_low_constant, sliding_high_constant) =
        if filter.offsets[0] < semantic_secondary_offset {
            (filter.offsets[0], 2_u8, SEMANTIC_SECONDARY_VECTOR_V3)
        } else {
            (
                semantic_secondary_offset,
                SEMANTIC_SECONDARY_VECTOR_V3,
                2_u8,
            )
        };
    let sliding_delta = filter.offsets[0].abs_diff(semantic_secondary_offset);
    let sparse_prefix_escalation = if filter.offsets[0] != 0 && filter.offsets[0] != last_offset {
        Some(assembler.new_label(LabelKindV3::Internal)?)
    } else {
        None
    };
    let match_run = if strategy == LoweringStrategyV3::PeriodicRun {
        Some(assembler.new_label(LabelKindV3::CandidateLoop)?)
    } else {
        None
    };
    let match_run_miss = if strategy == LoweringStrategyV3::PeriodicRun {
        Some(assembler.new_label(LabelKindV3::Miss)?)
    } else {
        None
    };
    let scalar = assembler.new_label(LabelKindV3::ScalarTail)?;
    let scalar_loop = if sve_tail.is_some() {
        assembler.new_label(LabelKindV3::ScalarTail)?
    } else {
        scalar
    };
    let scalar_miss = assembler.new_label(LabelKindV3::Miss)?;
    let width = u16::try_from(literal.len()).map_err(|_| CountAotError::ArithmeticOverflow {
        site: CountAotArithmeticSite::CodeOffset,
    })?;
    let sliding_required_remaining =
        sliding_pair_required_remaining_v3(width, sliding_low_offset, sliding_delta)?;
    let value_registers = [X10, X11, X12, X14];
    let vector_registers = [2_u8, 3, 16, 17];

    assembler.mov_imm64_minimal(X13, 0)?;
    assembler.cmp_imm64(X1, width)?;
    assembler.branch_cond(ConditionV3::CarryClear, done)?;
    assembler.sub_imm(X4, X1, width)?;
    assembler.mov_imm64_minimal(X3, 0)?;
    if wide_batch.is_some() {
        // Runtime mode is learned only from batch survival. Values zero
        // through three count consecutive fully dense endpoint-empty batches;
        // four selects the fused primary/endpoint absence scan.
        assembler.mov_imm64_minimal(X16, 0)?;
    }
    for index in 0..usize::from(filter.len) {
        let offset = usize::from(filter.offsets[index]);
        assembler.mov_imm64_minimal(value_registers[index], u64::from(literal[offset]))?;
        assembler.dup_byte16(vector_registers[index], value_registers[index])?;
    }
    assembler.mov_imm64_minimal(X17, SPARSE_NIBBLE_BITS_V3)?;
    assembler.mov_imm64_minimal(
        X8,
        u64::from(literal[usize::from(semantic_secondary_offset)]),
    )?;
    assembler.dup_byte16(SEMANTIC_SECONDARY_VECTOR_V3, X8)?;
    if sparse_prefix_escalation.is_some() {
        assembler.mov_imm64_minimal(X8, u64::from(literal[0]))?;
        assembler.dup_byte16(SEMANTIC_PREFIX_VECTOR_V3, X8)?;
    }

    // Hoist the exact confirmation constants once. Register identities are
    // fixed by the sealed Neon-v1 register plan.
    for (chunk_index, chunk) in literal.chunks_exact(16).enumerate() {
        let mut low = [0_u8; 8];
        let mut high = [0_u8; 8];
        low.copy_from_slice(&chunk[..8]);
        high.copy_from_slice(&chunk[8..]);
        let vector_register =
            u8::try_from(21_usize + chunk_index).expect("at most two full vectors");
        assembler.mov_imm64_minimal(X8, u64::from_le_bytes(low))?;
        assembler.move_x_to_vector_double(vector_register, X8)?;
        assembler.mov_imm64_minimal(X8, u64::from_le_bytes(high))?;
        assembler.insert_x_to_vector_double_lane1(vector_register, X8)?;
    }
    let full_vector_bytes = literal.len() / 16 * 16;
    for (tail_index, chunk) in literal[full_vector_bytes..].chunks_exact(8).enumerate() {
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(chunk);
        assembler.mov_imm64_minimal(X8, u64::from_le_bytes(bytes))?;
        let global_chunk = full_vector_bytes / 8 + tail_index;
        assembler.move_x_to_vector_double(
            u8::try_from(4_usize + global_chunk).expect("at most four double chunks"),
            X8,
        )?;
    }
    if let Some(suffix_offset) = overlapping_suffix_offset_v3(literal.len()) {
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(&literal[suffix_offset..]);
        assembler.mov_imm64_minimal(X8, u64::from_le_bytes(bytes))?;
        assembler.move_x_to_vector_double(OVERLAPPING_SUFFIX_VECTOR_V3, X8)?;
    }

    assembler.bind(vector)?;
    assembler.cmp_reg64(X3, X4)?;
    assembler.branch_cond(ConditionV3::Higher, done)?;
    if let (
        Some(narrow_vector),
        Some(wide_pair_batch),
        Some(wide_pair_to_narrow),
        Some(wide_batch),
    ) = (
        narrow_vector,
        wide_pair_batch,
        wide_pair_to_narrow,
        wide_batch,
    ) {
        assembler.sub_reg(X5, X4, X3)?;
        assembler.cmp_imm64(X5, SPARSE_SCAN_STARTS_V3 - 1)?;
        assembler.branch_cond(ConditionV3::CarryClear, wide_pair_to_narrow)?;
        assembler.cmp_imm64(X16, 4)?;
        assembler.branch_cond(ConditionV3::Equal, wide_pair_batch)?;
        assembler.branch(wide_batch)?;
        assembler.bind(wide_pair_to_narrow)?;
        for index in 0..usize::from(filter.len).min(2) {
            assembler.dup_byte16(vector_registers[index], value_registers[index])?;
        }
        assembler.mov_imm64_minimal(X16, 0)?;
        assembler.branch(narrow_vector)?;
        assembler.bind(narrow_vector)?;
    }
    assembler.sub_reg(X5, X4, X3)?;
    assembler.cmp_imm64(X5, SIMD_CANDIDATE_STARTS_V3 - 1)?;
    assembler.branch_cond(ConditionV3::CarryClear, scalar_loop)?;
    if sve_tail.is_some() {
        assembler.cmp_imm64(X5, SIMD_CANDIDATE_STARTS_V3 - 1)?;
        assembler.branch_cond(ConditionV3::Equal, scalar)?;
    }
    assembler.add_reg(X15, X0, X3)?;
    assembler.add_imm(X8, X15, u16::from(filter.offsets[0]))?;
    assembler.load_vector128(0, X8)?;
    assembler.compare_equal_bytes16(0, 0, vector_registers[0])?;
    // Prove the primary mask empty before paying for any other filter
    // column. Only this proof admits the wide one-column scan below.
    assembler.unsigned_max_across_bytes16(1, 0)?;
    assembler.move_vector_byte_to32(X8, 1)?;
    assembler.cmp_imm64(X8, 0)?;
    assembler.branch_cond(ConditionV3::Equal, primary_sparse_scan)?;
    for index in 1..usize::from(filter.len) {
        assembler.add_imm(X8, X15, u16::from(filter.offsets[index]))?;
        assembler.load_vector128(1, X8)?;
        assembler.compare_equal_bytes16(1, 1, vector_registers[index])?;
        assembler.and_bytes16(0, 0, 1)?;
    }
    assembler.shrink_narrow_bytes_from_halfwords(0, 0, 4)?;
    assembler.move_vector_double_to64(X6, 0)?;
    assembler.and_reg(X6, X6, X17)?;
    assembler.cmp_imm64(X6, 0)?;
    assembler.branch_cond(ConditionV3::Equal, sparse_scan)?;
    assembler.branch(candidate)?;

    if let (
        Some(wide_batch),
        Some(wide_batch_empty),
        Some(wide_pair_batch),
        Some(wide_pair_hit),
        Some(wide_batch_done),
        Some(wide_candidates),
        Some(wide_candidate_misses),
        Some(wide_advances),
    ) = (
        wide_batch,
        wide_batch_empty,
        wide_pair_batch,
        wide_pair_hit,
        wide_batch_done,
        wide_candidates,
        wide_candidate_misses,
        wide_advances,
    ) {
        // Start every long non-periodic iteration with eight primary masks.
        // An empty union skips all 128 candidate starts after one reduction.
        // Nonempty masks are consumed in order. Each block pays for the
        // remaining columns only until one rejects every surviving lane.
        // Candidate exhaustion continues with the next retained mask instead
        // of restarting a 128-start scan that overlaps the prior batch.
        assembler.bind(wide_batch)?;
        assembler.add_reg(X15, X0, X3)?;
        assembler.add_imm(X8, X15, u16::from(filter.offsets[0]))?;
        // Two structure loads collect all 128 primary bytes directly into
        // the retained masks. This is both denser than eight scalar Q loads
        // and leaves v0-v3 available for the semantic endpoint pass below.
        assembler.load_vectors4x128(SPARSE_BLOCK_MASK_BASE_V3, X8)?;
        assembler.add_imm(X9, X8, SIMD_CANDIDATE_STARTS_V3 * 4)?;
        assembler.load_vectors4x128(SPARSE_BLOCK_MASK_BASE_V3 + 4, X9)?;
        for block in 0..SPARSE_SCAN_BLOCKS_V3 {
            let mask = u8::try_from(u16::from(SPARSE_BLOCK_MASK_BASE_V3) + block)
                .expect("eight wide primary masks");
            assembler.compare_equal_bytes16(mask, mask, vector_registers[0])?;
        }
        assembler.or_bytes16(0, SPARSE_BLOCK_MASK_BASE_V3, SPARSE_BLOCK_MASK_BASE_V3 + 1)?;
        assembler.or_bytes16(
            1,
            SPARSE_BLOCK_MASK_BASE_V3 + 2,
            SPARSE_BLOCK_MASK_BASE_V3 + 3,
        )?;
        assembler.or_bytes16(0, 0, 1)?;
        assembler.or_bytes16(
            1,
            SPARSE_BLOCK_MASK_BASE_V3 + 4,
            SPARSE_BLOCK_MASK_BASE_V3 + 5,
        )?;
        assembler.or_bytes16(0, 0, 1)?;
        assembler.or_bytes16(
            1,
            SPARSE_BLOCK_MASK_BASE_V3 + 6,
            SPARSE_BLOCK_MASK_BASE_V3 + 7,
        )?;
        assembler.or_bytes16(1, 0, 1)?;
        assembler.unsigned_max_across_bytes16(1, 1)?;
        assembler.move_vector_byte_to32(X8, 1)?;
        assembler.and_reg(X16, X16, X8)?;
        assembler.cmp_imm64(X8, 0)?;
        assembler.branch_cond(ConditionV3::Equal, wide_batch_empty)?;
        // Bit three is the current-batch qualification marker; the low two
        // bits retain the prior consecutive count until the batch closes.
        assembler.add_imm(X16, X16, 8)?;

        for block in 0..usize::from(SPARSE_SCAN_BLOCKS_V3) {
            let mask = u8::try_from(usize::from(SPARSE_BLOCK_MASK_BASE_V3) + block)
                .expect("eight wide primary masks");
            let wide_candidate = wide_candidates[block];
            let wide_candidate_miss = wide_candidate_misses[block];
            let wide_advance = wide_advances[block];

            // Keep the fused-mode bit only while every block has a primary
            // survivor and the semantic endpoint rejects all of its lanes.
            assembler.unsigned_max_across_bytes16(1, mask)?;
            assembler.move_vector_byte_to32(X8, 1)?;
            assembler.and_reg(X16, X16, X8)?;
            assembler.cmp_imm64(X8, 0)?;
            assembler.branch_cond(ConditionV3::Equal, wide_advance)?;

            assembler.add_reg(X15, X0, X3)?;
            assembler.add_imm(X8, X15, u16::from(semantic_secondary_offset))?;
            assembler.load_vector128(0, X8)?;
            assembler.compare_equal_bytes16(0, 0, SEMANTIC_SECONDARY_VECTOR_V3)?;
            assembler.and_bytes16(mask, mask, 0)?;
            assembler.unsigned_max_across_bytes16(1, mask)?;
            assembler.move_vector_byte_to32(X8, 1)?;
            assembler.cmp_imm64(X8, 0)?;
            assembler.branch_cond(ConditionV3::Equal, wide_advance)?;
            assembler.mov_imm64_minimal(X16, 0)?;
            for index in 1..usize::from(filter.len) {
                if filter.offsets[index] == semantic_secondary_offset {
                    continue;
                }
                assembler.add_imm(X8, X15, u16::from(filter.offsets[index]))?;
                assembler.load_vector128(0, X8)?;
                assembler.compare_equal_bytes16(0, 0, vector_registers[index])?;
                assembler.and_bytes16(mask, mask, 0)?;
                assembler.unsigned_max_across_bytes16(1, mask)?;
                assembler.move_vector_byte_to32(X8, 1)?;
                assembler.cmp_imm64(X8, 0)?;
                assembler.branch_cond(ConditionV3::Equal, wide_advance)?;
            }
            assembler.or_bytes16(0, mask, mask)?;
            assembler.shrink_narrow_bytes_from_halfwords(0, 0, 4)?;
            assembler.move_vector_double_to64(X6, 0)?;
            assembler.and_reg(X6, X6, X17)?;
            assembler.cmp_imm64(X6, 0)?;
            assembler.branch_cond(ConditionV3::Equal, wide_advance)?;

            assembler.bind(wide_candidate)?;
            assembler.reverse_bits(X7, X6)?;
            assembler.count_leading_zeros(X7, X7)?;
            assembler.sub_imm(X9, X6, 1)?;
            assembler.and_reg(X6, X6, X9)?;
            assembler.lsr_imm(X7, X7, 2)?;
            assembler.add_reg(X5, X3, X7)?;
            assembler.add_reg(X15, X0, X5)?;
            emit_confirmation_ordered_v3(
                assembler,
                literal,
                confirmation_order,
                filter.offsets(),
                X15,
                wide_candidate_miss,
            )?;
            assembler.add_imm(X13, X13, 1)?;
            assembler.add_imm(X3, X5, width)?;
            assembler.branch(vector)?;

            assembler.bind(wide_candidate_miss)?;
            assembler.cmp_imm64(X6, 0)?;
            assembler.branch_cond(ConditionV3::NotEqual, wide_candidate)?;
            assembler.bind(wide_advance)?;
            assembler.add_imm(X3, X3, SIMD_CANDIDATE_STARTS_V3)?;
        }
        assembler.cmp_imm64(X16, 0)?;
        assembler.branch_cond(ConditionV3::Equal, wide_batch_done)?;
        assembler.and_low_bits(X16, X16, 2)?;
        assembler.add_imm(X16, X16, 1)?;
        // v20 is outside the LD1 scratch window and remains the primary
        // splat after four consecutive exact all-eight-primary,
        // endpoint-empty observations.
        assembler.or_bytes16(20, vector_registers[0], vector_registers[0])?;
        assembler.bind(wide_batch_done)?;
        assembler.branch(vector)?;

        assembler.bind(wide_pair_batch)?;
        assembler.add_reg(X15, X0, X3)?;
        assembler.add_imm(X8, X15, u16::from(filter.offsets[0]))?;
        assembler.load_vectors4x128(SPARSE_BLOCK_MASK_BASE_V3, X8)?;
        assembler.add_imm(X9, X8, SIMD_CANDIDATE_STARTS_V3 * 4)?;
        assembler.load_vectors4x128(SPARSE_BLOCK_MASK_BASE_V3 + 4, X9)?;
        for block in 0..SPARSE_SCAN_BLOCKS_V3 {
            let mask = u8::try_from(u16::from(SPARSE_BLOCK_MASK_BASE_V3) + block)
                .expect("eight fused primary masks");
            assembler.compare_equal_bytes16(mask, mask, 20)?;
        }
        assembler.add_imm(X8, X15, u16::from(semantic_secondary_offset))?;
        assembler.add_imm(X9, X8, SIMD_CANDIDATE_STARTS_V3 * 4)?;
        for (mask_base, base) in [
            (SPARSE_BLOCK_MASK_BASE_V3, X8),
            (SPARSE_BLOCK_MASK_BASE_V3 + 4, X9),
        ] {
            assembler.load_vectors4x128(0, base)?;
            for lane in 0_u8..4 {
                assembler.compare_equal_bytes16(lane, lane, SEMANTIC_SECONDARY_VECTOR_V3)?;
                assembler.and_bytes16(mask_base + lane, mask_base + lane, lane)?;
            }
        }
        assembler.or_bytes16(0, SPARSE_BLOCK_MASK_BASE_V3, SPARSE_BLOCK_MASK_BASE_V3 + 1)?;
        assembler.or_bytes16(
            1,
            SPARSE_BLOCK_MASK_BASE_V3 + 2,
            SPARSE_BLOCK_MASK_BASE_V3 + 3,
        )?;
        assembler.or_bytes16(0, 0, 1)?;
        assembler.or_bytes16(
            1,
            SPARSE_BLOCK_MASK_BASE_V3 + 4,
            SPARSE_BLOCK_MASK_BASE_V3 + 5,
        )?;
        assembler.or_bytes16(0, 0, 1)?;
        assembler.or_bytes16(
            1,
            SPARSE_BLOCK_MASK_BASE_V3 + 6,
            SPARSE_BLOCK_MASK_BASE_V3 + 7,
        )?;
        assembler.or_bytes16(1, 0, 1)?;
        assembler.unsigned_max_across_bytes16(1, 1)?;
        assembler.move_vector_byte_to32(X8, 1)?;
        assembler.cmp_imm64(X8, 0)?;
        assembler.branch_cond(ConditionV3::NotEqual, wide_pair_hit)?;
        assembler.add_imm(X3, X3, SPARSE_SCAN_STARTS_V3)?;
        assembler.branch(vector)?;

        assembler.bind(wide_pair_hit)?;
        for index in 0..usize::from(filter.len).min(2) {
            assembler.dup_byte16(vector_registers[index], value_registers[index])?;
        }
        assembler.mov_imm64_minimal(X16, 0)?;
        assembler.branch(sparse_scan)?;

        assembler.bind(wide_batch_empty)?;
        assembler.add_imm(X3, X3, SPARSE_SCAN_STARTS_V3)?;
        assembler.branch(vector)?;
    }

    assembler.bind(candidate)?;
    assembler.reverse_bits(X7, X6)?;
    assembler.count_leading_zeros(X7, X7)?;
    assembler.sub_imm(X9, X6, 1)?;
    assembler.and_reg(X6, X6, X9)?;
    assembler.lsr_imm(X7, X7, 2)?;
    assembler.add_reg(X5, X3, X7)?;
    assembler.add_reg(X15, X0, X5)?;
    emit_confirmation_ordered_v3(
        assembler,
        literal,
        confirmation_order,
        filter.offsets(),
        X15,
        candidate_miss,
    )?;
    assembler.add_imm(X13, X13, 1)?;
    assembler.add_imm(X3, X5, width)?;
    assembler.branch(match_run.unwrap_or(vector))?;

    assembler.bind(candidate_miss)?;
    assembler.cmp_imm64(X6, 0)?;
    assembler.branch_cond(ConditionV3::NotEqual, candidate)?;
    assembler.bind(block_advance)?;
    assembler.add_imm(X3, X3, SIMD_CANDIDATE_STARTS_V3)?;
    assembler.branch(vector)?;

    // A primary-empty ordinary block enters a single-column 128-start scan.
    // Every hit-bearing group returns through the shared classifier to the
    // complete filter, so a primary byte can never become a semantic match by
    // itself. On genuinely rare primaries this halves sparse-scan loads and
    // comparisons; primary-present/composite-empty blocks never enter here.
    assembler.bind(primary_sparse_scan)?;
    assembler.add_imm(X3, X3, SIMD_CANDIDATE_STARTS_V3)?;
    assembler.cmp_reg64(X3, X4)?;
    assembler.branch_cond(ConditionV3::Higher, done)?;
    assembler.sub_reg(X5, X4, X3)?;
    assembler.cmp_imm64(X5, SPARSE_SCAN_STARTS_V3 - 1)?;
    assembler.branch_cond(ConditionV3::CarryClear, vector)?;
    assembler.add_reg(X15, X0, X3)?;
    assembler.add_imm(X8, X15, u16::from(filter.offsets[0]))?;
    for block in 0..SPARSE_SCAN_BLOCKS_V3 {
        let offset = block.checked_mul(SIMD_CANDIDATE_STARTS_V3).ok_or(
            CountAotError::ArithmeticOverflow {
                site: CountAotArithmeticSite::CodeOffset,
            },
        )?;
        let mask = u8::try_from(u16::from(SPARSE_BLOCK_MASK_BASE_V3) + block)
            .expect("eight sparse primary masks");
        assembler.load_vector128_offset(mask, X8, offset)?;
        assembler.compare_equal_bytes16(mask, mask, vector_registers[0])?;
    }
    assembler.or_bytes16(
        SPARSE_PAIR_01_MASK_V3,
        SPARSE_BLOCK_MASK_BASE_V3,
        SPARSE_BLOCK_MASK_BASE_V3 + 1,
    )?;
    assembler.or_bytes16(
        SPARSE_PAIR_23_MASK_V3,
        SPARSE_BLOCK_MASK_BASE_V3 + 2,
        SPARSE_BLOCK_MASK_BASE_V3 + 3,
    )?;
    assembler.or_bytes16(
        SPARSE_PAIR_45_MASK_V3,
        SPARSE_BLOCK_MASK_BASE_V3 + 4,
        SPARSE_BLOCK_MASK_BASE_V3 + 5,
    )?;
    assembler.or_bytes16(
        SPARSE_PAIR_67_MASK_V3,
        SPARSE_BLOCK_MASK_BASE_V3 + 6,
        SPARSE_BLOCK_MASK_BASE_V3 + 7,
    )?;
    assembler.or_bytes16(1, SPARSE_PAIR_01_MASK_V3, SPARSE_PAIR_23_MASK_V3)?;
    assembler.or_bytes16(0, SPARSE_PAIR_45_MASK_V3, SPARSE_PAIR_67_MASK_V3)?;
    assembler.or_bytes16(1, 1, 0)?;
    assembler.unsigned_max_across_bytes16(1, 1)?;
    assembler.move_vector_byte_to32(X8, 1)?;
    assembler.cmp_imm64(X8, 0)?;
    assembler.branch_cond(ConditionV3::NotEqual, sparse_hit)?;
    assembler.add_imm(X3, X3, SPARSE_SCAN_STARTS_V3 - SIMD_CANDIDATE_STARTS_V3)?;
    assembler.branch(primary_sparse_scan)?;

    // A composite-empty block whose primary is present takes a semantic pair
    // route. The second column is the literal suffix unless the primary is
    // already the suffix, in which case it is the prefix. This retains the
    // original two-column wide-loop cost while preventing an internal
    // optimizer pair from repeatedly rediscovering suffix near-matches.
    assembler.bind(sparse_scan)?;
    assembler.add_imm(X3, X3, SIMD_CANDIDATE_STARTS_V3)?;
    assembler.cmp_reg64(X3, X4)?;
    assembler.branch_cond(ConditionV3::Higher, done)?;
    assembler.sub_reg(X5, X4, X3)?;
    assembler.cmp_imm64(X5, sliding_required_remaining)?;
    assembler.branch_cond(ConditionV3::CarryClear, vector)?;
    assembler.add_reg(X15, X0, X3)?;
    assembler.add_imm(X8, X15, u16::from(sliding_low_offset))?;
    emit_sliding_pair_masks_v3(
        assembler,
        X8,
        sliding_delta,
        sliding_low_constant,
        sliding_high_constant,
    )?;
    if sparse_prefix_escalation.is_some() {
        // Preserve all eight pair masks until the survivor branch so a dense
        // internal+suffix stream can be refined by the prefix without
        // rescanning either earlier column.
        assembler.or_bytes16(0, SPARSE_BLOCK_MASK_BASE_V3, SPARSE_BLOCK_MASK_BASE_V3 + 1)?;
        assembler.or_bytes16(
            1,
            SPARSE_BLOCK_MASK_BASE_V3 + 2,
            SPARSE_BLOCK_MASK_BASE_V3 + 3,
        )?;
        assembler.or_bytes16(0, 0, 1)?;
        assembler.or_bytes16(
            1,
            SPARSE_BLOCK_MASK_BASE_V3 + 4,
            SPARSE_BLOCK_MASK_BASE_V3 + 5,
        )?;
        assembler.or_bytes16(0, 0, 1)?;
        assembler.or_bytes16(
            1,
            SPARSE_BLOCK_MASK_BASE_V3 + 6,
            SPARSE_BLOCK_MASK_BASE_V3 + 7,
        )?;
        assembler.or_bytes16(1, 0, 1)?;
    } else {
        assembler.or_bytes16(
            SPARSE_PAIR_01_MASK_V3,
            SPARSE_BLOCK_MASK_BASE_V3,
            SPARSE_BLOCK_MASK_BASE_V3 + 1,
        )?;
        assembler.or_bytes16(
            SPARSE_PAIR_23_MASK_V3,
            SPARSE_BLOCK_MASK_BASE_V3 + 2,
            SPARSE_BLOCK_MASK_BASE_V3 + 3,
        )?;
        assembler.or_bytes16(
            SPARSE_PAIR_45_MASK_V3,
            SPARSE_BLOCK_MASK_BASE_V3 + 4,
            SPARSE_BLOCK_MASK_BASE_V3 + 5,
        )?;
        assembler.or_bytes16(
            SPARSE_PAIR_67_MASK_V3,
            SPARSE_BLOCK_MASK_BASE_V3 + 6,
            SPARSE_BLOCK_MASK_BASE_V3 + 7,
        )?;
        assembler.or_bytes16(1, SPARSE_PAIR_01_MASK_V3, SPARSE_PAIR_23_MASK_V3)?;
        assembler.or_bytes16(0, SPARSE_PAIR_45_MASK_V3, SPARSE_PAIR_67_MASK_V3)?;
        assembler.or_bytes16(1, 1, 0)?;
    }
    assembler.unsigned_max_across_bytes16(1, 1)?;
    assembler.move_vector_byte_to32(X8, 1)?;
    assembler.cmp_imm64(X8, 0)?;
    assembler.branch_cond(
        ConditionV3::NotEqual,
        sparse_prefix_escalation.unwrap_or(sparse_hit),
    )?;
    assembler.add_imm(X3, X3, SPARSE_SCAN_STARTS_V3 - SIMD_CANDIDATE_STARTS_V3)?;
    assembler.branch(sparse_scan)?;

    if let Some(sparse_prefix_escalation) = sparse_prefix_escalation {
        // Only a surviving internal-primary+suffix batch pays for the prefix.
        // If all three semantic columns reject the batch, resume the same
        // 128-start loop; otherwise classify its earliest hit-bearing block.
        assembler.bind(sparse_prefix_escalation)?;
        for block in 0..SPARSE_SCAN_BLOCKS_V3 {
            let offset = block.checked_mul(SIMD_CANDIDATE_STARTS_V3).ok_or(
                CountAotError::ArithmeticOverflow {
                    site: CountAotArithmeticSite::CodeOffset,
                },
            )?;
            let mask = u8::try_from(u16::from(SPARSE_BLOCK_MASK_BASE_V3) + block)
                .expect("eight sparse masks");
            assembler.load_vector128_offset(0, X15, offset)?;
            assembler.compare_equal_bytes16(0, 0, SEMANTIC_PREFIX_VECTOR_V3)?;
            assembler.and_bytes16(mask, mask, 0)?;
        }
        assembler.or_bytes16(
            SPARSE_PAIR_01_MASK_V3,
            SPARSE_BLOCK_MASK_BASE_V3,
            SPARSE_BLOCK_MASK_BASE_V3 + 1,
        )?;
        assembler.or_bytes16(
            SPARSE_PAIR_23_MASK_V3,
            SPARSE_BLOCK_MASK_BASE_V3 + 2,
            SPARSE_BLOCK_MASK_BASE_V3 + 3,
        )?;
        assembler.or_bytes16(
            SPARSE_PAIR_45_MASK_V3,
            SPARSE_BLOCK_MASK_BASE_V3 + 4,
            SPARSE_BLOCK_MASK_BASE_V3 + 5,
        )?;
        assembler.or_bytes16(
            SPARSE_PAIR_67_MASK_V3,
            SPARSE_BLOCK_MASK_BASE_V3 + 6,
            SPARSE_BLOCK_MASK_BASE_V3 + 7,
        )?;
        assembler.or_bytes16(1, SPARSE_PAIR_01_MASK_V3, SPARSE_PAIR_23_MASK_V3)?;
        assembler.or_bytes16(0, SPARSE_PAIR_45_MASK_V3, SPARSE_PAIR_67_MASK_V3)?;
        assembler.or_bytes16(1, 1, 0)?;
        assembler.unsigned_max_across_bytes16(1, 1)?;
        assembler.move_vector_byte_to32(X8, 1)?;
        assembler.cmp_imm64(X8, 0)?;
        assembler.branch_cond(ConditionV3::NotEqual, sparse_hit)?;
        assembler.add_imm(X3, X3, SPARSE_SCAN_STARTS_V3 - SIMD_CANDIDATE_STARTS_V3)?;
        assembler.branch(sparse_scan)?;
    }

    assembler.bind(sparse_hit)?;
    assembler.or_bytes16(1, SPARSE_PAIR_01_MASK_V3, SPARSE_PAIR_23_MASK_V3)?;
    assembler.unsigned_max_across_bytes16(1, 1)?;
    assembler.move_vector_byte_to32(X8, 1)?;
    assembler.cmp_imm64(X8, 0)?;
    assembler.branch_cond(ConditionV3::NotEqual, sparse_first_half)?;
    assembler.add_imm(X3, X3, SIMD_CANDIDATE_STARTS_V3 * 4)?;
    assembler.unsigned_max_across_bytes16(1, SPARSE_PAIR_45_MASK_V3)?;
    assembler.move_vector_byte_to32(X8, 1)?;
    assembler.cmp_imm64(X8, 0)?;
    assembler.branch_cond(ConditionV3::NotEqual, vector)?;
    assembler.add_imm(X3, X3, SIMD_CANDIDATE_STARTS_V3 * 2)?;
    assembler.branch(vector)?;

    assembler.bind(sparse_first_half)?;
    assembler.unsigned_max_across_bytes16(1, SPARSE_PAIR_01_MASK_V3)?;
    assembler.move_vector_byte_to32(X8, 1)?;
    assembler.cmp_imm64(X8, 0)?;
    assembler.branch_cond(ConditionV3::NotEqual, vector)?;
    assembler.add_imm(X3, X3, SIMD_CANDIDATE_STARTS_V3 * 2)?;
    assembler.branch(vector)?;

    if let (Some(match_run), Some(match_run_miss)) = (match_run, match_run_miss) {
        assembler.bind(match_run)?;
        assembler.cmp_reg64(X3, X4)?;
        assembler.branch_cond(ConditionV3::Higher, done)?;
        assembler.add_reg(X15, X0, X3)?;
        emit_confirmation_ordered_v3(
            assembler,
            literal,
            confirmation_order,
            &[],
            X15,
            match_run_miss,
        )?;
        assembler.add_imm(X13, X13, 1)?;
        assembler.add_imm(X3, X3, width)?;
        assembler.branch(match_run)?;
        assembler.bind(match_run_miss)?;
        assembler.add_imm(X3, X3, 1)?;
        assembler.branch(vector)?;
    }

    assembler.bind(scalar)?;
    if let Some(sve_tail) = sve_tail {
        emit_hybrid_sve_exact_tail_v3(assembler, literal, sve_tail, scalar_loop, done)?;
        assembler.bind(scalar_loop)?;
    }
    assembler.cmp_reg64(X3, X4)?;
    assembler.branch_cond(ConditionV3::Higher, done)?;
    assembler.add_reg(X15, X0, X3)?;
    for index in 0..usize::from(filter.len) {
        assembler.load_byte(X8, X15, u16::from(filter.offsets[index]))?;
        assembler.cmp_reg32(X8, value_registers[index])?;
        assembler.branch_cond(ConditionV3::NotEqual, scalar_miss)?;
    }
    emit_confirmation_ordered_v3(
        assembler,
        literal,
        confirmation_order,
        filter.offsets(),
        X15,
        scalar_miss,
    )?;
    assembler.add_imm(X13, X13, 1)?;
    assembler.add_imm(X3, X3, width)?;
    assembler.branch(if sve_tail.is_some() {
        scalar_loop
    } else {
        match_run.unwrap_or(vector)
    })?;
    assembler.bind(scalar_miss)?;
    assembler.add_imm(X3, X3, 1)?;
    assembler.branch(scalar_loop)
}

/// NEON periodic scan with one complete-filter reduction per 16 starts.
///
/// Periodic literals deliberately bypass the generic staged sparse graph:
/// their repeated bytes make a one-column absence classifier unreliable.
/// Intersecting the complete sealed period filter first both removes false
/// candidate storms and leaves a compact lane-recovery loop. Confirmed matches
/// enter the exact non-overlapping successor run.
#[allow(
    clippy::too_many_lines,
    reason = "the closed periodic mask and successor graph is intentionally explicit"
)]
fn emit_periodic_neon_v3(
    assembler: &mut AssemblerV3,
    literal: &[u8],
    filter: CandidateFilterV3,
    confirmation_order: &[u8],
    periodic_stride: u8,
    sve_tail: Option<HybridSveTailV3>,
    done: LabelV3,
) -> Result<(), CountAotError> {
    if periodic_stride == 0 || usize::from(periodic_stride) >= literal.len() || filter.len != 2 {
        return Err(CountAotError::InternalInvariant {
            at: "invalid periodic NEON stride",
        });
    }
    let wide = assembler.new_label(LabelKindV3::VectorLoop)?;
    let wide_hit = assembler.new_label(LabelKindV3::Internal)?;
    let vector = assembler.new_label(LabelKindV3::VectorLoop)?;
    let candidate = assembler.new_label(LabelKindV3::CandidateLoop)?;
    let candidate_miss = assembler.new_label(LabelKindV3::Miss)?;
    let advance = assembler.new_label(LabelKindV3::Internal)?;
    let match_run = if sve_tail.is_none() {
        Some(assembler.new_label(LabelKindV3::CandidateLoop)?)
    } else {
        None
    };
    let match_run_miss = if sve_tail.is_none() {
        Some(assembler.new_label(LabelKindV3::Miss)?)
    } else {
        None
    };
    let scalar = assembler.new_label(LabelKindV3::ScalarTail)?;
    let scalar_loop = if sve_tail.is_some() {
        assembler.new_label(LabelKindV3::ScalarTail)?
    } else {
        scalar
    };
    let scalar_miss = assembler.new_label(LabelKindV3::Miss)?;
    let width = u16::try_from(literal.len()).map_err(|_| CountAotError::ArithmeticOverflow {
        site: CountAotArithmeticSite::CodeOffset,
    })?;
    let value_registers = [X10, X11, X12, X14];
    // V0-V3 are the four-register load window in the wide loop. Keep the
    // filter splats above it so each 64-byte group needs only two LD1s.
    let vector_registers = [18_u8, 19, 16, 17];

    assembler.mov_imm64_minimal(X13, 0)?;
    assembler.cmp_imm64(X1, width)?;
    assembler.branch_cond(ConditionV3::CarryClear, done)?;
    assembler.sub_imm(X4, X1, width)?;
    assembler.mov_imm64_minimal(X3, 0)?;
    for index in 0..usize::from(filter.len) {
        let offset = usize::from(filter.offsets[index]);
        assembler.mov_imm64_minimal(value_registers[index], u64::from(literal[offset]))?;
        assembler.dup_byte16(vector_registers[index], value_registers[index])?;
    }
    assembler.mov_imm64_minimal(X17, SPARSE_NIBBLE_BITS_V3)?;

    for (chunk_index, chunk) in literal.chunks_exact(16).enumerate() {
        let mut low = [0_u8; 8];
        let mut high = [0_u8; 8];
        low.copy_from_slice(&chunk[..8]);
        high.copy_from_slice(&chunk[8..]);
        let vector_register =
            u8::try_from(21_usize + chunk_index).expect("at most two full vectors");
        assembler.mov_imm64_minimal(X8, u64::from_le_bytes(low))?;
        assembler.move_x_to_vector_double(vector_register, X8)?;
        assembler.mov_imm64_minimal(X8, u64::from_le_bytes(high))?;
        assembler.insert_x_to_vector_double_lane1(vector_register, X8)?;
    }
    let full_vector_bytes = literal.len() / 16 * 16;
    for (tail_index, chunk) in literal[full_vector_bytes..].chunks_exact(8).enumerate() {
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(chunk);
        assembler.mov_imm64_minimal(X8, u64::from_le_bytes(bytes))?;
        let global_chunk = full_vector_bytes / 8 + tail_index;
        assembler.move_x_to_vector_double(
            u8::try_from(4_usize + global_chunk).expect("at most four double chunks"),
            X8,
        )?;
    }
    if let Some(suffix_offset) = overlapping_suffix_offset_v3(literal.len()) {
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(&literal[suffix_offset..]);
        assembler.mov_imm64_minimal(X8, u64::from_le_bytes(bytes))?;
        assembler.move_x_to_vector_double(OVERLAPPING_SUFFIX_VECTOR_V3, X8)?;
    }

    // Scan eight blocks using the two sealed period-boundary columns. This
    // retains their close structural relationship; semantic endpoints are
    // paid only by confirmation after a surviving block.
    assembler.bind(wide)?;
    assembler.cmp_reg64(X3, X4)?;
    assembler.branch_cond(ConditionV3::Higher, done)?;
    assembler.sub_reg(X5, X4, X3)?;
    assembler.cmp_imm64(X5, SPARSE_SCAN_STARTS_V3 - 1)?;
    assembler.branch_cond(ConditionV3::CarryClear, vector)?;
    assembler.add_reg(X15, X0, X3)?;
    assembler.add_imm(X8, X15, u16::from(filter.offsets[0]))?;
    assembler.add_imm(X9, X15, u16::from(filter.offsets[1]))?;
    for (group, (first_base, second_base)) in [(X8, X9), (X16, X5)].into_iter().enumerate() {
        if group != 0 {
            assembler.add_imm(first_base, X8, 64)?;
            assembler.add_imm(second_base, X9, 64)?;
        }
        let mask_base =
            SPARSE_BLOCK_MASK_BASE_V3 + u8::try_from(group * 4).expect("two four-vector groups");
        assembler.load_vectors4x128(0, first_base)?;
        for lane in 0_u8..4 {
            assembler.compare_equal_bytes16(mask_base + lane, lane, vector_registers[0])?;
        }
        assembler.load_vectors4x128(0, second_base)?;
        for lane in 0_u8..4 {
            assembler.compare_equal_bytes16(lane, lane, vector_registers[1])?;
            assembler.and_bytes16(mask_base + lane, mask_base + lane, lane)?;
        }
    }
    assembler.or_bytes16(
        SPARSE_PAIR_01_MASK_V3,
        SPARSE_BLOCK_MASK_BASE_V3,
        SPARSE_BLOCK_MASK_BASE_V3 + 1,
    )?;
    assembler.or_bytes16(
        SPARSE_PAIR_23_MASK_V3,
        SPARSE_BLOCK_MASK_BASE_V3 + 2,
        SPARSE_BLOCK_MASK_BASE_V3 + 3,
    )?;
    assembler.or_bytes16(
        SPARSE_PAIR_45_MASK_V3,
        SPARSE_BLOCK_MASK_BASE_V3 + 4,
        SPARSE_BLOCK_MASK_BASE_V3 + 5,
    )?;
    assembler.or_bytes16(
        SPARSE_PAIR_67_MASK_V3,
        SPARSE_BLOCK_MASK_BASE_V3 + 6,
        SPARSE_BLOCK_MASK_BASE_V3 + 7,
    )?;
    assembler.or_bytes16(1, SPARSE_PAIR_01_MASK_V3, SPARSE_PAIR_23_MASK_V3)?;
    assembler.or_bytes16(0, SPARSE_PAIR_45_MASK_V3, SPARSE_PAIR_67_MASK_V3)?;
    assembler.or_bytes16(1, 1, 0)?;
    assembler.unsigned_max_across_bytes16(1, 1)?;
    assembler.move_vector_byte_to32(X8, 1)?;
    assembler.cmp_imm64(X8, 0)?;
    assembler.branch_cond(ConditionV3::NotEqual, wide_hit)?;
    assembler.add_imm(X3, X3, SPARSE_SCAN_STARTS_V3)?;
    assembler.branch(wide)?;

    // A hit-bearing batch is rare. Locate its exact earliest 16-start block
    // from the retained masks, avoiding a second 128-start scan.
    assembler.bind(wide_hit)?;
    for mask in SPARSE_BLOCK_MASK_BASE_V3..SPARSE_BLOCK_MASK_BASE_V3 + 7 {
        assembler.unsigned_max_across_bytes16(1, mask)?;
        assembler.move_vector_byte_to32(X8, 1)?;
        assembler.cmp_imm64(X8, 0)?;
        assembler.branch_cond(ConditionV3::NotEqual, vector)?;
        assembler.add_imm(X3, X3, SIMD_CANDIDATE_STARTS_V3)?;
    }
    assembler.branch(vector)?;

    assembler.bind(vector)?;
    assembler.cmp_reg64(X3, X4)?;
    assembler.branch_cond(ConditionV3::Higher, done)?;
    assembler.sub_reg(X5, X4, X3)?;
    assembler.cmp_imm64(X5, SIMD_CANDIDATE_STARTS_V3 - 1)?;
    assembler.branch_cond(ConditionV3::CarryClear, scalar_loop)?;
    if sve_tail.is_some() {
        assembler.cmp_imm64(X5, SIMD_CANDIDATE_STARTS_V3 - 1)?;
        assembler.branch_cond(ConditionV3::Equal, scalar)?;
    }
    assembler.add_reg(X15, X0, X3)?;
    for index in 0..usize::from(filter.len) {
        let mask_register = if index == 0 { 0 } else { 1 };
        assembler.add_imm(X8, X15, u16::from(filter.offsets[index]))?;
        assembler.load_vector128(mask_register, X8)?;
        assembler.compare_equal_bytes16(mask_register, mask_register, vector_registers[index])?;
        if index != 0 {
            assembler.and_bytes16(0, 0, 1)?;
        }
    }
    assembler.shrink_narrow_bytes_from_halfwords(0, 0, 4)?;
    assembler.move_vector_double_to64(X6, 0)?;
    assembler.and_reg(X6, X6, X17)?;
    assembler.cmp_imm64(X6, 0)?;
    assembler.branch_cond(ConditionV3::Equal, advance)?;

    assembler.bind(candidate)?;
    assembler.reverse_bits(X7, X6)?;
    assembler.count_leading_zeros(X7, X7)?;
    assembler.sub_imm(X16, X6, 1)?;
    assembler.and_reg(X6, X6, X16)?;
    assembler.lsr_imm(X7, X7, 2)?;
    assembler.add_reg(X5, X3, X7)?;
    assembler.add_reg(X15, X0, X5)?;
    emit_confirmation_ordered_v3(
        assembler,
        literal,
        confirmation_order,
        filter.offsets(),
        X15,
        candidate_miss,
    )?;
    assembler.add_imm(X13, X13, 1)?;
    assembler.add_imm(X3, X5, width)?;
    assembler.branch(match_run.unwrap_or(wide))?;

    assembler.bind(candidate_miss)?;
    assembler.cmp_imm64(X6, 0)?;
    assembler.branch_cond(ConditionV3::NotEqual, candidate)?;
    assembler.bind(advance)?;
    assembler.add_imm(X3, X3, SIMD_CANDIDATE_STARTS_V3)?;
    assembler.branch(wide)?;

    if let (Some(match_run), Some(match_run_miss)) = (match_run, match_run_miss) {
        assembler.bind(match_run)?;
        assembler.cmp_reg64(X3, X4)?;
        assembler.branch_cond(ConditionV3::Higher, done)?;
        assembler.add_reg(X15, X0, X3)?;
        emit_confirmation_ordered_v3(
            assembler,
            literal,
            confirmation_order,
            &[],
            X15,
            match_run_miss,
        )?;
        assembler.add_imm(X13, X13, 1)?;
        assembler.add_imm(X3, X3, width)?;
        assembler.branch(match_run)?;
        assembler.bind(match_run_miss)?;
        assembler.add_imm(X3, X3, 1)?;
        assembler.branch(wide)?;
    }

    assembler.bind(scalar)?;
    if let Some(sve_tail) = sve_tail {
        emit_hybrid_sve_exact_tail_v3(assembler, literal, sve_tail, scalar_loop, done)?;
        assembler.bind(scalar_loop)?;
    }
    assembler.cmp_reg64(X3, X4)?;
    assembler.branch_cond(ConditionV3::Higher, done)?;
    assembler.add_reg(X15, X0, X3)?;
    for index in 0..usize::from(filter.len) {
        assembler.load_byte(X8, X15, u16::from(filter.offsets[index]))?;
        assembler.cmp_reg32(X8, value_registers[index])?;
        assembler.branch_cond(ConditionV3::NotEqual, scalar_miss)?;
    }
    emit_confirmation_ordered_v3(
        assembler,
        literal,
        confirmation_order,
        filter.offsets(),
        X15,
        scalar_miss,
    )?;
    assembler.add_imm(X13, X13, 1)?;
    assembler.add_imm(X3, X3, width)?;
    assembler.branch(if sve_tail.is_some() {
        scalar_loop
    } else {
        match_run.expect("periodic match run")
    })?;
    assembler.bind(scalar_miss)?;
    assembler.add_imm(X3, X3, 1)?;
    assembler.branch(scalar_loop)
}

fn emit_confirmation_ordered_v3(
    assembler: &mut AssemblerV3,
    literal: &[u8],
    confirmation_order: &[u8],
    proven_filter_offsets: &[u8],
    candidate_pointer: u8,
    mismatch: LabelV3,
) -> Result<(), CountAotError> {
    let vector_chunks = literal.len() / 16;
    let vector_tail_offset = vector_chunks * 16;
    let double_chunks = (literal.len() - vector_tail_offset) / 8;
    let double_tail_offset = vector_tail_offset + double_chunks * 8;
    let overlapping_suffix_offset = overlapping_suffix_offset_v3(literal.len());
    let mut emitted_vector_chunks = 0_u8;
    let mut emitted_double_chunks = 0_u8;
    let mut emitted_overlapping_suffix = false;
    for offset in confirmation_order.iter().copied() {
        if proven_filter_offsets.contains(&offset) {
            continue;
        }
        let offset = usize::from(offset);
        if offset < vector_tail_offset {
            let chunk = offset / 16;
            let bit = 1_u8 << u8::try_from(chunk).expect("at most two vector chunks");
            if emitted_vector_chunks & bit != 0 {
                continue;
            }
            emitted_vector_chunks |= bit;
            assembler.load_vector128_offset(
                0,
                candidate_pointer,
                u16::try_from(chunk * 16).expect("bounded vector offset"),
            )?;
            assembler.compare_equal_bytes16(
                0,
                0,
                u8::try_from(21_usize + chunk).expect("at most v22"),
            )?;
            assembler.unsigned_min_across_bytes16(0, 0)?;
        } else if offset < double_tail_offset {
            let chunk = (offset - vector_tail_offset) / 8;
            let bit = 1_u8 << u8::try_from(chunk).expect("at most one double chunk");
            if emitted_double_chunks & bit != 0 {
                continue;
            }
            emitted_double_chunks |= bit;
            let global_chunk = vector_tail_offset / 8 + chunk;
            assembler.load_vector_double(
                0,
                candidate_pointer,
                u16::try_from(vector_tail_offset + chunk * 8).expect("bounded double offset"),
            )?;
            assembler.compare_equal_bytes8(
                0,
                0,
                u8::try_from(4_usize + global_chunk).expect("at most v7"),
            )?;
            assembler.unsigned_min_across_bytes8(0, 0)?;
        } else if let Some(suffix_offset) = overlapping_suffix_offset {
            if emitted_overlapping_suffix {
                continue;
            }
            emitted_overlapping_suffix = true;
            assembler.add_imm(
                X9,
                candidate_pointer,
                u16::try_from(suffix_offset).expect("bounded overlapping suffix offset"),
            )?;
            assembler.load_vector_double(0, X9, 0)?;
            assembler.compare_equal_bytes8(0, 0, OVERLAPPING_SUFFIX_VECTOR_V3)?;
            assembler.unsigned_min_across_bytes8(0, 0)?;
        } else {
            assembler.load_byte(
                X8,
                candidate_pointer,
                u16::try_from(offset).expect("bounded tail offset"),
            )?;
            assembler.mov_imm64_minimal(X9, u64::from(literal[offset]))?;
            assembler.cmp_reg32(X8, X9)?;
            assembler.branch_cond(ConditionV3::NotEqual, mismatch)?;
            continue;
        }
        assembler.move_vector_byte_to32(X8, 0)?;
        assembler.cmp_imm32(X8, 255)?;
        assembler.branch_cond(ConditionV3::NotEqual, mismatch)?;
    }
    Ok(())
}

fn emit_confirmation_v3(
    assembler: &mut AssemblerV3,
    literal: &[u8],
    proven_filter_offsets: &[u8],
    candidate_pointer: u8,
    mismatch: LabelV3,
) -> Result<(), CountAotError> {
    let vector_chunks = literal.len() / 16;
    for chunk_index in 0..vector_chunks {
        let first = chunk_index * 16;
        if (first..first + 16).all(|offset| {
            proven_filter_offsets.contains(&u8::try_from(offset).expect("bounded literal offset"))
        }) {
            continue;
        }
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
        assembler.branch_cond(ConditionV3::NotEqual, mismatch)?;
    }
    let vector_tail_offset = vector_chunks * 16;
    let double_chunks = (literal.len() - vector_tail_offset) / 8;
    for chunk_index in 0..double_chunks {
        let first = vector_tail_offset + chunk_index * 8;
        if (first..first + 8).all(|offset| {
            proven_filter_offsets.contains(&u8::try_from(offset).expect("bounded literal offset"))
        }) {
            continue;
        }
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
        assembler.branch_cond(ConditionV3::NotEqual, mismatch)?;
    }
    let tail_offset = vector_tail_offset + double_chunks * 8;
    if let Some(suffix_offset) = overlapping_suffix_offset_v3(literal.len()) {
        if !(suffix_offset..literal.len()).all(|offset| {
            proven_filter_offsets.contains(&u8::try_from(offset).expect("bounded literal offset"))
        }) {
            assembler.add_imm(
                X9,
                candidate_pointer,
                u16::try_from(suffix_offset).expect("bounded overlapping suffix offset"),
            )?;
            assembler.load_vector_double(0, X9, 0)?;
            assembler.compare_equal_bytes8(0, 0, OVERLAPPING_SUFFIX_VECTOR_V3)?;
            assembler.unsigned_min_across_bytes8(0, 0)?;
            assembler.move_vector_byte_to32(X8, 0)?;
            assembler.cmp_imm32(X8, 255)?;
            assembler.branch_cond(ConditionV3::NotEqual, mismatch)?;
        }
        return Ok(());
    }
    for (index, byte) in literal[tail_offset..].iter().copied().enumerate() {
        let literal_offset = tail_offset + index;
        let narrow_offset = u8::try_from(literal_offset).expect("bounded literal offset");
        if proven_filter_offsets.contains(&narrow_offset) {
            continue;
        }
        let offset = u16::from(narrow_offset);
        assembler.load_byte(X8, candidate_pointer, offset)?;
        assembler.mov_imm64_minimal(X9, u64::from(byte))?;
        assembler.cmp_reg32(X8, X9)?;
        assembler.branch_cond(ConditionV3::NotEqual, mismatch)?;
    }
    Ok(())
}

/// Return a safe 8-byte suffix load for a residual tail when it wins over
/// scalar byte confirmation.
///
/// The suffix ends exactly at the literal boundary, so it cannot overread the
/// last legal candidate. A one-byte residual remains scalar: its four
/// instructions are cheaper than the seven-instruction unaligned suffix
/// confirmation.
fn overlapping_suffix_offset_v3(literal_len: usize) -> Option<usize> {
    let residual = literal_len % 8;
    if literal_len >= 8 && residual >= 2 {
        Some(literal_len - 8)
    } else {
        None
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LabelV3(u32);

#[derive(Clone, Copy, Debug)]
struct LabelRecordV3 {
    offset: Option<u32>,
    kind: LabelKindV3,
}

#[derive(Clone, Copy, Debug)]
struct FixupV3 {
    at: u32,
    kind: RelocationKindV3,
    target: LabelV3,
}

struct AssemblerV3 {
    code: ExactVec<u8>,
    labels: ExactVec<LabelRecordV3>,
    fixups: ExactVec<FixupV3>,
    prospective: ProspectiveV3,
    emission_work: u64,
    vector_instructions: u32,
    asimd_instructions: u32,
    sve_instructions: u32,
    sve2_instructions: u32,
    peak_scratch_bytes: u64,
}

impl AssemblerV3 {
    fn new(prospective: ProspectiveV3) -> Result<Self, CountAotError> {
        let code = exact_vec_v3(
            prospective.code_bytes,
            CountAotResource::CodeBytes,
            prospective.scratch,
            prospective.scratch_limit,
        )?;
        let labels = exact_vec_v3(
            prospective.labels,
            CountAotResource::Labels,
            prospective.scratch,
            prospective.scratch_limit,
        )?;
        let fixups = exact_vec_v3(
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
            asimd_instructions: 0,
            sve_instructions: 0,
            sve2_instructions: 0,
            peak_scratch_bytes: 0,
        };
        assembler.observe_scratch(0, 0, EmissionPhaseV3::Canonical)?;
        Ok(assembler)
    }

    fn observe_scratch(
        &mut self,
        output_labels: usize,
        output_relocations: usize,
        phase: EmissionPhaseV3,
    ) -> Result<(), CountAotError> {
        let actual = observed_emission_phase_scratch_v3(
            self.code.capacity(),
            self.labels.capacity(),
            self.fixups.capacity(),
            output_labels,
            output_relocations,
            phase,
        )?;
        if actual > self.prospective.emission_scratch {
            return Err(CountAotError::InternalInvariant {
                at: "v3 emission scratch prospective",
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

    fn new_label(&mut self, kind: LabelKindV3) -> Result<LabelV3, CountAotError> {
        if self.labels.len() >= self.prospective.labels {
            return Err(CountAotError::InternalInvariant {
                at: "v3 label prospective",
            });
        }
        self.charge(1)?;
        let label = LabelV3(to_u32(
            self.labels.len(),
            CountAotArithmeticSite::CodeOffset,
        )?);
        push_exact_v3(
            &mut self.labels,
            LabelRecordV3 { offset: None, kind },
            "v3 label capacity",
        )?;
        Ok(label)
    }

    fn bind(&mut self, label: LabelV3) -> Result<(), CountAotError> {
        self.charge(1)?;
        let offset = to_u32(self.code.len(), CountAotArithmeticSite::CodeOffset)?;
        let record = self
            .labels
            .get_mut(usize::try_from(label.0).expect("u32 fits usize"))
            .ok_or(CountAotError::InternalInvariant {
                at: "v3 label index",
            })?;
        if record.offset.replace(offset).is_some() {
            return Err(CountAotError::InternalInvariant {
                at: "v3 label rebound",
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
                at: "v3 code prospective",
            });
        }
        self.charge(1)?;
        for byte in word.to_le_bytes() {
            push_exact_v3(&mut self.code, byte, "v3 code capacity")?;
        }
        if vector {
            self.vector_instructions = self.vector_instructions.checked_add(1).ok_or(
                CountAotError::ArithmeticOverflow {
                    site: CountAotArithmeticSite::CodeOffset,
                },
            )?;
            self.asimd_instructions = self.asimd_instructions.checked_add(1).ok_or(
                CountAotError::ArithmeticOverflow {
                    site: CountAotArithmeticSite::CodeOffset,
                },
            )?;
        }
        Ok(())
    }

    fn emit_sve_word(&mut self, word: u32, sve2: bool) -> Result<(), CountAotError> {
        self.emit_word(word, false)?;
        self.vector_instructions =
            self.vector_instructions
                .checked_add(1)
                .ok_or(CountAotError::ArithmeticOverflow {
                    site: CountAotArithmeticSite::CodeOffset,
                })?;
        if sve2 {
            self.sve2_instructions =
                self.sve2_instructions
                    .checked_add(1)
                    .ok_or(CountAotError::ArithmeticOverflow {
                        site: CountAotArithmeticSite::CodeOffset,
                    })?;
        } else {
            self.sve_instructions =
                self.sve_instructions
                    .checked_add(1)
                    .ok_or(CountAotError::ArithmeticOverflow {
                        site: CountAotArithmeticSite::CodeOffset,
                    })?;
        }
        Ok(())
    }

    fn add_fixup(
        &mut self,
        kind: RelocationKindV3,
        target: LabelV3,
        placeholder: u32,
    ) -> Result<(), CountAotError> {
        if self.fixups.len() >= self.prospective.relocations {
            return Err(CountAotError::InternalInvariant {
                at: "v3 relocation prospective",
            });
        }
        let at = to_u32(self.code.len(), CountAotArithmeticSite::CodeOffset)?;
        self.emit_word(placeholder, false)?;
        push_exact_v3(
            &mut self.fixups,
            FixupV3 { at, kind, target },
            "v3 fixup capacity",
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
            0xeb00_001f | register_field_v3(right, 16) | register_field_v3(left, 5),
            false,
        )
    }

    fn cmp_reg32(&mut self, left: u8, right: u8) -> Result<(), CountAotError> {
        self.emit_word(
            0x6b00_001f | register_field_v3(right, 16) | register_field_v3(left, 5),
            false,
        )
    }

    fn cmp_imm64(&mut self, register: u8, immediate: u16) -> Result<(), CountAotError> {
        self.emit_word(
            0xf100_001f | (u32::from(immediate) << 10) | register_field_v3(register, 5),
            false,
        )
    }

    fn cmp_imm32(&mut self, register: u8, immediate: u16) -> Result<(), CountAotError> {
        self.emit_word(
            0x7100_001f | (u32::from(immediate) << 10) | register_field_v3(register, 5),
            false,
        )
    }

    fn add_reg(&mut self, destination: u8, left: u8, right: u8) -> Result<(), CountAotError> {
        self.emit_word(
            0x8b00_0000
                | register_field_v3(right, 16)
                | register_field_v3(left, 5)
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
                | register_field_v3(source, 5)
                | u32::from(destination),
            false,
        )
    }

    fn sub_reg(&mut self, destination: u8, left: u8, right: u8) -> Result<(), CountAotError> {
        self.emit_word(
            0xcb00_0000
                | register_field_v3(right, 16)
                | register_field_v3(left, 5)
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
                | register_field_v3(source, 5)
                | u32::from(destination),
            false,
        )
    }

    fn and_reg(&mut self, destination: u8, left: u8, right: u8) -> Result<(), CountAotError> {
        self.emit_word(
            0x8a00_0000
                | register_field_v3(right, 16)
                | register_field_v3(left, 5)
                | u32::from(destination),
            false,
        )
    }

    fn and_low_bits(&mut self, destination: u8, source: u8, bits: u8) -> Result<(), CountAotError> {
        let mask = u32::from(
            bits.checked_sub(1)
                .ok_or(CountAotError::InternalInvariant {
                    at: "v3 zero low-bit mask",
                })?,
        ) << 10;
        self.emit_word(
            0x9240_0000 | mask | register_field_v3(source, 5) | u32::from(destination),
            false,
        )
    }

    fn lsr_imm(&mut self, destination: u8, source: u8, shift: u8) -> Result<(), CountAotError> {
        self.emit_word(
            0xd340_0000
                | (u32::from(shift) << 16)
                | (63 << 10)
                | register_field_v3(source, 5)
                | u32::from(destination),
            false,
        )
    }

    fn reverse_bits(&mut self, destination: u8, source: u8) -> Result<(), CountAotError> {
        self.emit_word(
            0xdac0_0000 | register_field_v3(source, 5) | u32::from(destination),
            false,
        )
    }

    fn count_leading_zeros(&mut self, destination: u8, source: u8) -> Result<(), CountAotError> {
        self.emit_word(
            0xdac0_1000 | register_field_v3(source, 5) | u32::from(destination),
            false,
        )
    }

    fn load_byte(&mut self, destination: u8, base: u8, offset: u16) -> Result<(), CountAotError> {
        self.emit_word(
            0x3940_0000
                | (u32::from(offset) << 10)
                | register_field_v3(base, 5)
                | u32::from(destination),
            false,
        )
    }

    fn load_byte_reg(&mut self, destination: u8, base: u8, index: u8) -> Result<(), CountAotError> {
        self.emit_word(
            0x3860_6800
                | register_field_v3(index, 16)
                | register_field_v3(base, 5)
                | u32::from(destination),
            false,
        )
    }

    fn store64(&mut self, source: u8, base: u8, offset: u16) -> Result<(), CountAotError> {
        self.emit_word(
            0xf900_0000
                | (u32::from(offset / 8) << 10)
                | register_field_v3(base, 5)
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
                at: "v3 vector load alignment",
            });
        }
        self.emit_word(
            0x3dc0_0000
                | (u32::from(offset / 16) << 10)
                | register_field_v3(base, 5)
                | u32::from(destination),
            true,
        )
    }

    fn load_vectors4x128(&mut self, first_destination: u8, base: u8) -> Result<(), CountAotError> {
        if first_destination > 28 {
            return Err(CountAotError::InternalInvariant {
                at: "v3 four-vector load register wrap",
            });
        }
        self.emit_word(
            0x4c40_2000 | register_field_v3(base, 5) | u32::from(first_destination),
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
                | register_field_v3(base, 5)
                | u32::from(destination),
            true,
        )
    }

    fn dup_byte16(&mut self, destination: u8, source: u8) -> Result<(), CountAotError> {
        self.emit_word(
            0x4e01_0c00 | register_field_v3(source, 5) | u32::from(destination),
            true,
        )
    }

    fn sve_ptrue_bytes_vl16(&mut self, destination: u8) -> Result<(), CountAotError> {
        self.emit_sve_word(0x2518_e120 | u32::from(destination), false)
    }

    fn sve_duplicate_byte(&mut self, destination: u8, source: u8) -> Result<(), CountAotError> {
        self.emit_sve_word(
            0x0520_3800 | register_field_v3(source, 5) | u32::from(destination),
            false,
        )
    }

    fn sve_load_bytes(
        &mut self,
        destination: u8,
        predicate: u8,
        base: u8,
    ) -> Result<(), CountAotError> {
        self.sve_load_bytes_mul_vl(destination, predicate, base, 0)
    }

    fn sve_load_bytes_mul_vl(
        &mut self,
        destination: u8,
        predicate: u8,
        base: u8,
        vector_offset: i8,
    ) -> Result<(), CountAotError> {
        if !(-8..=7).contains(&vector_offset) {
            return Err(CountAotError::InternalInvariant {
                at: "v3 SVE LD1B vector offset",
            });
        }
        let immediate = u32::from(vector_offset.to_le_bytes()[0] & 0x0f);
        self.emit_sve_word(
            0xa400_a000
                | (immediate << 16)
                | (u32::from(predicate) << 10)
                | register_field_v3(base, 5)
                | u32::from(destination),
            false,
        )
    }

    fn sve_compare_equal_bytes(
        &mut self,
        destination: u8,
        predicate: u8,
        left: u8,
        right: u8,
    ) -> Result<(), CountAotError> {
        self.emit_sve_word(
            0x2400_a000
                | register_field_v3(right, 16)
                | (u32::from(predicate) << 10)
                | register_field_v3(left, 5)
                | u32::from(destination),
            false,
        )
    }

    fn sve2_match_bytes(
        &mut self,
        destination: u8,
        predicate: u8,
        left: u8,
        right: u8,
    ) -> Result<(), CountAotError> {
        self.emit_sve_word(
            0x4520_8000
                | register_field_v3(right, 16)
                | (u32::from(predicate) << 10)
                | register_field_v3(left, 5)
                | u32::from(destination),
            true,
        )
    }

    fn sve_and_predicate_bytes(
        &mut self,
        destination: u8,
        predicate: u8,
        left: u8,
        right: u8,
    ) -> Result<(), CountAotError> {
        self.emit_sve_word(
            0x2500_4000
                | (u32::from(right) << 16)
                | (u32::from(predicate) << 10)
                | (u32::from(left) << 5)
                | u32::from(destination),
            false,
        )
    }

    #[allow(
        dead_code,
        reason = "retained for the superseded pure-SVE lowering reference"
    )]
    fn sve_or_predicate_bytes(
        &mut self,
        destination: u8,
        predicate: u8,
        left: u8,
        right: u8,
    ) -> Result<(), CountAotError> {
        self.emit_sve_word(
            0x2580_4000
                | (u32::from(right) << 16)
                | (u32::from(predicate) << 10)
                | (u32::from(left) << 5)
                | u32::from(destination),
            false,
        )
    }

    #[allow(
        dead_code,
        reason = "retained for the superseded pure-SVE lowering reference"
    )]
    fn sve_bit_clear_predicate_bytes_set_flags(
        &mut self,
        destination: u8,
        predicate: u8,
        left: u8,
        right: u8,
    ) -> Result<(), CountAotError> {
        self.emit_sve_word(
            0x2540_4010
                | (u32::from(right) << 16)
                | (u32::from(predicate) << 10)
                | (u32::from(left) << 5)
                | u32::from(destination),
            false,
        )
    }

    fn sve_test_predicate_bytes(&mut self, predicate: u8, tested: u8) -> Result<(), CountAotError> {
        self.emit_sve_word(
            0x2550_c000 | (u32::from(predicate) << 10) | (u32::from(tested) << 5),
            false,
        )
    }

    fn sve_break_before_bytes(
        &mut self,
        destination: u8,
        predicate: u8,
        source: u8,
    ) -> Result<(), CountAotError> {
        self.emit_sve_word(
            0x2590_4000
                | (u32::from(predicate) << 10)
                | (u32::from(source) << 5)
                | u32::from(destination),
            false,
        )
    }

    #[allow(
        dead_code,
        reason = "retained for the superseded pure-SVE lowering reference"
    )]
    fn sve_break_after_bytes(
        &mut self,
        destination: u8,
        predicate: u8,
        source: u8,
    ) -> Result<(), CountAotError> {
        self.emit_sve_word(
            0x2510_4000
                | (u32::from(predicate) << 10)
                | (u32::from(source) << 5)
                | u32::from(destination),
            false,
        )
    }

    fn sve_count_predicate_bytes(
        &mut self,
        destination: u8,
        predicate: u8,
        source: u8,
    ) -> Result<(), CountAotError> {
        self.emit_sve_word(
            0x2520_8000
                | (u32::from(predicate) << 10)
                | (u32::from(source) << 5)
                | u32::from(destination),
            false,
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
                | register_field_v3(right, 16)
                | register_field_v3(left, 5)
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
                | register_field_v3(right, 16)
                | register_field_v3(left, 5)
                | u32::from(destination),
            true,
        )
    }

    fn and_bytes16(&mut self, destination: u8, left: u8, right: u8) -> Result<(), CountAotError> {
        self.emit_word(
            0x4e20_1c00
                | register_field_v3(right, 16)
                | register_field_v3(left, 5)
                | u32::from(destination),
            true,
        )
    }

    fn add_bytes16(&mut self, destination: u8, left: u8, right: u8) -> Result<(), CountAotError> {
        self.emit_word(
            0x4e20_8400
                | register_field_v3(right, 16)
                | register_field_v3(left, 5)
                | u32::from(destination),
            true,
        )
    }

    fn or_bytes16(&mut self, destination: u8, left: u8, right: u8) -> Result<(), CountAotError> {
        self.emit_word(
            0x4ea0_1c00
                | register_field_v3(right, 16)
                | register_field_v3(left, 5)
                | u32::from(destination),
            true,
        )
    }

    fn extract_bytes16(
        &mut self,
        destination: u8,
        left: u8,
        right: u8,
        byte_offset: u8,
    ) -> Result<(), CountAotError> {
        if byte_offset >= 16 {
            return Err(CountAotError::InternalInvariant {
                at: "v3 EXT byte offset",
            });
        }
        self.emit_word(
            0x6e00_0000
                | register_field_v3(right, 16)
                | (u32::from(byte_offset) << 11)
                | register_field_v3(left, 5)
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
                at: "v3 SHRN shift",
            });
        }
        self.emit_word(
            0x0f0c_8400 | register_field_v3(source, 5) | u32::from(destination),
            true,
        )
    }

    fn add_across_bytes16(&mut self, destination: u8, source: u8) -> Result<(), CountAotError> {
        self.emit_word(
            0x4e31_b800 | register_field_v3(source, 5) | u32::from(destination),
            true,
        )
    }

    fn unsigned_max_across_bytes16(
        &mut self,
        destination: u8,
        source: u8,
    ) -> Result<(), CountAotError> {
        self.emit_word(
            0x6e30_a800 | register_field_v3(source, 5) | u32::from(destination),
            true,
        )
    }

    fn unsigned_min_across_bytes8(
        &mut self,
        destination: u8,
        source: u8,
    ) -> Result<(), CountAotError> {
        self.emit_word(
            0x2e31_a800 | register_field_v3(source, 5) | u32::from(destination),
            true,
        )
    }

    fn unsigned_min_across_bytes16(
        &mut self,
        destination: u8,
        source: u8,
    ) -> Result<(), CountAotError> {
        self.emit_word(
            0x6e31_a800 | register_field_v3(source, 5) | u32::from(destination),
            true,
        )
    }

    fn move_vector_byte_to32(&mut self, destination: u8, source: u8) -> Result<(), CountAotError> {
        self.emit_word(
            0x0e01_3c00 | register_field_v3(source, 5) | u32::from(destination),
            true,
        )
    }

    fn move_vector_double_to64(
        &mut self,
        destination: u8,
        source: u8,
    ) -> Result<(), CountAotError> {
        self.emit_word(
            0x9e66_0000 | register_field_v3(source, 5) | u32::from(destination),
            true,
        )
    }

    fn move_x_to_vector_double(
        &mut self,
        destination: u8,
        source: u8,
    ) -> Result<(), CountAotError> {
        self.emit_word(
            0x9e67_0000 | register_field_v3(source, 5) | u32::from(destination),
            true,
        )
    }

    fn insert_x_to_vector_double_lane1(
        &mut self,
        destination: u8,
        source: u8,
    ) -> Result<(), CountAotError> {
        self.emit_word(
            0x4e18_1c00 | register_field_v3(source, 5) | u32::from(destination),
            true,
        )
    }

    fn branch(&mut self, target: LabelV3) -> Result<(), CountAotError> {
        self.add_fixup(RelocationKindV3::Branch26, target, 0x1400_0000)
    }

    fn branch_cond(
        &mut self,
        condition: ConditionV3,
        target: LabelV3,
    ) -> Result<(), CountAotError> {
        self.add_fixup(
            RelocationKindV3::ConditionalBranch19,
            target,
            0x5400_0000 | u32::from(condition_encoding_v3(condition)),
        )
    }

    fn ret(&mut self) -> Result<(), CountAotError> {
        self.emit_word(0xd65f_03c0, false)
    }

    fn order_labels(&mut self, labels: &mut [CodeLabelV3]) -> Result<(), CountAotError> {
        let budget = label_order_work_upper_bound_v3(labels.len())?;
        let recomposed = budget
            .comparisons
            .checked_add(budget.moves)
            .and_then(|work| work.checked_add(budget.placements))
            .ok_or(arithmetic_prospective_v3())?;
        if recomposed != budget.total {
            return Err(CountAotError::InternalInvariant {
                at: "v3 label order work envelope",
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
                    .ok_or(arithmetic_prospective_v3())?;
                let previous_index = cursor.checked_sub(1).ok_or(arithmetic_prospective_v3())?;
                let previous = labels[previous_index];
                if previous <= key {
                    break;
                }
                labels[cursor] = previous;
                moves = moves.checked_add(1).ok_or(arithmetic_prospective_v3())?;
                cursor = previous_index;
            }
            labels[cursor] = key;
            placements = placements
                .checked_add(1)
                .ok_or(arithmetic_prospective_v3())?;
        }
        if comparisons > budget.comparisons
            || moves > budget.moves
            || placements != budget.placements
        {
            return Err(CountAotError::InternalInvariant {
                at: "v3 label order observed work",
            });
        }
        Ok(())
    }

    fn finalize(mut self) -> Result<FinalizedV3, CountAotError> {
        let mut relocations = exact_vec_v3(
            self.fixups.len(),
            CountAotResource::Relocations,
            self.prospective.scratch,
            self.prospective.scratch_limit,
        )?;
        self.observe_scratch(
            0,
            relocations.capacity(),
            EmissionPhaseV3::FinalizeRelocations,
        )?;
        for index in 0..self.fixups.len() {
            let fixup = self.fixups[index];
            self.charge(1)?;
            let target = self
                .labels
                .get(usize::try_from(fixup.target.0).expect("u32 fits usize"))
                .and_then(|record| record.offset)
                .ok_or(CountAotError::InternalInvariant {
                    at: "v3 unbound fixup target",
                })?;
            let word = read_word_v3(&self.code, fixup.at)?;
            let resolved = resolve_branch_v3(word, fixup.kind, fixup.at, target)?;
            write_word_v3(&mut self.code, fixup.at, resolved)?;
            push_exact_v3(
                &mut relocations,
                RelocationV3 {
                    code_offset: fixup.at,
                    kind: fixup.kind,
                    target: RelocationTargetV3::CodeOffset(target),
                    resolved_word: resolved,
                },
                "v3 finalized relocation capacity",
            )?;
        }
        let mut labels = exact_vec_v3(
            self.labels.len(),
            CountAotResource::Labels,
            self.prospective.scratch,
            self.prospective.scratch_limit,
        )?;
        self.observe_scratch(
            labels.capacity(),
            relocations.capacity(),
            EmissionPhaseV3::CollectLabels,
        )?;
        for record in self.labels.iter().copied() {
            push_exact_v3(
                &mut labels,
                CodeLabelV3 {
                    offset: record.offset.ok_or(CountAotError::InternalInvariant {
                        at: "v3 unbound label",
                    })?,
                    kind: record.kind,
                },
                "v3 finalized label capacity",
            )?;
        }
        self.observe_scratch(
            labels.capacity(),
            relocations.capacity(),
            EmissionPhaseV3::OrderLabels,
        )?;
        self.order_labels(&mut labels)?;
        let code_capacity_bytes = self.code.capacity();
        let label_capacity_bytes = labels
            .capacity()
            .checked_mul(size_of::<CodeLabelV3>())
            .ok_or(CountAotError::ArithmeticOverflow {
                site: CountAotArithmeticSite::Persistent,
            })?;
        let relocation_capacity_bytes = relocations
            .capacity()
            .checked_mul(size_of::<RelocationV3>())
            .ok_or(CountAotError::ArithmeticOverflow {
                site: CountAotArithmeticSite::Persistent,
            })?;
        self.observe_scratch(
            labels.capacity(),
            relocations.capacity(),
            EmissionPhaseV3::FinalizeReturn,
        )?;
        let mut actual_features = AotCountCpuFeatures::NONE;
        if self.asimd_instructions != 0 {
            actual_features = actual_features.union(AotCountCpuFeatures::ASIMD);
        }
        if self.sve_instructions != 0 {
            actual_features = actual_features.union(AotCountCpuFeatures::SVE);
        }
        if self.sve2_instructions != 0 {
            actual_features = actual_features
                .union(AotCountCpuFeatures::SVE)
                .union(AotCountCpuFeatures::SVE2);
        }
        Ok(FinalizedV3 {
            code: self.code,
            labels,
            relocations,
            emission_work: self.emission_work,
            vector_instructions: self.vector_instructions,
            actual_features,
            code_capacity_bytes,
            label_capacity_bytes,
            relocation_capacity_bytes,
            emission_peak_scratch_bytes: self.peak_scratch_bytes,
        })
    }
}

const fn condition_encoding_v3(condition: ConditionV3) -> u8 {
    match condition {
        ConditionV3::Equal => 0,
        ConditionV3::NotEqual => 1,
        ConditionV3::CarrySet => 2,
        ConditionV3::CarryClear => 3,
        ConditionV3::Higher => 8,
    }
}

const fn label_kind_encoding_v3(kind: LabelKindV3) -> u8 {
    match kind {
        LabelKindV3::Entry => 1,
        LabelKindV3::VectorLoop => 2,
        LabelKindV3::CandidateLoop => 3,
        LabelKindV3::ScalarTail => 4,
        LabelKindV3::Miss => 5,
        LabelKindV3::Success => 6,
        LabelKindV3::Overflow => 7,
        LabelKindV3::Internal => 8,
    }
}

const fn relocation_kind_encoding_v3(kind: RelocationKindV3) -> u8 {
    match kind {
        RelocationKindV3::Branch26 => 1,
        RelocationKindV3::ConditionalBranch19 => 2,
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct FinalizedV3 {
    pub(crate) code: ExactVec<u8>,
    pub(crate) labels: ExactVec<CodeLabelV3>,
    pub(crate) relocations: ExactVec<RelocationV3>,
    pub(crate) emission_work: u64,
    pub(crate) vector_instructions: u32,
    pub(crate) actual_features: AotCountCpuFeatures,
    pub(crate) code_capacity_bytes: usize,
    pub(crate) label_capacity_bytes: usize,
    pub(crate) relocation_capacity_bytes: usize,
    pub(crate) emission_peak_scratch_bytes: u64,
}

pub(crate) fn compute_artifact_identity_v3(
    image: &AotCountImageV3,
) -> Result<(AotCountArtifactIdentityV3, u64), CountAotError> {
    let mut encoder = IdentityEncoderV3::hasher();
    encode_artifact_identity_v3(&mut encoder, image)?;
    encoder.finish()
}

pub(crate) fn artifact_identity_encoded_len_v3(
    image: &AotCountImageV3,
) -> Result<u64, CountAotError> {
    let mut encoder = IdentityEncoderV3::counter();
    encode_artifact_identity_v3(&mut encoder, image)?;
    Ok(encoder.bytes)
}

fn encode_artifact_identity_v3(
    encoder: &mut IdentityEncoderV3,
    image: &AotCountImageV3,
) -> Result<(), CountAotError> {
    encoder.raw(IDENTITY_DOMAIN_V3)?;
    encoder.u16(AOT_COUNT_IMAGE_SCHEMA_VERSION_V3)?;
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
    encoder.u16(support.vector_bytes)?;
    encoder.u16(support.sve_vector_length_bytes)?;
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
    encode_recipe_manifest_v3(encoder, image.recipe_manifest)?;
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
        encoder.u8(label_kind_encoding_v3(label.kind))?;
    }
    encoder.u32(to_u32(
        image.relocations.len(),
        CountAotArithmeticSite::Identity,
    )?)?;
    for relocation in &image.relocations {
        encoder.u32(relocation.code_offset)?;
        encoder.u8(relocation_kind_encoding_v3(relocation.kind))?;
        let RelocationTargetV3::CodeOffset(target) = relocation.target;
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
    encoder.u8(stats.strategy_id)?;
    encoder.u8(stats.schedule_id)?;
    encoder.u8(stats.register_plan_id)?;
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
    encode_recipe_manifest_v3(encoder, receipt.recipe)?;
    encode_audit_identity_v3(encoder, receipt.audit)
}

fn encode_recipe_manifest_v3(
    encoder: &mut IdentityEncoderV3,
    recipe: crate::AotCountRecipeManifestV3,
) -> Result<(), CountAotError> {
    encoder.u16(recipe.recipe_schema_version)?;
    encoder.u16(recipe.optimizer_version)?;
    encoder.u8(recipe.tuning_class_id)?;
    encoder.u8(recipe.strategy_id)?;
    encoder.u8(recipe.schedule_id)?;
    encoder.u8(recipe.register_plan_id)?;
    encoder.u8(recipe.required_isa_id)?;
    encoder.u8(recipe.successor_mode_id)?;
    encoder.u8(recipe.filter_len)?;
    encoder.u8(recipe.confirmation_len)?;
    encoder.u8(recipe.sparse_group_count)?;
    encoder.u8(recipe.mismatch_stride)?;
    encoder.u8(recipe.match_stride)?;
    encoder.u8(recipe.periodic_stride)?;
    encoder.raw(&recipe.padded_filter_offsets())?;
    encoder.raw(&recipe.padded_confirmation_order())?;
    encoder.raw(&recipe.padded_sparse_group_first_offsets())?;
    encoder.raw(&recipe.padded_sparse_group_lengths())?;
    encoder.raw(&recipe.literal_identity)?;
    encoder.raw(&recipe.recipe_identity)?;
    encoder.raw(&recipe.canonical_recipe)
}

fn encode_audit_identity_v3(
    encoder: &mut IdentityEncoderV3,
    audit: CountAuditReportV3,
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

pub(crate) fn identity_bytes_upper_bound_v3(
    code_bytes: usize,
    labels: usize,
    relocations: usize,
) -> Result<u64, CountAotError> {
    // Exact fixed-width encoding, excluding the domain, code, label records,
    // and relocation records. The optimizer recipe manifest is encoded both
    // as a semantic image input and as an independently comparable build
    // receipt; each canonical projection is exactly 380 bytes.
    const FIXED_IDENTITY_BYTES_V3: u64 = 1_094;
    to_u64(IDENTITY_DOMAIN_V3.len(), CountAotArithmeticSite::Identity)?
        .checked_add(FIXED_IDENTITY_BYTES_V3)
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

type IdentityEncoderInlineStateV3 = (
    IdentityEncoderV3,
    &'static AotCountImageV3,
    AotCountArtifactIdentityV3,
    AotCountImageStatsV3,
    AotCountImageBuildReceiptV3,
    CountAuditReportV3,
    core::slice::Iter<'static, CodeLabelV3>,
    core::slice::Iter<'static, RelocationV3>,
    &'static CodeLabelV3,
    &'static RelocationV3,
    [u8; 64],
    [u8; 32],
    [u64; 4],
    CountAotError,
);

pub(crate) const fn identity_scratch_bytes_v3() -> usize {
    size_of::<IdentityEncoderInlineStateV3>()
}

struct IdentityEncoderV3 {
    hasher: Option<Sha256>,
    bytes: u64,
}

impl IdentityEncoderV3 {
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

    fn finish(self) -> Result<(AotCountArtifactIdentityV3, u64), CountAotError> {
        let digest = self
            .hasher
            .ok_or(CountAotError::InternalInvariant {
                at: "finish v3 identity counter",
            })?
            .finalize();
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(&digest);
        Ok((AotCountArtifactIdentityV3::new(bytes), self.bytes))
    }
}

fn resolve_branch_v3(
    word: u32,
    kind: RelocationKindV3,
    from: u32,
    target: u32,
) -> Result<u32, CountAotError> {
    let displacement = i64::from(target).checked_sub(i64::from(from)).ok_or(
        CountAotError::ArithmeticOverflow {
            site: CountAotArithmeticSite::Relocation,
        },
    )?;
    let (bits, shift) = match kind {
        RelocationKindV3::Branch26 => (26_u8, 0_u8),
        RelocationKindV3::ConditionalBranch19 => (19, 5),
    };
    if displacement % 4 != 0 {
        return Err(CountAotError::InternalInvariant {
            at: "v3 unaligned branch",
        });
    }
    let scaled = displacement / 4;
    let magnitude = 1_i64 << u32::from(bits - 1);
    if scaled < -magnitude || scaled >= magnitude {
        return Err(CountAotError::InvalidImage {
            at: "v3 branch range",
        });
    }
    let mask = (1_u32 << u32::from(bits)) - 1;
    let encoded = u32::try_from(scaled & i64::from(mask)).expect("masked displacement");
    Ok(word | (encoded << u32::from(shift)))
}

fn read_word_v3(code: &[u8], offset: u32) -> Result<u32, CountAotError> {
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
            at: "v3 read relocation word",
        })?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn write_word_v3(code: &mut [u8], offset: u32, word: u32) -> Result<(), CountAotError> {
    let offset = usize::try_from(offset).expect("u32 fits usize");
    let end = offset
        .checked_add(4)
        .ok_or(CountAotError::ArithmeticOverflow {
            site: CountAotArithmeticSite::CodeOffset,
        })?;
    code.get_mut(offset..end)
        .ok_or(CountAotError::InternalInvariant {
            at: "v3 write relocation word",
        })?
        .copy_from_slice(&word.to_le_bytes());
    Ok(())
}

fn register_field_v3(register: u8, shift: u8) -> u32 {
    debug_assert!(register < 32);
    u32::from(register) << shift
}

fn align_up_v3(value: usize, alignment: usize) -> Result<usize, CountAotError> {
    let mask = alignment
        .checked_sub(1)
        .ok_or(CountAotError::InternalInvariant {
            at: "v3 zero alignment",
        })?;
    value
        .checked_add(mask)
        .map(|sum| sum & !mask)
        .ok_or(CountAotError::ArithmeticOverflow {
            site: CountAotArithmeticSite::ImageLayout,
        })
}

fn exact_vec_v3<T>(
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

fn push_exact_v3<T>(
    values: &mut ExactVec<T>,
    value: T,
    at: &'static str,
) -> Result<(), CountAotError> {
    values
        .try_push(value)
        .map_err(|_| CountAotError::InternalInvariant { at })
}

fn enforce_all_v3(
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

const fn arithmetic_prospective_v3() -> CountAotError {
    CountAotError::ArithmeticOverflow {
        site: CountAotArithmeticSite::Prospective,
    }
}
