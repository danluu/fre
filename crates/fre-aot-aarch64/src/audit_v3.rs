#![allow(
    clippy::arithmetic_side_effects,
    reason = "instruction-policy arithmetic is bounded by the admitted 0..=32-byte template; resource formulas use checked operations"
)]

use core::mem::size_of;

use fre_aot_optimizer::{
    COUNT_V3_RECIPE_CANONICAL_BYTES, CountRecipeV3, CountV3RegisterPlanId, CountV3RequiredIsa,
    CountV3ScheduleId, CountV3Strategy, CountV3SuccessorMode, decode_count_recipe_v3,
    encode_count_recipe_v3, validate_count_recipe_v3,
};
use fre_exact_alloc::{CopyError, ExactVec};
use fre_kernel_ir::{
    AggregateOutput, Count, ExactAggregateProgram, MAX_EXACT_AGGREGATE_LITERAL_BYTES,
};

use crate::audit_cfg_v3::{
    audit_decoded_cfg_safety_v3, decoded_cfg_safety_scratch_bytes_v3,
    decoded_cfg_safety_work_upper_bound_v3,
};
use crate::{
    AOT_COUNT_BACKEND_VERSION_V3, AotCountArtifactIdentityV3, AotCountCpuFeatures, AotCountImageV3,
    AotCountImageViewV3, AotCountLiteralManifestV3, AotCountMappedMetadataV3,
    AotCountRecipeManifestV3, CodeLabelV3, CountAotArithmeticSite, CountAotError, CountAotResource,
    CountEmitLimitsV3, LabelKindV3, RelocationKindV3, RelocationTargetV3, RelocationV3,
    SUPPORTED_AOT_COUNT_BACKEND_TUPLES_V3, emit_count_v3,
    emit_v3::{
        ProspectiveV3, artifact_identity_encoded_len_v3,
        assembler_scratch_derivation_work_upper_bound_v3, assembler_scratch_for_capacities_v3,
        assembler_scratch_upper_bound_v3, compute_artifact_identity_v3,
        identity_bytes_upper_bound_v3, identity_scratch_bytes_v3,
        identity_structural_traversal_work_v3, image_assembly_scratch_for_capacities_v3,
        label_order_work_upper_bound_v3, prospective_v3,
    },
    is_supported_aot_count_backend_tuple_v3,
};

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AuditCandidateFilterV3 {
    offsets: [u8; 4],
    len: u8,
}

impl AuditCandidateFilterV3 {
    fn offsets(&self) -> &[u8] {
        &self.offsets[..usize::from(self.len)]
    }

    const fn len(self) -> u8 {
        self.len
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuditLoweringStrategyV3 {
    Incumbent,
    SparseRareColumns,
    EndpointDense,
    PeriodicRun,
    DirectExactMask,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AuditLoweringRecipeV3 {
    strategy: AuditLoweringStrategyV3,
    required_isa: CountV3RequiredIsa,
    filter: Option<AuditCandidateFilterV3>,
    confirmation_order: [u8; 32],
    confirmation_len: u8,
}

impl AuditLoweringRecipeV3 {
    fn confirmation_order(&self) -> &[u8] {
        &self.confirmation_order[..usize::from(self.confirmation_len)]
    }
}

/// `AArch64` condition codes admitted by the optimizing-v3 template.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ConditionV3 {
    Equal = 0,
    NotEqual = 1,
    CarrySet = 2,
    CarryClear = 3,
    Higher = 8,
}

/// Independently decoded instruction subset admitted by Count AOT v3.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodedInstructionV3 {
    MoveZero64 {
        destination: u8,
        immediate: u16,
        shift: u8,
    },
    MoveKeep64 {
        destination: u8,
        immediate: u16,
        shift: u8,
    },
    CompareRegister64 {
        left: u8,
        right: u8,
    },
    CompareRegister32 {
        left: u8,
        right: u8,
    },
    CompareImmediate64 {
        register: u8,
        immediate: u16,
    },
    CompareImmediate32 {
        register: u8,
        immediate: u16,
    },
    AddRegister64 {
        destination: u8,
        left: u8,
        right: u8,
    },
    AddImmediate64 {
        destination: u8,
        source: u8,
        immediate: u16,
    },
    SubtractRegister64 {
        destination: u8,
        left: u8,
        right: u8,
    },
    SubtractImmediate64 {
        destination: u8,
        source: u8,
        immediate: u16,
    },
    AndRegister64 {
        destination: u8,
        left: u8,
        right: u8,
    },
    AndLowBits64 {
        destination: u8,
        source: u8,
        bits: u8,
    },
    LogicalShiftRight64 {
        destination: u8,
        source: u8,
        shift: u8,
    },
    ReverseBits64 {
        destination: u8,
        source: u8,
    },
    CountLeadingZeros64 {
        destination: u8,
        source: u8,
    },
    LoadByte {
        destination: u8,
        base: u8,
        offset: u16,
    },
    LoadByteRegister {
        destination: u8,
        base: u8,
        index: u8,
    },
    Store64 {
        source: u8,
        base: u8,
        offset: u16,
    },
    LoadVector128 {
        destination: u8,
        base: u8,
        offset: u16,
    },
    LoadVectorDouble {
        destination: u8,
        base: u8,
        offset: u16,
    },
    DuplicateByte16 {
        destination: u8,
        source: u8,
    },
    CompareEqualBytes16 {
        destination: u8,
        left: u8,
        right: u8,
    },
    CompareEqualBytes8 {
        destination: u8,
        left: u8,
        right: u8,
    },
    AndBytes16 {
        destination: u8,
        left: u8,
        right: u8,
    },
    AddBytes16 {
        destination: u8,
        left: u8,
        right: u8,
    },
    OrBytes16 {
        destination: u8,
        left: u8,
        right: u8,
    },
    ShrinkNarrowBytesFromHalfwords {
        destination: u8,
        source: u8,
        shift: u8,
    },
    AddAcrossBytes16 {
        destination: u8,
        source: u8,
    },
    UnsignedMaxAcrossBytes16 {
        destination: u8,
        source: u8,
    },
    UnsignedMinAcrossBytes8 {
        destination: u8,
        source: u8,
    },
    UnsignedMinAcrossBytes16 {
        destination: u8,
        source: u8,
    },
    MoveVectorByteTo32 {
        destination: u8,
        source: u8,
    },
    MoveVectorDoubleTo64 {
        destination: u8,
        source: u8,
    },
    Move64ToVectorDouble {
        destination: u8,
        source: u8,
    },
    Insert64ToVectorDoubleLane1 {
        destination: u8,
        source: u8,
    },
    SvePtrueBytesVl16 {
        destination: u8,
    },
    SveDuplicateByte {
        destination: u8,
        source: u8,
    },
    SveLoadBytes {
        destination: u8,
        predicate: u8,
        base: u8,
    },
    SveLoadBytesMulVl {
        destination: u8,
        predicate: u8,
        base: u8,
        vector_offset: i8,
    },
    SveCompareEqualBytes {
        destination: u8,
        predicate: u8,
        left: u8,
        right: u8,
    },
    Sve2MatchBytes {
        destination: u8,
        predicate: u8,
        left: u8,
        right: u8,
    },
    SveAndPredicateBytes {
        destination: u8,
        predicate: u8,
        left: u8,
        right: u8,
    },
    SveOrPredicateBytes {
        destination: u8,
        predicate: u8,
        left: u8,
        right: u8,
    },
    SveBitClearPredicateBytesSetFlags {
        destination: u8,
        predicate: u8,
        left: u8,
        right: u8,
    },
    SveTestPredicateBytes {
        predicate: u8,
        tested: u8,
    },
    SveBreakBeforeBytes {
        destination: u8,
        predicate: u8,
        source: u8,
    },
    SveBreakAfterBytes {
        destination: u8,
        predicate: u8,
        source: u8,
    },
    SveCountPredicateBytes {
        destination: u8,
        predicate: u8,
        source: u8,
    },
    Branch {
        displacement: i32,
    },
    BranchCondition {
        condition: ConditionV3,
        displacement: i32,
    },
    Return,
}

impl DecodedInstructionV3 {
    const fn is_asimd(self) -> bool {
        matches!(
            self,
            Self::LoadVector128 { .. }
                | Self::LoadVectorDouble { .. }
                | Self::DuplicateByte16 { .. }
                | Self::CompareEqualBytes16 { .. }
                | Self::CompareEqualBytes8 { .. }
                | Self::AndBytes16 { .. }
                | Self::AddBytes16 { .. }
                | Self::OrBytes16 { .. }
                | Self::ShrinkNarrowBytesFromHalfwords { .. }
                | Self::AddAcrossBytes16 { .. }
                | Self::UnsignedMaxAcrossBytes16 { .. }
                | Self::UnsignedMinAcrossBytes8 { .. }
                | Self::UnsignedMinAcrossBytes16 { .. }
                | Self::MoveVectorByteTo32 { .. }
                | Self::MoveVectorDoubleTo64 { .. }
                | Self::Move64ToVectorDouble { .. }
                | Self::Insert64ToVectorDoubleLane1 { .. }
        )
    }

    const fn is_sve(self) -> bool {
        matches!(
            self,
            Self::SvePtrueBytesVl16 { .. }
                | Self::SveDuplicateByte { .. }
                | Self::SveLoadBytes { .. }
                | Self::SveLoadBytesMulVl { .. }
                | Self::SveCompareEqualBytes { .. }
                | Self::SveAndPredicateBytes { .. }
                | Self::SveOrPredicateBytes { .. }
                | Self::SveBitClearPredicateBytesSetFlags { .. }
                | Self::SveTestPredicateBytes { .. }
                | Self::SveBreakBeforeBytes { .. }
                | Self::SveBreakAfterBytes { .. }
                | Self::SveCountPredicateBytes { .. }
        )
    }

    const fn is_sve2(self) -> bool {
        matches!(self, Self::Sve2MatchBytes { .. })
    }

    const fn is_vector(self) -> bool {
        self.is_asimd() || self.is_sve() || self.is_sve2()
    }

    const fn direct_displacement(self) -> Option<i32> {
        match self {
            Self::Branch { displacement } | Self::BranchCondition { displacement, .. } => {
                Some(displacement)
            }
            _ => None,
        }
    }

    const fn expected_relocation_kind(self) -> Option<RelocationKindV3> {
        match self {
            Self::Branch { .. } => Some(RelocationKindV3::Branch26),
            Self::BranchCondition { .. } => Some(RelocationKindV3::ConditionalBranch19),
            _ => None,
        }
    }

    const fn written_gpr(self) -> Option<u8> {
        match self {
            Self::MoveZero64 { destination, .. }
            | Self::MoveKeep64 { destination, .. }
            | Self::AddRegister64 { destination, .. }
            | Self::AddImmediate64 { destination, .. }
            | Self::SubtractRegister64 { destination, .. }
            | Self::SubtractImmediate64 { destination, .. }
            | Self::AndRegister64 { destination, .. }
            | Self::AndLowBits64 { destination, .. }
            | Self::LogicalShiftRight64 { destination, .. }
            | Self::ReverseBits64 { destination, .. }
            | Self::CountLeadingZeros64 { destination, .. }
            | Self::LoadByte { destination, .. }
            | Self::LoadByteRegister { destination, .. }
            | Self::MoveVectorByteTo32 { destination, .. }
            | Self::MoveVectorDoubleTo64 { destination, .. }
            | Self::SveCountPredicateBytes { destination, .. } => Some(destination),
            _ => None,
        }
    }

    /// Return the SIMD/FP destination whose low 64 bits an instruction can
    /// overwrite. AAPCS64 requires callees to preserve d8-d15, even though
    /// the corresponding q-register upper halves are caller-saved.
    pub(crate) const fn written_simd_register(self) -> Option<u8> {
        match self {
            Self::LoadVector128 { destination, .. }
            | Self::LoadVectorDouble { destination, .. }
            | Self::DuplicateByte16 { destination, .. }
            | Self::CompareEqualBytes16 { destination, .. }
            | Self::CompareEqualBytes8 { destination, .. }
            | Self::AndBytes16 { destination, .. }
            | Self::AddBytes16 { destination, .. }
            | Self::OrBytes16 { destination, .. }
            | Self::ShrinkNarrowBytesFromHalfwords { destination, .. }
            | Self::AddAcrossBytes16 { destination, .. }
            | Self::UnsignedMaxAcrossBytes16 { destination, .. }
            | Self::UnsignedMinAcrossBytes8 { destination, .. }
            | Self::UnsignedMinAcrossBytes16 { destination, .. }
            | Self::Move64ToVectorDouble { destination, .. }
            | Self::Insert64ToVectorDoubleLane1 { destination, .. }
            | Self::SveDuplicateByte { destination, .. }
            | Self::SveLoadBytes { destination, .. }
            | Self::SveLoadBytesMulVl { destination, .. } => Some(destination),
            _ => None,
        }
    }
}

/// Independent exact-template, decode, CFG, ABI, and seal audit receipt.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CountAuditReportV3 {
    /// Complete instruction decode passes performed by this cold audit.
    pub decode_passes: u32,
    /// Semantic source identities rebuilt from authenticated image data.
    ///
    /// The direct Count audit receives the original typed KIR as its source
    /// witness, so the current value is zero.
    pub source_identity_rebuilds: u32,
    pub instructions: u32,
    pub direct_branches: u32,
    pub vector_instructions: u32,
    pub simd_candidate_blocks: u32,
    pub staged_filter_checks: u32,
    pub sparse_lane_recoveries: u32,
    pub stores: u32,
    pub returns: u32,
    pub work_upper_bound: u64,
    pub scratch_bytes_upper_bound: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AuditWorkComponentsV3 {
    pub(crate) support_target_layout_and_seals: u64,
    pub(crate) manifest_and_recipe_validation: u64,
    pub(crate) decode: u64,
    pub(crate) canonical_policy_regeneration: u64,
    pub(crate) canonical_label_order: u64,
    pub(crate) canonical_compare: u64,
    pub(crate) cfg_and_relocations: u64,
    pub(crate) identity_structural_traversal: u64,
    pub(crate) identity_hash_bytes: u64,
    pub(crate) identity_hash_finalization: u64,
    pub(crate) scratch_and_allocation_accounting: u64,
    pub(crate) total: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AuditRecipeWorkEnvelopeV3 {
    pub(crate) identity_and_literal: u64,
    pub(crate) filter_membership: u64,
    pub(crate) confirmation_permutation: u64,
    pub(crate) fixed_manifest: u64,
    pub(crate) total: u64,
}

pub(crate) fn independent_recipe_work_envelope_v3(
    literal_len: usize,
) -> Result<AuditRecipeWorkEnvelopeV3, CountAotError> {
    // This derivation intentionally does not use the emitter's formula.
    let literal = audit_to_u64(literal_len)?;
    let identity_and_literal = literal
        .checked_add(literal)
        .and_then(|work| work.checked_add(literal))
        .ok_or(audit_arithmetic_v3())?;
    let filter_membership = literal
        .checked_add(literal)
        .and_then(|work| work.checked_add(literal))
        .and_then(|work| work.checked_add(literal))
        .ok_or(audit_arithmetic_v3())?;
    let confirmation_permutation = literal
        .checked_mul(literal)
        .and_then(|work| work.checked_add(work))
        .ok_or(audit_arithmetic_v3())?;
    let fixed_manifest = 96;
    let total = identity_and_literal
        .checked_add(filter_membership)
        .and_then(|work| work.checked_add(confirmation_permutation))
        .and_then(|work| work.checked_add(fixed_manifest))
        .ok_or(audit_arithmetic_v3())?;
    Ok(AuditRecipeWorkEnvelopeV3 {
        identity_and_literal,
        filter_membership,
        confirmation_permutation,
        fixed_manifest,
        total,
    })
}

#[allow(
    clippy::items_after_statements,
    reason = "named audit-work constants stay next to the exact phase formula they justify"
)]
pub(crate) fn audit_work_components_v3(
    code_bytes: usize,
    labels: usize,
    relocations: usize,
    literal_len: usize,
) -> Result<AuditWorkComponentsV3, CountAotError> {
    let instruction_count = code_bytes / 4;
    let label_count = labels;
    let instructions = audit_to_u64(instruction_count)?;
    let code_bytes = audit_to_u64(code_bytes)?;
    let labels = audit_to_u64(labels)?;
    let relocations = audit_to_u64(relocations)?;
    let literal = audit_to_u64(literal_len)?;
    let label_order = label_order_work_upper_bound_v3(
        usize::try_from(labels).map_err(|_| audit_arithmetic_v3())?,
    )?;
    let identity_bytes = identity_bytes_upper_bound_v3(
        usize::try_from(code_bytes).map_err(|_| audit_arithmetic_v3())?,
        usize::try_from(labels).map_err(|_| audit_arithmetic_v3())?,
        usize::try_from(relocations).map_err(|_| audit_arithmetic_v3())?,
    )?;
    let identity_structural =
        identity_structural_traversal_work_v3(labels, relocations).ok_or(audit_arithmetic_v3())?;

    // Every fixed component below corresponds to named checks in audit_impl:
    // support/target 14, source/layout/dimensions 15, stats/receipt 28,
    // decoded summary 14, public wrapper/report 9, and checked conversions 16.
    const SUPPORT_TARGET_LAYOUT_AND_SEALS_FIXED_V3: u64 = 14 + 15 + 28 + 14 + 9 + 16;
    const FILTER_FIXED_WORK_V3: u64 = 16;
    // Manifest construction separately validates the bounded filter offsets
    // and copies every literal byte into its authenticated fixed-width record.
    const MANIFEST_WORK_PER_LITERAL_BYTE_V3: u64 = 1;
    const MANIFEST_FIXED_WORK_V3: u64 = 16;
    // Each decoded word reads four bytes, decodes one ordered mask row, and
    // appends one exact record.
    let decode = code_bytes
        .checked_add(instructions.checked_mul(2).ok_or(audit_arithmetic_v3())?)
        .ok_or(audit_arithmetic_v3())?;
    // The policy generator appends no more than the prospective instruction
    // and label dimensions, resolves each instruction once, and scans each
    // literal byte in setup/confirmation at most eight times.
    let canonical_policy_regeneration = instructions
        .checked_mul(3)
        .and_then(|work| work.checked_add(labels.checked_mul(2)?))
        .and_then(|work| work.checked_add(literal.checked_mul(8)?))
        .and_then(|work| work.checked_add(32))
        .ok_or(audit_arithmetic_v3())?;
    let canonical_label_order = label_order.total;
    let canonical_compare = instructions
        .checked_add(labels)
        .ok_or(audit_arithmetic_v3())?;
    // Each instruction performs fixed classification/ABI checks. A branch may
    // scan every label, then consumes one four-field relocation record.
    let decoded_cfg_safety =
        decoded_cfg_safety_work_upper_bound_v3(instruction_count, label_count)?;
    let cfg_and_relocations = instructions
        .checked_mul(labels.checked_add(18).ok_or(audit_arithmetic_v3())?)
        .and_then(|work| work.checked_add(relocations.checked_mul(8)?))
        .and_then(|work| work.checked_add(decoded_cfg_safety))
        .ok_or(audit_arithmetic_v3())?;
    let recipe_validation = independent_recipe_work_envelope_v3(literal_len)?.total;
    let manifest_and_recipe_validation = literal
        .checked_mul(MANIFEST_WORK_PER_LITERAL_BYTE_V3)
        .and_then(|work| work.checked_add(recipe_validation))
        .and_then(|work| work.checked_add(FILTER_FIXED_WORK_V3))
        .and_then(|work| work.checked_add(MANIFEST_FIXED_WORK_V3))
        .ok_or(audit_arithmetic_v3())?;
    // A sealed audit counts the encoding and hashes it: two structural
    // traversals, one complete byte traversal, and one digest finalization.
    let identity_structural_traversal = identity_structural
        .checked_mul(2)
        .ok_or(audit_arithmetic_v3())?;
    let identity_hash_bytes = identity_bytes;
    let identity_hash_finalization = 8;
    // One complete scratch derivation, one assembler-envelope recomputation,
    // six ExactVec admission sites, actual-capacity arithmetic, persistent
    // envelope arithmetic, and caller/hard/receipt seals.
    let scratch_and_allocation_accounting = 24_u64
        .checked_add(assembler_scratch_derivation_work_upper_bound_v3())
        .and_then(|work| work.checked_add(6 * 3))
        .and_then(|work| work.checked_add(18))
        .and_then(|work| work.checked_add(16))
        .ok_or(audit_arithmetic_v3())?;
    let support_target_layout_and_seals = SUPPORT_TARGET_LAYOUT_AND_SEALS_FIXED_V3;
    let total = support_target_layout_and_seals
        .checked_add(manifest_and_recipe_validation)
        .and_then(|work| work.checked_add(decode))
        .and_then(|work| work.checked_add(canonical_policy_regeneration))
        .and_then(|work| work.checked_add(canonical_label_order))
        .and_then(|work| work.checked_add(canonical_compare))
        .and_then(|work| work.checked_add(cfg_and_relocations))
        .and_then(|work| work.checked_add(identity_structural_traversal))
        .and_then(|work| work.checked_add(identity_hash_bytes))
        .and_then(|work| work.checked_add(identity_hash_finalization))
        .and_then(|work| work.checked_add(scratch_and_allocation_accounting))
        .ok_or(audit_arithmetic_v3())?;
    Ok(AuditWorkComponentsV3 {
        support_target_layout_and_seals,
        manifest_and_recipe_validation,
        decode,
        canonical_policy_regeneration,
        canonical_label_order,
        canonical_compare,
        cfg_and_relocations,
        identity_structural_traversal,
        identity_hash_bytes,
        identity_hash_finalization,
        scratch_and_allocation_accounting,
        total,
    })
}

pub(crate) fn audit_work_upper_bound_v3(
    code_bytes: usize,
    labels: usize,
    relocations: usize,
    literal_len: usize,
) -> Result<u64, CountAotError> {
    Ok(audit_work_components_v3(code_bytes, labels, relocations, literal_len)?.total)
}

type AuditCommonInlineStateV3 = (
    &'static ExactAggregateProgram<Count>,
    &'static AotCountImageV3,
    ProspectiveV3,
    bool,
    CountAuditReportV3,
    AotCountLiteralManifestV3,
    [usize; 20],
    [u32; 16],
    [u64; 16],
    CountAotError,
);
type AuditDecodeInlineStateV3 = (
    AuditCommonInlineStateV3,
    ExactVec<DecodedInstructionV3>,
    core::iter::Enumerate<core::slice::ChunksExact<'static, u8>>,
    DecodedInstructionV3,
    [u32; 8],
    CountAotError,
);
type AuditPolicyInlineStateV3 = (
    AuditDecodeInlineStateV3,
    PolicySinkV3,
    ResolvedPolicyV3,
    [usize; 12],
    [u64; 8],
    CountAotError,
);
type AuditIdentityInlineStateV3 = (
    AuditPolicyInlineStateV3,
    AotCountArtifactIdentityV3,
    [u8; 32],
    [u64; 8],
    CountAotError,
);
type AuditCandidateWrapperInlineStateV3 = (
    &'static ExactAggregateProgram<Count>,
    &'static AotCountImageV3,
    ProspectiveV3,
    Result<CountAuditReportV3, CountAotError>,
);
type AuditPublicWrapperInlineStateV3 = (
    &'static ExactAggregateProgram<Count>,
    &'static AotCountImageV3,
    ProspectiveV3,
    CountAuditReportV3,
    Result<CountAuditReportV3, CountAotError>,
);

pub(crate) const fn audit_candidate_wrapper_inline_bytes_v3() -> usize {
    size_of::<AuditCandidateWrapperInlineStateV3>()
}

pub(crate) const fn audit_public_wrapper_inline_bytes_v3() -> usize {
    size_of::<AuditPublicWrapperInlineStateV3>()
}

pub(crate) fn audit_scratch_upper_bound_v3(
    code_bytes: usize,
    labels: usize,
    relocations: usize,
) -> Result<u64, CountAotError> {
    let instructions = code_bytes / 4;
    let fixed = size_of::<AuditIdentityInlineStateV3>();
    let requested = instructions
        .checked_mul(size_of::<DecodedInstructionV3>())
        .and_then(|bytes| {
            bytes.checked_add(
                instructions.checked_mul(size_of::<PolicyInstructionV3>())?,
            )
        })
        .and_then(|bytes| {
            bytes.checked_add(
                labels.checked_mul(size_of::<PolicyLabelRecordV3>())?,
            )
        })
        .and_then(|bytes| {
            bytes.checked_add(
                instructions.checked_mul(size_of::<DecodedInstructionV3>())?,
            )
        })
        .and_then(|bytes| {
            bytes.checked_add(labels.checked_mul(size_of::<CodeLabelV3>())?)
        })
        .and_then(|bytes| bytes.checked_add(fixed))
        .and_then(|bytes| bytes.checked_add(identity_scratch_bytes_v3()))
        // Relocations are retained in the borrowed image, but the active
        // relocation walk keeps one complete record plus iterator state live.
        .and_then(|bytes| {
            bytes.checked_add(
                relocations
                    .min(1)
                    .checked_mul(size_of::<RelocationV3>())?,
            )
        })
        .ok_or(audit_arithmetic_v3())?;
    audit_to_u64(requested)?
        .checked_add(decoded_cfg_safety_scratch_bytes_v3(instructions)?)
        .ok_or(audit_arithmetic_v3())
}

/// Audit a sealed optimizing-v3 image without trusting emitter templates.
pub fn audit_count_image_v3(
    program: &ExactAggregateProgram<Count>,
    recipe: &CountRecipeV3,
    image: &AotCountImageV3,
) -> Result<CountAuditReportV3, CountAotError> {
    let literal_len = independent_preflight_v3(program)?;
    let prospective = prospective_v3(literal_len)?;
    audit_impl_v3(program, recipe, image, prospective, true)
}

/// Audit an untrusted borrowed image by bounded regeneration, independent
/// decoded-policy audit, and exact field/byte comparison.
///
/// This is the static-runtime adoption surface: callers may construct a view
/// over mapped code and parsed read-only metadata without allocating an
/// `AotCountImageV3`. Regeneration allocations and work are bounded by the
/// explicit emitter limits.
pub fn audit_count_image_view_v3(
    program: &ExactAggregateProgram<Count>,
    recipe: &CountRecipeV3,
    view: AotCountImageViewV3<'_>,
    limits: CountEmitLimitsV3,
) -> Result<CountAuditReportV3, CountAotError> {
    let expected = emit_count_v3(program, recipe, limits)?;
    let report = audit_count_image_v3(program, recipe, &expected)?;
    if view.support != expected.support
        || view.target != expected.target
        || view.source_identity != expected.source_identity
        || view.literal_manifest != expected.literal_manifest
        || view.recipe_manifest != expected.recipe_manifest
        || view.layout != expected.layout
        || view.code != expected.code.as_slice()
        || view.labels != expected.labels.as_slice()
        || view.relocations != expected.relocations.as_slice()
        || view.stats != expected.stats
        || view.artifact_identity != expected.artifact_identity
        || view.build_receipt != expected.build_receipt
    {
        return Err(invalid_v3("v3 borrowed image mismatch"));
    }
    Ok(report)
}

/// Audit raw mapped code using compact metadata and a source-bound recipe.
///
/// Internal labels, relocations, statistics, and resource receipts are
/// regenerated under `limits`; they do not need to be retained in the object
/// wire format.
pub fn audit_count_mapped_code_v3(
    program: &ExactAggregateProgram<Count>,
    canonical_recipe: &[u8; COUNT_V3_RECIPE_CANONICAL_BYTES],
    mapped_code: &[u8],
    metadata: AotCountMappedMetadataV3,
    limits: CountEmitLimitsV3,
) -> Result<CountAuditReportV3, CountAotError> {
    let recipe = decode_count_recipe_v3(program, canonical_recipe)
        .map_err(|_| invalid_v3("v3 canonical recipe decode"))?;
    let expected = emit_count_v3(program, &recipe, limits)?;
    let report = audit_count_image_v3(program, &recipe, &expected)?;
    let expected_metadata = AotCountMappedMetadataV3::from_image(&expected);
    if metadata != expected_metadata || mapped_code != expected.code.as_slice() {
        return Err(invalid_v3("v3 mapped code or metadata mismatch"));
    }
    Ok(report)
}

pub(crate) fn audit_count_image_candidate_v3(
    program: &ExactAggregateProgram<Count>,
    recipe: &CountRecipeV3,
    image: &AotCountImageV3,
    prospective: ProspectiveV3,
) -> Result<CountAuditReportV3, CountAotError> {
    audit_impl_v3(program, recipe, image, prospective, false)
}

#[cfg(test)]
pub(crate) fn audit_count_image_with_scratch_limit_for_test_v3(
    program: &ExactAggregateProgram<Count>,
    recipe: &CountRecipeV3,
    image: &AotCountImageV3,
    scratch_limit: u64,
) -> Result<CountAuditReportV3, CountAotError> {
    let literal_len = independent_preflight_v3(program)?;
    let mut prospective = prospective_v3(literal_len)?;
    prospective.scratch_limit = prospective.scratch_limit.min(scratch_limit);
    audit_impl_v3(program, recipe, image, prospective, true)
}

fn same_source_bounds_v3(mut observed: ProspectiveV3, source: ProspectiveV3) -> bool {
    observed.scratch_limit = source.scratch_limit;
    observed.persistent_limit = source.persistent_limit;
    observed == source
}

#[allow(
    clippy::too_many_lines,
    reason = "the independent v3 audit keeps every seal and decoded invariant visible"
)]
fn audit_impl_v3(
    program: &ExactAggregateProgram<Count>,
    recipe: &CountRecipeV3,
    image: &AotCountImageV3,
    prospective: ProspectiveV3,
    sealed: bool,
) -> Result<CountAuditReportV3, CountAotError> {
    let literal_len = independent_preflight_v3(program)?;
    let source_prospective = prospective_v3(literal_len)?;
    if !same_source_bounds_v3(prospective, source_prospective) {
        return Err(invalid_v3("v3 prospective source bounds"));
    }
    let independent_recipe_work = independent_recipe_work_envelope_v3(literal_len)?;
    if prospective.recipe_validation_work != independent_recipe_work.total
        || independent_recipe_work.total > prospective.audit_work
    {
        return Err(invalid_v3("v3 recipe work pre-admission"));
    }
    let complete_audit_scratch = audit_scratch_upper_bound_v3(
        prospective.code_bytes,
        prospective.labels,
        prospective.relocations,
    )?;
    if complete_audit_scratch != prospective.audit_scratch {
        return Err(invalid_v3("v3 audit scratch recomputation"));
    }
    let complete_assembler_scratch = assembler_scratch_upper_bound_v3(
        prospective.code_bytes,
        prospective.labels,
        prospective.relocations,
    )?;
    if complete_assembler_scratch != prospective.assembler_scratch {
        return Err(invalid_v3("v3 assembler scratch recomputation"));
    }
    refuse_audit_scratch_v3(complete_audit_scratch, prospective.scratch_limit)?;
    if prospective.persistent > prospective.persistent_limit {
        return Err(CountAotError::ResourceLimit {
            resource: CountAotResource::PersistentBytes,
            limit: prospective.persistent_limit,
            required: prospective.persistent,
        });
    }
    // Capacity and persistent admission deliberately precede the first
    // literal byte, code byte, label, or relocation traversal.
    let expected_label_capacity_bytes = image
        .labels
        .capacity()
        .checked_mul(size_of::<CodeLabelV3>())
        .ok_or(audit_arithmetic_v3())?;
    let expected_relocation_capacity_bytes = image
        .relocations
        .capacity()
        .checked_mul(size_of::<RelocationV3>())
        .ok_or(audit_arithmetic_v3())?;
    let expected_retained_heap_bytes = image
        .code
        .capacity()
        .checked_add(expected_label_capacity_bytes)
        .and_then(|bytes| bytes.checked_add(expected_relocation_capacity_bytes))
        .ok_or(audit_arithmetic_v3())?;
    let actual_persistent_bytes = expected_retained_heap_bytes
        .checked_add(size_of::<AotCountImageV3>())
        .ok_or(audit_arithmetic_v3())?;
    let actual_persistent = audit_to_u64(actual_persistent_bytes)?;
    if image.code.capacity() > prospective.code_bytes
        || image.labels.capacity() > prospective.labels
        || image.relocations.capacity() > prospective.relocations
        || actual_persistent > prospective.persistent
    {
        return Err(invalid_v3("v3 prospective persistent seal"));
    }
    if actual_persistent > prospective.persistent_limit {
        return Err(CountAotError::ResourceLimit {
            resource: CountAotResource::PersistentBytes,
            limit: prospective.persistent_limit,
            required: actual_persistent,
        });
    }
    let receipt = image.build_receipt;
    let observed_assembler_scratch = assembler_scratch_for_capacities_v3(
        image.code.capacity(),
        prospective.labels,
        prospective.relocations,
        image.labels.capacity(),
        image.relocations.capacity(),
    )?;
    let observed_image_assembly_scratch = image_assembly_scratch_for_capacities_v3(
        image.code.capacity(),
        image.labels.capacity(),
        image.relocations.capacity(),
    )?;
    let observed_emission_scratch = observed_assembler_scratch.max(observed_image_assembly_scratch);
    if receipt.code_capacity_bytes != image.code.capacity()
        || receipt.label_capacity_bytes != expected_label_capacity_bytes
        || receipt.relocation_capacity_bytes != expected_relocation_capacity_bytes
        || receipt.retained_heap_bytes != expected_retained_heap_bytes
        || receipt.inline_bytes != size_of::<AotCountImageV3>()
    {
        return Err(invalid_v3("v3 persistent capacity receipt"));
    }
    if observed_assembler_scratch > prospective.assembler_scratch
        || observed_image_assembly_scratch > prospective.image_assembly_scratch
        || observed_emission_scratch > prospective.emission_scratch
        || receipt.emission_peak_scratch_bytes != observed_emission_scratch
    {
        return Err(invalid_v3("v3 emission scratch receipt"));
    }
    let literal = program.literal();
    let (audit_recipe, expected_recipe_manifest) = audit_project_recipe_v3(program, recipe)?;
    let expected_support = match audit_recipe.required_isa {
        CountV3RequiredIsa::Aarch64Neon128 => SUPPORTED_AOT_COUNT_BACKEND_TUPLES_V3[0],
        CountV3RequiredIsa::Aarch64SveVl16 => SUPPORTED_AOT_COUNT_BACKEND_TUPLES_V3[1],
        CountV3RequiredIsa::Aarch64Sve2Vl16 => SUPPORTED_AOT_COUNT_BACKEND_TUPLES_V3[2],
    };
    if literal_len != literal.len()
        || image.support.backend_version != AOT_COUNT_BACKEND_VERSION_V3
        || !is_supported_aot_count_backend_tuple_v3(image.support)
        || image.support != expected_support
        || image.support.candidate_block_starts
            != u8::try_from(SIMD_CANDIDATE_STARTS_V3).expect("candidate block width fits u8")
        || image.support.vector_bytes != 16
    {
        return Err(invalid_v3("v3 support tuple"));
    }
    if image.target.architecture != image.support.architecture
        || image.target.little_endian != image.support.little_endian
        || image.target.pointer_width != image.support.pointer_width
        || image.target.abi != image.support.target_abi
        || !image
            .support
            .allowed_features
            .contains(image.target.features)
    {
        return Err(invalid_v3("v3 target tuple"));
    }
    let independent_filter = audit_recipe.filter;
    let independent_filter_offsets = independent_filter
        .as_ref()
        .map_or(&[][..], AuditCandidateFilterV3::offsets);
    let expected_manifest =
        AotCountLiteralManifestV3::from_literal_and_offsets(literal, independent_filter_offsets)
            .ok_or(invalid_v3("v3 independent manifest"))?;
    if image.source_identity != program.cache_identity()
        || image.literal_manifest != expected_manifest
        || image.recipe_manifest != expected_recipe_manifest
        || image.build_receipt.recipe != expected_recipe_manifest
    {
        return Err(invalid_v3("v3 semantic manifest"));
    }
    let expected_code_alignment = 16_u32;
    let expected_rodata_offset = align_up_audit_v3(
        image.code.len(),
        usize::try_from(expected_code_alignment).unwrap(),
    )?;
    let expected_rodata_offset =
        u32::try_from(expected_rodata_offset).map_err(|_| audit_arithmetic_v3())?;
    if image.layout.code_alignment != expected_code_alignment
        || image.layout.rodata_alignment != expected_code_alignment
        || image.layout.rodata_from_code_start != expected_rodata_offset
        || image.layout.total_mapped_bytes != expected_rodata_offset
        || !image.code.len().is_multiple_of(4)
        || image.code.len() > prospective.code_bytes
        || image.labels.len() > prospective.labels
        || image.relocations.len() > prospective.relocations
    {
        return Err(invalid_v3("v3 image layout"));
    }
    let expected_emission_work = audit_to_u64(image.code.len() / 4)?
        .checked_add(
            audit_to_u64(image.labels.len())?
                .checked_mul(2)
                .ok_or(audit_arithmetic_v3())?,
        )
        .and_then(|work| work.checked_add(audit_to_u64(image.relocations.len()).ok()?))
        .and_then(|work| {
            work.checked_add(
                label_order_work_upper_bound_v3(image.labels.len())
                    .ok()?
                    .total,
            )
        })
        .ok_or(audit_arithmetic_v3())?;
    if image.stats.code_bytes
        != u32::try_from(image.code.len()).map_err(|_| audit_arithmetic_v3())?
        || image.stats.data_bytes != 0
        || image.stats.labels
            != u32::try_from(image.labels.len()).map_err(|_| audit_arithmetic_v3())?
        || image.stats.relocations
            != u32::try_from(image.relocations.len()).map_err(|_| audit_arithmetic_v3())?
        || image.stats.emitted_instructions != image.stats.code_bytes / 4
        || image.stats.strategy_id != expected_recipe_manifest.strategy_id
        || image.stats.schedule_id != expected_recipe_manifest.schedule_id
        || image.stats.register_plan_id != expected_recipe_manifest.register_plan_id
        || image.stats.candidate_filter_bytes
            != independent_filter.map_or(0, AuditCandidateFilterV3::len)
        || image.stats.confirmation_chunks != u8::try_from(literal_len / 8).expect("bounded chunks")
        || image.stats.confirmation_tail_bytes
            != u8::try_from(literal_len % 8).expect("bounded tail")
        || image.stats.audit_work_upper_bound != prospective.audit_work
        || image.stats.total_work_upper_bound != prospective.work
        || image.stats.emission_work != expected_emission_work
        || image.build_receipt.support != image.support
        || image.build_receipt.work_upper_bound != prospective.work
        || image.build_receipt.code_capacity_bytes != image.code.capacity()
    {
        return Err(invalid_v3("v3 image statistics"));
    }

    let instruction_count = image.code.len() / 4;
    let mut decoded = audit_exact_vec_v3(instruction_count, prospective)?;
    for (index, bytes) in image.code.chunks_exact(4).enumerate() {
        let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let offset = u32::try_from(index.checked_mul(4).ok_or(audit_arithmetic_v3())?)
            .map_err(|_| audit_arithmetic_v3())?;
        let instruction = decode_word_v3(word, offset)?;
        if let Some(destination) = instruction.written_simd_register()
            && (8..=15).contains(&destination)
        {
            return Err(invalid_v3("v3 forbidden callee-saved SIMD write"));
        }
        audit_push_v3(&mut decoded, instruction, "v3 decoded capacity")?;
    }

    let policy = independent_policy_template_v3(literal, audit_recipe, prospective)?;
    if decoded.as_slice() != policy.instructions.as_slice()
        || image.labels.as_slice() != policy.labels.as_slice()
    {
        return Err(invalid_v3("v3 independent full template"));
    }
    audit_decoded_cfg_safety_v3(decoded.as_slice(), image.labels.as_slice(), literal_len)?;

    let mut relocation_index = 0_usize;
    let mut direct_branches = 0_u32;
    let mut vector_instructions = 0_u32;
    let mut asimd_instructions = 0_u32;
    let mut sve_instructions = 0_u32;
    let mut sve2_instructions = 0_u32;
    let mut simd_candidate_blocks = 0_u32;
    let mut staged_filter_checks = 0_u32;
    let mut sparse_lane_recoveries = 0_u32;
    let mut stores = 0_u32;
    let mut returns = 0_u32;
    for (index, instruction) in decoded.iter().copied().enumerate() {
        if instruction.is_vector() {
            vector_instructions = vector_instructions
                .checked_add(1)
                .ok_or(audit_arithmetic_v3())?;
        }
        if instruction.is_asimd() {
            asimd_instructions = asimd_instructions
                .checked_add(1)
                .ok_or(audit_arithmetic_v3())?;
        }
        if instruction.is_sve() {
            sve_instructions = sve_instructions
                .checked_add(1)
                .ok_or(audit_arithmetic_v3())?;
        }
        if instruction.is_sve2() {
            sve2_instructions = sve2_instructions
                .checked_add(1)
                .ok_or(audit_arithmetic_v3())?;
        }
        if matches!(
            instruction,
            DecodedInstructionV3::ShrinkNarrowBytesFromHalfwords { shift: 4, .. }
        ) {
            simd_candidate_blocks = simd_candidate_blocks
                .checked_add(1)
                .ok_or(audit_arithmetic_v3())?;
        }
        if matches!(
            instruction,
            DecodedInstructionV3::CountLeadingZeros64 { .. }
        ) {
            sparse_lane_recoveries = sparse_lane_recoveries
                .checked_add(1)
                .ok_or(audit_arithmetic_v3())?;
        }
        if matches!(
            instruction,
            DecodedInstructionV3::UnsignedMaxAcrossBytes16 { source: 0, .. }
        ) {
            staged_filter_checks = staged_filter_checks
                .checked_add(1)
                .ok_or(audit_arithmetic_v3())?;
        }
        if let Some(destination) = instruction.written_gpr()
            && (destination == X2 || destination > X17)
        {
            return Err(invalid_v3("v3 forbidden GPR write"));
        }
        match instruction {
            DecodedInstructionV3::Store64 {
                source,
                base,
                offset,
            } => {
                if source != X13 || base != X2 || offset != 0 {
                    return Err(invalid_v3("v3 store policy"));
                }
                stores = stores.checked_add(1).ok_or(audit_arithmetic_v3())?;
            }
            DecodedInstructionV3::Return => {
                returns = returns.checked_add(1).ok_or(audit_arithmetic_v3())?;
            }
            _ => {}
        }
        if let Some(displacement) = instruction.direct_displacement() {
            direct_branches = direct_branches
                .checked_add(1)
                .ok_or(audit_arithmetic_v3())?;
            let code_offset = u32::try_from(index.checked_mul(4).ok_or(audit_arithmetic_v3())?)
                .map_err(|_| audit_arithmetic_v3())?;
            let target = i64::from(code_offset)
                .checked_add(i64::from(displacement))
                .ok_or(audit_arithmetic_v3())?;
            let target = u32::try_from(target).map_err(|_| invalid_v3("v3 branch target range"))?;
            if target >= image.stats.code_bytes
                || target % 4 != 0
                || image.labels.iter().all(|label| label.offset != target)
            {
                return Err(invalid_v3("v3 branch target"));
            }
            let relocation = image
                .relocations
                .get(relocation_index)
                .ok_or(invalid_v3("v3 missing relocation"))?;
            let word = read_word_audit_v3(&image.code, usize::try_from(code_offset).unwrap())?;
            if relocation.code_offset != code_offset
                || relocation.kind
                    != instruction
                        .expected_relocation_kind()
                        .ok_or(invalid_v3("v3 relocation instruction"))?
                || relocation.target != RelocationTargetV3::CodeOffset(target)
                || relocation.resolved_word != word
            {
                return Err(invalid_v3("v3 relocation mismatch"));
            }
            relocation_index = relocation_index
                .checked_add(1)
                .ok_or(audit_arithmetic_v3())?;
        }
    }
    let (expected_candidate_blocks, expected_lane_recoveries, expected_staged_checks) =
        if literal_len < 2 || audit_recipe.required_isa != CountV3RequiredIsa::Aarch64Neon128 {
            (0, 0, 0)
        } else if audit_recipe.strategy == AuditLoweringStrategyV3::DirectExactMask {
            (0, 0, 0)
        } else if audit_recipe.strategy == AuditLoweringStrategyV3::Incumbent {
            (
                2,
                1,
                u32::from(
                    independent_filter
                        .map_or(0, AuditCandidateFilterV3::len)
                        .saturating_sub(3),
                ),
            )
        } else if audit_recipe.strategy == AuditLoweringStrategyV3::PeriodicRun {
            // Every specialized NEON graph has one UMAXV over its primary
            // equality mask before it can enter the one-column sparse scan.
            // This is a staged filter proof just as surely as the incumbent's
            // optional third-column guard, and must be closed by the decoded
            // summary instead of silently omitted from the receipt.
            (1, 1, 1)
        } else {
            // Non-periodic specialized graphs add one direct mask pack plus
            // the first-half and first-pair reductions used to recover the
            // earliest surviving block from a 128-start composite batch.
            (2, 1, 3)
        };
    if relocation_index != image.relocations.len()
        || direct_branches != image.stats.relocations
        || vector_instructions != image.stats.vector_instructions
        || stores != 1
        || returns != (if literal.is_empty() { 2 } else { 1 })
        || simd_candidate_blocks != expected_candidate_blocks
        || sparse_lane_recoveries != expected_lane_recoveries
        || staged_filter_checks != expected_staged_checks
    {
        return Err(invalid_v3("v3 decoded summary"));
    }
    let mut decoded_features = AotCountCpuFeatures::NONE;
    if asimd_instructions != 0 {
        decoded_features = decoded_features.union(AotCountCpuFeatures::ASIMD);
    }
    if sve_instructions != 0 {
        decoded_features = decoded_features.union(AotCountCpuFeatures::SVE);
    }
    if sve2_instructions != 0 {
        decoded_features = decoded_features
            .union(AotCountCpuFeatures::SVE)
            .union(AotCountCpuFeatures::SVE2);
    }
    let expected_features = if literal.is_empty() {
        AotCountCpuFeatures::NONE
    } else {
        match audit_recipe.required_isa {
            CountV3RequiredIsa::Aarch64Neon128 => AotCountCpuFeatures::ASIMD,
            CountV3RequiredIsa::Aarch64SveVl16 => AotCountCpuFeatures::SVE,
            CountV3RequiredIsa::Aarch64Sve2Vl16 => {
                AotCountCpuFeatures::SVE.union(AotCountCpuFeatures::SVE2)
            }
        }
    };
    let instruction_classes_match = match audit_recipe.required_isa {
        CountV3RequiredIsa::Aarch64Neon128 => {
            literal.is_empty()
                || (asimd_instructions != 0 && sve_instructions == 0 && sve2_instructions == 0)
        }
        CountV3RequiredIsa::Aarch64SveVl16 => {
            literal.is_empty()
                || (asimd_instructions == 0 && sve_instructions != 0 && sve2_instructions == 0)
        }
        CountV3RequiredIsa::Aarch64Sve2Vl16 => {
            literal.is_empty()
                || (asimd_instructions == 0 && sve_instructions != 0 && sve2_instructions != 0)
        }
    };
    if !instruction_classes_match
        || vector_instructions
            != asimd_instructions
                .checked_add(sve_instructions)
                .and_then(|value| value.checked_add(sve2_instructions))
                .ok_or(audit_arithmetic_v3())?
        || decoded_features != expected_features
        || image.target.features != decoded_features
    {
        return Err(invalid_v3("v3 decoded target features"));
    }

    let report = CountAuditReportV3 {
        decode_passes: 1,
        source_identity_rebuilds: 0,
        instructions: u32::try_from(instruction_count).map_err(|_| audit_arithmetic_v3())?,
        direct_branches,
        vector_instructions,
        simd_candidate_blocks,
        staged_filter_checks,
        sparse_lane_recoveries,
        stores,
        returns,
        work_upper_bound: prospective.audit_work,
        scratch_bytes_upper_bound: prospective.audit_scratch,
    };
    if sealed
        && (image.build_receipt.audit != report
            || report.scratch_bytes_upper_bound != prospective.audit_scratch
            || image.stats.scratch_bytes_upper_bound != prospective.scratch
            || image.build_receipt.scratch_bytes_upper_bound != prospective.scratch
            || image.stats.identity_bytes_hashed != artifact_identity_encoded_len_v3(image)?
            || image.stats.identity_bytes_hashed > prospective.identity_bytes_hashed
            || compute_artifact_identity_v3(image)?.0 != image.artifact_identity)
    {
        return Err(invalid_v3("v3 sealed receipt or identity"));
    }
    Ok(report)
}

fn independent_preflight_v3(
    program: &ExactAggregateProgram<Count>,
) -> Result<usize, CountAotError> {
    if program.output() != AggregateOutput::Count {
        return Err(invalid_v3("v3 audit output"));
    }
    let literal_len = program.literal().len();
    if literal_len > MAX_EXACT_AGGREGATE_LITERAL_BYTES || literal_len > 32 {
        return Err(invalid_v3("v3 audit literal width"));
    }
    // The typed exact-Count program is the structural-shape witness. Safe
    // callers cannot forge or mutate its private fixed-shape KIR payload.
    Ok(literal_len)
}

fn audit_project_recipe_v3(
    program: &ExactAggregateProgram<Count>,
    recipe: &CountRecipeV3,
) -> Result<(AuditLoweringRecipeV3, AotCountRecipeManifestV3), CountAotError> {
    validate_count_recipe_v3(program, recipe)
        .map_err(|_| invalid_v3("v3 optimizer recipe validation"))?;
    let canonical_recipe = encode_count_recipe_v3(recipe);
    match decode_count_recipe_v3(program, &canonical_recipe) {
        Ok(decoded) if decoded == *recipe => {}
        _ => return Err(invalid_v3("v3 canonical recipe round trip")),
    }
    let expected_register_plan = match recipe.required_isa() {
        CountV3RequiredIsa::Aarch64Neon128 => CountV3RegisterPlanId::Aarch64NeonV1,
        CountV3RequiredIsa::Aarch64SveVl16 => CountV3RegisterPlanId::Aarch64SveVl16V1,
        CountV3RequiredIsa::Aarch64Sve2Vl16 => CountV3RegisterPlanId::Aarch64Sve2Vl16V1,
    };
    if recipe.register_plan_id() != expected_register_plan
        || recipe.successor_mode() != CountV3SuccessorMode::NonOverlapping
    {
        return Err(invalid_v3("v3 recipe ISA or ABI"));
    }
    let expected_schedule = match recipe.strategy() {
        CountV3Strategy::Incumbent => CountV3ScheduleId::IncumbentV2,
        CountV3Strategy::SparseRareColumns => CountV3ScheduleId::SparseColumnsV1,
        CountV3Strategy::EndpointDense => CountV3ScheduleId::EndpointDenseV1,
        CountV3Strategy::PeriodicRun => CountV3ScheduleId::PeriodicRunV1,
        CountV3Strategy::DirectExactMask => CountV3ScheduleId::DirectExactMaskV1,
    };
    if recipe.schedule_id() != expected_schedule {
        return Err(invalid_v3("v3 strategy schedule"));
    }

    let literal = program.literal();
    let width = literal.len();
    let filters = recipe.filter_offsets();
    if (width < 2 && !filters.is_empty())
        || (width >= 2 && !(2..=4).contains(&filters.len()))
        || filters.iter().any(|offset| usize::from(*offset) >= width)
    {
        return Err(invalid_v3("v3 recipe filters"));
    }
    for right in 0..filters.len() {
        for left in 0..right {
            if filters[left] == filters[right] {
                return Err(invalid_v3("v3 duplicate recipe filter"));
            }
        }
    }
    if recipe.strategy() == CountV3Strategy::EndpointDense {
        let last =
            u8::try_from(width.saturating_sub(1)).map_err(|_| invalid_v3("v3 endpoint width"))?;
        let endpoints = filters.len() >= 2
            && ((filters[0] == 0 && filters[1] == last) || (filters[0] == last && filters[1] == 0));
        if width < 2 || !(2..=3).contains(&filters.len()) || !endpoints {
            return Err(invalid_v3("v3 endpoint schedule"));
        }
    }
    let mut minimum_period = 0_usize;
    if width != 0 {
        'period: for candidate in 1..=width {
            for index in candidate..width {
                if literal[index] != literal[index - candidate] {
                    continue 'period;
                }
            }
            minimum_period = candidate;
            break;
        }
    }
    if recipe.strategy() == CountV3Strategy::DirectExactMask {
        let covers_literal = (2..=4).contains(&width)
            && filters.len() == width
            && filters
                .iter()
                .copied()
                .enumerate()
                .all(|(offset, filter)| usize::from(filter) == offset);
        if !covers_literal || minimum_period != width {
            return Err(invalid_v3("v3 direct exact-mask schedule"));
        }
    }
    let valid_periodic_stride = if recipe.strategy() == CountV3Strategy::PeriodicRun {
        width >= 2
            && minimum_period < width
            && usize::from(recipe.periodic_stride()) == minimum_period
    } else {
        recipe.periodic_stride() == 0
    };
    if recipe.mismatch_stride() != 1
        || usize::from(recipe.match_stride()) != width
        || !valid_periodic_stride
    {
        return Err(invalid_v3("v3 recipe strides"));
    }

    let order = recipe.confirmation_order();
    if order.len() != width {
        return Err(invalid_v3("v3 confirmation length"));
    }
    let mut seen = [false; 32];
    for offset in order.iter().copied() {
        let offset = usize::from(offset);
        if offset >= width || seen[offset] {
            return Err(invalid_v3("v3 confirmation permutation"));
        }
        seen[offset] = true;
    }

    let groups = recipe.sparse_group_blocks();
    if groups.len() > 4 {
        return Err(invalid_v3("v3 sparse group count"));
    }
    let mut group_covered = [false; 32];
    let mut sparse_group_first_offsets = [0_u8; 4];
    let mut sparse_group_lengths = [0_u8; 4];
    for (group_index, group) in groups.iter().copied().enumerate() {
        let first = usize::from(group.first_offset());
        let length = usize::from(group.len());
        let end = first
            .checked_add(length)
            .ok_or(invalid_v3("v3 sparse group range"))?;
        if length == 0 || end > width {
            return Err(invalid_v3("v3 sparse group bounds"));
        }
        for covered in &mut group_covered[first..end] {
            if *covered {
                return Err(invalid_v3("v3 sparse group overlap"));
            }
            *covered = true;
        }
        sparse_group_first_offsets[group_index] = group.first_offset();
        sparse_group_lengths[group_index] = group.len();
    }

    let mut filter_offsets = [0_u8; 4];
    filter_offsets[..filters.len()].copy_from_slice(filters);
    let filter = if filters.is_empty() {
        None
    } else {
        Some(AuditCandidateFilterV3 {
            offsets: filter_offsets,
            len: u8::try_from(filters.len()).map_err(|_| invalid_v3("v3 filter width"))?,
        })
    };
    let mut confirmation_order = [0_u8; 32];
    confirmation_order[..order.len()].copy_from_slice(order);
    let strategy = match recipe.strategy() {
        CountV3Strategy::Incumbent => AuditLoweringStrategyV3::Incumbent,
        CountV3Strategy::SparseRareColumns => AuditLoweringStrategyV3::SparseRareColumns,
        CountV3Strategy::EndpointDense => AuditLoweringStrategyV3::EndpointDense,
        CountV3Strategy::PeriodicRun => AuditLoweringStrategyV3::PeriodicRun,
        CountV3Strategy::DirectExactMask => AuditLoweringStrategyV3::DirectExactMask,
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
        filter_len: u8::try_from(filters.len()).map_err(|_| invalid_v3("v3 filter width"))?,
        confirmation_len: u8::try_from(order.len())
            .map_err(|_| invalid_v3("v3 confirmation width"))?,
        sparse_group_count: u8::try_from(groups.len())
            .map_err(|_| invalid_v3("v3 sparse group width"))?,
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
        AuditLoweringRecipeV3 {
            strategy,
            required_isa: recipe.required_isa(),
            filter,
            confirmation_order,
            confirmation_len: u8::try_from(order.len())
                .map_err(|_| invalid_v3("v3 confirmation width"))?,
        },
        manifest,
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PolicyInstructionV3 {
    Exact(DecodedInstructionV3),
    Branch(PolicyLabelV3),
    BranchCondition {
        condition: ConditionV3,
        target: PolicyLabelV3,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PolicyLabelV3(u32);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PolicyLabelRecordV3 {
    offset: Option<u32>,
    kind: LabelKindV3,
}

struct PolicySinkV3 {
    instructions: ExactVec<PolicyInstructionV3>,
    labels: ExactVec<PolicyLabelRecordV3>,
    prospective: ProspectiveV3,
}

struct ResolvedPolicyV3 {
    instructions: ExactVec<DecodedInstructionV3>,
    labels: ExactVec<CodeLabelV3>,
}

impl PolicySinkV3 {
    fn new(prospective: ProspectiveV3) -> Result<Self, CountAotError> {
        Ok(Self {
            instructions: audit_exact_vec_v3(prospective.code_bytes / 4, prospective)?,
            labels: audit_exact_vec_v3(prospective.labels, prospective)?,
            prospective,
        })
    }

    fn new_label(&mut self, kind: LabelKindV3) -> Result<PolicyLabelV3, CountAotError> {
        let label =
            PolicyLabelV3(u32::try_from(self.labels.len()).map_err(|_| audit_arithmetic_v3())?);
        audit_push_v3(
            &mut self.labels,
            PolicyLabelRecordV3 { offset: None, kind },
            "v3 policy label capacity",
        )?;
        Ok(label)
    }

    fn bind(&mut self, label: PolicyLabelV3) -> Result<(), CountAotError> {
        let offset = u32::try_from(
            self.instructions
                .len()
                .checked_mul(4)
                .ok_or(audit_arithmetic_v3())?,
        )
        .map_err(|_| audit_arithmetic_v3())?;
        let record = self
            .labels
            .get_mut(usize::try_from(label.0).expect("u32 fits usize"))
            .ok_or(invalid_v3("v3 policy label"))?;
        if record.offset.replace(offset).is_some() {
            return Err(invalid_v3("v3 policy label rebound"));
        }
        Ok(())
    }

    fn exact(&mut self, instruction: DecodedInstructionV3) -> Result<(), CountAotError> {
        audit_push_v3(
            &mut self.instructions,
            PolicyInstructionV3::Exact(instruction),
            "v3 policy instruction capacity",
        )
    }

    fn branch(&mut self, target: PolicyLabelV3) -> Result<(), CountAotError> {
        audit_push_v3(
            &mut self.instructions,
            PolicyInstructionV3::Branch(target),
            "v3 policy instruction capacity",
        )
    }

    fn condition(
        &mut self,
        condition: ConditionV3,
        target: PolicyLabelV3,
    ) -> Result<(), CountAotError> {
        audit_push_v3(
            &mut self.instructions,
            PolicyInstructionV3::BranchCondition { condition, target },
            "v3 policy instruction capacity",
        )
    }

    fn resolve(self) -> Result<ResolvedPolicyV3, CountAotError> {
        let mut instructions = audit_exact_vec_v3(self.instructions.len(), self.prospective)?;
        for (index, instruction) in self.instructions.iter().copied().enumerate() {
            let offset = i64::try_from(index.checked_mul(4).ok_or(audit_arithmetic_v3())?)
                .map_err(|_| audit_arithmetic_v3())?;
            let decoded = match instruction {
                PolicyInstructionV3::Exact(instruction) => instruction,
                PolicyInstructionV3::Branch(target) => {
                    let target = self
                        .labels
                        .get(usize::try_from(target.0).expect("u32 fits usize"))
                        .and_then(|record| record.offset)
                        .ok_or(invalid_v3("v3 unresolved policy branch"))?;
                    DecodedInstructionV3::Branch {
                        displacement: i32::try_from(i64::from(target) - offset)
                            .map_err(|_| audit_arithmetic_v3())?,
                    }
                }
                PolicyInstructionV3::BranchCondition { condition, target } => {
                    let target = self
                        .labels
                        .get(usize::try_from(target.0).expect("u32 fits usize"))
                        .and_then(|record| record.offset)
                        .ok_or(invalid_v3("v3 unresolved policy branch"))?;
                    DecodedInstructionV3::BranchCondition {
                        condition,
                        displacement: i32::try_from(i64::from(target) - offset)
                            .map_err(|_| audit_arithmetic_v3())?,
                    }
                }
            };
            audit_push_v3(&mut instructions, decoded, "v3 resolved policy capacity")?;
        }
        let mut labels = audit_exact_vec_v3(self.labels.len(), self.prospective)?;
        for record in self.labels.iter().copied() {
            audit_push_v3(
                &mut labels,
                CodeLabelV3 {
                    offset: record
                        .offset
                        .ok_or(invalid_v3("v3 unresolved policy label"))?,
                    kind: record.kind,
                },
                "v3 resolved policy label capacity",
            )?;
        }
        order_policy_labels_v3(&mut labels)?;
        Ok(ResolvedPolicyV3 {
            instructions,
            labels,
        })
    }
}

fn order_policy_labels_v3(labels: &mut [CodeLabelV3]) -> Result<(), CountAotError> {
    let budget = label_order_work_upper_bound_v3(labels.len())?;
    let mut comparisons = 0_u64;
    let mut moves = 0_u64;
    let mut placements = 0_u64;
    for insertion in 1..labels.len() {
        let key = labels[insertion];
        let mut cursor = insertion;
        while cursor != 0 {
            comparisons = comparisons.checked_add(1).ok_or(audit_arithmetic_v3())?;
            let previous_index = cursor.checked_sub(1).ok_or(audit_arithmetic_v3())?;
            let previous = labels[previous_index];
            if previous <= key {
                break;
            }
            labels[cursor] = previous;
            moves = moves.checked_add(1).ok_or(audit_arithmetic_v3())?;
            cursor = previous_index;
        }
        labels[cursor] = key;
        placements = placements.checked_add(1).ok_or(audit_arithmetic_v3())?;
    }
    if comparisons > budget.comparisons || moves > budget.moves || placements != budget.placements {
        return Err(invalid_v3("v3 policy label order work"));
    }
    Ok(())
}

fn independent_policy_template_v3(
    literal: &[u8],
    recipe: AuditLoweringRecipeV3,
    prospective: ProspectiveV3,
) -> Result<ResolvedPolicyV3, CountAotError> {
    let mut policy = PolicySinkV3::new(prospective)?;
    let entry = policy.new_label(LabelKindV3::Entry)?;
    let done = policy.new_label(LabelKindV3::Success)?;
    policy.bind(entry)?;
    if literal.is_empty() {
        policy_empty_v3(&mut policy, done)?;
    } else {
        match recipe.required_isa {
            CountV3RequiredIsa::Aarch64Neon128 => match literal.len() {
                1 => policy_single_v3(&mut policy, literal[0], done)?,
                _ => {
                    let filter = recipe.filter.ok_or(invalid_v3("v3 policy filter"))?;
                    match recipe.strategy {
                        AuditLoweringStrategyV3::Incumbent => {
                            policy_multi_incumbent_v3(&mut policy, literal, filter, done)?;
                        }
                        AuditLoweringStrategyV3::DirectExactMask => {
                            policy_direct_exact_mask_v3(&mut policy, literal, filter, done)?;
                        }
                        AuditLoweringStrategyV3::SparseRareColumns
                        | AuditLoweringStrategyV3::EndpointDense
                        | AuditLoweringStrategyV3::PeriodicRun => policy_multi_specialized_v3(
                            &mut policy,
                            literal,
                            filter,
                            recipe.confirmation_order(),
                            recipe.strategy,
                            done,
                        )?,
                    }
                }
            },
            CountV3RequiredIsa::Aarch64SveVl16 | CountV3RequiredIsa::Aarch64Sve2Vl16 => {
                let sve2 = recipe.required_isa == CountV3RequiredIsa::Aarch64Sve2Vl16;
                if literal.len() == 1 || recipe.strategy == AuditLoweringStrategyV3::DirectExactMask
                {
                    policy_sve_direct_exact_v3(&mut policy, literal, sve2, done)?;
                } else {
                    let filter = recipe.filter.ok_or(invalid_v3("v3 SVE policy filter"))?;
                    policy_sve_filtered_v3(
                        &mut policy,
                        literal,
                        filter,
                        recipe.confirmation_order(),
                        sve2,
                        done,
                    )?;
                }
            }
        }
    }
    policy.bind(done)?;
    exact_v3(
        &mut policy,
        DecodedInstructionV3::Store64 {
            source: X13,
            base: X2,
            offset: 0,
        },
    )?;
    policy_mov_minimal_v3(&mut policy, X0, 0)?;
    exact_v3(&mut policy, DecodedInstructionV3::Return)?;
    policy.resolve()
}

fn policy_empty_v3(policy: &mut PolicySinkV3, done: PolicyLabelV3) -> Result<(), CountAotError> {
    let overflow = policy.new_label(LabelKindV3::Overflow)?;
    policy_mov_minimal_v3(policy, X10, u64::MAX)?;
    exact_v3(
        policy,
        DecodedInstructionV3::CompareRegister64 {
            left: X1,
            right: X10,
        },
    )?;
    condition_v3(policy, ConditionV3::Equal, overflow)?;
    exact_v3(
        policy,
        DecodedInstructionV3::AddImmediate64 {
            destination: X13,
            source: X1,
            immediate: 1,
        },
    )?;
    branch_v3(policy, done)?;
    policy.bind(overflow)?;
    policy_mov_minimal_v3(policy, X0, 1)?;
    exact_v3(policy, DecodedInstructionV3::Return)
}

#[allow(
    clippy::too_many_lines,
    reason = "the independent single-byte policy mirrors the complete admitted instruction sequence"
)]
fn policy_single_v3(
    policy: &mut PolicySinkV3,
    literal: u8,
    done: PolicyLabelV3,
) -> Result<(), CountAotError> {
    let vector64 = policy.new_label(LabelKindV3::VectorLoop)?;
    let vector16 = policy.new_label(LabelKindV3::VectorLoop)?;
    let tail = policy.new_label(LabelKindV3::ScalarTail)?;
    let miss = policy.new_label(LabelKindV3::Miss)?;
    policy_mov_minimal_v3(policy, X13, 0)?;
    policy_mov_minimal_v3(policy, X3, 0)?;
    policy_mov_minimal_v3(policy, X10, u64::from(literal))?;
    exact_v3(
        policy,
        DecodedInstructionV3::DuplicateByte16 {
            destination: 1,
            source: X10,
        },
    )?;
    policy_mov_minimal_v3(policy, X5, 256)?;
    policy.bind(vector64)?;
    subtract_register64_v3(policy, X6, X1, X3)?;
    compare_immediate64_v3(policy, X6, 64)?;
    condition_v3(policy, ConditionV3::CarryClear, vector16)?;
    add_register64_v3(policy, X15, X0, X3)?;
    for (destination, offset) in [(0, 0), (2, 16), (3, 32), (4, 48)] {
        exact_v3(
            policy,
            DecodedInstructionV3::LoadVector128 {
                destination,
                base: X15,
                offset,
            },
        )?;
    }
    for destination in [0, 2, 3, 4] {
        exact_v3(
            policy,
            DecodedInstructionV3::CompareEqualBytes16 {
                destination,
                left: destination,
                right: 1,
            },
        )?;
    }
    for right in [2, 3, 4] {
        exact_v3(
            policy,
            DecodedInstructionV3::AddBytes16 {
                destination: 0,
                left: 0,
                right,
            },
        )?;
    }
    exact_v3(
        policy,
        DecodedInstructionV3::AddAcrossBytes16 {
            destination: 0,
            source: 0,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::MoveVectorByteTo32 {
            destination: X6,
            source: 0,
        },
    )?;
    subtract_register64_v3(policy, X6, X5, X6)?;
    exact_v3(
        policy,
        DecodedInstructionV3::AndLowBits64 {
            destination: X6,
            source: X6,
            bits: 8,
        },
    )?;
    add_register64_v3(policy, X13, X13, X6)?;
    add_immediate64_v3(policy, X3, X3, 64)?;
    branch_v3(policy, vector64)?;
    policy.bind(vector16)?;
    exact_v3(
        policy,
        DecodedInstructionV3::SubtractRegister64 {
            destination: X6,
            left: X1,
            right: X3,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::CompareImmediate64 {
            register: X6,
            immediate: SIMD_CANDIDATE_STARTS_V3,
        },
    )?;
    condition_v3(policy, ConditionV3::CarryClear, tail)?;
    exact_v3(
        policy,
        DecodedInstructionV3::AddRegister64 {
            destination: X15,
            left: X0,
            right: X3,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::LoadVector128 {
            destination: 0,
            base: X15,
            offset: 0,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::CompareEqualBytes16 {
            destination: 0,
            left: 0,
            right: 1,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::AddAcrossBytes16 {
            destination: 0,
            source: 0,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::MoveVectorByteTo32 {
            destination: X6,
            source: 0,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::SubtractRegister64 {
            destination: X6,
            left: X5,
            right: X6,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::AndLowBits64 {
            destination: X6,
            source: X6,
            bits: 8,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::AddRegister64 {
            destination: X13,
            left: X13,
            right: X6,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::AddImmediate64 {
            destination: X3,
            source: X3,
            immediate: SIMD_CANDIDATE_STARTS_V3,
        },
    )?;
    branch_v3(policy, vector16)?;
    policy.bind(tail)?;
    exact_v3(
        policy,
        DecodedInstructionV3::CompareRegister64 {
            left: X3,
            right: X1,
        },
    )?;
    condition_v3(policy, ConditionV3::CarrySet, done)?;
    exact_v3(
        policy,
        DecodedInstructionV3::LoadByteRegister {
            destination: X6,
            base: X0,
            index: X3,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::CompareRegister32 {
            left: X6,
            right: X10,
        },
    )?;
    condition_v3(policy, ConditionV3::NotEqual, miss)?;
    exact_v3(
        policy,
        DecodedInstructionV3::AddImmediate64 {
            destination: X13,
            source: X13,
            immediate: 1,
        },
    )?;
    policy.bind(miss)?;
    exact_v3(
        policy,
        DecodedInstructionV3::AddImmediate64 {
            destination: X3,
            source: X3,
            immediate: 1,
        },
    )?;
    branch_v3(policy, tail)
}

#[allow(
    clippy::too_many_lines,
    reason = "the independent direct-mask policy spells out both unrolled vector loops and the scalar tail"
)]
fn policy_direct_exact_mask_v3(
    policy: &mut PolicySinkV3,
    literal: &[u8],
    filter: AuditCandidateFilterV3,
    done: PolicyLabelV3,
) -> Result<(), CountAotError> {
    let vector64 = policy.new_label(LabelKindV3::VectorLoop)?;
    let vector16 = policy.new_label(LabelKindV3::VectorLoop)?;
    let tail = policy.new_label(LabelKindV3::ScalarTail)?;
    let tail_miss = policy.new_label(LabelKindV3::Miss)?;
    let width = u16::try_from(literal.len()).expect("bounded width");
    let value_registers = [X10, X11, X12, X14];
    let vector_registers = [2_u8, 3, 16, 17];
    let pointer_registers = [X8, X9, X16, X17];
    let block_masks = [0_u8, 18, 19, 20];

    policy_mov_minimal_v3(policy, X13, 0)?;
    compare_immediate64_v3(policy, X1, width)?;
    condition_v3(policy, ConditionV3::CarryClear, done)?;
    subtract_immediate64_v3(policy, X4, X1, width)?;
    policy_mov_minimal_v3(policy, X3, 0)?;
    for index in 0..usize::from(filter.len) {
        let offset = usize::from(filter.offsets[index]);
        policy_mov_minimal_v3(policy, value_registers[index], u64::from(literal[offset]))?;
        exact_v3(
            policy,
            DecodedInstructionV3::DuplicateByte16 {
                destination: vector_registers[index],
                source: value_registers[index],
            },
        )?;
    }
    policy_mov_minimal_v3(policy, X5, 256)?;

    policy.bind(vector64)?;
    compare_register64_v3(policy, X3, X4)?;
    condition_v3(policy, ConditionV3::Higher, done)?;
    subtract_register64_v3(policy, X6, X4, X3)?;
    compare_immediate64_v3(policy, X6, 63)?;
    condition_v3(policy, ConditionV3::CarryClear, vector16)?;
    add_register64_v3(policy, X15, X0, X3)?;
    for index in 0..usize::from(filter.len) {
        add_immediate64_v3(
            policy,
            pointer_registers[index],
            X15,
            u16::from(filter.offsets[index]),
        )?;
    }
    for (block, mask) in block_masks.into_iter().enumerate() {
        let block_offset = u16::try_from(block * usize::from(SIMD_CANDIDATE_STARTS_V3))
            .expect("four direct-mask blocks");
        for index in 0..usize::from(filter.len) {
            let destination = if index == 0 { mask } else { 1 };
            exact_v3(
                policy,
                DecodedInstructionV3::LoadVector128 {
                    destination,
                    base: pointer_registers[index],
                    offset: block_offset,
                },
            )?;
            exact_v3(
                policy,
                DecodedInstructionV3::CompareEqualBytes16 {
                    destination,
                    left: destination,
                    right: vector_registers[index],
                },
            )?;
            if index != 0 {
                exact_v3(
                    policy,
                    DecodedInstructionV3::AndBytes16 {
                        destination: mask,
                        left: mask,
                        right: destination,
                    },
                )?;
            }
        }
    }
    for right in &block_masks[1..] {
        exact_v3(
            policy,
            DecodedInstructionV3::AddBytes16 {
                destination: 0,
                left: 0,
                right: *right,
            },
        )?;
    }
    exact_v3(
        policy,
        DecodedInstructionV3::AddAcrossBytes16 {
            destination: 0,
            source: 0,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::MoveVectorByteTo32 {
            destination: X6,
            source: 0,
        },
    )?;
    subtract_register64_v3(policy, X6, X5, X6)?;
    exact_v3(
        policy,
        DecodedInstructionV3::AndLowBits64 {
            destination: X6,
            source: X6,
            bits: 8,
        },
    )?;
    add_register64_v3(policy, X13, X13, X6)?;
    add_immediate64_v3(policy, X3, X3, 64)?;
    branch_v3(policy, vector64)?;

    policy.bind(vector16)?;
    compare_register64_v3(policy, X3, X4)?;
    condition_v3(policy, ConditionV3::Higher, done)?;
    subtract_register64_v3(policy, X6, X4, X3)?;
    compare_immediate64_v3(policy, X6, 15)?;
    condition_v3(policy, ConditionV3::CarryClear, tail)?;
    add_register64_v3(policy, X15, X0, X3)?;
    for index in 0..usize::from(filter.len) {
        add_immediate64_v3(
            policy,
            pointer_registers[index],
            X15,
            u16::from(filter.offsets[index]),
        )?;
        let destination = if index == 0 { 0 } else { 1 };
        exact_v3(
            policy,
            DecodedInstructionV3::LoadVector128 {
                destination,
                base: pointer_registers[index],
                offset: 0,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::CompareEqualBytes16 {
                destination,
                left: destination,
                right: vector_registers[index],
            },
        )?;
        if index != 0 {
            exact_v3(
                policy,
                DecodedInstructionV3::AndBytes16 {
                    destination: 0,
                    left: 0,
                    right: destination,
                },
            )?;
        }
    }
    exact_v3(
        policy,
        DecodedInstructionV3::AddAcrossBytes16 {
            destination: 0,
            source: 0,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::MoveVectorByteTo32 {
            destination: X6,
            source: 0,
        },
    )?;
    subtract_register64_v3(policy, X6, X5, X6)?;
    exact_v3(
        policy,
        DecodedInstructionV3::AndLowBits64 {
            destination: X6,
            source: X6,
            bits: 8,
        },
    )?;
    add_register64_v3(policy, X13, X13, X6)?;
    add_immediate64_v3(policy, X3, X3, SIMD_CANDIDATE_STARTS_V3)?;
    branch_v3(policy, vector16)?;

    policy.bind(tail)?;
    compare_register64_v3(policy, X3, X4)?;
    condition_v3(policy, ConditionV3::Higher, done)?;
    add_register64_v3(policy, X15, X0, X3)?;
    for index in 0..usize::from(filter.len) {
        load_byte_v3(policy, X6, X15, u16::from(filter.offsets[index]))?;
        compare_register32_v3(policy, X6, value_registers[index])?;
        condition_v3(policy, ConditionV3::NotEqual, tail_miss)?;
    }
    add_immediate64_v3(policy, X13, X13, 1)?;
    policy.bind(tail_miss)?;
    add_immediate64_v3(policy, X3, X3, 1)?;
    branch_v3(policy, tail)
}

fn policy_sve_compare_bytes_v3(
    policy: &mut PolicySinkV3,
    destination: u8,
    predicate: u8,
    left: u8,
    right: u8,
    sve2: bool,
) -> Result<(), CountAotError> {
    exact_v3(
        policy,
        if sve2 {
            DecodedInstructionV3::Sve2MatchBytes {
                destination,
                predicate,
                left,
                right,
            }
        } else {
            DecodedInstructionV3::SveCompareEqualBytes {
                destination,
                predicate,
                left,
                right,
            }
        },
    )
}

fn policy_sve_load_bytes_mul_vl_v3(
    policy: &mut PolicySinkV3,
    destination: u8,
    predicate: u8,
    base: u8,
    vector_offset: i8,
) -> Result<(), CountAotError> {
    // The architectural zero-offset form has the same bits as ordinary LD1B
    // and therefore retains the decoder's canonical legacy representation.
    exact_v3(
        policy,
        if vector_offset == 0 {
            DecodedInstructionV3::SveLoadBytes {
                destination,
                predicate,
                base,
            }
        } else {
            DecodedInstructionV3::SveLoadBytesMulVl {
                destination,
                predicate,
                base,
                vector_offset,
            }
        },
    )
}

fn policy_scalar_confirmation_sve_v3(
    policy: &mut PolicySinkV3,
    literal: &[u8],
    confirmation_order: &[u8],
    proven_filter_offsets: &[u8],
    candidate_pointer: u8,
    mismatch: PolicyLabelV3,
) -> Result<(), CountAotError> {
    for offset in confirmation_order.iter().copied() {
        if proven_filter_offsets.contains(&offset) {
            continue;
        }
        load_byte_v3(policy, X8, candidate_pointer, u16::from(offset))?;
        compare_immediate32_v3(policy, X8, u16::from(literal[usize::from(offset)]))?;
        condition_v3(policy, ConditionV3::NotEqual, mismatch)?;
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "the independent SVE direct policy mirrors two unrolled vector loops and its exact scalar tail"
)]
fn policy_sve_direct_exact_v3(
    policy: &mut PolicySinkV3,
    literal: &[u8],
    sve2: bool,
    done: PolicyLabelV3,
) -> Result<(), CountAotError> {
    let vector64 = policy.new_label(LabelKindV3::VectorLoop)?;
    let vector16 = policy.new_label(LabelKindV3::VectorLoop)?;
    let tail = policy.new_label(LabelKindV3::ScalarTail)?;
    let tail_miss = policy.new_label(LabelKindV3::Miss)?;
    let width = u16::try_from(literal.len()).expect("bounded width");
    let constants = [2_u8, 3, 16, 17];

    policy_mov_minimal_v3(policy, X13, 0)?;
    compare_immediate64_v3(policy, X1, width)?;
    condition_v3(policy, ConditionV3::CarryClear, done)?;
    subtract_immediate64_v3(policy, X4, X1, width)?;
    policy_mov_minimal_v3(policy, X3, 0)?;
    exact_v3(
        policy,
        DecodedInstructionV3::SvePtrueBytesVl16 { destination: 0 },
    )?;
    for (offset, byte) in literal.iter().copied().enumerate() {
        policy_mov_minimal_v3(policy, X8, u64::from(byte))?;
        exact_v3(
            policy,
            DecodedInstructionV3::SveDuplicateByte {
                destination: constants[offset],
                source: X8,
            },
        )?;
    }

    policy.bind(vector64)?;
    compare_register64_v3(policy, X3, X4)?;
    condition_v3(policy, ConditionV3::Higher, done)?;
    subtract_register64_v3(policy, X6, X4, X3)?;
    compare_immediate64_v3(policy, X6, 63)?;
    condition_v3(policy, ConditionV3::CarryClear, vector16)?;
    add_register64_v3(policy, X15, X0, X3)?;
    for (index, constant) in constants[..literal.len()].iter().copied().enumerate() {
        add_immediate64_v3(
            policy,
            X8,
            X15,
            u16::try_from(index).expect("direct literal width"),
        )?;
        for block in 0_u8..4 {
            policy_sve_load_bytes_mul_vl_v3(
                policy,
                0,
                0,
                X8,
                i8::try_from(block).expect("nonnegative imm4"),
            )?;
            let block_predicate = 4_u8.checked_add(block).expect("p4 through p7");
            let result = if index == 0 { block_predicate } else { 1 };
            policy_sve_compare_bytes_v3(policy, result, 0, 0, constant, sve2)?;
            if index != 0 {
                exact_v3(
                    policy,
                    DecodedInstructionV3::SveAndPredicateBytes {
                        destination: block_predicate,
                        predicate: 0,
                        left: block_predicate,
                        right: result,
                    },
                )?;
            }
        }
    }
    for block_predicate in 4_u8..8 {
        exact_v3(
            policy,
            DecodedInstructionV3::SveCountPredicateBytes {
                destination: X6,
                predicate: 0,
                source: block_predicate,
            },
        )?;
        add_register64_v3(policy, X13, X13, X6)?;
    }
    add_immediate64_v3(policy, X3, X3, 64)?;
    branch_v3(policy, vector64)?;

    policy.bind(vector16)?;
    compare_register64_v3(policy, X3, X4)?;
    condition_v3(policy, ConditionV3::Higher, done)?;
    subtract_register64_v3(policy, X6, X4, X3)?;
    compare_immediate64_v3(policy, X6, 15)?;
    condition_v3(policy, ConditionV3::CarryClear, tail)?;
    add_register64_v3(policy, X15, X0, X3)?;
    for (index, constant) in constants[..literal.len()].iter().copied().enumerate() {
        add_immediate64_v3(
            policy,
            X8,
            X15,
            u16::try_from(index).expect("direct literal width"),
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::SveLoadBytes {
                destination: 0,
                predicate: 0,
                base: X8,
            },
        )?;
        let result = if index == 0 { 1 } else { 2 };
        policy_sve_compare_bytes_v3(policy, result, 0, 0, constant, sve2)?;
        if index != 0 {
            exact_v3(
                policy,
                DecodedInstructionV3::SveAndPredicateBytes {
                    destination: 1,
                    predicate: 0,
                    left: 1,
                    right: result,
                },
            )?;
        }
    }
    exact_v3(
        policy,
        DecodedInstructionV3::SveCountPredicateBytes {
            destination: X6,
            predicate: 0,
            source: 1,
        },
    )?;
    add_register64_v3(policy, X13, X13, X6)?;
    add_immediate64_v3(policy, X3, X3, SIMD_CANDIDATE_STARTS_V3)?;
    branch_v3(policy, vector16)?;

    policy.bind(tail)?;
    compare_register64_v3(policy, X3, X4)?;
    condition_v3(policy, ConditionV3::Higher, done)?;
    add_register64_v3(policy, X15, X0, X3)?;
    for (offset, byte) in literal.iter().copied().enumerate() {
        load_byte_v3(
            policy,
            X6,
            X15,
            u16::try_from(offset).expect("direct literal width"),
        )?;
        compare_immediate32_v3(policy, X6, u16::from(byte))?;
        condition_v3(policy, ConditionV3::NotEqual, tail_miss)?;
    }
    add_immediate64_v3(policy, X13, X13, 1)?;
    policy.bind(tail_miss)?;
    add_immediate64_v3(policy, X3, X3, 1)?;
    branch_v3(policy, tail)
}

#[allow(
    clippy::too_many_lines,
    reason = "the independent SVE filtered policy retains the full predicate-recovery graph"
)]
fn policy_sve_filtered_v3(
    policy: &mut PolicySinkV3,
    literal: &[u8],
    filter: AuditCandidateFilterV3,
    confirmation_order: &[u8],
    sve2: bool,
    done: PolicyLabelV3,
) -> Result<(), CountAotError> {
    let vector = policy.new_label(LabelKindV3::VectorLoop)?;
    let candidate = policy.new_label(LabelKindV3::CandidateLoop)?;
    let candidate_miss = policy.new_label(LabelKindV3::Miss)?;
    let advance = policy.new_label(LabelKindV3::Internal)?;
    let primary_sparse_scan = policy.new_label(LabelKindV3::VectorLoop)?;
    let primary_sparse_hit = policy.new_label(LabelKindV3::Internal)?;
    let primary_sparse_first_half = policy.new_label(LabelKindV3::Internal)?;
    let tail = policy.new_label(LabelKindV3::ScalarTail)?;
    let tail_miss = policy.new_label(LabelKindV3::Miss)?;
    let width = u16::try_from(literal.len()).expect("bounded width");
    let constants = [2_u8, 3, 16, 17];

    policy_mov_minimal_v3(policy, X13, 0)?;
    compare_immediate64_v3(policy, X1, width)?;
    condition_v3(policy, ConditionV3::CarryClear, done)?;
    subtract_immediate64_v3(policy, X4, X1, width)?;
    policy_mov_minimal_v3(policy, X3, 0)?;
    exact_v3(
        policy,
        DecodedInstructionV3::SvePtrueBytesVl16 { destination: 0 },
    )?;
    for (index, offset) in filter.offsets().iter().copied().enumerate() {
        policy_mov_minimal_v3(policy, X8, u64::from(literal[usize::from(offset)]))?;
        exact_v3(
            policy,
            DecodedInstructionV3::SveDuplicateByte {
                destination: constants[index],
                source: X8,
            },
        )?;
    }

    policy.bind(vector)?;
    compare_register64_v3(policy, X3, X4)?;
    condition_v3(policy, ConditionV3::Higher, done)?;
    subtract_register64_v3(policy, X6, X4, X3)?;
    compare_immediate64_v3(policy, X6, SIMD_CANDIDATE_STARTS_V3 - 1)?;
    condition_v3(policy, ConditionV3::CarryClear, tail)?;
    add_register64_v3(policy, X15, X0, X3)?;
    let primary_offset = filter.offsets[0];
    let primary_base = if primary_offset == 0 {
        X15
    } else {
        add_immediate64_v3(policy, X8, X15, u16::from(primary_offset))?;
        X8
    };
    exact_v3(
        policy,
        DecodedInstructionV3::SveLoadBytes {
            destination: 0,
            predicate: 0,
            base: primary_base,
        },
    )?;
    policy_sve_compare_bytes_v3(policy, 1, 0, 0, constants[0], sve2)?;
    exact_v3(
        policy,
        DecodedInstructionV3::SveTestPredicateBytes {
            predicate: 0,
            tested: 1,
        },
    )?;
    condition_v3(policy, ConditionV3::Equal, primary_sparse_scan)?;
    for (index, offset) in filter.offsets()[1..].iter().copied().enumerate() {
        let base = if offset == 0 {
            X15
        } else {
            add_immediate64_v3(policy, X8, X15, u16::from(offset))?;
            X8
        };
        exact_v3(
            policy,
            DecodedInstructionV3::SveLoadBytes {
                destination: 0,
                predicate: 0,
                base,
            },
        )?;
        policy_sve_compare_bytes_v3(policy, 2, 0, 0, constants[index + 1], sve2)?;
        exact_v3(
            policy,
            DecodedInstructionV3::SveAndPredicateBytes {
                destination: 1,
                predicate: 0,
                left: 1,
                right: 2,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::SveTestPredicateBytes {
                predicate: 0,
                tested: 1,
            },
        )?;
        condition_v3(policy, ConditionV3::Equal, advance)?;
    }

    policy.bind(candidate)?;
    exact_v3(
        policy,
        DecodedInstructionV3::SveBreakBeforeBytes {
            destination: 3,
            predicate: 0,
            source: 1,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::SveCountPredicateBytes {
            destination: X7,
            predicate: 0,
            source: 3,
        },
    )?;
    add_register64_v3(policy, X5, X3, X7)?;
    add_register64_v3(policy, X15, X0, X5)?;
    policy_scalar_confirmation_sve_v3(
        policy,
        literal,
        confirmation_order,
        filter.offsets(),
        X15,
        candidate_miss,
    )?;
    add_immediate64_v3(policy, X13, X13, 1)?;
    add_immediate64_v3(policy, X3, X5, width)?;
    branch_v3(policy, vector)?;

    policy.bind(candidate_miss)?;
    exact_v3(
        policy,
        DecodedInstructionV3::SveBreakAfterBytes {
            destination: 3,
            predicate: 0,
            source: 1,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::SveBitClearPredicateBytesSetFlags {
            destination: 1,
            predicate: 0,
            left: 1,
            right: 3,
        },
    )?;
    condition_v3(policy, ConditionV3::NotEqual, candidate)?;

    policy.bind(advance)?;
    add_immediate64_v3(policy, X3, X3, SIMD_CANDIDATE_STARTS_V3)?;
    branch_v3(policy, vector)?;

    policy.bind(primary_sparse_scan)?;
    add_immediate64_v3(policy, X3, X3, SIMD_CANDIDATE_STARTS_V3)?;
    compare_register64_v3(policy, X3, X4)?;
    condition_v3(policy, ConditionV3::Higher, done)?;
    subtract_register64_v3(policy, X6, X4, X3)?;
    compare_immediate64_v3(policy, X6, SPARSE_SCAN_STARTS_V3 - 1)?;
    condition_v3(policy, ConditionV3::CarryClear, vector)?;
    add_register64_v3(policy, X15, X0, X3)?;
    let primary_base = if primary_offset == 0 {
        X15
    } else {
        add_immediate64_v3(policy, X8, X15, u16::from(primary_offset))?;
        X8
    };
    for block in 0_u8..8 {
        let block_predicate = 4_u8.checked_add(block).expect("p4 through p11");
        policy_sve_load_bytes_mul_vl_v3(
            policy,
            0,
            0,
            primary_base,
            i8::try_from(block).expect("nonnegative imm4"),
        )?;
        policy_sve_compare_bytes_v3(policy, block_predicate, 0, 0, constants[0], sve2)?;
    }
    for (destination, left, right) in [(12, 4, 5), (13, 6, 7), (14, 8, 9), (15, 10, 11)] {
        exact_v3(
            policy,
            DecodedInstructionV3::SveOrPredicateBytes {
                destination,
                predicate: 0,
                left,
                right,
            },
        )?;
    }
    exact_v3(
        policy,
        DecodedInstructionV3::SveOrPredicateBytes {
            destination: 1,
            predicate: 0,
            left: 12,
            right: 13,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::SveOrPredicateBytes {
            destination: 2,
            predicate: 0,
            left: 14,
            right: 15,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::SveOrPredicateBytes {
            destination: 1,
            predicate: 0,
            left: 1,
            right: 2,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::SveTestPredicateBytes {
            predicate: 0,
            tested: 1,
        },
    )?;
    condition_v3(policy, ConditionV3::NotEqual, primary_sparse_hit)?;
    add_immediate64_v3(
        policy,
        X3,
        X3,
        SPARSE_SCAN_STARTS_V3 - SIMD_CANDIDATE_STARTS_V3,
    )?;
    branch_v3(policy, primary_sparse_scan)?;

    policy.bind(primary_sparse_hit)?;
    exact_v3(
        policy,
        DecodedInstructionV3::SveOrPredicateBytes {
            destination: 1,
            predicate: 0,
            left: 12,
            right: 13,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::SveTestPredicateBytes {
            predicate: 0,
            tested: 1,
        },
    )?;
    condition_v3(policy, ConditionV3::NotEqual, primary_sparse_first_half)?;
    add_immediate64_v3(policy, X3, X3, SIMD_CANDIDATE_STARTS_V3 * 4)?;
    exact_v3(
        policy,
        DecodedInstructionV3::SveTestPredicateBytes {
            predicate: 0,
            tested: 14,
        },
    )?;
    condition_v3(policy, ConditionV3::NotEqual, vector)?;
    add_immediate64_v3(policy, X3, X3, SIMD_CANDIDATE_STARTS_V3 * 2)?;
    branch_v3(policy, vector)?;

    policy.bind(primary_sparse_first_half)?;
    exact_v3(
        policy,
        DecodedInstructionV3::SveTestPredicateBytes {
            predicate: 0,
            tested: 12,
        },
    )?;
    condition_v3(policy, ConditionV3::NotEqual, vector)?;
    add_immediate64_v3(policy, X3, X3, SIMD_CANDIDATE_STARTS_V3 * 2)?;
    branch_v3(policy, vector)?;

    policy.bind(tail)?;
    compare_register64_v3(policy, X3, X4)?;
    condition_v3(policy, ConditionV3::Higher, done)?;
    add_register64_v3(policy, X15, X0, X3)?;
    policy_scalar_confirmation_sve_v3(policy, literal, confirmation_order, &[], X15, tail_miss)?;
    add_immediate64_v3(policy, X13, X13, 1)?;
    add_immediate64_v3(policy, X3, X3, width)?;
    branch_v3(policy, tail)?;
    policy.bind(tail_miss)?;
    add_immediate64_v3(policy, X3, X3, 1)?;
    branch_v3(policy, tail)
}

#[allow(
    clippy::too_many_lines,
    reason = "the independent full-template policy mirrors semantics, not emitter code"
)]
fn policy_multi_incumbent_v3(
    policy: &mut PolicySinkV3,
    literal: &[u8],
    filter: AuditCandidateFilterV3,
    done: PolicyLabelV3,
) -> Result<(), CountAotError> {
    let vector = policy.new_label(LabelKindV3::VectorLoop)?;
    let sparse_scan = policy.new_label(LabelKindV3::VectorLoop)?;
    let sparse_hit = policy.new_label(LabelKindV3::Internal)?;
    let sparse_first_half = policy.new_label(LabelKindV3::Internal)?;
    let pair_absent = policy.new_label(LabelKindV3::Internal)?;
    let pair_single = policy.new_label(LabelKindV3::Internal)?;
    let pair_dense = policy.new_label(LabelKindV3::Internal)?;
    let candidate = policy.new_label(LabelKindV3::CandidateLoop)?;
    let candidate_miss = policy.new_label(LabelKindV3::Miss)?;
    let block_advance = policy.new_label(LabelKindV3::Internal)?;
    let dense_scan = policy.new_label(LabelKindV3::VectorLoop)?;
    let dense_absent = policy.new_label(LabelKindV3::Internal)?;
    let match_run = policy.new_label(LabelKindV3::CandidateLoop)?;
    let match_run_miss = policy.new_label(LabelKindV3::Miss)?;
    let scalar = policy.new_label(LabelKindV3::ScalarTail)?;
    let scalar_miss = policy.new_label(LabelKindV3::Miss)?;
    let width = u16::try_from(literal.len()).expect("bounded width");
    let primary = u16::from(filter.offsets[0]);
    let secondary = u16::from(filter.offsets[1]);
    policy_mov_minimal_v3(policy, X13, 0)?;
    compare_immediate64_v3(policy, X1, width)?;
    condition_v3(policy, ConditionV3::CarryClear, done)?;
    subtract_immediate64_v3(policy, X4, X1, width)?;
    policy_mov_minimal_v3(policy, X3, 0)?;
    policy_mov_minimal_v3(
        policy,
        X10,
        u64::from(literal[usize::from(filter.offsets[0])]),
    )?;
    policy_mov_minimal_v3(
        policy,
        X11,
        u64::from(literal[usize::from(filter.offsets[1])]),
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::DuplicateByte16 {
            destination: 2,
            source: X10,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::DuplicateByte16 {
            destination: 3,
            source: X11,
        },
    )?;
    if filter.len >= 3 {
        policy_mov_minimal_v3(
            policy,
            X12,
            u64::from(literal[usize::from(filter.offsets[2])]),
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::DuplicateByte16 {
                destination: 16,
                source: X12,
            },
        )?;
    }
    if filter.len >= 4 {
        policy_mov_minimal_v3(
            policy,
            X14,
            u64::from(literal[usize::from(filter.offsets[3])]),
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::DuplicateByte16 {
                destination: 17,
                source: X14,
            },
        )?;
    }
    policy_mov_minimal_v3(policy, X17, SPARSE_NIBBLE_BITS_V3)?;
    policy_mov_minimal_v3(policy, X8, u64::from(literal[0]))?;
    exact_v3(
        policy,
        DecodedInstructionV3::DuplicateByte16 {
            destination: 19,
            source: X8,
        },
    )?;
    policy_mov_minimal_v3(
        policy,
        X8,
        u64::from(literal[literal.len().checked_sub(1).expect("nonempty literal")]),
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::DuplicateByte16 {
            destination: 20,
            source: X8,
        },
    )?;
    for (chunk_index, chunk) in literal.chunks_exact(16).enumerate() {
        let mut low = [0_u8; 8];
        let mut high = [0_u8; 8];
        low.copy_from_slice(&chunk[..8]);
        high.copy_from_slice(&chunk[8..]);
        let vector = u8::try_from(21 + chunk_index).expect("at most v22");
        policy_mov_minimal_v3(policy, X8, u64::from_le_bytes(low))?;
        exact_v3(
            policy,
            DecodedInstructionV3::Move64ToVectorDouble {
                destination: vector,
                source: X8,
            },
        )?;
        policy_mov_minimal_v3(policy, X8, u64::from_le_bytes(high))?;
        exact_v3(
            policy,
            DecodedInstructionV3::Insert64ToVectorDoubleLane1 {
                destination: vector,
                source: X8,
            },
        )?;
    }
    let full_vector_bytes = literal.len() / 16 * 16;
    for (tail_index, chunk) in literal[full_vector_bytes..].chunks_exact(8).enumerate() {
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(chunk);
        policy_mov_minimal_v3(policy, X8, u64::from_le_bytes(bytes))?;
        let global_chunk = full_vector_bytes / 8 + tail_index;
        exact_v3(
            policy,
            DecodedInstructionV3::Move64ToVectorDouble {
                destination: u8::try_from(4 + global_chunk).expect("at most v7"),
                source: X8,
            },
        )?;
    }
    if let Some(suffix_offset) = policy_overlapping_suffix_offset_v3(literal.len()) {
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(&literal[suffix_offset..]);
        policy_mov_minimal_v3(policy, X8, u64::from_le_bytes(bytes))?;
        exact_v3(
            policy,
            DecodedInstructionV3::Move64ToVectorDouble {
                destination: OVERLAPPING_SUFFIX_VECTOR_V3,
                source: X8,
            },
        )?;
    }
    policy.bind(vector)?;
    compare_register64_v3(policy, X3, X4)?;
    condition_v3(policy, ConditionV3::Higher, done)?;
    subtract_register64_v3(policy, X5, X4, X3)?;
    compare_immediate64_v3(policy, X5, 15)?;
    condition_v3(policy, ConditionV3::CarryClear, scalar)?;
    add_register64_v3(policy, X15, X0, X3)?;
    add_immediate64_v3(policy, X8, X15, primary)?;
    exact_v3(
        policy,
        DecodedInstructionV3::LoadVector128 {
            destination: 0,
            base: X8,
            offset: 0,
        },
    )?;
    add_immediate64_v3(policy, X9, X15, secondary)?;
    exact_v3(
        policy,
        DecodedInstructionV3::LoadVector128 {
            destination: 1,
            base: X9,
            offset: 0,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::CompareEqualBytes16 {
            destination: 0,
            left: 0,
            right: 2,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::CompareEqualBytes16 {
            destination: 1,
            left: 1,
            right: 3,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::AndBytes16 {
            destination: 0,
            left: 0,
            right: 1,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::AddAcrossBytes16 {
            destination: 1,
            source: 0,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::MoveVectorByteTo32 {
            destination: X8,
            source: 1,
        },
    )?;
    compare_immediate64_v3(policy, X8, 0)?;
    condition_v3(policy, ConditionV3::Equal, pair_absent)?;
    compare_immediate64_v3(policy, X8, 255)?;
    condition_v3(policy, ConditionV3::NotEqual, pair_dense)?;

    policy.bind(pair_single)?;
    if filter.len >= 3 {
        add_immediate64_v3(policy, X8, X15, u16::from(filter.offsets[2]))?;
        exact_v3(
            policy,
            DecodedInstructionV3::LoadVector128 {
                destination: 1,
                base: X8,
                offset: 0,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::CompareEqualBytes16 {
                destination: 1,
                left: 1,
                right: 16,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::AndBytes16 {
                destination: 0,
                left: 0,
                right: 1,
            },
        )?;
    }
    if filter.len >= 4 {
        exact_v3(
            policy,
            DecodedInstructionV3::UnsignedMaxAcrossBytes16 {
                destination: 1,
                source: 0,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::MoveVectorByteTo32 {
                destination: X8,
                source: 1,
            },
        )?;
        compare_immediate64_v3(policy, X8, 0)?;
        condition_v3(policy, ConditionV3::Equal, block_advance)?;
        add_immediate64_v3(policy, X8, X15, u16::from(filter.offsets[3]))?;
        exact_v3(
            policy,
            DecodedInstructionV3::LoadVector128 {
                destination: 1,
                base: X8,
                offset: 0,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::CompareEqualBytes16 {
                destination: 1,
                left: 1,
                right: 17,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::AndBytes16 {
                destination: 0,
                left: 0,
                right: 1,
            },
        )?;
    }
    exact_v3(
        policy,
        DecodedInstructionV3::ShrinkNarrowBytesFromHalfwords {
            destination: 0,
            source: 0,
            shift: 4,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::MoveVectorDoubleTo64 {
            destination: X6,
            source: 0,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::AndRegister64 {
            destination: X6,
            left: X6,
            right: X17,
        },
    )?;
    compare_immediate64_v3(policy, X6, 0)?;
    condition_v3(policy, ConditionV3::Equal, block_advance)?;
    branch_v3(policy, candidate)?;

    policy.bind(pair_dense)?;
    exact_v3(
        policy,
        DecodedInstructionV3::OrBytes16 {
            destination: 18,
            left: 0,
            right: 0,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::LoadVector128 {
            destination: 0,
            base: X15,
            offset: 0,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::CompareEqualBytes16 {
            destination: 0,
            left: 0,
            right: 19,
        },
    )?;
    add_immediate64_v3(
        policy,
        X8,
        X15,
        u16::try_from(literal.len() - 1).expect("bounded last offset"),
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::LoadVector128 {
            destination: 1,
            base: X8,
            offset: 0,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::CompareEqualBytes16 {
            destination: 1,
            left: 1,
            right: 20,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::AndBytes16 {
            destination: 0,
            left: 0,
            right: 1,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::AndBytes16 {
            destination: 0,
            left: 0,
            right: 18,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::ShrinkNarrowBytesFromHalfwords {
            destination: 0,
            source: 0,
            shift: 4,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::MoveVectorDoubleTo64 {
            destination: X6,
            source: 0,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::AndRegister64 {
            destination: X6,
            left: X6,
            right: X17,
        },
    )?;
    compare_immediate64_v3(policy, X6, 0)?;
    condition_v3(policy, ConditionV3::Equal, dense_absent)?;
    branch_v3(policy, candidate)?;

    policy.bind(candidate)?;
    exact_v3(
        policy,
        DecodedInstructionV3::ReverseBits64 {
            destination: X7,
            source: X6,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::CountLeadingZeros64 {
            destination: X7,
            source: X7,
        },
    )?;
    subtract_immediate64_v3(policy, X16, X6, 1)?;
    exact_v3(
        policy,
        DecodedInstructionV3::AndRegister64 {
            destination: X6,
            left: X6,
            right: X16,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::LogicalShiftRight64 {
            destination: X7,
            source: X7,
            shift: 2,
        },
    )?;
    add_register64_v3(policy, X5, X3, X7)?;
    add_register64_v3(policy, X15, X0, X5)?;
    policy_confirmation_v3(policy, literal, filter.offsets(), X15, candidate_miss)?;
    add_immediate64_v3(policy, X13, X13, 1)?;
    add_immediate64_v3(policy, X3, X5, width)?;
    branch_v3(policy, match_run)?;
    policy.bind(candidate_miss)?;
    compare_immediate64_v3(policy, X6, 0)?;
    condition_v3(policy, ConditionV3::NotEqual, candidate)?;
    policy.bind(block_advance)?;
    add_immediate64_v3(policy, X3, X3, SIMD_CANDIDATE_STARTS_V3)?;
    branch_v3(policy, vector)?;

    policy.bind(match_run)?;
    compare_register64_v3(policy, X3, X4)?;
    condition_v3(policy, ConditionV3::Higher, done)?;
    add_register64_v3(policy, X15, X0, X3)?;
    policy_confirmation_v3(policy, literal, &[], X15, match_run_miss)?;
    add_immediate64_v3(policy, X13, X13, 1)?;
    add_immediate64_v3(policy, X3, X3, width)?;
    branch_v3(policy, match_run)?;
    policy.bind(match_run_miss)?;
    add_immediate64_v3(policy, X3, X3, 1)?;
    branch_v3(policy, vector)?;

    policy.bind(dense_absent)?;
    add_immediate64_v3(policy, X3, X3, SIMD_CANDIDATE_STARTS_V3)?;
    branch_v3(policy, dense_scan)?;
    policy.bind(dense_scan)?;
    compare_register64_v3(policy, X3, X4)?;
    condition_v3(policy, ConditionV3::Higher, done)?;
    subtract_register64_v3(policy, X5, X4, X3)?;
    compare_immediate64_v3(policy, X5, SPARSE_SCAN_STARTS_V3 - 1)?;
    condition_v3(policy, ConditionV3::CarryClear, vector)?;
    add_register64_v3(policy, X15, X0, X3)?;
    add_immediate64_v3(
        policy,
        X9,
        X15,
        u16::try_from(literal.len() - 1).expect("bounded last offset"),
    )?;
    for block in 0..SPARSE_SCAN_BLOCKS_V3 {
        let offset = block
            .checked_mul(SIMD_CANDIDATE_STARTS_V3)
            .ok_or(audit_arithmetic_v3())?;
        exact_v3(
            policy,
            DecodedInstructionV3::LoadVector128 {
                destination: 0,
                base: X15,
                offset,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::LoadVector128 {
                destination: 1,
                base: X9,
                offset,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::CompareEqualBytes16 {
                destination: 0,
                left: 0,
                right: 19,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::CompareEqualBytes16 {
                destination: 1,
                left: 1,
                right: 20,
            },
        )?;
        if block == 0 {
            exact_v3(
                policy,
                DecodedInstructionV3::AndBytes16 {
                    destination: 18,
                    left: 0,
                    right: 1,
                },
            )?;
        } else {
            exact_v3(
                policy,
                DecodedInstructionV3::AndBytes16 {
                    destination: 0,
                    left: 0,
                    right: 1,
                },
            )?;
            exact_v3(
                policy,
                DecodedInstructionV3::OrBytes16 {
                    destination: 18,
                    left: 18,
                    right: 0,
                },
            )?;
        }
    }
    exact_v3(
        policy,
        DecodedInstructionV3::UnsignedMaxAcrossBytes16 {
            destination: 1,
            source: 18,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::MoveVectorByteTo32 {
            destination: X8,
            source: 1,
        },
    )?;
    compare_immediate64_v3(policy, X8, 0)?;
    condition_v3(policy, ConditionV3::NotEqual, vector)?;
    add_immediate64_v3(policy, X3, X3, SPARSE_SCAN_STARTS_V3)?;
    branch_v3(policy, dense_scan)?;

    policy.bind(pair_absent)?;
    add_immediate64_v3(policy, X3, X3, SIMD_CANDIDATE_STARTS_V3)?;
    branch_v3(policy, sparse_scan)?;
    policy.bind(sparse_scan)?;
    compare_register64_v3(policy, X3, X4)?;
    condition_v3(policy, ConditionV3::Higher, done)?;
    subtract_register64_v3(policy, X5, X4, X3)?;
    compare_immediate64_v3(policy, X5, SPARSE_SCAN_STARTS_V3 - 1)?;
    condition_v3(policy, ConditionV3::CarryClear, vector)?;
    add_register64_v3(policy, X15, X0, X3)?;
    add_immediate64_v3(policy, X8, X15, primary)?;
    add_immediate64_v3(policy, X9, X15, secondary)?;
    for block in 0..SPARSE_SCAN_BLOCKS_V3 {
        let offset = block
            .checked_mul(SIMD_CANDIDATE_STARTS_V3)
            .ok_or(audit_arithmetic_v3())?;
        exact_v3(
            policy,
            DecodedInstructionV3::LoadVector128 {
                destination: 0,
                base: X8,
                offset,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::LoadVector128 {
                destination: 1,
                base: X9,
                offset,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::CompareEqualBytes16 {
                destination: 0,
                left: 0,
                right: 2,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::CompareEqualBytes16 {
                destination: 1,
                left: 1,
                right: 3,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::AndBytes16 {
                destination: u8::try_from(u16::from(SPARSE_BLOCK_MASK_BASE_V3) + block)
                    .expect("eight caller-saved sparse block masks"),
                left: 0,
                right: 1,
            },
        )?;
    }
    exact_v3(
        policy,
        DecodedInstructionV3::OrBytes16 {
            destination: SPARSE_PAIR_01_MASK_V3,
            left: SPARSE_BLOCK_MASK_BASE_V3,
            right: SPARSE_BLOCK_MASK_BASE_V3 + 1,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::OrBytes16 {
            destination: SPARSE_PAIR_23_MASK_V3,
            left: SPARSE_BLOCK_MASK_BASE_V3 + 2,
            right: SPARSE_BLOCK_MASK_BASE_V3 + 3,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::OrBytes16 {
            destination: SPARSE_PAIR_45_MASK_V3,
            left: SPARSE_BLOCK_MASK_BASE_V3 + 4,
            right: SPARSE_BLOCK_MASK_BASE_V3 + 5,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::OrBytes16 {
            destination: SPARSE_PAIR_67_MASK_V3,
            left: SPARSE_BLOCK_MASK_BASE_V3 + 6,
            right: SPARSE_BLOCK_MASK_BASE_V3 + 7,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::OrBytes16 {
            destination: 1,
            left: SPARSE_PAIR_01_MASK_V3,
            right: SPARSE_PAIR_23_MASK_V3,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::OrBytes16 {
            destination: 0,
            left: SPARSE_PAIR_45_MASK_V3,
            right: SPARSE_PAIR_67_MASK_V3,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::OrBytes16 {
            destination: 1,
            left: 1,
            right: 0,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::UnsignedMaxAcrossBytes16 {
            destination: 1,
            source: 1,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::MoveVectorByteTo32 {
            destination: X8,
            source: 1,
        },
    )?;
    compare_immediate64_v3(policy, X8, 0)?;
    condition_v3(policy, ConditionV3::NotEqual, sparse_hit)?;
    add_immediate64_v3(policy, X3, X3, SPARSE_SCAN_STARTS_V3)?;
    branch_v3(policy, sparse_scan)?;

    policy.bind(sparse_hit)?;
    exact_v3(
        policy,
        DecodedInstructionV3::OrBytes16 {
            destination: 1,
            left: SPARSE_PAIR_01_MASK_V3,
            right: SPARSE_PAIR_23_MASK_V3,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::UnsignedMaxAcrossBytes16 {
            destination: 1,
            source: 1,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::MoveVectorByteTo32 {
            destination: X8,
            source: 1,
        },
    )?;
    compare_immediate64_v3(policy, X8, 0)?;
    condition_v3(policy, ConditionV3::NotEqual, sparse_first_half)?;
    add_immediate64_v3(policy, X3, X3, SIMD_CANDIDATE_STARTS_V3 * 4)?;
    exact_v3(
        policy,
        DecodedInstructionV3::UnsignedMaxAcrossBytes16 {
            destination: 1,
            source: SPARSE_PAIR_45_MASK_V3,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::MoveVectorByteTo32 {
            destination: X8,
            source: 1,
        },
    )?;
    compare_immediate64_v3(policy, X8, 0)?;
    condition_v3(policy, ConditionV3::NotEqual, vector)?;
    add_immediate64_v3(policy, X3, X3, SIMD_CANDIDATE_STARTS_V3 * 2)?;
    branch_v3(policy, vector)?;

    policy.bind(sparse_first_half)?;
    exact_v3(
        policy,
        DecodedInstructionV3::UnsignedMaxAcrossBytes16 {
            destination: 1,
            source: SPARSE_PAIR_01_MASK_V3,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::MoveVectorByteTo32 {
            destination: X8,
            source: 1,
        },
    )?;
    compare_immediate64_v3(policy, X8, 0)?;
    condition_v3(policy, ConditionV3::NotEqual, vector)?;
    add_immediate64_v3(policy, X3, X3, SIMD_CANDIDATE_STARTS_V3 * 2)?;
    branch_v3(policy, vector)?;

    policy.bind(scalar)?;
    compare_register64_v3(policy, X3, X4)?;
    condition_v3(policy, ConditionV3::Higher, done)?;
    add_register64_v3(policy, X15, X0, X3)?;
    load_byte_v3(policy, X8, X15, primary)?;
    compare_register32_v3(policy, X8, X10)?;
    condition_v3(policy, ConditionV3::NotEqual, scalar_miss)?;
    load_byte_v3(policy, X8, X15, secondary)?;
    compare_register32_v3(policy, X8, X11)?;
    condition_v3(policy, ConditionV3::NotEqual, scalar_miss)?;
    if filter.len >= 3 {
        load_byte_v3(policy, X8, X15, u16::from(filter.offsets[2]))?;
        compare_register32_v3(policy, X8, X12)?;
        condition_v3(policy, ConditionV3::NotEqual, scalar_miss)?;
    }
    if filter.len >= 4 {
        load_byte_v3(policy, X8, X15, u16::from(filter.offsets[3]))?;
        compare_register32_v3(policy, X8, X14)?;
        condition_v3(policy, ConditionV3::NotEqual, scalar_miss)?;
    }
    policy_confirmation_v3(policy, literal, filter.offsets(), X15, scalar_miss)?;
    add_immediate64_v3(policy, X13, X13, 1)?;
    add_immediate64_v3(policy, X3, X3, width)?;
    branch_v3(policy, match_run)?;
    policy.bind(scalar_miss)?;
    add_immediate64_v3(policy, X3, X3, 1)?;
    branch_v3(policy, scalar)
}

#[allow(
    clippy::too_many_lines,
    reason = "the independent recipe policy spells out the complete reviewed instruction graph"
)]
fn policy_multi_specialized_v3(
    policy: &mut PolicySinkV3,
    literal: &[u8],
    filter: AuditCandidateFilterV3,
    confirmation_order: &[u8],
    strategy: AuditLoweringStrategyV3,
    done: PolicyLabelV3,
) -> Result<(), CountAotError> {
    let vector = policy.new_label(LabelKindV3::VectorLoop)?;
    let candidate = policy.new_label(LabelKindV3::CandidateLoop)?;
    let candidate_miss = policy.new_label(LabelKindV3::Miss)?;
    let block_advance = policy.new_label(LabelKindV3::Internal)?;
    let primary_sparse_scan = policy.new_label(LabelKindV3::VectorLoop)?;
    let sparse_scan = policy.new_label(LabelKindV3::VectorLoop)?;
    let sparse_hit = policy.new_label(LabelKindV3::Internal)?;
    let sparse_first_half = policy.new_label(LabelKindV3::Internal)?;
    let wide_batch = if strategy != AuditLoweringStrategyV3::PeriodicRun {
        Some(policy.new_label(LabelKindV3::VectorLoop)?)
    } else {
        None
    };
    let wide_batch_empty = if wide_batch.is_some() {
        Some(policy.new_label(LabelKindV3::Internal)?)
    } else {
        None
    };
    let wide_first_half = if wide_batch.is_some() {
        Some(policy.new_label(LabelKindV3::Internal)?)
    } else {
        None
    };
    let wide_first_pair = if wide_batch.is_some() {
        Some(policy.new_label(LabelKindV3::Internal)?)
    } else {
        None
    };
    let wide_first_block = if wide_batch.is_some() {
        Some(policy.new_label(LabelKindV3::Internal)?)
    } else {
        None
    };
    let last_offset = u8::try_from(literal.len() - 1).expect("bounded nonempty literal");
    let semantic_secondary_offset = if filter.offsets[0] == last_offset {
        0
    } else {
        last_offset
    };
    let sparse_prefix_escalation = if filter.offsets[0] != 0 && filter.offsets[0] != last_offset {
        Some(policy.new_label(LabelKindV3::Internal)?)
    } else {
        None
    };
    let match_run = if strategy == AuditLoweringStrategyV3::PeriodicRun {
        Some(policy.new_label(LabelKindV3::CandidateLoop)?)
    } else {
        None
    };
    let match_run_miss = if strategy == AuditLoweringStrategyV3::PeriodicRun {
        Some(policy.new_label(LabelKindV3::Miss)?)
    } else {
        None
    };
    let scalar = policy.new_label(LabelKindV3::ScalarTail)?;
    let scalar_miss = policy.new_label(LabelKindV3::Miss)?;
    let width = u16::try_from(literal.len()).expect("bounded width");
    let value_registers = [X10, X11, X12, X14];
    let vector_registers = [2_u8, 3, 16, 17];

    policy_mov_minimal_v3(policy, X13, 0)?;
    compare_immediate64_v3(policy, X1, width)?;
    condition_v3(policy, ConditionV3::CarryClear, done)?;
    subtract_immediate64_v3(policy, X4, X1, width)?;
    policy_mov_minimal_v3(policy, X3, 0)?;
    for index in 0..usize::from(filter.len) {
        policy_mov_minimal_v3(
            policy,
            value_registers[index],
            u64::from(literal[usize::from(filter.offsets[index])]),
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::DuplicateByte16 {
                destination: vector_registers[index],
                source: value_registers[index],
            },
        )?;
    }
    policy_mov_minimal_v3(policy, X17, SPARSE_NIBBLE_BITS_V3)?;
    policy_mov_minimal_v3(
        policy,
        X8,
        u64::from(literal[usize::from(semantic_secondary_offset)]),
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::DuplicateByte16 {
            destination: SEMANTIC_SECONDARY_VECTOR_V3,
            source: X8,
        },
    )?;
    if sparse_prefix_escalation.is_some() {
        policy_mov_minimal_v3(policy, X8, u64::from(literal[0]))?;
        exact_v3(
            policy,
            DecodedInstructionV3::DuplicateByte16 {
                destination: SEMANTIC_PREFIX_VECTOR_V3,
                source: X8,
            },
        )?;
    }
    for (chunk_index, chunk) in literal.chunks_exact(16).enumerate() {
        let mut low = [0_u8; 8];
        let mut high = [0_u8; 8];
        low.copy_from_slice(&chunk[..8]);
        high.copy_from_slice(&chunk[8..]);
        let vector_register =
            u8::try_from(21_usize + chunk_index).expect("at most two full vectors");
        policy_mov_minimal_v3(policy, X8, u64::from_le_bytes(low))?;
        exact_v3(
            policy,
            DecodedInstructionV3::Move64ToVectorDouble {
                destination: vector_register,
                source: X8,
            },
        )?;
        policy_mov_minimal_v3(policy, X8, u64::from_le_bytes(high))?;
        exact_v3(
            policy,
            DecodedInstructionV3::Insert64ToVectorDoubleLane1 {
                destination: vector_register,
                source: X8,
            },
        )?;
    }
    let full_vector_bytes = literal.len() / 16 * 16;
    for (tail_index, chunk) in literal[full_vector_bytes..].chunks_exact(8).enumerate() {
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(chunk);
        policy_mov_minimal_v3(policy, X8, u64::from_le_bytes(bytes))?;
        exact_v3(
            policy,
            DecodedInstructionV3::Move64ToVectorDouble {
                destination: u8::try_from(4_usize + full_vector_bytes / 8 + tail_index)
                    .expect("at most four double chunks"),
                source: X8,
            },
        )?;
    }
    if let Some(suffix_offset) = policy_overlapping_suffix_offset_v3(literal.len()) {
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(&literal[suffix_offset..]);
        policy_mov_minimal_v3(policy, X8, u64::from_le_bytes(bytes))?;
        exact_v3(
            policy,
            DecodedInstructionV3::Move64ToVectorDouble {
                destination: OVERLAPPING_SUFFIX_VECTOR_V3,
                source: X8,
            },
        )?;
    }

    policy.bind(vector)?;
    compare_register64_v3(policy, X3, X4)?;
    condition_v3(policy, ConditionV3::Higher, done)?;
    subtract_register64_v3(policy, X5, X4, X3)?;
    if let Some(wide_batch) = wide_batch {
        compare_immediate64_v3(policy, X5, SPARSE_SCAN_STARTS_V3 - 1)?;
        condition_v3(policy, ConditionV3::CarrySet, wide_batch)?;
    }
    compare_immediate64_v3(policy, X5, SIMD_CANDIDATE_STARTS_V3 - 1)?;
    condition_v3(policy, ConditionV3::CarryClear, scalar)?;
    add_register64_v3(policy, X15, X0, X3)?;
    add_immediate64_v3(policy, X8, X15, u16::from(filter.offsets[0]))?;
    exact_v3(
        policy,
        DecodedInstructionV3::LoadVector128 {
            destination: 0,
            base: X8,
            offset: 0,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::CompareEqualBytes16 {
            destination: 0,
            left: 0,
            right: vector_registers[0],
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::UnsignedMaxAcrossBytes16 {
            destination: 1,
            source: 0,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::MoveVectorByteTo32 {
            destination: X8,
            source: 1,
        },
    )?;
    compare_immediate64_v3(policy, X8, 0)?;
    condition_v3(policy, ConditionV3::Equal, primary_sparse_scan)?;
    for index in 1..usize::from(filter.len) {
        add_immediate64_v3(policy, X8, X15, u16::from(filter.offsets[index]))?;
        exact_v3(
            policy,
            DecodedInstructionV3::LoadVector128 {
                destination: 1,
                base: X8,
                offset: 0,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::CompareEqualBytes16 {
                destination: 1,
                left: 1,
                right: vector_registers[index],
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::AndBytes16 {
                destination: 0,
                left: 0,
                right: 1,
            },
        )?;
    }
    exact_v3(
        policy,
        DecodedInstructionV3::ShrinkNarrowBytesFromHalfwords {
            destination: 0,
            source: 0,
            shift: 4,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::MoveVectorDoubleTo64 {
            destination: X6,
            source: 0,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::AndRegister64 {
            destination: X6,
            left: X6,
            right: X17,
        },
    )?;
    compare_immediate64_v3(policy, X6, 0)?;
    condition_v3(policy, ConditionV3::Equal, sparse_scan)?;
    branch_v3(policy, candidate)?;

    if let (
        Some(wide_batch),
        Some(wide_batch_empty),
        Some(wide_first_half),
        Some(wide_first_pair),
        Some(wide_first_block),
    ) = (
        wide_batch,
        wide_batch_empty,
        wide_first_half,
        wide_first_pair,
        wide_first_block,
    ) {
        policy.bind(wide_batch)?;
        add_register64_v3(policy, X15, X0, X3)?;
        add_immediate64_v3(policy, X8, X15, u16::from(filter.offsets[0]))?;
        for block in 0..SPARSE_SCAN_BLOCKS_V3 {
            let offset = block * SIMD_CANDIDATE_STARTS_V3;
            let mask = u8::try_from(u16::from(SPARSE_BLOCK_MASK_BASE_V3) + block)
                .expect("eight wide primary masks");
            exact_v3(
                policy,
                DecodedInstructionV3::LoadVector128 {
                    destination: mask,
                    base: X8,
                    offset,
                },
            )?;
            exact_v3(
                policy,
                DecodedInstructionV3::CompareEqualBytes16 {
                    destination: mask,
                    left: mask,
                    right: vector_registers[0],
                },
            )?;
        }
        exact_v3(
            policy,
            DecodedInstructionV3::OrBytes16 {
                destination: 0,
                left: SPARSE_BLOCK_MASK_BASE_V3,
                right: SPARSE_BLOCK_MASK_BASE_V3 + 1,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::OrBytes16 {
                destination: 1,
                left: SPARSE_BLOCK_MASK_BASE_V3 + 2,
                right: SPARSE_BLOCK_MASK_BASE_V3 + 3,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::OrBytes16 {
                destination: 0,
                left: 0,
                right: 1,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::OrBytes16 {
                destination: 1,
                left: SPARSE_BLOCK_MASK_BASE_V3 + 4,
                right: SPARSE_BLOCK_MASK_BASE_V3 + 5,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::OrBytes16 {
                destination: 0,
                left: 0,
                right: 1,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::OrBytes16 {
                destination: 1,
                left: SPARSE_BLOCK_MASK_BASE_V3 + 6,
                right: SPARSE_BLOCK_MASK_BASE_V3 + 7,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::OrBytes16 {
                destination: 1,
                left: 0,
                right: 1,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::UnsignedMaxAcrossBytes16 {
                destination: 1,
                source: 1,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::MoveVectorByteTo32 {
                destination: X8,
                source: 1,
            },
        )?;
        compare_immediate64_v3(policy, X8, 0)?;
        condition_v3(policy, ConditionV3::Equal, wide_batch_empty)?;

        for index in 1..usize::from(filter.len) {
            add_immediate64_v3(policy, X8, X15, u16::from(filter.offsets[index]))?;
            for block in 0..SPARSE_SCAN_BLOCKS_V3 {
                let offset = block * SIMD_CANDIDATE_STARTS_V3;
                let mask = u8::try_from(u16::from(SPARSE_BLOCK_MASK_BASE_V3) + block)
                    .expect("eight wide composite masks");
                exact_v3(
                    policy,
                    DecodedInstructionV3::LoadVector128 {
                        destination: 0,
                        base: X8,
                        offset,
                    },
                )?;
                exact_v3(
                    policy,
                    DecodedInstructionV3::CompareEqualBytes16 {
                        destination: 0,
                        left: 0,
                        right: vector_registers[index],
                    },
                )?;
                exact_v3(
                    policy,
                    DecodedInstructionV3::AndBytes16 {
                        destination: mask,
                        left: mask,
                        right: 0,
                    },
                )?;
            }
        }
        exact_v3(
            policy,
            DecodedInstructionV3::OrBytes16 {
                destination: 0,
                left: SPARSE_BLOCK_MASK_BASE_V3,
                right: SPARSE_BLOCK_MASK_BASE_V3 + 1,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::OrBytes16 {
                destination: 1,
                left: SPARSE_BLOCK_MASK_BASE_V3 + 2,
                right: SPARSE_BLOCK_MASK_BASE_V3 + 3,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::OrBytes16 {
                destination: 0,
                left: 0,
                right: 1,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::OrBytes16 {
                destination: 1,
                left: SPARSE_BLOCK_MASK_BASE_V3 + 4,
                right: SPARSE_BLOCK_MASK_BASE_V3 + 5,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::OrBytes16 {
                destination: 0,
                left: 0,
                right: 1,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::OrBytes16 {
                destination: 1,
                left: SPARSE_BLOCK_MASK_BASE_V3 + 6,
                right: SPARSE_BLOCK_MASK_BASE_V3 + 7,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::OrBytes16 {
                destination: 1,
                left: 0,
                right: 1,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::UnsignedMaxAcrossBytes16 {
                destination: 1,
                source: 1,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::MoveVectorByteTo32 {
                destination: X8,
                source: 1,
            },
        )?;
        compare_immediate64_v3(policy, X8, 0)?;
        condition_v3(policy, ConditionV3::Equal, wide_batch_empty)?;

        exact_v3(
            policy,
            DecodedInstructionV3::OrBytes16 {
                destination: 0,
                left: SPARSE_BLOCK_MASK_BASE_V3,
                right: SPARSE_BLOCK_MASK_BASE_V3 + 1,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::OrBytes16 {
                destination: 1,
                left: SPARSE_BLOCK_MASK_BASE_V3 + 2,
                right: SPARSE_BLOCK_MASK_BASE_V3 + 3,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::OrBytes16 {
                destination: 0,
                left: 0,
                right: 1,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::UnsignedMaxAcrossBytes16 {
                destination: 1,
                source: 0,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::MoveVectorByteTo32 {
                destination: X8,
                source: 1,
            },
        )?;
        compare_immediate64_v3(policy, X8, 0)?;
        condition_v3(policy, ConditionV3::NotEqual, wide_first_half)?;
        add_immediate64_v3(policy, X3, X3, SIMD_CANDIDATE_STARTS_V3 * 4)?;
        exact_v3(
            policy,
            DecodedInstructionV3::OrBytes16 {
                destination: SPARSE_BLOCK_MASK_BASE_V3,
                left: SPARSE_BLOCK_MASK_BASE_V3 + 4,
                right: SPARSE_BLOCK_MASK_BASE_V3 + 4,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::OrBytes16 {
                destination: SPARSE_BLOCK_MASK_BASE_V3 + 1,
                left: SPARSE_BLOCK_MASK_BASE_V3 + 5,
                right: SPARSE_BLOCK_MASK_BASE_V3 + 5,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::OrBytes16 {
                destination: SPARSE_BLOCK_MASK_BASE_V3 + 2,
                left: SPARSE_BLOCK_MASK_BASE_V3 + 6,
                right: SPARSE_BLOCK_MASK_BASE_V3 + 6,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::OrBytes16 {
                destination: SPARSE_BLOCK_MASK_BASE_V3 + 3,
                left: SPARSE_BLOCK_MASK_BASE_V3 + 7,
                right: SPARSE_BLOCK_MASK_BASE_V3 + 7,
            },
        )?;

        policy.bind(wide_first_half)?;
        exact_v3(
            policy,
            DecodedInstructionV3::OrBytes16 {
                destination: 0,
                left: SPARSE_BLOCK_MASK_BASE_V3,
                right: SPARSE_BLOCK_MASK_BASE_V3 + 1,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::UnsignedMaxAcrossBytes16 {
                destination: 1,
                source: 0,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::MoveVectorByteTo32 {
                destination: X8,
                source: 1,
            },
        )?;
        compare_immediate64_v3(policy, X8, 0)?;
        condition_v3(policy, ConditionV3::NotEqual, wide_first_pair)?;
        add_immediate64_v3(policy, X3, X3, SIMD_CANDIDATE_STARTS_V3 * 2)?;
        exact_v3(
            policy,
            DecodedInstructionV3::OrBytes16 {
                destination: SPARSE_BLOCK_MASK_BASE_V3,
                left: SPARSE_BLOCK_MASK_BASE_V3 + 2,
                right: SPARSE_BLOCK_MASK_BASE_V3 + 2,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::OrBytes16 {
                destination: SPARSE_BLOCK_MASK_BASE_V3 + 1,
                left: SPARSE_BLOCK_MASK_BASE_V3 + 3,
                right: SPARSE_BLOCK_MASK_BASE_V3 + 3,
            },
        )?;

        policy.bind(wide_first_pair)?;
        exact_v3(
            policy,
            DecodedInstructionV3::UnsignedMaxAcrossBytes16 {
                destination: 1,
                source: SPARSE_BLOCK_MASK_BASE_V3,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::MoveVectorByteTo32 {
                destination: X8,
                source: 1,
            },
        )?;
        compare_immediate64_v3(policy, X8, 0)?;
        condition_v3(policy, ConditionV3::NotEqual, wide_first_block)?;
        add_immediate64_v3(policy, X3, X3, SIMD_CANDIDATE_STARTS_V3)?;
        exact_v3(
            policy,
            DecodedInstructionV3::OrBytes16 {
                destination: SPARSE_BLOCK_MASK_BASE_V3,
                left: SPARSE_BLOCK_MASK_BASE_V3 + 1,
                right: SPARSE_BLOCK_MASK_BASE_V3 + 1,
            },
        )?;

        policy.bind(wide_first_block)?;
        exact_v3(
            policy,
            DecodedInstructionV3::OrBytes16 {
                destination: 0,
                left: SPARSE_BLOCK_MASK_BASE_V3,
                right: SPARSE_BLOCK_MASK_BASE_V3,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::ShrinkNarrowBytesFromHalfwords {
                destination: 0,
                source: 0,
                shift: 4,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::MoveVectorDoubleTo64 {
                destination: X6,
                source: 0,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::AndRegister64 {
                destination: X6,
                left: X6,
                right: X17,
            },
        )?;
        compare_immediate64_v3(policy, X6, 0)?;
        condition_v3(policy, ConditionV3::NotEqual, candidate)?;
        branch_v3(policy, wide_batch_empty)?;

        policy.bind(wide_batch_empty)?;
        add_immediate64_v3(policy, X3, X3, SPARSE_SCAN_STARTS_V3)?;
        branch_v3(policy, vector)?;
    }

    policy.bind(candidate)?;
    exact_v3(
        policy,
        DecodedInstructionV3::ReverseBits64 {
            destination: X7,
            source: X6,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::CountLeadingZeros64 {
            destination: X7,
            source: X7,
        },
    )?;
    subtract_immediate64_v3(policy, X16, X6, 1)?;
    exact_v3(
        policy,
        DecodedInstructionV3::AndRegister64 {
            destination: X6,
            left: X6,
            right: X16,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::LogicalShiftRight64 {
            destination: X7,
            source: X7,
            shift: 2,
        },
    )?;
    add_register64_v3(policy, X5, X3, X7)?;
    add_register64_v3(policy, X15, X0, X5)?;
    policy_confirmation_ordered_v3(
        policy,
        literal,
        confirmation_order,
        filter.offsets(),
        X15,
        candidate_miss,
    )?;
    add_immediate64_v3(policy, X13, X13, 1)?;
    add_immediate64_v3(policy, X3, X5, width)?;
    branch_v3(policy, match_run.unwrap_or(vector))?;

    policy.bind(candidate_miss)?;
    compare_immediate64_v3(policy, X6, 0)?;
    condition_v3(policy, ConditionV3::NotEqual, candidate)?;
    policy.bind(block_advance)?;
    add_immediate64_v3(policy, X3, X3, SIMD_CANDIDATE_STARTS_V3)?;
    branch_v3(policy, vector)?;

    policy.bind(primary_sparse_scan)?;
    add_immediate64_v3(policy, X3, X3, SIMD_CANDIDATE_STARTS_V3)?;
    compare_register64_v3(policy, X3, X4)?;
    condition_v3(policy, ConditionV3::Higher, done)?;
    subtract_register64_v3(policy, X5, X4, X3)?;
    compare_immediate64_v3(policy, X5, SPARSE_SCAN_STARTS_V3 - 1)?;
    condition_v3(policy, ConditionV3::CarryClear, vector)?;
    add_register64_v3(policy, X15, X0, X3)?;
    add_immediate64_v3(policy, X8, X15, u16::from(filter.offsets[0]))?;
    for block in 0..SPARSE_SCAN_BLOCKS_V3 {
        let offset = block * SIMD_CANDIDATE_STARTS_V3;
        let mask = u8::try_from(u16::from(SPARSE_BLOCK_MASK_BASE_V3) + block)
            .expect("eight sparse primary masks");
        exact_v3(
            policy,
            DecodedInstructionV3::LoadVector128 {
                destination: mask,
                base: X8,
                offset,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::CompareEqualBytes16 {
                destination: mask,
                left: mask,
                right: vector_registers[0],
            },
        )?;
    }
    exact_v3(
        policy,
        DecodedInstructionV3::OrBytes16 {
            destination: SPARSE_PAIR_01_MASK_V3,
            left: SPARSE_BLOCK_MASK_BASE_V3,
            right: SPARSE_BLOCK_MASK_BASE_V3 + 1,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::OrBytes16 {
            destination: SPARSE_PAIR_23_MASK_V3,
            left: SPARSE_BLOCK_MASK_BASE_V3 + 2,
            right: SPARSE_BLOCK_MASK_BASE_V3 + 3,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::OrBytes16 {
            destination: SPARSE_PAIR_45_MASK_V3,
            left: SPARSE_BLOCK_MASK_BASE_V3 + 4,
            right: SPARSE_BLOCK_MASK_BASE_V3 + 5,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::OrBytes16 {
            destination: SPARSE_PAIR_67_MASK_V3,
            left: SPARSE_BLOCK_MASK_BASE_V3 + 6,
            right: SPARSE_BLOCK_MASK_BASE_V3 + 7,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::OrBytes16 {
            destination: 1,
            left: SPARSE_PAIR_01_MASK_V3,
            right: SPARSE_PAIR_23_MASK_V3,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::OrBytes16 {
            destination: 0,
            left: SPARSE_PAIR_45_MASK_V3,
            right: SPARSE_PAIR_67_MASK_V3,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::OrBytes16 {
            destination: 1,
            left: 1,
            right: 0,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::UnsignedMaxAcrossBytes16 {
            destination: 1,
            source: 1,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::MoveVectorByteTo32 {
            destination: X8,
            source: 1,
        },
    )?;
    compare_immediate64_v3(policy, X8, 0)?;
    condition_v3(policy, ConditionV3::NotEqual, sparse_hit)?;
    add_immediate64_v3(
        policy,
        X3,
        X3,
        SPARSE_SCAN_STARTS_V3 - SIMD_CANDIDATE_STARTS_V3,
    )?;
    branch_v3(policy, primary_sparse_scan)?;

    policy.bind(sparse_scan)?;
    add_immediate64_v3(policy, X3, X3, SIMD_CANDIDATE_STARTS_V3)?;
    compare_register64_v3(policy, X3, X4)?;
    condition_v3(policy, ConditionV3::Higher, done)?;
    subtract_register64_v3(policy, X5, X4, X3)?;
    compare_immediate64_v3(policy, X5, SPARSE_SCAN_STARTS_V3 - 1)?;
    condition_v3(policy, ConditionV3::CarryClear, vector)?;
    add_register64_v3(policy, X15, X0, X3)?;
    add_immediate64_v3(policy, X8, X15, u16::from(filter.offsets[0]))?;
    add_immediate64_v3(policy, X9, X15, u16::from(semantic_secondary_offset))?;
    for block in 0..SPARSE_SCAN_BLOCKS_V3 {
        let offset = block * SIMD_CANDIDATE_STARTS_V3;
        let mask =
            u8::try_from(u16::from(SPARSE_BLOCK_MASK_BASE_V3) + block).expect("eight sparse masks");
        exact_v3(
            policy,
            DecodedInstructionV3::LoadVector128 {
                destination: 0,
                base: X8,
                offset,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::LoadVector128 {
                destination: 1,
                base: X9,
                offset,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::CompareEqualBytes16 {
                destination: 0,
                left: 0,
                right: vector_registers[0],
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::CompareEqualBytes16 {
                destination: 1,
                left: 1,
                right: SEMANTIC_SECONDARY_VECTOR_V3,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::AndBytes16 {
                destination: mask,
                left: 0,
                right: 1,
            },
        )?;
    }
    if sparse_prefix_escalation.is_some() {
        exact_v3(
            policy,
            DecodedInstructionV3::OrBytes16 {
                destination: 0,
                left: SPARSE_BLOCK_MASK_BASE_V3,
                right: SPARSE_BLOCK_MASK_BASE_V3 + 1,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::OrBytes16 {
                destination: 1,
                left: SPARSE_BLOCK_MASK_BASE_V3 + 2,
                right: SPARSE_BLOCK_MASK_BASE_V3 + 3,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::OrBytes16 {
                destination: 0,
                left: 0,
                right: 1,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::OrBytes16 {
                destination: 1,
                left: SPARSE_BLOCK_MASK_BASE_V3 + 4,
                right: SPARSE_BLOCK_MASK_BASE_V3 + 5,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::OrBytes16 {
                destination: 0,
                left: 0,
                right: 1,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::OrBytes16 {
                destination: 1,
                left: SPARSE_BLOCK_MASK_BASE_V3 + 6,
                right: SPARSE_BLOCK_MASK_BASE_V3 + 7,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::OrBytes16 {
                destination: 1,
                left: 0,
                right: 1,
            },
        )?;
    } else {
        exact_v3(
            policy,
            DecodedInstructionV3::OrBytes16 {
                destination: SPARSE_PAIR_01_MASK_V3,
                left: SPARSE_BLOCK_MASK_BASE_V3,
                right: SPARSE_BLOCK_MASK_BASE_V3 + 1,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::OrBytes16 {
                destination: SPARSE_PAIR_23_MASK_V3,
                left: SPARSE_BLOCK_MASK_BASE_V3 + 2,
                right: SPARSE_BLOCK_MASK_BASE_V3 + 3,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::OrBytes16 {
                destination: SPARSE_PAIR_45_MASK_V3,
                left: SPARSE_BLOCK_MASK_BASE_V3 + 4,
                right: SPARSE_BLOCK_MASK_BASE_V3 + 5,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::OrBytes16 {
                destination: SPARSE_PAIR_67_MASK_V3,
                left: SPARSE_BLOCK_MASK_BASE_V3 + 6,
                right: SPARSE_BLOCK_MASK_BASE_V3 + 7,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::OrBytes16 {
                destination: 1,
                left: SPARSE_PAIR_01_MASK_V3,
                right: SPARSE_PAIR_23_MASK_V3,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::OrBytes16 {
                destination: 0,
                left: SPARSE_PAIR_45_MASK_V3,
                right: SPARSE_PAIR_67_MASK_V3,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::OrBytes16 {
                destination: 1,
                left: 1,
                right: 0,
            },
        )?;
    }
    exact_v3(
        policy,
        DecodedInstructionV3::UnsignedMaxAcrossBytes16 {
            destination: 1,
            source: 1,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::MoveVectorByteTo32 {
            destination: X8,
            source: 1,
        },
    )?;
    compare_immediate64_v3(policy, X8, 0)?;
    condition_v3(
        policy,
        ConditionV3::NotEqual,
        sparse_prefix_escalation.unwrap_or(sparse_hit),
    )?;
    add_immediate64_v3(
        policy,
        X3,
        X3,
        SPARSE_SCAN_STARTS_V3 - SIMD_CANDIDATE_STARTS_V3,
    )?;
    branch_v3(policy, sparse_scan)?;

    if let Some(sparse_prefix_escalation) = sparse_prefix_escalation {
        policy.bind(sparse_prefix_escalation)?;
        for block in 0..SPARSE_SCAN_BLOCKS_V3 {
            let offset = block * SIMD_CANDIDATE_STARTS_V3;
            let mask = u8::try_from(u16::from(SPARSE_BLOCK_MASK_BASE_V3) + block)
                .expect("eight sparse masks");
            exact_v3(
                policy,
                DecodedInstructionV3::LoadVector128 {
                    destination: 0,
                    base: X15,
                    offset,
                },
            )?;
            exact_v3(
                policy,
                DecodedInstructionV3::CompareEqualBytes16 {
                    destination: 0,
                    left: 0,
                    right: SEMANTIC_PREFIX_VECTOR_V3,
                },
            )?;
            exact_v3(
                policy,
                DecodedInstructionV3::AndBytes16 {
                    destination: mask,
                    left: mask,
                    right: 0,
                },
            )?;
        }
        exact_v3(
            policy,
            DecodedInstructionV3::OrBytes16 {
                destination: SPARSE_PAIR_01_MASK_V3,
                left: SPARSE_BLOCK_MASK_BASE_V3,
                right: SPARSE_BLOCK_MASK_BASE_V3 + 1,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::OrBytes16 {
                destination: SPARSE_PAIR_23_MASK_V3,
                left: SPARSE_BLOCK_MASK_BASE_V3 + 2,
                right: SPARSE_BLOCK_MASK_BASE_V3 + 3,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::OrBytes16 {
                destination: SPARSE_PAIR_45_MASK_V3,
                left: SPARSE_BLOCK_MASK_BASE_V3 + 4,
                right: SPARSE_BLOCK_MASK_BASE_V3 + 5,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::OrBytes16 {
                destination: SPARSE_PAIR_67_MASK_V3,
                left: SPARSE_BLOCK_MASK_BASE_V3 + 6,
                right: SPARSE_BLOCK_MASK_BASE_V3 + 7,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::OrBytes16 {
                destination: 1,
                left: SPARSE_PAIR_01_MASK_V3,
                right: SPARSE_PAIR_23_MASK_V3,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::OrBytes16 {
                destination: 0,
                left: SPARSE_PAIR_45_MASK_V3,
                right: SPARSE_PAIR_67_MASK_V3,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::OrBytes16 {
                destination: 1,
                left: 1,
                right: 0,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::UnsignedMaxAcrossBytes16 {
                destination: 1,
                source: 1,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::MoveVectorByteTo32 {
                destination: X8,
                source: 1,
            },
        )?;
        compare_immediate64_v3(policy, X8, 0)?;
        condition_v3(policy, ConditionV3::NotEqual, sparse_hit)?;
        add_immediate64_v3(
            policy,
            X3,
            X3,
            SPARSE_SCAN_STARTS_V3 - SIMD_CANDIDATE_STARTS_V3,
        )?;
        branch_v3(policy, sparse_scan)?;
    }

    policy.bind(sparse_hit)?;
    exact_v3(
        policy,
        DecodedInstructionV3::OrBytes16 {
            destination: 1,
            left: SPARSE_PAIR_01_MASK_V3,
            right: SPARSE_PAIR_23_MASK_V3,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::UnsignedMaxAcrossBytes16 {
            destination: 1,
            source: 1,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::MoveVectorByteTo32 {
            destination: X8,
            source: 1,
        },
    )?;
    compare_immediate64_v3(policy, X8, 0)?;
    condition_v3(policy, ConditionV3::NotEqual, sparse_first_half)?;
    add_immediate64_v3(policy, X3, X3, SIMD_CANDIDATE_STARTS_V3 * 4)?;
    exact_v3(
        policy,
        DecodedInstructionV3::UnsignedMaxAcrossBytes16 {
            destination: 1,
            source: SPARSE_PAIR_45_MASK_V3,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::MoveVectorByteTo32 {
            destination: X8,
            source: 1,
        },
    )?;
    compare_immediate64_v3(policy, X8, 0)?;
    condition_v3(policy, ConditionV3::NotEqual, vector)?;
    add_immediate64_v3(policy, X3, X3, SIMD_CANDIDATE_STARTS_V3 * 2)?;
    branch_v3(policy, vector)?;

    policy.bind(sparse_first_half)?;
    exact_v3(
        policy,
        DecodedInstructionV3::UnsignedMaxAcrossBytes16 {
            destination: 1,
            source: SPARSE_PAIR_01_MASK_V3,
        },
    )?;
    exact_v3(
        policy,
        DecodedInstructionV3::MoveVectorByteTo32 {
            destination: X8,
            source: 1,
        },
    )?;
    compare_immediate64_v3(policy, X8, 0)?;
    condition_v3(policy, ConditionV3::NotEqual, vector)?;
    add_immediate64_v3(policy, X3, X3, SIMD_CANDIDATE_STARTS_V3 * 2)?;
    branch_v3(policy, vector)?;

    if let (Some(match_run), Some(match_run_miss)) = (match_run, match_run_miss) {
        policy.bind(match_run)?;
        compare_register64_v3(policy, X3, X4)?;
        condition_v3(policy, ConditionV3::Higher, done)?;
        add_register64_v3(policy, X15, X0, X3)?;
        policy_confirmation_ordered_v3(
            policy,
            literal,
            confirmation_order,
            &[],
            X15,
            match_run_miss,
        )?;
        add_immediate64_v3(policy, X13, X13, 1)?;
        add_immediate64_v3(policy, X3, X3, width)?;
        branch_v3(policy, match_run)?;
        policy.bind(match_run_miss)?;
        add_immediate64_v3(policy, X3, X3, 1)?;
        branch_v3(policy, vector)?;
    }

    policy.bind(scalar)?;
    compare_register64_v3(policy, X3, X4)?;
    condition_v3(policy, ConditionV3::Higher, done)?;
    add_register64_v3(policy, X15, X0, X3)?;
    for index in 0..usize::from(filter.len) {
        load_byte_v3(policy, X8, X15, u16::from(filter.offsets[index]))?;
        compare_register32_v3(policy, X8, value_registers[index])?;
        condition_v3(policy, ConditionV3::NotEqual, scalar_miss)?;
    }
    policy_confirmation_ordered_v3(
        policy,
        literal,
        confirmation_order,
        filter.offsets(),
        X15,
        scalar_miss,
    )?;
    add_immediate64_v3(policy, X13, X13, 1)?;
    add_immediate64_v3(policy, X3, X3, width)?;
    branch_v3(policy, match_run.unwrap_or(vector))?;
    policy.bind(scalar_miss)?;
    add_immediate64_v3(policy, X3, X3, 1)?;
    branch_v3(policy, scalar)
}

fn policy_confirmation_ordered_v3(
    policy: &mut PolicySinkV3,
    literal: &[u8],
    confirmation_order: &[u8],
    proven_filter_offsets: &[u8],
    candidate_pointer: u8,
    mismatch: PolicyLabelV3,
) -> Result<(), CountAotError> {
    let vector_chunks = literal.len() / 16;
    let vector_tail_offset = vector_chunks * 16;
    let double_chunks = (literal.len() - vector_tail_offset) / 8;
    let double_tail_offset = vector_tail_offset + double_chunks * 8;
    let overlapping_suffix_offset = policy_overlapping_suffix_offset_v3(literal.len());
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
            exact_v3(
                policy,
                DecodedInstructionV3::LoadVector128 {
                    destination: 0,
                    base: candidate_pointer,
                    offset: u16::try_from(chunk * 16).expect("bounded vector offset"),
                },
            )?;
            exact_v3(
                policy,
                DecodedInstructionV3::CompareEqualBytes16 {
                    destination: 0,
                    left: 0,
                    right: u8::try_from(21_usize + chunk).expect("at most v22"),
                },
            )?;
            exact_v3(
                policy,
                DecodedInstructionV3::UnsignedMinAcrossBytes16 {
                    destination: 0,
                    source: 0,
                },
            )?;
        } else if offset < double_tail_offset {
            let chunk = (offset - vector_tail_offset) / 8;
            let bit = 1_u8 << u8::try_from(chunk).expect("at most one double chunk");
            if emitted_double_chunks & bit != 0 {
                continue;
            }
            emitted_double_chunks |= bit;
            let global_chunk = vector_tail_offset / 8 + chunk;
            exact_v3(
                policy,
                DecodedInstructionV3::LoadVectorDouble {
                    destination: 0,
                    base: candidate_pointer,
                    offset: u16::try_from(vector_tail_offset + chunk * 8)
                        .expect("bounded double offset"),
                },
            )?;
            exact_v3(
                policy,
                DecodedInstructionV3::CompareEqualBytes8 {
                    destination: 0,
                    left: 0,
                    right: u8::try_from(4_usize + global_chunk).expect("at most v7"),
                },
            )?;
            exact_v3(
                policy,
                DecodedInstructionV3::UnsignedMinAcrossBytes8 {
                    destination: 0,
                    source: 0,
                },
            )?;
        } else if let Some(suffix_offset) = overlapping_suffix_offset {
            if emitted_overlapping_suffix {
                continue;
            }
            emitted_overlapping_suffix = true;
            add_immediate64_v3(
                policy,
                X9,
                candidate_pointer,
                u16::try_from(suffix_offset).expect("bounded overlapping suffix offset"),
            )?;
            exact_v3(
                policy,
                DecodedInstructionV3::LoadVectorDouble {
                    destination: 0,
                    base: X9,
                    offset: 0,
                },
            )?;
            exact_v3(
                policy,
                DecodedInstructionV3::CompareEqualBytes8 {
                    destination: 0,
                    left: 0,
                    right: OVERLAPPING_SUFFIX_VECTOR_V3,
                },
            )?;
            exact_v3(
                policy,
                DecodedInstructionV3::UnsignedMinAcrossBytes8 {
                    destination: 0,
                    source: 0,
                },
            )?;
        } else {
            load_byte_v3(
                policy,
                X8,
                candidate_pointer,
                u16::try_from(offset).expect("bounded tail offset"),
            )?;
            policy_mov_minimal_v3(policy, X9, u64::from(literal[offset]))?;
            compare_register32_v3(policy, X8, X9)?;
            condition_v3(policy, ConditionV3::NotEqual, mismatch)?;
            continue;
        }
        exact_v3(
            policy,
            DecodedInstructionV3::MoveVectorByteTo32 {
                destination: X8,
                source: 0,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::CompareImmediate32 {
                register: X8,
                immediate: 255,
            },
        )?;
        condition_v3(policy, ConditionV3::NotEqual, mismatch)?;
    }
    Ok(())
}

fn policy_confirmation_v3(
    policy: &mut PolicySinkV3,
    literal: &[u8],
    proven_filter_offsets: &[u8],
    candidate_pointer: u8,
    mismatch: PolicyLabelV3,
) -> Result<(), CountAotError> {
    let vector_chunks = literal.len() / 16;
    for chunk_index in 0..vector_chunks {
        let first = chunk_index * 16;
        if (first..first + 16).all(|offset| {
            proven_filter_offsets.contains(&u8::try_from(offset).expect("bounded literal offset"))
        }) {
            continue;
        }
        exact_v3(
            policy,
            DecodedInstructionV3::LoadVector128 {
                destination: 0,
                base: candidate_pointer,
                offset: u16::try_from(chunk_index * 16).expect("bounded offset"),
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::CompareEqualBytes16 {
                destination: 0,
                left: 0,
                right: u8::try_from(21 + chunk_index).expect("at most v22"),
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::UnsignedMinAcrossBytes16 {
                destination: 0,
                source: 0,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::MoveVectorByteTo32 {
                destination: X8,
                source: 0,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::CompareImmediate32 {
                register: X8,
                immediate: 255,
            },
        )?;
        condition_v3(policy, ConditionV3::NotEqual, mismatch)?;
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
        exact_v3(
            policy,
            DecodedInstructionV3::LoadVectorDouble {
                destination: 0,
                base: candidate_pointer,
                offset: u16::try_from(vector_tail_offset + chunk_index * 8)
                    .expect("bounded offset"),
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::CompareEqualBytes8 {
                destination: 0,
                left: 0,
                right: u8::try_from(4 + global_chunk).expect("at most v7"),
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::UnsignedMinAcrossBytes8 {
                destination: 0,
                source: 0,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::MoveVectorByteTo32 {
                destination: X8,
                source: 0,
            },
        )?;
        exact_v3(
            policy,
            DecodedInstructionV3::CompareImmediate32 {
                register: X8,
                immediate: 255,
            },
        )?;
        condition_v3(policy, ConditionV3::NotEqual, mismatch)?;
    }
    let tail_offset = vector_tail_offset + double_chunks * 8;
    if let Some(suffix_offset) = policy_overlapping_suffix_offset_v3(literal.len()) {
        if !(suffix_offset..literal.len()).all(|offset| {
            proven_filter_offsets.contains(&u8::try_from(offset).expect("bounded literal offset"))
        }) {
            add_immediate64_v3(
                policy,
                X9,
                candidate_pointer,
                u16::try_from(suffix_offset).expect("bounded overlapping suffix offset"),
            )?;
            exact_v3(
                policy,
                DecodedInstructionV3::LoadVectorDouble {
                    destination: 0,
                    base: X9,
                    offset: 0,
                },
            )?;
            exact_v3(
                policy,
                DecodedInstructionV3::CompareEqualBytes8 {
                    destination: 0,
                    left: 0,
                    right: OVERLAPPING_SUFFIX_VECTOR_V3,
                },
            )?;
            exact_v3(
                policy,
                DecodedInstructionV3::UnsignedMinAcrossBytes8 {
                    destination: 0,
                    source: 0,
                },
            )?;
            exact_v3(
                policy,
                DecodedInstructionV3::MoveVectorByteTo32 {
                    destination: X8,
                    source: 0,
                },
            )?;
            exact_v3(
                policy,
                DecodedInstructionV3::CompareImmediate32 {
                    register: X8,
                    immediate: 255,
                },
            )?;
            condition_v3(policy, ConditionV3::NotEqual, mismatch)?;
        }
        return Ok(());
    }
    for (index, byte) in literal[tail_offset..].iter().copied().enumerate() {
        let literal_offset = tail_offset + index;
        let narrow_offset = u8::try_from(literal_offset).expect("bounded literal offset");
        if proven_filter_offsets.contains(&narrow_offset) {
            continue;
        }
        load_byte_v3(policy, X8, candidate_pointer, u16::from(narrow_offset))?;
        policy_mov_minimal_v3(policy, X9, u64::from(byte))?;
        compare_register32_v3(policy, X8, X9)?;
        condition_v3(policy, ConditionV3::NotEqual, mismatch)?;
    }
    Ok(())
}

fn policy_overlapping_suffix_offset_v3(literal_len: usize) -> Option<usize> {
    let residual = literal_len % 8;
    if literal_len >= 8 && residual >= 2 {
        Some(literal_len - 8)
    } else {
        None
    }
}

fn policy_mov_minimal_v3(
    policy: &mut PolicySinkV3,
    destination: u8,
    value: u64,
) -> Result<(), CountAotError> {
    let first = (0_u8..4)
        .find(|halfword| {
            let shift = u32::from(*halfword) * 16;
            ((value >> shift) & 0xffff) != 0
        })
        .unwrap_or(0);
    let first_shift = u32::from(first) * 16;
    exact_v3(
        policy,
        DecodedInstructionV3::MoveZero64 {
            destination,
            immediate: u16::try_from((value >> first_shift) & 0xffff).expect("masked halfword"),
            shift: first * 16,
        },
    )?;
    for halfword in 0_u8..4 {
        if halfword == first {
            continue;
        }
        let shift = u32::from(halfword) * 16;
        let immediate = u16::try_from((value >> shift) & 0xffff).expect("masked halfword");
        if immediate != 0 {
            exact_v3(
                policy,
                DecodedInstructionV3::MoveKeep64 {
                    destination,
                    immediate,
                    shift: halfword * 16,
                },
            )?;
        }
    }
    Ok(())
}

fn exact_v3(
    policy: &mut PolicySinkV3,
    instruction: DecodedInstructionV3,
) -> Result<(), CountAotError> {
    policy.exact(instruction)
}

fn branch_v3(policy: &mut PolicySinkV3, target: PolicyLabelV3) -> Result<(), CountAotError> {
    policy.branch(target)
}

fn condition_v3(
    policy: &mut PolicySinkV3,
    condition: ConditionV3,
    target: PolicyLabelV3,
) -> Result<(), CountAotError> {
    policy.condition(condition, target)
}

fn compare_register64_v3(
    policy: &mut PolicySinkV3,
    left: u8,
    right: u8,
) -> Result<(), CountAotError> {
    exact_v3(
        policy,
        DecodedInstructionV3::CompareRegister64 { left, right },
    )
}

fn compare_register32_v3(
    policy: &mut PolicySinkV3,
    left: u8,
    right: u8,
) -> Result<(), CountAotError> {
    exact_v3(
        policy,
        DecodedInstructionV3::CompareRegister32 { left, right },
    )
}

fn compare_immediate64_v3(
    policy: &mut PolicySinkV3,
    register: u8,
    immediate: u16,
) -> Result<(), CountAotError> {
    exact_v3(
        policy,
        DecodedInstructionV3::CompareImmediate64 {
            register,
            immediate,
        },
    )
}

fn compare_immediate32_v3(
    policy: &mut PolicySinkV3,
    register: u8,
    immediate: u16,
) -> Result<(), CountAotError> {
    exact_v3(
        policy,
        DecodedInstructionV3::CompareImmediate32 {
            register,
            immediate,
        },
    )
}

fn add_register64_v3(
    policy: &mut PolicySinkV3,
    destination: u8,
    left: u8,
    right: u8,
) -> Result<(), CountAotError> {
    exact_v3(
        policy,
        DecodedInstructionV3::AddRegister64 {
            destination,
            left,
            right,
        },
    )
}

fn add_immediate64_v3(
    policy: &mut PolicySinkV3,
    destination: u8,
    source: u8,
    immediate: u16,
) -> Result<(), CountAotError> {
    exact_v3(
        policy,
        DecodedInstructionV3::AddImmediate64 {
            destination,
            source,
            immediate,
        },
    )
}

fn subtract_register64_v3(
    policy: &mut PolicySinkV3,
    destination: u8,
    left: u8,
    right: u8,
) -> Result<(), CountAotError> {
    exact_v3(
        policy,
        DecodedInstructionV3::SubtractRegister64 {
            destination,
            left,
            right,
        },
    )
}

fn subtract_immediate64_v3(
    policy: &mut PolicySinkV3,
    destination: u8,
    source: u8,
    immediate: u16,
) -> Result<(), CountAotError> {
    exact_v3(
        policy,
        DecodedInstructionV3::SubtractImmediate64 {
            destination,
            source,
            immediate,
        },
    )
}

fn load_byte_v3(
    policy: &mut PolicySinkV3,
    destination: u8,
    base: u8,
    offset: u16,
) -> Result<(), CountAotError> {
    exact_v3(
        policy,
        DecodedInstructionV3::LoadByte {
            destination,
            base,
            offset,
        },
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "one ordered mask table makes the independent decoder auditable"
)]
pub(crate) fn decode_word_v3(
    word: u32,
    offset: u32,
) -> Result<DecodedInstructionV3, CountAotError> {
    let rd = register_v3(word);
    let rn = register_v3(word >> 5);
    let rm = register_v3(word >> 16);
    if word & 0xff80_0000 == 0xd280_0000 {
        Ok(DecodedInstructionV3::MoveZero64 {
            destination: rd,
            immediate: immediate16_v3(word),
            shift: halfword_shift_v3(word),
        })
    } else if word & 0xff80_0000 == 0xf280_0000 {
        Ok(DecodedInstructionV3::MoveKeep64 {
            destination: rd,
            immediate: immediate16_v3(word),
            shift: halfword_shift_v3(word),
        })
    } else if word & 0xffe0_fc1f == 0xeb00_001f {
        Ok(DecodedInstructionV3::CompareRegister64 {
            left: rn,
            right: rm,
        })
    } else if word & 0xffe0_fc1f == 0x6b00_001f {
        Ok(DecodedInstructionV3::CompareRegister32 {
            left: rn,
            right: rm,
        })
    } else if word & 0xffc0_001f == 0xf100_001f {
        Ok(DecodedInstructionV3::CompareImmediate64 {
            register: rn,
            immediate: immediate12_v3(word),
        })
    } else if word & 0xffc0_001f == 0x7100_001f {
        Ok(DecodedInstructionV3::CompareImmediate32 {
            register: rn,
            immediate: immediate12_v3(word),
        })
    } else if word & 0xffe0_fc00 == 0x8b00_0000 {
        Ok(DecodedInstructionV3::AddRegister64 {
            destination: rd,
            left: rn,
            right: rm,
        })
    } else if word & 0xffc0_0000 == 0x9100_0000 {
        Ok(DecodedInstructionV3::AddImmediate64 {
            destination: rd,
            source: rn,
            immediate: immediate12_v3(word),
        })
    } else if word & 0xffe0_fc00 == 0xcb00_0000 {
        Ok(DecodedInstructionV3::SubtractRegister64 {
            destination: rd,
            left: rn,
            right: rm,
        })
    } else if word & 0xffc0_0000 == 0xd100_0000 {
        Ok(DecodedInstructionV3::SubtractImmediate64 {
            destination: rd,
            source: rn,
            immediate: immediate12_v3(word),
        })
    } else if word & 0xffe0_fc00 == 0x8a00_0000 {
        Ok(DecodedInstructionV3::AndRegister64 {
            destination: rd,
            left: rn,
            right: rm,
        })
    } else if word & 0xffc0_0000 == 0x9240_0000 && (word >> 16).trailing_zeros() >= 6 {
        Ok(DecodedInstructionV3::AndLowBits64 {
            destination: rd,
            source: rn,
            bits: u8::try_from(((word >> 10) & 0x3f) + 1).expect("at most 64 bits"),
        })
    } else if word & 0xffc0_0000 == 0xd340_0000 && ((word >> 10) & 0x3f) == 63 {
        Ok(DecodedInstructionV3::LogicalShiftRight64 {
            destination: rd,
            source: rn,
            shift: u8::try_from((word >> 16) & 0x3f).expect("six-bit shift"),
        })
    } else if word & 0xffff_fc00 == 0xdac0_0000 {
        Ok(DecodedInstructionV3::ReverseBits64 {
            destination: rd,
            source: rn,
        })
    } else if word & 0xffff_fc00 == 0xdac0_1000 {
        Ok(DecodedInstructionV3::CountLeadingZeros64 {
            destination: rd,
            source: rn,
        })
    } else if word & 0xffc0_0000 == 0x3940_0000 {
        Ok(DecodedInstructionV3::LoadByte {
            destination: rd,
            base: rn,
            offset: immediate12_v3(word),
        })
    } else if word & 0xffe0_fc00 == 0x3860_6800 {
        Ok(DecodedInstructionV3::LoadByteRegister {
            destination: rd,
            base: rn,
            index: rm,
        })
    } else if word & 0xffff_fff0 == 0x2518_e120 {
        Ok(DecodedInstructionV3::SvePtrueBytesVl16 {
            destination: predicate_destination_v3(word),
        })
    } else if word & 0xffff_fc00 == 0x0520_3800 {
        Ok(DecodedInstructionV3::SveDuplicateByte {
            destination: rd,
            source: rn,
        })
    } else if word & 0xffff_e000 == 0xa400_a000 {
        Ok(DecodedInstructionV3::SveLoadBytes {
            destination: rd,
            predicate: governing_predicate_v3(word),
            base: rn,
        })
    } else if word & 0xfff0_e000 == 0xa400_a000 {
        Ok(DecodedInstructionV3::SveLoadBytesMulVl {
            destination: rd,
            predicate: governing_predicate_v3(word),
            base: rn,
            vector_offset: signed_immediate4_v3(word),
        })
    } else if word & 0xffe0_e010 == 0x2400_a000 {
        Ok(DecodedInstructionV3::SveCompareEqualBytes {
            destination: predicate_destination_v3(word),
            predicate: governing_predicate_v3(word),
            left: rn,
            right: rm,
        })
    } else if word & 0xffe0_e010 == 0x4520_8000 {
        Ok(DecodedInstructionV3::Sve2MatchBytes {
            destination: predicate_destination_v3(word),
            predicate: governing_predicate_v3(word),
            left: rn,
            right: rm,
        })
    } else if word & 0xfff0_e210 == 0x2500_4000 {
        Ok(DecodedInstructionV3::SveAndPredicateBytes {
            destination: predicate_destination_v3(word),
            predicate: governing_predicate_v3(word),
            left: predicate_source_v3(word),
            right: predicate_right_v3(word),
        })
    } else if word & 0xfff0_e210 == 0x2580_4000 {
        Ok(DecodedInstructionV3::SveOrPredicateBytes {
            destination: predicate_destination_v3(word),
            predicate: governing_predicate_v3(word),
            left: predicate_source_v3(word),
            right: predicate_right_v3(word),
        })
    } else if word & 0xfff0_e210 == 0x2540_4010 {
        Ok(DecodedInstructionV3::SveBitClearPredicateBytesSetFlags {
            destination: predicate_destination_v3(word),
            predicate: governing_predicate_v3(word),
            left: predicate_source_v3(word),
            right: predicate_right_v3(word),
        })
    } else if word & 0xffff_e21f == 0x2550_c000 {
        Ok(DecodedInstructionV3::SveTestPredicateBytes {
            predicate: governing_predicate_v3(word),
            tested: predicate_source_v3(word),
        })
    } else if word & 0xffff_e210 == 0x2590_4000 {
        Ok(DecodedInstructionV3::SveBreakBeforeBytes {
            destination: predicate_destination_v3(word),
            predicate: governing_predicate_v3(word),
            source: predicate_source_v3(word),
        })
    } else if word & 0xffff_e210 == 0x2510_4000 {
        Ok(DecodedInstructionV3::SveBreakAfterBytes {
            destination: predicate_destination_v3(word),
            predicate: governing_predicate_v3(word),
            source: predicate_source_v3(word),
        })
    } else if word & 0xffff_e200 == 0x2520_8000 {
        Ok(DecodedInstructionV3::SveCountPredicateBytes {
            destination: rd,
            predicate: governing_predicate_v3(word),
            source: predicate_source_v3(word),
        })
    } else if word & 0xffc0_0000 == 0xf900_0000 {
        Ok(DecodedInstructionV3::Store64 {
            source: rd,
            base: rn,
            offset: immediate12_v3(word)
                .checked_mul(8)
                .expect("scaled store offset"),
        })
    } else if word & 0xffc0_0000 == 0x3dc0_0000 {
        Ok(DecodedInstructionV3::LoadVector128 {
            destination: rd,
            base: rn,
            offset: immediate12_v3(word)
                .checked_mul(16)
                .expect("scaled vector offset"),
        })
    } else if word & 0xffc0_0000 == 0xfd40_0000 {
        Ok(DecodedInstructionV3::LoadVectorDouble {
            destination: rd,
            base: rn,
            offset: immediate12_v3(word)
                .checked_mul(8)
                .expect("scaled double offset"),
        })
    } else if word & 0xffff_fc00 == 0x4e01_0c00 {
        Ok(DecodedInstructionV3::DuplicateByte16 {
            destination: rd,
            source: rn,
        })
    } else if word & 0xffe0_fc00 == 0x6e20_8c00 {
        Ok(DecodedInstructionV3::CompareEqualBytes16 {
            destination: rd,
            left: rn,
            right: rm,
        })
    } else if word & 0xffe0_fc00 == 0x2e20_8c00 {
        Ok(DecodedInstructionV3::CompareEqualBytes8 {
            destination: rd,
            left: rn,
            right: rm,
        })
    } else if word & 0xffe0_fc00 == 0x4e20_1c00 {
        Ok(DecodedInstructionV3::AndBytes16 {
            destination: rd,
            left: rn,
            right: rm,
        })
    } else if word & 0xffe0_fc00 == 0x4e20_8400 {
        Ok(DecodedInstructionV3::AddBytes16 {
            destination: rd,
            left: rn,
            right: rm,
        })
    } else if word & 0xffe0_fc00 == 0x4ea0_1c00 {
        Ok(DecodedInstructionV3::OrBytes16 {
            destination: rd,
            left: rn,
            right: rm,
        })
    } else if word & 0xffff_fc00 == 0x0f0c_8400 {
        Ok(DecodedInstructionV3::ShrinkNarrowBytesFromHalfwords {
            destination: rd,
            source: rn,
            shift: 4,
        })
    } else if word & 0xffff_fc00 == 0x4e31_b800 {
        Ok(DecodedInstructionV3::AddAcrossBytes16 {
            destination: rd,
            source: rn,
        })
    } else if word & 0xffff_fc00 == 0x6e30_a800 {
        Ok(DecodedInstructionV3::UnsignedMaxAcrossBytes16 {
            destination: rd,
            source: rn,
        })
    } else if word & 0xffff_fc00 == 0x2e31_a800 {
        Ok(DecodedInstructionV3::UnsignedMinAcrossBytes8 {
            destination: rd,
            source: rn,
        })
    } else if word & 0xffff_fc00 == 0x6e31_a800 {
        Ok(DecodedInstructionV3::UnsignedMinAcrossBytes16 {
            destination: rd,
            source: rn,
        })
    } else if word & 0xffff_fc00 == 0x0e01_3c00 {
        Ok(DecodedInstructionV3::MoveVectorByteTo32 {
            destination: rd,
            source: rn,
        })
    } else if word & 0xffff_fc00 == 0x9e66_0000 {
        Ok(DecodedInstructionV3::MoveVectorDoubleTo64 {
            destination: rd,
            source: rn,
        })
    } else if word & 0xffff_fc00 == 0x9e67_0000 {
        Ok(DecodedInstructionV3::Move64ToVectorDouble {
            destination: rd,
            source: rn,
        })
    } else if word & 0xffff_fc00 == 0x4e18_1c00 {
        Ok(DecodedInstructionV3::Insert64ToVectorDoubleLane1 {
            destination: rd,
            source: rn,
        })
    } else if word & 0xfc00_0000 == 0x1400_0000 {
        Ok(DecodedInstructionV3::Branch {
            displacement: sign_extend_v3(word & 0x03ff_ffff, 26) << 2,
        })
    } else if word & 0xff00_0010 == 0x5400_0000 {
        let condition = match u8::try_from(word & 0xf).expect("four-bit condition") {
            0 => ConditionV3::Equal,
            1 => ConditionV3::NotEqual,
            2 => ConditionV3::CarrySet,
            3 => ConditionV3::CarryClear,
            8 => ConditionV3::Higher,
            _ => return Err(CountAotError::UnknownInstruction { offset, word }),
        };
        Ok(DecodedInstructionV3::BranchCondition {
            condition,
            displacement: sign_extend_v3((word >> 5) & 0x7_ffff, 19) << 2,
        })
    } else if word == 0xd65f_03c0 {
        Ok(DecodedInstructionV3::Return)
    } else {
        Err(CountAotError::UnknownInstruction { offset, word })
    }
}

fn read_word_audit_v3(code: &[u8], offset: usize) -> Result<u32, CountAotError> {
    let bytes = code
        .get(offset..offset.checked_add(4).ok_or(audit_arithmetic_v3())?)
        .ok_or(invalid_v3("v3 audit word"))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn register_v3(word: u32) -> u8 {
    u8::try_from(word & 0x1f).expect("five-bit register")
}

fn predicate_destination_v3(word: u32) -> u8 {
    u8::try_from(word & 0xf).expect("four-bit predicate")
}

fn predicate_source_v3(word: u32) -> u8 {
    u8::try_from((word >> 5) & 0xf).expect("four-bit predicate")
}

fn governing_predicate_v3(word: u32) -> u8 {
    u8::try_from((word >> 10) & 7).expect("three-bit governing predicate")
}

fn predicate_right_v3(word: u32) -> u8 {
    u8::try_from((word >> 16) & 0xf).expect("four-bit predicate")
}

fn signed_immediate4_v3(word: u32) -> i8 {
    let raw = i8::try_from((word >> 16) & 0xf).expect("four-bit signed immediate");
    if raw & 8 == 0 { raw } else { raw - 16 }
}

fn immediate12_v3(word: u32) -> u16 {
    u16::try_from((word >> 10) & 0xfff).expect("twelve-bit immediate")
}

fn immediate16_v3(word: u32) -> u16 {
    u16::try_from((word >> 5) & 0xffff).expect("sixteen-bit immediate")
}

fn halfword_shift_v3(word: u32) -> u8 {
    u8::try_from(((word >> 21) & 3) * 16).expect("two-bit shift")
}

fn sign_extend_v3(value: u32, bits: u8) -> i32 {
    let shift = 32_u32
        .checked_sub(u32::from(bits))
        .expect("field no wider than u32");
    (value << shift).cast_signed() >> shift
}

fn align_up_audit_v3(value: usize, alignment: usize) -> Result<usize, CountAotError> {
    let mask = alignment
        .checked_sub(1)
        .ok_or(invalid_v3("v3 zero audit alignment"))?;
    value
        .checked_add(mask)
        .map(|sum| sum & !mask)
        .ok_or(audit_arithmetic_v3())
}

fn audit_exact_vec_v3<T>(
    capacity: usize,
    prospective: ProspectiveV3,
) -> Result<ExactVec<T>, CountAotError> {
    // Keep the complete source-derived admission adjacent to every allocator
    // call, even though audit_impl also refuses once before any content scan.
    refuse_audit_scratch_v3(prospective.audit_scratch, prospective.scratch_limit)?;
    ExactVec::try_with_capacity(capacity).map_err(|error| match error {
        CopyError::LayoutOverflow => audit_arithmetic_v3(),
        CopyError::AllocationFailed => CountAotError::AllocationFailed {
            resource: CountAotResource::ScratchBytes,
        },
    })
}

fn audit_push_v3<T>(
    values: &mut ExactVec<T>,
    value: T,
    at: &'static str,
) -> Result<(), CountAotError> {
    values
        .try_push(value)
        .map_err(|_| CountAotError::InternalInvariant { at })
}

fn refuse_audit_scratch_v3(required: u64, limit: u64) -> Result<(), CountAotError> {
    if required > limit {
        return Err(CountAotError::ResourceLimit {
            resource: CountAotResource::ScratchBytes,
            limit,
            required,
        });
    }
    Ok(())
}

fn audit_to_u64(value: usize) -> Result<u64, CountAotError> {
    u64::try_from(value).map_err(|_| audit_arithmetic_v3())
}

const fn invalid_v3(at: &'static str) -> CountAotError {
    CountAotError::InvalidImage { at }
}

const fn audit_arithmetic_v3() -> CountAotError {
    CountAotError::ArithmeticOverflow {
        site: CountAotArithmeticSite::Audit,
    }
}
