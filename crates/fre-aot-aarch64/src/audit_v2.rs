#![allow(
    clippy::arithmetic_side_effects,
    reason = "instruction-policy arithmetic is bounded by the admitted 0..=32-byte template; resource formulas use checked operations"
)]

use core::mem::size_of;

use fre_exact_alloc::{CopyError, ExactVec};
use fre_kernel_ir::{
    AggregateOutput, Count, ExactAggregateProgram, MAX_EXACT_AGGREGATE_LITERAL_BYTES,
};

use crate::{
    AOT_COUNT_BACKEND_VERSION_V2, AotCountArtifactIdentityV2, AotCountCpuFeatures, AotCountImageV2,
    AotCountLiteralManifestV2, CodeLabelV2, CountAotArithmeticSite, CountAotError,
    CountAotResource, LabelKindV2, RelocationKindV2, RelocationTargetV2, RelocationV2,
    emit_v2::{
        ProspectiveV2, artifact_identity_encoded_len_v2,
        assembler_scratch_derivation_work_upper_bound_v2, assembler_scratch_for_capacities_v2,
        assembler_scratch_upper_bound_v2, compute_artifact_identity_v2,
        identity_bytes_upper_bound_v2, identity_scratch_bytes_v2,
        identity_structural_traversal_work_v2, image_assembly_scratch_for_capacities_v2,
        label_order_work_upper_bound_v2, prospective_v2,
    },
    is_supported_aot_count_backend_tuple_v2,
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
const SIMD_CANDIDATE_STARTS_V2: u16 = 16;
const SPARSE_SCAN_BLOCKS_V2: u16 = 4;
const SPARSE_SCAN_STARTS_V2: u16 = SIMD_CANDIDATE_STARTS_V2 * SPARSE_SCAN_BLOCKS_V2;
const SPARSE_NIBBLE_BITS_V2: u64 = 0x1111_1111_1111_1111;
const SPARSE_BLOCK_MASK_BASE_V2: u8 = 24;
const SPARSE_FIRST_HALF_MASK_V2: u8 = 28;
const SPARSE_SECOND_HALF_MASK_V2: u8 = 29;

/// `AArch64` condition codes admitted by the experimental v2 template.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ConditionV2 {
    Equal = 0,
    NotEqual = 1,
    CarrySet = 2,
    CarryClear = 3,
    Higher = 8,
}

/// Independently decoded instruction subset admitted by Count AOT v2.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodedInstructionV2 {
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
    Branch {
        displacement: i32,
    },
    BranchCondition {
        condition: ConditionV2,
        displacement: i32,
    },
    Return,
}

impl DecodedInstructionV2 {
    const fn is_vector(self) -> bool {
        matches!(
            self,
            Self::LoadVector128 { .. }
                | Self::LoadVectorDouble { .. }
                | Self::DuplicateByte16 { .. }
                | Self::CompareEqualBytes16 { .. }
                | Self::CompareEqualBytes8 { .. }
                | Self::AndBytes16 { .. }
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

    const fn direct_displacement(self) -> Option<i32> {
        match self {
            Self::Branch { displacement } | Self::BranchCondition { displacement, .. } => {
                Some(displacement)
            }
            _ => None,
        }
    }

    const fn expected_relocation_kind(self) -> Option<RelocationKindV2> {
        match self {
            Self::Branch { .. } => Some(RelocationKindV2::Branch26),
            Self::BranchCondition { .. } => Some(RelocationKindV2::ConditionalBranch19),
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
            | Self::MoveVectorDoubleTo64 { destination, .. } => Some(destination),
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
            | Self::OrBytes16 { destination, .. }
            | Self::ShrinkNarrowBytesFromHalfwords { destination, .. }
            | Self::AddAcrossBytes16 { destination, .. }
            | Self::UnsignedMaxAcrossBytes16 { destination, .. }
            | Self::UnsignedMinAcrossBytes8 { destination, .. }
            | Self::UnsignedMinAcrossBytes16 { destination, .. }
            | Self::Move64ToVectorDouble { destination, .. }
            | Self::Insert64ToVectorDoubleLane1 { destination, .. } => Some(destination),
            _ => None,
        }
    }
}

/// Independent exact-template, decode, CFG, ABI, and seal audit receipt.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CountAuditReportV2 {
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
pub(crate) struct AuditWorkComponentsV2 {
    pub(crate) support_target_layout_and_seals: u64,
    pub(crate) manifest_and_filter_selection: u64,
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
pub(crate) struct AuditFilterWorkEnvelopeV2 {
    pub(crate) initial_scan: u64,
    pub(crate) two_offset_scan: u64,
    pub(crate) three_offset_scan: u64,
    pub(crate) total: u64,
}

pub(crate) fn independent_filter_work_envelope_v2(
    literal_len: usize,
) -> Result<AuditFilterWorkEnvelopeV2, CountAotError> {
    // This derivation intentionally does not use the emitter's formula.
    // Initial selection visits every byte once. With two selected offsets an
    // additional byte can require one visit, two index probes and two value
    // probes; with three offsets the corresponding bound is one plus three
    // plus three.
    const TWO_OFFSET_TOUCHES_PER_BYTE_V2: u64 = 1 + 2 + 2;
    const THREE_OFFSET_TOUCHES_PER_BYTE_V2: u64 = 1 + 3 + 3;
    let literal = audit_to_u64(literal_len)?;
    let initial_scan = literal;
    let two_offset_scan = literal
        .checked_mul(TWO_OFFSET_TOUCHES_PER_BYTE_V2)
        .ok_or(audit_arithmetic_v2())?;
    let three_offset_scan = literal
        .checked_mul(THREE_OFFSET_TOUCHES_PER_BYTE_V2)
        .ok_or(audit_arithmetic_v2())?;
    let total = initial_scan
        .checked_add(two_offset_scan)
        .and_then(|work| work.checked_add(three_offset_scan))
        .ok_or(audit_arithmetic_v2())?;
    Ok(AuditFilterWorkEnvelopeV2 {
        initial_scan,
        two_offset_scan,
        three_offset_scan,
        total,
    })
}

#[allow(
    clippy::items_after_statements,
    reason = "named audit-work constants stay next to the exact phase formula they justify"
)]
pub(crate) fn audit_work_components_v2(
    code_bytes: usize,
    labels: usize,
    relocations: usize,
    literal_len: usize,
) -> Result<AuditWorkComponentsV2, CountAotError> {
    let instructions = audit_to_u64(code_bytes / 4)?;
    let code_bytes = audit_to_u64(code_bytes)?;
    let labels = audit_to_u64(labels)?;
    let relocations = audit_to_u64(relocations)?;
    let literal = audit_to_u64(literal_len)?;
    let label_order = label_order_work_upper_bound_v2(
        usize::try_from(labels).map_err(|_| audit_arithmetic_v2())?,
    )?;
    let identity_bytes = identity_bytes_upper_bound_v2(
        usize::try_from(code_bytes).map_err(|_| audit_arithmetic_v2())?,
        usize::try_from(labels).map_err(|_| audit_arithmetic_v2())?,
        usize::try_from(relocations).map_err(|_| audit_arithmetic_v2())?,
    )?;
    let identity_structural =
        identity_structural_traversal_work_v2(labels, relocations).ok_or(audit_arithmetic_v2())?;

    // Every fixed component below corresponds to named checks in audit_impl:
    // support/target 14, source/layout/dimensions 15, stats/receipt 28,
    // decoded summary 14, public wrapper/report 9, and checked conversions 16.
    const SUPPORT_TARGET_LAYOUT_AND_SEALS_FIXED_V2: u64 = 14 + 15 + 28 + 14 + 9 + 16;
    const FILTER_FIXED_WORK_V2: u64 = 16;
    // Manifest construction separately validates the bounded filter offsets
    // and copies every literal byte into its authenticated fixed-width record.
    const MANIFEST_WORK_PER_LITERAL_BYTE_V2: u64 = 1;
    const MANIFEST_FIXED_WORK_V2: u64 = 16;
    // Each decoded word reads four bytes, decodes one ordered mask row, and
    // appends one exact record.
    let decode = code_bytes
        .checked_add(instructions.checked_mul(2).ok_or(audit_arithmetic_v2())?)
        .ok_or(audit_arithmetic_v2())?;
    // The policy generator appends no more than the prospective instruction
    // and label dimensions, resolves each instruction once, and scans each
    // literal byte in setup/confirmation at most eight times.
    let canonical_policy_regeneration = instructions
        .checked_mul(3)
        .and_then(|work| work.checked_add(labels.checked_mul(2)?))
        .and_then(|work| work.checked_add(literal.checked_mul(8)?))
        .and_then(|work| work.checked_add(32))
        .ok_or(audit_arithmetic_v2())?;
    let canonical_label_order = label_order.total;
    let canonical_compare = instructions
        .checked_add(labels)
        .ok_or(audit_arithmetic_v2())?;
    // Each instruction performs fixed classification/ABI checks. A branch may
    // scan every label, then consumes one four-field relocation record.
    let cfg_and_relocations = instructions
        .checked_mul(labels.checked_add(18).ok_or(audit_arithmetic_v2())?)
        .and_then(|work| work.checked_add(relocations.checked_mul(8)?))
        .ok_or(audit_arithmetic_v2())?;
    let filter_selection = independent_filter_work_envelope_v2(literal_len)?.total;
    let manifest_and_filter_selection = literal
        .checked_mul(MANIFEST_WORK_PER_LITERAL_BYTE_V2)
        .and_then(|work| work.checked_add(filter_selection))
        .and_then(|work| work.checked_add(FILTER_FIXED_WORK_V2))
        .and_then(|work| work.checked_add(MANIFEST_FIXED_WORK_V2))
        .ok_or(audit_arithmetic_v2())?;
    // A sealed audit counts the encoding and hashes it: two structural
    // traversals, one complete byte traversal, and one digest finalization.
    let identity_structural_traversal = identity_structural
        .checked_mul(2)
        .ok_or(audit_arithmetic_v2())?;
    let identity_hash_bytes = identity_bytes;
    let identity_hash_finalization = 8;
    // One complete scratch derivation, one assembler-envelope recomputation,
    // five ExactVec admission sites, actual-capacity arithmetic, persistent
    // envelope arithmetic, and caller/hard/receipt seals.
    let scratch_and_allocation_accounting = 24_u64
        .checked_add(assembler_scratch_derivation_work_upper_bound_v2())
        .and_then(|work| work.checked_add(5 * 3))
        .and_then(|work| work.checked_add(18))
        .and_then(|work| work.checked_add(16))
        .ok_or(audit_arithmetic_v2())?;
    let support_target_layout_and_seals = SUPPORT_TARGET_LAYOUT_AND_SEALS_FIXED_V2;
    let total = support_target_layout_and_seals
        .checked_add(manifest_and_filter_selection)
        .and_then(|work| work.checked_add(decode))
        .and_then(|work| work.checked_add(canonical_policy_regeneration))
        .and_then(|work| work.checked_add(canonical_label_order))
        .and_then(|work| work.checked_add(canonical_compare))
        .and_then(|work| work.checked_add(cfg_and_relocations))
        .and_then(|work| work.checked_add(identity_structural_traversal))
        .and_then(|work| work.checked_add(identity_hash_bytes))
        .and_then(|work| work.checked_add(identity_hash_finalization))
        .and_then(|work| work.checked_add(scratch_and_allocation_accounting))
        .ok_or(audit_arithmetic_v2())?;
    Ok(AuditWorkComponentsV2 {
        support_target_layout_and_seals,
        manifest_and_filter_selection,
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

pub(crate) fn audit_work_upper_bound_v2(
    code_bytes: usize,
    labels: usize,
    relocations: usize,
    literal_len: usize,
) -> Result<u64, CountAotError> {
    Ok(audit_work_components_v2(code_bytes, labels, relocations, literal_len)?.total)
}

type AuditCommonInlineStateV2 = (
    &'static ExactAggregateProgram<Count>,
    &'static AotCountImageV2,
    ProspectiveV2,
    bool,
    CountAuditReportV2,
    AotCountLiteralManifestV2,
    [usize; 20],
    [u32; 16],
    [u64; 16],
    CountAotError,
);
type AuditDecodeInlineStateV2 = (
    AuditCommonInlineStateV2,
    ExactVec<DecodedInstructionV2>,
    core::iter::Enumerate<core::slice::ChunksExact<'static, u8>>,
    DecodedInstructionV2,
    [u32; 8],
    CountAotError,
);
type AuditPolicyInlineStateV2 = (
    AuditDecodeInlineStateV2,
    PolicySinkV2,
    ResolvedPolicyV2,
    [usize; 12],
    [u64; 8],
    CountAotError,
);
type AuditIdentityInlineStateV2 = (
    AuditPolicyInlineStateV2,
    AotCountArtifactIdentityV2,
    [u8; 32],
    [u64; 8],
    CountAotError,
);
type AuditCandidateWrapperInlineStateV2 = (
    &'static ExactAggregateProgram<Count>,
    &'static AotCountImageV2,
    ProspectiveV2,
    Result<CountAuditReportV2, CountAotError>,
);
type AuditPublicWrapperInlineStateV2 = (
    &'static ExactAggregateProgram<Count>,
    &'static AotCountImageV2,
    ProspectiveV2,
    CountAuditReportV2,
    Result<CountAuditReportV2, CountAotError>,
);

pub(crate) const fn audit_candidate_wrapper_inline_bytes_v2() -> usize {
    size_of::<AuditCandidateWrapperInlineStateV2>()
}

pub(crate) const fn audit_public_wrapper_inline_bytes_v2() -> usize {
    size_of::<AuditPublicWrapperInlineStateV2>()
}

pub(crate) fn audit_scratch_upper_bound_v2(
    code_bytes: usize,
    labels: usize,
    relocations: usize,
) -> Result<u64, CountAotError> {
    let instructions = code_bytes / 4;
    let fixed = size_of::<AuditIdentityInlineStateV2>();
    let requested = instructions
        .checked_mul(size_of::<DecodedInstructionV2>())
        .and_then(|bytes| {
            bytes.checked_add(
                instructions.checked_mul(size_of::<PolicyInstructionV2>())?,
            )
        })
        .and_then(|bytes| {
            bytes.checked_add(
                labels.checked_mul(size_of::<PolicyLabelRecordV2>())?,
            )
        })
        .and_then(|bytes| {
            bytes.checked_add(
                instructions.checked_mul(size_of::<DecodedInstructionV2>())?,
            )
        })
        .and_then(|bytes| {
            bytes.checked_add(labels.checked_mul(size_of::<CodeLabelV2>())?)
        })
        .and_then(|bytes| bytes.checked_add(fixed))
        .and_then(|bytes| bytes.checked_add(identity_scratch_bytes_v2()))
        // Relocations are retained in the borrowed image, but the active
        // relocation walk keeps one complete record plus iterator state live.
        .and_then(|bytes| {
            bytes.checked_add(
                relocations
                    .min(1)
                    .checked_mul(size_of::<RelocationV2>())?,
            )
        })
        .ok_or(audit_arithmetic_v2())?;
    audit_to_u64(requested)
}

/// Audit a sealed experimental v2 image without trusting emitter templates.
pub fn audit_count_image_v2(
    program: &ExactAggregateProgram<Count>,
    image: &AotCountImageV2,
) -> Result<CountAuditReportV2, CountAotError> {
    let literal_len = independent_preflight_v2(program)?;
    let prospective = prospective_v2(literal_len)?;
    audit_impl_v2(program, image, prospective, true)
}

pub(crate) fn audit_count_image_candidate_v2(
    program: &ExactAggregateProgram<Count>,
    image: &AotCountImageV2,
    prospective: ProspectiveV2,
) -> Result<CountAuditReportV2, CountAotError> {
    audit_impl_v2(program, image, prospective, false)
}

#[cfg(test)]
pub(crate) fn audit_count_image_with_scratch_limit_for_test_v2(
    program: &ExactAggregateProgram<Count>,
    image: &AotCountImageV2,
    scratch_limit: u64,
) -> Result<CountAuditReportV2, CountAotError> {
    let literal_len = independent_preflight_v2(program)?;
    let mut prospective = prospective_v2(literal_len)?;
    prospective.scratch_limit = prospective.scratch_limit.min(scratch_limit);
    audit_impl_v2(program, image, prospective, true)
}

fn same_source_bounds_v2(mut observed: ProspectiveV2, source: ProspectiveV2) -> bool {
    observed.scratch_limit = source.scratch_limit;
    observed.persistent_limit = source.persistent_limit;
    observed == source
}

#[allow(
    clippy::too_many_lines,
    reason = "the independent v2 audit keeps every seal and decoded invariant visible"
)]
fn audit_impl_v2(
    program: &ExactAggregateProgram<Count>,
    image: &AotCountImageV2,
    prospective: ProspectiveV2,
    sealed: bool,
) -> Result<CountAuditReportV2, CountAotError> {
    let literal_len = independent_preflight_v2(program)?;
    let source_prospective = prospective_v2(literal_len)?;
    if !same_source_bounds_v2(prospective, source_prospective) {
        return Err(invalid_v2("v2 prospective source bounds"));
    }
    let independent_filter_work = independent_filter_work_envelope_v2(literal_len)?;
    if prospective.filter_selection_work != independent_filter_work.total
        || independent_filter_work.total > prospective.audit_work
    {
        return Err(invalid_v2("v2 filter work pre-admission"));
    }
    let complete_audit_scratch = audit_scratch_upper_bound_v2(
        prospective.code_bytes,
        prospective.labels,
        prospective.relocations,
    )?;
    if complete_audit_scratch != prospective.audit_scratch {
        return Err(invalid_v2("v2 audit scratch recomputation"));
    }
    let complete_assembler_scratch = assembler_scratch_upper_bound_v2(
        prospective.code_bytes,
        prospective.labels,
        prospective.relocations,
    )?;
    if complete_assembler_scratch != prospective.assembler_scratch {
        return Err(invalid_v2("v2 assembler scratch recomputation"));
    }
    refuse_audit_scratch_v2(complete_audit_scratch, prospective.scratch_limit)?;
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
        .checked_mul(size_of::<CodeLabelV2>())
        .ok_or(audit_arithmetic_v2())?;
    let expected_relocation_capacity_bytes = image
        .relocations
        .capacity()
        .checked_mul(size_of::<RelocationV2>())
        .ok_or(audit_arithmetic_v2())?;
    let expected_retained_heap_bytes = image
        .code
        .capacity()
        .checked_add(expected_label_capacity_bytes)
        .and_then(|bytes| bytes.checked_add(expected_relocation_capacity_bytes))
        .ok_or(audit_arithmetic_v2())?;
    let actual_persistent_bytes = expected_retained_heap_bytes
        .checked_add(size_of::<AotCountImageV2>())
        .ok_or(audit_arithmetic_v2())?;
    let actual_persistent = audit_to_u64(actual_persistent_bytes)?;
    if image.code.capacity() > prospective.code_bytes
        || image.labels.capacity() > prospective.labels
        || image.relocations.capacity() > prospective.relocations
        || actual_persistent > prospective.persistent
    {
        return Err(invalid_v2("v2 prospective persistent seal"));
    }
    if actual_persistent > prospective.persistent_limit {
        return Err(CountAotError::ResourceLimit {
            resource: CountAotResource::PersistentBytes,
            limit: prospective.persistent_limit,
            required: actual_persistent,
        });
    }
    let receipt = image.build_receipt;
    let observed_assembler_scratch = assembler_scratch_for_capacities_v2(
        image.code.capacity(),
        prospective.labels,
        prospective.relocations,
        image.labels.capacity(),
        image.relocations.capacity(),
    )?;
    let observed_image_assembly_scratch = image_assembly_scratch_for_capacities_v2(
        image.code.capacity(),
        image.labels.capacity(),
        image.relocations.capacity(),
    )?;
    let observed_emission_scratch = observed_assembler_scratch.max(observed_image_assembly_scratch);
    if receipt.code_capacity_bytes != image.code.capacity()
        || receipt.label_capacity_bytes != expected_label_capacity_bytes
        || receipt.relocation_capacity_bytes != expected_relocation_capacity_bytes
        || receipt.retained_heap_bytes != expected_retained_heap_bytes
        || receipt.inline_bytes != size_of::<AotCountImageV2>()
    {
        return Err(invalid_v2("v2 persistent capacity receipt"));
    }
    if observed_assembler_scratch > prospective.assembler_scratch
        || observed_image_assembly_scratch > prospective.image_assembly_scratch
        || observed_emission_scratch > prospective.emission_scratch
        || receipt.emission_peak_scratch_bytes != observed_emission_scratch
    {
        return Err(invalid_v2("v2 emission scratch receipt"));
    }
    let literal = program.literal();
    if literal_len != literal.len()
        || image.support.backend_version != AOT_COUNT_BACKEND_VERSION_V2
        || !is_supported_aot_count_backend_tuple_v2(image.support)
        || image.support.candidate_block_starts
            != u8::try_from(SIMD_CANDIDATE_STARTS_V2).expect("candidate block width fits u8")
    {
        return Err(invalid_v2("v2 support tuple"));
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
        return Err(invalid_v2("v2 target tuple"));
    }
    let independent_selection = independent_candidate_filter_v2(literal)?;
    if independent_selection.observed.total()? > independent_filter_work.total {
        return Err(invalid_v2("v2 observed filter work"));
    }
    let independent_filter = independent_selection.filter;
    let independent_filter_offsets = independent_filter
        .as_ref()
        .map_or(&[][..], AuditCandidateFilterV2::offsets);
    let expected_manifest =
        AotCountLiteralManifestV2::from_literal_and_offsets(literal, independent_filter_offsets)
            .ok_or(invalid_v2("v2 independent manifest"))?;
    if image.source_identity != program.cache_identity()
        || image.literal_manifest != expected_manifest
    {
        return Err(invalid_v2("v2 semantic manifest"));
    }
    let expected_code_alignment = 16_u32;
    let expected_rodata_offset = align_up_audit_v2(
        image.code.len(),
        usize::try_from(expected_code_alignment).unwrap(),
    )?;
    let expected_rodata_offset =
        u32::try_from(expected_rodata_offset).map_err(|_| audit_arithmetic_v2())?;
    if image.layout.code_alignment != expected_code_alignment
        || image.layout.rodata_alignment != expected_code_alignment
        || image.layout.rodata_from_code_start != expected_rodata_offset
        || image.layout.total_mapped_bytes != expected_rodata_offset
        || !image.code.len().is_multiple_of(4)
        || image.code.len() > prospective.code_bytes
        || image.labels.len() > prospective.labels
        || image.relocations.len() > prospective.relocations
    {
        return Err(invalid_v2("v2 image layout"));
    }
    let expected_emission_work = audit_to_u64(image.code.len() / 4)?
        .checked_add(
            audit_to_u64(image.labels.len())?
                .checked_mul(2)
                .ok_or(audit_arithmetic_v2())?,
        )
        .and_then(|work| work.checked_add(audit_to_u64(image.relocations.len()).ok()?))
        .and_then(|work| {
            work.checked_add(
                label_order_work_upper_bound_v2(image.labels.len())
                    .ok()?
                    .total,
            )
        })
        .ok_or(audit_arithmetic_v2())?;
    if image.stats.code_bytes
        != u32::try_from(image.code.len()).map_err(|_| audit_arithmetic_v2())?
        || image.stats.data_bytes != 0
        || image.stats.labels
            != u32::try_from(image.labels.len()).map_err(|_| audit_arithmetic_v2())?
        || image.stats.relocations
            != u32::try_from(image.relocations.len()).map_err(|_| audit_arithmetic_v2())?
        || image.stats.emitted_instructions != image.stats.code_bytes / 4
        || image.stats.candidate_filter_bytes
            != independent_filter.map_or(0, AuditCandidateFilterV2::len)
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
        return Err(invalid_v2("v2 image statistics"));
    }

    let instruction_count = image.code.len() / 4;
    let mut decoded = audit_exact_vec_v2(instruction_count, prospective)?;
    for (index, bytes) in image.code.chunks_exact(4).enumerate() {
        let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let offset = u32::try_from(index.checked_mul(4).ok_or(audit_arithmetic_v2())?)
            .map_err(|_| audit_arithmetic_v2())?;
        let instruction = decode_word_v2(word, offset)?;
        if let Some(destination) = instruction.written_simd_register()
            && (8..=15).contains(&destination)
        {
            return Err(invalid_v2("v2 forbidden callee-saved SIMD write"));
        }
        audit_push_v2(&mut decoded, instruction, "v2 decoded capacity")?;
    }

    let policy = independent_policy_template_v2(literal, independent_filter, prospective)?;
    if decoded.as_slice() != policy.instructions.as_slice()
        || image.labels.as_slice() != policy.labels.as_slice()
    {
        return Err(invalid_v2("v2 independent full template"));
    }

    let mut relocation_index = 0_usize;
    let mut direct_branches = 0_u32;
    let mut vector_instructions = 0_u32;
    let mut simd_candidate_blocks = 0_u32;
    let mut staged_filter_checks = 0_u32;
    let mut sparse_lane_recoveries = 0_u32;
    let mut stores = 0_u32;
    let mut returns = 0_u32;
    for (index, instruction) in decoded.iter().copied().enumerate() {
        if instruction.is_vector() {
            vector_instructions = vector_instructions
                .checked_add(1)
                .ok_or(audit_arithmetic_v2())?;
        }
        if matches!(
            instruction,
            DecodedInstructionV2::ShrinkNarrowBytesFromHalfwords { shift: 4, .. }
        ) {
            simd_candidate_blocks = simd_candidate_blocks
                .checked_add(1)
                .ok_or(audit_arithmetic_v2())?;
        }
        if matches!(
            instruction,
            DecodedInstructionV2::CountLeadingZeros64 { .. }
        ) {
            sparse_lane_recoveries = sparse_lane_recoveries
                .checked_add(1)
                .ok_or(audit_arithmetic_v2())?;
        }
        if matches!(
            instruction,
            DecodedInstructionV2::UnsignedMaxAcrossBytes16 { source: 0, .. }
        ) {
            staged_filter_checks = staged_filter_checks
                .checked_add(1)
                .ok_or(audit_arithmetic_v2())?;
        }
        if let Some(destination) = instruction.written_gpr()
            && (destination == X2 || destination > X17)
        {
            return Err(invalid_v2("v2 forbidden GPR write"));
        }
        match instruction {
            DecodedInstructionV2::Store64 {
                source,
                base,
                offset,
            } => {
                if source != X13 || base != X2 || offset != 0 {
                    return Err(invalid_v2("v2 store policy"));
                }
                stores = stores.checked_add(1).ok_or(audit_arithmetic_v2())?;
            }
            DecodedInstructionV2::Return => {
                returns = returns.checked_add(1).ok_or(audit_arithmetic_v2())?;
            }
            _ => {}
        }
        if let Some(displacement) = instruction.direct_displacement() {
            direct_branches = direct_branches
                .checked_add(1)
                .ok_or(audit_arithmetic_v2())?;
            let code_offset = u32::try_from(index.checked_mul(4).ok_or(audit_arithmetic_v2())?)
                .map_err(|_| audit_arithmetic_v2())?;
            let target = i64::from(code_offset)
                .checked_add(i64::from(displacement))
                .ok_or(audit_arithmetic_v2())?;
            let target = u32::try_from(target).map_err(|_| invalid_v2("v2 branch target range"))?;
            if target >= image.stats.code_bytes
                || target % 4 != 0
                || image.labels.iter().all(|label| label.offset != target)
            {
                return Err(invalid_v2("v2 branch target"));
            }
            let relocation = image
                .relocations
                .get(relocation_index)
                .ok_or(invalid_v2("v2 missing relocation"))?;
            let word = read_word_audit_v2(&image.code, usize::try_from(code_offset).unwrap())?;
            if relocation.code_offset != code_offset
                || relocation.kind
                    != instruction
                        .expected_relocation_kind()
                        .ok_or(invalid_v2("v2 relocation instruction"))?
                || relocation.target != RelocationTargetV2::CodeOffset(target)
                || relocation.resolved_word != word
            {
                return Err(invalid_v2("v2 relocation mismatch"));
            }
            relocation_index = relocation_index
                .checked_add(1)
                .ok_or(audit_arithmetic_v2())?;
        }
    }
    if relocation_index != image.relocations.len()
        || direct_branches != image.stats.relocations
        || vector_instructions != image.stats.vector_instructions
        || stores != 1
        || returns != (if literal.is_empty() { 2 } else { 1 })
        || (literal_len >= 2 && (simd_candidate_blocks != 2 || sparse_lane_recoveries != 1))
        || (literal_len < 2 && (simd_candidate_blocks != 0 || sparse_lane_recoveries != 0))
        || staged_filter_checks
            != u32::from(
                independent_filter
                    .map_or(0, AuditCandidateFilterV2::len)
                    .saturating_sub(3),
            )
    {
        return Err(invalid_v2("v2 decoded summary"));
    }
    let required_features = if vector_instructions == 0 {
        AotCountCpuFeatures::NONE
    } else {
        AotCountCpuFeatures::ASIMD
    };
    if image.target.features != required_features {
        return Err(invalid_v2("v2 decoded target features"));
    }

    let report = CountAuditReportV2 {
        decode_passes: 1,
        source_identity_rebuilds: 0,
        instructions: u32::try_from(instruction_count).map_err(|_| audit_arithmetic_v2())?,
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
            || image.stats.identity_bytes_hashed != artifact_identity_encoded_len_v2(image)?
            || image.stats.identity_bytes_hashed > prospective.identity_bytes_hashed
            || compute_artifact_identity_v2(image)?.0 != image.artifact_identity)
    {
        return Err(invalid_v2("v2 sealed receipt or identity"));
    }
    Ok(report)
}

fn independent_preflight_v2(
    program: &ExactAggregateProgram<Count>,
) -> Result<usize, CountAotError> {
    if program.output() != AggregateOutput::Count {
        return Err(invalid_v2("v2 audit output"));
    }
    let literal_len = program.literal().len();
    if literal_len > MAX_EXACT_AGGREGATE_LITERAL_BYTES || literal_len > 32 {
        return Err(invalid_v2("v2 audit literal width"));
    }
    // The typed exact-Count program is the structural-shape witness. Safe
    // callers cannot forge or mutate its private fixed-shape KIR payload.
    Ok(literal_len)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PolicyInstructionV2 {
    Exact(DecodedInstructionV2),
    Branch(PolicyLabelV2),
    BranchCondition {
        condition: ConditionV2,
        target: PolicyLabelV2,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PolicyLabelV2(u32);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PolicyLabelRecordV2 {
    offset: Option<u32>,
    kind: LabelKindV2,
}

struct PolicySinkV2 {
    instructions: ExactVec<PolicyInstructionV2>,
    labels: ExactVec<PolicyLabelRecordV2>,
    prospective: ProspectiveV2,
}

struct ResolvedPolicyV2 {
    instructions: ExactVec<DecodedInstructionV2>,
    labels: ExactVec<CodeLabelV2>,
}

impl PolicySinkV2 {
    fn new(prospective: ProspectiveV2) -> Result<Self, CountAotError> {
        Ok(Self {
            instructions: audit_exact_vec_v2(prospective.code_bytes / 4, prospective)?,
            labels: audit_exact_vec_v2(prospective.labels, prospective)?,
            prospective,
        })
    }

    fn new_label(&mut self, kind: LabelKindV2) -> Result<PolicyLabelV2, CountAotError> {
        let label =
            PolicyLabelV2(u32::try_from(self.labels.len()).map_err(|_| audit_arithmetic_v2())?);
        audit_push_v2(
            &mut self.labels,
            PolicyLabelRecordV2 { offset: None, kind },
            "v2 policy label capacity",
        )?;
        Ok(label)
    }

    fn bind(&mut self, label: PolicyLabelV2) -> Result<(), CountAotError> {
        let offset = u32::try_from(
            self.instructions
                .len()
                .checked_mul(4)
                .ok_or(audit_arithmetic_v2())?,
        )
        .map_err(|_| audit_arithmetic_v2())?;
        let record = self
            .labels
            .get_mut(usize::try_from(label.0).expect("u32 fits usize"))
            .ok_or(invalid_v2("v2 policy label"))?;
        if record.offset.replace(offset).is_some() {
            return Err(invalid_v2("v2 policy label rebound"));
        }
        Ok(())
    }

    fn exact(&mut self, instruction: DecodedInstructionV2) -> Result<(), CountAotError> {
        audit_push_v2(
            &mut self.instructions,
            PolicyInstructionV2::Exact(instruction),
            "v2 policy instruction capacity",
        )
    }

    fn branch(&mut self, target: PolicyLabelV2) -> Result<(), CountAotError> {
        audit_push_v2(
            &mut self.instructions,
            PolicyInstructionV2::Branch(target),
            "v2 policy instruction capacity",
        )
    }

    fn condition(
        &mut self,
        condition: ConditionV2,
        target: PolicyLabelV2,
    ) -> Result<(), CountAotError> {
        audit_push_v2(
            &mut self.instructions,
            PolicyInstructionV2::BranchCondition { condition, target },
            "v2 policy instruction capacity",
        )
    }

    fn resolve(self) -> Result<ResolvedPolicyV2, CountAotError> {
        let mut instructions = audit_exact_vec_v2(self.instructions.len(), self.prospective)?;
        for (index, instruction) in self.instructions.iter().copied().enumerate() {
            let offset = i64::try_from(index.checked_mul(4).ok_or(audit_arithmetic_v2())?)
                .map_err(|_| audit_arithmetic_v2())?;
            let decoded = match instruction {
                PolicyInstructionV2::Exact(instruction) => instruction,
                PolicyInstructionV2::Branch(target) => {
                    let target = self
                        .labels
                        .get(usize::try_from(target.0).expect("u32 fits usize"))
                        .and_then(|record| record.offset)
                        .ok_or(invalid_v2("v2 unresolved policy branch"))?;
                    DecodedInstructionV2::Branch {
                        displacement: i32::try_from(i64::from(target) - offset)
                            .map_err(|_| audit_arithmetic_v2())?,
                    }
                }
                PolicyInstructionV2::BranchCondition { condition, target } => {
                    let target = self
                        .labels
                        .get(usize::try_from(target.0).expect("u32 fits usize"))
                        .and_then(|record| record.offset)
                        .ok_or(invalid_v2("v2 unresolved policy branch"))?;
                    DecodedInstructionV2::BranchCondition {
                        condition,
                        displacement: i32::try_from(i64::from(target) - offset)
                            .map_err(|_| audit_arithmetic_v2())?,
                    }
                }
            };
            audit_push_v2(&mut instructions, decoded, "v2 resolved policy capacity")?;
        }
        let mut labels = audit_exact_vec_v2(self.labels.len(), self.prospective)?;
        for record in self.labels.iter().copied() {
            audit_push_v2(
                &mut labels,
                CodeLabelV2 {
                    offset: record
                        .offset
                        .ok_or(invalid_v2("v2 unresolved policy label"))?,
                    kind: record.kind,
                },
                "v2 resolved policy label capacity",
            )?;
        }
        order_policy_labels_v2(&mut labels)?;
        Ok(ResolvedPolicyV2 {
            instructions,
            labels,
        })
    }
}

fn order_policy_labels_v2(labels: &mut [CodeLabelV2]) -> Result<(), CountAotError> {
    let budget = label_order_work_upper_bound_v2(labels.len())?;
    let mut comparisons = 0_u64;
    let mut moves = 0_u64;
    let mut placements = 0_u64;
    for insertion in 1..labels.len() {
        let key = labels[insertion];
        let mut cursor = insertion;
        while cursor != 0 {
            comparisons = comparisons.checked_add(1).ok_or(audit_arithmetic_v2())?;
            let previous_index = cursor.checked_sub(1).ok_or(audit_arithmetic_v2())?;
            let previous = labels[previous_index];
            if previous <= key {
                break;
            }
            labels[cursor] = previous;
            moves = moves.checked_add(1).ok_or(audit_arithmetic_v2())?;
            cursor = previous_index;
        }
        labels[cursor] = key;
        placements = placements.checked_add(1).ok_or(audit_arithmetic_v2())?;
    }
    if comparisons > budget.comparisons || moves > budget.moves || placements != budget.placements {
        return Err(invalid_v2("v2 policy label order work"));
    }
    Ok(())
}

fn independent_policy_template_v2(
    literal: &[u8],
    filter: Option<AuditCandidateFilterV2>,
    prospective: ProspectiveV2,
) -> Result<ResolvedPolicyV2, CountAotError> {
    let mut policy = PolicySinkV2::new(prospective)?;
    let entry = policy.new_label(LabelKindV2::Entry)?;
    let done = policy.new_label(LabelKindV2::Success)?;
    policy.bind(entry)?;
    match literal.len() {
        0 => policy_empty_v2(&mut policy, done)?,
        1 => policy_single_v2(&mut policy, literal[0], done)?,
        _ => policy_multi_v2(
            &mut policy,
            literal,
            filter.ok_or(invalid_v2("v2 policy filter"))?,
            done,
        )?,
    }
    policy.bind(done)?;
    exact_v2(
        &mut policy,
        DecodedInstructionV2::Store64 {
            source: X13,
            base: X2,
            offset: 0,
        },
    )?;
    policy_mov_minimal_v2(&mut policy, X0, 0)?;
    exact_v2(&mut policy, DecodedInstructionV2::Return)?;
    policy.resolve()
}

fn policy_empty_v2(policy: &mut PolicySinkV2, done: PolicyLabelV2) -> Result<(), CountAotError> {
    let overflow = policy.new_label(LabelKindV2::Overflow)?;
    policy_mov_minimal_v2(policy, X10, u64::MAX)?;
    exact_v2(
        policy,
        DecodedInstructionV2::CompareRegister64 {
            left: X1,
            right: X10,
        },
    )?;
    condition_v2(policy, ConditionV2::Equal, overflow)?;
    exact_v2(
        policy,
        DecodedInstructionV2::AddImmediate64 {
            destination: X13,
            source: X1,
            immediate: 1,
        },
    )?;
    branch_v2(policy, done)?;
    policy.bind(overflow)?;
    policy_mov_minimal_v2(policy, X0, 1)?;
    exact_v2(policy, DecodedInstructionV2::Return)
}

#[allow(
    clippy::too_many_lines,
    reason = "the independent single-byte policy mirrors the complete admitted instruction sequence"
)]
fn policy_single_v2(
    policy: &mut PolicySinkV2,
    literal: u8,
    done: PolicyLabelV2,
) -> Result<(), CountAotError> {
    let vector = policy.new_label(LabelKindV2::VectorLoop)?;
    let tail = policy.new_label(LabelKindV2::ScalarTail)?;
    let miss = policy.new_label(LabelKindV2::Miss)?;
    policy_mov_minimal_v2(policy, X13, 0)?;
    policy_mov_minimal_v2(policy, X3, 0)?;
    policy_mov_minimal_v2(policy, X10, u64::from(literal))?;
    exact_v2(
        policy,
        DecodedInstructionV2::DuplicateByte16 {
            destination: 1,
            source: X10,
        },
    )?;
    policy_mov_minimal_v2(policy, X5, 256)?;
    policy.bind(vector)?;
    exact_v2(
        policy,
        DecodedInstructionV2::SubtractRegister64 {
            destination: X6,
            left: X1,
            right: X3,
        },
    )?;
    exact_v2(
        policy,
        DecodedInstructionV2::CompareImmediate64 {
            register: X6,
            immediate: SIMD_CANDIDATE_STARTS_V2,
        },
    )?;
    condition_v2(policy, ConditionV2::CarryClear, tail)?;
    exact_v2(
        policy,
        DecodedInstructionV2::AddRegister64 {
            destination: X15,
            left: X0,
            right: X3,
        },
    )?;
    exact_v2(
        policy,
        DecodedInstructionV2::LoadVector128 {
            destination: 0,
            base: X15,
            offset: 0,
        },
    )?;
    exact_v2(
        policy,
        DecodedInstructionV2::CompareEqualBytes16 {
            destination: 0,
            left: 0,
            right: 1,
        },
    )?;
    exact_v2(
        policy,
        DecodedInstructionV2::AddAcrossBytes16 {
            destination: 0,
            source: 0,
        },
    )?;
    exact_v2(
        policy,
        DecodedInstructionV2::MoveVectorByteTo32 {
            destination: X6,
            source: 0,
        },
    )?;
    exact_v2(
        policy,
        DecodedInstructionV2::SubtractRegister64 {
            destination: X6,
            left: X5,
            right: X6,
        },
    )?;
    exact_v2(
        policy,
        DecodedInstructionV2::AndLowBits64 {
            destination: X6,
            source: X6,
            bits: 8,
        },
    )?;
    exact_v2(
        policy,
        DecodedInstructionV2::AddRegister64 {
            destination: X13,
            left: X13,
            right: X6,
        },
    )?;
    exact_v2(
        policy,
        DecodedInstructionV2::AddImmediate64 {
            destination: X3,
            source: X3,
            immediate: SIMD_CANDIDATE_STARTS_V2,
        },
    )?;
    branch_v2(policy, vector)?;
    policy.bind(tail)?;
    exact_v2(
        policy,
        DecodedInstructionV2::CompareRegister64 {
            left: X3,
            right: X1,
        },
    )?;
    condition_v2(policy, ConditionV2::CarrySet, done)?;
    exact_v2(
        policy,
        DecodedInstructionV2::LoadByteRegister {
            destination: X6,
            base: X0,
            index: X3,
        },
    )?;
    exact_v2(
        policy,
        DecodedInstructionV2::CompareRegister32 {
            left: X6,
            right: X10,
        },
    )?;
    condition_v2(policy, ConditionV2::NotEqual, miss)?;
    exact_v2(
        policy,
        DecodedInstructionV2::AddImmediate64 {
            destination: X13,
            source: X13,
            immediate: 1,
        },
    )?;
    policy.bind(miss)?;
    exact_v2(
        policy,
        DecodedInstructionV2::AddImmediate64 {
            destination: X3,
            source: X3,
            immediate: 1,
        },
    )?;
    branch_v2(policy, tail)
}

#[allow(
    clippy::too_many_lines,
    reason = "the independent full-template policy mirrors semantics, not emitter code"
)]
fn policy_multi_v2(
    policy: &mut PolicySinkV2,
    literal: &[u8],
    filter: AuditCandidateFilterV2,
    done: PolicyLabelV2,
) -> Result<(), CountAotError> {
    let vector = policy.new_label(LabelKindV2::VectorLoop)?;
    let sparse_scan = policy.new_label(LabelKindV2::VectorLoop)?;
    let sparse_hit = policy.new_label(LabelKindV2::Internal)?;
    let sparse_first_half = policy.new_label(LabelKindV2::Internal)?;
    let pair_absent = policy.new_label(LabelKindV2::Internal)?;
    let pair_single = policy.new_label(LabelKindV2::Internal)?;
    let pair_dense = policy.new_label(LabelKindV2::Internal)?;
    let candidate = policy.new_label(LabelKindV2::CandidateLoop)?;
    let candidate_miss = policy.new_label(LabelKindV2::Miss)?;
    let block_advance = policy.new_label(LabelKindV2::Internal)?;
    let dense_scan = policy.new_label(LabelKindV2::VectorLoop)?;
    let dense_absent = policy.new_label(LabelKindV2::Internal)?;
    let match_run = policy.new_label(LabelKindV2::CandidateLoop)?;
    let match_run_miss = policy.new_label(LabelKindV2::Miss)?;
    let scalar = policy.new_label(LabelKindV2::ScalarTail)?;
    let scalar_miss = policy.new_label(LabelKindV2::Miss)?;
    let width = u16::try_from(literal.len()).expect("bounded width");
    let primary = u16::from(filter.offsets[0]);
    let secondary = u16::from(filter.offsets[1]);
    policy_mov_minimal_v2(policy, X13, 0)?;
    compare_immediate64_v2(policy, X1, width)?;
    condition_v2(policy, ConditionV2::CarryClear, done)?;
    subtract_immediate64_v2(policy, X4, X1, width)?;
    policy_mov_minimal_v2(policy, X3, 0)?;
    policy_mov_minimal_v2(
        policy,
        X10,
        u64::from(literal[usize::from(filter.offsets[0])]),
    )?;
    policy_mov_minimal_v2(
        policy,
        X11,
        u64::from(literal[usize::from(filter.offsets[1])]),
    )?;
    exact_v2(
        policy,
        DecodedInstructionV2::DuplicateByte16 {
            destination: 2,
            source: X10,
        },
    )?;
    exact_v2(
        policy,
        DecodedInstructionV2::DuplicateByte16 {
            destination: 3,
            source: X11,
        },
    )?;
    if filter.len >= 3 {
        policy_mov_minimal_v2(
            policy,
            X12,
            u64::from(literal[usize::from(filter.offsets[2])]),
        )?;
        exact_v2(
            policy,
            DecodedInstructionV2::DuplicateByte16 {
                destination: 16,
                source: X12,
            },
        )?;
    }
    if filter.len >= 4 {
        policy_mov_minimal_v2(
            policy,
            X14,
            u64::from(literal[usize::from(filter.offsets[3])]),
        )?;
        exact_v2(
            policy,
            DecodedInstructionV2::DuplicateByte16 {
                destination: 17,
                source: X14,
            },
        )?;
    }
    policy_mov_minimal_v2(policy, X17, SPARSE_NIBBLE_BITS_V2)?;
    policy_mov_minimal_v2(policy, X8, u64::from(literal[0]))?;
    exact_v2(
        policy,
        DecodedInstructionV2::DuplicateByte16 {
            destination: 19,
            source: X8,
        },
    )?;
    policy_mov_minimal_v2(
        policy,
        X8,
        u64::from(literal[literal.len().checked_sub(1).expect("nonempty literal")]),
    )?;
    exact_v2(
        policy,
        DecodedInstructionV2::DuplicateByte16 {
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
        policy_mov_minimal_v2(policy, X8, u64::from_le_bytes(low))?;
        exact_v2(
            policy,
            DecodedInstructionV2::Move64ToVectorDouble {
                destination: vector,
                source: X8,
            },
        )?;
        policy_mov_minimal_v2(policy, X8, u64::from_le_bytes(high))?;
        exact_v2(
            policy,
            DecodedInstructionV2::Insert64ToVectorDoubleLane1 {
                destination: vector,
                source: X8,
            },
        )?;
    }
    let full_vector_bytes = literal.len() / 16 * 16;
    for (tail_index, chunk) in literal[full_vector_bytes..].chunks_exact(8).enumerate() {
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(chunk);
        policy_mov_minimal_v2(policy, X8, u64::from_le_bytes(bytes))?;
        let global_chunk = full_vector_bytes / 8 + tail_index;
        exact_v2(
            policy,
            DecodedInstructionV2::Move64ToVectorDouble {
                destination: u8::try_from(4 + global_chunk).expect("at most v7"),
                source: X8,
            },
        )?;
    }
    policy.bind(vector)?;
    compare_register64_v2(policy, X3, X4)?;
    condition_v2(policy, ConditionV2::Higher, done)?;
    subtract_register64_v2(policy, X5, X4, X3)?;
    compare_immediate64_v2(policy, X5, 15)?;
    condition_v2(policy, ConditionV2::CarryClear, scalar)?;
    add_register64_v2(policy, X15, X0, X3)?;
    add_immediate64_v2(policy, X8, X15, primary)?;
    exact_v2(
        policy,
        DecodedInstructionV2::LoadVector128 {
            destination: 0,
            base: X8,
            offset: 0,
        },
    )?;
    add_immediate64_v2(policy, X9, X15, secondary)?;
    exact_v2(
        policy,
        DecodedInstructionV2::LoadVector128 {
            destination: 1,
            base: X9,
            offset: 0,
        },
    )?;
    exact_v2(
        policy,
        DecodedInstructionV2::CompareEqualBytes16 {
            destination: 0,
            left: 0,
            right: 2,
        },
    )?;
    exact_v2(
        policy,
        DecodedInstructionV2::CompareEqualBytes16 {
            destination: 1,
            left: 1,
            right: 3,
        },
    )?;
    exact_v2(
        policy,
        DecodedInstructionV2::AndBytes16 {
            destination: 0,
            left: 0,
            right: 1,
        },
    )?;
    exact_v2(
        policy,
        DecodedInstructionV2::AddAcrossBytes16 {
            destination: 1,
            source: 0,
        },
    )?;
    exact_v2(
        policy,
        DecodedInstructionV2::MoveVectorByteTo32 {
            destination: X8,
            source: 1,
        },
    )?;
    compare_immediate64_v2(policy, X8, 0)?;
    condition_v2(policy, ConditionV2::Equal, pair_absent)?;
    compare_immediate64_v2(policy, X8, 255)?;
    condition_v2(policy, ConditionV2::NotEqual, pair_dense)?;

    policy.bind(pair_single)?;
    if filter.len >= 3 {
        add_immediate64_v2(policy, X8, X15, u16::from(filter.offsets[2]))?;
        exact_v2(
            policy,
            DecodedInstructionV2::LoadVector128 {
                destination: 1,
                base: X8,
                offset: 0,
            },
        )?;
        exact_v2(
            policy,
            DecodedInstructionV2::CompareEqualBytes16 {
                destination: 1,
                left: 1,
                right: 16,
            },
        )?;
        exact_v2(
            policy,
            DecodedInstructionV2::AndBytes16 {
                destination: 0,
                left: 0,
                right: 1,
            },
        )?;
    }
    if filter.len >= 4 {
        exact_v2(
            policy,
            DecodedInstructionV2::UnsignedMaxAcrossBytes16 {
                destination: 1,
                source: 0,
            },
        )?;
        exact_v2(
            policy,
            DecodedInstructionV2::MoveVectorByteTo32 {
                destination: X8,
                source: 1,
            },
        )?;
        compare_immediate64_v2(policy, X8, 0)?;
        condition_v2(policy, ConditionV2::Equal, block_advance)?;
        add_immediate64_v2(policy, X8, X15, u16::from(filter.offsets[3]))?;
        exact_v2(
            policy,
            DecodedInstructionV2::LoadVector128 {
                destination: 1,
                base: X8,
                offset: 0,
            },
        )?;
        exact_v2(
            policy,
            DecodedInstructionV2::CompareEqualBytes16 {
                destination: 1,
                left: 1,
                right: 17,
            },
        )?;
        exact_v2(
            policy,
            DecodedInstructionV2::AndBytes16 {
                destination: 0,
                left: 0,
                right: 1,
            },
        )?;
    }
    exact_v2(
        policy,
        DecodedInstructionV2::ShrinkNarrowBytesFromHalfwords {
            destination: 0,
            source: 0,
            shift: 4,
        },
    )?;
    exact_v2(
        policy,
        DecodedInstructionV2::MoveVectorDoubleTo64 {
            destination: X6,
            source: 0,
        },
    )?;
    exact_v2(
        policy,
        DecodedInstructionV2::AndRegister64 {
            destination: X6,
            left: X6,
            right: X17,
        },
    )?;
    compare_immediate64_v2(policy, X6, 0)?;
    condition_v2(policy, ConditionV2::Equal, block_advance)?;
    branch_v2(policy, candidate)?;

    policy.bind(pair_dense)?;
    exact_v2(
        policy,
        DecodedInstructionV2::OrBytes16 {
            destination: 18,
            left: 0,
            right: 0,
        },
    )?;
    exact_v2(
        policy,
        DecodedInstructionV2::LoadVector128 {
            destination: 0,
            base: X15,
            offset: 0,
        },
    )?;
    exact_v2(
        policy,
        DecodedInstructionV2::CompareEqualBytes16 {
            destination: 0,
            left: 0,
            right: 19,
        },
    )?;
    add_immediate64_v2(
        policy,
        X8,
        X15,
        u16::try_from(literal.len() - 1).expect("bounded last offset"),
    )?;
    exact_v2(
        policy,
        DecodedInstructionV2::LoadVector128 {
            destination: 1,
            base: X8,
            offset: 0,
        },
    )?;
    exact_v2(
        policy,
        DecodedInstructionV2::CompareEqualBytes16 {
            destination: 1,
            left: 1,
            right: 20,
        },
    )?;
    exact_v2(
        policy,
        DecodedInstructionV2::AndBytes16 {
            destination: 0,
            left: 0,
            right: 1,
        },
    )?;
    exact_v2(
        policy,
        DecodedInstructionV2::AndBytes16 {
            destination: 0,
            left: 0,
            right: 18,
        },
    )?;
    exact_v2(
        policy,
        DecodedInstructionV2::ShrinkNarrowBytesFromHalfwords {
            destination: 0,
            source: 0,
            shift: 4,
        },
    )?;
    exact_v2(
        policy,
        DecodedInstructionV2::MoveVectorDoubleTo64 {
            destination: X6,
            source: 0,
        },
    )?;
    exact_v2(
        policy,
        DecodedInstructionV2::AndRegister64 {
            destination: X6,
            left: X6,
            right: X17,
        },
    )?;
    compare_immediate64_v2(policy, X6, 0)?;
    condition_v2(policy, ConditionV2::Equal, dense_absent)?;
    branch_v2(policy, candidate)?;

    policy.bind(candidate)?;
    exact_v2(
        policy,
        DecodedInstructionV2::ReverseBits64 {
            destination: X7,
            source: X6,
        },
    )?;
    exact_v2(
        policy,
        DecodedInstructionV2::CountLeadingZeros64 {
            destination: X7,
            source: X7,
        },
    )?;
    subtract_immediate64_v2(policy, X16, X6, 1)?;
    exact_v2(
        policy,
        DecodedInstructionV2::AndRegister64 {
            destination: X6,
            left: X6,
            right: X16,
        },
    )?;
    exact_v2(
        policy,
        DecodedInstructionV2::LogicalShiftRight64 {
            destination: X7,
            source: X7,
            shift: 2,
        },
    )?;
    add_register64_v2(policy, X5, X3, X7)?;
    add_register64_v2(policy, X15, X0, X5)?;
    policy_confirmation_v2(policy, literal, X15, candidate_miss)?;
    add_immediate64_v2(policy, X13, X13, 1)?;
    add_immediate64_v2(policy, X3, X5, width)?;
    branch_v2(policy, match_run)?;
    policy.bind(candidate_miss)?;
    compare_immediate64_v2(policy, X6, 0)?;
    condition_v2(policy, ConditionV2::NotEqual, candidate)?;
    policy.bind(block_advance)?;
    add_immediate64_v2(policy, X3, X3, SIMD_CANDIDATE_STARTS_V2)?;
    branch_v2(policy, vector)?;

    policy.bind(match_run)?;
    compare_register64_v2(policy, X3, X4)?;
    condition_v2(policy, ConditionV2::Higher, done)?;
    add_register64_v2(policy, X15, X0, X3)?;
    policy_confirmation_v2(policy, literal, X15, match_run_miss)?;
    add_immediate64_v2(policy, X13, X13, 1)?;
    add_immediate64_v2(policy, X3, X3, width)?;
    branch_v2(policy, match_run)?;
    policy.bind(match_run_miss)?;
    add_immediate64_v2(policy, X3, X3, 1)?;
    branch_v2(policy, vector)?;

    policy.bind(dense_absent)?;
    add_immediate64_v2(policy, X3, X3, SIMD_CANDIDATE_STARTS_V2)?;
    branch_v2(policy, dense_scan)?;
    policy.bind(dense_scan)?;
    compare_register64_v2(policy, X3, X4)?;
    condition_v2(policy, ConditionV2::Higher, done)?;
    subtract_register64_v2(policy, X5, X4, X3)?;
    compare_immediate64_v2(policy, X5, SPARSE_SCAN_STARTS_V2 - 1)?;
    condition_v2(policy, ConditionV2::CarryClear, vector)?;
    add_register64_v2(policy, X15, X0, X3)?;
    add_immediate64_v2(
        policy,
        X9,
        X15,
        u16::try_from(literal.len() - 1).expect("bounded last offset"),
    )?;
    for block in 0..SPARSE_SCAN_BLOCKS_V2 {
        let offset = block
            .checked_mul(SIMD_CANDIDATE_STARTS_V2)
            .ok_or(audit_arithmetic_v2())?;
        exact_v2(
            policy,
            DecodedInstructionV2::LoadVector128 {
                destination: 0,
                base: X15,
                offset,
            },
        )?;
        exact_v2(
            policy,
            DecodedInstructionV2::LoadVector128 {
                destination: 1,
                base: X9,
                offset,
            },
        )?;
        exact_v2(
            policy,
            DecodedInstructionV2::CompareEqualBytes16 {
                destination: 0,
                left: 0,
                right: 19,
            },
        )?;
        exact_v2(
            policy,
            DecodedInstructionV2::CompareEqualBytes16 {
                destination: 1,
                left: 1,
                right: 20,
            },
        )?;
        if block == 0 {
            exact_v2(
                policy,
                DecodedInstructionV2::AndBytes16 {
                    destination: 18,
                    left: 0,
                    right: 1,
                },
            )?;
        } else {
            exact_v2(
                policy,
                DecodedInstructionV2::AndBytes16 {
                    destination: 0,
                    left: 0,
                    right: 1,
                },
            )?;
            exact_v2(
                policy,
                DecodedInstructionV2::OrBytes16 {
                    destination: 18,
                    left: 18,
                    right: 0,
                },
            )?;
        }
    }
    exact_v2(
        policy,
        DecodedInstructionV2::UnsignedMaxAcrossBytes16 {
            destination: 1,
            source: 18,
        },
    )?;
    exact_v2(
        policy,
        DecodedInstructionV2::MoveVectorByteTo32 {
            destination: X8,
            source: 1,
        },
    )?;
    compare_immediate64_v2(policy, X8, 0)?;
    condition_v2(policy, ConditionV2::NotEqual, vector)?;
    add_immediate64_v2(policy, X3, X3, SPARSE_SCAN_STARTS_V2)?;
    branch_v2(policy, dense_scan)?;

    policy.bind(pair_absent)?;
    add_immediate64_v2(policy, X3, X3, SIMD_CANDIDATE_STARTS_V2)?;
    branch_v2(policy, sparse_scan)?;
    policy.bind(sparse_scan)?;
    compare_register64_v2(policy, X3, X4)?;
    condition_v2(policy, ConditionV2::Higher, done)?;
    subtract_register64_v2(policy, X5, X4, X3)?;
    compare_immediate64_v2(policy, X5, SPARSE_SCAN_STARTS_V2 - 1)?;
    condition_v2(policy, ConditionV2::CarryClear, vector)?;
    add_register64_v2(policy, X15, X0, X3)?;
    add_immediate64_v2(policy, X8, X15, primary)?;
    add_immediate64_v2(policy, X9, X15, secondary)?;
    for block in 0..SPARSE_SCAN_BLOCKS_V2 {
        let offset = block
            .checked_mul(SIMD_CANDIDATE_STARTS_V2)
            .ok_or(audit_arithmetic_v2())?;
        exact_v2(
            policy,
            DecodedInstructionV2::LoadVector128 {
                destination: 0,
                base: X8,
                offset,
            },
        )?;
        exact_v2(
            policy,
            DecodedInstructionV2::LoadVector128 {
                destination: 1,
                base: X9,
                offset,
            },
        )?;
        exact_v2(
            policy,
            DecodedInstructionV2::CompareEqualBytes16 {
                destination: 0,
                left: 0,
                right: 2,
            },
        )?;
        exact_v2(
            policy,
            DecodedInstructionV2::CompareEqualBytes16 {
                destination: 1,
                left: 1,
                right: 3,
            },
        )?;
        exact_v2(
            policy,
            DecodedInstructionV2::AndBytes16 {
                destination: u8::try_from(u16::from(SPARSE_BLOCK_MASK_BASE_V2) + block)
                    .expect("four caller-saved sparse block masks"),
                left: 0,
                right: 1,
            },
        )?;
    }
    exact_v2(
        policy,
        DecodedInstructionV2::OrBytes16 {
            destination: SPARSE_FIRST_HALF_MASK_V2,
            left: SPARSE_BLOCK_MASK_BASE_V2,
            right: SPARSE_BLOCK_MASK_BASE_V2 + 1,
        },
    )?;
    exact_v2(
        policy,
        DecodedInstructionV2::OrBytes16 {
            destination: SPARSE_SECOND_HALF_MASK_V2,
            left: SPARSE_BLOCK_MASK_BASE_V2 + 2,
            right: SPARSE_BLOCK_MASK_BASE_V2 + 3,
        },
    )?;
    exact_v2(
        policy,
        DecodedInstructionV2::OrBytes16 {
            destination: 18,
            left: SPARSE_FIRST_HALF_MASK_V2,
            right: SPARSE_SECOND_HALF_MASK_V2,
        },
    )?;
    exact_v2(
        policy,
        DecodedInstructionV2::UnsignedMaxAcrossBytes16 {
            destination: 1,
            source: 18,
        },
    )?;
    exact_v2(
        policy,
        DecodedInstructionV2::MoveVectorByteTo32 {
            destination: X8,
            source: 1,
        },
    )?;
    compare_immediate64_v2(policy, X8, 0)?;
    condition_v2(policy, ConditionV2::NotEqual, sparse_hit)?;
    add_immediate64_v2(policy, X3, X3, SPARSE_SCAN_STARTS_V2)?;
    branch_v2(policy, sparse_scan)?;
    policy.bind(sparse_hit)?;
    exact_v2(
        policy,
        DecodedInstructionV2::UnsignedMaxAcrossBytes16 {
            destination: 1,
            source: SPARSE_FIRST_HALF_MASK_V2,
        },
    )?;
    exact_v2(
        policy,
        DecodedInstructionV2::MoveVectorByteTo32 {
            destination: X8,
            source: 1,
        },
    )?;
    compare_immediate64_v2(policy, X8, 0)?;
    condition_v2(policy, ConditionV2::NotEqual, sparse_first_half)?;
    add_immediate64_v2(policy, X3, X3, SIMD_CANDIDATE_STARTS_V2 * 2)?;
    exact_v2(
        policy,
        DecodedInstructionV2::UnsignedMaxAcrossBytes16 {
            destination: 1,
            source: SPARSE_BLOCK_MASK_BASE_V2 + 2,
        },
    )?;
    exact_v2(
        policy,
        DecodedInstructionV2::MoveVectorByteTo32 {
            destination: X8,
            source: 1,
        },
    )?;
    compare_immediate64_v2(policy, X8, 0)?;
    condition_v2(policy, ConditionV2::NotEqual, vector)?;
    add_immediate64_v2(policy, X3, X3, SIMD_CANDIDATE_STARTS_V2)?;
    branch_v2(policy, vector)?;
    policy.bind(sparse_first_half)?;
    exact_v2(
        policy,
        DecodedInstructionV2::UnsignedMaxAcrossBytes16 {
            destination: 1,
            source: SPARSE_BLOCK_MASK_BASE_V2,
        },
    )?;
    exact_v2(
        policy,
        DecodedInstructionV2::MoveVectorByteTo32 {
            destination: X8,
            source: 1,
        },
    )?;
    compare_immediate64_v2(policy, X8, 0)?;
    condition_v2(policy, ConditionV2::NotEqual, vector)?;
    add_immediate64_v2(policy, X3, X3, SIMD_CANDIDATE_STARTS_V2)?;
    branch_v2(policy, vector)?;

    policy.bind(scalar)?;
    compare_register64_v2(policy, X3, X4)?;
    condition_v2(policy, ConditionV2::Higher, done)?;
    add_register64_v2(policy, X15, X0, X3)?;
    load_byte_v2(policy, X8, X15, primary)?;
    compare_register32_v2(policy, X8, X10)?;
    condition_v2(policy, ConditionV2::NotEqual, scalar_miss)?;
    load_byte_v2(policy, X8, X15, secondary)?;
    compare_register32_v2(policy, X8, X11)?;
    condition_v2(policy, ConditionV2::NotEqual, scalar_miss)?;
    if filter.len >= 3 {
        load_byte_v2(policy, X8, X15, u16::from(filter.offsets[2]))?;
        compare_register32_v2(policy, X8, X12)?;
        condition_v2(policy, ConditionV2::NotEqual, scalar_miss)?;
    }
    if filter.len >= 4 {
        load_byte_v2(policy, X8, X15, u16::from(filter.offsets[3]))?;
        compare_register32_v2(policy, X8, X14)?;
        condition_v2(policy, ConditionV2::NotEqual, scalar_miss)?;
    }
    policy_confirmation_v2(policy, literal, X15, scalar_miss)?;
    add_immediate64_v2(policy, X13, X13, 1)?;
    add_immediate64_v2(policy, X3, X3, width)?;
    branch_v2(policy, match_run)?;
    policy.bind(scalar_miss)?;
    add_immediate64_v2(policy, X3, X3, 1)?;
    branch_v2(policy, scalar)
}

fn policy_confirmation_v2(
    policy: &mut PolicySinkV2,
    literal: &[u8],
    candidate_pointer: u8,
    mismatch: PolicyLabelV2,
) -> Result<(), CountAotError> {
    let vector_chunks = literal.len() / 16;
    for chunk_index in 0..vector_chunks {
        exact_v2(
            policy,
            DecodedInstructionV2::LoadVector128 {
                destination: 0,
                base: candidate_pointer,
                offset: u16::try_from(chunk_index * 16).expect("bounded offset"),
            },
        )?;
        exact_v2(
            policy,
            DecodedInstructionV2::CompareEqualBytes16 {
                destination: 0,
                left: 0,
                right: u8::try_from(21 + chunk_index).expect("at most v22"),
            },
        )?;
        exact_v2(
            policy,
            DecodedInstructionV2::UnsignedMinAcrossBytes16 {
                destination: 0,
                source: 0,
            },
        )?;
        exact_v2(
            policy,
            DecodedInstructionV2::MoveVectorByteTo32 {
                destination: X8,
                source: 0,
            },
        )?;
        exact_v2(
            policy,
            DecodedInstructionV2::CompareImmediate32 {
                register: X8,
                immediate: 255,
            },
        )?;
        condition_v2(policy, ConditionV2::NotEqual, mismatch)?;
    }
    let vector_tail_offset = vector_chunks * 16;
    let double_chunks = (literal.len() - vector_tail_offset) / 8;
    for chunk_index in 0..double_chunks {
        let global_chunk = vector_tail_offset / 8 + chunk_index;
        exact_v2(
            policy,
            DecodedInstructionV2::LoadVectorDouble {
                destination: 0,
                base: candidate_pointer,
                offset: u16::try_from(vector_tail_offset + chunk_index * 8)
                    .expect("bounded offset"),
            },
        )?;
        exact_v2(
            policy,
            DecodedInstructionV2::CompareEqualBytes8 {
                destination: 0,
                left: 0,
                right: u8::try_from(4 + global_chunk).expect("at most v7"),
            },
        )?;
        exact_v2(
            policy,
            DecodedInstructionV2::UnsignedMinAcrossBytes8 {
                destination: 0,
                source: 0,
            },
        )?;
        exact_v2(
            policy,
            DecodedInstructionV2::MoveVectorByteTo32 {
                destination: X8,
                source: 0,
            },
        )?;
        exact_v2(
            policy,
            DecodedInstructionV2::CompareImmediate32 {
                register: X8,
                immediate: 255,
            },
        )?;
        condition_v2(policy, ConditionV2::NotEqual, mismatch)?;
    }
    let tail_offset = vector_tail_offset + double_chunks * 8;
    for (index, byte) in literal[tail_offset..].iter().copied().enumerate() {
        load_byte_v2(
            policy,
            X8,
            candidate_pointer,
            u16::try_from(tail_offset + index).expect("bounded offset"),
        )?;
        policy_mov_minimal_v2(policy, X9, u64::from(byte))?;
        compare_register32_v2(policy, X8, X9)?;
        condition_v2(policy, ConditionV2::NotEqual, mismatch)?;
    }
    Ok(())
}

fn policy_mov_minimal_v2(
    policy: &mut PolicySinkV2,
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
    exact_v2(
        policy,
        DecodedInstructionV2::MoveZero64 {
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
            exact_v2(
                policy,
                DecodedInstructionV2::MoveKeep64 {
                    destination,
                    immediate,
                    shift: halfword * 16,
                },
            )?;
        }
    }
    Ok(())
}

fn exact_v2(
    policy: &mut PolicySinkV2,
    instruction: DecodedInstructionV2,
) -> Result<(), CountAotError> {
    policy.exact(instruction)
}

fn branch_v2(policy: &mut PolicySinkV2, target: PolicyLabelV2) -> Result<(), CountAotError> {
    policy.branch(target)
}

fn condition_v2(
    policy: &mut PolicySinkV2,
    condition: ConditionV2,
    target: PolicyLabelV2,
) -> Result<(), CountAotError> {
    policy.condition(condition, target)
}

fn compare_register64_v2(
    policy: &mut PolicySinkV2,
    left: u8,
    right: u8,
) -> Result<(), CountAotError> {
    exact_v2(
        policy,
        DecodedInstructionV2::CompareRegister64 { left, right },
    )
}

fn compare_register32_v2(
    policy: &mut PolicySinkV2,
    left: u8,
    right: u8,
) -> Result<(), CountAotError> {
    exact_v2(
        policy,
        DecodedInstructionV2::CompareRegister32 { left, right },
    )
}

fn compare_immediate64_v2(
    policy: &mut PolicySinkV2,
    register: u8,
    immediate: u16,
) -> Result<(), CountAotError> {
    exact_v2(
        policy,
        DecodedInstructionV2::CompareImmediate64 {
            register,
            immediate,
        },
    )
}

fn add_register64_v2(
    policy: &mut PolicySinkV2,
    destination: u8,
    left: u8,
    right: u8,
) -> Result<(), CountAotError> {
    exact_v2(
        policy,
        DecodedInstructionV2::AddRegister64 {
            destination,
            left,
            right,
        },
    )
}

fn add_immediate64_v2(
    policy: &mut PolicySinkV2,
    destination: u8,
    source: u8,
    immediate: u16,
) -> Result<(), CountAotError> {
    exact_v2(
        policy,
        DecodedInstructionV2::AddImmediate64 {
            destination,
            source,
            immediate,
        },
    )
}

fn subtract_register64_v2(
    policy: &mut PolicySinkV2,
    destination: u8,
    left: u8,
    right: u8,
) -> Result<(), CountAotError> {
    exact_v2(
        policy,
        DecodedInstructionV2::SubtractRegister64 {
            destination,
            left,
            right,
        },
    )
}

fn subtract_immediate64_v2(
    policy: &mut PolicySinkV2,
    destination: u8,
    source: u8,
    immediate: u16,
) -> Result<(), CountAotError> {
    exact_v2(
        policy,
        DecodedInstructionV2::SubtractImmediate64 {
            destination,
            source,
            immediate,
        },
    )
}

fn load_byte_v2(
    policy: &mut PolicySinkV2,
    destination: u8,
    base: u8,
    offset: u16,
) -> Result<(), CountAotError> {
    exact_v2(
        policy,
        DecodedInstructionV2::LoadByte {
            destination,
            base,
            offset,
        },
    )
}

/// Independently pinned copy of the frequency table used by policy selection.
const AUDIT_FREQUENCY_RANK_V2: [u8; 256] = [
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
struct AuditCandidateFilterV2 {
    offsets: [u8; 4],
    len: u8,
}

impl AuditCandidateFilterV2 {
    fn offsets(&self) -> &[u8] {
        &self.offsets[..usize::from(self.len)]
    }

    const fn len(self) -> u8 {
        self.len
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct AuditFilterObservedWorkV2 {
    pub(crate) initial_byte_visits: u64,
    pub(crate) two_offset_byte_visits: u64,
    pub(crate) two_offset_contains_probes: u64,
    pub(crate) two_offset_value_probes: u64,
    pub(crate) three_offset_byte_visits: u64,
    pub(crate) three_offset_contains_probes: u64,
    pub(crate) three_offset_value_probes: u64,
}

impl AuditFilterObservedWorkV2 {
    fn initial_byte(&mut self) -> Result<(), CountAotError> {
        audit_filter_tick_v2(&mut self.initial_byte_visits)
    }

    fn byte(&mut self, selected: usize) -> Result<(), CountAotError> {
        match selected {
            2 => audit_filter_tick_v2(&mut self.two_offset_byte_visits),
            3 => audit_filter_tick_v2(&mut self.three_offset_byte_visits),
            _ => Err(invalid_v2("v2 audit filter selected width")),
        }
    }

    fn contains_probe(&mut self, selected: usize) -> Result<(), CountAotError> {
        match selected {
            2 => audit_filter_tick_v2(&mut self.two_offset_contains_probes),
            3 => audit_filter_tick_v2(&mut self.three_offset_contains_probes),
            _ => Err(invalid_v2("v2 audit filter contains width")),
        }
    }

    fn value_probe(&mut self, selected: usize) -> Result<(), CountAotError> {
        match selected {
            2 => audit_filter_tick_v2(&mut self.two_offset_value_probes),
            3 => audit_filter_tick_v2(&mut self.three_offset_value_probes),
            _ => Err(invalid_v2("v2 audit filter value width")),
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
            .ok_or(audit_arithmetic_v2())
    }
}

fn audit_filter_tick_v2(counter: &mut u64) -> Result<(), CountAotError> {
    *counter = counter.checked_add(1).ok_or(audit_arithmetic_v2())?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AuditFilterSelectionV2 {
    filter: Option<AuditCandidateFilterV2>,
    observed: AuditFilterObservedWorkV2,
}

#[allow(
    clippy::similar_names,
    reason = "rare1/rare2 and index1/index2 make the independent pair policy explicit"
)]
fn independent_candidate_filter_v2(
    literal: &[u8],
) -> Result<AuditFilterSelectionV2, CountAotError> {
    let mut observed = AuditFilterObservedWorkV2::default();
    if literal.len() < 2 {
        return Ok(AuditFilterSelectionV2 {
            filter: None,
            observed,
        });
    }
    observed.initial_byte()?;
    let (mut rare1, mut index1) = (literal[0], 0_u8);
    observed.initial_byte()?;
    let (mut rare2, mut index2) = (literal[1], 1_u8);
    if audit_rank_v2(rare2) < audit_rank_v2(rare1) {
        core::mem::swap(&mut rare1, &mut rare2);
        core::mem::swap(&mut index1, &mut index2);
    }
    for (index, byte) in literal.iter().copied().enumerate().skip(2) {
        observed.initial_byte()?;
        let index = u8::try_from(index).expect("bounded literal");
        if audit_rank_v2(byte) < audit_rank_v2(rare1) {
            rare2 = rare1;
            index2 = index1;
            rare1 = byte;
            index1 = index;
        } else if byte != rare1 && audit_rank_v2(byte) < audit_rank_v2(rare2) {
            rare2 = byte;
            index2 = index;
        }
    }
    let mut filter = AuditCandidateFilterV2 {
        offsets: [index1, index2, 0, 0],
        len: 2,
    };
    while filter.len < 4 {
        let selected = usize::from(filter.len);
        let mut best = None;
        for (index, byte) in literal.iter().copied().enumerate() {
            observed.byte(selected)?;
            let index = u8::try_from(index).expect("bounded literal");
            let mut already_selected = false;
            for offset in filter.offsets() {
                observed.contains_probe(selected)?;
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
                observed.value_probe(selected)?;
                if literal[usize::from(*offset)] == byte {
                    duplicate_value = true;
                    break;
                }
            }
            if duplicate_value {
                continue;
            }
            if best.is_none_or(|best_index| {
                audit_rank_v2(byte) < audit_rank_v2(literal[usize::from(best_index)])
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
    Ok(AuditFilterSelectionV2 {
        filter: Some(filter),
        observed,
    })
}

#[cfg(test)]
pub(crate) fn independent_filter_observed_work_for_test_v2(
    literal: &[u8],
) -> Result<AuditFilterObservedWorkV2, CountAotError> {
    independent_candidate_filter_v2(literal).map(|selection| selection.observed)
}

#[cfg(test)]
pub(crate) fn independent_filter_meter_overflow_for_test_v2() -> Result<(), CountAotError> {
    let mut observed = AuditFilterObservedWorkV2 {
        initial_byte_visits: u64::MAX,
        ..AuditFilterObservedWorkV2::default()
    };
    observed.initial_byte()
}

fn audit_rank_v2(byte: u8) -> u8 {
    AUDIT_FREQUENCY_RANK_V2[usize::from(byte)]
}

#[allow(
    clippy::too_many_lines,
    reason = "one ordered mask table makes the independent decoder auditable"
)]
fn decode_word_v2(word: u32, offset: u32) -> Result<DecodedInstructionV2, CountAotError> {
    let rd = register_v2(word);
    let rn = register_v2(word >> 5);
    let rm = register_v2(word >> 16);
    if word & 0xff80_0000 == 0xd280_0000 {
        Ok(DecodedInstructionV2::MoveZero64 {
            destination: rd,
            immediate: immediate16_v2(word),
            shift: halfword_shift_v2(word),
        })
    } else if word & 0xff80_0000 == 0xf280_0000 {
        Ok(DecodedInstructionV2::MoveKeep64 {
            destination: rd,
            immediate: immediate16_v2(word),
            shift: halfword_shift_v2(word),
        })
    } else if word & 0xffe0_fc1f == 0xeb00_001f {
        Ok(DecodedInstructionV2::CompareRegister64 {
            left: rn,
            right: rm,
        })
    } else if word & 0xffe0_fc1f == 0x6b00_001f {
        Ok(DecodedInstructionV2::CompareRegister32 {
            left: rn,
            right: rm,
        })
    } else if word & 0xffc0_001f == 0xf100_001f {
        Ok(DecodedInstructionV2::CompareImmediate64 {
            register: rn,
            immediate: immediate12_v2(word),
        })
    } else if word & 0xffc0_001f == 0x7100_001f {
        Ok(DecodedInstructionV2::CompareImmediate32 {
            register: rn,
            immediate: immediate12_v2(word),
        })
    } else if word & 0xffe0_fc00 == 0x8b00_0000 {
        Ok(DecodedInstructionV2::AddRegister64 {
            destination: rd,
            left: rn,
            right: rm,
        })
    } else if word & 0xffc0_0000 == 0x9100_0000 {
        Ok(DecodedInstructionV2::AddImmediate64 {
            destination: rd,
            source: rn,
            immediate: immediate12_v2(word),
        })
    } else if word & 0xffe0_fc00 == 0xcb00_0000 {
        Ok(DecodedInstructionV2::SubtractRegister64 {
            destination: rd,
            left: rn,
            right: rm,
        })
    } else if word & 0xffc0_0000 == 0xd100_0000 {
        Ok(DecodedInstructionV2::SubtractImmediate64 {
            destination: rd,
            source: rn,
            immediate: immediate12_v2(word),
        })
    } else if word & 0xffe0_fc00 == 0x8a00_0000 {
        Ok(DecodedInstructionV2::AndRegister64 {
            destination: rd,
            left: rn,
            right: rm,
        })
    } else if word & 0xffc0_0000 == 0x9240_0000 && (word >> 16).trailing_zeros() >= 6 {
        Ok(DecodedInstructionV2::AndLowBits64 {
            destination: rd,
            source: rn,
            bits: u8::try_from(((word >> 10) & 0x3f) + 1).expect("at most 64 bits"),
        })
    } else if word & 0xffc0_0000 == 0xd340_0000 && ((word >> 10) & 0x3f) == 63 {
        Ok(DecodedInstructionV2::LogicalShiftRight64 {
            destination: rd,
            source: rn,
            shift: u8::try_from((word >> 16) & 0x3f).expect("six-bit shift"),
        })
    } else if word & 0xffff_fc00 == 0xdac0_0000 {
        Ok(DecodedInstructionV2::ReverseBits64 {
            destination: rd,
            source: rn,
        })
    } else if word & 0xffff_fc00 == 0xdac0_1000 {
        Ok(DecodedInstructionV2::CountLeadingZeros64 {
            destination: rd,
            source: rn,
        })
    } else if word & 0xffc0_0000 == 0x3940_0000 {
        Ok(DecodedInstructionV2::LoadByte {
            destination: rd,
            base: rn,
            offset: immediate12_v2(word),
        })
    } else if word & 0xffe0_fc00 == 0x3860_6800 {
        Ok(DecodedInstructionV2::LoadByteRegister {
            destination: rd,
            base: rn,
            index: rm,
        })
    } else if word & 0xffc0_0000 == 0xf900_0000 {
        Ok(DecodedInstructionV2::Store64 {
            source: rd,
            base: rn,
            offset: immediate12_v2(word)
                .checked_mul(8)
                .expect("scaled store offset"),
        })
    } else if word & 0xffc0_0000 == 0x3dc0_0000 {
        Ok(DecodedInstructionV2::LoadVector128 {
            destination: rd,
            base: rn,
            offset: immediate12_v2(word)
                .checked_mul(16)
                .expect("scaled vector offset"),
        })
    } else if word & 0xffc0_0000 == 0xfd40_0000 {
        Ok(DecodedInstructionV2::LoadVectorDouble {
            destination: rd,
            base: rn,
            offset: immediate12_v2(word)
                .checked_mul(8)
                .expect("scaled double offset"),
        })
    } else if word & 0xffff_fc00 == 0x4e01_0c00 {
        Ok(DecodedInstructionV2::DuplicateByte16 {
            destination: rd,
            source: rn,
        })
    } else if word & 0xffe0_fc00 == 0x6e20_8c00 {
        Ok(DecodedInstructionV2::CompareEqualBytes16 {
            destination: rd,
            left: rn,
            right: rm,
        })
    } else if word & 0xffe0_fc00 == 0x2e20_8c00 {
        Ok(DecodedInstructionV2::CompareEqualBytes8 {
            destination: rd,
            left: rn,
            right: rm,
        })
    } else if word & 0xffe0_fc00 == 0x4e20_1c00 {
        Ok(DecodedInstructionV2::AndBytes16 {
            destination: rd,
            left: rn,
            right: rm,
        })
    } else if word & 0xffe0_fc00 == 0x4ea0_1c00 {
        Ok(DecodedInstructionV2::OrBytes16 {
            destination: rd,
            left: rn,
            right: rm,
        })
    } else if word & 0xffff_fc00 == 0x0f0c_8400 {
        Ok(DecodedInstructionV2::ShrinkNarrowBytesFromHalfwords {
            destination: rd,
            source: rn,
            shift: 4,
        })
    } else if word & 0xffff_fc00 == 0x4e31_b800 {
        Ok(DecodedInstructionV2::AddAcrossBytes16 {
            destination: rd,
            source: rn,
        })
    } else if word & 0xffff_fc00 == 0x6e30_a800 {
        Ok(DecodedInstructionV2::UnsignedMaxAcrossBytes16 {
            destination: rd,
            source: rn,
        })
    } else if word & 0xffff_fc00 == 0x2e31_a800 {
        Ok(DecodedInstructionV2::UnsignedMinAcrossBytes8 {
            destination: rd,
            source: rn,
        })
    } else if word & 0xffff_fc00 == 0x6e31_a800 {
        Ok(DecodedInstructionV2::UnsignedMinAcrossBytes16 {
            destination: rd,
            source: rn,
        })
    } else if word & 0xffff_fc00 == 0x0e01_3c00 {
        Ok(DecodedInstructionV2::MoveVectorByteTo32 {
            destination: rd,
            source: rn,
        })
    } else if word & 0xffff_fc00 == 0x9e66_0000 {
        Ok(DecodedInstructionV2::MoveVectorDoubleTo64 {
            destination: rd,
            source: rn,
        })
    } else if word & 0xffff_fc00 == 0x9e67_0000 {
        Ok(DecodedInstructionV2::Move64ToVectorDouble {
            destination: rd,
            source: rn,
        })
    } else if word & 0xffff_fc00 == 0x4e18_1c00 {
        Ok(DecodedInstructionV2::Insert64ToVectorDoubleLane1 {
            destination: rd,
            source: rn,
        })
    } else if word & 0xfc00_0000 == 0x1400_0000 {
        Ok(DecodedInstructionV2::Branch {
            displacement: sign_extend_v2(word & 0x03ff_ffff, 26) << 2,
        })
    } else if word & 0xff00_0010 == 0x5400_0000 {
        let condition = match u8::try_from(word & 0xf).expect("four-bit condition") {
            0 => ConditionV2::Equal,
            1 => ConditionV2::NotEqual,
            2 => ConditionV2::CarrySet,
            3 => ConditionV2::CarryClear,
            8 => ConditionV2::Higher,
            _ => return Err(CountAotError::UnknownInstruction { offset, word }),
        };
        Ok(DecodedInstructionV2::BranchCondition {
            condition,
            displacement: sign_extend_v2((word >> 5) & 0x7_ffff, 19) << 2,
        })
    } else if word == 0xd65f_03c0 {
        Ok(DecodedInstructionV2::Return)
    } else {
        Err(CountAotError::UnknownInstruction { offset, word })
    }
}

fn read_word_audit_v2(code: &[u8], offset: usize) -> Result<u32, CountAotError> {
    let bytes = code
        .get(offset..offset.checked_add(4).ok_or(audit_arithmetic_v2())?)
        .ok_or(invalid_v2("v2 audit word"))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn register_v2(word: u32) -> u8 {
    u8::try_from(word & 0x1f).expect("five-bit register")
}

fn immediate12_v2(word: u32) -> u16 {
    u16::try_from((word >> 10) & 0xfff).expect("twelve-bit immediate")
}

fn immediate16_v2(word: u32) -> u16 {
    u16::try_from((word >> 5) & 0xffff).expect("sixteen-bit immediate")
}

fn halfword_shift_v2(word: u32) -> u8 {
    u8::try_from(((word >> 21) & 3) * 16).expect("two-bit shift")
}

fn sign_extend_v2(value: u32, bits: u8) -> i32 {
    let shift = 32_u32
        .checked_sub(u32::from(bits))
        .expect("field no wider than u32");
    (value << shift).cast_signed() >> shift
}

fn align_up_audit_v2(value: usize, alignment: usize) -> Result<usize, CountAotError> {
    let mask = alignment
        .checked_sub(1)
        .ok_or(invalid_v2("v2 zero audit alignment"))?;
    value
        .checked_add(mask)
        .map(|sum| sum & !mask)
        .ok_or(audit_arithmetic_v2())
}

fn audit_exact_vec_v2<T>(
    capacity: usize,
    prospective: ProspectiveV2,
) -> Result<ExactVec<T>, CountAotError> {
    // Keep the complete source-derived admission adjacent to every allocator
    // call, even though audit_impl also refuses once before any content scan.
    refuse_audit_scratch_v2(prospective.audit_scratch, prospective.scratch_limit)?;
    ExactVec::try_with_capacity(capacity).map_err(|error| match error {
        CopyError::LayoutOverflow => audit_arithmetic_v2(),
        CopyError::AllocationFailed => CountAotError::AllocationFailed {
            resource: CountAotResource::ScratchBytes,
        },
    })
}

fn audit_push_v2<T>(
    values: &mut ExactVec<T>,
    value: T,
    at: &'static str,
) -> Result<(), CountAotError> {
    values
        .try_push(value)
        .map_err(|_| CountAotError::InternalInvariant { at })
}

fn refuse_audit_scratch_v2(required: u64, limit: u64) -> Result<(), CountAotError> {
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
    u64::try_from(value).map_err(|_| audit_arithmetic_v2())
}

const fn invalid_v2(at: &'static str) -> CountAotError {
    CountAotError::InvalidImage { at }
}

const fn audit_arithmetic_v2() -> CountAotError {
    CountAotError::ArithmeticOverflow {
        site: CountAotArithmeticSite::Audit,
    }
}
