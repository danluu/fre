use core::mem::size_of;

use fre_exact_alloc::{CopyError, ExactVec};
use fre_kernel_ir::{
    AggregateOutput, Count, ExactAggregateProgram, MAX_EXACT_AGGREGATE_LITERAL_BYTES,
};

use crate::{
    AOT_COUNT_BACKEND_VERSION_V1, AotCountArtifactIdentity, AotCountCpuFeatures,
    AotCountImageBuildReceiptV1, AotCountImageLayoutV1, AotCountImageStatsV1, AotCountImageV1,
    AotCountLiteralManifestV1, AotCountTargetSpec, CodeLabelV1, CountAotArithmeticSite,
    CountAotError, CountAotResource, LabelKindV1, RelocationKindV1, RelocationTargetV1,
    RelocationV1,
    emit::{
        AssemblerScratchObservationWorkV1, Prospective, artifact_identity_encoded_len,
        assembler_scratch_derivation_work_upper_bound_v1,
        assembler_scratch_observation_work_components_v1,
        assembler_scratch_upper_bound_for_dimensions, canonical_template,
        compute_artifact_identity, identity_bytes_upper_bound, identity_encoder_scratch_bytes_v1,
        identity_structural_traversal_work_v1, label_order_work_upper_bound, prospective,
    },
    is_supported_aot_count_backend_tuple_v1,
};

const RESULT_POINTER_REGISTER: u8 = 2;
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

/// `AArch64` condition codes admitted by the Count template.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ConditionV1 {
    Equal = 0,
    NotEqual = 1,
    CarrySet = 2,
    CarryClear = 3,
    Higher = 8,
}

/// Independently decoded instruction subset admitted by this AOT backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodedInstructionV1 {
    MoveRegister64 {
        destination: u8,
        source: u8,
    },
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
    AndLowBits64 {
        destination: u8,
        source: u8,
        bits: u8,
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
    Load64RegisterScaled {
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
    DuplicateByte16 {
        destination: u8,
        source: u8,
    },
    CompareEqualBytes16 {
        destination: u8,
        left: u8,
        right: u8,
    },
    AddAcrossBytes16 {
        destination: u8,
        source: u8,
    },
    MoveVectorByteTo32 {
        destination: u8,
        source: u8,
    },
    Branch {
        displacement: i32,
    },
    BranchCondition {
        condition: ConditionV1,
        displacement: i32,
    },
    Return,
}

impl DecodedInstructionV1 {
    const fn is_vector(self) -> bool {
        matches!(
            self,
            Self::LoadVector128 { .. }
                | Self::DuplicateByte16 { .. }
                | Self::CompareEqualBytes16 { .. }
                | Self::AddAcrossBytes16 { .. }
                | Self::MoveVectorByteTo32 { .. }
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

    const fn expected_relocation_kind(self) -> Option<RelocationKindV1> {
        match self {
            Self::Branch { .. } => Some(RelocationKindV1::Branch26),
            Self::BranchCondition { .. } => Some(RelocationKindV1::ConditionalBranch19),
            _ => None,
        }
    }

    const fn written_gpr(self) -> Option<u8> {
        match self {
            Self::MoveRegister64 { destination, .. }
            | Self::MoveZero64 { destination, .. }
            | Self::MoveKeep64 { destination, .. }
            | Self::AddRegister64 { destination, .. }
            | Self::AddImmediate64 { destination, .. }
            | Self::SubtractRegister64 { destination, .. }
            | Self::SubtractImmediate64 { destination, .. }
            | Self::AndLowBits64 { destination, .. }
            | Self::LoadByte { destination, .. }
            | Self::LoadByteRegister { destination, .. }
            | Self::Load64RegisterScaled { destination, .. }
            | Self::MoveVectorByteTo32 { destination, .. } => Some(destination),
            _ => None,
        }
    }
}

/// Independent exact-template, decode, CFG, memory, and seal audit receipt.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CountAuditReportV1 {
    pub instructions: u32,
    pub direct_branches: u32,
    pub data_addresses: u32,
    pub vector_instructions: u32,
    pub stores: u32,
    pub returns: u32,
    pub work_upper_bound: u64,
    pub scratch_bytes_upper_bound: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AuditWorkComponentsV1 {
    pub(crate) canonical_emission: u64,
    pub(crate) canonical_resource_accounting: AuditCanonicalResourceWorkV1,
    pub(crate) canonical_compare: u64,
    pub(crate) decode: u64,
    pub(crate) independent_policy: u64,
    pub(crate) cfg_and_relocations: u64,
    pub(crate) identity_structural_traversal: u64,
    pub(crate) identity_hash_bytes: u64,
    pub(crate) identity_hash_finalization: u64,
    pub(crate) fixed_scalar_checks: u64,
    pub(crate) total: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AuditCanonicalResourceWorkV1 {
    pub(crate) scratch_envelope_arithmetic: u64,
    pub(crate) assembler_envelope_derivations: u64,
    pub(crate) observed_emission_phase_scratch: AssemblerScratchObservationWorkV1,
    pub(crate) admission_and_seal_checks: u64,
    pub(crate) total: u64,
}

pub(crate) fn audit_canonical_resource_work_components_v1()
-> Result<AuditCanonicalResourceWorkV1, CountAotError> {
    const SCRATCH_ENVELOPE_ARITHMETIC_WORK_V1: u64 = 16;
    const ASSEMBLER_ENVELOPE_DERIVATION_PASSES_V1: u64 = 2;
    const SCRATCH_ADMISSION_AND_SEAL_CHECKS_V1: u64 = 7;
    // `audit_scratch_upper_bound_for_dimensions` derives the assembler
    // envelope once before admission, and the canonical receipt seal derives
    // it again after regeneration.
    let assembler_envelope_derivations = assembler_scratch_derivation_work_upper_bound_v1()
        .checked_mul(ASSEMBLER_ENVELOPE_DERIVATION_PASSES_V1)
        .ok_or(audit_arithmetic())?;
    // Canonical regeneration itself executes all five allocator-capacity
    // observations performed by `Assembler`.
    let observed_emission_phase_scratch = assembler_scratch_observation_work_components_v1();
    let total = SCRATCH_ENVELOPE_ARITHMETIC_WORK_V1
        .checked_add(assembler_envelope_derivations)
        .and_then(|work| work.checked_add(observed_emission_phase_scratch.total))
        .and_then(|work| work.checked_add(SCRATCH_ADMISSION_AND_SEAL_CHECKS_V1))
        .ok_or(audit_arithmetic())?;
    Ok(AuditCanonicalResourceWorkV1 {
        scratch_envelope_arithmetic: SCRATCH_ENVELOPE_ARITHMETIC_WORK_V1,
        assembler_envelope_derivations,
        observed_emission_phase_scratch,
        admission_and_seal_checks: SCRATCH_ADMISSION_AND_SEAL_CHECKS_V1,
        total,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "the named audit-work proof intentionally keeps every checked component visible"
)]
pub(crate) fn audit_work_components_for_dimensions(
    code_bytes: usize,
    labels: usize,
    relocations: usize,
) -> Result<AuditWorkComponentsV1, CountAotError> {
    const IDENTITY_TRAVERSAL_PASSES_V1: u64 = 2;
    const IDENTITY_HASH_PASSES_V1: u64 = 1;
    const IDENTITY_HASH_FINALIZATION_WORK_V1: u64 = 8;
    // One work unit is reserved for each named O(1) field check or checked
    // scalar transformation not already covered by a byte/label/relocation
    // term below. Keeping the components separate makes additions reviewable.
    const SUPPORT_AND_TARGET_FIELD_CHECKS_V1: u64 = 3 + 5;
    const DIMENSION_LAYOUT_AND_SOURCE_FIELD_CHECKS_V1: u64 = 5 + 7 + 3;
    const PROSPECTIVE_WORK_FIELD_CHECKS_V1: u64 = 4;
    const MANIFEST_FIXED_FIELD_CHECKS_V1: u64 = 3;
    const CANONICAL_FEATURE_FIELD_CHECKS_V1: u64 = 2;
    const CANONICAL_STATS_FIELD_CHECKS_V1: u64 = 11;
    const TERMINAL_CARDINALITY_FIELD_CHECKS_V1: u64 = 4;
    const CAPACITY_ARITHMETIC_WORK_V1: u64 = 4;
    const FINAL_STATS_AND_RECEIPT_FIELD_CHECKS_V1: u64 = 12;
    const IDENTITY_SEAL_FIELD_CHECKS_V1: u64 = 4;
    const REPORT_FIELD_CONSTRUCTION_WORK_V1: u64 = 8;
    const PUBLIC_RECEIPT_FIELD_CHECKS_V1: u64 = 1;
    const PERSISTENT_ENVELOPE_CAPACITY_MULTIPLICATIONS_V1: u64 = 4;
    const PERSISTENT_ENVELOPE_CHECKED_ADDITIONS_V1: u64 = 10;
    const PERSISTENT_ENVELOPE_CONVERSIONS_V1: u64 = 2;
    const PERSISTENT_ENVELOPE_FIELD_CHECKS_V1: u64 = 9;
    const CANDIDATE_WRAPPER_DISPATCH_WORK_V1: u64 = 1;
    const PUBLIC_WRAPPER_DISPATCH_AND_RECEIPT_WORK_V1: u64 = 4;
    let canonical_resource_accounting = audit_canonical_resource_work_components_v1()?;
    let fixed_scalar_checks = SUPPORT_AND_TARGET_FIELD_CHECKS_V1
        .checked_add(PERSISTENT_ENVELOPE_CAPACITY_MULTIPLICATIONS_V1)
        .and_then(|work| work.checked_add(PERSISTENT_ENVELOPE_CHECKED_ADDITIONS_V1))
        .and_then(|work| work.checked_add(PERSISTENT_ENVELOPE_CONVERSIONS_V1))
        .and_then(|work| work.checked_add(PERSISTENT_ENVELOPE_FIELD_CHECKS_V1))
        .and_then(|work| work.checked_add(DIMENSION_LAYOUT_AND_SOURCE_FIELD_CHECKS_V1))
        .and_then(|work| work.checked_add(PROSPECTIVE_WORK_FIELD_CHECKS_V1))
        .and_then(|work| work.checked_add(MANIFEST_FIXED_FIELD_CHECKS_V1))
        .and_then(|work| work.checked_add(CANONICAL_FEATURE_FIELD_CHECKS_V1))
        .and_then(|work| work.checked_add(CANONICAL_STATS_FIELD_CHECKS_V1))
        .and_then(|work| work.checked_add(TERMINAL_CARDINALITY_FIELD_CHECKS_V1))
        .and_then(|work| work.checked_add(CAPACITY_ARITHMETIC_WORK_V1))
        .and_then(|work| work.checked_add(FINAL_STATS_AND_RECEIPT_FIELD_CHECKS_V1))
        .and_then(|work| work.checked_add(IDENTITY_SEAL_FIELD_CHECKS_V1))
        .and_then(|work| work.checked_add(REPORT_FIELD_CONSTRUCTION_WORK_V1))
        .and_then(|work| work.checked_add(PUBLIC_RECEIPT_FIELD_CHECKS_V1))
        .and_then(|work| work.checked_add(CANDIDATE_WRAPPER_DISPATCH_WORK_V1))
        .and_then(|work| work.checked_add(PUBLIC_WRAPPER_DISPATCH_AND_RECEIPT_WORK_V1))
        .ok_or(audit_arithmetic())?;
    let label_order = label_order_work_upper_bound(labels)?.total;
    let instructions = to_u64(code_bytes / 4)?;
    let identity_bytes = identity_bytes_upper_bound(code_bytes, labels, relocations)?;
    let code_bytes = to_u64(code_bytes)?;
    let labels = to_u64(labels)?;
    let relocations = to_u64(relocations)?;
    let literal =
        u64::try_from(MAX_EXACT_AGGREGATE_LITERAL_BYTES).map_err(|_| audit_arithmetic())?;
    let canonical_emission = instructions
        .checked_add(labels.checked_mul(2).ok_or(audit_arithmetic())?)
        .and_then(|work| work.checked_add(relocations.checked_mul(2)?))
        .and_then(|work| work.checked_add(label_order))
        .and_then(|work| work.checked_add(literal))
        .ok_or(audit_arithmetic())?;
    let canonical_compare = code_bytes
        .checked_add(labels)
        .and_then(|work| work.checked_add(relocations))
        .ok_or(audit_arithmetic())?;
    let decode = code_bytes
        .checked_add(instructions)
        .ok_or(audit_arithmetic())?;
    let independent_policy = instructions
        .checked_mul(2)
        .and_then(|work| work.checked_add(literal.checked_mul(4)?))
        .ok_or(audit_arithmetic())?;
    let cfg_and_relocations = instructions
        .checked_mul(labels.checked_add(8).ok_or(audit_arithmetic())?)
        .and_then(|work| work.checked_add(relocations.checked_mul(8)?))
        .ok_or(audit_arithmetic())?;
    // A sealed public audit traverses the complete identity encoding twice:
    // once to count its canonical bytes and once to hash them.  One unit per
    // encoder field write captures the checked counter/update work, and one
    // unit per hashed byte captures the SHA-256 input traversal. Candidate
    // audit uses only the first pass, but sharing the sealed maximum keeps the
    // public receipt conservative for both call sites.
    let identity_traversal =
        identity_structural_traversal_work_v1(labels, relocations).ok_or(audit_arithmetic())?;
    let identity_structural_traversal = identity_traversal
        .checked_mul(IDENTITY_TRAVERSAL_PASSES_V1)
        .ok_or(audit_arithmetic())?;
    let identity_hash_bytes = identity_bytes
        .checked_mul(IDENTITY_HASH_PASSES_V1)
        .ok_or(audit_arithmetic())?;
    let identity_hash_finalization = IDENTITY_HASH_FINALIZATION_WORK_V1;
    let total = canonical_emission
        .checked_add(canonical_resource_accounting.total)
        .and_then(|work| work.checked_add(canonical_compare))
        .and_then(|work| work.checked_add(decode))
        .and_then(|work| work.checked_add(independent_policy))
        .and_then(|work| work.checked_add(cfg_and_relocations))
        .and_then(|work| work.checked_add(identity_structural_traversal))
        .and_then(|work| work.checked_add(identity_hash_bytes))
        .and_then(|work| work.checked_add(identity_hash_finalization))
        .and_then(|work| work.checked_add(fixed_scalar_checks))
        .ok_or(CountAotError::ArithmeticOverflow {
            site: CountAotArithmeticSite::Audit,
        })?;
    Ok(AuditWorkComponentsV1 {
        canonical_emission,
        canonical_resource_accounting,
        canonical_compare,
        decode,
        independent_policy,
        cfg_and_relocations,
        identity_structural_traversal,
        identity_hash_bytes,
        identity_hash_finalization,
        fixed_scalar_checks,
        total,
    })
}

pub(crate) fn audit_work_upper_bound_for_dimensions(
    code_bytes: usize,
    labels: usize,
    relocations: usize,
) -> Result<u64, CountAotError> {
    Ok(audit_work_components_for_dimensions(code_bytes, labels, relocations)?.total)
}

type AuditScratchCalculationInlineStateV1 = ([usize; 16], [u64; 6], CountAotError);
type AuditCommonInlineStateV1 = (
    AuditScratchCalculationInlineStateV1,
    &'static ExactAggregateProgram<Count>,
    &'static AotCountImageV1,
    Prospective,
    bool,
    usize,
    AotCountTargetSpec,
    &'static [u8],
    AotCountImageLayoutV1,
    u32,
    AotCountImageStatsV1,
    AotCountImageBuildReceiptV1,
    PersistentEnvelopeV1,
    PersistentEnvelopeV1,
    (u32, u32, u32, u32, u32, u64),
    &'static [u8],
    AotCountLiteralManifestV1,
    [u8; 32],
    CountAotError,
);
type AuditCanonicalInlineStateV1 = (AuditCommonInlineStateV1, AotCountCpuFeatures);
type AuditDecodeIteratorV1 = core::iter::Enumerate<core::slice::ChunksExact<'static, u8>>;
type AuditDecodeWordInlineStateV1 = ([u32; 6], [u16; 3], [u8; 4], CountAotError);
type AuditDecodeInlineStateV1 = (
    AuditCommonInlineStateV1,
    ExactVec<DecodedInstructionV1>,
    AuditDecodeIteratorV1,
    AuditDecodeWordInlineStateV1,
    usize,
    &'static [u8],
    u32,
    u32,
    DecodedInstructionV1,
    CountAotError,
);
type AuditPolicyIteratorV1 =
    core::iter::Enumerate<core::iter::Copied<core::slice::Iter<'static, DecodedInstructionV1>>>;
type AuditPolicyChunkIteratorV1 = core::iter::Enumerate<core::slice::ChunksExact<'static, u8>>;
type AuditPolicyTailIteratorV1 = core::slice::Iter<'static, u8>;
type AuditPolicyMatchIteratorV1 = core::iter::Zip<
    core::slice::Iter<'static, PolicyInstructionV1>,
    core::slice::Iter<'static, DecodedInstructionV1>,
>;
type AuditLabelBindingIteratorV1 = core::iter::Zip<
    core::slice::Iter<'static, PolicyLabelBindingV1>,
    core::slice::Iter<'static, CodeLabelV1>,
>;
type AuditPolicyLabelOffsetInlineStateV1 = (
    &'static [PolicyLabelBindingV1],
    core::slice::Iter<'static, PolicyLabelBindingV1>,
    &'static PolicyLabelBindingV1,
    PolicyLabelV1,
    Option<u32>,
    CountAotError,
);
type AuditValidationInlineStateV1 = (
    &'static [CodeLabelV1],
    &'static [PolicyLabelBindingV1],
    &'static [RelocationV1],
    core::slice::Windows<'static, CodeLabelV1>,
    core::slice::Iter<'static, CodeLabelV1>,
    AuditPolicyMatchIteratorV1,
    AuditLabelBindingIteratorV1,
    core::slice::Iter<'static, RelocationV1>,
    Option<u32>,
    Option<&'static RelocationV1>,
    [usize; 8],
    [u32; 6],
    CountAotError,
);
type AuditPolicyInlineStateV1 = (
    AuditCommonInlineStateV1,
    ExactVec<DecodedInstructionV1>,
    ExactVec<PolicyInstructionV1>,
    ExactVec<PolicyLabelBindingV1>,
    PolicySink<'static>,
    AuditPolicyIteratorV1,
    AuditPolicyChunkIteratorV1,
    AuditPolicyTailIteratorV1,
    core::ops::Range<u8>,
    [u8; 8],
    AuditValidationInlineStateV1,
    AuditPolicyLabelOffsetInlineStateV1,
    DecodedInstructionV1,
    PolicyInstructionV1,
    Option<&'static RelocationV1>,
    Option<i32>,
    Option<PolicyLabelV1>,
    [usize; 4],
    [u32; 9],
    CountAuditReportV1,
    CountAotError,
);
type AuditSealInlineStateV1 = (
    AuditCommonInlineStateV1,
    CountAuditReportV1,
    [usize; 5],
    [u64; 3],
    AotCountArtifactIdentity,
    CountAotError,
);
type AuditCandidateWrapperInlineStateV1 = (
    &'static ExactAggregateProgram<Count>,
    &'static AotCountImageV1,
    Prospective,
    Result<CountAuditReportV1, CountAotError>,
    CountAotError,
);
type AuditPublicWrapperInlineStateV1 = (
    &'static ExactAggregateProgram<Count>,
    &'static AotCountImageV1,
    Prospective,
    CountAuditReportV1,
    Result<CountAuditReportV1, CountAotError>,
    CountAotError,
);

pub(crate) const fn audit_candidate_wrapper_inline_bytes_v1() -> usize {
    size_of::<AuditCandidateWrapperInlineStateV1>()
}

pub(crate) const fn audit_public_wrapper_inline_bytes_v1() -> usize {
    size_of::<AuditPublicWrapperInlineStateV1>()
}

pub(crate) fn audit_scratch_upper_bound_for_dimensions(
    code_bytes: usize,
    labels: usize,
    relocations: usize,
) -> Result<u64, CountAotError> {
    let instructions = code_bytes / 4;
    let decoded_backing = instructions
        .checked_mul(size_of::<DecodedInstructionV1>())
        .ok_or(audit_arithmetic())?;
    let policy_backing = instructions
        .checked_mul(size_of::<PolicyInstructionV1>())
        .ok_or(audit_arithmetic())?;
    let policy_label_backing = labels
        .checked_mul(size_of::<PolicyLabelBindingV1>())
        .ok_or(audit_arithmetic())?;
    let canonical = assembler_scratch_upper_bound_for_dimensions(code_bytes, labels, relocations)?
        .checked_add(to_u64(size_of::<AuditCanonicalInlineStateV1>())?)
        .ok_or(audit_arithmetic())?;
    let decode = decoded_backing
        .checked_add(size_of::<AuditDecodeInlineStateV1>())
        .ok_or(audit_arithmetic())
        .and_then(to_u64)?;
    let policy = decoded_backing
        .checked_add(policy_backing)
        .and_then(|bytes| bytes.checked_add(policy_label_backing))
        .and_then(|bytes| bytes.checked_add(size_of::<AuditPolicyInlineStateV1>()))
        .ok_or(audit_arithmetic())
        .and_then(to_u64)?;
    let hash_and_seal = identity_encoder_scratch_bytes_v1()
        .checked_add(size_of::<AuditSealInlineStateV1>())
        .ok_or(audit_arithmetic())
        .and_then(to_u64)?;
    Ok(canonical.max(decode).max(policy).max(hash_and_seal))
}

/// Audit an inert image against the original typed Count KIR and its literal.
///
/// The image alone is intentionally insufficient evidence: the original
/// program binds the retained literal manifest and source identity. The audit
/// regenerates canonical bytes/labels/relocations, independently decodes every
/// word, checks a separately described width-specific policy sequence, proves
/// relocation completeness, and recomputes all sealed dimensions and identity.
pub fn audit_count_image_v1(
    program: &ExactAggregateProgram<Count>,
    image: &AotCountImageV1,
) -> Result<CountAuditReportV1, CountAotError> {
    let bounds = prospective_program(program)?;
    let report = audit_impl(program, image, bounds, true)?;
    if image.build_receipt().audit != report {
        return Err(invalid("audit receipt"));
    }
    Ok(report)
}

pub(crate) fn audit_count_image_candidate_v1(
    program: &ExactAggregateProgram<Count>,
    image: &AotCountImageV1,
    bounds: Prospective,
) -> Result<CountAuditReportV1, CountAotError> {
    audit_impl(program, image, bounds, false)
}

#[cfg(test)]
pub(crate) fn audit_count_image_with_scratch_limit_for_test(
    program: &ExactAggregateProgram<Count>,
    image: &AotCountImageV1,
    scratch_limit: u64,
) -> Result<CountAuditReportV1, CountAotError> {
    let mut bounds = prospective_program(program)?;
    bounds.scratch_limit = bounds.scratch_limit.min(scratch_limit);
    audit_impl(program, image, bounds, true)
}

#[allow(
    clippy::too_many_lines,
    reason = "one ordered source-bound audit keeps every preflight and seal comparison visible"
)]
fn audit_impl(
    program: &ExactAggregateProgram<Count>,
    image: &AotCountImageV1,
    bounds: Prospective,
    sealed: bool,
) -> Result<CountAuditReportV1, CountAotError> {
    let literal_len = preflight_program(program)?;
    if image.backend_version() != AOT_COUNT_BACKEND_VERSION_V1
        || !is_supported_aot_count_backend_tuple_v1(image.support())
        || image.output_kind() != 1
    {
        return Err(invalid("backend support tuple"));
    }
    let target = image.target();
    if target.architecture != image.support().architecture
        || target.little_endian != image.support().little_endian
        || target.pointer_width != image.support().pointer_width
        || target.abi != image.support().target_abi
        || !image.support().allowed_features.contains(target.features)
    {
        return Err(invalid("target tuple"));
    }

    let complete_audit_scratch = audit_scratch_upper_bound_for_dimensions(
        bounds.code_bytes,
        bounds.labels,
        bounds.relocations,
    )?;
    if complete_audit_scratch != bounds.audit_scratch {
        return Err(CountAotError::InternalInvariant {
            at: "audit scratch recomputation",
        });
    }
    // Refuse the complete source-derived phase maximum before canonical
    // regeneration or the first audit ExactVec allocation.
    refuse_audit_scratch(complete_audit_scratch, bounds.scratch_limit)?;
    let stats = image.stats();
    let receipt = image.build_receipt();
    let source_persistent = source_persistent_envelope(bounds)?;
    let actual_persistent = image_persistent_envelope(image)?;
    if source_persistent.persistent_bytes != bounds.persistent
        || bounds.persistent > bounds.persistent_limit
        || actual_persistent.persistent_bytes > bounds.persistent_limit
        || actual_persistent != source_persistent
        || receipt.code_capacity_bytes != actual_persistent.code_capacity_bytes
        || receipt.label_capacity_bytes != actual_persistent.label_capacity_bytes
        || receipt.relocation_capacity_bytes != actual_persistent.relocation_capacity_bytes
        || receipt.retained_heap_bytes != actual_persistent.retained_heap_bytes
        || receipt.inline_bytes != actual_persistent.inline_bytes
    {
        return Err(invalid("prospective persistent seal"));
    }
    if sealed
        && (receipt.emission_peak_scratch_bytes != bounds.emission_scratch
            || receipt.audit.work_upper_bound != bounds.audit_work
            || receipt.audit.scratch_bytes_upper_bound != bounds.audit_scratch
            || stats.scratch_bytes_upper_bound != bounds.scratch
            || receipt.scratch_bytes_upper_bound != bounds.scratch)
    {
        return Err(invalid("prospective scratch seal"));
    }

    // These O(1) dimensions are refused before literal traversal, canonical
    // regeneration, hashing, decode, or policy scans.
    let code = image.code();
    if code.is_empty()
        || !code.len().is_multiple_of(4)
        || code.len() > bounds.code_bytes
        || image.labels().len() > bounds.labels
        || image.relocations().len() > bounds.relocations
    {
        return Err(invalid("bounded image dimensions"));
    }
    let layout = image.layout();
    let code_len_u32 = to_u32(code.len())?;
    if layout.code_alignment != 16
        || layout.rodata_alignment != 16
        || layout.rodata_from_code_start < code_len_u32
        || !layout.rodata_from_code_start.is_multiple_of(16)
        || layout.total_mapped_bytes != layout.rodata_from_code_start
        || !image.rodata().is_empty()
        || image.data_symbol_count() != 0
    {
        return Err(invalid("image layout"));
    }
    if image.source_identity() != program.cache_identity()
        || usize::try_from(image.literal_bytes()).ok() != Some(literal_len)
        || usize::from(image.literal_manifest().len()) != literal_len
    {
        return Err(invalid("source identity/literal dimensions"));
    }
    if stats.audit_work_upper_bound != bounds.audit_work
        || stats.total_work_upper_bound != bounds.work
        || image.build_receipt().work_upper_bound != bounds.work
        || image.build_receipt().support != image.support()
    {
        return Err(invalid("prospective work seal"));
    }

    // First literal byte access occurs after every dimension/work preflight.
    let literal = program.literal();
    let manifest =
        AotCountLiteralManifestV1::from_literal(literal).ok_or(invalid("literal manifest"))?;
    if image.literal_manifest() != manifest || image.literal_manifest().literal() != literal {
        return Err(invalid("literal manifest binding"));
    }

    let expected = canonical_template(literal, bounds)?;
    if image.code() != expected.code.as_slice()
        || image.labels() != expected.labels.as_slice()
        || image.relocations() != expected.relocations.as_slice()
    {
        return Err(invalid("canonical template bytes/labels/relocations"));
    }
    let expected_features = if expected.vector_instructions == 0 {
        AotCountCpuFeatures::NONE
    } else {
        AotCountCpuFeatures::ASIMD
    };
    if target.features != expected_features {
        return Err(invalid("canonical feature envelope"));
    }
    let expected_stats = (
        expected.code_bytes,
        expected.label_count,
        expected.relocation_count,
        expected.code_bytes / 4,
        expected.vector_instructions,
        expected.emission_work,
    );
    let canonical_assembler_peak = expected.emission_peak_scratch_bytes;
    let expected_assembler_peak = assembler_scratch_upper_bound_for_dimensions(
        bounds.code_bytes,
        bounds.labels,
        bounds.relocations,
    )?;
    if canonical_assembler_peak != expected_assembler_peak
        || receipt.emission_peak_scratch_bytes != bounds.emission_scratch
    {
        return Err(invalid("emission scratch receipt"));
    }
    drop(expected);

    let mut decoded = audit_exact_vec(code.len() / 4)?;
    for (index, bytes) in code.chunks_exact(4).enumerate() {
        let offset = index
            .checked_mul(4)
            .ok_or(audit_arithmetic())
            .and_then(to_u32)?;
        audit_push(
            &mut decoded,
            decode_word(
                u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
                offset,
            )?,
            "decoded instruction capacity",
        )?;
    }

    let mut policy = audit_exact_vec(bounds.code_bytes / 4)?;
    let mut policy_labels = audit_exact_vec(bounds.labels)?;
    {
        let mut policy_sink = PolicySink {
            values: &mut policy,
            labels: &mut policy_labels,
            overflowed: false,
        };
        build_independent_policy(literal, &mut policy_sink)?;
        if policy_sink.overflowed {
            return Err(invalid("independent policy capacity"));
        }
    }
    if policy.len() != decoded.len()
        || !policy
            .iter()
            .zip(&decoded)
            .all(|(expected, actual)| expected.matches(*actual))
    {
        return Err(invalid("independent exact instruction policy"));
    }

    validate_labels(image.labels(), code.len())?;
    validate_independent_labels(&policy_labels, image.labels())?;
    validate_relocation_order(image.relocations(), code.len())?;
    let mut relocation_index = 0_usize;
    let mut direct_branches = 0_u32;
    let mut vector_instructions = 0_u32;
    let mut stores = 0_u32;
    let mut returns = 0_u32;
    for (index, instruction) in decoded.iter().copied().enumerate() {
        let offset_usize = index.checked_mul(4).ok_or(audit_arithmetic())?;
        let offset = to_u32(offset_usize)?;
        if instruction.written_gpr() == Some(RESULT_POINTER_REGISTER) {
            return Err(invalid("result pointer clobber"));
        }
        let relocation = image
            .relocations()
            .get(relocation_index)
            .filter(|relocation| relocation.code_offset == offset);
        if let Some(displacement) = instruction.direct_displacement() {
            let policy_target = policy
                .get(index)
                .and_then(|expected| expected.target())
                .ok_or(invalid("independent branch edge"))?;
            let expected_target = policy_label_offset(&policy_labels, policy_target)?;
            let relocation = relocation.ok_or(invalid("missing direct relocation"))?;
            let expected_kind = instruction
                .expected_relocation_kind()
                .ok_or(invalid("branch relocation kind"))?;
            let target = i64::from(offset)
                .checked_add(i64::from(displacement))
                .ok_or(audit_arithmetic())
                .and_then(|value| {
                    u32::try_from(value).map_err(|_| invalid("branch target range"))
                })?;
            let RelocationTargetV1::CodeOffset(receipt_target) = relocation.target;
            let word = read_word(code, offset_usize)?;
            if relocation.kind != expected_kind
                || receipt_target != target
                || target != expected_target
                || relocation.resolved_word != word
                || image
                    .labels()
                    .binary_search_by_key(&target, |label| label.offset)
                    .is_err()
            {
                return Err(invalid("complete direct relocation"));
            }
            relocation_index = relocation_index.checked_add(1).ok_or(audit_arithmetic())?;
            direct_branches = direct_branches.checked_add(1).ok_or(audit_arithmetic())?;
        } else if relocation.is_some() {
            return Err(invalid("relocation on non-branch"));
        } else if policy
            .get(index)
            .is_some_and(|expected| expected.target().is_some())
        {
            return Err(invalid("missing independently described branch"));
        }
        if instruction.is_vector() {
            vector_instructions = vector_instructions
                .checked_add(1)
                .ok_or(audit_arithmetic())?;
        }
        match instruction {
            DecodedInstructionV1::Store64 {
                source,
                base,
                offset,
            } => {
                if source != X13 || base != X2 || offset != 0 {
                    return Err(invalid("sole result store"));
                }
                stores = stores.checked_add(1).ok_or(audit_arithmetic())?;
            }
            DecodedInstructionV1::Return => {
                returns = returns.checked_add(1).ok_or(audit_arithmetic())?;
            }
            _ => {}
        }
    }
    if relocation_index != image.relocations().len()
        || usize::try_from(direct_branches).ok() != Some(image.relocations().len())
        || stores != 1
        || returns != 2
    {
        return Err(invalid("terminal/relocation cardinality"));
    }

    let report = CountAuditReportV1 {
        instructions: to_u32(decoded.len())?,
        direct_branches,
        data_addresses: 0,
        vector_instructions,
        stores,
        returns,
        work_upper_bound: bounds.audit_work,
        scratch_bytes_upper_bound: bounds.audit_scratch,
    };
    drop(policy_labels);
    drop(policy);
    drop(decoded);
    let identity_bytes = artifact_identity_encoded_len(image)?;
    let code_capacity_bytes = image.code.capacity();
    let label_capacity_bytes = image
        .labels
        .capacity()
        .checked_mul(size_of::<CodeLabelV1>())
        .ok_or(audit_arithmetic())?;
    let relocation_capacity_bytes = image
        .relocations
        .capacity()
        .checked_mul(size_of::<RelocationV1>())
        .ok_or(audit_arithmetic())?;
    let retained_heap_bytes = AotCountImageV1::retained_heap_bytes(
        code_capacity_bytes,
        label_capacity_bytes,
        relocation_capacity_bytes,
    )
    .ok_or(audit_arithmetic())?;
    if (
        stats.code_bytes,
        stats.labels,
        stats.relocations,
        stats.emitted_instructions,
        stats.vector_instructions,
        stats.emission_work,
    ) != expected_stats
        || stats.data_bytes != 0
        || stats.identity_bytes_hashed != identity_bytes
        || receipt.code_capacity_bytes != code_capacity_bytes
        || receipt.label_capacity_bytes != label_capacity_bytes
        || receipt.relocation_capacity_bytes != relocation_capacity_bytes
        || receipt.retained_heap_bytes != retained_heap_bytes
        || receipt.inline_bytes != size_of::<AotCountImageV1>()
    {
        return Err(invalid("stats/capacity dimensions"));
    }
    if sealed {
        if receipt.audit != report {
            return Err(invalid("sealed scratch/audit receipt"));
        }
        let (identity, hashed_bytes) = compute_artifact_identity(image)?;
        if identity != image.artifact_identity() || hashed_bytes != identity_bytes {
            return Err(invalid("artifact identity"));
        }
    }
    Ok(report)
}

fn prospective_program(
    program: &ExactAggregateProgram<Count>,
) -> Result<Prospective, CountAotError> {
    prospective(preflight_program(program)?)
}

fn preflight_program(program: &ExactAggregateProgram<Count>) -> Result<usize, CountAotError> {
    if program.output() != AggregateOutput::Count {
        return Err(invalid("program output"));
    }
    let literal_len = program.literal().len();
    let max_supported_literal =
        usize::from(crate::SUPPORTED_AOT_COUNT_BACKEND_TUPLES_V1[0].max_literal_bytes);
    if literal_len > MAX_EXACT_AGGREGATE_LITERAL_BYTES || literal_len > max_supported_literal {
        return Err(invalid("program literal width"));
    }
    // The sealed `ExactAggregateProgram<Count>` type is the structural-shape
    // witness. Its private representation can only be constructed by the KIR
    // exact-aggregate builder, which seals the fixed four-block,
    // four-instruction, one-literal-blob form.
    Ok(literal_len)
}

fn validate_labels(labels: &[CodeLabelV1], code_len: usize) -> Result<(), CountAotError> {
    if labels
        .first()
        .is_none_or(|label| label.offset != 0 || label.kind != LabelKindV1::Entry)
        || labels
            .windows(2)
            .any(|pair| pair[0].offset >= pair[1].offset)
        || labels.iter().any(|label| {
            usize::try_from(label.offset)
                .ok()
                .is_none_or(|offset| offset >= code_len || !offset.is_multiple_of(4))
        })
    {
        return Err(invalid("ordered code labels"));
    }
    Ok(())
}

fn validate_independent_labels(
    bindings: &[PolicyLabelBindingV1],
    labels: &[CodeLabelV1],
) -> Result<(), CountAotError> {
    if bindings.len() != labels.len() {
        return Err(invalid("independent label cardinality"));
    }
    for (binding, actual) in bindings.iter().zip(labels) {
        let expected_offset = binding
            .instruction_index
            .checked_mul(4)
            .ok_or(audit_arithmetic())
            .and_then(to_u32)?;
        if actual.offset != expected_offset || actual.kind != binding.kind {
            return Err(invalid("independent label kind/offset"));
        }
    }
    Ok(())
}

fn policy_label_offset(
    bindings: &[PolicyLabelBindingV1],
    expected: PolicyLabelV1,
) -> Result<u32, CountAotError> {
    let mut found = None;
    for binding in bindings {
        if binding.label == expected {
            if found.is_some() {
                return Err(invalid("duplicate independent semantic label"));
            }
            found = Some(
                binding
                    .instruction_index
                    .checked_mul(4)
                    .ok_or(audit_arithmetic())
                    .and_then(to_u32)?,
            );
        }
    }
    found.ok_or(invalid("missing independent semantic label"))
}

fn validate_relocation_order(
    relocations: &[RelocationV1],
    code_len: usize,
) -> Result<(), CountAotError> {
    let mut prior = None;
    for relocation in relocations {
        let offset =
            usize::try_from(relocation.code_offset).map_err(|_| invalid("relocation offset"))?;
        if !offset.is_multiple_of(4)
            || offset.checked_add(4).is_none_or(|end| end > code_len)
            || prior.is_some_and(|previous| previous >= relocation.code_offset)
        {
            return Err(invalid("ordered unique relocations"));
        }
        prior = Some(relocation.code_offset);
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum PolicyInstructionV1 {
    Exact(DecodedInstructionV1),
    Branch(PolicyLabelV1),
    BranchCondition {
        condition: ConditionV1,
        target: PolicyLabelV1,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PolicyLabelV1 {
    Entry,
    Loop,
    SlowPath,
    Success,
    Overflow,
    Internal,
}

#[derive(Clone, Copy)]
struct PolicyLabelBindingV1 {
    label: PolicyLabelV1,
    kind: LabelKindV1,
    instruction_index: usize,
}

struct PolicySink<'a> {
    values: &'a mut ExactVec<PolicyInstructionV1>,
    labels: &'a mut ExactVec<PolicyLabelBindingV1>,
    overflowed: bool,
}

impl PolicySink<'_> {
    fn push(&mut self, instruction: PolicyInstructionV1) {
        if self.values.try_push(instruction).is_err() {
            self.overflowed = true;
        }
    }

    fn bind(&mut self, label: PolicyLabelV1, kind: LabelKindV1) {
        if self
            .labels
            .try_push(PolicyLabelBindingV1 {
                label,
                kind,
                instruction_index: self.values.len(),
            })
            .is_err()
        {
            self.overflowed = true;
        }
    }
}

impl PolicyInstructionV1 {
    fn matches(self, actual: DecodedInstructionV1) -> bool {
        match (self, actual) {
            (Self::Exact(expected), actual) => expected == actual,
            (Self::Branch(_), DecodedInstructionV1::Branch { .. }) => true,
            (
                Self::BranchCondition {
                    condition: expected,
                    ..
                },
                DecodedInstructionV1::BranchCondition {
                    condition: actual, ..
                },
            ) => expected == actual,
            _ => false,
        }
    }

    const fn target(self) -> Option<PolicyLabelV1> {
        match self {
            Self::Branch(target) | Self::BranchCondition { target, .. } => Some(target),
            Self::Exact(_) => None,
        }
    }
}

fn build_independent_policy(
    literal: &[u8],
    policy: &mut PolicySink<'_>,
) -> Result<(), CountAotError> {
    policy.bind(PolicyLabelV1::Entry, LabelKindV1::Entry);
    if literal.is_empty() {
        policy_mov_imm64(policy, X10, u64::MAX);
        exact(
            policy,
            DecodedInstructionV1::CompareRegister64 {
                left: X1,
                right: X10,
            },
        );
        condition(policy, ConditionV1::Equal, PolicyLabelV1::Overflow);
        exact(
            policy,
            DecodedInstructionV1::AddImmediate64 {
                destination: X13,
                source: X1,
                immediate: 1,
            },
        );
        branch(policy, PolicyLabelV1::Success);
    } else if literal.len() == 1 {
        policy_single_byte(policy, literal[0]);
    } else {
        policy_chunked(policy, literal)?;
    }
    policy.bind(PolicyLabelV1::Success, LabelKindV1::Success);
    exact(
        policy,
        DecodedInstructionV1::Store64 {
            source: X13,
            base: X2,
            offset: 0,
        },
    );
    policy_mov_imm64(policy, X0, 0);
    exact(policy, DecodedInstructionV1::Return);
    policy.bind(PolicyLabelV1::Overflow, LabelKindV1::Overflow);
    policy_mov_imm64(policy, X0, 1);
    exact(policy, DecodedInstructionV1::Return);
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "the independent exact single-byte policy is kept linear for review"
)]
fn policy_single_byte(policy: &mut PolicySink<'_>, literal: u8) {
    policy_mov_imm64(policy, X13, 0);
    policy_mov_imm64(policy, X3, 0);
    policy_mov_imm64(policy, X11, u64::from(literal));
    exact(
        policy,
        DecodedInstructionV1::DuplicateByte16 {
            destination: 1,
            source: X11,
        },
    );
    policy.bind(PolicyLabelV1::Loop, LabelKindV1::Loop);
    exact(
        policy,
        DecodedInstructionV1::SubtractRegister64 {
            destination: X10,
            left: X1,
            right: X3,
        },
    );
    exact(
        policy,
        DecodedInstructionV1::CompareImmediate64 {
            register: X10,
            immediate: 16,
        },
    );
    condition(policy, ConditionV1::CarryClear, PolicyLabelV1::SlowPath);
    exact(
        policy,
        DecodedInstructionV1::AddRegister64 {
            destination: X15,
            left: X0,
            right: X3,
        },
    );
    exact(
        policy,
        DecodedInstructionV1::LoadVector128 {
            destination: 0,
            base: X15,
            offset: 0,
        },
    );
    exact(
        policy,
        DecodedInstructionV1::CompareEqualBytes16 {
            destination: 0,
            left: 0,
            right: 1,
        },
    );
    exact(
        policy,
        DecodedInstructionV1::AddAcrossBytes16 {
            destination: 0,
            source: 0,
        },
    );
    exact(
        policy,
        DecodedInstructionV1::MoveVectorByteTo32 {
            destination: X10,
            source: 0,
        },
    );
    policy_mov_imm64(policy, X5, 256);
    exact(
        policy,
        DecodedInstructionV1::SubtractRegister64 {
            destination: X10,
            left: X5,
            right: X10,
        },
    );
    exact(
        policy,
        DecodedInstructionV1::AndLowBits64 {
            destination: X10,
            source: X10,
            bits: 8,
        },
    );
    policy_add_register(policy, X10, PolicyLabelV1::Overflow);
    exact(
        policy,
        DecodedInstructionV1::AddImmediate64 {
            destination: X3,
            source: X3,
            immediate: 16,
        },
    );
    branch(policy, PolicyLabelV1::Loop);
    policy.bind(PolicyLabelV1::SlowPath, LabelKindV1::SlowPath);
    exact(
        policy,
        DecodedInstructionV1::CompareRegister64 {
            left: X3,
            right: X1,
        },
    );
    condition(policy, ConditionV1::CarrySet, PolicyLabelV1::Success);
    exact(
        policy,
        DecodedInstructionV1::LoadByteRegister {
            destination: X10,
            base: X0,
            index: X3,
        },
    );
    exact(
        policy,
        DecodedInstructionV1::CompareRegister32 {
            left: X10,
            right: X11,
        },
    );
    condition(policy, ConditionV1::NotEqual, PolicyLabelV1::Internal);
    policy_add_immediate(policy, PolicyLabelV1::Overflow);
    policy.bind(PolicyLabelV1::Internal, LabelKindV1::Internal);
    exact(
        policy,
        DecodedInstructionV1::AddImmediate64 {
            destination: X3,
            source: X3,
            immediate: 1,
        },
    );
    branch(policy, PolicyLabelV1::SlowPath);
}

#[allow(
    clippy::too_many_lines,
    reason = "the independent exact chunked policy is kept linear for review"
)]
fn policy_chunked(policy: &mut PolicySink<'_>, literal: &[u8]) -> Result<(), CountAotError> {
    let width = u16::try_from(literal.len()).map_err(|_| audit_arithmetic())?;
    policy_mov_imm64(policy, X13, 0);
    exact(
        policy,
        DecodedInstructionV1::CompareImmediate64 {
            register: X1,
            immediate: width,
        },
    );
    condition(policy, ConditionV1::CarryClear, PolicyLabelV1::Success);
    exact(
        policy,
        DecodedInstructionV1::SubtractImmediate64 {
            destination: X4,
            source: X1,
            immediate: width,
        },
    );
    policy_mov_imm64(policy, X3, 0);
    policy.bind(PolicyLabelV1::Loop, LabelKindV1::Loop);
    exact(
        policy,
        DecodedInstructionV1::CompareRegister64 {
            left: X3,
            right: X4,
        },
    );
    condition(policy, ConditionV1::Higher, PolicyLabelV1::Success);
    exact(
        policy,
        DecodedInstructionV1::AddRegister64 {
            destination: X15,
            left: X0,
            right: X3,
        },
    );
    let mut offset = 0_u16;
    for (chunk_index, chunk) in literal.chunks_exact(8).enumerate() {
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(chunk);
        policy_mov_imm64(
            policy,
            X9,
            u64::try_from(chunk_index).map_err(|_| audit_arithmetic())?,
        );
        exact(
            policy,
            DecodedInstructionV1::Load64RegisterScaled {
                destination: X6,
                base: X15,
                index: X9,
            },
        );
        policy_mov_imm64(policy, X7, u64::from_le_bytes(bytes));
        exact(
            policy,
            DecodedInstructionV1::CompareRegister64 {
                left: X6,
                right: X7,
            },
        );
        condition(policy, ConditionV1::NotEqual, PolicyLabelV1::Internal);
        offset = offset.checked_add(8).ok_or(audit_arithmetic())?;
    }
    for byte in literal.chunks_exact(8).remainder() {
        exact(
            policy,
            DecodedInstructionV1::LoadByte {
                destination: X6,
                base: X15,
                offset,
            },
        );
        policy_mov_imm64(policy, X7, u64::from(*byte));
        exact(
            policy,
            DecodedInstructionV1::CompareRegister32 {
                left: X6,
                right: X7,
            },
        );
        condition(policy, ConditionV1::NotEqual, PolicyLabelV1::Internal);
        offset = offset.checked_add(1).ok_or(audit_arithmetic())?;
    }
    policy_add_immediate(policy, PolicyLabelV1::Overflow);
    exact(
        policy,
        DecodedInstructionV1::AddImmediate64 {
            destination: X3,
            source: X3,
            immediate: width,
        },
    );
    branch(policy, PolicyLabelV1::Loop);
    policy.bind(PolicyLabelV1::Internal, LabelKindV1::Internal);
    exact(
        policy,
        DecodedInstructionV1::AddImmediate64 {
            destination: X3,
            source: X3,
            immediate: 1,
        },
    );
    branch(policy, PolicyLabelV1::Loop);
    Ok(())
}

fn policy_add_register(policy: &mut PolicySink<'_>, delta: u8, overflow: PolicyLabelV1) {
    exact(
        policy,
        DecodedInstructionV1::MoveRegister64 {
            destination: X14,
            source: X13,
        },
    );
    exact(
        policy,
        DecodedInstructionV1::AddRegister64 {
            destination: X13,
            left: X13,
            right: delta,
        },
    );
    exact(
        policy,
        DecodedInstructionV1::CompareRegister64 {
            left: X13,
            right: X14,
        },
    );
    condition(policy, ConditionV1::CarryClear, overflow);
}

fn policy_add_immediate(policy: &mut PolicySink<'_>, overflow: PolicyLabelV1) {
    exact(
        policy,
        DecodedInstructionV1::MoveRegister64 {
            destination: X14,
            source: X13,
        },
    );
    exact(
        policy,
        DecodedInstructionV1::AddImmediate64 {
            destination: X13,
            source: X13,
            immediate: 1,
        },
    );
    exact(
        policy,
        DecodedInstructionV1::CompareRegister64 {
            left: X13,
            right: X14,
        },
    );
    condition(policy, ConditionV1::CarryClear, overflow);
}

fn policy_mov_imm64(policy: &mut PolicySink<'_>, destination: u8, value: u64) {
    for halfword in 0_u8..4 {
        let shift = u32::from(halfword)
            .checked_mul(16)
            .expect("bounded halfword shift");
        let immediate = u16::try_from((value >> shift) & 0xffff).expect("masked halfword");
        exact(
            policy,
            if halfword == 0 {
                DecodedInstructionV1::MoveZero64 {
                    destination,
                    immediate,
                    shift: 0,
                }
            } else {
                DecodedInstructionV1::MoveKeep64 {
                    destination,
                    immediate,
                    shift: halfword.checked_mul(16).expect("bounded halfword shift"),
                }
            },
        );
    }
}

fn exact(policy: &mut PolicySink<'_>, instruction: DecodedInstructionV1) {
    policy.push(PolicyInstructionV1::Exact(instruction));
}

fn branch(policy: &mut PolicySink<'_>, target: PolicyLabelV1) {
    policy.push(PolicyInstructionV1::Branch(target));
}

fn condition(policy: &mut PolicySink<'_>, condition: ConditionV1, target: PolicyLabelV1) {
    policy.push(PolicyInstructionV1::BranchCondition { condition, target });
}

#[allow(
    clippy::too_many_lines,
    reason = "one independent ordered mask table keeps the AOT policy decoder auditable"
)]
fn decode_word(word: u32, offset: u32) -> Result<DecodedInstructionV1, CountAotError> {
    let rd = register(word);
    let rn = register(word >> 5);
    let rm = register(word >> 16);
    if word & 0xffe0_ffe0 == 0xaa00_03e0 {
        Ok(DecodedInstructionV1::MoveRegister64 {
            destination: rd,
            source: rm,
        })
    } else if word & 0xff80_0000 == 0xd280_0000 {
        Ok(DecodedInstructionV1::MoveZero64 {
            destination: rd,
            immediate: immediate16(word),
            shift: halfword_shift(word),
        })
    } else if word & 0xff80_0000 == 0xf280_0000 {
        Ok(DecodedInstructionV1::MoveKeep64 {
            destination: rd,
            immediate: immediate16(word),
            shift: halfword_shift(word),
        })
    } else if word & 0xffe0_fc1f == 0xeb00_001f {
        Ok(DecodedInstructionV1::CompareRegister64 {
            left: rn,
            right: rm,
        })
    } else if word & 0xffe0_fc1f == 0x6b00_001f {
        Ok(DecodedInstructionV1::CompareRegister32 {
            left: rn,
            right: rm,
        })
    } else if word & 0xffc0_001f == 0xf100_001f {
        Ok(DecodedInstructionV1::CompareImmediate64 {
            register: rn,
            immediate: immediate12(word),
        })
    } else if word & 0xffe0_fc00 == 0x8b00_0000 {
        Ok(DecodedInstructionV1::AddRegister64 {
            destination: rd,
            left: rn,
            right: rm,
        })
    } else if word & 0xffc0_0000 == 0x9100_0000 {
        Ok(DecodedInstructionV1::AddImmediate64 {
            destination: rd,
            source: rn,
            immediate: immediate12(word),
        })
    } else if word & 0xffe0_fc00 == 0xcb00_0000 {
        Ok(DecodedInstructionV1::SubtractRegister64 {
            destination: rd,
            left: rn,
            right: rm,
        })
    } else if word & 0xffc0_0000 == 0xd100_0000 {
        Ok(DecodedInstructionV1::SubtractImmediate64 {
            destination: rd,
            source: rn,
            immediate: immediate12(word),
        })
    } else if word & 0xffc0_0000 == 0x9240_0000 && (word >> 16).trailing_zeros() >= 6 {
        Ok(DecodedInstructionV1::AndLowBits64 {
            destination: rd,
            source: rn,
            bits: u8::try_from(
                ((word >> 10) & 0x3f)
                    .checked_add(1)
                    .expect("six-bit field plus one"),
            )
            .expect("at most 64 bits"),
        })
    } else if word & 0xffc0_0000 == 0x3940_0000 {
        Ok(DecodedInstructionV1::LoadByte {
            destination: rd,
            base: rn,
            offset: immediate12(word),
        })
    } else if word & 0xffe0_fc00 == 0x3860_6800 {
        Ok(DecodedInstructionV1::LoadByteRegister {
            destination: rd,
            base: rn,
            index: rm,
        })
    } else if word & 0xffe0_fc00 == 0xf860_7800 {
        Ok(DecodedInstructionV1::Load64RegisterScaled {
            destination: rd,
            base: rn,
            index: rm,
        })
    } else if word & 0xffc0_0000 == 0xf900_0000 {
        Ok(DecodedInstructionV1::Store64 {
            source: rd,
            base: rn,
            offset: immediate12(word)
                .checked_mul(8)
                .expect("scaled store offset fits u16"),
        })
    } else if word & 0xffc0_0000 == 0x3dc0_0000 {
        Ok(DecodedInstructionV1::LoadVector128 {
            destination: rd,
            base: rn,
            offset: immediate12(word)
                .checked_mul(16)
                .expect("scaled vector offset fits u16"),
        })
    } else if word & 0xffff_fc00 == 0x4e01_0c00 {
        Ok(DecodedInstructionV1::DuplicateByte16 {
            destination: rd,
            source: rn,
        })
    } else if word & 0xffe0_fc00 == 0x6e20_8c00 {
        Ok(DecodedInstructionV1::CompareEqualBytes16 {
            destination: rd,
            left: rn,
            right: rm,
        })
    } else if word & 0xffff_fc00 == 0x4e31_b800 {
        Ok(DecodedInstructionV1::AddAcrossBytes16 {
            destination: rd,
            source: rn,
        })
    } else if word & 0xffff_fc00 == 0x0e01_3c00 {
        Ok(DecodedInstructionV1::MoveVectorByteTo32 {
            destination: rd,
            source: rn,
        })
    } else if word & 0xfc00_0000 == 0x1400_0000 {
        Ok(DecodedInstructionV1::Branch {
            displacement: sign_extend(word & 0x03ff_ffff, 26) << 2,
        })
    } else if word & 0xff00_0010 == 0x5400_0000 {
        let condition = match u8::try_from(word & 0xf).expect("four-bit condition") {
            0 => ConditionV1::Equal,
            1 => ConditionV1::NotEqual,
            2 => ConditionV1::CarrySet,
            3 => ConditionV1::CarryClear,
            8 => ConditionV1::Higher,
            _ => return Err(CountAotError::UnknownInstruction { offset, word }),
        };
        Ok(DecodedInstructionV1::BranchCondition {
            condition,
            displacement: sign_extend((word >> 5) & 0x7_ffff, 19) << 2,
        })
    } else if word == 0xd65f_03c0 {
        Ok(DecodedInstructionV1::Return)
    } else {
        Err(CountAotError::UnknownInstruction { offset, word })
    }
}

fn read_word(code: &[u8], offset: usize) -> Result<u32, CountAotError> {
    let bytes = code
        .get(offset..offset.checked_add(4).ok_or(audit_arithmetic())?)
        .ok_or(invalid("branch word"))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn register(word: u32) -> u8 {
    u8::try_from(word & 0x1f).expect("five-bit register")
}

fn immediate12(word: u32) -> u16 {
    u16::try_from((word >> 10) & 0xfff).expect("twelve-bit immediate")
}

fn immediate16(word: u32) -> u16 {
    u16::try_from((word >> 5) & 0xffff).expect("sixteen-bit immediate")
}

fn halfword_shift(word: u32) -> u8 {
    u8::try_from(
        ((word >> 21) & 3)
            .checked_mul(16)
            .expect("two-bit halfword shift"),
    )
    .expect("two-bit halfword shift")
}

fn sign_extend(value: u32, bits: u8) -> i32 {
    let shift = 32_u32
        .checked_sub(u32::from(bits))
        .expect("field no wider than u32");
    (value << shift).cast_signed() >> shift
}

fn refuse_audit_scratch(required: u64, limit: u64) -> Result<(), CountAotError> {
    if required > limit {
        return Err(CountAotError::ResourceLimit {
            resource: CountAotResource::ScratchBytes,
            limit,
            required,
        });
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_field_names,
    reason = "the byte units are part of the resource-proof field names"
)]
struct PersistentEnvelopeV1 {
    code_capacity_bytes: usize,
    label_capacity_bytes: usize,
    relocation_capacity_bytes: usize,
    retained_heap_bytes: usize,
    inline_bytes: usize,
    persistent_bytes: u64,
}

fn source_persistent_envelope(bounds: Prospective) -> Result<PersistentEnvelopeV1, CountAotError> {
    persistent_envelope(
        bounds.code_bytes,
        bounds
            .labels
            .checked_mul(size_of::<CodeLabelV1>())
            .ok_or(audit_arithmetic())?,
        bounds
            .relocations
            .checked_mul(size_of::<RelocationV1>())
            .ok_or(audit_arithmetic())?,
    )
}

fn image_persistent_envelope(
    image: &AotCountImageV1,
) -> Result<PersistentEnvelopeV1, CountAotError> {
    persistent_envelope(
        image.code.capacity(),
        image
            .labels
            .capacity()
            .checked_mul(size_of::<CodeLabelV1>())
            .ok_or(audit_arithmetic())?,
        image
            .relocations
            .capacity()
            .checked_mul(size_of::<RelocationV1>())
            .ok_or(audit_arithmetic())?,
    )
}

fn persistent_envelope(
    code_capacity_bytes: usize,
    label_capacity_bytes: usize,
    relocation_capacity_bytes: usize,
) -> Result<PersistentEnvelopeV1, CountAotError> {
    let retained_heap_bytes = AotCountImageV1::retained_heap_bytes(
        code_capacity_bytes,
        label_capacity_bytes,
        relocation_capacity_bytes,
    )
    .ok_or(audit_arithmetic())?;
    let inline_bytes = size_of::<AotCountImageV1>();
    let persistent_bytes = retained_heap_bytes
        .checked_add(inline_bytes)
        .ok_or(audit_arithmetic())
        .and_then(to_u64)?;
    Ok(PersistentEnvelopeV1 {
        code_capacity_bytes,
        label_capacity_bytes,
        relocation_capacity_bytes,
        retained_heap_bytes,
        inline_bytes,
        persistent_bytes,
    })
}

fn audit_exact_vec<T>(capacity: usize) -> Result<ExactVec<T>, CountAotError> {
    ExactVec::try_with_capacity(capacity).map_err(|error| match error {
        CopyError::LayoutOverflow => audit_arithmetic(),
        CopyError::AllocationFailed => CountAotError::AllocationFailed {
            resource: CountAotResource::ScratchBytes,
        },
    })
}

fn audit_push<T>(
    values: &mut ExactVec<T>,
    value: T,
    at: &'static str,
) -> Result<(), CountAotError> {
    values
        .try_push(value)
        .map_err(|_| CountAotError::InternalInvariant { at })
}

fn to_u32(value: usize) -> Result<u32, CountAotError> {
    u32::try_from(value).map_err(|_| audit_arithmetic())
}

fn to_u64(value: usize) -> Result<u64, CountAotError> {
    u64::try_from(value).map_err(|_| audit_arithmetic())
}

const fn invalid(at: &'static str) -> CountAotError {
    CountAotError::InvalidImage { at }
}

const fn audit_arithmetic() -> CountAotError {
    CountAotError::ArithmeticOverflow {
        site: CountAotArithmeticSite::Audit,
    }
}
